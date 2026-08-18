/*
 * smoke.test.js — boots the real server and exercises the paths that have to work
 * before the site can take a booking. Runs with plain `node --test`-free asserts
 * so there is no test framework to install.
 *
 *   npm test
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

const PORT = 3799;
const BASE = `http://127.0.0.1:${PORT}`;

const ADMIN_TOKEN = crypto.randomBytes(24).toString('hex');
const OVERRIDE_TOKEN = crypto.randomBytes(24).toString('hex');

let passed = 0, failed = 0;
const results = [];

async function check(name, fn) {
  try {
    await fn();
    passed++;
    results.push(`  PASS  ${name}`);
  } catch (err) {
    failed++;
    results.push(`  FAIL  ${name}\n          ${err.message}`);
  }
}

const api = (path, init) => fetch(BASE + path, init);
const postJson = (path, body, headers = {}) =>
  api(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

// --- boot -------------------------------------------------------------------
// Held in a const rather than inlined below: the unsubscribe test has to derive
// the same HMAC the Worker does, so it needs the pepper the server booted with.
const SESSION_PEPPER = crypto.randomBytes(24).toString('hex');

const server = spawn(process.execPath, ['server.js'], {
  cwd: new URL('..', import.meta.url).pathname,
  env: {
    ...process.env,
    PORT: String(PORT),
    NODE_ENV: 'test',
    SESSION_PEPPER,
    ADMIN_TOKEN,
    OVERRIDE_TOKEN,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});

let serverOutput = '';
server.stdout.on('data', d => { serverOutput += d; });
server.stderr.on('data', d => { serverOutput += d; });

async function waitForServer(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await api('/api/health');
      if (r.ok || r.status === 200) return;
    } catch { /* not up yet */ }
    await new Promise(r => setTimeout(r, 200));
  }
  throw new Error(`server did not start in ${timeoutMs}ms:\n${serverOutput}`);
}

try {
  await waitForServer();

  // --- health & catalogue ---------------------------------------------------
  await check('health endpoint reports a loaded catalogue', async () => {
    const r = await api('/api/health');
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.catalogue.tyres > 1000, `expected >1000 tyres, got ${d.catalogue.tyres}`);
    assert.ok(d.catalogue.sizes > 50, `expected >50 sizes, got ${d.catalogue.sizes}`);
    assert.equal(d.ok, true);
  });

  // This is the regression that mattered most: the Worker had no tyre routes at
  // all, so production served placeholder prices while dev looked fine.
  await check('tyre lookup returns real priced tyres from the Worker', async () => {
    const r = await api('/api/tyres/lookup?size=195/65R15');
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.total > 0, 'no tyres returned for 195/65R15');
    const t = d.tyres[0];
    assert.ok(t.brand, 'tyre has no brand');
    assert.ok(typeof t.price === 'number' && t.price > 0, `bad price: ${t.price}`);
    assert.match(t.image, /^\/images\//, `bad image path: ${t.image}`);
    assert.ok(t.sku, 'tyre has no SKU');
  });

  await check('tyre lookup normalises alternative size formats', async () => {
    const canonical = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    for (const variant of ['195/65/15', '195 65 15', '195/65 R15', '1956515']) {
      const d = await (await api(`/api/tyres/lookup?size=${encodeURIComponent(variant)}`)).json();
      assert.equal(d.total, canonical.total, `"${variant}" gave ${d.total}, expected ${canonical.total}`);
    }
  });

  await check('tyre lookup returns cheapest first', async () => {
    const d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    const prices = d.tyres.map(t => t.price);
    const sorted = [...prices].sort((a, b) => a - b);
    assert.deepEqual(prices, sorted, 'results are not price-ascending');
  });

  await check('tyre search finds a known brand', async () => {
    const d = await (await api('/api/tyres/search?q=michelin')).json();
    assert.ok(d.total > 0, 'no Michelin tyres found');
    assert.ok(d.tyres.every(t => JSON.stringify(t).toLowerCase().includes('michelin')));
  });

  await check('unknown tyre size returns empty, not an error', async () => {
    const r = await api('/api/tyres/lookup?size=999/99R99');
    assert.equal(r.status, 200);
    assert.equal((await r.json()).total, 0);
  });

  // --- admin auth -----------------------------------------------------------
  await check('admin login rejects a wrong token', async () => {
    const r = await postJson('/api/admin-login', { token: 'definitely-wrong' });
    assert.equal(r.status, 401);
  });

  await check('admin login accepts the real token', async () => {
    const r = await postJson('/api/admin-login', { token: ADMIN_TOKEN });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.token && d.token.length >= 20, 'admin session token too short');
  });

  await check('admin endpoints reject an unauthenticated caller', async () => {
    const r = await api('/api/admin/jobs');
    assert.equal(r.status, 403);
  });

  await check('admin endpoints accept a valid session', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN })).json();
    const r = await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + token } });
    assert.equal(r.status, 200);
    assert.ok(Array.isArray((await r.json()).jobs));
  });

  await check('override token grants access and is distinct from admin token', async () => {
    const r = await postJson('/api/admin-login', { token: OVERRIDE_TOKEN });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).override, true);
  });

  // --- 2FA ------------------------------------------------------------------
  let totpSecret = null;
  await check('2FA enrolment issues a secret and an otpauth URI', async () => {
    const r = await postJson('/api/admin-2fa/new', { token: ADMIN_TOKEN });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(/^[A-Z2-7]{32}$/.test(d.secret), `bad base32 secret: ${d.secret}`);
    assert.match(d.otpauth, /^otpauth:\/\/totp\//);
    totpSecret = d.secret;
  });

  // Independent TOTP implementation, so we are testing the Worker's maths
  // against RFC 6238 rather than against itself.
  function totpNow(base32) {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0, val = 0;
    const bytes = [];
    for (const c of base32.replace(/=+$/, '').toUpperCase()) {
      const i = A.indexOf(c);
      if (i < 0) continue;
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { bytes.push((val >> (bits - 8)) & 0xff); bits -= 8; }
    }
    const counter = Buffer.alloc(8);
    counter.writeUInt32BE(Math.floor(Date.now() / 30000), 4);
    const hmac = crypto.createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
    const off = hmac[19] & 0xf;
    const code = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
    return String(code % 1000000).padStart(6, '0');
  }

  await check('2FA rejects a wrong code', async () => {
    const r = await postJson('/api/admin-2fa/enable', { token: ADMIN_TOKEN, secret: totpSecret, code: '000000' });
    assert.equal(r.status, 400);
  });

  await check('2FA enables with a correct code', async () => {
    const r = await postJson('/api/admin-2fa/enable', { token: ADMIN_TOKEN, secret: totpSecret, code: totpNow(totpSecret) });
    assert.equal(r.status, 200);
  });

  await check('once enrolled, admin login requires the 2FA code', async () => {
    const r = await postJson('/api/admin-login', { token: ADMIN_TOKEN });
    assert.equal(r.status, 401);
  });

  await check('admin login succeeds with token + valid 2FA code', async () => {
    const r = await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) });
    assert.equal(r.status, 200);
    assert.ok((await r.json()).token);
  });

  await check('2FA cannot be silently re-enrolled by a token holder', async () => {
    const r = await postJson('/api/admin-2fa/new', { token: ADMIN_TOKEN });
    assert.equal(r.status, 409);
  });

  // --- driver auth ----------------------------------------------------------
  const driverPass = 'driver-password-123';
  await check('driver registration succeeds and starts unapproved', async () => {
    const r = await postJson('/api/driver/register', { username: 'TestDriver', password: driverPass, name: 'Test Driver' });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).pending, true);
  });

  await check('driver password is never stored in plaintext', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const r = await api('/api/admin/drivers', { headers: { authorization: 'Bearer ' + token } });
    const body = await r.text();
    assert.ok(!body.includes(driverPass), 'plaintext driver password leaked in /admin/drivers');
    assert.ok(!body.includes('"hash"'), 'password hash leaked in /admin/drivers');
    assert.ok(!body.includes('"salt"'), 'password salt leaked in /admin/drivers');
  });

  await check('unapproved driver cannot log in', async () => {
    const r = await postJson('/api/driver/login', { username: 'TestDriver', password: driverPass });
    assert.equal(r.status, 403);
  });

  await check('driver login rejects a wrong password', async () => {
    const r = await postJson('/api/driver/login', { username: 'TestDriver', password: 'wrong-password' });
    assert.equal(r.status, 401);
  });

  let driverId = null;
  await check('admin can approve a driver', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const list = await (await api('/api/admin/drivers', { headers: { authorization: 'Bearer ' + token } })).json();
    driverId = list.drivers.find(d => d.username === 'testdriver')?.id;
    assert.ok(driverId, 'registered driver not present in admin list');
    const r = await postJson('/api/admin/drivers', { action: 'approve', id: driverId }, { authorization: 'Bearer ' + token });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).drivers.find(d => d.id === driverId).approved, true);
  });

  let driverToken = null;
  await check('approved driver can log in and gets a random token', async () => {
    const r = await postJson('/api/driver/login', { username: 'TestDriver', password: driverPass });
    assert.equal(r.status, 200);
    const d = await r.json();
    driverToken = d.token;
    // "DRVTOK-" + 40 random chars. The old build used Date.now(), which was guessable.
    assert.ok(d.token.length > 30, `driver token too short: ${d.token}`);
    assert.ok(!/DRVTOK-[0-9A-Z]{8,11}$/.test(d.token), 'driver token still looks timestamp-derived');
    assert.equal(d.driver.hash, undefined, 'login response leaked password hash');
    assert.equal(d.driver.salt, undefined, 'login response leaked salt');
  });

  await check('editing a driver in admin does not destroy their login', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    // Previously this wrote a fresh object and silently dropped username/hash/approved.
    await postJson('/api/admin/drivers', { id: driverId, name: 'Renamed Driver', vanReg: 'WV68 PLT' }, { authorization: 'Bearer ' + token });
    const r = await postJson('/api/driver/login', { username: 'TestDriver', password: driverPass });
    assert.equal(r.status, 200, 'driver could no longer log in after an admin edit');
  });

  await check('revoking a driver kills their live session', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    await postJson('/api/admin/drivers', { action: 'revoke', id: driverId }, { authorization: 'Bearer ' + token });
    const r = await postJson('/api/driver/jobs', { token: driverToken });
    assert.equal(r.status, 403, 'revoked driver still had API access');
  });

  // --- customer accounts & bookings ----------------------------------------
  const email = `test-${Date.now()}@example.com`;
  const password = 'customer-password-123';
  let customerToken = null;

  await check('customer can sign up', async () => {
    const r = await postJson('/api/auth/signup', {
      email, password, name: 'Test Customer', phone: '07900000000', consent: true,
    });
    assert.equal(r.status, 200);
    const d = await r.json();
    customerToken = d.token;
    assert.ok(customerToken, 'no session token returned on signup');
    assert.equal(d.user.hash, undefined, 'signup response leaked password hash');
  });

  await check('customer login rejects a wrong password', async () => {
    const r = await postJson('/api/auth/login', { email, password: 'nope-wrong' });
    assert.equal(r.status, 401);
  });

  await check('customer login works with the right password', async () => {
    const r = await postJson('/api/auth/login', { email, password });
    assert.equal(r.status, 200);
    customerToken = (await r.json()).token;
  });

  await check('login on an unknown email does not reveal that it is unknown', async () => {
    const r = await postJson('/api/auth/login', { email: 'nobody-here@example.com', password: 'whatever' });
    assert.equal(r.status, 401);
    const d = await r.json();
    assert.ok(!/not found|no account|unknown/i.test(d.error), `error leaks account existence: ${d.error}`);
  });

  await check('a booking can be created and read back', async () => {
    const r = await postJson('/api/bookings', {
      svc: 'tyre', svcLabel: 'Tyre fitting — test', reg: 'AB12CDE',
      postcode: 'DT6 3QP', date: '2026-09-01', notes: 'smoke test booking',
    }, { authorization: 'Bearer ' + customerToken });
    const d = await r.json();
    assert.equal(r.status, 200, `booking failed: ${JSON.stringify(d)}`);
    assert.ok(d.ref || d.booking?.ref, 'booking returned no reference');

    const list = await (await api('/api/bookings', { headers: { authorization: 'Bearer ' + customerToken } })).json();
    assert.ok((list.bookings || []).length > 0, 'booking did not persist');
  });

  await check('bookings require a signed-in customer', async () => {
    const r = await postJson('/api/bookings', { svc: 'tyre' });
    assert.equal(r.status, 401);
  });

  // --- GDPR -----------------------------------------------------------------
  await check('customer can export their own data', async () => {
    const r = await api('/api/gdpr/export', { headers: { authorization: 'Bearer ' + customerToken } });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.equal(d.account.hash, undefined, 'data export leaked password hash');
    assert.ok(Array.isArray(d.bookings));
  });


  // --- live location tracking ----------------------------------------------
  await check('driver GPS posts are rejected without a valid session', async () => {
    const r = await postJson('/api/driver/location', { ref: 'CMS-TEST1', lat: 50.73, lng: -2.75, token: 'not-a-real-token' });
    assert.equal(r.status, 403);
  });

  await check('driver GPS is stored and readable by the admin map', async () => {
    // Re-approve the driver revoked by the earlier test, then log back in.
    const { token: adminTok } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    await postJson('/api/admin/drivers', { action: 'approve', id: driverId }, { authorization: 'Bearer ' + adminTok });
    const { token: drvTok } = await (await postJson('/api/driver/login', { username: 'TestDriver', password: driverPass })).json();

    // The ref must name a REAL booking now, so make one. Previously any string
    // was accepted and became a new KV key.
    const bk = await postJson('/api/service-requests', {
      name: 'GPS Job', phone: '07900556111', reg: 'GP11SXX', service: 'diagnostics', svcLabel: 'Diagnostics',
    });
    const gpsRef = (await bk.json()).ref;

    const post = await postJson('/api/driver/location', { ref: gpsRef, lat: 50.7333, lng: -2.7581, eta: 12, token: drvTok });
    assert.equal(post.status, 200, `location post failed: ${await post.text()}`);

    const r = await api('/api/admin/locations', { headers: { authorization: 'Bearer ' + adminTok } });
    assert.equal(r.status, 200);
    const { locations } = await r.json();
    const hit = locations.find(l => l.jobRef === gpsRef);
    assert.ok(hit, 'driver location did not reach the admin map');
    assert.equal(hit.lat, 50.7333);
    assert.ok(hit.t > 0, 'location has no timestamp');

    // Junk coordinates must be refused, not written. They used to go straight
    // into KV and on to the customer's map, where Leaflet throws on an invalid
    // LatLng and the tracker dies.
    for (const bad of [{ lat: 'north', lng: 1 }, { lat: 999, lng: 1 }, { lat: 50, lng: -400 }, { lat: NaN, lng: 0 }]) {
      const res = await postJson('/api/driver/location', { ref: gpsRef, ...bad, token: drvTok });
      assert.equal(res.status, 400, `bad coordinates ${JSON.stringify(bad)} were accepted`);
    }

    // A ref that names no booking must 404 rather than create a KV key.
    const ghost = await postJson('/api/driver/location', { ref: 'CMS-NOPE1', lat: 50, lng: -2, token: drvTok });
    assert.equal(ghost.status, 404, 'posting GPS for a non-existent job was accepted');

    // A second driver must not be able to hijack a job the first has claimed.
    // Any approved driver used to be able to plant GPS on any ref, or flag a
    // stranger's customer as "your mechanic is with you".
    const other = 'Driver2-' + Date.now();
    const otherPass = 'anotherLongPassword1';
    const reg2 = await postJson('/api/driver/register', { username: other, password: otherPass, name: 'Second Driver' });
    const d2 = await reg2.json();
    await postJson('/api/admin/drivers', { action: 'approve', id: d2.id || d2.driver?.id }, { authorization: 'Bearer ' + adminTok });
    const { token: tok2 } = await (await postJson('/api/driver/login', { username: other, password: otherPass })).json();
    if (tok2) {
      const steal = await postJson('/api/driver/location', { ref: gpsRef, lat: 51, lng: -1, token: tok2 });
      assert.equal(steal.status, 403, 'a second driver hijacked a job already claimed by another');
    }

    // The driver's job list must carry the coordinates, or the live ETA the
    // customer is shown can never be calculated.
    const jl = await (await postJson('/api/driver/jobs', { token: drvTok })).json();
    assert.ok('lat' in (jl.jobs.find(j => j.ref === gpsRef) || {}), 'driver job list omits coordinates — the ETA cannot work');
  });

  await check('job tracking requires sign-in and is scoped to the owner', async () => {
    // Anonymous callers get nothing.
    assert.equal((await api('/api/track/CMS-TEST1')).status, 401);
    // A signed-in customer cannot read someone else's job either.
    const r = await api('/api/track/CMS-NOTMINE', { headers: { authorization: 'Bearer ' + customerToken } });
    assert.equal(r.status, 404);
  });

  await check('a customer can track their own booking', async () => {
    const list = await (await api('/api/bookings', { headers: { authorization: 'Bearer ' + customerToken } })).json();
    const ref = list.bookings[0].ref;
    const r = await api('/api/track/' + ref, { headers: { authorization: 'Bearer ' + customerToken } });
    assert.equal(r.status, 200, 'customer could not track their own booking');
    const d = await r.json();
    assert.ok('status' in d && 'location' in d, 'track response missing status/location');
  });

  await check('service-requests endpoint accepts a booking from the site', async () => {
    const r = await postJson('/api/service-requests', {
      ref: 'CMS-SR001', svcLabel: 'Tyre fitting', reg: 'AB12CDE', postcode: 'DT6 3QP',
      name: 'Walk-in Customer', email: 'walkin@example.com', phone: '07900000001',
    });
    assert.ok(r.status < 500, `service-requests errored: ${r.status}`);
  });

  // --- inventory ------------------------------------------------------------
  await check('admin inventory endpoint returns a summary', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const r = await api('/api/admin/inventory', { headers: { authorization: 'Bearer ' + token } });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.summary, 'no inventory summary returned');
    assert.ok(typeof d.summary.totalSkus === 'number');
  });

  // --- WhatsApp reminders --------------------------------------------------
  await check('reminder endpoint reports WhatsApp is not configured', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const r = await postJson('/api/admin/test-reminder', {}, { authorization: 'Bearer ' + token });
    // No WHATSAPP_TOKEN in the test env, so it must say so rather than fail silently.
    assert.equal(r.status, 503);
    const d = await r.json();
    assert.match(d.error, /WhatsApp is not configured/);
  });

  await check('reminder endpoint requires admin auth', async () => {
    const r = await postJson('/api/admin/test-reminder', {});
    assert.equal(r.status, 403);
  });


  // --- tyre pricing (admin-controlled) --------------------------------------
  // OVERRIDE_TOKEN, not ADMIN_TOKEN: the shared setup token is deliberately
  // disabled once a staff account exists, and several tests below create one.
  // The override is the documented break-glass path and always works.
  const adminTok = async () =>
    (await (await postJson('/api/admin-login', { token: OVERRIDE_TOKEN })).json()).token;

  await check('public tyre lookup never leaks wholesale cost or supplier link', async () => {
    const d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    const raw = JSON.stringify(d);
    assert.ok(!raw.includes('ctyres.co.uk'), 'supplier URL leaked to the public API');
    for (const t of d.tyres) {
      assert.equal(t.cost, undefined, 'wholesale cost leaked to customers');
      assert.equal(t.supplierUrl, undefined, 'supplier URL leaked to customers');
      assert.equal(t.margin, undefined, 'margin leaked to customers');
    }
  });

  await check('customer SKU is CUZ/<ref><tier> and tier is one of B/M/P', async () => {
    const d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    for (const t of d.tyres) {
      assert.match(t.sku, /^CUZ\/.+[BMP]$/, `bad SKU: ${t.sku}`);
      assert.ok(['B', 'M', 'P'].includes(t.tier), `bad tier: ${t.tier}`);
      assert.ok(t.sku.endsWith(t.tier), `SKU tier letter does not match tier: ${t.sku} / ${t.tier}`);
    }
    // All three tiers should be represented in a size with plenty of options.
    const tiers = new Set(d.tyres.map(t => t.tier));
    assert.equal(tiers.size, 3, `expected all 3 tiers, got ${[...tiers].join(',')}`);
  });

  await check('admin tyre view exposes cost, margin and the wholesaler link', async () => {
    const r = await api('/api/admin/tyres?size=195/65R15', { headers: { authorization: 'Bearer ' + await adminTok() } });
    assert.equal(r.status, 200);
    const d = await r.json();
    const t = d.tyres[0];
    assert.ok(typeof t.cost === 'number' && t.cost > 0, 'no wholesale cost in admin view');
    assert.ok(typeof t.margin === 'number', 'no margin in admin view');
    assert.match(t.supplierUrl, /^https:\/\/www\.ctyres\.co\.uk\//, `bad supplier URL: ${t.supplierUrl}`);
    assert.ok(t.ean, 'no EAN in admin view');
    assert.ok(t.supplierSku, 'no supplier SKU in admin view');
  });

  await check('admin tyre view requires auth', async () => {
    assert.equal((await api('/api/admin/tyres?size=195/65R15')).status, 403);
  });

  await check('changing the markup percentage moves customer prices', async () => {
    const tok = await adminTok();
    const before = (await (await api('/api/tyres/lookup?size=195/65R15')).json()).tyres[0].price;

    const r = await postJson('/api/admin/pricing',
      { markupPct: { B: 200, M: 50, P: 42 }, fittingFee: 15, roundTo: 1 },
      { authorization: 'Bearer ' + tok });
    assert.equal(r.status, 200);

    const after = (await (await api('/api/tyres/lookup?size=195/65R15')).json()).tyres[0].price;
    assert.ok(after > before, `price did not rise: ${before} -> ${after}`);

    // put it back
    await postJson('/api/admin/pricing', { markupPct: { B: 60, M: 50, P: 42 }, fittingFee: 15, roundTo: 1 },
      { authorization: 'Bearer ' + tok });
  });

  await check('markup is validated', async () => {
    const r = await postJson('/api/admin/pricing', { markupPct: { B: 9999 } }, { authorization: 'Bearer ' + await adminTok() });
    assert.equal(r.status, 400);
  });

  await check('an individual price override wins, and can be cleared', async () => {
    const tok = await adminTok();
    const first = (await (await api('/api/tyres/lookup?size=195/65R15')).json()).tyres[0];

    await postJson('/api/admin/pricing/override', { id: first.id, price: 199.5 }, { authorization: 'Bearer ' + tok });
    let d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    assert.equal(d.tyres.find(t => t.id === first.id).price, 199.5, 'override not applied');

    await postJson('/api/admin/pricing/override', { id: first.id, price: null }, { authorization: 'Bearer ' + tok });
    d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    assert.equal(d.tyres.find(t => t.id === first.id).price, first.price, 'override not cleared');
  });

  await check('marking a tyre in stock shows on the customer side and filters', async () => {
    const tok = await adminTok();
    const all = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    const pick = all.tyres[1];

    await postJson('/api/admin/pricing/stock', { ids: [pick.id] }, { authorization: 'Bearer ' + tok });

    const d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    assert.equal(d.tyres.find(t => t.id === pick.id).inStock, true, 'in-stock flag not set');

    const only = await (await api('/api/tyres/lookup?size=195/65R15&inStock=1')).json();
    assert.equal(only.total, 1, `in-stock filter returned ${only.total}`);
    assert.equal(only.tyres[0].id, pick.id);

    await postJson('/api/admin/pricing/stock', { ids: [] }, { authorization: 'Bearer ' + tok });
  });

  // --- rate limiting --------------------------------------------------------
  // --- Customer CRM (discount + notes) ---------------------------------------
  // --- Booking reliability: a job the customer is told is confirmed MUST exist ---
  await check('a website booking reaches the admin dashboard', async () => {
    const r = await postJson('/api/service-requests', {
      name: 'Smoke Booker', phone: '07900555111', email: `booker-${Date.now()}@example.com`,
      reg: 'KM16GLY', postcode: 'dt64lb', date: '2026-08-21', time: 'Afternoon (12-5)',
      service: 'recovery', svcLabel: 'Breakdown / recovery',
    });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.ok && d.ref, 'booking was not accepted');
    const tok = await adminTok();
    const jobs = (await (await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + tok } })).json()).jobs;
    assert.ok(jobs.some(j => j.ref === d.ref), `booking ${d.ref} confirmed to the customer but missing from the dashboard`);
  });

  await check('a guest booking creates a CRM contact without creating a login account', async () => {
    const em = `guest-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Guest Booker', phone: '07900555333', email: em,
      reg: 'GU11EST', service: 'diagnostics', svcLabel: 'Diagnostics',
    });
    assert.ok((await r.json()).ok, 'guest booking was not accepted');

    const tok = await adminTok();
    const list = (await (await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } })).json()).customers;
    const row = list.find(c => c.email === em);
    assert.ok(row, 'a guest who booked without an account is missing from the CRM');
    assert.equal(row.hasAccount, false, 'a booking must not silently create a login account');
    assert.equal(row.jobCount, 1);

    // The booking must not have made them signup-blocked: /auth/signup answers
    // 409 "already exists" off the presence of a user: record, so a contact
    // record must be a different key entirely.
    const su = await postJson('/api/auth/signup', {
      name: 'Guest Booker', email: em, phone: '07900555333', password: 'aVeryLongPassword1', consent: true,
    });
    assert.equal(su.status, 200, 'booking as a guest locked that email out of ever signing up');
  });

  await check('booking without ticking the optional box records no marketing consent', async () => {
    const em = `nomkt-${Date.now()}@example.com`;
    await postJson('/api/service-requests', {
      name: 'No Marketing', phone: '07900555444', email: em,
      reg: 'NO11MKT', service: 'recovery', svcLabel: 'Breakdown / recovery',
    });
    const tok = await adminTok();
    const list = (await (await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } })).json()).customers;
    const row = list.find(c => c.email === em);
    assert.ok(row, 'contact not recorded');
    assert.equal(row.marketing, false, 'marketing consent was inferred from a booking — it must need an explicit tick');
  });

  await check('ticking the optional box records marketing consent', async () => {
    const em = `mkt-${Date.now()}@example.com`;
    await postJson('/api/service-requests', {
      name: 'Yes Marketing', phone: '07900555555', email: em, marketing: true,
      reg: 'YE11MKT', service: 'recovery', svcLabel: 'Breakdown / recovery',
    });
    const tok = await adminTok();
    const list = (await (await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } })).json()).customers;
    assert.equal(list.find(c => c.email === em).marketing, true, 'an explicit opt-in was not recorded');
  });

  await check('CRM notes work on a guest contact, not just account holders', async () => {
    const em = `gnote-${Date.now()}@example.com`;
    await postJson('/api/service-requests', {
      name: 'Note Me', phone: '07900555666', email: em, reg: 'NO11TES', service: 'diagnostics', svcLabel: 'Diagnostics',
    });
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    const n = await api(`/api/admin/customers/${encodeURIComponent(em)}/notes`, {
      method: 'POST', headers: h, body: JSON.stringify({ text: 'Paid cash, wants a callback about tyres.' }),
    });
    assert.equal(n.status, 200, 'could not add a note to a guest customer');
    const rec = await (await api(`/api/admin/customers/${encodeURIComponent(em)}`, { headers: h })).json();
    assert.equal(rec.customer.hasAccount, false);
    assert.equal(rec.notes.length, 1);
    assert.equal(rec.bookings.length, 1, 'guest detail view did not show their job');
  });

  await check('the metered third-party proxies are not open to the world', async () => {
    // These bill the client per call. Nothing on the public site uses them, so
    // open access was pure liability: anyone could run the quota to zero.
    for (const path of ['/api/ukvd?vrm=AB12CDE', '/api/v1/tyres']) {
      const r = await api(path);
      assert.equal(r.status, 403, `${path} is reachable without admin auth (${r.status})`);
    }
  });

  await check('a markup change reaches the customer price list', async () => {
    // Reported live: saving a markup appeared to do nothing, because the value
    // was cached in the Worker isolate AND in the HTTP response. The maths was
    // always right; the customer just could not see it.
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    const before = await (await api('/api/admin/pricing', { headers: h })).json();
    const orig = before.pricing.markupPct;

    const set = async (M) => {
      const r = await api('/api/admin/pricing', {
        method: 'POST', headers: h,
        body: JSON.stringify({ markupPct: { ...orig, M }, fittingFee: before.pricing.fittingFee, roundTo: 1 }),
      });
      assert.equal(r.status, 200, `saving markup ${M} failed`);
    };

    const priceOf = async () => {
      const d = await (await api('/api/tyres/lookup?size=195/65R15&cb=' + Date.now())).json();
      const t = d.tyres.find(x => x.tier === 'M');
      assert.ok(t, 'no mid-range tyre in the result');
      return t.price;
    };

    await set(50);
    const low = await priceOf();
    await set(200);
    const high = await priceOf();
    assert.ok(high > low, `markup 50% gave £${low} and 200% gave £${high} — the change did not reach the customer list`);

    await set(orig.M); // leave the business's real pricing alone
  });

  // ---- Inventory / ordering regressions --------------------------------------

  await check('a fresh inventory is empty, not seeded with invented tyres', async () => {
    // This used to write 5 fabricated tyres into a live business's stock the
    // moment anyone opened the Inventory tab — and then told real customers
    // "Allocated 2x Michelin Primacy 4 ... Remaining stock: 1" for tyres the
    // business had never owned.
    const tok = await adminTok();
    const inv = await (await api('/api/admin/inventory', { headers: { authorization: 'Bearer ' + tok } })).json();
    const names = (inv.stock || []).map(i => (i.name || '') + ' ' + (i.supplierEmail || '')).join(' | ');
    for (const ghost of ['Michelin Primacy 4 225/45 R17', 'Falken Ziex', 'Aplus', 'ctyreswholesale']) {
      assert.ok(!names.includes(ghost), `inventory was seeded with invented data: ${ghost}`);
    }
  });

  await check('auto-ordering defaults to off and names no supplier', async () => {
    const tok = await adminTok();
    const d = await (await api('/api/admin/inventory/settings', { headers: { authorization: 'Bearer ' + tok } })).json();
    const st = d.settings || d;
    assert.notEqual(st.masterAutoReorder, true, 'auto-ordering is ON by default — it can email a supplier unprompted');
    assert.ok(!/ctyres/i.test(st.supplierEmail || ''), 'the default supplier is a domain that does not exist');
    assert.ok(!/ctyres/i.test(st.supplierApiUrl || ''), 'the default supplier API is a host that does not exist');
  });

  await check('a non-tyre job never touches stock', async () => {
    // The guard used to sit AFTER the stock decrement, so it only protected one
    // branch. And the match key included free-text notes, on a public endpoint.
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    await api('/api/admin/stock', { method: 'POST', headers: h, body: JSON.stringify({ name: 'Michelin Primacy 4 Test', sku: 'TEST-MICH', qty: 10, price: 100 }) });

    const before = (await (await api('/api/admin/stock', { headers: h })).json()).stock.find(i => i.sku === 'TEST-MICH');
    await postJson('/api/service-requests', {
      name: 'Notes Attacker', phone: '07900000009', reg: 'NO11TES',
      service: 'recovery', svcLabel: 'Breakdown / recovery',
      notes: 'michelin primacy 4 test tyres please, lots of them',
    });
    const after = (await (await api('/api/admin/stock', { headers: h })).json()).stock.find(i => i.sku === 'TEST-MICH');
    assert.equal(after.qty, before.qty, 'a recovery job drained tyre stock via the free-text notes box');
  });

  await check('the reorder list is reachable and sending validates the address', async () => {
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    const add = await api('/api/admin/reorder-list', { method: 'POST', headers: h, body: JSON.stringify({ action: 'add', description: '2x 205/55R16', qty: 2, reason: 'test' }) });
    assert.equal(add.status, 200);
    assert.ok((await add.json()).pending >= 1, 'the line did not reach the list');

    for (const to of ['tbc', 'none', 'not an email']) {
      const r = await api('/api/admin/reorder-list/send', { method: 'POST', headers: h, body: JSON.stringify({ to }) });
      assert.equal(r.status, 400, `"${to}" was accepted as a supplier address`);
    }
  });

  // ---- Security regressions --------------------------------------------------
  // Each of these reproduces a real hole found in the pre-go-live audit. They
  // are here so the hole cannot quietly come back.

  await check('a booking cannot inject payment records into someone elses job', async () => {
    // The handler used to spread the whole request body into the stored job, so
    // an anonymous POST could write a fake payment into a victim's booking list
    // — which the refund ceiling then trusts, authorising a refund of money
    // that was never taken.
    const victim = `victim-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Attacker', phone: '07900000001', email: victim,
      service: 'diagnostics', svcLabel: 'Diagnostics',
      payments: [{ kind: 'payment', pence: 5000000 }], paidPence: 5000000,
      status: 'complete', ref: 'CMS-CHOSEN',
    });
    const d = await r.json();
    assert.ok(d.ok, 'booking rejected');
    assert.notEqual(d.ref, 'CMS-CHOSEN', 'the caller was allowed to choose the booking reference');
    assert.equal(d.booking.paidPence, undefined, 'an anonymous caller injected a paid balance');
    assert.equal(d.booking.payments, undefined, 'an anonymous caller injected payment records');
    assert.equal(d.booking.status, 'confirmed', 'an anonymous caller set the job status');
  });

  await check('a customer cannot mark their own booking paid', async () => {
    const em = `selfpay-${Date.now()}@example.com`;
    const pw = 'aVeryLongPassword1';
    const su = await postJson('/api/auth/signup', { name: 'Self Pay', email: em, phone: '07900000002', password: pw, consent: true });
    const { token } = await su.json();
    const h = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };

    const mk = await api('/api/bookings', { method: 'POST', headers: h, body: JSON.stringify({ service: 'diagnostics', svcLabel: 'Diagnostics', reg: 'SE11LF' }) });
    const ref = (await mk.json()).booking.ref;

    const patched = await api(`/api/bookings/${ref}`, {
      method: 'PATCH', headers: h,
      body: JSON.stringify({ date: '2026-09-01', paidPence: 20000, payments: [{ kind: 'payment', pence: 20000 }], status: 'complete' }),
    });
    const job = (await patched.json()).booking;
    assert.equal(job.date, '2026-09-01', 'a legitimate amendment was refused');
    assert.equal(job.paidPence, undefined, 'a customer marked their own job paid');
    assert.equal(job.payments, undefined, 'a customer wrote their own payment records');
    assert.notEqual(job.status, 'complete', 'a customer set their own job status');
  });

  await check('calendar invites cannot be sent by an anonymous caller', async () => {
    // Ungated, this sent a real Google invite FROM the business account to any
    // address the caller chose.
    const r = await postJson('/api/calendar/add-event', { date: '2026-09-01', name: 'Spam', customerEmail: 'target@example.com' });
    assert.equal(r.status, 403, `calendar event creation is open to the world (status ${r.status})`);
  });

  await check('driver endpoints reject a missing or wrong token', async () => {
    // These compared with raw === against ADMIN_TOKEN. With the token unset,
    // omitting it gave undefined === undefined, i.e. open access.
    for (const body of [{}, { token: '' }, { token: 'wrong' }, { token: null }]) {
      const loc = await postJson('/api/driver/location', { ref: 'CMS-TEST1', lat: 50, lng: -2, ...body });
      assert.ok(loc.status === 403 || loc.status === 429, `driver/location accepted ${JSON.stringify(body)} (${loc.status})`);
      const jobs = await postJson('/api/driver/jobs', body);
      assert.ok(jobs.status === 403 || jobs.status === 429, `driver/jobs leaked the job list for ${JSON.stringify(body)} (${jobs.status})`);
    }
  });

  await check('the backup carries no password material or 2FA seed', async () => {
    const tok = await adminTok();
    const dump = await (await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } })).json();
    const raw = JSON.stringify(dump);
    assert.ok(!/"hash"/.test(raw), 'the backup exports password hashes');
    assert.ok(!/"salt"/.test(raw), 'the backup exports password salts');
    assert.ok(!Object.keys(dump.data).includes('admin_totp'), 'the backup exports the owner 2FA secret');
    assert.ok(!Object.keys(dump.data).some(k => k.startsWith('asess:') || k.startsWith('sess:')), 'the backup exports live sessions');
  });

  await check('2FA enrolment state is not readable by the public', async () => {
    const r = await api('/api/admin-2fa/status');
    assert.equal(r.status, 403, 'anyone can see whether 2FA is on, which tells them when a bare token still works');
  });

  await check('GDPR erasure removes every record about the person', async () => {
    const em = `erase-${Date.now()}@example.com`;
    const pw = 'aVeryLongPassword1';
    const { token } = await (await postJson('/api/auth/signup', { name: 'Erase Me', email: em, phone: '07900000003', password: pw, consent: true })).json();
    const h = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
    await api('/api/messages', { method: 'POST', headers: h, body: JSON.stringify({ text: 'hello' }) });
    await postJson('/api/service-requests', { name: 'Erase Me', phone: '07900000003', email: em, service: 'diagnostics', svcLabel: 'Diagnostics' });

    const tok = await adminTok();
    const ah = { authorization: 'Bearer ' + tok };
    assert.ok((await (await api('/api/admin/customers', { headers: ah })).json()).customers.some(c => c.email === em), 'setup failed');

    await api('/api/gdpr/delete', { method: 'POST', headers: h });

    const after = (await (await api('/api/admin/customers', { headers: ah })).json()).customers;
    assert.ok(!after.some(c => c.email === em), 'the contact record survived erasure');
    const threads = (await (await api('/api/admin/threads', { headers: ah })).json()).threads;
    assert.ok(!threads.some(t => t.email === em), 'the message thread survived erasure');
  });

  // ---- Recording money -------------------------------------------------------

  await check('marking a job paid records it in pence and shows on the job', async () => {
    const em = `paid-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Pay Tester', phone: '07900555888', email: em,
      reg: 'PA11YED', service: 'tyres', svcLabel: 'Tyre fitting — Michelin 205/55R16',
    });
    const ref = (await r.json()).ref;
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };

    const pay = await api(`/api/admin/jobs/${ref}/payment`, {
      method: 'POST', headers: h,
      body: JSON.stringify({ customerEmail: em, amount: 188.1, method: 'card' }),
    });
    assert.equal(pay.status, 200);
    const d = await pay.json();
    // Pence, not pounds: 188.10 held as a float and summed drifts to
    // 188.09999999999999, which is wrong the moment it feeds a day's takings.
    assert.equal(d.entry.pence, 18810, 'amount was not stored as an integer number of pence');
    assert.equal(d.job.paidPence, 18810);
    assert.equal(d.entry.kind, 'payment');

    const jobs = (await (await api('/api/admin/jobs', { headers: h })).json()).jobs;
    assert.equal(jobs.find(j => j.ref === ref).paidPence, 18810, 'the payment did not reach the job list');
  });

  await check('a refund cannot exceed what was actually taken', async () => {
    const em = `refund-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Refund Tester', phone: '07900555999', email: em,
      reg: 'RE11FND', service: 'tyres', svcLabel: 'Tyre fitting',
    });
    const ref = (await r.json()).ref;
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    const pay = (body) => api(`/api/admin/jobs/${ref}/payment`, { method: 'POST', headers: h, body: JSON.stringify(body) });

    await pay({ customerEmail: em, amount: 100, method: 'cash' });

    const tooMuch = await pay({ customerEmail: em, kind: 'refund', amount: 150 });
    assert.equal(tooMuch.status, 400, 'refunded more than was ever taken');

    const ok = await pay({ customerEmail: em, kind: 'refund', amount: 40 });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).job.paidPence, 6000, 'net balance after a partial refund is wrong');
  });

  await check('a payment of zero or a silly amount is refused', async () => {
    const em = `zero-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Zero Tester', phone: '07900556000', email: em, reg: 'ZE11RO', service: 'diagnostics', svcLabel: 'Diagnostics',
    });
    const ref = (await r.json()).ref;
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    for (const amount of [0, -5, 'banana', 99999999]) {
      const res = await api(`/api/admin/jobs/${ref}/payment`, {
        method: 'POST', headers: h, body: JSON.stringify({ customerEmail: em, amount }),
      });
      assert.equal(res.status, 400, `amount ${amount} was accepted`);
    }
  });

  await check('recording money requires admin auth', async () => {
    const res = await postJson('/api/admin/jobs/CMS-FAKE1/payment', { customerEmail: 'x@example.com', amount: 10 });
    assert.equal(res.status, 403, 'anyone could record a payment and email a customer a receipt');
  });

  // ---- HTML email templates -------------------------------------------------
  // The whole point of these: a customer must never receive "Hi {{{firstname}}}".

  await check('every email template renders with no variable left unfilled', async () => {
    const { renderEmail, EMAIL_BLOCKS } = await import('../worker.js');
    // Supply every token any block declares, so a missing *supplier* is the
    // only thing that can fail here.
    const vars = {
      subject: 'Test', preheader: 'Test preheader', firstname: 'Josh',
      booking_ref: 'CMS-TEST1', service: 'Tyre fitting', vehicle_reg: 'KM16GLY',
      booking_date: '2026-08-21', booking_time: 'Afternoon (12-5)', booking_location: 'DT6 4LB',
      manage_booking_url: 'https://cousinsmechanicalservices.co.uk/#track=CMS-TEST1',
      amount: '245.00',
    };
    for (const name of Object.keys(EMAIL_BLOCKS)) {
      const html = renderEmail(name, vars, { footer_note: 'note' });
      const leftover = html.match(/\{\{\{\s*[a-z_]+\s*\}\}\}/gi);
      assert.equal(leftover, null, `${name} left ${leftover && leftover.join(', ')} unfilled`);
      assert.ok(html.includes('Cousins Mechanical Services Ltd'), `${name} lost the footer`);
      assert.ok(html.includes('16045339'), `${name} is missing the company number`);
    }
  });

  await check('email templates escape customer-supplied values', async () => {
    const { renderEmail } = await import('../worker.js');
    const html = renderEmail('booking_confirmed', {
      subject: 'x', preheader: 'x', firstname: 'Bob & <script>alert(1)</script>',
      booking_ref: 'CMS-X', service: 'Tyres', vehicle_reg: '"><b>', booking_date: 'd',
      booking_time: 't', booking_location: 'l', manage_booking_url: 'https://example.com',
    }, { footer_note: 'n' });
    assert.ok(!html.includes('<script>'), 'a customer name injected raw HTML into the email');
    assert.ok(html.includes('&lt;script&gt;'), 'the name was not escaped');
  });

  await check('a missing template variable is stripped, never shown to a customer', async () => {
    const { renderEmail } = await import('../worker.js');
    // firstname deliberately omitted.
    const html = renderEmail('refund_processed', { subject: 'x', preheader: 'x', amount: '10', booking_ref: 'CMS-Y' }, {});
    assert.ok(!/\{\{\{/.test(html), 'an unfilled token would have reached the customer');
  });

  await check('the booking email supplies exactly the variables its template declares', async () => {
    // This is the wiring check. If someone adds {{{engineer_name}}} to the
    // block and forgets to pass it, or renames a field on the order, this fails
    // instead of a customer getting a blank line.
    const { EMAIL_BLOCKS } = await import('../worker.js');
    const declared = new Set([...EMAIL_BLOCKS.booking_confirmed.matchAll(/\{\{\{\s*([a-z_]+)\s*\}\}\}/gi)].map(m => m[1]));
    const supplied = new Set(['firstname', 'booking_ref', 'service', 'vehicle_reg',
      'booking_date', 'booking_time', 'booking_location', 'manage_booking_url']);
    for (const d of declared) assert.ok(supplied.has(d), `template needs {{{${d}}}} but the booking handler never passes it`);
    for (const sup of supplied) assert.ok(declared.has(sup), `booking handler passes ${sup} but no template uses it`);
  });

  await check('unsubscribe rejects a tampered link and accepts a signed one', async () => {
    const em = `unsub-${Date.now()}@example.com`;
    await postJson('/api/service-requests', {
      name: 'Unsub Tester', phone: '07900555777', email: em, marketing: true,
      reg: 'UN11SUB', service: 'recovery', svcLabel: 'Breakdown / recovery',
    });

    const forged = await api(`/api/unsubscribe?e=${encodeURIComponent(em)}&s=deadbeef`);
    assert.ok((await forged.text()).includes("didn't work"), 'a forged signature unsubscribed someone');

    const tok = await adminTok();
    const before = (await (await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } })).json()).customers;
    assert.equal(before.find(c => c.email === em).marketing, true, 'setup failed — not opted in');

    // Re-derive the signature the same way the Worker does.
    const sig = crypto.createHmac('sha256', SESSION_PEPPER).update('unsub:' + em).digest('hex').slice(0, 32);
    const good = await api(`/api/unsubscribe?e=${encodeURIComponent(em)}&s=${sig}`);
    assert.ok((await good.text()).includes('unsubscribed'), 'a correctly signed unsubscribe link did not work');

    const after = (await (await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } })).json()).customers;
    assert.equal(after.find(c => c.email === em).marketing, false, 'consent was not withdrawn');
  });

  await check('the Resend webhook refuses unsigned and forged bounce reports', async () => {
    // Public endpoint. If it trusted its input, anyone could POST a fake bounce
    // and stop a real customer receiving their confirmation.
    const r = await postJson('/api/resend-webhook', { type: 'email.bounced', data: { to: ['victim@example.com'] } });
    assert.ok(r.status === 503 || r.status === 400 || r.status === 401,
      `unsigned webhook was accepted (status ${r.status})`);
  });

  await check('a booking with no contact details is rejected, not silently accepted', async () => {
    const r = await postJson('/api/service-requests', { reg: 'AB12CDE', service: 'recovery' });
    assert.equal(r.status, 400, 'a booking with no name or phone should be refused');
  });

  await check('a booking still saves when optional side-effects are unconfigured', async () => {
    // Calendar/SMS are not configured in tests. Persistence must not depend on them.
    const r = await postJson('/api/service-requests', {
      name: 'No Extras', phone: '07900555222', reg: 'XY11ZZZ', service: 'diagnostics', svcLabel: 'Diagnostics',
    });
    const d = await r.json();
    assert.ok(d.ok, 'booking failed when optional integrations were absent');
    assert.equal(d.calendarEventCreated, false);
    assert.deepEqual(d.warnings, [], `unexpected warnings: ${JSON.stringify(d.warnings)}`);
    const tok = await adminTok();
    const jobs = (await (await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + tok } })).json()).jobs;
    assert.ok(jobs.some(j => j.ref === d.ref), 'booking without a calendar did not reach the dashboard');
  });

  // --- Staff logins ---
  await check('staff account can be created and used to sign in', async () => {
    const tok = await adminTok();
    const email = `staff-${Date.now()}@cousinsmechanicalservices.co.uk`;
    const password = 'a-properly-long-password';
    const c = await api('/api/admin/staff', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok }, body: JSON.stringify({ email, password, name: 'Smoke Staff' }) });
    assert.equal(c.status, 200, 'could not create staff account');
    const good = await postJson('/api/admin-login', { email, password, code: totpNow(totpSecret) });
    assert.equal(good.status, 200, 'correct staff credentials were rejected');
    assert.ok((await good.json()).token, 'no session issued for valid staff login');
  });

  await check('staff login rejects a wrong password and an unknown email identically', async () => {
    const email = `staff2-${Date.now()}@cousinsmechanicalservices.co.uk`;
    const tok = await adminTok();
    await api('/api/admin/staff', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok }, body: JSON.stringify({ email, password: 'a-properly-long-password' }) });
    const wrong = await postJson('/api/admin-login', { email, password: 'definitely-not-it', code: totpNow(totpSecret) });
    const unknown = await postJson('/api/admin-login', { email: 'nobody-' + Date.now() + '@example.com', password: 'definitely-not-it', code: totpNow(totpSecret) });
    assert.equal(wrong.status, 401);
    assert.equal(unknown.status, 401);
    assert.equal((await wrong.json()).error, (await unknown.json()).error, 'error text reveals which emails are staff accounts');
  });

  await check('staff passwords must be at least 10 characters', async () => {
    const tok = await adminTok();
    const r = await api('/api/admin/staff', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok }, body: JSON.stringify({ email: `weak-${Date.now()}@example.com`, password: 'short' }) });
    assert.equal(r.status, 400);
  });

  await check('the staff list never exposes password material', async () => {
    const tok = await adminTok();
    const d = await (await api('/api/admin/staff', { headers: { authorization: 'Bearer ' + tok } })).json();
    assert.ok(d.staff.length > 0);
    for (const a of d.staff) {
      assert.equal(a.hash, undefined, 'staff list leaked a password hash');
      assert.equal(a.salt, undefined, 'staff list leaked a password salt');
    }
  });

  await check('staff endpoints require admin auth', async () => {
    assert.equal((await api('/api/admin/staff')).status, 403);
  });

  await check('the shared admin token stops working once staff accounts exist', async () => {
    // Bootstrap-only: after the first real account the shared secret must not
    // grant a session, otherwise the dashboard is still behind one password.
    const r = await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) });
    assert.ok(r.status === 403 || r.status === 401, `shared token still logs in (status ${r.status})`);
  });

  await check('admin.<domain> serves the dashboard at its root and is noindex', async () => {
    // Exercised against the Worker directly: the hostname branch cannot be
    // reached over HTTP here because fetch() refuses to set a Host header.
    const worker = (await import('../worker.js')).default;
    const stubEnv = {
      ASSETS: { fetch: async (req) => new Response('SERVED:' + new URL(req.url).pathname, { status: 200, headers: { 'content-type': 'text/html' } }) },
    };
    const ctx = { waitUntil() {} };

    const adminRoot = await worker.fetch(new Request('https://admin.cousinsmechanicalservices.co.uk/'), stubEnv, ctx);
    assert.equal(await adminRoot.text(), 'SERVED:/admin.html', 'admin host root did not rewrite to admin.html');
    assert.equal(adminRoot.headers.get('x-robots-tag'), 'noindex, nofollow', 'admin host is not marked noindex');

    const adminRobots = await worker.fetch(new Request('https://admin.cousinsmechanicalservices.co.uk/robots.txt'), stubEnv, ctx);
    assert.ok((await adminRobots.text()).includes('Disallow: /'), 'admin host robots.txt does not block crawlers');

    // The public hostname must be untouched by that rewrite.
    const publicRoot = await worker.fetch(new Request('https://cousinsmechanicalservices.co.uk/'), stubEnv, ctx);
    assert.equal(await publicRoot.text(), 'SERVED:/', 'public root was rewritten — it must still serve the marketing page');
    assert.equal(publicRoot.headers.get('x-robots-tag'), null, 'public site must not be noindex');
  });

  await check('the public site root still serves the marketing page, not admin', async () => {
    const html = await (await api('/')).text();
    assert.ok(/WE COME TO YOU|FIND YOUR TYRE SIZE/.test(html), 'apex root no longer serves the public site');
  });

  await check('Google sign-in endpoints exist and fail closed when unconfigured', async () => {
    // FIREBASE_WEB_CONFIG is not set in the test environment, so the config
    // endpoint must 404 (the button hides itself) and the login endpoint must
    // refuse cleanly rather than granting a session.
    assert.equal((await api('/api/firebase-config')).status, 404);
    const r = await postJson('/api/admin-login-firebase', { idToken: 'anything' });
    assert.equal(r.status, 503);
    const mode = await (await api('/api/admin-auth/mode')).json();
    assert.equal(mode.google, false, 'auth mode should report Google sign-in as off');
  });

  await check('admin backup exports durable data and excludes sessions', async () => {
    const tok = await adminTok();
    const noAuth = await api('/api/admin/backup');
    assert.equal(noAuth.status, 403, 'backup must require admin auth');
    const r = await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200);
    assert.ok(/attachment/.test(r.headers.get('content-disposition') || ''), 'backup is not a download');
    const d = await r.json();
    const keys = Object.keys(d.data);
    assert.ok(keys.some(k => k.startsWith('user:')), 'backup missing customer accounts');
    assert.ok(keys.some(k => k.startsWith('bookings:')), 'backup missing bookings');
    assert.ok(keys.some(k => k.startsWith('staff:')), 'backup missing staff accounts');
    assert.ok(!keys.some(k => /^(sess|asess|dsess|rl|reset):/.test(k)), 'backup leaked transient session/rate-limit keys');
  });

  await check('service pricing is public but exposes no cost data', async () => {
    const d = await (await api('/api/pricing/service')).json();
    assert.ok('calloutFee' in d && 'hourlyRate' in d && 'payment' in d);
    assert.ok(/on site/i.test(d.payment), 'payment terms not stated');
    assert.equal(d.costPrice, undefined);
    assert.equal(d.markupPct, undefined);
  });

  await check('CRM: new customer starts with no discount and no notes', async () => {
    const em = `crm-${Date.now()}@example.com`;
    await postJson('/api/auth/signup', { email: em, password: 'crm-password-123', name: 'CRM Person', phone: '07900111222', consent: true });
    const tok = await adminTok();
    const r = await api('/api/admin/customers', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200);
    const row = (await r.json()).customers.find(c => c.email === em);
    assert.ok(row, 'new customer not listed');
    assert.equal(row.discount, 0);
    assert.equal(row.notesCount, 0);
  });

  await check('CRM: setting a discount is recorded and clamped to 0-100', async () => {
    const em = `crm2-${Date.now()}@example.com`;
    await postJson('/api/auth/signup', { email: em, password: 'crm-password-123', name: 'CRM Two', phone: '07900111333', consent: true });
    const tok = await adminTok();
    const auth = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    let r = await api('/api/admin/customers/' + encodeURIComponent(em), { method: 'PATCH', headers: auth, body: JSON.stringify({ discount: 10, discountReason: 'Loyal customer' }) });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).discount, 10);
    r = await api('/api/admin/customers/' + encodeURIComponent(em), { method: 'PATCH', headers: auth, body: JSON.stringify({ discount: 150 }) });
    assert.equal((await r.json()).discount, 100, 'discount not clamped to 100');
  });

  await check('CRM: notes append and read back on the detail record', async () => {
    const em = `crm3-${Date.now()}@example.com`;
    await postJson('/api/auth/signup', { email: em, password: 'crm-password-123', name: 'CRM Three', phone: '07900111444', consent: true });
    const tok = await adminTok();
    const auth = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    const empty = await api('/api/admin/customers/' + encodeURIComponent(em) + '/notes', { method: 'POST', headers: auth, body: JSON.stringify({ text: '   ' }) });
    assert.equal(empty.status, 400, 'empty note should be rejected');
    const add = await api('/api/admin/customers/' + encodeURIComponent(em) + '/notes', { method: 'POST', headers: auth, body: JSON.stringify({ text: 'Prefers early morning fittings' }) });
    assert.equal(add.status, 200);
    assert.equal((await add.json()).notes.length, 1);
    const det = await api('/api/admin/customers/' + encodeURIComponent(em), { headers: { authorization: 'Bearer ' + tok } });
    const d = await det.json();
    assert.equal(d.notes.length, 1);
    assert.equal(d.notes[0].text, 'Prefers early morning fittings');
    assert.ok(Array.isArray(d.bookings), 'detail should include a bookings array');
    assert.equal(d.customer.email, em);
  });

  await check('CRM: customer records require admin auth', async () => {
    const r = await api('/api/admin/customers/anyone@example.com');
    assert.equal(r.status, 403);
  });

  await check('CRM: discount and notes never leak to the customer profile', async () => {
    const em = `crm4-${Date.now()}@example.com`;
    const signup = await postJson('/api/auth/signup', { email: em, password: 'crm-password-123', name: 'CRM Four', phone: '07900111555', consent: true });
    const custTok = (await signup.json()).token;
    const tok = await adminTok();
    const auth = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    await api('/api/admin/customers/' + encodeURIComponent(em), { method: 'PATCH', headers: auth, body: JSON.stringify({ discount: 25 }) });
    const me = await api('/api/auth/me', { headers: { authorization: 'Bearer ' + custTok } });
    const prof = (await me.json()).user;
    assert.equal(prof.discount, undefined, 'discount leaked to customer profile');
    assert.equal(prof.notes, undefined, 'notes leaked to customer profile');
  });

  await check('repeated bad admin logins get rate limited', async () => {
    let sawLimit = false;
    for (let i = 0; i < 12; i++) {
      const r = await postJson('/api/admin-login', { token: 'wrong-token-' + i });
      if (r.status === 429) { sawLimit = true; break; }
    }
    assert.ok(sawLimit, 'brute-force attempts were never rate limited');
  });

  // --- static site ----------------------------------------------------------
  await check('home page renders', async () => {
    const r = await api('/');
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.match(html, /Cousins Mechanical Services/);
  });

  await check('sitemap and robots are served', async () => {
    assert.equal((await api('/sitemap.xml')).status, 200);
    assert.equal((await api('/robots.txt')).status, 200);
    assert.equal((await api('/site.webmanifest')).status, 200);
  });

  await check('every public page is served and carries the shared menu + footer', async () => {
    for (const page of ['/terms.html', '/privacy.html', '/cookies.html', '/accessibility.html']) {
      const r = await api(page);
      assert.equal(r.status, 200, `${page} not served`);
      const html = await r.text();
      assert.ok(html.includes('index.html#services'), `${page} is missing the shared menu bar`);
      assert.ok(html.includes('Staff login'), `${page} is missing the shared footer`);
      for (const legal of ['terms.html', 'privacy.html', 'cookies.html', 'accessibility.html']) {
        assert.ok(html.includes(legal), `${page} footer does not link ${legal}`);
      }
    }
  });

  await check('the home page footer links every legal page', async () => {
    const html = await (await api('/')).text();
    for (const legal of ['terms.html', 'privacy.html', 'cookies.html', 'accessibility.html']) {
      assert.ok(html.includes(legal), `home page does not link ${legal}`);
    }
  });

  await check('company number and registered office appear on every public page', async () => {
    // A UK limited company must show these on its website (Companies Act 2006 /
    // e-commerce regulations). They live in the shared footer.
    for (const page of ['/', '/terms.html', '/privacy.html', '/cookies.html', '/accessibility.html', '/404.html']) {
      const html = await (await api(page)).text();
      assert.ok(html.includes('16045339'), `${page} does not show the company number`);
      assert.ok(/7 Watton Park/.test(html), `${page} does not show the registered office`);
    }
  });

  await check('legal pages carry no unfilled placeholders or draft warnings', async () => {
    for (const page of ['/terms.html', '/privacy.html', '/cookies.html', '/accessibility.html']) {
      const html = await (await api(page)).text();
      const left = html.match(/\[[A-Z][^\]]*\]/g) || [];
      assert.equal(left.length, 0, `${page} still has placeholders: ${left.join(', ')}`);
      assert.ok(!/DRAFT/.test(html), `${page} still carries a DRAFT warning`);
    }
  });

  await check('robots.txt blocks un-hydrated template tokens and API paths', async () => {
    const txt = await (await api('/robots.txt')).text();
    for (const rule of ['Disallow: /*{{', 'Disallow: /bookings', 'Disallow: /messages', 'Disallow: /track']) {
      assert.ok(txt.includes(rule), `robots.txt missing "${rule}"`);
    }
  });

  await check('a branded 404 page exists and offers a way back', async () => {
    const r = await api('/404.html');
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(/not found/i.test(html), '404 page has no "not found" wording');
    assert.ok(html.includes('07925'), '404 page does not offer the phone number');
    assert.ok(html.includes('index.html'), '404 page has no route back to the site');
  });

  await check('an unknown URL does not return a 200', async () => {
    const r = await api('/definitely-not-a-real-page-' + Date.now());
    assert.notEqual(r.status, 200, 'unknown URL returned 200 — check not_found_handling');
  });

  await check('PWA manifest icons exist and match their declared sizes', async () => {
    const r = await api('/site.webmanifest');
    assert.equal(r.status, 200);
    const m = JSON.parse(await r.text());
    assert.ok(m.icons.length >= 2, 'manifest needs at least 192 and 512 icons');
    assert.ok(m.icons.some(i => i.purpose === 'maskable'), 'no maskable icon for Android');
    for (const icon of m.icons) {
      const res = await api(icon.src);
      assert.equal(res.status, 200, `${icon.src} is declared but missing`);
      const buf = Buffer.from(await res.arrayBuffer());
      // PNG header: width/height are big-endian uint32 at bytes 16 and 20.
      const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
      const [dw, dh] = icon.sizes.split('x').map(Number);
      assert.equal(w, dw, `${icon.src} is ${w}px wide but declares ${dw}`);
      assert.equal(h, dh, `${icon.src} is ${h}px tall but declares ${dh}`);
    }
  });

  await check('no stray cousinsmechanical.co.uk addresses (wrong domain)', async () => {
    const fs = await import('node:fs');
    for (const f of ['worker.js', 'Cousins Mechanical.dc.html', 'Cousins Admin.dc.html']) {
      const src = fs.readFileSync(new URL('../' + f, import.meta.url), 'utf8');
      const bad = src.match(/@cousinsmechanical\.co\.uk/g) || [];
      assert.equal(bad.length, 0, `${f} still uses the wrong email domain`);
    }
  });

  await check('every catalogue image exists and is a real image, not an error page', async () => {
    // The scraper once saved HTML error pages under .jpg names; 14 listings
    // shipped a broken thumbnail. Existence alone is not enough — check magic bytes.
    const fs = await import('node:fs');
    const cat = JSON.parse(fs.readFileSync(new URL('../public/data/tyre-catalogue.json', import.meta.url), 'utf8'));
    const refs = new Set();
    (function walk(o) {
      if (Array.isArray(o)) return o.forEach(walk);
      if (o && typeof o === 'object') {
        if (typeof o.img === 'string') refs.add(o.img); else Object.values(o).forEach(walk);
      }
    })(cat);
    assert.ok(refs.size > 100, `only ${refs.size} catalogue images found — catalogue may be empty`);
    const broken = [];
    for (const img of refs) {
      const file = new URL('../public/images/' + img, import.meta.url);
      if (!fs.existsSync(file)) { broken.push(img + ' (missing)'); continue; }
      const head = Buffer.alloc(4);
      const fd = fs.openSync(file, 'r'); fs.readSync(fd, head, 0, 4, 0); fs.closeSync(fd);
      const isJpg = head[0] === 0xff && head[1] === 0xd8;
      const isPng = head.toString('ascii', 1, 4) === 'PNG';
      if (!isJpg && !isPng) broken.push(img + ' (not an image)');
    }
    assert.equal(broken.length, 0, `broken catalogue images: ${broken.join(', ')}`);
  });

  await check('a tyre image referenced by the API actually exists', async () => {
    const d = await (await api('/api/tyres/lookup?size=195/65R15')).json();
    const r = await api(d.tyres[0].image);
    assert.equal(r.status, 200, `missing image ${d.tyres[0].image}`);
  });

  await check('source files outside public/ are not served', async () => {
    // The old server.js did express.static(__dirname), exposing .env and ctyres.db.
    for (const leak of ['/.env', '/worker.js', '/ctyres.db', '/server.js', '/package.json']) {
      const r = await api(leak);
      assert.notEqual(r.status, 200, `${leak} is publicly readable`);
    }
  });

  await check('security headers are present on the site', async () => {
    const r = await api('/');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });

  await check('API does not send a wildcard CORS header', async () => {
    const r = await api('/api/health', { headers: { origin: 'https://evil.example.com' } });
    assert.notEqual(r.headers.get('access-control-allow-origin'), '*');
    assert.notEqual(r.headers.get('access-control-allow-origin'), 'https://evil.example.com');
  });

} finally {
  server.kill();
}

console.log('\n' + results.join('\n'));
console.log(`\n  ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  console.log('--- server output ---\n' + serverOutput);
  process.exit(1);
}
