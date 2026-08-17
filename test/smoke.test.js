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
const server = spawn(process.execPath, ['server.js'], {
  cwd: new URL('..', import.meta.url).pathname,
  env: {
    ...process.env,
    PORT: String(PORT),
    NODE_ENV: 'test',
    SESSION_PEPPER: crypto.randomBytes(24).toString('hex'),
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

    const post = await postJson('/api/driver/location', { ref: 'CMS-TEST1', lat: 50.7333, lng: -2.7581, eta: '12 mins', token: drvTok });
    assert.equal(post.status, 200, `location post failed: ${await post.text()}`);

    const r = await api('/api/admin/locations', { headers: { authorization: 'Bearer ' + adminTok } });
    assert.equal(r.status, 200);
    const { locations } = await r.json();
    const hit = locations.find(l => l.jobRef === 'CMS-TEST1');
    assert.ok(hit, 'driver location did not reach the admin map');
    assert.equal(hit.lat, 50.7333);
    assert.ok(hit.t > 0, 'location has no timestamp');
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
  const adminTok = async () =>
    (await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json()).token;

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
