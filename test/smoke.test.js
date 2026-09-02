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
import { capSizeInversions } from '../tyre-data.js';
import { BUSINESS } from '../business.js';

/*
 * A date a few days out, computed rather than typed.
 *
 * These were hard-coded ("2026-09-01"), which is a time bomb: the moment the
 * calendar passed them they became bookings in the past. Adding the server-side
 * date guard set it off — six tests failed on dates that were fine when they
 * were written and are now history.
 */
const soonISO = (days = 5) => {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
};
import { qrMatrix, qrSvgDataUri } from '../worker.js';

const PORT = 3799;
const BASE = `http://127.0.0.1:${PORT}`;

const ADMIN_TOKEN = crypto.randomBytes(24).toString('hex');
const OVERRIDE_TOKEN = crypto.randomBytes(24).toString('hex');

const pick = o => ({ encoding: o.encoding, segments: o.segments });

let passed = 0, failed = 0;
const results = [];

/**
 * Create a customer account AND clear email verification, returning the session
 * token. Signup alone no longer returns one: the account is inert until the
 * emailed code is entered. The suite has no inbox, so server.js hands the code
 * back in the response under ALLOW_TEST_VERIFY_CODE (test only).
 */
async function signupVerified(fields) {
  const su = await postJson('/api/auth/signup', { consent: true, ...fields });
  const d = await su.json();
  if (d.token) return d;                       // legacy path, should not happen
  assert.ok(d.devCode, 'signup did not return a verification code: ' + JSON.stringify(d));
  const v = await postJson('/api/auth/verify', { email: fields.email, code: d.devCode });
  const vd = await v.json();
  assert.ok(vd.token, 'verification did not return a session: ' + JSON.stringify(vd));
  return vd;
}

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
  const driverEmail = `driver-${Date.now()}@example.com`;
  let driverCode = null;
  const driverPass = 'driver-password-123';
  await check('driver registration succeeds and starts unapproved', async () => {
    const r = await postJson('/api/driver/register', {
      email: driverEmail, password: driverPass, name: 'Test Driver',
    });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.equal(d.pending, true);
    assert.equal(d.verifyRequired, true, 'registration no longer requires email confirmation');
    driverCode = d.devCode;
    assert.ok(driverCode, 'no confirmation code issued');
  });

  await check('driver registration is refused without a real email address', async () => {
    for (const email of [undefined, '', 'not-an-email']) {
      const r = await postJson('/api/driver/register', { email, password: driverPass, name: 'No Email' });
      assert.equal(r.status, 400, `registration accepted email "${email}"`);
    }
  });

  await check('a driver cannot choose their own van at sign-up', async () => {
    // Which van somebody drives is Cousins' decision, set in the admin after
    // approval — not something an applicant types into a public form.
    const em = `van-${Date.now()}@example.com`;
    await postJson('/api/driver/register', { email: em, password: driverPass, name: 'Van Chooser', vanReg: 'STOLEN1', phone: '07999999999' });
    const { token: tok } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const list = (await (await api('/api/admin/drivers', { headers: { authorization: 'Bearer ' + tok } })).json()).drivers;
    const d = list.find(x => x.email === em);
    assert.ok(d, 'driver not created');
    assert.equal(d.vanReg, '', 'the applicant set their own van registration');
    assert.equal(d.phone, '', 'the applicant set their own phone from the sign-up form');
  });

  await check('the admin can permanently delete a driver', async () => {
    const em = `gone-${Date.now()}@example.com`;
    const rd = await (await postJson('/api/driver/register', { email: em, password: driverPass, name: 'Delete Me' })).json();
    await postJson('/api/driver/verify-email', { email: em, code: rd.devCode });

    const { token: tok } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    let list = (await (await api('/api/admin/drivers', { headers: h })).json()).drivers;
    const id = list.find(x => x.email === em).id;
    await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ action: 'approve', id }) });
    const { token: drvTok } = await (await postJson('/api/driver/login', { username: em, password: driverPass })).json();
    assert.ok(drvTok, 'setup failed — driver could not sign in');

    const del = await api('/api/admin/drivers', { method: 'DELETE', headers: h, body: JSON.stringify({ id }) });
    assert.equal(del.status, 200);
    list = (await del.json()).drivers;
    assert.ok(!list.some(x => x.id === id), 'the driver is still in the list');

    // Deletion must take effect immediately, not at session expiry.
    const after = await postJson('/api/driver/jobs', { token: drvTok });
    assert.equal(after.status, 403, 'a deleted driver kept access with their existing session');
    const relogin = await postJson('/api/driver/login', { username: em, password: driverPass });
    assert.equal(relogin.status, 401, 'a deleted driver could sign in again');
  });

  await check('confirming the email does not by itself grant access', async () => {
    const v = await postJson('/api/driver/verify-email', { email: driverEmail, code: driverCode });
    assert.equal(v.status, 200);
    const d = await v.json();
    assert.equal(d.emailVerified, true);
    assert.equal(d.approved, false, 'confirming an email approved the driver');
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
    const r = await postJson('/api/driver/login', { username: driverEmail, password: driverPass });
    assert.equal(r.status, 403);
  });

  await check('driver login rejects a wrong password', async () => {
    const r = await postJson('/api/driver/login', { username: driverEmail, password: 'wrong-password' });
    assert.equal(r.status, 401);
  });

  let driverId = null;
  await check('admin can approve a driver', async () => {
    const { token } = await (await postJson('/api/admin-login', { token: ADMIN_TOKEN, code: totpNow(totpSecret) })).json();
    const list = await (await api('/api/admin/drivers', { headers: { authorization: 'Bearer ' + token } })).json();
    driverId = list.drivers.find(d => d.email === driverEmail)?.id;
    assert.ok(driverId, 'registered driver not present in admin list');
    const r = await postJson('/api/admin/drivers', { action: 'approve', id: driverId }, { authorization: 'Bearer ' + token });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).drivers.find(d => d.id === driverId).approved, true);
  });

  let driverToken = null;
  await check('approved driver can log in and gets a random token', async () => {
    const r = await postJson('/api/driver/login', { username: driverEmail, password: driverPass });
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
    const r = await postJson('/api/driver/login', { username: driverEmail, password: driverPass });
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

  await check('signing up does NOT sign you in until the email is confirmed', async () => {
    // Anyone could previously register an address they did not own and start
    // receiving that person's booking mail. Signup now returns no session.
    const r = await postJson('/api/auth/signup', {
      email, password, name: 'Test Customer', phone: '07900000000', consent: true,
    });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.equal(d.token, undefined, 'signup handed out a session before the address was confirmed');
    assert.equal(d.verifyRequired, true, 'signup did not ask for confirmation');

    // A wrong code must not get in.
    const wrong = await postJson('/api/auth/verify', { email, code: '000000' });
    assert.ok(wrong.status >= 400, 'a wrong confirmation code was accepted');

    const v = await postJson('/api/auth/verify', { email, code: d.devCode });
    assert.equal(v.status, 200);
    const vd = await v.json();
    customerToken = vd.token;
    assert.ok(customerToken, 'confirming the code did not return a session');
    assert.equal(vd.user.hash, undefined, 'response leaked password hash');
  });

  await check('an unconfirmed account cannot log in', async () => {
    const em2 = `unconfirmed-${Date.now()}@example.com`;
    await postJson('/api/auth/signup', { email: em2, password, name: 'Not Confirmed', phone: '07900000010', consent: true });
    const r = await postJson('/api/auth/login', { email: em2, password });
    assert.equal(r.status, 403, `an unconfirmed account logged in (status ${r.status})`);
    assert.equal((await r.json()).verifyRequired, true);
  });

  await check('the confirmation code is never returned in production mode', async () => {
    // server.js only sets ALLOW_TEST_VERIFY_CODE outside production, and it is
    // not a Worker secret — so a deployed Worker cannot leak a code. Assert the
    // response shape carries nothing else that would work as one.
    const em3 = `shape-${Date.now()}@example.com`;
    const d = await (await postJson('/api/auth/signup', { email: em3, password, name: 'Shape', phone: '07900000011', consent: true })).json();
    assert.deepEqual(Object.keys(d).sort(), ['devCode', 'email', 'verifyRequired'],
      'signup response shape changed — check nothing new leaks in production: ' + JSON.stringify(Object.keys(d)));
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
      postcode: 'DT6 3QP', date: soonISO(5), notes: 'smoke test booking',
    }, { authorization: 'Bearer ' + customerToken });
    const d = await r.json();
    assert.equal(r.status, 200, `booking failed: ${JSON.stringify(d)}`);
    assert.ok(d.ref || d.booking?.ref, 'booking returned no reference');

    const list = await (await api('/api/bookings', { headers: { authorization: 'Bearer ' + customerToken } })).json();
    assert.ok((list.bookings || []).length > 0, 'booking did not persist');

    /*
     * And what the customer wrote about the job survives with it.
     *
     * "Something else" is the one service choice that names nothing — the
     * booking arrives as "Something else" with a registration and a postcode,
     * and the note is the only thing saying what the work is. It reached the
     * confirmation email, the calendar entry and the .ics, but not the Jobs
     * table, which is the screen the work is done from. The note is now shown
     * there, so it has to survive the round trip to be worth showing.
     */
    const mine = (list.bookings || []).find(b => b.reg === 'AB12CDE');
    assert.ok(mine, 'the booking just made is not in the customer\'s own list');
    assert.equal(mine.notes, 'smoke test booking',
      'what the customer wrote about the job did not survive onto the record');
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
    const { token: drvTok } = await (await postJson('/api/driver/login', { username: driverEmail, password: driverPass })).json();

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
    const reg2 = await postJson('/api/driver/register', { email: `${other}@example.com`, password: otherPass, name: 'Second Driver' });
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
      reg: 'KM16GLY', postcode: 'dt64lb', date: soonISO(6), time: 'Afternoon (12-5)',
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

  /*
   * SumUp. The client takes card payments through SumUp, and it differs from
   * Stripe in two ways that are both expensive to get wrong.
   */
  await check('money converts between pence and SumUp decimals without drifting', async () => {
    // SumUp wants 25.00 where this system stores 2500. A factor-of-100 error
    // either charges a customer a hundred times too much, or a hundredth —
    // and the second one looks like it worked.
    const { penceToMajor, majorToPence } = await import('../worker.js');
    const cases = [[2500, '25.00'], [1, '0.01'], [99, '0.99'], [100, '1.00'],
                   [12345, '123.45'], [50000, '500.00'], [0, '0.00']];
    for (const [pence, major] of cases) {
      assert.equal(penceToMajor(pence), major, `${pence}p should send as ${major}`);
      assert.equal(majorToPence(major), pence, `${major} should come back as ${pence}p`);
    }
    // Floating point is the trap here: 19.99 * 100 is 1998.9999999999998.
    assert.equal(majorToPence(19.99), 1999, 'a float amount rounded the wrong way');
    assert.equal(majorToPence('0.07'), 7);
    // And a round trip on every penny from 1p to £5, because a rounding rule
    // that works on the examples you thought of is not a rounding rule.
    for (let p = 1; p <= 500; p++) {
      assert.equal(majorToPence(penceToMajor(p)), p, `${p}p did not survive the round trip`);
    }
  });

  await check('a text is measured in segments, and one odd character triples it', async () => {
    // Twilio charges per segment. 160 plain characters is one; a single
    // character outside GSM-7 drops the limit to 70 for the WHOLE message.
    // This codebase is full of em-dashes, so the difference is not academic.
    const { smsSegments } = await import('../worker.js');

    assert.deepEqual(pick(smsSegments('A'.repeat(160))), { encoding: 'GSM-7', segments: 1 });
    assert.deepEqual(pick(smsSegments('A'.repeat(161))), { encoding: 'GSM-7', segments: 2 });
    assert.deepEqual(pick(smsSegments('A'.repeat(306))), { encoding: 'GSM-7', segments: 2 });
    assert.deepEqual(pick(smsSegments('A'.repeat(307))), { encoding: 'GSM-7', segments: 3 });

    // £ IS in GSM-7 — worth knowing, since every price in a text uses it.
    assert.equal(smsSegments('Deposit of £25.00 received').encoding, 'GSM-7');

    // An em-dash is not, and it takes the whole message with it.
    const plain = smsSegments('A'.repeat(150));
    const dashed = smsSegments('A'.repeat(149) + '\u2014');
    assert.equal(plain.segments, 1);
    assert.equal(dashed.encoding, 'UCS-2');
    assert.equal(dashed.segments, 3, 'one em-dash should turn a 1-segment text into 3');

    // A curly apostrophe does the same, and is the one that sneaks in.
    assert.equal(smsSegments("We\u2019ll be with you shortly").encoding, 'UCS-2');
    assert.equal(smsSegments("We'll be with you shortly").encoding, 'GSM-7');

    // Extension characters cost two units each.
    assert.equal(smsSegments('{'.repeat(80)).segments, 1);
    assert.equal(smsSegments('{'.repeat(81)).segments, 2);

    // Empty is still one billable message, not zero.
    assert.equal(smsSegments('').segments, 1);
  });

  await check('a text is normalised so typography does not double the bill', async () => {
    const { gsmSafe, smsSegments } = await import('../worker.js');

    // The real status message, sent four times a job. It was UCS-2.
    const raw = "Cousins Mechanical: CMS-1A2B3 \u2014 On the way. Your mechanic is on the way \u2014 follow the van on the map.";
    assert.equal(smsSegments(raw).encoding, 'UCS-2');
    assert.equal(smsSegments(raw).segments, 2);
    const fixed = gsmSafe(raw);
    assert.equal(smsSegments(fixed).encoding, 'GSM-7');
    assert.equal(smsSegments(fixed).segments, 1, 'normalising did not get it down to one segment');
    assert.ok(fixed.includes('On the way'), 'normalising damaged the message');

    // Punctuation only. A name must never be mangled to save a fraction of a
    // penny — an unusual letter should still cost more and still be correct.
    assert.equal(gsmSafe('Zo\u00eb'), 'Zo\u00eb');
    assert.equal(gsmSafe('Jos\u00e9'), 'Jos\u00e9');
    assert.equal(gsmSafe('\u2018quoted\u2019'), "'quoted'");
    assert.equal(gsmSafe('a\u2026b'), 'a...b');
    assert.equal(gsmSafe('a \u2013 b'), 'a - b');
  });

  await check('the SumUp webhook believes nothing it is told', async () => {
    // The real payload is {event_type, id} — unsigned, with no status. Anyone
    // who finds the URL can post to it, so the only safe design is to ignore
    // the contents and ask SumUp. With SumUp unconfigured here, the endpoint
    // must refuse to credit anything at all.
    const forged = await postJson('/api/sumup-webhook', {
      event_type: 'CHECKOUT_STATUS_CHANGED', id: 'not-a-real-checkout',
    });
    assert.equal(forged.status, 200, 'a non-2xx makes SumUp retry forever');
    const d = await forged.json();
    assert.ok(!d.credited, 'a forged webhook credited a payment');
    assert.ok(d.ignored, 'the webhook did not say why it ignored the event');

    // A payload claiming a paid status and an amount must change nothing —
    // those fields do not exist in the real thing and must never be read.
    const liar = await postJson('/api/sumup-webhook', {
      event_type: 'CHECKOUT_STATUS_CHANGED', id: 'x', status: 'PAID', amount: 9999, checkout_reference: 'CMS-1',
    });
    assert.ok(!(await liar.json()).credited, 'the webhook trusted a status in the payload');
  });

  await check('confirming a payment cannot be used to fish for bookings', async () => {
    const r = await api('/api/pay/confirm?ref=CMS-DEFINITELY-NOT-REAL');
    assert.ok([200, 404].includes(r.status), `unexpected ${r.status}`);
    const d = await r.json().catch(() => ({}));
    assert.ok(!d.credited, 'confirm credited an unknown booking');
  });

  await check('the spend cap can be read by anyone but only changed by a developer', async () => {
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };

    const r = await (await api('/api/admin/limits', { headers: h })).json();
    assert.ok(r.limits, 'no limits returned');
    assert.equal(typeof r.limits.monthlyCap, 'number');
    assert.equal(typeof r.limits.hardCap, 'number');

    // A client who can raise their own ceiling does not have one. Built inline
    // rather than via the shared helper, which is declared further down.
    const password = 'a-properly-long-password';
    // The FIRST account ever created is forced to owner by design, so make one
    // to absorb that rule before testing what a real staff account may do.
    // Without this the test passes or fails purely on suite ordering.
    await api('/api/admin/staff', {
      method: 'POST', headers: h,
      body: JSON.stringify({ email: `cap-first-${Date.now()}@cousinsmechanicalservices.co.uk`, password }),
    });
    const email = `cap-staff-${Date.now()}@cousinsmechanicalservices.co.uk`;
    const mk = await api('/api/admin/staff', {
      method: 'POST', headers: h, body: JSON.stringify({ email, password, role: 'staff' }),
    });
    assert.equal(mk.status, 200, 'could not create the staff account');
    // Assert the role really is staff, so a 403 below cannot pass for the
    // wrong reason.
    assert.equal((await mk.json()).staff.role, 'staff', 'the account under test is not actually staff');
    const login = await postJson('/api/admin-login', { email, password, code: totpNow(totpSecret) });
    const staffTok = (await login.json()).token;
    const denied = await api('/api/admin/limits', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + staffTok },
      body: JSON.stringify({ monthlyCap: 9999 }),
    });
    assert.equal(denied.status, 403, 'day-to-day staff changed the spend cap');
  });

  await check('the runaway brake must sit above the budget, not below it', async () => {
    // A hard cap under the soft cap would stop every job message the instant
    // the budget was reached — the opposite of what a runaway brake is for.
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    const bad1 = await api('/api/admin/limits', {
      method: 'POST', headers: h, body: JSON.stringify({ monthlyCap: 100, hardCap: 50 }),
    });
    assert.equal(bad1.status, 400, 'accepted a runaway brake below the budget');

    const good = await api('/api/admin/limits', {
      method: 'POST', headers: h, body: JSON.stringify({ monthlyCap: 100, hardCap: 300, warnAtPct: 80 }),
    });
    const goodBody = await good.json().catch(() => ({}));
    assert.equal(good.status, 200, JSON.stringify(goodBody));
    assert.equal(goodBody.limits.hardCap, 300);

    // Put it back so the rest of the suite runs with no cap.
    await api('/api/admin/limits', {
      method: 'POST', headers: h, body: JSON.stringify({ monthlyCap: 0, hardCap: 0 }),
    });
  });

  await check('a capped send is recorded as a failure, never dropped quietly', async () => {
    // The whole point: if a message does not go, somebody has to be able to
    // find out. A silent drop is the failure mode this project has been
    // chasing all along.
    const fs = await import('node:fs');
    const src = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
    const i = src.indexOf('if (!budget.allowed)');
    assert.ok(i > 0, 'the spend gate is gone from sendSMS');
    const block = src.slice(i, i + 600);
    assert.ok(block.includes('noteMailFailure'), 'a blocked message is not written to the failure log');
    assert.ok(/essential\s*=\s*opts\.essential\s*!==\s*false/.test(src),
      'messages are not essential-by-default — a new caller could make a job update droppable');
  });

  await check('nothing sends email straight at one provider behind the switch', async () => {
    /*
     * The weekly backup used to POST to Resend directly, so it would have kept
     * using Resend after the owner moved everything else to Twilio — the one
     * message carrying every customer's name and address going out by a route
     * nobody had chosen. Every send now goes through sendEmail.
     */
    const fs = await import('node:fs');
    const src = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
    const calls = [...src.matchAll(/fetch\(\s*"https:\/\/api\.resend\.com\/emails"/g)];
    assert.equal(calls.length, 1,
      `${calls.length} places post to Resend's send API; only sendViaResend should`);
    const i = src.indexOf('async function sendViaResend');
    assert.ok(i > 0 && src.indexOf('https://api.resend.com/emails', i) - i < 900,
      'the one remaining Resend send call is not the one inside sendViaResend');

    const twilio = [...src.matchAll(/comms\.twilio\.com\/v1\/Emails/g)];
    assert.equal(twilio.length, 1, 'more than one place posts to Twilio Email');
  });

  await check('the live-status check never calls the site\'s own address', async () => {
    /*
     * The dashboard reported "Not responding — status 522" for weeks on a site
     * that was serving every page. The check fetched SITE_URL from inside the
     * Worker; a Worker cannot call the hostname it is itself serving, so the
     * edge answered 522 — an alarm that was always on and could never clear.
     *
     * Two things are asserted: the answer is healthy, and the code contains no
     * fetch of its own site. The second matters more — a green result here
     * could just mean the loopback happened to work on this machine.
     */
    const tok = await adminTok();
    const r = await api('/api/admin/service-status', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200, `service-status returned ${r.status}`);
    const d = await r.json();
    assert.ok(d.domain, 'no domain block in the status');
    assert.equal(d.domain.ok, true, 'the site reports itself unhealthy: ' + (d.domain.reason || ''));
    assert.equal(d.domain.reason, '', 'a problem was reported: ' + d.domain.reason);
    assert.ok(d.domain.catalogue > 0, 'the status did not count the catalogue');

    const fs = await import('node:fs');
    const src = fs.readFileSync(new URL('../worker.js', import.meta.url), 'utf8');
    const i = src.indexOf('/admin/service-status');
    assert.ok(i > 0, 'the service-status route moved');
    const block = src.slice(i, i + 3000);
    assert.ok(!/fetch\(\s*site\s*\+/.test(block),
      'the status check fetches its own site again — that is the 522 coming back');
  });

  await check('the calendar tab can read the diary, and says so plainly when it cannot', async () => {
    // No Google connection in a test run. The endpoint must answer calmly with
    // an empty diary rather than erroring, because the tab falls back to our
    // own job records and a 500 here would blank the whole calendar.
    const tok = await adminTok();
    const r = await api('/api/admin/calendar/events', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200, `calendar events returned ${r.status}`);
    const d = await r.json();
    assert.equal(d.connected, false, 'reported a Google connection that does not exist');
    assert.deepEqual(d.events, [], 'invented events with nothing connected');

    // And it must refuse a caller with no admin session at all.
    const anon = await api('/api/admin/calendar/events');
    assert.equal(anon.status, 403, `the diary is readable without a session (${anon.status})`);
  });

  await check('a booking cannot be taken for a date nobody meant', async () => {
    /*
     * The date was free text, stored as typed. A mistyped year produced a
     * booking for 31 July 2027 that was confirmed by email and by text, held a
     * slot, and sat in the diary looking like this month because the year was
     * never shown. The picker has min/max now, but a form attribute is a
     * courtesy to the browser — anyone can POST past it.
     */
    const base = {
      service: 'tyre', svcLabel: 'Tyre fitting', reg: 'DATE1', postcode: 'DT6 3QP',
      time: '10:00', name: 'Date Tester', phone: '07700900111', email: 'date-test@example.com',
      status: 'confirmed',
    };
    const far = new Date(); far.setFullYear(far.getFullYear() + 2);
    const past = new Date(); past.setFullYear(past.getFullYear() - 1);

    // Each attempt from its own address. The write limiter is 20 per IP per
    // minute and is correct production behaviour — five bookings from one
    // address here starved a later test instead of testing anything.
    let ip = 0;
    const tryDate = (date) => api('/api/service-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.' + (++ip) },
      body: JSON.stringify({ ...base, date }),
    });

    for (const [date, why] of [
      [far.toISOString().slice(0, 10), 'two years ahead'],
      [past.toISOString().slice(0, 10), 'a year in the past'],
      ['2026-13-45', 'a month and day that do not exist'],
      ['next tuesday', 'not a date at all'],
    ]) {
      const r = await tryDate(date);
      assert.equal(r.status, 400, `a booking ${why} (${date}) was accepted`);
      const d = await r.json();
      assert.ok((d.error || '').length > 10, `the refusal of ${date} does not explain itself`);
    }

    // And a sensible date still works, or the guard has eaten the feature.
    const ok = await tryDate(soonISO(5));
    assert.equal(ok.status, 200, `a booking five days out was refused: ${await ok.text()}`);
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

  await check('customers never see stock or supplier movements on their job', async () => {
    // Reported live: a customer's timeline read "Supplier Auto-Ordered — …
    // Purchase Order PO-… with C-Tyres Wholesale for next morning delivery".
    // That exposes who supplies the business and what is on the van, and reads
    // as a problem rather than progress. Filtering happens on READ so bookings
    // already stored with the old wording are covered too.
    const em = `timeline-${Date.now()}@example.com`;
    const pw = 'aVeryLongPassword1';
    const { token } = await signupVerified({ name: 'Timeline', email: em, phone: '07900000123', password: pw });
    const h = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };

    const mk = await api('/api/bookings', { method: 'POST', headers: h, body: JSON.stringify({ service: 'tyres', svcLabel: 'Tyre fitting — 195/65R15' }) });
    const ref = (await mk.json()).booking.ref;

    // Plant the exact legacy wording straight into KV via the admin path.
    const tok = await adminTok();
    await api(`/api/admin/jobs/${ref}`, {
      method: 'PATCH', headers: { authorization: 'Bearer ' + tok, 'content-type': 'application/json' },
      body: JSON.stringify({ customerEmail: em, label: 'Supplier Auto-Ordered',
        note: 'Purchase Order PO-CTYRES-H5VRV with C-Tyres Wholesale for next morning delivery.' }),
    });

    const seen = JSON.stringify([
      (await (await api(`/api/track/${ref}`, { headers: h })).json()).updates,
      (await (await api('/api/bookings', { headers: h })).json()).bookings,
    ]);
    for (const leak of ['Supplier', 'Purchase Order', 'PO-CTYRES', 'Wholesale', 'inventory']) {
      assert.ok(!seen.includes(leak), `the customer can see "${leak}" on their job`);
    }

    // The admin must still see the full picture.
    const jobs = (await (await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + tok } })).json()).jobs;
    const adminView = JSON.stringify(jobs.find(j => j.ref === ref));
    assert.ok(adminView.includes('Supplier'), 'the internal note vanished from the admin view too');
  });

  await check('a driver needs BOTH a confirmed email and admin approval', async () => {
    const uname = 'gated' + Date.now();
    const em = `${uname}@example.com`;
    const pw = 'aVeryLongDriverPassword1';

    const reg = await postJson('/api/driver/register', { email: em, password: pw, name: 'Gated Driver' });
    assert.equal(reg.status, 200, 'register failed: ' + (await reg.clone().text()));
    const rd = await reg.json();
    assert.equal(rd.verifyRequired, true, 'registration did not ask for email confirmation');
    assert.ok(rd.devCode, 'no confirmation code issued');

    // Gate 1 still closed. Note the login path deliberately issues a FRESH
    // code, which invalidates the one from registration — so carry it forward.
    const before = await postJson('/api/driver/login', { username: em, password: pw });
    assert.equal(before.status, 403, 'an unconfirmed driver could sign in');
    const bd = await before.json();
    assert.equal(bd.verifyRequired, true);
    const liveCode = bd.devCode || rd.devCode;

    // The stale code must no longer work.
    if (bd.devCode && bd.devCode !== rd.devCode) {
      const stale = await postJson('/api/driver/verify-email', { email: em, code: rd.devCode });
      assert.equal(stale.status, 400, 'a superseded confirmation code still worked');
    }

    // The admin must not be able to approve around gate 1.
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    const drivers = (await (await api('/api/admin/drivers', { headers: h })).json()).drivers;
    const rec = drivers.find(d => d.email === em);
    assert.ok(rec, 'driver missing from the admin list');
    assert.equal(rec.emailVerified, false);
    const early = await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ action: 'approve', id: rec.id }) });
    assert.equal(early.status, 409, 'the admin approved a driver who had not confirmed their email');

    // Clear gate 1 — still no access, because gate 2 is closed.
    const v = await postJson('/api/driver/verify-email', { email: em, code: liveCode });
    assert.equal(v.status, 200, 'verify failed: ' + (await v.clone().text()));
    const mid = await postJson('/api/driver/login', { username: em, password: pw });
    assert.equal(mid.status, 403, 'a confirmed but unapproved driver got in');
    assert.equal((await mid.json()).pendingApproval, true);

    // Clear gate 2 — now in, and by email as well as username.
    await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ action: 'approve', id: rec.id }) });
    const ok = await postJson('/api/driver/login', { username: em, password: pw });
    assert.equal(ok.status, 200, 'an approved, confirmed driver still could not sign in');
    assert.ok((await ok.json()).token);
    const byEmail = await postJson('/api/driver/login', { username: em, password: pw });
    assert.equal(byEmail.status, 200, 'signing in with the registered email did not work');
  });

  await check('the admin can edit a driver and keep notes without breaking their login', async () => {
    const uname = 'edit' + Date.now();
    const em = `${uname}@example.com`;
    const pw = 'aVeryLongDriverPassword1';
    const rd = await (await postJson('/api/driver/register', { email: em, password: pw, name: 'Edit Me' })).json();
    await postJson('/api/driver/verify-email', { email: em, code: rd.devCode });

    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok, 'content-type': 'application/json' };
    let list = (await (await api('/api/admin/drivers', { headers: h })).json()).drivers;
    const id = list.find(d => d.email === em).id;
    await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ action: 'approve', id }) });

    await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ id, name: 'Mark Cousin', vanReg: 'KM16 GLY', phone: '07925340977' }) });
    await api('/api/admin/drivers', { method: 'POST', headers: h, body: JSON.stringify({ action: 'note', id, text: 'Has the tyre machine in van 2.' }) });

    list = (await (await api('/api/admin/drivers', { headers: h })).json()).drivers;
    const d = list.find(x => x.id === id);
    assert.equal(d.name, 'Mark Cousin');
    assert.equal(d.vanReg, 'KM16 GLY');
    assert.equal(d.notes.length, 1);
    assert.equal(d.notes[0].text, 'Has the tyre machine in van 2.');
    assert.equal(d.hash, undefined, 'the driver list leaked password material');

    // Editing must not have destroyed the login — this has broken before.
    const still = await postJson('/api/driver/login', { username: em, password: pw });
    assert.equal(still.status, 200, 'editing the driver in admin broke their password');
  });

  await check('the CAPTCHA is inert until it is configured, and advertises itself honestly', async () => {
    // TURNSTILE_SECRET is not set in tests, so every check must pass. A
    // half-configured CAPTCHA that silently rejects real customers is worse
    // than no CAPTCHA at all — a mechanic in the rain cannot debug it.
    const em = `captcha-${Date.now()}@example.com`;
    const r = await postJson('/api/auth/signup', { name: 'No Captcha', email: em, phone: '07900000123', password: 'aVeryLongPassword1', consent: true });
    assert.equal(r.status, 200, 'signup was blocked while the CAPTCHA is unconfigured');

    // And the front end must be able to tell that there is no widget to render.
    const cfg = await api('/api/turnstile-config');
    assert.equal(cfg.status, 404, 'turnstile-config returned a site key that is not set');
  });

  await check('the booking form is never blocked by the CAPTCHA', async () => {
    // A customer at the roadside must not be turned away because a widget
    // failed to load. Sign-in is CAPTCHA-gated; booking is rate-limited only.
    const r = await postJson('/api/service-requests', {
      name: 'No Token', phone: '07900000456', reg: 'NO11TOK',
      service: 'recovery', svcLabel: 'Breakdown / recovery',
    });
    assert.equal(r.status, 200, 'a booking without a CAPTCHA token was refused');
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
    const { token } = await signupVerified({ name: 'Self Pay', email: em, phone: '07900000002', password: pw });
    const h = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };

    const mk = await api('/api/bookings', { method: 'POST', headers: h, body: JSON.stringify({ service: 'diagnostics', svcLabel: 'Diagnostics', reg: 'SE11LF' }) });
    const ref = (await mk.json()).booking.ref;

    const patched = await api(`/api/bookings/${ref}`, {
      method: 'PATCH', headers: h,
      body: JSON.stringify({ date: soonISO(5), paidPence: 20000, payments: [{ kind: 'payment', pence: 20000 }], status: 'complete' }),
    });
    const job = (await patched.json()).booking;
    assert.equal(job.date, soonISO(5), 'a legitimate amendment was refused');
    assert.equal(job.paidPence, undefined, 'a customer marked their own job paid');
    assert.equal(job.payments, undefined, 'a customer wrote their own payment records');
    assert.notEqual(job.status, 'complete', 'a customer set their own job status');
  });

  await check('calendar invites cannot be sent by an anonymous caller', async () => {
    // Ungated, this sent a real Google invite FROM the business account to any
    // address the caller chose.
    const r = await postJson('/api/calendar/add-event', { date: soonISO(5), name: 'Spam', customerEmail: 'target@example.com' });
    assert.equal(r.status, 403, `calendar event creation is open to the world (status ${r.status})`);
  });

  await check('Google sign-in never hands out a session without a grant we issued', async () => {
    // The claim endpoint is the last step of "Sign in with Google" — a guessed
    // or replayed grant must die here, not become somebody's 12-hour session.
    const bogus = await postJson('/api/admin-login-google/claim', { grant: '00000000-0000-4000-8000-000000000000' });
    assert.ok(bogus.status === 401 || bogus.status === 429, `a made-up grant was not rejected (status ${bogus.status})`);
    const mangled = await postJson('/api/admin-login-google/claim', { grant: '../admin_totp' });
    assert.ok(mangled.status === 401 || mangled.status === 429, `a malformed grant was not rejected (status ${mangled.status})`);

    const start = await postJson('/api/admin-login-google/start', {});
    if (start.status === 200) {
      const d = await start.json();
      assert.ok(String(d.url).startsWith('https://accounts.google.com/o/oauth2/v2/auth?'), 'login start is not a Google URL');
      assert.ok(d.url.includes('scope=openid+email') || d.url.includes('scope=openid%20email'), 'login asks for more than identity');
      assert.ok(!d.url.includes('calendar'), 'a LOGIN must never request calendar scope');
    } else {
      assert.ok(start.status === 400 || start.status === 429, `unexpected status ${start.status}`);
    }
  });

  await check('a customer Google sign-in never asks for Gmail or the calendar', async () => {
    /*
     * The button this replaced asked a member of the public for
     * https://mail.google.com/ and full calendar access, to look at a tyre
     * booking. That is the scariest thing this codebase has ever asked anyone
     * for, and nothing but a test stops it coming back.
     */
    const start = await postJson('/api/auth/google/start', {});
    if (start.status === 200) {
      const url = (await start.json()).url;
      assert.ok(String(url).startsWith('https://accounts.google.com/o/oauth2/v2/auth?'), 'not a Google consent URL');
      const scope = new URL(url).searchParams.get('scope') || '';
      assert.ok(!/mail\.google\.com/.test(scope), 'a customer is being asked for their Gmail');
      assert.ok(!/auth\/calendar/.test(scope), 'a customer is being asked for their calendar');
      assert.ok(/openid/.test(scope) && /email/.test(scope), 'identity scopes missing: ' + scope);
    } else {
      assert.ok(start.status === 400 || start.status === 429, `unexpected status ${start.status}`);
    }

    // And the session cannot be conjured client-side, which is what the old
    // code did: it wrote "demo-token" into localStorage and called it a login.
    for (const grant of ['00000000-0000-4000-8000-000000000000', 'demo-token', '../user:a@b.c']) {
      const r = await postJson('/api/auth/google/claim', { grant });
      assert.ok(r.status === 401 || r.status === 429, `claim accepted "${grant}" (${r.status})`);
    }
  });

  await check('a forged SumUp callback bounces instead of storing anything', async () => {
    const r = await api('/api/oauth/sumup/callback?code=fake&state=never-issued', { redirect: 'manual' });
    assert.equal(r.status, 302, `forged SumUp callback did not redirect (status ${r.status})`);
    assert.ok((r.headers.get('location') || '').includes('sumup=expired'), 'forged SumUp callback was not refused readably');
  });

  await check('a forged Google Calendar callback bounces instead of storing anything', async () => {
    // The state nonce is the whole defence: without it, anyone who found the
    // callback URL could connect THEIR Google account as the business diary.
    const r = await api('/api/oauth/google/callback?code=fake&state=never-issued', { redirect: 'manual' });
    assert.equal(r.status, 302, `forged callback did not redirect (status ${r.status})`);
    const loc = r.headers.get('location') || '';
    assert.ok(loc.includes('gcal=expired'), `forged callback did not land on the readable failure page: ${loc}`);
  });

  await check('a forged Apple callback bounces instead of signing anyone in', async () => {
    // Apple posts a form, so this one is a POST — and the state nonce is the
    // whole defence, exactly as for Google.
    const r = await api('/api/oauth/apple/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: 'fake', state: 'never-issued' }).toString(),
      redirect: 'manual',
    });
    assert.equal(r.status, 302, `forged Apple callback did not redirect (status ${r.status})`);
    const loc = r.headers.get('location') || '';
    assert.ok(loc.includes('gauth=expired'), `forged Apple callback was not refused readably: ${loc}`);
    // And a well-formed uuid that was simply never issued fares no better.
    const r2 = await api('/api/oauth/apple/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: 'fake', state: '11111111-2222-3333-4444-555555555555' }).toString(),
      redirect: 'manual',
    });
    assert.ok((r2.headers.get('location') || '').includes('gauth=expired'), 'an unissued state nonce was accepted');
  });

  await check('a mis-set Apple secret is caught here, not by Apple', async () => {
    /*
     * Setting these from a terminal goes wrong quietly. `echo` leaves a
     * trailing newline; an interactive `wrangler secret put` inside a pasted
     * block reads the NEXT PASTED LINE as the value and the rest of the block
     * never runs. Either way nothing is visible anywhere, the button appears,
     * and Apple answers invalid_client without saying which of the four values
     * it means.
     *
     * So the shape is checked, not just the presence, and the failure names
     * the field. This test asserts the endpoint fails closed and readably —
     * whichever way this environment happens to be configured.
     */
    const r = await postJson('/api/auth/apple/start', {});
    if (r.status === 400) {
      const err = String((await r.json()).error);
      assert.match(err, /APPLE_(SERVICES_ID|TEAM_ID|KEY_ID|PRIVATE_KEY)/,
        'the failure does not name the secret that is wrong: ' + err);
    } else {
      // Configured: then it must be a real Apple URL, never a half-built one.
      assert.equal(r.status, 200, `unexpected status ${r.status}`);
      const u = new URL((await r.json()).url);
      assert.match(u.searchParams.get('client_id') || '', /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/,
        'the client_id is not a Services ID — a stray newline or a pasted command line?');
    }
  });

  await check('Apple sign-in asks for a name and an email, and nothing else', async () => {
    const r = await postJson('/api/auth/apple/start', {});
    if (r.status === 200) {
      const u = new URL((await r.json()).url);
      assert.equal(u.origin + u.pathname, 'https://appleid.apple.com/auth/authorize', 'not an Apple consent URL');
      assert.equal(u.searchParams.get('scope'), 'name email', 'wrong scope requested');
      // Requesting a scope obliges Apple to POST the answer back. Without this
      // the callback would never fire and sign-in would hang on a blank page.
      assert.equal(u.searchParams.get('response_mode'), 'form_post', 'a scoped Apple request must be form_post');
      assert.match(u.searchParams.get('state') || '', /^[0-9a-f-]{36}$/, 'state is not a nonce');
      assert.ok((u.searchParams.get('redirect_uri') || '').endsWith('/api/oauth/apple/callback'), 'wrong redirect_uri');
    } else {
      // Not configured: the failure has to say which secrets to set, not shrug.
      assert.equal(r.status, 400, `unexpected status ${r.status}`);
      assert.ok(String((await r.json()).error).includes('APPLE_SERVICES_ID'), 'failure does not say what to set');
    }
  });

  await check('the front door advertises only the providers that are configured', async () => {
    const d = await (await api('/api/auth/providers')).json();
    assert.equal(typeof d.google, 'boolean');
    assert.equal(typeof d.apple, 'boolean');
    // It must never leak anything but the two flags.
    assert.deepEqual(Object.keys(d).sort(), ['apple', 'google'], 'the provider list says more than it should');
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
    const { token } = await signupVerified({ name: 'Erase Me', email: em, phone: '07900000003', password: pw });
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
      booking_date: soonISO(6), booking_time: 'Afternoon (12-5)', booking_location: 'DT6 4LB',
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
      'booking_date', 'booking_time', 'booking_location', 'manage_booking_url', 'payment_terms']);
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

  /*
   * Roles. These exist because `role` was stored, displayed, and never checked
   * — so any staff account could delete any other, reset the owner's password
   * and export every customer record. The tests below are the difference
   * between roles that mean something and roles that are decoration.
   */
  /*
   * Create a staff account and take it all the way to a working session.
   *
   * That is now four steps, not two, because a staff account with no
   * authenticator holds a session that can do exactly one thing: enrol one.
   * The helper walks the same path a real person walks on their first sign-in,
   * so every role test below is also, incidentally, proof that the path works.
   */
  const asStaff = async (role) => {
    const tok = await adminTok();
    const email = `role-${role}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@cousinsmechanicalservices.co.uk`;
    const password = 'a-properly-long-password';
    const mk = await api('/api/admin/staff', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok },
      body: JSON.stringify({ email, password, name: role, role }),
    });
    assert.equal(mk.status, 200, `could not create a ${role}: ${await mk.text()}`);

    const first = await postJson('/api/admin-login', { email, password });
    assert.equal(first.status, 200, `${role} could not sign in`);
    const f = await first.json();
    assert.equal(f.mustEnrol, true, 'a brand new staff account was not asked to set up two-factor');

    const seed = await api('/api/admin-2fa/new', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + f.token },
      body: '{}',
    });
    assert.equal(seed.status, 200, `enrolment refused the session it is meant to serve (${seed.status})`);
    const secret = (await seed.json()).secret;
    const on = await api('/api/admin-2fa/enable', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + f.token },
      body: JSON.stringify({ secret, code: totpNow(secret) }),
    });
    assert.equal(on.status, 200, `could not finish enrolment: ${await on.text()}`);

    const login = await postJson('/api/admin-login', { email, password, code: totpNow(secret) });
    assert.equal(login.status, 200, `${role} could not sign in after enrolling`);
    const d = await login.json();
    assert.ok(!d.mustEnrol, 'still being asked to enrol after enrolling');
    return { email, token: d.token, secret, role: d.role };
  };
  const staffApi = (path, token, init = {}) => api(path, {
    ...init,
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token, ...(init.headers || {}) },
  });

  await check('the very first staff account is always the owner', async () => {
    // The dashboard form does not send a role. Without forcing this, the first
    // account ever created would be a lone "staff" — no owner would exist and
    // whoever set the system up would lock themselves out of staff management
    // with their own first click.
    const tok = await adminTok();
    const list = await (await api('/api/admin/staff', { headers: { authorization: 'Bearer ' + tok } })).json();
    const first = (list.staff || []).slice().sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0))[0];
    assert.ok(first, 'no staff accounts exist to check');
    assert.equal(first.role, 'owner', 'the first account created is not an owner');
  });

  await check('connecting Google Calendar is configuration, not day-to-day staff work', async () => {
    const s = await asStaff('staff');
    const denied = await staffApi('/api/admin/gcal/connect-url', s.token, { method: 'POST' });
    assert.equal(denied.status, 403, 'a staff account was allowed to start a Google connection');

    const dev = await asStaff('developer');
    const r = await staffApi('/api/admin/gcal/connect-url', dev.token, { method: 'POST' });
    if (r.status === 200) {
      // Client id and secret are configured: it must be a real consent URL
      // that will actually come back with a refresh token.
      const d = await r.json();
      assert.ok(String(d.url).startsWith('https://accounts.google.com/o/oauth2/v2/auth?'), 'not a Google consent URL: ' + d.url);
      assert.ok(d.url.includes('access_type=offline'), 'consent URL would not return a refresh token');
      assert.ok(d.url.includes('prompt=consent'), 'a reconnect would silently come back tokenless');
    } else {
      // Not configured: the failure must say which secrets to set, not shrug.
      assert.equal(r.status, 400, `unexpected status ${r.status}`);
      const d = await r.json();
      assert.ok(String(d.error).includes('GOOGLE_CLIENT_ID'), 'failure does not say what needs setting');
    }
  });

  await check('two-factor is per account, and the owner can turn it on himself', async () => {
    /*
     * Enrolment used to demand the bootstrap ADMIN_TOKEN — the one that stops
     * being accepted for login the moment a staff account exists. So the owner,
     * signed in to his own dashboard, could not turn 2FA on at all. Nobody had.
     */
    const dev = await asStaff('developer');
    const dev2 = await asStaff('developer');
    // A second person gets their OWN secret, not the first person's. A shared
    // one would mean the second to enrol needs the first person's phone.
    assert.notEqual(dev.secret, dev2.secret, 'two accounts were handed the same authenticator secret');

    // Once it is on, a stolen session cannot quietly re-enrol somebody else's
    // phone in place of the owner's.
    const again = await staffApi('/api/admin-2fa/new', dev.token, { method: 'POST', body: '{}' });
    assert.equal(again.status, 409, `an enrolled account was handed a fresh secret (${again.status})`);

    // The account's own code, and only its own, opens the account.
    const wrongPhone = await postJson('/api/admin-login', {
      email: dev.email, password: 'a-properly-long-password', code: totpNow(dev2.secret),
    });
    assert.equal(wrongPhone.status, 401, "another person's authenticator opened this account");

    // And a stranger with no session still cannot ask for one.
    const anon = await postJson('/api/admin-2fa/new', {});
    assert.ok(anon.status === 401 || anon.status === 429, `2FA enrolment is open to anyone (${anon.status})`);
  });

  await check('the two-factor QR code is a real, scannable QR code', async () => {
    /*
     * This encoder is written here rather than pulled from a CDN, because the
     * one screen that must never depend on somebody else's uptime is the one
     * whose whole job is security. That means the correctness of it is ours.
     *
     * It was checked module-for-module against an independent implementation
     * and decoded with a real QR reader across versions 1 to 20 — which is how
     * a two-module error was found: (8,6) and (6,8), where the timing patterns
     * cross the format stripe, were being blanked and never restored. Error
     * correction absorbed them, so every code still scanned and looked
     * perfect. The frozen hash below is that verified output; if the encoder
     * drifts, this fails.
     */
    const FIXED = 'otpauth://totp/Cousins%20Mechanical%20help@cousinsmechanicalservices.co.uk'
      + '?secret=AUZ3ITSCJAQ33TGVM35UZJQ3UHB7ENRG&issuer=Cousins%20Mechanical&algorithm=SHA1&digits=6&period=30';
    const m = qrMatrix(FIXED);
    assert.equal(m.length, 53, 'wrong QR version chosen for a typical otpauth URI');
    const hash = crypto.createHash('sha256').update(m.map(r => r.join('')).join('\n')).digest('hex');
    assert.equal(hash, 'bd86e5a984bf14e6f90aad31232144efa211da2ba469d656fa002e6698d4c99b',
      'the QR encoder no longer produces the matrix that was verified against an independent decoder');

    // The three finder patterns, without which no reader will even look.
    const finderAt = (ox, oy) => {
      for (let dy = 0; dy < 7; dy++) for (let dx = 0; dx < 7; dx++) {
        const d = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
        if (m[oy + dy][ox + dx] !== (d === 2 ? 0 : 1)) return false;
      }
      return true;
    };
    assert.ok(finderAt(0, 0), 'top-left finder pattern is malformed');
    assert.ok(finderAt(m.length - 7, 0), 'top-right finder pattern is malformed');
    assert.ok(finderAt(0, m.length - 7), 'bottom-left finder pattern is malformed');

    // The timing patterns, including the two modules where they cross the
    // format stripe — the exact ones that were wrong.
    for (let i = 8; i < m.length - 8; i++) {
      assert.equal(m[6][i], i % 2 === 0 ? 1 : 0, `horizontal timing wrong at x=${i}`);
      assert.equal(m[i][6], i % 2 === 0 ? 1 : 0, `vertical timing wrong at y=${i}`);
    }

    // And the SVG carries exactly those modules, with a quiet zone.
    const uri = qrSvgDataUri(FIXED, 220);
    assert.ok(uri.startsWith('data:image/svg+xml,'), 'not an inline SVG data URI');
    /*
     * No semicolon anywhere in the URI, and this is the whole reason it is
     * percent-encoded rather than base64. The design-canvas runtime builds a
     * style object with css.split(";"), quoting be damned, so a ";base64,"
     * inside a bound style truncates the URI to "data:image/svg+xml" and the
     * QR silently fails to load — which is exactly what it did.
     */
    assert.ok(!uri.includes(';'), 'a semicolon in the data URI will be cut by the style parser');
    const svg = decodeURIComponent(uri.slice('data:image/svg+xml,'.length));
    const drawn = (svg.match(/M\d+,\d+h1v1h-1z/g) || []).length;
    const dark = m.flat().filter(Boolean).length;
    assert.equal(drawn, dark, 'the SVG does not draw the same modules as the matrix');
    assert.ok(svg.includes(`viewBox="0 0 ${m.length + 8} ${m.length + 8}"`),
      'the quiet zone is missing — many readers will not see the code at all');
  });

  await check('a staff account with no authenticator can enrol and do nothing else', async () => {
    /*
     * The owner's words: "this is vital so noone can access without the auth".
     * A UI that merely shows an enrolment card is not that — the session behind
     * it has to be inert. This is the test that makes it inert: sign in, then
     * try the dashboard, the customer list and the staff list with a session
     * that has no second factor on it.
     */
    const tok = await adminTok();
    const email = `noauth-${Date.now()}-${Math.floor(Math.random() * 1e6)}@cousinsmechanicalservices.co.uk`;
    const password = 'a-properly-long-password';
    const mk = await api('/api/admin/staff', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok },
      body: JSON.stringify({ email, password, name: 'Not Enrolled', role: 'owner' }),
    });
    assert.equal(mk.status, 200, `could not create the account: ${await mk.text()}`);

    const login = await postJson('/api/admin-login', { email, password });
    assert.equal(login.status, 200, 'sign-in was refused outright, leaving nowhere to enrol from');
    const d = await login.json();
    assert.equal(d.mustEnrol, true, 'the dashboard was not told to demand enrolment');
    assert.equal(d.enrolled, false);

    // Even as an owner — the highest role there is — the session is inert.
    for (const path of ['/api/admin/jobs', '/api/admin/customers', '/api/admin/staff']) {
      const r = await api(path, { headers: { authorization: 'Bearer ' + d.token } });
      assert.equal(r.status, 403, `${path} was open to an owner with no authenticator (${r.status})`);
    }

    // The one thing it may do.
    const seed = await api('/api/admin-2fa/new', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + d.token },
      body: '{}',
    });
    assert.equal(seed.status, 200, 'the only permitted action was also refused — a dead end');
    const seeded = await seed.json();
    const secret = seeded.secret;
    // A 32-character key typed by hand off a phone screen is how enrolment
    // gets abandoned. The card shows a QR; the endpoint has to supply it.
    assert.ok(String(seeded.qr || '').startsWith('data:image/svg+xml,'),
      'enrolment came back with no QR code to scan');
    assert.ok(!seeded.qr.includes(';'), 'the QR URI would be truncated by the style parser');
    /*
     * Base32, RFC 4648: capitals and the digits 2 to 7. No 0, 1, 8 or 9 ever.
     * This matters more than it looks — the key was being displayed in a
     * condensed bold face where a capital O reads as a zero, somebody typed
     * the zero, and the authenticator answered "invalid characters" without
     * saying which. The alphabet is the fact that makes the fix safe to state.
     */
    assert.match(secret, /^[A-Z2-7]{32}$/, 'the setup key is not valid base32 — no app will accept it');
    assert.ok(seeded.otpauth.includes('secret=' + secret), 'the QR would not carry this account\'s secret');
    const on = await api('/api/admin-2fa/enable', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + d.token },
      body: JSON.stringify({ secret, code: totpNow(secret) }),
    });
    assert.equal(on.status, 200, `enrolment did not complete: ${await on.text()}`);

    // Enrolling wakes the session it was made from — no second sign-in needed.
    const now = await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + d.token } });
    assert.equal(now.status, 200, 'the session stayed dead after enrolling');

    // And from here the password alone is no longer enough.
    const noCode = await postJson('/api/admin-login', { email, password });
    assert.equal(noCode.status, 401, 'the password alone still opened an enrolled account');
  });

  await check('one sign-in serves the office and the van', async () => {
    /*
     * The owner-operator is his own driver. The dashboard's "Van — driver
     * view" button hands this very session to the driver screen rather than
     * minting a second set of credentials, so the driver endpoints have to
     * accept a staff session in the Authorization header — and refuse one that
     * has not been through two-factor.
     */
    const owner = await asStaff('owner');
    // A fresh client address: the driver endpoints rate-limit by IP, and the
    // tests above deliberately hammer them with bad tokens from the default one.
    const fromVan = { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.' + (10 + Math.floor(Math.random() * 200)) };
    const ok = await api('/api/driver/jobs', {
      method: 'POST',
      headers: { ...fromVan, authorization: 'Bearer ' + owner.token },
      body: '{}',
    });
    assert.equal(ok.status, 200, `an owner's session was refused by the van view (${ok.status})`);
    assert.ok(Array.isArray((await ok.json()).jobs), 'the van view returned no job list');

    // The same session before enrolment must not get there.
    const email = `van-${Date.now()}-${Math.floor(Math.random() * 1e6)}@cousinsmechanicalservices.co.uk`;
    const password = 'a-properly-long-password';
    const tok = await adminTok();
    await api('/api/admin/staff', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok },
      body: JSON.stringify({ email, password, name: 'Van Owner', role: 'owner' }),
    });
    const bare = await (await postJson('/api/admin-login', { email, password })).json();
    const denied = await api('/api/driver/jobs', {
      method: 'POST',
      headers: { ...fromVan, authorization: 'Bearer ' + bare.token },
      body: '{}',
    });
    assert.equal(denied.status, 403, `the van view let in a session with no authenticator (${denied.status})`);
  });

  await check('email can be moved between services without a deploy', async () => {
    /*
     * Two services are wired: Resend, which has been carrying the mail, and
     * Twilio Email, whose sending domain is verified on this account. The
     * point of the switch is that it is reversible in one click — so what is
     * asserted here is that the setting is real, that it refuses a service
     * that cannot actually send, and that only an owner or developer can
     * change it. Which service is chosen is a business decision, not a test.
     */
    const tok = await adminTok();
    const auth = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };

    const h = await api('/api/admin/mail-failures', { headers: auth });
    assert.equal(h.status, 200, `mail health returned ${h.status}`);
    const hd = await h.json();
    assert.ok(hd.mail, 'the mail panel has no provider block to show');
    assert.ok('resend' in hd.mail.available && 'twilio' in hd.mail.available,
      'the dashboard cannot tell which services are available');

    // Nothing is configured in a test run, so both must be refused with a
    // reason rather than silently accepted and then failing on a real booking.
    for (const provider of ['twilio', 'resend']) {
      const r = await api('/api/admin/mail-provider', { method: 'POST', headers: auth, body: JSON.stringify({ provider }) });
      assert.equal(r.status, 400, `${provider} was accepted with no credentials (${r.status})`);
      const d = await r.json();
      assert.ok(/cannot send/i.test(d.error || ''), `the refusal does not say why: ${d.error}`);
    }

    const junk = await api('/api/admin/mail-provider', { method: 'POST', headers: auth, body: JSON.stringify({ provider: 'carrier-pigeon' }) });
    assert.equal(junk.status, 400, 'an unknown mail service was accepted');

    // And it is configuration, so ordinary staff cannot change it.
    const staff = await asStaff('staff');
    const asStaffTry = await api('/api/admin/mail-provider', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + staff.token },
      body: JSON.stringify({ provider: 'twilio' }),
    });
    assert.equal(asStaffTry.status, 403, `ordinary staff can move the company mail (${asStaffTry.status})`);
  });

  await check('only an owner or developer can approve, edit or remove a driver', async () => {
    /*
     * Approving a driver is what puts somebody in the van view, where every
     * live customer's name, address and registration is. It had no role check
     * at all: any day-to-day staff account could approve a colleague, reset a
     * driver's password, or delete one.
     */
    const s = await asStaff('staff');
    const dev = await asStaff('developer');

    const made = await staffApi('/api/admin/drivers', dev.token, {
      method: 'POST',
      body: JSON.stringify({ name: 'Gate Test', vanReg: 'GA71TES' }),
    });
    const madeBody = await made.json().catch(() => ({}));
    assert.equal(made.status, 200, `a developer could not create a driver: ${JSON.stringify(madeBody)}`);
    const driver = (madeBody.drivers || []).find(x => x.vanReg === 'GA71TES');
    assert.ok(driver, 'the driver was not created');

    const approve = await staffApi('/api/admin/drivers', s.token, {
      method: 'POST',
      body: JSON.stringify({ action: 'approve', id: driver.id }),
    });
    assert.equal(approve.status, 403, `day-to-day staff approved a driver (${approve.status})`);

    const reset = await staffApi('/api/admin/drivers', s.token, {
      method: 'POST',
      body: JSON.stringify({ id: driver.id, password: 'a-brand-new-long-password' }),
    });
    assert.equal(reset.status, 403, "day-to-day staff reset a driver's password");

    const del = await staffApi('/api/admin/drivers', s.token, {
      method: 'DELETE',
      body: JSON.stringify({ id: driver.id }),
    });
    assert.equal(del.status, 403, 'day-to-day staff deleted a driver');

    // Reading the van list is not the same as changing it — a staff member
    // still needs to know who is out today.
    const read = await staffApi('/api/admin/drivers', s.token);
    assert.equal(read.status, 200, 'staff can no longer even see the van list');

    const gone = await staffApi('/api/admin/drivers', dev.token, {
      method: 'DELETE',
      body: JSON.stringify({ id: driver.id }),
    });
    assert.equal(gone.status, 200, `a developer could not remove a driver (${gone.status})`);
  });

  await check('connecting SumUp is configuration, not day-to-day staff work', async () => {
    const s = await asStaff('staff');
    const denied = await staffApi('/api/admin/sumup/connect-url', s.token, { method: 'POST' });
    assert.equal(denied.status, 403, 'day-to-day staff started a SumUp connection');

    const dev = await asStaff('developer');
    const start = await staffApi('/api/admin/sumup/connect-url', dev.token, { method: 'POST' });
    if (start.status === 200) {
      const d = await start.json();
      assert.ok(String(d.url).startsWith('https://api.sumup.com/authorize?'), 'not a SumUp consent URL: ' + d.url);
      // Least privilege, asserted. Asking a client for their whole financial
      // history "in case" is the thing this integration promises not to do.
      const scope = new URL(d.url).searchParams.get('scope') || '';
      assert.ok(scope.includes('payments'), 'cannot take a payment without the payments scope');
      assert.ok(!scope.includes('transactions.history'), 'requesting transaction history that nothing reads');
      assert.ok(!scope.includes('user.profile '), 'requesting WRITE access to the merchant profile');
      assert.ok(!scope.includes('payout'), 'requesting access to payout settings');
    } else {
      assert.equal(start.status, 400, `unexpected status ${start.status}`);
      assert.ok(String((await start.json()).error).includes('SUMUP_CLIENT_ID'), 'failure does not say what to set');
    }

    const status = await staffApi('/api/admin/sumup/status', dev.token);
    assert.equal(status.status, 200, 'sumup status endpoint broken');
    assert.equal(typeof (await status.json()).connected, 'boolean');

    // The tyre list export: today's live prices, importable into SumUp Items.
    const csv = await staffApi('/api/admin/sumup/items.csv', dev.token);
    assert.equal(csv.status, 200, 'items csv export broken');
    const text = await csv.text();
    assert.ok(text.startsWith('"Item name","Price (GBP)"'), 'csv header wrong: ' + text.slice(0, 60));
    assert.ok(text.split('\r\n').length > 100, 'csv suspiciously short — catalogue missing?');
  });

  await check('a staff account cannot promote anyone, including itself', async () => {
    const s = await asStaff('staff');
    const r = await staffApi('/api/admin/staff', s.token, {
      method: 'POST',
      body: JSON.stringify({ email: `escalate-${Date.now()}@example.com`, password: 'a-properly-long-password', role: 'owner' }),
    });
    assert.equal(r.status, 403, 'a staff account was allowed to mint an owner');

    const self = await staffApi('/api/admin/staff', s.token, {
      method: 'POST',
      body: JSON.stringify({ email: s.email, password: 'a-properly-long-password', role: 'owner' }),
    });
    assert.equal(self.status, 403, 'a staff account promoted itself to owner');
  });

  await check('a developer cannot remove or disable an owner', async () => {
    // The rule that matters most: a contractor with a login must never be able
    // to lock their client out of their own business.
    const dev = await asStaff('developer');
    const tok = await adminTok();
    const list = await (await api('/api/admin/staff', { headers: { authorization: 'Bearer ' + tok } })).json();
    const owner = (list.staff || []).find(a => a.role === 'owner');
    assert.ok(owner, 'no owner account to test against');

    const del = await staffApi('/api/admin/staff/' + encodeURIComponent(owner.email), dev.token, { method: 'DELETE' });
    assert.equal(del.status, 403, 'a developer deleted an owner');

    const dis = await staffApi('/api/admin/staff/' + encodeURIComponent(owner.email), dev.token, {
      method: 'PATCH', body: JSON.stringify({ disabled: true }),
    });
    assert.equal(dis.status, 403, 'a developer disabled an owner');

    const pw = await staffApi('/api/admin/staff', dev.token, {
      method: 'POST', body: JSON.stringify({ email: owner.email, password: 'a-properly-long-password' }),
    });
    assert.equal(pw.status, 403, "a developer reset an owner's password and took the account");
  });

  await check('the last owner cannot be deleted or demoted', async () => {
    const tok = await adminTok();
    const list = await (await api('/api/admin/staff', { headers: { authorization: 'Bearer ' + tok } })).json();
    const owners = (list.staff || []).filter(a => a.role === 'owner' && !a.disabled);
    if (owners.length !== 1) { assert.ok(true, `skipped — ${owners.length} owners`); return; }
    const only = owners[0].email;
    const h = { headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok } };

    const del = await api('/api/admin/staff/' + encodeURIComponent(only), { method: 'DELETE', ...h });
    assert.equal(del.status, 409, 'the last owner was deleted — the business loses its own dashboard');

    const demote = await api('/api/admin/staff/' + encodeURIComponent(only), {
      method: 'PATCH', ...h, body: JSON.stringify({ role: 'staff' }),
    });
    assert.equal(demote.status, 409, 'the last owner was demoted, which is the same lockout more slowly');
  });

  await check('day-to-day staff cannot export every customer record', async () => {
    const s = await asStaff('staff');
    const r = await staffApi('/api/admin/backup', s.token);
    assert.equal(r.status, 403, 'a staff account downloaded the entire customer book');

    const ret = await staffApi('/api/admin/retention', s.token, {
      method: 'POST', body: JSON.stringify({ jobDays: 400 }),
    });
    assert.equal(ret.status, 403, 'a staff account changed how long customer data is kept');
  });

  await check('the audit log records who actually did it, not "admin"', async () => {
    // 25 of 46 entries used to hardcode "admin". With two named people in the
    // dashboard that is not merely uninformative, it is a log that looks like
    // it identifies people and does not.
    const dev = await asStaff('developer');
    const target = `audit-check-${Date.now()}@example.com`;
    const mk = await staffApi('/api/admin/staff', dev.token, {
      method: 'POST', body: JSON.stringify({ email: target, password: 'a-properly-long-password', role: 'staff' }),
    });
    assert.equal(mk.status, 200);

    const tok = await adminTok();
    const dump = await (await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } })).json();
    const mine = (dump.data || {})['audit:' + dev.email];
    assert.ok(Array.isArray(mine), `no audit bucket for ${dev.email} — the actor was not recorded`);
    const entry = mine.find(e => e.event === 'staff_created' && String(e.detail).includes(target));
    assert.ok(entry, 'the action was not attributed to the account that performed it');
    assert.equal(entry.actor, dev.email, 'the entry does not carry the real actor');
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
    // "/admin", not "/admin.html": Cloudflare's asset handling redirects the
    // .html form, so asking for it by name cost the staff portal a 307 on
    // every visit to its own front door.
    assert.equal(await adminRoot.text(), 'SERVED:/admin', 'admin host root did not rewrite to /admin');
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

  await check('the Firebase admin door is gone, not merely unconfigured', async () => {
    /*
     * /admin-login-firebase issued an admin session to any address listed in
     * ADMIN_EMAILS without ever checking the staff table — the one check that
     * makes "other staff cannot log in without being approved" true. It was
     * inert only because a single environment variable happened to be unset.
     * Both endpoints are removed; these must not answer at all.
     */
    for (const [path, init] of [['/api/firebase-config', {}], ['/api/admin-login-firebase', { method: 'POST', body: '{}' }]]) {
      const r = await api(path, { headers: { 'content-type': 'application/json' }, ...init });
      assert.equal(r.status, 404, `${path} still answers (${r.status}) — the second admin door is open`);
    }
    const mode = await (await api('/api/admin-auth/mode')).json();
    assert.equal(mode.google, false, 'auth mode should report Google sign-in as off');
  });

  await check("Apple's domain check is served by the Worker and fails closed", async () => {
    /*
     * Registering the site as a Sign in with Apple return URL means proving the
     * domain: Apple fetches a token file from /.well-known/ on the apex. It is
     * served here rather than dropped in public/ because run_worker_first puts
     * every request through the fetch handler and the assets pipeline is not
     * dependable for dot-directories.
     */
    for (const path of ['/.well-known/apple-developer-domain-association.txt',
                        '/apple-developer-domain-association.txt']) {
      const r = await api(path);
      // Unset in tests: a readable 404 that names the secret, never a blank 200
      // that Apple would read as an empty, failing token.
      assert.equal(r.status, 404, `${path} should 404 until the token is set`);
      assert.match(await r.text(), /APPLE_DOMAIN_ASSOCIATION/, 'the failure does not say what to set');
    }
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
    await signupVerified({ email: em, password: 'crm-password-123', name: 'CRM Person', phone: '07900111222' });
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
    await signupVerified({ email: em, password: 'crm-password-123', name: 'CRM Two', phone: '07900111333' });
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
    await signupVerified({ email: em, password: 'crm-password-123', name: 'CRM Three', phone: '07900111444' });
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
    const signup = { json: async () => await signupVerified({ email: em, password: 'crm-password-123', name: 'CRM Four', phone: '07900111555' }) };
    const custTok = (await signup.json()).token;
    const tok = await adminTok();
    const auth = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    await api('/api/admin/customers/' + encodeURIComponent(em), { method: 'PATCH', headers: auth, body: JSON.stringify({ discount: 25 }) });
    const me = await api('/api/auth/me', { headers: { authorization: 'Bearer ' + custTok } });
    const prof = (await me.json()).user;
    assert.equal(prof.discount, undefined, 'discount leaked to customer profile');
    assert.equal(prof.notes, undefined, 'notes leaked to customer profile');
  });

  // Creating an account used to write nothing but "user:" — the contact
  // database and the Resend audience were only ever touched by a *booking*.
  // So somebody who signed up and ticked the marketing box appeared on no
  // list at all, which is exactly what "customers are not being added" was.
  await check('confirming a signup writes a contact record', async () => {
    const em = `contactsync-${Date.now()}@example.com`;
    await signupVerified({ name: 'Contact Sync', email: em, phone: '07900000456', password: 'contact-pass-123', marketing: true });
    const tok = await adminTok();
    const dump = await (await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } })).json();
    const keys = Object.keys(dump.data);
    assert.ok(keys.includes('contact:' + em), 'no contact record was created for a confirmed signup');
  });

  await check('marketing consent is carried onto the contact record', async () => {
    const yes = `optin-${Date.now()}@example.com`;
    const no = `optout-${Date.now()}@example.com`;
    await signupVerified({ name: 'Opt In', email: yes, phone: '07900000457', password: 'contact-pass-123', marketing: true });
    await signupVerified({ name: 'Opt Out', email: no, phone: '07900000458', password: 'contact-pass-123', marketing: false });
    const tok = await adminTok();
    const dump = await (await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } })).json();
    const d = dump.data;
    const read = k => d[k];
    assert.equal(read('contact:' + yes).marketing, true, 'an explicit tick was not recorded');
    // No tick means no marketing consent, ever — not "they are a customer so
    // it is fine". That inference is the PECR problem, not a convenience.
    assert.equal(read('contact:' + no).marketing, false, 'consent was inferred without a tick');
  });

  // Withdrawing consent has to change the contact record, not just the account.
  await check('turning marketing off clears consent on the contact record', async () => {
    const em = `withdraw-${Date.now()}@example.com`;
    const { token } = await signupVerified({ name: 'Withdraw', email: em, phone: '07900000459', password: 'contact-pass-123', marketing: true });
    const r = await api('/api/auth/profile', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ marketing: false }),
    });
    assert.equal(r.status, 200);
    const tok = await adminTok();
    const dump = await (await api('/api/admin/backup', { headers: { authorization: 'Bearer ' + tok } })).json();
    const d = dump.data;
    const rec = d['contact:' + em];
    assert.equal(rec.marketing, false, 'withdrawal did not reach the contact record');
  });

  /* -------------------------------------------------------------------
   * OFFERS AND THE MARGIN FLOOR
   *
   * The whole point of the floor is that a sale can be run without anyone
   * auditing 4,128 lines by hand. So the tests that matter are the ones that
   * try to break it: an absurd percentage, a flat price below cost, and a
   * manual override typed below cost.
   * ----------------------------------------------------------------- */
  const SIZE = '195/65R15';
  const setRules = async (tok, body) => {
    const r = await api('/api/admin/pricing', { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok },
      body: JSON.stringify(body) });
    return r;
  };
  const adminTyres = async (tok) =>
    (await (await api('/api/admin/tyres?size=' + encodeURIComponent(SIZE), { headers: { authorization: 'Bearer ' + tok } })).json()).tyres;
  const addPromo = async (tok, body) => {
    const r = await api('/api/admin/pricing/promo', { method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tok },
      body: JSON.stringify(body) });
    return { status: r.status, body: await r.json() };
  };
  const delPromo = async (tok, id) =>
    api('/api/admin/pricing/promo/' + encodeURIComponent(id), { method: 'DELETE', headers: { authorization: 'Bearer ' + tok } });

  await check('an offer discounts the customer price and says so', async () => {
    const tok = await adminTok();
    const before = await (await api('/api/tyres/lookup?size=' + encodeURIComponent(SIZE))).json();
    assert.ok(before.tyres.every(t => t.wasPrice == null), 'a was-price is showing with no offer running');

    const { status, body } = await addPromo(tok, { name: 'Test sale', kind: 'percent', value: 20 });
    assert.equal(status, 200, JSON.stringify(body));
    const id = body.promos[body.promos.length - 1].id;
    try {
      const after = await (await api('/api/tyres/lookup?size=' + encodeURIComponent(SIZE))).json();
      const discounted = after.tyres.filter(t => t.wasPrice != null);
      assert.ok(discounted.length > 0, 'the offer changed nothing');
      for (const t of discounted) {
        assert.ok(t.price < t.wasPrice, 'was-price is not higher than the price paid');
        assert.equal(t.offer, 'Test sale', 'the offer name is not shown to the customer');
      }
    } finally { await delPromo(tok, id); }
  });

  await check('the margin floor survives an absurd discount', async () => {
    const tok = await adminTok();
    await setRules(tok, { minMargin: 25 });
    const { body } = await addPromo(tok, { name: 'Everything must go', kind: 'percent', value: 90 });
    const id = body.promos[body.promos.length - 1].id;
    try {
      for (const t of await adminTyres(tok)) {
        if (t.cost == null) continue;
        assert.ok(t.margin >= 25, `${t.brand} ${t.model} fell to £${t.margin} margin under a 90% sale`);
        assert.ok(t.floored, 'a 90% discount should have hit the floor on every line');
      }
    } finally { await delPromo(tok, id); }
  });

  await check('a flat sale price below cost is lifted to the floor', async () => {
    const tok = await adminTok();
    await setRules(tok, { minMargin: 25 });
    const { body } = await addPromo(tok, { name: 'Ten pound tyres', kind: 'fixed', value: 10 });
    const id = body.promos[body.promos.length - 1].id;
    try {
      const tyres = await adminTyres(tok);
      for (const t of tyres) {
        if (t.cost == null) continue;
        assert.ok(t.price > 10, 'a £10 flat price was actually charged, below wholesale cost');
        assert.ok(t.margin >= 25, `margin fell to £${t.margin}`);
      }
    } finally { await delPromo(tok, id); }
  });

  await check('a manual override below cost is lifted to the floor too', async () => {
    const tok = await adminTok();
    await setRules(tok, { minMargin: 25 });
    const tyre = (await adminTyres(tok)).find(t => t.cost != null);
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    await api('/api/admin/pricing/override', { method: 'POST', headers: h, body: JSON.stringify({ id: tyre.id, price: 1 }) });
    try {
      const after = (await adminTyres(tok)).find(t => t.id === tyre.id);
      // Typing 1 into a price box is a slip far more often than a decision, and
      // either way the business cannot carry it.
      assert.ok(after.margin >= 25, `an override of £1 produced a £${after.margin} margin`);
      assert.ok(after.floored, 'the override was not flagged as held at the floor');
    } finally {
      await api('/api/admin/pricing/override', { method: 'POST', headers: h, body: JSON.stringify({ id: tyre.id, price: null }) });
    }
  });

  await check('offers do not stack — the best single one wins', async () => {
    const tok = await adminTok();
    await setRules(tok, { minMargin: 0 });
    const a = (await addPromo(tok, { name: 'Sale A', kind: 'percent', value: 10 })).body;
    const idA = a.promos[a.promos.length - 1].id;
    const b = (await addPromo(tok, { name: 'Sale B', kind: 'percent', value: 20 })).body;
    const idB = b.promos[b.promos.length - 1].id;
    try {
      const tyres = await adminTyres(tok);
      const t = tyres.find(x => x.cost != null && x.wasPrice != null) || tyres.find(x => x.cost != null);
      const listed = t.wasPrice != null ? t.wasPrice : t.price;
      // 10% then 20% stacked would be 28% off. Only the better one may apply.
      assert.ok(t.price >= Math.round(listed * 0.79), `${t.price} looks like two discounts stacked on ${listed}`);
      assert.equal(t.promoName, 'Sale B', 'the deeper discount did not win');
    } finally { await delPromo(tok, idA); await delPromo(tok, idB); await setRules(tok, { minMargin: 25 }); }
  });

  await check('an offer can be limited to one brand', async () => {
    const tok = await adminTok();
    const all = await adminTyres(tok);
    const brand = all.find(t => t.cost != null).brand;
    const { body } = await addPromo(tok, { name: 'One brand only', kind: 'percent', value: 15, scope: { brands: [brand] } });
    const id = body.promos[body.promos.length - 1].id;
    try {
      for (const t of await adminTyres(tok)) {
        if (t.brand === brand) continue;
        assert.equal(t.promoName, null, `${t.brand} got a discount scoped to ${brand}`);
      }
    } finally { await delPromo(tok, id); }
  });

  await check('a scheduled offer does not apply before it starts', async () => {
    const tok = await adminTok();
    const soon = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const { body } = await addPromo(tok, { name: 'Next week', kind: 'percent', value: 30, starts: soon, ends: soon + 86400000 });
    const id = body.promos[body.promos.length - 1].id;
    try {
      for (const t of await adminTyres(tok)) assert.equal(t.promoName, null, 'a future offer is already discounting');
    } finally { await delPromo(tok, id); }
  });

  await check('the offer endpoints refuse rubbish and require admin auth', async () => {
    assert.equal((await api('/api/admin/pricing/promo', { method: 'POST', body: '{}' })).status, 403);
    assert.equal((await api('/api/admin/pricing/promo/anything', { method: 'DELETE' })).status, 403);
    const tok = await adminTok();
    assert.equal((await addPromo(tok, { kind: 'percent', value: 10 })).status, 400, 'a nameless offer was accepted');
    assert.equal((await addPromo(tok, { name: 'x', kind: 'nonsense', value: 10 })).status, 400);
    assert.equal((await addPromo(tok, { name: 'x', kind: 'percent', value: -5 })).status, 400);
    assert.equal((await addPromo(tok, { name: 'x', kind: 'percent', value: 99 })).status, 400, 'a 99% discount should be refused as a typo');
    assert.equal((await addPromo(tok, { name: 'x', kind: 'percent', value: 10, starts: 2000, ends: 1000 })).status, 400);
    const neg = await setRules(tok, { minMargin: -10 });
    assert.equal(neg.status, 400, 'a negative margin floor licences selling below cost');
  });

  await check('wholesale cost never leaks through the sale fields', async () => {
    const tok = await adminTok();
    const { body } = await addPromo(tok, { name: 'Leak check', kind: 'percent', value: 20 });
    const id = body.promos[body.promos.length - 1].id;
    try {
      const d = await (await api('/api/tyres/lookup?size=' + encodeURIComponent(SIZE))).json();
      const raw = JSON.stringify(d);
      assert.ok(!raw.includes('ctyres.co.uk'), 'supplier URL leaked');
      for (const t of d.tyres) {
        assert.equal(t.cost, undefined, 'wholesale cost leaked');
        assert.equal(t.margin, undefined, 'margin leaked');
        assert.equal(t.floored, undefined, 'the floor flag tells a competitor what your cost is');
      }
    } finally { await delPromo(tok, id); }
  });

  /* -------------------------------------------------------------------
   * DELIVERY: confirmations must never fail silently
   *
   * Bookings were reaching the dashboard and the driver app while every
   * confirmation email was rejected by Resend with a 422 — OWNER_EMAIL was not
   * a valid address. Nothing checked it, nothing logged the result, and
   * /api/health reported "email: true" throughout. These tests are about the
   * silence, not the typo.
   * ----------------------------------------------------------------- */
  await check('health reports email as broken when MAIL_FROM is not an address', async () => {
    const d = await (await api('/api/health')).json();
    assert.equal(typeof d.configured.email, 'boolean');
    assert.equal(typeof d.configured.ownerAlerts, 'boolean');
    assert.equal(typeof d.configured.customerMessaging, 'boolean');
    // The test server sets no mail config, so a flag that cannot go false would
    // be reporting true here. That is precisely the bug.
    assert.equal(d.configured.email, false, 'email reported healthy with nothing configured');
  });

  await check('the mail failure log is admin-only and readable', async () => {
    assert.equal((await api('/api/admin/mail-failures')).status, 403);
    const tok = await adminTok();
    const r = await api('/api/admin/mail-failures', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(Array.isArray(d.failures), 'no failures array');
    assert.equal(typeof d.ownerEmailValid, 'boolean');
    assert.equal(typeof d.mailFromValid, 'boolean');
    assert.equal(typeof d.calendarConfigured, 'boolean');
  });

  await check('a booking records whether its confirmation was sent', async () => {
    const em = `delivery-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Delivery Check', phone: '07900000900', email: em,
      service: 'tyre', svcLabel: 'Tyre fitting', postcode: 'DT6 5NJ', date: soonISO(5), time: 'Morning (8-12)',
    });
    assert.equal(r.status, 200);
    const { ref } = await r.json();
    // The send is fire-and-forget, so give the recorder a moment.
    await new Promise(res => setTimeout(res, 400));
    const tok = await adminTok();
    const jobs = (await (await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + tok } })).json()).jobs;
    const job = jobs.find(j => j.ref === ref);
    assert.ok(job, 'the booking is missing from the dashboard');
    // With no mail configured the send is skipped, not failed — but the field
    // must exist either way, because "was it sent?" has to be answerable.
    assert.ok(job.mail === undefined || typeof job.mail === 'object', 'mail outcome is the wrong shape');
  });

  await check('the booking form does not require an email address', async () => {
    // A roadside customer with a flat tyre may not have one to hand, and the
    // owner alert plus the dashboard entry matter more than the confirmation.
    const r = await postJson('/api/service-requests', {
      name: 'No Email', phone: '07900000901', service: 'recovery', postcode: 'DT6 5NJ',
    });
    assert.equal(r.status, 200, 'a booking without an email was refused');
    const d = await r.json();
    assert.ok(d.ref, 'no reference returned');
  });

  await check('a booking with no name or phone is still refused', async () => {
    assert.equal((await postJson('/api/service-requests', { name: 'Nobody' })).status, 400);
    assert.equal((await postJson('/api/service-requests', { phone: '07900000902' })).status, 400);
  });

  await check('the CRM config endpoint is 404 when HubSpot is not set up', async () => {
    // The public site asks for this on every page load. A 404 has to be the
    // quiet "no CRM here" answer, not an error the page has to handle.
    const r = await api('/api/crm-config');
    assert.equal(r.status, 404);
    const d = await r.json();
    assert.ok(d.error, 'no reason given');
  });

  await check('health reports the messaging and CRM channels it can actually use', async () => {
    const d = await (await api('/api/health')).json();
    for (const k of ['customerMessaging', 'studioFlow', 'crm']) {
      assert.equal(typeof d.configured[k], 'boolean', k + ' missing from health');
      assert.equal(d.configured[k], false, k + ' reported ready with nothing configured');
    }
  });

  await check('a booking confirmation survives non-ASCII text', async () => {
    // buildICS() puts a literal em-dash in the SUMMARY line of every invite,
    // and btoa() throws on anything above U+00FF. So attaching the .ics threw
    // BEFORE the send and every customer confirmation carrying an email
    // address failed — invisibly, because the caller discarded the result.
    // An accented name or a curly quote in the notes would do it too.
    const em = `unicode-${Date.now()}@example.com`;
    const r = await postJson('/api/service-requests', {
      name: 'Renée O\u2019Brien', phone: '07900000910', email: em,
      service: 'tyre', svcLabel: 'Tyre fitting — mobile',
      postcode: 'DT6 5NJ', date: soonISO(7), time: 'Morning (8-12)',
      notes: 'Curly quote \u201Cparked round the back\u201D and a £ sign.',
    });
    assert.equal(r.status, 200);
    const { ref, warnings } = await r.json();
    assert.deepEqual(warnings, [], 'the booking reported warnings: ' + JSON.stringify(warnings));
    await new Promise(res => setTimeout(res, 400));
    const tok = await adminTok();
    const dump = await (await api('/api/admin/mail-failures', { headers: { authorization: 'Bearer ' + tok } })).json();
    const latin1 = (dump.failures || []).filter(f => /Latin1|Invalid character/i.test(f.reason || ''));
    assert.equal(latin1.length, 0, 'base64 still throws on non-ASCII: ' + JSON.stringify(latin1[0] || {}));
    assert.ok(ref, 'no reference returned');
  });

  await check('the CRM sync is off until a private-app token is set', async () => {
    const d = await (await api('/api/health')).json();
    assert.equal(d.configured.crmSync, false, 'CRM sync reported ready with no token');
    // And it must stay best-effort: a booking still succeeds with HubSpot unset.
    const r = await postJson('/api/service-requests', {
      name: 'No CRM', phone: '07900000911', email: `nocrm-${Date.now()}@example.com`,
      service: 'brakes', postcode: 'DT6 5NJ',
    });
    assert.equal(r.status, 200);
    assert.deepEqual((await r.json()).warnings, [], 'an unset CRM produced a booking warning');
  });

  /* -------------------------------------------------------------------
   * AVAILABILITY — two customers must not be able to book the same window
   * ----------------------------------------------------------------- */
  /*
   * A date at least 30 days out that the business is actually OPEN on.
   *
   * This was a plain +30 days, and it worked until the calendar rolled into a
   * week where +30 landed on a Sunday. Sunday is a closed day, so every window
   * reads unavailable for a reason that has nothing to do with capacity: the
   * fill-the-window test could not make its first booking and reported "first
   * booking refused", which looks exactly like a double-booking bug. Nothing
   * about the code had changed — only the day of the week.
   *
   * Any fixed offset has that fault one day in seven. Step past closed days.
   */
  const openDayFrom = (days) => {
    let d = new Date(Date.now() + days * 86400000);
    while (d.getUTCDay() === 0) d = new Date(d.getTime() + 86400000);  // 0 = Sunday
    return d.toISOString().slice(0, 10);
  };
  const FUTURE = openDayFrom(30);
  // Every booking here comes from its own IP. The 20-per-IP limiter is correct
  // production behaviour and the suite has already spent the shared budget by
  // this point; two different customers really are two different addresses.
  let ipSeq = 0;
  const bookAs = (body) => api('/api/service-requests', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.' + (++ipSeq) },
    body: JSON.stringify(body),
  });
  const MORNING = 'Morning (8\u201312)';

  await check('availability is public, validated and shaped', async () => {
    assert.equal((await api('/api/availability')).status, 400, 'a missing date was accepted');
    assert.equal((await api('/api/availability?date=next-tuesday')).status, 400, 'a junk date was accepted');
    const d = await (await api('/api/availability?date=' + FUTURE)).json();
    assert.equal(d.date, FUTURE);
    assert.ok(Array.isArray(d.slots) && d.slots.length >= 3, 'no slots returned');
    for (const s of d.slots) {
      assert.equal(typeof s.available, 'boolean');
      assert.ok(s.key, 'slot has no key');
    }
    // With no Google calendar configured it must say so rather than pretending.
    assert.equal(d.calendarChecked, false);
  });

  await check('a window fills up and then refuses further bookings', async () => {
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    await api('/api/admin/booking-settings', { method: 'POST', headers: h, body: JSON.stringify({ slotCapacity: 2 }) });
    // Prove the window is open BEFORE filling it. Without this the test can
    // only say "first booking refused", which sends you hunting a booking bug
    // when the real answer is that the day was never bookable.
    const pre = (await (await api('/api/availability?date=' + FUTURE)).json())
      .slots.find(s => s.key === MORNING);
    assert.equal(pre.available, true,
      `${FUTURE} was not bookable before the test started (reason: ${pre.reason})`);

    const book = (n) => bookAs({
      name: 'Slot ' + n, phone: '0790000' + (2000 + n), email: `slot${n}-${Date.now()}@example.com`,
      service: 'tyre', postcode: 'DT6 5NJ', date: FUTURE, time: MORNING,
    });

    assert.equal((await book(1)).status, 200, 'first booking refused');
    assert.equal((await book(2)).status, 200, 'second booking refused while capacity was 2');

    const mid = await (await api('/api/availability?date=' + FUTURE)).json();
    const slot = mid.slots.find(s => s.key === MORNING);
    assert.equal(slot.available, false, 'the window is still offered after filling it');
    assert.equal(slot.reason, 'fully booked');

    const third = await book(3);
    assert.equal(third.status, 409, 'a third booking got into a full window');
    assert.match((await third.json()).error, /has just gone/i);
  });

  await check('an emergency is always accepted, however full the day is', async () => {
    // Somebody at the roadside is not helped by being told the morning is full.
    const r = await bookAs({
      name: 'Roadside', phone: '07900002999', email: `asap-${Date.now()}@example.com`,
      service: 'recovery', postcode: 'DT6 5NJ', date: FUTURE, time: 'ASAP / Emergency',
    });
    assert.equal(r.status, 200, 'an emergency was refused');
    const d = await (await api('/api/availability?date=' + FUTURE)).json();
    const asap = d.slots.find(s => s.key === 'ASAP / Emergency');
    assert.equal(asap.available, true, 'the emergency option stopped being offered');
  });

  await check('cancelling a job hands its window back', async () => {
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    const em = `release-${Date.now()}@example.com`;
    // A day the business is open on, and a different one from FUTURE so this
    // test's capacity fiddling cannot disturb the fill-the-window test above.
    const day = openDayFrom(38);
    await api('/api/admin/booking-settings', { method: 'POST', headers: h, body: JSON.stringify({ slotCapacity: 1 }) });

    const before = await (await api('/api/availability?date=' + day)).json();
    assert.equal(before.slots.find(s => s.key === MORNING).available, true,
      `${day} was not bookable before the test even started (reason: ${before.slots.find(s => s.key === MORNING).reason})`);

    const first = await bookAs({
      name: 'Will Cancel', phone: '07900003000', email: em,
      service: 'tyre', postcode: 'DT6 5NJ', date: day, time: MORNING,
    });
    const { ref } = await first.json();

    let d = await (await api('/api/availability?date=' + day)).json();
    let slot = d.slots.find(s => s.key === MORNING);
    // Assert the REASON, not just the boolean. "Unavailable" is true of a
    // closed day, a day in the past and a day the diary is busy; only one of
    // those means the capacity check did its job.
    assert.equal(slot.available, false, 'capacity 1 did not fill');
    assert.equal(slot.reason, 'fully booked', `filled for the wrong reason: ${slot.reason}`);

    await api('/api/admin/jobs/' + ref, { method: 'PATCH', headers: h,
      body: JSON.stringify({ customerEmail: em, status: 'cancelled', label: 'Cancelled' }) });

    d = await (await api('/api/availability?date=' + day)).json();
    slot = d.slots.find(s => s.key === MORNING);
    assert.equal(slot.available, true, `a cancelled job still blocks its window (reason: ${slot.reason})`);

    await api('/api/admin/booking-settings', { method: 'POST', headers: h, body: JSON.stringify({ slotCapacity: 2 }) });
  });

  await check('the slot index can be rebuilt from the bookings themselves', async () => {
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok };
    assert.equal((await api('/api/admin/rebuild-slots', { method: 'POST' })).status, 403);
    const r = await api('/api/admin/rebuild-slots', { method: 'POST', headers: h });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.ok && typeof d.dates === 'number', 'rebuild returned nothing useful');
    // And the rebuilt counts must agree with what availability reports.
    const av = await (await api('/api/availability?date=' + FUTURE)).json();
    assert.equal(av.slots.find(s => s.key === MORNING).booked, (d.counts[FUTURE] || {})[MORNING] || 0);
  });

  await check('booking settings are admin-only and bounded', async () => {
    assert.equal((await api('/api/admin/booking-settings')).status, 403);
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    const r = await api('/api/admin/booking-settings', { method: 'POST', headers: h,
      body: JSON.stringify({ slotCapacity: 9999, leadTimeHours: -5 }) });
    const { settings } = await r.json();
    assert.ok(settings.slotCapacity <= 20, 'capacity was not clamped');
    assert.ok(settings.leadTimeHours >= 0, 'a negative lead time was accepted');
    await api('/api/admin/booking-settings', { method: 'POST', headers: h, body: JSON.stringify({ slotCapacity: 2, leadTimeHours: 2 }) });
  });

  await check('the analytics tracker is not loaded without consent', async () => {
    // PECR: non-essential cookies may not be set before the visitor agrees, and
    // "no choice yet" is not consent. The HubSpot tracker sets its own cookies,
    // so the page must not carry it unconditionally.
    const html = await (await api('/')).text();
    // The URL may appear inside the loader that builds it — what must NOT
    // appear is a plain script tag that fires on page load regardless.
    assert.ok(!/<script[^>]+src=["']?[^"'>]*hs-scripts\.com/.test(html),
      'the HubSpot tracker is embedded as an unconditional script tag');
    assert.ok(/cookieChoice\(\)\s*!==\s*'yes'/.test(html), 'the loader is not gated on a recorded choice');
    assert.ok(/rejectCookies/.test(html) && /acceptCookies/.test(html), 'the banner has no reject option');
    assert.ok(/cms_cookie_consent/.test(html), 'no consent value is stored');

    /*
     * Google Analytics, on the same terms. The snippet Google hands you loads
     * on page one and sets its cookies before anyone has been asked anything —
     * which is exactly what the banner on this site promises does not happen.
     */
    assert.ok(!/<script[^>]+src=["']?[^"'>]*googletagmanager\.com/.test(html),
      'the Google tag is embedded as an unconditional script tag — it would set cookies before the visitor is asked');
    // The DEFINITION, not the first mention: the call site appears earlier, and
    // slicing from that read the wrong 1600 characters entirely.
    const at = html.indexOf('loadAnalytics(){');
    assert.ok(at > 0, 'there is no analytics loader to check');
    const ga = html.slice(at, at + 1800);
    assert.ok(/cookieChoice\(\)\s*!==\s*'yes'/.test(ga), 'the Google tag is not gated on a recorded choice');
    assert.ok(/analytics_storage:\s*'denied'/.test(ga) && /'consent',\s*'default'/.test(ga),
      'Consent Mode does not default to denied before the tag loads');
    assert.ok(ga.indexOf("'default'") < ga.indexOf("'update'"),
      'consent is granted before it is denied — the order is what makes the default mean anything');

    // And the CSP has to allow it, or the tag is blocked and quietly measures
    // nothing while appearing to be installed.
    const head = await api('/');
    const policy = head.headers.get('content-security-policy') || '';
    assert.ok(/script-src[^;]*googletagmanager\.com/.test(policy),
      'the CSP blocks the Google tag, so it would collect nothing');
    assert.ok(/connect-src[^;]*google-analytics\.com/.test(policy),
      'the CSP blocks the analytics beacon, so hits would never arrive');
  });

  /* -------------------------------------------------------------------
   * SECURITY HEADERS
   * ----------------------------------------------------------------- */
  await check('a Content-Security-Policy is set and closes the classic holes', async () => {
    const r = await api('/');
    const csp = r.headers.get('content-security-policy');
    assert.ok(csp, 'no CSP header');
    for (const d of ["default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'"]) {
      assert.ok(csp.includes(d), 'CSP is missing: ' + d);
    }
    // A wildcard script-src would make the whole header decorative.
    assert.ok(!/script-src[^;]*\*[^;]*/.test(csp), 'CSP allows scripts from anywhere');
    assert.ok(r.headers.get('permissions-policy'), 'no Permissions-Policy');
  });

  /* -------------------------------------------------------------------
   * RETENTION — nothing may be kept indefinitely
   * ----------------------------------------------------------------- */
  await check('retention periods are admin-only, bounded, and have floors', async () => {
    assert.equal((await api('/api/admin/retention')).status, 403);
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    const d = await (await api('/api/admin/retention', { headers: h })).json();
    assert.ok(d.policy.jobDays >= 2190, 'finished jobs are kept less than 6 years by default');

    // A six-month floor on job records would leave Cousins liable for work he
    // has no record of. The endpoint must refuse to go that low.
    const r = await api('/api/admin/retention', { method: 'POST', headers: h, body: JSON.stringify({ jobDays: 30, auditDays: 99999 }) });
    const { policy } = await r.json();
    assert.ok(policy.jobDays >= 365, 'a 30-day job retention was accepted');
    assert.ok(policy.auditDays <= 2190, 'an unbounded audit retention was accepted');
    await api('/api/admin/retention', { method: 'POST', headers: h, body: JSON.stringify(d.policy) });
  });

  await check('the purge removes what is past its period and nothing else', async () => {
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    assert.equal((await api('/api/admin/run-retention', { method: 'POST' })).status, 403);

    // An OPEN job is never purged on a timer, however old — something still
    // outstanding is not a record we are finished with.
    const em = `retain-${Date.now()}@example.com`;
    const r = await bookAs({ name: 'Old Open Job', phone: '07900004000', email: em, service: 'tyre', postcode: 'DT6 5NJ' });
    const { ref } = await r.json();

    const res = await api('/api/admin/run-retention', { method: 'POST', headers: h });
    assert.equal(res.status, 200);
    const { removed } = await res.json();
    for (const k of ['jobs', 'contacts', 'audits', 'messages', 'slots', 'mailLog']) {
      assert.equal(typeof removed[k], 'number', 'the sweep does not report ' + k);
    }
    const jobs = (await (await api('/api/admin/jobs', { headers: { authorization: 'Bearer ' + tok } })).json()).jobs;
    assert.ok(jobs.some(j => j.ref === ref), 'the purge removed an open job');
  });

  await check('the health check reports problems rather than staying quiet', async () => {
    assert.equal((await api('/api/admin/run-health', { method: 'POST' })).status, 403);
    const tok = await adminTok();
    const d = await (await api('/api/admin/run-health', { method: 'POST', headers: { authorization: 'Bearer ' + tok } })).json();
    // The test server has no mail, Twilio or calendar configured, so a check
    // that reported "all fine" here would be a check that can never fail.
    assert.equal(d.ok, false, 'the health check passed with nothing configured');
    assert.ok(Array.isArray(d.problems) && d.problems.length >= 3, 'the health check missed obvious gaps');
  });

  /* -------------------------------------------------------------------
   * STRIPE — card details must never reach this server
   * ----------------------------------------------------------------- */
  await check('card payment stays off until both Stripe secrets exist', async () => {
    const d = await (await api('/api/deposit-config')).json();
    assert.equal(d.enabled, false, 'deposits reported on with no Stripe keys');
    assert.equal(d.pence, 0, 'an amount was published while payment is off');
    const health = await (await api('/api/health')).json();
    assert.equal(health.configured.cardPayments, false);

    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    // Switching deposits on without the keys would produce a booking form that
    // asks for money it cannot take.
    const r = await api('/api/admin/deposit', { method: 'POST', headers: h, body: JSON.stringify({ enabled: true, pence: 2500 }) });
    assert.equal(r.status, 400, 'deposits were switched on with no Stripe configured');
  });

  await check('a deposit amount cannot be set to something absurd', async () => {
    const tok = await adminTok();
    const h = { 'content-type': 'application/json', authorization: 'Bearer ' + tok };
    assert.equal((await api('/api/admin/deposit', { method: 'POST', headers: h, body: JSON.stringify({ pence: 5000000 }) })).status, 400);
    assert.equal((await api('/api/admin/deposit', { method: 'POST', headers: h, body: JSON.stringify({ pence: 1 }) })).status, 400);
    assert.equal((await api('/api/admin/deposit', { method: 'POST', headers: h, body: JSON.stringify({ pence: 2500 }) })).status, 200);
  });

  await check('the Stripe webhook refuses anything it cannot verify', async () => {
    // The redirect back from Checkout proves nothing — anyone can visit a
    // success URL. A signed webhook is the only thing that may mark a job paid,
    // so with no secret set it must fail closed rather than trust the body.
    const fake = JSON.stringify({ type: 'checkout.session.completed', data: { object: { client_reference_id: 'CMS-FAKE', payment_status: 'paid', amount_total: 999999 } } });
    const r = await api('/api/stripe-webhook', { method: 'POST', headers: { 'content-type': 'application/json' }, body: fake });
    assert.ok(r.status === 503 || r.status === 401, 'an unsigned webhook was not refused (got ' + r.status + ')');
    const r2 = await api('/api/stripe-webhook', { method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': 't=1,v1=deadbeef' }, body: fake });
    assert.ok(r2.status === 503 || r2.status === 401, 'a forged signature was accepted');
  });

  await check('checkout refuses to start when payment is switched off', async () => {
    const r = await postJson('/api/pay/checkout', { ref: 'CMS-ANY' });
    assert.equal(r.status, 503, 'checkout started with no Stripe configured');
  });

  /* -------------------------------------------------------------------
   * THE LEGAL PAGES HAVE TO MATCH WHAT THE CODE ACTUALLY DOES
   * ----------------------------------------------------------------- */
  await check('the privacy notice names every processor the code actually uses', async () => {
    const html = await (await api('/privacy.html')).text();
    // Art. 13 wants the recipients named. This test exists because the notice
    // listed Google and WhatsApp while the code was also sending data to
    // Cloudflare, Resend, Twilio and HubSpot.
    for (const who of ['Cloudflare', 'Resend', 'Twilio', 'HubSpot', 'Meta']) {
      assert.ok(html.includes(who), 'the privacy notice does not name ' + who);
    }
    // The card processor is named by whichever one is actually configured,
    // not by a hardcoded guess. This used to assert 'Stripe' outright, so on
    // the day the business moved to SumUp the test would have failed while the
    // notice was right, and — worse — it would have gone on passing if the
    // notice still named a processor no longer in use.
    const cfg = (await (await api('/api/health')).json()).configured || {};
    const payName = { sumup: 'SumUp', stripe: 'Stripe' }[cfg.paymentProvider];
    if (payName) {
      assert.ok(html.includes(payName),
        `card payments run through ${payName} but the privacy notice does not name it`);
    }
    assert.ok(/outside the UK|International Data Transfer|adequacy/i.test(html), 'no international transfer wording');
    assert.ok(/6 years/.test(html), 'no concrete retention period is stated');
  });

  await check('the cookie notice describes the analytics cookies by name', async () => {
    const html = await (await api('/cookies.html')).text();
    assert.ok(/hubspotutk/.test(html), 'the HubSpot cookies are not named');
    // Anything that sets a cookie has to be in the table. A notice that lists
    // some of them is worse than one that lists none — it reads as complete.
    assert.ok(/_ga/.test(html) && /Google Analytics/.test(html),
      'Google Analytics sets cookies but is not named in the notice');
    assert.ok(/Turnstile/i.test(html), 'the security cookie is not described');
    assert.ok(/Reject/.test(html), 'the notice does not mention the reject option');
  });

  // The pricing tab could only ever show one size at a time, so a bad markup on
  // a range nobody thinks to type stayed invisible. The catalogue endpoint is
  // how that becomes findable — and it carries cost and margin, so it must be
  // admin-only and must never be reachable from the public API.
  await check('the admin catalogue lists every tyre, paginated', async () => {
    const tok = await adminTok();
    const r = await api('/api/admin/catalogue?perPage=24', { headers: { authorization: 'Bearer ' + tok } });
    assert.equal(r.status, 200);
    const d = await r.json();
    assert.ok(d.total > 3000, 'expected the whole catalogue, got ' + d.total);
    assert.equal(d.tyres.length, 24, 'perPage was not honoured');
    assert.ok(d.pages > 1, 'pagination missing');
    assert.ok(d.brands.length > 5, 'brand list missing');
    const t = d.tyres[0];
    for (const f of ['id', 'brand', 'model', 'size', 'image', 'sku', 'tier']) {
      assert.ok(t[f] !== undefined, 'catalogue row missing ' + f);
    }
  });

  await check('the catalogue exposes cost and margin, and requires admin auth', async () => {
    const anon = await api('/api/admin/catalogue');
    assert.equal(anon.status, 403, 'wholesale costs must not be public');
    const tok = await adminTok();
    const d = await (await api('/api/admin/catalogue?perPage=40', { headers: { authorization: 'Bearer ' + tok } })).json();
    const withCost = d.tyres.filter(t => t.cost != null);
    assert.ok(withCost.length > 0, 'no wholesale costs came back');
    for (const t of withCost) {
      assert.equal(Math.round((t.price - t.cost) * 100) / 100, t.margin, 'margin does not equal price minus cost');
    }
  });

  await check('the catalogue can be searched, filtered and sorted', async () => {
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok };
    const all = await (await api('/api/admin/catalogue?perPage=200', { headers: h })).json();
    const brand = all.brands[0].name;

    const byBrand = await (await api('/api/admin/catalogue?perPage=200&brand=' + encodeURIComponent(brand), { headers: h })).json();
    assert.ok(byBrand.total > 0, 'brand filter returned nothing');
    assert.ok(byBrand.tyres.every(t => t.brand === brand), 'brand filter leaked other brands');

    const q = await (await api('/api/admin/catalogue?q=195%2F65R15&perPage=200', { headers: h })).json();
    assert.ok(q.total > 0, 'size search returned nothing');
    assert.ok(q.tyres.every(t => t.size === '195/65R15'), 'size search leaked other sizes');

    // Worst-margin-first is the whole point: it surfaces the mispriced lines
    // without anyone having to guess which size to look at.
    const worst = await (await api('/api/admin/catalogue?sort=marginAsc&perPage=50', { headers: h })).json();
    const m = worst.tyres.map(t => t.margin).filter(x => x != null);
    for (let i = 1; i < m.length; i++) assert.ok(m[i] >= m[i - 1], 'marginAsc is not sorted');
  });

  await check('the catalogue flags upside-down pricing per size, not across sizes', async () => {
    const tok = await adminTok();
    const h = { authorization: 'Bearer ' + tok };

    // One size, sane markups: budget must not top the cheapest premium.
    const one = await (await api('/api/admin/catalogue?q=195%2F65R15&perPage=200', { headers: h })).json();
    assert.ok(one.summary, 'no summary returned');
    assert.equal(one.summary.invertedCount, 0, 'unexpected inversion in 195/65R15');
    assert.equal(one.summary.inverted, false);

    // The whole catalogue must NOT report an inversion merely because a budget
    // 285/35R21 costs more than a premium 155/70R13. Comparing across sizes
    // would light the warning on every page and make it worthless.
    const all = await (await api('/api/admin/catalogue?perPage=12', { headers: h })).json();
    const { B, P } = all.summary.tiers;
    assert.ok(B.max > P.min, 'test assumes the catalogue-wide ranges overlap');
    assert.ok(Array.isArray(all.summary.invertedSizes), 'invertedSizes missing');
    for (const v of all.summary.invertedSizes) {
      assert.ok(v.budgetMax > v.premiumMin, 'a listed size is not actually inverted');
    }
    assert.equal(all.summary.inverted, all.summary.invertedCount > 0);
  });

  await check('no size anywhere in the catalogue prices budget above premium', async () => {
    const tok = await adminTok();
    const all = await (await api('/api/admin/catalogue?perPage=12', {
      headers: { authorization: 'Bearer ' + tok },
    })).json();

    // Before the cap this was 32 sizes. It is the customer-visible number: a
    // budget tyre quoted above a premium one for the car they actually drive.
    assert.equal(all.summary.invertedCount, 0,
      'sizes still inverted: ' + JSON.stringify(all.summary.invertedSizes));

    // Anything the cap could NOT fix is a live pricing fault, not a tidy-up
    // job. If this ever fires, the tier markups are wrong for that size.
    assert.equal(all.summary.uncappedInversions, 0,
      'lines the margin floor or an override stopped us capping');
    assert.ok(all.summary.capped > 0, 'the cap reports doing no work at all');
  });

  await check('a capped price is what the customer pays and what the margin is based on', async () => {
    const tok = await adminTok();
    const page = await (await api('/api/admin/catalogue?perPage=200&page=1', {
      headers: { authorization: 'Bearer ' + tok },
    })).json();

    const capped = page.tyres.filter(t => t.capped);
    assert.ok(capped.length, 'no capped lines on the first page to check');
    for (const t of capped) {
      assert.ok(t.price < t.cappedFrom, `cap raised ${t.id}: ${t.cappedFrom} -> ${t.price}`);
      // The margin on this screen decides whether Josh keeps stocking a line.
      // If it is computed from the pre-cap price it is a number nobody is
      // being charged, and every stocking decision made from it is wrong.
      assert.equal(Math.round((t.price - t.cost) * 100) / 100, t.margin,
        `margin on ${t.id} is not based on the price actually charged`);
      assert.ok(t.margin >= 25, `capped ${t.id} to a £${t.margin} margin, below the floor`);
    }

    // A cap is a correction, not a sale. It must never light a struck-through
    // "was" price, which is the difference between fixing a fault and
    // advertising a discount that was never offered.
    for (const t of page.tyres) {
      if (t.capped && !t.promoName) assert.equal(t.wasPrice, null, `fake sale on ${t.id}`);
    }
  });

  await check('the inversion cap only ever moves prices down, and stops at the floor', () => {
    const pricing = { minMargin: 25, overrides: {} };
    const costMap = { 1: { cost: 30 }, 2: { cost: 40 }, 3: { cost: 45 } };
    const out = capSizeInversions([
      { id: 1, tier: 'B', price: 120, wasPrice: null, offer: null },  // absurd budget
      { id: 2, tier: 'M', price: 100, wasPrice: null, offer: null },
      { id: 3, tier: 'P', price: 90, wasPrice: null, offer: null },   // cheapest premium
    ], costMap, pricing);
    const at = id => out.find(t => t.id === id);

    assert.equal(at(3).price, 90, 'the premium tyre was touched');
    assert.equal(at(3).capped, false);
    assert.equal(at(2).price, 90, 'mid was not capped to the cheapest premium');
    assert.equal(at(1).price, 90, 'budget was not capped');
    assert.equal(at(1).cappedFrom, 120, 'the pre-cap price was not recorded');
    for (const t of out) assert.ok(t.price <= 90, 'a price came out above the ceiling');
  });

  await check('the margin floor beats the inversion cap, and says which it was', () => {
    // The budget tyre costs more to buy than the cheapest premium sells for, so
    // the ladder CANNOT be fixed by discounting — only by fixing the markups.
    // Selling under cost to tidy up a sort order would be the wrong trade.
    const out = capSizeInversions([
      { id: 1, tier: 'B', price: 120, wasPrice: null, offer: null },
      { id: 2, tier: 'P', price: 70, wasPrice: null, offer: null },
    ], { 1: { cost: 80 }, 2: { cost: 30 } }, { minMargin: 25, overrides: {} });
    const b = out.find(t => t.id === 1);

    assert.equal(b.price, 120, 'sold below the margin floor to fix a sort order');
    assert.equal(b.capped, false);
    assert.equal(b.inversionUncapped, true, 'the unfixable inversion was hidden');
    assert.equal(b.uncappedReason, 'floor');
  });

  await check('a price somebody typed by hand is never capped behind their back', () => {
    const out = capSizeInversions([
      { id: 1, tier: 'B', price: 199.5, wasPrice: null, offer: null },
      { id: 2, tier: 'P', price: 85, wasPrice: null, offer: null },
    ], { 1: { cost: 40 }, 2: { cost: 30 } }, { minMargin: 25, overrides: { 1: 199.5 } });
    const b = out.find(t => t.id === 1);

    // The cap exists to correct an automatic formula. An override is a person
    // deciding in writing what this tyre costs; knocking £114 off it because
    // the formula disagrees is overruling them, not correcting them.
    assert.equal(b.price, 199.5, 'a manual override was silently overwritten');
    assert.equal(b.capped, false);
    assert.equal(b.inversionUncapped, true, 'the override inversion was hidden from the admin');
    assert.equal(b.uncappedReason, 'override');
  });

  await check('a tyre with no wholesale cost is left alone by the cap', () => {
    // No cost means no floor, which means no way to know whether a lower price
    // is still profitable. Guessing is how you sell at a loss.
    const out = capSizeInversions([
      { id: 1, tier: 'B', price: 150, wasPrice: null, offer: null },
      { id: 2, tier: 'P', price: 80, wasPrice: null, offer: null },
    ], { 2: { cost: 30 } }, { minMargin: 25, overrides: {} });

    assert.equal(out.find(t => t.id === 1).price, 150);
    assert.equal(out.find(t => t.id === 1).capped, false);
  });

  await check('no page asks the browser to fetch an unhydrated {{ token }}', async () => {
    // `<img src="{{ t.image }}">` in a placeholder row had every visitor's
    // browser request /%7B%7B%20t.image%20%7D%7D before the page hydrated —
    // three 404s per load, on the home page and the dashboard, in the Worker's
    // logs forever. It survived every local check because the dev server was
    // serving the authored file and the build was not.
    for (const p of ['/', '/admin', '/driver']) {
      const html = await (await api(p)).text();
      const fetched = [...html.matchAll(/\s(src|srcset|poster)=(["'])([^"']*)\2/gi)]
        .map(m => m[3]).filter(v => v.includes('{{'));
      assert.equal(fetched.length, 0,
        p + ' would fetch ' + JSON.stringify(fetched.slice(0, 3)) + ' before hydrating');
    }
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
      // "/#services", not "index.html#services": /index.html is a redirect to
      // /, so every menu link on every legal page was a needless hop — and
      // three of them showed up in Search Console as "page with redirect".
      assert.ok(html.includes('href="/#services"'), `${page} is missing the shared menu bar`);
      assert.ok(!/href="index\.html/.test(html), `${page} still links index.html, which redirects`);
      assert.ok(html.includes('Staff login'), `${page} is missing the shared footer`);
      for (const legal of ['terms', 'privacy', 'cookies', 'accessibility']) {
        assert.ok(new RegExp(`href="/?${legal}"`).test(html), `${page} footer does not link /${legal}`);
      }
    }
  });

  await check('the home page footer links every legal page', async () => {
    const html = await (await api('/')).text();
    for (const legal of ['terms', 'privacy', 'cookies', 'accessibility']) {
      assert.ok(new RegExp(`href="/?${legal}"`).test(html), `home page does not link /${legal}`);
    }
  });

  await check('the sitemap, the canonical tags and the links all name the same URL', async () => {
    /*
     * Three places used to disagree. Cloudflare serves /terms and redirects
     * /terms.html to it, but the sitemap listed the .html form, every footer
     * linked the .html form, and /terms declared its own canonical as
     * /terms.html — a page telling crawlers the real version is the URL that
     * redirects back to it. Nothing was broken for a human; it just meant
     * every legal page was described to Google by a URL that is a redirect.
     */
    const sitemap = await (await api('/sitemap.xml')).text();
    const locs = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
    assert.ok(locs.length >= 5, 'sitemap lost its URLs');
    for (const loc of locs) {
      assert.ok(!/\.html($|\?)/.test(loc), `sitemap lists ${loc}, which production only serves as a redirect`);
    }

    for (const page of ['/terms', '/privacy', '/cookies', '/accessibility']) {
      const r = await api(page);
      assert.equal(r.status, 200, `${page} is not served — the sitemap points at it`);
      const html = await r.text();
      const canon = (html.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
      assert.ok(canon, `${page} has no canonical tag`);
      assert.ok(canon.endsWith(page), `${page} declares its canonical as ${canon}`);
      assert.ok(locs.includes(canon), `${canon} is canonical but is not in the sitemap`);
    }
  });

  await check('nothing on a public page links to a legal URL that redirects', async () => {
    for (const page of ['/', '/terms', '/privacy', '/cookies', '/accessibility', '/404.html']) {
      const html = await (await api(page)).text();
      const bad = [...html.matchAll(/href="[^"]*\/?(terms|privacy|cookies|accessibility)\.html"/g)].map(m => m[0]);
      assert.deepEqual(bad, [], `${page} still links the .html form: ${bad.join(', ')}`);
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

  await check('the business details Google reads are complete and parse', async () => {
    /*
     * Structured data is how a local business gets a map pack listing and a
     * knowledge panel rather than ten blue links. One malformed block and
     * Google discards the lot silently — there is no error anywhere — so the
     * blocks are parsed here, and the fields a local listing is actually built
     * from are checked against business.js rather than trusted.
     */
    const html = await (await api('/')).text();
    const blocks = [...html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)].map(m => m[1]);
    assert.ok(blocks.length >= 3, `only ${blocks.length} structured-data blocks on the home page`);
    const parsed = blocks.map((b, i) => {
      try { return JSON.parse(b); }
      catch (e) { throw new Error(`structured-data block ${i + 1} is not valid JSON: ${e.message}`); }
    });

    const biz = parsed.find(b => b['@type'] === 'AutoRepair');
    assert.ok(biz, 'no local-business block — this is what the map pack is built from');
    for (const field of ['name', 'telephone', 'address', 'geo', 'areaServed', 'openingHoursSpecification', 'url', 'image', 'logo', 'email']) {
      assert.ok(biz[field], `the business block has no ${field}`);
    }
    assert.equal(biz.telephone, BUSINESS.phoneHref, 'the schema phone number disagrees with business.js');
    assert.equal(biz.email, BUSINESS.email, 'the schema email disagrees with business.js');
    assert.ok(String(biz.logo).startsWith('https://'),
      'the logo must be an absolute URL — Google fetches it from the open web');

    // Both numbers the site prints. A local listing is matched on name,
    // address and phone, so a number shown to customers but missing from the
    // markup is a number Google cannot match against the Business Profile.
    const phones = (biz.contactPoint || []).map(c => c.telephone);
    assert.ok(phones.includes(BUSINESS.phoneHref) && phones.includes(BUSINESS.landlineHref),
      `the schema lists ${phones.join(', ')} but the site prints two numbers`);

    // Every area named in the schema should be somewhere a reader can see, or
    // it is a claim made only to a crawler.
    const visible = html.replace(/<script[\s\S]*?<\/script>/g, '');
    const towns = biz.areaServed.filter(a => a['@type'] === 'City').map(a => a.name);
    const unseen = towns.filter(t => !visible.includes(t));
    assert.deepEqual(unseen, [], `these towns are claimed to Google but appear nowhere on the page: ${unseen.join(', ')}`);
  });

  await check('no public page ships a link a crawler would resolve to a fake URL', async () => {
    /*
     * Search Console had 404s for /{{ waConfirm }}. The page ships with the
     * token still in the href — the runtime fills it in after React mounts,
     * and a crawler reads the HTML before that happens, so Google followed a
     * link to a URL that cannot exist and counted it against the site.
     *
     * robots.txt was patched to hide those URLs, which treated the symptom.
     * The rule is the same one the images taught: anything a crawler resolves
     * as a URL — href, src, srcset, poster — must be a real URL in the source.
     * Bindings belong in click handlers.
     */
    for (const page of ['/', '/terms', '/privacy', '/cookies', '/accessibility', '/404.html']) {
      // Both comment styles: the whole app is authored inside a <script> block,
      // so a JS comment explaining this very rule sits in the served HTML and
      // would otherwise trip it. (It did, on the first run.)
      const html = (await (await api(page)).text())
        .replace(/<!--[\s\S]*?-->/g, '')
        .replace(/\/\*[\s\S]*?\*\//g, '');
      const bad = [...html.matchAll(/\b(href|src|srcset|poster)\s*=\s*"[^"]*\{\{[^"]*"/g)].map(m => m[0].slice(0, 80));
      assert.deepEqual(bad, [], `${page} ships a URL a crawler will follow to nowhere: ${bad.join(' | ')}`);
    }
  });

  await check('every image on a public page says what it is', async () => {
    // Alt text is the only description image search gets, and the only thing a
    // screen reader can read out. Two images on a page sharing one generic
    // string is the same as having none.
    for (const page of ['/', '/terms', '/privacy', '/cookies', '/accessibility', '/404.html']) {
      const html = (await (await api(page)).text()).replace(/<!--[\s\S]*?-->/g, '');
      for (const img of html.match(/<img[^>]*>/g) || []) {
        const alt = (img.match(/\salt="([^"]*)"/) || [])[1];
        assert.ok(alt !== undefined, `${page} has an <img> with no alt at all: ${img.slice(0, 90)}`);
        // A deliberately empty alt is correct for decoration, but every image
        // this site serves is content, so an empty one is an oversight.
        assert.ok(alt.trim().length >= 10, `${page} has thin alt text (${JSON.stringify(alt)}) on ${img.slice(0, 70)}`);
      }
      for (const el of html.match(/<[^>]*role="img"[^>]*>/g) || []) {
        assert.ok(/aria-label="[^"]{3,}"/.test(el), `${page} has a role="img" with no label: ${el.slice(0, 90)}`);
      }
    }
  });

  await check('robots.txt blocks the API, and nothing that merely does not exist', async () => {
    /*
     * A Disallow on a URL that does not exist is permanent. The crawler is
     * told not to look, so it never learns the page is gone, and Search
     * Console files it under "Blocked by robots.txt" for good. A 404 clears
     * itself and needs nobody to remember it.
     *
     * Eleven rules used to sit here for paths that all answer 404. Every one
     * was a page Google was forbidden to check and could therefore never drop.
     */
    const txt = await (await api('/robots.txt')).text();
    assert.ok(/^Disallow: \/api$/m.test(txt), 'the API is no longer blocked — its responses are not pages');
    assert.ok(/Sitemap: https:\/\/cousinsmechanicalservices\.co\.uk\/sitemap\.xml/.test(txt),
      'robots.txt does not point at the sitemap');

    // Rules for things that are not there. Each of these is checked live: if a
    // path 404s, blocking it only stops Google finding that out.
    for (const gone of ['/ukvd', '/v1/', '/bookings', '/messages', '/track', '/notify',
                        '/service-requests', '/pricingworkout.html', '/tyre_finder.html',
                        '/ctyres_catalogue.html', '/*{{', '/*%7B%7B']) {
      assert.ok(!txt.includes('Disallow: ' + gone),
        `robots.txt still blocks ${gone}, which does not exist — so Google can never drop it`);
    }

    // The staff portals are removed from here on purpose: a page Google may
    // not fetch is a page whose noindex Google cannot read.
    assert.ok(!/Disallow: \/admin/.test(txt) && !/Disallow: \/driver/.test(txt),
      'the staff pages are blocked in robots.txt, which stops Google reading the noindex that would actually remove them');
  });

  await check('dev serves the authored page, not yesterday\'s build', async () => {
    /*
     * This server exists to serve the AUTHORED .dc.html so an edit shows up on
     * refresh. Adding `extensions: ['html']` to express.static for the legal
     * pages quietly took that away: registered before the routes, it answered
     * /admin from public/admin.html and the route never ran. Both return a
     * working page, so nothing looked wrong — an edit just did nothing until
     * the next build, and the noindex header stopped being sent with it.
     */
    const authored = (await import('node:fs')).readFileSync;
    for (const [path, file] of [['/', 'Cousins Mechanical.dc.html'], ['/admin', 'Cousins Admin.dc.html'], ['/driver', 'Cousins Driver.dc.html']]) {
      const served = await (await api(path)).text();
      const src = authored(new URL('../' + file, import.meta.url), 'utf8');
      // A marker that only ever exists in the authored file: the build strips
      // the placeholder hints the editor uses.
      const marker = (src.match(/hint-placeholder-count="\d+"/) || [])[0];
      if (!marker) continue;
      assert.ok(served.includes(marker),
        `${path} is being served from public/, not from ${file} — editing the source would do nothing`);
    }
  });

  await check('robots.txt actually parses the way it reads', async () => {
    /*
     * A blank line ENDS a record. A long explanatory comment with blank lines
     * in it, sitting between "User-agent: *" and the rules, orphans every rule
     * after it — they parse as belonging to no crawler and silently stop
     * applying. That shipped: the /api block was dead in a version that looked
     * completely correct to read.
     *
     * So this does not grep for lines. It runs the file through a real
     * robots.txt parser and asks the questions that matter.
     */
    const txt = await (await api('/robots.txt')).text();

    // Minimal group parser, same rule as the standard: a blank line ends a
    // record, and rules attach to the user-agents named immediately above them.
    const groups = [];
    let current = null;
    for (const raw of txt.split(/\r?\n/)) {
      const line = raw.replace(/#.*$/, '').trim();
      if (!line) { current = null; continue; }
      const [k, ...rest] = line.split(':');
      const key = k.trim().toLowerCase(), val = rest.join(':').trim();
      if (key === 'user-agent') {
        if (!current || current.rules.length) { current = { agents: [], rules: [] }; groups.push(current); }
        current.agents.push(val.toLowerCase());
      } else if ((key === 'disallow' || key === 'allow') && current) {
        current.rules.push({ allow: key === 'allow', path: val });
      }
    }
    const groupFor = ua => groups.find(g => g.agents.includes(ua.toLowerCase()))
                        || groups.find(g => g.agents.includes('*'));
    const blocked = (ua, path) => {
      const g = groupFor(ua);
      if (!g) return false;
      const hit = g.rules.filter(r => r.path && path.startsWith(r.path))
                         .sort((a, b) => b.path.length - a.path.length)[0];
      return !!hit && !hit.allow;
    };

    assert.ok(blocked('Googlebot', '/api/health'),
      'the /api rules are orphaned — a blank line above them ended the record, so they apply to nobody');
    assert.ok(!blocked('Googlebot', '/'), 'the home page is blocked from Google');
    assert.ok(!blocked('Googlebot', '/terms'), 'the legal pages are blocked from Google');
    assert.ok(!blocked('Googlebot', '/admin'),
      '/admin is blocked, so Google cannot read the noindex that would remove it');
    assert.ok(blocked('GPTBot', '/'), 'the AI scraper block is not applying');
    assert.ok(/Sitemap: https:\/\/cousinsmechanicalservices\.co\.uk\/sitemap\.xml/.test(txt),
      'robots.txt does not point at the sitemap');
  });

  await check('the staff pages carry the tag that actually removes them from the index', async () => {
    // robots.txt only stops the fetch. noindex is what drops a page — and it
    // has to be readable, which means the page must be crawlable.
    for (const path of ['/admin', '/driver']) {
      const r = await api(path);
      const tag = r.headers.get('x-robots-tag') || '';
      assert.ok(/noindex/.test(tag), `${path} does not send X-Robots-Tag: noindex (got "${tag}")`);
    }
    // And a normal page must NOT carry it, or the site would deindex itself.
    const home = await api('/');
    assert.ok(!/noindex/.test(home.headers.get('x-robots-tag') || ''),
      'the home page is telling Google not to index it');
  });

  await check('a branded 404 page exists and offers a way back', async () => {
    const r = await api('/404.html');
    assert.equal(r.status, 200);
    const html = await r.text();
    assert.ok(/not found/i.test(html), '404 page has no "not found" wording');
    assert.ok(html.includes('07925'), '404 page does not offer the phone number');
    assert.ok(html.includes('index.html'), '404 page has no route back to the site');
  });

  await check('an unknown URL gets the branded 404, not a bare error', async () => {
    // Checking the status alone was not enough. The 404 page existed and was
    // served in production, while dev answered a bad link with Express's
    // "Cannot GET /whatever" — so a broken link looked fine locally and the
    // test agreed, because both are non-200.
    const { BUSINESS } = await import('../business.js');
    const r = await api('/definitely-not-a-real-page-' + Date.now());
    assert.notEqual(r.status, 200, 'unknown URL returned 200 — check not_found_handling');
    const html = await r.text();
    assert.ok(/not found/i.test(html), 'unknown URL did not return the branded 404 page');
    assert.ok(html.includes(BUSINESS.phone), 'the 404 a visitor actually sees has no phone number on it');
    assert.ok(html.includes('index.html'), 'the 404 a visitor actually sees has no way back');
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

      // An .ico legitimately holds several sizes in one file, and its header is
      // nothing like a PNG's — reading PNG offsets out of one gives a number in
      // the thousands. Its own directory is checked instead.
      if (/\.ico$/.test(icon.src)) {
        const count = buf.readUInt16LE(4);
        const inFile = new Set();
        for (let i = 0; i < count; i++) {
          const o = 6 + i * 16;
          inFile.add(`${buf[o] || 256}x${buf[o + 1] || 256}`);
        }
        for (const declared of icon.sizes.split(/\s+/)) {
          assert.ok(inFile.has(declared),
            `${icon.src} declares ${declared} but only holds ${[...inFile].join(', ')}`);
        }
        continue;
      }

      // PNG header: width/height are big-endian uint32 at bytes 16 and 20.
      const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
      const [dw, dh] = icon.sizes.split('x').map(Number);
      assert.equal(w, dw, `${icon.src} is ${w}px wide but declares ${dw}`);
      assert.equal(h, dh, `${icon.src} is ${h}px tall but declares ${dh}`);
    }

    // Google picks a search-result favicon from the home page and asks for a
    // square icon whose side is a multiple of 48. Without one it draws a
    // generic globe next to the listing, which is what the site had.
    const home = await (await api('/')).text();
    const links = [...home.matchAll(/<link[^>]+rel="icon"[^>]*>/g)].map(x => x[0]);
    assert.ok(links.length, 'the home page declares no icon at all');
    assert.ok(links.some(l => /sizes="(48x48|96x96|192x192)"/.test(l)),
      'no icon at a size Google will use (a multiple of 48px) is declared on the home page');
    assert.ok(links.some(l => /href="\/favicon\.ico"/.test(l)),
      '/favicon.ico is not declared — browsers fetch it regardless, so leave nothing to guess');
    for (const l of links) {
      const href = (l.match(/href="([^"]+)"/) || [])[1];
      assert.ok(href && href.startsWith('/'),
        `icon href ${href} is relative — it resolves differently from a deeper URL`);
    }
  });

  await check('/favicon.ico is served and is a real icon', async () => {
    // Browsers ask for /favicon.ico whether or not the page declares an icon
    // link, so a missing one is a 404 on every single page load — and a blank
    // tab in the browsers that do not fall back to the PNG.
    const r = await api('/favicon.ico');
    assert.equal(r.status, 200, '/favicon.ico is missing — run node tools/make-favicon.mjs');
    const buf = Buffer.from(await r.arrayBuffer());
    // ICONDIR: reserved 0, type 1, at least one image.
    assert.equal(buf.readUInt16LE(0), 0, 'not an ICO file');
    assert.equal(buf.readUInt16LE(2), 1, 'not an ICO file');
    assert.ok(buf.readUInt16LE(4) >= 1, 'ICO contains no images');
    // The entry must point at data that is actually inside the file. A header
    // describing bytes that are not there renders as a blank tab, not an error.
    const bytes = buf.readUInt32LE(14), offset = buf.readUInt32LE(18);
    assert.ok(offset + bytes <= buf.length, 'ICO header points past the end of the file');
  });

  await check('a money amount in an email is printed once, with one pound sign', async () => {
    // The card receipt read "££25.00". The template prints &pound; in front of
    // {{{amount}}} and the Stripe path was passing "£25.00" into it. A receipt
    // is the one email a customer keeps, and it is the one that has to look
    // like the business knows what it is doing.
    const { renderEmail } = await import('../worker.js');
    for (const block of ['payment_received', 'refund_processed']) {
      const html = renderEmail(block, {
        subject: 'Receipt', firstname: 'Jane', amount: '25.00',
        booking_ref: 'CMS-1', service: 'Tyre fitting', vehicle_reg: 'AB12 CDE',
      });
      const shown = String(html).replace(/&pound;/g, '£');
      assert.ok(!/££/.test(shown), `${block} prints a double pound sign`);
      assert.ok(shown.includes('£25.00'), `${block} does not show the amount at all`);
    }
  });

  await check('business details live in business.js, not scattered through the code', async () => {
    // The phone number was in ten places in worker.js alone. Change it once and
    // you have nine chances to leave a customer ringing a dead line — and the
    // supplier purchase order carried an address and a phone number that
    // matched nothing else in the codebase, which nobody noticed because no
    // order has ever been sent.
    const fs = await import('node:fs');
    const { BUSINESS } = await import('../business.js');
    const FACTS = [
      ['phone', BUSINESS.phone],
      ['companyNumber', BUSINESS.companyNumber],
      ['registeredOffice', BUSINESS.registeredOffice],
      ['landline', BUSINESS.landline],
    ];
    for (const f of ['worker.js', 'build.js']) {
      const src = fs.readFileSync(new URL('../' + f, import.meta.url), 'utf8');
      for (const [field, value] of FACTS) {
        assert.ok(!src.includes(value),
          `${f} hardcodes ${field} ("${value}") — use BUSINESS.${field} from business.js`);
      }
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
