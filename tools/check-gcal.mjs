/*
 * check-gcal.mjs — prove a Google service-account key can actually read the
 * diary, BEFORE it goes anywhere near a production secret.
 *
 *   node tools/check-gcal.mjs ~/Downloads/cousins-xxxx.json help@cousinsmechanicalservices.co.uk
 *
 * The key never leaves this machine and is never printed.
 *
 * WHY BOTHER
 *
 * Google Calendar has three separate ways to be "set up" and only one of them
 * produces a working booking system. All three fail differently and two of them
 * fail QUIETLY:
 *
 *   1. Bad or malformed key      -> loud. Token request fails.
 *   2. Calendar API not enabled  -> loud-ish. 403 with a long enable-it message.
 *   3. Calendar not SHARED with  -> SILENT. The token works, freeBusy returns
 *      the service account            200, and the calendar simply reports
 *                                     "notFound". The site then believes your
 *                                     diary is completely empty and cheerfully
 *                                     books customers on top of existing jobs.
 *
 * Number 3 is the one that matters. It is indistinguishable from "a genuinely
 * free week" unless you go looking, which is exactly why this script goes
 * looking: it puts a known-busy window in front of the API and checks it comes
 * back.
 *
 * The signing code is deliberately the same shape as googleToken() in worker.js.
 * If this passes and production still fails, the difference is the secret's
 * value, not the logic.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const [, , keyPath, calendarIdArg] = process.argv;
if (!keyPath) {
  console.error('usage: node tools/check-gcal.mjs <service-account.json> [calendarId]');
  process.exit(2);
}

let sa;
try {
  sa = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
} catch (e) {
  console.error('Could not read that JSON key file: ' + e.message);
  process.exit(2);
}

const clientEmail = sa.client_email;
const privateKey = sa.private_key;
const calendarId = calendarIdArg || clientEmail;

if (!clientEmail || !privateKey) {
  console.error('That file is missing client_email or private_key — is it the service-account JSON?');
  process.exit(2);
}

console.log('service account : ' + clientEmail);
console.log('calendar        : ' + calendarId);
console.log('project         : ' + (sa.project_id || '(not in file)'));
console.log('');

// ---- 1. mint a JWT and swap it for an access token -------------------------
const b64url = buf => Buffer.from(buf).toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const now = Math.floor(Date.now() / 1000);
const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
const claim = b64url(JSON.stringify({
  iss: clientEmail,
  scope: 'https://www.googleapis.com/auth/calendar',
  aud: 'https://oauth2.googleapis.com/token',
  iat: now,
  exp: now + 3600,
}));
const unsigned = `${header}.${claim}`;

let jwt;
try {
  const sig = crypto.createSign('RSA-SHA256').update(unsigned).sign(privateKey);
  jwt = `${unsigned}.${b64url(sig)}`;
} catch (e) {
  console.error('FAIL — the private key would not sign anything: ' + e.message);
  console.error('That is a malformed key, not a permissions problem.');
  process.exit(1);
}

const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  }),
});
const tokenBody = await tokenRes.json().catch(() => ({}));

if (!tokenRes.ok || !tokenBody.access_token) {
  console.error('FAIL — Google would not issue an access token.');
  console.error('  ' + (tokenBody.error_description || tokenBody.error || tokenRes.status));
  process.exit(1);
}
console.log('1. access token .......... OK');

// ---- 2. ask for a window we KNOW should be answerable ----------------------
const start = new Date(Date.now() + 24 * 3600 * 1000); start.setHours(0, 0, 0, 0);
const end = new Date(start.getTime() + 7 * 24 * 3600 * 1000);

const fbRes = await fetch('https://www.googleapis.com/calendar/v3/freeBusy', {
  method: 'POST',
  headers: { authorization: 'Bearer ' + tokenBody.access_token, 'content-type': 'application/json' },
  body: JSON.stringify({
    timeMin: start.toISOString(),
    timeMax: end.toISOString(),
    timeZone: 'Europe/London',
    items: [{ id: calendarId }],
  }),
});
const fb = await fbRes.json().catch(() => ({}));

if (!fbRes.ok) {
  console.error('FAIL — the freeBusy call was rejected (HTTP ' + fbRes.status + ').');
  const msg = fb.error?.message || JSON.stringify(fb).slice(0, 400);
  console.error('  ' + msg);
  if (/has not been used|is disabled/i.test(msg)) {
    console.error('\n  ^ the Google Calendar API is not enabled on this project.');
    console.error('    Enable it in the Cloud Console, wait a minute, run this again.');
  }
  process.exit(1);
}
console.log('2. freeBusy call ......... OK');

// ---- 3. the quiet one: is the calendar actually shared with us? ------------
const cal = fb.calendars?.[calendarId];
if (!cal) {
  console.error('FAIL — Google did not return that calendar at all.');
  console.error('  Check the calendar id. It is usually an email address.');
  process.exit(1);
}
if (cal.errors?.length) {
  const reasons = cal.errors.map(e => e.reason).join(', ');
  console.error('FAIL — the calendar came back with: ' + reasons);
  if (/notFound|forbidden/i.test(reasons)) {
    console.error('\n  ^ THIS IS THE ONE THAT MATTERS, and it is the step everyone misses.');
    console.error('    The key is fine. The API is fine. The calendar has simply not been');
    console.error('    shared with the service account, so the site would think your diary');
    console.error('    is empty and double-book you without ever showing an error.');
    console.error('\n    Google Calendar -> the diary -> Settings and sharing ->');
    console.error('    Share with specific people -> add');
    console.error('      ' + clientEmail);
    console.error('    with "Make changes to events". Then run this again.');
  }
  process.exit(1);
}
console.log('3. calendar is shared .... OK');

const busy = cal.busy || [];
console.log('');
console.log(`Next 7 days: ${busy.length} busy block${busy.length === 1 ? '' : 's'}.`);
for (const b of busy.slice(0, 8)) {
  const s = new Date(b.start), e = new Date(b.end);
  const fmt = d => d.toLocaleString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  console.log('  ' + fmt(s) + '  ->  ' + fmt(e));
}

console.log('');
if (busy.length === 0) {
  console.log('Everything works, but the diary is EMPTY for the next week — so this run');
  console.log('has not actually proved the busy-check does anything. Put a test event in');
  console.log('tomorrow morning, run this again, and make sure it appears above. Only');
  console.log('then do you know the booking form will refuse that slot.');
} else {
  console.log('Working. Those blocks are the windows the booking form will now refuse.');
  console.log('Set the three secrets and you are done:');
  console.log('  GCAL_CLIENT_EMAIL  = ' + clientEmail);
  console.log('  GCAL_PRIVATE_KEY   = the private_key value from that JSON file');
  console.log('  GCAL_CALENDAR_ID   = ' + calendarId);
}
