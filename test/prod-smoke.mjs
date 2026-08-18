/**
 * Production smoke test — run against the REAL deployment.
 *
 *   npm run smoke:prod
 *
 * This exists because the main suite (test/smoke.test.js) runs against
 * server.js, which is Express and has no concept of Cloudflare's static-asset
 * precedence. Two production-only bugs got past 98 green local tests:
 *
 *   - admin.<domain>/ served the public homepage (the Worker never ran)
 *   - no HTML page carried security headers or HSTS
 *
 * Anything asserted here is something only the real edge can tell us. Keep it
 * read-only: no bookings, no emails, nothing that touches customer data.
 */
const BASE = process.env.SMOKE_BASE || 'https://cousinsmechanicalservices.co.uk';
const ADMIN = process.env.SMOKE_ADMIN || 'https://admin.cousinsmechanicalservices.co.uk';

let pass = 0, fail = 0;
const results = [];

async function check(name, fn) {
  try { await fn(); pass++; results.push(['PASS', name, '']); }
  catch (err) { fail++; results.push(['FAIL', name, err.message]); }
}
const get = (url, init) => fetch(url, { redirect: 'follow', ...init });
function assert(cond, msg) { if (!cond) throw new Error(msg); }

// --- the two bugs this file was written for --------------------------------

await check('admin.<domain> root serves the dashboard, not the public site', async () => {
  const r = await get(ADMIN + '/');
  const html = await r.text();
  assert(r.status === 200, `status ${r.status}`);
  assert(/Admin Dashboard/i.test(html),
    'admin host root is serving the public marketing page — the Worker is not running before assets');
});

await check('admin.<domain> is noindex', async () => {
  const r = await get(ADMIN + '/');
  assert(/noindex/i.test(r.headers.get('x-robots-tag') || ''),
    'no X-Robots-Tag: noindex — the staff dashboard hostname is crawlable');
});

await check('admin.<domain>/robots.txt blocks everything', async () => {
  const txt = await (await get(ADMIN + '/robots.txt')).text();
  assert(/Disallow:\s*\/\s*$/m.test(txt) && !/Allow:\s*\//.test(txt),
    'admin host is serving the PUBLIC robots.txt, which allows crawling');
});

await check('HTML pages carry the security headers', async () => {
  for (const path of ['/', '/terms', '/privacy']) {
    const r = await get(BASE + path);
    const h = (k) => r.headers.get(k) || '';
    assert(h('x-content-type-options') === 'nosniff', `${path}: missing X-Content-Type-Options`);
    assert(h('x-frame-options') === 'DENY', `${path}: missing X-Frame-Options — page can be framed`);
    assert(/strict-origin/.test(h('referrer-policy')), `${path}: missing Referrer-Policy`);
    assert(/max-age=/.test(h('strict-transport-security')), `${path}: missing HSTS`);
  }
});

// --- routes that must exist and must fail closed ---------------------------

await check('unsubscribe rejects a tampered signature', async () => {
  const r = await get(BASE + '/api/unsubscribe?e=a@b.com&s=deadbeef');
  const html = await r.text();
  assert(r.status === 200, `status ${r.status}`);
  assert(/didn.t work/i.test(html), 'a forged unsubscribe link was accepted');
});

await check('resend webhook refuses an unsigned bounce', async () => {
  const r = await fetch(BASE + '/api/resend-webhook', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'email.bounced', data: { to: ['victim@example.com'] } }),
  });
  assert([400, 401, 503].includes(r.status),
    `an unsigned webhook returned ${r.status} — anyone could forge a bounce and block a customer's confirmations`);
});

await check('resend webhook is actually configured (not failing 503)', async () => {
  const r = await fetch(BASE + '/api/resend-webhook', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'email.bounced' }),
  });
  assert(r.status !== 503, 'RESEND_WEBHOOK_SECRET is not set — every real bounce notification is being rejected');
});

await check('every admin endpoint refuses an unauthenticated caller', async () => {
  for (const ep of ['/api/admin/jobs', '/api/admin/customers', '/api/admin/staff',
                    '/api/admin/inventory', '/api/admin/backup', '/api/admin/reorder-list']) {
    const r = await get(BASE + ep);
    assert(r.status === 403, `${ep} returned ${r.status}, expected 403`);
  }
  const pay = await fetch(BASE + '/api/admin/jobs/CMS-FAKE1/payment', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ customerEmail: 'x@y.com', amount: 10 }),
  });
  assert(pay.status === 403, `payment recording returned ${pay.status} — anyone could email a customer a receipt`);
});

// --- the shipped UI actually contains what we built -------------------------

await check('the deployed dashboard has the payment UI', async () => {
  const html = await (await get(BASE + '/admin')).text();
  for (const marker of ['RECORD A PAYMENT', 'Mark paid', 'Record payment & email receipt']) {
    assert(html.includes(marker), `dashboard is missing "${marker}" — an old build is live`);
  }
});

await check('the deployed booking form has the marketing opt-in, unticked', async () => {
  const html = await (await get(BASE + '/')).text();
  assert(/servicing reminders/.test(html), 'marketing opt-in checkbox is not in the deployed page');
  assert(/marketing:false/.test(html), 'the opt-in is not defaulting to off');
});

await check('the deployed site handles the #track= deep link from the email', async () => {
  const html = await (await get(BASE + '/')).text();
  assert(/track=\(/.test(html), 'no #track= handler — the "Track & manage booking" button in the email is dead');
});

// --- exploit probes ---------------------------------------------------------
// Each of these reproduces a hole that was live in production before go-live.
// They are safe to run against the real site: nothing here creates a customer
// record, sends mail to a stranger, or moves money.

await check('an anonymous booking cannot inject a payment into a victim job', async () => {
  // The booking handler used to spread the whole request body into the stored
  // job, so this wrote a £50,000 "payment" into someone else's booking list —
  // which the refund ceiling then trusts.
  const r = await fetch(BASE + '/api/service-requests', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      name: 'UAT Probe', phone: '07000000000',
      email: 'uat-probe-donotuse@cousinsmechanicalservices.co.uk',
      service: 'diagnostics', svcLabel: 'UAT PROBE — safe to delete',
      paidPence: 5000000, payments: [{ kind: 'payment', pence: 5000000 }],
      status: 'complete', ref: 'CMS-PWNED',
    }),
  });
  const d = await r.json();
  if (r.status === 429) return; // already rate limited; the probe is moot
  assert(d.ok, 'probe booking refused: ' + JSON.stringify(d).slice(0, 120));
  assert(d.ref !== 'CMS-PWNED', 'the caller chose their own booking reference');
  assert(d.booking.paidPence === undefined, 'an anonymous caller injected a paid balance');
  assert(d.booking.payments === undefined, 'an anonymous caller injected payment records');
  assert(d.booking.status === 'confirmed', 'an anonymous caller set the job status');
  console.log('          note: probe booking ' + d.ref + ' created — delete it from the dashboard');
});

await check('calendar invites cannot be sent by an anonymous caller', async () => {
  const r = await fetch(BASE + '/api/calendar/add-event', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ date: '2026-09-01', name: 'x', customerEmail: 't@example.com' }),
  });
  assert(r.status === 403, `Google would send an invite from the business account (status ${r.status})`);
});

await check('driver endpoints reject a missing or empty token', async () => {
  for (const body of [{}, { token: '' }, { token: null }]) {
    const loc = await fetch(BASE + '/api/driver/location', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ref: 'CMS-TEST1', lat: 50, lng: -2, ...body }),
    });
    assert([403, 404, 429].includes(loc.status), `driver/location accepted ${JSON.stringify(body)} (${loc.status})`);
    const jobs = await fetch(BASE + '/api/driver/jobs', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    assert([403, 429].includes(jobs.status), `driver/jobs leaked the job list for ${JSON.stringify(body)} (${jobs.status})`);
  }
});

await check('2FA enrolment state is not readable by the public', async () => {
  const r = await get(BASE + '/api/admin-2fa/status');
  assert(r.status === 403, `anyone can see whether 2FA is on (status ${r.status})`);
});

await check('the metered third-party proxies require admin auth', async () => {
  // These bill per call on the client's own accounts and nothing public uses
  // them. Open, anyone could run the quota to zero.
  for (const path of ['/api/ukvd?vrm=AB12CDE', '/api/v1/tyres']) {
    const r = await get(BASE + path);
    assert(r.status === 403, `${path} is reachable without auth (${r.status})`);
  }
});

await check('admin login rate limits a brute-force attempt', async () => {
  let limited = false;
  for (let i = 0; i < 20; i++) {
    const r = await fetch(BASE + '/api/admin-login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.com', password: 'guess' + i }),
    });
    if (r.status === 429) { limited = true; break; }
  }
  assert(limited, 'the staff password can be guessed without limit');
});

// --- basics -----------------------------------------------------------------

await check('public pages are all served', async () => {
  for (const p of ['/', '/terms', '/privacy', '/cookies', '/accessibility', '/sitemap.xml', '/robots.txt']) {
    const r = await get(BASE + p);
    assert(r.status === 200, `${p} returned ${r.status}`);
  }
});

await check('an unknown URL is a 404, not a 200', async () => {
  const r = await get(BASE + '/definitely-not-a-real-page-xyz');
  assert(r.status === 404, `returned ${r.status}`);
});

await check('the API reports its bindings healthy', async () => {
  const d = await (await get(BASE + '/api/health')).json();
  assert(d.ok && d.kv && d.assets, 'health check is not clean: ' + JSON.stringify(d));
  assert(d.configured?.email, 'email is not configured — confirmations cannot send');
});

await check('the API does not send a wildcard CORS header', async () => {
  const r = await get(BASE + '/api/health');
  assert(r.headers.get('access-control-allow-origin') !== '*', 'wildcard CORS on the API');
});

// --- report -----------------------------------------------------------------

console.log('\nProduction smoke — ' + BASE + '\n');
for (const [state, name, msg] of results) {
  console.log(`  ${state}  ${name}` + (msg ? `\n          ${msg}` : ''));
}
console.log(`\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
