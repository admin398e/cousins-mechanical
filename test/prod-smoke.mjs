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

// Opt-in: this is the only probe that writes anything, and every run leaves a
// booking in the live dashboard for the owner to clear.
//   SMOKE_WRITE=1 npm run smoke:prod
await check(process.env.SMOKE_WRITE ? 'an anonymous booking cannot inject a payment into a victim job'
                                    : 'booking injection probe (skipped — set SMOKE_WRITE=1)', async () => {
  if (!process.env.SMOKE_WRITE) return;
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

// Runs LAST on purpose, and only when asked. Firing 20 bad logins consumes the
// auth rate-limit budget for THIS machine's IP for the next minute — which
// locked the owner out of his own dashboard straight after a routine smoke run.
//   SMOKE_BRUTE=1 npm run smoke:prod
await check(process.env.SMOKE_BRUTE ? 'admin login rate limits a brute-force attempt'
                                    : 'admin login brute-force check (skipped — set SMOKE_BRUTE=1)', async () => {
  if (!process.env.SMOKE_BRUTE) return;
  let limited = false;
  for (let i = 0; i < 40; i++) {
    const r = await fetch(BASE + '/api/admin-login', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.com', password: 'guess' + i }),
    });
    if (r.status === 429) { limited = true; break; }
  }
  assert(limited, 'the staff password can be guessed without limit');
});

await check('the site never builds an API URL without a scheme', async () => {
  // A stored config value with no scheme ("host.workers.dev") was being
  // concatenated straight into fetch(), so the browser resolved it RELATIVE to
  // the page and every call went to
  //   https://cousinsmechanicalservices.co.uk/host.workers.dev/api/...
  // Signup, login and job tracking were all broken on the live site by this.
  const html = await (await get(BASE + '/')).text();
  assert(/ignoring apiBase without a scheme/.test(html),
    'the apiBase scheme guard is not in the deployed page — an old build is live');
  // And the relative form must 404 rather than quietly serving something.
  const r = await get(BASE + '/cousins-mechanical.example.workers.dev/api/auth/me');
  assert(r.status === 404, `a schemeless API path returned ${r.status}, expected 404`);
});

// --- basics -----------------------------------------------------------------

await check('public pages are all served', async () => {
  for (const p of ['/', '/terms', '/privacy', '/cookies', '/accessibility', '/sitemap.xml', '/robots.txt']) {
    const r = await get(BASE + p);
    assert(r.status === 200, `${p} returned ${r.status}`);
  }
});

await check('the site has one address: https, no www', async () => {
  /*
   * http://<domain>/ answered 200 over plain HTTP. HSTS could not save it —
   * browsers ignore that header on an insecure response, so a visitor who
   * typed the domain stayed on http until something else moved them. And
   * www.<domain> served the same pages on a second hostname.
   */
  const http = await fetch('http://cousinsmechanicalservices.co.uk/', { redirect: 'manual' });
  assert(http.status === 301, `http:// returned ${http.status}, not a permanent redirect`);
  assert((http.headers.get('location') || '').startsWith('https://cousinsmechanicalservices.co.uk/'),
    `http:// redirected to ${http.headers.get('location')}`);

  const www = await fetch('https://www.cousinsmechanicalservices.co.uk/terms', { redirect: 'manual' });
  assert(www.status === 301, `www returned ${www.status}, not a permanent redirect`);
  assert(www.headers.get('location') === 'https://cousinsmechanicalservices.co.uk/terms',
    `www redirected to ${www.headers.get('location')}`);

  // The staff hostname is its own portal, not a duplicate — it must survive,
  // and its front door should be one request rather than a redirect and then
  // a page.
  const admin = await fetch(ADMIN + '/', { redirect: 'manual' });
  assert(admin.status === 200,
    `the admin front door answers ${admin.status} -> ${admin.headers.get('location')} instead of serving the dashboard`);
  assert(/Admin Dashboard/i.test(await admin.text()), 'the admin front door is not the dashboard');
});

await check('every URL the sitemap advertises is the URL that answers', async () => {
  const xml = await (await get(BASE + '/sitemap.xml')).text();
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1]);
  assert(locs.length >= 5, `sitemap lists only ${locs.length} URLs`);
  for (const loc of locs) {
    const r = await fetch(loc, { redirect: 'manual' });
    assert(r.status === 200, `${loc} answers ${r.status}${r.headers.get('location') ? ' -> ' + r.headers.get('location') : ''} — a sitemap should list the destination, not the hop`);
    const html = await r.text();
    const canon = (html.match(/<link rel="canonical" href="([^"]+)"/) || [])[1];
    if (canon) assert(canon === loc, `${loc} declares its canonical as ${canon}`);
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

// --- the sign-in rebuild, checked on the real edge ---------------------------

await check('the front door offers exactly the providers that are configured', async () => {
  const d = await (await get(BASE + '/api/auth/providers')).json();
  assert(d.google === true, 'Google sign-in is off in production');
  assert(d.apple === true, 'Apple sign-in is off in production');
  // It must never grow into a place that leaks configuration.
  assert(JSON.stringify(Object.keys(d).sort()) === '["apple","google"]',
    'the provider list says more than it should: ' + Object.keys(d));
});

await check('every sign-in button on every page is actually wired', async () => {
  /*
   * The bug this exists for: googleSignIn was written as a class field and
   * never returned by renderVals(), so the binding resolved to undefined and
   * React rendered a button with NO onClick. It looked perfect and did
   * nothing, on the only route customers had, for weeks. A dead handler is
   * invisible from the outside — nothing 404s, nothing errors — so the only
   * place to catch it is in the bytes the edge actually serves.
   */
  for (const [path, needs] of [
    ['/',       ['googleSignIn:this.googleSignIn', 'appleSignIn:this.appleSignIn', 'toggleBookMarketing:this.toggleBookMarketing']],
    ['/admin',  ['googleSignIn:this.googleSignIn', 'appleSignIn:this.appleSignIn']],
    ['/driver', ['googleSignIn:this.googleSignIn', 'appleSignIn:this.appleSignIn']],
  ]) {
    const html = await (await get(BASE + path)).text();
    for (const n of needs) {
      assert(html.includes(n), `${path} is serving a page where ${n.split(':')[0]} is not bound — that button does nothing`);
    }
    // And no binding may be left in an attribute the browser fetches: the
    // placeholder pass strips those, so they render as a blank image forever.
    //
    // Comments are stripped first. The code carries a comment explaining that
    // very mistake, quoting `src="{{ t.image }}"` verbatim, and a scan that
    // reads comments as markup fails on the documentation of the bug rather
    // than the bug. That is the second checker this has caught out.
    const markup = html.replace(/<!--[\s\S]*?-->/g, '');
    assert(!/\b(src|srcset|poster)\s*=\s*["']\s*\{\{/.test(markup),
      `${path} has a {{ binding }} in src/srcset/poster — it will never render`);
  }
});

await check('the two-factor card carries a scannable QR, not just a key', async () => {
  const html = await (await get(BASE + '/admin')).text();
  assert(html.includes('twofaQrStyle'), 'the enrolment card has no QR code');
  assert(html.includes('Copy key'), 'the setup key cannot be copied');
});

await check('Apple sign-in starts a real Apple flow', async () => {
  for (const [path, body] of [['/api/auth/apple/start', '{}'], ['/api/admin-login-apple/start', '{"return":"/driver"}']]) {
    const r = await get(BASE + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
    assert(r.status === 200, `${path} returned ${r.status} — Apple is not configured in production`);
    const u = new URL((await r.json()).url);
    assert(u.origin + u.pathname === 'https://appleid.apple.com/auth/authorize', 'not an Apple consent URL');
    assert(/^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/.test(u.searchParams.get('client_id') || ''),
      'the client_id is not a Services ID — a stray newline in the secret?');
    assert(u.searchParams.get('scope') === 'name email', 'wrong Apple scope');
    // Without form_post Apple never calls the callback and sign-in hangs.
    assert(u.searchParams.get('response_mode') === 'form_post', 'a scoped Apple request must be form_post');
    assert((u.searchParams.get('redirect_uri') || '').startsWith(BASE + '/api/oauth/apple/callback'),
      'the return URL does not match what is registered with Apple');
  }
});

await check('Google sign-in starts a real Google flow, for customers and staff', async () => {
  for (const [path, wanted] of [['/api/auth/google/start', 'openid email profile'], ['/api/admin-login-google/start', 'openid email']]) {
    const r = await get(BASE + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert(r.status === 200, `${path} returned ${r.status}`);
    const u = new URL((await r.json()).url);
    assert(u.origin + u.pathname === 'https://accounts.google.com/o/oauth2/v2/auth', 'not a Google consent URL');
    assert(u.searchParams.get('scope') === wanted, `wrong scope: ${u.searchParams.get('scope')}`);
    // Identity only. A customer sign-in must never ask for a mailbox again.
    assert(!/gmail|calendar|drive/.test(u.searchParams.get('scope') || ''), 'sign-in is asking for far more than identity');
  }
});

await check('the Firebase admin door is gone from production', async () => {
  /*
   * It issued an admin session to any address in ADMIN_EMAILS without ever
   * checking the staff table — the check that makes "other staff cannot log in
   * without being approved" true. It was inert only because one environment
   * variable was unset.
   */
  for (const [path, init] of [['/api/firebase-config', {}], ['/api/admin-login-firebase', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }]]) {
    const r = await get(BASE + path, init);
    assert(r.status === 404, `${path} still answers (${r.status}) — the second admin door is open`);
  }
});

await check('a forged Apple callback bounces instead of signing anyone in', async () => {
  const r = await fetch(BASE + '/api/oauth/apple/callback', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code: 'fake', state: '11111111-2222-3333-4444-555555555555' }).toString(),
    redirect: 'manual',
  });
  assert(r.status === 302, `forged Apple callback did not redirect (${r.status})`);
  assert((r.headers.get('location') || '').includes('gauth=expired'), 'a state nonce nobody issued was accepted');
});

await check("Apple's domain file is served by the Worker, and fails closed", async () => {
  const r = await get(BASE + '/.well-known/apple-developer-domain-association.txt');
  const body = await r.text();
  if (r.status === 404) {
    // Not set: it must say what to set, never a blank 200 Apple reads as an
    // empty token and fails on without explaining why.
    assert(/APPLE_DOMAIN_ASSOCIATION/.test(body), 'the failure does not name the secret');
  } else {
    assert(r.status === 200 && body.trim().length > 0, 'the domain file is empty');
  }
});

// --- report -----------------------------------------------------------------

console.log('\nProduction smoke — ' + BASE + '\n');
for (const [state, name, msg] of results) {
  console.log(`  ${state}  ${name}` + (msg ? `\n          ${msg}` : ''));
}
console.log(`\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
