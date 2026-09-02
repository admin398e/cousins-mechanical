/*
 * Load each page in a real browser and fail on anything the browser complains
 * about. Every test in the suite fetches HTML and reads it as text — which is
 * why a ReferenceError inside renderVals() shipped to production and put a red
 * error banner across the top of the home page. HTML that looks right and code
 * that runs are different claims.
 */
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';

const BASE = process.argv[2] || 'http://127.0.0.1:3799';
const PAGES = process.argv[3] ? process.argv[3].split(',') : ['/', '/admin', '/driver', '/terms'];

/*
 * Whatever Chromium this machine has. The sandbox ships one at a fixed path;
 * a Mac has Google Chrome. Pinning the sandbox path meant this could only ever
 * run in one place, and the one place it most needs to run is against the
 * live site — which the sandbox cannot reach.
 */
const browser = await (async () => {
  const tries = [
    { executablePath: process.env.CHROME_PATH, args: ['--no-sandbox'] },
    { executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] },
    { channel: 'chrome' },
    {},
  ].filter(o => o.executablePath !== undefined || !('executablePath' in o));
  let last;
  for (const opts of tries) {
    if ('executablePath' in opts && !opts.executablePath) continue;
    try { return await chromium.launch(opts); } catch (e) { last = e; }
  }
  throw last;
})();
let failed = 0;

/*
 * The pages load React and Babel from unpkg, which this sandbox cannot reach.
 * Serving the same versions from node_modules keeps the page exactly as it
 * ships — no test-only build, no divergence between what is checked and what
 * customers get — while making the check work without the open internet.
 */
/*
 * Serve React and Babel from node_modules when they are there, and otherwise
 * let the request go to unpkg. The sandbox has the packages but no internet;
 * a laptop running this against the live site has the internet but not the
 * packages. Insisting on one or the other meant the check only ran in one
 * place — and the place it matters most is against production.
 */
function serveLocallyOrLetItThrough(route) {
  const url = route.request().url();
  const hit = Object.keys(LOCAL).find(k => url.includes(k));
  if (hit) {
    try { return route.fulfill({ status: 200, contentType: 'text/javascript', body: readFileSync(LOCAL[hit], 'utf8') }); }
    catch (e) { /* not installed here — fall through to the real CDN */ }
  }
  return route.continue();
}

const LOCAL = {
  'react@18.3.1/umd/react.production.min.js': 'node_modules/react/umd/react.production.min.js',
  'react-dom@18.3.1/umd/react-dom.production.min.js': 'node_modules/react-dom/umd/react-dom.production.min.js',
  '@babel/standalone@7.29.0/babel.min.js': 'node_modules/@babel/standalone/babel.min.js',
};

for (const path of PAGES) {
  const page = await browser.newPage();
  await page.route('**://unpkg.com/**', serveLocallyOrLetItThrough);
  const problems = [];
  page.on('console', m => { if (m.type() === 'error') problems.push('console: ' + m.text().slice(0, 300)); });
  page.on('pageerror', e => problems.push('uncaught: ' + String(e.message).slice(0, 300)));
  try {
    await page.goto(BASE + path, { waitUntil: 'networkidle', timeout: 45000 });
    await page.waitForTimeout(1200);
    // The design-canvas runtime prints its own failures into the page rather
    // than only the console, so the DOM is checked too.
    const banner = await page.evaluate(() => {
      const t = document.body.innerText || '';
      const m = t.match(/[A-Za-z.]*renderVals\(\)[^\n]*|is not defined[^\n]*|Cannot read propert[^\n]*/);
      return m ? m[0].slice(0, 200) : '';
    });
    if (banner) problems.push('on the page: ' + banner);
    // A marker per page rather than a length threshold: /driver is a sign-in
    // card and is legitimately short, so "under 200 characters" called a
    // working page broken.
    const MARKER = { '/': 'WE COME TO YOU', '/admin': 'ADMIN', '/driver': 'DRIVER', '/terms': 'Terms' };
    const text = (await page.evaluate(() => document.body.innerText || '')).trim();
    const want = MARKER[path];
    if (want && !text.includes(want)) problems.push(`the page did not render — no "${want}" anywhere in it (${text.length} chars)`);
  } catch (e) {
    problems.push('navigation: ' + e.message.slice(0, 200));
  }
  // Missing images and fonts are noise from a local run without the CDN — but
  // a NAVIGATION failure is never noise. Filtering those made this check pass
  // against a server that was not even running, which is worse than no check.
  const real = problems.filter(p =>
    p.startsWith('navigation: ') || !/favicon|net::ERR_|Failed to load resource/i.test(p));
  if (real.length) { failed++; console.log(`  FAIL  ${path}`); real.forEach(p => console.log('          ' + p)); }
  else console.log(`  PASS  ${path} renders with no errors`);
  await page.close();
}
/*
 * The Calendar tab, driven the way a person drives it.
 *
 * It shipped drawing its month heading, its day names, and then nothing —
 * because <sc-for each="..."> is not a loop the runtime understands. walkFor()
 * in support.js reads `list` and `as` and never looks at `each`, so those
 * blocks compiled an empty list and rendered a hole. No error, no warning.
 *
 * Nothing that only reads HTML can catch that, so this signs in, clicks
 * through to the tab, and asserts there are actually day cells with numbers in
 * them and that clicking one opens that day. Google is stubbed: the point is
 * whether the grid renders, not whether Google is up.
 */
async function checkCalendar() {
  const token = process.env.SMOKE_ADMIN_TOKEN;
  if (!token) { console.log('  SKIP  the calendar grid (set SMOKE_ADMIN_TOKEN to run it)'); return 0; }
  const login = await fetch(BASE + '/api/admin-login', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }),
  });
  const d = await login.json().catch(() => ({}));
  if (!d.token) { console.log('  FAIL  the calendar grid — could not sign in'); return 1; }

  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', e => problems.push('uncaught: ' + String(e.message).slice(0, 200)));
  await page.route('**://unpkg.com/**', serveLocallyOrLetItThrough);

  const day = n => { const x = new Date(); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };
  // An open job dated in the past. The diary used to cut at today, so this is
  // exactly the booking that existed and could not be seen anywhere.
  await page.route('**/api/admin/jobs', r => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ jobs: [{ ref: 'CMS-OVERDUE', status: 'confirmed', date: day(-6), time: '11:00',
      svcLabel: 'Overdue test job', reg: 'AB12 CDE', name: 'Test Customer', postcode: 'DT6' }] }) }));
  await page.route('**/api/admin/calendar', r => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ connected: true, account: 'test@example.com', calendarId: 'primary', embedUrl: '' }) }));
  await page.route('**/api/admin/calendar/events*', r => r.fulfill({ status: 200, contentType: 'application/json',
    body: JSON.stringify({ connected: true, events: [
      { id: '1', title: 'Tyre fit — test', where: 'Bridport', allDay: false, start: day(0) + 'T09:30:00Z', end: day(0) + 'T10:30:00Z', day: day(0), ours: true },
      { id: '2', title: 'Day off', where: '', allDay: true, start: day(3), end: day(4), day: day(3), ours: false },
    ] }) }));

  await page.addInitScript(t => { try { sessionStorage.setItem('cms_admin_sess', t); } catch (e) {} }, d.token);
  await page.goto(BASE + '/admin', { waitUntil: 'networkidle', timeout: 45000 });
  await page.waitForTimeout(1200);
  const opened = await page.evaluate(() => {
    const el = [...document.querySelectorAll('button')].find(b => /^Calendar/.test(b.innerText.trim()));
    if (!el) return false; el.click(); return true;
  });
  if (!opened) problems.push('there is no Calendar tab to click');
  await page.waitForTimeout(1800);

  // Read the page BEFORE clicking anything. Clicking a day opens a detail
  // panel that also lists the job, so checking afterwards let a regression
  // pass on the strength of the panel alone.
  const beforeClick = await page.evaluate(() => document.body.innerText || '');

  const seen = await page.evaluate(() => {
    const t = document.body.innerText || '';
    const cells = [...document.querySelectorAll('button')].filter(b => /^\d{1,2}(\s|$)/.test(b.innerText.trim()));
    const withCount = cells.filter(b => b.innerText.trim().split(/\s+/).length === 2);
    if (withCount[0]) withCount[0].click();
    return { month: /\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}/.test(t),
             cells: cells.length, withCount: withCount.length, agenda: /Tyre fit — test/.test(t) };
  });
  await page.waitForTimeout(700);
  const detail = await page.evaluate(() => /(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday) \d{1,2} [A-Z][a-z]+/.test(document.body.innerText || ''));

  if (!seen.month) problems.push('no month heading — the grid did not render');
  if (seen.cells < 28) problems.push(`only ${seen.cells} day cells in the month grid`);
  if (!seen.withCount) problems.push('no day shows a count, so the events never reached the grid');
  if (!seen.agenda) problems.push('the diary below the grid is empty though there are events');
  if (!detail) problems.push('clicking a day did not open that day');

  if (!/Overdue test job/.test(beforeClick)) problems.push('an open job dated in the past is not in the diary — a booking that exists and cannot be seen');
  if (!/Still open/.test(beforeClick)) problems.push('the overdue job is listed but not marked as still open');

  await page.close();
  if (problems.length) { console.log('  FAIL  the calendar grid'); problems.forEach(p => console.log('          ' + p)); return 1; }
  console.log(`  PASS  the calendar grid (${seen.cells} days, ${seen.withCount} with entries)`);
  return 0;
}
/*
 * Booking "Something else".
 *
 * Every other choice names the job. This one used to move straight on, and
 * arrived at the van as "Something else" with a registration and a postcode —
 * Simon ringing the customer to find out what he was driving to. The notes box
 * existed, but two screens later, optional, headed "Anything we should know?".
 *
 * So it now asks on the spot, and will not move on without an answer. Driven
 * here the way a customer drives it, because none of this is visible to a test
 * that only reads HTML.
 */
async function checkOtherBooking() {
  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', e => problems.push('uncaught: ' + String(e.message).slice(0, 200)));
  await page.route('**://unpkg.com/**', serveLocallyOrLetItThrough);
  await page.goto(BASE + '/', { waitUntil: 'networkidle', timeout: 45000 });
  await page.waitForTimeout(1200);

  const click = async re => {
    await page.evaluate(r => {
      const b = [...document.querySelectorAll('button')].find(x => new RegExp(r).test(x.innerText));
      if (b) b.click();
    }, re);
    await page.waitForTimeout(650);
  };
  const text = () => page.evaluate(() => document.body.innerText || '');

  await click('Book a job online');
  if (!/What do you need/.test(await text())) problems.push('the booking form did not open');

  // A named service still goes straight on — the change must not slow the
  // common path down.
  await click('Tyre fitting');
  if (!/Vehicle registration/.test(await text())) problems.push('picking a named service no longer moves to the next step');
  await click('^Back$');

  await click('Something else');
  let t = await text();
  if (!/What do you need/.test(t)) problems.push('"Something else" skipped past the question instead of asking it');
  if (!/What do you need doing\?/.test(t)) problems.push('no box appeared asking what the job is');

  // Empty, then nonsense: neither is a job.
  await click('Continue');
  t = await text();
  if (/Vehicle registration/.test(t)) problems.push('it moved on with no description of the job at all');
  if (!/only thing telling us what the job is/.test(t)) problems.push('it refused without saying why');

  // A missing box must be a reported failure, not a thrown timeout: the first
  // run of this check aborted the whole file and skipped the calendar after it.
  try {
    await page.fill('textarea', 'Exhaust is blowing and the handbrake will not hold on a hill.', { timeout: 4000 });
    await page.waitForTimeout(400);
    if (/only thing telling us/.test(await text())) problems.push('the warning stayed up after the box was filled in');
    await click('Continue');
    if (!/Vehicle registration/.test(await text())) problems.push('it would not continue with the job described');
  } catch (e) {
    problems.push('could not type a description: ' + String(e.message).split('\n')[0]);
  }

  await page.close();
  if (problems.length) { console.log('  FAIL  booking "Something else"'); problems.forEach(p => console.log('          ' + p)); return 1; }
  console.log('  PASS  booking "Something else" asks what the job is, and insists');
  return 0;
}
/*
 * Tracking a booking this browser has never seen.
 *
 * The confirmation email's "Track & manage booking" link opens on whichever
 * phone received the text — not necessarily the one that made the booking, and
 * usually with no account behind it at all. The tracker required a session, so
 * that link landed on "LIVE TRACKING UNLOCKS ONCE YOU'RE BOOKED IN": an
 * instruction to book the job they had just booked.
 *
 * Driven end to end here — real booking, real challenge, real code — because
 * every part of this is behaviour, and none of it is visible in the HTML.
 */
async function checkGuestTracking() {
  const problems = [];
  const phoneTail = '390';
  const r = await fetch(BASE + '/api/service-requests', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.7' },
    body: JSON.stringify({
      name: 'Guest Tracker', phone: '0790000' + phoneTail,
      email: `guest-track-${Date.now()}@example.com`,
      service: 'tyre', svcLabel: 'Tyre fitting', postcode: 'DT6 5NJ',
      date: new Date(Date.now() + 3 * 864e5).toISOString().slice(0, 10), time: 'Morning (8-12)',
    }),
  });
  if (!r.ok) { console.log('  SKIP  guest tracking (the fixture booking was refused: ' + r.status + ')'); return 0; }
  const { ref } = await r.json();

  const page = await browser.newPage();
  page.on('pageerror', e => problems.push('uncaught: ' + String(e.message).slice(0, 200)));
  await page.route('**://unpkg.com/**', serveLocallyOrLetItThrough);
  await page.goto(BASE + '/#track=' + ref, { waitUntil: 'networkidle', timeout: 45000 });
  await page.waitForTimeout(2200);
  const text = () => page.evaluate(() => document.body.innerText || '');

  let t = await text();
  if (/LIVE TRACKING UNLOCKS ONCE YOU/.test(t)) problems.push('a real booking still lands on "book a job" — the dead end this exists to remove');
  if (!/CHECK IT'S YOU/.test(t)) problems.push('no unlock panel appeared for a real booking');
  if (!new RegExp('Booking ' + ref).test(t)) problems.push('the panel does not say which booking it is asking about');
  if (!/•••@/.test(t)) problems.push('the panel does not name the account to sign in with');

  const click = async re => {
    await page.evaluate(x => {
      const b = [...document.querySelectorAll('button')].find(y => new RegExp(x).test(y.innerText));
      if (b) b.click();
    }, re);
    await page.waitForTimeout(900);
  };

  await click('Text me a code');
  t = await text();
  if (!/six-digit code/.test(t)) problems.push('asking for a code did not move on to the code step');
  if (!new RegExp('•+ \\d*' + phoneTail).test(t)) problems.push('the code step does not say which number it went to');

  // A missing box has to be a reported failure, not a thrown timeout: a throw
  // here abandons the check and every assertion above it goes unreported, so
  // the run says "the check blew up" instead of naming what broke.
  const type = async code => {
    try { await page.fill('input[inputmode="numeric"]', code, { timeout: 4000 }); return true; }
    catch (e) { problems.push('there is no code box to type into'); return false; }
  };

  // The wrong code must be refused visibly, not silently swallowed.
  if (await type('000000')) {
    await click('Unlock tracking');
    t = await text();
    if (!/was not right|expired/.test(t)) problems.push('a wrong code produced no visible refusal');
  }

  // And the right one opens the tracker. The suite is the only thing that can
  // read the code — server.js returns it under ALLOW_TEST_VERIFY_CODE.
  const sd = await (await fetch(BASE + '/api/track/' + ref + '/code', {
    method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.8' }, body: '{}',
  })).json();
  if (!sd.devCode) { problems.push('no test code available to finish the flow'); }
  else if (await type(sd.devCode)) {
    await click('Unlock tracking');
    await page.waitForTimeout(1500);
    t = await text();
    if (/CHECK IT'S YOU/.test(t)) problems.push('the right code did not open the tracker');
    if (!new RegExp('Reference ' + ref).test(t)) problems.push('the tracker opened but is not showing this booking');
    if (!/JOB STATUS/.test(t)) problems.push('the status feed did not render');
  }

  await page.close();
  if (problems.length) { console.log('  FAIL  guest tracking'); problems.forEach(x => console.log('          ' + x)); return 1; }
  console.log('  PASS  guest tracking unlocks with a texted code');
  return 0;
}
/*
 * #book — the one url that can be given to Google, Maps, an ad or a QR code.
 *
 * The booking form only ever opened from a button inside the page, so the only
 * link that could be handed out was the homepage. Somebody who arrived having
 * already decided to book landed at the top of a marketing page to go and find
 * the button.
 */
async function checkBookDeepLink() {
  const problems = [];
  const page = await browser.newPage();
  page.on('pageerror', e => problems.push('uncaught: ' + String(e.message).slice(0, 200)));
  await page.route('**://unpkg.com/**', serveLocallyOrLetItThrough);
  await page.goto(BASE + '/#book', { waitUntil: 'networkidle', timeout: 45000 });
  await page.waitForTimeout(1800);
  const t = await page.evaluate(() => document.body.innerText || '');
  if (!/What do you need/.test(t)) problems.push('#book did not open the booking form');

  // And the plain homepage must NOT open it — a form in the face of somebody
  // who came to read about the business is worse than the missing link was.
  const plain = await browser.newPage();
  await plain.route('**://unpkg.com/**', serveLocallyOrLetItThrough);
  await plain.goto(BASE + '/', { waitUntil: 'networkidle', timeout: 45000 });
  await plain.waitForTimeout(1500);
  const pt = await plain.evaluate(() => document.body.innerText || '');
  if (/What do you need/.test(pt)) problems.push('the booking form opens on the plain homepage too');
  await plain.close();

  await page.close();
  if (problems.length) { console.log('  FAIL  the #book deep link'); problems.forEach(x => console.log('          ' + x)); return 1; }
  console.log('  PASS  #book opens the booking form, / does not');
  return 0;
}
failed += await checkBookDeepLink().catch(e => {
  console.log('  FAIL  the #book deep link');
  console.log('          the check itself blew up: ' + String(e.message).split('\n')[0]);
  return 1;
});

failed += await checkGuestTracking().catch(e => {
  console.log('  FAIL  guest tracking');
  console.log('          the check itself blew up: ' + String(e.message).split('\n')[0]);
  return 1;
});

failed += await checkOtherBooking().catch(e => {
  console.log('  FAIL  booking "Something else"');
  console.log('          the check itself blew up: ' + String(e.message).split('\n')[0]);
  return 1;
});

failed += await checkCalendar().catch(e => {
  console.log('  FAIL  the calendar grid');
  console.log('          the check itself blew up: ' + String(e.message).split('\n')[0]);
  return 1;
});

await browser.close();
console.log(failed ? `\n  ${failed} page(s) with runtime errors` : '\n  every page runs clean');
process.exit(failed ? 1 : 0);
