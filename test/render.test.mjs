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

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] });
let failed = 0;

/*
 * The pages load React and Babel from unpkg, which this sandbox cannot reach.
 * Serving the same versions from node_modules keeps the page exactly as it
 * ships — no test-only build, no divergence between what is checked and what
 * customers get — while making the check work without the open internet.
 */
const LOCAL = {
  'react@18.3.1/umd/react.production.min.js': 'node_modules/react/umd/react.production.min.js',
  'react-dom@18.3.1/umd/react-dom.production.min.js': 'node_modules/react-dom/umd/react-dom.production.min.js',
  '@babel/standalone@7.29.0/babel.min.js': 'node_modules/@babel/standalone/babel.min.js',
};

for (const path of PAGES) {
  const page = await browser.newPage();
  await page.route('**://unpkg.com/**', async route => {
    const url = route.request().url();
    const hit = Object.keys(LOCAL).find(k => url.includes(k));
    if (!hit) return route.abort();
    route.fulfill({ status: 200, contentType: 'text/javascript', body: readFileSync(LOCAL[hit], 'utf8') });
  });
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
  await page.route('**://unpkg.com/**', async route => {
    const url = route.request().url();
    const hit = Object.keys(LOCAL).find(k => url.includes(k));
    if (!hit) return route.abort();
    route.fulfill({ status: 200, contentType: 'text/javascript', body: readFileSync(LOCAL[hit], 'utf8') });
  });

  const day = n => { const x = new Date(); x.setDate(x.getDate() + n); return x.toISOString().slice(0, 10); };
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

  await page.close();
  if (problems.length) { console.log('  FAIL  the calendar grid'); problems.forEach(p => console.log('          ' + p)); return 1; }
  console.log(`  PASS  the calendar grid (${seen.cells} days, ${seen.withCount} with entries)`);
  return 0;
}
failed += await checkCalendar();

await browser.close();
console.log(failed ? `\n  ${failed} page(s) with runtime errors` : '\n  every page runs clean');
process.exit(failed ? 1 : 0);
