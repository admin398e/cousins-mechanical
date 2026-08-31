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
await browser.close();
console.log(failed ? `\n  ${failed} page(s) with runtime errors` : '\n  every page runs clean');
process.exit(failed ? 1 : 0);
