/*
 * drive-site.mjs — load every page in a real browser and report what a visitor
 * would actually get.
 *
 *   node tools/drive-site.mjs                        # the live site
 *   node tools/drive-site.mjs http://127.0.0.1:3000  # the dev server
 *
 * Needs puppeteer, which is deliberately NOT a dependency of this project —
 * it downloads a whole browser and none of the deploy needs it:
 *
 *   mkdir -p ~/.cousins-verify && cd ~/.cousins-verify
 *   npm init -y && npm install puppeteer
 *   npx puppeteer browsers install chrome
 *   node <path-to-repo>/tools/drive-site.mjs
 *
 * WHY THIS EXISTS
 *
 * The test suite checks what the server SENDS. This checks what the browser
 * DOES with it, and the gap between those two has produced every serious
 * outage this project has had:
 *
 *   - A Content-Security-Policy that was correct HTML and blocked the runtime
 *     from evaluating the application, so every page rendered as a static
 *     template with zero working buttons. Every test passed.
 *   - <img src="{{ t.image }}"> in a placeholder row, which made every
 *     visitor's browser request the literal token as a URL. The markup was
 *     correct; the browser was doing exactly what it said.
 *   - A driver login card that rendered completely empty after registering.
 *
 * None of those are visible in a diff or a response body. All of them are
 * obvious within two seconds of opening the page.
 *
 * It reports, per page: how much text rendered, how many buttons and images,
 * broken images, any leftover {{ tokens }}, any request for a token as a URL,
 * CSP violations, page errors and failed responses. A page with 3 buttons and
 * 108 characters is fine for a login screen and alarming for the home page —
 * the numbers are there to be compared against the last run.
 */
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/*
 * Node resolves a bare import against the FILE's location, not the working
 * directory, so a puppeteer installed in the harness folder is invisible to a
 * script living in the repo. Look in both, and if neither has it, say exactly
 * how to fix it rather than printing a module-resolution stack trace.
 */
async function loadPuppeteer() {
  try { return (await import('puppeteer')).default; } catch { /* not in the repo */ }
  const dir = process.env.PUPPETEER_HOME || path.join(homedir(), '.cousins-verify');
  try {
    const require = createRequire(path.join(dir, 'package.json'));
    return (await import(pathToFileURL(require.resolve('puppeteer')).href)).default;
  } catch {
    console.error(
      '\nCould not find puppeteer.\n\n' +
      '  mkdir -p ~/.cousins-verify && cd ~/.cousins-verify\n' +
      '  npm init -y && npm install puppeteer\n' +
      '  npx puppeteer browsers install chrome\n\n' +
      'Then run this again. Set PUPPETEER_HOME if you keep it somewhere else.\n'
    );
    process.exit(2);
  }
}

const puppeteer = await loadPuppeteer();

const BASE = (process.argv[2] || 'https://cousinsmechanicalservices.co.uk').replace(/\/+$/, '');
const PAGES = [
  '/', '/admin', '/driver',
  '/privacy.html', '/cookies.html', '/terms.html', '/accessibility.html',
  '/this-page-does-not-exist',
];

const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
const rows = [];

for (const p of PAGES) {
  const page = await browser.newPage();
  const viol = [], errs = [], bad = [], tokenReqs = [];

  page.on('console', m => {
    const t = m.text();
    if (/Content Security Policy|Refused to/i.test(t)) viol.push(t.slice(0, 160));
    // Skipped: Chrome's own devtools formatting noise, and "Failed to load
    // resource", which is the console's echo of a bad response. Those are
    // already collected below with their URL and status, where they are
    // actionable — here they are a second copy that says nothing, including
    // one for the 404 page's own deliberate 404.
    else if (m.type() === 'error' && !/font-size:0|Failed to load resource/.test(t)) errs.push(t.slice(0, 130));
  });
  page.on('pageerror', e => errs.push('PAGEERROR: ' + String(e.message).slice(0, 160)));
  page.on('request', r => { if (/%7B%7B|\{\{/.test(r.url())) tokenReqs.push(r.url().slice(0, 90)); });
  page.on('response', r => {
    // The 404 page is meant to 404, and Turnstile's challenge endpoint 401s by design.
    if (r.status() >= 400 && !/challenge-platform/.test(r.url()) && !r.url().endsWith(p)) {
      bad.push(r.status() + ' ' + r.url().slice(0, 100));
    }
  });

  let status = '—';
  try {
    const resp = await page.goto(BASE + p, { waitUntil: 'networkidle2', timeout: 45000 });
    status = resp ? resp.status() : '—';
  } catch (e) { errs.push('NAV: ' + e.message.slice(0, 110)); }
  await new Promise(r => setTimeout(r, 2500));   // let the runtime hydrate

  const r = await page.evaluate(() => ({
    chars: document.body.innerText.trim().length,
    buttons: document.querySelectorAll('button').length,
    images: document.querySelectorAll('img').length,
    broken: [...document.querySelectorAll('img')].filter(i => i.complete && i.naturalWidth === 0).length,
    unhydrated: (document.body.innerHTML.match(/\{\{\s*[a-zA-Z]/g) || []).length,
    title: document.title,
  })).catch(() => ({ chars: 0, buttons: 0, images: 0, broken: 0, unhydrated: 0, title: '(page would not evaluate)' }));

  rows.push({ p, status, ...r, viol, errs, bad, tokenReqs });
  await page.close();
}

await browser.close();

let findings = 0;
for (const r of rows) {
  console.log(
    `\n${r.p.padEnd(26)} [${r.status}]  text=${String(r.chars).padEnd(6)}buttons=${String(r.buttons).padEnd(4)}` +
    `images=${String(r.images).padEnd(4)}broken=${String(r.broken).padEnd(3)}tokens=${r.unhydrated}`
  );
  console.log('   ' + r.title);
  const say = (label, list) => { if (list.length) { findings += list.length; console.log('   ' + label + ': ' + list.slice(0, 4).join('\n      ')); } };
  say('CSP VIOLATION', r.viol);
  say('FETCHED A TOKEN AS A URL', r.tokenReqs);
  say('PAGE ERROR', r.errs);
  say('FAILED REQUEST', r.bad);
  if (r.chars > 0 && r.buttons === 0 && ['/', '/admin', '/driver'].includes(r.p)) {
    findings++;
    console.log('   NO BUTTONS — the runtime probably did not evaluate. This is what a broken CSP looks like.');
  }
}

console.log('\n' + (findings ? findings + ' finding(s)' : 'clean — every page rendered and nothing failed'));
process.exit(findings ? 1 : 0);
