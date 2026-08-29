#!/usr/bin/env node
/*
 * build.js — sync the authored .dc.html pages into ./public for static deploys.
 *
 * The three .dc.html files in the project root are the source of truth. Cloudflare
 * Pages / Workers serve ./public, so they must be copied in before every deploy.
 * Running this by hand is how the two copies drifted apart before; `npm run build`
 * and `npm run deploy` both call it now, so they cannot drift again.
 */
import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { neutralisePlaceholderFetches } from './dc-placeholder.js';
import { BUSINESS, fillBusinessTokens } from './business.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, 'public');

const PAGES = [
  ['Cousins Mechanical.dc.html', 'index.html'],
  ['Cousins Admin.dc.html', 'admin.html'],
  ['Cousins Driver.dc.html', 'driver.html'],
];

// Canonical site origin (also used by the sitemap below).
const SITE = (process.env.SITE_URL || 'https://cousinsmechanicalservices.co.uk').replace(/\/+$/, '');

// Legal / info pages. Bodies live in ./legal/<slug>; the shared header + footer
// (one menu bar for the whole public site) are applied by legalLayout() below.
const LEGAL = [
  ['terms.html', 'Terms & Conditions', `Booking, payment, cancellation, tyre fitting and liability terms for ${BUSINESS.name}.`],
  ['privacy.html', 'Privacy Policy', `How ${BUSINESS.name} collects and uses your personal data under UK GDPR.`],
  ['cookies.html', 'Cookie Policy', `The cookies and browser storage used on the ${BUSINESS.name} website.`],
  ['accessibility.html', 'Accessibility Statement', `How we make the ${BUSINESS.name} website usable for everyone.`],
];

/*
 * The address a page is actually reachable at.
 *
 * Cloudflare's asset handling redirects /terms.html to /terms, so every
 * .html link and every .html <loc> in the sitemap was a 307 on the way to the
 * real page. Worse, /terms declared its canonical as /terms.html — the page
 * pointing at the URL that redirects back to it. Harmless to a browser, but a
 * crawler is being told two contradictory things about which URL to index.
 *
 * One function, used by the canonical tag, the internal links and the sitemap,
 * so those three can never drift apart again.
 */
const canonicalPath = slug => slug.replace(/\.html$/, '');

function legalLayout(slug, title, desc, body) {
  const nav = (href, label) => `<a href="${href}" style="color:#d9d2cc;font-weight:600;font-size:14.5px;text-decoration:none">${label}</a>`;
  const foot = (href, label) => `<a href="${href}" style="color:#9a918a;font-size:14px;text-decoration:none">${label}</a>`;
  const legalCol = LEGAL.map(([s, t]) => foot(canonicalPath(s), t)).join('\n        ');
  const legalBar = LEGAL.map(([s, t]) => `<a href="${canonicalPath(s)}" style="color:#6f6862;text-decoration:none">${t}</a>`).join('\n      ');
  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} | ${BUSINESS.name}</title>
<meta name="description" content="${desc}">
<meta name="theme-color" content="#14100e">
<link rel="canonical" href="${SITE}/${canonicalPath(slug)}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600;700&family=Barlow+Condensed:wght@600;700;800&display=swap" rel="stylesheet">
<link rel="icon" type="image/png" sizes="192x192" href="images/icon-192.png">
<link rel="apple-touch-icon" sizes="180x180" href="images/apple-touch-icon.png">
<style>
  *{box-sizing:border-box}
  body{margin:0;background:#f4f2ef;font-family:'Barlow',system-ui,sans-serif;color:#1c1817;-webkit-font-smoothing:antialiased;line-height:1.6}
  .wrap{max-width:1200px;margin:0 auto;padding:0 20px}
  header nav a:hover{color:#f4a04a}
  .legal-main{max-width:820px;margin:0 auto;padding:48px 20px 72px}
  .legal-main h2{font-family:'Barlow Condensed';font-weight:800;font-size:clamp(32px,5vw,46px);line-height:1.02;margin:0 0 10px;color:#14100e}
  .legal-main h3{font-family:'Barlow Condensed';font-weight:700;font-size:22px;margin:30px 0 8px;color:#1c1817}
  .legal-main p,.legal-main li{font-size:16px;color:#3d3833}
  .legal-main p.lead{font-size:18px;color:#5c534d;margin:0 0 20px}
  .legal-main ul{padding-left:20px}
  .legal-main a{color:#c25e0c;font-weight:600}
  .legal-main p.updated{margin-top:36px;color:#8a817b;font-size:13.5px;border-top:1px solid #e0d9d2;padding-top:16px}
  /* The processor and retention tables. Wide content scrolls inside its own
     box so a phone never ends up scrolling the whole page sideways. */
  .legal-main table{border-collapse:collapse;width:100%;margin:14px 0 6px;font-size:14.5px;display:block;overflow-x:auto;white-space:normal}
  .legal-main thead{background:#eae5df}
  .legal-main th,.legal-main td{text-align:left;padding:9px 12px;border:1px solid #e0d9d2;vertical-align:top;min-width:110px}
  .legal-main th{font-family:'Barlow Condensed';font-weight:700;font-size:12.5px;letter-spacing:.06em;text-transform:uppercase;color:#5c534d;white-space:nowrap}
  .legal-main td{color:#3d3833}
  .legal-main code{background:#eae5df;border-radius:4px;padding:1px 5px;font-size:13px}
  .foot-grid{display:grid;grid-template-columns:1.4fr 1fr 1fr 1fr;gap:32px}
  @media(max-width:760px){.foot-grid{grid-template-columns:1fr 1fr}}
  @media(max-width:520px){.foot-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header style="position:sticky;top:0;z-index:60;background:rgba(20,16,14,.96);backdrop-filter:blur(8px);border-bottom:1px solid #2a2320">
  <div class="wrap" style="display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:11px;padding-bottom:11px">
    <a href="index.html" style="display:flex;align-items:center;gap:12px">
      <span style="display:inline-flex;align-items:center;background:#fff;border-radius:11px;padding:7px 13px;box-shadow:0 3px 12px rgba(0,0,0,.35)"><img src="images/logo.png" alt="${BUSINESS.name}" style="height:36px;width:auto;display:block"/></span>
    </a>
    <nav style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;justify-content:flex-end">
      ${nav('index.html', 'Home')}
      ${nav('index.html#services', 'Services')}
      ${nav('index.html#reg', 'Tyres &amp; Parts')}
      ${nav('index.html#work', 'Recent Work')}
      ${nav('index.html#track', 'Track Job')}
      <a href="index.html#reg" style="background:#e8791a;color:#14100e;font-weight:700;padding:9px 16px;border-radius:8px;font-size:14.5px;text-decoration:none">Book online</a>
    </nav>
  </div>
</header>

<main class="legal-main">
${body}
</main>

<footer style="background:#0f0c0b;color:#cfc7c1;padding:56px 0 26px">
  <div class="wrap foot-grid">
    <div>
      <span style="display:inline-flex;align-items:center;background:#fff;border-radius:14px;padding:12px 18px;margin-bottom:16px;box-shadow:0 4px 16px rgba(0,0,0,.3)"><img src="images/logo.png" alt="${BUSINESS.name}" style="height:50px;width:auto;display:block"/></span>
      <p style="color:#9a918a;font-size:14px;line-height:1.6;max-width:320px">Mobile mechanic, tyre fitting and 24hr breakdown &amp; recovery covering Bridport, Dorchester &amp; West Dorset. We come to your home, work or the roadside.</p>
      <div style="display:flex;gap:10px;margin-top:16px">
        <a href="https://wa.me/447925340977" target="_blank" rel="noopener" style="background:#25d366;color:#0a2c17;font-weight:700;border-radius:9px;padding:9px 15px;font-size:14px;text-decoration:none">WhatsApp</a>
        <a href="https://maps.google.com/?q=Bridport,+Dorset" target="_blank" rel="noopener" style="background:#1c1817;color:#fff;font-weight:700;border-radius:9px;padding:9px 15px;font-size:14px;text-decoration:none">Our area</a>
      </div>
    </div>
    <div>
      <div style="font-family:'Barlow Condensed';font-weight:700;color:#fff;font-size:16px;letter-spacing:.08em;margin-bottom:14px">PAGES</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        ${foot('index.html', 'Home')}
        ${foot('index.html#services', 'Services')}
        ${foot('index.html#reg', 'Tyres &amp; Parts')}
        ${foot('index.html#work', 'Recent Work')}
        ${foot('index.html#track', 'Track Job')}
        ${foot('index.html#reg', 'Book online')}
      </div>
    </div>
    <div>
      <div style="font-family:'Barlow Condensed';font-weight:700;color:#fff;font-size:16px;letter-spacing:.08em;margin-bottom:14px">LEGAL</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        ${legalCol}
      </div>
    </div>
    <div>
      <div style="font-family:'Barlow Condensed';font-weight:700;color:#fff;font-size:16px;letter-spacing:.08em;margin-bottom:14px">CONTACT</div>
      <div style="display:flex;flex-direction:column;gap:10px;font-size:14px">
        <a href="tel:${BUSINESS.phoneHref}" style="color:#f4a04a;font-weight:700;text-decoration:none">${BUSINESS.phone}</a>
        <a href="tel:${BUSINESS.landlineHref}" style="color:#cfc7c1;text-decoration:none">${BUSINESS.landline}</a>
        <span style="color:#9a918a">Bridport, West Dorset</span>
        <span style="color:#9a918a">Breakdown &amp; recovery 24 hours</span>
      </div>
    </div>
  </div>
  <div class="wrap" style="margin-top:32px;border-top:1px solid #241e1b;padding-top:18px;display:flex;flex-wrap:wrap;gap:10px 18px;justify-content:space-between;align-items:center;color:#6f6862;font-size:13px">
    <span>&copy; ${BUSINESS.legalName} &middot; Registered in England &amp; Wales no. ${BUSINESS.companyNumber} &middot; ${BUSINESS.registeredOffice}</span>
    <span style="display:flex;flex-wrap:wrap;gap:14px">
      ${legalBar}
    </span>
    <a href="admin.html" style="color:#6f6862;font-weight:600;text-decoration:none">Staff login</a>
  </div>
</footer>
</body>
</html>
`;
}

fs.mkdirSync(PUBLIC, { recursive: true });

let copied = 0;
for (const [src, dest] of PAGES) {
  const from = path.join(__dirname, src);
  if (!fs.existsSync(from)) {
    console.error(`  MISSING  ${src} — cannot build`);
    process.exitCode = 1;
    continue;
  }
  const { out, n } = neutralisePlaceholderFetches(fs.readFileSync(from, 'utf8'));
  fs.writeFileSync(path.join(PUBLIC, dest), out);
  console.log(`  ${src}  ->  public/${dest}${n ? `  (${n} placeholder fetch${n === 1 ? '' : 'es'} neutralised)` : ''}`);
  copied++;
}

// The site loads ./support.js and vehicle-data.js relative to the page, so they
// must sit next to the HTML in public/ as well.
for (const asset of ['support.js', 'vehicle-data.js']) {
  const inPublic = path.join(PUBLIC, asset);
  if (!fs.existsSync(inPublic)) {
    console.error(`  WARNING  public/${asset} is missing — pages will fail to render`);
    process.exitCode = 1;
  }
}

// The tyre catalogue is fetched by the Worker through the ASSETS binding, so it
// has to be in public/ — not just in data/. Missing here means production silently
// falls back to placeholder prices.
for (const asset of ['data/tyre-catalogue.json', 'data/tyre-cost.json', 'data/tyre-sizes.json']) {
  if (!fs.existsSync(path.join(PUBLIC, asset))) {
    console.error(`  ERROR  public/${asset} is missing — live tyre pricing will not work`);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Legal / info pages — one shared menu bar + footer wraps each body so every
// public page is linked together. Bodies are in ./legal; chrome is legalLayout.
// ---------------------------------------------------------------------------
for (const [slug, title, desc] of LEGAL) {
  const bodyPath = path.join(__dirname, 'legal', slug);
  if (!fs.existsSync(bodyPath)) {
    console.error(`  MISSING  legal/${slug} — cannot build legal page`);
    process.exitCode = 1;
    continue;
  }
  // Legal bodies are plain HTML; {{ business.x }} in them is filled here, so
  // the company number and address in a privacy notice cannot drift from the
  // ones in the footer.
  const body = fillBusinessTokens(fs.readFileSync(bodyPath, 'utf8'));
  fs.writeFileSync(path.join(PUBLIC, slug), legalLayout(slug, title, desc, body));
  console.log(`  legal/${slug}  ->  public/${slug}`);
}

// Branded 404 — same header/footer as every other public page, so a bad link
// still lands somewhere that can take a booking. Wired up in wrangler.toml via
// [assets] not_found_handling = "404-page". Deliberately NOT in the sitemap.
{
  const notFoundBody = path.join(__dirname, 'legal', '404.html');
  if (fs.existsSync(notFoundBody)) {
    fs.writeFileSync(
      path.join(PUBLIC, '404.html'),
      legalLayout('404.html', 'Page not found', `That page does not exist. Find tyre prices, our services, or call ${BUSINESS.name} on ${BUSINESS.phone}.`, fillBusinessTokens(fs.readFileSync(notFoundBody, 'utf8')))
    );
    console.log('  legal/404.html  ->  public/404.html');
  } else {
    console.error('  MISSING  legal/404.html — no branded 404 page');
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Sitemap — generated at build time so lastmod tracks the real page instead of
// going stale the moment someone edits the site.
// ---------------------------------------------------------------------------
/*
 * When did this page last actually change?
 *
 * From git, not from the file's mtime. A fresh `git clone` stamps every file
 * with the moment of the clone, so an mtime-based sitemap says "everything
 * changed today" on any new machine — which is both a lie to Google and a
 * working tree that is dirty the instant anyone runs the build. Two people on
 * two clones could never agree on the output.
 *
 * The commit date is the same on every checkout, which is the whole point.
 * Falls back to mtime where git is not available (a tarball, a CI shallow
 * copy with no history), because a slightly wrong date beats a failed build.
 */
const lastmodOf = file => {
  try {
    const out = execFileSync('git', ['log', '-1', '--format=%cs', '--', file],
      { cwd: __dirname, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(out)) return out;
  } catch (e) { /* no git, or the file is untracked — fall through */ }
  const p = path.join(__dirname, file);
  return (fs.existsSync(p) ? fs.statSync(p).mtime : new Date()).toISOString().slice(0, 10);
};
const homeModified = lastmodOf('Cousins Mechanical.dc.html');

// Only genuinely public, indexable destinations. The admin and driver portals are
// staff-only and are excluded here and in robots.txt.
// Only real, separately-addressable pages. Fragment URLs (/#services etc.) were
// listed here before, but search engines discard them as duplicates of "/" — they
// only made Search Console report more URLs submitted than could ever be indexed.
const urls = [
  { loc: '/', changefreq: 'weekly', priority: '1.0' },
  { loc: '/terms', changefreq: 'yearly', priority: '0.3', file: 'legal/terms.html' },
  { loc: '/privacy', changefreq: 'yearly', priority: '0.4', file: 'legal/privacy.html' },
  { loc: '/cookies', changefreq: 'yearly', priority: '0.2', file: 'legal/cookies.html' },
  { loc: '/accessibility', changefreq: 'yearly', priority: '0.2', file: 'legal/accessibility.html' },
];

const sitemap =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  urls.map(u => {
    const lm = u.file ? lastmodOf(u.file) : homeModified;
    return [
      '  <url>',
      `    <loc>${SITE}${u.loc}</loc>`,
      `    <lastmod>${lm}</lastmod>`,
      `    <changefreq>${u.changefreq}</changefreq>`,
      `    <priority>${u.priority}</priority>`,
      '  </url>',
    ].join('\n');
  }).join('\n') +
  '\n</urlset>\n';

fs.writeFileSync(path.join(PUBLIC, 'sitemap.xml'), sitemap);
console.log(`  sitemap.xml  ->  ${urls.length} URLs (lastmod ${homeModified})`);

console.log(`\nBuild complete — ${copied}/${PAGES.length} pages synced to public/`);
