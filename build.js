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
import { FAQ } from './content/faq-data.js';

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
  ['terms.html', 'Terms & Conditions',
   'Booking, payment, cancellation and call-out terms for mobile mechanic, tyre fitting and recovery work by Cousins Mechanical Services in Bridport & West Dorset.'],
  ['privacy.html', 'Privacy Policy',
   'What personal data Cousins Mechanical Services collects when you book a mobile mechanic, why we hold it, how long for, and the rights you have under UK GDPR.'],
  ['cookies.html', 'Cookie Policy',
   'The cookies and browser storage the Cousins Mechanical Services site uses, what each one does, which need your consent, and how to change your mind later.'],
  ['accessibility.html', 'Accessibility Statement',
   'How the Cousins Mechanical Services booking site is built to be usable with a keyboard, a screen reader or a small screen — and how to tell us if it is not.'],
];

/*
 * Content pages — the ones that exist to be found.
 *
 * The site was five pages: a home page and four legal notices. Everything the
 * business actually sells lived in fragments of the home page (#services,
 * #reg), and a fragment is not a page — Google collapses /#services into "/"
 * and indexes one thing. So there was exactly ONE indexable page competing for
 * every term, and no page whose title, headings and body were about any single
 * service.
 *
 * These are real pages with real content, one per thing somebody actually
 * searches for. Deliberately NOT one page per town: nine near-identical
 * "mobile mechanic in <town>" pages is the textbook doorway-page pattern
 * Google demotes for, and it would put the client's own visibility at risk to
 * chase it. One honest areas page, with something different to say about each
 * place, does the same job without the exposure.
 *
 *   [slug, title, description, primary keyword — for the audit trail]
 */
/*
 * `title` is the <title> tag and is kept under about 60 characters, because
 * that is where Google truncates one in a result. It is NOT the same string as
 * the h1: the h1 can afford to be a full sentence, the title cannot, and
 * forcing them to match makes one of the two worse. `crumb` is the breadcrumb
 * label. `keyword` is the term the page is built to answer for and exists so
 * that a future edit can be checked against the intent rather than guessed at.
 */
const CONTENT = [
  { slug: 'mobile-tyre-fitting.html',
    title: 'Mobile Tyre Fitting Bridport',
    crumb: 'Mobile tyre fitting',
    desc: 'New tyres supplied and fitted at your home, work or the roadside across Bridport, Dorchester, Weymouth and West Dorset. Prices include fitting. Book online.',
    keyword: 'mobile tyre fitting Bridport' },
  { slug: '24-hour-breakdown-recovery.html',
    title: '24hr Breakdown & Recovery Dorset',
    crumb: '24 hour breakdown & recovery',
    desc: '24 hour roadside assistance and vehicle recovery across Bridport, Dorchester, Weymouth and West Dorset. Roadside repair where possible, recovery where not.',
    keyword: '24 hour breakdown recovery Bridport' },
  { slug: 'mobile-car-servicing.html',
    title: 'Mobile Car Servicing, Bridport',
    crumb: 'Mobile car servicing',
    desc: 'Interim and full car servicing on your driveway or at work, across Bridport and West Dorset. Manufacturer schedule, warranty safe, price agreed before we start.',
    keyword: 'mobile car servicing Bridport' },
  { slug: 'car-diagnostics-and-repairs.html',
    title: 'Car Diagnostics & Repairs',
    crumb: 'Diagnostics & repairs',
    desc: 'Engine fault codes read and explained, plus brakes, clutches, timing belts and mobile welding for MOT repairs, carried out at your home or work in West Dorset.',
    keyword: 'car diagnostics Bridport' },
  { slug: 'areas-we-cover.html',
    title: 'Areas We Cover in West Dorset',
    crumb: 'Areas we cover',
    desc: 'Where we work: Bridport, Dorchester, Weymouth, Portland, Lyme Regis, Beaminster, Charmouth, Axminster and Crewkerne. The same call-out charge across the area.',
    keyword: 'mobile mechanic West Dorset' },
  { slug: 'faq.html',
    title: 'Common Questions',
    crumb: 'FAQ',
    desc: 'Call-out charges, the areas we cover, finding your tyre size, payment, warranties and how to book — the questions customers actually ask before they call us.',
    keyword: 'mobile mechanic questions' },
];

/*
 * Which service each content page is about, for Service schema.
 * Only pages that describe a service get one; /areas-we-cover and /faq do not.
 */
// Footer labels — the full page titles are too long for a footer column.
const SHORT_LABEL = {
  'mobile-tyre-fitting.html': 'Mobile tyre fitting',
  '24-hour-breakdown-recovery.html': '24hr breakdown &amp; recovery',
  'mobile-car-servicing.html': 'Mobile servicing',
  'car-diagnostics-and-repairs.html': 'Diagnostics &amp; repairs',
  'areas-we-cover.html': 'Areas we cover',
  'faq.html': 'FAQ',
};

const SERVICE_SCHEMA = {
  'mobile-tyre-fitting.html': ['Mobile tyre fitting', 'New tyres supplied and fitted at the customer\u2019s home, workplace or the roadside, including balancing, a new valve and disposal of the old tyre.'],
  '24-hour-breakdown-recovery.html': ['24 hour breakdown and recovery', 'Round-the-clock roadside assistance and vehicle recovery across West Dorset.'],
  'mobile-car-servicing.html': ['Mobile car servicing', 'Interim and full vehicle servicing carried out at the customer\u2019s home or workplace to the manufacturer schedule.'],
  'car-diagnostics-and-repairs.html': ['Car diagnostics and mobile repairs', 'Engine fault-code diagnostics, brakes, clutches, timing belts and mobile welding carried out at the customer\u2019s address.'],
};

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

function pageLayout(slug, title, desc, body, opts = {}) {
  const nav = (href, label) => `<a href="${href}" style="color:#d9d2cc;font-weight:600;font-size:14.5px;text-decoration:none">${label}</a>`;
  const foot = (href, label) => `<a href="${href}" style="color:#9a918a;font-size:14px;text-decoration:none">${label}</a>`;
  const legalCol = LEGAL.map(([s, t]) => foot(canonicalPath(s), t)).join('\n        ');
  const legalBar = LEGAL.map(([s, t]) => `<a href="${canonicalPath(s)}" style="color:#6f6862;text-decoration:none">${t}</a>`).join('\n      ');
  const serviceCol = CONTENT.map(c => foot(canonicalPath(c.slug), SHORT_LABEL[c.slug] || c.crumb)).join('\n        ');

  /*
   * Breadcrumbs, visible and marked up.
   *
   * The visible trail is what stops a visitor arriving from a search result on
   * /mobile-tyre-fitting with no idea what site they are on. The BreadcrumbList
   * is what lets Google print "cousinsmechanicalservices.co.uk > Mobile tyre
   * fitting" instead of a raw URL under the result.
   */
  const crumb = opts.crumb
    ? `<nav aria-label="Breadcrumb" style="margin:0 0 18px;font-size:14px;color:#8a817b">
  <a href="/" style="color:#c25e0c;font-weight:600;text-decoration:none">Home</a>
  <span aria-hidden="true" style="margin:0 7px">&rsaquo;</span>
  <span>${opts.crumb}</span>
</nav>`
    : '';
  const crumbLd = opts.crumb ? [{
    '@context': 'https://schema.org', '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: `${SITE}/` },
      { '@type': 'ListItem', position: 2, name: opts.crumb, item: `${SITE}/${canonicalPath(slug)}` },
    ],
  }] : [];

  const ld = [...crumbLd, ...(opts.schema || [])]
    .map(o => `<script type="application/ld+json">\n${JSON.stringify(o, null, 2)}\n</script>`)
    .join('\n');

  return `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} | ${BUSINESS.name}</title>
<meta name="description" content="${desc}">
<meta name="theme-color" content="#14100e">
<link rel="canonical" href="${SITE}/${canonicalPath(slug)}">
<!--
  Open Graph. Absent, a link to any of these pages pasted into WhatsApp or
  Facebook rendered as a bare URL with no title, no description and no picture
  — on a site whose customers arrange jobs over WhatsApp.
-->
<meta property="og:type" content="website">
<meta property="og:site_name" content="${BUSINESS.name}">
<meta property="og:title" content="${title} | ${BUSINESS.name}">
<meta property="og:description" content="${desc}">
<meta property="og:url" content="${SITE}/${canonicalPath(slug)}">
<meta property="og:image" content="${SITE}/images/tyre-van.jpg">
<meta property="og:locale" content="en_GB">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${title} | ${BUSINESS.name}">
<meta name="twitter:description" content="${desc}">
<meta name="twitter:image" content="${SITE}/images/tyre-van.jpg">
<meta name="geo.region" content="GB-DOR">
<meta name="geo.placename" content="Bridport, Dorset">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;600;700&family=Barlow+Condensed:wght@600;700;800&display=swap" rel="stylesheet">
<!--
  Icons.
  Google picks the favicon for a search result from the site's home page, and
  asks for a square icon whose side is a multiple of 48px. What was here was
  192 and 512 — 512 is not a multiple of 48 — and /favicon.ico, which browsers
  fetch whether or not it is declared, held a single 32x32 image and was not
  declared at all. It now carries 16, 32 and 48, and the small PNG sizes Google
  reaches for first are listed explicitly.

  Absolute paths on purpose: a relative href resolves against the page, so the
  same tag would point somewhere different from a URL with a deeper path.
-->
<link rel="icon" href="/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="icon" type="image/png" sizes="48x48" href="/images/icon-48.png">
<link rel="icon" type="image/png" sizes="96x96" href="/images/icon-96.png">
<link rel="icon" type="image/png" sizes="192x192" href="/images/icon-192.png">
<link rel="apple-touch-icon" sizes="180x180" href="/images/apple-touch-icon.png">
${ld}
<style>
  *{box-sizing:border-box}
  body{margin:0;background:#f4f2ef;font-family:'Barlow',system-ui,sans-serif;color:#1c1817;-webkit-font-smoothing:antialiased;line-height:1.6}
  .wrap{max-width:1200px;margin:0 auto;padding:0 20px}
  header nav a:hover{color:#f4a04a}
  .legal-main{max-width:820px;margin:0 auto;padding:48px 20px 72px}
  /* h1 is the page title, h2 a section, h3 a sub-section. It used to open at
     h2 with no h1 anywhere on four pages — a heading outline with no top. */
  .legal-main h1{font-family:'Barlow Condensed';font-weight:800;font-size:clamp(32px,5vw,46px);line-height:1.02;margin:0 0 10px;color:#14100e}
  .legal-main h2{font-family:'Barlow Condensed';font-weight:700;font-size:26px;margin:34px 0 8px;color:#14100e}
  .legal-main h3{font-family:'Barlow Condensed';font-weight:700;font-size:20px;margin:26px 0 8px;color:#1c1817}
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
  .foot-grid{display:grid;grid-template-columns:1.3fr 1fr 1fr 1fr 1fr;gap:28px}
  @media(max-width:1000px){.foot-grid{grid-template-columns:1fr 1fr 1fr}}
  @media(max-width:760px){.foot-grid{grid-template-columns:1fr 1fr}}
  @media(max-width:520px){.foot-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header style="position:sticky;top:0;z-index:60;background:rgba(20,16,14,.96);backdrop-filter:blur(8px);border-bottom:1px solid #2a2320">
  <div class="wrap" style="display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:11px;padding-bottom:11px">
    <a href="/" style="display:flex;align-items:center;gap:12px">
      <span style="display:inline-flex;align-items:center;background:#fff;border-radius:11px;padding:7px 13px;box-shadow:0 3px 12px rgba(0,0,0,.35)"><img src="images/logo.png" alt="${BUSINESS.name}" style="height:36px;width:auto;display:block"/></span>
    </a>
    <nav style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;justify-content:flex-end">
      ${nav('/', 'Home')}
      ${nav('/#services', 'Services')}
      ${nav('/areas-we-cover', 'Areas')}
      ${nav('/#reg', 'Tyres &amp; Parts')}
      ${nav('/faq', 'FAQ')}
      ${nav('/#track', 'Track Job')}
      <a href="/#reg" style="background:#e8791a;color:#14100e;font-weight:700;padding:9px 16px;border-radius:8px;font-size:14.5px;text-decoration:none">Book online</a>
    </nav>
  </div>
</header>

<main class="legal-main">
${crumb}${body}
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
        ${foot('/', 'Home')}
        ${foot('/#services', 'Services')}
        ${foot('/#reg', 'Tyres &amp; Parts')}
        ${foot('/#work', 'Recent Work')}
        ${foot('/#track', 'Track Job')}
        ${foot('/#reg', 'Book online')}
      </div>
    </div>
    <div>
      <div style="font-family:'Barlow Condensed';font-weight:700;color:#fff;font-size:16px;letter-spacing:.08em;margin-bottom:14px">SERVICES</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        ${serviceCol}
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
  fs.writeFileSync(path.join(PUBLIC, slug), pageLayout(slug, title, desc, body));
  console.log(`  legal/${slug}  ->  public/${slug}`);
}

// ---------------------------------------------------------------------------
// Content pages — the ones that exist to be found.
// ---------------------------------------------------------------------------
/*
 * The FAQ page is rendered from content/faq-data.js, and so is its FAQPage
 * JSON-LD. Google requires the marked-up questions and answers to match what a
 * visitor can read; generating both from one array is the only way that cannot
 * quietly stop being true.
 */
function faqBody() {
  const esc = t => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<h1>Frequently Asked Questions</h1>
<p class="lead">Call-out charges, where we come out to, how to find your tyre size, payment and booking. If your question is not here, call <a href="tel:${BUSINESS.phoneHref}">${BUSINESS.phone}</a> and ask.</p>
${FAQ.map(({ q, a }) => `
<h2>${esc(q)}</h2>
<p>${esc(a)}</p>`).join('\n')}

<h2>Still not answered?</h2>
<p>Call <a href="tel:${BUSINESS.phoneHref}">${BUSINESS.phone}</a>, or <a href="/#book">book online</a> and put the detail in the notes. For a breakdown, phone — it is always faster than a form.</p>
`;
}

const faqSchema = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: FAQ.map(({ q, a }) => ({
    '@type': 'Question', name: q,
    acceptedAnswer: { '@type': 'Answer', text: a },
  })),
};

for (const { slug, title, desc, crumb } of CONTENT) {
  const isFaq = slug === 'faq.html';
  const bodyPath = path.join(__dirname, 'content', slug);
  if (!isFaq && !fs.existsSync(bodyPath)) {
    console.error(`  MISSING  content/${slug} — cannot build content page`);
    process.exitCode = 1;
    continue;
  }
  const body = isFaq ? faqBody() : fillBusinessTokens(fs.readFileSync(bodyPath, 'utf8'));

  const schema = [];
  if (isFaq) schema.push(faqSchema);
  const svc = SERVICE_SCHEMA[slug];
  if (svc) {
    schema.push({
      '@context': 'https://schema.org',
      '@type': 'Service',
      name: svc[0],
      description: svc[1],
      serviceType: svc[0],
      url: `${SITE}/${canonicalPath(slug)}`,
      // The business is declared in full on the home page; this points at that
      // same node rather than describing a second, subtly different company.
      provider: { '@type': 'AutoRepair', '@id': `${SITE}/#business`, name: BUSINESS.legalName },
      areaServed: ['Bridport', 'Dorchester', 'Weymouth', 'Lyme Regis', 'Beaminster', 'Charmouth', 'Axminster', 'Crewkerne', 'West Dorset']
        .map(name => ({ '@type': 'City', name })),
      availableChannel: {
        '@type': 'ServiceChannel',
        serviceUrl: `${SITE}/#book`,
        servicePhone: { '@type': 'ContactPoint', telephone: BUSINESS.phoneHref, contactType: 'customer service' },
      },
    });
  }

  fs.writeFileSync(path.join(PUBLIC, slug), pageLayout(slug, title, desc, body, { schema, crumb }));
  console.log(`  content/${slug}  ->  public/${slug}`);
}

// Branded 404 — same header/footer as every other public page, so a bad link
// still lands somewhere that can take a booking. Wired up in wrangler.toml via
// [assets] not_found_handling = "404-page". Deliberately NOT in the sitemap.
{
  const notFoundBody = path.join(__dirname, 'legal', '404.html');
  if (fs.existsSync(notFoundBody)) {
    fs.writeFileSync(
      path.join(PUBLIC, '404.html'),
      pageLayout('404.html', 'Page not found', `That page does not exist. Find tyre prices, our services, or call ${BUSINESS.name} on ${BUSINESS.phone}.`, fillBusinessTokens(fs.readFileSync(notFoundBody, 'utf8')))
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
const git = args => {
  try {
    return execFileSync('git', args, { cwd: __dirname, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch (e) { return null; }   // no git, a tarball, a shallow CI copy
};

const lastmodOf = file => {
  /*
   * A file changed in the working tree is about to be committed, so its date
   * is TODAY — not the date of the last commit that touched it.
   *
   * Without this the generated sitemap can never be right at the moment it is
   * written. lastmodOf asks git "when was this last committed?", but the
   * sitemap is committed in the SAME commit as the pages it describes, and
   * that commit does not exist yet at build time. So every build produced a
   * sitemap one commit stale, and the committed artefact disagreed with what
   * was deployed. That is exactly how public/sitemap.xml ended up claiming
   * /terms last changed on 29 August while the live one, built after the
   * commit landed, correctly said 9 September.
   */
  if (git(['status', '--porcelain', '--', file])) return new Date().toISOString().slice(0, 10);

  /*
   * AUTHOR date, not committer date.
   *
   * `git am` and `git rebase` rewrite the committer date and preserve the
   * author date. Changes reach the deploy clone as patches applied with
   * `git am`, so a committer date makes the two clones generate different
   * sitemaps for identical content — the precise failure this function's
   * original comment set out to avoid by not using mtime.
   */
  const out = git(['log', '-1', '--format=%as', '--', file]);
  if (out && /^\d{4}-\d{2}-\d{2}$/.test(out)) return out;

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
  { loc: '/mobile-tyre-fitting', changefreq: 'monthly', priority: '0.9', file: 'content/mobile-tyre-fitting.html' },
  { loc: '/24-hour-breakdown-recovery', changefreq: 'monthly', priority: '0.9', file: 'content/24-hour-breakdown-recovery.html' },
  { loc: '/mobile-car-servicing', changefreq: 'monthly', priority: '0.8', file: 'content/mobile-car-servicing.html' },
  { loc: '/car-diagnostics-and-repairs', changefreq: 'monthly', priority: '0.8', file: 'content/car-diagnostics-and-repairs.html' },
  { loc: '/areas-we-cover', changefreq: 'monthly', priority: '0.8', file: 'content/areas-we-cover.html' },
  { loc: '/faq', changefreq: 'monthly', priority: '0.7', file: 'content/faq-data.js' },
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
