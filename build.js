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
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(__dirname, 'public');

const PAGES = [
  ['Cousins Mechanical.dc.html', 'index.html'],
  ['Cousins Admin.dc.html', 'admin.html'],
  ['Cousins Driver.dc.html', 'driver.html'],
];

fs.mkdirSync(PUBLIC, { recursive: true });

let copied = 0;
for (const [src, dest] of PAGES) {
  const from = path.join(__dirname, src);
  if (!fs.existsSync(from)) {
    console.error(`  MISSING  ${src} — cannot build`);
    process.exitCode = 1;
    continue;
  }
  fs.copyFileSync(from, path.join(PUBLIC, dest));
  console.log(`  ${src}  ->  public/${dest}`);
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
// Sitemap — generated at build time so lastmod tracks the real page instead of
// going stale the moment someone edits the site.
// ---------------------------------------------------------------------------
const SITE = (process.env.SITE_URL || 'https://cousinsmechanicalservices.co.uk').replace(/\/+$/, '');
const lastmodOf = file => {
  const p = path.join(__dirname, file);
  return (fs.existsSync(p) ? fs.statSync(p).mtime : new Date()).toISOString().slice(0, 10);
};
const homeModified = lastmodOf('Cousins Mechanical.dc.html');

// Only genuinely public, indexable destinations. The admin and driver portals are
// staff-only and are excluded here and in robots.txt.
const urls = [
  { loc: '/', changefreq: 'weekly', priority: '1.0' },
  { loc: '/#services', changefreq: 'monthly', priority: '0.8' },
  { loc: '/#reg', changefreq: 'weekly', priority: '0.9' },
  { loc: '/#work', changefreq: 'monthly', priority: '0.7' },
  { loc: '/#track', changefreq: 'monthly', priority: '0.5' },
  { loc: '/#privacy', changefreq: 'yearly', priority: '0.3' },
];

const sitemap =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
  urls.map(u => [
    '  <url>',
    `    <loc>${SITE}${u.loc}</loc>`,
    `    <lastmod>${homeModified}</lastmod>`,
    `    <changefreq>${u.changefreq}</changefreq>`,
    `    <priority>${u.priority}</priority>`,
    '  </url>',
  ].join('\n')).join('\n') +
  '\n</urlset>\n';

fs.writeFileSync(path.join(PUBLIC, 'sitemap.xml'), sitemap);
console.log(`  sitemap.xml  ->  ${urls.length} URLs (lastmod ${homeModified})`);

console.log(`\nBuild complete — ${copied}/${PAGES.length} pages synced to public/`);
