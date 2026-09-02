/*
 * server.js — local development server.
 *
 * Runs the exact same worker.js that Cloudflare runs, behind an Express shim that
 * fakes the two bindings the Worker expects (CMS_KV and ASSETS). Anything you can
 * do here works the same deployed, which is the point: the tyre API used to exist
 * only in this file, so it worked locally and 404'd in production.
 *
 * Production runs worker.js on Cloudflare, not this file.
 */
import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import worker, { SECURITY_HEADERS } from './worker.js';
import { catalogueStats } from './tyre-db.js';
import { neutralisePlaceholderFetches } from './dc-placeholder.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// ---------------------------------------------------------------------------
// Secrets
//
// There are deliberately NO hardcoded fallbacks for the security-critical values.
// This file used to ship "admin-token-secret" and "cms_session_pepper_secret_key_12345"
// as defaults, so anyone who ran it in production had a publicly-known admin
// password. Dev now generates a random one per boot and prints it; production
// refuses to start without real values.
// ---------------------------------------------------------------------------
const devGenerated = [];
function requiredSecret(name) {
  const val = process.env[name];
  if (val) return val;
  if (isProd) {
    console.error(`\n  FATAL: ${name} is not set. Refusing to start in production.\n`);
    process.exit(1);
  }
  const generated = crypto.randomBytes(24).toString('base64url');
  devGenerated.push([name, generated]);
  return generated;
}

// ---------------------------------------------------------------------------
// Binding shims
// ---------------------------------------------------------------------------

/**
 * In-memory stand-in for Cloudflare KV.
 * Supports the expirationTtl option the Worker relies on for sessions and
 * rate-limit counters — without it, dev logins never expire and the rate
 * limiter would lock you out permanently.
 */
const kvMap = new Map(); // key -> { value, expiresAt|null }
const CMS_KV = {
  get: async (key) => {
    const rec = kvMap.get(key);
    if (!rec) return null;
    if (rec.expiresAt && Date.now() > rec.expiresAt) { kvMap.delete(key); return null; }
    return rec.value;
  },
  put: async (key, val, options) => {
    const ttl = options?.expirationTtl;
    kvMap.set(key, { value: String(val), expiresAt: ttl ? Date.now() + ttl * 1000 : null });
  },
  delete: async (key) => { kvMap.delete(key); },
  list: async (opts) => {
    const prefix = opts?.prefix || '';
    const keys = [];
    for (const [k, rec] of kvMap.entries()) {
      if (!k.startsWith(prefix)) continue;
      if (rec.expiresAt && Date.now() > rec.expiresAt) { kvMap.delete(k); continue; }
      keys.push({ name: k });
    }
    return { keys, list_complete: true };
  },
};

/**
 * Stand-in for the ASSETS binding. The Worker fetches the tyre catalogue JSON
 * through this, so it must resolve paths the same way Cloudflare serves ./public.
 */
const ASSETS = {
  fetch: async (request) => {
    const url = new URL(typeof request === 'string' ? request : request.url);
    const rel = decodeURIComponent(url.pathname).replace(/^\/+/, '');
    // Block traversal outside public/.
    const target = path.resolve(__dirname, 'public', rel);
    const root = path.resolve(__dirname, 'public');
    if (!target.startsWith(root + path.sep) && target !== root) {
      return new Response('Forbidden', { status: 403 });
    }
    if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
      return new Response('Not found', { status: 404 });
    }
    const ext = path.extname(target).toLowerCase();
    const types = {
      '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
      '.json': 'application/json', '.css': 'text/css; charset=utf-8',
      '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
      '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon',
      '.xml': 'application/xml', '.txt': 'text/plain; charset=utf-8',
      '.webmanifest': 'application/manifest+json',
    };
    return new Response(fs.readFileSync(target), {
      status: 200,
      headers: { 'content-type': types[ext] || 'application/octet-stream' },
    });
  },
};

const env = {
  CMS_KV,
  ASSETS,
  // Lets the test suite read the email confirmation code back from the API,
  // because it has no inbox. NEVER set in production — it is a local dev/test
  // variable, not a Worker secret, so a deployed Worker cannot have it.
  ALLOW_TEST_VERIFY_CODE: isProd ? '' : (process.env.NODE_ENV === 'test' ? 'yes' : ''),
  SESSION_PEPPER: requiredSecret('SESSION_PEPPER'),
  ADMIN_TOKEN: requiredSecret('ADMIN_TOKEN'),
  OVERRIDE_TOKEN: requiredSecret('OVERRIDE_TOKEN'),
  TIRE_API_KEY: process.env.TIRE_API_KEY || '',
  UKVD_API_KEY: process.env.UKVD_API_KEY || '',
  UKVD_BASE: process.env.UKVD_BASE || '',
  SITE_URL: process.env.SITE_URL || `http://localhost:${PORT}`,
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  MAIL_FROM: process.env.MAIL_FROM || '',
  // Which email service carries the mail. The live choice is a dashboard
  // setting stored in KV; this is only the default before anyone has chosen.
  MAIL_PROVIDER: process.env.MAIL_PROVIDER || '',
  TWILIO_API_KEY: process.env.TWILIO_API_KEY || '',
  TWILIO_API_SECRET: process.env.TWILIO_API_SECRET || '',
  TWILIO_SID: process.env.TWILIO_SID || '',
  TWILIO_TOKEN: process.env.TWILIO_TOKEN || '',
  TWILIO_FROM: process.env.TWILIO_FROM || '',
  WHATSAPP_TOKEN: process.env.WHATSAPP_TOKEN || '',
  WHATSAPP_PHONE_ID: process.env.WHATSAPP_PHONE_ID || '',
  GCAL_CLIENT_EMAIL: process.env.GCAL_CLIENT_EMAIL || '',
  GCAL_PRIVATE_KEY: (process.env.GCAL_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
  GCAL_CALENDAR_ID: process.env.GCAL_CALENDAR_ID || '',
  OWNER_PHONE: process.env.OWNER_PHONE || '',
  EXTRA_ORIGINS: process.env.EXTRA_ORIGINS || '',
  ADMIN_EMAILS: process.env.ADMIN_EMAILS || '',
};

/*
 * Everything else the Worker reads.
 *
 * This list used to be hand-maintained above and had drifted twenty-six
 * variables behind worker.js — every OAuth secret among them. The effect was
 * that no sign-in, payment or calendar flow could be exercised locally at all:
 * the dev server always reported them unconfigured, so the only place those
 * paths ran was production, in front of customers. Keep this in step with
 * `grep -o 'env\.[A-Z][A-Z0-9_]*' worker.js`.
 */
for (const name of [
  'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GCAL_REFRESH_TOKEN',
  'APPLE_SERVICES_ID', 'APPLE_TEAM_ID', 'APPLE_KEY_ID', 'APPLE_PRIVATE_KEY',
  'APPLE_DOMAIN_ASSOCIATION',
  'SUMUP_CLIENT_ID', 'SUMUP_CLIENT_SECRET', 'SUMUP_API_KEY', 'SUMUP_MERCHANT_CODE',
  'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET',
  'TURNSTILE_SITE_KEY', 'TURNSTILE_SECRET',
  'HUBSPOT_TOKEN', 'HUBSPOT_PORTAL_ID', 'HUBSPOT_PIPELINE', 'HUBSPOT_WON_STAGE',
  'RESEND_AUDIENCE_ID', 'RESEND_CUSTOMER_AUDIENCE_ID', 'RESEND_WEBHOOK_SECRET',
  'MAIL_REPLY_TO', 'OWNER_EMAIL',
  'TWILIO_STUDIO_FLOW_SID', 'WHATSAPP_REMINDER_TEMPLATE',
]) {
  env[name] = process.env[name] || '';
}
// The .p8 and the service-account key arrive with literal backslash-n when they
// come from a shell or an .env file. The Worker gets real newlines from
// wrangler, so give the dev server the same thing.
if (env.APPLE_PRIVATE_KEY) env.APPLE_PRIVATE_KEY = env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n');

// Google sign-in is server-side OAuth (/api/admin-login-google/*), handled by
// the Worker itself, same as production. There is no Firebase project.

// ---------------------------------------------------------------------------
// Everything under /api, /v1, /ukvd goes to the real Worker
// ---------------------------------------------------------------------------
const handleWorkerRequest = async (req, res) => {
  try {
    const fullUrl = `${req.protocol || 'http'}://${req.get('host') || `localhost:${PORT}`}${req.originalUrl}`;
    const headers = new Headers();
    for (const [key, val] of Object.entries(req.headers)) {
      if (val === undefined) continue;
      if (Array.isArray(val)) for (const v of val) headers.append(key, v);
      else headers.set(key, String(val));
    }

    const init = { method: req.method, headers };
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body?.length) {
      init.body = req.body;
    }

    const ctx = {
      waitUntil: (p) => Promise.resolve(p).catch(err => console.error('Worker task error:', err)),
    };
    const workerRes = await worker.fetch(new Request(fullUrl, init), env, ctx);

    res.status(workerRes.status);
    workerRes.headers.forEach((value, name) => res.setHeader(name, value));
    res.send(Buffer.from(await workerRes.arrayBuffer()));
  } catch (err) {
    console.error('Worker proxy error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

app.use(['/api', '/v1', '/ukvd'], express.raw({ type: '*/*', limit: '1mb' }), handleWorkerRequest);

/*
 * Apple's domain-verification file is served by the Worker, not from public/,
 * so it has to reach the Worker here too. In production run_worker_first sends
 * every request through the fetch handler; this Express app only forwards
 * /api, /v1 and /ukvd, so without this line the file would 404 locally and
 * work live — the exact kind of divergence that hid the last two auth bugs.
 */
app.use(['/.well-known/apple-developer-domain-association.txt',
         '/apple-developer-domain-association.txt'], handleWorkerRequest);

// ---------------------------------------------------------------------------
// Static site
// ---------------------------------------------------------------------------
// Mirror the security headers the Worker sets in production, so dev behaves the
// same as live rather than only looking fine locally.
// Imported from worker.js, not retyped — a hand-copied duplicate drifts, and
// then dev passes a test that production would fail.
app.use((req, res, next) => {
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
  next();
});

const PUBLIC_DIR = path.join(__dirname, 'public');
/*
 * Dev serves the AUTHORED .dc.html so editing is live, but it must serve it
 * through the same transform the build applies — otherwise what you test here
 * is not what ships, which is exactly how the placeholder <img src="{{ ... }}">
 * 404s survived every local check and only showed up in production.
 */
const page = (file, opts) => (req, res) => {
  const authored = path.join(__dirname, file);
  if (!fs.existsSync(authored)) return res.status(404).send('Page not built — run `npm run build`');
  // The staff pages are noindex in production, set by the Worker on the way
  // out. Without the same header here, dev and prod disagree about the one
  // thing that keeps the dashboard out of Google.
  if (opts && opts.noindex) res.set('X-Robots-Tag', 'noindex, nofollow');
  const { out } = neutralisePlaceholderFetches(fs.readFileSync(authored, 'utf8'));
  res.type('html').send(out);
};
app.get(['/', '/index.html'], page('Cousins Mechanical.dc.html'));
app.get(['/admin', '/admin.html'], page('Cousins Admin.dc.html', { noindex: true }));
app.get(['/driver', '/driver.html'], page('Cousins Driver.dc.html', { noindex: true }));

/*
 * Static files come AFTER the three page routes, and that order matters.
 *
 * `extensions: ['html']` mirrors Cloudflare's asset handling, which serves
 * /terms from public/terms.html — without it, dev 404s on exactly the URLs the
 * sitemap and the canonical tags point at. But with the middleware registered
 * first it also answered /admin from public/admin.html, so the routes above
 * never ran: dev quietly stopped serving the AUTHORED .dc.html, which is the
 * entire reason this server exists, and stopped sending the noindex header
 * with it. Editing a .dc.html appeared to do nothing until the next build.
 */
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

/*
 * Serve the branded 404 for anything unmatched, which is what production does
 * via [assets] not_found_handling = "404-page" in wrangler.toml. Without this,
 * dev answered a bad link with Express's bare "Cannot GET /whatever" while the
 * live site showed a page with the menu, the phone number and a way back to
 * booking. Same class of gap as the placeholder-image transform: a difference
 * between what you test and what visitors get.
 */
app.use((req, res) => {
  const branded = path.join(PUBLIC_DIR, '404.html');
  if (fs.existsSync(branded)) return res.status(404).type('html').send(fs.readFileSync(branded, 'utf8'));
  res.status(404).type('text').send('Not found — run `npm run build` to generate the branded 404 page.');
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  const stats = catalogueStats();
  console.log(`\n  Cousins Mechanical — http://localhost:${PORT}`);
  console.log(`  Tyre catalogue: ${stats.tyres} tyres across ${stats.sizes} sizes, ${stats.costEntries} cost entries`);
  if (stats.tyres === 0) console.error('  WARNING: catalogue is empty — /api/tyres/lookup will return nothing');

  const off = [];
  if (!env.UKVD_API_KEY) off.push('reg lookup');
  if (!env.RESEND_API_KEY) off.push('email');
  if (!env.TWILIO_SID && !env.WHATSAPP_TOKEN) off.push('SMS/WhatsApp');
  if (!env.GCAL_CALENDAR_ID) off.push('calendar');
  if (!process.env.GOOGLE_CLIENT_ID) off.push('Google sign-in');
  if (!process.env.APPLE_SERVICES_ID) off.push('Apple sign-in');
  if (off.length) console.log(`  Disabled (no key set): ${off.join(', ')}`);

  if (devGenerated.length) {
    console.log('\n  Dev secrets generated for this run only:');
    for (const [name, val] of devGenerated) console.log(`    ${name}=${val}`);
    console.log('  Put real values in .env to keep them stable between restarts.\n');
  }
});
