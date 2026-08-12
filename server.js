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
import worker from './worker.js';
import { catalogueStats } from './tyre-db.js';

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
  SESSION_PEPPER: requiredSecret('SESSION_PEPPER'),
  ADMIN_TOKEN: requiredSecret('ADMIN_TOKEN'),
  OVERRIDE_TOKEN: requiredSecret('OVERRIDE_TOKEN'),
  TIRE_API_KEY: process.env.TIRE_API_KEY || '',
  UKVD_API_KEY: process.env.UKVD_API_KEY || '',
  UKVD_BASE: process.env.UKVD_BASE || '',
  SITE_URL: process.env.SITE_URL || `http://localhost:${PORT}`,
  RESEND_API_KEY: process.env.RESEND_API_KEY || '',
  MAIL_FROM: process.env.MAIL_FROM || '',
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
};

// ---------------------------------------------------------------------------
// Firebase (optional) — only used for "Sign in with Google"
// ---------------------------------------------------------------------------
// FIREBASE_WEB_CONFIG is the public web config, safe to serve to the browser.
// ADMIN_EMAILS is the allowlist of Google accounts permitted into the admin
// portal. Without it, any customer who signed in with Google could exchange
// their token for an admin session — this endpoint previously trusted every
// valid token from the project.
const FIREBASE_WEB_CONFIG = process.env.FIREBASE_WEB_CONFIG || '';
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

let firebaseAuth = null;
if (FIREBASE_WEB_CONFIG) {
  try {
    const cfg = JSON.parse(FIREBASE_WEB_CONFIG);
    const { initializeApp, getApps } = await import('firebase-admin/app');
    const { getAuth } = await import('firebase-admin/auth');
    if (!getApps().length) initializeApp({ projectId: cfg.projectId });
    firebaseAuth = getAuth();
  } catch (e) {
    console.error('[firebase] disabled —', e.message);
  }
}

app.get('/api/firebase-config', (req, res) => {
  if (!FIREBASE_WEB_CONFIG) return res.status(404).json({ error: 'Google sign-in is not configured' });
  res.type('application/json').send(FIREBASE_WEB_CONFIG);
});

app.post('/api/admin-login-firebase', express.json(), async (req, res) => {
  try {
    if (!firebaseAuth) return res.status(503).json({ error: 'Google sign-in is not configured' });
    if (ADMIN_EMAILS.length === 0) {
      return res.status(503).json({ error: 'ADMIN_EMAILS is not set — refusing to grant admin access' });
    }
    const decoded = await firebaseAuth.verifyIdToken(req.body?.idToken || '');
    const email = (decoded.email || '').toLowerCase();
    if (!decoded.email_verified || !ADMIN_EMAILS.includes(email)) {
      console.warn('[admin] rejected Google sign-in for', email || '(no email)');
      return res.status(403).json({ error: 'This account is not an administrator' });
    }
    // Cryptographically random, matching the Worker's own session tokens.
    const sessionToken = crypto.randomBytes(30).toString('base64url');
    await CMS_KV.put('asess:' + sessionToken, email, { expirationTtl: 60 * 60 * 12 });
    res.json({ token: sessionToken, user: { email, name: decoded.name || email } });
  } catch (err) {
    console.error('Firebase admin login error:', err.message);
    res.status(401).json({ error: 'Unauthorized' });
  }
});

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

// ---------------------------------------------------------------------------
// Static site
// ---------------------------------------------------------------------------
// Mirror the security headers the Worker sets in production, so dev behaves the
// same as live rather than only looking fine locally.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const page = file => (req, res) => {
  const authored = path.join(__dirname, file);
  if (fs.existsSync(authored)) return res.sendFile(authored);
  res.status(404).send('Page not built — run `npm run build`');
};
app.get(['/', '/index.html'], page('Cousins Mechanical.dc.html'));
app.get(['/admin', '/admin.html'], page('Cousins Admin.dc.html'));
app.get(['/driver', '/driver.html'], page('Cousins Driver.dc.html'));

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
  if (!FIREBASE_WEB_CONFIG) off.push('Google sign-in');
  if (off.length) console.log(`  Disabled (no key set): ${off.join(', ')}`);

  if (devGenerated.length) {
    console.log('\n  Dev secrets generated for this run only:');
    for (const [name, val] of devGenerated) console.log(`    ${name}=${val}`);
    console.log('  Put real values in .env to keep them stable between restarts.\n');
  }
});
