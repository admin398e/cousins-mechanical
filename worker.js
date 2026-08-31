import { BUSINESS } from "./business.js";
import {
  lookupBySize, lookupBySizeAdmin, search as searchCatalogue, byId as tyreById,
  normalisePricing, DEFAULT_PRICING, assignTiers, forAdmin, adminCatalogue,
} from "./tyre-data.js";

/*
 * Cousins Mechanical — full backend (Cloudflare Worker)
 * ====================================================================
 * One worker does everything:
 *   • Real customer accounts   (PBKDF2-hashed passwords, KV sessions)
 *   • Bookings API             (create / list / amend / cancel, per account)
 *   • Twilio SMS               (booking confirmation + live status texts)
 *   • Google Calendar          (invite created on the business calendar, customer added as guest)
 *   • Email (Resend)          (confirmation with .ics attachment)
 *   • UK Vehicle Data proxy    (number plate -> vehicle + tyre size)
 *   • tire.vdim.app proxy      (year/make/model/trim fitment)
 *   • GDPR                     (explicit consent, data export, right-to-erasure, retention, audit log)
 *   • Serves the website itself (static assets)
 *
 * --------------------------------------------------------------------
 * ONE-TIME SETUP (~10 min, all free tier)
 *
 * 1. npm i -g wrangler && wrangler login
 *
 * 2. KV (accounts, sessions, bookings, audit):
 *      wrangler kv namespace create CMS_KV
 *    Paste the id into wrangler.toml.
 *
 * 3. Secrets — `wrangler secret put NAME` for each:
 *      SESSION_PEPPER        long random string (openssl rand -hex 32)
 *      UKVD_API_KEY          Vehicle Data Global key (r2/lookup, TyreDetails package)
 *      TIRE_API_KEY          tire.vdim.app key (554fba09...de3f)
 *      TWILIO_SID            Twilio Account SID
 *      TWILIO_TOKEN          Twilio Auth Token
 *      TWILIO_FROM           your Twilio number, e.g. +447...
 *      GCAL_CALENDAR_ID      calendar id the diary lives on, usually an email address.
 *
 *      Then ONE of the two ways to authenticate against it:
 *
 *      (a) OAuth refresh token — the supported route. Google now blocks
 *          service-account key creation on organisations by default
 *          (iam.managed.disableServiceAccountKeyCreation), so on many accounts
 *          (b) is simply impossible. Run tools/gcal-authorize.mjs once to get
 *          the token; it never leaves your machine until you set it.
 *            GOOGLE_CLIENT_ID      OAuth web client id
 *            GOOGLE_CLIENT_SECRET  its client secret
 *            GCAL_REFRESH_TOKEN    from tools/gcal-authorize.mjs
 *
 *      (b) Service account — still works where the org policy does not apply.
 *            GCAL_CLIENT_EMAIL     service-account email
 *            GCAL_PRIVATE_KEY      its private key (PEM, keep the \n newlines)
 *          The calendar must be SHARED with that address or it reads as empty.
 *      RESEND_API_KEY        Resend API key (resend.com — free 3,000 emails/mo)
 *      MAIL_FROM             from address on a domain verified in Resend, e.g. bookings@cousinsmechanicalservices.co.uk
 *      TWILIO_SID / TWILIO_TOKEN   Twilio subaccount credentials.
 *      TWILIO_FROM                 The Twilio number in +44… form, e.g. +447576549872.
 *      TWILIO_STUDIO_FLOW_SID      Optional. FW… — when set, booking confirmations run
 *                                  through the Studio flow so the wording can be edited
 *                                  without a deploy. Falls back to the Messages API.
 *      HUBSPOT_PORTAL_ID           Optional. Numeric portal id; switches on the tracking
 *                                  script on the public site and the CRM links in admin.
 *      STRIPE_SECRET_KEY           Optional. sk_live_… — switches on card deposits. Card details
 *                                  NEVER reach this Worker; Stripe hosts the payment page.
 *      STRIPE_WEBHOOK_SECRET       Required alongside it. whsec_… — the ONLY thing that may mark
 *                                  a job paid is a webhook signed with this.
 *      HUBSPOT_TOKEN               Optional. Private App token (NOT OAuth). Switches on the
 *                                  contact-on-booking and deal-on-payment sync. Needs the
 *                                  crm.objects.contacts.write and crm.objects.deals.write scopes.
 *      HUBSPOT_PIPELINE            Optional, default "default".
 *      HUBSPOT_WON_STAGE           Optional, default "closedwon".
 *      RESEND_AUDIENCE_ID          Resend Audience id for MARKETING — optional. Only contacts who ticked
 *                                  the box are pushed here. Leave unset and the tick is still recorded in KV.
 *      RESEND_CUSTOMER_AUDIENCE_ID Resend Audience id for ALL CUSTOMERS — optional. Everyone who books or
 *                                  confirms an account lands here regardless of the marketing tick. This is
 *                                  an address book, NOT a mailing list: never send a marketing broadcast to
 *                                  it. Service notices about work already booked are fine.
 *      RESEND_WEBHOOK_SECRET Signing secret (whsec_...) from Resend → Webhooks. Required for /api/resend-webhook;
 *                            unset means the endpoint refuses every request rather than trusting forged bounces.
 *      TURNSTILE_SITE_KEY    Cloudflare Turnstile public site key — sent to the browser to render the widget.
 *      TURNSTILE_SECRET      Turnstile secret. While UNSET every CAPTCHA check passes, so a half-configured
 *                            widget can never lock real customers out. Set both together to switch it on.
 *      OWNER_PHONE           the business owner's number (E.164, e.g. 447925340977) — gets WhatsApp/SMS on new customer messages
 *      SITE_URL              your live site URL, e.g. https://cousinsmechanicalservices.co.uk (used in reset links)
 *      ADMIN_TOKEN           long random string — the admin dashboard password + status-text auth
 *      OVERRIDE_TOKEN        owner master key — always logs in and can reset 2FA (never get locked out)
 *      (2FA: enrolled in-app; the TOTP secret is stored in KV as "admin_totp", not a Worker secret)
 *
 *    Any secret you leave unset simply disables that channel (the booking still succeeds).
 *
 * 4. Put the exported site in ./public, then `wrangler deploy`.
 *    Same-origin frontend auto-detects the API — no extra config.
 *
 * 5. Retention cron (auto-erase old cancelled/'complete' data) — already wired in
 *    wrangler.toml as a scheduled trigger; adjust RETENTION_DAYS below.
 *
 * If your UK Vehicle Data package isn't "TyreData", change UKVD_PACKAGE.
 */

const UKVD_PACKAGE = "TyreDetails";
/*
 * Retention. GDPR Art. 5(1)(e) — personal data may not be kept longer than it
 * is needed, and "indefinitely" is not a period.
 *
 * These are the defaults; Admin → Retention overrides them. The reasoning
 * matters more than the numbers, so it is written down here rather than in
 * somebody's head:
 *
 *   jobs 6 years   — the limitation period for a workmanship claim, and
 *                    HMRC's record-keeping requirement. Shorter than this and
 *                    Cousins cannot defend a claim he is still liable for.
 *   contacts 3 yrs — a customer who has not been near us in three years is not
 *                    a customer. Reset by any new booking.
 *   audit 12 mths  — long enough to investigate an incident, short enough not
 *                    to be a standing record of who did what forever.
 *   messages 2 yrs — the conversation about a job outlives the job briefly.
 *   slots 90 days  — pure operational counters, no personal data.
 *   maillog 90 days
 */
const RETENTION = {
  jobDays: 2190,        // 6 years
  contactDays: 1095,    // 3 years
  auditDays: 365,
  messageDays: 730,
  slotDays: 90,
  mailLogDays: 90,
};
const RETENTION_DAYS = RETENTION.jobDays; // kept for the older call sites
const LOCATION_TTL_SEC = 3600; // live driver GPS is transient — expires an hour after the job
const RESET_TOKEN_TTL_SEC = 3600; // password-reset links are valid for one hour
const PRIVACY_VERSION = "2026-08-22"; // bump when your privacy notice changes to re-request consent

// Origins allowed to call the API from a browser. The site is same-origin so it
// needs no entry here; this list exists for the standalone driver app / previews.
// Anything not listed gets no CORS header at all rather than a wildcard, so a
// stolen admin token cannot be replayed from an attacker's page.
const ALLOWED_ORIGINS = [
  "https://cousinsmechanicalservices.co.uk",
  "https://www.cousinsmechanicalservices.co.uk",
  "https://admin.cousinsmechanicalservices.co.uk",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

// Set per-request by the fetch handler so responses echo the right origin.
let CORS = { "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS" };
function corsFor(request, env) {
  const origin = request.headers.get("origin") || "";
  const extra = (env?.EXTRA_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  const allowed = [...ALLOWED_ORIGINS, ...extra];
  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "content-type,authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
  if (origin && allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }
  return headers;
}

// Baseline security headers on every API response.
/*
 * Content-Security-Policy.
 *
 * The allow-list is every host the pages actually reach, verified by grepping
 * the three templates rather than guessed: Leaflet from unpkg, OpenStreetMap
 * tiles, Google Fonts, Cloudflare Turnstile, HubSpot's tracker, postcodes.io
 * for reverse geocoding, and Lottie for the animation on the home page.
 *
 * READ THIS BEFORE TIGHTENING IT.
 *
 * 'unsafe-inline' AND 'unsafe-eval' are both required, and both are load-bearing:
 * the design-canvas runtime puts the whole application in an inline
 * <script type="text/x-dc"> block and then EVALUATES the logic class at runtime.
 * A policy without them does not degrade the site, it kills it — the first
 * version of this header shipped without 'unsafe-eval' and the live admin,
 * driver and booking pages rendered as static templates with zero working
 * buttons. It was caught by driving the real pages in a browser, which is the
 * only way this kind of break shows up.
 *
 * So be honest about what this policy is and is not:
 *
 *   Still protects  — a script pulled from a host that is not on this list;
 *                     plugin embeds (object-src none); clickjacking
 *                     (frame-ancestors none, stronger than X-Frame-Options);
 *                     an injected form posting credentials off-site
 *                     (form-action self); base-tag hijacking (base-uri self).
 *   No longer stops — an inline <script> injected into our own HTML.
 *
 * The route to a strict policy is to lift the logic out of the .dc.html
 * templates into a real .js file served from our own origin, then drop both
 * unsafe-* keywords. That is a real piece of work, not a header change.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' https://unpkg.com https://challenges.cloudflare.com https://js-eu1.hs-scripts.com https://js-eu1.hs-analytics.net https://js-eu1.hsadspixel.net https://js-eu1.usemessages.com https://lottie.host https://cdn.jsdelivr.net",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob: https://*.tile.openstreetmap.org https://unpkg.com https://*.hubspot.com https://*.hsforms.com https://track.hubspot.com",
  // jsdelivr serves the WebAssembly the Lottie player fetches at runtime.
  "connect-src 'self' https://api.postcodes.io https://*.hubspot.com https://*.hubapi.com https://challenges.cloudflare.com https://lottie.host https://cdn.jsdelivr.net",
  "frame-src 'self' https://challenges.cloudflare.com https://calendar.google.com https://*.hubspot.com",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), payment=(), interest-cohort=()",
  "Content-Security-Policy": CSP,
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, ...SECURITY_HEADERS, "content-type": "application/json" },
  });
const bad = (msg, status = 400) => json({ error: msg }, status);

function b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b64url(buf) { return b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
async function pbkdf2(password, saltB64, pepper) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", enc.encode(password + (pepper || "")), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256);
  return b64(bits);
}
function token() { return b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[^a-zA-Z0-9]/g, "").slice(0, 40); }

/** A fresh random salt for a new password. */
function newSalt() { return b64(crypto.getRandomValues(new Uint8Array(16))); }

/**
 * Compare two secrets without leaking their contents through timing.
 * Used for every bearer-token / admin-token check.
 */
function safeEqual(a, b) {
  const x = String(a ?? ""), y = String(b ?? "");
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

/**
 * Brute-force guard for the login endpoints. Counts failures per key in KV and
 * locks out once the limit is hit; the KV TTL handles expiry so nothing to sweep.
 */
const RATE_LIMIT = { max: 8, windowSec: 900 }; // 8 attempts per 15 minutes
/**
 * Edge rate limit, using Cloudflare's rate-limiting binding.
 *
 * Returns true when the caller should be refused. Falls through to `false` if
 * the binding is absent (local dev via server.js has no such binding), so the
 * KV counters below remain the fallback there.
 */
async function edgeLimited(env, binding, key) {
  const rl = env[binding];
  if (!rl || typeof rl.limit !== "function") return false;
  try {
    const { success } = await rl.limit({ key });
    return !success;
  } catch (err) {
    console.error("[ratelimit]", binding, err && err.message);
    return false; // never let the limiter itself take the site down
  }
}

async function rateLimited(env, key, max) {
  const n = Number((await env.CMS_KV.get("rl:" + key)) || 0);
  return n >= (max || RATE_LIMIT.max);
}

/**
 * Which customer a booking ref belongs to, or null if no such booking exists.
 *
 * Endpoints that take a ref from the caller need this: a ref that names nothing
 * used to be accepted and written to KV anyway, so any string created a new key.
 */
/**
 * The job timeline as the CUSTOMER should see it.
 *
 * Stock and supplier lines are internal. A customer who books tyres has no
 * business being told "Purchase order PO-… raised with <supplier> for next
 * morning delivery" — it exposes who supplies the business and what it does or
 * does not have on the van, and it reads as a problem rather than progress.
 *
 * Filtering happens on READ, not just on write, because bookings already in KV
 * carry the old wording and would otherwise keep showing it forever. The two
 * rules:
 *   - anything explicitly flagged internal
 *   - anything that mentions stock, a supplier or a purchase order (legacy
 *     records written before the flag existed)
 */
const INTERNAL_UPDATE = /supplier|purchase order|\bPO-|wholesale|stock allocated|reorder|local inventory|in stock|out of stock/i;

function customerUpdates(updates) {
  return (Array.isArray(updates) ? updates : []).filter(u => {
    if (!u || u.internal) return false;
    return !INTERNAL_UPDATE.test(String(u.s || "") + " " + String(u.d || ""));
  });
}

// ---------- Turnstile (bot check on the forms that cost us something) ----------
//
// Cloudflare's CAPTCHA. Chosen over reCAPTCHA because the site already runs on
// Cloudflare, it is free at any volume, and it does not profile the visitor —
// which matters when the privacy notice promises we do not.
//
// Set TURNSTILE_SITE_KEY (public, sent to the browser) and TURNSTILE_SECRET.
// While the secret is unset every check passes: a half-configured CAPTCHA that
// silently rejects real customers is worse than no CAPTCHA at all. Once the
// secret exists it is enforced everywhere.
async function turnstileOk(env, request, body) {
  if (!env.TURNSTILE_SECRET) return true;
  const tokenValue = body && (body.turnstileToken || body["cf-turnstile-response"]);
  if (!tokenValue) return false;
  try {
    const form = new FormData();
    form.append("secret", env.TURNSTILE_SECRET);
    form.append("response", String(tokenValue));
    form.append("remoteip", clientIp(request));
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const d = await r.json().catch(() => ({}));
    if (!d.success) console.error("[turnstile] rejected", JSON.stringify(d["error-codes"] || []));
    return !!d.success;
  } catch (err) {
    // Never let an outage at the CAPTCHA provider stop somebody booking a
    // breakdown recovery. The rate limiters are still in front of everything.
    console.error("[turnstile] verify failed, allowing through:", err && err.message);
    return true;
  }
}

// ---------- Email verification ----------
// A signup used to hand out a 30-day session immediately, so anyone could
// register somebody else's address and start receiving their booking mail.
// Now the account exists but is inert until a code sent to that inbox is
// entered — which is the only thing that proves the person owns it.

const VERIFY_TTL_SEC = 30 * 60;   // 30 minutes
const VERIFY_MAX_TRIES = 5;       // a 6-digit code is guessable without this

function verifyCode() {
  // Six digits, uniformly distributed. Math.random() is not acceptable for
  // anything that grants account access.
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

/**
 * Issue a fresh code for an address and email it.
 *
 * The code is stored hashed. A KV dump — or the backup endpoint — should never
 * hand somebody a working key to every pending account.
 */
async function sendVerifyCode(env, ctx, em, name, keyPrefix) {
  const code = verifyCode();
  // pbkdf2() takes a BASE64 salt, and a fresh one per code — passing the email
  // both fed it a non-base64 string (which threw) and would have made the same
  // code hash identically every time for a given address.
  const salt = newSalt();
  const hash = await pbkdf2(code, salt, env.SESSION_PEPPER);
  await env.CMS_KV.put((keyPrefix || "verify:") + em, JSON.stringify({ hash, salt, tries: 0, sentAt: Date.now() }),
    { expirationTtl: VERIFY_TTL_SEC });

  const subject = "Your " + BUSINESS.shortName + " confirmation code: " + code;
  const text = `Hi ${name || "there"},\n\n`
    + `Your confirmation code is ${code}\n\n`
    + `Enter it on the site to finish setting up your account. It expires in 30 minutes.\n\n`
    + `If you did not try to create an account with ${BUSINESS.name}, you can ignore this email — `
    + `nothing has been set up and nobody can use your address without this code.\n\n`
    + `${BUSINESS.legalName}\nRegistered in England & Wales no. ${BUSINESS.companyNumber}`;

  sendEmailTracked(env, ctx, em, subject, text);
  return code;
}

/**
 * Expose the code in the API response — TEST ONLY.
 *
 * The automated suite has no inbox, so without this it cannot complete a
 * signup. Gated on an explicit environment variable that ONLY test/server.js
 * sets: it is not a Worker secret and does not exist in production, so a
 * deployed Worker can never return a code. Deliberately not keyed off
 * "is email configured", because that would start leaking codes the moment
 * RESEND_API_KEY went missing.
 */
function testCode(env, code) {
  return env.ALLOW_TEST_VERIFY_CODE === "yes" ? { devCode: code } : {};
}

/**
 * Has this account cleared email verification?
 *
 * Accounts created before verification existed have no flag at all. Treating
 * those as unverified would lock out every existing customer, so absent means
 * legacy-verified; only an explicit false blocks.
 */
function isVerified(user) {
  return user && user.emailVerified !== false;
}

async function findBookingOwner(env, ref) {
  const list = await env.CMS_KV.list({ prefix: "bookings:" });
  for (const k of list.keys) {
    const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
    if (arr.some(o => o.ref === ref)) return k.name.slice("bookings:".length);
  }
  return null;
}
async function noteFailure(env, key) {
  const k = "rl:" + key;
  const n = Number((await env.CMS_KV.get(k)) || 0);
  await env.CMS_KV.put(k, String(n + 1), { expirationTtl: RATE_LIMIT.windowSec });
}
async function clearFailures(env, key) { await env.CMS_KV.delete("rl:" + key); }
function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown";
}

// ---------- tyre catalogue (loaded from the ASSETS binding) ----------
// The catalogue is ~1.1 MB of JSON — too big to inline in the Worker bundle — so it
// is read from the static assets on first use and cached for the isolate's lifetime.
// Before this the Worker had no /api/tyres/* at all: production silently fell back
// to placeholder prices while local dev (server.js) worked fine.
let _tyreCache = null;
async function tyreData(env) {
  if (_tyreCache) return _tyreCache;
  if (!env.ASSETS) throw new Error("ASSETS binding missing — cannot load tyre catalogue");
  const grab = async (path, fallback) => {
    try {
      const r = await env.ASSETS.fetch(new Request("https://assets.local" + path));
      if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`);
      return await r.json();
    } catch (e) {
      console.error("[tyres] failed to load", path, e.message);
      return fallback;
    }
  };
  const [catalogue, costMap, sizes] = await Promise.all([
    grab("/data/tyre-catalogue.json", {}),
    grab("/data/tyre-cost.json", {}),
    grab("/data/tyre-sizes.json", { tree: {}, widths: [] }),
  ]);
  _tyreCache = { catalogue, costMap, sizes };
  return _tyreCache;
}


// ---------- retail pricing (admin-controlled, stored in KV) ----------
// Cached per isolate. `pricingVersion` is bumped on every save so other isolates
// pick the change up on their next request instead of serving stale prices.
let _pricingCache = null;
let _pricingStamp = 0;
async function getPricing(env) {
  const now = Date.now();
  // 5s, not 30s. savePricing() only refreshes the cache in the ONE isolate that
  // handled the save; every other isolate keeps serving the old markup until its
  // own copy expires. Stacked on top of the HTTP cache below, a price change
  // took well over a minute to reach customers and looked like it had not saved
  // at all. KV reads are cheap — this is not a hot path.
  if (_pricingCache && now - _pricingStamp < 5000) return _pricingCache;
  const raw = await env.CMS_KV.get("pricing");
  _pricingCache = normalisePricing(raw ? JSON.parse(raw) : null);
  _pricingStamp = now;
  return _pricingCache;
}
async function savePricing(env, pricing) {
  const clean = normalisePricing({ ...pricing, updatedAt: Date.now() });
  await env.CMS_KV.put("pricing", JSON.stringify(clean));
  _pricingCache = clean;
  _pricingStamp = Date.now();
  return clean;
}

// ---------- TOTP 2FA (RFC 6238, SHA-1, 6 digits, 30s) ----------
function b32decode(s) {
  s = (s || "").replace(/=+$/, "").toUpperCase(); const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, val = 0; const out = [];
  for (const c of s) { const i = A.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >> (bits - 8)) & 0xff); bits -= 8; } }
  return new Uint8Array(out);
}
/* ============================== QR CODES ==================================
 *
 * Why this is here rather than a library: the only thing that needs a QR code
 * is the two-factor enrolment card, it needs it server-side and offline, and
 * the alternative was loading a script from a CDN onto the one screen whose
 * whole job is security — where a CDN outage would silently remove the QR and
 * leave a setup key nobody can scan.
 *
 * Byte mode, error-correction level M, smallest version that fits. Output is a
 * self-contained SVG data URI, which the Content-Security-Policy already
 * allows as an image source. The algorithm is ISO/IEC 18004; the structure
 * follows Nayuki's public reference implementation.
 */
const QR_EXP = new Uint8Array(512);
const QR_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) { QR_EXP[i] = x; QR_LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
  for (let i = 255; i < 512; i++) QR_EXP[i] = QR_EXP[i - 255];
})();
const qrMul = (a, b) => (a === 0 || b === 0) ? 0 : QR_EXP[QR_LOG[a] + QR_LOG[b]];

// Level M, versions 1..40. Not derivable — these are the standard's own tables.
const QR_ECC_PER_BLOCK = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const QR_BLOCKS = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];

function qrRawDataModules(ver) {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const a = Math.floor(ver / 7) + 2;
    n -= (25 * a - 10) * a - 55;
    if (ver >= 7) n -= 36;
  }
  return n;
}
const qrDataCodewords = ver => Math.floor(qrRawDataModules(ver) / 8) - QR_ECC_PER_BLOCK[ver] * QR_BLOCKS[ver];

function qrAlignPositions(ver) {
  if (ver === 1) return [];
  const num = Math.floor(ver / 7) + 2;
  const step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (num * 2 - 2)) * 2;
  const out = [6];
  for (let pos = ver * 4 + 10; out.length < num; pos -= step) out.splice(1, 0, pos);
  return out;
}

function qrRsDivisor(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= qrMul(poly[j], QR_EXP[i]);
    }
    poly = next;
  }
  return poly.slice(1); // drop the leading 1
}
function qrRsRemainder(data, degree) {
  const div = qrRsDivisor(degree);
  const res = new Uint8Array(degree);
  for (const b of data) {
    const factor = b ^ res[0];
    res.copyWithin(0, 1);
    res[degree - 1] = 0;
    for (let i = 0; i < degree; i++) res[i] ^= qrMul(div[i], factor);
  }
  return res;
}

/**
 * The module matrix for `text`, as an array of rows of 0/1.
 *
 * `forceMask` exists so a test can pin the mask and compare the whole matrix
 * against an independent implementation. Leave it out in real use: the mask is
 * chosen by the standard's penalty rules, which is what makes a code scan well.
 */
function qrMatrix(text, forceMask) {
  const bytes = new TextEncoder().encode(text);

  let ver = 1;
  while (ver <= 40) {
    const cap = qrDataCodewords(ver) * 8;
    const need = 4 + (ver <= 9 ? 8 : 16) + bytes.length * 8;
    if (need <= cap) break;
    ver++;
  }
  if (ver > 40) throw new Error("too much data for a QR code");

  // ---- bit stream ---------------------------------------------------------
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(4, 4);                                   // byte mode
  push(bytes.length, ver <= 9 ? 8 : 16);        // character count
  for (const b of bytes) push(b, 8);
  const capacity = qrDataCodewords(ver) * 8;
  push(0, Math.min(4, capacity - bits.length)); // terminator
  while (bits.length % 8 !== 0) bits.push(0);
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    codewords.push(b);
  }
  for (let pad = 0xec; codewords.length < qrDataCodewords(ver); pad ^= 0xec ^ 0x11) codewords.push(pad);

  // ---- error correction, split into blocks and interleaved ----------------
  const numBlocks = QR_BLOCKS[ver];
  const eccLen = QR_ECC_PER_BLOCK[ver];
  const rawCodewords = Math.floor(qrRawDataModules(ver) / 8);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks) - eccLen;
  const numShort = numBlocks - (rawCodewords % numBlocks);

  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const len = shortBlockLen + (i < numShort ? 0 : 1);
    const dat = codewords.slice(k, k + len);
    k += len;
    blocks.push({ dat, ecc: qrRsRemainder(dat, eccLen) });
  }
  const out = [];
  for (let i = 0; i < shortBlockLen + 1; i++)
    for (const b of blocks) if (i < b.dat.length) out.push(b.dat[i]);
  for (let i = 0; i < eccLen; i++) for (const b of blocks) out.push(b.ecc[i]);

  // ---- draw ---------------------------------------------------------------
  const size = ver * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(0));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, v) => { if (x >= 0 && y >= 0 && x < size && y < size) { m[y][x] = v; fixed[y][x] = true; } };

  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const d = Math.max(Math.abs(dx), Math.abs(dy));
      set(cx + dx, cy + dy, (d !== 2 && d !== 4) ? 1 : 0);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);

  for (let i = 8; i < size - 8; i++) { set(i, 6, (i % 2 === 0) ? 1 : 0); set(6, i, (i % 2 === 0) ? 1 : 0); }

  const align = qrAlignPositions(ver);
  for (let i = 0; i < align.length; i++) for (let j = 0; j < align.length; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      set(align[i] + dx, align[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1 ? 1 : 0);
  }

  // Reserve the format areas, and the dark module, before laying data.
  // Skip index 6: that is where the two timing patterns cross the format
  // stripe, at (8,6) and (6,8). Those modules belong to the timing pattern and
  // no format bit is ever written over them — blanking them here left exactly
  // two wrong modules in every code ever produced, which error correction
  // quietly absorbed, so it scanned anyway and looked completely fine.
  for (let i = 0; i <= 8; i++) { if (i === 6) continue; set(i, 8, 0); set(8, i, 0); }
  for (let i = 0; i < 8; i++) { set(size - 1 - i, 8, 0); set(8, size - 1 - i, 0); }
  set(8, size - 8, 1);

  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bitsV = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = (bitsV >>> i) & 1;
      const a = size - 11 + i % 3, b = Math.floor(i / 3);
      set(a, b, bit); set(b, a, bit);
    }
  }

  let idx = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (fixed[y][x]) continue;
        m[y][x] = idx < out.length * 8 ? (out[idx >>> 3] >>> (7 - (idx & 7))) & 1 : 0;
        idx++;
      }
    }
  }

  // ---- mask, chosen by the standard's own penalty rules -------------------
  const maskFn = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
    (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ];
  const drawFormat = (grid, mask) => {
    const data = (0 << 3) | mask; // 0b00 = level M
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bitsF = ((data << 10) | rem) ^ 0x5412;
    const at = (x, y, v) => { grid[y][x] = v; };
    for (let i = 0; i <= 5; i++) at(8, i, (bitsF >>> i) & 1);
    at(8, 7, (bitsF >>> 6) & 1);
    at(8, 8, (bitsF >>> 7) & 1);
    at(7, 8, (bitsF >>> 8) & 1);
    for (let i = 9; i < 15; i++) at(14 - i, 8, (bitsF >>> i) & 1);
    for (let i = 0; i < 8; i++) at(size - 1 - i, 8, (bitsF >>> i) & 1);
    for (let i = 8; i < 15; i++) at(8, size - 15 + i, (bitsF >>> i) & 1);
    at(8, size - 8, 1);
  };

  let best = null, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    if (forceMask !== undefined && mask !== forceMask) continue;
    const g = m.map(r => r.slice());
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
      if (!fixed[y][x] && maskFn[mask](x, y)) g[y][x] ^= 1;
    drawFormat(g, mask);
    const s = qrPenalty(g, size);
    if (s < bestScore) { bestScore = s; best = g; }
  }
  return best;
}

function qrPenalty(g, size) {
  let p = 0;
  const runScore = line => {
    let score = 0, run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && line[i] === line[i - 1]) { run++; continue; }
      if (run >= 5) score += 3 + (run - 5);
      run = 1;
    }
    return score;
  };
  for (let y = 0; y < size; y++) p += runScore(g[y]);
  for (let x = 0; x < size; x++) p += runScore(g.map(r => r[x]));
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) {
    const c = g[y][x];
    if (c === g[y][x + 1] && c === g[y + 1][x] && c === g[y + 1][x + 1]) p += 3;
  }
  const finderish = [1, 0, 1, 1, 1, 0, 1];
  const hasPattern = (line, at) => {
    for (let i = 0; i < 7; i++) if (line[at + i] !== finderish[i]) return false;
    const before = line.slice(Math.max(0, at - 4), at);
    const after = line.slice(at + 7, at + 11);
    const quiet = arr => arr.length === 0 || arr.every(v => v === 0);
    return (before.length >= 4 && quiet(before)) || (after.length >= 4 && quiet(after))
        || (at < 4 && quiet(before)) || (at + 11 > size && quiet(after));
  };
  for (let y = 0; y < size; y++) for (let x = 0; x + 7 <= size; x++) if (hasPattern(g[y], x)) p += 40;
  for (let x = 0; x < size; x++) { const col = g.map(r => r[x]); for (let y = 0; y + 7 <= size; y++) if (hasPattern(col, y)) p += 40; }
  let dark = 0;
  for (const row of g) for (const v of row) dark += v;
  const total = size * size;
  p += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return p;
}

/**
 * `text` as an SVG data URI, for a CSS background-image.
 *
 * Percent-encoded rather than base64, and that is not a style preference: a
 * base64 data URI carries the literal ";base64," in it, and the design-canvas
 * runtime turns a style attribute into an object with `css.split(";")` — no
 * regard for quoting. A base64 QR in a bound style is therefore cut off after
 * "data:image/svg+xml", which the browser reports as nothing more than a
 * failed image load. Percent-encoding removes every semicolon from the URI, so
 * there is nothing left to split on. The path uses commas rather than spaces
 * for the same reason: fewer characters that have to be escaped.
 */
function qrSvgDataUri(text, px) {
  const m = qrMatrix(text);
  const size = m.length;
  const quiet = 4;
  const dim = size + quiet * 2;
  let path = "";
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++)
    if (m[y][x]) path += `M${x + quiet},${y + quiet}h1v1h-1z`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${px || 200}" height="${px || 200}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
  const escaped = svg.replace(/[%#<>"'&;\s]/g, c => "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0"));
  return "data:image/svg+xml," + escaped;
}

function b32encode(bytes) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, val = 0, out = "";
  for (const b of bytes) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += A[(val >> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += A[(val << (5 - bits)) & 31];
  return out;
}
async function totpAt(secret, step) {
  const key = b32decode(secret); const msg = new ArrayBuffer(8); const dv = new DataView(msg); dv.setUint32(4, step);
  const ck = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", ck, msg));
  const off = sig[19] & 0xf;
  const code = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
  return (code % 1000000).toString().padStart(6, "0");
}
async function totpValid(secret, code) {
  const c = String(code || "").trim(); if (!/^\d{6}$/.test(c)) return false;
  const now = Math.floor(Date.now() / 30000);
  for (let w = -1; w <= 1; w++) if (await totpAt(secret, now + w) === c) return true;
  return false;
}
/**
 * Revoke every live admin session belonging to one staff email.
 *
 * Disabling or deleting a staff account used to leave their 12-hour `asess:`
 * token working, because isAdmin() only checks that the session key exists and
 * never re-reads the staff record. A dismissed employee kept full admin API
 * access for the rest of the day. The driver endpoints already did this sweep
 * on revoke; staff did not.
 */
async function revokeAdminSessions(env, email) {
  const em = String(email || "").toLowerCase();
  let cursor, killed = 0;
  do {
    const page = await env.CMS_KV.list({ prefix: "asess:", cursor });
    for (const k of page.keys) {
      if ((await env.CMS_KV.get(k.name)) === em) { await env.CMS_KV.delete(k.name); killed++; }
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return killed;
}

/**
 * The identity behind this request, enrolment aside.
 *
 * Split out of isAdmin() so that a staff member who has signed in but has not
 * yet set up an authenticator still has somewhere to go: they hold a real
 * session, it is just not one that may touch the business yet. Everything that
 * is not enrolment asks isAdmin(); the three enrolment endpoints ask this.
 *
 * Returns the signed-in email, "admin" for the identity-less bootstrap token,
 * or "" for no session at all.
 */
async function adminSession(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return "";

  const who = await env.CMS_KV.get("asess:" + t);
  if (who != null) {
    // Re-read the staff record on every request. A session alone is not proof
    // of current employment — the account may have been disabled or deleted
    // since the token was issued.
    if (who && who.includes("@")) {
      const raw = await env.CMS_KV.get("staff:" + who);
      if (raw) {
        const acct = JSON.parse(raw);
        if (acct.disabled) { await env.CMS_KV.delete("asess:" + t); return ""; }
      }
    }
    return who || "admin";
  }

  // Bootstrap only. Before ANY staff account exists the raw admin token is
  // accepted so the owner can reach the dashboard and create one. Once real
  // accounts exist it must stop working as a bearer credential too — not just
  // at /admin-login — or the per-person accountability those accounts provide
  // is bypassable by anyone still holding the old shared secret.
  const staff = await env.CMS_KV.list({ prefix: "staff:" });
  if (staff.keys.length > 0) return "";
  const enrolled = await env.CMS_KV.get("admin_totp");
  if (!enrolled && safeEqual(t, env.ADMIN_TOKEN)) return "admin";
  return "";
}

/**
 * Has this identity got an authenticator on it?
 *
 * Per account, never shared: one secret for everybody means the second person
 * to enrol needs the first person's phone, which is a shared password with
 * extra steps rather than a second factor.
 */
async function totpEnrolled(env, who) {
  if (!who) return false;
  if (!who.includes("@")) return !!(await env.CMS_KV.get("admin_totp"));
  return !!(await env.CMS_KV.get("totp:" + who));
}

/**
 * A staff session that may actually do something.
 *
 * A signed-in staff account with no authenticator gets a session that can do
 * exactly one thing — enrol one. Every other admin endpoint answers 403 until
 * it has. The owner asked for this in those words: nobody reaches the business
 * without the second factor. The break-glass identity ("admin", issued only by
 * OVERRIDE_TOKEN or first-run setup) is deliberately outside the rule, because
 * the point of break-glass is to work on the day the phone is lost.
 */
/* ============================ SIGN IN WITH APPLE ===========================
 *
 * Apple's OAuth is Google's with three differences that matter here.
 *
 *  1. There is no client secret to paste. You sign one yourself: an ES256 JWT
 *     made from the .p8 key Apple issues. Apple will accept one that lasts six
 *     months — and a six-month secret is a secret somebody has to remember to
 *     replace on a Tuesday in February, or Apple sign-in stops dead with no
 *     warning. This one is minted per exchange and lasts five minutes, so
 *     there is nothing to expire and nothing to diarise.
 *  2. Asking for the name or the email makes Apple POST the answer back as a
 *     form instead of redirecting with it, which is why the callback is a POST.
 *  3. The person's name arrives exactly once, on their very first
 *     authorisation, in a separate `user` field — never in the identity token,
 *     and never again. Read it there or lose it permanently.
 */
/*
 * The three Apple identifiers, trimmed.
 *
 * A secret set from a terminal picks up whitespace with depressing ease — a
 * trailing newline from `echo`, or a whole command line if a pasted block gets
 * eaten by an interactive prompt reading stdin. None of it is visible
 * anywhere, and Apple's only answer is invalid_client, which says nothing
 * about which of the four values is wrong.
 *
 * So they are trimmed on the way out, and appleReady() checks their SHAPE
 * rather than merely that they are non-empty: Team ID and Key ID are exactly
 * ten alphanumeric characters, and a Services ID is a reverse-domain string.
 * A secret holding something else means the button stays hidden and the start
 * endpoint says so, instead of sending somebody to Apple to be refused.
 */
const appleId = v => String(v || "").trim();
const APPLE_TEN = /^[A-Za-z0-9]{10}$/;
const appleReady = env => !!(
  /^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/.test(appleId(env.APPLE_SERVICES_ID))
  && APPLE_TEN.test(appleId(env.APPLE_TEAM_ID))
  && APPLE_TEN.test(appleId(env.APPLE_KEY_ID))
  && String(env.APPLE_PRIVATE_KEY || "").includes("PRIVATE KEY")
);

async function appleClientSecret(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: appleId(env.APPLE_KEY_ID), typ: "JWT" })));
  const claim = b64url(new TextEncoder().encode(JSON.stringify({
    iss: appleId(env.APPLE_TEAM_ID), iat: now, exp: now + 300,
    aud: "https://appleid.apple.com", sub: appleId(env.APPLE_SERVICES_ID),
  })));
  const unsigned = header + "." + claim;
  const pem = String(env.APPLE_PRIVATE_KEY).replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const binaryStr = typeof Buffer !== "undefined" ? Buffer.from(pem, "base64").toString("binary") : atob(pem);
  const der = Uint8Array.from(binaryStr, c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(unsigned));
  return unsigned + "." + b64url(sig);
}

// base64url -> bytes, padding restored. Used on both halves of a JWT.
function b64urlBytes(s) {
  const t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(t.padEnd(Math.ceil(t.length / 4) * 4, "=")), c => c.charCodeAt(0));
}

/**
 * Verify an Apple identity token against Apple's own published signing keys.
 *
 * The code was swapped with Apple over TLS moments ago, so this is belt and
 * braces — but an identity assertion nobody checks is how a system ends up
 * trusting whatever the last hop felt like sending it.
 */
async function appleVerifyIdToken(env, idToken) {
  const parts = String(idToken || "").split(".");
  if (parts.length !== 3) return null;
  const [h, pl, sg] = parts;
  let head, claims;
  try {
    head = JSON.parse(new TextDecoder().decode(b64urlBytes(h)));
    claims = JSON.parse(new TextDecoder().decode(b64urlBytes(pl)));
  } catch (e) { return null; }
  const jr = await fetch("https://appleid.apple.com/auth/keys").catch(() => null);
  if (!jr || !jr.ok) return null;
  const jwks = await jr.json().catch(() => null);
  const jwk = jwks && Array.isArray(jwks.keys) ? jwks.keys.find(k => k.kid === head.kid) : null;
  if (!jwk) return null;
  let ok = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64urlBytes(sg), new TextEncoder().encode(h + "." + pl));
  } catch (e) { return null; }
  if (!ok) return null;
  if (claims.iss !== "https://appleid.apple.com") return null;
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(appleId(env.APPLE_SERVICES_ID))) return null;
  if (!(Number(claims.exp) * 1000 > Date.now())) return null;
  return claims;
}

/**
 * The last few inches of a staff sign-in, whichever provider proved the
 * address: check the person is actually on the staff list, mint the session,
 * and park it as a one-shot grant.
 *
 * The session token travels back in the URL FRAGMENT: fragments never reach
 * server logs, and the grant dies on first use or in 60 seconds, whichever
 * comes first. Returns the grant id, or null if this address is nobody here —
 * which is the whole of "other staff cannot log in without being approved".
 * Nothing in this path can create an account.
 */
async function grantStaffSession(env, request, email, backTo, provider) {
  const acctRaw = await env.CMS_KV.get("staff:" + email);
  const acct = acctRaw ? JSON.parse(acctRaw) : null;
  if (!acct || acct.disabled) {
    await audit(env, email, "admin_login_" + provider + "_rejected", "not a staff account");
    return null;
  }
  const t = token();
  await env.CMS_KV.put("asess:" + t, email, { expirationTtl: 60 * 60 * 12 });
  const grant = crypto.randomUUID();
  await env.CMS_KV.put("glogin_grant:" + grant, JSON.stringify({
    token: t, email, name: acct.name || "", role: acct.role || "staff",
  }), { expirationTtl: 60 });
  await audit(env, email, "admin_login_" + provider, email + " " + clientIp(request) + " -> " + backTo);
  return grant;
}

/**
 * The same for a customer, who unlike a staff member may be new. The provider
 * has proved the address, so the account starts verified — but marketing stays
 * OFF, because signing in is consent to have an account, never consent to be
 * marketed at.
 */
async function grantCustomerSession(env, request, email, name, provider) {
  const raw = await env.CMS_KV.get("user:" + email);
  let user = raw ? JSON.parse(raw) : null;
  if (!user) {
    user = {
      name: String(name || email.split("@")[0]).trim(),
      email, phone: "",
      marketing: false,
      smsUpdates: true,
      emailVerified: true,
      [provider]: true,
      consentAt: Date.now(), privacyVersion: PRIVACY_VERSION, createdAt: Date.now(),
    };
    await env.CMS_KV.put("user:" + email, JSON.stringify(user));
    await audit(env, email, "account_created", provider + " sign-in, consent v" + PRIVACY_VERSION);
  } else if (!isVerified(user)) {
    // They signed up with a password and never confirmed the address. The
    // provider just confirmed it for them, which is stronger than the code.
    user.emailVerified = true;
    await env.CMS_KV.put("user:" + email, JSON.stringify(user));
    await audit(env, email, "email_verified", "by " + provider + " sign-in");
  }
  const t = token();
  await env.CMS_KV.put("sess:" + t, email, { expirationTtl: 60 * 60 * 24 * 30 });
  const grant = crypto.randomUUID();
  await env.CMS_KV.put("cglogin_grant:" + grant, JSON.stringify({ token: t, email }), { expirationTtl: 60 });
  await audit(env, email, "login_" + provider, clientIp(request));
  return grant;
}

async function isAdmin(request, env) {
  const who = await adminSession(request, env);
  if (!who) return false;
  if (who.includes("@") && !(await env.CMS_KV.get("totp:" + who))) return false;
  return true;
}
/**
 * Which staff member is behind this request.
 *
 * /admin-login stores the signed-in email as the value of the "asess:" key, so
 * a money entry can be attributed to a person rather than to "admin". Falls
 * back to "admin" for the pre-2FA bootstrap token, which has no identity.
 */
async function whoAmI(env, request) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return "";
  return (await env.CMS_KV.get("asess:" + t)) || "admin";
}

function ref() { return "CMS-" + Date.now().toString(36).toUpperCase().slice(-5); }

async function sessionUser(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return null;
  const email = await env.CMS_KV.get("sess:" + t);
  if (!email) return null;
  const raw = await env.CMS_KV.get("user:" + email);
  return raw ? JSON.parse(raw) : null;
}
const publicUser = u => ({
  name: u.name, email: u.email, phone: u.phone,
  marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false,
  consentAt: u.consentAt, privacyVersion: u.privacyVersion,
});

// GDPR: append-only audit log of processing events (lawful-basis accountability)
async function audit(env, email, event, detail) {
  try {
    // 25 of the 46 audit calls used to pass the literal string "admin", so every
    // administrative action in the system landed in one bucket called
    // "audit:admin" no matter who performed it. With a single shared token that
    // was merely uninformative. The moment there is more than one named person
    // in the dashboard it is worse than useless: the log looks like it
    // identifies people and does not, which is precisely the situation where
    // somebody goes looking — a price changed, a job deleted, a backup
    // exported — and the answer has to be better than "an admin did it".
    const who = String(email || "unknown");
    const key = "audit:" + who;
    const log = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    // `actor` is duplicated inside the entry on purpose. The key alone carries
    // the identity today, and an entry that only makes sense in the context of
    // its key is one refactor away from being anonymous again.
    log.push({ t: Date.now(), actor: who, event, detail: detail || "" });
    await env.CMS_KV.put(key, JSON.stringify(log.slice(-500)));
  } catch (e) {}
}

/*
 * Roles.
 *
 * `role` was stored on every staff record and shown in the dashboard, and then
 * never checked anywhere — so "owner" and "staff" were decoration. Any staff
 * account could delete any other, reset the owner's password, or export every
 * customer record. That is tolerable with one person and indefensible the
 * moment a contractor has a login too.
 *
 * Three levels, deliberately few:
 *
 *   staff      day-to-day work: jobs, customers, messages, stock, pricing.
 *   developer  everything staff can do, plus the technical settings and the
 *              data export. For whoever maintains the system. Revocable at
 *              handover without touching the owner's account.
 *   owner      the business. The only role that can remove or disable another
 *              owner, and the only one that can hand out the owner role.
 *
 * The rule that matters most is the one stopping a contractor locking out their
 * client, so a developer can do almost everything but cannot touch an owner.
 */
const ROLES = { staff: 1, developer: 2, owner: 3 };
const ROLE_NAMES = Object.keys(ROLES);

/** The role behind this request. The bootstrap token has no identity, and is
 *  only ever accepted while no staff account exists at all, so it gets owner. */
async function actorRole(env, actor) {
  if (!actor || !actor.includes("@")) return "owner";
  const raw = await env.CMS_KV.get("staff:" + actor);
  if (!raw) return "staff";
  const r = JSON.parse(raw).role;
  return ROLES[r] ? r : "staff";
}

const atLeast = (role, needed) => (ROLES[role] || 0) >= (ROLES[needed] || 99);

// ---------- .ics ----------
/**
 * Base64 for text that may contain anything a human typed.
 *
 * btoa() throws on any character above U+00FF, and buildICS() puts a literal
 * em-dash in the SUMMARY line of every invite. So attaching the .ics threw
 * before the send, and EVERY customer booking confirmation with an email
 * address on it failed — silently, because the caller discarded the result.
 * A customer name with an accent or a note with a curly quote would have done
 * the same thing. Encode to UTF-8 bytes first, then base64 those.
 */
function b64utf8(str) {
  const bytes = new TextEncoder().encode(String(str));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function buildICS(o, org) {
  const d = (o.date || "").replace(/-/g, "");
  const start = d ? d + "T090000" : new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  return [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//" + BUSINESS.shortName + "//EN", "METHOD:REQUEST",
    "BEGIN:VEVENT", "UID:" + o.ref + "@cousinsmechanical", "DTSTAMP:" + stamp, "DTSTART:" + start,
    "SUMMARY:" + BUSINESS.shortName + " — " + (o.svcLabel || "Mobile job"),
    "DESCRIPTION:Ref " + o.ref + ". " + (o.svcLabel || "") + " for " + (o.reg || "") + ". " + (o.notes || ""),
    "LOCATION:" + (o.postcode || "Your location"),
    "ORGANIZER;CN=" + BUSINESS.shortName + ":mailto:" + (org || "bookings@cousinsmechanicalservices.co.uk"),
    "END:VEVENT", "END:VCALENDAR",
  ].join("\r\n");
}

// ---------- Messaging (WhatsApp Cloud API — cheaper than SMS) ----------
// Set WHATSAPP_TOKEN + WHATSAPP_PHONE_ID (Meta WhatsApp Business Cloud API).
// Falls back to Twilio SMS only if those are set instead. UK numbers auto-normalised to E.164.
function toE164(num) {
  let n = (num || "").replace(/[^\d+]/g, "");
  if (n.startsWith("+")) return n.slice(1);
  if (n.startsWith("0")) return "44" + n.slice(1);
  if (n.startsWith("44")) return n;
  return n;
}
async function sendWhatsApp(env, to, body) {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID || !to) return { skipped: true };
  const r = await fetch(`https://graph.facebook.com/v20.0/${env.WHATSAPP_PHONE_ID}/messages`, {
    method: "POST",
    headers: { authorization: "Bearer " + env.WHATSAPP_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({ messaging_product: "whatsapp", to: toE164(to), type: "text", text: { body } }),
  }).catch(() => null);
  return { ok: r && r.ok };
}

/**
 * Send an approved WhatsApp *template* message.
 *
 * WhatsApp only allows free-form text inside the 24-hour window that opens when
 * the customer last messaged you. A reminder the day before a job is outside
 * that window, so it MUST be a template Meta has approved — a plain text send
 * is silently rejected with a 131047 error. That is why reminders use this and
 * not sendWhatsApp().
 *
 * The template's body must contain the same number of {{n}} placeholders as
 * `params`, in the same order.
 */
async function sendWhatsAppTemplate(env, to, templateName, params, lang = "en_GB") {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID || !to) return { skipped: true, reason: "WhatsApp not configured" };
  if (!templateName) return { skipped: true, reason: "No template name set" };

  const payload = {
    messaging_product: "whatsapp",
    to: toE164(to),
    type: "template",
    template: {
      name: templateName,
      language: { code: lang },
      components: [{
        type: "body",
        parameters: params.map(t => ({ type: "text", text: String(t ?? "") })),
      }],
    },
  };

  const r = await fetch(`https://graph.facebook.com/v20.0/${env.WHATSAPP_PHONE_ID}/messages`, {
    method: "POST",
    headers: { authorization: "Bearer " + env.WHATSAPP_TOKEN, "content-type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(() => null);

  if (!r) return { ok: false, reason: "network error" };
  if (!r.ok) {
    // Log the real Meta error — template problems are otherwise invisible.
    const detail = await r.text().catch(() => "");
    console.error("[whatsapp] template send failed", r.status, detail.slice(0, 400));
    return { ok: false, status: r.status, detail };
  }
  return { ok: true };
}
/* =========================================================================
 * USAGE METERING
 *
 * Each client runs on their own deployment with their own HubSpot, Google
 * Calendar and SumUp. The one thing they share is Twilio, through a subaccount
 * per client — which gives per-client isolation AND per-client billing under
 * one master account. To price that on, somebody has to know how much each
 * client actually sends.
 *
 * There are two different numbers here and conflating them would cost money:
 *
 *   OUR COUNT     what this system sent — texts, WhatsApp messages, emails.
 *                 Always available, covers channels Twilio never sees, and
 *                 works when Twilio is unreachable. It is a record of
 *                 activity, not an invoice.
 *   TWILIO'S      what Twilio actually charges, from their Usage Records API
 *                 for this subaccount. This is the billing truth.
 *
 * They will not match, and the gap is the point: Twilio bills per SEGMENT, not
 * per message.
 *
 * WHICH IS WHY smsSegments() EXISTS. An SMS is 160 characters in GSM-7. Put a
 * single character outside that alphabet in it and the whole message switches
 * to UCS-2, where a segment is 70 characters — so one stray em-dash or curly
 * apostrophe can turn a one-segment text into three, and triple the cost of
 * every message sent from that template, invisibly and forever.
 *
 * This codebase is full of em-dashes. That is fine in email and would be
 * expensive in SMS, so the count is surfaced and the encoding is named.
 * ====================================================================== */

// GSM 03.38 basic set plus its extension table. Anything not in here forces
// the whole message to UCS-2 and cuts the segment size from 160 to 70.
const GSM7 =
  "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
  "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
const GSM7_EXT = "^{}\\[~]|€";   // these cost TWO characters each

function smsSegments(text) {
  const s = String(text == null ? "" : text);
  let units = 0, gsm = true;
  for (const ch of s) {
    if (GSM7.includes(ch)) units += 1;
    else if (GSM7_EXT.includes(ch)) units += 2;
    else { gsm = false; break; }
  }
  if (!gsm) {
    // UCS-2: count UTF-16 code units, so an emoji correctly costs two.
    units = s.length;
    const per = units <= 70 ? 70 : 67;
    return { encoding: "UCS-2", chars: s.length, units, segments: Math.max(1, Math.ceil(units / per)) };
  }
  const per = units <= 160 ? 160 : 153;
  return { encoding: "GSM-7", chars: s.length, units, segments: Math.max(1, Math.ceil(units / per)) };
}

/**
 * Swap typographic punctuation for its plain equivalent, so a text does not
 * cost double for the sake of a nicer dash.
 *
 * Measured on the real templates: the status update — sent four times a job,
 * on confirmed, on the way, arrived, complete — was going out as UCS-2 and
 * billing two segments instead of one, because of a single em-dash. That is
 * roughly half the SMS bill for the most frequently sent message in the system.
 *
 * ONLY punctuation is touched, never letters. Turning an em-dash into a hyphen
 * loses nothing; turning "Zoë" into "Zoe" mangles somebody's name to save a
 * fraction of a penny, which is not a trade worth making. A name with an
 * unusual letter will still send as UCS-2, and it should.
 */
const GSM_SWAPS = [
  [/[‐-―]/g, "-"],   // hyphens, en dash, em dash, horizontal bar
  [/[‘’‛]/g, "'"],
  [/[“”‟]/g, '"'],
  [/…/g, "..."],
  [/[•·]/g, "-"],
  [/ /g, " "],            // non-breaking space
  [/–/g, "-"],
];
function gsmSafe(text) {
  let out = String(text == null ? "" : text);
  for (const [re, to] of GSM_SWAPS) out = out.replace(re, to);
  return out;
}

/* ---------------------------------------------------------- SPEND CAP ----
 *
 * Twilio is the one service billed to the developer's master account and
 * resold, so it is the one place a client's traffic can run up somebody else's
 * bill. This is the brake.
 *
 * THREE DECISIONS, EACH DELIBERATE:
 *
 * 1. It never blocks a job-critical message. A cap that stops a customer being
 *    told their van is on the way has broken the product to save a few pounds,
 *    and the client would rightly rather pay. Only the discretionary traffic —
 *    test messages, bulk sends — stops. Job messages keep flowing and the
 *    ALERTS get louder instead.
 *
 * 2. It fails open. If Twilio's usage API is unreachable we do not know the
 *    spend, and refusing to send on a guess would take the site down every
 *    time Twilio has a bad afternoon. Unknown means allowed, and says so.
 *
 * 3. Only a developer can change it. The client can SEE the cap and their
 *    usage — that is the point, it makes the invoice evidence rather than a
 *    claim — but a client who can raise their own ceiling is not a ceiling.
 *
 * The spend figure is cached and refreshed hourly by the cron rather than
 * fetched per message: a booking confirmation should not wait on Twilio's
 * billing API, and that API is rate limited.
 */
/*
 * TWO ceilings, because one is not enough and I nearly shipped only the soft one.
 *
 *   monthlyCap  the budget. Alerts, and stops DISCRETIONARY traffic — tests,
 *               bulk sends. Job messages keep flowing.
 *   hardCap     the runaway brake. Stops EVERYTHING, including job messages.
 *
 * The soft cap alone protects nobody, and it took writing it to see why: the
 * traffic that would actually run up a surprise bill — a retry loop, a
 * compromised token, a client doing ten times the volume they were quoted — is
 * all job traffic, and job traffic is exactly what the soft cap refuses to
 * touch. A brake that cannot stop the runaway case is decoration.
 *
 * So hardCap exists and should be set well above any honest month, because
 * reaching it means something is wrong rather than busy. When it does bite,
 * every blocked message is written to the delivery-failure log and surfaces in
 * the dashboard banner. Nothing is ever dropped quietly.
 */
const DEFAULT_LIMITS = {
  monthlyCap: 0,        // in Twilio's own billing currency. 0 = no cap.
  hardCap: 0,           // 0 = no runaway brake.
  warnAtPct: 80,
  blockDiscretionary: true,
};

async function usageLimits(env) {
  const raw = await env.CMS_KV.get("usage_limits");
  return { ...DEFAULT_LIMITS, ...(raw ? JSON.parse(raw) : {}) };
}

/** Month-to-date Twilio spend for this subaccount. Cached; `force` refetches. */
async function twilioSpend(env, force = false) {
  const CACHE = "twilio_spend";
  if (!force) {
    const c = JSON.parse((await env.CMS_KV.get(CACHE)) || "null");
    if (c && Date.now() - c.at < 60 * 60 * 1000) return c;
  }
  if (!(env.TWILIO_SID && env.TWILIO_TOKEN)) {
    return { at: Date.now(), known: false, reason: "Twilio is not configured" };
  }
  const r = await fetch(
    "https://api.twilio.com/2010-04-01/Accounts/" + env.TWILIO_SID + "/Usage/Records/ThisMonth.json?PageSize=50",
    { headers: { authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) } },
  ).catch(() => null);
  if (!r || !r.ok) {
    // Deliberately NOT cached — a transient failure must not pin "unknown" in
    // place for an hour and blind the cap for the rest of it.
    return { at: Date.now(), known: false, reason: r ? "Twilio returned " + r.status : "could not reach Twilio" };
  }
  const d = await r.json().catch(() => ({}));
  const rows = d.usage_records || [];
  const total = rows.reduce((n, x) => n + (Number(x.price) || 0), 0);
  const out = {
    at: Date.now(), known: true,
    spend: Math.round(total * 10000) / 10000,
    currency: (rows.find(x => x.price_unit) || {}).price_unit || "",
    month: new Date().toISOString().slice(0, 7),
  };
  await env.CMS_KV.put(CACHE, JSON.stringify(out));
  return out;
}

/**
 * May we send a discretionary message right now?
 *
 * `essential` traffic is never blocked — see decision 1 above.
 */
async function spendAllows(env, essential) {
  const lim = await usageLimits(env);
  if (!lim.monthlyCap && !lim.hardCap) return { allowed: true, reason: "no cap set" };

  const s = await twilioSpend(env);
  if (!s.known) return { allowed: true, reason: "spend unknown — failing open: " + (s.reason || "") };
  const money = n => (s.currency ? s.currency + " " : "") + Number(n).toFixed(2);

  // The runaway brake applies to everything, job messages included.
  if (lim.hardCap && s.spend >= Number(lim.hardCap)) {
    return {
      allowed: false, hard: true, spend: s.spend, cap: lim.hardCap, currency: s.currency,
      reason: "Runaway spend brake hit at " + money(s.spend) + " against a hard cap of "
        + money(lim.hardCap) + ". ALL messages are stopped, including job updates, "
        + "because spend this far above the budget means something is wrong rather than busy.",
    };
  }
  // The budget cap stops only discretionary traffic.
  if (essential) return { allowed: true, essential: true };
  if (!lim.monthlyCap || !lim.blockDiscretionary) return { allowed: true, reason: "no soft cap" };
  if (s.spend < Number(lim.monthlyCap)) return { allowed: true, spend: s.spend, cap: lim.monthlyCap };
  return {
    allowed: false, spend: s.spend, cap: lim.monthlyCap, currency: s.currency,
    reason: "Monthly message spend cap reached (" + money(s.spend) + " of " + money(lim.monthlyCap)
      + "). Job messages are still being sent; this one was not.",
  };
}

/**
 * Warn once when the spend crosses the threshold, and once more at the cap.
 * Once per month per level — an alert that arrives every hour is an alert
 * nobody reads by the second day.
 */
async function spendWatch(env) {
  const lim = await usageLimits(env);
  if (!lim.monthlyCap) return { skipped: true, reason: "no cap set" };
  const s = await twilioSpend(env, true);
  if (!s.known) return { skipped: true, reason: s.reason };

  const pct = (s.spend / Number(lim.monthlyCap)) * 100;
  const level = pct >= 100 ? "cap" : pct >= Number(lim.warnAtPct) ? "warn" : null;
  if (!level) return { ok: true, spend: s.spend, pct: Math.round(pct) };

  const stamp = "spend_alert:" + s.month + ":" + level;
  if (await env.CMS_KV.get(stamp)) return { ok: true, alreadyAlerted: level };
  await env.CMS_KV.put(stamp, "1", { expirationTtl: 60 * 60 * 24 * 40 });

  const to = validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM;
  if (to) {
    await sendEmail(env, to,
      level === "cap"
        ? "Message spend cap reached — " + BUSINESS.name
        : "Message spend at " + Math.round(pct) + "% — " + BUSINESS.name,
      "Twilio spend so far this month: " + s.currency + " " + s.spend.toFixed(2)
      + " against a cap of " + Number(lim.monthlyCap).toFixed(2) + ".\n\n"
      + (level === "cap"
        ? "Discretionary messages have stopped. Booking confirmations and job updates are STILL being sent — the cap deliberately does not break customer communication.\n\nRaise the cap in the dashboard, or top up Twilio."
        : "Nothing has stopped. This is the early warning.")
      + "\n\nUsage: " + (env.SITE_URL || "") + "/admin");
  }
  return { ok: true, alerted: level, spend: s.spend, pct: Math.round(pct) };
}

/**
 * Add to this month's tally. Read-modify-write on one small key per month —
 * fine at a garage's volume, and deliberately never allowed to break a send:
 * a failed counter must not stop a customer being told their van is coming.
 */
async function recordUsage(env, kind, n = 1) {
  try {
    const key = "usage:" + new Date().toISOString().slice(0, 7);   // usage:YYYY-MM
    const u = JSON.parse((await env.CMS_KV.get(key)) || "{}");
    u[kind] = (Number(u[kind]) || 0) + n;
    u.updatedAt = Date.now();
    await env.CMS_KV.put(key, JSON.stringify(u));
  } catch (e) { /* metering is never worth a failed message */ }
}

/**
 * Send a message to a customer's mobile.
 *
 * WhatsApp first because it is cheaper, but it MUST fall through to Twilio when
 * it fails. Meta only allows free-form text inside 24 hours of the customer
 * messaging you first; a booking confirmation is business-initiated, so for
 * anyone who has never WhatsApp'd Cousins it is rejected every time. The old
 * version returned that rejection and stopped, which is why customers were
 * getting no updates at all while the config looked complete.
 */
async function sendSMS(env, to, body, opts = {}) {
  if (!to) return { skipped: true, reason: "no phone number" };

  // Essential by default. Anything genuinely discretionary — a test send, a
  // bulk push — has to opt IN to being stoppable, so a new caller can never
  // accidentally make a customer's job update droppable.
  const essential = opts.essential !== false;
  const budget = await spendAllows(env, essential);
  if (!budget.allowed) {
    // Recorded, never dropped quietly: this surfaces in the dashboard's
    // delivery-failure banner exactly like a Twilio rejection would.
    await noteMailFailure(env, to, "SMS blocked by spend cap", { reason: budget.reason, channel: "spend-cap" });
    return { ok: false, blocked: true, reason: budget.reason };
  }

  const attempts = [];

  if (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID) {
    const wa = await sendWhatsApp(env, to, body);
    if (wa && wa.ok) { await recordUsage(env, "whatsapp"); return { ok: true, channel: "whatsapp" }; }
    attempts.push("WhatsApp: " + ((wa && (wa.reason || wa.detail)) || "rejected"));
  }

  if (env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM) {
    // Only the SMS body is normalised. WhatsApp bills per conversation, not
    // per character, so it keeps the nicer typography.
    const smsBody = gsmSafe(body);
    const form = new URLSearchParams({ To: "+" + toE164(to), From: env.TWILIO_FROM, Body: smsBody });
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) },
      body: form,
    }).catch(() => null);
    if (r && r.ok) {
      // Segments, not messages. Twilio bills per segment and a single
      // non-GSM character turns one text into three.
      const seg = smsSegments(smsBody);
      await recordUsage(env, "sms");
      await recordUsage(env, "smsSegments", seg.segments);
      if (seg.encoding === "UCS-2") await recordUsage(env, "smsUnicode");
      return { ok: true, channel: "sms", segments: seg.segments, encoding: seg.encoding };
    }
    const detail = r ? await r.text().catch(() => "") : "network error";
    attempts.push("Twilio: " + String(detail).slice(0, 200));
  }

  if (!attempts.length) return { skipped: true, reason: "no messaging channel configured" };
  return { ok: false, reason: attempts.join(" | ") };
}

/* =========================================================================
 * STRIPE
 *
 * ONE RULE, and everything else follows from it: card details never touch this
 * Worker. The customer is sent to Stripe's own hosted Checkout page, enters the
 * card there, and comes back with nothing but a session id. Cousins stays on
 * SAQ-A — the shortest PCI self-assessment there is.
 *
 * The moment a card number passes through our own form or server it becomes
 * SAQ-D: quarterly scans, penetration testing, a documented security
 * programme. Same feature to the customer, an order of magnitude more
 * obligation. Nothing below should ever be changed in a way that crosses that
 * line.
 *
 * A deposit, not the full amount. The problem in mobile work is the no-show,
 * not the payment — and taking the full price up front for a job whose price
 * can move once the van arrives creates refunds nobody wanted.
 * ====================================================================== */
const DEFAULT_DEPOSIT = { enabled: false, pence: 2500, label: "Booking deposit" };

async function depositSettings(env) {
  const raw = await env.CMS_KV.get("deposit_settings");
  return { ...DEFAULT_DEPOSIT, ...(raw ? JSON.parse(raw) : {}) };
}

function stripeReady(env) { return !!(env.STRIPE_SECRET_KEY && env.STRIPE_WEBHOOK_SECRET); }

/** Stripe wants form encoding, including for nested fields. */
function stripeForm(obj, prefix = "", out = new URLSearchParams()) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    const key = prefix ? `${prefix}[${k}]` : k;
    if (typeof v === "object" && !Array.isArray(v)) stripeForm(v, key, out);
    else if (Array.isArray(v)) v.forEach((item, i) => (typeof item === "object" ? stripeForm(item, `${key}[${i}]`, out) : out.append(`${key}[${i}]`, String(item))));
    else out.append(key, String(v));
  }
  return out;
}

async function stripeCall(env, path, body) {
  if (!env.STRIPE_SECRET_KEY) return { skipped: true, reason: "Stripe not configured" };
  const r = await fetch("https://api.stripe.com/v1" + path, {
    method: "POST",
    headers: {
      authorization: "Bearer " + env.STRIPE_SECRET_KEY,
      "content-type": "application/x-www-form-urlencoded",
      // Stripe replays a retried request rather than charging twice.
      "idempotency-key": body && body.__idem ? String(body.__idem) : crypto.randomUUID(),
    },
    body: stripeForm({ ...body, __idem: undefined }),
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error reaching Stripe" };
  const text = await r.text().catch(() => "");
  if (!r.ok) {
    console.error("[stripe]", path, r.status, text.slice(0, 300));
    return { ok: false, status: r.status, reason: "Stripe returned " + r.status + ": " + text.slice(0, 200) };
  }
  try { return { ok: true, data: JSON.parse(text) }; } catch { return { ok: false, reason: "unreadable response" }; }
}

/**
 * Verify a Stripe webhook signature.
 *
 * This is the whole security model for payments. The redirect back from
 * Checkout proves nothing — anyone can visit a success URL — so the ONLY thing
 * that may mark a job paid is a signed webhook. Constant-time compare, and a
 * five-minute replay window so a captured POST cannot be sent again tomorrow.
 */
async function stripeSigOk(env, rawBody, header) {
  if (!env.STRIPE_WEBHOOK_SECRET || !header) return false;
  const parts = Object.fromEntries(String(header).split(",").map(p => p.split("=").map(x => x.trim())));
  const t = Number(parts.t), sig = parts.v1;
  if (!Number.isFinite(t) || !sig) return false;
  if (Math.abs(Date.now() / 1000 - t) > 300) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(t + "." + rawBody));
  const hex = [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("");
  return safeEqual(hex, sig);
}

/* ---------------------------------------------------------------- SumUp ----
 *
 * The client takes card payments through SumUp, not Stripe, so this is the
 * provider actually in use. Stripe stays because it is written and tested and
 * the next garage may well use it — paymentProvider() picks one.
 *
 * SumUp differs from Stripe in two ways that are both quietly dangerous:
 *
 * 1. AMOUNTS ARE DECIMAL MAJOR UNITS. SumUp wants 25.00, Stripe wants 2500,
 *    and this system stores pence everywhere. Get it backwards and you charge
 *    a customer either 100x too much or 100x too little, and the second one
 *    looks like it worked. Conversion happens here and nowhere else, and there
 *    are tests in both directions.
 *
 * 2. WEBHOOKS ARE NOT SIGNED, AND CARRY NO STATUS. The whole payload is
 *    {event_type, id} — an id and nothing else. There is no HMAC, no secret,
 *    no replay window. Anyone who finds the URL can POST to it.
 *
 *    So the webhook is treated as a nudge, never as evidence: it tells us
 *    something changed, and then we ask SumUp what actually happened using our
 *    own API key. SumUp's own documentation is explicit about this — "your
 *    application must always verify if the event really took place, by calling
 *    a relevant SumUp's API".
 *
 *    That ends up STRONGER than the Stripe signature check rather than weaker.
 *    A forged Stripe webhook is stopped by failing the HMAC; a forged SumUp
 *    webhook is stopped because nothing it says is believed in the first
 *    place. The worst a forger achieves is making us ask SumUp about a
 *    checkout id, and being told it is not paid.
 */
/*
 * Two ways in, one rule. An API key set as a secret (the client makes one in
 * his own SumUp dashboard) always wins — it is a deliberate configuration.
 * Otherwise the "Connect SumUp" button: the client signs in with HIS SumUp
 * account, the OAuth tokens land in KV under "sumup_oauth", and access tokens
 * are refreshed on demand. SumUp ROTATES refresh tokens — every refresh hands
 * back a new one and the old one dies — so the rotated token is persisted
 * immediately or the connection silently breaks within the hour.
 */
async function sumupStored(env) {
  try { return JSON.parse((await env.CMS_KV.get("sumup_oauth")) || "null"); }
  catch { return null; }
}

/** Live SumUp credentials: { token, merchant } — or null when not configured. */
async function sumupAuth(env) {
  if (env.SUMUP_API_KEY && env.SUMUP_MERCHANT_CODE) {
    return { token: env.SUMUP_API_KEY, merchant: env.SUMUP_MERCHANT_CODE };
  }
  if (!env.SUMUP_CLIENT_ID || !env.SUMUP_CLIENT_SECRET) return null;
  const s = await sumupStored(env);
  if (!s || !s.refresh_token) return null;
  if (s.access_token && Number(s.access_expires) > Date.now() + 60000) {
    return { token: s.access_token, merchant: s.merchant_code || "" };
  }
  const r = await fetch("https://api.sumup.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: s.refresh_token,
      client_id: env.SUMUP_CLIENT_ID,
      client_secret: env.SUMUP_CLIENT_SECRET,
    }),
  }).catch(() => null);
  if (!r || !r.ok) {
    const detail = r ? await r.text().catch(() => "") : "network error";
    console.error("[sumup] token refresh failed:", String(detail).slice(0, 300));
    // invalid_grant means the refresh token is dead (revoked, or a rotation
    // was lost). The connection is over; the dashboard shows Connect again.
    if (String(detail).includes("invalid_grant")) await env.CMS_KV.delete("sumup_oauth");
    return null;
  }
  const t = await r.json().catch(() => ({}));
  if (!t.access_token) return null;
  const next = {
    ...s,
    access_token: t.access_token,
    access_expires: Date.now() + (Number(t.expires_in) || 3599) * 1000,
    refresh_token: t.refresh_token || s.refresh_token,
  };
  await env.CMS_KV.put("sumup_oauth", JSON.stringify(next));
  return { token: next.access_token, merchant: next.merchant_code || "" };
}

async function sumupReady(env) { return !!(await sumupAuth(env)); }

/** Which provider is live. Explicit, because "both configured" must not be ambiguous. */
async function paymentProvider(env) {
  if (await sumupReady(env)) return "sumup";
  if (stripeReady(env)) return "stripe";
  return null;
}
const paymentsReady = async env => (await paymentProvider(env)) !== null;

/** Pence in, SumUp's decimal string out. The only place this conversion happens. */
const penceToMajor = pence => (Math.round(Number(pence) || 0) / 100).toFixed(2);
/** And back. Rounded, because 0.1 + 0.2 is not 0.3 and money cannot be approximate. */
const majorToPence = major => Math.round(Number(major) * 100);

async function sumupCall(env, method, path, body) {
  const auth = await sumupAuth(env);
  if (!auth) return { ok: false, reason: "SumUp not configured" };
  const r = await fetch("https://api.sumup.com/v0.1" + path, {
    method,
    headers: {
      authorization: "Bearer " + auth.token,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error reaching SumUp" };
  const text = await r.text().catch(() => "");
  if (!r.ok) {
    console.error("[sumup]", method, path, r.status, text.slice(0, 300));
    return { ok: false, status: r.status, reason: "SumUp returned " + r.status + ": " + text.slice(0, 200) };
  }
  try { return { ok: true, data: text ? JSON.parse(text) : {} }; }
  catch { return { ok: false, reason: "unreadable response from SumUp" }; }
}

/**
 * Ask SumUp what really happened to a checkout.
 *
 * Everything that marks a job paid goes through here. Returns the booking
 * reference and the amount as SumUp reports them, never as the caller claims.
 */
async function sumupVerify(env, checkoutId) {
  const id = String(checkoutId || "").trim();
  if (!id) return { ok: false, reason: "no checkout id" };
  const res = await sumupCall(env, "GET", "/checkouts/" + encodeURIComponent(id));
  if (!res.ok) return res;
  const c = res.data || {};
  return {
    ok: true,
    id: c.id || id,
    status: String(c.status || "").toUpperCase(),   // PENDING | PAID | FAILED | EXPIRED
    paid: String(c.status || "").toUpperCase() === "PAID",
    ref: String(c.checkout_reference || "").trim(),
    pence: majorToPence(c.amount),
    currency: String(c.currency || "").toUpperCase(),
  };
}

/**
 * Credit a verified payment to a job: record it, update the running total, and
 * send the receipt to the customer and the alert to the owner.
 *
 * Shared by both providers on purpose. This logic used to live inside the
 * Stripe webhook, and porting SumUp by copying it would have meant two receipt
 * paths to keep in step — which is exactly how the card receipt came to print
 * "££25.00" while the other path was correct.
 *
 * CALLERS MUST HAVE VERIFIED THE PAYMENT FIRST. Nothing here checks that money
 * changed hands; it trusts `pence` completely. For Stripe that means a valid
 * signature, for SumUp it means SumUp itself said PAID.
 */
async function creditPayment(env, ctx, { ref, email, pence, method, providerRef, auditEvent }) {
  if (!ref) return { ok: true, ignored: "no reference" };
  const owner = String(email || "").toLowerCase() || (await findBookingOwner(env, ref)) || "";
  const key = "bookings:" + (owner || "guest");
  const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
  const i = arr.findIndex(o => o.ref === ref);
  if (i < 0) return { ok: true, ignored: "unknown booking" };

  const job = arr[i];
  job.payments = Array.isArray(job.payments) ? job.payments : [];
  // Both providers retry until they get a 2xx, and the customer may also come
  // back through the return URL, so the same payment can arrive three times.
  // Keying on the provider's own id makes every repeat a no-op instead of a
  // second charge against the job. `stripeSession` is still read so payments
  // recorded before this was generalised still de-duplicate.
  if (job.payments.some(x => x.providerRef === providerRef || x.stripeSession === providerRef)) {
    return { ok: true, duplicate: true };
  }

  const amount = Math.round(Number(pence) || 0);
  if (amount <= 0) return { ok: true, ignored: "zero amount" };

  job.payments.push({ t: Date.now(), kind: "payment", pence: amount, method, note: "Deposit paid online", by: method, providerRef });
  job.paidPence = (Number(job.paidPence) || 0) + amount;
  job.updates = [...(job.updates || []), { t: Date.now(), s: "Deposit received", d: "£" + (amount / 100).toFixed(2) + " paid by card" }];
  await env.CMS_KV.put(key, JSON.stringify(arr));
  await audit(env, owner || "guest", auditEvent || "card_payment", ref + " £" + (amount / 100).toFixed(2));

  if (job.email) {
    const unsub = await unsubUrl(env, job.email);
    const subject = "Payment received — " + ref + " — " + BUSINESS.shortName;
    const html = renderEmail("payment_received", {
      subject, preheader: "£" + (amount / 100).toFixed(2) + " received for " + ref,
      firstname: String(job.name || "there").trim().split(/\s+/)[0],
      // No £ here — the template already prints &pound; before {{{amount}}}.
      booking_ref: ref, amount: (amount / 100).toFixed(2),
      vehicle_reg: job.reg || "Not given",
      service: job.svcLabel || job.service || "Mobile job",
    }, { footer_note: "This is a receipt for job " + esc(ref) + ", not marketing." + (unsub ? '<br /><a href="' + unsub + '" style="color:#6b7280;text-decoration:underline;">Unsubscribe from marketing emails</a>' : "") });
    sendEmailTracked(env, ctx, job.email, subject,
      "Hi " + (job.name || "there") + ",\n\nWe have received your £" + (amount / 100).toFixed(2)
      + " deposit for job " + ref + ".\n\nThe balance is payable on site when the work is done.\n\n" + BUSINESS.legalName,
      null, { html, unsubscribeUrl: unsub });
  }
  if (validEmail(env.OWNER_EMAIL) || env.MAIL_FROM) {
    sendEmailTracked(env, ctx, validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM,
      "DEPOSIT PAID " + ref + " — £" + (amount / 100).toFixed(2),
      "£" + (amount / 100).toFixed(2) + " deposit received for " + ref + " (" + (job.name || "") + ").");
  }
  return { ok: true, credited: amount };
}

/* =========================================================================
 * AVAILABILITY
 *
 * Two independent things can make a slot unbookable, and both have to be
 * checked or the promise is worthless:
 *
 *   1. Cousins is already doing enough jobs in that window. That is OUR data,
 *      so it works with nothing configured — which matters, because until now
 *      two customers could book the same morning and nothing anywhere noticed.
 *   2. Something else is in the Google calendar — a holiday, a dentist, a job
 *      taken over the phone. Only visible once GCAL_* is set, so the calendar
 *      check degrades to "not busy" rather than blocking bookings when it is
 *      unavailable. Refusing work because a third party is unreachable would be
 *      a worse failure than the double-booking it prevents.
 * ====================================================================== */
const SLOTS = [
  { key: "Morning (8–12)",   start: 8,  end: 12 },
  { key: "Afternoon (12–5)", start: 12, end: 17 },
  { key: "Evening (5–7)",    start: 17, end: 19 },
];
// Not a real window — an emergency is taken whenever it comes in, so it is
// never counted against capacity and never blocked.
const ASAP_SLOT = "ASAP / Emergency";

const DEFAULT_BOOKING_SETTINGS = {
  slotCapacity: 2,      // jobs per window
  leadTimeHours: 2,     // no booking closer than this
  daysAhead: 60,
  closedDays: [0],      // 0 = Sunday
};

async function bookingSettings(env) {
  const raw = await env.CMS_KV.get("booking_settings");
  const s = raw ? JSON.parse(raw) : {};
  return {
    ...DEFAULT_BOOKING_SETTINGS, ...s,
    closedDays: Array.isArray(s.closedDays) ? s.closedDays : DEFAULT_BOOKING_SETTINGS.closedDays,
  };
}

/**
 * How many jobs are already booked into each window on a date.
 *
 * Kept as its own small key per date rather than counted by walking every
 * customer's booking list. Availability is read on every date change in the
 * booking form; listing all of KV to answer it would be slow and would get
 * slower as the business grows.
 */
async function slotCounts(env, date) {
  const raw = await env.CMS_KV.get("slots:" + date);
  return raw ? JSON.parse(raw) : {};
}

async function bumpSlot(env, date, time, delta) {
  if (!date || !time || time === ASAP_SLOT) return;
  const counts = await slotCounts(env, date);
  counts[time] = Math.max(0, (Number(counts[time]) || 0) + delta);
  await env.CMS_KV.put("slots:" + date, JSON.stringify(counts));
}

/** Google free/busy for one day. Returns [] when the calendar is not set up. */
async function googleBusy(env, date) {
  const calId = await gcalCalendarId(env);
  if (!calId) return { configured: false, busy: [] };
  const tok = await googleToken(env);
  if (!tok) return { configured: false, busy: [] };
  const r = await fetch("https://www.googleapis.com/calendar/v3/freeBusy", {
    method: "POST",
    headers: { authorization: "Bearer " + tok, "content-type": "application/json" },
    body: JSON.stringify({
      timeMin: date + "T00:00:00Z",
      timeMax: date + "T23:59:59Z",
      timeZone: "Europe/London",
      items: [{ id: calId }],
    }),
  }).catch(() => null);
  if (!r || !r.ok) {
    console.error("[gcal] freeBusy failed", r && r.status);
    // Deliberately NOT treated as "everything is busy". See the note above.
    return { configured: false, busy: [] };
  }
  const d = await r.json().catch(() => ({}));
  const cal = d.calendars && d.calendars[calId];
  return { configured: true, busy: (cal && cal.busy) || [] };
}

/** Does a busy block overlap the window? Both in London local hours. */
function busyCovers(busy, date, startHour, endHour) {
  const winStart = new Date(date + "T" + String(startHour).padStart(2, "0") + ":00:00Z").getTime();
  const winEnd = new Date(date + "T" + String(endHour).padStart(2, "0") + ":00:00Z").getTime();
  for (const b of busy) {
    const s = new Date(b.start).getTime(), e = new Date(b.end).getTime();
    if (!Number.isFinite(s) || !Number.isFinite(e)) continue;
    // Any overlap at all counts — a two-hour job in the middle of the morning
    // makes that morning unusable, not half-usable.
    if (s < winEnd && e > winStart) return true;
  }
  return false;
}

async function availabilityFor(env, date) {
  const set = await bookingSettings(env);
  const counts = await slotCounts(env, date);
  const gb = await googleBusy(env, date);
  const day = new Date(date + "T12:00:00Z");
  const closed = set.closedDays.includes(day.getUTCDay());
  const now = Date.now();

  const slots = SLOTS.map(s => {
    const booked = Number(counts[s.key]) || 0;
    const tooLate = new Date(date + "T" + String(s.end).padStart(2, "0") + ":00:00Z").getTime()
      < now + set.leadTimeHours * 3600 * 1000;
    const calendarBusy = busyCovers(gb.busy, date, s.start, s.end);
    let reason = null;
    if (closed) reason = "closed";
    else if (tooLate) reason = "too soon";
    else if (booked >= set.slotCapacity) reason = "fully booked";
    else if (calendarBusy) reason = "unavailable";
    return { key: s.key, label: s.key, available: !reason, reason, booked };
  });

  // The emergency option is always offered. Somebody at the roadside is not
  // helped by being told the morning is full.
  slots.push({ key: ASAP_SLOT, label: ASAP_SLOT, available: true, reason: null, booked: 0 });

  return {
    date,
    slots,
    calendarChecked: gb.configured,
    capacity: set.slotCapacity,
    anyAvailable: slots.some(s => s.available && s.key !== ASAP_SLOT),
  };
}

/* =========================================================================
 * HUBSPOT
 *
 * A Private App token, not OAuth. HubSpot OAuth exists for public apps that
 * many different HubSpot accounts install, which is why it has a redirect URI
 * and a consent screen. Cousins is one account integrating with itself, so a
 * private-app token is the whole of the authentication story.
 *
 * Everything here is best-effort. A CRM that is down, rate-limited or
 * misconfigured must never stop a booking being taken — but it must also never
 * fail quietly, so failures land in the same log as the email ones.
 * ====================================================================== */
async function hubspot(env, path, method, body) {
  if (!env.HUBSPOT_TOKEN) return { skipped: true, reason: "HUBSPOT_TOKEN not set" };
  const r = await fetch("https://api.hubapi.com" + path, {
    method,
    headers: { authorization: "Bearer " + env.HUBSPOT_TOKEN, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error reaching HubSpot" };
  const text = await r.text().catch(() => "");
  if (!r.ok) {
    console.error("[hubspot]", method, path, r.status, text.slice(0, 300));
    return { ok: false, status: r.status, reason: "HubSpot returned " + r.status + ": " + text.slice(0, 200) };
  }
  let data = null;
  try { data = JSON.parse(text); } catch { /* some endpoints return no body */ }
  return { ok: true, data };
}

/**
 * Create or update the contact, keyed on email.
 *
 * Upsert rather than search-then-write: a repeat customer must not become a
 * second record, and two bookings arriving together must not race into
 * duplicates. Returns the contact id so a deal can be attached to it.
 */
async function hubspotUpsertContact(env, order) {
  const email = String(order.email || "").trim().toLowerCase();
  if (!email) return { skipped: true, reason: "no email — HubSpot keys contacts on it" };
  const parts = String(order.name || "").trim().split(/\s+/);
  const res = await hubspot(env, "/crm/v3/objects/contacts/batch/upsert", "POST", {
    inputs: [{
      idProperty: "email",
      id: email,
      properties: {
        email,
        firstname: parts[0] || "",
        lastname: parts.slice(1).join(" ") || "",
        phone: order.phone || "",
        zip: order.postcode || "",
      },
    }],
  });
  if (!res.ok) return res;
  const id = res.data && res.data.results && res.data.results[0] && res.data.results[0].id;
  return { ok: true, contactId: id || null };
}

/**
 * Log the job as a deal, already Closed Won.
 *
 * A booking is not a sales opportunity that might not land — by the time it
 * exists the work is agreed. Running it through Appointment Scheduled →
 * Qualified To Buy → Decision Maker Bought-In would be pure theatre in a
 * two-person mobile mechanic business. So the deal is created at the point
 * money is recorded, at the value actually taken.
 */
async function hubspotCreateDeal(env, order, pence, contactId) {
  const amount = Number(pence || 0) / 100;
  const body = {
    properties: {
      dealname: (order.svcLabel || order.service || "Mobile job") + " — " + order.ref,
      pipeline: env.HUBSPOT_PIPELINE || "default",
      dealstage: env.HUBSPOT_WON_STAGE || "closedwon",
      amount: amount ? String(amount) : "0",
    },
  };
  if (contactId) {
    // 3 is HubSpot's built-in deal→contact association type.
    body.associations = [{
      to: { id: contactId },
      types: [{ associationCategory: "HUBSPOT_DEFINED", associationTypeId: 3 }],
    }];
  }
  return hubspot(env, "/crm/v3/objects/deals", "POST", body);
}

/** Push to HubSpot without ever blocking or silently swallowing the outcome. */
function hubspotSync(env, ctx, label, fn) {
  const task = fn().then(async (r) => {
    if (r && r.ok === false) await noteMailFailure(env, "HubSpot", label, { ...r, channel: "crm" });
    return r;
  }).catch(async (err) => {
    await noteMailFailure(env, "HubSpot", label, { reason: err && err.message, channel: "crm" });
    return { ok: false };
  });
  if (ctx && ctx.waitUntil) ctx.waitUntil(task);
  return task;
}

/**
 * Start a Twilio Studio Flow execution.
 *
 * Studio is where Josh edits the wording of the confirmation without a deploy,
 * and it is the same flow that already handles call forwarding and inbound SMS.
 * Worth knowing: on a REST trigger there is no inbound message, so
 * `trigger.message.ChannelSid` and `trigger.message.InstanceSid` are empty
 * inside the flow — the send widget must not bind its channel/service to them
 * or it fails with nothing useful in the log. `contact.channel.address` is set
 * from the `To` below and does work.
 */
async function triggerStudioFlow(env, to, params) {
  if (!env.TWILIO_SID || !env.TWILIO_TOKEN || !env.TWILIO_FROM || !env.TWILIO_STUDIO_FLOW_SID) {
    return { skipped: true, reason: "Studio flow not configured" };
  }
  if (!to) return { skipped: true, reason: "no phone number" };
  const form = new URLSearchParams({
    To: "+" + toE164(to),
    From: env.TWILIO_FROM,
    Parameters: JSON.stringify(params || {}),
  });
  const r = await fetch(`https://studio.twilio.com/v2/Flows/${env.TWILIO_STUDIO_FLOW_SID}/Executions`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN),
    },
    body: form,
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error reaching Twilio Studio" };
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    console.error("[studio] execution failed", r.status, detail.slice(0, 400));
    return { ok: false, status: r.status, reason: "Studio returned " + r.status + ": " + detail.slice(0, 200) };
  }
  return { ok: true, channel: "studio" };
}

/**
 * Text the customer about their own job.
 *
 * Takes the number from the BOOKING, not from a user account. Every real
 * booking so far has been a guest — no account — so every path that looked up
 * "user:" before texting simply did nothing, and no customer has ever received
 * a status message.
 */
function customerPhone(order, user) {
  const p = (order && order.phone) || (user && user.phone) || "";
  return String(p).trim();
}

function customerWantsTexts(order, user) {
  if (user && user.smsUpdates === false) return false;
  if (order && order.smsUpdates === false) return false;
  return true;
}

async function notifyCustomer(env, ctx, order, user, text, label) {
  const to = customerPhone(order, user);
  if (!to || !customerWantsTexts(order, user)) return { skipped: true };
  const task = sendSMS(env, to, text).then(async (r) => {
    if (r && r.ok === false) {
      await noteMailFailure(env, to, (label || "message") + " " + ((order && order.ref) || ""), { ...r, channel: "sms" });
    }
    return r;
  }).catch(async (err) => {
    await noteMailFailure(env, to, (label || "message"), { reason: err && err.message, channel: "sms" });
    return { ok: false };
  });
  if (ctx && ctx.waitUntil) ctx.waitUntil(task);
  return task;
}

// ---------- Google Calendar (service account, JWT -> access token) ----------
/*
 * Is the calendar wired up at all, by either route?
 *
 * There are two, because Google blocks the obvious one. A service-account key
 * is the textbook way to let a server read a calendar, but Google now applies
 * `iam.managed.disableServiceAccountKeyCreation` to organisations by default —
 * long-lived private keys leak, so they stopped letting you make them. On this
 * account the key simply cannot be created.
 *
 * So the supported route here is an OAuth refresh token belonging to the
 * account that owns the diary. It is arguably the better credential anyway: it
 * is scoped to one user's calendar rather than being a project identity that
 * could later be granted other roles, and it can be revoked from that Google
 * account's own security page without a Cloud Console visit.
 *
 * The service-account path stays because it still works wherever the org policy
 * does not apply, and ripping it out would break the template for the next
 * client. Refresh token wins when both are set — if somebody has deliberately
 * configured the newer one, that is the one they mean.
 */
const calendarReadyEnv = env => !!(env.GCAL_CALENDAR_ID && (
  (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.GCAL_REFRESH_TOKEN) ||
  (env.GCAL_CLIENT_EMAIL && env.GCAL_PRIVATE_KEY)
));

/*
 * The third route, and the one a client can actually operate: the "Connect
 * Google Calendar" button in the dashboard. Pressing it walks through Google's
 * own consent screen and the refresh token lands in KV under "gcal_oauth" —
 * nobody copies a token, nobody runs a script, nobody shares a password.
 * Secrets in env still win when set, because a deliberately configured secret
 * is a decision and a button press is a default.
 */
async function gcalStored(env) {
  try { return JSON.parse((await env.CMS_KV.get("gcal_oauth")) || "null"); }
  catch { return null; }
}

async function calendarReady(env) {
  if (calendarReadyEnv(env)) return true;
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return false;
  const s = await gcalStored(env);
  return !!(s && s.refresh_token);
}

/** Which calendar bookings land on. "primary"-style ids work for the API;
 *  the connected account's email is stored so embeds and humans see a name. */
async function gcalCalendarId(env) {
  if (env.GCAL_CALENDAR_ID) return env.GCAL_CALENDAR_ID;
  const s = await gcalStored(env);
  if (s && s.refresh_token) return s.calendar_id || s.email || "primary";
  return "";
}

/** Swap a long-lived refresh token for a short-lived access token. */
async function googleTokenFromRefresh(env, refreshToken) {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken || env.GCAL_REFRESH_TOKEN,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
    }),
  }).catch(() => null);
  if (!r || !r.ok) {
    // Worth a log line rather than a silent null: a refresh token that has been
    // revoked, or expired because the consent screen was left in "Testing",
    // fails exactly like a diary with nothing in it.
    const detail = r ? await r.text().catch(() => "") : "network error";
    console.error("[gcal] refresh token rejected:", String(detail).slice(0, 300));
    return null;
  }
  return (await r.json()).access_token;
}

async function googleToken(env) {
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    let rt = env.GCAL_REFRESH_TOKEN;
    if (!rt) { const s = await gcalStored(env); rt = s && s.refresh_token; }
    if (rt) {
      try { return await googleTokenFromRefresh(env, rt); }
      catch (err) { console.error("googleToken (refresh) error:", err); return null; }
    }
  }
  if (!env.GCAL_CLIENT_EMAIL || !env.GCAL_PRIVATE_KEY) return null;
  try {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
    const claim = b64url(new TextEncoder().encode(JSON.stringify({
      iss: env.GCAL_CLIENT_EMAIL, scope: "https://www.googleapis.com/auth/calendar",
      aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600,
    })));
    const unsigned = header + "." + claim;
    const pem = env.GCAL_PRIVATE_KEY.replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
    const binaryStr = typeof Buffer !== "undefined" ? Buffer.from(pem, "base64").toString("binary") : atob(pem);
    const der = Uint8Array.from(binaryStr, c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
    const jwt = unsigned + "." + b64url(sig);
    const r = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
    }).catch(() => null);
    if (!r || !r.ok) return null;
    return (await r.json()).access_token;
  } catch (err) {
    console.error("googleToken error:", err);
    return null;
  }
}
async function addCalendarEvent(env, o, customerEmail) {
  const tok = await googleToken(env);
  const calId = await gcalCalendarId(env);
  if (!tok || !calId) {
    return { skipped: true, reason: "Google Calendar is not connected — press Connect Google Calendar in the dashboard, or set the calendar secrets." };
  }
  const dateStr = o.date || new Date().toISOString().slice(0, 10);
  let startTime = "09:00:00";
  let endTime = "10:00:00";
  if (o.time) {
    const match = String(o.time).match(/(\d{1,2}):?(\d{2})?/);
    if (match) {
      const hh = match[1].padStart(2, "0");
      const mm = match[2] ? match[2].padStart(2, "0") : "00";
      startTime = `${hh}:${mm}:00`;
      const endHH = String((parseInt(hh, 10) + 1) % 24).padStart(2, "0");
      endTime = `${endHH}:${mm}:00`;
    }
  }

  const startIso = `${dateStr}T${startTime}`;
  const endIso = `${dateStr}T${endTime}`;

  const event = {
    summary: BUSINESS.shortName + " — " + (o.svcLabel || o.service || "Mobile Service Request"),
    description: `Service Request Ref: ${o.ref || 'NEW'}\nCustomer: ${o.name || 'N/A'}\nPhone: ${o.phone || 'N/A'}\nVehicle Reg: ${o.reg || 'N/A'}\nService: ${o.svcLabel || o.service || ''}\nLocation/Postcode: ${o.postcode || o.location || 'N/A'}\nNotes: ${o.notes || ''}\nTyre Details: ${o.tyreDetails ? (typeof o.tyreDetails === 'string' ? o.tyreDetails : JSON.stringify(o.tyreDetails)) : 'N/A'}`,
    location: o.postcode || o.location || "Bridport & West Dorset",
    start: { dateTime: startIso, timeZone: "Europe/London" },
    end: { dateTime: endIso, timeZone: "Europe/London" },
    attendees: customerEmail ? [{ email: customerEmail }] : (o.email ? [{ email: o.email }] : []),
    reminders: { useDefault: true },
  };

  const insert = (ev, sendUpdates) =>
    fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events${sendUpdates ? "?sendUpdates=all" : ""}`, {
      method: "POST",
      headers: { authorization: "Bearer " + tok, "content-type": "application/json" },
      body: JSON.stringify(ev),
    }).catch((err) => {
      console.error("GCAL fetch error:", err);
      return null;
    });

  let r = await insert(event, true);

  // Plain service accounts (no Google Workspace domain-wide delegation) are
  // forbidden from inviting attendees — Google returns 403
  // "Service accounts cannot invite attendees". The event itself is still
  // valid, and the customer already receives an .ics in their confirmation
  // email, so retry once without attendees rather than losing the event.
  if (r && !r.ok && event.attendees.length) {
    const errText = await r.text();
    if (/attendee/i.test(errText) || r.status === 403) {
      console.error("GCAL attendees rejected, retrying without:", errText.slice(0, 200));
      const { attendees, ...noAttendees } = event;
      noAttendees.description += `\nCustomer email: ${event.attendees[0].email}`;
      r = await insert(noAttendees, false);
    } else {
      console.error("GCAL API Error response:", errText);
      return { ok: false, error: errText };
    }
  }

  if (!r || !r.ok) {
    const errText = r ? await r.text() : "Network error reaching Google Calendar API";
    console.error("GCAL API Error response:", errText);
    return { ok: false, error: errText };
  }

  const data = await r.json().catch(() => ({}));
  return { ok: true, eventId: data.id, htmlLink: data.htmlLink };
}

// ---------- Email (Resend — free tier, works from Workers) ----------
// Set RESEND_API_KEY (from resend.com) + MAIL_FROM (a verified sender on your domain).
/**
 * Send an email through Resend.
 *
 * `reply_to` is set to the same help@ address so a customer hitting Reply lands
 * in the business inbox rather than a no-reply void — that only works if the
 * address is set up to receive (Resend forwards inbound to your real mailbox).
 * Failures are logged with Resend's own error body; a silent false here is what
 * makes "why did the confirmation never arrive" impossible to debug.
 */
/**
 * Is this actually an email address?
 *
 * Deliberately strict about the things that silently break a send: a stray
 * space, a trailing newline pasted in from a terminal, a display name, or a
 * phone number typed into the wrong secret. OWNER_EMAIL was set to a value
 * Resend rejected with a 422, and because nothing checked and nothing logged
 * the result, every "new job" alert for every booking vanished while the
 * dashboard, the driver app and /api/health all reported healthy.
 */
function validEmail(v) {
  const s = String(v == null ? "" : v);
  if (s !== s.trim()) return false;                 // leading/trailing whitespace
  if (/[\s<>,;]/.test(s)) return false;             // spaces, display names, lists
  return /^[^@]+@[^@.]+(\.[^@.]+)+$/.test(s);
}

/**
 * Keep the last 50 send failures where an admin can read them.
 *
 * Any send that fails must leave a trace. The whole reason this outage lasted
 * is that sendEmail() returned a perfectly good error object to a caller that
 * threw it away inside ctx.waitUntil().
 */
async function noteMailFailure(env, to, subject, result) {
  try {
    const log = JSON.parse((await env.CMS_KV.get("maillog")) || "[]");
    log.unshift({
      t: Date.now(), to: String(to || "").slice(0, 200), subject: String(subject || "").slice(0, 160),
      reason: String(result && (result.reason || result.detail) || "unknown").slice(0, 300),
      status: result && result.status ? result.status : null,
    });
    await env.CMS_KV.put("maillog", JSON.stringify(log.slice(0, 50)));
  } catch (e) { /* logging must never break the caller */ }
}

/**
 * Write the outcome of a send back onto the booking, so "did the customer
 * actually get their confirmation?" is answerable from the dashboard instead of
 * being a question only the Resend logs could settle.
 */
async function recordJobMail(env, listKey, ref, which, sendPromise) {
  const r = await sendPromise.catch((e) => ({ ok: false, reason: e && e.message }));
  try {
    const arr = JSON.parse((await env.CMS_KV.get(listKey)) || "[]");
    const i = arr.findIndex(o => o.ref === ref);
    if (i < 0) return r;
    arr[i].mail = arr[i].mail || {};
    arr[i].mail[which] = r && r.ok ? { ok: true, t: Date.now() }
      : { ok: false, t: Date.now(), reason: String((r && (r.reason || r.detail)) || (r && r.skipped ? "skipped" : "unknown")).slice(0, 300) };
    await env.CMS_KV.put(listKey, JSON.stringify(arr));
  } catch (e) { /* never break a booking over bookkeeping */ }
  return r;
}

/** Fire and forget, but never fail silently. Use instead of a bare waitUntil. */
function sendEmailTracked(env, ctx, to, subject, text, ics, opts) {
  const task = sendEmail(env, to, subject, text, ics, opts).then(async (r) => {
    if (r && r.ok === false) await noteMailFailure(env, to, subject, r);
    return r;
  }).catch(async (err) => {
    await noteMailFailure(env, to, subject, { reason: err && err.message });
    return { ok: false, reason: err && err.message };
  });
  if (ctx && ctx.waitUntil) ctx.waitUntil(task);
  return task;
}

/* ---------------------------------------------------------------------------
 * Which service actually carries the mail.
 *
 * Two are wired: Resend, which has been carrying it, and Twilio Email
 * (comms.twilio.com), whose sending domain is verified on this account. They
 * are interchangeable for what this site sends, so the choice is a setting
 * rather than a deploy — the owner flips it in the dashboard after sending a
 * test to himself, and flips it straight back if anything looks wrong. A
 * migration you cannot undo in ten seconds is a migration nobody performs.
 *
 * KV wins over the environment on purpose: the secret is the starting default,
 * the dashboard is the live control.
 * ------------------------------------------------------------------------ */

/** Basic-auth pair for Twilio's email API. An API key is preferred over the
 *  account's auth token — it can be revoked on its own — but either works. */
function twilioMailAuth(env) {
  if (env.TWILIO_API_KEY && env.TWILIO_API_SECRET) return { user: env.TWILIO_API_KEY, pass: env.TWILIO_API_SECRET };
  if (env.TWILIO_SID && env.TWILIO_TOKEN) return { user: env.TWILIO_SID, pass: env.TWILIO_TOKEN };
  return null;
}

function twilioMailReady(env) { return !!(twilioMailAuth(env) && validEmail(env.MAIL_FROM)); }
function resendMailReady(env) { return !!(env.RESEND_API_KEY && validEmail(env.MAIL_FROM)); }

/** "twilio" | "resend" | "" (nothing is configured). */
async function mailProvider(env) {
  let stored = "";
  try { stored = (await env.CMS_KV.get("mail_provider")) || ""; } catch (e) { /* KV hiccup falls through to the default */ }
  const want = String(stored || env.MAIL_PROVIDER || "auto").toLowerCase();
  if (want === "twilio" && twilioMailReady(env)) return "twilio";
  if (want === "resend" && resendMailReady(env)) return "resend";
  // "auto", or the named provider is not configured: whichever can actually
  // send. Resend first because it is the one with delivery history here.
  if (resendMailReady(env)) return "resend";
  if (twilioMailReady(env)) return "twilio";
  return "";
}

/**
 * Twilio's Email API reads the body as a Liquid template, so a literal "{{" in
 * a customer's note or a vehicle description would be swallowed as a variable
 * that was never supplied — the text would simply vanish from the email. There
 * is no escape sequence worth relying on, so the braces are separated. A
 * customer who genuinely wrote "{{" sees "{ {", which is a far smaller wrong
 * than a missing paragraph.
 */
const noLiquid = v => String(v == null ? "" : v).replace(/\{\{/g, "{ {").replace(/\}\}/g, "} }");

async function sendViaTwilio(env, msg) {
  const auth = twilioMailAuth(env);
  const content = {
    subject: noLiquid(msg.subject),
    // html is required by the API; text alone is rejected.
    html: noLiquid(msg.html || "<p>" + esc(msg.text || "").replace(/\n/g, "<br>") + "</p>"),
    text: noLiquid(msg.text || ""),
  };
  if (msg.headers) content.headers = msg.headers;
  if (msg.attachments && msg.attachments.length) {
    content.attachments = msg.attachments.map(a => ({
      filename: a.filename,
      contentType: a.contentType || "application/octet-stream",
      content: a.content,
    }));
  }
  const r = await fetch("https://comms.twilio.com/v1/Emails", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: "Basic " + btoa(auth.user + ":" + auth.pass),
    },
    body: JSON.stringify({
      from: { address: env.MAIL_FROM, name: BUSINESS.name },
      to: [{ address: msg.to }],
      content,
    }),
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error" };
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    console.error("[email] Twilio rejected the send", r.status, detail.slice(0, 400));
    const reason = r.status === 401
      ? "Twilio refused the credentials — check TWILIO_SID/TWILIO_TOKEN, or the API key pair."
      : r.status === 400
        ? "Twilio rejected the message — usually the from address is not on a verified sending domain. " + detail.slice(0, 200)
        : "Twilio returned " + r.status + ": " + detail.slice(0, 200);
    return { ok: false, status: r.status, detail, reason };
  }
  // 202 with an operationId: queued, not delivered. Kept so a failure can be
  // traced back to a specific send in the Twilio console.
  const d = await r.json().catch(() => ({}));
  return { ok: true, provider: "twilio", id: d.operationId || "" };
}

async function sendViaResend(env, msg) {
  const body = {
    from: BUSINESS.name + " <" + env.MAIL_FROM + ">",
    to: [msg.to],
    reply_to: env.MAIL_REPLY_TO || env.MAIL_FROM,
    subject: msg.subject,
    text: msg.text,
  };
  if (msg.html) body.html = msg.html;
  if (msg.headers) body.headers = msg.headers;
  if (msg.attachments && msg.attachments.length) {
    body.attachments = msg.attachments.map(a => ({ filename: a.filename, content: a.content }));
  }
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + env.RESEND_API_KEY },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error" };
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    console.error("[email] Resend rejected the send", r.status, detail.slice(0, 400));
    const reason = r.status === 403
      ? "Resend refused the send — usually the sending domain is not verified, or the API key has no send permission."
      : "Resend returned " + r.status + ": " + detail.slice(0, 200);
    return { ok: false, status: r.status, detail, reason };
  }
  return { ok: true, provider: "resend" };
}

async function sendEmail(env, to, subject, text, ics, opts) {
  if (!env.MAIL_FROM || !to) return { skipped: true };
  const provider = await mailProvider(env);
  if (!provider) return { skipped: true };
  const o = opts || {};

  // Check the addresses BEFORE spending a call on them, so the reason reads
  // "OWNER_EMAIL is not an email address" rather than a 422 nobody sees.
  if (!validEmail(to)) {
    console.error("[email] refusing to send: the recipient is not a valid address", JSON.stringify(String(to).slice(0, 80)));
    return { ok: false, reason: "Not a valid email address: " + String(to).slice(0, 80) };
  }
  if (!validEmail(env.MAIL_FROM)) {
    console.error("[email] MAIL_FROM is not a valid address", JSON.stringify(String(env.MAIL_FROM).slice(0, 80)));
    return { ok: false, reason: "MAIL_FROM is not a valid email address" };
  }

  // Never send to an address we already know is dead or hostile. Repeatedly
  // mailing a hard-bouncing address is precisely what got this domain's
  // reputation damaged, and Resend will suppress it at their end anyway — this
  // just stops us burning sends and looking like a careless sender first.
  try {
    const fail = JSON.parse((await env.CMS_KV.get("mailfail:" + String(to).toLowerCase())) || "null");
    if (fail && fail.blocked) {
      console.error("[email] refusing to send to a blocked address", to, fail.lastType);
      return { skipped: true, reason: "address blocked after " + fail.lastType };
    }
  } catch (e) { /* KV hiccup must never stop a real email going out */ }

  const msg = {
    to,
    subject,
    // Always send the plain-text part, even alongside HTML. An HTML-only
    // message is a well-known spam signal, and the text part is what shows in
    // watch/notification previews.
    text,
    html: o.html || "",
    attachments: (o.attachments || []).slice(),
  };
  // One-click unsubscribe. Gmail and Yahoo require this on bulk mail, and it is
  // what stops an annoyed recipient reaching for "report spam" instead — which
  // costs far more reputation than an unsubscribe does.
  if (o.unsubscribeUrl) {
    msg.headers = {
      "List-Unsubscribe": "<" + o.unsubscribeUrl + ">",
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    };
  }
  if (ics) msg.attachments.push({ filename: "booking.ics", contentType: "text/calendar", content: b64utf8(ics) });

  const r = provider === "twilio" ? await sendViaTwilio(env, msg) : await sendViaResend(env, msg);
  if (!r.ok) return r;
  await recordUsage(env, "email");
  return r;
}

// Named exports for the test suite. The Workers runtime only looks at the
// default export, so these cost nothing at runtime but let the tests assert
// that no template variable is left unfilled.
// penceToMajor/majorToPence are exported so the money conversion can be tested
// directly. It is the one piece of arithmetic here that moves real money by a
// factor of a hundred when it is wrong.
export { renderEmail, EMAIL_BLOCKS, esc, SECURITY_HEADERS, penceToMajor, majorToPence, smsSegments, gsmSafe, qrMatrix, qrSvgDataUri };

// ---------- Unsubscribe links ----------
// The link has to work without the recipient logging in, and it must not let
// anyone unsubscribe a stranger by guessing an address — so the address is
// carried in the URL alongside an HMAC of it. No token store, nothing to
// expire, and a tampered address simply fails to verify.
async function unsubSig(env, email) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.SESSION_PEPPER || "cms-unsub"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("unsub:" + email));
  return [...new Uint8Array(mac)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

async function unsubUrl(env, email) {
  const em = String(email || "").trim().toLowerCase();
  if (!em) return "";
  const base = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
  return base + "/api/unsubscribe?e=" + encodeURIComponent(em) + "&s=" + (await unsubSig(env, em));
}

// ---------- HTML email templates ----------
// One shell, several content blocks, and a renderer that substitutes {{{token}}}.
//
// We render these OURSELVES rather than relying on Resend's merge tags. Resend
// only substitutes {{{...}}} for *broadcasts* sent to an audience, where the
// values come from contact fields. Everything this Worker sends is
// transactional (POST /emails), which does no substitution at all — so a
// template pasted in as-is would reach the customer showing the literal text
// "Hi {{{firstname}}}". Doing it here also means the booking reference, reg and
// times come from the order record, which is the only place they actually exist.

const EMAIL_SHELL = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html dir="ltr" lang="en">
  <head>
    <meta content="width=device-width" name="viewport" />
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type" />
    <meta name="x-apple-disable-message-reformatting" />
    <meta content="IE=edge" http-equiv="X-UA-Compatible" />
    <meta content="telephone=no,address=no,email=no,date=no,url=no" name="format-detection" />
    <title>{{{subject}}}</title>
    <style>
      @media (prefers-color-scheme: dark){li::marker{color:#c4c4c4}}
      body, p, h1, h2, h3, h4, h5, h6 { margin: 0; padding: 0; }
      a { color: #ed6b23; text-decoration: none; }
      .details-box { background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 20px; margin-bottom: 25px; }
      .btn { display: inline-block; background-color: #ed6b23; color: #ffffff !important; font-weight: 600; font-size: 16px; padding: 14px 28px; border-radius: 4px; text-decoration: none; }
    </style>
  </head>
  <body dir="ltr" lang="en" style="background-color: #f4f5f7; margin: 0; padding: 0;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;height:0;width:0">{{{preheader}}}</div>
    <table border="0" width="100%" cellpadding="0" cellspacing="0" role="presentation" align="center" style="background-color: #f4f5f7;">
      <tbody>
        <tr>
          <td dir="ltr" lang="en" style="font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica Neue', sans-serif; font-size:16px; min-height:100%; line-height:155%; padding: 40px 20px;">
            <table align="center" width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="max-width:600px; width:100%; background-color: #ffffff; border-radius:8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); overflow: hidden;">
              <tbody>
                <tr>
                  <td style="padding: 30px 20px; text-align: center; border-bottom: 3px solid #ed6b23;">
                    <img src="${BUSINESS.siteUrl}/images/logo.png" alt="${BUSINESS.name}" width="220" style="max-width: 220px; height: auto; display: block; margin: 0 auto;" />
                  </td>
                </tr>
                <tr>
                  <td style="padding: 40px 30px; color: #2a2a2a;">
{{{content}}}
                  </td>
                </tr>
                <tr>
                  <td style="padding: 30px; text-align: center; background-color: #2a2a2a; color: #9ca3af; font-size: 13px; line-height: 1.5;">
                    <strong style="color: #ffffff; font-size: 14px; display: block; margin-bottom: 10px;">${BUSINESS.legalName}</strong>
                    Mobile Mechanic &bull; Tyre Fitting &bull; Recovery<br />
                    Bridport, Dorchester &amp; West Dorset<br /><br />
                    Call: <a href="tel:${BUSINESS.phoneHref}" style="color: #ed6b23;">${BUSINESS.phone}</a> | <a href="tel:${BUSINESS.landlineHref}" style="color: #ed6b23;">${BUSINESS.landline}</a><br /><br />
                    <p style="font-size: 12px; color: #6b7280; margin: 0; padding-top: 15px;">
                      Registered in England &amp; Wales no. ${BUSINESS.companyNumber}<br />
                      ${BUSINESS.registeredOffice}<br /><br />
                      {{{footer_note}}}
                    </p>
                  </td>
                </tr>
              </tbody>
            </table>
          </td>
        </tr>
      </tbody>
    </table>
  </body>
</html>`;

// Content blocks. Every {{{token}}} here must be supplied by the caller —
// renderEmail refuses to send anything with a token left in it.
const EMAIL_BLOCKS = {
  booking_confirmed: `<h1 style="font-size: 24px; font-weight: 700; color: #2a2a2a; margin-bottom: 20px; margin-top: 0;">You're booked in, {{{firstname}}}!</h1>
<p style="color: #4a4a4a; margin-bottom: 20px;">Thanks for choosing ${BUSINESS.name}. Your booking is confirmed. We'll text you on the day with a live tracking link so you can see exactly when we're arriving.</p>
<div class="details-box" style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 20px; margin-bottom: 25px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Reference:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{booking_ref}}}</td>
    </tr>
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Service:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{service}}}</td>
    </tr>
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Vehicle:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{vehicle_reg}}}</td>
    </tr>
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Date &amp; Time:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{booking_date}}} | {{{booking_time}}}</td>
    </tr>
    <tr>
      <td style="font-size: 15px; color: #6b7280; font-weight: bold;">Location:</td>
      <td style="font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{booking_location}}}</td>
    </tr>
  </table>
</div>
<p style="color: #4a4a4a; margin-bottom: 25px;">{{{payment_terms}}}</p>
<div style="text-align: center; margin-bottom: 25px;">
  <a href="{{{manage_booking_url}}}" class="btn" style="display: inline-block; background-color: #ed6b23; color: #ffffff; font-weight: 600; font-size: 16px; padding: 14px 28px; border-radius: 4px; text-decoration: none;">Track &amp; manage booking</a>
</div>
<p style="color: #4a4a4a; margin-bottom: 0; font-size: 14px;">Need to change or cancel? Call <a href="tel:${BUSINESS.phoneHref}" style="color:#ed6b23;">${BUSINESS.phone}</a> or <a href="tel:${BUSINESS.landlineHref}" style="color:#ed6b23;">${BUSINESS.landline}</a>, or just reply to this email.</p>`,

  // Josh's brief pasted the refund markup under both "payment received" and
  // "refund" headings. This is the payment block written properly — a receipt
  // for money taken, not a refund.
  payment_received: `<h1 style="font-size: 24px; font-weight: 700; color: #2a2a2a; margin-bottom: 20px; margin-top: 0;">Payment received — thank you, {{{firstname}}}</h1>
<p style="color: #4a4a4a; margin-bottom: 20px;">We've received your payment. This email is your receipt — keep it for your records.</p>
<div class="details-box" style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 20px; margin-bottom: 25px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Amount paid:</td>
      <td style="padding-bottom: 10px; font-size: 15px; color: #ed6b23; font-weight: 700; text-align: right;">&pound;{{{amount}}}</td>
    </tr>
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Booking:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{booking_ref}}}</td>
    </tr>
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Work carried out:</td>
      <td style="padding-bottom: 10px; font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{service}}}</td>
    </tr>
    <tr>
      <td style="font-size: 15px; color: #6b7280; font-weight: bold;">Vehicle:</td>
      <td style="font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{vehicle_reg}}}</td>
    </tr>
  </table>
</div>
<p style="color: #4a4a4a; margin-bottom: 0;">Any questions about this payment or the work done, reply to this email or call <a href="tel:${BUSINESS.phoneHref}" style="color:#ed6b23;">${BUSINESS.phone}</a>.</p>`,

  refund_processed: `<h1 style="font-size: 24px; font-weight: 700; color: #2a2a2a; margin-bottom: 20px; margin-top: 0;">Refund processed</h1>
<p style="color: #4a4a4a; margin-bottom: 20px;">Hi {{{firstname}}}, we've processed a refund for your recent transaction.</p>
<div class="details-box" style="background-color: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 20px; margin-bottom: 25px;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="width: 100%;">
    <tr>
      <td style="padding-bottom: 10px; font-size: 15px; color: #6b7280; font-weight: bold;">Refund amount:</td>
      <td style="padding-bottom: 10px; font-size: 15px; color: #ed6b23; font-weight: 700; text-align: right;">&pound;{{{amount}}}</td>
    </tr>
    <tr>
      <td style="font-size: 15px; color: #6b7280; font-weight: bold;">Original booking:</td>
      <td style="font-size: 15px; font-weight: 600; text-align: right; color: #2a2a2a;">{{{booking_ref}}}</td>
    </tr>
  </table>
</div>
<p style="color: #4a4a4a; margin-bottom: 0;">The funds go back to your original payment method. Please allow 3-5 working days for it to show on your statement.</p>`,
};

/**
 * Escape a value for insertion into HTML.
 *
 * Every variable in these templates is customer-supplied — name, registration,
 * postcode, service label all come straight off the booking form. Without this
 * a name containing "&" renders wrong and one containing a tag breaks the
 * layout outright.
 */
function esc(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * Render a named block into the shell.
 *
 * Unresolved tokens are treated as a bug, not a cosmetic problem: sending
 * "Hi {{{firstname}}}" to a customer is worse than sending nothing, so this
 * logs loudly and strips them rather than letting them through silently.
 * `raw` holds values that are already trusted HTML (the rendered content and
 * the footer note) — everything else is escaped.
 */
function renderEmail(blockName, vars, raw) {
  const block = EMAIL_BLOCKS[blockName];
  if (!block) throw new Error("Unknown email block: " + blockName);

  const fill = (tpl, values) =>
    tpl.replace(/\{\{\{\s*([a-z_]+)\s*\}\}\}/gi, (m, key) =>
      Object.prototype.hasOwnProperty.call(values, key) ? values[key] : m);

  const escaped = {};
  for (const k of Object.keys(vars || {})) escaped[k] = esc(vars[k]);

  const content = fill(block, escaped);
  const html = fill(EMAIL_SHELL, {
    ...escaped,
    content,                                        // already-rendered markup
    subject: esc((vars && vars.subject) || BUSINESS.name),
    preheader: esc((vars && vars.preheader) || ""),
    footer_note: (raw && raw.footer_note) || "You are receiving this email because you booked a job with us.",
  });

  const leftover = html.match(/\{\{\{\s*[a-z_]+\s*\}\}\}/gi);
  if (leftover) {
    console.error("[email] unresolved template variables in " + blockName + ":", leftover.join(", "));
    return html.replace(/\{\{\{\s*[a-z_]+\s*\}\}\}/gi, "");
  }
  return html;
}

// ---------- Contacts (own database) + Resend Audience (marketing only) ----------
/**
 * Record every person who books, in our own store, under "contact:<email>".
 *
 * Deliberately a SEPARATE key prefix from "user:". A "user:" record is a login
 * account and carries a password salt+hash; writing a passwordless one here
 * would (a) put a credential-shaped record with no credential into the auth
 * path and (b) make /auth/signup answer "Account already exists" to a customer
 * who has never signed up. Contacts are CRM data, not accounts.
 *
 * This is contract/legitimate-interest data — it is created for every booking
 * because we need it to do the job. Marketing consent is tracked separately in
 * `marketing` and is the ONLY thing that gates the Resend audience sync below.
 */
async function upsertContact(env, order) {
  const em = String(order.email || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return { skipped: true, reason: "no usable email" };

  const prev = JSON.parse((await env.CMS_KV.get("contact:" + em)) || "null") || {};
  const now = Date.now();
  const contact = {
    email: em,
    name: (order.name || prev.name || "").trim(),
    phone: (order.phone || prev.phone || "").trim(),
    postcode: order.postcode || prev.postcode || "",
    source: prev.source || "booking",
    firstSeenAt: prev.firstSeenAt || now,
    lastSeenAt: now,
    lastRef: order.ref || prev.lastRef || "",
    // Consent is only ever raised by an explicit tick on the form. It is never
    // inferred from "they booked, so they must want emails" — that is exactly
    // the soft-opt-in overreach the ICO takes issue with.
    marketing: order.marketing === true ? true : !!prev.marketing,
    marketingAt: order.marketing === true ? now : (prev.marketingAt || null),
    privacyVersion: PRIVACY_VERSION,
  };
  await env.CMS_KV.put("contact:" + em, JSON.stringify(contact));
  return { ok: true, contact, newlyConsented: order.marketing === true && !prev.marketing };
}

/**
 * Push a contact into a Resend Audience.
 *
 * Only called when `contact.marketing` is true. An audience is a marketing
 * mailing list, so putting a customer in it without a tick is an unsolicited
 * marketing list under PECR — no amount of "but they were a customer" fixes
 * that once they are in the list. Transactional booking confirmations do not
 * go through here at all; they are sent direct and need no consent.
 */
async function syncResendAudience(env, contact) {
  if (!env.RESEND_API_KEY || !env.RESEND_AUDIENCE_ID) return { skipped: true, reason: "audience not configured" };
  if (!contact || !contact.marketing) return { skipped: true, reason: "no marketing consent" };
  return pushToAudience(env, env.RESEND_AUDIENCE_ID, contact);
}

/**
 * Push a contact into the ALL-CUSTOMERS audience.
 *
 * No consent check, because this is not a marketing list — it is the address
 * book for people we have a contract with, and the lawful basis is that
 * contract. The consent rule lives on what you SEND, not on what you store, so
 * the one thing that must never happen is a marketing broadcast aimed at this
 * audience. Name it something that makes that obvious in the Resend UI.
 */
async function syncCustomerAudience(env, contact) {
  if (!env.RESEND_API_KEY || !env.RESEND_CUSTOMER_AUDIENCE_ID) return { skipped: true, reason: "customer audience not configured" };
  if (!contact || !contact.email) return { skipped: true, reason: "no email" };
  return pushToAudience(env, env.RESEND_CUSTOMER_AUDIENCE_ID, contact);
}

async function pushToAudience(env, audienceId, contact) {
  const parts = String(contact.name || "").trim().split(/\s+/);
  const r = await fetch("https://api.resend.com/audiences/" + audienceId + "/contacts", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + env.RESEND_API_KEY },
    body: JSON.stringify({
      email: contact.email,
      first_name: parts[0] || "",
      last_name: parts.slice(1).join(" "),
      unsubscribed: false,
    }),
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error" };
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    console.error("[audience] Resend rejected the contact", r.status, detail.slice(0, 300));
    return { ok: false, status: r.status, detail };
  }
  return { ok: true };
}

// Fire all booking automations (best-effort, never blocks the response)
async function runAutomations(env, u, o) {
  const jobs = [];
  const when = o.date ? `${o.date} ${o.time || ""}`.trim() : "soon";
  if (u.smsUpdates !== false)
    jobs.push(sendSMS(env, u.phone, `${BUSINESS.shortName}: booking ${o.ref} confirmed for ${when}. We'll message you when the van's on the way.`));
  jobs.push(addCalendarEvent(env, o, u.email));
  jobs.push(sendEmailTracked(env, null, u.email,
    `Booking confirmed — ${o.ref}`,
    `Hi ${u.name},\n\nYour ${o.svcLabel || "mobile job"} is booked for ${when}.\nRef: ${o.ref}\nVehicle: ${o.reg || "-"}\nWhere: ${o.postcode || "-"}\n\nManage or cancel any time in your account. A calendar invite is attached.\n\n${BUSINESS.shortName}`,
    buildICS(o, env.MAIL_FROM)));

  // Tell the business about the new job — this is what the owner actually needs
  // on day one. WhatsApp/SMS to OWNER_PHONE and a copy to the help@ inbox.
  jobs.push(notifyOwner(env, u, o, when));

  await Promise.allSettled(jobs);
  await audit(env, u.email, "booking_automations", o.ref);
}

/**
 * Alert the business owner that a booking has come in.
 *
 * Deliberately separate from the customer's confirmation: the owner wants the
 * customer's phone number and postcode, which we would never put in a message
 * to the customer themselves.
 */
async function notifyOwner(env, u, o, when) {
  const summary =
    `NEW BOOKING ${o.ref}\n` +
    `${o.svcLabel || "Mobile job"}\n` +
    `When: ${when}\n` +
    `Customer: ${u.name || "-"} (${u.phone || "no phone"})\n` +
    `Vehicle: ${o.reg || "-"}\n` +
    `Where: ${o.postcode || "-"}\n` +
    (o.notes ? `Notes: ${o.notes}\n` : "");

  const out = [];
  if (env.OWNER_PHONE) out.push(sendSMS(env, env.OWNER_PHONE, summary));
  if (env.OWNER_EMAIL || env.MAIL_FROM) {
    out.push(sendEmailTracked(env, null, validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM, `New booking ${o.ref} — ${when}`, summary));
  }
  const settled = await Promise.allSettled(out);
  return { notified: settled.length };
}

// ---------- API ----------
async function api(request, env, url, ctx) {
  const p = url.pathname.replace(/^\/api/, "");

  // Public: privacy notice version (frontend uses it to know when to re-ask consent)
  if (p === "/privacy" && request.method === "GET") return json({ version: PRIVACY_VERSION });

  // --- TYRE CATALOGUE (public read-only) ---
  // These power the live pricing cards on the customer site and the wholesale
  // search in the admin portal. They must exist here, not only in server.js,
  // or production quietly serves placeholder prices.
  // Public: labour rates + how payment is taken, shown on the booking form.
  // Never exposes cost prices or any other pricing internals.
  if (p === "/pricing/service" && request.method === "GET") {
    const pr = await getPricing(env);
    const callout = Number(pr.calloutFee) || 0;
    const hourly = Number(pr.hourlyRate) || 0;
    return json({
      calloutFee: callout,
      hourlyRate: hourly,
      configured: callout > 0 || hourly > 0,
      payment: "Payment is taken on site when the work is done — card or cash. Nothing is charged when you book.",
    });
  }

  if (p === "/tyres/sizes" && request.method === "GET") {
    const { sizes } = await tyreData(env);
    return json(sizes);
  }
  if (p === "/tyres/lookup" && request.method === "GET") {
    const { catalogue, costMap } = await tyreData(env);
    const pricing = await getPricing(env);
    let result = lookupBySize(catalogue, costMap, url.searchParams.get("size"), pricing);
    // ?inStock=1 narrows to what the van is actually carrying.
    if (url.searchParams.get("inStock") === "1") {
      const tyres = result.tyres.filter(t => t.inStock);
      result = { ...result, tyres, total: tyres.length };
    }
    // Short cache, and it carries the pricing version so the admin can bust it
    // deliberately. stale-while-revalidate keeps the page fast without letting a
    // stale price sit there once the markup has moved.
    return new Response(JSON.stringify({ ...result, pricingUpdatedAt: pricing.updatedAt || 0 }), {
      headers: {
        ...CORS, ...SECURITY_HEADERS,
        "content-type": "application/json",
        "cache-control": "public, max-age=30, stale-while-revalidate=30",
      },
    });
  }
  if (p === "/tyres/search" && request.method === "GET") {
    const { catalogue, costMap } = await tyreData(env);
    return json(searchCatalogue(catalogue, costMap, url.searchParams.get("q"), 100, await getPricing(env)));
  }
  if (p.startsWith("/tyres/details/") && request.method === "GET") {
    const { catalogue, costMap } = await tyreData(env);
    const tyre = tyreById(catalogue, costMap, p.slice("/tyres/details/".length), await getPricing(env));
    return tyre ? json(tyre) : bad("Tyre not found", 404);
  }

  // Health probe — confirms the catalogue actually loaded in production.
    /*
     * The public site needs the HubSpot portal id to load the tracking script,
     * and the admin needs it to build deep links into the CRM. It is not a
     * secret — it appears in the script tag on every page — but serving it from
     * config rather than hardcoding means it moves with the environment.
     */
  /*
   * What the booking form asks before it offers a time. Public on purpose —
   * it exposes only whether a window is free, never who booked it or why.
   */
  if (p === "/availability" && request.method === "GET") {
    const date = String(url.searchParams.get("date") || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return bad("Give a date as YYYY-MM-DD", 400);
    if (await edgeLimited(env, "RL_LOOKUP", "avail:" + clientIp(request))) {
      return bad("Too many requests — try again shortly.", 429);
    }
    return json(await availabilityFor(env, date));
  }

  /*
   * Is a deposit being asked for, and how much? Public — the booking form has
   * to know before it can say so, and the amount is not a secret.
   */
  if (p === "/deposit-config" && request.method === "GET") {
    const d = await depositSettings(env);
    const live = d.enabled && (await paymentsReady(env));
    return json({ enabled: live, pence: live ? d.pence : 0, label: d.label });
  }

  /*
   * Start a Checkout session for a booking that already exists.
   *
   * The amount comes from OUR settings, never from the request. A price posted
   * by the browser is a price the customer chose.
   */
  if (p === "/pay/checkout" && request.method === "POST") {
    if (await edgeLimited(env, "RL_WRITE", "pay:" + clientIp(request))) return bad("Too many attempts — try again shortly.", 429);
    const b = await request.json().catch(() => ({}));
    const ref = String(b.ref || "").trim();
    if (!ref) return bad("Missing booking reference");
    if (!(await paymentsReady(env))) return bad("Card payment is not switched on.", 503);

    const d = await depositSettings(env);
    if (!d.enabled) return bad("Card payment is not switched on.", 503);

    const email = String(b.email || "").trim().toLowerCase() || (await findBookingOwner(env, ref));
    const key = "bookings:" + (email || "guest");
    const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    const job = arr.find(o => o.ref === ref);
    if (!job) return bad("We cannot find that booking.", 404);
    if (job.paidPence > 0) return bad("That booking is already paid.", 409);

    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";

    if ((await paymentProvider(env)) === "sumup") {
      /*
       * checkout_reference is the booking ref, and it is how the webhook finds
       * the job later. That matters: the webhook is unsigned, so the reference
       * has to come back to us FROM SumUp rather than from whoever posted it.
       */
      const res = await sumupCall(env, "POST", "/checkouts", {
        checkout_reference: ref,
        // Decimal major units. The rest of this system is pence; the
        // conversion lives in penceToMajor and nowhere else.
        amount: Number(penceToMajor(d.pence)),
        currency: "GBP",
        merchant_code: (await sumupAuth(env)).merchant,
        description: d.label + " — " + (job.svcLabel || job.service || "Mobile job") + " (" + ref + ")",
        redirect_url: site + "/#paid=" + encodeURIComponent(ref),
        return_url: site + "/api/sumup-webhook",
        hosted_checkout: { enabled: true },
      });
      if (!res.ok || !res.data || !res.data.hosted_checkout_url) {
        await noteMailFailure(env, job.email || "(no email)", "SumUp checkout " + ref, { ...res, channel: "sumup" });
        return bad("Could not start the payment. Please call " + BUSINESS.phone + ".", 502);
      }
      // Remembered so the return page can confirm without a webhook, and so an
      // unknown checkout id arriving at the webhook can be ignored outright.
      job.sumupCheckout = res.data.id;
      await env.CMS_KV.put(key, JSON.stringify(arr));
      return json({ url: res.data.hosted_checkout_url, id: res.data.id, provider: "sumup" });
    }

    const res = await stripeCall(env, "/checkout/sessions", {
      __idem: "co_" + ref,
      mode: "payment",
      success_url: site + "/#paid=" + encodeURIComponent(ref),
      cancel_url: site + "/#track=" + encodeURIComponent(ref),
      client_reference_id: ref,
      customer_email: job.email || undefined,
      line_items: [{
        quantity: 1,
        price_data: {
          currency: "gbp",
          unit_amount: d.pence,
          product_data: { name: d.label + " — " + (job.svcLabel || job.service || "Mobile job") + " (" + ref + ")" },
        },
      }],
      // Carried back on the webhook so the job can be found without trusting
      // anything the browser says on the way home.
      metadata: { ref, email: job.email || "" },
    });
    if (!res.ok) {
      await noteMailFailure(env, job.email || "(no email)", "Stripe checkout " + ref, { ...res, channel: "stripe" });
      return bad("Could not start the payment. Please call " + BUSINESS.phone + ".", 502);
    }
    return json({ url: res.data.url, id: res.data.id, provider: "stripe" });
  }

  /*
   * SumUp webhook. The entire payload is {event_type, id} — unsigned, and it
   * does not even say whether the checkout was paid. So none of it is trusted:
   * we take the id, ask SumUp what happened, and act only on SumUp's answer.
   *
   * A forged POST therefore achieves nothing except making us ask about a
   * checkout that is not paid. Always answers 200, because a non-2xx makes
   * SumUp retry, and there is nothing to retry when the answer is "that is not
   * one of ours".
   */
  if (p === "/sumup-webhook") {
    if (!(await sumupReady(env))) {
      console.error("[sumup-webhook] rejected: SumUp is not configured");
      return json({ ok: true, ignored: "not configured" });
    }
    const b = await request.json().catch(() => ({}));
    // The return_url lands here as a GET when the customer comes back from the
    // hosted page, so accept the id from either place.
    const checkoutId = String(b.id || url.searchParams.get("checkout_id") || url.searchParams.get("id") || "").trim();
    if (!checkoutId) return json({ ok: true, ignored: "no checkout id" });

    const v = await sumupVerify(env, checkoutId);
    if (!v.ok) return json({ ok: true, ignored: "could not verify", reason: v.reason });
    if (!v.paid) return json({ ok: true, ignored: "status " + (v.status || "unknown") });

    const out = await creditPayment(env, ctx, {
      ref: v.ref,
      pence: v.pence,
      method: "card (SumUp)",
      providerRef: v.id,
      auditEvent: "sumup_payment",
    });
    return json({ ok: true, ...out });
  }

  /*
   * Confirm a payment from the page the customer lands on afterwards.
   *
   * Webhooks are not instant and are not guaranteed. Without this, a customer
   * who has genuinely paid can sit looking at a booking that still says unpaid
   * and ring up about it. Safe to expose: it takes a booking reference,
   * verifies with SumUp, and credits only what SumUp confirms — exactly what
   * the webhook does. Calling it for an unpaid booking changes nothing.
   */
  if (p === "/pay/confirm" && request.method === "GET") {
    if (await edgeLimited(env, "RL_LOOKUP", "payc:" + clientIp(request))) return bad("Too many attempts — try again shortly.", 429);
    const ref = String(url.searchParams.get("ref") || "").trim();
    if (!ref) return bad("Missing booking reference");
    if ((await paymentProvider(env)) !== "sumup") return json({ ok: true, paid: false, reason: "not applicable" });

    const owner = (await findBookingOwner(env, ref)) || "";
    const arr = JSON.parse((await env.CMS_KV.get("bookings:" + (owner || "guest"))) || "[]");
    const job = arr.find(o => o.ref === ref);
    if (!job) return bad("We cannot find that booking.", 404);
    if (Number(job.paidPence) > 0) return json({ ok: true, paid: true, alreadyRecorded: true });
    if (!job.sumupCheckout) return json({ ok: true, paid: false, reason: "no payment was started for this booking" });

    const v = await sumupVerify(env, job.sumupCheckout);
    if (!v.ok) return json({ ok: true, paid: false, reason: "could not reach SumUp" });
    if (!v.paid) return json({ ok: true, paid: false, status: v.status });

    const out = await creditPayment(env, ctx, {
      ref: v.ref || ref,
      pence: v.pence,
      method: "card (SumUp)",
      providerRef: v.id,
      auditEvent: "sumup_payment",
    });
    return json({ ok: true, paid: true, ...out });
  }

  /*
   * The webhook. The ONLY thing that may mark a job paid.
   */
  if (p === "/stripe-webhook" && request.method === "POST") {
    const raw = await request.text();
    if (!env.STRIPE_WEBHOOK_SECRET) {
      console.error("[stripe-webhook] rejected: STRIPE_WEBHOOK_SECRET is not set");
      return bad("Webhook not configured", 503);
    }
    if (!(await stripeSigOk(env, raw, request.headers.get("stripe-signature")))) {
      await noteFailure(env, "ip:" + clientIp(request));
      return bad("Bad signature", 401);
    }
    const evt = JSON.parse(raw || "{}");
    if (evt.type !== "checkout.session.completed") return json({ ok: true, ignored: evt.type });

    const s = evt.data && evt.data.object || {};
    if (s.payment_status !== "paid") return json({ ok: true, ignored: "unpaid session" });
    const ref = s.client_reference_id || (s.metadata && s.metadata.ref);
    const email = String((s.metadata && s.metadata.email) || s.customer_email || "").toLowerCase();
    if (!ref) return json({ ok: true, ignored: "no reference" });

    // Everything from here is shared with the SumUp path, so there is one
    // receipt to keep correct rather than two that drift.
    const out = await creditPayment(env, ctx, {
      ref, email,
      pence: Number(s.amount_total) || 0,
      method: "card (Stripe)",
      providerRef: s.id,
      auditEvent: "stripe_payment",
    });
    return json({ ok: true, ...out });
  }

  if (p === "/crm-config" && request.method === "GET") {
    if (!env.HUBSPOT_PORTAL_ID) return bad("CRM not configured", 404);
    return json({ portalId: String(env.HUBSPOT_PORTAL_ID) });
  }

  if (p === "/health" && request.method === "GET") {
    let tyres = 0, sizes = 0;
    try {
      const d = await tyreData(env);
      sizes = Object.keys(d.catalogue).length;
      for (const list of Object.values(d.catalogue)) tyres += list.length;
    } catch (e) { /* reported as zero below */ }
    return json({
      ok: tyres > 0,
      catalogue: { sizes, tyres },
      kv: !!env.CMS_KV,
      assets: !!env.ASSETS,
      configured: {
        vehicleLookup: !!env.UKVD_API_KEY,
        // "email: true" while every single send came back 422 is exactly how
        // the missing-confirmations outage stayed invisible. A flag that cannot
        // go false is not a health check, so the address shapes are checked
        // here — the one failure mode that costs nothing to detect.
        email: resendMailReady(env) || twilioMailReady(env),
        ownerAlerts: validEmail(env.OWNER_EMAIL || env.MAIL_FROM),
        // NOTE: every flag here means "a value is configured", NOT "it works".
        // UKVD_API_KEY is currently set but rejected upstream with
        // UnknownApiKey, and this endpoint still reported vehicleLookup: true.
        // Use /admin/test-channels for a live check that actually calls out.
        sms: !!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM) || !!env.WHATSAPP_TOKEN,
        // WhatsApp alone cannot start a conversation: Meta rejects free-form
        // text outside 24 hours of the customer messaging first. Without an SMS
        // fallback, business-initiated updates do not reach anybody.
        customerMessaging: !!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM),
        studioFlow: !!(env.TWILIO_STUDIO_FLOW_SID && env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM),
        crm: !!env.HUBSPOT_PORTAL_ID,
        crmSync: !!env.HUBSPOT_TOKEN,
        cardPayments: await paymentsReady(env),
        paymentProvider: await paymentProvider(env),
        calendar: await calendarReady(env),
        adminToken: !!env.ADMIN_TOKEN,
        sessionPepper: !!env.SESSION_PEPPER,
      },
    });
  }

  // --- Resend webhook: bounces and spam complaints ---
  // This is the safety net for exactly what went wrong before: the system sent
  // to a dead address over and over, Resend suppressed it, and the domain's
  // reputation took the hit while nothing in the app knew. Now a bounce is
  // recorded and the address stops being mailed.
  //
  // Resend signs with Svix headers. Verification is REQUIRED — the endpoint is
  // public, so without it anyone could POST a forged "bounce" and get a real
  // customer blocked from receiving their booking confirmation.
  if (p === "/resend-webhook" && request.method === "POST") {
    const raw = await request.text();

    if (!env.RESEND_WEBHOOK_SECRET) {
      console.error("[resend-webhook] rejected: RESEND_WEBHOOK_SECRET is not set");
      return bad("Webhook not configured", 503);
    }

    const id = request.headers.get("svix-id") || "";
    const ts = request.headers.get("svix-timestamp") || "";
    const sigHeader = request.headers.get("svix-signature") || "";
    if (!id || !ts || !sigHeader) return bad("Missing signature headers", 400);

    // Reject anything older than 5 minutes so a captured request cannot be
    // replayed later.
    const age = Math.abs(Date.now() / 1000 - Number(ts));
    if (!Number.isFinite(age) || age > 300) return bad("Stale webhook", 400);

    const secret = env.RESEND_WEBHOOK_SECRET.replace(/^whsec_/, "");
    const keyBytes = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(id + "." + ts + "." + raw));
    const expected = btoa(String.fromCharCode(...new Uint8Array(mac)));
    // The header can carry several space-separated "v1,<sig>" values during a
    // secret rotation; any one matching is a valid signature.
    const ok = sigHeader.split(" ").some(part => safeEqual(part.split(",")[1] || "", expected));
    if (!ok) {
      console.error("[resend-webhook] signature mismatch");
      return bad("Bad signature", 401);
    }

    const evt = JSON.parse(raw || "{}");
    const type = evt.type || "";
    const to = [].concat(evt.data && evt.data.to || []).map(a => String(a).toLowerCase());

    if (/^email\.(bounced|complained)$/.test(type)) {
      for (const em of to) {
        if (!em) continue;
        const rec = JSON.parse((await env.CMS_KV.get("mailfail:" + em)) || "null") || { email: em, count: 0 };
        rec.count += 1;
        rec.lastType = type;
        rec.lastAt = Date.now();
        rec.reason = (evt.data && (evt.data.reason || (evt.data.bounce && evt.data.bounce.message))) || "";
        // A complaint is a one-strike event — they pressed "this is spam".
        // A bounce might be a full mailbox, so allow one retry before blocking.
        rec.blocked = type === "email.complained" || rec.count >= 2;
        await env.CMS_KV.put("mailfail:" + em, JSON.stringify(rec));

        // A spam complaint also withdraws marketing consent, everywhere.
        if (type === "email.complained") {
          for (const k of ["user:" + em, "contact:" + em]) {
            const r2 = await env.CMS_KV.get(k);
            if (!r2) continue;
            const o2 = JSON.parse(r2);
            o2.marketing = false; o2.unsubscribedAt = Date.now();
            await env.CMS_KV.put(k, JSON.stringify(o2));
          }
        }
        await audit(env, em, type.replace("email.", "mail_"), rec.reason.slice(0, 120));
      }

      // Tell the owner, once the address is actually blocked. A booking
      // confirmation silently not arriving is the failure mode that started
      // all of this.
      if (to.length && (env.OWNER_EMAIL || env.MAIL_FROM)) {
        sendEmailTracked(env, ctx, validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM,
          `Email problem — ${to[0]}`,
          `${type === "email.complained" ? "A recipient marked our email as spam" : "An email bounced"}.\n\n`
          + `Address: ${to.join(", ")}\n`
          + `Reason: ${(evt.data && (evt.data.reason || "")) || "not given"}\n\n`
          + `If this is a customer, phone them — they are not getting their confirmations.`);
      }
    }

    return json({ ok: true });
  }

  // --- Unsubscribe (public, no login — it is a link in an email) ---
  // Accepts GET so a click works, and POST so Gmail/Yahoo one-click works.
  if (p === "/unsubscribe" && (request.method === "GET" || request.method === "POST")) {
    const em = String(url.searchParams.get("e") || "").trim().toLowerCase();
    const sig = String(url.searchParams.get("s") || "");
    const page = (title, msg) => new Response(
      `<!doctype html><html lang="en"><head><meta charset="utf-8"/>`
      + `<meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="robots" content="noindex"/>`
      + `<title>${title} — ${BUSINESS.name}</title></head>`
      + `<body style="margin:0;background:#f4f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif">`
      + `<div style="max-width:520px;margin:60px auto;background:#fff;border-radius:8px;padding:40px 30px;text-align:center">`
      + `<h1 style="font-size:22px;color:#2a2a2a;margin:0 0 14px">${title}</h1>`
      + `<p style="color:#4a4a4a;line-height:1.55;margin:0 0 24px">${msg}</p>`
      + `<a href="${esc(env.SITE_URL || "https://cousinsmechanicalservices.co.uk")}" `
      + `style="display:inline-block;background:#ed6b23;color:#fff;font-weight:600;padding:12px 24px;border-radius:4px;text-decoration:none">Back to the site</a>`
      + `</div></body></html>`,
      { headers: { "content-type": "text/html; charset=utf-8", "x-robots-tag": "noindex", ...SECURITY_HEADERS } });

    if (!em || !safeEqual(sig, await unsubSig(env, em))) {
      return page("That link didn't work", "This unsubscribe link is invalid or incomplete. Reply to any of our emails and we'll take you off the list by hand.");
    }

    // Clear consent on whichever records exist. Marketing consent lives in two
    // places because a customer may have both a login account and a guest
    // contact record; missing one would leave them still opted in.
    for (const key of ["user:" + em, "contact:" + em]) {
      const raw = await env.CMS_KV.get(key);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      rec.marketing = false;
      rec.unsubscribedAt = Date.now();
      await env.CMS_KV.put(key, JSON.stringify(rec));
    }

    // Mirror it to Resend so a broadcast can't reach them either. Best effort —
    // our own record is the one that governs.
    // Marketing audience only — an unsubscribe is not an erasure request.
    if (env.RESEND_API_KEY && env.RESEND_AUDIENCE_ID) {
      ctx.waitUntil(fetch("https://api.resend.com/audiences/" + env.RESEND_AUDIENCE_ID + "/contacts/" + encodeURIComponent(em), {
        method: "PATCH",
        headers: { "content-type": "application/json", authorization: "Bearer " + env.RESEND_API_KEY },
        body: JSON.stringify({ unsubscribed: true }),
      }).catch(() => null));
    }

    await audit(env, em, "marketing_unsubscribed", "one-click");
    return page("You're unsubscribed",
      "We won't send you any more marketing emails. You'll still get messages about jobs you book with us — those aren't marketing and you need them.");
  }

  // --- AUTH ---
  if (p === "/auth/signup" && request.method === "POST") {
    const signupBody = await request.json().catch(() => ({}));
    const { name, email, phone, password, marketing, smsUpdates, consent } = signupBody;
    const em = (email || "").trim().toLowerCase();
    // 10 per 15 minutes was too tight — a family or a small office shares one
    // address, and every signup now costs a confirmation email, so the burst
    // ceiling that matters is the per-minute edge limiter above.
    if (await edgeLimited(env, "RL_AUTH", "signup:" + clientIp(request))
        || await rateLimited(env, "signup:" + clientIp(request), 30)) {
      return bad("Too many attempts — try again later.", 429);
    }
    await noteFailure(env, "signup:" + clientIp(request));
    if (!(await turnstileOk(env, request, signupBody))) return bad("Please complete the check that proves you are not a robot.", 400);
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || (password || "").length < 6) return bad("Invalid details");
    if (!consent) return bad("Please accept the privacy notice to create an account."); // GDPR: no account without lawful basis
    const existingRaw = await env.CMS_KV.get("user:" + em);
    if (existingRaw) {
      // If the previous attempt was never confirmed, the address is not really
      // taken — somebody may simply have lost the email. Re-send rather than
      // telling them the account exists, which would also be an enumeration
      // oracle. The old record is replaced below.
      const existing = JSON.parse(existingRaw);
      if (isVerified(existing)) return bad("Account already exists", 409);
    }
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await pbkdf2(password, salt, env.SESSION_PEPPER);
    const user = {
      name: name.trim(), email: em, phone: (phone || "").trim(), salt, hash,
      marketing: !!marketing,           // explicit opt-in, default OFF (GDPR)
      smsUpdates: smsUpdates !== false,  // service texts for a job they booked
      consentAt: Date.now(), privacyVersion: PRIVACY_VERSION, createdAt: Date.now(),
    };
    user.emailVerified = false;
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await audit(env, em, "account_created", "consent v" + PRIVACY_VERSION + " (pending verification)");

    // NO session token here. The account is inert until the code is entered.
    const code = await sendVerifyCode(env, ctx, em, user.name);
    return json({ verifyRequired: true, email: em, ...testCode(env, code) });
  }

  // Confirm the code that was emailed at signup.
  if (p === "/auth/verify" && request.method === "POST") {
    const { email, code } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    if (await edgeLimited(env, "RL_AUTH", "verify:" + clientIp(request))) {
      return bad("Too many attempts — try again shortly.", 429);
    }

    const raw = await env.CMS_KV.get("verify:" + em);
    const uraw = await env.CMS_KV.get("user:" + em);
    if (!raw || !uraw) return bad("That code has expired. Ask for a new one.", 400);

    const rec = JSON.parse(raw);
    // Bound the guesses. Six digits is only a million combinations, which is
    // nothing to a script if it can keep trying.
    if (rec.tries >= VERIFY_MAX_TRIES) {
      await env.CMS_KV.delete("verify:" + em);
      return bad("Too many wrong codes. Ask for a new one.", 429);
    }

    const attempt = await pbkdf2(String(code || "").trim(), rec.salt, env.SESSION_PEPPER);
    if (!safeEqual(attempt, rec.hash)) {
      rec.tries += 1;
      await env.CMS_KV.put("verify:" + em, JSON.stringify(rec), { expirationTtl: VERIFY_TTL_SEC });
      return bad("That code is not right. " + (VERIFY_MAX_TRIES - rec.tries) + " attempts left.", 400);
    }

    const user = JSON.parse(uraw);
    user.emailVerified = true;
    user.emailVerifiedAt = Date.now();
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await env.CMS_KV.delete("verify:" + em);
    await audit(env, em, "email_verified", "");

    // Signing up used to touch nothing but `user:` — only *bookings* wrote a
    // contact record or reached Resend. So someone who created an account and
    // ticked "keep me posted" never appeared on the mailing list, and never
    // appeared in the contacts database either. Do it here rather than at
    // signup so an unconfirmed address can never reach the audience.
    const signupContact = await upsertContact(env, {
      email: em, name: user.name, phone: user.phone, marketing: user.marketing === true,
    }).catch(() => null);
    if (signupContact && signupContact.contact) {
      signupContact.contact.source = signupContact.contact.source || "account";
      ctx.waitUntil(syncCustomerAudience(env, signupContact.contact).catch(() => null));
      if (user.marketing === true) {
        ctx.waitUntil(syncResendAudience(env, signupContact.contact).catch(() => null));
      }
    }

    const t = token();
    await env.CMS_KV.put("sess:" + t, em, { expirationTtl: 60 * 60 * 24 * 30 });
    return json({ token: t, user: publicUser(user) });
  }

  // Send another code.
  if (p === "/auth/resend-code" && request.method === "POST") {
    const { email } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    if (await edgeLimited(env, "RL_AUTH", "resend:" + clientIp(request))
        || await rateLimited(env, "resend:" + em, 5)) {
      return json({ ok: true }); // never reveal whether the address exists
    }
    await noteFailure(env, "resend:" + em);
    const uraw = await env.CMS_KV.get("user:" + em);
    if (uraw) {
      const u = JSON.parse(uraw);
      if (!isVerified(u)) await sendVerifyCode(env, ctx, em, u.name);
    }
    return json({ ok: true });
  }

  /*
   * "Sign in with Google" for CUSTOMERS. Identity only — openid email profile.
   * Never the calendar, and never Gmail, whatever the old Firebase button did.
   */
  if (p === "/auth/google/start" && request.method === "POST") {
    const rlKey = "cglogin:" + clientIp(request);
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes.", 429);
    }
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
      return bad("Google sign-in is not available.", 400);
    }
    const nonce = crypto.randomUUID();
    await env.CMS_KV.put("gcal_state:" + nonce, JSON.stringify({ kind: "customer", t: Date.now() }), { expirationTtl: 600 });
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    u.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
    u.searchParams.set("redirect_uri", site + "/api/oauth/google/callback");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("scope", "openid email profile");
    u.searchParams.set("prompt", "select_account");
    u.searchParams.set("state", nonce);
    return json({ url: u.toString() });
  }

  if (p === "/auth/google/claim" && request.method === "POST") {
    const rlKey = "cglogin:" + clientIp(request);
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes.", 429);
    }
    const b = await request.json().catch(() => ({}));
    const grant = String(b.grant || "");
    if (!/^[0-9a-f-]{36}$/.test(grant)) return bad("Sign-in expired — try again.", 401);
    const raw = await env.CMS_KV.get("cglogin_grant:" + grant);
    if (!raw) { await noteFailure(env, rlKey); return bad("Sign-in expired — try again.", 401); }
    await env.CMS_KV.delete("cglogin_grant:" + grant);
    const g = JSON.parse(raw);
    const uRaw = await env.CMS_KV.get("user:" + g.email);
    if (!uRaw) return bad("Sign-in expired — try again.", 401);
    return json({ token: g.token, user: publicUser(JSON.parse(uRaw)) });
  }

  if (p === "/auth/login" && request.method === "POST") {
    const loginBody = await request.json().catch(() => ({}));
    const { email, password } = loginBody;
    const em = (email || "").trim().toLowerCase();
    if (!(await turnstileOk(env, request, loginBody))) return bad("Please complete the check that proves you are not a robot.", 400);
    // Brute-force protection: limit by email *and* by source IP, so an attacker
    // cannot spread guesses across many accounts from one machine.
    // Edge limiter first (accurate, per-location), KV second (per-account, so
    // spreading guesses across locations still gets caught).
    if (await edgeLimited(env, "RL_AUTH", "login:" + clientIp(request))
        || await rateLimited(env, em) || await rateLimited(env, "ip:" + clientIp(request))) {
      return bad("Too many attempts — try again in 15 minutes.", 429);
    }
    const raw = await env.CMS_KV.get("user:" + em);
    const user = raw ? JSON.parse(raw) : null;
    // Hash even when the account does not exist, so response time doesn't reveal
    // which emails are registered.
    const hash = await pbkdf2(password || "", user?.salt || newSalt(), env.SESSION_PEPPER);
    if (!user || !safeEqual(hash, user.hash)) {
      await noteFailure(env, em);
      await noteFailure(env, "ip:" + clientIp(request));
      return bad("Email or password not recognised", 401);
    }
    // Correct password, but the address was never confirmed. Checked AFTER the
    // password so this cannot be used to enumerate which addresses are
    // registered — a stranger still just sees "not recognised".
    if (!isVerified(user)) {
      const code = await sendVerifyCode(env, ctx, em, user.name);
      return json({ verifyRequired: true, email: em, ...testCode(env, code),
        error: "Please confirm your email address. We have sent you a new code." }, 403);
    }

    await clearFailures(env, em);
    await clearFailures(env, "ip:" + clientIp(request));
    const t = token();
    await env.CMS_KV.put("sess:" + t, em, { expirationTtl: 60 * 60 * 24 * 30 });
    await audit(env, em, "login", "");
    return json({ token: t, user: publicUser(user) });
  }

  // --- Password reset ---
  if (p === "/auth/forgot" && request.method === "POST") {
    const { email } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    // Every call here sends a real email. Unlimited, it is a free outbound
    // amplifier pointed at anyone's inbox from our domain — the exact
    // reputation damage the bounce handling exists to prevent.
    if (await edgeLimited(env, "RL_AUTH", "forgot:" + clientIp(request))
        || await rateLimited(env, "ip:" + clientIp(request))) return json({ ok: true });
    await noteFailure(env, "ip:" + clientIp(request));
    const raw = await env.CMS_KV.get("user:" + em);
    if (raw) {
      const rt = token();
      await env.CMS_KV.put("reset:" + rt, em, { expirationTtl: RESET_TOKEN_TTL_SEC });
      const link = (env.SITE_URL || "") + "/#reset=" + rt;
      sendEmailTracked(env, ctx, em, "Reset your " + BUSINESS.shortName + " password",
        `Someone asked to reset your password. Use this link within 1 hour:\n${link}\n\nIf that wasn't you, ignore this email.`);
      await audit(env, em, "password_reset_requested", "");
    }
    return json({ ok: true }); // always ok — never reveal whether an email exists
  }
  if (p === "/auth/reset" && request.method === "POST") {
    const { resetToken, password } = await request.json().catch(() => ({}));
    if ((password || "").length < 6) return bad("Password must be at least 6 characters.");
    const em = await env.CMS_KV.get("reset:" + resetToken);
    if (!em) return bad("This reset link is invalid or has expired.", 400);
    const raw = await env.CMS_KV.get("user:" + em);
    if (!raw) return bad("Account not found", 404);
    const user = JSON.parse(raw);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    user.salt = salt; user.hash = await pbkdf2(password, salt, env.SESSION_PEPPER);
    // Completing a reset means they read a link sent to that inbox, which is
    // exactly what verification proves. Marking it verified here stops a
    // customer who resets first from being stuck in a loop.
    user.emailVerified = true;
    user.emailVerifiedAt = user.emailVerifiedAt || Date.now();
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await env.CMS_KV.delete("reset:" + resetToken);
    await env.CMS_KV.delete("verify:" + em);
    await audit(env, em, "password_reset_completed", "");
    return json({ ok: true });
  }

  if (p === "/auth/me" && request.method === "GET") {
    const u = await sessionUser(request, env);
    return u ? json({ user: publicUser(u) }) : bad("Not signed in", 401);
  }

  if (p === "/auth/logout" && request.method === "POST") {
    const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (t) await env.CMS_KV.delete("sess:" + t);
    return json({ ok: true });
  }

  if (p === "/auth/profile" && request.method === "PATCH") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const b = await request.json().catch(() => ({}));
    if (b.name !== undefined) u.name = String(b.name).trim();
    if (b.phone !== undefined) u.phone = String(b.phone).trim();
    if (b.marketing !== undefined) u.marketing = !!b.marketing;      // consent withdrawable any time
    if (b.smsUpdates !== undefined) u.smsUpdates = !!b.smsUpdates;
    await env.CMS_KV.put("user:" + u.email, JSON.stringify(u));
    await audit(env, u.email, "profile_updated", "marketing=" + u.marketing + " sms=" + u.smsUpdates);

    // Consent is only real if it reaches the list. Ticking the box wrote `true`
    // to KV and stopped there, so the audience never changed either way.
    if (b.marketing !== undefined) {
      const c = await upsertContact(env, {
        email: u.email, name: u.name, phone: u.phone, marketing: u.marketing === true,
      }).catch(() => null);
      if (u.marketing === true) {
        if (c && c.contact) ctx.waitUntil(syncResendAudience(env, c.contact).catch(() => null));
      } else {
        // upsertContact deliberately never *lowers* consent — a booking form
        // with the box unticked must not wipe a tick given elsewhere. A
        // withdrawal is the one case that has to, so clear it here, and do it
        // whether or not Resend is configured: the local record is the record.
        if (c && c.contact) {
          c.contact.marketing = false;
          c.contact.unsubscribedAt = Date.now();
          await env.CMS_KV.put("contact:" + u.email, JSON.stringify(c.contact));
        }
        // Marketing only. They stay in the customer address book — withdrawing
        // consent to marketing is not a request to be forgotten, and we still
        // need to email them about the job they booked.
        if (env.RESEND_API_KEY && env.RESEND_AUDIENCE_ID) {
          ctx.waitUntil(fetch("https://api.resend.com/audiences/" + env.RESEND_AUDIENCE_ID + "/contacts/" + encodeURIComponent(u.email), {
            method: "DELETE", headers: { authorization: "Bearer " + env.RESEND_API_KEY },
          }).catch(() => null));
        }
      }
    }
    return json({ user: publicUser(u) });
  }

  // --- GDPR: data portability (Art. 20) — full export of everything we hold ---
  if (p === "/gdpr/export" && request.method === "GET") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const bookings = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
    const log = JSON.parse((await env.CMS_KV.get("audit:" + u.email)) || "[]");
    await audit(env, u.email, "data_exported", "");
    const { salt, hash, ...rest } = u; // never expose the password material
    return new Response(JSON.stringify({ account: rest, bookings, processingLog: log }, null, 2), {
      status: 200,
      headers: { ...CORS, "content-type": "application/json", "content-disposition": 'attachment; filename="cousins-my-data.json"' },
    });
  }

  // --- GDPR: right to erasure (Art. 17) — delete account + all data + sessions ---
  if (p === "/gdpr/delete" && request.method === "POST") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    // Every key that holds anything about this person. The list used to stop
    // after user/bookings/audit, which left their message history, CRM notes
    // and full contact record queryable by the admin — so a route advertised
    // as erasure under Art. 17 was not erasure.
    for (const k of ["user:", "bookings:", "audit:", "msgs:", "contact:", "crm:", "mailfail:"]) {
      await env.CMS_KV.delete(k + u.email);
    }

    // The inbox index is a single object keyed by email — deleting the thread
    // without this leaves their name sitting in the admin's message list.
    const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
    if (inbox[u.email]) { delete inbox[u.email]; await env.CMS_KV.put("inbox", JSON.stringify(inbox)); }

    // Suppression at Resend, so an erased customer is not later re-added by a
    // stale list. Erasure is total: BOTH audiences, not just the marketing one.
    // Leaving them in the address book would mean a route advertised as Art. 17
    // erasure still had their name and address sitting at a processor.
    if (env.RESEND_API_KEY) {
      for (const aud of [env.RESEND_AUDIENCE_ID, env.RESEND_CUSTOMER_AUDIENCE_ID]) {
        if (!aud) continue;
        ctx.waitUntil(fetch("https://api.resend.com/audiences/" + aud + "/contacts/" + encodeURIComponent(u.email), {
          method: "DELETE", headers: { authorization: "Bearer " + env.RESEND_API_KEY },
        }).catch(() => null));
      }
    }

    const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (t) await env.CMS_KV.delete("sess:" + t);
    return json({ ok: true, erased: true });
  }

  // --- MESSAGING: customer <-> business (stored per customer) ---
  if (p === "/messages") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const key = "msgs:" + u.email;
    const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    if (request.method === "GET") return json({ messages: thread });
    if (request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const text = String(b.text || "").slice(0, 2000).trim();
      if (!text) return bad("Empty message");
      thread.push({ t: Date.now(), from: "customer", text, read: false });
      await env.CMS_KV.put(key, JSON.stringify(thread.slice(-200)));
      // flag that this customer has an unread message for the admin
      const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
      inbox[u.email] = { name: u.name, phone: u.phone, last: text, t: Date.now(), unread: (inbox[u.email]?.unread || 0) + 1 };
      await env.CMS_KV.put("inbox", JSON.stringify(inbox));
      // notify the business by WhatsApp/SMS if configured
      ctx.waitUntil(sendSMS(env, env.OWNER_PHONE || "", `New message from ${u.name} (${u.phone}): ${text}`));
      return json({ messages: thread });
    }
  }

// ---------- Centralized Tyre Inventory Monitoring & Reorder Engine ----------
async function checkAndTriggerReorders(env, opts = {}) {
  try {
    const { triggerSource = "Manual Scan", force = false, specificSku = null, customQty = null } = opts;

    let stock = JSON.parse((await env.CMS_KV.get("stock")) || "null");
    
    // NO DEMO SEED. This used to write five invented tyres into KV whenever
    // stock was empty — including on a plain GET /admin/inventory, so simply
    // opening the Inventory tab on a fresh install fabricated the business's
    // stock. Real consequences, not cosmetic ones:
    //
    //   - A customer booking 225/45 R17 was told, in their own live job
    //     timeline: "Allocated 2x Michelin Primacy 4 ... Remaining stock: 1"
    //     for a tyre Cousins has never owned.
    //   - Every seeded row hardcoded supplierEmail orders@ctyreswholesale.co.uk,
    //     the address that bounces and got this domain suppressed by Resend.
    //   - The dashboard's stock valuation, low-stock alerts and reorder counts
    //     were all computed from the fiction.
    //
    // An empty inventory is the correct state for a business that has not
    // entered its stock yet. The admin adds real items in the Inventory tab.
    if (!Array.isArray(stock)) stock = [];

    // Defaults are deliberately inert. The previous defaults pointed at
    // ctyreswholesale.co.uk (which bounces / delays every message) and copied
    // inventory@ (which has no mailbox, so it bounced and Resend then
    // SUPPRESSED the address). Both were quietly destroying sender reputation,
    // which is a large part of why genuine booking emails were landing in spam.
    // Nothing is emailed to a supplier until a real address is entered in admin.
    const defaultSettings = {
      masterAutoReorder: false,          // off until a real supplier is configured
      defaultMinStock: 3,
      defaultReorderQty: 10,
      supplierEmail: "",                 // no fictional supplier
      supplierApiUrl: "",                // no fictional API
      notifyEmail: env.OWNER_EMAIL || env.MAIL_FROM || "",  // a mailbox that exists
      reorderCooldownHours: 12
    };

    let settings = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "null");
    if (!settings) {
      settings = defaultSettings;
      await env.CMS_KV.put("inventory_settings", JSON.stringify(settings));
    }

    const supplierOrders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");
    const reorderLogs = JSON.parse((await env.CMS_KV.get("reorder_logs")) || "[]");

    const triggeredReorders = [];
    const now = Date.now();
    const cooldownMs = (settings.reorderCooldownHours || 12) * 3600 * 1000;

    for (let i = 0; i < stock.length; i++) {
      const item = stock[i];
      if (specificSku && item.sku !== specificSku && item.id !== specificSku) continue;

      const minThresh = item.minStock !== undefined && item.minStock !== null ? parseInt(item.minStock, 10) : settings.defaultMinStock;
      const isBelowThreshold = item.qty <= minThresh;
      // Opt-in, both levels. `!== false` treated "unset" as ON, which is the
      // wrong default for something that sends real purchase orders.
      const autoEnabled = (item.autoReorder !== false) && (settings.masterAutoReorder === true);
      const isCoolingDown = item.lastReorderedAt && (now - item.lastReorderedAt < cooldownMs);

      // The old second clause was `(force && specificSku)`, which consulted
      // neither autoEnabled nor the cooldown. The admin's "1-Click Reorder"
      // button always passes force+sku, so it fired a live purchase order with
      // the master switch OFF — one click from emailing a supplier that does
      // not exist. force may now skip the cooldown, but never the master switch.
      if (autoEnabled && isBelowThreshold && (!isCoolingDown || force)) {
        const orderQty = customQty ? parseInt(customQty, 10) : (item.reorderQty || settings.defaultReorderQty || 10);
        const poRef = "PO-AUTO-" + now.toString(36).toUpperCase().slice(-5);
        // No fictional fallback. If nobody has configured a supplier, there is
        // nobody to email, and inventing an address just generates bounces.
        const supplierEmail = item.supplierEmail || settings.supplierEmail || "";
        const supplierApiUrl = item.supplierApiUrl || settings.supplierApiUrl || "";

        // Build Email Purchase Order
        const emailSubject = `[PURCHASE ORDER ${poRef}] Tyre Stock Auto-Reorder: ${item.name}`;
        const emailBody = `COUSINS MECHANICAL SERVICES - AUTOMATED TYRE PURCHASE ORDER
====================================================================
PO Reference: ${poRef}
Date / Time: ${new Date().toLocaleString("en-GB", { timeZone: "Europe/London" })}
Trigger Source: ${triggerSource}

REORDER ITEM SPECIFICATION:
--------------------------------------------------------------------
SKU: ${item.sku || item.id}
Description: ${item.name}
Brand & Size: ${item.brand || "Standard"} (${item.size || "Tyre Fitment"})
Current Stock Level: ${item.qty} units
Reorder Threshold Level: ${minThresh} units
REORDER QUANTITY REQUESTED: ${orderQty} units
Unit Wholesale Cost: £${(item.costPrice || 45).toFixed(2)}
Estimated Total PO Cost: £${(orderQty * (item.costPrice || 45)).toFixed(2)}

DELIVERY ADDRESS & INSTRUCTIONS:
--------------------------------------------------------------------
${BUSINESS.legalName}
${BUSINESS.deliveryAddress}
Contact Tel: ${BUSINESS.phone} / ${BUSINESS.landline}
Delivery Schedule: Next Business Day Morning (By 8:30 AM)

Automated reorder dispatched via Centralized Tyre Inventory Management System.`;

        // Dispatch Email Notification
        let emailRes = { skipped: true };
        if (supplierEmail && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(supplierEmail)) {
          emailRes = await sendEmail(env, supplierEmail, emailSubject, emailBody);
          if (settings.notifyEmail && settings.notifyEmail !== supplierEmail) {
            await sendEmail(env, settings.notifyEmail, `[COPY] ${emailSubject}`, emailBody);
          }
        }

        // Dispatch API / Webhook Reorder Request
        let apiRes = { skipped: true, note: "No webhook URL provided" };
        if (supplierApiUrl) {
          try {
            const apiPayload = {
              poRef,
              sku: item.sku || item.id,
              qty: orderQty,
              description: item.name,
              supplierEmail,
              costPrice: item.costPrice || 45,
              deliveryAddress: BUSINESS.deliveryAddress,
              requestedAt: new Date().toISOString()
            };
            const r = await fetch(supplierApiUrl, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(apiPayload)
            }).catch(err => ({ ok: false, statusText: err.message }));

            if (r && r.ok) {
              apiRes = { ok: true, status: r.status || 200, note: "Supplier API acknowledged order" };
            } else {
              // This branch used to return ok:true / "Dispatched (200 OK)".
              // A DNS failure, a refused connection and a 500 all logged as a
              // success, so the reorder log was a fabricated record and the
              // owner believed stock was on its way for a booked appointment.
              apiRes = { ok: false, status: (r && r.status) || 0,
                note: "Supplier API did not accept the order" + ((r && r.statusText) ? ": " + r.statusText : "") };
            }
          } catch (err) {
            apiRes = { ok: false, error: err.message };
          }
        }

        // Add Supplier PO Record
        const poRecord = {
          poRef,
          jobRef: "INVENTORY-REORDER",
          customerName: "Central Inventory Stocking",
          tyreDetails: `${item.name} (${item.sku || 'SKU'})`,
          sku: item.sku || item.id,
          qty: orderQty,
          wholesaleCost: item.costPrice || 45,
          retailPrice: item.price || 65,
          supplier: supplierEmail || "Not configured",
          // Report what actually happened. This was the hardcoded string
          // "Auto-Reordered (Email/API Sent)" regardless of outcome, so the
          // owner saw a confirmed order for tyres nobody had ordered.
          status: emailRes.ok ? "Ordered — supplier emailed"
            : emailRes.skipped ? "NOT ordered — no supplier configured"
            : "NOT ordered — the email failed to send",
          orderedAt: now,
          estDelivery: "Tomorrow 8:00 AM"
        };
        supplierOrders.unshift(poRecord);

        // Record Audit Log
        const logEntry = {
          id: "LOG-" + now.toString(36).toUpperCase(),
          poRef,
          sku: item.sku || item.id,
          itemName: item.name,
          triggerSource,
          currentQty: item.qty,
          minStockThreshold: minThresh,
          reorderQty: orderQty,
          supplierEmail,
          emailStatus: emailRes.ok ? "Sent (Resend API)" : (emailRes.skipped ? "Skipped (No Key)" : "Queued"),
          supplierApiUrl: supplierApiUrl || "N/A",
          apiStatus: apiRes.ok ? (apiRes.note || "Dispatched") : (apiRes.skipped ? "N/A" : "Failed"),
          timestamp: now,
          status: "Active Purchase Order"
        };
        reorderLogs.unshift(logEntry);

        // Update item stock record
        stock[i].lastReorderedAt = now;
        stock[i].lastReorderPoRef = poRef;
        stock[i].status = `Low Stock - Reordered (${poRef})`;

        triggeredReorders.push({
          sku: item.sku,
          name: item.name,
          poRef,
          orderQty,
          supplierEmail,
          emailSent: !!emailRes.ok,
          apiDispatched: !!apiRes.ok
        });
      }
    }

    // Save updated records
    if (triggeredReorders.length > 0 || !await env.CMS_KV.get("stock")) {
      await env.CMS_KV.put("stock", JSON.stringify(stock));
      await env.CMS_KV.put("supplier_orders", JSON.stringify(supplierOrders.slice(0, 250)));
      await env.CMS_KV.put("reorder_logs", JSON.stringify(reorderLogs.slice(0, 250)));
    }

    return {
      totalItems: stock.length,
      triggeredCount: triggeredReorders.length,
      triggeredReorders,
      stock
    };
  } catch (err) {
    console.error("checkAndTriggerReorders error:", err);
    return { error: err.message, triggeredCount: 0 };
  }
}

// ---------- Stock & Auto-Ordering Helper ----------
async function processTyreStockForOrder(env, order) {
  try {
    // GUARD FIRST. This check used to sit 40 lines below, AFTER the stock
    // decrement and after an unconditional return — so it only ever protected
    // the not-in-stock branch. Any booking that happened to match a stock row
    // consumed stock before it was reached.
    const consumesStock = /tyre|tire/i.test(order.svcLabel || order.service || "");
    if (!consumesStock) {
      return { inStock: null, skipped: true, reason: "This service does not consume stock" };
    }

    const rawStock = await env.CMS_KV.get("stock");
    let stock = JSON.parse(rawStock || "[]");
    // Match on the service label ONLY. `order.notes` used to be included, and
    // /service-requests is public — so "michelin primacy tyres please" typed
    // into the notes box by anyone drained real stock anonymously.
    const label = (order.svcLabel || order.service || "").toLowerCase();
    
    // Determine quantity required (e.g. 2 or 4 or default 2 for tyre fitting)
    let qtyNeeded = 2;
    if (label.includes("4x") || label.includes("4 tyres") || label.includes("four")) qtyNeeded = 4;
    if (label.includes("1x") || label.includes("single") || label.includes("one tyre")) qtyNeeded = 1;

    // Try to find matching item in stock by SKU or name
    let matchedIndex = stock.findIndex(item => {
      const name = (item.name || "").toLowerCase();
      const sku = (item.sku || "").toLowerCase();
      return (sku && label.includes(sku)) || (name && label.includes(name.slice(0, 10)));
    });

    if (matchedIndex >= 0 && stock[matchedIndex].qty >= qtyNeeded) {
      stock[matchedIndex].qty -= qtyNeeded;
      await env.CMS_KV.put("stock", JSON.stringify(stock));
      order.stockStatus = "In Stock (Allocated)";
      order.updates = order.updates || [];
      order.updates.push({
        t: Date.now(),
        internal: true,                    // admin timeline only — never the customer's
        s: "Stock Allocated",
        d: `Allocated ${qtyNeeded}x ${stock[matchedIndex].name} from local inventory. Remaining stock: ${stock[matchedIndex].qty}.`
      });

      // Immediately run threshold reorder check
      await checkAndTriggerReorders(env, { triggerSource: `Customer Booking (${order.ref})`, specificSku: stock[matchedIndex].sku });

      return { inStock: true, item: stock[matchedIndex] };
    }

    // Not in stock or insufficient quantity -> Auto-order from supplier.
    // Read settings here: autoPO below needs supplierName, and this used to be
    // declared after it (a TDZ ReferenceError that the try/catch swallowed, so
    // every tyre booking silently skipped stock handling).
    const settings = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "{}");
    const autoOrderOn = settings.masterAutoReorder === true; // opt-in, never assumed
    const poRef = "PO-AUTO-" + Date.now().toString(36).toUpperCase().slice(-5);
    const supplierOrders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");
    
    const autoPO = {
      poRef,
      jobRef: order.ref,
      customerName: order.name || "Customer",
      customerPhone: order.phone || "-",
      tyreDetails: order.svcLabel || order.notes || "Tyre Fitting",
      vehicleReg: order.reg || "-",
      qty: qtyNeeded,
      supplier: settings.supplierName || "Supplier (not yet configured)",
      status: "Ordered (Auto-Generated)",
      orderedAt: Date.now(),
      estDelivery: "Next Business Day (8:00 AM)"
    };
    
    if (autoOrderOn) {
      supplierOrders.unshift(autoPO);
      await env.CMS_KV.put("supplier_orders", JSON.stringify(supplierOrders.slice(0, 200)));

      if (matchedIndex >= 0) {
        // Track what is ON ORDER separately. This used to do `qty += qtyNeeded`,
        // adding goods that had not arrived to the on-hand count: one unit left
        // and two needed became three in stock. It inflated the stock valuation
        // and, because qty then sat above minStock, silently suppressed the
        // reorder that was actually required.
        stock[matchedIndex].onOrder = (Number(stock[matchedIndex].onOrder) || 0) + qtyNeeded;
        stock[matchedIndex].status = "Supplier Delivery Pending";
        await env.CMS_KV.put("stock", JSON.stringify(stock));
      }
      // Deliberately does NOT invent a catalogue item any more. If it is not in
      // the catalogue the shortfall goes on the reorder list below, where a human
      // decides what to actually buy.

      order.stockStatus = `Auto-Ordered (${poRef})`;
      order.updates = order.updates || [];
      order.updates.push({
        t: Date.now(),
        internal: true,                    // admin timeline only — never the customer's
        s: "Supplier Auto-Ordered",
        // Customer-facing. Do not name a supplier here at all: it told customers
        // their tyres were ordered from "C-Tyres Wholesale", a company that does
        // not exist, and it is none of their business who supplies us.
        d: `Not in local stock — we have placed an order for it. We will confirm your fitting time.`,
      });
      return { inStock: false, autoPO };
    }

    // Automation is switched off: record what is needed on the reorder list so
    // the owner can review it and either email the supplier or just work from it.
    const list = JSON.parse((await env.CMS_KV.get("reorder_list")) || "[]");
    list.unshift({
      id: "RL-" + Date.now().toString(36).toUpperCase().slice(-6),
      addedAt: Date.now(),
      status: "pending",
      description: order.svcLabel || order.service || "Tyre",
      sku: matchedIndex >= 0 ? stock[matchedIndex].sku : null,
      qty: qtyNeeded,
      jobRef: order.ref,
      vehicleReg: order.reg || "-",
      customerName: order.name || "-",
      note: matchedIndex >= 0 ? "Below minimum stock" : "Not held in stock",
    });
    await env.CMS_KV.put("reorder_list", JSON.stringify(list.slice(0, 500)));

    order.stockStatus = "Added to reorder list";
    order.updates = order.updates || [];
    order.updates.push({
      t: Date.now(),
      internal: true,                      // admin timeline only — never the customer's
      s: "Added to reorder list",
      d: `${qtyNeeded} x ${order.svcLabel || "tyre"} added to the reorder list for ordering.`,
    });
    return { inStock: false, queued: true };
  } catch (err) {
    console.error("processTyreStockForOrder error:", err);
    return { inStock: false, error: err.message };
  }
}

  // --- Service Requests & Direct Google Calendar Integration ---
  if (p === "/service-requests" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));

    // NO CAPTCHA on the booking form, deliberately.
    //
    // The brief was a CAPTCHA on sign-in. Putting one on the booking form as
    // well means a customer at the roadside with a flat tyre is blocked if the
    // widget fails to load, on the one form where that costs Cousins actual
    // work. The rate limiter above already caps this at 20 per IP per window,
    // which is what stops it being used to send mail in bulk.
    //
    // If booking spam ever becomes real, add a widget to the booking modal
    // FIRST, then re-enable the check here — not the other way round.

    // A booking with no way to contact the customer back is worse than no booking.
    if (!b.name || !b.phone) return bad("Name and mobile number are required.");

    // The slot has to still be free NOW, not when the form was opened. Two
    // people filling in the same window at the same time is exactly how a
    // double-booking happens, and the front-end check cannot catch it.
    if (b.date && b.time && b.time !== ASAP_SLOT && /^\d{4}-\d{2}-\d{2}$/.test(String(b.date))) {
      const av = await availabilityFor(env, String(b.date));
      const slot = av.slots.find(s => s.key === b.time);
      if (slot && !slot.available) {
        return bad("Sorry — " + b.time.toLowerCase() + " on " + b.date + " has just gone. Pick another time, or call " + BUSINESS.phone + " and we will fit you in.", 409);
      }
    }

    // Public endpoint — no login. It must not send email without limit, or it
    // is an open relay for our own domain's reputation.
    if (await edgeLimited(env, "RL_WRITE", "book:" + clientIp(request))
        || await rateLimited(env, "book:" + clientIp(request), 20)) {
      return bad("Too many booking attempts — please call " + BUSINESS.phone + ".", 429);
    }
    await noteFailure(env, "book:" + clientIp(request));

    // WHITELIST. This used to be `{ ...b }` — every field of an anonymous
    // request body spread straight into the stored job. That let anyone POST
    // {"email":"victim@…","payments":[{"kind":"payment","pence":5000000}],
    //  "paidPence":5000000} to write a fake £50,000 payment into someone else's
    // booking list, which /admin/jobs/:ref/payment then trusts when it computes
    // how much may be refunded.
    const str = (v, max) => (v === undefined || v === null) ? undefined : String(v).slice(0, max);
    const num = (v) => { const x = Number(v); return Number.isFinite(x) ? x : undefined; };
    const orderRef = "CMS-" + Date.now().toString(36).toUpperCase().slice(-5);
    const order = {
      name: str(b.name, 100), phone: str(b.phone, 30), email: str(b.email, 200),
      reg: str(b.reg, 15), service: str(b.service, 60), svcLabel: str(b.svcLabel, 200),
      postcode: str(b.postcode, 60), date: str(b.date, 30), time: str(b.time, 40),
      notes: str(b.notes, 2000),
      lat: num(b.lat), lng: num(b.lng),
      calendar: b.calendar !== false,
      marketing: b.marketing === true,
      ref: orderRef,
      status: "confirmed",
      createdAt: Date.now(),
      updates: [{ t: Date.now(), s: "Booking confirmed", d: "We have your job — you will get a message when the van is on the way." }],
    };

    // ---------------------------------------------------------------------
    // PERSIST FIRST. Everything else here (stock allocation, calendar invite,
    // emails, owner alerts) is optional and must never be able to stop a
    // booking being saved. This used to run stock processing and a calendar
    // call BEFORE the KV write, so any failure in either lost the job while
    // still showing the customer a confirmation.
    // ---------------------------------------------------------------------
    const emailKey = order.email ? ("bookings:" + order.email.toLowerCase()) : "bookings:guest";
    const existing = JSON.parse((await env.CMS_KV.get(emailKey)) || "[]");
    if (!existing.some(o => o.ref === order.ref)) existing.unshift(order); // idempotent on retry
    await env.CMS_KV.put(emailKey, JSON.stringify(existing));

    // Hold the slot immediately, before any of the optional work below. A
    // booking that is saved but not counted is a double-booking waiting to
    // happen on the next request.
    await bumpSlot(env, order.date, order.time, +1).catch(() => null);

    // From here on, nothing may throw out of the handler.
    const warnings = [];
    const safe = async (label, fn) => {
      try { return await fn(); }
      catch (err) { console.error("[booking:" + label + "]", orderRef, err && err.stack ? err.stack : err); warnings.push(label); return null; }
    };

    await safe("stock", () => processTyreStockForOrder(env, order));

    // Our own contact record — always. This is how a guest booking (someone who
    // never created an account) shows up in the CRM at all; before this, the
    // customer list was built only from "user:" records, so anyone who booked
    // without signing up was invisible to the admin.
    const contactRes = (await safe("contact", () => upsertContact(env, order))) || {};

    // The address book gets everyone who books, tick or no tick. It is a record
    // of people we are doing work for, not a mailing list.
    if (contactRes.contact) ctx.waitUntil(syncCustomerAudience(env, contactRes.contact).catch(() => null));

    // HubSpot contact. Created on the booking, not on payment, because the
    // point of a CRM record is to have it BEFORE you need to chase someone.
    if (order.email) hubspotSync(env, ctx, "contact " + order.ref, () => hubspotUpsertContact(env, order));

    // Resend audience — only on an explicit marketing tick, and only the first
    // time it goes from off to on, so a repeat customer is not re-POSTed on
    // every job.
    if (contactRes.newlyConsented) {
      await safe("audience", () => syncResendAudience(env, contactRes.contact));
    }

    // Re-persist so any enrichment (stock status, extra updates) is kept. Best
    // effort only — the booking is already safely stored above.
    await safe("persist-enriched", async () => {
      const arr = JSON.parse((await env.CMS_KV.get(emailKey)) || "[]");
      const i = arr.findIndex(o => o.ref === order.ref);
      if (i >= 0) { arr[i] = order; await env.CMS_KV.put(emailKey, JSON.stringify(arr)); }
    });

    const gcalResult = (await safe("calendar", () => addCalendarEvent(env, order, order.email))) || { skipped: true };

    const when = (order.date || "as soon as possible") + " " + (order.time || "");
    const lines = [
      "Ref: " + order.ref,
      "Service: " + (order.svcLabel || order.service || "Mobile job"),
      "Vehicle: " + (order.reg || "-"),
      "When: " + when,
      "Location: " + (order.postcode || "-"),
      "Name: " + order.name,
      "Phone: " + order.phone,
      order.email ? "Email: " + order.email : null,
      order.notes ? "Notes: " + order.notes : null,
    ].filter(Boolean).join("\n");

    // Customer confirmation (only possible if they gave us an address).
    if (order.email) {
      await safe("customer-email", async () => {
        const ics = buildICS(order, env.MAIL_FROM);
        const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
        const unsub = await unsubUrl(env, order.email);
        // Same price terms the booking form showed, so the email never
        // promises less than the site did. The call-out charge comes from the
        // owner's pricing settings — one number, changed in one place.
        const svcPr = await getPricing(env).catch(() => ({}));
        const calloutSentence = Number(svcPr.calloutFee)
          ? `A £${Number(svcPr.calloutFee)} call-out charge applies. `
          : "";
        const paymentTerms = calloutSentence
          + "Payment is taken on site when the work is done — card or cash. We'll confirm the full price with you before any work starts.";
        const subject = `Booking confirmed — ${order.ref} — ${BUSINESS.shortName}`;
        const html = renderEmail("booking_confirmed", {
          subject,
          // Shown in the inbox list next to the subject. Left blank it gets
          // filled with whatever text comes first, which here is the address.
          preheader: `${order.svcLabel || order.service || "Your job"} · ${order.date || "as soon as possible"} · ref ${order.ref}`,
          firstname: String(order.name || "there").trim().split(/\s+/)[0],
          booking_ref: order.ref,
          service: order.svcLabel || order.service || "Mobile job",
          vehicle_reg: order.reg || "Not given",
          booking_date: order.date || "As soon as possible",
          booking_time: order.time || "We'll confirm a time",
          booking_location: order.postcode || "To be confirmed",
          // Deep link into the tracker on the public site. The homepage reads
          // this hash on load and opens that job.
          manage_booking_url: `${site}/#track=${encodeURIComponent(order.ref)}`,
          payment_terms: paymentTerms,
        }, {
          footer_note: `You are receiving this because you booked job ${esc(order.ref)} with us. This is a service message about that job, not marketing.`
            + (unsub ? `<br /><a href="${unsub}" style="color:#6b7280;text-decoration:underline;">Unsubscribe from marketing emails</a>` : ""),
        });

        ctx.waitUntil(recordJobMail(env, emailKey, order.ref, "customer",
          sendEmailTracked(env, null, order.email, subject,
          `Hi ${order.name},\n\nYour booking is confirmed.\n\n${lines}\n\n`
          + `Track it: ${site}/#track=${order.ref}\n\n`
          + paymentTerms + `\n\n`
          + `Need to change or cancel it? Call ${BUSINESS.landline} or ${BUSINESS.phone}, or reply to this email.\n\n`
          + `${BUSINESS.legalName}\nRegistered in England & Wales no. ${BUSINESS.companyNumber}\n${BUSINESS.registeredOffice}`,
          ics, { html, unsubscribeUrl: unsub })));
      });
    }

    // The customer's own confirmation text. Until now only the OWNER was texted
    // on a website booking — the customer got an email or nothing at all.
    //
    // Studio first, so the wording lives somewhere Josh can edit without a
    // deploy, then the plain Messages API if Studio is unset or errors. A
    // confirmation is too important to depend on one path.
    await safe("customer-sms", async () => {
      const studio = await triggerStudioFlow(env, order.phone, {
        customer_name: String(order.name || "there").trim().split(/\s+/)[0],
        booking_time: when.trim(),
        booking_ref: order.ref,
        service: order.svcLabel || order.service || "Mobile job",
      });
      if (studio && studio.ok) return studio;
      if (studio && !studio.skipped) {
        await noteMailFailure(env, order.phone, "Studio confirmation " + order.ref, { ...studio, channel: "studio" });
      }
      return notifyCustomer(env, ctx, order, null,
        `${BUSINESS.shortName}: booking ${order.ref} confirmed for ${when.trim()}. `
        + `${order.svcLabel || order.service || "Mobile job"}${order.reg ? " · " + order.reg : ""}. `
        + `We'll message you when the van is on the way. Questions? ${BUSINESS.phone}.`,
        "booking confirmation");
    });

    // Owner alert — Josh must hear about a new job even if the customer gave no
    // email and even if he is not looking at the dashboard.
    await safe("owner-alert", async () => {
      // Fall back to MAIL_FROM when OWNER_EMAIL is missing OR malformed. A
      // typo in one secret must not mean nobody at Cousins hears about a job.
      const ownerTo = validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM;
      if (ownerTo) {
        if (!validEmail(env.OWNER_EMAIL) && env.OWNER_EMAIL) {
          await noteMailFailure(env, env.OWNER_EMAIL, "owner alert " + order.ref,
            { reason: "OWNER_EMAIL is not a valid email address — alerts were sent to MAIL_FROM instead. Re-set it with: npx wrangler secret put OWNER_EMAIL" });
        }
        ctx.waitUntil(recordJobMail(env, emailKey, order.ref, "owner",
          sendEmailTracked(env, null, ownerTo,
            `NEW JOB ${order.ref} — ${order.svcLabel || order.service || "Mobile job"} — ${order.reg || ""}`,
            `New booking taken on the website.\n\n${lines}\n\nOpen the dashboard: ${(env.SITE_URL || "")}/admin`)));
      }
      if (env.OWNER_PHONE) {
        ctx.waitUntil(sendSMS(env, env.OWNER_PHONE,
          `NEW JOB ${order.ref}: ${order.svcLabel || order.service || "job"} · ${order.reg || ""} · ${when} · ${order.postcode || ""} · ${order.name} ${order.phone}`));
      }
    });

    return json({
      ok: true,
      ref: order.ref,
      booking: order,
      calendarEventCreated: !!gcalResult.ok,
      calendarDetails: gcalResult,
      warnings,
    });
  }

  if (p === "/calendar/add-event" && request.method === "POST") {
    // Admin only. This was open to the world: anyone could POST arbitrary
    // details and Google would send a real calendar invite FROM the business
    // account to any address they chose — spam sent under the client's identity.
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);
    const b = await request.json().catch(() => ({}));
    const calResult = await addCalendarEvent(env, b, b.customerEmail || b.email);
    // Do not echo the raw Google error body back to the caller; it names the
    // service account and calendar id.
    return json({ ok: calResult.ok || false, eventId: calResult.eventId, skipped: calResult.skipped });
  }

  // --- BOOKINGS (per account) ---
  if (p === "/bookings") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const kvKey = "bookings:" + u.email;
    const list = JSON.parse((await env.CMS_KV.get(kvKey)) || "[]");

    // Same filter as /track: the customer's own booking list shows their job,
    // not the business's stock and supplier movements.
    if (request.method === "GET") {
      return json({ bookings: list.map(o => ({ ...o, updates: customerUpdates(o.updates) })) });
    }

    if (request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      // Whitelisted, same as /service-requests. `{ ...b }` let a signed-in
      // customer set paidPence, payments, status and even choose their own
      // booking reference.
      const str = (v, max) => (v === undefined || v === null) ? undefined : String(v).slice(0, max);
      const num = (v) => { const x = Number(v); return Number.isFinite(x) ? x : undefined; };
      const order = {
        name: str(b.name, 100) || u.name, phone: str(b.phone, 30) || u.phone, email: u.email,
        reg: str(b.reg, 15), service: str(b.service, 60), svcLabel: str(b.svcLabel, 200),
        postcode: str(b.postcode, 60), date: str(b.date, 30), time: str(b.time, 40),
        notes: str(b.notes, 2000), lat: num(b.lat), lng: num(b.lng),
        calendar: b.calendar !== false,
        ref: ref(), status: "confirmed", createdAt: Date.now(),
        updates: [{ t: Date.now(), s: "Booking confirmed", d: "We have your job — you will get a text when the van is on the way." }] };
      
      // Auto-check stock & trigger supplier auto-order if required
      await processTyreStockForOrder(env, order);

      list.unshift(order);
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_created", order.ref);
      // Twilio + Google Calendar + email — after the response, doesn't block the customer
      ctx.waitUntil(runAutomations(env, u, order));
      return json({ booking: order });
    }
  }

  const mRef = p.match(/^\/bookings\/([\w-]+)$/);
  if (mRef) {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const kvKey = "bookings:" + u.email;
    let list = JSON.parse((await env.CMS_KV.get(kvKey)) || "[]");
    const i = list.findIndex(o => o.ref === mRef[1]);
    if (i < 0) return bad("Not found", 404);

    if (request.method === "PATCH") {
      const b = await request.json().catch(() => ({}));
      // Whitelist. This used to spread the whole body over the stored job, so a
      // customer could PATCH {"paidPence":20000,"payments":[...]} and mark their
      // own job paid — which the refund ceiling in /admin/jobs/:ref/payment
      // then trusts, authorising a refund of money never taken.
      const AMENDABLE = ["date", "time", "postcode", "notes", "phone", "reg", "lat", "lng"];
      const patch = {};
      for (const k of AMENDABLE) if (b[k] !== undefined) patch[k] = b[k];
      list[i] = { ...list[i], ...patch, updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking amended", d: "Your booking was updated." }] };
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_amended", list[i].ref);
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `${BUSINESS.shortName}: booking ${list[i].ref} updated to ${list[i].date || ""} ${list[i].time || ""}.`));
      return json({ booking: list[i] });
    }
    if (request.method === "DELETE") {
      list[i] = { ...list[i], status: "cancelled", updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking cancelled", d: "This job was cancelled." }] };
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_cancelled", list[i].ref);
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `${BUSINESS.shortName}: booking ${list[i].ref} cancelled. Re-book any time.`));
      return json({ booking: list[i] });
    }
  }

  // --- Driver/admin: push a live status text (protected by ADMIN_TOKEN secret) ---
  if (p === "/notify" && request.method === "POST") {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);
    const { email, ref: r, message } = await request.json().catch(() => ({}));
    const raw = await env.CMS_KV.get("user:" + (email || "").toLowerCase());
    if (!raw) return bad("Unknown customer", 404);
    const u = JSON.parse(raw);
    if (u.smsUpdates !== false) await sendSMS(env, u.phone, message || `${BUSINESS.shortName}: update on booking ${r}.`);
    await audit(env, u.email, "status_sms", r || "");
    return json({ ok: true });
  }

  // --- LIVE LOCATION: driver posts GPS, customer reads it for their own job ---
  if (p === "/driver/location" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    // safeEqual, not ===. With `===`, an unset ADMIN_TOKEN and an omitted
    // body.token gave `undefined === undefined` → true → an unauthenticated
    // stranger could plant GPS on any job.
    const driverId = body.token ? await env.CMS_KV.get("dsess:" + body.token) : null;
    const okAdmin = (await isAdmin(request, env))
      || (env.ADMIN_TOKEN && safeEqual(body.token || "", env.ADMIN_TOKEN))
      || driverId;
    if (!okAdmin) {
      await noteFailure(env, "ip:" + clientIp(request));
      return bad("Forbidden", 403);
    }
    // A sharing driver posts a fix every few seconds, so this ceiling is high;
    // the point is to stop an unbounded flood, not to throttle normal use.
    if (await rateLimited(env, "loc:" + clientIp(request), 600)) return bad("Too many updates", 429);

    const { ref: r, lat, lng, eta, arrived } = body;
    if (!r || !/^[\w-]{1,32}$/.test(String(r))) return bad("Missing or invalid ref");

    // The ref must name a real booking. Without this, any string became a new
    // KV key — unbounded writes from one endpoint.
    const owner = await findBookingOwner(env, r);
    if (!owner) return bad("Not found", 404);

    // A driver session authenticated the caller but authorised nothing: any
    // approved driver could plant GPS on any job, or flag someone else's
    // customer as "your mechanic is with you". Refs are sequential and easy to
    // guess. First driver to touch a job claims it; after that only they (or an
    // admin) may update it.
    if (driverId && !(await isAdmin(request, env))) {
      const claimKey = "jobdrv:" + r;
      const claimed = await env.CMS_KV.get(claimKey);
      if (claimed && claimed !== driverId) return bad("That job is assigned to another driver.", 403);
      if (!claimed) await env.CMS_KV.put(claimKey, driverId, { expirationTtl: 60 * 60 * 24 * 2 });
    }
    if (arrived) {
      const list = await env.CMS_KV.list({ prefix: "bookings:" });
      for (const k of list.keys) {
        const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
        let changed = false;
        for (const o of arr) if (o.ref === r && o.status !== "arrived") { o.status = "arrived"; o.updates = [...(o.updates || []), { t: Date.now(), s: "Arrived", d: "Your mechanic is with you." }]; changed = true; }
        if (changed) await env.CMS_KV.put(k.name, JSON.stringify(arr));
      }
    } else {
      // Validate. These went straight from the request body into KV and on to
      // the customer's map, where a NaN or an out-of-range value makes
      // Leaflet throw "Invalid LatLng" and kills the tracker.
      // Require a real number. Number(null) and Number("") are both 0, which is
      // a perfectly valid latitude — so a missing coordinate would have quietly
      // placed the van at 0,0 in the Atlantic instead of being rejected.
      const coord = (v, limit, name) => {
        if (v === null || v === undefined || v === "" || typeof v === "boolean") return null;
        const x = Number(v);
        return (Number.isFinite(x) && Math.abs(x) <= limit) ? x : null;
      };
      const la = coord(lat, 90), lo = coord(lng, 180);
      if (la === null) return bad("Invalid latitude");
      if (lo === null) return bad("Invalid longitude");
      const e = Number(eta);
      await env.CMS_KV.put("loc:" + r, JSON.stringify({
        lat: la, lng: lo, eta: Number.isFinite(e) && e >= 0 && e < 1440 ? e : null, t: Date.now(),
      }), { expirationTtl: LOCATION_TTL_SEC });
    }
    return json({ ok: true });
  }
  // Driver page needs the active job list without a 2FA session — gated by the admin token in the body.
  if (p === "/driver/register" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!(await turnstileOk(env, request, b))) return bad("Please complete the check that proves you are not a robot.", 400);
    // The email IS the username. Two separate identifiers was one thing too
    // many to remember and to type at the roadside, and it made the sign-up
    // form look like it was asking for the same thing twice.
    const email = String(b.email || b.username || "").trim().toLowerCase();
    const username = email;
    if (await edgeLimited(env, "RL_AUTH", "drvreg:" + clientIp(request))) {
      return bad("Too many attempts — try again shortly.", 429);
    }
    if (!b.password) return bad("Missing password", 400);
    // A driver account grants access to every active customer's name, address
    // and phone number, so we need a way to prove the person is who they say
    // and a way to reach them.
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad("A valid email address is required", 400);
    if (String(b.password).length < 10) return bad("Password must be at least 10 characters", 400);
    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    if (drivers.find(d => d.username === username)) return bad("Username taken", 400);
    if (drivers.find(d => (d.email || "").toLowerCase() === email)) return bad("That email is already registered", 400);
    // Salted PBKDF2, same scheme as customer accounts. Never store the password itself.
    const salt = newSalt();
    const hash = await pbkdf2(b.password, salt, env.SESSION_PEPPER);
    const id = "DRV-" + token().slice(0, 8).toUpperCase();
    drivers.push({
      id, username, email, salt, hash,
      // vanReg and phone are deliberately NOT taken from the sign-up form —
      // which van somebody drives is Cousins' decision, not the applicant's.
      name: b.name || email.split("@")[0], vanReg: "", phone: "",
      // TWO independent gates. Confirming the email proves the person owns the
      // inbox; approval is Cousins deciding this person may see customer jobs.
      // Neither alone is enough, and the account does nothing until both pass.
      emailVerified: false,
      approved: false,
      status: "Awaiting email confirmation",
      notes: [], assignedJob: "-", createdAt: Date.now(),
    });
    await env.CMS_KV.put("drivers", JSON.stringify(drivers));
    const code = await sendVerifyCode(env, ctx, email, b.name || username, "dverify:");
    await audit(env, email, "driver_registered", username + " (" + email + ") pending");
    return json({ ok: true, pending: true, verifyRequired: true, email, ...testCode(env, code) });
  }

  // Confirm the code emailed at driver registration. This does NOT grant
  // access — it only clears the first of the two gates.
  if (p === "/driver/verify-email" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const email = String(b.email || "").trim().toLowerCase();
    if (await edgeLimited(env, "RL_AUTH", "drvver:" + clientIp(request))) {
      return bad("Too many attempts — try again shortly.", 429);
    }
    const raw = await env.CMS_KV.get("dverify:" + email);
    if (!raw) return bad("That code has expired. Ask for a new one.", 400);
    const rec = JSON.parse(raw);
    if (rec.tries >= VERIFY_MAX_TRIES) {
      await env.CMS_KV.delete("dverify:" + email);
      return bad("Too many wrong codes. Ask for a new one.", 429);
    }
    const attempt = await pbkdf2(String(b.code || "").trim(), rec.salt, env.SESSION_PEPPER);
    if (!safeEqual(attempt, rec.hash)) {
      rec.tries += 1;
      await env.CMS_KV.put("dverify:" + email, JSON.stringify(rec), { expirationTtl: VERIFY_TTL_SEC });
      return bad("That code is not right. " + (VERIFY_MAX_TRIES - rec.tries) + " attempts left.", 400);
    }

    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    const i = drivers.findIndex(d => (d.email || "").toLowerCase() === email);
    if (i < 0) return bad("No account for that address", 404);
    drivers[i].emailVerified = true;
    drivers[i].emailVerifiedAt = Date.now();
    if (!drivers[i].approved) drivers[i].status = "Pending Approval";
    await env.CMS_KV.put("drivers", JSON.stringify(drivers));
    await env.CMS_KV.delete("dverify:" + email);
    await audit(env, email, "driver_email_verified", drivers[i].username);

    // Tell the owner there is somebody waiting, or the driver sits in limbo
    // until he happens to open the Drivers tab.
    const ownerTo = validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM;
    if (ownerTo) {
      sendEmailTracked(env, ctx, ownerTo,
        "Driver awaiting approval — " + drivers[i].name,
        `${drivers[i].name} (${drivers[i].username}) has confirmed their email and is waiting for you to approve them.\n\n`
        + `Email: ${email}\nVan: ${drivers[i].vanReg || "not set"}\n\n`
        + `They cannot see any jobs until you approve them in the Drivers tab of the dashboard.`);
    }
    return json({ ok: true, emailVerified: true, approved: !!drivers[i].approved });
  }

  if (p === "/driver/resend-code" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const email = String(b.email || "").trim().toLowerCase();
    if (await edgeLimited(env, "RL_AUTH", "drvres:" + clientIp(request))
        || await rateLimited(env, "drvres:" + email, 5)) return json({ ok: true });
    await noteFailure(env, "drvres:" + email);
    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    const d = drivers.find(x => (x.email || "").toLowerCase() === email);
    if (d && !d.emailVerified) await sendVerifyCode(env, ctx, email, d.name, "dverify:");
    return json({ ok: true });
  }

  if (p === "/driver/login" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!(await turnstileOk(env, request, b))) return bad("Please complete the check that proves you are not a robot.", 400);
    const username = String(b.username || "").trim().toLowerCase();
    const rlKey = "drv:" + clientIp(request);
    // The most important limiters in the file: these guard the staff password,
    // the owner's break-glass token and 2FA enrolment. The KV counter alone was
    // close to useless because KV reads are edge-cached for up to a minute.
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }

    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    // Accept either the username or the registered email. A driver stood at the
    // roadside should not be locked out because they typed the wrong one of two
    // identifiers they gave us.
    const d = drivers.find(x => x.username === username || (x.email || "").toLowerCase() === username);
    // Always run the KDF, even for an unknown user, so a wrong username and a
    // wrong password take the same time and cannot be told apart.
    const salt = d?.salt || newSalt();
    const attempt = await pbkdf2(b.password || "", salt, env.SESSION_PEPPER);
    if (!d || !d.hash || !safeEqual(attempt, d.hash)) {
      await noteFailure(env, rlKey);
      return bad("Invalid credentials", 401);
    }
    // BOTH gates, checked after the password so neither can be used to work out
    // which usernames exist.
    if (d.emailVerified === false) {
      const code = await sendVerifyCode(env, ctx, d.email, d.name, "dverify:");
      return json({ verifyRequired: true, email: d.email, ...testCode(env, code),
        error: "Confirm your email address first — we have sent you a new code." }, 403);
    }
    if (!d.approved) {
      return json({ pendingApproval: true,
        error: "Your account is waiting for Cousins to approve it. You will not see any jobs until then." }, 403);
    }

    await clearFailures(env, rlKey);
    const token_ = "DRVTOK-" + token();
    await env.CMS_KV.put("dsess:" + token_, d.id, { expirationTtl: 60 * 60 * 12 });
    const { salt: _s, hash: _h, ...safeDriver } = d;
    return json({ token: token_, driver: safeDriver });
  }

  if (p === "/driver/jobs" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    // Was `body.token !== env.ADMIN_TOKEN` with a raw !==. If ADMIN_TOKEN were
    // ever unset, omitting the token satisfied it and this endpoint handed out
    // every active customer's name, postcode and registration to anyone asking.
    // Also unlimited-brute-forceable: no rate limit on a secret comparison.
    if (await rateLimited(env, "ip:" + clientIp(request))) return bad("Too many attempts", 429);
    const isDriver = body.token ? await env.CMS_KV.get("dsess:" + body.token) : null;
    if (!isDriver
        && !(env.ADMIN_TOKEN && safeEqual(body.token || "", env.ADMIN_TOKEN))
        && !(await isAdmin(request, env))) {
      await noteFailure(env, "ip:" + clientIp(request));
      return bad("Forbidden", 403);
    }
    const out = [];
    const list = await env.CMS_KV.list({ prefix: "bookings:" });
    for (const k of list.keys) {
      const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
      for (const o of arr) if (o.status !== "cancelled" && o.status !== "complete")
        // lat/lng included: the customer's exact position was captured at
        // booking but never sent to the driver, so the driver app's ETA had
        // nothing to measure against and returned null on every fix — the
        // "live ETA" the customer is promised never worked at all.
        out.push({ ref: o.ref, svcLabel: o.svcLabel, reg: o.reg, postcode: o.postcode, name: o.name, date: o.date, time: o.time, status: o.status,
          // ?? null, not bare o.lat: JSON.stringify drops undefined values, so
          // the field would silently vanish from the response for any job
          // booked without GPS and the client could not tell "no coordinates"
          // from "field not sent".
          lat: o.lat ?? null, lng: o.lng ?? null });
    }
    return json({ jobs: out });
  }
  const tm = p.match(/^\/track\/([\w-]+)$/);
  if (tm && request.method === "GET") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const arr = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
    const job = arr.find(o => o.ref === tm[1]);
    if (!job) return bad("Not found", 404); // customers can only track their own jobs
    const loc = JSON.parse((await env.CMS_KV.get("loc:" + tm[1])) || "null");
    return json({ status: job.status, updates: customerUpdates(job.updates), location: loc });
  }

  // --- ADMIN LOGIN + 2FA ---
  // Step 1: exchange admin token (+ TOTP code once enrolled) for a short-lived admin session.
  // Public Firebase web config for the "Sign in with Google" button. Firebase
  // web config is client-side by design (not a secret); 404 when unset lets
  // the login screen hide the button entirely.
  // Public site key so the browser can render the widget. 404 when unset, which
  // is how the front end knows not to show one.
  if (p === "/turnstile-config" && request.method === "GET") {
    if (!env.TURNSTILE_SITE_KEY) return bad("Turnstile is not configured", 404);
    return json({ siteKey: env.TURNSTILE_SITE_KEY });
  }

  /*
   * "Connect Google Calendar" — step two. Google sends the person back here
   * after consent. The state nonce proves the flow started from a signed-in
   * owner/developer in the dashboard minutes ago; the code is swapped for a
   * refresh token which lives in KV, never in the browser. On any failure the
   * person lands back on the dashboard with a readable reason instead of a
   * bare error page.
   */
  if (p === "/oauth/google/callback" && request.method === "GET") {
    const back = (msg) => new Response(null, {
      status: 302,
      headers: { ...SECURITY_HEADERS, Location: "/admin?gcal=" + encodeURIComponent(msg) },
    });
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") || "";
    if (!code || !state) return back("cancelled");
    const stRaw = await env.CMS_KV.get("gcal_state:" + state);
    if (!stRaw) return back("expired");
    await env.CMS_KV.delete("gcal_state:" + state);
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return back("not-configured");
    let st = {};
    try { st = JSON.parse(stRaw) || {}; } catch (e) { /* treated as connect below */ }
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const r = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: site + "/api/oauth/google/callback",
      }),
    }).catch(() => null);
    if (!r || !r.ok) {
      const detail = r ? await r.text().catch(() => "") : "network error";
      console.error("[gcal] code exchange failed:", String(detail).slice(0, 300));
      return back("exchange-failed");
    }
    const tok = await r.json().catch(() => ({}));

    /*
     * Same door, two keys. A "login" state means this person pressed "Sign in
     * with Google" on the login screen — identity only, no calendar scope. The
     * id_token is verified BY GOOGLE (tokeninfo checks the signature), the
     * audience must be OUR client id, and the address must already be a live
     * staff account. Google sign-in never creates an account: whoever is not
     * in Staff Logins stays outside, however real their Google account is.
     */
    /*
     * A CUSTOMER signing in to look at their own bookings.
     *
     * The button that used to do this ran a Firebase popup that was never
     * configured, and asked the member of the public for
     * https://mail.google.com/ and full calendar access — their whole inbox,
     * to check when a tyre is being fitted. That is what produced Google's
     * "requesting access to sensitive info" warning, and no sane customer
     * would ever accept it. Identity only now, and verified server-side.
     */
    if (st.kind === "customer") {
      const site2 = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
      const fail = (msg) => new Response(null, {
        status: 302,
        headers: { ...SECURITY_HEADERS, Location: site2 + "/?gauth=" + encodeURIComponent(msg) },
      });
      if (!tok.id_token) return fail("no-identity");
      const vr = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(tok.id_token)).catch(() => null);
      const info = vr && vr.ok ? await vr.json().catch(() => null) : null;
      const email = ((info && info.email) || "").toLowerCase();
      if (!info || info.aud !== env.GOOGLE_CLIENT_ID || String(info.email_verified) !== "true" || !email) {
        return fail("rejected");
      }
      const grant = await grantCustomerSession(env, request, email, info.name || info.given_name || "", "google");
      return new Response(null, {
        status: 302,
        headers: { ...SECURITY_HEADERS, Location: site2 + "/#glogin=" + grant },
      });
    }

    if (st.kind === "login") {
      // Re-checked against the allowlist here too, not trusted from storage.
      const backTo = st.backTo === "/driver" ? "/driver" : "/admin";
      const fail = (msg) => new Response(null, {
        status: 302,
        headers: { ...SECURITY_HEADERS, Location: backTo + "?gauth=" + encodeURIComponent(msg) },
      });
      if (!tok.id_token) return fail("no-identity");
      const vr = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(tok.id_token)).catch(() => null);
      const info = vr && vr.ok ? await vr.json().catch(() => null) : null;
      const email = ((info && info.email) || "").toLowerCase();
      if (!info || info.aud !== env.GOOGLE_CLIENT_ID || String(info.email_verified) !== "true" || !email) {
        await audit(env, email || "unknown", "admin_login_google_rejected", "bad id_token");
        return fail("rejected");
      }
      const grant = await grantStaffSession(env, request, email, backTo, "google");
      if (!grant) return fail("not-staff");
      return new Response(null, {
        status: 302,
        headers: { ...SECURITY_HEADERS, Location: backTo + "#glogin=" + grant },
      });
    }

    if (!tok.refresh_token) return back("no-refresh-token");
    // Ask Google whose diary this is, so the dashboard can say "connected as
    // help@…" instead of leaving everyone to hope it was the right account.
    let email = "";
    try {
      const c = await fetch("https://www.googleapis.com/calendar/v3/calendars/primary", {
        headers: { authorization: "Bearer " + tok.access_token },
      });
      if (c.ok) email = ((await c.json()).id || "");
    } catch (e) { /* cosmetic only */ }
    await env.CMS_KV.put("gcal_oauth", JSON.stringify({
      refresh_token: tok.refresh_token,
      calendar_id: email || "primary",
      email,
      connected_at: Date.now(),
    }));
    let who = "oauth";
    try { who = (JSON.parse(stRaw).actor) || "oauth"; } catch (e) { /* keep default */ }
    await audit(env, who, "gcal-connected", email);
    return back("connected");
  }

  /*
   * Which sign-in buttons the front door should show. Public on purpose: it
   * says only which providers are configured, never anything about a person.
   */
  if (p === "/auth/providers" && request.method === "GET") {
    return json({
      google: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
      apple: appleReady(env),
    });
  }

  /*
   * "Sign in with Apple" — step one. Same shape as the Google routes: a state
   * nonce in KV records which flow this is and where to land afterwards, then
   * the browser goes to Apple's own screen. /auth/apple/start is the customer
   * door; /admin-login-apple/start is the staff one, with the same two-entry
   * return allowlist — an open redirect on a login callback is how you hand
   * somebody's fresh session to another site.
   */
  if ((p === "/auth/apple/start" || p === "/admin-login-apple/start") && request.method === "POST") {
    const staffFlow = p === "/admin-login-apple/start";
    const rlKey = (staffFlow ? "admin:" : "cglogin:") + clientIp(request);
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    if (!appleReady(env)) {
      // Name which one is wrong. "Not configured" when three of four are set
      // is the least useful sentence a setup screen can produce.
      const missing = [];
      if (!/^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$/.test(appleId(env.APPLE_SERVICES_ID))) missing.push("APPLE_SERVICES_ID (the Services ID, e.g. uk.co.example.web)");
      if (!APPLE_TEN.test(appleId(env.APPLE_TEAM_ID))) missing.push("APPLE_TEAM_ID (10 characters)");
      if (!APPLE_TEN.test(appleId(env.APPLE_KEY_ID))) missing.push("APPLE_KEY_ID (10 characters)");
      if (!String(env.APPLE_PRIVATE_KEY || "").includes("PRIVATE KEY")) missing.push("APPLE_PRIVATE_KEY (the whole .p8 file, BEGIN and END lines included)");
      return bad("Apple sign-in is not set up correctly. Check: " + missing.join("; ") + ".", 400);
    }
    const b0 = await request.json().catch(() => ({}));
    const backTo = String(b0.return || "") === "/driver" ? "/driver" : "/admin";
    const nonce = crypto.randomUUID();
    await env.CMS_KV.put("gcal_state:" + nonce, JSON.stringify({
      kind: staffFlow ? "apple-login" : "apple-customer", backTo, t: Date.now(),
    }), { expirationTtl: 600 });
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const u = new URL("https://appleid.apple.com/auth/authorize");
    u.searchParams.set("client_id", appleId(env.APPLE_SERVICES_ID));
    u.searchParams.set("redirect_uri", site + "/api/oauth/apple/callback");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("scope", "name email");
    // Asking for a name or an email obliges Apple to POST the answer back
    // rather than redirect with it — hence the POST callback below.
    u.searchParams.set("response_mode", "form_post");
    u.searchParams.set("state", nonce);
    // Apple is strict about the encoding of the scope separator: it wants %20,
    // and URLSearchParams always writes a space as "+". A "+" here reads to
    // Apple as a scope literally named "name+email", which it rejects.
    u.search = u.searchParams.toString().replace(/(^|&)scope=[^&]*/, "$1scope=name%20email");
    return json({ url: u.toString() });
  }

  /*
   * "Sign in with Apple" — step two. Apple posts a form here. Everything that
   * decides anything comes from the identity token, verified against Apple's
   * published keys; the form is trusted for exactly one thing, the person's
   * name, which is cosmetic and arrives only once in a lifetime.
   */
  if (p === "/oauth/apple/callback" && request.method === "POST") {
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const form = await request.formData().catch(() => null);
    const state = form ? String(form.get("state") || "") : "";
    const code = form ? String(form.get("code") || "") : "";
    const stRaw = /^[0-9a-f-]{36}$/.test(state) ? await env.CMS_KV.get("gcal_state:" + state) : null;
    let st = {};
    try { st = JSON.parse(stRaw || "{}") || {}; } catch (e) { st = {}; }
    const staffFlow = st.kind === "apple-login";
    const backTo = staffFlow ? (st.backTo === "/driver" ? "/driver" : "/admin") : site + "/";
    const fail = (msg) => new Response(null, {
      status: 302,
      headers: { ...SECURITY_HEADERS, Location: backTo + "?gauth=" + encodeURIComponent(msg) },
    });
    if (!stRaw) return fail("expired");
    await env.CMS_KV.delete("gcal_state:" + state);
    if (!staffFlow && st.kind !== "apple-customer") return fail("expired");
    if (!appleReady(env)) return fail("not-configured");
    if (!code) return fail("cancelled");

    const r = await fetch("https://appleid.apple.com/auth/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        client_id: appleId(env.APPLE_SERVICES_ID),
        client_secret: await appleClientSecret(env),
        redirect_uri: site + "/api/oauth/apple/callback",
      }),
    }).catch(() => null);
    if (!r || !r.ok) {
      const detail = r ? await r.text().catch(() => "") : "network error";
      console.error("[apple] code exchange failed:", String(detail).slice(0, 300));
      return fail("exchange-failed");
    }
    const tok = await r.json().catch(() => ({}));
    const claims = await appleVerifyIdToken(env, tok.id_token);
    const email = claims ? String(claims.email || "").toLowerCase() : "";
    if (!claims || !email || String(claims.email_verified) === "false") {
      await audit(env, email || "unknown", "login_apple_rejected", "bad identity token");
      return fail("rejected");
    }

    // Apple hands over the person's name exactly once, on the first
    // authorisation, and never again. Take it now or lose it for good.
    let appleName = "";
    try {
      const u = JSON.parse(String((form && form.get("user")) || "null"));
      if (u && u.name) appleName = [u.name.firstName, u.name.lastName].filter(Boolean).join(" ").trim();
    } catch (e) { /* not the first authorisation — nothing to take */ }

    if (staffFlow) {
      const grant = await grantStaffSession(env, request, email, backTo, "apple");
      // "Hide My Email" gives a per-app relay address, which will never match a
      // staff record. Say so, rather than leaving the owner to guess why his
      // own portal does not know him.
      if (!grant) return fail(email.endsWith("privaterelay.appleid.com") ? "apple-relay" : "not-staff");
      return new Response(null, {
        status: 302,
        headers: { ...SECURITY_HEADERS, Location: backTo + "#glogin=" + grant },
      });
    }
    const grant = await grantCustomerSession(env, request, email, appleName, "apple");
    return new Response(null, {
      status: 302,
      headers: { ...SECURITY_HEADERS, Location: site + "/#glogin=" + grant },
    });
  }

  /*
   * "Connect SumUp" — step two. Same discipline as the Google callback: the
   * state nonce proves a signed-in owner/developer started this minutes ago,
   * the code is exchanged server-side, and the rotating refresh token lives
   * in KV. The merchant code is read from SumUp's own /me answer — never
   * typed, so it can never be somebody else's account by typo.
   */
  if (p === "/oauth/sumup/callback" && request.method === "GET") {
    const back = (msg) => new Response(null, {
      status: 302,
      headers: { ...SECURITY_HEADERS, Location: "/admin?sumup=" + encodeURIComponent(msg) },
    });
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") || "";
    if (!code || !state) return back("cancelled");
    const stRaw = await env.CMS_KV.get("gcal_state:" + state);
    if (!stRaw) return back("expired");
    await env.CMS_KV.delete("gcal_state:" + state);
    let st = {};
    try { st = JSON.parse(stRaw) || {}; } catch (e) { /* fall through */ }
    if (st.kind !== "sumup") return back("expired");
    if (!env.SUMUP_CLIENT_ID || !env.SUMUP_CLIENT_SECRET) return back("not-configured");
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const r = await fetch("https://api.sumup.com/token", {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code", code,
        client_id: env.SUMUP_CLIENT_ID, client_secret: env.SUMUP_CLIENT_SECRET,
        redirect_uri: site + "/api/oauth/sumup/callback",
      }),
    }).catch(() => null);
    if (!r || !r.ok) {
      const detail = r ? await r.text().catch(() => "") : "network error";
      console.error("[sumup] code exchange failed:", String(detail).slice(0, 300));
      return back("exchange-failed");
    }
    const tok = await r.json().catch(() => ({}));
    if (!tok.access_token) return back("exchange-failed");
    if (!tok.refresh_token) return back("no-refresh-token");
    // Whose account is this really? Ask SumUp, then store its answer.
    let merchant = "", email = "";
    try {
      const me = await fetch("https://api.sumup.com/v0.1/me", {
        headers: { authorization: "Bearer " + tok.access_token },
      });
      if (me.ok) {
        const d = await me.json();
        merchant = (d.merchant_profile && d.merchant_profile.merchant_code) || "";
        email = (d.account && d.account.username) || d.personal_profile && d.personal_profile.email || "";
      }
    } catch (e) { /* status shows blank merchant; connect can be retried */ }
    if (!merchant) return back("no-merchant");
    await env.CMS_KV.put("sumup_oauth", JSON.stringify({
      refresh_token: tok.refresh_token,
      access_token: tok.access_token,
      access_expires: Date.now() + (Number(tok.expires_in) || 3599) * 1000,
      merchant_code: merchant,
      email,
      connected_at: Date.now(),
    }));
    let who = "oauth";
    try { who = st.actor || "oauth"; } catch (e) { /* keep default */ }
    await audit(env, who, "sumup-connected", merchant + (email ? " " + email : ""));
    return back("connected");
  }

  /*
   * Firebase sign-in used to live here — /firebase-config handed the browser a
   * web config, and /admin-login-firebase swapped a Firebase ID token for an
   * admin session. Both are gone, and the reason is not tidiness.
   *
   * That endpoint granted a session to any address listed in ADMIN_EMAILS
   * WITHOUT checking the staff table. Every other way in goes through
   * grantStaffSession(), which refuses an address that is not already a staff
   * account — that is the whole of "other staff cannot log in without being
   * approved". A second door that skipped it, waiting on one environment
   * variable being set, is not a door worth keeping for a sign-in method
   * nothing uses: Google identity comes from the same OAuth client as the
   * calendar, and needs no Firebase project at all.
   */


  /*
   * "Sign in with Google" — the version that needs no Firebase project. It
   * reuses the calendar's OAuth client: /start mints a login-flavoured state
   * and sends the browser to Google's own account chooser; the shared
   * /oauth/google/callback (above) verifies the identity and parks a one-shot
   * grant; /claim swaps that grant for the session token. Identity only —
   * scope is openid email, no calendar, nothing offline.
   */
  if (p === "/admin-login-google/start" && request.method === "POST") {
    const rlKey = "admin:" + clientIp(request);
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
      return bad("Google sign-in is not configured — set the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET secrets.", 400);
    }
    // Where to land afterwards. The same sign-in serves the dashboard and the
    // driver portal, and an owner-operator who signs in from the van must come
    // back to the van screen, not be dumped on the office one. An allowlist,
    // not the caller's string: an open redirect on a login callback is how you
    // hand somebody's fresh session to another site.
    const b0 = await request.json().catch(() => ({}));
    const backTo = String(b0.return || "") === "/driver" ? "/driver" : "/admin";
    const nonce = crypto.randomUUID();
    await env.CMS_KV.put("gcal_state:" + nonce, JSON.stringify({ kind: "login", backTo, t: Date.now() }), { expirationTtl: 600 });
    const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
    const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    u.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
    u.searchParams.set("redirect_uri", site + "/api/oauth/google/callback");
    u.searchParams.set("response_type", "code");
    u.searchParams.set("scope", "openid email");
    u.searchParams.set("prompt", "select_account");
    u.searchParams.set("state", nonce);
    return json({ url: u.toString() });
  }

  if (p === "/admin-login-google/claim" && request.method === "POST") {
    const rlKey = "admin:" + clientIp(request);
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    const b = await request.json().catch(() => ({}));
    const grant = String(b.grant || "");
    // UUIDs only: anything else is not something we issued.
    if (!/^[0-9a-f-]{36}$/.test(grant)) return bad("Sign-in expired — try again.", 401);
    const raw = await env.CMS_KV.get("glogin_grant:" + grant);
    if (!raw) { await noteFailure(env, rlKey); return bad("Sign-in expired — try again.", 401); }
    await env.CMS_KV.delete("glogin_grant:" + grant);
    const g = JSON.parse(raw);
    // This used to report the legacy SHARED secret's state, so an owner who had
    // never enrolled was told he had. Per account, like everywhere else.
    const enrolled = await totpEnrolled(env, g.email);
    return json({
      token: g.token, who: g.email, name: g.name || "", enrolled,
      mustEnrol: !enrolled,
      role: g.role || (await actorRole(env, g.email)),
    });
  }

  if (p === "/admin-login" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const rlKey = "admin:" + clientIp(request);
    if (!(await turnstileOk(env, request, b))) return bad("Please complete the check that proves you are not a robot.", 400);
    // The most important limiters in the file: these guard the staff password,
    // the owner's break-glass token and 2FA enrolment. The KV counter alone was
    // close to useless because KV reads are edge-cached for up to a minute.
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    if (!env.ADMIN_TOKEN) return bad("Admin login is not configured — set the ADMIN_TOKEN secret", 503);

    const issue = async (who, extra) => {
      await clearFailures(env, rlKey);
      const t = token();
      await env.CMS_KV.put("asess:" + t, who, { expirationTtl: 60 * 60 * 12 });
      const enrolled = await totpEnrolled(env, who);
      return json({
        token: t, who, enrolled,
        // The session exists but can do nothing until an authenticator is on
        // the account. The dashboard shows the enrolment card and nothing else.
        mustEnrol: who.includes("@") && !enrolled,
        // Which portals to offer. An owner-operator is his own driver, so the
        // same sign-in has to be able to land in the van view.
        role: await actorRole(env, who),
        ...(extra || {}),
      });
    };

    // Break-glass: OVERRIDE_TOKEN always works and can clear a stuck 2FA, so the
    // owner can never be permanently locked out of his own business.
    if (env.OVERRIDE_TOKEN && safeEqual(b.token, env.OVERRIDE_TOKEN)) {
      // Break-glass clears EVERY authenticator, not just the legacy shared one.
      // A locked-out owner with a dead phone is exactly who this is for, and
      // leaving per-account secrets behind would not actually let them back in.
      if (b.reset2fa) {
        await env.CMS_KV.delete("admin_totp");
        const staffKeys = await env.CMS_KV.list({ prefix: "staff:" });
        for (const k of staffKeys.keys) {
          await env.CMS_KV.delete("totp:" + k.name.slice("staff:".length));
        }
      }
      await audit(env, "override-token", "admin_login_override", clientIp(request));
      return issue("admin", { override: true });
    }

    const staffList = await env.CMS_KV.list({ prefix: "staff:" });
    const haveStaff = staffList.keys.length > 0;

    // --- Email + password (the normal path once staff accounts exist) ---
    if (b.email) {
      const em = String(b.email).trim().toLowerCase();
      // Rate-limit the account as well as the IP, so one address cannot be
      // ground down from many machines.
      if (await rateLimited(env, "staffacct:" + em)) return bad("Too many attempts — try again in 15 minutes", 429);
      const raw = await env.CMS_KV.get("staff:" + em);
      const acct = raw ? JSON.parse(raw) : null;
      // Always hash, even for an unknown address, so response time does not
      // reveal which addresses are staff accounts.
      const hash = await pbkdf2(b.password || "", acct?.salt || newSalt(), env.SESSION_PEPPER);
      if (!acct || acct.disabled || !safeEqual(hash, acct.hash)) {
        await noteFailure(env, rlKey);
        await noteFailure(env, "staffacct:" + em);
        await audit(env, em, "admin_login_failed", em + " " + clientIp(request));
        return bad("Email or password not recognised", 401);
      }
      // THIS account's authenticator, not a single shared one. A shared secret
      // would mean the second person to enrol needs the first person's phone.
      const enrolled = await env.CMS_KV.get("totp:" + em);
      if (enrolled && !(await totpValid(enrolled, b.code))) {
        await noteFailure(env, rlKey);
        return bad("Enter the 6-digit code from your authenticator app.", 401);
      }
      await clearFailures(env, "staffacct:" + em);
      await audit(env, em, "admin_login", em + " " + clientIp(request));
      return issue(em, { name: acct.name || "" });
    }

    // --- Bootstrap only: the shared ADMIN_TOKEN ---
    // Accepted ONLY until the first staff account exists. After that this stops
    // working, so the dashboard is behind a real per-person email + password
    // rather than one shared secret that cannot be attributed or revoked.
    if (!safeEqual(b.token, env.ADMIN_TOKEN)) {
      await noteFailure(env, rlKey);
      await audit(env, "admin-token", "admin_login_failed", clientIp(request));
      return bad(haveStaff ? "Enter your staff email and password." : "Invalid admin token", 401);
    }
    if (haveStaff) {
      await noteFailure(env, rlKey);
      return bad("The setup token is disabled now that staff accounts exist. Sign in with your email and password.", 403);
    }
    const enrolled = await env.CMS_KV.get("admin_totp");
    if (enrolled && !(await totpValid(enrolled, b.code))) {
      await noteFailure(env, rlKey);
      return bad("Enter the 6-digit code from your authenticator app.", 401);
    }
    await audit(env, "admin-token", "admin_login_bootstrap", clientIp(request));
    return issue("admin", { mustCreateAccount: true });
  }
  // Log out of the admin dashboard — revokes the session immediately.
  if (p === "/admin-logout" && request.method === "POST") {
    const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (t) await env.CMS_KV.delete("asess:" + t);
    return json({ ok: true });
  }
  // Generate a new secret to enroll an authenticator (must know the admin token).
  if (p === "/admin-2fa/new" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const rlKey = "admin2fa:" + clientIp(request);
    // The most important limiters in the file: these guard the staff password,
    // the owner's break-glass token and 2FA enrolment. The KV counter alone was
    // close to useless because KV reads are edge-cached for up to a minute.
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    /*
     * Who may enrol, and who they enrol FOR.
     *
     * This used to demand the bootstrap ADMIN_TOKEN — the one that stops being
     * accepted for login the moment a staff account exists. So the owner, sat
     * signed in to his own dashboard, could not turn 2FA on at all: he would
     * have had to know a secret nobody had given him. Nobody had enrolled.
     *
     * A signed-in person may now enrol, and the secret belongs to THEIR
     * account. It has to be per-account: one shared secret means the second
     * person to sign in needs the first person's phone, which is not
     * two-factor authentication, it is a shared password with extra steps.
     */
    // adminSession(), not isAdmin(): isAdmin now refuses a staff account that
    // has no authenticator, and refusing them here would leave them holding a
    // session whose only permitted action they are locked out of.
    const sessWho = await adminSession(request, env);
    const signedIn = !!sessWho;
    const who = sessWho || "admin";
    if (!signedIn && !safeEqual(b.token, env.ADMIN_TOKEN)) {
      await noteFailure(env, rlKey);
      return bad("Sign in first, or use the setup token.", 401);
    }
    const key = signedIn && who && who.includes("@") ? "totp:" + who : "admin_totp";
    // Refuse to hand out a new secret once this account has one — otherwise a
    // stolen session could silently re-enrol the attacker's own authenticator.
    if (await env.CMS_KV.get(key)) {
      return bad("Two-factor is already on for this account. Use OVERRIDE_TOKEN with reset2fa to re-enrol.", 409);
    }
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    const label = encodeURIComponent(BUSINESS.shortName + " " + (key === "admin_totp" ? "Admin" : who));
    const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=Cousins%20Mechanical&algorithm=SHA1&digits=6&period=30`;
    // The QR is drawn here rather than in the browser: this is the one screen
    // whose entire job is security, and a script fetched from a CDN to draw it
    // would mean a CDN outage silently removes the QR and leaves a 32-character
    // key to be typed by hand off a phone screen.
    let qr = "";
    try { qr = qrSvgDataUri(otpauth, 220); } catch (e) { console.error("[2fa] qr:", e); }
    return json({ secret, otpauth, qr, alreadyEnrolled: false, account: key === "admin_totp" ? "admin" : who });
  }
  // Confirm the code works, then lock 2FA on. From now, admin login requires the app.
  if (p === "/admin-2fa/enable" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const rlKey = "admin2fa:" + clientIp(request);
    // The most important limiters in the file: these guard the staff password,
    // the owner's break-glass token and 2FA enrolment. The KV counter alone was
    // close to useless because KV reads are edge-cached for up to a minute.
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    const sessWho2 = await adminSession(request, env);
    const signedIn2 = !!sessWho2;
    const who2 = sessWho2 || "admin";
    if (!signedIn2 && !safeEqual(b.token, env.ADMIN_TOKEN)) {
      await noteFailure(env, rlKey);
      return bad("Sign in first, or use the setup token.", 401);
    }
    const key2 = signedIn2 && who2 && who2.includes("@") ? "totp:" + who2 : "admin_totp";
    if (await env.CMS_KV.get(key2)) return bad("Two-factor is already on for this account.", 409);
    if (!b.secret || !(await totpValid(b.secret, b.code))) return bad("That code didn't match — check the app and try again.", 400);
    await env.CMS_KV.put(key2, b.secret);
    await audit(env, key2 === "admin_totp" ? "admin-token" : who2, "admin_2fa_enrolled", key2 === "admin_totp" ? "" : who2);
    return json({ ok: true, account: key2 === "admin_totp" ? "admin" : who2 });
  }
  // Only an admin needs to know whether 2FA is on. Unauthenticated, it told an
  // attacker precisely when a bare ADMIN_TOKEN bearer would still be accepted.
  if (p === "/admin-2fa/status" && request.method === "GET" && !(await adminSession(request, env))) {
    return bad("Forbidden", 403);
  }
  if (p === "/admin-2fa/status" && request.method === "GET") {
    const me = (await adminSession(request, env)) || "admin";
    return json({
      enrolled: await totpEnrolled(env, me),
      account: me,
      // The dashboard blocks itself on this. A staff account that has not
      // enrolled holds a session that can do nothing else.
      mustEnrol: me.includes("@") && !(await totpEnrolled(env, me)),
    });
  }

  // Unauthenticated: lets the login screen show email+password vs first-run
  // setup. Reveals only whether any staff account exists, never who.
  if (p === "/admin-auth/mode" && request.method === "GET") {
    const list = await env.CMS_KV.list({ prefix: "staff:" });
    return json({
      staffConfigured: list.keys.length > 0,
      enrolled: !!(await env.CMS_KV.get("admin_totp")),
      // Two ways Google sign-in can be live: the OAuth client (shared with the
      // calendar — the normal route) or the older Firebase setup.
      google: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
      googleOauth: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
      apple: appleReady(env),
    });
  }

  // --- ADMIN (business owner) — all protected by 2FA-verified session ---
  if (p.startsWith("/admin/")) {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);

    // Who is doing this, and what are they allowed to do. Resolved once here
    // rather than at each call site, because 25 audit entries used to record
    // the literal string "admin" and the fix has to be the path of least
    // resistance or it will not survive the next feature.
    const actor = await whoAmI(env, request);
    const role = await actorRole(env, actor);
    const needs = r => (atLeast(role, r) ? null : bad(
      "Your account does not have permission for this. It needs the " + r + " role; yours is " + role + ".", 403));

    // All jobs across every customer
    if (p === "/admin/jobs" && request.method === "GET") {
      const out = [];
      const list = await env.CMS_KV.list({ prefix: "bookings:" });
      for (const k of list.keys) {
        const email = k.name.slice("bookings:".length);
        const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
        for (const o of arr) out.push({ ...o, customerEmail: email });
      }
      out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json({ jobs: out });
    }

    // Update a job's status (owner moving it through the workflow)
    const jm = p.match(/^\/admin\/jobs\/([\w-]+)$/);
    if (jm && request.method === "PATCH") {
      const b = await request.json().catch(() => ({}));
      const email = (b.customerEmail || "").toLowerCase();
      const key = "bookings:" + email;
      const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
      const i = arr.findIndex(o => o.ref === jm[1]);
      if (i < 0) return bad("Not found", 404);
      // Cancelling frees the window. Without this a cancelled job would go on
      // blocking the slot forever and the day would silently fill up.
      if (b.status && b.status !== arr[i].status) {
        const wasLive = arr[i].status !== "cancelled";
        const nowCancelled = b.status === "cancelled";
        if (wasLive && nowCancelled) await bumpSlot(env, arr[i].date, arr[i].time, -1).catch(() => null);
        if (!wasLive && !nowCancelled) await bumpSlot(env, arr[i].date, arr[i].time, +1).catch(() => null);
      }
      if (b.status) arr[i].status = b.status;
      arr[i].updates = [...(arr[i].updates || []), { t: Date.now(), s: b.label || "Status updated", d: b.note || "" }];
      await env.CMS_KV.put(key, JSON.stringify(arr));
      // Notify the customer. The number comes off the booking, so this works
      // for the guests who make up nearly every job — the old lookup went to
      // "user:" only and silently did nothing for them.
      if (b.sms) {
        const uraw = await env.CMS_KV.get("user:" + email);
        const u = uraw ? JSON.parse(uraw) : null;
        await notifyCustomer(env, ctx, arr[i], u, b.sms, "status update");
      }
      return json({ job: arr[i] });
    }

    // Permanently remove a job.
    //
    // Cancelling sets a status and keeps the record; this erases it. Needed for
    // test bookings and duplicates that would otherwise sit in the dashboard
    // and the customer's own list forever. Everything attached to the job goes
    // with it, or the leftovers keep a deleted job half-alive.
    const jdel = p.match(/^\/admin\/jobs\/([\w-]+)$/);
    if (jdel && request.method === "DELETE") {
      const b = await request.json().catch(() => ({}));
      const ref = jdel[1];
      const email = String(b.customerEmail || "").toLowerCase() || (await findBookingOwner(env, ref));
      if (!email) return bad("Job not found", 404);

      const key = "bookings:" + email;
      const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
      const job = arr.find(o => o.ref === ref);
      if (!job) return bad("Job not found", 404);
      // Deleting a live job hands its window back, same as cancelling one.
      if (job.status !== "cancelled") await bumpSlot(env, job.date, job.time, -1).catch(() => null);

      // Refuse to erase a job that has money against it. Deleting the record
      // would destroy the only trace of a payment or refund, and that is an
      // accounting record, not clutter.
      const paid = (job.payments || []).length;
      if (paid && !b.force) {
        return bad("That job has " + paid + " payment record(s) against it. Deleting it would erase them.", 409);
      }

      await env.CMS_KV.put(key, JSON.stringify(arr.filter(o => o.ref !== ref)));
      await env.CMS_KV.delete("loc:" + ref);
      await env.CMS_KV.delete("jobdrv:" + ref);
      await audit(env, email, "job_deleted", ref + " by " + ((await whoAmI(env, request)) || "admin"));
      return json({ ok: true, ref });
    }

    // Record a payment or a refund against a job, and send the receipt.
    //
    // Money is held in PENCE as an integer. Storing 188.10 as a float and
    // adding it up gives 188.09999999999999 — fine on one job, wrong the moment
    // these totals feed a day's takings or an invoice.
    //
    // This deliberately does NOT take money. It records money already taken on
    // site (card machine or cash) so the customer gets a receipt and the job
    // carries a payment history. Stripe can call the same endpoint later.
    const pm = p.match(/^\/admin\/jobs\/([\w-]+)\/payment$/);
    if (pm && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const email = String(b.customerEmail || "").toLowerCase();
      const key = "bookings:" + email;
      const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
      const i = arr.findIndex(o => o.ref === pm[1]);
      if (i < 0) return bad("Job not found", 404);

      const kind = b.kind === "refund" ? "refund" : "payment";
      const pence = Math.round(Number(b.amount) * 100);
      if (!Number.isFinite(pence) || pence <= 0) return bad("Enter an amount greater than zero.");
      if (pence > 5000000) return bad("That amount looks wrong — over £50,000.");

      const job = arr[i];
      job.payments = Array.isArray(job.payments) ? job.payments : [];

      // Do not refund more than was taken. Without this a slip of the keyboard
      // emails a customer a receipt for a refund larger than they ever paid.
      const takenPence = job.payments.filter(x => x.kind === "payment").reduce((n, x) => n + x.pence, 0);
      const refundedPence = job.payments.filter(x => x.kind === "refund").reduce((n, x) => n + x.pence, 0);
      if (kind === "refund" && pence > takenPence - refundedPence) {
        return bad("You cannot refund more than the £" + ((takenPence - refundedPence) / 100).toFixed(2) + " still held on this job.");
      }

      const entry = {
        t: Date.now(), kind, pence,
        method: String(b.method || "card").slice(0, 20),
        note: String(b.note || "").slice(0, 200),
        by: (await whoAmI(env, request)) || "admin",
      };
      job.payments.push(entry);
      job.paidPence = takenPence + (kind === "payment" ? pence : 0) - refundedPence - (kind === "refund" ? pence : 0);
      job.updates = [...(job.updates || []), {
        t: Date.now(),
        s: kind === "refund" ? "Refund processed" : "Payment received",
        d: "£" + (pence / 100).toFixed(2) + (entry.method ? " by " + entry.method : ""),
      }];
      await env.CMS_KV.put(key, JSON.stringify(arr));
      await audit(env, email, "job_" + kind, job.ref + " £" + (pence / 100).toFixed(2));

      // The deal goes to HubSpot when money is taken, at the value actually
      // taken — a booking is not a sales opportunity that might not land, so
      // there is no pipeline to walk it through. A refund is not a new deal;
      // it belongs against the one already there, which is a reporting job for
      // HubSpot, not something to model with a second record here.
      if (kind === "payment" && env.HUBSPOT_TOKEN) {
        hubspotSync(env, ctx, "deal " + job.ref, async () => {
          const c = await hubspotUpsertContact(env, job);
          return hubspotCreateDeal(env, job, pence, c && c.contactId);
        });
      }

      // Receipt. Best effort — the money is recorded either way, and a failed
      // send must not make Josh think the payment did not save.
      let emailed = { skipped: true, reason: "customer gave no email address" };
      if (email && email !== "guest" && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        try {
          const amount = (pence / 100).toFixed(2);
          const subject = kind === "refund"
            ? `Refund processed — ${job.ref} — ${BUSINESS.shortName}`
            : `Payment received — ${job.ref} — ${BUSINESS.shortName}`;
          const unsub = await unsubUrl(env, email);
          const html = renderEmail(kind === "refund" ? "refund_processed" : "payment_received", {
            subject,
            preheader: (kind === "refund" ? "£" + amount + " is on its way back to you" : "Your receipt for £" + amount),
            firstname: String(job.name || "there").trim().split(/\s+/)[0],
            amount,
            booking_ref: job.ref,
            service: job.svcLabel || job.service || "Mobile job",
            vehicle_reg: job.reg || "Not given",
          }, {
            footer_note: `This relates to job ${esc(job.ref)}. It is a receipt, not marketing.`
              + (unsub ? `<br /><a href="${unsub}" style="color:#6b7280;text-decoration:underline;">Unsubscribe from marketing emails</a>` : ""),
          });
          const text = kind === "refund"
            ? `Hi ${job.name},\n\nWe have processed a refund of £${amount} for job ${job.ref}.\n\n`
              + `It goes back to your original payment method — please allow 3-5 working days.\n\n`
              + `${BUSINESS.legalName}\nRegistered in England & Wales no. ${BUSINESS.companyNumber}`
            : `Hi ${job.name},\n\nThanks — we have received your payment of £${amount}.\n\n`
              + `Job: ${job.ref}\nWork: ${job.svcLabel || job.service || "Mobile job"}\nVehicle: ${job.reg || "-"}\n\n`
              + `Keep this email as your receipt.\n\n`
              + `${BUSINESS.legalName}\nRegistered in England & Wales no. ${BUSINESS.companyNumber}`;
          emailed = await sendEmail(env, email, subject, text, null, { html, unsubscribeUrl: unsub });
        } catch (err) {
          console.error("[payment:receipt]", job.ref, err && err.stack ? err.stack : err);
          emailed = { ok: false, reason: "receipt could not be sent" };
        }
      }

      return json({ job, entry, emailed });
    }

    // --- MESSAGING (admin): list threads, read a thread, reply ---
    if (p === "/admin/threads" && request.method === "GET") {
      const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
      const out = Object.entries(inbox).map(([email, v]) => ({ email, ...v }));
      out.sort((a, b) => (b.t || 0) - (a.t || 0));
      return json({ threads: out });
    }
    const tmA = p.match(/^\/admin\/threads\/(.+)$/);
    if (tmA) {
      const email = decodeURIComponent(tmA[1]).toLowerCase();
      const key = "msgs:" + email;
      if (request.method === "GET") {
        const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]").map(m => ({ ...m, read: true }));
        await env.CMS_KV.put(key, JSON.stringify(thread));
        const inbox = JSON.parse((await env.CMS_KV.get("inbox")) || "{}");
        if (inbox[email]) { inbox[email].unread = 0; await env.CMS_KV.put("inbox", JSON.stringify(inbox)); }
        return json({ messages: thread });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const text = String(b.text || "").slice(0, 2000).trim();
        if (!text) return bad("Empty message");
        const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]");
        thread.push({ t: Date.now(), from: "admin", text, read: true });
        await env.CMS_KV.put(key, JSON.stringify(thread.slice(-200)));
        // Push the reply to the customer's mobile. Falls back to the phone on
        // their most recent booking when they have no account.
        const uraw = await env.CMS_KV.get("user:" + email);
        const u = uraw ? JSON.parse(uraw) : null;
        const bookings = JSON.parse((await env.CMS_KV.get("bookings:" + email)) || "[]");
        await notifyCustomer(env, ctx, bookings[0] || null, u, BUSINESS.shortName + ": " + text, "reply");
        return json({ messages: thread });
      }
    }

    // --- REORDER LIST (used when auto-ordering is switched off) ---
    if (p === "/admin/reorder-list") {
      if (request.method === "GET") {
        const list = JSON.parse((await env.CMS_KV.get("reorder_list")) || "[]");
        return json({ list, pending: list.filter(i => i.status === "pending").length });
      }

      // Add a line by hand, mark lines ordered, or clear what is done.
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const list = JSON.parse((await env.CMS_KV.get("reorder_list")) || "[]");
        // Accept a single `id` as well as an `ids` array. The admin UI acts on
        // one row at a time; without this every button was a silent no-op.
        const ids = b.ids || (b.id ? [b.id] : null);
        const pendingCount = (arr) => arr.filter(i => i.status === "pending").length;

        if (b.action === "add") {
          if (!b.description) return bad("Describe what needs ordering.");
          list.unshift({
            id: "RL-" + Date.now().toString(36).toUpperCase().slice(-6),
            addedAt: Date.now(), status: "pending",
            description: String(b.description).slice(0, 200),
            sku: b.sku || null, qty: Math.max(1, Number(b.qty) || 1),
            jobRef: b.jobRef || null, vehicleReg: b.vehicleReg || "-",
            customerName: b.customerName || "-", note: b.note || "Added by hand",
          });
        } else if (b.action === "mark_ordered") {
          for (const i of list) if (!ids || ids.includes(i.id)) {
            if (i.status === "pending") { i.status = "ordered"; i.orderedAt = Date.now(); }
          }
        } else if (b.action === "remove") {
          const keep = list.filter(i => !(ids || []).includes(i.id));
          await env.CMS_KV.put("reorder_list", JSON.stringify(keep));
          return json({ list: keep, pending: pendingCount(keep) });
        } else if (b.action === "clear_ordered") {
          const keep = list.filter(i => i.status !== "ordered");
          await env.CMS_KV.put("reorder_list", JSON.stringify(keep));
          return json({ list: keep, pending: pendingCount(keep) });
        } else {
          return bad("Unknown action");
        }

        const saved = list.slice(0, 500);
        await env.CMS_KV.put("reorder_list", JSON.stringify(saved));
        // The UI needs the pending count back on every action, not just on GET.
        return json({ list: saved, pending: pendingCount(saved) });
      }
    }

    // Email the pending list to the supplier. Explicit action — nothing is sent
    // to a supplier without someone pressing the button.
    if (p === "/admin/reorder-list/send" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const settings = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "{}");
      const to = (b.to || settings.supplierEmail || "").trim();
      if (!to) return bad("No supplier email set — add one in the automation settings.");
      // Non-empty was the only check, so "tbc" or "none" passed and a
      // syntactically valid but non-existent address sent for real and bounced.
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(to)) return bad("That supplier email is not a valid address.");

      const list = JSON.parse((await env.CMS_KV.get("reorder_list")) || "[]");
      const pending = list.filter(i => i.status === "pending");
      if (!pending.length) return bad("Nothing on the list to order.");

      const body = [
        "Please supply the following:",
        "",
        ...pending.map(i => `  ${i.qty} x ${i.description}${i.sku ? " (" + i.sku + ")" : ""}${i.vehicleReg && i.vehicleReg !== "-" ? "  [veh " + i.vehicleReg + "]" : ""}`),
        "",
        "Delivery to: " + BUSINESS.legalName + ", " + BUSINESS.deliveryAddress,
        "Contact: " + (env.MAIL_FROM || BUSINESS.email) + " / " + BUSINESS.phone,
        "",
        BUSINESS.legalName + " — registered in England & Wales no. " + BUSINESS.companyNumber,
      ].join("\n");

      const sent = await sendEmail(env, to, `Tyre order — ${BUSINESS.shortName} (${pending.length} line${pending.length === 1 ? "" : "s"})`, body);
      if (!sent || sent.ok === false) return bad("Could not send the order email — check the email settings.", 502);

      for (const i of list) if (i.status === "pending") { i.status = "ordered"; i.orderedAt = Date.now(); }
      await env.CMS_KV.put("reorder_list", JSON.stringify(list));
      await audit(env, actor, "reorder_list_emailed", to + " (" + pending.length + " lines)");
      return json({ ok: true, sentTo: to, lines: pending.length, list });
    }

    // --- BACKUP: full export of everything durable in KV ---
    // The one real weakness of KV vs a hosted database is that there is no
    // queryable copy outside Cloudflare. This closes it: one click in admin
    // downloads the whole business state as JSON. Transient keys (sessions,
    // rate-limit counters, reset tokens) are deliberately excluded — restoring
    // them would be wrong, and sessions are secrets.
    /*
     * Recent email failures. Everything else in this system tells you a booking
     * succeeded; nothing told you the confirmation for it never left.
     */
    /* Capacity rules. How many jobs fit in a window is a business decision
     * that changes with the van count, so it lives in KV, not in the code. */
    if (p === "/admin/booking-settings") {
      if (request.method === "GET") return json({ settings: await bookingSettings(env), defaults: DEFAULT_BOOKING_SETTINGS });
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const cur = await bookingSettings(env);
        const numOr = (v, f, lo, hi) => {
          const n = Number(v);
          return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : f;
        };
        const next = {
          slotCapacity: numOr(b.slotCapacity, cur.slotCapacity, 1, 20),
          leadTimeHours: numOr(b.leadTimeHours, cur.leadTimeHours, 0, 168),
          daysAhead: numOr(b.daysAhead, cur.daysAhead, 1, 365),
          closedDays: Array.isArray(b.closedDays)
            ? b.closedDays.map(Number).filter(n => n >= 0 && n <= 6)
            : cur.closedDays,
        };
        await env.CMS_KV.put("booking_settings", JSON.stringify(next));
        await audit(env, actor, "booking_settings_updated", JSON.stringify(next));
        return json({ settings: next });
      }
    }

    /*
     * Rebuild the slot index from the bookings themselves.
     *
     * The index is incremented as jobs come and go, so it can drift — a job
     * edited straight in KV, or a delete that half-failed. This walks the real
     * bookings and rewrites the counts, which is the only honest way to fix a
     * count nobody can see.
     */
    if (p === "/admin/rebuild-slots" && request.method === "POST") {
      const counts = {};
      let cursor;
      do {
        const page = await env.CMS_KV.list({ prefix: "bookings:", cursor });
        for (const k of page.keys) {
          const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
          for (const o of arr) {
            if (!o.date || !o.time || o.time === ASAP_SLOT) continue;
            if (o.status === "cancelled") continue;
            counts[o.date] = counts[o.date] || {};
            counts[o.date][o.time] = (counts[o.date][o.time] || 0) + 1;
          }
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);

      // Clear stale keys first, or a date that emptied keeps its old count.
      let c2;
      do {
        const page = await env.CMS_KV.list({ prefix: "slots:", cursor: c2 });
        for (const k of page.keys) if (!counts[k.name.slice(6)]) await env.CMS_KV.delete(k.name);
        c2 = page.list_complete ? undefined : page.cursor;
      } while (c2);

      for (const [date, byslot] of Object.entries(counts)) {
        await env.CMS_KV.put("slots:" + date, JSON.stringify(byslot));
      }
      await audit(env, actor, "slots_rebuilt", Object.keys(counts).length + " dates");
      return json({ ok: true, dates: Object.keys(counts).length, counts });
    }

    /* Deposit amount and whether to ask for one at all. */
    if (p === "/admin/deposit") {
      if (request.method === "GET") {
        return json({ settings: await depositSettings(env), stripeReady: await paymentsReady(env), provider: await paymentProvider(env), defaults: DEFAULT_DEPOSIT });
      }
      if (request.method === "POST") {
        // Switching deposits on starts charging customers before a job exists.
        const denied = needs("developer");
        if (denied) return denied;
        const b = await request.json().catch(() => ({}));
        const cur = await depositSettings(env);
        const pence = Number.isFinite(Number(b.pence)) ? Math.round(Number(b.pence)) : cur.pence;
        // £1 to £500. A "deposit" of £5,000 is a typo, not a policy.
        if (pence < 100 || pence > 50000) return bad("A deposit must be between £1 and £500.", 400);
        const next = {
          enabled: b.enabled === undefined ? cur.enabled : !!b.enabled,
          pence,
          label: String(b.label || cur.label).slice(0, 60),
        };
        if (next.enabled && !(await paymentsReady(env))) return bad("Connect SumUp (or set the SumUp/Stripe secrets) before switching deposits on.", 400);
        await env.CMS_KV.put("deposit_settings", JSON.stringify(next));
        await audit(env, actor, "deposit_settings_updated", JSON.stringify(next));
        return json({ settings: next });
      }
    }

    /* Retention periods, and proof the purge is actually running. */
    if (p === "/admin/retention") {
      if (request.method === "GET") {
        return json({
          policy: await retentionPolicy(env),
          defaults: RETENTION,
          lastRun: JSON.parse((await env.CMS_KV.get("retention_last_run")) || "null"),
          lastBackup: JSON.parse((await env.CMS_KV.get("backup_last_run")) || "null"),
        });
      }
      if (request.method === "POST") {
        // Shortening a retention period destroys records, and the number here
        // is one the privacy notice publishes. Not a day-to-day setting.
        const denied = needs("developer");
        if (denied) return denied;
        const b = await request.json().catch(() => ({}));
        const cur = await retentionPolicy(env);
        const numOr = (v, f, lo, hi) => { const n = Number(v); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, Math.round(n))) : f; };
        const next = {
          // Floors are deliberate. Six months on finished jobs would put Cousins
          // in the position of being liable for work he has no record of.
          jobDays: numOr(b.jobDays, cur.jobDays, 365, 3650),
          contactDays: numOr(b.contactDays, cur.contactDays, 90, 3650),
          auditDays: numOr(b.auditDays, cur.auditDays, 30, 2190),
          messageDays: numOr(b.messageDays, cur.messageDays, 30, 3650),
          slotDays: numOr(b.slotDays, cur.slotDays, 7, 730),
          mailLogDays: numOr(b.mailLogDays, cur.mailLogDays, 7, 730),
        };
        await env.CMS_KV.put("retention_policy", JSON.stringify(next));
        await audit(env, actor, "retention_policy_updated", JSON.stringify(next));
        return json({ policy: next });
      }
    }

    /* Run the sweeps by hand — for testing, and for the day somebody needs
     * to prove the purge works rather than trust that it does. */
    if (p === "/admin/run-retention" && request.method === "POST") {
      const denied = needs("developer");
      if (denied) return denied;
      return json({ removed: await retentionSweep(env) });
    }
    if (p === "/admin/run-health" && request.method === "POST") return json(await healthSweep(env));
    if (p === "/admin/run-backup" && request.method === "POST") return json(await backupSweep(env));

    /*
     * What this client has sent, and what Twilio actually charges for it.
     *
     * Deliberately TWO numbers, never blended. Our own count covers every
     * channel including WhatsApp and email, which Twilio never sees, and keeps
     * working when Twilio is unreachable. Twilio's Usage Records are the
     * billing truth for texts and calls. Quoting our count as money would
     * undercharge on long messages; quoting Twilio's as activity would miss
     * every WhatsApp message. So both are shown, labelled.
     */
    /*
     * "Is my site up, is my number live, what has come in?" — the questions a
     * business owner actually asks, answered without them needing to log into
     * Cloudflare or Twilio.
     *
     * DELIBERATELY NOT CACHED, and deliberately not stored. Call records
     * contain customers' phone numbers: keeping a copy here would create a
     * second store of personal data with its own retention obligation, its own
     * place to leak from, and its own line in the privacy notice — to save a
     * fetch. It is read live from Twilio each time and thrown away.
     */
    if (p === "/admin/service-status" && request.method === "GET") {
      const site = (env.SITE_URL || "").replace(/\/+$/, "");

      /*
       * Is the site up?
       *
       * This used to answer by fetching its own public URL — and the dashboard
       * has been reporting "Not responding — status 522" ever since, on a site
       * that was serving every page perfectly well. A Worker cannot call the
       * hostname it is itself serving: the subrequest leaves the isolate,
       * comes back to the same Cloudflare route, finds no origin behind it and
       * times out. 522 is the edge saying "there is nothing to connect to",
       * which is true, and completely uninformative about whether the site
       * works. It was a false alarm that could never clear.
       *
       * The honest answer is available without leaving the isolate. This
       * request reached this Worker, on this hostname, over this scheme — that
       * IS the site answering, and no round trip can prove it better. What is
       * worth checking on top is the things that can fail while the front door
       * still opens: the catalogue, the static files, the data store, and
       * whether SITE_URL still names the host we are actually served from
       * (it is the base for every OAuth redirect and every emailed link, so a
       * stale value breaks sign-in and tracking links while the site looks fine).
       */
      const domain = await (async () => {
        if (!site) return { ok: false, reason: "SITE_URL is not set" };
        let siteHost = "";
        try { siteHost = new URL(site).hostname; }
        catch { return { ok: false, host: site, reason: "SITE_URL is not a valid web address" }; }

        let tyres = 0;
        try {
          const d = await tyreData(env);
          for (const list of Object.values(d.catalogue)) tyres += list.length;
        } catch (e) { /* counted as zero, reported below */ }

        const assetOk = env.ASSETS
          ? await env.ASSETS.fetch(new Request(new URL("/robots.txt", url).toString()))
              .then(r => r.ok).catch(() => false)
          : false;

        let kvOk = false;
        try { await env.CMS_KV.get("health_probe"); kvOk = true; }
        catch (e) { /* reported below */ }

        const here = url.hostname;
        // localhost and 127.0.0.1 are the same machine wearing two names, and
        // a developer running the site locally is not a misconfiguration.
        const loopback = h => h === "localhost" || h === "127.0.0.1" || h === "0.0.0.0" || h === "[::1]" || h === "::1";
        const onSite = here === siteHost
          || here === "www." + siteHost
          || here.endsWith("." + siteHost)
          || (loopback(here) && loopback(siteHost));

        const problems = [];
        if (!tyres) problems.push("the tyre catalogue is not loading");
        if (!assetOk) problems.push("the site's own files are not being served");
        if (!kvOk) problems.push("the data store did not answer");
        if (!onSite) problems.push("SITE_URL says " + siteHost + ", but this is being served from " + here);

        return {
          ok: problems.length === 0,
          host: site,
          servedFrom: here,
          https: url.protocol === "https:",
          catalogue: tyres,
          reason: problems.join(" · "),
        };
      })();

      const twilioGet = async (path) => {
        if (!(env.TWILIO_SID && env.TWILIO_TOKEN)) return null;
        const r = await fetch("https://api.twilio.com/2010-04-01/Accounts/" + env.TWILIO_SID + path,
          { headers: { authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) } }).catch(() => null);
        if (!r || !r.ok) return null;
        return r.json().catch(() => null);
      };

      const numbers = await (async () => {
        const d = await twilioGet("/IncomingPhoneNumbers.json?PageSize=10");
        if (!d) return { ok: false, reason: env.TWILIO_SID ? "could not reach Twilio" : "Twilio is not configured" };
        return {
          ok: (d.incoming_phone_numbers || []).length > 0,
          numbers: (d.incoming_phone_numbers || []).map(n => ({
            number: n.phone_number,
            name: n.friendly_name,
            sms: !!(n.capabilities && n.capabilities.sms),
            voice: !!(n.capabilities && n.capabilities.voice),
            status: n.status || "in-use",
          })),
        };
      })();

      const calls = await (async () => {
        const d = await twilioGet("/Calls.json?PageSize=20");
        if (!d) return { ok: false, reason: env.TWILIO_SID ? "could not reach Twilio" : "Twilio is not configured" };
        const list = d.calls || [];
        return {
          ok: true,
          recent: list.map(c => ({
            from: c.from, to: c.to, direction: c.direction,
            status: c.status, seconds: Number(c.duration) || 0, at: c.start_time,
          })),
          inbound: list.filter(c => String(c.direction || "").startsWith("inbound")).length,
          answered: list.filter(c => c.status === "completed").length,
          missed: list.filter(c => ["no-answer", "busy", "failed"].includes(c.status)).length,
        };
      })();

      return json({ domain, numbers, calls, checkedAt: new Date().toISOString() });
    }

    /* The spend cap. Readable by anyone in the dashboard — the client should be
     * able to see their own ceiling and where they are against it — but only a
     * developer may change it, because a client who can raise their own cap
     * does not have one. */
    if (p === "/admin/limits") {
      if (request.method === "GET") {
        return json({ limits: await usageLimits(env), spend: await twilioSpend(env), defaults: DEFAULT_LIMITS });
      }
      if (request.method === "POST") {
        const denied = needs("developer");
        if (denied) return denied;
        const b = await request.json().catch(() => ({}));
        const cur = await usageLimits(env);
        const num = (v, f) => { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : f; };
        const next = {
          monthlyCap: num(b.monthlyCap, cur.monthlyCap),
          hardCap: num(b.hardCap, cur.hardCap),
          warnAtPct: Math.max(10, Math.min(100, num(b.warnAtPct, cur.warnAtPct))),
          blockDiscretionary: b.blockDiscretionary === undefined ? cur.blockDiscretionary : !!b.blockDiscretionary,
        };
        // A hard cap below the budget would stop everything the moment the
        // budget is reached, which is not what "runaway brake" means.
        if (next.hardCap && next.monthlyCap && next.hardCap < next.monthlyCap) {
          return bad("The runaway brake must be higher than the budget, or it stops all messages as soon as the budget is reached.", 400);
        }
        await env.CMS_KV.put("usage_limits", JSON.stringify(next));
        await audit(env, actor, "spend_limits_updated", JSON.stringify(next));
        return json({ limits: next });
      }
    }

    if (p === "/admin/usage" && request.method === "GET") {
      const months = [];
      const now = new Date();
      for (let i = 0; i < 6; i++) {
        const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
        const key = "usage:" + d.toISOString().slice(0, 7);
        const u = JSON.parse((await env.CMS_KV.get(key)) || "{}");
        months.push({
          month: d.toISOString().slice(0, 7),
          sms: Number(u.sms) || 0,
          smsSegments: Number(u.smsSegments) || 0,
          smsUnicode: Number(u.smsUnicode) || 0,
          whatsapp: Number(u.whatsapp) || 0,
          email: Number(u.email) || 0,
        });
      }

      // Twilio's own figures for this subaccount. Absent is not an error —
      // it just means nobody has set Twilio up, or Twilio is having a bad day.
      let twilio = { available: false, reason: "Twilio is not configured" };
      if (env.TWILIO_SID && env.TWILIO_TOKEN) {
        const r = await fetch(
          "https://api.twilio.com/2010-04-01/Accounts/" + env.TWILIO_SID + "/Usage/Records/Monthly.json?PageSize=50",
          { headers: { authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) } },
        ).catch(() => null);
        if (!r || !r.ok) {
          twilio = { available: false, reason: r ? "Twilio returned " + r.status : "could not reach Twilio" };
        } else {
          const d = await r.json().catch(() => ({}));
          const rows = (d.usage_records || [])
            .filter(x => Number(x.count) > 0 || Number(x.price) > 0)
            .map(x => ({
              category: x.category, description: x.description,
              count: Number(x.count) || 0, countUnit: x.count_unit,
              usage: x.usage, usageUnit: x.usage_unit,
              price: Number(x.price) || 0, currency: (x.price_unit || "").toUpperCase(),
              from: x.start_date, to: x.end_date,
            }));
          twilio = {
            available: true,
            subaccount: env.TWILIO_SID,
            currency: rows.length ? rows[0].currency : "",
            total: Math.round(rows.reduce((n, x) => n + x.price, 0) * 10000) / 10000,
            rows,
          };
        }
      }
      return json({ months, twilio });
    }

    if (p === "/admin/mail-failures" && request.method === "GET") {
      const log = JSON.parse((await env.CMS_KV.get("maillog")) || "[]");
      return json({
        failures: log,
        ownerEmailValid: validEmail(env.OWNER_EMAIL || env.MAIL_FROM),
        mailFromValid: validEmail(env.MAIL_FROM),
        calendarConfigured: await calendarReady(env),
        // Which service is carrying the mail, and which ones could. Shown in
        // the dashboard so "email is working" names a service rather than
        // being a flag nobody can check.
        mail: {
          provider: await mailProvider(env),
          from: env.MAIL_FROM || "",
          available: {
            resend: resendMailReady(env),
            twilio: twilioMailReady(env),
          },
        },
      });
    }

    /*
     * Switch the sending service.
     *
     * Owner or developer only, and deliberately reversible in one click: the
     * safe way to move mail from one provider to another is to switch, send
     * yourself a test from the button right next to it, and switch back if it
     * does not arrive. Stored in KV rather than a secret so it takes effect
     * immediately and does not need a deploy.
     */
    if (p === "/admin/mail-provider" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      const b = await request.json().catch(() => ({}));
      const want = String(b.provider || "").toLowerCase();
      if (!["auto", "resend", "twilio"].includes(want)) {
        return bad("Choose auto, resend or twilio.", 400);
      }
      if (want === "twilio" && !twilioMailReady(env)) {
        return bad("Twilio cannot send yet — it needs TWILIO_SID and TWILIO_TOKEN (or an API key pair) and a valid MAIL_FROM on a verified sending domain.", 400);
      }
      if (want === "resend" && !resendMailReady(env)) {
        return bad("Resend cannot send yet — it needs RESEND_API_KEY and a valid MAIL_FROM.", 400);
      }
      await env.CMS_KV.put("mail_provider", want);
      await audit(env, actor, "mail_provider_changed", want);
      return json({ ok: true, provider: await mailProvider(env), setting: want });
    }

    if (p === "/admin/mail-failures" && request.method === "DELETE") {
      await env.CMS_KV.delete("maillog");
      return json({ ok: true });
    }

    if (p === "/admin/backup" && request.method === "GET") {
      // Every customer's name, address, phone and job history in one download.
      // Day-to-day staff have no reason to take a copy of the whole book home.
      { const denied = needs("developer"); if (denied) return denied; }
            // Sessions, rate-limit counters and reset tokens are transient. The rest
      // of this list is credential material: exporting it turns "download a
      // backup" into "download every password hash and the owner's 2FA seed",
      // which any staff-level account could then use to log in as the owner.
      // "verify:" holds a hashed email-confirmation code and its salt. It is
      // transient credential material like a session or a reset token, and the
      // backup test caught it leaking the moment verification was added.
      const EXCLUDE = ["sess:", "asess:", "dsess:", "rl:", "reset:", "verify:", "dverify:", "admin_totp"];
      const data = {};
      let cursor;
      do {
        const page = await env.CMS_KV.list({ cursor });
        for (const k of page.keys) {
          if (EXCLUDE.some(pre => k.name.startsWith(pre))) continue;
          const raw = await env.CMS_KV.get(k.name);
          if (raw == null) continue;
          let val;
          try { val = JSON.parse(raw); } catch { val = raw; }
          // Strip password material. A backup is for restoring business data,
          // not for carrying every customer's and every staff member's salt and
          // PBKDF2 hash out of the system in a file that lands in Downloads.
          if (val && typeof val === "object") {
            if (k.name.startsWith("user:") || k.name.startsWith("staff:")) {
              delete val.salt; delete val.hash;
            }
            if (k.name === "drivers" && Array.isArray(val)) {
              val = val.map(d => { const c = { ...d }; delete c.salt; delete c.hash; return c; });
            }
          }
          data[k.name] = val;
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      await audit(env, actor, "backup_downloaded", Object.keys(data).length + " keys");
      return new Response(JSON.stringify({ exportedAt: new Date().toISOString(), site: env.SITE_URL || "", keys: Object.keys(data).length, data }, null, 2), {
        status: 200,
        headers: {
          ...CORS, ...SECURITY_HEADERS,
          "content-type": "application/json",
          "content-disposition": `attachment; filename="cousins-backup-${stamp}.json"`,
        },
      });
    }

    // --- STAFF ACCOUNTS (email + password logins for the dashboard) ---
    if (p === "/admin/staff") {
      if (request.method === "GET") {
        const list = await env.CMS_KV.list({ prefix: "staff:" });
        const out = [];
        for (const k of list.keys) {
          const a = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
          // Never return salt or hash.
          out.push({ email: a.email, name: a.name || "", role: a.role || "staff", disabled: !!a.disabled, createdAt: a.createdAt, lastLoginAt: a.lastLoginAt || null });
        }
        out.sort((x, y) => (x.createdAt || 0) - (y.createdAt || 0));
        return json({ staff: out });
      }

      if (request.method === "POST") {
        const denied = needs("developer");
        if (denied) return denied;

        const b = await request.json().catch(() => ({}));
        const em = String(b.email || "").trim().toLowerCase();
        const pw = String(b.password || "");
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return bad("Enter a valid email address.");
        if (pw.length < 10) return bad("Password must be at least 10 characters.");

        const existingRaw = await env.CMS_KV.get("staff:" + em);
        const existing = existingRaw ? JSON.parse(existingRaw) : null;
        const anyStaff = await env.CMS_KV.list({ prefix: "staff:" });

        // The FIRST account is always the owner. Without this the dashboard —
        // which does not send a role — would create a lone "staff" account, no
        // owner would exist, and the person setting the system up would lock
        // themselves out of staff management with their own first click.
        let wanted;
        if (!anyStaff.keys.length) {
          wanted = "owner";
        } else if (b.role === undefined) {
          wanted = existing?.role || "staff";
        } else if (ROLE_NAMES.includes(String(b.role))) {
          wanted = String(b.role);
        } else {
          return bad("Role must be one of: " + ROLE_NAMES.join(", "));
        }

        // You cannot hand out authority you do not have. Without this a staff
        // account could mint itself an owner and the roles would be theatre.
        if (!atLeast(role, wanted)) {
          return bad("You cannot grant the " + wanted + " role — yours is " + role + ".", 403);
        }
        // Changing an owner's password is how you take over an owner's account.
        // Only another owner may do it.
        if (existing && existing.role === "owner" && !atLeast(role, "owner")) {
          return bad("Only an owner can change another owner's password or role.", 403);
        }

        const salt = newSalt();
        const acct = {
          email: em,
          name: String(b.name || existing?.name || "").trim(),
          role: wanted,
          salt,
          hash: await pbkdf2(pw, salt, env.SESSION_PEPPER),
          disabled: false,
          createdAt: existing?.createdAt || Date.now(),
          updatedAt: Date.now(),
        };
        await env.CMS_KV.put("staff:" + em, JSON.stringify(acct));
        await audit(env, actor, existing ? "staff_password_changed" : "staff_created", em + " role=" + wanted);
        return json({ ok: true, staff: { email: acct.email, name: acct.name, role: acct.role, disabled: false, createdAt: acct.createdAt } });
      }
    }

    const staffOne = p.match(/^\/admin\/staff\/([^/]+)$/);
    if (staffOne && (request.method === "DELETE" || request.method === "PATCH")) {
      const denied = needs("developer");
      if (denied) return denied;

      const em = decodeURIComponent(staffOne[1]).toLowerCase();
      const raw = await env.CMS_KV.get("staff:" + em);
      if (!raw) return bad("Staff account not found", 404);
      const target = JSON.parse(raw);
      const list = await env.CMS_KV.list({ prefix: "staff:" });

      /*
       * A contractor must never be able to lock their client out of their own
       * business. A developer can do nearly everything in here, but an owner's
       * account is off limits to anyone who is not themselves an owner — and
       * the last owner cannot be removed by anybody, including another owner,
       * because the account that is left would have no way back in.
       */
      if (target.role === "owner" && !atLeast(role, "owner")) {
        return bad("Only an owner can remove or change another owner's account.", 403);
      }
      const owners = [];
      for (const k of list.keys) {
        const a = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
        if (a.role === "owner" && !a.disabled) owners.push(a.email);
      }
      const lastOwner = target.role === "owner" && owners.length <= 1 && owners[0] === em;

      if (request.method === "DELETE") {
        // Refuse to remove the last account — that would lock everyone out and
        // leave only the break-glass OVERRIDE_TOKEN.
        if (list.keys.length <= 1) return bad("This is the only staff account — create another before removing it.", 409);
        if (lastOwner) return bad("This is the last owner. Make somebody else an owner first, or the business loses control of its own dashboard.", 409);
        await env.CMS_KV.delete("staff:" + em);
        await revokeAdminSessions(env, em);
        await audit(env, actor, "staff_deleted", em + " role=" + target.role);
        return json({ ok: true, deleted: em });
      }

      const b = await request.json().catch(() => ({}));
      const acct = JSON.parse(raw);
      if (b.disabled !== undefined) {
        const active = [];
        for (const k of list.keys) {
          const a = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
          if (!a.disabled) active.push(a.email);
        }
        if (b.disabled && active.length <= 1 && active[0] === em) {
          return bad("This is the only active staff account — you would lock yourself out.", 409);
        }
        if (b.disabled && lastOwner) {
          return bad("This is the last owner. Make somebody else an owner first, or the business loses control of its own dashboard.", 409);
        }
        acct.disabled = !!b.disabled;
      }
      if (b.role !== undefined && b.role !== acct.role) {
        if (!ROLE_NAMES.includes(String(b.role))) return bad("Role must be one of: " + ROLE_NAMES.join(", "));
        if (!atLeast(role, String(b.role))) return bad("You cannot grant the " + b.role + " role — yours is " + role + ".", 403);
        // Demoting the last owner is the same lockout as deleting them, just
        // slower to notice.
        if (lastOwner && b.role !== "owner") {
          return bad("This is the last owner. Promote somebody else first.", 409);
        }
        acct.role = String(b.role);
      }
      if (b.name !== undefined) acct.name = String(b.name).trim();
      acct.updatedAt = Date.now();
      await env.CMS_KV.put("staff:" + em, JSON.stringify(acct));
      // Disabling must take effect now, not at the end of their 12h session.
      if (acct.disabled) await revokeAdminSessions(env, em);
      await audit(env, actor, "staff_updated", em + " disabled=" + !!acct.disabled);
      return json({ ok: true, staff: { email: acct.email, name: acct.name, role: acct.role, disabled: !!acct.disabled } });
    }

    // Customers (CRM list) — profile + job count + discount + notes count
    if (p === "/admin/customers" && request.method === "GET") {
      // Two sources, merged: "user:" = someone who created a login account,
      // "contact:" = someone who booked as a guest. This list used to read
      // "user:" only, so every guest booking — most of them — was missing from
      // the CRM entirely. An account record wins on conflict because it has the
      // richer profile (SMS preference, consent version).
      const byEmail = new Map();

      const contacts = await env.CMS_KV.list({ prefix: "contact:" });
      for (const k of contacts.keys) {
        const c = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
        if (!c.email) continue;
        byEmail.set(c.email, {
          name: c.name, email: c.email, phone: c.phone,
          marketing: !!c.marketing, smsUpdates: true,
          createdAt: c.firstSeenAt || 0, hasAccount: false,
        });
      }

      const list = await env.CMS_KV.list({ prefix: "user:" });
      for (const k of list.keys) {
        const u = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
        if (!u.email) continue;
        byEmail.set(u.email, {
          name: u.name, email: u.email, phone: u.phone,
          marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false,
          createdAt: u.createdAt, hasAccount: true,
        });
      }

      const out = [];
      for (const base of byEmail.values()) {
        const jobs = JSON.parse((await env.CMS_KV.get("bookings:" + base.email)) || "[]");
        const crm = JSON.parse((await env.CMS_KV.get("crm:" + base.email)) || "{}");
        out.push({
          ...base,
          jobCount: jobs.length,
          discount: Number(crm.discount) || 0, discountReason: crm.discountReason || "",
          notesCount: Array.isArray(crm.notes) ? crm.notes.length : 0,
          lastJobAt: jobs.reduce((m, j) => Math.max(m, j.createdAt || j.t || 0), 0),
        });
      }
      out.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
      return json({ customers: out });
    }

    // Add a CRM note to a customer (append-only log). Kept before the record
    // route so ".../notes" is not swallowed by the single-segment matcher.
    const custNotes = p.match(/^\/admin\/customers\/(.+)\/notes$/);
    if (custNotes && request.method === "POST") {
      const email = decodeURIComponent(custNotes[1]).toLowerCase();
      // A guest who booked without an account is still a customer you need to
      // keep notes on, so accept either record type.
      if (!(await env.CMS_KV.get("user:" + email)) && !(await env.CMS_KV.get("contact:" + email))) {
        return bad("Customer not found", 404);
      }
      const b = await request.json().catch(() => ({}));
      const text = String(b.text || "").slice(0, 2000).trim();
      if (!text) return bad("Note is empty");
      const crm = JSON.parse((await env.CMS_KV.get("crm:" + email)) || "{}");
      crm.notes = Array.isArray(crm.notes) ? crm.notes : [];
      crm.notes.push({ t: Date.now(), text });
      crm.notes = crm.notes.slice(-500); // keep the log bounded
      await env.CMS_KV.put("crm:" + email, JSON.stringify(crm));
      await audit(env, email, "crm_note_added", text.slice(0, 80));
      return json({ notes: crm.notes });
    }

    // Single customer CRM record: full detail (GET) or set discount (PATCH)
    const custRec = p.match(/^\/admin\/customers\/([^/]+)$/);
    if (custRec) {
      const email = decodeURIComponent(custRec[1]).toLowerCase();
      const uraw = await env.CMS_KV.get("user:" + email);
      const craw = uraw ? null : await env.CMS_KV.get("contact:" + email);
      if (!uraw && !craw) return bad("Customer not found", 404);
      const rec = JSON.parse(uraw || craw);
      // Normalise the two shapes so the admin UI does not have to care which
      // kind of record it is looking at.
      const u = uraw ? rec : {
        name: rec.name, email: rec.email, phone: rec.phone,
        marketing: !!rec.marketing, smsUpdates: true, createdAt: rec.firstSeenAt,
      };
      const crm = JSON.parse((await env.CMS_KV.get("crm:" + email)) || "{}");

      if (request.method === "GET") {
        const bookings = JSON.parse((await env.CMS_KV.get("bookings:" + email)) || "[]");
        return json({
          customer: {
            name: u.name, email: u.email, phone: u.phone,
            marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false, createdAt: u.createdAt,
            hasAccount: !!uraw,
          },
          discount: Number(crm.discount) || 0,
          discountReason: crm.discountReason || "",
          notes: Array.isArray(crm.notes) ? crm.notes : [],
          bookings,
        });
      }

      if (request.method === "PATCH") {
        const b = await request.json().catch(() => ({}));
        if (b.discount !== undefined) {
          let d = Number(b.discount);
          if (!Number.isFinite(d)) d = 0;
          crm.discount = Math.max(0, Math.min(100, Math.round(d))); // record-only %, 0-100
        }
        if (b.discountReason !== undefined) crm.discountReason = String(b.discountReason).slice(0, 200).trim();
        await env.CMS_KV.put("crm:" + email, JSON.stringify(crm));
        await audit(env, email, "crm_discount_set", "discount=" + (crm.discount || 0) + "%");
        return json({ discount: crm.discount || 0, discountReason: crm.discountReason || "" });
      }
    }

    // Centralized Tyre Inventory API Endpoints
    if (p === "/admin/inventory" && request.method === "GET") {
      let stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      if (stock.length === 0) {
        await checkAndTriggerReorders(env, { triggerSource: "Initial System Setup" });
        stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      }
      const settings = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "{}");
      const reorderLogs = JSON.parse((await env.CMS_KV.get("reorder_logs")) || "[]");
      const supplierOrders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");

      const defaultMin = settings.defaultMinStock !== undefined ? settings.defaultMinStock : 3;
      const lowStockCount = stock.filter(item => item.qty <= (item.minStock !== undefined ? item.minStock : defaultMin)).length;
      const outOfStockCount = stock.filter(item => item.qty === 0).length;
      const totalValue = stock.reduce((sum, item) => sum + ((item.qty || 0) * (item.price || item.costPrice || 0)), 0);

      return json({
        stock,
        settings,
        reorderLogs,
        supplierOrders,
        summary: {
          totalSkus: stock.length,
          lowStockCount,
          outOfStockCount,
          reordersTriggeredCount: reorderLogs.length,
          totalInventoryValue: Math.round(totalValue * 100) / 100
        }
      });
    }

    if (p === "/admin/inventory" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      let stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      
      const id = b.id || ("P" + Date.now().toString(36).toUpperCase().slice(-5));
      const record = {
        id,
        sku: b.sku || ("TY-" + Math.random().toString(36).slice(2, 7).toUpperCase()),
        name: b.name || "Tyre Item",
        brand: b.brand || "Standard",
        size: b.size || "205/55R16",
        category: b.category || "Mid-Range",
        qty: parseInt(b.qty || "0", 10) || 0,
        minStock: parseInt(b.minStock || "3", 10) || 3,
        reorderQty: parseInt(b.reorderQty || "10", 10) || 10,
        costPrice: parseFloat(b.costPrice || b.cost || "45") || 45,
        price: parseFloat(b.price || b.retailPrice || "65") || 65,
        supplierEmail: b.supplierEmail || "",
        supplierApiUrl: b.supplierApiUrl || "",
        autoReorder: b.autoReorder !== false,
        lastReorderedAt: b.lastReorderedAt || null,
        status: b.status || "In Stock"
      };

      const idx = stock.findIndex(s => s.id === id || (b.sku && s.sku === b.sku));
      if (idx >= 0) stock[idx] = { ...stock[idx], ...record };
      else stock.unshift(record);

      await env.CMS_KV.put("stock", JSON.stringify(stock));

      // Run automatic threshold check immediately
      const triggerRes = await checkAndTriggerReorders(env, { triggerSource: "Inventory Update (" + record.sku + ")" });

      return json({ ok: true, item: record, stock, triggered: triggerRes });
    }

    if (p === "/admin/inventory/adjust" && request.method === "POST") {
      const { id, sku, delta, newQty, reason } = await request.json().catch(() => ({}));
      let stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      const idx = stock.findIndex(s => s.id === id || s.sku === sku);
      if (idx < 0) return bad("Inventory item not found", 404);

      if (newQty !== undefined) stock[idx].qty = Math.max(0, parseInt(newQty, 10) || 0);
      else if (delta !== undefined) stock[idx].qty = Math.max(0, (stock[idx].qty || 0) + parseInt(delta, 10));

      await env.CMS_KV.put("stock", JSON.stringify(stock));

      const triggerRes = await checkAndTriggerReorders(env, { triggerSource: `Manual Adjust (${reason || 'Stock Update'})`, specificSku: stock[idx].sku });

      return json({ ok: true, item: stock[idx], stock, triggered: triggerRes });
    }

    if (p === "/admin/inventory/check-reorders" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const triggerRes = await checkAndTriggerReorders(env, {
        triggerSource: "Manual Admin Stock Scan",
        force: !!b.force,
        specificSku: b.sku || null
      });
      return json({ ok: true, scanResult: triggerRes });
    }

    if (p === "/admin/inventory/reorder-now" && request.method === "POST") {
      const { id, sku, customQty } = await request.json().catch(() => ({}));
      const triggerRes = await checkAndTriggerReorders(env, {
        triggerSource: "1-Click Manual Admin Reorder",
        force: true,
        specificSku: sku || id,
        customQty
      });
      return json({ ok: true, reorderResult: triggerRes });
    }

    if (p === "/admin/inventory/settings") {
      if (request.method === "GET") {
        const settings = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "{}");
        return json({ settings });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const current = JSON.parse((await env.CMS_KV.get("inventory_settings")) || "{}");
        const updated = { ...current, ...b };
        await env.CMS_KV.put("inventory_settings", JSON.stringify(updated));
        return json({ ok: true, settings: updated });
      }
    }

    if (p === "/admin/inventory/reorder-logs" && request.method === "GET") {
      const reorderLogs = JSON.parse((await env.CMS_KV.get("reorder_logs")) || "[]");
      return json({ reorderLogs });
    }

    // Parts & stock (KV key "stock")
    if (p === "/admin/stock") {
      if (request.method === "GET") return json({ stock: JSON.parse((await env.CMS_KV.get("stock")) || "[]") });
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
        if (b.id) { const i = stock.findIndex(s => s.id === b.id); if (i >= 0) stock[i] = { ...stock[i], ...b }; else stock.push(b); }
        else stock.push({ ...b, id: "P" + Date.now().toString(36).toUpperCase().slice(-5) });
        await env.CMS_KV.put("stock", JSON.stringify(stock));
        await checkAndTriggerReorders(env, { triggerSource: "Stock Add/Edit" });
        return json({ stock });
      }
    }
    const sm = p.match(/^\/admin\/stock\/([\w-]+)$/);
    if (sm && request.method === "DELETE") {
      let stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
      stock = stock.filter(s => s.id !== sm[1]);
      await env.CMS_KV.put("stock", JSON.stringify(stock));
      return json({ stock });
    }

    // --- SUPPLIER PURCHASE ORDERS ---
    if (p === "/admin/supplier-orders") {
      if (request.method === "GET") {
        const orders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");
        return json({ supplierOrders: orders });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const poRef = "PO-CTYRES-" + Date.now().toString(36).toUpperCase().slice(-5);
        const order = {
          poRef,
          tyreDetails: b.tyreDetails || b.brand + " " + b.model,
          sku: b.sku || "-",
          qty: parseInt(b.qty || "1", 10) || 1,
          wholesaleCost: b.cost || 45,
          retailPrice: b.price || 65,
          supplier: b.supplier || "Supplier (not set)",
          status: "Manual Order Placed",
          orderedAt: Date.now(),
          estDelivery: "Tomorrow 8:00 AM"
        };
        const orders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");
        orders.unshift(order);
        await env.CMS_KV.put("supplier_orders", JSON.stringify(orders.slice(0, 200)));

        // Optionally increment stock inventory count for incoming item
        const stock = JSON.parse((await env.CMS_KV.get("stock")) || "[]");
        stock.unshift({
          id: "P" + Date.now().toString(36).toUpperCase().slice(-5),
          name: order.tyreDetails,
          sku: order.sku,
          qty: order.qty,
          price: order.retailPrice,
          status: "Ordered from Supplier"
        });
        await env.CMS_KV.put("stock", JSON.stringify(stock));

        return json({ ok: true, po: order, supplierOrders: orders });
      }
    }

    // --- DRIVERS & FLEET MANAGEMENT ---
    if (p === "/admin/drivers") {
      // Strip credentials on the way out — the dashboard never needs them.
      const publicView = list => list.map(({ salt, hash, password, ...rest }) => rest);

      if (request.method === "GET") {
        const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
        return json({ drivers: publicView(drivers) });
      }
      if (request.method === "POST") {
        /*
         * Approving a driver, resetting their password, or creating one, is
         * how somebody gets into the van view and sees every live customer's
         * name, address and registration. It had no role check at all, so any
         * day-to-day staff account could approve itself a colleague. The owner
         * asked for the opposite in as many words: only he or the developer
         * add, edit or remove people.
         */
        const denied = needs("developer");
        if (denied) return denied;

        const b = await request.json().catch(() => ({}));
        const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");

        // Approve / revoke a driver's access. The dashboard posts {action, id} here.
        // (This block was previously spliced into the customer /messages handler by
        // a patch script, which left worker.js unparseable and undeployable.)
        // Add a note against a driver.
        if (b.action === "note") {
          const idx = drivers.findIndex(d => d.id === b.id);
          if (idx < 0) return bad("Driver not found", 404);
          const text = String(b.text || "").slice(0, 2000).trim();
          if (!text) return bad("Note is empty");
          drivers[idx].notes = Array.isArray(drivers[idx].notes) ? drivers[idx].notes : [];
          drivers[idx].notes.push({ t: Date.now(), text, by: (await whoAmI(env, request)) || "admin" });
          drivers[idx].notes = drivers[idx].notes.slice(-200);
          await env.CMS_KV.put("drivers", JSON.stringify(drivers));
          await audit(env, actor, "driver_note", b.id + " " + text.slice(0, 60));
          return json({ drivers: publicView(drivers) });
        }

        if (b.action === "approve" || b.action === "revoke") {
          const idx = drivers.findIndex(d => d.id === b.id);
          if (idx < 0) return bad("Driver not found", 404);
          const approving = b.action === "approve";
          // Approval is the SECOND gate. Approving somebody who has not
          // confirmed their address would defeat the first one entirely.
          if (approving && drivers[idx].emailVerified === false) {
            return bad("That driver has not confirmed their email address yet, so they cannot be approved.", 409);
          }
          drivers[idx].approved = approving;
          drivers[idx].status = approving ? "Active" : "Suspended";
          drivers[idx][approving ? "approvedAt" : "revokedAt"] = Date.now();
          drivers[idx].approvedBy = approving ? ((await whoAmI(env, request)) || "admin") : drivers[idx].approvedBy;
          await env.CMS_KV.put("drivers", JSON.stringify(drivers));
          // Revoking must kill any live session, not just flip the flag.
          if (!approving) {
            const sessions = await env.CMS_KV.list({ prefix: "dsess:" });
            for (const k of sessions.keys) {
              if ((await env.CMS_KV.get(k.name)) === b.id) await env.CMS_KV.delete(k.name);
            }
          }
          await audit(env, actor, "driver_" + b.action, b.id);
          return json({ drivers: publicView(drivers) });
        }

        const id = b.id || ("DRV-" + token().slice(0, 8).toUpperCase());
        const idx = drivers.findIndex(d => d.id === id);
        const existing = idx >= 0 ? drivers[idx] : {};

        // Merge onto the existing record. Writing a fresh object here used to wipe
        // username/salt/hash/approved, silently destroying the driver's login.
        const record = {
          ...existing,
          id,
          name: b.name ?? existing.name ?? "Van Driver",
          vanReg: b.vanReg ?? existing.vanReg ?? "",
          phone: b.phone ?? existing.phone ?? "",
          email: b.email ?? existing.email ?? "",
          // Append-only, like the CRM notes. An editable free-text blob loses
          // history the moment two people touch it.
          notes: Array.isArray(existing.notes) ? existing.notes : [],
          status: b.status ?? existing.status ?? "Active",
          assignedJob: b.assignedJob ?? existing.assignedJob ?? "-",
          approved: b.approved !== undefined ? !!b.approved : (existing.approved ?? false),
        };

        // Admin-set or admin-reset password, hashed like every other credential.
        if (b.password) {
          if (String(b.password).length < 10) return bad("Password must be at least 10 characters", 400);
          record.salt = newSalt();
          record.hash = await pbkdf2(b.password, record.salt, env.SESSION_PEPPER);
        }
        if (b.username) record.username = String(b.username).trim().toLowerCase();

        if (idx >= 0) drivers[idx] = record; else drivers.push(record);
        await env.CMS_KV.put("drivers", JSON.stringify(drivers));
        return json({ drivers: publicView(drivers) });
      }
      if (request.method === "DELETE") {
        const denied = needs("developer");
        if (denied) return denied;

        const b = await request.json().catch(() => ({}));
        if (!b.id) return bad("Missing driver id");
        const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
        const gone = drivers.find(d => d.id === b.id);
        if (!gone) return bad("Driver not found", 404);
        const kept = drivers.filter(d => d.id !== b.id);
        await env.CMS_KV.put("drivers", JSON.stringify(kept));

        // Revoke any live session for that driver so removal takes effect at once.
        const sessions = await env.CMS_KV.list({ prefix: "dsess:" });
        for (const k of sessions.keys) {
          if ((await env.CMS_KV.get(k.name)) === b.id) await env.CMS_KV.delete(k.name);
        }

        // Leave nothing behind that would let the account half-exist: a pending
        // confirmation code would otherwise sit there, and the job claims would
        // keep a deleted driver's id attached to live jobs.
        if (gone.email) await env.CMS_KV.delete("dverify:" + String(gone.email).toLowerCase());
        const claims = await env.CMS_KV.list({ prefix: "jobdrv:" });
        for (const k of claims.keys) {
          if ((await env.CMS_KV.get(k.name)) === b.id) await env.CMS_KV.delete(k.name);
        }

        await audit(env, actor, "driver_deleted", (gone.username || gone.id) + " by " + ((await whoAmI(env, request)) || "admin"));
        return json({ drivers: publicView(kept) });
      }
    }

    // --- USERS & PORTAL ACCOUNTS MANAGEMENT ---
    if (p === "/admin/users") {
      if (request.method === "GET") {
        const out = [];
        const list = await env.CMS_KV.list({ prefix: "user:" });
        for (const k of list.keys) {
          const u = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
          const { salt, hash, ...rest } = u;
          out.push(rest);
        }
        return json({ users: out });
      }
    }

    // --- ALL LIVE LOCATIONS FOR ADMIN MAP ---
    // Fire a WhatsApp reminder on demand, so the template can be tested without
    // waiting for 5pm. POST {phone} sends a sample to that number; POST {} runs
    // the real sweep for tomorrow's jobs regardless of the hour.
    /* ---------------------------------------------------------------------
     * TYRE PRICING
     *
     * GET  /admin/pricing            current rules
     * POST /admin/pricing            save rules (markup %, fitting fee, rounding)
     * POST /admin/pricing/override   set or clear one tyre's price
     * POST /admin/pricing/stock      mark tyres in / out of stock
     * GET  /admin/tyres?size=...     the size, priced, WITH cost, margin and the
     *                                direct ctyres.co.uk link for reordering
     * GET  /admin/catalogue          EVERY tyre, priced, paginated and filterable
     * ------------------------------------------------------------------- */
    /*
     * The whole catalogue, browsable. The size lookup below needs you to already
     * know which size is wrong, so a bad markup on a range nobody thinks to type
     * stays invisible. This lists everything with cost, sell price and margin,
     * and can sort worst-margin-first.
     */
    if (p === "/admin/catalogue" && request.method === "GET") {
      const { catalogue, costMap } = await tyreData(env);
      const qp = url.searchParams;
      return json(adminCatalogue(catalogue, costMap, await getPricing(env), {
        q: qp.get("q"), brand: qp.get("brand"), tier: qp.get("tier"),
        stock: qp.get("stock"), sort: qp.get("sort"),
        page: qp.get("page"), perPage: qp.get("perPage"),
      }));
    }

    if (p === "/admin/pricing") {
      if (request.method === "GET") {
        return json({ pricing: await getPricing(env), defaults: DEFAULT_PRICING });
      }
      if (request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        const current = await getPricing(env);
        const numOr = (v, fallback) => (v === "" || v == null || !Number.isFinite(Number(v)) ? fallback : Number(v));

        // Only the rule fields are accepted here. Overrides and stock have their
        // own endpoints so a careless save can never wipe them.
        const next = {
          ...current,
          markupPct: {
            B: numOr(b.markupPct && b.markupPct.B, current.markupPct.B),
            M: numOr(b.markupPct && b.markupPct.M, current.markupPct.M),
            P: numOr(b.markupPct && b.markupPct.P, current.markupPct.P),
          },
          fittingFee: numOr(b.fittingFee, current.fittingFee),
          // The floor every offer, sale and override is clamped to.
          minMargin: numOr(b.minMargin, current.minMargin),
          // Labour rates shown on the booking form. 0/absent means "not set", and
          // the site then promises a quote before work instead of inventing a price.
          calloutFee: numOr(b.calloutFee, current.calloutFee || 0),
          hourlyRate: numOr(b.hourlyRate, current.hourlyRate || 0),
          roundTo: numOr(b.roundTo, current.roundTo) || 1,
          priceEnding: b.priceEnding === "" || b.priceEnding == null ? null : Number(b.priceEnding),
        };
        for (const t of ["B", "M", "P"]) {
          if (next.markupPct[t] < 0 || next.markupPct[t] > 500) return bad(`Markup for ${t} must be between 0 and 500%`, 400);
        }
        if (next.fittingFee < 0 || next.fittingFee > 200) return bad("Fitting fee must be between 0 and 200", 400);
        // A floor of 0 is allowed — it means "no floor" — but a negative one
        // would licence selling below cost, which is never what anybody meant.
        if (next.minMargin < 0 || next.minMargin > 500) return bad("Minimum margin must be between 0 and 500", 400);
        if (next.calloutFee < 0 || next.calloutFee > 1000) return bad("Call-out fee must be between 0 and 1000", 400);
        if (next.hourlyRate < 0 || next.hourlyRate > 1000) return bad("Hourly rate must be between 0 and 1000", 400);

        const saved = await savePricing(env, next);
        await audit(env, actor, "pricing_updated", JSON.stringify(saved.markupPct));
        return json({ pricing: saved });
      }
    }

    /*
     * OFFERS AND SALES
     *
     * Several offers can be live at once; a tyre takes the best single one it
     * qualifies for. They are never stacked — a 20% sale plus a 20% clearance
     * is 36% off, which is not what anyone setting the second one intended.
     *
     * None of them can breach the margin floor. That is enforced in
     * retailPrice(), not here, so a promo written straight into KV by some
     * future script cannot get round it either.
     */
    if (p === "/admin/pricing/promos" && request.method === "GET") {
      const cur = await getPricing(env);
      return json({ promos: cur.promos, minMargin: cur.minMargin });
    }

    if (p === "/admin/pricing/promo" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const current = await getPricing(env);
      const promos = [...current.promos];

      const name = String(b.name || "").trim().slice(0, 80);
      if (!name) return bad("Give the offer a name — it is what the customer sees.", 400);
      const kind = ["percent", "amount", "fixed"].includes(b.kind) ? b.kind : null;
      if (!kind) return bad("Offer type must be percent, amount or fixed", 400);
      const value = Number(b.value);
      if (!Number.isFinite(value) || value < 0) return bad("Offer value must be a positive number", 400);
      if (kind === "percent" && value > 90) return bad("A discount over 90% is almost certainly a typo. The margin floor would swallow it anyway.", 400);

      const strList = (v, n) => (Array.isArray(v) ? v : []).map(x => String(x).trim()).filter(Boolean).slice(0, n);
      const promo = {
        id: b.id ? String(b.id) : "promo_" + token().slice(0, 10),
        name, kind, value: Math.round(value * 100) / 100,
        active: b.active !== false,
        starts: b.starts ? Number(b.starts) : null,
        ends: b.ends ? Number(b.ends) : null,
        scope: {
          tiers: strList(b.scope && b.scope.tiers, 3).filter(t => ["B", "M", "P"].includes(t)),
          brands: strList(b.scope && b.scope.brands, 40),
          sizes: strList(b.scope && b.scope.sizes, 60),
          ids: (Array.isArray(b.scope && b.scope.ids) ? b.scope.ids : []).map(Number).filter(Number.isFinite).slice(0, 500),
        },
      };
      if (promo.starts && promo.ends && promo.ends < promo.starts) return bad("The offer ends before it starts", 400);

      const at = promos.findIndex(x => x.id === promo.id);
      if (at >= 0) promos[at] = promo; else promos.push(promo);
      if (promos.length > 40) return bad("That is a lot of offers. Delete some old ones first.", 400);

      const saved = await savePricing(env, { ...current, promos });
      await audit(env, actor, "promo_saved", promo.name + " " + promo.kind + " " + promo.value);
      return json({ promos: saved.promos });
    }

    const promoDel = p.match(/^\/admin\/pricing\/promo\/(.+)$/);
    if (promoDel && request.method === "DELETE") {
      const id = decodeURIComponent(promoDel[1]);
      const current = await getPricing(env);
      const promos = current.promos.filter(x => x.id !== id);
      if (promos.length === current.promos.length) return bad("No offer with that id", 404);
      const saved = await savePricing(env, { ...current, promos });
      await audit(env, actor, "promo_deleted", id);
      return json({ promos: saved.promos });
    }

    if (p === "/admin/pricing/override" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      if (b.id == null) return bad("Missing tyre id");
      const current = await getPricing(env);
      const overrides = { ...current.overrides };
      // null / "" clears the override, returning the tyre to calculated pricing.
      if (b.price == null || b.price === "") delete overrides[String(b.id)];
      else {
        const v = Number(b.price);
        if (!Number.isFinite(v) || v <= 0) return bad("Price must be a positive number", 400);
        overrides[String(b.id)] = Math.round(v * 100) / 100;
      }
      const saved = await savePricing(env, { ...current, overrides });
      return json({ pricing: saved, overrideCount: Object.keys(saved.overrides).length });
    }

    if (p === "/admin/pricing/stock" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const current = await getPricing(env);
      let inStock = new Set(current.inStock);

      if (Array.isArray(b.ids)) {
        inStock = new Set(b.ids.map(Number).filter(Number.isFinite)); // bulk replace
      } else if (b.id != null) {
        const id = Number(b.id);
        if (b.inStock === false) inStock.delete(id); else inStock.add(id);
      } else {
        return bad("Send { id, inStock } or { ids: [...] }");
      }
      const saved = await savePricing(env, { ...current, inStock: [...inStock] });
      return json({ inStock: saved.inStock, count: saved.inStock.length });
    }

    if (p === "/admin/tyres" && request.method === "GET") {
      const size = url.searchParams.get("size");
      if (!size) return bad("Add ?size= e.g. 195/65R15");
      const { catalogue, costMap } = await tyreData(env);
      const pricing = await getPricing(env);
      return json({ ...lookupBySizeAdmin(catalogue, costMap, size, pricing), pricing });
    }

    /*
     * End-to-end channel test. POST {} and it exercises whatever is configured —
     * email to the owner, WhatsApp/SMS to OWNER_PHONE, and a calendar event —
     * reporting exactly what worked and what did not. Use this to prove the
     * client's three channels are live without taking a real booking.
     */
    /*
     * One test email, to the owner, through whichever service is currently
     * chosen. Separate from /admin/test-channels because that one also fires
     * an SMS and writes a calendar event — a button for "did the email switch
     * work" should not cost a text message every time it is pressed.
     *
     * Owner or developer: it sends real mail, and the reply names the service,
     * which is how you tell a working switch from a silent one.
     */
    if (p === "/admin/test-email" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      const via = await mailProvider(env);
      if (!via) return bad("No email service is configured, so there is nothing to test.", 400);
      const to = env.OWNER_EMAIL || env.MAIL_FROM;
      const stamp = new Date().toLocaleString("en-GB", { timeZone: "Europe/London" });
      const name = via === "twilio" ? "Twilio Email" : "Resend";
      const res = await sendEmail(env, to,
        BUSINESS.shortName + " — test email (" + name + ")",
        `This is a test from your booking system, sent ${stamp}.\n\n`
        + `It went out through ${name}. If you can read this, booking confirmations will reach customers the same way.\n\n`
        + `If it never arrives, switch back to the other service in the dashboard — nothing else changes.`);
      return json({ ok: !!(res && res.ok), via, to, reason: (res && res.reason) || "", skipped: !!(res && res.skipped) });
    }

    if (p === "/admin/test-channels" && request.method === "POST") {
      const stamp = new Date().toLocaleString("en-GB", { timeZone: "Europe/London" });
      const results = {};

      // Live check of the paid vehicle-lookup key. /api/health only reports
      // that a key is SET, which is how an invalid key sat there reporting
      // vehicleLookup:true while every call came back UnknownApiKey.
      results.vehicleLookup = await (async () => {
        if (!env.UKVD_API_KEY) return { skipped: true, reason: "UKVD_API_KEY not set" };
        try {
          const base = (env.UKVD_BASE || "https://uk.api.vehicledataglobal.com/r2/lookup").replace(/\/+$/, "");
          const r = await fetch(`${base}?packagename=${encodeURIComponent(UKVD_PACKAGE)}&apikey=${encodeURIComponent(env.UKVD_API_KEY)}&vrm=AA19AAA`, { headers: { accept: "application/json" } });
          const d = await r.json().catch(() => ({}));
          const info = d.ResponseInformation || {};
          // StatusCode 7 = UnknownApiKey. A "vehicle not found" for the dummy
          // plate is a PASS: it proves the key was accepted.
          if (info.StatusMessage === "UnknownApiKey") return { ok: false, reason: "The UKVD API key is rejected — regenerate it and set UKVD_API_KEY." };
          return { ok: true, reason: info.StatusMessage || "Key accepted" };
        } catch (err) { return { ok: false, reason: "Could not reach UK Vehicle Data: " + err.message }; }
      })();

      // Is RESEND_AUDIENCE_ID actually an AUDIENCE? Resend's dashboard also
      // shows *segment* ids in its URLs, and the two look identical — both are
      // plain UUIDs. Pointing this at a segment means every consented contact
      // sync silently 404s, which is invisible until someone asks why the
      // mailing list is empty.
      const checkAudience = async (id, what, whenMissing) => {
        if (!id) return { skipped: true, reason: whenMissing };
        if (!env.RESEND_API_KEY) return { skipped: true, reason: "RESEND_API_KEY not set" };
        try {
          const r = await fetch("https://api.resend.com/audiences/" + encodeURIComponent(id), {
            headers: { authorization: "Bearer " + env.RESEND_API_KEY },
          });
          if (r.ok) {
            const d = await r.json().catch(() => ({}));
            return { ok: true, reason: what + " audience found: " + (d.name || d.id || "unnamed") };
          }
          if (r.status === 404) return { ok: false, reason: "No audience with that id. It is probably a SEGMENT id — open Resend → Audience → Contacts and take the id from the audience itself, not the Segments tab." };
          return { ok: false, reason: "Resend returned " + r.status };
        } catch (err) { return { ok: false, reason: "Could not reach Resend: " + err.message }; }
      };
      results.audience = await checkAudience(env.RESEND_AUDIENCE_ID, "Marketing",
        "RESEND_AUDIENCE_ID not set — the marketing tick is recorded, nothing is synced");
      results.customerAudience = await checkAudience(env.RESEND_CUSTOMER_AUDIENCE_ID, "Customer",
        "RESEND_CUSTOMER_AUDIENCE_ID not set — customers are kept in the dashboard only, nothing is synced");

      const mailVia = await mailProvider(env);
      const mailViaName = mailVia === "twilio" ? "Twilio Email" : "Resend";
      results.email = mailVia
        ? { ...(await sendEmail(env, env.OWNER_EMAIL || env.MAIL_FROM,
            BUSINESS.shortName + " — test email",
            `This is a test from your booking system, sent ${stamp}.\n\nIt went out through ${mailViaName}. If you can read this, confirmations will reach customers.\nReply to this message to check the inbound forwarding on ${env.MAIL_FROM} as well.`)), via: mailVia }
        : { skipped: true, reason: "No email service is configured — set RESEND_API_KEY, or Twilio credentials, plus MAIL_FROM." };

      results.phone = env.OWNER_PHONE
        ? await sendSMS(env, env.OWNER_PHONE, `${BUSINESS.shortName}: test message sent ${stamp}. Your booking alerts are working.`, { essential: false })
        : { skipped: true, reason: "OWNER_PHONE not set" };

      results.calendar = await addCalendarEvent(env, {
        ref: "CMS-TEST", svcLabel: "System test — safe to delete",
        date: londonDate(0), postcode: "Bridport", notes: "Automated channel test.",
      }, env.OWNER_EMAIL || env.MAIL_FROM || "");

      results.channelInUse = (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID)
        ? "WhatsApp" : (env.TWILIO_SID ? "Twilio SMS" : "none configured");

      /*
       * Does the HubSpot token actually have the scopes to WRITE?
       *
       * /api/health reports crmSync:true as soon as HUBSPOT_TOKEN is set, which
       * says nothing about what the token may do. A read-only token
       * authenticates perfectly and then 403s on every write, so the CRM sync
       * looks configured, looks healthy, and silently never creates anybody.
       * That is the same trap the vehicle-lookup check above exists for.
       *
       * HubSpot will list a token's own scopes, so this proves the permissions
       * without creating a junk contact just to find out.
       */
      results.crm = await (async () => {
        if (!env.HUBSPOT_TOKEN) return { skipped: true, reason: "HUBSPOT_TOKEN not set — bookings are not reaching the CRM" };
        try {
          const r = await fetch("https://api.hubapi.com/oauth/v2/private-apps/get/access-token-info", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ tokenKey: env.HUBSPOT_TOKEN }),
          });
          if (!r.ok) {
            if (r.status === 401) return { ok: false, reason: "HubSpot rejected the token. If it was pasted from a developer project or an MCP auth app, that is the wrong kind — this needs a Private App token." };
            return { ok: false, reason: "HubSpot returned " + r.status + " when asked about the token." };
          }
          const d = await r.json().catch(() => ({}));
          const scopes = Array.isArray(d.scopes) ? d.scopes : [];
          const needed = ["crm.objects.contacts.write", "crm.objects.deals.write"];
          const missing = needed.filter(sc => !scopes.includes(sc));
          if (missing.length) {
            return { ok: false, reason: "The token is valid but cannot write. Missing: " + missing.join(", ")
              + ". Every booking will 403 without a word. Add those scopes to the Private App and paste the new token." };
          }
          return { ok: true, reason: "Can write contacts and deals" + (d.hubId ? " (portal " + d.hubId + ")" : "") };
        } catch (err) { return { ok: false, reason: "Could not reach HubSpot: " + err.message }; }
      })();

      /*
       * Stripe. The secret key can be proved outright; the webhook secret
       * cannot, because only a real signed event exercises it — and that one
       * is the important half, since the webhook is the ONLY thing permitted to
       * mark a job paid. Say so rather than implying both were checked.
       */
      results.payments = await (async () => {
        if ((await paymentProvider(env)) === "sumup") {
          // Prove the credentials AND the merchant code together. Valid
          // credentials with the wrong merchant code create checkouts against
          // somebody else's account — the one failure here that moves real
          // money to the wrong place — so it is worth an explicit check.
          const auth = await sumupAuth(env);
          const me = await sumupCall(env, "GET", "/me");
          if (!me.ok) {
            return { ok: false, reason: "SumUp rejected the credentials: " + (me.reason || "unknown") };
          }
          const merchant = me.data && me.data.merchant_profile && me.data.merchant_profile.merchant_code;
          if (merchant && auth.merchant && merchant !== auth.merchant) {
            return { ok: false, reason: "The credentials belong to merchant " + merchant
              + " but the configured merchant code is " + auth.merchant
              + ". Payments would be raised against the wrong account." };
          }
          if (!merchant && !auth.merchant) return { ok: false, reason: "SumUp accepted the credentials but no merchant code is known." };
          return { ok: true, reason: "SumUp connected for merchant " + (merchant || auth.merchant)
            + ". Take a £1 booking to prove the full round trip." };
        }
        if (!env.STRIPE_SECRET_KEY) return { skipped: true, reason: "Card payments are off" };
        try {
          const r = await fetch("https://api.stripe.com/v1/balance", {
            headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY },
          });
          if (!r.ok) {
            const d = await r.json().catch(() => ({}));
            return { ok: false, reason: "Stripe rejected the secret key: " + ((d.error && d.error.message) || r.status) };
          }
          const live = String(env.STRIPE_SECRET_KEY).startsWith("sk_live");
          if (!env.STRIPE_WEBHOOK_SECRET) {
            return { ok: false, reason: "The secret key works, but STRIPE_WEBHOOK_SECRET is not set. Customers could be charged and no job would ever be marked paid." };
          }
          return { ok: true, reason: (live ? "Live" : "TEST MODE") + " key accepted. The webhook secret can only be proved by a real payment — take a £1 booking and check it shows as paid." };
        } catch (err) { return { ok: false, reason: "Could not reach Stripe: " + err.message }; }
      })();

      return json({ sentAt: stamp, results });
    }

    if (p === "/admin/test-reminder" && request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const template = env.WHATSAPP_REMINDER_TEMPLATE || "appointment_reminder";
      if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID) {
        return bad("WhatsApp is not configured — set WHATSAPP_TOKEN and WHATSAPP_PHONE_ID", 503);
      }
      if (b.phone) {
        const res = await sendWhatsAppTemplate(env, b.phone, template, [
          b.name || "there",
          b.svcLabel || "Mobile tyre fitting",
          b.date || londonDate(1),
          b.time || "9am - 12pm",
          b.ref || "CMS-TEST",
        ]);
        return json({ template, sent: !!res.ok, detail: res.detail || res.reason || null });
      }
      const summary = await reminderSweepNow(env);
      return json({ template, ...summary });
    }

    if (p === "/admin/locations" && request.method === "GET") {
      const locKeys = await env.CMS_KV.list({ prefix: "loc:" });
      const locations = [];
      for (const k of locKeys.keys) {
        const jobRef = k.name.slice("loc:".length);
        const data = JSON.parse((await env.CMS_KV.get(k.name)) || "null");
        if (data) locations.push({ jobRef, ...data });
      }
      return json({ locations });
    }

    // Calendar embed link for the dashboard
    if (p === "/admin/calendar" && request.method === "GET") {
      const id = await gcalCalendarId(env);
      const stored = await gcalStored(env);
      // "primary" is meaningless to an embed iframe (it would show whoever is
      // looking, not the business diary), so the embed only uses a real id.
      const embedId = id === "primary" ? "" : id;
      return json({
        calendarId: id,
        connected: await calendarReady(env),
        account: (stored && stored.email) || "",
        canConnect: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
        embedUrl: embedId ? `https://calendar.google.com/calendar/embed?src=${encodeURIComponent(embedId)}&ctz=Europe/London` : "",
      });
    }

    /*
     * The diary itself, read back out of Google.
     *
     * The Calendar tab used to draw only our own job records, which meant the
     * dashboard and the calendar Simon actually keeps could say different
     * things: anything he added in Google — a day off, a private job, a
     * rescheduled slot — was invisible here. And a Google embed iframe is not
     * an answer, because it renders only for a browser already signed in to
     * that exact Google account and is a tall white box for everyone else.
     *
     * So the events are fetched with the connection the site already holds and
     * rendered by us. Read-only, and it fails soft: if Google is unreachable
     * the tab still shows the jobs we know about rather than an error page.
     */
    if (p === "/admin/calendar/events" && request.method === "GET") {
      if (!(await calendarReady(env))) return json({ connected: false, events: [] });
      const tok = await googleToken(env);
      if (!tok) return json({ connected: true, events: [], error: "Google would not renew the connection. Press Connect again." });
      const calId = await gcalCalendarId(env);
      if (!calId) return json({ connected: true, events: [], error: "No calendar is selected yet." });

      // A window either side of now: enough history to see what just happened,
      // and far enough ahead to plan. Clamped so a hand-edited URL cannot ask
      // Google for ten years of events on every dashboard load.
      const days = Math.max(1, Math.min(180, Number(url.searchParams.get("days")) || 62));
      const back = Math.max(0, Math.min(90, Number(url.searchParams.get("back")) || 31));
      const from = new Date(Date.now() - back * 86400000).toISOString();
      const to = new Date(Date.now() + days * 86400000).toISOString();

      const q = new URLSearchParams({
        timeMin: from, timeMax: to,
        singleEvents: "true",       // expand recurring events into real slots
        orderBy: "startTime",
        maxResults: "250",
        timeZone: "Europe/London",
      });
      const r = await fetch(
        `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events?` + q,
        { headers: { authorization: "Bearer " + tok } }).catch(() => null);
      if (!r || !r.ok) {
        const detail = r ? await r.text().catch(() => "") : "network error";
        console.error("[gcal] events list failed", r && r.status, String(detail).slice(0, 300));
        return json({ connected: true, events: [], error: "Could not read the calendar from Google." });
      }
      const d = await r.json().catch(() => ({}));
      const events = (d.items || [])
        .filter(e => e.status !== "cancelled")
        .map(e => {
          // An all-day event carries `date`; a timed one carries `dateTime`.
          const allDay = !!(e.start && e.start.date);
          const startsAt = (e.start && (e.start.dateTime || e.start.date)) || "";
          const endsAt = (e.end && (e.end.dateTime || e.end.date)) || "";
          return {
            id: e.id,
            title: e.summary || "(no title)",
            where: e.location || "",
            allDay,
            start: startsAt,
            end: endsAt,
            // The date key the dashboard groups by, in local terms rather than
            // UTC — a 00:30 job must not land on the previous day.
            day: allDay ? String(startsAt).slice(0, 10) : londonDayKey(startsAt),
            link: e.htmlLink || "",
            // Our own bookings write this line into the description; it is how
            // the tab can tell a site booking from something Simon typed in.
            ours: /Service Request Ref:/.test(e.description || ""),
          };
        });
      return json({ connected: true, calendarId: calId, events, from, to });
    }

    /*
     * "Connect Google Calendar" — step one. The dashboard asks for a consent
     * URL; the server mints a one-shot state nonce so the callback can tell a
     * genuine return-from-Google apart from somebody replaying the endpoint.
     * Owner or developer only: connecting a diary is configuration, not
     * day-to-day staff work.
     */
    if (p === "/admin/gcal/connect-url" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
        return bad("The Google connection is not set up yet. The developer needs to add the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET secrets first.", 400);
      }
      const nonce = crypto.randomUUID();
      await env.CMS_KV.put("gcal_state:" + nonce, JSON.stringify({ kind: "connect", actor, t: Date.now() }), { expirationTtl: 600 });
      const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
      const redirectUri = site + "/api/oauth/google/callback";
      const u = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      u.searchParams.set("client_id", env.GOOGLE_CLIENT_ID);
      u.searchParams.set("redirect_uri", redirectUri);
      u.searchParams.set("response_type", "code");
      u.searchParams.set("scope", "https://www.googleapis.com/auth/calendar");
      // Without access_type=offline there is no refresh token, and without
      // prompt=consent Google only issues one on the very first grant — a
      // reconnect would silently come back tokenless.
      u.searchParams.set("access_type", "offline");
      u.searchParams.set("prompt", "consent");
      u.searchParams.set("state", nonce);
      return json({ url: u.toString(), redirectUri });
    }

    if (p === "/admin/gcal/disconnect" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      await env.CMS_KV.delete("gcal_oauth");
      await audit(env, actor, "gcal-disconnected", "");
      return json({ ok: true });
    }

    /*
     * "Connect SumUp" — the client signs in with his own SumUp account, the
     * same shape as the Google Calendar connect. Owner/developer only.
     */
    if (p === "/admin/sumup/connect-url" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      if (!env.SUMUP_CLIENT_ID || !env.SUMUP_CLIENT_SECRET) {
        return bad("The SumUp connection is not set up yet. The developer needs to add the SUMUP_CLIENT_ID and SUMUP_CLIENT_SECRET secrets first.", 400);
      }
      const nonce = crypto.randomUUID();
      await env.CMS_KV.put("gcal_state:" + nonce, JSON.stringify({ kind: "sumup", actor, t: Date.now() }), { expirationTtl: 600 });
      const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
      const u = new URL("https://api.sumup.com/authorize");
      u.searchParams.set("response_type", "code");
      u.searchParams.set("client_id", env.SUMUP_CLIENT_ID);
      u.searchParams.set("redirect_uri", site + "/api/oauth/sumup/callback");
      /*
       * Exactly the two scopes this system uses, and no more.
       *
       *   payments             POST /checkouts and GET /checkouts/{id} — taking
       *                        the money, and verifying it was really taken.
       *   user.profile_readonly  GET /me, read once at connect time to learn the
       *                        merchant code from SumUp rather than have anybody
       *                        type it and get it wrong.
       *
       * transactions.history is deliberately NOT requested. Nothing reads a
       * transaction list, and asking a client to hand over their financial
       * history "in case we need it later" is the opposite of what the rest of
       * this integration promises them. If a reconciliation view is built one
       * day, adding the scope costs the client one more button press.
       *
       * "payments" is a RESTRICTED scope: SumUp enables it per app on request.
       * Until they do, the consent screen will refuse it — that is expected,
       * not a bug in this code.
       */
      u.searchParams.set("scope", "payments user.profile_readonly");
      u.searchParams.set("state", nonce);
      return json({ url: u.toString(), redirectUri: site + "/api/oauth/sumup/callback" });
    }

    if (p === "/admin/sumup/disconnect" && request.method === "POST") {
      const deny = needs("developer");
      if (deny) return deny;
      await env.CMS_KV.delete("sumup_oauth");
      await audit(env, actor, "sumup-disconnected", "");
      return json({ ok: true });
    }

    /* What the payments panel shows: which provider, whose account, how connected. */
    if (p === "/admin/sumup/status" && request.method === "GET") {
      const s = await sumupStored(env);
      return json({
        provider: await paymentProvider(env),
        viaApiKey: !!(env.SUMUP_API_KEY && env.SUMUP_MERCHANT_CODE),
        connected: !!(s && s.refresh_token),
        merchant: (env.SUMUP_MERCHANT_CODE || (s && s.merchant_code)) || "",
        account: (s && s.email) || "",
        canConnect: !!(env.SUMUP_CLIENT_ID && env.SUMUP_CLIENT_SECRET),
      });
    }

    /*
     * The tyre catalogue as a SumUp-importable CSV. SumUp has no public
     * catalogue API, so this is the honest version of "keep SumUp in step
     * with the site": one click exports every priced tyre at TODAY'S retail
     * price, with the site's image URL, ready for the Items import in the
     * SumUp dashboard. Prices on the site itself never depend on this —
     * every checkout is raised at the live site price.
     */
    if (p === "/admin/sumup/items.csv" && request.method === "GET") {
      const { catalogue, costMap } = await tyreData(env);
      const pricing = await getPricing(env);
      const site = env.SITE_URL || "https://cousinsmechanicalservices.co.uk";
      const esc2 = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
      const rows = [["Item name", "Price (GBP)", "Category", "Description", "Image URL", "SKU"]];
      for (const [sizeKey, list] of Object.entries(catalogue)) {
        if (!Array.isArray(list) || !list.length) continue;
        // Same pricing path the live site uses — lookupBySize prices whole
        // sizes through pricedSize, so the CSV can never disagree with the
        // price a customer sees today.
        for (const t of lookupBySize(catalogue, costMap, sizeKey, pricing).tyres) {
          if (t.price == null) continue;
          const tierName = t.tier === "P" ? "Premium tyres" : t.tier === "M" ? "Mid-range tyres" : "Budget tyres";
          rows.push([
            [t.brand, t.model, t.label || sizeKey].filter(Boolean).join(" "),
            Number(t.price).toFixed(2),
            tierName,
            `${t.tierLabel || "Budget"} tyre, fitted at your location — ${sizeKey}. Price includes mobile fitting, balancing and disposal.`,
            t.image ? site + t.image : "",
            t.sku || t.id || "",
          ]);
        }
      }
      await audit(env, actor, "sumup_items_exported", (rows.length - 1) + " items");
      return new Response(rows.map(r => r.map(esc2).join(",")).join("\r\n"), {
        headers: {
          ...SECURITY_HEADERS,
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": 'attachment; filename="sumup-tyre-items.csv"',
        },
      });
    }

    return bad("Not found", 404);
  }

  // --- UK Vehicle Data: plate -> vehicle + tyre ---
  // These two proxy PAID third-party APIs using the client's keys. Open to the
  // world with no limit, a script can burn the whole vehicle-lookup quota — the
  // bill and the outage are the client's. CORS does not help: it restrains
  // browsers, not curl.
  // ADMIN ONLY. These proxy metered third-party APIs on the client's paid
  // accounts. Nothing on the public site calls them — the registration box on
  // the booking form is a plain text field — so leaving them open to the world
  // was pure liability: anyone could run the vehicle-lookup quota to zero and
  // the bill and the outage would be the client's. Rate limiting alone only
  // slows that down; requiring auth removes it.
  if (p === "/ukvd" || p.startsWith("/v1/")) {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);
    if (await edgeLimited(env, "RL_LOOKUP", "lookup:" + clientIp(request))
        || await rateLimited(env, "lookup:" + clientIp(request), 60)) {
      return bad("Too many lookups — slow down.", 429);
    }
    await noteFailure(env, "lookup:" + clientIp(request));
  }

  if (p === "/ukvd" && request.method === "GET") {
    const vrm = (url.searchParams.get("vrm") || "").toUpperCase().replace(/\s+/g, "");
    if (!vrm) return bad("Missing vrm");
    const pkg = url.searchParams.get("package") || UKVD_PACKAGE;
    // Vehicle Data Global (r2) — packagename + apikey + vrm query params.
    const base = (env.UKVD_BASE || "https://uk.api.vehicledataglobal.com/r2/lookup").replace(/\/+$/, "");
    const target = `${base}?packagename=${encodeURIComponent(pkg)}&apikey=${encodeURIComponent(env.UKVD_API_KEY)}&vrm=${encodeURIComponent(vrm)}`;
    const r = await fetch(target, { headers: { accept: "application/json" } }).catch(() => null);
    if (!r) return bad("UK Vehicle Data unreachable", 502);
    return new Response(await r.text(), { status: r.status, headers: { ...CORS, "content-type": "application/json" } });
  }

  // --- tire.vdim.app fitment proxy ---
  if (p.startsWith("/v1/")) {
    const r = await fetch("https://tire.vdim.app/api" + p + url.search, {
      headers: { "x-api-key": env.TIRE_API_KEY, accept: "application/json" },
    }).catch(() => null);
    if (!r) return bad("Tyre API unreachable", 502);
    return new Response(await r.text(), { status: r.status, headers: { ...CORS, "content-type": r.headers.get("content-type") || "application/json" } });
  }

  return bad("Not found", 404);
}

// ---------------------------------------------------------------------------
// Appointment reminders
// ---------------------------------------------------------------------------

/** Current hour (0-23) in Europe/London, handling BST automatically. */
function londonHour() {
  return Number(new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/London", hour: "numeric", hour12: false,
  }).format(new Date()));
}

/**
 * Which London day a timestamp falls on, as YYYY-MM-DD.
 *
 * Not `.slice(0, 10)` on the ISO string: that is the UTC day, so a job at
 * 00:30 on a British Summer Time morning would be filed under the day before
 * and appear in the diary under the wrong heading.
 */
function londonDayKey(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return String(iso || "").slice(0, 10);
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/London", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(d);
}

/** Today's date in Europe/London as YYYY-MM-DD, offset by `addDays`. */
function londonDate(addDays = 0) {
  const d = new Date(Date.now() + addDays * 86400000);
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Europe/London", year: "numeric", month: "2-digit", day: "2-digit",
  }).format(d);
  return parts; // en-CA formats as YYYY-MM-DD
}

/**
 * Send a WhatsApp reminder for every confirmed job happening tomorrow.
 *
 * Runs hourly but only acts at REMINDER_HOUR London time, so customers are not
 * messaged at 3am. Each booking is marked `reminderSent` so a job can never be
 * reminded twice, even if the cron runs late or twice.
 */
const REMINDER_HOUR = 17; // 5pm the day before

async function reminderSweep(env) {
  if (!env.WHATSAPP_TOKEN || !env.WHATSAPP_PHONE_ID) return { skipped: "WhatsApp not configured" };
  if (londonHour() !== REMINDER_HOUR) return { skipped: "not the reminder hour" };
  return reminderSweepNow(env);
}

/** The sweep itself, with no time-of-day guard — used by the admin test endpoint. */
async function reminderSweepNow(env) {
  const template = env.WHATSAPP_REMINDER_TEMPLATE || "appointment_reminder";
  const tomorrow = londonDate(1);
  let sent = 0, failed = 0;

  const list = await env.CMS_KV.list({ prefix: "bookings:" });
  for (const k of list.keys) {
    const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
    let changed = false;

    for (const o of arr) {
      if (o.reminderSent) continue;
      if (o.date !== tomorrow) continue;
      if (o.status === "cancelled" || o.status === "complete") continue;

      // The customer's number: on the booking, else on their account record.
      let phone = o.phone;
      if (!phone) {
        const email = k.name.slice("bookings:".length);
        const u = JSON.parse((await env.CMS_KV.get("user:" + email)) || "null");
        phone = u?.phone;
        // Respect the same opt-out that governs every other message we send.
        if (u && u.smsUpdates === false) continue;
      }
      if (!phone) continue;

      const res = await sendWhatsAppTemplate(env, phone, template, [
        o.name || "there",
        o.svcLabel || "your booking",
        o.date,
        o.time || "during the day",
        o.ref,
      ]);

      if (res.ok) {
        o.reminderSent = Date.now();
        o.updates = [...(o.updates || []), { t: Date.now(), s: "Reminder sent", d: "We sent you a WhatsApp reminder about tomorrow's job." }];
        changed = true;
        sent++;
      } else {
        failed++;
      }
    }

    if (changed) await env.CMS_KV.put(k.name, JSON.stringify(arr));
  }

  if (sent || failed) console.log(`[reminders] sent ${sent}, failed ${failed}, for ${tomorrow}`);
  return { sent, failed, date: tomorrow };
}

// GDPR storage limitation: scheduled purge of finished jobs older than RETENTION_DAYS
async function retentionPolicy(env) {
  const raw = await env.CMS_KV.get("retention_policy");
  return { ...RETENTION, ...(raw ? JSON.parse(raw) : {}) };
}

/**
 * The daily purge.
 *
 * Everything it removes is listed in the audit trail with a count, because a
 * deletion nobody can see is indistinguishable from data loss. It walks each
 * prefix separately rather than everything at once so one bad record cannot
 * stop the rest of the sweep.
 */
async function retentionSweep(env) {
  const P = await retentionPolicy(env);
  const now = Date.now();
  const cut = d => now - d * 86400000;
  const removed = { jobs: 0, contacts: 0, audits: 0, messages: 0, slots: 0, mailLog: 0 };

  const eachKey = async (prefix, fn) => {
    let cursor;
    do {
      const page = await env.CMS_KV.list({ prefix, cursor });
      for (const k of page.keys) { try { await fn(k.name); } catch (e) { console.error("[retention]", k.name, e && e.message); } }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
  };

  // Finished jobs only. An open job is never purged however old it is —
  // something still outstanding is not a record we are done with.
  await eachKey("bookings:", async (key) => {
    const arr = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    const kept = arr.filter(o => {
      const finished = o.status === "cancelled" || o.status === "complete";
      return !(finished && (o.createdAt || 0) < cut(P.jobDays));
    });
    if (kept.length !== arr.length) {
      removed.jobs += arr.length - kept.length;
      if (kept.length) await env.CMS_KV.put(key, JSON.stringify(kept));
      else await env.CMS_KV.delete(key);
    }
  });

  // A contact goes when they have neither booked nor been in touch in the
  // window — and never while they still have a job on file.
  await eachKey("contact:", async (key) => {
    const c = JSON.parse((await env.CMS_KV.get(key)) || "{}");
    const last = Math.max(Number(c.lastSeenAt) || 0, Number(c.firstSeenAt) || 0);
    if (!last || last >= cut(P.contactDays)) return;
    const email = key.slice("contact:".length);
    const jobs = JSON.parse((await env.CMS_KV.get("bookings:" + email)) || "[]");
    if (jobs.length) return;
    // An account holder is not a stale contact — they can still sign in.
    if (await env.CMS_KV.get("user:" + email)) return;
    await env.CMS_KV.delete(key);
    await env.CMS_KV.delete("crm:" + email);
    removed.contacts += 1;
  });

  await eachKey("audit:", async (key) => {
    const log = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    const kept = log.filter(e => (e.t || 0) >= cut(P.auditDays));
    if (kept.length === log.length) return;
    removed.audits += log.length - kept.length;
    if (kept.length) await env.CMS_KV.put(key, JSON.stringify(kept));
    else await env.CMS_KV.delete(key);
  });

  await eachKey("msgs:", async (key) => {
    const thread = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    const kept = thread.filter(m => (m.t || 0) >= cut(P.messageDays));
    if (kept.length === thread.length) return;
    removed.messages += thread.length - kept.length;
    if (kept.length) await env.CMS_KV.put(key, JSON.stringify(kept));
    else await env.CMS_KV.delete(key);
  });

  // Operational only — no personal data, just counters for days long past.
  await eachKey("slots:", async (key) => {
    const date = key.slice("slots:".length);
    const t = new Date(date + "T12:00:00Z").getTime();
    if (Number.isFinite(t) && t < cut(P.slotDays)) { await env.CMS_KV.delete(key); removed.slots += 1; }
  });

  const log = JSON.parse((await env.CMS_KV.get("maillog")) || "[]");
  const keptLog = log.filter(e => (e.t || 0) >= cut(P.mailLogDays));
  if (keptLog.length !== log.length) {
    removed.mailLog = log.length - keptLog.length;
    await env.CMS_KV.put("maillog", JSON.stringify(keptLog));
  }

  const total = Object.values(removed).reduce((a, b) => a + b, 0);
  if (total) await audit(env, "system", "retention_sweep", JSON.stringify(removed));
  await env.CMS_KV.put("retention_last_run", JSON.stringify({ t: now, removed }));
  return removed;
}

/**
 * Daily health check.
 *
 * The dashboard banner only reaches somebody who opens the dashboard. A quiet
 * weekend where every confirmation failed would look exactly like a quiet
 * weekend, so once a day the system checks itself and says so.
 */
async function healthSweep(env) {
  const problems = [];
  if (!validEmail(env.MAIL_FROM)) problems.push("MAIL_FROM is not a valid email address — nothing can be sent at all.");
  else if (!resendMailReady(env) && !twilioMailReady(env)) {
    problems.push("No email service is configured — neither Resend nor Twilio can send, so nothing is going out.");
  }
  if (!validEmail(env.OWNER_EMAIL)) problems.push("OWNER_EMAIL is not a valid address — new-job alerts are falling back to MAIL_FROM.");
  if (!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM)) problems.push("Twilio is not configured — customers get no texts.");
  if (!(await calendarReady(env))) problems.push("Google Calendar is not connected — bookings are not checked against your diary.");

  const fails = JSON.parse((await env.CMS_KV.get("maillog")) || "[]");
  const dayAgo = Date.now() - 86400000;
  const recent = fails.filter(f => (f.t || 0) > dayAgo);
  if (recent.length) problems.push(recent.length + " message" + (recent.length === 1 ? "" : "s") + " failed to send in the last 24 hours. Open the dashboard — the people affected are named there.");

  // Say nothing when there is nothing to say. An alert that arrives every day
  // stops being read by the end of the first week.
  if (!problems.length) return { ok: true };

  // Always hand the problems back, even when there is nowhere to email them.
  // Swallowing the findings because the alert could not be delivered is the
  // same class of mistake as the confirmations outage — the check would look
  // like it had passed.
  const to = validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM;
  if (!to) return { ok: false, problems, alerted: false, reason: "nowhere to send the alert" };
  await sendEmail(env, to, "Cousins booking system — " + problems.length + " thing" + (problems.length === 1 ? "" : "s") + " needs attention",
    "The daily check found the following:\n\n" + problems.map((p, i) => (i + 1) + ". " + p).join("\n\n")
    + "\n\nDashboard: " + (env.SITE_URL || "") + "/admin"
    + "\n\nThis email is sent once a day, and only when something is wrong.");
  return { ok: false, problems, alerted: true };
}

/**
 * Weekly off-platform backup.
 *
 * Cloudflare KV has no point-in-time restore: an overwritten key is simply
 * gone. A copy that lives in an inbox is a worse backup than a real one and a
 * far better backup than none, which is what there was.
 */
async function backupSweep(env) {
  const to = validEmail(env.OWNER_EMAIL) ? env.OWNER_EMAIL : env.MAIL_FROM;
  if (!to || !(await mailProvider(env))) return { skipped: true };
  const EXCLUDE = ["sess:", "asess:", "dsess:", "rl:", "reset:", "verify:", "dverify:", "admin_totp"];
  const data = {};
  let cursor;
  do {
    const page = await env.CMS_KV.list({ cursor });
    for (const k of page.keys) {
      if (EXCLUDE.some(pre => k.name.startsWith(pre))) continue;
      const raw = await env.CMS_KV.get(k.name);
      if (raw == null) continue;
      let val; try { val = JSON.parse(raw); } catch { val = raw; }
      if (val && typeof val === "object") {
        if (k.name.startsWith("user:") || k.name.startsWith("staff:")) { delete val.salt; delete val.hash; }
        if (k.name === "drivers" && Array.isArray(val)) val = val.map(d => { const c = { ...d }; delete c.salt; delete c.hash; return c; });
      }
      data[k.name] = val;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  const stamp = new Date().toISOString().slice(0, 10);
  const body = JSON.stringify({ exportedAt: new Date().toISOString(), keys: Object.keys(data).length, data }, null, 2);
  // Through sendEmail rather than straight at one provider's API: the backup
  // is email like any other, and it used to be the one message that ignored
  // which service the owner had chosen.
  const res = await sendEmail(env, to,
    "Weekly backup — " + stamp + " (" + Object.keys(data).length + " records)",
    "Attached is this week's copy of the booking system's data.\n\n"
      + "Passwords and 2FA seeds are deliberately excluded. Keep it somewhere private —\n"
      + "it contains customers' names, addresses and phone numbers.\n\n"
      + "Records: " + Object.keys(data).length,
    null,
    { attachments: [{ filename: "cousins-backup-" + stamp + ".json", contentType: "application/json", content: b64utf8(body) }] });
  const ok = !!(res && res.ok);
  if (!ok) await noteMailFailure(env, to, "weekly backup", { reason: (res && res.reason) || "the send did not go out" });
  await env.CMS_KV.put("backup_last_run", JSON.stringify({ t: Date.now(), ok, keys: Object.keys(data).length }));
  return { ok };
}

export default {
  async fetch(request, env, ctx) {
    // Resolve the allowed origin once per request; json()/bad() read this.
    CORS = corsFor(request, env);

    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(request.url);

    /*
     * One canonical address for the site: https, no www.
     *
     * Both were live. http://cousinsmechanicalservices.co.uk answered 200 over
     * plain HTTP rather than redirecting, so anyone who typed the domain (or
     * followed an old link) got an unencrypted page — and the HSTS header the
     * asset path sets is ignored by browsers over http, so it could not fix
     * itself. www.<domain> served the same pages on a second hostname, which is
     * two URLs for every page as far as a crawler is concerned.
     *
     * Done here rather than as a Cloudflare redirect rule because
     * run_worker_first means this code sees the request first anyway, and a
     * rule in a dashboard is invisible to `git log` and to the test suite.
     *
     * The admin hostname is deliberately left alone apart from the scheme:
     * admin.<domain> is its own portal, not a duplicate of the public site.
     * Local development is exempt — server.js speaks http on localhost.
     */
    {
      const host = url.hostname;
      const local = host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "[::1]" || host.endsWith(".local");
      const visitor = request.headers.get("cf-visitor") || "";
      const insecure = url.protocol === "http:" || /"scheme"\s*:\s*"http"/.test(visitor);
      const wwwed = host.startsWith("www.");
      if (!local && (insecure || wwwed)) {
        const to = new URL(url.toString());
        to.protocol = "https:";
        if (wwwed) to.hostname = host.slice(4);
        // 301: this is permanent, and a 302 would leave the wrong URL in every
        // crawler's index and every browser's address bar for good.
        return new Response(null, {
          status: 301,
          headers: {
            location: to.toString(),
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "cache-control": "public, max-age=3600",
          },
        });
      }
    }

    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env, url, ctx);
      } catch (err) {
        // Never leak a stack trace to the caller, but do log it for `wrangler tail`.
        console.error("[api]", url.pathname, err && err.stack ? err.stack : err);
        return bad("Something went wrong handling that request.", 500);
      }
    }

    /*
     * Apple's domain verification.
     *
     * Registering the site as a Sign in with Apple return URL means proving
     * the domain is ours: Apple hands over a token file and then fetches it
     * from /.well-known/ on the apex. It has to be served by the Worker rather
     * than dropped in public/, because run_worker_first sends every request
     * here first and the assets pipeline is not dependable for dot-directories.
     *
     * The token is not a secret — it is a public proof of control — but it is
     * set the same way as everything else so there is one place to look:
     *   npx wrangler secret put APPLE_DOMAIN_ASSOCIATION
     *
     * Apple also accepts the file at the site root, so both are served.
     */
    if (url.pathname === "/.well-known/apple-developer-domain-association.txt"
        || url.pathname === "/apple-developer-domain-association.txt") {
      if (!env.APPLE_DOMAIN_ASSOCIATION) {
        return new Response("Not configured. Set the APPLE_DOMAIN_ASSOCIATION secret to the file Apple gave you.", {
          status: 404,
          headers: { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8" },
        });
      }
      return new Response(env.APPLE_DOMAIN_ASSOCIATION, {
        headers: {
          ...SECURITY_HEADERS,
          "content-type": "text/plain; charset=utf-8",
          // Apple re-checks periodically; let it, rather than serving a stale
          // copy from a cache after the token is rotated.
          "cache-control": "no-store",
        },
      });
    }

    // ---------------------------------------------------------------
    // admin.<domain> is the staff dashboard on its own hostname: its root
    // serves admin.html, and the whole host is blocked from search engines
    // (the apex robots.txt only covers the apex).
    // ---------------------------------------------------------------
    let assetRequest = request;
    if (url.hostname.split(".")[0] === "admin") {
      if (url.pathname === "/robots.txt") {
        return new Response("User-agent: *\nDisallow: /\n", {
          headers: { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8", "X-Robots-Tag": "noindex, nofollow" },
        });
      }
      if (url.pathname === "/" || url.pathname === "") {
        // "/admin", not "/admin.html": the assets pipeline redirects the .html
        // form to the extensionless one, so asking for the file by name made
        // the staff portal's front door a 307 followed by a 200 on every visit.
        assetRequest = new Request(new URL("/admin", url).toString(), request);
      }
    }

    if (env.ASSETS) {
      const res = await env.ASSETS.fetch(assetRequest);
      // Security headers on the HTML pages too, not just the API.
      const headers = new Headers(res.headers);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
      headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      if (url.hostname.split(".")[0] === "admin") headers.set("X-Robots-Tag", "noindex, nofollow");
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    }
    return new Response("API worker running. Bind ASSETS to serve the site, or call /api/*.", { status: 200 });
  },
  async scheduled(event, env, ctx) {
    // The cron fires hourly. Reminders decide for themselves whether it is the
    // right hour; the GDPR purge only needs to run once a day.
    ctx.waitUntil(reminderSweep(env).catch(e => console.error("[reminders]", e)));
    // Hourly, so the warning arrives while there is still time to act on it.
    ctx.waitUntil(spendWatch(env).catch(e => console.error("[spend]", e)));
    if (londonHour() === 3) {
      ctx.waitUntil(retentionSweep(env).catch(e => console.error("[retention]", e)));
    }
    // 7am, so the alert is read with the first coffee rather than at 3am.
    if (londonHour() === 7) {
      ctx.waitUntil(healthSweep(env).catch(e => console.error("[health]", e)));
    }
    // Monday 4am.
    if (londonHour() === 4 && new Date().getUTCDay() === 1) {
      ctx.waitUntil(backupSweep(env).catch(e => console.error("[backup]", e)));
    }
  },
};
