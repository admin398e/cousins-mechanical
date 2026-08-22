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
 *      GCAL_CLIENT_EMAIL     Google service-account email
 *      GCAL_PRIVATE_KEY      service-account private key (PEM, keep the \n newlines)
 *      GCAL_CALENDAR_ID      calendar id the invites land on (share it with the service account)
 *      RESEND_API_KEY        Resend API key (resend.com — free 3,000 emails/mo)
 *      MAIL_FROM             from address on a domain verified in Resend, e.g. bookings@cousinsmechanicalservices.co.uk
 *      TWILIO_SID / TWILIO_TOKEN   Twilio subaccount credentials.
 *      TWILIO_FROM                 The Twilio number in +44… form, e.g. +447576549872.
 *      TWILIO_STUDIO_FLOW_SID      Optional. FW… — when set, booking confirmations run
 *                                  through the Studio flow so the wording can be edited
 *                                  without a deploy. Falls back to the Messages API.
 *      HUBSPOT_PORTAL_ID           Optional. Numeric portal id; switches on the tracking
 *                                  script on the public site and the CRM links in admin.
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
const RETENTION_DAYS = 365; // GDPR storage limitation: purge finished jobs after this
const LOCATION_TTL_SEC = 3600; // live driver GPS is transient — expires an hour after the job
const RESET_TOKEN_TTL_SEC = 3600; // password-reset links are valid for one hour
const PRIVACY_VERSION = "2026-08-05"; // bump when your privacy notice changes to re-request consent

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
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
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

  const subject = "Your Cousins Mechanical confirmation code: " + code;
  const text = `Hi ${name || "there"},\n\n`
    + `Your confirmation code is ${code}\n\n`
    + `Enter it on the site to finish setting up your account. It expires in 30 minutes.\n\n`
    + `If you did not try to create an account with Cousins Mechanical Services, you can ignore this email — `
    + `nothing has been set up and nobody can use your address without this code.\n\n`
    + `Cousins Mechanical Services Ltd\nRegistered in England & Wales no. 16045339`;

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

async function isAdmin(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return false;

  // A session issued by /admin-login is always valid — that is what the dashboard
  // actually sends. (This used to be rejected whenever 2FA was not yet enrolled,
  // which broke the whole admin portal on a fresh install.)
  const who = await env.CMS_KV.get("asess:" + t);
  if (who != null) {
    // Re-read the staff record on every request. A session alone is not proof
    // of current employment — the account may have been disabled or deleted
    // since the token was issued.
    if (who && who.includes("@")) {
      const raw = await env.CMS_KV.get("staff:" + who);
      if (raw) {
        const acct = JSON.parse(raw);
        if (acct.disabled) { await env.CMS_KV.delete("asess:" + t); return false; }
      }
    }
    return true;
  }

  // Bootstrap only. Before ANY staff account exists the raw admin token is
  // accepted so the owner can reach the dashboard and create one. Once real
  // accounts exist it must stop working as a bearer credential too — not just
  // at /admin-login — or the per-person accountability those accounts provide
  // is bypassable by anyone still holding the old shared secret.
  const staff = await env.CMS_KV.list({ prefix: "staff:" });
  if (staff.keys.length > 0) return false;
  const enrolled = await env.CMS_KV.get("admin_totp");
  if (!enrolled) return safeEqual(t, env.ADMIN_TOKEN);
  return false;
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
    const key = "audit:" + email;
    const log = JSON.parse((await env.CMS_KV.get(key)) || "[]");
    log.push({ t: Date.now(), event, detail: detail || "" });
    await env.CMS_KV.put(key, JSON.stringify(log.slice(-500)));
  } catch (e) {}
}

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
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Cousins Mechanical//EN", "METHOD:REQUEST",
    "BEGIN:VEVENT", "UID:" + o.ref + "@cousinsmechanical", "DTSTAMP:" + stamp, "DTSTART:" + start,
    "SUMMARY:Cousins Mechanical — " + (o.svcLabel || "Mobile job"),
    "DESCRIPTION:Ref " + o.ref + ". " + (o.svcLabel || "") + " for " + (o.reg || "") + ". " + (o.notes || ""),
    "LOCATION:" + (o.postcode || "Your location"),
    "ORGANIZER;CN=Cousins Mechanical:mailto:" + (org || "bookings@cousinsmechanicalservices.co.uk"),
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
async function sendSMS(env, to, body) {
  if (!to) return { skipped: true, reason: "no phone number" };
  const attempts = [];

  if (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID) {
    const wa = await sendWhatsApp(env, to, body);
    if (wa && wa.ok) return { ok: true, channel: "whatsapp" };
    attempts.push("WhatsApp: " + ((wa && (wa.reason || wa.detail)) || "rejected"));
  }

  if (env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM) {
    const form = new URLSearchParams({ To: "+" + toE164(to), From: env.TWILIO_FROM, Body: body });
    const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) },
      body: form,
    }).catch(() => null);
    if (r && r.ok) return { ok: true, channel: "sms" };
    const detail = r ? await r.text().catch(() => "") : "network error";
    attempts.push("Twilio: " + String(detail).slice(0, 200));
  }

  if (!attempts.length) return { skipped: true, reason: "no messaging channel configured" };
  return { ok: false, reason: attempts.join(" | ") };
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
async function googleToken(env) {
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
  if (!tok || !env.GCAL_CALENDAR_ID) {
    return { skipped: true, reason: "Missing GCAL_CLIENT_EMAIL, GCAL_PRIVATE_KEY, or GCAL_CALENDAR_ID environment variables" };
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
    summary: "Cousins Mechanical — " + (o.svcLabel || o.service || "Mobile Service Request"),
    description: `Service Request Ref: ${o.ref || 'NEW'}\nCustomer: ${o.name || 'N/A'}\nPhone: ${o.phone || 'N/A'}\nVehicle Reg: ${o.reg || 'N/A'}\nService: ${o.svcLabel || o.service || ''}\nLocation/Postcode: ${o.postcode || o.location || 'N/A'}\nNotes: ${o.notes || ''}\nTyre Details: ${o.tyreDetails ? (typeof o.tyreDetails === 'string' ? o.tyreDetails : JSON.stringify(o.tyreDetails)) : 'N/A'}`,
    location: o.postcode || o.location || "Bridport & West Dorset",
    start: { dateTime: startIso, timeZone: "Europe/London" },
    end: { dateTime: endIso, timeZone: "Europe/London" },
    attendees: customerEmail ? [{ email: customerEmail }] : (o.email ? [{ email: o.email }] : []),
    reminders: { useDefault: true },
  };

  const insert = (ev, sendUpdates) =>
    fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(env.GCAL_CALENDAR_ID)}/events${sendUpdates ? "?sendUpdates=all" : ""}`, {
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

async function sendEmail(env, to, subject, text, ics, opts) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM || !to) return { skipped: true };
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

  const body = {
    from: "Cousins Mechanical Services <" + env.MAIL_FROM + ">",
    to: [to],
    reply_to: env.MAIL_REPLY_TO || env.MAIL_FROM,
    subject,
    // Always send the plain-text part, even alongside HTML. An HTML-only
    // message is a well-known spam signal, and the text part is what shows in
    // watch/notification previews.
    text,
  };
  if (o.html) body.html = o.html;
  // One-click unsubscribe. Gmail and Yahoo require this on bulk mail, and it is
  // what stops an annoyed recipient reaching for "report spam" instead — which
  // costs far more reputation than an unsubscribe does.
  if (o.unsubscribeUrl) {
    body.headers = {
      "List-Unsubscribe": "<" + o.unsubscribeUrl + ">",
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    };
  }
  if (ics) body.attachments = [{ filename: "booking.ics", content: b64utf8(ics) }];
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
  return { ok: true };
}

// Named exports for the test suite. The Workers runtime only looks at the
// default export, so these cost nothing at runtime but let the tests assert
// that no template variable is left unfilled.
export { renderEmail, EMAIL_BLOCKS, esc };

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
                    <img src="https://cousinsmechanicalservices.co.uk/images/logo.png" alt="Cousins Mechanical Services" width="220" style="max-width: 220px; height: auto; display: block; margin: 0 auto;" />
                  </td>
                </tr>
                <tr>
                  <td style="padding: 40px 30px; color: #2a2a2a;">
{{{content}}}
                  </td>
                </tr>
                <tr>
                  <td style="padding: 30px; text-align: center; background-color: #2a2a2a; color: #9ca3af; font-size: 13px; line-height: 1.5;">
                    <strong style="color: #ffffff; font-size: 14px; display: block; margin-bottom: 10px;">Cousins Mechanical Services Ltd</strong>
                    Mobile Mechanic &bull; Tyre Fitting &bull; Recovery<br />
                    Bridport, Dorchester &amp; West Dorset<br /><br />
                    Call: <a href="tel:07925340977" style="color: #ed6b23;">07925 340977</a> | <a href="tel:01308538046" style="color: #ed6b23;">01308 538046</a><br /><br />
                    <p style="font-size: 12px; color: #6b7280; margin: 0; padding-top: 15px;">
                      Registered in England &amp; Wales no. 16045339<br />
                      7 Watton Park, Bridport, DT6 5NJ<br /><br />
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
<p style="color: #4a4a4a; margin-bottom: 20px;">Thanks for choosing Cousins Mechanical Services. Your booking is confirmed. We'll text you on the day with a live tracking link so you can see exactly when we're arriving.</p>
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
<p style="color: #4a4a4a; margin-bottom: 25px;">Payment is taken on site when the work is done — card or cash. We'll confirm the price with you before any work starts.</p>
<div style="text-align: center; margin-bottom: 25px;">
  <a href="{{{manage_booking_url}}}" class="btn" style="display: inline-block; background-color: #ed6b23; color: #ffffff; font-weight: 600; font-size: 16px; padding: 14px 28px; border-radius: 4px; text-decoration: none;">Track &amp; manage booking</a>
</div>
<p style="color: #4a4a4a; margin-bottom: 0; font-size: 14px;">Need to change or cancel? Call <a href="tel:07925340977" style="color:#ed6b23;">07925 340977</a> or <a href="tel:01308538046" style="color:#ed6b23;">01308 538046</a>, or just reply to this email.</p>`,

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
<p style="color: #4a4a4a; margin-bottom: 0;">Any questions about this payment or the work done, reply to this email or call <a href="tel:07925340977" style="color:#ed6b23;">07925 340977</a>.</p>`,

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
    subject: esc((vars && vars.subject) || "Cousins Mechanical Services"),
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
    jobs.push(sendSMS(env, u.phone, `Cousins Mechanical: booking ${o.ref} confirmed for ${when}. We'll message you when the van's on the way.`));
  jobs.push(addCalendarEvent(env, o, u.email));
  jobs.push(sendEmailTracked(env, null, u.email,
    `Booking confirmed — ${o.ref}`,
    `Hi ${u.name},\n\nYour ${o.svcLabel || "mobile job"} is booked for ${when}.\nRef: ${o.ref}\nVehicle: ${o.reg || "-"}\nWhere: ${o.postcode || "-"}\n\nManage or cancel any time in your account. A calendar invite is attached.\n\nCousins Mechanical`,
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
        email: !!env.RESEND_API_KEY && validEmail(env.MAIL_FROM),
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
        calendar: !!(env.GCAL_CLIENT_EMAIL && env.GCAL_PRIVATE_KEY && env.GCAL_CALENDAR_ID),
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
      + `<title>${title} — Cousins Mechanical Services</title></head>`
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
      sendEmailTracked(env, ctx, em, "Reset your Cousins Mechanical password",
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
Cousins Mechanical Services
Unit 4, Dreadnought Trading Estate
Bridport, Dorset, DT6 5BU
Contact Tel: 07925 340977 / 01308 422000
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
              deliveryAddress: "Unit 4, Dreadnought Trading Estate, Bridport, Dorset, DT6 5BU",
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

    // Public endpoint — no login. It must not send email without limit, or it
    // is an open relay for our own domain's reputation.
    if (await edgeLimited(env, "RL_WRITE", "book:" + clientIp(request))
        || await rateLimited(env, "book:" + clientIp(request), 20)) {
      return bad("Too many booking attempts — please call 07925 340977.", 429);
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
        const subject = `Booking confirmed — ${order.ref} — Cousins Mechanical`;
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
        }, {
          footer_note: `You are receiving this because you booked job ${esc(order.ref)} with us. This is a service message about that job, not marketing.`
            + (unsub ? `<br /><a href="${unsub}" style="color:#6b7280;text-decoration:underline;">Unsubscribe from marketing emails</a>` : ""),
        });

        ctx.waitUntil(recordJobMail(env, emailKey, order.ref, "customer",
          sendEmailTracked(env, null, order.email, subject,
          `Hi ${order.name},\n\nYour booking is confirmed.\n\n${lines}\n\n`
          + `Track it: ${site}/#track=${order.ref}\n\n`
          + `Payment is taken on site when the work is done — card or cash. We will confirm the price with you before any work starts.\n\n`
          + `Need to change or cancel it? Call 01308 538046 or 07925 340977, or reply to this email.\n\n`
          + `Cousins Mechanical Services Ltd\nRegistered in England & Wales no. 16045339\n7 Watton Park, Bridport, DT6 5NJ`,
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
        `Cousins Mechanical: booking ${order.ref} confirmed for ${when.trim()}. `
        + `${order.svcLabel || order.service || "Mobile job"}${order.reg ? " · " + order.reg : ""}. `
        + `We'll message you when the van is on the way. Questions? 07925 340977.`,
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
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `Cousins Mechanical: booking ${list[i].ref} updated to ${list[i].date || ""} ${list[i].time || ""}.`));
      return json({ booking: list[i] });
    }
    if (request.method === "DELETE") {
      list[i] = { ...list[i], status: "cancelled", updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking cancelled", d: "This job was cancelled." }] };
      await env.CMS_KV.put(kvKey, JSON.stringify(list));
      await audit(env, u.email, "booking_cancelled", list[i].ref);
      if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, `Cousins Mechanical: booking ${list[i].ref} cancelled. Re-book any time.`));
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
    if (u.smsUpdates !== false) await sendSMS(env, u.phone, message || `Cousins Mechanical: update on booking ${r}.`);
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
    await audit(env, "admin", "driver_registered", username + " (" + email + ") pending");
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
    await audit(env, "admin", "driver_email_verified", drivers[i].username);

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

  if (p === "/firebase-config" && request.method === "GET") {
    if (!env.FIREBASE_WEB_CONFIG) return bad("Google sign-in is not configured", 404);
    return new Response(env.FIREBASE_WEB_CONFIG, {
      headers: { ...CORS, ...SECURITY_HEADERS, "content-type": "application/json" },
    });
  }

  // Google sign-in for the admin dashboard. The browser gets a Firebase ID
  // token; we verify it SERVER-SIDE with Google Identity Toolkit (so a forged
  // token is useless) and only then check the email against ADMIN_EMAILS.
  // Previously this endpoint existed only in the dev server — on Cloudflare
  // the Google button 404'd.
  if (p === "/admin-login-firebase" && request.method === "POST") {
    const rlKey = "admin:" + clientIp(request);
    // The most important limiters in the file: these guard the staff password,
    // the owner's break-glass token and 2FA enrolment. The KV counter alone was
    // close to useless because KV reads are edge-cached for up to a minute.
    if (await edgeLimited(env, "RL_AUTH", rlKey) || await rateLimited(env, rlKey)) {
      return bad("Too many attempts — try again in 15 minutes", 429);
    }
    if (!env.FIREBASE_WEB_CONFIG) return bad("Google sign-in is not configured", 503);
    const admins = String(env.ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
    if (!admins.length) return bad("ADMIN_EMAILS is not set — refusing to grant admin access", 503);
    let apiKey = "";
    try { apiKey = JSON.parse(env.FIREBASE_WEB_CONFIG).apiKey || ""; } catch {}
    if (!apiKey) return bad("Google sign-in is misconfigured", 503);
    const b = await request.json().catch(() => ({}));
    if (!b.idToken) { await noteFailure(env, rlKey); return bad("Unauthorized", 401); }
    const vr = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" + encodeURIComponent(apiKey), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken: b.idToken }),
    }).catch(() => null);
    const vd = vr && vr.ok ? await vr.json().catch(() => null) : null;
    const u = vd && Array.isArray(vd.users) ? vd.users[0] : null;
    const email = ((u && u.email) || "").toLowerCase();
    if (!u || !email || !u.emailVerified || !admins.includes(email)) {
      await noteFailure(env, rlKey);
      await audit(env, "admin", "admin_login_google_rejected", email || "invalid-token");
      return bad("This account is not an administrator", 403);
    }
    await clearFailures(env, rlKey);
    const t = token();
    await env.CMS_KV.put("asess:" + t, email, { expirationTtl: 60 * 60 * 12 });
    await audit(env, "admin", "admin_login_google", email + " " + clientIp(request));
    return json({ token: t, user: { email, name: u.displayName || email } });
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
      return json({ token: t, who, enrolled: !!(await env.CMS_KV.get("admin_totp")), ...(extra || {}) });
    };

    // Break-glass: OVERRIDE_TOKEN always works and can clear a stuck 2FA, so the
    // owner can never be permanently locked out of his own business.
    if (env.OVERRIDE_TOKEN && safeEqual(b.token, env.OVERRIDE_TOKEN)) {
      if (b.reset2fa) await env.CMS_KV.delete("admin_totp");
      await audit(env, "admin", "admin_login_override", clientIp(request));
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
        await audit(env, "admin", "admin_login_failed", em + " " + clientIp(request));
        return bad("Email or password not recognised", 401);
      }
      const enrolled = await env.CMS_KV.get("admin_totp");
      if (enrolled && !(await totpValid(enrolled, b.code))) {
        await noteFailure(env, rlKey);
        return bad("Enter the 6-digit code from your authenticator app.", 401);
      }
      await clearFailures(env, "staffacct:" + em);
      await audit(env, "admin", "admin_login", em + " " + clientIp(request));
      return issue(em, { name: acct.name || "" });
    }

    // --- Bootstrap only: the shared ADMIN_TOKEN ---
    // Accepted ONLY until the first staff account exists. After that this stops
    // working, so the dashboard is behind a real per-person email + password
    // rather than one shared secret that cannot be attributed or revoked.
    if (!safeEqual(b.token, env.ADMIN_TOKEN)) {
      await noteFailure(env, rlKey);
      await audit(env, "admin", "admin_login_failed", clientIp(request));
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
    await audit(env, "admin", "admin_login_bootstrap", clientIp(request));
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
    if (!safeEqual(b.token, env.ADMIN_TOKEN)) { await noteFailure(env, rlKey); return bad("Invalid admin token", 401); }
    // Refuse to hand out a new secret once 2FA is live — otherwise anyone holding
    // the admin token could silently re-enrol their own authenticator.
    if (await env.CMS_KV.get("admin_totp")) {
      return bad("2FA is already enrolled. Use OVERRIDE_TOKEN with reset2fa to re-enrol.", 409);
    }
    const secret = b32encode(crypto.getRandomValues(new Uint8Array(20)));
    const label = encodeURIComponent("Cousins Mechanical Admin");
    const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=Cousins%20Mechanical&algorithm=SHA1&digits=6&period=30`;
    return json({ secret, otpauth, alreadyEnrolled: false });
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
    if (!safeEqual(b.token, env.ADMIN_TOKEN)) { await noteFailure(env, rlKey); return bad("Invalid admin token", 401); }
    if (await env.CMS_KV.get("admin_totp")) return bad("2FA is already enrolled.", 409);
    if (!b.secret || !(await totpValid(b.secret, b.code))) return bad("That code didn't match — check the app and try again.", 400);
    await env.CMS_KV.put("admin_totp", b.secret);
    await audit(env, "admin", "admin_2fa_enrolled", "");
    return json({ ok: true });
  }
  // Only an admin needs to know whether 2FA is on. Unauthenticated, it told an
  // attacker precisely when a bare ADMIN_TOKEN bearer would still be accepted.
  if (p === "/admin-2fa/status" && request.method === "GET" && !(await isAdmin(request, env))) {
    return bad("Forbidden", 403);
  }
  if (p === "/admin-2fa/status" && request.method === "GET") {
    return json({ enrolled: !!(await env.CMS_KV.get("admin_totp")) });
  }

  // Unauthenticated: lets the login screen show email+password vs first-run
  // setup. Reveals only whether any staff account exists, never who.
  if (p === "/admin-auth/mode" && request.method === "GET") {
    const list = await env.CMS_KV.list({ prefix: "staff:" });
    return json({ staffConfigured: list.keys.length > 0, enrolled: !!(await env.CMS_KV.get("admin_totp")), google: !!(env.FIREBASE_WEB_CONFIG && env.ADMIN_EMAILS) });
  }

  // --- ADMIN (business owner) — all protected by 2FA-verified session ---
  if (p.startsWith("/admin/")) {
    if (!(await isAdmin(request, env))) return bad("Forbidden", 403);

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
            ? `Refund processed — ${job.ref} — Cousins Mechanical`
            : `Payment received — ${job.ref} — Cousins Mechanical`;
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
              + `Cousins Mechanical Services Ltd\nRegistered in England & Wales no. 16045339`
            : `Hi ${job.name},\n\nThanks — we have received your payment of £${amount}.\n\n`
              + `Job: ${job.ref}\nWork: ${job.svcLabel || job.service || "Mobile job"}\nVehicle: ${job.reg || "-"}\n\n`
              + `Keep this email as your receipt.\n\n`
              + `Cousins Mechanical Services Ltd\nRegistered in England & Wales no. 16045339`;
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
        await notifyCustomer(env, ctx, bookings[0] || null, u, "Cousins Mechanical: " + text, "reply");
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
        "Delivery to: Cousins Mechanical Services Ltd, 7 Watton Park, Bridport, DT6 5NJ",
        "Contact: " + (env.MAIL_FROM || "help@cousinsmechanicalservices.co.uk") + " / 07925 340977",
        "",
        "Cousins Mechanical Services Ltd — registered in England & Wales no. 16045339",
      ].join("\n");

      const sent = await sendEmail(env, to, `Tyre order — Cousins Mechanical (${pending.length} line${pending.length === 1 ? "" : "s"})`, body);
      if (!sent || sent.ok === false) return bad("Could not send the order email — check the email settings.", 502);

      for (const i of list) if (i.status === "pending") { i.status = "ordered"; i.orderedAt = Date.now(); }
      await env.CMS_KV.put("reorder_list", JSON.stringify(list));
      await audit(env, "admin", "reorder_list_emailed", to + " (" + pending.length + " lines)");
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
    if (p === "/admin/mail-failures" && request.method === "GET") {
      const log = JSON.parse((await env.CMS_KV.get("maillog")) || "[]");
      return json({
        failures: log,
        ownerEmailValid: validEmail(env.OWNER_EMAIL || env.MAIL_FROM),
        mailFromValid: validEmail(env.MAIL_FROM),
        calendarConfigured: !!(env.GCAL_CLIENT_EMAIL && env.GCAL_PRIVATE_KEY && env.GCAL_CALENDAR_ID),
      });
    }

    if (p === "/admin/mail-failures" && request.method === "DELETE") {
      await env.CMS_KV.delete("maillog");
      return json({ ok: true });
    }

    if (p === "/admin/backup" && request.method === "GET") {
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
      await audit(env, "admin", "backup_downloaded", Object.keys(data).length + " keys");
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
        const b = await request.json().catch(() => ({}));
        const em = String(b.email || "").trim().toLowerCase();
        const pw = String(b.password || "");
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return bad("Enter a valid email address.");
        if (pw.length < 10) return bad("Password must be at least 10 characters.");
        const existingRaw = await env.CMS_KV.get("staff:" + em);
        const existing = existingRaw ? JSON.parse(existingRaw) : null;
        const salt = newSalt();
        const acct = {
          email: em,
          name: String(b.name || existing?.name || "").trim(),
          role: b.role === "owner" ? "owner" : (existing?.role || "staff"),
          salt,
          hash: await pbkdf2(pw, salt, env.SESSION_PEPPER),
          disabled: false,
          createdAt: existing?.createdAt || Date.now(),
          updatedAt: Date.now(),
        };
        await env.CMS_KV.put("staff:" + em, JSON.stringify(acct));
        await audit(env, "admin", existing ? "staff_password_changed" : "staff_created", em);
        return json({ ok: true, staff: { email: acct.email, name: acct.name, role: acct.role, disabled: false, createdAt: acct.createdAt } });
      }
    }

    const staffOne = p.match(/^\/admin\/staff\/([^/]+)$/);
    if (staffOne && (request.method === "DELETE" || request.method === "PATCH")) {
      const em = decodeURIComponent(staffOne[1]).toLowerCase();
      const raw = await env.CMS_KV.get("staff:" + em);
      if (!raw) return bad("Staff account not found", 404);
      const list = await env.CMS_KV.list({ prefix: "staff:" });

      if (request.method === "DELETE") {
        // Refuse to remove the last account — that would lock everyone out and
        // leave only the break-glass OVERRIDE_TOKEN.
        if (list.keys.length <= 1) return bad("This is the only staff account — create another before removing it.", 409);
        await env.CMS_KV.delete("staff:" + em);
        await audit(env, "admin", "staff_deleted", em);
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
        acct.disabled = !!b.disabled;
      }
      if (b.name !== undefined) acct.name = String(b.name).trim();
      acct.updatedAt = Date.now();
      await env.CMS_KV.put("staff:" + em, JSON.stringify(acct));
      // Disabling must take effect now, not at the end of their 12h session.
      if (acct.disabled) await revokeAdminSessions(env, em);
      await audit(env, "admin", "staff_updated", em + " disabled=" + !!acct.disabled);
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
          await audit(env, "admin", "driver_note", b.id + " " + text.slice(0, 60));
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
          await audit(env, "admin", "driver_" + b.action, b.id);
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

        await audit(env, "admin", "driver_deleted", (gone.username || gone.id) + " by " + ((await whoAmI(env, request)) || "admin"));
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
        await audit(env, "admin", "pricing_updated", JSON.stringify(saved.markupPct));
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
      await audit(env, "admin", "promo_saved", promo.name + " " + promo.kind + " " + promo.value);
      return json({ promos: saved.promos });
    }

    const promoDel = p.match(/^\/admin\/pricing\/promo\/(.+)$/);
    if (promoDel && request.method === "DELETE") {
      const id = decodeURIComponent(promoDel[1]);
      const current = await getPricing(env);
      const promos = current.promos.filter(x => x.id !== id);
      if (promos.length === current.promos.length) return bad("No offer with that id", 404);
      const saved = await savePricing(env, { ...current, promos });
      await audit(env, "admin", "promo_deleted", id);
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

      results.email = env.RESEND_API_KEY && env.MAIL_FROM
        ? await sendEmail(env, env.OWNER_EMAIL || env.MAIL_FROM,
            "Cousins Mechanical — test email",
            `This is a test from your booking system, sent ${stamp}.\n\nIf you can read this, Resend is working and confirmations will reach customers.\nReply to this message to check the inbound forwarding on ${env.MAIL_FROM} as well.`)
        : { skipped: true, reason: "RESEND_API_KEY or MAIL_FROM not set" };

      results.phone = env.OWNER_PHONE
        ? await sendSMS(env, env.OWNER_PHONE, `Cousins Mechanical: test message sent ${stamp}. Your booking alerts are working.`)
        : { skipped: true, reason: "OWNER_PHONE not set" };

      results.calendar = await addCalendarEvent(env, {
        ref: "CMS-TEST", svcLabel: "System test — safe to delete",
        date: londonDate(0), postcode: "Bridport", notes: "Automated channel test.",
      }, env.OWNER_EMAIL || env.MAIL_FROM || "");

      results.channelInUse = (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID)
        ? "WhatsApp" : (env.TWILIO_SID ? "Twilio SMS" : "none configured");

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
      const id = env.GCAL_CALENDAR_ID || "";
      return json({ calendarId: id, embedUrl: id ? `https://calendar.google.com/calendar/embed?src=${encodeURIComponent(id)}&ctz=Europe/London` : "" });
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
async function retentionSweep(env) {
  const cutoff = Date.now() - RETENTION_DAYS * 86400000;
  const list = await env.CMS_KV.list({ prefix: "bookings:" });
  for (const k of list.keys) {
    const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
    const kept = arr.filter(o => !((o.status === "cancelled" || o.status === "complete" || o.status === "arrived") && (o.createdAt || 0) < cutoff));
    if (kept.length !== arr.length) await env.CMS_KV.put(k.name, JSON.stringify(kept));
  }
}

export default {
  async fetch(request, env, ctx) {
    // Resolve the allowed origin once per request; json()/bad() read this.
    CORS = corsFor(request, env);

    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await api(request, env, url, ctx);
      } catch (err) {
        // Never leak a stack trace to the caller, but do log it for `wrangler tail`.
        console.error("[api]", url.pathname, err && err.stack ? err.stack : err);
        return bad("Something went wrong handling that request.", 500);
      }
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
        assetRequest = new Request(new URL("/admin.html", url).toString(), request);
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
    if (londonHour() === 3) {
      ctx.waitUntil(retentionSweep(env).catch(e => console.error("[retention]", e)));
    }
  },
};
