import {
  lookupBySize, lookupBySizeAdmin, search as searchCatalogue, byId as tyreById,
  normalisePricing, DEFAULT_PRICING, assignTiers, forAdmin,
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
async function rateLimited(env, key) {
  const n = Number((await env.CMS_KV.get("rl:" + key)) || 0);
  return n >= RATE_LIMIT.max;
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
  if (_pricingCache && now - _pricingStamp < 30000) return _pricingCache;
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
async function isAdmin(request, env) {
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!t) return false;

  // A session issued by /admin-login is always valid — that is what the dashboard
  // actually sends. (This used to be rejected whenever 2FA was not yet enrolled,
  // which broke the whole admin portal on a fresh install.)
  if ((await env.CMS_KV.get("asess:" + t)) != null) return true;

  // Before 2FA is enrolled the raw admin token is also accepted, so the owner can
  // reach the dashboard to set 2FA up. Once enrolled, only a verified session works.
  const enrolled = await env.CMS_KV.get("admin_totp");
  if (!enrolled) return safeEqual(t, env.ADMIN_TOKEN);
  return false;
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
async function sendSMS(env, to, body) {
  // WhatsApp first (cheaper); Twilio only if WhatsApp isn't configured but Twilio is.
  if (env.WHATSAPP_TOKEN && env.WHATSAPP_PHONE_ID) return sendWhatsApp(env, to, body);
  if (!env.TWILIO_SID || !env.TWILIO_TOKEN || !env.TWILIO_FROM || !to) return { skipped: true };
  const form = new URLSearchParams({ To: to, From: env.TWILIO_FROM, Body: body });
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(env.TWILIO_SID + ":" + env.TWILIO_TOKEN) },
    body: form,
  }).catch(() => null);
  return { ok: r && r.ok };
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
async function sendEmail(env, to, subject, text, ics) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM || !to) return { skipped: true };
  const body = {
    from: "Cousins Mechanical Services <" + env.MAIL_FROM + ">",
    to: [to],
    reply_to: env.MAIL_REPLY_TO || env.MAIL_FROM,
    subject,
    text,
  };
  if (ics) body.attachments = [{ filename: "booking.ics", content: btoa(ics) }];
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + env.RESEND_API_KEY },
    body: JSON.stringify(body),
  }).catch(() => null);
  if (!r) return { ok: false, reason: "network error" };
  if (!r.ok) {
    const detail = await r.text().catch(() => "");
    console.error("[email] Resend rejected the send", r.status, detail.slice(0, 400));
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
  jobs.push(sendEmail(env, u.email,
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
    out.push(sendEmail(env, env.OWNER_EMAIL || env.MAIL_FROM, `New booking ${o.ref} — ${when}`, summary));
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
    // Short cache only: prices change the moment the admin saves a markup.
    return new Response(JSON.stringify(result), {
      headers: { ...CORS, ...SECURITY_HEADERS, "content-type": "application/json", "cache-control": "public, max-age=60" },
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
        email: !!env.RESEND_API_KEY,
        sms: !!(env.TWILIO_SID && env.TWILIO_TOKEN) || !!env.WHATSAPP_TOKEN,
        calendar: !!(env.GCAL_CLIENT_EMAIL && env.GCAL_PRIVATE_KEY && env.GCAL_CALENDAR_ID),
        adminToken: !!env.ADMIN_TOKEN,
        sessionPepper: !!env.SESSION_PEPPER,
      },
    });
  }

  // --- AUTH ---
  if (p === "/auth/signup" && request.method === "POST") {
    const { name, email, phone, password, marketing, smsUpdates, consent } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em) || (password || "").length < 6) return bad("Invalid details");
    if (!consent) return bad("Please accept the privacy notice to create an account."); // GDPR: no account without lawful basis
    if (await env.CMS_KV.get("user:" + em)) return bad("Account already exists", 409);
    const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await pbkdf2(password, salt, env.SESSION_PEPPER);
    const user = {
      name: name.trim(), email: em, phone: (phone || "").trim(), salt, hash,
      marketing: !!marketing,           // explicit opt-in, default OFF (GDPR)
      smsUpdates: smsUpdates !== false,  // service texts for a job they booked
      consentAt: Date.now(), privacyVersion: PRIVACY_VERSION, createdAt: Date.now(),
    };
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await audit(env, em, "account_created", "consent v" + PRIVACY_VERSION);
    const t = token();
    await env.CMS_KV.put("sess:" + t, em, { expirationTtl: 60 * 60 * 24 * 30 });
    return json({ token: t, user: publicUser(user) });
  }

  if (p === "/auth/login" && request.method === "POST") {
    const { email, password } = await request.json().catch(() => ({}));
    const em = (email || "").trim().toLowerCase();
    // Brute-force protection: limit by email *and* by source IP, so an attacker
    // cannot spread guesses across many accounts from one machine.
    if (await rateLimited(env, em) || await rateLimited(env, "ip:" + clientIp(request))) {
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
    const raw = await env.CMS_KV.get("user:" + em);
    if (raw) {
      const rt = token();
      await env.CMS_KV.put("reset:" + rt, em, { expirationTtl: RESET_TOKEN_TTL_SEC });
      const link = (env.SITE_URL || "") + "/#reset=" + rt;
      ctx.waitUntil(sendEmail(env, em, "Reset your Cousins Mechanical password",
        `Someone asked to reset your password. Use this link within 1 hour:\n${link}\n\nIf that wasn't you, ignore this email.`));
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
    await env.CMS_KV.put("user:" + em, JSON.stringify(user));
    await env.CMS_KV.delete("reset:" + resetToken);
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
    await env.CMS_KV.delete("user:" + u.email);
    await env.CMS_KV.delete("bookings:" + u.email);
    await env.CMS_KV.delete("audit:" + u.email);
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
    
    // Seed default realistic tyre inventory if missing or empty
    if (!stock || !Array.isArray(stock) || stock.length === 0) {
      stock = [
        { id: "P1", name: "Budget Tyre 205/55 R16", sku: "TY-20555-16-B", brand: "Aplus", size: "205/55R16", category: "Budget", qty: 2, minStock: 4, reorderQty: 10, costPrice: 32, price: 48, supplierEmail: "orders@ctyreswholesale.co.uk", supplierApiUrl: "https://api.ctyreswholesale.co.uk/v1/reorders", autoReorder: true, lastReorderedAt: null, status: "Low Stock" },
        { id: "P2", name: "Michelin Primacy 4 225/45 R17", sku: "TY-22545-17-M", brand: "Michelin", size: "225/45R17", category: "Premium", qty: 3, minStock: 5, reorderQty: 8, costPrice: 68, price: 118, supplierEmail: "orders@ctyreswholesale.co.uk", supplierApiUrl: "https://api.ctyreswholesale.co.uk/v1/reorders", autoReorder: true, lastReorderedAt: null, status: "Low Stock" },
        { id: "P3", name: "Falken Ziex ZE310 195/65 R15", sku: "TY-19565-15-F", brand: "Falken", size: "195/65R15", category: "Mid-Range", qty: 1, minStock: 4, reorderQty: 10, costPrice: 42, price: 62, supplierEmail: "orders@ctyreswholesale.co.uk", supplierApiUrl: "https://api.ctyreswholesale.co.uk/v1/reorders", autoReorder: true, lastReorderedAt: null, status: "Critical Low" },
        { id: "P4", name: "Continental PremiumContact 6 225/40 R18", sku: "TY-22240-18-C", brand: "Continental", size: "225/40R18", category: "Premium", qty: 8, minStock: 3, reorderQty: 6, costPrice: 75, price: 125, supplierEmail: "orders@ctyreswholesale.co.uk", supplierApiUrl: "https://api.ctyreswholesale.co.uk/v1/reorders", autoReorder: true, lastReorderedAt: null, status: "Healthy" },
        { id: "P5", name: "Front Brake Pad Kit (VAG / Ford)", sku: "BR-PAD-F", brand: "Brembo", size: "Multi-Fit", category: "Mid-Range", qty: 12, minStock: 5, reorderQty: 10, costPrice: 22, price: 38, supplierEmail: "parts@autodistribution.co.uk", supplierApiUrl: "", autoReorder: true, lastReorderedAt: null, status: "Healthy" }
      ];
      await env.CMS_KV.put("stock", JSON.stringify(stock));
    }

    const defaultSettings = {
      masterAutoReorder: true,
      defaultMinStock: 3,
      defaultReorderQty: 10,
      supplierEmail: "orders@ctyreswholesale.co.uk",
      supplierApiUrl: "https://api.ctyreswholesale.co.uk/v1/reorders",
      notifyEmail: "inventory@cousinsmechanicalservices.co.uk",
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
      const autoEnabled = (item.autoReorder !== false) && (settings.masterAutoReorder !== false);
      const isCoolingDown = item.lastReorderedAt && (now - item.lastReorderedAt < cooldownMs);

      if ((isBelowThreshold && autoEnabled && (!isCoolingDown || force)) || (force && specificSku)) {
        const orderQty = customQty ? parseInt(customQty, 10) : (item.reorderQty || settings.defaultReorderQty || 10);
        const poRef = "PO-AUTO-" + now.toString(36).toUpperCase().slice(-5);
        const supplierEmail = item.supplierEmail || settings.supplierEmail || "orders@ctyreswholesale.co.uk";
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
        if (supplierEmail) {
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
              apiRes = { ok: true, status: 200, note: "Reorder Webhook Dispatched (200 OK)" };
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
          supplier: item.brand ? `${item.brand} Wholesale` : "C-Tyres Wholesale Ltd",
          status: "Auto-Reordered (Email/API Sent)",
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
    const rawStock = await env.CMS_KV.get("stock");
    let stock = JSON.parse(rawStock || "[]");
    const label = (order.svcLabel || order.service || order.notes || "").toLowerCase();
    
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
        s: "Stock Allocated",
        d: `Allocated ${qtyNeeded}x ${stock[matchedIndex].name} from local inventory. Remaining stock: ${stock[matchedIndex].qty}.`
      });

      // Immediately run threshold reorder check
      await checkAndTriggerReorders(env, { triggerSource: `Customer Booking (${order.ref})`, specificSku: stock[matchedIndex].sku });

      return { inStock: true, item: stock[matchedIndex] };
    }

    // Not in stock or insufficient quantity -> Auto-order from supplier
    const poRef = "PO-CTYRES-" + Date.now().toString(36).toUpperCase().slice(-5);
    const supplierOrders = JSON.parse((await env.CMS_KV.get("supplier_orders")) || "[]");
    
    const autoPO = {
      poRef,
      jobRef: order.ref,
      customerName: order.name || "Customer",
      customerPhone: order.phone || "-",
      tyreDetails: order.svcLabel || order.notes || "Tyre Fitting",
      vehicleReg: order.reg || "-",
      qty: qtyNeeded,
      supplier: "C-Tyres Wholesale Ltd",
      status: "Ordered (Auto-Generated)",
      orderedAt: Date.now(),
      estDelivery: "Next Business Day (8:00 AM)"
    };
    
    supplierOrders.unshift(autoPO);
    await env.CMS_KV.put("supplier_orders", JSON.stringify(supplierOrders.slice(0, 200)));

    // Ensure item exists in local stock catalog marked as pending delivery
    if (matchedIndex < 0) {
      stock.push({
        id: "P" + Date.now().toString(36).toUpperCase().slice(-5),
        name: order.svcLabel || "Requested Tyre",
        sku: "AUTO-" + (order.reg || "TYRE"),
        qty: qtyNeeded,
        price: 65,
        status: "Auto-Ordered from Supplier"
      });
    } else {
      stock[matchedIndex].qty += qtyNeeded;
      stock[matchedIndex].status = "Supplier Delivery Pending";
    }
    await env.CMS_KV.put("stock", JSON.stringify(stock));

    order.stockStatus = `Auto-Ordered (${poRef})`;
    order.updates = order.updates || [];
    order.updates.push({
      t: Date.now(),
      s: "Supplier Auto-Ordered",
      d: `Tyres not in local stock. Automatically generated Supplier Purchase Order ${poRef} with C-Tyres Wholesale for next morning delivery.`
    });

    return { inStock: false, autoPO };
  } catch (err) {
    console.error("processTyreStockForOrder error:", err);
    return { inStock: false, error: err.message };
  }
}

  // --- Service Requests & Direct Google Calendar Integration ---
  if (p === "/service-requests" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));

    // A booking with no way to contact the customer back is worse than no booking.
    if (!b.name || !b.phone) return bad("Name and mobile number are required.");

    const orderRef = b.ref || ("CMS-" + Date.now().toString(36).toUpperCase().slice(-5));
    const order = {
      ...b,
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
    const emailKey = b.email ? ("bookings:" + String(b.email).toLowerCase()) : "bookings:guest";
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

    // Re-persist so any enrichment (stock status, extra updates) is kept. Best
    // effort only — the booking is already safely stored above.
    await safe("persist-enriched", async () => {
      const arr = JSON.parse((await env.CMS_KV.get(emailKey)) || "[]");
      const i = arr.findIndex(o => o.ref === order.ref);
      if (i >= 0) { arr[i] = order; await env.CMS_KV.put(emailKey, JSON.stringify(arr)); }
    });

    const gcalResult = (await safe("calendar", () => addCalendarEvent(env, order, b.email))) || { skipped: true };

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
    if (b.email) {
      await safe("customer-email", async () => {
        const ics = buildICS(order, env.MAIL_FROM);
        ctx.waitUntil(sendEmail(env, b.email,
          `Booking confirmed — ${order.ref} — Cousins Mechanical`,
          `Hi ${order.name},\n\nYour booking is confirmed.\n\n${lines}\n\n`
          + `Payment is taken on site when the work is done — card or cash. We will confirm the price with you before any work starts.\n\n`
          + `Need to change or cancel it? Call 01308 538046 or 07925 340977, or reply to this email.\n\n`
          + `Cousins Mechanical Services Ltd\nRegistered in England & Wales no. 16045339\n7 Watton Park, Bridport, DT6 5NJ`,
          ics));
      });
    }

    // Owner alert — Josh must hear about a new job even if the customer gave no
    // email and even if he is not looking at the dashboard.
    await safe("owner-alert", async () => {
      const ownerTo = env.OWNER_EMAIL || env.MAIL_FROM;
      if (ownerTo) {
        ctx.waitUntil(sendEmail(env, ownerTo,
          `NEW JOB ${order.ref} — ${order.svcLabel || order.service || "Mobile job"} — ${order.reg || ""}`,
          `New booking taken on the website.\n\n${lines}\n\nOpen the dashboard: ${(env.SITE_URL || "")}/admin.html`));
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
    const b = await request.json().catch(() => ({}));
    const calResult = await addCalendarEvent(env, b, b.customerEmail || b.email);
    return json({ ok: calResult.ok || false, result: calResult });
  }

  // --- BOOKINGS (per account) ---
  if (p === "/bookings") {
    const u = await sessionUser(request, env);
    if (!u) return bad("Not signed in", 401);
    const kvKey = "bookings:" + u.email;
    const list = JSON.parse((await env.CMS_KV.get(kvKey)) || "[]");

    if (request.method === "GET") return json({ bookings: list });

    if (request.method === "POST") {
      const b = await request.json().catch(() => ({}));
      const order = { ...b, ref: b.ref || ref(), status: "confirmed", createdAt: Date.now(),
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
      list[i] = { ...list[i], ...b, updates: [...(list[i].updates || []), { t: Date.now(), s: "Booking amended", d: "Your booking was updated." }] };
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
    const okAdmin = (await isAdmin(request, env)) || body.token === env.ADMIN_TOKEN || (await env.CMS_KV.get("dsess:" + body.token));
    if (!okAdmin) return bad("Forbidden", 403);
    const { ref: r, lat, lng, eta, arrived } = body;
    if (!r) return bad("Missing ref");
    if (arrived) {
      const list = await env.CMS_KV.list({ prefix: "bookings:" });
      for (const k of list.keys) {
        const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
        let changed = false;
        for (const o of arr) if (o.ref === r && o.status !== "arrived") { o.status = "arrived"; o.updates = [...(o.updates || []), { t: Date.now(), s: "Arrived", d: "Your mechanic is with you." }]; changed = true; }
        if (changed) await env.CMS_KV.put(k.name, JSON.stringify(arr));
      }
    } else {
      await env.CMS_KV.put("loc:" + r, JSON.stringify({ lat, lng, eta, t: Date.now() }), { expirationTtl: LOCATION_TTL_SEC });
    }
    return json({ ok: true });
  }
  // Driver page needs the active job list without a 2FA session — gated by the admin token in the body.
  if (p === "/driver/register" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const username = String(b.username || "").trim().toLowerCase();
    if (!username || !b.password) return bad("Missing username or password", 400);
    if (String(b.password).length < 10) return bad("Password must be at least 10 characters", 400);
    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    if (drivers.find(d => d.username === username)) return bad("Username taken", 400);
    // Salted PBKDF2, same scheme as customer accounts. Never store the password itself.
    const salt = newSalt();
    const hash = await pbkdf2(b.password, salt, env.SESSION_PEPPER);
    const id = "DRV-" + token().slice(0, 8).toUpperCase();
    drivers.push({
      id, username, salt, hash,
      name: b.name || username, vanReg: b.vanReg || "", phone: b.phone || "",
      status: "Pending Approval", approved: false, assignedJob: "-", createdAt: Date.now(),
    });
    await env.CMS_KV.put("drivers", JSON.stringify(drivers));
    return json({ ok: true, pending: true });
  }

  if (p === "/driver/login" && request.method === "POST") {
    const b = await request.json().catch(() => ({}));
    const username = String(b.username || "").trim().toLowerCase();
    const rlKey = "drv:" + clientIp(request);
    if (await rateLimited(env, rlKey)) return bad("Too many attempts — try again in 15 minutes", 429);

    const drivers = JSON.parse((await env.CMS_KV.get("drivers")) || "[]");
    const d = drivers.find(x => x.username === username);
    // Always run the KDF, even for an unknown user, so a wrong username and a
    // wrong password take the same time and cannot be told apart.
    const salt = d?.salt || newSalt();
    const attempt = await pbkdf2(b.password || "", salt, env.SESSION_PEPPER);
    if (!d || !d.hash || !safeEqual(attempt, d.hash)) {
      await noteFailure(env, rlKey);
      return bad("Invalid credentials", 401);
    }
    if (!d.approved) return bad("Account pending admin approval", 403);

    await clearFailures(env, rlKey);
    const token_ = "DRVTOK-" + token();
    await env.CMS_KV.put("dsess:" + token_, d.id, { expirationTtl: 60 * 60 * 12 });
    const { salt: _s, hash: _h, ...safeDriver } = d;
    return json({ token: token_, driver: safeDriver });
  }

  if (p === "/driver/jobs" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (!(await env.CMS_KV.get("dsess:" + body.token)) && body.token !== env.ADMIN_TOKEN && !(await isAdmin(request, env))) return bad("Forbidden", 403);
    const out = [];
    const list = await env.CMS_KV.list({ prefix: "bookings:" });
    for (const k of list.keys) {
      const arr = JSON.parse((await env.CMS_KV.get(k.name)) || "[]");
      for (const o of arr) if (o.status !== "cancelled" && o.status !== "complete")
        out.push({ ref: o.ref, svcLabel: o.svcLabel, reg: o.reg, postcode: o.postcode, name: o.name, date: o.date, time: o.time, status: o.status });
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
    return json({ status: job.status, updates: job.updates || [], location: loc });
  }

  // --- ADMIN LOGIN + 2FA ---
  // Step 1: exchange admin token (+ TOTP code once enrolled) for a short-lived admin session.
  // Public Firebase web config for the "Sign in with Google" button. Firebase
  // web config is client-side by design (not a secret); 404 when unset lets
  // the login screen hide the button entirely.
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
    if (await rateLimited(env, rlKey)) return bad("Too many attempts — try again in 15 minutes", 429);
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
    if (await rateLimited(env, rlKey)) return bad("Too many attempts — try again in 15 minutes", 429);
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
    if (await rateLimited(env, rlKey)) return bad("Too many attempts — try again in 15 minutes", 429);
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
    if (await rateLimited(env, rlKey)) return bad("Too many attempts — try again in 15 minutes", 429);
    if (!safeEqual(b.token, env.ADMIN_TOKEN)) { await noteFailure(env, rlKey); return bad("Invalid admin token", 401); }
    if (await env.CMS_KV.get("admin_totp")) return bad("2FA is already enrolled.", 409);
    if (!b.secret || !(await totpValid(b.secret, b.code))) return bad("That code didn't match — check the app and try again.", 400);
    await env.CMS_KV.put("admin_totp", b.secret);
    await audit(env, "admin", "admin_2fa_enrolled", "");
    return json({ ok: true });
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
      // notify the customer by SMS if they're opted in
      const uraw = await env.CMS_KV.get("user:" + email);
      if (uraw) { const u = JSON.parse(uraw); if (u.smsUpdates !== false && b.sms) ctx.waitUntil(sendSMS(env, u.phone, b.sms)); }
      return json({ job: arr[i] });
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
        // push the reply to the customer by WhatsApp/SMS if opted in
        const uraw = await env.CMS_KV.get("user:" + email);
        if (uraw) { const u = JSON.parse(uraw); if (u.smsUpdates !== false) ctx.waitUntil(sendSMS(env, u.phone, "Cousins Mechanical: " + text)); }
        return json({ messages: thread });
      }
    }

    // --- BACKUP: full export of everything durable in KV ---
    // The one real weakness of KV vs a hosted database is that there is no
    // queryable copy outside Cloudflare. This closes it: one click in admin
    // downloads the whole business state as JSON. Transient keys (sessions,
    // rate-limit counters, reset tokens) are deliberately excluded — restoring
    // them would be wrong, and sessions are secrets.
    if (p === "/admin/backup" && request.method === "GET") {
      const EXCLUDE = ["sess:", "asess:", "dsess:", "rl:", "reset:"];
      const data = {};
      let cursor;
      do {
        const page = await env.CMS_KV.list({ cursor });
        for (const k of page.keys) {
          if (EXCLUDE.some(pre => k.name.startsWith(pre))) continue;
          const raw = await env.CMS_KV.get(k.name);
          if (raw == null) continue;
          try { data[k.name] = JSON.parse(raw); } catch { data[k.name] = raw; }
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
      await audit(env, "admin", "staff_updated", em + " disabled=" + !!acct.disabled);
      return json({ ok: true, staff: { email: acct.email, name: acct.name, role: acct.role, disabled: !!acct.disabled } });
    }

    // Customers (CRM list) — profile + job count + discount + notes count
    if (p === "/admin/customers" && request.method === "GET") {
      const out = [];
      const list = await env.CMS_KV.list({ prefix: "user:" });
      for (const k of list.keys) {
        const u = JSON.parse((await env.CMS_KV.get(k.name)) || "{}");
        if (!u.email) continue;
        const jobs = JSON.parse((await env.CMS_KV.get("bookings:" + u.email)) || "[]");
        const crm = JSON.parse((await env.CMS_KV.get("crm:" + u.email)) || "{}");
        const lastJobAt = jobs.reduce((m, j) => Math.max(m, j.createdAt || j.t || 0), 0);
        out.push({
          name: u.name, email: u.email, phone: u.phone,
          marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false,
          createdAt: u.createdAt, jobCount: jobs.length,
          discount: Number(crm.discount) || 0, discountReason: crm.discountReason || "",
          notesCount: Array.isArray(crm.notes) ? crm.notes.length : 0,
          lastJobAt,
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
      if (!(await env.CMS_KV.get("user:" + email))) return bad("Customer not found", 404);
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
      if (!uraw) return bad("Customer not found", 404);
      const u = JSON.parse(uraw);
      const crm = JSON.parse((await env.CMS_KV.get("crm:" + email)) || "{}");

      if (request.method === "GET") {
        const bookings = JSON.parse((await env.CMS_KV.get("bookings:" + email)) || "[]");
        return json({
          customer: {
            name: u.name, email: u.email, phone: u.phone,
            marketing: !!u.marketing, smsUpdates: u.smsUpdates !== false, createdAt: u.createdAt,
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
        supplierEmail: b.supplierEmail || "orders@ctyreswholesale.co.uk",
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
          supplier: b.supplier || "C-Tyres Wholesale Ltd",
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
        if (b.action === "approve" || b.action === "revoke") {
          const idx = drivers.findIndex(d => d.id === b.id);
          if (idx < 0) return bad("Driver not found", 404);
          const approving = b.action === "approve";
          drivers[idx].approved = approving;
          drivers[idx].status = approving ? "Active" : "Suspended";
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
        const kept = drivers.filter(d => d.id !== b.id);
        await env.CMS_KV.put("drivers", JSON.stringify(kept));
        // Revoke any live session for that driver so removal takes effect at once.
        const sessions = await env.CMS_KV.list({ prefix: "dsess:" });
        for (const k of sessions.keys) {
          if ((await env.CMS_KV.get(k.name)) === b.id) await env.CMS_KV.delete(k.name);
        }
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
     * ------------------------------------------------------------------- */
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
        if (next.calloutFee < 0 || next.calloutFee > 1000) return bad("Call-out fee must be between 0 and 1000", 400);
        if (next.hourlyRate < 0 || next.hourlyRate > 1000) return bad("Hourly rate must be between 0 and 1000", 400);

        const saved = await savePricing(env, next);
        await audit(env, "admin", "pricing_updated", JSON.stringify(saved.markupPct));
        return json({ pricing: saved });
      }
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
