# Cousins Mechanical Services

Mobile mechanic, tyre fitting and 24hr breakdown recovery for Bridport & West Dorset.
One repository containing the customer website, the admin portal, the driver app and
the Cloudflare Worker backend that serves all three.

```
npm install
cp .env.example .env      # fill in what you have; the rest degrades gracefully
npm run dev               # http://localhost:3000
```

---

## What is here

| Path | What it is |
|------|-----------|
| `Cousins Mechanical.dc.html` | The customer site — **source of truth** |
| `Cousins Admin.dc.html` | Admin portal — jobs, inventory, drivers, fleet map |
| `Cousins Driver.dc.html` | Driver app — job list, live GPS |
| `worker.js` | The entire backend. Runs on Cloudflare in production |
| `tyre-data.js` | Tyre size matching — shared by the Worker and the dev server |
| `tyre-db.js` | Loads the catalogue from disk for local dev |
| `server.js` | Local dev server. Runs the *real* `worker.js` behind an Express shim |
| `build.js` | Copies the three pages into `public/` and regenerates `sitemap.xml` |
| `public/` | What actually gets deployed |
| `data/`, `public/data/` | The tyre catalogue, sizes and cost map |
| `ctyres_scraper.py`, `ctyres_ajax.py` | Regenerate the tyre catalogue from the supplier |
| `test/smoke.test.js` | 45 checks covering auth, bookings, tyres, tracking |

**Edit the `.dc.html` files in the root, never the copies in `public/`.**
`npm run build` overwrites `public/` from the root files. This is what stops the two
copies drifting apart, which is how the old repos ended up disagreeing with each other.

---

## Commands

| Command | What it does |
|---------|--------------|
| `npm run dev` | Local server on :3000 |
| `npm run build` | Sync pages into `public/`, regenerate the sitemap |
| `npm run check` | Syntax-check every JS file |
| `npm test` | Boot the server and run 45 smoke tests |
| `npm run verify` | check + build + test — run before deploying |
| `npm run deploy` | Verify, then `wrangler deploy` |

---

## Going live

### 1. Cloudflare

```bash
npm i -g wrangler
wrangler login
wrangler kv namespace create CMS_KV     # paste the id into wrangler.toml
```

### 2. Set the secrets

Every value goes in with `wrangler secret put NAME`. Nothing sensitive is committed —
`.env` is gitignored and there are no fallback defaults anywhere in the code.

**Required — the site will not run without these:**

```bash
wrangler secret put SESSION_PEPPER      # openssl rand -hex 32
wrangler secret put ADMIN_TOKEN         # openssl rand -hex 32 — this IS the admin password
wrangler secret put OVERRIDE_TOKEN      # openssl rand -hex 32 — master key, store separately
wrangler secret put SITE_URL            # https://cousinsmechanicalservices.co.uk
```

**Required to actually confirm a booking to a customer:**

```bash
wrangler secret put RESEND_API_KEY      # resend.com, free 3,000 emails/month
wrangler secret put MAIL_FROM           # bookings@cousinsmechanicalservices.co.uk
wrangler secret put GCAL_CLIENT_EMAIL   # Google service account
wrangler secret put GCAL_PRIVATE_KEY    # its private key (PEM)
wrangler secret put GCAL_CALENDAR_ID    # share the calendar with that service account
```

**Customer texts — pick one:**

```bash
# WhatsApp Cloud API (cheaper)
wrangler secret put WHATSAPP_TOKEN
wrangler secret put WHATSAPP_PHONE_ID
# or Twilio SMS
wrangler secret put TWILIO_SID
wrangler secret put TWILIO_TOKEN
wrangler secret put TWILIO_FROM

wrangler secret put OWNER_PHONE         # alerts the owner on new customer messages
```

**Number-plate lookup** — without these the reg box still works, but falls back to a
default tyre size instead of the customer's real fitment:

```bash
wrangler secret put UKVD_API_KEY
wrangler secret put TIRE_API_KEY
```

**Google sign-in (optional):**

```bash
wrangler secret put FIREBASE_WEB_CONFIG # the public web config, one line of JSON
wrangler secret put ADMIN_EMAILS        # comma-separated admin Google accounts
```

> `ADMIN_EMAILS` is not optional if Google sign-in is on. Without it, any customer who
> signs in with Google could exchange their token for an admin session.

### 3. Deploy

```bash
npm run deploy
```

### 4. Check it came up

```bash
curl https://cousinsmechanicalservices.co.uk/api/health
```

`catalogue.tyres` should be **4128**. If it reads `0`, the build did not run and the
site is quietly serving placeholder tyre prices instead of real ones.

### 5. Turn on 2FA — do this before anything else

1. Open `/admin.html` and sign in with `ADMIN_TOKEN`
2. Enrol an authenticator app when prompted
3. Sign out and back in — it should now demand the 6-digit code

Until 2FA is enrolled, the admin token alone grants access. Once enrolled, only a
verified session works and the enrolment endpoint refuses to issue a second secret.
If you lose the phone, `OVERRIDE_TOKEN` with `reset2fa` clears it.

### 6. Submit the sitemap

Add the property in Google Search Console and submit
`https://cousinsmechanicalservices.co.uk/sitemap.xml`.

---

## Security

- Customer **and** driver passwords are salted and hashed with PBKDF2 (100k iterations,
  SHA-256) plus a server-side pepper. Nothing is stored in plaintext.
- Admin 2FA is TOTP (RFC 6238), verified in the test suite against an independent
  implementation rather than against itself.
- Login endpoints are rate limited to 8 attempts per 15 minutes, by IP and by account.
  Failed admin logins go to the audit log.
- Session tokens are 256 bits of CSPRNG output. Admin and driver sessions last 12
  hours, customer sessions 30 days. Revoking a driver kills their live session.
- CORS is an allowlist, not a wildcard. Add origins with `EXTRA_ORIGINS`.
- Driver GPS has a 1-hour TTL and is readable only by the admin map or the customer
  whose job it belongs to.
- Finished jobs are purged after 365 days by the nightly cron (GDPR storage
  limitation). Customers can export or erase their own data at any time.

---

## Refreshing tyre prices

The catalogue in `data/` is a snapshot. To update it:

```bash
python3 ctyres_scraper.py     # rebuilds ctyres.db + data/tyre-catalogue.json
npm run build                 # copies it into public/ where the Worker reads it
npm run deploy
```

Running costs and what to charge the client are in `GO-LIVE-and-costs.md`.
