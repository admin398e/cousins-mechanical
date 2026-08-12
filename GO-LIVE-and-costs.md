# Cousins Mechanical — Running Costs & Go-Live

_Figures are typical UK pricing as a guide — confirm each provider's current rate before quoting the client. Prices ex-VAT unless noted._

## Monthly running costs

| Service | What it does | Free allowance | Cost after that |
| --- | --- | --- | --- |
| **Cloudflare Workers** | Hosts the whole site + backend | 100,000 requests/day free | £0 on free tier; **~£4/mo** ($5) paid plan if you exceed it |
| **Cloudflare KV** | Stores accounts, bookings, stock | Generous free tier | £0 for this scale |
| **Domain name** | e.g. cousinsmechanical.co.uk | — | **~£8–12/year** (.co.uk) |
| **Google Calendar** | Booking invites | Free with any Google account | £0 |
| **Email** | Booking confirmations + password reset | **Resend** free 3,000 emails/mo | £0 low volume; ~£15/mo above 3k |
| **Twilio SMS** | Confirmation + status texts | Pay-as-you-go | **~£0.04 per text** (UK). ~£0.80 to register a sender |
| **UK Vehicle Data** | Number-plate → tyre size | Per-lookup credits | typically **~£0.05–0.15 per lookup** — confirm your plan |
| **tire.vdim.app** | Year/make/model fitment | Your existing key | per your current subscription |

**Realistic baseline (low volume):** roughly **£1–3/month** in usage + ~£10/year domain, as long as you stay on free tiers. The only costs that scale with use are Twilio texts and vehicle lookups.

### Example: 100 jobs/month
- SMS: ~3 texts per job × 100 = 300 texts × £0.04 ≈ **£12**
- Vehicle lookups: ~150 × ~£0.10 ≈ **£15**
- Hosting/email/calendar: **£0–4**
- **≈ £27–31/month** in third-party costs at 100 jobs.

## One-off / your time
- Domain registration (~£10/yr)
- Deploying the Worker + setting API keys (one afternoon)
- Twilio number + sender registration (small one-off)

## What to charge the client — suggested model
1. **Build fee** (one-off) — your development time.
2. **Monthly care plan** — cover the running costs above + support + margin. Even at 100 jobs the hard cost is ~£30/mo, so a plan of e.g. £60–120/mo leaves healthy margin.
3. **Pass-through usage** (optional) — bill SMS + lookups at cost + markup if volume is unpredictable.

> Tip: keep marketing texts opt-in only (already built) — it keeps Twilio spend down and stays GDPR-clean.

## To flip it live (summary — full steps in `worker.js`)
1. `npm i -g wrangler && wrangler login`
2. `wrangler kv namespace create CMS_KV` → paste id into `wrangler.toml`
3. `wrangler secret put` each key (SESSION_PEPPER, UKVD_API_KEY, TIRE_API_KEY, TWILIO_*, GCAL_*, MAIL_FROM, ADMIN_TOKEN)
4. Export the site into `./public`, then `wrangler deploy`
5. Point your domain at the Worker in the Cloudflare dashboard
