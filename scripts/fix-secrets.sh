#!/usr/bin/env bash
#
# Repairs the Cloudflare Worker secrets for cousins-mechanical.
#
# WHY THIS EXISTS
# ---------------
# `wrangler secret put` takes the secret's NAME as its argument and then PROMPTS
# for the value:
#
#     npx wrangler secret put RESEND_WEBHOOK_SECRET
#     ✔ Enter a secret value: … › whsec_xxxxxxxx        <-- value goes HERE
#
# Pasting the value as the argument creates a secret whose NAME is your secret.
# That has happened five times on this account, which is why
# RESEND_WEBHOOK_SECRET does not exist and every bounce notification from Resend
# is being rejected with a 503.
#
# Run this from the repo root:   bash scripts/fix-secrets.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

put() {  # put NAME VALUE
  printf '%s' "$2" | npx wrangler secret put "$1" >/dev/null 2>&1 \
    && echo "  set    $1" \
    || echo "  FAILED $1  — run: npx wrangler secret put $1"
}

echo "Setting secrets under their correct names"
echo "-----------------------------------------"

# Known values, recovered from the misnamed secrets already on the account.
put RESEND_WEBHOOK_SECRET 'whsec_U5UBhD/LZl+Rw2SAvNoAEQLCHwJIivI9'
put OWNER_PHONE           '+447925340977'
put SITE_URL              'https://cousinsmechanicalservices.co.uk'

# Where new-job alerts land. Change this if Cousins should get them directly.
read -r -p "  OWNER_EMAIL [admin@joshuastone.co.uk]: " OWNER_EMAIL
put OWNER_EMAIL "${OWNER_EMAIL:-admin@joshuastone.co.uk}"

# Optional. Leave blank and marketing consent is still recorded in KV — nothing
# is synced to Resend. Find the id in the URL of the Audience page in Resend.
# NOTE: 8fcdef39-… is a *segment* id, not an audience id. Do not use it.
read -r -p "  RESEND_AUDIENCE_ID (optional, Enter to skip): " AUD
[ -n "${AUD:-}" ] && put RESEND_AUDIENCE_ID "$AUD" || echo "  skipped RESEND_AUDIENCE_ID (safe — consent is still recorded)"

echo
echo "Removing the secrets whose NAME is a secret VALUE"
echo "------------------------------------------------"
for junk in \
  'whsec_U5UBhD/LZl+Rw2SAvNoAEQLCHwJIivI9' \
  '+447925340977' \
  '3f5d200d-482c-4752-879b-9bd8d48aaffe' \
  '8fcdef39-7b2e-47bb-9d38-84b5663bab5e' \
  'fcdef39-7b2e-47bb-9d38-84b5663bab5e'
do
  npx wrangler secret delete "$junk" --force >/dev/null 2>&1 \
    && echo "  deleted  ${junk:0:24}…" \
    || echo "  not present or already gone: ${junk:0:24}…"
done

echo
echo "Remaining secrets"
echo "-----------------"
npx wrangler secret list 2>/dev/null | grep '"name"' | sed 's/.*: "/  /;s/".*//' | sort

echo
echo "Verifying against the live site"
echo "-------------------------------"
npm run smoke:prod

cat <<'NOTE'

ONE THING LEFT: rotate the webhook secret.
Its value has been sitting in Cloudflare as a secret NAME, and names are not
treated as sensitive. In Resend → Webhooks, roll the signing secret, then:

    npx wrangler secret put RESEND_WEBHOOK_SECRET
    (paste the NEW whsec_… at the prompt)
NOTE
