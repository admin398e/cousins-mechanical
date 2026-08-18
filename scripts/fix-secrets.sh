#!/usr/bin/env bash
#
# Cleans up Cloudflare Worker secrets for cousins-mechanical.
#
# BACKGROUND
# ----------
# `wrangler secret put` takes the secret's NAME as its argument and then PROMPTS
# for the value:
#
#     npx wrangler secret put RESEND_WEBHOOK_SECRET
#     ✔ Enter a secret value: … › whsec_xxxxxxxx        <-- value goes HERE
#
# Pasting the value as the argument creates a secret whose NAME is your secret.
# That happened several times on this account. All the real secrets are now set
# correctly; this script removes the leftovers.
#
# TWO OF THEM CANNOT BE DELETED FROM THE CLI. Cloudflare's API puts the secret
# name in the URL path, and `+` and `/` do not survive that round trip:
#
#     whsec_U5UBhD/LZl+Rw2SAvNoAEQLCHwJIivI9
#       -> Binding 'whsec_U5UBhD/LZl Rw2SAvNoAEQLCHwJIivI9' not found
#     +447925340977
#       -> Binding ' 447925340977' not found
#
# Delete those two in the dashboard instead:
#   Cloudflare → Workers & Pages → cousins-mechanical → Settings → Variables
#
# Note there is no --force flag on `secret delete`; it asks for confirmation,
# which this script answers.
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Deleting leftover secrets whose NAME is a secret VALUE"
echo "-----------------------------------------------------"

for junk in \
  '3f5d200d-482c-4752-879b-9bd8d48aaffe' \
  '8fcdef39-7b2e-47bb-9d38-84b5663bab5e' \
  'fcdef39-7b2e-47bb-9d38-84b5663bab5e'
do
  if yes | npx wrangler secret delete "$junk" >/dev/null 2>&1; then
    echo "  deleted  $junk"
  else
    echo "  gone already (or not deletable): $junk"
  fi
done

echo
echo "Remaining secrets"
echo "-----------------"
npx wrangler secret list 2>/dev/null | grep '"name"' | sed 's/.*: "/  /;s/".*//' | sort

cat <<'NOTE'

STILL TO DO BY HAND
-------------------
1. In the Cloudflare dashboard, delete these two — the CLI cannot, because
   `+` and `/` are mangled in the API URL:

       whsec_U5UBhD/LZl+Rw2SAvNoAEQLCHwJIivI9
       +447925340977

   Workers & Pages → cousins-mechanical → Settings → Variables and Secrets

2. Rotate the webhook signing secret in Resend afterwards. Its value has been
   sitting in Cloudflare as a secret NAME, and names are not treated as
   sensitive. Then:

       npx wrangler secret put RESEND_WEBHOOK_SECRET
       (paste the NEW whsec_… at the prompt)
NOTE
