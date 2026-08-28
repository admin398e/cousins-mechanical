#!/bin/bash
#
# Sign in with Apple — set the four values, deploy, and check.
#
# Run it as ONE command, from the repo folder:
#
#     bash setup-apple.sh
#
# It exists because pasting a multi-line block into a shell kept going wrong:
# an interactive `wrangler secret put` reads its value from stdin, so inside a
# pasted block it swallows the next pasted line, and an unbalanced quote leaves
# the shell sitting at a `quote>` prompt eating everything after it. A script
# has neither problem.
#
# The first three values are NOT secrets. The Services ID appears in the URL in
# every customer's browser when they sign in with Apple, the Team ID is the App
# ID prefix, and the Key ID is public metadata. Only the .p8 is secret, and it
# is piped from the file rather than typed.

set -u

SERVICES_ID='uk.co.cousinsmechanicalservices.web'
TEAM_ID='MUU85JNW96'
KEY_ID='6FZL2G46Y2'

cd "$(dirname "$0")" || exit 1

# ---- find the private key -------------------------------------------------
P8=''
for candidate in \
  "$HOME/Downloads/AuthKey_${KEY_ID}.p8" \
  "$HOME/Desktop/AuthKey_${KEY_ID}.p8" \
  "./AuthKey_${KEY_ID}.p8" \
  "$HOME/Downloads/AuthKey_"*.p8
do
  [ -f "$candidate" ] && { P8="$candidate"; break; }
done

if [ -z "$P8" ]; then
  echo
  echo "Could not find the Apple private key."
  echo
  echo "  Looked for AuthKey_${KEY_ID}.p8 in ~/Downloads, ~/Desktop and here."
  echo
  echo "  If you never clicked Download on the 'Download Your Key' page, the key"
  echo "  is gone for good — Apple only serves it once. Delete key ${KEY_ID} at"
  echo "  https://developer.apple.com/account/resources/authkeys/list, create a"
  echo "  new one, and put its Key ID in this script before running it again."
  echo
  echo "  If you saved it somewhere else, move it to ~/Downloads and re-run."
  exit 1
fi

echo "Using private key: $P8"
if ! grep -q "PRIVATE KEY" "$P8"; then
  echo "That file does not look like a .p8 private key — it has no PEM header."
  exit 1
fi
echo

# ---- set them -------------------------------------------------------------
# Each value arrives on wrangler's stdin through a pipe, so nothing it reads can
# come from the terminal by accident. printf, not echo: no trailing newline.
fail=0
put () {
  echo "── $1"
  if printf '%s' "$2" | npx wrangler secret put "$1"; then :; else fail=1; echo "   ^ FAILED"; fi
  echo
}
put APPLE_SERVICES_ID "$SERVICES_ID"
put APPLE_TEAM_ID     "$TEAM_ID"
put APPLE_KEY_ID      "$KEY_ID"

echo "── APPLE_PRIVATE_KEY"
if npx wrangler secret put APPLE_PRIVATE_KEY < "$P8"; then :; else fail=1; echo "   ^ FAILED"; fi
echo

if [ "$fail" -ne 0 ]; then
  echo "At least one secret did not upload. Nothing has been deployed."
  echo "Scroll up for the error, fix it, and run this again."
  exit 1
fi

# ---- ship it --------------------------------------------------------------
echo "── deploying"
npx wrangler deploy || exit 1
echo

echo "── checking the live site"
sleep 3
providers=$(curl -s --max-time 10 https://cousinsmechanicalservices.co.uk/api/auth/providers)
echo "  /api/auth/providers -> $providers"
case "$providers" in
  *'"apple":true'*)
    echo
    echo "Apple sign-in is live. The button is now on the public site, the"
    echo "dashboard and the van screen."
    ;;
  *)
    echo
    echo "Apple is still off. Ask the Worker which value it does not like:"
    echo
    echo '  curl -s -X POST -H "content-type: application/json" -d "{}" \'
    echo '    https://cousinsmechanicalservices.co.uk/api/auth/apple/start'
    echo
    echo "  It names the field rather than just saying 'not configured'."
    ;;
esac
