#!/bin/bash
#
# Sign in with Apple — set the four values, deploy, and check.
#
#     bash setup-apple.sh
#
# One command, because pasting a multi-line block into a shell kept failing two
# different ways: an interactive `wrangler secret put` reads its value from
# stdin and swallows the next pasted line, and an unbalanced quote leaves the
# shell at a `quote>` prompt eating everything after it.
#
# The first three values are NOT secrets. The Services ID appears in the URL in
# every customer's browser when they sign in with Apple, the Team ID is the App
# ID prefix, and the Key ID is public metadata. Only the .p8 is secret, and it
# is piped straight from the file — never typed, never on a command line.

set -u

SERVICES_ID='uk.co.cousinsmechanicalservices.web'
TEAM_ID='MUU85JNW96'
KEY_ID='6FZL2G46Y2'

cd "$(dirname "$0")" || exit 1

# ---------------------------------------------------------------------------
# Find a Node that can actually run wrangler.
#
# On Node 25 wrangler exits 0 and prints nothing at all — no error, no version,
# no "Success". Every command looks like it worked and none of them did. That
# is how four secrets appeared to upload and none arrived. wrangler declares
# node >= 22, so 25 passes its own check and fails silently after it.
#
# So: try each Node until one actually answers with a version. And call
# wrangler-dist/cli.js rather than bin/wrangler.js — the latter re-spawns a
# child process, and when output is redirected to a file that child's output
# can be lost even when the command works.
# ---------------------------------------------------------------------------
CLI='node_modules/wrangler/wrangler-dist/cli.js'

# ---------------------------------------------------------------------------
# Is wrangler actually READABLE?
#
# On this machine wrangler-dist/cli.js reported 18 MB from stat and returned
# zero bytes when read — md5 came back d41d8cd9…, the hash of an empty file,
# and `head -c 64` printed nothing. Node then ran an empty script: no output,
# no error, exit 0. Every wrangler command looked like it worked and none of
# them ran, which is how four secrets appeared to upload and a deploy appeared
# to succeed while the live site never changed.
#
# `wc -c` does NOT catch this — it takes the size from fstat without reading
# the file, so it cheerfully reports 18 MB for a file that reads as nothing.
# Reading a byte is the only honest test.
# ---------------------------------------------------------------------------
readable () { [ -f "$1" ] && [ -n "$(head -c 1 "$1" 2>/dev/null)" ]; }

if ! readable "$CLI"; then
  echo "wrangler is installed but unreadable — reinstalling it."
  echo "  (stat says $(stat -f%z "$CLI" 2>/dev/null || echo 0) bytes; reading it returns nothing.)"
  rm -rf node_modules/wrangler node_modules/.bin/wrangler node_modules/.bin/wrangler2 node_modules/.bin/cf-wrangler
  npm install wrangler@4.122.0 --no-save --no-audit --no-fund || {
    echo "Reinstall failed. Scroll up for the reason."; exit 1; }
  echo
fi

readable "$CLI" || {
  echo
  echo "wrangler still reads as empty after a reinstall. That is a disk or file"
  echo "sync problem, not a wrangler one — this project lives under ~/Desktop,"
  echo "which macOS may be syncing to iCloud and evicting."
  echo
  echo "  Move the project somewhere local and try again:"
  echo "      mkdir -p ~/dev && cp -R ~/Desktop/cousins ~/dev/cousins"
  echo "      cd ~/dev/cousins/cousins-mechanical && npm install"
  exit 1
}

NODE=''
for candidate in \
  /opt/homebrew/opt/node@22/bin/node \
  /opt/homebrew/opt/node@24/bin/node \
  /opt/homebrew/opt/node@20/bin/node \
  /usr/local/opt/node@22/bin/node \
  "$(command -v node || true)"
do
  [ -n "$candidate" ] && [ -x "$candidate" ] || continue
  v=$("$candidate" "$CLI" --version 2>/dev/null | tr -d '[:space:]')
  if [ -n "$v" ]; then NODE="$candidate"; NODE_V=$("$candidate" --version); WV="$v"; break; fi
done

if [ -z "$NODE" ]; then
  echo
  echo "No installed Node can run wrangler — every one tried exits silently."
  echo
  echo "  Node 25 is the usual cause. Install the LTS alongside it:"
  echo
  echo "      brew install node@22"
  echo
  echo "  then run this script again. It will find it on its own."
  "$(command -v node || echo node)" --version 2>/dev/null | sed 's/^/  Node currently on PATH: /'
  exit 1
fi

echo "Node:     $NODE_V  ($NODE)"
echo "Wrangler: $WV"
WR () { "$NODE" "$CLI" "$@"; }

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
  echo "Could not find the Apple private key (AuthKey_${KEY_ID}.p8)."
  echo "  Looked in ~/Downloads, ~/Desktop and here."
  echo
  echo "  If it was never downloaded, it is gone — Apple serves it once. Delete"
  echo "  key ${KEY_ID} at developer.apple.com, create a new one, and put the new"
  echo "  Key ID at the top of this script."
  exit 1
fi
grep -q "PRIVATE KEY" "$P8" || { echo "$P8 has no PEM header — that is not a .p8 key."; exit 1; }
echo "Key file: $P8"
echo

# ---- set them -------------------------------------------------------------
fail=0
put () {
  printf '── %s\n' "$1"
  if printf '%s' "$2" | WR secret put "$1"; then :; else fail=1; echo "   ^ FAILED"; fi
  echo
}
put APPLE_SERVICES_ID "$SERVICES_ID"
put APPLE_TEAM_ID     "$TEAM_ID"
put APPLE_KEY_ID      "$KEY_ID"

echo "── APPLE_PRIVATE_KEY"
if WR secret put APPLE_PRIVATE_KEY < "$P8"; then :; else fail=1; echo "   ^ FAILED"; fi
echo

[ "$fail" -eq 0 ] || { echo "A secret did not upload. Nothing deployed — fix the error above and re-run."; exit 1; }

# ---- ship it --------------------------------------------------------------
echo "── deploying"
WR deploy || exit 1
echo

echo "── checking the live site"
sleep 3
providers=$(curl -s --max-time 10 https://cousinsmechanicalservices.co.uk/api/auth/providers)
echo "  /api/auth/providers -> $providers"
case "$providers" in
  *'"apple":true'*)
    echo
    echo "Apple sign-in is live — the button is on the public site, the dashboard"
    echo "and the van screen."
    ;;
  *)
    echo
    echo "Apple is still off. Ask the Worker which value it dislikes:"
    echo
    echo '  curl -s -X POST -H "content-type: application/json" -d "{}" \'
    echo '    https://cousinsmechanicalservices.co.uk/api/auth/apple/start'
    ;;
esac
