/*
 * gcal-authorize.mjs — get a Google Calendar refresh token, once, locally.
 *
 *   node tools/gcal-authorize.mjs <CLIENT_ID> <CLIENT_SECRET>
 *
 * Everything happens on this machine. The token is printed to your terminal and
 * is never sent anywhere.
 *
 * WHY A REFRESH TOKEN AND NOT A SERVICE ACCOUNT
 *
 * Google now enforces `iam.managed.disableServiceAccountKeyCreation` on
 * organisations by default — long-lived private keys leak, so they stopped
 * letting you create them. The textbook approach is simply blocked. A refresh
 * token belonging to the account that owns the diary is the supported route,
 * and is a better credential anyway: it is scoped to one user's calendar rather
 * than being a project identity, and it can be revoked from that Google
 * account's own security page.
 *
 * BEFORE YOU RUN THIS, two things in the Google Cloud Console:
 *
 *   1. Add this exact redirect URI to the OAuth client:
 *        http://localhost:8788/oauth/callback
 *      Google matches it character for character. A web client with no redirect
 *      URI registered cannot complete this flow at all.
 *
 *   2. Set the OAuth consent screen's publishing status to "In production",
 *      or User type "Internal" if this is a Workspace account.
 *
 *      This one bites weeks later. While the consent screen is in "Testing",
 *      Google expires refresh tokens after SEVEN DAYS. Everything works, you
 *      forget about it, and the following week the booking form quietly stops
 *      checking the diary and starts double-booking — with no error, because a
 *      dead token and an empty week look identical from the outside.
 *      An Internal Workspace app needs no verification review.
 */
import http from 'node:http';
import { execFile } from 'node:child_process';

const [, , clientId, clientSecret] = process.argv;
if (!clientId || !clientSecret) {
  console.error('usage: node tools/gcal-authorize.mjs <CLIENT_ID> <CLIENT_SECRET>');
  process.exit(2);
}

const PORT = 8788;
const REDIRECT = `http://localhost:${PORT}/oauth/callback`;
// Full calendar scope, not readonly: the site both checks whether a slot is
// busy AND writes the booking into the diary.
const SCOPE = 'https://www.googleapis.com/auth/calendar';

const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
  client_id: clientId,
  redirect_uri: REDIRECT,
  response_type: 'code',
  scope: SCOPE,
  // Both are required to be handed a refresh token at all. Without
  // prompt=consent Google returns only an access token on a repeat
  // authorisation, and you get a confusing "it worked but there's no refresh
  // token" result.
  access_type: 'offline',
  prompt: 'consent',
});

console.log('\nSign in as the account that OWNS the diary — help@cousinsmechanicalservices.co.uk,');
console.log('not a personal account. The token inherits whatever that account can see.\n');
console.log('Opening your browser. If nothing happens, paste this in yourself:\n');
console.log(authUrl + '\n');

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (url.pathname !== '/oauth/callback') { res.writeHead(404).end('not here'); return; }

  const err = url.searchParams.get('error');
  const code = url.searchParams.get('code');
  const done = (msg) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;padding:40px;max-width:32em">
      <h2>${msg}</h2><p>You can close this tab and go back to the terminal.</p></body>`);
  };

  if (err) { done('Google said: ' + err); console.error('\nFAIL — ' + err); server.close(); process.exit(1); }
  if (!code) { done('No code came back.'); return; }

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code, client_id: clientId, client_secret: clientSecret,
      redirect_uri: REDIRECT, grant_type: 'authorization_code',
    }),
  });
  const body = await r.json().catch(() => ({}));

  if (!r.ok || !body.refresh_token) {
    done('Could not get a refresh token — check the terminal.');
    console.error('\nFAIL — no refresh token came back.');
    console.error('  ' + (body.error_description || body.error || JSON.stringify(body).slice(0, 300)));
    if (r.ok && !body.refresh_token) {
      console.error('\n  Google returned an access token but no refresh token. That happens when');
      console.error('  this account has already authorised the app. Revoke it at');
      console.error('  https://myaccount.google.com/permissions and run this again.');
    }
    server.close();
    process.exit(1);
  }

  // Prove it actually reads the diary before declaring success. A token that
  // authenticates but cannot see the calendar is the failure mode that matters.
  let calCheck = '';
  try {
    const cal = await fetch('https://www.googleapis.com/calendar/v3/users/me/calendarList', {
      headers: { authorization: 'Bearer ' + body.access_token },
    });
    const list = await cal.json().catch(() => ({}));
    const items = (list.items || []).filter(c => c.accessRole === 'owner' || c.accessRole === 'writer');
    calCheck = items.length
      ? '\nCalendars this token can write to:\n' + items.map(c => '  ' + c.id + (c.primary ? '   (primary)' : '')).join('\n')
      : '\nWARNING: this token can see no writable calendar. Signed in as the wrong account?';
  } catch { calCheck = '\n(could not list calendars to confirm)'; }

  done('Done — check your terminal.');
  console.log('\n' + '-'.repeat(64));
  console.log('GCAL_REFRESH_TOKEN\n');
  console.log(body.refresh_token);
  console.log('\n' + '-'.repeat(64));
  console.log(calCheck);
  console.log('\nSet three secrets (paste each at the prompt, never on the command line):');
  console.log('  npx wrangler secret put GOOGLE_CLIENT_ID');
  console.log('  npx wrangler secret put GOOGLE_CLIENT_SECRET');
  console.log('  npx wrangler secret put GCAL_REFRESH_TOKEN');
  console.log('\n...plus GCAL_CALENDAR_ID, which is one of the ids listed above.');
  console.log('\nThen put a test event in tomorrow morning and reload the booking form.');
  console.log('That slot should be gone. If it is not, the diary is not being read.\n');
  server.close();
  process.exit(0);
});

server.listen(PORT, () => {
  const open = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  execFile(open, [authUrl], () => {});
});

setTimeout(() => {
  console.error('\nTimed out after 5 minutes with no response from Google.');
  console.error('The usual cause is the redirect URI: ' + REDIRECT);
  console.error('It must be registered on the OAuth client, character for character.');
  server.close();
  process.exit(1);
}, 5 * 60 * 1000).unref?.();
