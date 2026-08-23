/*
 * dc-placeholder.js — make the pre-hydration HTML safe to send to a browser.
 *
 * The served page is a PLACEHOLDER. The design-canvas runtime replaces it on
 * hydration, so a {{ token }} left in the markup is only on screen for a few
 * hundred milliseconds — harmless in text, not harmless in an attribute the
 * browser fetches on sight.
 *
 * `<img src="{{ t.image }}">` inside an <sc-for> placeholder row made every
 * visitor's browser request /%7B%7B%20t.image%20%7D%7D, and
 * `<iframe src="{{ calendarUrl }}">` did the same on the admin calendar tab.
 * Three 404s per page load, in the Worker's logs forever, for images nobody was
 * ever going to see.
 *
 * Exactly the attributes the browser fetches without being asked — src, srcset,
 * poster — and nothing else. href is left alone deliberately: a link is not
 * fetched until it is clicked, and rewriting real links would be a far worse
 * failure than a stray request.
 *
 * The replacement differs by element, and the reason is worth keeping:
 *
 *   images  a transparent 1x1 GIF as a data: URI. It costs no request, it
 *           LOADS rather than failing, so there is no broken-image icon and no
 *           onerror handler firing at a component that is about to be replaced.
 *   frames  about:blank. A data: URI in a frame is refused by our own CSP
 *           (frame-src has no data:), which swaps a 404 in the network log for
 *           a violation in the console — no better, and noisier, because a
 *           console full of expected violations is how a real one gets missed.
 *
 * It lives in its own file because BOTH the build and the dev server need it.
 * The dev server serves the authored .dc.html directly so that editing is live,
 * which means anything the build does to the HTML and the dev server does not
 * is a difference between what you test and what you ship. That gap is exactly
 * why this bug reached production and survived every local check.
 */

// 1x1 transparent GIF. Loads instantly, draws nothing, makes no request.
const BLANK_IMAGE = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
const BLANK_FRAME = 'about:blank';
const FRAMEY = /^(iframe|frame|embed|object|portal)$/i;

const TAG = /<([a-zA-Z][\w-]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
const FETCHED_ATTR = /\s(src|srcset|poster)=(["'])\s*\{\{[^"']*\}\}\s*\2/gi;

export function neutralisePlaceholderFetches(html) {
  let n = 0;
  const out = String(html).replace(TAG, (whole, name, attrs) => {
    if (!attrs.includes('{{')) return whole;
    const blank = FRAMEY.test(name) ? BLANK_FRAME : BLANK_IMAGE;
    const next = attrs.replace(FETCHED_ATTR, (m, attr) => { n++; return ` ${attr}="${blank}"`; });
    return next === attrs ? whole : `<${name}${next}>`;
  });
  return { out, n };
}
