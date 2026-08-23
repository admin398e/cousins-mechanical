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
 * about:blank rather than a data: URI because the CSP allows data: for images
 * but not for frames, and this has to be safe for both.
 *
 * It lives in its own file because BOTH the build and the dev server need it.
 * The dev server serves the authored .dc.html directly so that editing is live,
 * which means anything the build does to the HTML and the dev server does not
 * is a difference between what you test and what you ship. That gap is how the
 * two copies of these pages drifted apart before.
 */
const NO_FETCH_PLACEHOLDER = /\s(src|srcset|poster)=(["'])\s*\{\{[^"']*\}\}\s*\2/gi;

export function neutralisePlaceholderFetches(html) {
  let n = 0;
  const out = String(html).replace(NO_FETCH_PLACEHOLDER, (m, attr) => {
    n++;
    return ` ${attr}="about:blank"`;
  });
  return { out, n };
}
