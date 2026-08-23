/*
 * business.js — who this site belongs to.
 *
 * Everything here is a fact about the BUSINESS, not about the software: the
 * trading name, the company number, the phone number, the registered office.
 * They were scattered across worker.js, build.js, the legal pages and the
 * design templates — the phone number alone appeared in ten places in
 * worker.js — which meant changing one meant finding all of them, and missing
 * one meant a customer ringing a number nobody answers.
 *
 * Standing this up as one module is also what makes the site reusable. The
 * plan is to run it for other garages; the parts that differ per client are
 * here, and the parts that do not are everywhere else.
 *
 * WHAT IS NOT HERE, deliberately:
 *
 *   Secrets. Keys, tokens and passwords come from the environment. Nothing in
 *   this file is secret — all of it is on the website already.
 *
 *   The design copy in the .dc.html templates — headlines, service
 *   descriptions, the photographs. That is bespoke work per client, not
 *   configuration, and pretending otherwise would produce a template that
 *   makes every garage's site read identically.
 *
 * A note on the legal fields. companyNumber and registeredOffice are on every
 * public page because s.82 of the Companies Act 2006 and the Companies
 * (Trading Disclosures) Regulations require a limited company to disclose them
 * on its website. They are not decoration and must not be dropped when this is
 * reused — the next business's own number goes in their place.
 */

export const BUSINESS = {
  /* Identity */
  name: 'Cousins Mechanical Services',
  // What a text message says. An SMS is billed per 160 characters and read on a
  // lock screen, so it uses the short form everywhere.
  shortName: 'Cousins Mechanical',
  legalName: 'Cousins Mechanical Services Ltd',
  companyNumber: '16045339',
  registeredOffice: '7 Watton Park, Bridport, DT6 5NJ',

  /* Contact. `phone` is what is printed; `phoneHref` is what tel: links use.
   * The href is in E.164 so it still dials correctly from a phone that is not
   * on a UK network. */
  phone: '07925 340977',
  phoneHref: '+447925340977',
  landline: '01308 538046',
  landlineHref: '+441308538046',
  email: 'help@cousinsmechanicalservices.co.uk',

  /*
   * Where a supplier delivers. CHECK THIS before switching automatic reordering
   * on.
   *
   * The purchase-order email used to carry "Unit 4, Dreadnought Trading Estate,
   * Bridport, Dorset, DT6 5BU" and a phone number, 01308 422000, that appeared
   * nowhere else in the entire codebase — every other page uses 01308 538046.
   * Neither could be verified against anything, and they read as invented
   * filler that nobody caught because no PO has ever been sent.
   *
   * It now defaults to the registered office and the real numbers, because a
   * delivery address that is definitely right is worth more than one that
   * sounds more like a garage. If goods actually go somewhere else, put the
   * real address here.
   */
  deliveryAddress: '7 Watton Park, Bridport, DT6 5NJ',

  /* Web */
  domain: 'cousinsmechanicalservices.co.uk',
  siteUrl: 'https://cousinsmechanicalservices.co.uk',

  /* What and where */
  trade: 'Mobile Mechanic & Tyre Fitting',
  area: 'Bridport & West Dorset',

  /* Where a data-protection question goes. Same inbox today, but it is asked
   * for by name in the privacy notice, so it gets its own field: the day it
   * becomes a separate address, nothing else has to change. */
  privacyEmail: 'help@cousinsmechanicalservices.co.uk',

  /* The supervisory authority named in the privacy notice. UK-specific. */
  regulator: {
    name: "Information Commissioner's Office",
    url: 'https://ico.org.uk',
    phone: '0303 123 1113',
  },
};

/*
 * Token substitution for the legal page bodies, which are plain HTML rather
 * than templates. Any {{ business.field }} in them is filled at build time.
 *
 * Deliberately strict: an unknown token is left ALONE rather than replaced
 * with an empty string. A privacy notice that silently loses the company's
 * address is worse than one that visibly still says {{ business.foo }} — and
 * the build test that forbids unfilled placeholders will then catch it.
 */
export function fillBusinessTokens(html) {
  return String(html).replace(/\{\{\s*business\.([a-zA-Z][\w.]*)\s*\}\}/g, (whole, path) => {
    let v = BUSINESS;
    for (const part of path.split('.')) {
      if (v == null || typeof v !== 'object' || !(part in v)) return whole;
      v = v[part];
    }
    return typeof v === 'string' || typeof v === 'number' ? String(v) : whole;
  });
}
