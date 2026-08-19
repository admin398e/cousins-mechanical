/*
 * tyre-data.js — pure tyre catalogue logic, shared by the Worker and the dev server.
 *
 * Deliberately has no `fs` and no `fetch`: the caller supplies the already-parsed
 * catalogue and cost map. That keeps one copy of the size-matching rules, which is
 * the part that is easy to get subtly wrong in two places — previously the Worker
 * had no tyre code at all, so production silently fell back to placeholder prices.
 *
 *   catalogue : { "195/65R15": [ { id, b, m, l, k, img, price }, ... ], ... }
 *   costMap   : { "<id>": { cost, ean, src }, ... }
 */

const FALLBACK_IMAGE = '/images/qs-tyre-round.png';

/* ---------------------------------------------------------------------------
 * Pricing
 *
 * The customer never sees the wholesale cost or the supplier link — those are
 * admin-only and are attached by `forAdmin()`, never by the public lookup.
 *
 * Retail price for a tyre is, in order of precedence:
 *   1. an explicit per-tyre override the admin typed in
 *   2. cost + the tier's markup % + the fitting fee, rounded
 *   3. the catalogue's own scraped price (only if we have no cost for it)
 * ------------------------------------------------------------------------- */

export const DEFAULT_PRICING = {
  // Markup applied to wholesale cost, per tier. Budget carries the highest
  // percentage because the cash margin on a £40 tyre is otherwise tiny.
  markupPct: { B: 60, M: 50, P: 42 },
  fittingFee: 15,      // £ added per tyre — mobile fitting, valve, balance, disposal
  roundTo: 1,          // round the final price to the nearest £1
  priceEnding: null,   // e.g. 0.99 to make prices end .99; null = plain rounding
  overrides: {},       // { "<tyreId>": 89.5 }
  inStock: [],         // tyre ids the admin has marked as physically in stock

  // The floor. No offer, sale or manual override may ever price a tyre below
  // cost + this, in pounds. It exists so a sale can be run without anyone
  // having to check every line by hand: the discount is applied, and where it
  // would eat the margin the price simply stops falling.
  minMargin: 25,

  // Offers. Several can be live at once; the customer gets the best one they
  // qualify for, never several stacked, because stacking is how a 20% sale and
  // a 20% clearance quietly become 36% off.
  promos: [],
  updatedAt: null,
};

/** An empty scope means "everything" — that is the common case for a sale. */
export function promoApplies(promo, tyre, now) {
  if (!promo || promo.active === false) return false;
  const t = Number(now == null ? 0 : now);
  if (promo.starts && t && t < Number(promo.starts)) return false;
  if (promo.ends && t && t > Number(promo.ends)) return false;
  const s = promo.scope || {};
  const has = a => Array.isArray(a) && a.length > 0;
  if (has(s.ids) && !s.ids.map(Number).includes(Number(tyre.id))) return false;
  if (has(s.tiers) && !s.tiers.includes(tyre.tier)) return false;
  if (has(s.brands) && !s.brands.map(x => String(x).toLowerCase()).includes(String(tyre.brand || '').toLowerCase())) return false;
  if (has(s.sizes) && !s.sizes.map(x => normaliseSize(x)).includes(normaliseSize(tyre.size))) return false;
  return true;
}

/** What one offer would charge for a tyre currently priced at `base`. */
export function promoPrice(promo, base) {
  const v = Number(promo.value);
  if (!Number.isFinite(v) || v < 0) return base;
  if (promo.kind === 'percent') return base * (1 - Math.min(100, v) / 100);
  if (promo.kind === 'amount') return base - v;
  if (promo.kind === 'fixed') return v;
  return base;
}

export const TIER_LABELS = { B: 'Budget', M: 'Mid-range', P: 'Premium' };

/** Merge a stored pricing record over the defaults, tolerating partial saves. */
export function normalisePricing(p) {
  const s = p || {};
  return {
    ...DEFAULT_PRICING,
    ...s,
    markupPct: { ...DEFAULT_PRICING.markupPct, ...(s.markupPct || {}) },
    overrides: s.overrides || {},
    inStock: Array.isArray(s.inStock) ? s.inStock : [],
    minMargin: Number.isFinite(Number(s.minMargin)) ? Number(s.minMargin) : DEFAULT_PRICING.minMargin,
    promos: Array.isArray(s.promos) ? s.promos : [],
  };
}

/**
 * Split a size's tyres into Budget / Mid / Premium by wholesale cost.
 *
 * Terciles rather than fixed price bands, because what counts as "premium" in a
 * 155/60R15 is nothing like a 285/35R21. Returns a Map of id -> 'B' | 'M' | 'P'.
 */
export function assignTiers(items, costMap) {
  const priced = items
    .map(i => ({ id: i.id, cost: costMap[String(i.id)]?.cost ?? i.price ?? 0 }))
    .sort((a, b) => a.cost - b.cost);

  const tiers = new Map();
  const n = priced.length;
  if (n === 0) return tiers;

  // With very few tyres in a size, don't invent three tiers.
  if (n <= 2) {
    priced.forEach((t, i) => tiers.set(t.id, i === 0 ? 'B' : 'P'));
    return tiers;
  }

  const cut1 = Math.floor(n / 3);
  const cut2 = Math.floor((2 * n) / 3);
  priced.forEach((t, i) => tiers.set(t.id, i < cut1 ? 'B' : i < cut2 ? 'M' : 'P'));
  return tiers;
}

/**
 * The customer-facing product code.
 * Format: CUZ/<wholesaler ref><tier letter>, e.g. CUZ/4717622059212B
 * The wholesaler ref is the EAN where we have one — that is the code ctyres
 * themselves key on — so the office can quote a customer code straight back at
 * the supplier without a lookup table.
 */
export function cousinsSku(item, costInfo, tier) {
  const ref = costInfo?.ean || item.k || String(item.id);
  return `CUZ/${ref}${tier || ''}`;
}

/** Round a price per the admin's rounding preference. */
function applyRounding(value, pricing) {
  const step = Number(pricing.roundTo) || 1;
  let out = Math.round(value / step) * step;
  if (pricing.priceEnding != null && pricing.priceEnding !== '') {
    const ending = Number(pricing.priceEnding);
    out = Math.floor(out) + ending;      // e.g. 89 -> 89.99
  }
  return Math.round(out * 100) / 100;
}

/**
 * Work out what the customer pays for one tyre, fitted.
 * Returns the number plus how it was arrived at, so the admin screen can show
 * the margin without recomputing it.
 */
export function retailPrice(item, costInfo, tier, pricing, ctx = {}) {
  const p = normalisePricing(pricing);
  const cost = costInfo?.cost ?? null;
  const override = p.overrides[String(item.id)];
  const now = ctx.now == null ? Date.now() : ctx.now;

  let base, source, markupPct = null;
  if (override != null && override !== '' && Number.isFinite(Number(override))) {
    base = Number(override);
    source = 'override';
  } else if (cost == null) {
    // No wholesale cost for this line — fall back to the scraped catalogue price
    // rather than inventing one. With no cost there is no floor to enforce
    // either, so offers are skipped: discounting a price we cannot check the
    // margin on is exactly what the floor exists to prevent.
    return { price: item.price ?? null, source: 'catalogue', cost: null, markupPct: null, was: null, promo: null, floored: false };
  } else {
    markupPct = Number(p.markupPct[tier] ?? p.markupPct.M ?? 50);
    base = cost * (1 + markupPct / 100) + Number(p.fittingFee || 0);
    source = 'calculated';
  }

  // An override means "charge exactly this". Rounding it to the nearest pound
  // would quietly turn £199.50 into £200, which is not what the person typing
  // it asked for — so the rounding rules apply to CALCULATED prices only.
  const listPrice = source === 'override' ? Math.round(base * 100) / 100 : applyRounding(base, p);

  // Best single offer, never several stacked.
  const candidate = { id: item.id, tier, brand: item.b, size: ctx.size || '' };
  let best = null, bestPrice = base;
  for (const promo of p.promos) {
    if (!promoApplies(promo, candidate, now)) continue;
    const next = promoPrice(promo, base);
    if (next < bestPrice) { bestPrice = next; best = promo; }
  }

  // The floor, applied last so it beats offers AND manual overrides. An
  // override typed below cost is a slip of the keyboard far more often than it
  // is a decision, and either way the business cannot carry it.
  const floor = cost == null ? null : cost + Number(p.minMargin || 0);
  let finalRaw = best ? bestPrice : base;
  let floored = false;
  if (floor != null && finalRaw < floor) { finalRaw = floor; floored = true; }

  let price = (source === 'override' && !best) ? Math.round(finalRaw * 100) / 100 : applyRounding(finalRaw, p);
  // Rounding runs after the floor, so a "round to nearest £1" could hand back
  // 48p less than the floor allows. Where the floor is doing the work, round UP
  // instead — a floor that rounds down is not a floor.
  if (floor != null && price < floor) {
    const step = Number(p.roundTo) > 0 ? Number(p.roundTo) : 1;
    price = Math.ceil(floor / step) * step;
    if (p.priceEnding != null && p.priceEnding !== '') price = Math.floor(price) + Number(p.priceEnding);
    price = Math.round(price * 100) / 100;
    floored = true;
  }
  return {
    price, source, cost, markupPct, floored,
    // `was` is only set when the customer is actually paying less, so the site
    // never shows a struck-through price identical to the one next to it.
    was: price < listPrice ? listPrice : null,
    promo: best && price < listPrice ? { id: best.id, name: best.name || 'Offer' } : null,
  };
}

/**
 * Normalise the many ways a tyre size gets typed into the catalogue's key format
 * (e.g. "195/65R15"). Accepts "195/65/15", "195 65 15", "195/65 R15", "19565R15".
 */
export function normaliseSize(rawSize) {
  if (!rawSize) return '';
  const clean = String(rawSize).toUpperCase().trim();

  // 195/65R15, 195/65 R 15, 195/65-15, 195/65/15, 195 65 15
  const m = clean.match(/(\d{3})\s*[\/\s-]\s*(\d{2})\s*[\/\sR-]*\s*(\d{2})/);
  if (m) return `${m[1]}/${m[2]}R${m[3]}`;

  // 19565R15 / 1956515 with no separators at all
  const digits = clean.replace(/[^0-9]/g, '');
  if (digits.length === 7) return `${digits.slice(0, 3)}/${digits.slice(3, 5)}R${digits.slice(5, 7)}`;

  return clean.replace(/\s+/g, '');
}

/**
 * Build the customer-facing record for one tyre.
 *
 * Note what is NOT here: wholesale cost, margin, EAN and the supplier URL. Those
 * are commercially sensitive and are added only by `forAdmin()`. Anyone can call
 * /api/tyres/lookup, so leaking cost here would publish the client's buy prices.
 */
function enrich(item, costMap, size, tier, pricing) {
  const cost = costMap[String(item.id)] || {};
  const p = normalisePricing(pricing);
  const priced = retailPrice(item, cost, tier, p, { size });

  return {
    id: item.id,
    brand: item.b,
    model: item.m,
    label: item.l,
    sku: cousinsSku(item, cost, tier),
    tier: tier || null,
    tierLabel: tier ? TIER_LABELS[tier] : null,
    image: item.img && item.img !== 'no_image.jpg' ? `/images/${item.img}` : FALLBACK_IMAGE,
    price: priced.price,
    // Customer-facing sale fields. `wasPrice` is the pre-offer price and is null
    // unless there really is a saving, so the site cannot render a fake discount.
    wasPrice: priced.was,
    offer: priced.promo ? priced.promo.name : null,
    inStock: p.inStock.includes(item.id),
    size,
  };
}

/**
 * Re-attach the trade-only fields for the admin dashboard: what we pay, what we
 * make, the supplier's own code and a direct link to the product page so the
 * office can reorder in one click.
 */
export function forAdmin(publicTyre, item, costMap, pricing) {
  const cost = costMap[String(publicTyre.id)] || {};
  const detail = retailPrice(item, cost, publicTyre.tier, pricing, { size: publicTyre.size });
  const margin = detail.price != null && detail.cost != null ? detail.price - detail.cost : null;

  return {
    ...publicTyre,
    supplierSku: item.k,
    ean: cost.ean ?? null,
    supplierUrl: cost.src ?? null,
    cost: detail.cost,
    priceSource: detail.source,
    markupPct: detail.markupPct,
    margin: margin == null ? null : Math.round(margin * 100) / 100,
    marginPct: margin == null || !detail.cost ? null : Math.round((margin / detail.cost) * 1000) / 10,
    cataloguePrice: item.price ?? null,
    // `floored` means an offer or an override wanted to go lower and the margin
    // floor stopped it. Worth showing: it is the difference between "the sale is
    // running" and "the sale is running but not on this line".
    floored: !!detail.floored,
    promoName: detail.promo ? detail.promo.name : null,
  };
}

export function lookupBySize(catalogue, costMap, rawSize, pricing) {
  const key = normaliseSize(rawSize);
  if (!key) return { size: '', total: 0, tyres: [] };

  let matchedKey = key;
  let items = catalogue[key] || [];

  // Fall back to comparing digits only, so "195/65R15" still finds "195/65 R15".
  if (items.length === 0) {
    const wanted = key.replace(/[^0-9]/g, '');
    for (const [k, list] of Object.entries(catalogue)) {
      if (k.replace(/[^0-9]/g, '') === wanted) {
        items = list;
        matchedKey = k;
        break;
      }
    }
  }

  // Tier by wholesale cost across the whole size, then price each tyre.
  const tiers = assignTiers(items, costMap);
  const tyres = items
    .map(i => enrich(i, costMap, matchedKey, tiers.get(i.id), pricing))
    .sort((a, b) => (a.price ?? Infinity) - (b.price ?? Infinity));

  return { size: matchedKey, total: tyres.length, tyres };
}

/**
 * Same lookup, but with the trade fields attached. Admin routes only.
 */
export function lookupBySizeAdmin(catalogue, costMap, rawSize, pricing) {
  const pub = lookupBySize(catalogue, costMap, rawSize, pricing);
  const byId = {};
  for (const list of Object.values(catalogue)) for (const i of list) byId[i.id] = i;
  return {
    ...pub,
    tyres: pub.tyres.map(t => forAdmin(t, byId[t.id] || {}, costMap, pricing)),
  };
}

export function search(catalogue, costMap, query, limit = 100, pricing) {
  const q = String(query || '').toLowerCase().trim();
  if (!q) return { query: '', total: 0, tyres: [] };

  const results = [];
  const tierCache = {};
  for (const [sizeKey, list] of Object.entries(catalogue)) {
    const sizeHit = sizeKey.toLowerCase().includes(q);
    for (const item of list) {
      if (
        sizeHit ||
        (item.b || '').toLowerCase().includes(q) ||
        (item.m || '').toLowerCase().includes(q) ||
        (item.l || '').toLowerCase().includes(q) ||
        (item.k || '').toLowerCase().includes(q)
      ) {
        const tier = tierCache[sizeKey] || (tierCache[sizeKey] = assignTiers(list, costMap));
        results.push(enrich(item, costMap, sizeKey, tier.get(item.id), pricing));
      }
    }
  }

  return { query: q, total: results.length, tyres: results.slice(0, limit) };
}

/**
 * The whole catalogue, priced, for the admin screen.
 *
 * The pricing tab could only ever show one size at a time — you had to already
 * know which size to type. That makes a mispriced range invisible: nobody types
 * 275/50R19 on the off-chance. This walks every size, assigns tiers, prices each
 * line and hands back a filtered, sorted page of the lot, plus the facts you need
 * to spot a bad rule (worst margins first, tier price ranges, inversions).
 *
 * Trade-only fields are included, so this must stay behind admin auth.
 */
export function adminCatalogue(catalogue, costMap, pricing, opts = {}) {
  const q = String(opts.q || '').toLowerCase().trim();
  const brandWanted = String(opts.brand || '').toLowerCase().trim();
  const tierWanted = String(opts.tier || '').trim().toUpperCase();
  const stockOnly = opts.stock === true || opts.stock === 'true' || opts.stock === '1';
  const sort = String(opts.sort || 'size').trim();
  const perPage = Math.min(200, Math.max(12, Number(opts.perPage) || 60));
  const page = Math.max(1, Number(opts.page) || 1);
  const p = normalisePricing(pricing);

  const rows = [];
  const brandCounts = new Map();
  for (const [sizeKey, list] of Object.entries(catalogue)) {
    if (!Array.isArray(list) || !list.length) continue;
    const tiers = assignTiers(list, costMap);
    for (const item of list) {
      brandCounts.set(item.b, (brandCounts.get(item.b) || 0) + 1);
      if (brandWanted && String(item.b || '').toLowerCase() !== brandWanted) continue;
      const tier = tiers.get(item.id);
      if (tierWanted && tier !== tierWanted) continue;
      if (q && !(
        sizeKey.toLowerCase().includes(q) ||
        String(item.b || '').toLowerCase().includes(q) ||
        String(item.m || '').toLowerCase().includes(q) ||
        String(item.l || '').toLowerCase().includes(q) ||
        String(item.k || '').toLowerCase().includes(q)
      )) continue;
      const pub = enrich(item, costMap, sizeKey, tier, p);
      if (stockOnly && !pub.inStock) continue;
      rows.push(forAdmin(pub, item, costMap, p));
    }
  }

  // Summary over the FILTERED set, so narrowing to one brand tells you about
  // that brand rather than about the catalogue.
  const priced = rows.filter(r => r.price != null);
  const range = t => {
    const v = priced.filter(r => r.tier === t).map(r => r.price);
    return v.length ? { n: v.length, min: Math.min(...v), max: Math.max(...v) } : { n: 0, min: null, max: null };
  };
  const B = range('B'), M = range('M'), P = range('P');

  // The inversion check has to be done WITHIN a size and never across the
  // catalogue. A budget 285/35R21 outpricing a premium 155/70R13 is not a
  // pricing fault, it is just a bigger tyre — comparing the two would light a
  // warning on every single page. What is a fault is a customer being shown a
  // budget tyre dearer than a premium one for the car they actually drive.
  const bySize = new Map();
  for (const r of priced) {
    if (!r.tier || (r.tier !== 'B' && r.tier !== 'P')) continue;
    const e = bySize.get(r.size) || { bMax: null, pMin: null };
    if (r.tier === 'B') e.bMax = e.bMax == null ? r.price : Math.max(e.bMax, r.price);
    else e.pMin = e.pMin == null ? r.price : Math.min(e.pMin, r.price);
    bySize.set(r.size, e);
  }
  const invertedSizes = [...bySize.entries()]
    .filter(([, e]) => e.bMax != null && e.pMin != null && e.bMax > e.pMin)
    .map(([size, e]) => ({ size, budgetMax: e.bMax, premiumMin: e.pMin }))
    .sort((a, b) => (b.budgetMax - b.premiumMin) - (a.budgetMax - a.premiumMin));

  const summary = {
    total: rows.length,
    priced: priced.length,
    noCost: rows.filter(r => r.cost == null).length,
    overridden: rows.filter(r => r.priceSource === 'override').length,
    inStock: rows.filter(r => r.inStock).length,
    sizes: bySize.size,
    tiers: { B, M, P },
    invertedCount: invertedSizes.length,
    invertedSizes: invertedSizes.slice(0, 12),
    inverted: invertedSizes.length > 0,
  };

  const num = (v, hi) => (v == null ? (hi ? Infinity : -Infinity) : v);
  const sorters = {
    size: (a, b) => String(a.size).localeCompare(String(b.size)) || num(a.price, true) - num(b.price, true),
    priceAsc: (a, b) => num(a.price, true) - num(b.price, true),
    priceDesc: (a, b) => num(b.price, false) - num(a.price, false),
    marginAsc: (a, b) => num(a.margin, true) - num(b.margin, true),
    marginDesc: (a, b) => num(b.margin, false) - num(a.margin, false),
    marginPctDesc: (a, b) => num(b.marginPct, false) - num(a.marginPct, false),
    brand: (a, b) => String(a.brand).localeCompare(String(b.brand)) || String(a.size).localeCompare(String(b.size)),
  };
  rows.sort(sorters[sort] || sorters.size);

  const pages = Math.max(1, Math.ceil(rows.length / perPage));
  const start = (Math.min(page, pages) - 1) * perPage;

  return {
    total: rows.length, page: Math.min(page, pages), pages, perPage,
    brands: [...brandCounts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([name, count]) => ({ name, count })),
    summary,
    tyres: rows.slice(start, start + perPage),
  };
}

export function byId(catalogue, costMap, id, pricing) {
  const target = Number(id);
  if (!Number.isFinite(target)) return null;
  for (const [sizeKey, list] of Object.entries(catalogue)) {
    for (const item of list) {
      if (item.id === target) return enrich(item, costMap, sizeKey, assignTiers(list, costMap).get(item.id), pricing);
    }
  }
  return null;
}
