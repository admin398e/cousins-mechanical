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
  updatedAt: null,
};

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
export function retailPrice(item, costInfo, tier, pricing) {
  const p = normalisePricing(pricing);
  const override = p.overrides[String(item.id)];

  if (override != null && override !== '' && Number.isFinite(Number(override))) {
    const price = Math.round(Number(override) * 100) / 100;
    return { price, source: 'override', cost: costInfo?.cost ?? null, markupPct: null };
  }

  const cost = costInfo?.cost;
  if (cost == null) {
    // No wholesale cost for this line — fall back to the scraped catalogue price
    // rather than inventing one.
    return { price: item.price ?? null, source: 'catalogue', cost: null, markupPct: null };
  }

  const markupPct = Number(p.markupPct[tier] ?? p.markupPct.M ?? 50);
  const raw = cost * (1 + markupPct / 100) + Number(p.fittingFee || 0);
  return { price: applyRounding(raw, p), source: 'calculated', cost, markupPct };
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
  const { price } = retailPrice(item, cost, tier, p);

  return {
    id: item.id,
    brand: item.b,
    model: item.m,
    label: item.l,
    sku: cousinsSku(item, cost, tier),
    tier: tier || null,
    tierLabel: tier ? TIER_LABELS[tier] : null,
    image: item.img && item.img !== 'no_image.jpg' ? `/images/${item.img}` : FALLBACK_IMAGE,
    price,
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
  const detail = retailPrice(item, cost, publicTyre.tier, pricing);
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
