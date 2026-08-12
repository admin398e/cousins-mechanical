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

function enrich(item, costMap, size) {
  const cost = costMap[String(item.id)] || {};
  return {
    id: item.id,
    brand: item.b,
    model: item.m,
    label: item.l,
    sku: item.k,
    image: item.img && item.img !== 'no_image.jpg' ? `/images/${item.img}` : FALLBACK_IMAGE,
    price: item.price,
    cost: cost.cost ?? null,
    ean: cost.ean ?? null,
    sourceUrl: cost.src ?? null,
    size,
  };
}

export function lookupBySize(catalogue, costMap, rawSize) {
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

  // Cheapest first — the customer-facing cards read better ascending, and the
  // admin reorder screen wants the same ordering.
  const tyres = items
    .map(i => enrich(i, costMap, matchedKey))
    .sort((a, b) => (a.price ?? Infinity) - (b.price ?? Infinity));

  return { size: matchedKey, total: tyres.length, tyres };
}

export function search(catalogue, costMap, query, limit = 100) {
  const q = String(query || '').toLowerCase().trim();
  if (!q) return { query: '', total: 0, tyres: [] };

  const results = [];
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
        results.push(enrich(item, costMap, sizeKey));
      }
    }
  }

  return { query: q, total: results.length, tyres: results.slice(0, limit) };
}

export function byId(catalogue, costMap, id) {
  const target = Number(id);
  if (!Number.isFinite(target)) return null;
  for (const [sizeKey, list] of Object.entries(catalogue)) {
    for (const item of list) {
      if (item.id === target) return enrich(item, costMap, sizeKey);
    }
  }
  return null;
}
