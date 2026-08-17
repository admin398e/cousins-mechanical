/*
 * tyre-db.js — Node-side tyre catalogue loader for server.js (local dev).
 *
 * Reads the JSON off disk once and delegates all matching to tyre-data.js, which
 * the Worker uses too. Keep the logic in tyre-data.js so dev and production
 * cannot disagree about what a size lookup returns.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { lookupBySize, lookupBySizeAdmin, search, byId } from './tyre-data.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let catalogue = null;
let sizes = null;
let costMap = null;

function readJson(relPath, fallback) {
  try {
    const full = path.join(__dirname, relPath);
    if (fs.existsSync(full)) return JSON.parse(fs.readFileSync(full, 'utf8'));
    console.error(`[tyre-db] missing ${relPath} — tyre lookups will return nothing`);
  } catch (e) {
    console.error(`[tyre-db] failed to parse ${relPath}:`, e.message);
  }
  return fallback;
}

function load() {
  if (!catalogue) catalogue = readJson(path.join('data', 'tyre-catalogue.json'), {});
  if (!sizes) sizes = readJson(path.join('data', 'tyre-sizes.json'), { tree: {}, widths: [] });
  if (!costMap) costMap = readJson(path.join('public', 'data', 'tyre-cost.json'), {});
}

export function getTyreSizes() {
  load();
  return sizes;
}

export function getTyreCatalogue() {
  load();
  return catalogue;
}

export function lookupTyresBySize(rawSize, pricing) {
  load();
  return lookupBySize(catalogue, costMap, rawSize, pricing);
}

export function lookupTyresBySizeAdmin(rawSize, pricing) {
  load();
  return lookupBySizeAdmin(catalogue, costMap, rawSize, pricing);
}

export function searchTyres(query, pricing) {
  load();
  return search(catalogue, costMap, query, 100, pricing);
}

export function getTyreById(id, pricing) {
  load();
  return byId(catalogue, costMap, id, pricing);
}

/** Sanity check used by server startup and `npm run check`. */
export function catalogueStats() {
  load();
  let total = 0;
  for (const list of Object.values(catalogue)) total += list.length;
  return { sizes: Object.keys(catalogue).length, tyres: total, costEntries: Object.keys(costMap).length };
}
