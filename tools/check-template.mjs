/*
 * check-template.mjs — catch the two ways a .dc.html edit breaks silently.
 *
 * The design-canvas runtime evaluates the inline logic class at RUNTIME. A
 * syntax error in it does not fail the build, does not fail the tests, and does
 * not show up in the served HTML: the page renders with the template's
 * placeholder values and every button does nothing. That is exactly how the CSP
 * change took the live admin down, and a static check is what would have caught
 * it a day earlier.
 *
 * Two checks:
 *   1. The logic class parses. `node --check` on the extracted script.
 *   2. Every {{ binding }} in the markup is a name the logic actually produces.
 *      A typo there renders as an empty string, so a mislabelled button just
 *      looks like a design choice.
 *
 *   node tools/check-template.mjs "Cousins Admin.dc.html"
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const files = process.argv.slice(2);
if (!files.length) { console.error('usage: check-template.mjs <file.dc.html> [...]'); process.exit(2); }

let failed = 0;

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8');
  const label = path.basename(file);

  // ---- 1. does the logic class parse? -------------------------------------
  const script = src.match(/<script[^>]*type=["']text\/x-dc["'][^>]*>([\s\S]*?)<\/script>/);
  if (!script) {
    console.error(`${label}: no <script type="text/x-dc"> block found`);
    failed++;
    continue;
  }
  const tmp = path.join(os.tmpdir(), 'dc-check-' + label.replace(/\W+/g, '_') + '.mjs');
  fs.writeFileSync(tmp, script[1]);
  try {
    execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
    console.log(`${label}: logic class parses`);
  } catch (e) {
    console.error(`${label}: LOGIC CLASS DOES NOT PARSE — the page would render with placeholders and dead buttons`);
    console.error(String(e.stderr || e.message).split('\n').slice(0, 12).join('\n'));
    failed++;
    continue;
  } finally {
    fs.rmSync(tmp, { force: true });
  }

  // ---- 2. is every {{ binding }} actually produced? ------------------------
  const markup = src.slice(0, script.index);
  const used = new Set();
  for (const m of markup.matchAll(/\{\{\s*([A-Za-z_$][\w$]*)/g)) used.add(m[1]);

  // Names introduced by <sc-for ... as="x"> are loop variables, not bindings.
  const loopVars = new Set([...markup.matchAll(/<sc-for[^>]*\bas=["']([^"']+)["']/g)].map(m => m[1]));

  // Anything the logic assigns as an object key, a class field or a method is a
  // candidate. Deliberately generous: this exists to catch typos, and a false
  // alarm on a real binding is how a check like this gets switched off.
  const logic = script[1];
  const produced = new Set(['true', 'false', 'null']);
  for (const m of logic.matchAll(/(?:^|[\s{,(])([A-Za-z_$][\w$]*)\s*:/gm)) produced.add(m[1]);
  for (const m of logic.matchAll(/(?:^|\s)([A-Za-z_$][\w$]*)\s*=/gm)) produced.add(m[1]);
  for (const m of logic.matchAll(/^\s{2,6}([A-Za-z_$][\w$]*)\s*\(/gm)) produced.add(m[1]);
  // A spread hides its keys behind a call — `...this.systemBindings(s)` — so
  // take the keys of every object literal in the file, which the first pattern
  // above already does. Nothing more to do; noted so the gap is not a surprise.

  const missing = [...used].filter(n => !produced.has(n) && !loopVars.has(n));
  if (missing.length) {
    console.error(`${label}: ${missing.length} binding(s) used in the markup that the logic never sets:`);
    for (const n of missing) console.error('  {{ ' + n + ' }}');
    failed++;
  } else {
    console.log(`${label}: all ${used.size} bindings are produced by the logic`);
  }
}

process.exit(failed ? 1 : 0);
