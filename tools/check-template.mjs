/*
 * check-template.mjs — catch the ways a .dc.html edit breaks silently.
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
 *   2. Every {{ binding }} in the markup is a name renderVals() actually
 *      RETURNS.
 *
 * That second check used to be much weaker, and it cost real money. It counted
 * a name as "produced" if it appeared anywhere in the logic as `name =` or
 * `name:` — so a method written as a class field,
 *
 *     googleSignIn = async () => { ... }
 *
 * and then never put into the object renderVals() returns, passed the check
 * while the button it was bound to rendered with NO onClick at all. Sign in
 * with Google on the public site and the driver portal were dead on arrival and
 * stayed dead through several rounds of "fixing" the server, which was never
 * the broken half. A binding that resolves to undefined is invisible: the
 * button looks perfect and does nothing.
 *
 * So the check now parses the object literal renderVals() returns and takes its
 * top-level keys, following `...this.someHelper()` spreads one level down. If
 * it meets a spread it cannot resolve it says so rather than quietly widening.
 *
 *   node tools/check-template.mjs "Cousins Admin.dc.html"
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const files = process.argv.slice(2);
if (!files.length) { console.error('usage: check-template.mjs <file.dc.html> [...]'); process.exit(2); }

/**
 * How far to skip from `i`, if a string, comment or regex literal starts there.
 *
 * Regex literals matter: `.replace(/'/g, "%27")` contains a lone apostrophe,
 * and a scanner that mistakes it for the start of a string runs off the end of
 * the object it was reading and reports every remaining binding as missing.
 * Telling a regex from a division is the usual heuristic — look at the last
 * meaningful character before the slash.
 */
function skipToken(src, i, prevSignificant) {
  const two = src.slice(i, i + 2);
  if (two === '//') { const j = src.indexOf('\n', i); return (j < 0 ? src.length : j) - i; }
  if (two === '/*') { const j = src.indexOf('*/', i); return (j < 0 ? src.length : j + 2) - i; }
  const c = src[i];
  if (c === '"' || c === "'" || c === '`') {
    let j = i + 1;
    while (j < src.length) {
      if (src[j] === '\\') { j += 2; continue; }
      if (src[j] === c) break;
      if (c === '`' && src.slice(j, j + 2) === '${') {
        let d = 1; j += 2;
        while (j < src.length && d > 0) { if (src[j] === '{') d++; else if (src[j] === '}') d--; j++; }
        continue;
      }
      j++;
    }
    return j + 1 - i;
  }
  // The LAST significant character, not the whole tail — `.includes` on the
  // eight-character tail is always false, which quietly turned this test off.
  const last = String(prevSignificant).slice(-1);
  if (c === '/' && (last === '' || '(,=:[!&|?{};+-*%~^<>'.includes(last)
      || /\b(return|typeof|case|in|of|new|delete|void|do|else)$/.test(prevSignificant))) {
    let j = i + 1, inClass = false;
    while (j < src.length) {
      if (src[j] === '\\') { j += 2; continue; }
      if (src[j] === '[') inClass = true;
      else if (src[j] === ']') inClass = false;
      else if (src[j] === '/' && !inClass) break;
      else if (src[j] === '\n') return 1; // not a regex after all
      j++;
    }
    while (j < src.length && /[a-z]/.test(src[j + 1] || '')) j++;
    return j + 1 - i;
  }
  return 0;
}

/**
 * Walk an object literal and report its top-level keys and spreads.
 *
 * `open` is the index of the opening brace. Strings, template literals,
 * comments and nested braces/brackets/parens are skipped, so a key inside a
 * nested object or an arrow-function body is never mistaken for a top-level
 * one — which matters, because renderVals() is mostly nested objects.
 */
function objectLiteral(src, open) {
  const keys = new Set();
  const spreads = [];
  // `foo: this.bar` — the value is a bare method reference, which is the shape
  // that loses its `this` (see the handler check below).
  const methodRefs = new Set();
  let i = open + 1;
  let depth = 1;
  // Text of the current top-level segment, so a key can be read off the front.
  let seg = '';
  const flush = () => {
    const s = seg.trim();
    seg = '';
    if (!s) return;
    if (s.startsWith('...')) { spreads.push(s.slice(3).trim()); return; }
    const kv = s.match(/^([A-Za-z_$][\w$]*)\s*:/);
    if (kv) {
      keys.add(kv[1]);
      const bare = s.match(/^[A-Za-z_$][\w$]*\s*:\s*this\.([A-Za-z_$][\w$]*)\s*$/);
      if (bare) methodRefs.add(bare[1]);
      return;
    }
    const short = s.match(/^([A-Za-z_$][\w$]*)$/);
    if (short) keys.add(short[1]);
    // A quoted key: 'name': value
    const q = s.match(/^['"]([^'"]+)['"]\s*:/);
    if (q) keys.add(q[1]);
  };
  let prev = '';
  while (i < src.length) {
    const c = src[i];
    const skip = skipToken(src, i, prev);
    if (skip > 0) {
      // A comment is not part of the value: appending it puts "// note" in
      // front of the key and the key stops being recognised at all.
      const isComment = src.startsWith('//', i) || src.startsWith('/*', i);
      if (depth === 1 && !isComment) seg += src.slice(i, i + skip);
      if (!isComment) prev = 'x';
      i += skip;
      continue;
    }
    if (!/\s/.test(c)) prev = (prev + c).slice(-8);
    if (c === '{' || c === '[' || c === '(') {
      if (depth === 1) seg += c;
      depth++; i++; continue;
    }
    if (c === '}' || c === ']' || c === ')') {
      depth--;
      if (depth === 0) { flush(); return { keys, spreads, methodRefs, end: i }; }
      if (depth === 1) seg += c;
      i++; continue;
    }
    if (c === ',' && depth === 1) { flush(); i++; continue; }
    if (depth === 1) seg += c;
    i++;
  }
  return { keys, spreads, methodRefs, end: src.length };
}

/**
 * The object literal `name(...)` returns from its OWN body.
 *
 * It has to be the return at the method's top level, not the first `return {`
 * in the text: renderVals() is full of `.map(x => ({ ... }))`, and taking one
 * of those instead reports every real binding as missing — a check that cries
 * wolf 400 times is a check somebody deletes.
 */
function returnedObjectOf(logic, name) {
  const decl = new RegExp('(?:^|[\\s;}])' + name + '\\s*\\([^)]*\\)\\s*\\{', 'm').exec(logic);
  if (!decl) return null;
  let i = decl.index + decl[0].length;
  let depth = 0;
  let prev = '';
  while (i < logic.length) {
    const c = logic[i];
    const skip = skipToken(logic, i, prev);
    if (skip > 0) {
      if (!(logic.startsWith('//', i) || logic.startsWith('/*', i))) prev = 'x';
      i += skip; continue;
    }
    if (!/\s/.test(c)) prev = (prev + c).slice(-8);
    if (c === '{' || c === '(' || c === '[') { depth++; i++; continue; }
    if (c === '}' || c === ')' || c === ']') { depth--; if (depth < 0) return null; i++; continue; }
    if (depth === 0 && logic.startsWith('return', i) && !/[\w$]/.test(logic[i - 1] || '') && !/[\w$]/.test(logic[i + 6] || '')) {
      let j = i + 6;
      while (j < logic.length && /\s/.test(logic[j])) j++;
      if (logic[j] === '{') return objectLiteral(logic, j);
      i = j; continue;
    }
    i++;
  }
  return null;
}

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

  // ---- 2. is every {{ binding }} actually RETURNED by renderVals()? --------
  // Comments are not markup: a {{ token }} written inside one is documentation,
  // not a binding, and counting it produces a failure nobody can act on.
  const markup = src.slice(0, script.index).replace(/<!--[\s\S]*?-->/g, '');
  const logic = script[1];

  const used = new Set();
  for (const m of markup.matchAll(/\{\{\s*([A-Za-z_$][\w$]*)/g)) used.add(m[1]);
  // Names introduced by <sc-for ... as="x"> are loop variables, not bindings.
  const loopVars = new Set([...markup.matchAll(/<sc-for[^>]*\bas=["']([^"']+)["']/g)].map(m => m[1]));

  /*
   * There is exactly ONE loop form the runtime understands.
   *
   * walkFor() in support.js reads `list` and `as` and nothing else. It never
   * looks at `each`. So `<sc-for each="{{ rows }}">` compiles an empty list
   * expression, gets undefined, and renders nothing at all — no error, no
   * warning, just a hole in the page where the rows should be.
   *
   * This checker used to EXEMPT those blocks, on the belief that `each` was a
   * second loop form that put the row's fields into scope unnamed. It is not.
   * That exemption is how six dead lists reached production, including the
   * whole of the Calendar tab, which drew its headings and then nothing.
   *
   * So the rule is now the opposite of an exemption: any sc-for without a
   * `list` attribute is a failure, and the row fields inside a real one are
   * reached through the `as` alias like every other binding.
   */
  for (const open of markup.matchAll(/<sc-for\b[^>]*>/g)) {
    if (/\blist=/.test(open[0])) continue;
    const line = markup.slice(0, open.index).split('\n').length;
    console.error(`${label}:${line}: ${open[0].slice(0, 70)} has no list= attribute.`);
    console.error('  The runtime only reads list= and as=. This loop renders nothing, silently.');
    console.error('  Use: <sc-for list="{{ rows }}" as="r"> ... {{ r.field }} ... </sc-for>');
    failed++;
  }
  const itemScoped = new Set();

  const top = returnedObjectOf(logic, 'renderVals');
  if (!top) {
    console.error(`${label}: could not find the object renderVals() returns — cannot verify any binding`);
    failed++;
    continue;
  }

  const produced = new Set(['true', 'false', 'null', ...top.keys]);
  const unresolved = [];
  for (const s of top.spreads) {
    const call = s.match(/^this\.([A-Za-z_$][\w$]*)\s*\(/);
    const helper = call ? returnedObjectOf(logic, call[1]) : null;
    if (helper) for (const k of helper.keys) produced.add(k);
    else unresolved.push(s);
  }
  if (unresolved.length) {
    console.log(`${label}: note — ${unresolved.length} spread(s) in renderVals() could not be resolved: ${unresolved.join(', ')}`);
  }

  /*
   * A {{ binding }} in src / srcset / poster can never work.
   *
   * dc-placeholder.js rewrites those attributes to a blank 1x1 GIF before the
   * page is served, so the browser does not fetch a literal "{{ t.image }}"
   * URL — and the runtime then compiles the template from that same rewritten
   * HTML, so the binding is gone by the time anything could use it. Every tyre
   * thumbnail on the site and in the admin catalogue was a blank GIF for
   * exactly this reason, and it is invisible: the alt text still binds, the
   * layout is right, there is simply never a picture.
   *
   * Use a bound style with a background-image instead.
   */
  const fetched = [...markup.matchAll(/\b(src|srcset|poster)\s*=\s*(["'])\s*\{\{([^"']*?)\}\}\s*\2/gi)];
  if (fetched.length) {
    console.error(`${label}: ${fetched.length} binding(s) in an attribute the browser fetches — these are stripped`);
    console.error('  before the runtime sees them, so they render as a blank image, always.');
    console.error('  Use a bound style with background-image instead.');
    for (const m of fetched) console.error(`  ${m[1]}="{{${m[3]}}}"`);
    failed++;
  }

  /*
   * A handler handed over as `onClick: this.doThing` must carry its own `this`.
   *
   * Written as a class METHOD — `doThing(){...}` or `async doThing(){...}` —
   * the reference arrives at the button detached from the instance, and the
   * first `this.setState` inside it throws "Cannot read properties of undefined
   * (reading 'state')". The button looks right, does nothing visible, and the
   * only trace is one line in a console nobody has open. Written as a class
   * FIELD — `doThing = () => {...}` — it is bound for life.
   *
   * Every working handler in these files is already a field. This makes the
   * next one that is not a build failure rather than a bug report.
   */
  const detached = [];
  for (const name of top.methodRefs || []) {
    // A field wins wherever both could match: `name = ...` is unambiguous.
    if (new RegExp('(?:^|[;{}\\n])\\s*' + name + '\\s*=', 'm').test(logic)) continue;
    if (new RegExp('(?:^|[;{}\\n])\\s*(?:async\\s+)?' + name + '\\s*\\([^)]*\\)\\s*\\{', 'm').test(logic)) {
      detached.push(name);
    }
  }
  if (detached.length) {
    console.error(`${label}: ${detached.length} handler(s) passed to the view as a plain class method.`);
    console.error('  These reach the button with no `this`, so the first setState inside them throws');
    console.error('  and the click does nothing. Declare them as arrow fields instead:');
    for (const n of detached) console.error(`  ${n}(){ ... }   ->   ${n} = () => { ... }`);
    failed++;
  }

  const missing = [...used].filter(n => !produced.has(n) && !loopVars.has(n) && !itemScoped.has(n));
  if (missing.length > used.size / 4) {
    // Not 100 new bugs at once — this check lost its place in the source.
    console.error(`${label}: ${missing.length} of ${used.size} bindings look missing, which means this`);
    console.error('  check has lost sync reading renderVals() rather than found that many faults.');
    console.error('  Look for syntax it cannot follow (a regex literal, an unusual string) near the top of it.');
    failed++;
  } else if (missing.length) {
    console.error(`${label}: ${missing.length} binding(s) used in the markup that renderVals() never returns.`);
    console.error('  These render as undefined. A text binding shows blank; an onClick binding');
    console.error('  produces a button with NO handler — it looks right and does nothing.');
    for (const n of missing) console.error('  {{ ' + n + ' }}');
    failed++;
  } else {
    const scoped = [...itemScoped].filter(n => !produced.has(n)).length;
    console.log(`${label}: all ${used.size} bindings are returned by renderVals()`
      + (scoped ? ` (${scoped} more come from <sc-for each> row fields)` : ''));
  }
}

process.exit(failed ? 1 : 0);
