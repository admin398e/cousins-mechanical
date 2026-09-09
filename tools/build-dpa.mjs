/*
 * build-dpa.mjs — turn legal/data-processing-agreement.md into the two files a
 * client actually receives: the signable agreement, and the covering note that
 * explains it.
 *
 * Both come out of ONE source file, split on the AGREEMENT BEGINS marker.
 * The obvious alternative — keep a "working" markdown and a separate "signable"
 * copy — is how a security schedule ends up describing a system that changed
 * six weeks ago, which in a signed contract is a misrepresentation rather than
 * a stale document.
 *
 *   node tools/build-dpa.mjs [outputDir]
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const SRC = 'legal/data-processing-agreement.md';
const out = process.argv[2] || 'legal/build';
mkdirSync(out, { recursive: true });

const src = readFileSync(SRC, 'utf8');
const MARK = '<!-- AGREEMENT BEGINS -->';
if (!src.includes(MARK)) throw new Error(`${SRC} has no ${MARK} marker`);

const [front, body] = src.split(MARK);
const strip = t => t.replace(/<!--[\s\S]*?-->/g, '').replace(/\n{3,}/g, '\n\n').trim();

// A contract that still has a bracketed placeholder in it is worse than no
// contract: it looks like diligence and is not. Refuse to build one.
const holes = [...src.matchAll(/`\[[^\]]*\]`/g)].map(m => m[0]);
if (holes.length) {
  console.error(`REFUSING TO BUILD — ${holes.length} unfilled placeholder(s):`);
  for (const h of holes) console.error('  ' + h);
  process.exit(1);
}

const title = front.slice(0, front.indexOf('## Covering note')).trim();

const files = {
  'Cousins-DPA-agreement': title + '\n\n---\n\n' + strip(body),
  'Cousins-DPA-covering-note':
    '# Data Processing Agreement — covering note\n\n'
    + '**Cousins Mechanical Services Ltd and Rockwell Consulting**\n\n'
    + strip(front.slice(front.indexOf('## Covering note')))
        .replace(/^## Covering note — not part of the agreement\n+/, ''),
};

for (const [name, md] of Object.entries(files)) {
  const mdPath = path.join(out, name + '.md');
  writeFileSync(mdPath, md + '\n');
  execFileSync('pandoc', [mdPath, '-o', path.join(out, name + '.docx'),
    '--from', 'markdown+pipe_tables', '--standalone']);
  execFileSync('soffice', ['--headless', '--convert-to', 'pdf',
    '--outdir', out, path.join(out, name + '.docx')], { stdio: 'ignore' });
  console.log('  ' + name + '.docx + .pdf');
}
console.log('Built into ' + out);
