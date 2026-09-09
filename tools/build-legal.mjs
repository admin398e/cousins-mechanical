/*
 * build-legal.mjs — turn each markdown source in legal/ into the two files a
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

const DOCS = [
  { src: 'legal/data-processing-agreement.md', slug: 'Cousins-DPA',
    note: 'Data Processing Agreement — covering note', checkProvider: true },
  { src: 'legal/services-agreement.md', slug: 'Cousins-services',
    note: 'Website, Hosting and Marketing Agreement — covering note' },
];

const out = process.argv.find(a => !a.startsWith('--') && a !== process.argv[0]
  && a !== process.argv[1]) || 'legal/build';
mkdirSync(out, { recursive: true });

let anyMismatch = false;
for (const doc of DOCS) await build(doc);
process.exit(anyMismatch ? 1 : 0);

async function build({ src: SRC, slug, note, checkProvider }) {
console.log(SRC);

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

/*
 * Does the agreement name the payment processor the live system actually uses?
 *
 * v1.1 said SumUp for weeks while the site took money through Stripe. Nothing
 * caught it, because a contract is a document and nothing in the build had ever
 * read one. Section 6 is the part that tells the ICO who handles Cousins'
 * customers' payment data; if it and the running system disagree on the day of
 * signature, the document misrepresents the arrangement it exists to record.
 *
 * Deliberately a WARNING and an explicit flag rather than a hard failure: there
 * is a legitimate window where the agreement is drafted ahead of a switch and
 * has to be built before the switch lands. What must not happen is building
 * through a mismatch without noticing.
 */
if (checkProvider) {
const PROVIDERS = ['stripe', 'sumup'];
const named = PROVIDERS.filter(x => new RegExp(x, 'i').test(body));
const health = await fetch('https://cousinsmechanicalservices.co.uk/api/health')
  .then(r => r.json()).then(d => d?.configured?.paymentProvider || '')
  .catch(() => '');

if (!health) {
  console.warn('  ! could not reach /api/health — payment provider NOT verified');
} else if (named.length !== 1 || named[0] !== health.toLowerCase()) {
  const how = named.length === 1 ? `names ${named[0]}`
    : named.length ? `names more than one (${named.join(', ')})` : 'names none of them';
  console.error('');
  console.error('  PAYMENT PROVIDER MISMATCH');
  console.error(`    the agreement ${how}`);
  console.error(`    the live system reports  ${health}`);
  console.error('    Section 6 records who handles the customers\' payment data.');
  console.error('    Do not put this in front of anyone to sign until they agree.');
  if (!process.argv.includes('--accept-provider-mismatch')) {
    console.error('');
    console.error('    Re-run with --accept-provider-mismatch if this is intentional');
    console.error('    (drafted ahead of a switch that has not landed yet).');
    anyMismatch = true;
    return;
  }
  console.error('    --accept-provider-mismatch given; building anyway.');
  console.error('');
} else {
  console.log(`  provider check: agreement and live system both say ${health}`);
}
}

const title = front.slice(0, front.indexOf('## Covering note')).trim();

const files = {
  [slug + '-agreement']: title + '\n\n---\n\n' + strip(body),
  [slug + '-covering-note']:
    '# ' + note + '\n\n'
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
}
