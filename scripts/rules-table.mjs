#!/usr/bin/env node
/**
 * Generate the README's rules table from src/rules.ts, or check that the committed
 * table still matches. CI runs `--check`, so the documentation cannot drift away from
 * the code without the build going red.
 *
 *   node scripts/rules-table.mjs           print the table
 *   node scripts/rules-table.mjs --check   exit 1 if README.md disagrees
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { RULES } = await import(resolve(root, 'dist/src/rules.js'));

const BEGIN = '<!-- rules-table:begin -->';
const END = '<!-- rules-table:end -->';

const rows = RULES.map((rule) => {
  const kind = rule.kind === 'guard-quality' ? 'guard quality' : rule.kind;
  return `| \`${rule.id}\` | ${rule.name} | ${kind} | ${rule.severity} | ${rule.shortDescription} |`;
});

const table = [
  '| ID | Name | Kind | Default severity | What it means |',
  '| --- | --- | --- | --- | --- |',
  ...rows,
].join('\n');

if (!process.argv.includes('--check')) {
  process.stdout.write(`${BEGIN}\n${table}\n${END}\n`);
  process.exit(0);
}

const readme = readFileSync(resolve(root, 'README.md'), 'utf8');
const start = readme.indexOf(BEGIN);
const end = readme.indexOf(END);
if (start === -1 || end === -1) {
  process.stderr.write(`README.md is missing the ${BEGIN} / ${END} markers\n`);
  process.exit(1);
}
const committed = readme.slice(start + BEGIN.length, end).trim();
if (committed !== table) {
  process.stderr.write(
    'The rules table in README.md does not match src/rules.ts.\n' +
      'Regenerate it with: npm run build && node scripts/rules-table.mjs\n',
  );
  process.exit(1);
}
process.stdout.write(`rules table matches src/rules.ts (${RULES.length} rules)\n`);
