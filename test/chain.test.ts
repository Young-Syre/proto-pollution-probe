import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyseSources } from '../src/analyse.js';
import { pairFindings } from '../src/pair.js';
import { findingsFor, hasRule, scanFixture, scanFixtureDir } from './helpers.js';

const SINK = [
  'export function mergeInto(target, source) {',
  '  for (const key in source) {',
  '    if (source[key] !== null && typeof source[key] === "object") {',
  '      mergeInto((target[key] ??= {}), source[key]);',
  '    } else {',
  '      target[key] = source[key];',
  '    }',
  '  }',
  '  return target;',
  '}',
].join('\n');

const GADGET = [
  'import { execSync } from "node:child_process";',
  'export function runHook(hook) {',
  '  return execSync(hook.shellCommand);',
  '}',
].join('\n');

/** Two more ranked gadgets, for the tests that need pairing to have a choice. */
const MORE_GADGETS = [
  'import { join } from "node:path";',
  'export const first = (o) => join(o.firstRoot, "a");',
  'export const second = (o) => join(o.secondRoot, "b");',
].join('\n');

test('PP-C01 pairs a sink and a gadget in the same file', () => {
  const result = scanFixture('vulnerable', 'chain.js');
  assert.ok(hasRule(result, 'PP-C01'));
  const chain = findingsFor(result, 'PP-C01')[0];
  assert.ok(chain);
  assert.equal(chain.kind, 'chain');
  assert.equal(chain.severity, 'critical');
  assert.match(chain.message, /Both halves are in this file/);
  assert.match(chain.message, /shellCommand/);
  assert.equal(chain.loc.file, 'vulnerable/chain.js', 'the chain is located at the write, which is what gets fixed');
});

test('PP-C01 names both halves as related locations', () => {
  const chain = findingsFor(scanFixture('vulnerable', 'chain.js'), 'PP-C01')[0];
  assert.ok(chain);
  const labels = chain.related.map((related) => related.label);
  assert.ok(labels.some((label) => label.startsWith('write primitive: PP-S01')));
  assert.ok(labels.some((label) => label.startsWith('read primitive: PP-G01')));
  const write = chain.related.find((related) => related.label.startsWith('write primitive'));
  const read = chain.related.find((related) => related.label.startsWith('read primitive'));
  assert.ok(write && read);
  assert.notEqual(write.loc.start.line, read.loc.start.line, 'the two halves are different places');
});

test('PP-C01 pairs across files, and says so', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
    ],
    { minSeverity: 'low' },
  );
  const chains = result.findings.filter((finding) => finding.ruleId === 'PP-C01');
  assert.equal(chains.length, 1);
  assert.match(chains[0]?.message ?? '', /different files/);
  assert.match(chains[0]?.message ?? '', /process-wide/);
  assert.equal(chains[0]?.loc.file, 'merge.js', 'the chain sits at the write, which is what gets fixed');
});

test('a sink with no gadget produces no chain', () => {
  const result = analyseSources([{ file: 'merge.js', source: SINK }], { minSeverity: 'low' });
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 0);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'PP-S01'), 'the sink is still reported');
});

test('a gadget with no sink produces no chain', () => {
  const result = analyseSources([{ file: 'hooks.js', source: GADGET }], { minSeverity: 'low' });
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 0);
  assert.ok(result.findings.some((finding) => finding.ruleId === 'PP-G01'), 'the gadget is still reported');
});

test('pairing is gadget-led: one chain per gadget by default', () => {
  const result = scanFixtureDir('vulnerable');
  const sinks = result.findings.filter((finding) => finding.kind === 'sink');
  const gadgets = result.findings.filter((finding) => finding.kind === 'gadget');
  const chains = result.findings.filter((finding) => finding.kind === 'chain');
  assert.ok(sinks.length > gadgets.length, 'sinks outnumber gadgets, which is why pairing is gadget-led');
  assert.equal(chains.length, gadgets.length, 'one chain per gadget keeps the report readable');
  assert.match(chains[0]?.message ?? '', /other write primitives in this scan could serve instead/);
});

test('a candidate-level half does not form a chain', () => {
  // PP-S07 is reported at note level, so it is a candidate rather than a pairable write.
  const result = analyseSources(
    [
      { file: 'define.js', source: 'export const d = (o, k, v) => Object.defineProperty(o, k, { value: v });\n' },
      { file: 'hooks.js', source: GADGET },
    ],
    { minSeverity: 'note' },
  );
  assert.ok(result.findings.some((finding) => finding.ruleId === 'PP-S07'));
  assert.ok(result.findings.some((finding) => finding.ruleId === 'PP-G01'));
  assert.equal(
    result.findings.filter((finding) => finding.ruleId === 'PP-C01').length,
    0,
    'a note-level write primitive must not be promoted into a critical chain',
  );
});

test('--max-sinks-per-gadget widens pairing', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
      { file: 'more.js', source: MORE_GADGETS },
    ],
    { minSeverity: 'low', maxSinksPerGadget: 3 },
  );
  // Three ranked gadgets and one sink: each gadget pairs with the only write there is.
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 3);
});

test('pairing can be switched off', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
    ],
    { minSeverity: 'low', pair: false },
  );
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 0);
});

test('maxChains caps the output', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
      { file: 'more.js', source: MORE_GADGETS },
    ],
    { minSeverity: 'low', maxChains: 2 },
  );
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 2);
});

test('a same-file sink is preferred over one elsewhere', () => {
  const localSink = [
    SINK,
    'import { join } from "node:path";',
    'export const label = (o) => join(o.localRoot, "x");',
  ].join('\n');
  const result = analyseSources(
    [
      { file: 'elsewhere.js', source: SINK },
      { file: 'together.js', source: localSink },
    ],
    { minSeverity: 'low' },
  );
  const chain = result.findings.find((finding) => finding.ruleId === 'PP-C01');
  assert.ok(chain);
  const write = chain.related.find((related) => related.label.startsWith('write primitive'));
  assert.equal(write?.loc.file, 'together.js', 'the reviewer can check a same-file pair fastest');
  assert.match(chain.message, /Both halves are in this file/);
});

test('pairFindings is a pure function over findings', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
    ],
    { minSeverity: 'low', pair: false },
  );
  const chains = pairFindings(result.findings);
  assert.equal(chains.length, 1);
  assert.equal(chains[0]?.ruleId, 'PP-C01');
  assert.equal(pairFindings([]).length, 0);
  assert.equal(pairFindings(result.findings, { maxSinksPerGadget: 0 }).length, 0);
});

test('chain fingerprints differ per sink-gadget pair', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: SINK },
      { file: 'hooks.js', source: GADGET },
      { file: 'more.js', source: MORE_GADGETS },
    ],
    { minSeverity: 'low', maxSinksPerGadget: 3 },
  );
  const fingerprints = result.findings
    .filter((finding) => finding.ruleId === 'PP-C01')
    .map((finding) => finding.fingerprint);
  assert.equal(new Set(fingerprints).size, fingerprints.length, 'fingerprints must be distinct');
  assert.ok(fingerprints.every((value) => /^[0-9a-f]{16}$/.test(value)));
});
