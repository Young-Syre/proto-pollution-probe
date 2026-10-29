import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  findingsFor,
  hasRule,
  scanFixture,
  scanFixtureAt,
  scanSource,
  scanSourceAt,
  severityOf,
} from './helpers.js';

test('PP-S01 reports a recursive for..in merge', () => {
  const result = scanFixture('vulnerable', 'merge-recursive.js');
  assert.ok(hasRule(result, 'PP-S01'), 'expected PP-S01');
  const finding = findingsFor(result, 'PP-S01')[0];
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.equal(finding.kind, 'sink');
  assert.match(finding.message, /Recursive merge/);
  assert.match(finding.loc.excerpt, /target\[key\] = source\[key\]/);
  assert.equal(finding.loc.file, 'vulnerable/merge-recursive.js');
  assert.ok(finding.loc.start.line > 0);
  assert.ok(finding.loc.start.column > 0);
  assert.ok(finding.related.length >= 1, 'expected related locations');
});

test('PP-S01 reports a merge written with Object.keys().forEach', () => {
  const result = scanFixture('vulnerable', 'merge-foreach.js');
  assert.ok(hasRule(result, 'PP-S01'), 'callback-shaped merges must be found too');
  assert.equal(severityOf(result, 'PP-S01'), 'high');
});

test('PP-S03 reports a shallow key-copy loop and not PP-S01', () => {
  const result = scanFixture('vulnerable', 'merge-shallow.js');
  assert.ok(hasRule(result, 'PP-S03'));
  assert.equal(hasRule(result, 'PP-S01'), false, 'a shallow copy is not a recursive merge');
  assert.equal(severityOf(result, 'PP-S03'), 'medium');
  assert.match(findingsFor(result, 'PP-S03')[0]?.message ?? '', /replaces the destination object/);
});

test('PP-S02 reports a dotted path setter', () => {
  const result = scanFixture('vulnerable', 'path-setter.js');
  assert.ok(hasRule(result, 'PP-S02'));
  assert.equal(severityOf(result, 'PP-S02'), 'high');
  const finding = findingsFor(result, 'PP-S02')[0];
  assert.ok(finding);
  assert.match(finding.message, /constructor\.prototype\.x/);
  assert.ok(
    finding.related.some((related) => /split into segments/.test(related.label)),
    'expected the split site as a related location',
  );
});

test('PP-S02 still fires when only the root is Object.create(null)', () => {
  const result = scanFixture('vulnerable', 'path-setter-null-root.js');
  assert.ok(hasRule(result, 'PP-S02'), 'a null-prototype root does not protect plain intermediates');
  const finding = findingsFor(result, 'PP-S02')[0];
  assert.ok(finding);
  assert.match(finding.message, /intermediate objects are created as plain/);
  const note = finding.guards.find((guard) => guard.kind === 'null-prototype');
  assert.ok(note, 'the partial guard should be recorded');
  assert.equal(note.quality, 'partial');
});

test('PP-S04 reports Object.assign into a module-level object', () => {
  const result = scanFixture('vulnerable', 'assign-shared.js');
  assert.ok(hasRule(result, 'PP-S04'));
  assert.equal(severityOf(result, 'PP-S04'), 'medium');
  assert.match(findingsFor(result, 'PP-S04')[0]?.message ?? '', /module-level object defaults/);
});

test('PP-S04 ignores Object.assign into a fresh literal', () => {
  const result = scanFixture('guarded', 'assign-fresh-target.js');
  assert.equal(hasRule(result, 'PP-S04'), false);
  assert.equal(result.findings.length, 0);
});

test('PP-S04 reports a spread into a prototype', () => {
  const result = scanSource(
    'import { incoming } from "./x.js";\nWidget.prototype = { ...incoming };\n',
  );
  assert.ok(hasRule(result, 'PP-S04'));
  assert.match(findingsFor(result, 'PP-S04')[0]?.message ?? '', /prototype/);
});

test('PP-S05 reports lodash merge, set and defaultsDeep via require', () => {
  const result = scanFixture('vulnerable', 'lodash-helpers.js');
  const found = findingsFor(result, 'PP-S05');
  assert.equal(found.length, 3, `expected three lodash findings, got ${found.length}`);
  assert.ok(found.every((finding) => finding.severity === 'high'));
  const messages = found.map((finding) => finding.message).join('\n');
  assert.match(messages, /merge deep-merges/);
  assert.match(messages, /set writes to the non-literal key path/);
  assert.match(messages, /defaultsDeep deep-merges/);
});

test('PP-S05 recognises lodash through a default import', () => {
  const result = scanSource('import _ from "lodash";\nexport const f = (a, b) => _.merge(a, b);\n');
  assert.ok(hasRule(result, 'PP-S05'));
});

test('PP-S05 recognises a named import from lodash-es', () => {
  const result = scanSource(
    'import { defaultsDeep } from "lodash-es";\nexport const f = (a, b) => defaultsDeep(a, b);\n',
  );
  assert.ok(hasRule(result, 'PP-S05'));
});

test('PP-S05 recognises a single-method lodash package', () => {
  const result = scanSource('const merge = require("lodash.merge");\nmodule.exports = (a, b) => merge(a, b);\n');
  assert.ok(hasRule(result, 'PP-S05'));
});

test('PP-S05 ignores a literal key path and literal merge sources', () => {
  const result = scanFixture('guarded', 'lodash-literal-path.js');
  assert.equal(hasRule(result, 'PP-S05'), false);
  assert.equal(result.findings.length, 0);
});

test('PP-S05 ignores a bare merge() that is not imported from lodash', () => {
  const result = scanSource('export const f = (a, b) => merge(a, b);\n');
  assert.equal(hasRule(result, 'PP-S05'), false);
});

test('PP-S06 reports a bracket-syntax query parser', () => {
  const result = scanFixture('vulnerable', 'query-nested.js');
  assert.ok(hasRule(result, 'PP-S06'));
  assert.equal(severityOf(result, 'PP-S06'), 'high');
  assert.match(findingsFor(result, 'PP-S06')[0]?.message ?? '', /a\[__proto__\]\[x\]=1/);
});

test('PP-S06 reports allowPrototypes: true', () => {
  const result = scanFixture('vulnerable', 'query-allow-prototypes.js');
  assert.ok(hasRule(result, 'PP-S06'));
  assert.match(findingsFor(result, 'PP-S06')[0]?.message ?? '', /allowPrototypes/);
});

test('PP-S06 does not double-report a bracket parser as a path setter', () => {
  const result = scanFixture('vulnerable', 'query-nested.js');
  assert.equal(hasRule(result, 'PP-S02'), false, 'bracket syntax belongs to PP-S06 alone');
});

test('PP-S07 reports defineProperty and Reflect.set, at note level', () => {
  assert.equal(
    scanFixture('vulnerable', 'define-computed.js').findings.length,
    0,
    'the rule is below the default threshold',
  );
  const result = scanFixtureAt('note', 'vulnerable', 'define-computed.js');
  const found = findingsFor(result, 'PP-S07');
  assert.equal(found.length, 2);
  const messages = found.map((finding) => finding.message).join('\n');
  assert.match(messages, /Object\.defineProperty/);
  assert.match(messages, /Reflect\.set/);
  assert.ok(found.every((finding) => finding.severity === 'note'));
});

test('PP-S07 ignores a computed class field with a symbol key', () => {
  const result = scanSourceAt('note', 'export class A { [Symbol.toStringTag] = "A"; }\n');
  assert.equal(hasRule(result, 'PP-S07'), false);
});

test('PP-S07 ignores a well-known symbol key', () => {
  const result = scanSourceAt(
    'note',
    'export function tag(o) { Object.defineProperty(o, Symbol.toStringTag, { value: "X" }); }\n',
  );
  assert.equal(hasRule(result, 'PP-S07'), false, 'nothing can forge Symbol.toStringTag');
});

test('PP-S07 ignores the transpiler interop helpers', () => {
  const result = scanSourceAt(
    'note',
    [
      'function __createBinding(o, m, k, k2) {',
      '  if (k2 === undefined) k2 = k;',
      '  Object.defineProperty(o, k2, { enumerable: true, get: function () { return m[k]; } });',
      '}',
      'module.exports = __createBinding;',
    ].join('\n'),
  );
  assert.equal(hasRule(result, 'PP-S07'), false, 'the key is a module export name, not input');
});

test('PP-S07 ignores a literal key', () => {
  const result = scanFixtureAt('note', 'guarded', 'define-literal-key.js');
  assert.equal(hasRule(result, 'PP-S07'), false);
  assert.equal(result.findings.length, 0);
});

test('PP-S07 reports a computed class field', () => {
  const result = scanSourceAt(
    'note',
    'export class A { constructor(k) { this.k = k; } }\nexport const make = (k) => class { [k] = 1; };\n',
  );
  assert.ok(hasRule(result, 'PP-S07'));
});

test('PP-S08 reports JSON.parse flowing into a local sink function', () => {
  const result = scanFixture('vulnerable', 'json-flow.js');
  assert.ok(hasRule(result, 'PP-S08'));
  assert.equal(severityOf(result, 'PP-S08'), 'high');
  const finding = findingsFor(result, 'PP-S08')[0];
  assert.ok(finding);
  assert.match(finding.message, /JSON\.parse output reaches applyAll/);
  assert.ok(
    finding.related.some((related) => /JSON\.parse with no reviver/.test(related.label)),
    'expected the JSON.parse site as a related location',
  );
});

test('PP-S08 reports JSON.parse flowing into Object.assign', () => {
  const result = scanSource(
    'const shared = {};\nexport function load(raw) {\n  const parsed = JSON.parse(raw);\n  return Object.assign(shared, parsed);\n}\n',
  );
  assert.ok(hasRule(result, 'PP-S08'));
});

test('PP-S08 does not fire when the parse has a proto-stripping reviver', () => {
  const result = scanFixture('guarded', 'json-reviver.js');
  assert.equal(hasRule(result, 'PP-S08'), false);
  assert.equal(result.findings.length, 0);
});

test('every sink rule fires somewhere in the vulnerable fixtures', () => {
  const ids = new Set<string>();
  for (const name of [
    'merge-recursive.js',
    'merge-shallow.js',
    'path-setter.js',
    'assign-shared.js',
    'lodash-helpers.js',
    'query-nested.js',
    'define-computed.js',
    'json-flow.js',
  ]) {
    for (const finding of scanFixtureAt('note', 'vulnerable', name).findings) ids.add(finding.ruleId);
  }
  for (const expected of ['PP-S01', 'PP-S02', 'PP-S03', 'PP-S04', 'PP-S05', 'PP-S06', 'PP-S07', 'PP-S08']) {
    assert.ok(ids.has(expected), `${expected} never fired`);
  }
});
