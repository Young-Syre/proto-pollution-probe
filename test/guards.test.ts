import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  findingsFor,
  hasRule,
  scanFixture,
  scanFixtureAt,
  scanFixtureDir,
  scanSource,
  severityOf,
} from './helpers.js';
import { SEVERITY_RANK } from '../src/types.js';

/**
 * The guard suite is the one that decides whether anyone keeps the tool installed, so
 * every guard the README claims to honour has a fixture here proving a correctly
 * guarded sink produces nothing.
 */

test('the whole guarded fixture directory is clean at the default threshold', () => {
  const result = scanFixtureDir('guarded');
  assert.deepEqual(
    result.findings.map((finding) => `${finding.ruleId} ${finding.loc.file}:${finding.loc.start.line}`),
    [],
    'a guarded fixture produced a finding',
  );
  assert.equal(result.skipped.length, 0);
  assert.ok(result.filesScanned >= 13, 'expected the guarded fixtures to be analysed');
});

test('guard: a denylist covering all three key names suppresses a recursive merge', () => {
  const result = scanFixture('guarded', 'merge-denylist.js');
  assert.equal(result.findings.length, 0);
});

test('guard: the denylist may be a module-level constant', () => {
  const result = scanSource(
    [
      'const DENY = new Set(["__proto__", "constructor", "prototype"]);',
      'export function merge(target, source) {',
      '  for (const key of Object.keys(source)) {',
      '    if (DENY.has(key)) continue;',
      '    target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.length, 0, 'a constant one scope up is still a guard');
});

test('guard: a regex denylist is recognised', () => {
  const result = scanSource(
    [
      'export function merge(target, source) {',
      '  for (const key of Object.keys(source)) {',
      '    if (/^(__proto__|constructor|prototype)$/.test(key)) continue;',
      '    target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.length, 0);
});

test('guard: an array denylist with .includes is recognised', () => {
  const result = scanSource(
    [
      'const BAD = ["__proto__", "constructor", "prototype"];',
      'export function merge(target, source) {',
      '  for (const key in source) {',
      '    if (BAD.includes(key)) continue;',
      '    target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.length, 0);
});

test('guard: Object.create(null) with no plain intermediates suppresses a key copy', () => {
  const result = scanFixture('guarded', 'merge-null-prototype.js');
  assert.equal(result.findings.length, 0);
});

test('guard: a Map destination produces no sink at all', () => {
  const result = scanFixture('guarded', 'merge-map.js');
  assert.equal(result.findings.length, 0);
});

test('guard: bracket writes onto a Map binding are not reported', () => {
  const result = scanFixture('guarded', 'map-bracket-write.js');
  assert.equal(result.findings.length, 0);
});

test('guard: Object.freeze(Object.prototype) suppresses an otherwise bare merge', () => {
  const result = scanFixture('guarded', 'merge-frozen-prototype.js');
  assert.equal(result.findings.length, 0);
});

test('guard: freezing Object.prototype is recognised anywhere in the program', () => {
  const result = scanSource(
    [
      'export function merge(target, source) {',
      '  for (const key in source) target[key] = source[key];',
      '  return target;',
      '}',
      'Object.freeze(Object.prototype);',
    ].join('\n'),
  );
  assert.equal(result.findings.length, 0, 'the order of the freeze in the file is irrelevant');
});

test('guard: a JSON.parse reviver that drops __proto__ removes the source', () => {
  const result = scanFixture('guarded', 'json-reviver.js');
  assert.equal(result.findings.length, 0);
});

test('guard: a path setter with a full denylist is suppressed', () => {
  const result = scanFixture('guarded', 'path-setter-denylist.js');
  assert.equal(result.findings.length, 0);
});

test('guard: a path setter that is prototype-less all the way down is suppressed', () => {
  const result = scanFixture('guarded', 'path-setter-null-prototype.js');
  assert.equal(result.findings.length, 0);
});

test('guard: an own-property filter alone is silent at low but reported at note', () => {
  assert.equal(
    scanFixture('guarded', 'merge-has-own.js').findings.length,
    0,
    'nothing at the default threshold',
  );
  const quality = scanFixtureDir('guarded', 'note').findings.filter(
    (finding) => finding.ruleId === 'PP-Q02',
  );
  assert.equal(quality.length, 1, 'exactly one PP-Q02 across the guarded fixtures');
  assert.equal(quality[0]?.severity, 'note');
  assert.match(quality[0]?.message ?? '', /own-property filter/);
  assert.equal(quality[0]?.loc.file, 'guarded/merge-has-own.js');
});

test('guard quality: a __proto__-only denylist is reported and the sink stands, downgraded', () => {
  const result = scanFixture('weak', 'merge-proto-only-denylist.js');
  assert.ok(hasRule(result, 'PP-S01'), 'constructor.prototype still reaches the sink');
  assert.ok(hasRule(result, 'PP-Q01'), 'the gap in the denylist is reported');
  assert.equal(severityOf(result, 'PP-S01'), 'medium', 'downgraded from high by the partial guard');
  assert.equal(severityOf(result, 'PP-Q01'), 'low');
  const sink = findingsFor(result, 'PP-S01')[0];
  assert.ok(sink);
  assert.match(sink.message, /only rejects __proto__/);
  const note = sink.guards.find((guard) => guard.kind === 'key-denylist');
  assert.ok(note);
  assert.equal(note.quality, 'weak');
  assert.ok(note.detail.includes('constructor'));
});

test('guard quality: an own-property filter plus JSON.parse keeps the sink', () => {
  const result = scanFixture('weak', 'merge-has-own-json.js');
  assert.ok(hasRule(result, 'PP-S03'), 'JSON.parse defeats the filter, so the sink stands');
  assert.equal(severityOf(result, 'PP-S03'), 'low', 'downgraded, not dropped');
  const sink = findingsFor(result, 'PP-S03')[0];
  assert.ok(sink);
  assert.match(sink.message, /JSON\.parse defeats/);
  assert.ok(
    sink.related.some((related) => /own "__proto__" key/.test(related.label)),
    'the finding points at the parser that defeats the filter',
  );
  const note = sink.guards.find((guard) => guard.kind === 'has-own-property');
  assert.ok(note);
  assert.equal(note.quality, 'partial');
});

test('guard quality: a null-prototype root with plain intermediates is partial, not sufficient', () => {
  const result = scanFixture('vulnerable', 'path-setter-null-root.js');
  const sink = findingsFor(result, 'PP-S02')[0];
  assert.ok(sink, 'the sink must survive the partial guard');
  assert.equal(SEVERITY_RANK[sink.severity] <= SEVERITY_RANK['high'], true);
});

test('guard notes carry a location when one exists', () => {
  const result = scanFixture('weak', 'merge-proto-only-denylist.js');
  const sink = findingsFor(result, 'PP-S01')[0];
  assert.ok(sink);
  const note = sink.guards.find((guard) => guard.kind === 'key-denylist');
  assert.ok(note?.loc, 'the denylist should be locatable');
  assert.equal(note.loc.file, 'weak/merge-proto-only-denylist.js');
});

test('a key denylist that only mentions prototype is still incomplete', () => {
  const result = scanSource(
    [
      'export function merge(target, source) {',
      '  for (const key in source) {',
      '    if (key === "prototype") continue;',
      '    target[key] = source[key];',
      '  }',
      '  return target;',
      '}',
    ].join('\n'),
  );
  assert.ok(hasRule(result, 'PP-S03'));
  assert.ok(hasRule(result, 'PP-Q01'));
});

test('guard: a __proto__-only denylist is sufficient for a one-level write', () => {
  const result = scanFixture('guarded', 'merge-shallow-proto-denylist.js');
  assert.equal(
    result.findings.length,
    0,
    'for a shallow copy there is no constructor.prototype route, so the denylist is complete',
  );
});

test('guard quality: the same denylist is incomplete once the write recurses', () => {
  const shallow = scanFixture('guarded', 'merge-shallow-proto-denylist.js');
  const deep = scanFixture('weak', 'merge-proto-only-denylist.js');
  assert.equal(shallow.findings.length, 0);
  assert.ok(hasRule(deep, 'PP-Q01'), 'depth is what makes the same guard inadequate');
  assert.ok(hasRule(deep, 'PP-S01'));
});

test('a guard-quality finding never outranks the sink it describes', () => {
  const notes = scanFixtureAt('note', 'weak', 'merge-proto-only-denylist.js');
  const sink = notes.findings.find((finding) => finding.ruleId === 'PP-S01');
  const quality = notes.findings.find((finding) => finding.ruleId === 'PP-Q01');
  assert.ok(sink && quality);
  assert.ok(
    SEVERITY_RANK[quality.severity] >= SEVERITY_RANK[sink.severity],
    'the note must not be more severe than the finding it annotates',
  );
});
