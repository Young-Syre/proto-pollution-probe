import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyseSources } from '../src/analyse.js';
import { findingsFor, hasRule, scanFixture, scanFixtureAt, scanSource, severityOf } from './helpers.js';

test('PP-G01 reports properties that reach child_process', () => {
  const result = scanFixture('vulnerable', 'gadget-exec.js');
  const found = findingsFor(result, 'PP-G01');
  assert.equal(found.length, 3, `expected three exec gadgets, got ${found.length}`);
  assert.ok(found.every((finding) => finding.severity === 'critical'));
  assert.ok(found.every((finding) => finding.reach === 'command-execution'));
  const properties = found.map((finding) => finding.property).sort();
  assert.deepEqual(properties, ['launchArgv', 'launcher', 'workingRoot']);
});

test('PP-G01 recognises an exec options key such as cwd', () => {
  const result = scanFixture('vulnerable', 'gadget-exec.js');
  const cwd = findingsFor(result, 'PP-G01').find((finding) => finding.property === 'workingRoot');
  assert.ok(cwd);
  assert.ok(
    cwd.related.some((related) => /"cwd" option/.test(related.label)),
    'the finding should name the option it becomes',
  );
});

test('PP-G02 reports a property that reaches path resolution', () => {
  const result = scanFixture('vulnerable', 'gadget-path.js');
  assert.ok(hasRule(result, 'PP-G02'));
  const finding = findingsFor(result, 'PP-G02')[0];
  assert.ok(finding);
  assert.equal(finding.severity, 'high');
  assert.equal(finding.reach, 'path-resolution');
  assert.equal(finding.property, 'layoutRoot');
});

test('PP-G03 reports a property that reaches a template compile', () => {
  const result = scanFixture('vulnerable', 'gadget-template.js');
  assert.ok(hasRule(result, 'PP-G03'));
  const finding = findingsFor(result, 'PP-G03')[0];
  assert.ok(finding);
  assert.equal(finding.reach, 'template-render');
  assert.equal(finding.property, 'layoutSource');
});

test('PP-G04 reports privilege-shaped properties used as conditions', () => {
  const result = scanFixture('vulnerable', 'gadget-auth.js');
  const found = findingsFor(result, 'PP-G04');
  assert.equal(found.length, 2);
  assert.ok(found.every((finding) => finding.severity === 'high'));
  assert.ok(found.every((finding) => finding.reach === 'auth-decision'));
  assert.deepEqual(found.map((finding) => finding.property).sort(), ['isAdmin', 'permissions']);
});

test('PP-G05 is a note, below the default threshold', () => {
  const quiet = scanFixture('vulnerable', 'gadget-default.js');
  assert.equal(hasRule(quiet, 'PP-G05'), false, 'unranked candidates are not default findings');

  const loud = scanFixtureAt('note', 'vulnerable', 'gadget-default.js');
  assert.ok(hasRule(loud, 'PP-G05'));
  assert.equal(severityOf(loud, 'PP-G05'), 'note');
  assert.equal(findingsFor(loud, 'PP-G05')[0]?.reach, 'framework-default');
  assert.equal(findingsFor(loud, 'PP-G05')[0]?.property, 'humanLabel');
});

test('a note-level gadget does not form a chain', () => {
  const result = analyseSources(
    [
      { file: 'merge.js', source: 'export function m(t, s) { for (const k in s) t[k] = s[k]; return t; }\n' },
      { file: 'read.js', source: 'export const f = (o) => `${o.someCaption}`;\n' },
    ],
    { minSeverity: 'note' },
  );
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-G05').length, 1);
  assert.equal(result.findings.filter((finding) => finding.ruleId === 'PP-C01').length, 0);
});

test('a property assigned anywhere in the scan is not a gadget', () => {
  const guarded = scanSource(
    [
      'export function configure(options) {',
      '  options.allowShell = false;',
      '  return options.allowShell;',
      '}',
    ].join('\n'),
  );
  assert.equal(guarded.findings.length, 0, 'the property is assigned in the same file');
});

test('a property assigned in a different file of the same scan is not a gadget', () => {
  const result = analyseSources(
    [
      { file: 'a.js', source: 'import { spawnSync } from "node:child_process";\nexport const go = (o) => spawnSync(o.binaryPath);\n' },
      { file: 'b.js', source: 'export function init(o) { o.binaryPath = "/usr/bin/true"; }\n' },
    ],
    { minSeverity: 'low' },
  );
  assert.equal(
    result.findings.filter((finding) => finding.kind === 'gadget').length,
    0,
    'cross-file assignment must suppress the gadget',
  );
});

test('an own-property check suppresses the gadget', () => {
  const result = scanFixture('guarded', 'gadget-has-own.js');
  assert.equal(result.findings.length, 0);
});

test('hasOwnProperty.call suppresses the gadget too', () => {
  const result = scanSource(
    [
      'import { execSync } from "node:child_process";',
      'export function run(cfg) {',
      '  if (!Object.prototype.hasOwnProperty.call(cfg, "bootCommand")) return null;',
      '  return execSync(cfg.bootCommand);',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.filter((finding) => finding.kind === 'gadget').length, 0);
});

test('an `in` check downgrades rather than suppresses, and says why', () => {
  const result = scanFixture('weak', 'gadget-in-check.js');
  const finding = findingsFor(result, 'PP-G01')[0];
  assert.ok(finding);
  assert.equal(finding.severity, 'high', 'critical downgraded to high, not dropped');
  assert.match(finding.message, /walks the prototype chain/);
  assert.ok(finding.related.some((related) => /`in` check/.test(related.label)));
});

test('a destructuring default is treated as an assignment', () => {
  const result = scanSource(
    [
      'import { execSync } from "node:child_process";',
      'export function run(options) {',
      '  const { bootCommand = "true" } = options;',
      '  return execSync(bootCommand);',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.filter((finding) => finding.kind === 'gadget').length, 0);
});

test('a destructuring read with no default is a gadget', () => {
  const result = scanSource(
    [
      'import { execSync } from "node:child_process";',
      'export function run(options) {',
      '  const { bootCommand } = options;',
      '  return execSync(bootCommand);',
      '}',
    ].join('\n'),
  );
  assert.ok(hasRule(result, 'PP-G01'), 'destructuring is still a property read');
  assert.equal(findingsFor(result, 'PP-G01')[0]?.property, 'bootCommand');
});

test('optional chaining is not a gadget: the code already tolerates absence', () => {
  const result = scanSource('export const read = (o) => o?.maybeMissing;\n');
  assert.equal(result.findings.length, 0);
});

test('builtins and module namespaces are never gadget objects', () => {
  const result = scanSource(
    [
      'import * as crypto from "node:crypto";',
      'export function f() {',
      '  return [process.someUnsetThing, crypto.someUnsetThing, Math.someUnsetThing, JSON.someUnsetThing];',
      '}',
    ].join('\n'),
  );
  assert.equal(result.findings.length, 0);
});

test('method calls are not gadget reads', () => {
  const result = scanSource('export const f = (o) => o.unlikelyMethodName();\n');
  assert.equal(result.findings.length, 0, 'a callee is a method, not a trusted default');
});

test('prototype-method names are allow-listed', () => {
  const result = scanSource('export const f = (o) => [o.length, o.toString, o.constructor];\n');
  assert.equal(result.findings.length, 0);
});

test('only the outermost read of a chain is reported', () => {
  const result = scanSource(
    'import { execSync } from "node:child_process";\nexport const f = (o) => execSync(o.deepThing.innerThing);\n',
  );
  const gadgets = result.findings.filter((finding) => finding.kind === 'gadget');
  assert.equal(gadgets.length, 1, 'a.b.c reports once, not twice');
  assert.equal(gadgets[0]?.property, 'innerThing');
});

test('an assignment target is not a read', () => {
  const result = scanSource('export const f = (o) => { o.neverReadOnlyWritten = 1; };\n');
  assert.equal(result.findings.filter((finding) => finding.kind === 'gadget').length, 0);
});
