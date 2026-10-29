import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { analyseSources } from '../src/analyse.js';
import { eraseTypes, typeErasureAvailable } from '../src/ts-erase.js';
import { findingsFor, hasRule, readFixture, scanFixture } from './helpers.js';

const require_ = createRequire(import.meta.url);
const builtinStripper =
  typeof (require_('node:module') as { stripTypeScriptTypes?: unknown }).stripTypeScriptTypes === 'function';

test('type erasure availability matches the Node built-in', () => {
  assert.equal(typeErasureAvailable(), builtinStripper);
});

test('erasure preserves the exact byte length, so positions do not move', { skip: !builtinStripper }, () => {
  const source = readFixture('modern', 'typed.ts');
  const erased = eraseTypes(source);
  assert.ok(erased.ok, erased.ok ? '' : erased.reason);
  assert.equal(erased.code.length, source.length, 'strip mode must substitute spaces, not delete');
  assert.equal(erased.code.split('\n').length, source.length > 0 ? source.split('\n').length : 0);
});

test('erasure leaves non-type code untouched', { skip: !builtinStripper }, () => {
  const erased = eraseTypes('const x: number = 1;\nexport function f<T>(a: T): T { return a; }\n');
  assert.ok(erased.ok);
  assert.match(erased.code, /^const x\s+= 1;$/m);
  assert.match(erased.code, /return a;/);
  assert.match(erased.code, /^export function f\s+\(a\s+\)\s+\{ return a; \}$/m);
  assert.equal(erased.code.includes('number'), false);
  assert.equal(erased.code.includes('<T>'), false);
});

test('a TypeScript merge is reported at its position in the .ts file', { skip: !builtinStripper }, () => {
  const result = scanFixture('modern', 'typed.ts');
  assert.ok(hasRule(result, 'PP-S01'), 'the recursive merge must survive type erasure');
  const finding = findingsFor(result, 'PP-S01')[0];
  assert.ok(finding);
  const lines = readFixture('modern', 'typed.ts').split('\n');
  const reported = lines[finding.loc.start.line - 1];
  assert.ok(reported, 'the reported line must exist in the original file');
  assert.match(reported, /\[key\] = incoming;/, 'the line number must point at the TypeScript source');
  assert.equal(finding.loc.excerpt.trim(), reported.trim());
});

test('TypeScript generics, as, satisfies and non-null assertions all parse', { skip: !builtinStripper }, () => {
  const result = analyseSources(
    [
      {
        file: 'x.ts',
        source: [
          'type Dict = Record<string, unknown>;',
          'interface Opts { deep?: boolean }',
          'const o = { deep: true } satisfies Opts;',
          'export function f<T extends Dict>(a: T, b: Partial<T>): T {',
          '  const c = (a as Dict)["k"] as string | undefined;',
          '  return (b as T)!;',
          '}',
          'export const g = <T,>(x: T): T => x;',
        ].join('\n'),
      },
    ],
    { minSeverity: 'note' },
  );
  assert.equal(result.skipped.length, 0, JSON.stringify(result.skipped));
  assert.equal(result.filesScanned, 1);
});

test('an enum is skipped and reported as PP-E02, never silently dropped', () => {
  const result = scanFixture('modern', 'unsupported.ts');
  assert.equal(result.filesScanned, 0);
  assert.equal(result.skipped.length, 1);
  const skip = result.skipped[0];
  assert.ok(skip);
  assert.equal(skip.code, 'PP-E02');
  assert.equal(skip.file, 'modern/unsupported.ts');
  assert.ok(skip.reason.length > 0);
  if (builtinStripper) assert.match(skip.reason, /enum/);
  else assert.match(skip.reason, /Node 22\.13/);
});

test('a namespace declaration is skipped and reported', { skip: !builtinStripper }, () => {
  const result = analyseSources([{ file: 'ns.ts', source: 'namespace N { export const a = 1; }\n' }]);
  assert.equal(result.skipped.length, 1);
  assert.equal(result.skipped[0]?.code, 'PP-E02');
  assert.match(result.skipped[0]?.reason ?? '', /namespace/);
});

test('a constructor parameter property is skipped and reported', { skip: !builtinStripper }, () => {
  const result = analyseSources([
    { file: 'p.ts', source: 'export class C { constructor(private readonly x: number) {} }\n' },
  ]);
  assert.equal(result.skipped.length, 1);
  assert.equal(result.skipped[0]?.code, 'PP-E02');
  assert.match(result.skipped[0]?.reason ?? '', /parameter property/);
});

test('a syntax error is reported as PP-E01 and the scan continues', () => {
  const result = analyseSources([
    { file: 'broken.js', source: 'export function unbalanced( {\n' },
    { file: 'fine.js', source: 'export function merge(t, s) { for (const k in s) t[k] = s[k]; return t; }\n' },
  ], { minSeverity: 'low' });
  assert.equal(result.filesScanned, 1, 'the good file is still analysed');
  assert.equal(result.skipped.length, 1);
  assert.equal(result.skipped[0]?.code, 'PP-E01');
  assert.ok(result.findings.some((finding) => finding.ruleId === 'PP-S03'));
});

test('an unreadable path is reported as PP-E03', async () => {
  const { analysePaths } = await import('../src/analyse.js');
  const result = analysePaths(['./definitely-not-a-real-file-9f3a.js']);
  assert.equal(result.filesScanned, 0);
  assert.equal(result.skipped.length, 1);
  assert.equal(result.skipped[0]?.code, 'PP-E03');
});

test('a script-only file still parses via the script fallback', () => {
  const result = analyseSources(
    [{ file: 'legacy.js', source: 'function f(o) { return o.someUnsetProp; }\nreturn f;\n' }],
    { minSeverity: 'low' },
  );
  assert.equal(result.skipped.length, 0, 'a bare return must not fail the file');
  assert.equal(result.filesScanned, 1);
});

test('modern JavaScript syntax is analysed, not merely parsed', () => {
  const result = scanFixture('modern', 'syntax.js');
  assert.equal(result.skipped.length, 0);
  assert.ok(hasRule(result, 'PP-S02'), 'the ??= path setter inside a class must be found');
  const finding = findingsFor(result, 'PP-S02')[0];
  assert.ok(finding);
  assert.match(finding.loc.excerpt, /\?\?=/);
});

test('a hashbang does not break parsing', () => {
  const result = analyseSources(
    [{ file: 'bin.js', source: '#!/usr/bin/env node\nexport const f = (o) => o.someUnsetProp;\n' }],
    { minSeverity: 'low' },
  );
  assert.equal(result.skipped.length, 0);
});
