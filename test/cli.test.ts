import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from './helpers.js';

test('--help exits 0 and documents the exit codes', () => {
  const run = runCli(['--help']);
  assert.equal(run.status, 0);
  assert.match(run.stdout, /Usage/);
  assert.match(run.stdout, /--format <text\|json\|sarif>/);
  assert.match(run.stdout, /Exit codes/);
  assert.match(run.stdout, /--corpus <dir>/);
  assert.match(run.stdout, /--min-severity/);
});

test('--version prints a semver-shaped version', () => {
  const run = runCli(['--version']);
  assert.equal(run.status, 0);
  assert.match(run.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('--rules lists every rule', () => {
  const run = runCli(['--rules']);
  assert.equal(run.status, 0);
  for (const id of ['PP-S01', 'PP-S08', 'PP-G01', 'PP-G05', 'PP-C01', 'PP-Q01', 'PP-Q02', 'PP-E01']) {
    assert.ok(run.stdout.includes(id), `${id} missing from --rules`);
  }
});

test('exit code 1 when the vulnerable fixtures are scanned', () => {
  const run = runCli(['--no-color', 'test/fixtures/vulnerable']);
  assert.equal(run.status, 1);
  assert.match(run.stdout, /PP-S01/);
  assert.match(run.stdout, /PP-C01/);
});

test('exit code 0 when the guarded fixtures are scanned', () => {
  const run = runCli(['--no-color', 'test/fixtures/guarded']);
  assert.equal(run.status, 0, run.stdout);
  assert.match(run.stdout, /no findings/);
});

test('exit code 2 on an unknown option', () => {
  const run = runCli(['--not-a-real-flag', 'test/fixtures']);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /unknown option/);
});

test('exit code 2 when no path is given', () => {
  const run = runCli([]);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /no path given/);
});

test('exit code 2 on a bad --format value', () => {
  const run = runCli(['--format', 'yaml', 'test/fixtures']);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /text, json or sarif/);
});

test('exit code 2 on a bad --min-severity value', () => {
  const run = runCli(['--min-severity', 'spicy', 'test/fixtures']);
  assert.equal(run.status, 2);
  assert.match(run.stderr, /--min-severity expects/);
});

test('exit code 3 when nothing analysable is found', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ppp-empty-'));
  try {
    const run = runCli([dir]);
    assert.equal(run.status, 3);
    assert.match(run.stderr, /no \.js/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('exit code 3 with --strict-files when a file cannot be analysed', () => {
  const run = runCli(['--no-color', '--strict-files', 'test/fixtures/modern']);
  assert.equal(run.status, 3);
  assert.match(run.stdout, /Skipped files/);
});

test('--exit-zero forces a 0 exit even with findings', () => {
  const run = runCli(['--no-color', '--exit-zero', 'test/fixtures/vulnerable']);
  assert.equal(run.status, 0);
  assert.match(run.stdout, /PP-S01/);
});

test('--min-severity raises the bar and the exit code follows', () => {
  const low = runCli(['--no-color', '--min-severity', 'medium', 'test/fixtures/weak']);
  assert.equal(low.status, 1);
  const high = runCli(['--no-color', '--min-severity', 'high', 'test/fixtures/guarded']);
  assert.equal(high.status, 0);
});

test('--format json emits parseable JSON on stdout', () => {
  const run = runCli(['--format', 'json', 'test/fixtures/vulnerable']);
  assert.equal(run.status, 1);
  const parsed = JSON.parse(run.stdout) as { findings: unknown[]; counts: { byRule: Record<string, number> } };
  assert.ok(Array.isArray(parsed.findings));
  assert.ok((parsed.counts.byRule['PP-S01'] ?? 0) >= 1);
});

test('--format sarif emits a 2.1.0 log on stdout', () => {
  const run = runCli(['--format', 'sarif', 'test/fixtures/vulnerable']);
  assert.equal(run.status, 1);
  const parsed = JSON.parse(run.stdout) as { version: string; runs: unknown[] };
  assert.equal(parsed.version, '2.1.0');
  assert.equal(parsed.runs.length, 1);
});

test('--output writes the report to a file and the summary to stderr', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ppp-out-'));
  try {
    const target = join(dir, 'report.sarif');
    const run = runCli(['--format', 'sarif', '--output', target, 'test/fixtures/vulnerable']);
    assert.equal(run.status, 1);
    assert.equal(run.stdout, '');
    assert.match(run.stderr, /files scanned in/);
    const parsed = JSON.parse(readFileSync(target, 'utf8')) as { version: string };
    assert.equal(parsed.version, '2.1.0');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--no-pair removes the chain findings', () => {
  const run = runCli(['--no-color', '--no-pair', 'test/fixtures/vulnerable']);
  assert.equal(run.status, 1);
  assert.equal(run.stdout.includes('PP-C01'), false);
  assert.match(run.stdout, /PP-S01/);
});

test('a single file may be scanned directly', () => {
  const run = runCli(['--no-color', 'test/fixtures/vulnerable/merge-recursive.js']);
  assert.equal(run.status, 1);
  assert.match(run.stdout, /1 file scanned/);
  assert.match(run.stdout, /PP-S01/);
});

test('reported paths are relative to the working directory', () => {
  const run = runCli(['--no-color', 'test/fixtures/vulnerable/merge-recursive.js']);
  assert.match(run.stdout, /^test\/fixtures\/vulnerable\/merge-recursive\.js$/m);
  assert.equal(/\/home\/|\/Users\//.test(run.stdout), false, 'no absolute path in CLI output');
});

test('--corpus reports counts per rule rather than individual findings', () => {
  const run = runCli(['--corpus', 'test/fixtures']);
  assert.match(run.stdout, /rule\s+name\s+findings\s+files/);
  assert.match(run.stdout, /PP-S01\s+unguarded-recursive-merge\s+\d+\s+\d+/);
  assert.match(run.stdout, /file\(s\) discovered/);
  assert.match(run.stdout, /by severity:/);
  assert.match(run.stdout, /files with the most findings/);
  assert.equal(/\/home\/|\/Users\//.test(run.stdout), false);
});

test('--corpus --format json is machine readable', () => {
  const run = runCli(['--corpus', 'test/fixtures', '--format', 'json']);
  const parsed = JSON.parse(run.stdout) as {
    byRule: Array<{ id: string; count: number; files: number }>;
    filesDiscovered: number;
    filesScanned: number;
    skippedByCode: Array<{ code: string; count: number }>;
  };
  assert.ok(parsed.filesDiscovered > parsed.filesScanned, 'the broken fixtures are discovered but not scanned');
  assert.ok(parsed.byRule.length >= 18, 'every rule should appear, including the zeroes');
  assert.ok(parsed.byRule.some((entry) => entry.id === 'PP-S01' && entry.count > 0));
  assert.ok(parsed.byRule.some((entry) => entry.count === 0), 'rules that did not fire are listed as zero');
  assert.ok(parsed.skippedByCode.some((entry) => entry.code === 'PP-E01'));
});

test('--verbose shows the guard analysis', () => {
  const run = runCli(['--no-color', '--verbose', 'test/fixtures/weak']);
  assert.match(run.stdout, /\[guard: key-denylist, weak\]/);
});

test('NO_COLOR is honoured without the flag', () => {
  const run = runCli(['test/fixtures/vulnerable/merge-recursive.js']);
  assert.equal(run.stdout.includes('\u001b['), false, 'non-TTY output must not be coloured');
});

test('--corpus exits 0 even when it finds things, because it measures', () => {
  const run = runCli(['--corpus', 'test/fixtures']);
  assert.equal(run.status, 0, 'corpus mode must not gate a pipeline');
  assert.match(run.stdout, /PP-S01/);
});

test('--corpus honours --min-severity', () => {
  const all = runCli(['--corpus', 'test/fixtures', '--format', 'json']);
  const strict = runCli(['--corpus', 'test/fixtures', '--format', 'json', '-s', 'critical']);
  const total = (text: string): number =>
    (JSON.parse(text) as { byRule: Array<{ count: number }> }).byRule.reduce(
      (sum, rule) => sum + rule.count,
      0,
    );
  assert.ok(total(all.stdout) > total(strict.stdout));
});
