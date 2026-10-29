import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import { analysePaths, analyseSources } from '../src/analyse.js';
import { discoverFiles } from '../src/discover.js';
import type { Finding, ScanResult, Severity } from '../src/types.js';

/** Repository root, derived from this file's location in `dist/test`. */
export const ROOT = fileURLToPath(new URL('../../', import.meta.url));
export const FIXTURES = join(ROOT, 'test', 'fixtures');
export const CLI = join(ROOT, 'dist', 'src', 'cli.js');

export function fixture(...parts: string[]): string {
  return join(FIXTURES, ...parts);
}

/**
 * Scan one fixture file on its own, at the CLI's default severity threshold, so that
 * "clean" in a test means the same thing as "clean" on the command line.
 */
export function scanFixture(...parts: string[]): ScanResult {
  const path = fixture(...parts);
  return analysePaths([path], {
    minSeverity: 'low',
    display: () => relative(FIXTURES, path).split('\\').join('/'),
  });
}

/** Scan one fixture file at an explicit severity threshold. */
export function scanFixtureAt(minSeverity: Severity, ...parts: string[]): ScanResult {
  const path = fixture(...parts);
  return analysePaths([path], {
    minSeverity,
    display: () => relative(FIXTURES, path).split('\\').join('/'),
  });
}

/** Scan a whole fixture directory, the way the CLI would. */
export function scanFixtureDir(name: string, minSeverity: Severity = 'low'): ScanResult {
  const dir = fixture(name);
  const files = discoverFiles(dir);
  return analysePaths(files, {
    minSeverity,
    display: (p) => relative(FIXTURES, p).split('\\').join('/'),
  });
}

export function scanSource(source: string, file = 'inline.js'): ScanResult {
  return analyseSources([{ file, source }], { minSeverity: 'low' });
}

export function scanSourceAt(minSeverity: Severity, source: string, file = 'inline.js'): ScanResult {
  return analyseSources([{ file, source }], { minSeverity });
}

export function ruleIds(result: ScanResult): string[] {
  return result.findings.map((finding) => finding.ruleId);
}

export function hasRule(result: ScanResult, ruleId: string): boolean {
  return result.findings.some((finding) => finding.ruleId === ruleId);
}

export function findingsFor(result: ScanResult, ruleId: string): Finding[] {
  return result.findings.filter((finding) => finding.ruleId === ruleId);
}

export function severityOf(result: ScanResult, ruleId: string): Severity | undefined {
  return result.findings.find((finding) => finding.ruleId === ruleId)?.severity;
}

export function readFixture(...parts: string[]): string {
  return readFileSync(fixture(...parts), 'utf8');
}

export interface CliRun {
  status: number;
  stdout: string;
  stderr: string;
}

/** Run the built CLI the way a user would, from the repository root. */
export function runCli(args: string[]): CliRun {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const error = err as { status?: number; stdout?: string; stderr?: string };
    return {
      status: error.status ?? -1,
      stdout: error.stdout ?? '',
      stderr: error.stderr ?? '',
    };
  }
}
