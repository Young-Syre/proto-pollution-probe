import { readdirSync, statSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';

export const ANALYSED_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts']);

/**
 * Directories skipped by default. Build output and vendored dependencies are excluded
 * because scanning them says more about other people's code than about the code under
 * review; `--include-node-modules` turns that off, which is exactly what the corpus
 * mode needs when measuring a false-positive rate.
 */
export const DEFAULT_IGNORED_DIRECTORIES = new Set([
  '.git',
  '.hg',
  '.svn',
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  '.next',
  '.nuxt',
  '.output',
  '.cache',
  '.turbo',
  'vendor',
  '__pycache__',
]);

export interface DiscoverOptions {
  includeNodeModules?: boolean;
  /** Analyse minified bundles too. Off by default: they are unreadable and never actionable. */
  includeMinified?: boolean;
  /** Extra directory names to skip. */
  ignore?: Iterable<string>;
}

const MINIFIED = /\.min\.(js|mjs|cjs)$/;
const DECLARATION = /\.d\.(ts|mts|cts)$/;

/** Files to analyse under a path, which may itself be a single file. */
export function discoverFiles(root: string, options: DiscoverOptions = {}): string[] {
  const ignored = new Set(DEFAULT_IGNORED_DIRECTORIES);
  for (const name of options.ignore ?? []) ignored.add(name);
  if (options.includeNodeModules) ignored.delete('node_modules');

  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    let stats;
    try {
      stats = statSync(current);
    } catch {
      continue;
    }
    if (stats.isFile()) {
      if (isAnalysable(current, options)) out.push(current);
      continue;
    }
    if (!stats.isDirectory()) continue;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (ignored.has(entry.name)) continue;
        stack.push(join(current, entry.name));
        continue;
      }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      const path = join(current, entry.name);
      if (isAnalysable(path, options)) out.push(path);
    }
  }
  return out.sort();
}

function isAnalysable(path: string, options: DiscoverOptions): boolean {
  if (!ANALYSED_EXTENSIONS.has(extname(path))) return false;
  if (DECLARATION.test(path)) return false;
  if (!options.includeMinified && MINIFIED.test(path)) return false;
  return true;
}

/**
 * Does this look like generated output rather than source?
 *
 * Bundlers and minifiers produce lines thousands of characters long. A finding on such a
 * line has an unreadable excerpt, a line number that points at a quarter of the file, and
 * a fix that belongs in a source file the scan never saw. Measured against a real
 * dependency tree, generated bundles were the largest single source of unactionable
 * output, so they are skipped unless asked for.
 */
export function looksGenerated(source: string): boolean {
  if (source.length < 20_000) return false;
  let longest = 0;
  let start = 0;
  for (let i = 0; i <= source.length; i += 1) {
    if (i === source.length || source.charCodeAt(i) === 10) {
      if (i - start > longest) longest = i - start;
      start = i + 1;
    }
  }
  if (longest > 2000) return true;
  const lines = source.split('\n').length;
  return source.length / lines > 300;
}

/**
 * Paths in findings must never embed the machine they were produced on: a SARIF file
 * goes into a pull request, and a README pastes real output. Everything is reported
 * relative to the scan root, with forward slashes.
 */
export function displayPath(path: string, base: string): string {
  const rel = relative(base, path);
  const chosen = rel === '' || rel.startsWith('..') ? path : rel;
  return sep === '/' ? chosen : chosen.split(sep).join('/');
}
