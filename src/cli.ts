#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analysePaths } from './analyse.js';
import { buildCorpusReport, renderCorpusText } from './corpus.js';
import { discoverFiles, displayPath } from './discover.js';
import { renderJson, renderText, summaryLine } from './report.js';
import { renderSarif } from './sarif.js';
import { RULES } from './rules.js';
import { SEVERITIES, SEVERITY_RANK, type Severity } from './types.js';
import { typeErasureAvailable } from './ts-erase.js';

/**
 * Exit codes. Documented here and in the README, and asserted by the test suite,
 * because a security tool whose exit code is a guess cannot gate anything.
 *
 *   0  scan completed, nothing at or above the severity threshold
 *   1  scan completed, at least one finding at or above the threshold
 *   2  bad usage: unknown flag, missing value, no path given
 *   3  scan could not be completed, or --strict-files was set and a file was skipped
 */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;
export const EXIT_ERROR = 3;

type Format = 'text' | 'json' | 'sarif';

interface Options {
  paths: string[];
  format: Format;
  minSeverity: Severity;
  corpus: boolean;
  pair: boolean;
  verbose: boolean;
  colour: boolean;
  includeNodeModules: boolean;
  includeMinified: boolean;
  strictFiles: boolean;
  exitZero: boolean;
  output: string | undefined;
  maxSinksPerGadget: number;
  maxChains: number;
}

function version(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(resolve(here, '../../package.json'), 'utf8')) as {
      version?: unknown;
    };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const HELP = `proto-pollution-probe — find prototype-pollution sinks, gadgets and the chains between them

Usage
  proto-pollution-probe [options] <path>...
  proto-pollution-probe --corpus <dir> [options]

Prototype pollution needs two halves: a write that can reach Object.prototype, and a
read of a property nothing ever assigns. This tool reports both, and pairs them.

Options
  -f, --format <text|json|sarif>  Output format (default: text)
  -o, --output <file>             Write the report to a file instead of stdout
  -s, --min-severity <level>      critical|high|medium|low|note (default: low)
      --no-pair                   Do not emit PP-C01 chain findings
      --corpus <dir>              Count findings per rule over a tree, for measuring
                                  the false-positive rate yourself (always exits 0)
      --include-node-modules      Do not skip node_modules (corpus runs usually want this)
      --include-minified          Analyse *.min.js and bundled output as well
      --strict-files              Exit 3 if any file could not be analysed
      --exit-zero                 Always exit 0, whatever was found
      --max-sinks-per-gadget <n>  Write primitives paired with each gadget (default: 1)
      --max-chains <n>            Cap on chain findings (default: 100)
  -v, --verbose                   Show the guard analysis behind each finding
      --no-color                  Disable colour (also honours NO_COLOR)
      --rules                     Print the rule table and exit
      --version                   Print the version and exit
  -h, --help                      Show this help and exit

Exit codes
  0  nothing at or above the severity threshold
  1  at least one finding at or above the threshold
  2  bad usage
  3  the scan could not be completed (or --strict-files and a file was skipped)

Scope
  JavaScript (.js, .mjs, .cjs) and TypeScript (.ts, .mts, .cts). TypeScript types are
  erased with Node's built-in stripper, which needs Node 22.13 or later and cannot
  handle enum, namespace or constructor parameter properties; such files are skipped
  and reported, never silently ignored. JSX and TSX are not parsed. The analysed code
  is never imported, required or evaluated.
`;

function parseArgs(argv: string[]): { options: Options } | { error: string } | { help: string } {
  const options: Options = {
    paths: [],
    format: 'text',
    minSeverity: 'low',
    corpus: false,
    pair: true,
    verbose: false,
    colour: process.stdout.isTTY === true && process.env['NO_COLOR'] === undefined,
    includeNodeModules: false,
    includeMinified: false,
    strictFiles: false,
    exitZero: false,
    output: undefined,
    maxSinksPerGadget: 1,
    maxChains: 100,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) continue;
    const next = (): string | undefined => {
      i += 1;
      return argv[i];
    };
    switch (arg) {
      case '-h':
      case '--help':
        return { help: HELP };
      case '--version':
        return { help: `${version()}\n` };
      case '--rules':
        return { help: rulesTable() };
      case '-f':
      case '--format': {
        const value = next();
        if (value !== 'text' && value !== 'json' && value !== 'sarif') {
          return { error: `--format expects text, json or sarif, got ${value ?? '(nothing)'}` };
        }
        options.format = value;
        break;
      }
      case '-o':
      case '--output': {
        const value = next();
        if (value === undefined) return { error: '--output expects a file path' };
        options.output = value;
        break;
      }
      case '-s':
      case '--min-severity': {
        const value = next();
        if (value === undefined || !(SEVERITIES as readonly string[]).includes(value)) {
          return { error: `--min-severity expects one of ${SEVERITIES.join(', ')}` };
        }
        options.minSeverity = value as Severity;
        break;
      }
      case '--corpus': {
        const value = next();
        if (value === undefined) return { error: '--corpus expects a directory' };
        options.corpus = true;
        options.paths.push(value);
        break;
      }
      case '--no-pair':
        options.pair = false;
        break;
      case '--include-node-modules':
        options.includeNodeModules = true;
        break;
      case '--include-minified':
        options.includeMinified = true;
        break;
      case '--strict-files':
        options.strictFiles = true;
        break;
      case '--exit-zero':
        options.exitZero = true;
        break;
      case '--max-sinks-per-gadget': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 0) return { error: '--max-sinks-per-gadget expects an integer' };
        options.maxSinksPerGadget = value;
        break;
      }
      case '--max-chains': {
        const value = Number(next());
        if (!Number.isInteger(value) || value < 0) return { error: '--max-chains expects an integer' };
        options.maxChains = value;
        break;
      }
      case '-v':
      case '--verbose':
        options.verbose = true;
        break;
      case '--no-color':
      case '--no-colour':
        options.colour = false;
        break;
      default:
        if (arg.startsWith('-')) return { error: `unknown option ${arg}` };
        options.paths.push(arg);
    }
  }

  if (options.paths.length === 0) return { error: 'no path given' };
  if (options.corpus && options.paths.length !== 1) {
    return { error: '--corpus takes exactly one directory' };
  }
  return { options };
}

function rulesTable(): string {
  const lines = ['rule     severity  kind           name'];
  lines.push('-------  --------  -------------  ------------------------------------');
  for (const meta of RULES) {
    lines.push(
      `${meta.id.padEnd(7)}  ${meta.severity.padEnd(8)}  ${meta.kind.padEnd(13)}  ${meta.name}`,
    );
  }
  return `${lines.join('\n')}\n`;
}

export function run(argv: string[]): number {
  const parsed = parseArgs(argv);
  if ('help' in parsed) {
    process.stdout.write(parsed.help);
    return EXIT_OK;
  }
  if ('error' in parsed) {
    process.stderr.write(`proto-pollution-probe: ${parsed.error}\nTry --help.\n`);
    return EXIT_USAGE;
  }
  const { options } = parsed;

  const discovered: string[] = [];
  const base = options.corpus ? (options.paths[0] as string) : process.cwd();
  for (const path of options.paths) {
    discovered.push(
      ...discoverFiles(path, {
        includeNodeModules: options.includeNodeModules || options.corpus,
        includeMinified: options.includeMinified,
      }),
    );
  }
  if (discovered.length === 0) {
    process.stderr.write(
      `proto-pollution-probe: no .js/.mjs/.cjs/.ts files found under ${options.paths.join(', ')}\n`,
    );
    return EXIT_ERROR;
  }

  const result = analysePaths(discovered, {
    minSeverity: options.minSeverity,
    includeMinified: options.includeMinified,
    pair: options.pair,
    maxSinksPerGadget: options.maxSinksPerGadget,
    maxChains: options.maxChains,
    display: (path) => displayPath(path, base),
  });

  let output: string;
  if (options.corpus) {
    const report = buildCorpusReport(displayPath(base, base) || '.', result, discovered.length);
    output = options.format === 'json' ? `${JSON.stringify(report, null, 2)}\n` : renderCorpusText(report);
  } else if (options.format === 'json') {
    output = renderJson(result);
  } else if (options.format === 'sarif') {
    output = renderSarif(result, { toolVersion: version() });
  } else {
    output = renderText(result, { colour: options.colour, verbose: options.verbose });
  }

  if (options.output !== undefined) {
    writeFileSync(options.output, output);
    process.stderr.write(`${summaryLine(result)}\n`);
  } else {
    process.stdout.write(output);
  }

  if (options.verbose && !typeErasureAvailable()) {
    process.stderr.write(
      `note: TypeScript type erasure is unavailable on Node ${process.versions.node}; ` +
        '.ts files were skipped. Node 22.13 or later provides it.\n',
    );
  }

  if (options.exitZero) return EXIT_OK;
  if (options.strictFiles && result.skipped.length > 0) return EXIT_ERROR;
  // Corpus mode measures; it does not gate. Exiting non-zero because a tree of other
  // people's dependencies contains findings would make it useless in a pipeline, and
  // the per-rule table is the output that matters.
  if (options.corpus) return EXIT_OK;
  const threshold = SEVERITY_RANK[options.minSeverity];
  const triggered = result.findings.some((finding) => SEVERITY_RANK[finding.severity] <= threshold);
  return triggered ? EXIT_FINDINGS : EXIT_OK;
}

const invokedDirectly = (() => {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return resolve(entry) === resolve(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  process.exitCode = run(process.argv.slice(2));
}
