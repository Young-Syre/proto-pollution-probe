import { readFileSync } from 'node:fs';
import { extname } from 'node:path';
import { type ParsedFile, ParseFailure, buildParsedFile } from './ast.js';
import { looksGenerated } from './discover.js';
import { collectWrittenProperties, scanGadgets } from './gadgets.js';
import { dedupeFindings, sortFindings } from './finding.js';
import { pairFindings, type PairOptions } from './pair.js';
import { scanSinks } from './sinks.js';
import { TYPESCRIPT_EXTENSIONS, eraseTypes } from './ts-erase.js';
import {
  SEVERITY_RANK,
  type Finding,
  type ScanResult,
  type Severity,
  type SkippedFile,
} from './types.js';

export interface SourceInput {
  /** Path reported in findings. Keep it relative to the scan root. */
  file: string;
  source: string;
}

export interface AnalyseOptions extends PairOptions {
  /** Emit PP-C01 chain findings. On by default: pairing is the point of the tool. */
  pair?: boolean;
  /** Drop findings below this severity. */
  minSeverity?: Severity;
  /** Analyse bundled and minified output too. Off by default; see `looksGenerated`. */
  includeMinified?: boolean;
}

/**
 * Analyse already-loaded sources.
 *
 * Two passes, and the reason for the first one is the gadget rule: a property that some
 * other module assigns is not a gadget, so the set of assigned property names has to be
 * known across the whole scan before any single file can be judged. Scanning one file in
 * isolation therefore reports more gadgets than scanning the project it belongs to, which
 * is the correct direction for a tool whose job is to narrow a reviewer's attention.
 */
export function analyseSources(inputs: SourceInput[], options: AnalyseOptions = {}): ScanResult {
  const started = process.hrtime.bigint();
  const parsedFiles: ParsedFile[] = [];
  const skipped: SkippedFile[] = [];

  for (const input of inputs) {
    if (options.includeMinified !== true && looksGenerated(input.source)) {
      skipped.push({
        file: input.file,
        code: 'PP-E04',
        reason:
          'the file has lines too long to have been hand-written, so it looks like bundled or ' +
          'minified output; pass --include-minified to analyse it anyway',
      });
      continue;
    }
    const extension = extname(input.file);
    let analysed = input.source;
    if (TYPESCRIPT_EXTENSIONS.has(extension)) {
      const erased = eraseTypes(input.source);
      if (!erased.ok) {
        skipped.push({ file: input.file, code: 'PP-E02', reason: erased.reason });
        continue;
      }
      analysed = erased.code;
    }
    try {
      parsedFiles.push(buildParsedFile(input.file, input.source, analysed));
    } catch (err) {
      const reason = err instanceof ParseFailure || err instanceof Error ? err.message : String(err);
      skipped.push({ file: input.file, code: 'PP-E01', reason });
    }
  }

  const written = new Set<string>();
  for (const parsed of parsedFiles) collectWrittenProperties(parsed, written);

  let findings: Finding[] = [];
  for (const parsed of parsedFiles) {
    findings.push(...scanSinks(parsed).findings);
    findings.push(...scanGadgets(parsed, written));
  }
  findings = dedupeFindings(findings);

  if (options.pair !== false) {
    findings.push(...pairFindings(findings, options));
  }

  const threshold = options.minSeverity ? SEVERITY_RANK[options.minSeverity] : undefined;
  if (threshold !== undefined) {
    findings = findings.filter((finding) => SEVERITY_RANK[finding.severity] <= threshold);
  }

  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  return {
    findings: sortFindings(findings),
    skipped,
    filesScanned: parsedFiles.length,
    elapsedMs,
  };
}

export interface AnalysePathsOptions extends AnalyseOptions {
  /** Maps an on-disk path to the path reported in findings. */
  display?: (path: string) => string;
}

/** Read and analyse files from disk. The analysed code is never executed or imported. */
export function analysePaths(paths: string[], options: AnalysePathsOptions = {}): ScanResult {
  const inputs: SourceInput[] = [];
  const unreadable: SkippedFile[] = [];
  for (const path of paths) {
    const file = options.display ? options.display(path) : path;
    try {
      inputs.push({ file, source: readFileSync(path, 'utf8') });
    } catch (err) {
      unreadable.push({
        file,
        code: 'PP-E03',
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }
  const result = analyseSources(inputs, options);
  return { ...result, skipped: [...unreadable, ...result.skipped] };
}
