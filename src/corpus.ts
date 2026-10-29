import { RULES } from './rules.js';
import { countBySeverity } from './report.js';
import { SEVERITIES, type ScanResult } from './types.js';

export interface CorpusReport {
  root: string;
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  elapsedMs: number;
  byRule: Array<{ id: string; name: string; count: number; files: number }>;
  bySeverity: Partial<Record<string, number>>;
  skippedByCode: Array<{ code: string; count: number }>;
  /** Files with the most findings, so a reviewer can start with the noisiest. */
  topFiles: Array<{ file: string; count: number }>;
}

/**
 * Corpus mode exists so that nobody has to take a false-positive claim on trust.
 *
 * Run the analyser over a tree, get counts per rule and the files that drove them, and
 * triage a sample yourself. A rule that fires on a third of the files in a dependency
 * tree is telling you something about the rule, not about the tree.
 */
export function buildCorpusReport(
  root: string,
  result: ScanResult,
  filesDiscovered: number,
  topFileLimit = 15,
): CorpusReport {
  const perRule = new Map<string, { count: number; files: Set<string> }>();
  const perFile = new Map<string, number>();
  for (const finding of result.findings) {
    const entry = perRule.get(finding.ruleId) ?? { count: 0, files: new Set<string>() };
    entry.count += 1;
    entry.files.add(finding.loc.file);
    perRule.set(finding.ruleId, entry);
    perFile.set(finding.loc.file, (perFile.get(finding.loc.file) ?? 0) + 1);
  }

  const skippedByCode = new Map<string, number>();
  for (const skip of result.skipped) {
    skippedByCode.set(skip.code, (skippedByCode.get(skip.code) ?? 0) + 1);
  }

  return {
    root,
    filesDiscovered,
    filesScanned: result.filesScanned,
    filesSkipped: result.skipped.length,
    elapsedMs: result.elapsedMs,
    byRule: RULES.map((meta) => ({
      id: meta.id,
      name: meta.name,
      count: perRule.get(meta.id)?.count ?? 0,
      files: perRule.get(meta.id)?.files.size ?? 0,
    })),
    bySeverity: countBySeverity(result.findings),
    skippedByCode: [...skippedByCode].map(([code, count]) => ({ code, count })).sort((a, b) => a.code.localeCompare(b.code)),
    topFiles: [...perFile]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, topFileLimit)
      .map(([file, count]) => ({ file, count })),
  };
}

export function renderCorpusText(report: CorpusReport): string {
  const lines: string[] = [];
  lines.push(`corpus: ${report.root}`);
  lines.push(
    `${report.filesDiscovered} file(s) discovered, ${report.filesScanned} analysed, ` +
      `${report.filesSkipped} skipped, ${report.elapsedMs.toFixed(0)}ms`,
  );
  lines.push('');
  lines.push('rule     name                                   findings   files');
  lines.push('-------  -------------------------------------  --------  ------');
  for (const entry of report.byRule) {
    lines.push(
      `${entry.id.padEnd(7)}  ${entry.name.padEnd(37)}  ${String(entry.count).padStart(8)}  ` +
        String(entry.files).padStart(6),
    );
  }
  lines.push('');
  const severityParts = SEVERITIES.filter((severity) => (report.bySeverity[severity] ?? 0) > 0).map(
    (severity) => `${report.bySeverity[severity]} ${severity}`,
  );
  lines.push(`by severity: ${severityParts.length > 0 ? severityParts.join(', ') : 'none'}`);
  if (report.skippedByCode.length > 0) {
    lines.push(`skipped: ${report.skippedByCode.map((entry) => `${entry.count} ${entry.code}`).join(', ')}`);
  }
  if (report.topFiles.length > 0) {
    lines.push('');
    lines.push('files with the most findings:');
    for (const entry of report.topFiles) {
      lines.push(`  ${String(entry.count).padStart(4)}  ${entry.file}`);
    }
  }
  return `${lines.join('\n')}\n`;
}
