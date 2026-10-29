import { RULES } from './rules.js';
import { SEVERITIES, type Finding, type ScanResult, type Severity } from './types.js';

export interface TextOptions {
  colour?: boolean;
  /** Show the guard notes attached to each finding. */
  verbose?: boolean;
}

const ANSI: Record<string, string> = {
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
  blue: '\u001b[34m',
  magenta: '\u001b[35m',
  cyan: '\u001b[36m',
  grey: '\u001b[90m',
};

const SEVERITY_COLOUR: Record<Severity, string> = {
  critical: 'magenta',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
  note: 'grey',
};

export function renderText(result: ScanResult, options: TextOptions = {}): string {
  const paint = (text: string, colour: string): string =>
    options.colour ? `${ANSI[colour] ?? ''}${text}${ANSI['reset']}` : text;

  const lines: string[] = [];
  const byFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const bucket = byFile.get(finding.loc.file);
    if (bucket) bucket.push(finding);
    else byFile.set(finding.loc.file, [finding]);
  }

  for (const [file, findings] of byFile) {
    lines.push(paint(file, 'bold'));
    for (const finding of findings) {
      const header =
        `  ${paint(finding.severity.toUpperCase().padEnd(8), SEVERITY_COLOUR[finding.severity])} ` +
        `${paint(finding.ruleId, 'cyan')} ${finding.ruleName}  ` +
        paint(`${finding.loc.start.line}:${finding.loc.start.column}`, 'dim');
      lines.push(header);
      for (const chunk of wrap(finding.message, 92)) lines.push(`    ${chunk}`);
      if (finding.loc.excerpt !== '') {
        lines.push(`    ${paint('|', 'grey')} ${finding.loc.excerpt.trim()}`);
      }
      for (const related of finding.related) {
        lines.push(
          `    ${paint('→', 'grey')} ${related.label} ` +
            paint(`(${related.loc.file}:${related.loc.start.line}:${related.loc.start.column})`, 'dim'),
        );
      }
      if (options.verbose) {
        for (const guard of finding.guards) {
          lines.push(`    ${paint(`[guard: ${guard.kind}, ${guard.quality}]`, 'grey')} ${guard.detail}`);
        }
      }
      lines.push('');
    }
  }

  if (result.skipped.length > 0) {
    lines.push(paint('Skipped files', 'bold'));
    for (const skip of result.skipped) {
      lines.push(`  ${paint(skip.code, 'cyan')} ${skip.file}`);
      for (const chunk of wrap(skip.reason, 92)) lines.push(`    ${chunk}`);
    }
    lines.push('');
  }

  lines.push(summaryLine(result));
  return `${lines.join('\n')}\n`;
}

export function summaryLine(result: ScanResult): string {
  const counts = countBySeverity(result.findings);
  const parts = SEVERITIES.filter((severity) => (counts[severity] ?? 0) > 0).map(
    (severity) => `${counts[severity]} ${severity}`,
  );
  const findingText = parts.length > 0 ? parts.join(', ') : 'no findings';
  const chains = result.findings.filter((finding) => finding.kind === 'chain').length;
  const skipped = result.skipped.length > 0 ? `, ${result.skipped.length} skipped` : '';
  return (
    `${result.filesScanned} file${result.filesScanned === 1 ? '' : 's'} scanned in ` +
    `${result.elapsedMs.toFixed(0)}ms${skipped} — ${findingText}` +
    (chains > 0 ? ` (${chains} paired chain${chains === 1 ? '' : 's'})` : '')
  );
}

export function countBySeverity(findings: Finding[]): Partial<Record<Severity, number>> {
  const counts: Partial<Record<Severity, number>> = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return counts;
}

export function countByRule(findings: Finding[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const rule of RULES) counts.set(rule.id, 0);
  for (const finding of findings) {
    counts.set(finding.ruleId, (counts.get(finding.ruleId) ?? 0) + 1);
  }
  return counts;
}

export function renderJson(result: ScanResult): string {
  return `${JSON.stringify(
    {
      tool: 'proto-pollution-probe',
      filesScanned: result.filesScanned,
      elapsedMs: Math.round(result.elapsedMs),
      counts: {
        bySeverity: countBySeverity(result.findings),
        byRule: Object.fromEntries([...countByRule(result.findings)].filter(([, count]) => count > 0)),
      },
      findings: result.findings,
      skipped: result.skipped,
    },
    null,
    2,
  )}\n`;
}

function wrap(text: string, width: number): string[] {
  const words = text.split(/\s+/).filter((word) => word !== '');
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    if (current === '') current = word;
    else if (current.length + 1 + word.length <= width) current += ` ${word}`;
    else {
      lines.push(current);
      current = word;
    }
  }
  if (current !== '') lines.push(current);
  return lines;
}
