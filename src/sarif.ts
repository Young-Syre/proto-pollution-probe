import { RULES, rule } from './rules.js';
import type { Finding, ScanResult, Severity, SourceLocation } from './types.js';

export const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
export const SARIF_VERSION = '2.1.0';

/**
 * SARIF 2.1.0 has three result levels that mean "look at this" and no notion of
 * "critical", so severity is carried twice: `level` for tools that only understand
 * SARIF, and `security-severity` (a CVSS-shaped number, which is what GitHub code
 * scanning sorts and filters on) in rule and result properties.
 */
const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  note: 'note',
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.3',
  high: '7.5',
  medium: '5.0',
  low: '3.5',
  note: '1.0',
};

export interface SarifOptions {
  toolVersion: string;
  informationUri?: string;
}

export function renderSarif(result: ScanResult, options: SarifOptions): string {
  const used = new Map<string, number>();
  const rules: unknown[] = [];
  for (const finding of result.findings) {
    if (used.has(finding.ruleId)) continue;
    used.set(finding.ruleId, rules.length);
    rules.push(sarifRule(finding.ruleId));
  }

  const results = result.findings.map((finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: used.get(finding.ruleId) ?? 0,
    level: SARIF_LEVEL[finding.severity],
    message: { text: finding.message },
    locations: [sarifLocation(finding.loc)],
    ...(finding.related.length > 0
      ? {
          relatedLocations: finding.related.map((related, index) => ({
            ...sarifLocation(related.loc),
            id: index + 1,
            message: { text: related.label },
          })),
        }
      : {}),
    partialFingerprints: { 'protoPollutionProbe/v1': finding.fingerprint },
    properties: {
      severity: finding.severity,
      'security-severity': SECURITY_SEVERITY[finding.severity],
      kind: finding.kind,
      ...(finding.reach ? { reach: finding.reach } : {}),
      ...(finding.guards.length > 0
        ? {
            guards: finding.guards.map((guard) => ({
              kind: guard.kind,
              quality: guard.quality,
              detail: guard.detail,
            })),
          }
        : {}),
    },
  }));

  const notifications = result.skipped.map((skip) => ({
    level: 'note' as const,
    message: { text: `${skip.code}: ${skip.reason}` },
    descriptor: { id: skip.code },
    locations: [{ physicalLocation: { artifactLocation: { uri: skip.file } } }],
  }));

  const log = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'proto-pollution-probe',
            version: options.toolVersion,
            semanticVersion: options.toolVersion,
            informationUri: options.informationUri ?? 'https://github.com/Young-Syre/proto-pollution-probe',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            ...(notifications.length > 0 ? { toolExecutionNotifications: notifications } : {}),
          },
        ],
        results,
        properties: {
          filesScanned: result.filesScanned,
          filesSkipped: result.skipped.length,
        },
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}

function sarifRule(ruleId: string): unknown {
  const meta = rule(ruleId);
  return {
    id: meta.id,
    name: meta.name,
    shortDescription: { text: meta.shortDescription },
    fullDescription: { text: meta.fullDescription },
    help: { text: meta.fullDescription },
    defaultConfiguration: { level: SARIF_LEVEL[meta.severity] },
    properties: {
      tags: ['security', 'prototype-pollution', ...meta.cwe.map((cwe) => `external/cwe/${cwe.toLowerCase()}`)],
      'security-severity': SECURITY_SEVERITY[meta.severity],
      precision: meta.kind === 'chain' ? 'high' : 'medium',
    },
  };
}

function sarifLocation(loc: SourceLocation): {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: {
      startLine: number;
      startColumn: number;
      endLine: number;
      endColumn: number;
      snippet: { text: string };
    };
  };
} {
  return {
    physicalLocation: {
      artifactLocation: { uri: loc.file },
      region: {
        startLine: loc.start.line,
        startColumn: loc.start.column,
        endLine: loc.end.line,
        endColumn: loc.end.column,
        snippet: { text: loc.excerpt },
      },
    },
  };
}

/** Every rule the tool knows, for documentation generators. */
export function allRuleIds(): string[] {
  return RULES.map((meta) => meta.id);
}

export function sarifLevelFor(severity: Severity): 'error' | 'warning' | 'note' {
  return SARIF_LEVEL[severity];
}

export function securitySeverityFor(severity: Severity): string {
  return SECURITY_SEVERITY[severity];
}

export type { Finding };
