import { createHash } from 'node:crypto';
import { type Node, type ParsedFile, locationOf } from './ast.js';
import { rule } from './rules.js';
import {
  SEVERITIES,
  SEVERITY_RANK,
  type Finding,
  type GuardNote,
  type RelatedLocation,
  type Severity,
  type SourceLocation,
} from './types.js';

export function downgrade(severity: Severity): Severity {
  const next = SEVERITIES[SEVERITY_RANK[severity] + 1];
  return next ?? severity;
}

export function upgrade(severity: Severity): Severity {
  const index = SEVERITY_RANK[severity];
  return index === 0 ? severity : (SEVERITIES[index - 1] ?? severity);
}

/**
 * Identity that survives unrelated edits to the same file: the rule, the path and the
 * text of the offending line. Line numbers deliberately play no part, so a finding keeps
 * its identity when code moves above it.
 */
export function fingerprint(ruleId: string, loc: SourceLocation): string {
  const normalised = loc.excerpt.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${ruleId}\u0000${loc.file}\u0000${normalised}`).digest('hex').slice(0, 16);
}

export interface FindingDraft {
  ruleId: string;
  node: Node;
  message: string;
  severity?: Severity;
  related?: RelatedLocation[];
  guards?: GuardNote[];
  reach?: Finding['reach'];
  property?: string;
}

export function makeFinding(parsed: ParsedFile, draft: FindingDraft): Finding {
  const meta = rule(draft.ruleId);
  const loc = locationOf(parsed, draft.node);
  const finding: Finding = {
    ruleId: meta.id,
    ruleName: meta.name,
    kind: meta.kind === 'diagnostic' ? 'guard-quality' : meta.kind,
    severity: draft.severity ?? meta.severity,
    message: draft.message,
    loc,
    related: draft.related ?? [],
    guards: draft.guards ?? [],
    // The property name is part of the identity: two gadget reads can share a line.
    fingerprint: fingerprint(draft.property === undefined ? meta.id : `${meta.id}:${draft.property}`, loc),
  };
  if (draft.reach) finding.reach = draft.reach;
  if (draft.property !== undefined) finding.property = draft.property;
  return finding;
}

export function relatedAt(parsed: ParsedFile, node: Node, label: string): RelatedLocation {
  return { label, loc: locationOf(parsed, node) };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
      a.loc.file.localeCompare(b.loc.file) ||
      a.loc.start.offset - b.loc.start.offset ||
      a.ruleId.localeCompare(b.ruleId),
  );
}

export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.ruleId}|${finding.loc.file}|${finding.loc.start.offset}|${finding.loc.end.offset}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}
