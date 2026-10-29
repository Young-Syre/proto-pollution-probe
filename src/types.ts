/** Public data model. Everything the analyser produces is described here. */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'note'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Lower number = more severe. Used for threshold comparisons and sorting. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  note: 4,
};

export interface Position {
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** 0-based byte offset into the original file. */
  offset: number;
}

export interface SourceLocation {
  /** Path as supplied to the analyser, kept relative when the caller passed a relative path. */
  file: string;
  start: Position;
  end: Position;
  /** The source line the finding starts on, trimmed of trailing whitespace. */
  excerpt: string;
}

export interface RelatedLocation {
  label: string;
  loc: SourceLocation;
}

/** A guard the analyser recognised near a sink, with a judgement on how much it actually buys. */
export type GuardKind =
  | 'key-denylist'
  | 'has-own-property'
  | 'null-prototype'
  | 'map-container'
  | 'frozen-object-prototype'
  | 'json-reviver'
  | 'in-operator';

export type GuardQuality = 'sufficient' | 'partial' | 'weak';

export interface GuardNote {
  kind: GuardKind;
  quality: GuardQuality;
  /** Human-readable explanation of what the guard does and does not stop. */
  detail: string;
  loc?: SourceLocation;
}

/** What an unvalidated property read is able to influence. Drives gadget ranking. */
export type GadgetReach =
  | 'command-execution'
  | 'path-resolution'
  | 'template-render'
  | 'auth-decision'
  | 'framework-default';

export const REACH_SEVERITY: Record<GadgetReach, Severity> = {
  'command-execution': 'critical',
  'path-resolution': 'high',
  'template-render': 'high',
  'auth-decision': 'high',
  'framework-default': 'note',
};

export type FindingKind = 'sink' | 'gadget' | 'chain' | 'guard-quality';

export interface Finding {
  ruleId: string;
  ruleName: string;
  kind: FindingKind;
  severity: Severity;
  message: string;
  loc: SourceLocation;
  related: RelatedLocation[];
  /** Guards recognised in the sink's scope. Present on sink and chain findings. */
  guards: GuardNote[];
  reach?: GadgetReach;
  /** For gadget findings, the property name that is read but never assigned. */
  property?: string;
  /** Stable-ish identity for deduplication across runs. */
  fingerprint: string;
}

/** A file the analyser could not analyse, and exactly why. */
export interface SkippedFile {
  file: string;
  /** Rule-style code so the reason is greppable: see RULES in rules.ts. */
  code: 'PP-E01' | 'PP-E02' | 'PP-E03' | 'PP-E04';
  reason: string;
}

export interface ScanResult {
  findings: Finding[];
  skipped: SkippedFile[];
  filesScanned: number;
  /** Milliseconds spent inside the analyser, excluding file discovery. */
  elapsedMs: number;
}

export interface RuleMeta {
  id: string;
  name: string;
  kind: FindingKind | 'diagnostic';
  severity: Severity;
  shortDescription: string;
  fullDescription: string;
  /** CWE identifiers, e.g. 'CWE-1321'. */
  cwe: string[];
}
