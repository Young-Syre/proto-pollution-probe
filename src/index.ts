export { analyseSources, analysePaths } from './analyse.js';
export type { AnalyseOptions, AnalysePathsOptions, SourceInput } from './analyse.js';
export {
  discoverFiles,
  displayPath,
  looksGenerated,
  ANALYSED_EXTENSIONS,
  DEFAULT_IGNORED_DIRECTORIES,
} from './discover.js';
export type { DiscoverOptions } from './discover.js';
export { buildCorpusReport, renderCorpusText } from './corpus.js';
export type { CorpusReport } from './corpus.js';
export { renderText, renderJson, summaryLine, countByRule, countBySeverity } from './report.js';
export { renderSarif, SARIF_SCHEMA, SARIF_VERSION, sarifLevelFor, securitySeverityFor } from './sarif.js';
export { RULES, rule, SINK_RULE_IDS, GADGET_RULE_IDS } from './rules.js';
export { pairFindings } from './pair.js';
export type { PairOptions } from './pair.js';
export { scanSinks } from './sinks.js';
export { scanGadgets, collectWrittenProperties } from './gadgets.js';
export { analyseGuards, findPrototypeFreeze, PROTO_KEYS } from './guards.js';
export type { GuardAnalysis } from './guards.js';
export { findOwnProtoSources } from './sources.js';
export { eraseTypes, typeErasureAvailable, TYPESCRIPT_EXTENSIONS } from './ts-erase.js';
export { buildParsedFile, parseProgram, locationOf, baseIdentifier, ParseFailure } from './ast.js';
export type { Node, ParsedFile } from './ast.js';
export {
  SEVERITIES,
  SEVERITY_RANK,
  REACH_SEVERITY,
} from './types.js';
export type {
  Finding,
  FindingKind,
  GadgetReach,
  GuardKind,
  GuardNote,
  GuardQuality,
  Position,
  RelatedLocation,
  RuleMeta,
  ScanResult,
  Severity,
  SkippedFile,
  SourceLocation,
} from './types.js';
