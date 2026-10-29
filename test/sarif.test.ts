import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RULES, rule } from '../src/rules.js';
import { SARIF_SCHEMA, SARIF_VERSION, renderSarif, sarifLevelFor, securitySeverityFor } from '../src/sarif.js';
import { renderJson, renderText } from '../src/report.js';
import { SEVERITIES } from '../src/types.js';
import { scanFixtureDir } from './helpers.js';

const result = scanFixtureDir('vulnerable');
const log = JSON.parse(renderSarif(result, { toolVersion: '0.1.0' })) as Record<string, any>;

test('the SARIF log has the 2.1.0 envelope', () => {
  assert.equal(log['version'], SARIF_VERSION);
  assert.equal(log['$schema'], SARIF_SCHEMA);
  assert.ok(Array.isArray(log['runs']));
  assert.equal(log['runs'].length, 1);
});

test('the driver is described', () => {
  const driver = log['runs'][0].tool.driver;
  assert.equal(driver.name, 'proto-pollution-probe');
  assert.equal(driver.version, '0.1.0');
  assert.equal(driver.semanticVersion, '0.1.0');
  assert.match(driver.informationUri, /^https:\/\//);
  assert.ok(Array.isArray(driver.rules));
  assert.ok(driver.rules.length > 0);
});

test('every emitted rule is declared exactly once', () => {
  const declared = log['runs'][0].tool.driver.rules.map((entry: { id: string }) => entry.id);
  assert.equal(new Set(declared).size, declared.length, 'no duplicate rule declarations');
  for (const found of result.findings) {
    assert.ok(declared.includes(found.ruleId), `${found.ruleId} is emitted but not declared`);
  }
});

test('rule metadata carries descriptions, a level and security tags', () => {
  for (const entry of log['runs'][0].tool.driver.rules) {
    assert.equal(typeof entry.name, 'string');
    assert.ok(entry.shortDescription.text.length > 10, `${entry.id} short description`);
    assert.ok(entry.fullDescription.text.length > 40, `${entry.id} full description`);
    assert.ok(['error', 'warning', 'note'].includes(entry.defaultConfiguration.level));
    assert.ok(entry.properties.tags.includes('security'));
    assert.ok(entry.properties.tags.includes('prototype-pollution'));
    assert.ok(/^\d+(\.\d+)?$/.test(entry.properties['security-severity']));
  }
});

test('CWE identifiers are carried as external tags', () => {
  const declared = log['runs'][0].tool.driver.rules;
  const s01 = declared.find((entry: { id: string }) => entry.id === 'PP-S01');
  assert.ok(s01);
  assert.ok(s01.properties.tags.includes('external/cwe/cwe-1321'));
  const g01 = declared.find((entry: { id: string }) => entry.id === 'PP-G01');
  assert.ok(g01);
  assert.ok(g01.properties.tags.includes('external/cwe/cwe-78'));
});

test('every result has a rule, a level, a message and a physical location', () => {
  const results = log['runs'][0].results;
  assert.equal(results.length, result.findings.length);
  for (const entry of results) {
    assert.equal(typeof entry.ruleId, 'string');
    assert.equal(typeof entry.ruleIndex, 'number');
    assert.ok(entry.ruleIndex >= 0);
    assert.ok(['error', 'warning', 'note'].includes(entry.level));
    assert.ok(entry.message.text.length > 20);
    const region = entry.locations[0].physicalLocation.region;
    assert.ok(region.startLine >= 1);
    assert.ok(region.startColumn >= 1);
    assert.ok(region.endLine >= region.startLine);
    assert.equal(typeof region.snippet.text, 'string');
    assert.equal(typeof entry.locations[0].physicalLocation.artifactLocation.uri, 'string');
  }
});

test('ruleIndex points at the matching declared rule', () => {
  const declared = log['runs'][0].tool.driver.rules;
  for (const entry of log['runs'][0].results) {
    assert.equal(declared[entry.ruleIndex].id, entry.ruleId);
  }
});

test('artifact URIs are relative and carry no absolute path', () => {
  for (const entry of log['runs'][0].results) {
    const uri = entry.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri.startsWith('/'), false, `absolute path leaked: ${uri}`);
    assert.equal(/^[A-Za-z]:/.test(uri), false, `drive letter leaked: ${uri}`);
    assert.equal(uri.includes('\\'), false, 'URIs use forward slashes');
  }
});

test('partial fingerprints are present and versioned', () => {
  for (const entry of log['runs'][0].results) {
    const value = entry.partialFingerprints['protoPollutionProbe/v1'];
    assert.ok(/^[0-9a-f]{16}$/.test(value), `bad fingerprint ${value}`);
  }
});

test('related locations carry an id and a message', () => {
  const withRelated = log['runs'][0].results.filter((entry: { relatedLocations?: unknown }) => entry.relatedLocations);
  assert.ok(withRelated.length > 0, 'the fixtures should produce related locations');
  for (const entry of withRelated) {
    for (const related of entry.relatedLocations) {
      assert.ok(related.id >= 1);
      assert.ok(related.message.text.length > 0);
      assert.ok(related.physicalLocation.region.startLine >= 1);
    }
  }
});

test('result properties carry severity, kind and security-severity', () => {
  for (const entry of log['runs'][0].results) {
    assert.ok(SEVERITIES.includes(entry.properties.severity));
    assert.ok(['sink', 'gadget', 'chain', 'guard-quality'].includes(entry.properties.kind));
    assert.equal(entry.properties['security-severity'], securitySeverityFor(entry.properties.severity));
  }
});

test('skipped files become tool execution notifications, not results', () => {
  const withSkips = scanFixtureDir('modern', 'note');
  const skipped = JSON.parse(renderSarif(withSkips, { toolVersion: '0.1.0' })) as Record<string, any>;
  const invocation = skipped['runs'][0].invocations[0];
  assert.equal(invocation.executionSuccessful, true);
  assert.ok(Array.isArray(invocation.toolExecutionNotifications));
  assert.equal(invocation.toolExecutionNotifications.length, withSkips.skipped.length);
  for (const notification of invocation.toolExecutionNotifications) {
    assert.equal(notification.level, 'note');
    assert.match(notification.descriptor.id, /^PP-E0\d$/);
    assert.ok(notification.message.text.length > 0);
  }
  const ids = skipped['runs'][0].results.map((entry: { ruleId: string }) => entry.ruleId);
  assert.equal(ids.includes('PP-E01'), false, 'diagnostics are not results');
});

test('run properties record how much was scanned', () => {
  const properties = log['runs'][0].properties;
  assert.equal(properties.filesScanned, result.filesScanned);
  assert.equal(properties.filesSkipped, result.skipped.length);
});

test('severity maps onto the three SARIF levels', () => {
  assert.equal(sarifLevelFor('critical'), 'error');
  assert.equal(sarifLevelFor('high'), 'error');
  assert.equal(sarifLevelFor('medium'), 'warning');
  assert.equal(sarifLevelFor('low'), 'warning');
  assert.equal(sarifLevelFor('note'), 'note');
});

test('security-severity is monotonic in severity', () => {
  const values = SEVERITIES.map((severity) => Number(securitySeverityFor(severity)));
  for (let i = 1; i < values.length; i += 1) {
    assert.ok((values[i] ?? 0) < (values[i - 1] ?? 0), 'security-severity must decrease with severity');
  }
});

test('the rule table is internally consistent', () => {
  const ids = RULES.map((meta) => meta.id);
  assert.equal(new Set(ids).size, ids.length, 'rule ids are unique');
  for (const meta of RULES) {
    assert.match(meta.id, /^PP-[SGCQE]\d{2}$/);
    assert.match(meta.name, /^[a-z0-9-]+$/);
    assert.equal(rule(meta.id), meta);
    assert.ok(SEVERITIES.includes(meta.severity));
    if (meta.kind !== 'diagnostic') assert.ok(meta.cwe.length > 0, `${meta.id} should cite a CWE`);
  }
  assert.throws(() => rule('PP-NOPE'), /unknown rule id/);
});

test('the JSON report is valid JSON with counts and findings', () => {
  const parsed = JSON.parse(renderJson(result)) as Record<string, any>;
  assert.equal(parsed['tool'], 'proto-pollution-probe');
  assert.equal(parsed['filesScanned'], result.filesScanned);
  assert.equal(parsed['findings'].length, result.findings.length);
  assert.ok(Object.keys(parsed['counts'].byRule).length > 0);
  const total = Object.values(parsed['counts'].bySeverity as Record<string, number>).reduce(
    (sum, value) => sum + value,
    0,
  );
  assert.equal(total, result.findings.length);
});

test('the text report mentions every finding and no absolute path', () => {
  const text = renderText(result, { colour: false, verbose: true });
  for (const found of result.findings.slice(0, 10)) {
    assert.ok(text.includes(found.ruleId), `${found.ruleId} missing from the text report`);
  }
  assert.equal(/(^|\s)\/(home|Users)\//.test(text), false, 'no absolute path in the text report');
  assert.match(text, /files scanned in/);
});

test('colour is opt-in', () => {
  const plain = renderText(result, { colour: false });
  const coloured = renderText(result, { colour: true });
  assert.equal(plain.includes('\u001b['), false);
  assert.ok(coloured.includes('\u001b['));
});
