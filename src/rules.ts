import type { RuleMeta } from './types.js';

/**
 * Every rule the tool can emit. The README's rules table is generated from this
 * array by `scripts/rules-table.mjs`, so the two cannot drift.
 */
export const RULES: RuleMeta[] = [
  {
    id: 'PP-S01',
    name: 'unguarded-recursive-merge',
    kind: 'sink',
    severity: 'high',
    shortDescription: 'Recursive merge copies attacker-chosen keys into a destination object',
    fullDescription:
      'A function iterates the keys of a source object and assigns or recurses into the ' +
      'same key on a destination object, with no key denylist, no null-prototype ' +
      'destination and no own-property filter. A source key of "__proto__" makes the ' +
      'write land on Object.prototype, where every plain object in the process can read it.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S02',
    name: 'unguarded-path-setter',
    kind: 'sink',
    severity: 'high',
    shortDescription: 'Dotted or slashed path setter creates intermediate objects without a key check',
    fullDescription:
      'A function splits a string into segments and walks or vivifies a nested object for ' +
      'each segment before assigning the final one. A path of "__proto__.polluted" or ' +
      '"constructor.prototype.polluted" reaches Object.prototype.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S03',
    name: 'unguarded-key-copy-loop',
    kind: 'sink',
    severity: 'medium',
    shortDescription: 'Shallow key-copy loop assigns a computed key onto a destination object',
    fullDescription:
      'A loop over source keys performs dst[key] = value with no key check. This is not a ' +
      'deep merge, so it cannot add properties to Object.prototype, but assigning the key ' +
      '"__proto__" replaces the destination object\'s prototype outright, which is enough to ' +
      'forge properties the rest of the program reads as defaults.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S04',
    name: 'unvalidated-assign-into-shared-object',
    kind: 'sink',
    severity: 'medium',
    shortDescription: 'Object.assign or object spread copies an unvalidated source into a shared object',
    fullDescription:
      'Object.assign or a spread writes an unvalidated source into an object that outlives ' +
      'the current call: a module-level binding, globalThis, a prototype, or a defaults ' +
      'object. Object.assign does not walk into __proto__, so the prototype of the target ' +
      'itself is what is at risk, along with every later read of the shared object.',
    cwe: ['CWE-1321', 'CWE-915'],
  },
  {
    id: 'PP-S05',
    name: 'dynamic-path-utility-call',
    kind: 'sink',
    severity: 'high',
    shortDescription: 'Lodash-shaped merge or set helper called with a non-literal key or path',
    fullDescription:
      'merge, mergeWith, defaultsDeep, set, setWith, update, updateWith and zipObjectDeep all ' +
      'walk into nested keys. Called with a path or source the caller does not control, they ' +
      'are a direct prototype-pollution primitive. Historic versions of these helpers were ' +
      'vulnerable even with a literal path; current versions are only vulnerable through the ' +
      'argument, which is what this rule reports.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S06',
    name: 'nested-key-query-parse',
    kind: 'sink',
    severity: 'high',
    shortDescription: 'Flat input is expanded into nested objects by bracket or operator syntax',
    fullDescription:
      'A parser turns flat text such as "a[b][c]=d" into a nested object graph, or a ' +
      'query-string library is configured to allow prototype keys. Either way an attacker ' +
      'writes "a[__proto__][x]=1" and controls object depth from a single flat string.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S07',
    name: 'computed-key-property-definition',
    kind: 'sink',
    severity: 'note',
    shortDescription: 'Object.defineProperty, Reflect.set or a class field uses a non-literal key',
    fullDescription:
      'Defining a property under a computed key lets an attacker choose "__proto__" or ' +
      '"constructor", and defineProperty in particular bypasses setters and writability ' +
      'checks that would otherwise stop the write. Reported at note level, below the ' +
      'default threshold, because measurement said so: the key is almost always a ' +
      'module\'s own export name or an internal field name rather than input. The rule ' +
      'excludes well-known symbols and the transpiler interop helpers, and what survives ' +
      'that is still mostly generic defineProperty wrappers. Raise the threshold to note ' +
      'to see it, and expect to decide for yourself where each key came from.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-S08',
    name: 'json-parse-into-sink',
    kind: 'sink',
    severity: 'high',
    shortDescription: 'JSON.parse output reaches a pollution sink with no reviver and no key filter',
    fullDescription:
      'JSON.parse is the usual way an attacker-controlled "__proto__" key becomes an own ' +
      'property of a real object: JSON.parse(\'{"__proto__":{"x":1}}\') produces an object ' +
      'whose own "__proto__" key a for..in loop will happily copy. This rule fires when such ' +
      'a value flows into another sink in the same file, and it is the reason an own-property ' +
      'filter alone is not treated as sufficient.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-G01',
    name: 'gadget-command-execution',
    kind: 'gadget',
    severity: 'critical',
    shortDescription: 'Unvalidated property read reaches a process-spawning call',
    fullDescription:
      'A property is read from a plain object, is never assigned anywhere in the program, and ' +
      'flows into child_process. A polluted Object.prototype supplies the value. The classic ' +
      'shape is an options object forwarded to exec or spawn, where a forged "shell" or "env" ' +
      'turns a default read into command execution.',
    cwe: ['CWE-1321', 'CWE-78'],
  },
  {
    id: 'PP-G02',
    name: 'gadget-path-resolution',
    kind: 'gadget',
    severity: 'high',
    shortDescription: 'Unvalidated property read reaches path or filesystem resolution',
    fullDescription:
      'An unassigned property read is used to build a path or is handed to the filesystem or ' +
      'a module loader. A polluted default redirects reads and writes outside the intended ' +
      'directory.',
    cwe: ['CWE-1321', 'CWE-22'],
  },
  {
    id: 'PP-G03',
    name: 'gadget-template-render',
    kind: 'gadget',
    severity: 'high',
    shortDescription: 'Unvalidated property read reaches a template compile, render or HTML sink',
    fullDescription:
      'An unassigned property read is passed to a template engine or written into markup. ' +
      'Most engines compile their input, so a polluted default is server-side template ' +
      'injection rather than merely stored HTML.',
    cwe: ['CWE-1321', 'CWE-1336'],
  },
  {
    id: 'PP-G04',
    name: 'gadget-auth-decision',
    kind: 'gadget',
    severity: 'high',
    shortDescription: 'Unvalidated property read is used as a security decision',
    fullDescription:
      'An unassigned property read whose name indicates a privilege, role or bypass is used ' +
      'as a condition. With Object.prototype polluted the condition is attacker-chosen, so ' +
      'the check it guards no longer holds.',
    cwe: ['CWE-1321', 'CWE-285'],
  },
  {
    id: 'PP-G05',
    name: 'gadget-unvalidated-default',
    kind: 'gadget',
    severity: 'note',
    shortDescription: 'Property read that is never assigned and never own-checked',
    fullDescription:
      'A property is read from a plain object but assigned nowhere in the scanned source and ' +
      'never filtered with an own-property check, and the reach analysis found nothing of ' +
      'value at the other end. This is a candidate list rather than a finding: it is the ' +
      'noisiest rule by a wide margin, it fires heavily on bundled output whose type ' +
      'declarations were not scanned, and it is below the default severity threshold. Raise ' +
      'the threshold to note to see it, and expect to triage it by hand.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-C01',
    name: 'pollution-chain',
    kind: 'chain',
    severity: 'critical',
    shortDescription: 'A reported sink and a reported gadget together form an exploitable chain',
    fullDescription:
      'A write primitive that can reach Object.prototype was found in the same scan as a read ' +
      'of a never-assigned property. The finding names both locations. A sink on its own is ' +
      'usually unactionable and a gadget on its own is harmless; the pair is the bug.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-Q01',
    name: 'incomplete-key-denylist',
    kind: 'guard-quality',
    severity: 'low',
    shortDescription: 'Key denylist blocks __proto__ but not constructor or prototype',
    fullDescription:
      'The sink is guarded, but only against the literal key "__proto__". That leaves the ' +
      '"constructor" and "prototype" names unchecked. Where the sink recurses or walks a ' +
      'path, those two are a complete bypass: constructor.prototype.x arrives exactly where ' +
      '__proto__.x would have. Where the sink only writes one level deep the bypass does not ' +
      'apply, but the denylist is still narrower than its author probably intended. A ' +
      'denylist wants all three names, or a null-prototype destination.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-Q02',
    name: 'own-property-filter-only',
    kind: 'guard-quality',
    severity: 'low',
    shortDescription: 'Sink relies on an own-property filter, which JSON input defeats',
    fullDescription:
      'The sink filters keys with hasOwnProperty or Object.hasOwn and nothing else. That ' +
      'stops keys inherited through the prototype chain, but JSON.parse creates "__proto__" ' +
      'as an own property, so the filter passes it straight through. Treated as a partial ' +
      'guard: the sink is not reported, but the weakness is.',
    cwe: ['CWE-1321'],
  },
  {
    id: 'PP-E01',
    name: 'parse-error',
    kind: 'diagnostic',
    severity: 'note',
    shortDescription: 'File could not be parsed as a module or a script',
    fullDescription:
      'acorn rejected the file in both module and script mode. The file is not analysed and ' +
      'is reported here so it is never silently ignored.',
    cwe: [],
  },
  {
    id: 'PP-E02',
    name: 'typescript-erasure-unavailable',
    kind: 'diagnostic',
    severity: 'note',
    shortDescription: 'TypeScript file could not have its types erased',
    fullDescription:
      'Type erasure uses the Node built-in module.stripTypeScriptTypes in strip-only mode. ' +
      'It is unavailable before Node 22.13, and it rejects enum declarations, namespace ' +
      'declarations and constructor parameter properties. Such files are not analysed and are ' +
      'reported here.',
    cwe: [],
  },
  {
    id: 'PP-E03',
    name: 'file-unreadable',
    kind: 'diagnostic',
    severity: 'note',
    shortDescription: 'File could not be read from disk',
    fullDescription: 'The file was discovered but reading it failed. Reported rather than ignored.',
    cwe: [],
  },
  {
    id: 'PP-E04',
    name: 'minified-source',
    kind: 'diagnostic',
    severity: 'note',
    shortDescription: 'File looks like bundled or minified output and was not analysed',
    fullDescription:
      'The file has lines far too long to have been written by hand. Findings in generated ' +
      'output are not actionable \u2014 the excerpt is unreadable, the line number means nothing, ' +
      'and the fix belongs in a source file that is not here \u2014 so such files are skipped by ' +
      'default. Pass --include-minified to analyse them anyway.',
    cwe: [],
  },
];

const byId = new Map(RULES.map((r) => [r.id, r]));

export function rule(id: string): RuleMeta {
  const found = byId.get(id);
  if (!found) throw new Error(`unknown rule id: ${id}`);
  return found;
}

export const SINK_RULE_IDS = RULES.filter((r) => r.kind === 'sink').map((r) => r.id);
export const GADGET_RULE_IDS = RULES.filter((r) => r.kind === 'gadget').map((r) => r.id);
