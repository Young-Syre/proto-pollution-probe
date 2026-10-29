import {
  type Node,
  type ParsedFile,
  ancestors,
  baseIdentifier,
  calleePath,
  descendants,
  enclosingFunction,
  functionName,
  identifierName,
  isLiteralish,
  isNode,
  literalStringValue,
  memberPath,
  nodeText,
  parameterNames,
  rootIdentifier,
  staticPropertyName,
} from './ast.js';
import { analyseGuards, findPrototypeFreeze } from './guards.js';
import { downgrade, makeFinding, relatedAt } from './finding.js';
import { rule } from './rules.js';
import {
  type OwnProtoSource,
  findOwnProtoSources,
  findParsedBindings,
  isAuthorControlled,
  unwrapAwait,
} from './sources.js';
import { SEVERITY_RANK, type Finding, type GuardNote, type Severity } from './types.js';

export interface SinkScan {
  findings: Finding[];
  /** Names of functions that contain a reported sink, so JSON flow can be traced into them. */
  sinkFunctions: Map<string, Node>;
  ownProtoSources: OwnProtoSource[];
}

interface Context {
  parsed: ParsedFile;
  freeze: Node | undefined;
  ownProtoSources: OwnProtoSource[];
  moduleBindings: Map<string, Node>;
  lodashMembers: Map<string, string>;
  lodashNamespaces: Set<string>;
  mapBindings: Set<string>;
}

// ---------------------------------------------------------------------------
// Emission: the single place that decides whether a detected sink is reported
// ---------------------------------------------------------------------------

/** The less severe of two severities. */
function atMost(severity: Severity, ceiling: Severity): Severity {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[ceiling] ? severity : ceiling;
}

interface SinkDraft {
  ruleId: string;
  node: Node;
  message: string;
  related?: Array<{ node: Node; label: string }>;
  /** Names the sink's key is bound to, so a denylist must be seen to test it. */
  keyNames?: readonly string[];
  /**
   * Does the write recurse or walk into nested levels? This decides whether a denylist
   * of "__proto__" alone is enough. For a single-level write it is: only the literal
   * "__proto__" key reaches a prototype, so rejecting it closes the hole. For a deep
   * write it is not, because the merge can recurse through the destination's inherited
   * "constructor" and on into "prototype".
   */
  deep?: boolean;
}

/**
 * Apply guard analysis to a detected sink and turn it into nothing, a guard-quality
 * note, or a finding.
 *
 * The three outcomes are the tool's whole editorial position:
 *
 *  - A sufficient guard (frozen prototype, null-prototype destination, denylist that
 *    covers `constructor` as well as `__proto__`) means silence. Reporting guarded code
 *    is how static analysers get switched off.
 *  - An own-property filter and nothing else is sufficient only while the file contains
 *    no parser that can mint an own `__proto__` key. When it does, the filter is reported
 *    as inadequate and the sink stands, one severity lower.
 *  - A denylist covering only `__proto__` leaves `constructor.prototype` open, so the
 *    sink stands one severity lower and the gap is reported separately as PP-Q01.
 */
function emitSink(context: Context, draft: SinkDraft): Finding[] {
  const { parsed } = context;
  const guards = analyseGuards(parsed, draft.node, {
    freeze: context.freeze,
    ...(draft.keyNames ? { keyNames: draft.keyNames } : {}),
  });
  if (guards.sufficient) return [];

  const related = (draft.related ?? []).map((item) => relatedAt(parsed, item.node, item.label));
  const meta = rule(draft.ruleId);
  const out: Finding[] = [];

  const denylistNote = guards.notes.find((note) => note.kind === 'key-denylist');
  if (
    draft.deep !== true &&
    denylistNote !== undefined &&
    guards.blockedKeys.has('__proto__')
  ) {
    // Shallow write, "__proto__" rejected: there is no second route, so nothing to say.
    return [];
  }
  const hasOwnNote = guards.notes.find((note) => note.kind === 'has-own-property');
  const nullProtoNote = guards.notes.find((note) => note.kind === 'null-prototype');
  let severity = meta.severity;
  let message = draft.message;

  if (nullProtoNote?.quality === 'partial') {
    message +=
      ' Object.create(null) is used here, but intermediate objects are created as plain {}, so ' +
      'only the top level is prototype-less: a path through an intermediate reaches its inherited ' +
      '"constructor" and from there Object.prototype.';
  }

  if (denylistNote && denylistNote.quality === 'weak') {
    severity = downgrade(severity);
    message += ' The key denylist here only rejects __proto__, so constructor.prototype still reaches it.';
    out.push(
      makeFinding(parsed, {
        ruleId: 'PP-Q01',
        node: draft.node,
        // A note about a note-level sink must not outrank the sink it describes.
        severity: atMost(rule('PP-Q01').severity, meta.severity),
        message:
          'Key denylist covers __proto__ but not constructor or prototype. Where this sink ' +
          'recurses or walks a path, constructor.prototype arrives in the same place.',
        related,
        guards: guards.notes,
      }),
    );
  } else if (hasOwnNote && !denylistNote) {
    const source = context.ownProtoSources[0];
    if (!source) {
      // The filter holds for every source present in this file. Record the fragility at
      // note level and stop; the sink itself is not reported.
      return [
        makeFinding(parsed, {
          ruleId: 'PP-Q02',
          node: draft.node,
          severity: atMost('note', meta.severity),
          message:
            'This sink is guarded only by an own-property filter. No parser in this file can ' +
            'produce an own "__proto__" key today, so the filter holds, but it will stop holding ' +
            'the moment JSON.parse, Object.fromEntries or a query-string parser feeds it.',
          related,
          guards: guards.notes,
        }),
      ];
    }
    severity = downgrade(severity);
    message +=
      ` An own-property filter guards it, which ${source.label} defeats: that parser creates ` +
      '"__proto__" as an own property.';
    related.push(relatedAt(parsed, source.node, `${source.label} produces an own "__proto__" key`));
  }

  out.unshift(
    makeFinding(parsed, {
      ruleId: draft.ruleId,
      node: draft.node,
      message,
      severity,
      related,
      guards: guards.notes,
    }),
  );
  return out;
}

// ---------------------------------------------------------------------------
// Context construction
// ---------------------------------------------------------------------------

const LODASH_MODULES = /^lodash(-es)?(\/|$)|^lodash\.[a-z]+$/;

function buildContext(parsed: ParsedFile): Context {
  const moduleBindings = new Map<string, Node>();
  const lodashMembers = new Map<string, string>();
  const lodashNamespaces = new Set<string>();
  const mapBindings = new Set<string>();

  const body = parsed.program['body'];
  if (Array.isArray(body)) {
    for (const statement of body) {
      if (!isNode(statement)) continue;
      if (statement.type === 'VariableDeclaration') {
        const declarations = statement['declarations'];
        if (!Array.isArray(declarations)) continue;
        for (const declarator of declarations) {
          if (!isNode(declarator)) continue;
          const name = identifierName(declarator['id']);
          if (name) moduleBindings.set(name, declarator);
        }
      }
      if (statement.type === 'ImportDeclaration') {
        const source = literalStringValue(statement['source']);
        if (source === undefined || !LODASH_MODULES.test(source)) continue;
        const single = /^lodash\.([a-z]+)$/.exec(source);
        const specifiers = statement['specifiers'];
        if (!Array.isArray(specifiers)) continue;
        for (const specifier of specifiers) {
          if (!isNode(specifier)) continue;
          const local = identifierName(specifier['local']);
          if (!local) continue;
          if (specifier.type === 'ImportDefaultSpecifier' || specifier.type === 'ImportNamespaceSpecifier') {
            if (single) lodashMembers.set(local, single[1] ?? local);
            else lodashNamespaces.add(local);
          } else {
            const imported = identifierName(specifier['imported']) ?? local;
            lodashMembers.set(local, imported);
          }
        }
      }
    }
  }

  // `require` forms, wherever they appear, plus Map bindings.
  for (const node of parsed.nodes) {
    if (node.type === 'VariableDeclarator') {
      const init = node['init'];
      if (!isNode(init)) continue;
      if (init.type === 'NewExpression') {
        const callee = init['callee'];
        const name = isNode(callee) ? callee['name'] : undefined;
        if (name === 'Map' || name === 'WeakMap') {
          const bound = identifierName(node['id']);
          if (bound) mapBindings.add(bound);
        }
        continue;
      }
      if (init.type !== 'CallExpression') continue;
      const callee = calleePath(init);
      if (callee?.join('.') !== 'require') continue;
      const args = init['arguments'];
      const moduleName = Array.isArray(args) && isNode(args[0]) ? literalStringValue(args[0]) : undefined;
      if (moduleName === undefined || !LODASH_MODULES.test(moduleName)) continue;
      const single = /^lodash\.([a-z]+)$/.exec(moduleName);
      const id = node['id'];
      if (!isNode(id)) continue;
      if (id.type === 'Identifier') {
        const local = id['name'] as string;
        if (single) lodashMembers.set(local, single[1] ?? local);
        else lodashNamespaces.add(local);
      } else if (id.type === 'ObjectPattern') {
        const properties = id['properties'];
        if (!Array.isArray(properties)) continue;
        for (const property of properties) {
          if (!isNode(property) || property.type !== 'Property') continue;
          const imported = identifierName(property['key']) ?? literalStringValue(property['key']);
          const local = identifierName(property['value']);
          if (imported && local) lodashMembers.set(local, imported);
        }
      }
    }
  }

  return {
    parsed,
    freeze: findPrototypeFreeze(parsed),
    ownProtoSources: findOwnProtoSources(parsed),
    moduleBindings,
    lodashMembers,
    lodashNamespaces,
    mapBindings,
  };
}

// ---------------------------------------------------------------------------
// Key iteration: the shape every merge rule is built on
// ---------------------------------------------------------------------------

interface KeyLoop {
  /** The loop or iteration call. */
  node: Node;
  /** Name bound to each key. */
  keyName: string;
  /** Name bound to each value, when the loop destructures entries. */
  valueName?: string;
  /** Expression the keys come from. */
  source: Node;
  /** Statements or expressions executed per key. */
  body: Node;
}

const KEY_ENUMERATORS = new Set([
  'Object.keys',
  'Object.entries',
  'Object.getOwnPropertyNames',
  'Reflect.ownKeys',
]);

function enumeratedSource(node: Node): Node | undefined {
  if (node.type !== 'CallExpression') return undefined;
  const path = calleePath(node);
  if (!path || !KEY_ENUMERATORS.has(path.join('.'))) return undefined;
  const args = node['arguments'];
  const first = Array.isArray(args) ? args[0] : undefined;
  return isNode(first) ? first : undefined;
}

function declaredNames(left: unknown): string[] {
  if (!isNode(left)) return [];
  if (left.type === 'VariableDeclaration') {
    const declarations = left['declarations'];
    if (!Array.isArray(declarations)) return [];
    const first = declarations[0];
    if (!isNode(first)) return [];
    return patternNames(first['id']);
  }
  return patternNames(left);
}

function patternNames(pattern: unknown): string[] {
  if (!isNode(pattern)) return [];
  if (pattern.type === 'Identifier') return [pattern['name'] as string];
  if (pattern.type === 'ArrayPattern') {
    const elements = pattern['elements'];
    if (!Array.isArray(elements)) return [];
    return elements.map((element) => (isNode(element) ? identifierName(element) ?? '' : ''));
  }
  return [];
}

/** Every per-key iteration in a function, whatever syntax it is spelled with. */
function keyLoops(fn: Node): KeyLoop[] {
  const out: KeyLoop[] = [];
  for (const node of descendants(fn)) {
    if (node.type === 'ForInStatement') {
      const names = declaredNames(node['left']);
      const keyName = names[0];
      const right = node['right'];
      const body = node['body'];
      if (keyName && isNode(right) && isNode(body)) {
        out.push({ node, keyName, source: right, body });
      }
      continue;
    }
    if (node.type === 'ForOfStatement') {
      const right = node['right'];
      if (!isNode(right)) continue;
      const source = enumeratedSource(right);
      if (!source) continue;
      const names = declaredNames(node['left']);
      const keyName = names[0];
      const body = node['body'];
      if (keyName && isNode(body)) {
        const loop: KeyLoop = { node, keyName, source, body };
        const valueName = names[1];
        if (valueName) loop.valueName = valueName;
        out.push(loop);
      }
      continue;
    }
    if (node.type === 'CallExpression') {
      const callee = node['callee'];
      if (!isNode(callee)) continue;
      const method = staticPropertyName(callee);
      if (method !== 'forEach' && method !== 'map' && method !== 'reduce') continue;
      const object = callee['object'];
      if (!isNode(object)) continue;
      const source = enumeratedSource(object);
      if (!source) continue;
      const args = node['arguments'];
      const callback = Array.isArray(args) ? args[method === 'reduce' ? 0 : 0] : undefined;
      if (!isNode(callback)) continue;
      if (callback.type !== 'ArrowFunctionExpression' && callback.type !== 'FunctionExpression') continue;
      const params = callback['params'];
      if (!Array.isArray(params)) continue;
      const firstParam = method === 'reduce' ? params[1] : params[0];
      if (!isNode(firstParam)) continue;
      const names = patternNames(firstParam);
      const keyName = names[0];
      const body = callback['body'];
      if (keyName && isNode(body)) {
        const loop: KeyLoop = { node, keyName, source, body };
        const valueName = names[1];
        if (valueName) loop.valueName = valueName;
        out.push(loop);
      }
    }
  }
  return out;
}

/** `dst[key] = ...` where `key` is the loop variable. */
interface KeyedWrite {
  node: Node;
  destination: Node;
  destinationRoot: string | undefined;
}

function keyedWrites(body: Node, keyName: string): KeyedWrite[] {
  const out: KeyedWrite[] = [];
  for (const node of descendants(body)) {
    if (node.type !== 'AssignmentExpression') continue;
    const left = node['left'];
    if (!isNode(left) || left.type !== 'MemberExpression' || left['computed'] !== true) continue;
    if (identifierName(left['property']) !== keyName) continue;
    const destination = left['object'];
    if (!isNode(destination)) continue;
    out.push({ node, destination, destinationRoot: rootIdentifier(destination) });
  }
  return out;
}

/** Does the loop body recurse — into itself, or into any `[key]` of both sides? */
function looksRecursive(body: Node, keyName: string, ownName: string | undefined): boolean {
  for (const node of descendants(body)) {
    if (node.type !== 'CallExpression') continue;
    const path = calleePath(node);
    const callee = path?.[path.length - 1];
    const args = node['arguments'];
    if (!Array.isArray(args)) continue;
    const keyedArgs = args.filter(
      (arg) =>
        isNode(arg) &&
        arg.type === 'MemberExpression' &&
        arg['computed'] === true &&
        identifierName(arg['property']) === keyName,
    );
    if (ownName !== undefined && callee === ownName && keyedArgs.length > 0) return true;
    // A helper called with both `dst[key]` and `src[key]` is a deep merge regardless of
    // what it is named.
    if (keyedArgs.length >= 2) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// PP-S01 / PP-S03: merge loops
// ---------------------------------------------------------------------------

/**
 * Was this destination created inside the function, as a plain object or array?
 *
 * Used only by the shallow-copy rule. `const out = {}; for (const k in src) out[k] = src[k]`
 * is the single most common loop in any codebase, and writing `__proto__` into `out`
 * replaces the prototype of an object nothing else has seen. Treating that as a finding
 * produced 370 reports on one dependency tree, none of which a reviewer could act on.
 */
/**
 * Does this source expression resolve to an object literal written in this file?
 *
 * `for (const code in _styles)` where `_styles` is a module-level literal enumerates
 * keys the author typed, not keys an attacker chose. One indirection is followed, which
 * is enough for the constant-table pattern and stops short of being a dataflow engine.
 */
function resolvesToLiteralObject(context: Context, source: Node): boolean {
  const name = identifierName(source);
  if (name === undefined) return false;
  const declarator = context.moduleBindings.get(name);
  if (!declarator) return false;
  const init = declarator['init'];
  return isNode(init) && init.type === 'ObjectExpression';
}

function isFreshObject(value: unknown): boolean {
  if (!isNode(value)) return false;
  if (value.type === 'ObjectExpression' || value.type === 'ArrayExpression') return true;
  return value.type === 'CallExpression' && calleePath(value)?.join('.') === 'Object.create';
}

function isFreshLocal(context: Context, fn: Node, root: string | undefined): boolean {
  if (root === undefined) return false;
  // A parameter belongs to the caller, so it is never "fresh" however it is used here.
  if (new Set(parameterNames(fn)).has(root)) return false;
  if (context.moduleBindings.has(root)) return false;
  let declaredHere = false;
  for (const node of descendants(fn)) {
    if (node.type === 'VariableDeclarator') {
      if (identifierName(node['id']) !== root) continue;
      declaredHere = true;
      if (isFreshObject(node['init'])) return true;
      continue;
    }
    // `var newProps = props; if (...) { newProps = {}; ... }` — React's prop-copy shape.
    // The declaration says nothing; the reassignment is what makes the destination fresh.
    if (node.type === 'AssignmentExpression' && node['operator'] === '=') {
      const left = node['left'];
      if (!isNode(left) || identifierName(left) !== root) continue;
      if (isFreshObject(node['right'])) return declaredHere || true;
    }
  }
  return false;
}

function detectMergeLoops(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];
  const seen = new Set<Node>();

  for (const fn of parsed.nodes) {
    if (
      fn.type !== 'FunctionDeclaration' &&
      fn.type !== 'FunctionExpression' &&
      fn.type !== 'ArrowFunctionExpression'
    ) {
      continue;
    }
    const ownName = functionName(parsed, fn);
    for (const loop of keyLoops(fn)) {
      // Attribute each loop to the function that owns it, so a callback body is not
      // analysed twice.
      if (enclosingFunction(parsed, loop.node) !== fn && loop.node.type !== 'CallExpression') continue;
      if (isAuthorControlled(loop.source) || resolvesToLiteralObject(context, loop.source)) continue;

      // No write, no sink. An earlier version reported a recursive call with no
      // assignment, which found read-only tree walks and nothing else.
      const writes = keyedWrites(loop.body, loop.keyName);
      const target = writes[0];
      if (!target) continue;
      const recursive = looksRecursive(loop.body, loop.keyName, ownName);
      if (target.destinationRoot !== undefined && context.mapBindings.has(target.destinationRoot)) continue;
      if (seen.has(target.node)) continue;
      seen.add(target.node);

      // A shallow copy into an object this function just created can only replace that
      // object's own prototype, which nothing else reads. A recursive merge is different:
      // it walks into the destination's inherited "constructor", so a fresh {} is no
      // protection and the restriction below is deliberately not applied to it.
      if (!recursive && isFreshLocal(context, fn, target.destinationRoot)) continue;

      // `for (const i in value) value[i] = f(value[i])` transforms a structure in place.
      // It is not a merge from one object into another, and describing it as one was
      // simply wrong.
      const sourceRoot = baseIdentifier(loop.source);
      if (sourceRoot !== undefined && sourceRoot === target.destinationRoot) continue;

      const sourceText = nodeText(parsed, loop.source, 40);
      const destinationText = nodeText(parsed, target.destination, 40);
      if (recursive) {
        out.push(
          ...emitSink(context, {
            ruleId: 'PP-S01',
            deep: true,
            node: target.node,
            keyNames: [loop.keyName],
            message:
              `Recursive merge writes every key of ${sourceText} onto ${destinationText} with no key ` +
              'check. A source key of "__proto__" makes the write land on Object.prototype.',
            related: [
              { node: loop.node, label: 'keys are taken from the source object here' },
              ...(ownName ? [{ node: fn, label: `merge function ${ownName}` }] : []),
            ],
          }),
        );
      } else {
        out.push(
          ...emitSink(context, {
            ruleId: 'PP-S03',
            node: target.node,
            keyNames: [loop.keyName],
            message:
              `Key-copy loop assigns ${destinationText}[${loop.keyName}] from ${sourceText} with no key ` +
              'check. The key "__proto__" replaces the destination object\'s prototype.',
            related: [{ node: loop.node, label: 'keys are taken from the source object here' }],
          }),
        );
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S02: path setters
// ---------------------------------------------------------------------------

// '[' is deliberately absent: bracket syntax is PP-S06's territory, and listing it here
// would make every nested query parser report twice.
const PATH_SEPARATORS = new Set(['.', '/', '->', '::', ':']);

/** A string being cut into segments, and the name those segments were bound to. */
interface SegmentSource {
  call: Node;
  /** Binding the segments ended up in, when there is one. */
  name: string | undefined;
}

/**
 * Calls that cut a string into segments on the given separators.
 *
 * `split` is the usual one; `match` and `matchAll` with a capture group do the same job
 * for a bracketed key syntax.
 */
function segmentSources(
  parsed: ParsedFile,
  fn: Node,
  accepts: (argument: Node) => boolean,
): SegmentSource[] {
  const out: SegmentSource[] = [];
  for (const node of descendants(fn)) {
    if (node.type !== 'CallExpression') continue;
    const callee = node['callee'];
    if (!isNode(callee)) continue;
    const method = staticPropertyName(callee);
    if (method !== 'split' && method !== 'match' && method !== 'matchAll') continue;
    const args = node['arguments'];
    const first = Array.isArray(args) ? args[0] : undefined;
    if (!isNode(first) || !accepts(first)) continue;
    // The binding the segments land in, looking through `?? []`, `.filter(...)` and the
    // rest of the usual tidying.
    let name: string | undefined;
    for (const ancestor of ancestors(parsed, node).slice(0, 5)) {
      if (ancestor.type === 'VariableDeclarator') {
        name = identifierName(ancestor['id']);
        break;
      }
      if (ancestor.type === 'ForOfStatement' || ancestor.type === 'ForInStatement') break;
    }
    out.push({ call: node, name });
  }
  return out;
}

/** Names bound to one segment at a time by a loop over `source`. */
function segmentVariables(fn: Node, source: SegmentSource): Set<string> {
  const names = new Set<string>();
  // `segment = unescapeJsonPointer(segment)` keeps the name a segment, so names are
  // carried through one round of reassignment from themselves.
  const carryThrough = (): void => {
    for (const node of descendants(fn)) {
      if (node.type !== 'AssignmentExpression') continue;
      const name = isNode(node['left']) ? identifierName(node['left']) : undefined;
      if (name === undefined || names.has(name)) continue;
      const value = node['right'];
      if (!isNode(value)) continue;
      if (descendants(value).some((inner) => identifierName(inner) !== undefined && names.has(identifierName(inner) as string))) {
        names.add(name);
      }
    }
  };
  const iteratesSource = (expression: unknown): boolean => {
    if (!isNode(expression)) return false;
    if (source.name !== undefined && baseIdentifier(expression) === source.name) return true;
    return descendants(expression).includes(source.call);
  };

  for (const node of descendants(fn)) {
    if (node.type === 'ForOfStatement') {
      if (!iteratesSource(node['right'])) continue;
      for (const name of declaredNames(node['left'])) if (name) names.add(name);
      continue;
    }
    // A classic index loop: `for (let i = 1; i < segments.length; i++) { let segment =
    // segments[i]; ... }`. The index is irrelevant; what matters is that `segment` was
    // read out of the segments array.
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const bound = node.type === 'VariableDeclarator' ? node['id'] : node['left'];
      const value = node.type === 'VariableDeclarator' ? node['init'] : node['right'];
      const name = isNode(bound) ? identifierName(bound) : undefined;
      if (name === undefined || !isNode(value)) continue;
      if (source.name === undefined || baseIdentifier(value) !== source.name) continue;
      if (value.type !== 'MemberExpression' && value.type !== 'CallExpression') continue;
      names.add(name);
      continue;
    }
    if (node.type === 'CallExpression') {
      const callee = node['callee'];
      if (!isNode(callee)) continue;
      const method = staticPropertyName(callee);
      if (method !== 'forEach' && method !== 'map' && method !== 'reduce') continue;
      if (!iteratesSource(callee['object'])) continue;
      const args = node['arguments'];
      if (!Array.isArray(args)) continue;
      const callback = args[0];
      if (!isNode(callback)) continue;
      const params = callback['params'];
      if (!Array.isArray(params)) continue;
      const first = params[method === 'reduce' ? 1 : 0];
      if (isNode(first)) for (const name of patternNames(first)) if (name) names.add(name);
    }
  }
  carryThrough();
  return names;
}

/**
 * Writes whose key is one of the path segments.
 *
 * Linking the write to the split is the whole rule. An earlier version accepted any
 * computed write in a function that happened to call `.split('.')` somewhere, which
 * reported fourteen sites on one dependency tree and was right about at most one of
 * them: a cache keyed by a cache key, an alias map keyed by an alias, a header map keyed
 * by a header name. None of those keys came from the path.
 */
function segmentWrites(fn: Node, source: SegmentSource, variables: Set<string>): Node[] {
  const out: Node[] = [];
  for (const node of descendants(fn)) {
    if (node.type !== 'AssignmentExpression') continue;
    const left = node['left'];
    if (!isNode(left) || left.type !== 'MemberExpression' || left['computed'] !== true) continue;
    const property = left['property'];
    if (!isNode(property) || isLiteralish(property)) continue;

    const keyName = identifierName(property);
    const keyIsSegmentVariable = keyName !== undefined && variables.has(keyName);
    // `cursor[parts[parts.length - 1]] = value`, `cursor[parts[i]] = value`,
    // `cursor[parts.at(-1)] = value`.
    const keyIsSegmentIndex = source.name !== undefined && baseIdentifier(property) === source.name;
    if (!keyIsSegmentVariable && !keyIsSegmentIndex) continue;

    // Writing back into the segments array itself is not a nested write.
    const destination = left['object'];
    if (isNode(destination) && source.name !== undefined && rootIdentifier(destination) === source.name) {
      continue;
    }
    out.push(node);
  }
  return out;
}

interface PathSetter {
  write: Node;
  source: SegmentSource;
  keyNames: string[];
}

function findPathSetters(
  parsed: ParsedFile,
  fn: Node,
  accepts: (argument: Node) => boolean,
): PathSetter | undefined {
  for (const source of segmentSources(parsed, fn, accepts)) {
    const variables = segmentVariables(fn, source);
    const write = segmentWrites(fn, source, variables)[0];
    if (!write) continue;
    // Only report the innermost function that owns the write, so a wrapper is not
    // reported alongside the helper it calls.
    if (enclosingFunction(parsed, write) !== fn) continue;
    return { write, source, keyNames: [...variables, ...(source.name ? [source.name] : [])] };
  }
  return undefined;
}

function acceptsPathSeparator(argument: Node): boolean {
  const literal = literalStringValue(argument);
  if (literal !== undefined) return PATH_SEPARATORS.has(literal);
  if (argument.type === 'Literal' && argument['regex'] !== undefined) {
    const pattern = (argument['regex'] as { pattern?: unknown }).pattern;
    return typeof pattern === 'string' && /[./]|\\\\\./.test(pattern);
  }
  return false;
}

function detectPathSetters(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];
  for (const fn of parsed.nodes) {
    if (
      fn.type !== 'FunctionDeclaration' &&
      fn.type !== 'FunctionExpression' &&
      fn.type !== 'ArrowFunctionExpression'
    ) {
      continue;
    }
    const found = findPathSetters(parsed, fn, acceptsPathSeparator);
    if (!found) continue;
    out.push(
      ...emitSink(context, {
        ruleId: 'PP-S02',
        deep: true,
        node: found.write,
        keyNames: found.keyNames,
        message:
          `Path setter writes ${nodeText(parsed, found.write, 60)} under a segment of a split string ` +
          'with no key check. A path of "__proto__.x" or "constructor.prototype.x" reaches ' +
          'Object.prototype.',
        related: [{ node: found.source.call, label: 'the path string is split into segments here' }],
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S04: assign or spread into a shared object
// ---------------------------------------------------------------------------

const GLOBAL_OBJECT = /^(globalThis|global|window|self|module|exports)$/;

/**
 * Is the target an object that outlives the call?
 *
 * Only three things qualify: a prototype, a global, and a module-level binding. An
 * earlier version also accepted any identifier whose *name* suggested shared state
 * (`options`, `config`, `defaults`, …). That matched `options = { ...defaults, ...options }`
 * — a parameter being normalised, which is not shared at all — and `this.options = {...}`
 * in every constructor it saw.
 */
function isSharedTarget(context: Context, target: Node): string | undefined {
  const path = memberPath(target);
  if (path) {
    const joined = path.join('.');
    if (path[path.length - 1] === 'prototype') return `the prototype ${joined}`;
    const root = path[0] ?? '';
    if (GLOBAL_OBJECT.test(root)) return `the global object ${joined}`;
  }
  const name = identifierName(target);
  if (name === undefined) return undefined;
  if (GLOBAL_OBJECT.test(name)) return `the global object ${name}`;
  if (context.moduleBindings.has(name)) return `the module-level object ${name}`;
  return undefined;
}

function detectSharedAssign(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];
  for (const node of parsed.nodes) {
    if (node.type === 'CallExpression') {
      const path = calleePath(node);
      if (path?.join('.') !== 'Object.assign') continue;
      const args = node['arguments'];
      if (!Array.isArray(args)) continue;
      const target = args[0];
      if (!isNode(target)) continue;
      const description = isSharedTarget(context, target);
      if (!description) continue;
      const sources = args.slice(1).filter((arg): arg is Node => isNode(arg) && !isAuthorControlled(arg));
      const source = sources[0];
      if (!source) continue;
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S04',
          node,
          message:
            `Object.assign copies the unvalidated ${nodeText(parsed, source, 40)} into ${description}. ` +
            'Every later read of that object sees whatever keys the source carried, and the target\'s ' +
            'own prototype is reachable through a "__proto__" key.',
          related: [{ node: source, label: 'unvalidated source' }],
        }),
      );
      continue;
    }

    if (node.type === 'AssignmentExpression' && node['operator'] === '=') {
      const left = node['left'];
      const right = node['right'];
      if (!isNode(left) || !isNode(right) || right.type !== 'ObjectExpression') continue;
      const description = isSharedTarget(context, left);
      if (!description) continue;
      const properties = right['properties'];
      if (!Array.isArray(properties)) continue;
      const spread = properties.find(
        (property) =>
          isNode(property) &&
          property.type === 'SpreadElement' &&
          !isAuthorControlled(property['argument']),
      );
      if (!isNode(spread)) continue;
      const argument = spread['argument'];
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S04',
          node,
          message:
            `A spread writes the unvalidated ${isNode(argument) ? nodeText(parsed, argument, 40) : 'source'} ` +
            `into ${description}.`,
          related: isNode(argument) ? [{ node: argument, label: 'unvalidated source' }] : [],
        }),
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S05: lodash-shaped helpers
// ---------------------------------------------------------------------------

/** Helpers that walk into nested keys of their source arguments. */
const DEEP_MERGE_HELPERS = new Set([
  'merge',
  'mergeWith',
  'defaultsDeep',
  'defaultsDeepAll',
  'assignIn',
  'assignInWith',
  'extend',
  'extendWith',
]);

/** Helpers whose first or second argument is a key path. */
const PATH_HELPERS: ReadonlyMap<string, number> = new Map([
  ['set', 1],
  ['setWith', 1],
  ['update', 1],
  ['updateWith', 1],
  ['zipObjectDeep', 0],
]);

function lodashMethod(context: Context, call: Node): string | undefined {
  const path = calleePath(call);
  if (!path) return undefined;
  if (path.length === 1) {
    const local = path[0];
    return local === undefined ? undefined : context.lodashMembers.get(local);
  }
  if (path.length === 2) {
    const [namespace, method] = path;
    if (namespace === undefined || method === undefined) return undefined;
    // `_` is only lodash when something imported it as lodash. In minified code `_` is
    // one of the most common local names there is.
    if (context.lodashNamespaces.has(namespace)) return method;
  }
  return undefined;
}

function detectLodashHelpers(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];
  for (const node of parsed.nodes) {
    if (node.type !== 'CallExpression') continue;
    const method = lodashMethod(context, node);
    if (method === undefined) continue;
    const args = node['arguments'];
    if (!Array.isArray(args)) continue;

    if (DEEP_MERGE_HELPERS.has(method)) {
      const source = args.slice(1).find((arg): arg is Node => isNode(arg) && !isAuthorControlled(arg));
      if (!source) continue;
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S05',
          node,
          deep: true,
          message:
            `${method} deep-merges the unvalidated ${nodeText(parsed, source, 40)} into its target. ` +
            'A "__proto__" key anywhere in that value is written through to Object.prototype.',
          related: [{ node: source, label: 'unvalidated merge source' }],
        }),
      );
      continue;
    }

    const pathIndex = PATH_HELPERS.get(method);
    if (pathIndex === undefined) continue;
    const pathArgument = args[pathIndex];
    if (!isNode(pathArgument) || isLiteralish(pathArgument)) continue;
    out.push(
      ...emitSink(context, {
        ruleId: 'PP-S05',
        node,
        deep: true,
        message:
          `${method} writes to the non-literal key path ${nodeText(parsed, pathArgument, 40)}. ` +
          'A path of "__proto__.x" or "constructor.prototype.x" reaches Object.prototype.',
        related: [{ node: pathArgument, label: 'caller-supplied key path' }],
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S06: nested keys from flat input
// ---------------------------------------------------------------------------

/**
 * Does this argument describe bracketed key syntax?
 *
 * A literal `'['`, or a regular expression with *escaped* brackets. An unescaped `[`
 * opens a character class, so accepting one matched patterns such as `/[^\w]/`; and a
 * bare `'['` literal anywhere in the function used to count too, which turned every
 * function that built a string containing a bracket into a query parser. Eight reports
 * on a real dependency tree, all wrong.
 */
function acceptsBracketSyntax(argument: Node): boolean {
  if (literalStringValue(argument) === '[') return true;
  if (argument.type === 'Literal' && argument['regex'] !== undefined) {
    const pattern = (argument['regex'] as { pattern?: unknown }).pattern;
    return typeof pattern === 'string' && pattern.includes('\\[') && pattern.includes('\\]');
  }
  return false;
}

function detectNestedQueryParse(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];

  // Explicit opt-in: qs allows prototype keys only when asked to.
  for (const node of parsed.nodes) {
    if (node.type !== 'ObjectExpression') continue;
    const properties = node['properties'];
    if (!Array.isArray(properties)) continue;
    for (const property of properties) {
      if (!isNode(property) || property.type !== 'Property') continue;
      const key = identifierName(property['key']) ?? literalStringValue(property['key']);
      if (key !== 'allowPrototypes' && key !== 'plainObjects') continue;
      const value = property['value'];
      const enabled = isNode(value) && value.type === 'Literal' && value['value'] === true;
      if (key === 'allowPrototypes' && enabled) {
        out.push(
          ...emitSink(context, {
            ruleId: 'PP-S06',
            deep: true,
            node: property,
            message:
              'allowPrototypes: true tells the query-string parser to keep keys such as ' +
              '"__proto__" instead of dropping them, which is the parser\'s only defence.',
          }),
        );
      }
    }
  }

  for (const fn of parsed.nodes) {
    if (
      fn.type !== 'FunctionDeclaration' &&
      fn.type !== 'FunctionExpression' &&
      fn.type !== 'ArrowFunctionExpression'
    ) {
      continue;
    }
    const found = findPathSetters(parsed, fn, acceptsBracketSyntax);
    if (!found) continue;
    out.push(
      ...emitSink(context, {
        ruleId: 'PP-S06',
        deep: true,
        node: found.write,
        keyNames: found.keyNames,
        message:
          'Bracketed key segments from flat input are expanded into nested objects here with no key ' +
          'check, so "a[__proto__][x]=1" in a single flat string reaches Object.prototype.',
        related: [{ node: found.source.call, label: 'bracket syntax is parsed here' }],
      }),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S07: computed property definition
// ---------------------------------------------------------------------------

const DEFINE_CALLS: ReadonlyMap<string, number> = new Map([
  ['Object.defineProperty', 1],
  ['Reflect.defineProperty', 1],
  ['Reflect.set', 1],
]);

/**
 * Module-interop and decorator helpers emitted by TypeScript, Babel and SWC. Every one
 * of them calls `Object.defineProperty` with a computed key, and in every one of them
 * the key comes from the module's own export list rather than from input. They accounted
 * for essentially all of this rule's output on a real dependency tree, so they are
 * excluded by name.
 */
const INTEROP_HELPERS = new Set([
  '__createBinding',
  '__exportStar',
  '__esDecorate',
  '__decorate',
  '__setFunctionName',
  '__copyProps',
  '__reExport',
  '__toCommonJS',
  '__toESM',
  '_defineProperty',
  '_defineProperties',
  '_createClass',
  '_objectSpread',
  '_objectSpread2',
  '_classPrivateFieldInitSpec',
  'defineProperties',
  'copyProps',
  'bindExports',
]);

/** Is the computed key a well-known symbol? Nothing can forge `Symbol.toStringTag`. */
function isSymbolKey(key: Node): boolean {
  const path = memberPath(key);
  return path?.[0] === 'Symbol';
}

function inInteropHelper(parsed: ParsedFile, node: Node): boolean {
  let fn = enclosingFunction(parsed, node);
  while (fn) {
    const name = functionName(parsed, fn);
    if (name !== undefined && INTEROP_HELPERS.has(name)) return true;
    fn = enclosingFunction(parsed, fn);
  }
  return false;
}

function detectComputedDefine(context: Context): Finding[] {
  const { parsed } = context;
  const out: Finding[] = [];
  for (const node of parsed.nodes) {
    if (node.type === 'CallExpression') {
      const path = calleePath(node);
      const index = path ? DEFINE_CALLS.get(path.join('.')) : undefined;
      if (index === undefined) continue;
      const args = node['arguments'];
      const key = Array.isArray(args) ? args[index] : undefined;
      if (!isNode(key) || isLiteralish(key)) continue;
      if (isSymbolKey(key)) continue;
      if (inInteropHelper(parsed, node)) continue;
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S07',
          node,
          message:
            `${path?.join('.')} defines the computed key ${nodeText(parsed, key, 40)}. defineProperty ` +
            'ignores setters and writability, so a key of "__proto__" or "constructor" is written ' +
            'even where plain assignment would not be.',
          related: [{ node: key, label: 'computed key' }],
        }),
      );
      continue;
    }
    if (node.type === 'PropertyDefinition' && node['computed'] === true) {
      const key = node['key'];
      if (!isNode(key) || isLiteralish(key)) continue;
      if (isSymbolKey(key)) continue;
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S07',
          node,
          message: `Class field uses the computed key ${nodeText(parsed, key, 40)} with no key check.`,
          related: [{ node: key, label: 'computed key' }],
        }),
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// PP-S08: parsed input flowing into a sink
// ---------------------------------------------------------------------------

function detectJsonFlow(context: Context, sinkFunctions: Map<string, Node>): Finding[] {
  const { parsed } = context;
  const jsonSources = context.ownProtoSources.filter((source) => source.label === 'JSON.parse');
  if (jsonSources.length === 0) return [];
  const bindings = findParsedBindings(parsed, jsonSources);
  const out: Finding[] = [];
  const reported = new Set<Node>();

  const sinkTargets = (call: Node): string | undefined => {
    const path = calleePath(call);
    if (!path) return undefined;
    const last = path[path.length - 1];
    if (last === undefined) return undefined;
    if (path.length === 1 && sinkFunctions.has(last)) return last;
    const lodash = lodashMethod(context, call);
    if (lodash !== undefined && (DEEP_MERGE_HELPERS.has(lodash) || PATH_HELPERS.has(lodash))) return lodash;
    if (path.join('.') === 'Object.assign') return 'Object.assign';
    return undefined;
  };

  for (const node of parsed.nodes) {
    if (node.type !== 'CallExpression') continue;
    const target = sinkTargets(node);
    if (target === undefined) continue;
    const args = node['arguments'];
    if (!Array.isArray(args)) continue;
    for (const arg of args) {
      if (!isNode(arg)) continue;
      const unwrapped = unwrapAwait(arg);
      const direct = jsonSources.find((source) => source.node === unwrapped);
      const name = identifierName(unwrapped) ?? rootIdentifier(unwrapped);
      const bound = name === undefined ? undefined : bindings.get(name);
      const source = direct ?? bound;
      if (!source || reported.has(node)) continue;
      reported.add(node);
      out.push(
        ...emitSink(context, {
          ruleId: 'PP-S08',
          node,
          deep: true,
          message:
            `JSON.parse output reaches ${target}. JSON.parse is what turns the text "__proto__" into ` +
            'an own property of a real object, so this is the end-to-end write primitive rather than ' +
            'a theoretical one.',
          related: [
            { node: source.node, label: 'JSON.parse with no reviver' },
            ...(sinkFunctions.get(target) ? [{ node: sinkFunctions.get(target) as Node, label: `sink ${target}` }] : []),
          ],
        }),
      );
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

export function scanSinks(parsed: ParsedFile): SinkScan {
  const context = buildContext(parsed);
  const findings: Finding[] = [
    ...detectMergeLoops(context),
    ...detectPathSetters(context),
    ...detectSharedAssign(context),
    ...detectLodashHelpers(context),
    ...detectNestedQueryParse(context),
    ...detectComputedDefine(context),
  ];

  const sinkFunctions = new Map<string, Node>();
  for (const finding of findings) {
    if (finding.kind !== 'sink') continue;
    const node = parsed.nodes.find(
      (candidate) =>
        candidate.start === finding.loc.start.offset && candidate.end === finding.loc.end.offset,
    );
    if (!node) continue;
    let fn = enclosingFunction(parsed, node);
    while (fn) {
      const name = functionName(parsed, fn);
      if (name) sinkFunctions.set(name, fn);
      fn = enclosingFunction(parsed, fn);
    }
  }

  findings.push(...detectJsonFlow(context, sinkFunctions));
  return { findings, sinkFunctions, ownProtoSources: context.ownProtoSources };
}

export type { GuardNote };
