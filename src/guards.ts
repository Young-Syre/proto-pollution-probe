import {
  type Node,
  type ParsedFile,
  calleePath,
  descendants,
  enclosingFunction,
  isNode,
  literalStringValue,
  locationOf,
  memberPath,
  staticPropertyName,
} from './ast.js';
import type { GuardNote } from './types.js';

/** The three key names that reach Object.prototype, in the order attackers try them. */
export const PROTO_KEYS = ['__proto__', 'constructor', 'prototype'] as const;
const PROTO_KEY_SET: ReadonlySet<string> = new Set<string>(PROTO_KEYS);

export interface GuardAnalysis {
  notes: GuardNote[];
  /** At least one recognised guard closes the hole on its own. */
  sufficient: boolean;
  /** Key names the scope compares against or rejects. */
  blockedKeys: Set<string>;
  /** The scope filters keys with hasOwnProperty or Object.hasOwn. */
  hasOwnFilter: boolean;
  /** The scope builds its destination with Object.create(null) or {__proto__: null}. */
  nullPrototype: boolean;
  /**
   * The scope creates intermediate objects as plain `{}`. This is what stops a
   * null-prototype root from being a complete guard: see `analyseGuards`.
   */
  plainVivification: boolean;
  /** Object.freeze(Object.prototype) somewhere in the program. */
  frozenPrototype: boolean;
}

export function emptyGuardAnalysis(): GuardAnalysis {
  return {
    notes: [],
    sufficient: false,
    blockedKeys: new Set(),
    hasOwnFilter: false,
    nullPrototype: false,
    plainVivification: false,
    frozenPrototype: false,
  };
}

/**
 * Does the scope create an intermediate object as a plain `{}`?
 *
 * This matters more than it looks. `Object.create(null)` on the destination is widely
 * recommended as the fix for prototype pollution, and for a shallow key copy it is one:
 * `dst['__proto__'] = v` on a prototype-less object is an ordinary own property with
 * nothing behind it. But a *deep* merge or a path setter creates the objects it writes
 * into, and if it creates them as `{}` then the second level down is an ordinary object
 * again. Its own `constructor` is inherited and truthy, so a key path of
 * `a.constructor.prototype.polluted` walks straight out of the null-prototype root,
 * through the real Object, and onto Object.prototype.
 *
 * So the null-prototype guard is treated as sufficient only when nothing in the scope
 * vivifies a plain object. When something does, the guard is recorded as partial and the
 * sink still stands.
 */
function hasPlainVivification(nodes: Node[]): boolean {
  for (const node of nodes) {
    if (node.type !== 'AssignmentExpression') continue;
    const left = node['left'];
    if (!isNode(left) || left.type !== 'MemberExpression' || left['computed'] !== true) continue;
    const right = node['right'];
    if (!isNode(right)) continue;
    if (right.type === 'ObjectExpression' || right.type === 'ArrayExpression') return true;
    if (right.type === 'LogicalExpression') {
      const fallback = right['right'];
      if (isNode(fallback) && (fallback.type === 'ObjectExpression' || fallback.type === 'ArrayExpression')) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Does the program freeze Object.prototype? That is a process-wide mitigation, so it
 * is looked up once per file rather than per sink.
 */
export function findPrototypeFreeze(parsed: ParsedFile): Node | undefined {
  for (const node of parsed.nodes) {
    if (node.type !== 'CallExpression') continue;
    const callee = calleePath(node);
    if (!callee) continue;
    const method = callee[callee.length - 1];
    if (method !== 'freeze' && method !== 'seal' && method !== 'preventExtensions') continue;
    const args = node['arguments'];
    if (!Array.isArray(args)) continue;
    const first = args[0];
    if (!isNode(first)) continue;
    const path = memberPath(first);
    if (!path) continue;
    const joined = path.join('.');
    if (joined === 'Object.prototype' || joined === 'Object.__proto__') return node;
  }
  return undefined;
}

/**
 * Where a sink's guards may live: the function containing it, and nothing wider.
 *
 * The enclosing function used to be searched too, on the theory that a wrapper might
 * validate before delegating. In a bundled file that enclosing function is the whole
 * module IIFE, so any `__proto__` check anywhere in the bundle was credited to every
 * loop in it — including, memorably, js-yaml's own mitigation being read as a guard on
 * three unrelated functions. The key the sink writes is bound inside the sink's own
 * function anyway, so a wider search bought nothing real.
 */
export function guardScope(parsed: ParsedFile, sinkNode: Node): Node[] {
  const own = enclosingFunction(parsed, sinkNode);
  return own ? [own] : [parsed.program];
}

function scopeNodes(scope: Node[]): Node[] {
  const seen = new Set<Node>();
  const out: Node[] = [];
  for (const root of scope) {
    for (const node of descendants(root)) {
      if (seen.has(node)) continue;
      seen.add(node);
      out.push(node);
    }
  }
  return out;
}

/** Methods that test a key against something rather than write it. */
const CHECK_METHODS = new Set([
  'has',
  'includes',
  'indexOf',
  'test',
  'match',
  'some',
  'every',
  'startsWith',
  'endsWith',
  'find',
  'filter',
]);

/**
 * Expressions in a scope that test a key against something.
 *
 * Finding the *check* and then resolving the names it mentions is the only way to
 * recognise the guard people actually write, which is a module-level constant:
 *
 *     const UNSAFE = new Set(['__proto__', 'constructor', 'prototype']);
 *     function merge(dst, src) { for (const k of Object.keys(src)) { if (UNSAFE.has(k)) continue; ... } }
 *
 * The literals are nowhere near the sink. A scope-local literal search sees no guard at
 * all and reports a correctly written merge, which is precisely the behaviour that gets
 * a static analyser uninstalled.
 */
function keyChecks(nodes: Node[]): Node[] {
  const out: Node[] = [];
  for (const node of nodes) {
    if (node.type === 'CallExpression') {
      const path = calleePath(node);
      const method = path?.[path.length - 1] ?? calleeTail(node)?.split('.').pop();
      if (method !== undefined && CHECK_METHODS.has(method)) out.push(node);
      continue;
    }
    if (node.type === 'BinaryExpression') {
      const operator = node['operator'];
      if (operator === '===' || operator === '!==' || operator === '==' || operator === '!=' || operator === 'in') {
        out.push(node);
      }
      continue;
    }
    if (node.type === 'SwitchCase') out.push(node);
  }
  return out;
}

/** Initialiser of each named binding in the file, for resolving a denylist constant. */
const bindingCache = new WeakMap<ParsedFile, Map<string, Node>>();

function bindingInits(parsed: ParsedFile): Map<string, Node> {
  const cached = bindingCache.get(parsed);
  if (cached) return cached;
  const map = new Map<string, Node>();
  for (const node of parsed.nodes) {
    if (node.type !== 'VariableDeclarator') continue;
    const id = node['id'];
    const init = node['init'];
    if (!isNode(id) || id.type !== 'Identifier' || !isNode(init)) continue;
    map.set(id['name'] as string, init);
  }
  bindingCache.set(parsed, map);
  return map;
}

/**
 * Key names a check rejects: literals written into the check itself, plus the literals
 * inside any binding it names. One level of indirection is followed, which covers every
 * denylist spelling seen in the wild (`Set`, array, regex, bare comparison) without
 * turning into a dataflow engine.
 */
function checkedKeys(parsed: ParsedFile, check: Node): { keys: Set<string>; evidence: Node | undefined } {
  const keys = new Set<string>();
  let evidence: Node | undefined;

  const harvest = (root: Node): void => {
    for (const node of descendants(root)) {
      const value = literalStringValue(node);
      if (value !== undefined) {
        if (PROTO_KEY_SET.has(value)) {
          keys.add(value);
          evidence ??= node;
        } else if (value === '__' || value === 'proto') {
          // `key.startsWith('__')` rejects __proto__ and nothing else.
          keys.add('__proto__');
          evidence ??= node;
        }
      }
      for (const key of regexBlockedKeys(node)) {
        keys.add(key);
        evidence ??= node;
      }
    }
  };

  harvest(check);
  const inits = bindingInits(parsed);
  for (const node of descendants(check)) {
    if (node.type !== 'Identifier') continue;
    const init = inits.get(node['name'] as string);
    if (init) harvest(init);
  }
  return { keys, evidence };
}

function regexBlockedKeys(node: Node): string[] {
  if (node.type !== 'Literal') return [];
  const regex = node['regex'] as { pattern?: unknown } | undefined;
  const pattern = typeof regex?.pattern === 'string' ? regex.pattern : undefined;
  if (!pattern) return [];
  const out: string[] = [];
  for (const key of PROTO_KEYS) {
    if (pattern.includes(key)) out.push(key);
  }
  return out;
}

/**
 * Collect the guards protecting a sink.
 *
 * Deliberately generous about *recognising* a guard and deliberately strict about
 * calling one sufficient. A tool that reports guarded code is a tool nobody runs
 * twice; a tool that calls a weak denylist "safe" is worse. Both outcomes are
 * avoided by reporting guard quality separately from the sink itself.
 */
export function analyseGuards(
  parsed: ParsedFile,
  sinkNode: Node,
  options: { freeze?: Node | undefined; keyNames?: readonly string[] } = {},
): GuardAnalysis {
  const analysis = emptyGuardAnalysis();
  const scope = guardScope(parsed, sinkNode);
  const nodes = scopeNodes(scope);
  analysis.plainVivification = hasPlainVivification(nodes);

  // When the sink's key has a name, a denylist only counts if it tests *that* key. In a
  // bundled file the guard scope can be thousands of lines, and without this a stray
  // `__proto__` literal anywhere in it was read as a guard on everything: it credited
  // js-yaml's own mitigation to three unrelated loops and reported eight of nine
  // guard-quality findings wrongly.
  const keyNames = new Set(options.keyNames ?? []);
  const testsSinkKey = (check: Node): boolean => {
    if (keyNames.size === 0) return true;
    return descendants(check).some((node) => {
      const name = node.type === 'Identifier' ? (node['name'] as string) : undefined;
      return name !== undefined && keyNames.has(name);
    });
  };

  let denylistLoc: Node | undefined;
  let hasOwnLoc: Node | undefined;
  let nullProtoLoc: Node | undefined;

  // Key denylists: find the check, then resolve the names it mentions.
  for (const check of keyChecks(nodes)) {
    if (!testsSinkKey(check)) continue;
    const { keys, evidence } = checkedKeys(parsed, check);
    for (const key of keys) analysis.blockedKeys.add(key);
    if (keys.size > 0) denylistLoc ??= evidence ?? check;
  }

  for (const node of nodes) {
    if (node.type === 'CallExpression') {
      const callee = calleePath(node);
      const joined = callee?.join('.');
      const method = callee?.[callee.length - 1];

      // Own-property filters.
      if (
        joined === 'Object.hasOwn' ||
        joined === 'Object.prototype.hasOwnProperty.call' ||
        joined === 'hasOwnProperty.call' ||
        method === 'hasOwn' ||
        method === 'hasOwnProperty'
      ) {
        analysis.hasOwnFilter = true;
        hasOwnLoc ??= node;
      }
      // `{}.hasOwnProperty.call(...)` has an ObjectExpression root, so memberPath fails.
      if (!callee) {
        const path = calleeTail(node);
        if (path === 'hasOwnProperty.call') {
          analysis.hasOwnFilter = true;
          hasOwnLoc ??= node;
        }
      }

      // Object.create(null) destinations.
      if (joined === 'Object.create') {
        const args = node['arguments'];
        const first = Array.isArray(args) ? args[0] : undefined;
        if (isNode(first) && first.type === 'Literal' && first['value'] === null) {
          analysis.nullPrototype = true;
          nullProtoLoc ??= node;
        }
      }

    }

    // `{ __proto__: null }` object literals.
    if (node.type === 'ObjectExpression') {
      const properties = node['properties'];
      if (Array.isArray(properties)) {
        for (const property of properties) {
          if (!isNode(property) || property.type !== 'Property') continue;
          const key = property['key'];
          const keyName = isNode(key)
            ? (key['name'] as string | undefined) ?? literalStringValue(key)
            : undefined;
          const value = property['value'];
          if (keyName === '__proto__' && isNode(value) && value.type === 'Literal' && value['value'] === null) {
            analysis.nullPrototype = true;
            nullProtoLoc ??= node;
          }
        }
      }
    }
  }

  if (options.freeze) {
    analysis.frozenPrototype = true;
    analysis.notes.push({
      kind: 'frozen-object-prototype',
      quality: 'sufficient',
      detail:
        'Object.prototype is frozen in this program, so a write through this sink throws in ' +
        'strict mode and is silently dropped otherwise.',
      loc: locationOf(parsed, options.freeze),
    });
  }

  if (analysis.nullPrototype) {
    analysis.notes.push({
      kind: 'null-prototype',
      quality: analysis.plainVivification ? 'partial' : 'sufficient',
      detail: analysis.plainVivification
        ? 'A prototype-less object is built here, but intermediate objects are created as plain ' +
          '{}, so only the first level is protected. A key path through an intermediate reaches ' +
          'its inherited "constructor" and from there Object.prototype.'
        : 'A prototype-less object is built in this scope and nothing vivifies a plain {}, so a ' +
          '"__proto__" key is an ordinary own property with nothing behind it.',
      loc: nullProtoLoc ? locationOf(parsed, nullProtoLoc) : undefined,
    });
  }

  if (analysis.blockedKeys.size > 0) {
    const blocksProto = analysis.blockedKeys.has('__proto__');
    const blocksConstructor =
      analysis.blockedKeys.has('constructor') || analysis.blockedKeys.has('prototype');
    const quality = blocksProto && blocksConstructor ? 'sufficient' : 'weak';
    analysis.notes.push({
      kind: 'key-denylist',
      quality,
      detail:
        quality === 'sufficient'
          ? `Keys ${[...analysis.blockedKeys].sort().join(', ')} are rejected, which closes both the ` +
            'direct __proto__ route and the constructor.prototype route.'
          : `Only ${[...analysis.blockedKeys].sort().join(', ')} is rejected; a merge still recurses ` +
            'through the own "constructor" property into "prototype".',
      loc: denylistLoc ? locationOf(parsed, denylistLoc) : undefined,
    });
  }

  if (analysis.hasOwnFilter) {
    analysis.notes.push({
      kind: 'has-own-property',
      quality: 'partial',
      detail:
        'Keys are filtered with an own-property check. That excludes anything inherited ' +
        'through the prototype chain, but JSON.parse creates "__proto__" as an own property, ' +
        'so JSON input passes the filter unchanged.',
      loc: hasOwnLoc ? locationOf(parsed, hasOwnLoc) : undefined,
    });
  }

  analysis.sufficient =
    analysis.frozenPrototype ||
    (analysis.nullPrototype && !analysis.plainVivification) ||
    analysis.notes.some((note) => note.kind === 'key-denylist' && note.quality === 'sufficient');

  return analysis;
}

/** Tail of a callee path whose root is not an identifier, e.g. `{}.hasOwnProperty.call`. */
function calleeTail(call: Node): string | undefined {
  const callee = call['callee'];
  if (!isNode(callee)) return undefined;
  const parts: string[] = [];
  let current: Node = callee;
  while (current.type === 'MemberExpression' || current.type === 'OptionalMemberExpression') {
    const name = staticPropertyName(current);
    if (name === undefined) return undefined;
    parts.unshift(name);
    const object = current['object'];
    if (!isNode(object)) return undefined;
    current = object;
  }
  return parts.length > 0 ? parts.join('.') : undefined;
}

/**
 * A JSON.parse reviver that removes prototype keys. Recognised so that
 * `JSON.parse(body, stripProto)` is not reported as a source.
 */
export function isProtoStrippingReviver(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type !== 'FunctionExpression' && node.type !== 'ArrowFunctionExpression') {
    // A named reviver passed by reference cannot be judged without resolving it; the
    // caller treats that as unguarded, which errs towards reporting.
    return false;
  }
  for (const descendant of descendants(node)) {
    const value = literalStringValue(descendant);
    if (value !== undefined && PROTO_KEY_SET.has(value)) return true;
    if (regexBlockedKeys(descendant).length > 0) return true;
  }
  return false;
}
