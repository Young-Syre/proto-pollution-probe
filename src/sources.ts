import {
  type Node,
  type ParsedFile,
  calleePath,
  isNode,
  memberPath,
  staticPropertyName,
} from './ast.js';
import { isProtoStrippingReviver } from './guards.js';

/**
 * Where an *own* `__proto__` property comes from.
 *
 * This distinction decides whether an own-property filter is a real guard. Writing
 * `{ __proto__: x }` in source sets the prototype, so `for..in` never sees the key and
 * `hasOwnProperty` is beside the point. But a parser that builds objects from text has
 * to create `__proto__` as an ordinary own property, because it has no other way to
 * represent the key — `JSON.parse('{"__proto__":{"polluted":1}}')` is the canonical
 * example. Once such a value is in the file, `hasOwnProperty` stops being a guard.
 */
export interface OwnProtoSource {
  node: Node;
  /** Short description for the finding message, e.g. `JSON.parse`. */
  label: string;
}

const PARSER_CALLS: ReadonlyArray<{ path: string; label: string }> = [
  { path: 'Object.fromEntries', label: 'Object.fromEntries' },
  { path: 'qs.parse', label: 'qs.parse' },
  { path: 'querystring.parse', label: 'querystring.parse' },
  { path: 'YAML.parse', label: 'YAML.parse' },
  { path: 'yaml.parse', label: 'yaml.parse' },
  { path: 'yaml.load', label: 'yaml.load' },
  { path: 'toml.parse', label: 'toml.parse' },
  { path: 'ini.parse', label: 'ini.parse' },
];

const PARSER_METHODS: ReadonlySet<string> = new Set(['parse', 'load', 'fromEntries', 'decode']);

/** Member reads that carry request data in every mainstream Node web framework. */
const REQUEST_PROPERTIES: ReadonlySet<string> = new Set(['body', 'query', 'params', 'headers', 'cookies']);
const REQUEST_ROOTS = /^(req|request|ctx|context|event|httpRequest|r)$/;

export function findOwnProtoSources(parsed: ParsedFile): OwnProtoSource[] {
  const out: OwnProtoSource[] = [];
  for (const node of parsed.nodes) {
    if (node.type === 'CallExpression') {
      const path = calleePath(node);
      const joined = path?.join('.');
      const args = node['arguments'];
      const argList = Array.isArray(args) ? args : [];

      if (joined === 'JSON.parse') {
        const reviver = argList[1];
        if (!isProtoStrippingReviver(reviver)) out.push({ node, label: 'JSON.parse' });
        continue;
      }
      if (joined !== undefined) {
        const known = PARSER_CALLS.find((candidate) => candidate.path === joined);
        if (known) {
          out.push({ node, label: known.label });
          continue;
        }
      }
      // `await res.json()` and `await request.json()`.
      const method = path?.[path.length - 1];
      if (method === 'json' && path !== undefined && path.length >= 2) {
        out.push({ node, label: `${joined ?? 'json'}()` });
        continue;
      }
      if (method !== undefined && PARSER_METHODS.has(method) && path !== undefined && path.length === 2) {
        const namespace = path[0] ?? '';
        if (/^(qs|querystring|yaml|YAML|toml|ini|dotenv|formidable|multer|xml2js|plist)$/.test(namespace)) {
          out.push({ node, label: `${joined ?? method}` });
        }
      }
      continue;
    }

    if (node.type === 'NewExpression') {
      const callee = node['callee'];
      if (isNode(callee) && callee['name'] === 'URLSearchParams') {
        out.push({ node, label: 'URLSearchParams' });
      }
      continue;
    }

    if (node.type === 'MemberExpression') {
      const property = staticPropertyName(node);
      if (property === undefined || !REQUEST_PROPERTIES.has(property)) continue;
      const path = memberPath(node);
      const root = path?.[0];
      if (root !== undefined && REQUEST_ROOTS.test(root)) {
        out.push({ node, label: path?.join('.') ?? property });
      }
    }
  }
  return out;
}

/** Bindings whose value came from a parser that can produce an own `__proto__` key. */
export function findParsedBindings(parsed: ParsedFile, sources: OwnProtoSource[]): Map<string, OwnProtoSource> {
  const bySourceNode = new Set(sources.map((source) => source.node));
  const out = new Map<string, OwnProtoSource>();
  for (const node of parsed.nodes) {
    let value: unknown;
    let name: string | undefined;
    if (node.type === 'VariableDeclarator') {
      value = node['init'];
      const id = node['id'];
      name = isNode(id) && id.type === 'Identifier' ? (id['name'] as string) : undefined;
    } else if (node.type === 'AssignmentExpression' && node['operator'] === '=') {
      value = node['right'];
      const left = node['left'];
      name = isNode(left) && left.type === 'Identifier' ? (left['name'] as string) : undefined;
    }
    if (name === undefined || !isNode(value)) continue;
    const unwrapped = unwrapAwait(value);
    const source = sources.find((candidate) => candidate.node === unwrapped);
    if (source && bySourceNode.has(source.node)) out.set(name, source);
  }
  return out;
}

export function unwrapAwait(node: Node): Node {
  let current = node;
  while (
    (current.type === 'AwaitExpression' || current.type === 'TSNonNullExpression') &&
    isNode(current['argument'])
  ) {
    current = current['argument'] as Node;
  }
  return current;
}

/**
 * Is this expression plausibly attacker-influenced? Used to keep rules that would
 * otherwise fire on every object copy in a codebase down to the ones worth reading.
 * An object literal written in the file is not; anything else is treated as unknown,
 * which counts as influenced — a static analyser cannot prove the negative.
 */
export function isAuthorControlled(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === 'ObjectExpression') {
    const properties = node['properties'];
    if (!Array.isArray(properties)) return true;
    return properties.every((property) => isNode(property) && property.type === 'Property');
  }
  return node.type === 'Literal' || node.type === 'ArrayExpression' || node.type === 'TemplateLiteral';
}
