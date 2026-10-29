import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import type { Position, SourceLocation } from './types.js';

/**
 * A loose node view. acorn's own types are deliberately narrow per-node, and the
 * analyser is structural rather than exhaustive, so an index signature is more
 * honest here than a cast at every access site.
 */
export interface Node {
  type: string;
  start: number;
  end: number;
  loc?: { start: { line: number; column: number }; end: { line: number; column: number } };
  [key: string]: unknown;
}

const NON_CHILD_KEYS = new Set(['type', 'start', 'end', 'loc', 'range', 'parent', 'raw', 'regex']);

/**
 * Children of a node, discovered structurally.
 *
 * Only used as a fallback. `acorn-walk` knows the real visitor keys and is the primary
 * traversal, but it throws on a node type its base visitor has never heard of, which is
 * what happens when acorn gains syntax before acorn-walk does. Rather than fail the file,
 * the walk falls back to this: any own property that looks like a node is a child. It
 * over-approximates (it would follow a `parent` back-reference if one existed, hence the
 * exclusion list) but it cannot go stale.
 */
export function childNodes(node: Node): Node[] {
  const out: Node[] = [];
  for (const key of Object.keys(node)) {
    if (NON_CHILD_KEYS.has(key)) continue;
    const value = (node as Record<string, unknown>)[key];
    if (isNode(value)) out.push(value);
    else if (Array.isArray(value)) {
      for (const item of value) if (isNode(item)) out.push(item);
    }
  }
  return out;
}

export function isNode(value: unknown): value is Node {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string' &&
    typeof (value as { start?: unknown }).start === 'number'
  );
}

export interface ParsedFile {
  /** Path as supplied by the caller. */
  file: string;
  /** Original source text, before any type erasure. Positions index into this. */
  source: string;
  lineStarts: number[];
  program: Node;
  parents: Map<Node, Node | undefined>;
  /** Every node, in document order. */
  nodes: Node[];
}

export class ParseFailure extends Error {}

const ACORN_OPTIONS: acorn.Options = {
  ecmaVersion: 2024,
  locations: true,
  allowHashBang: true,
  allowAwaitOutsideFunction: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
  preserveParens: false,
};

/**
 * Parse as an ES module, falling back to a script. The fallback matters: plenty of
 * real-world CommonJS uses `with`, HTML comments or a bare `return`, all of which a
 * module parse rejects.
 */
export function parseProgram(code: string): Node {
  let moduleError: unknown;
  try {
    return acorn.parse(code, { ...ACORN_OPTIONS, sourceType: 'module' }) as unknown as Node;
  } catch (err) {
    moduleError = err;
  }
  try {
    return acorn.parse(code, { ...ACORN_OPTIONS, sourceType: 'script' }) as unknown as Node;
  } catch {
    const message = moduleError instanceof Error ? moduleError.message : String(moduleError);
    throw new ParseFailure(message);
  }
}

/** Offsets of the first character of every line, for position lookups. */
export function computeLineStarts(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i += 1) {
    if (source.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

export function buildParsedFile(file: string, source: string, analysed: string): ParsedFile {
  const program = parseProgram(analysed);
  const parents = new Map<Node, Node | undefined>();
  const nodes: Node[] = [];

  const record = (node: Node, parent: Node | undefined): void => {
    if (parents.has(node)) return;
    parents.set(node, parent);
    nodes.push(node);
  };

  let walked = false;
  try {
    walk.fullAncestor(program as unknown as acorn.Node, (node, _state, chain) => {
      const current = node as unknown as Node;
      const parent = chain[chain.length - 2] as unknown as Node | undefined;
      record(current, parent);
    });
    walked = true;
  } catch {
    // acorn-walk has no visitor for something in this file; fall through.
  }
  if (!walked) {
    const stack: Array<{ node: Node; parent: Node | undefined }> = [{ node: program, parent: undefined }];
    while (stack.length > 0) {
      const entry = stack.pop();
      if (!entry) break;
      record(entry.node, entry.parent);
      for (const child of childNodes(entry.node)) stack.push({ node: child, parent: entry.node });
    }
  }
  if (!parents.has(program)) record(program, undefined);

  nodes.sort((a, b) => a.start - b.start || b.end - a.end);
  return { file, source, lineStarts: computeLineStarts(source), program, parents, nodes };
}

export function offsetToPosition(lineStarts: number[], offset: number): Position {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    const start = lineStarts[mid];
    if (start !== undefined && start <= offset) lo = mid;
    else hi = mid - 1;
  }
  const lineStart = lineStarts[lo] ?? 0;
  return { line: lo + 1, column: offset - lineStart + 1, offset };
}

export function locationOf(parsed: ParsedFile, node: Node): SourceLocation {
  const start = offsetToPosition(parsed.lineStarts, node.start);
  const end = offsetToPosition(parsed.lineStarts, node.end);
  return { file: parsed.file, start, end, excerpt: lineText(parsed, start.line) };
}

export function lineText(parsed: ParsedFile, line: number): string {
  const from = parsed.lineStarts[line - 1];
  if (from === undefined) return '';
  const to = parsed.lineStarts[line] ?? parsed.source.length;
  return parsed.source.slice(from, to).replace(/\r?\n$/, '').replace(/\s+$/, '');
}

/** Source text of a node, truncated so a finding message cannot run away. */
export function nodeText(parsed: ParsedFile, node: Node, limit = 120): string {
  const raw = parsed.source.slice(node.start, node.end).replace(/\s+/g, ' ').trim();
  return raw.length > limit ? `${raw.slice(0, limit - 1)}…` : raw;
}

// ---------------------------------------------------------------------------
// Structural helpers
// ---------------------------------------------------------------------------

export function isIdentifier(node: unknown, name?: string): node is Node {
  if (!isNode(node) || node.type !== 'Identifier') return false;
  return name === undefined || node['name'] === name;
}

export function identifierName(node: unknown): string | undefined {
  if (isNode(node) && node.type === 'Identifier') return node['name'] as string;
  return undefined;
}

/** Static property name of a member expression, or undefined when computed and non-literal. */
export function staticPropertyName(node: Node): string | undefined {
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined;
  const property = node['property'];
  if (!isNode(property)) return undefined;
  if (node['computed'] === true) {
    if (property.type === 'Literal' && typeof property['value'] === 'string') {
      return property['value'];
    }
    return undefined;
  }
  if (property.type === 'Identifier') return property['name'] as string;
  if (property.type === 'PrivateIdentifier') return `#${String(property['name'])}`;
  return undefined;
}

/**
 * Dotted path of a member expression rooted at an identifier, e.g. `Object.assign`
 * becomes ['Object', 'assign']. Returns undefined when the chain is dynamic.
 */
export function memberPath(node: Node): string[] | undefined {
  const parts: string[] = [];
  let current: Node = node;
  for (;;) {
    if (current.type === 'Identifier') {
      parts.unshift(current['name'] as string);
      return parts;
    }
    if (current.type === 'ThisExpression') {
      parts.unshift('this');
      return parts;
    }
    if (current.type !== 'MemberExpression' && current.type !== 'OptionalMemberExpression') {
      return undefined;
    }
    const name = staticPropertyName(current);
    if (name === undefined) return undefined;
    parts.unshift(name);
    const object = current['object'];
    if (!isNode(object)) return undefined;
    current = object;
  }
}

export function calleePath(call: Node): string[] | undefined {
  const callee = call['callee'];
  if (!isNode(callee)) return undefined;
  if (callee.type === 'Identifier') return [callee['name'] as string];
  return memberPath(callee);
}

/** Root identifier of a member chain: `a.b.c` and `a[k]` both give `a`. */
export function rootIdentifier(node: Node): string | undefined {
  let current: Node = node;
  while (current.type === 'MemberExpression' || current.type === 'OptionalMemberExpression') {
    const object = current['object'];
    if (!isNode(object)) return undefined;
    current = object;
  }
  return identifierName(current);
}

/**
 * Like `rootIdentifier`, but also steps through calls and optional chains, so
 * `parts.slice(0, -1)` and `path?.split('.')` both answer `parts` and `path`.
 */
export function baseIdentifier(node: Node): string | undefined {
  let current: Node = node;
  for (let guard = 0; guard < 64; guard += 1) {
    switch (current.type) {
      case 'Identifier':
        return current['name'] as string;
      case 'ThisExpression':
        return 'this';
      case 'MemberExpression':
      case 'OptionalMemberExpression': {
        const object = current['object'];
        if (!isNode(object)) return undefined;
        current = object;
        continue;
      }
      case 'CallExpression':
      case 'OptionalCallExpression':
      case 'NewExpression': {
        const callee = current['callee'];
        if (!isNode(callee)) return undefined;
        current = callee;
        continue;
      }
      case 'ChainExpression':
      case 'TSNonNullExpression': {
        const expression = current['expression'];
        if (!isNode(expression)) return undefined;
        current = expression;
        continue;
      }
      case 'AwaitExpression': {
        const argument = current['argument'];
        if (!isNode(argument)) return undefined;
        current = argument;
        continue;
      }
      default:
        return undefined;
    }
  }
  return undefined;
}

export const FUNCTION_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
]);

export function isFunction(node: Node): boolean {
  return FUNCTION_TYPES.has(node.type);
}

export function ancestors(parsed: ParsedFile, node: Node): Node[] {
  const out: Node[] = [];
  let current = parsed.parents.get(node);
  while (current) {
    out.push(current);
    current = parsed.parents.get(current);
  }
  return out;
}

export function enclosingFunction(parsed: ParsedFile, node: Node): Node | undefined {
  for (const ancestor of ancestors(parsed, node)) {
    if (isFunction(ancestor)) return ancestor;
  }
  return undefined;
}

/**
 * Name of a function however it was declared: declaration, method, assigned arrow, or
 * buried in the feature-detection expression a transpiler wraps its helpers in:
 *
 *     var __createBinding = (this && this.__createBinding) || (Object.create
 *       ? (function (o, m, k, k2) { ... })
 *       : (function (o, m, k, k2) { ... }));
 *
 * Resolving that name is what lets the analyser recognise and skip those helpers, so the
 * wrappers below are stepped through rather than giving up at the first parenthesis.
 */
export function functionName(parsed: ParsedFile, fn: Node): string | undefined {
  const id = fn['id'];
  if (isNode(id)) return identifierName(id);
  let parent = parsed.parents.get(fn);
  for (let guard = 0; guard < 8 && parent !== undefined; guard += 1) {
    if (
      parent.type !== 'ConditionalExpression' &&
      parent.type !== 'LogicalExpression' &&
      parent.type !== 'SequenceExpression' &&
      parent.type !== 'ParenthesizedExpression' &&
      parent.type !== 'ChainExpression'
    ) {
      break;
    }
    parent = parsed.parents.get(parent);
  }
  if (!parent) return undefined;
  if (parent.type === 'VariableDeclarator') return identifierName(parent['id']);
  if (parent.type === 'Property' || parent.type === 'MethodDefinition' || parent.type === 'PropertyDefinition') {
    const key = parent['key'];
    if (isNode(key)) return identifierName(key) ?? (key.type === 'Literal' ? String(key['value']) : undefined);
  }
  if (parent.type === 'AssignmentExpression') {
    const left = parent['left'];
    if (isNode(left)) {
      if (left.type === 'Identifier') return left['name'] as string;
      const path = memberPath(left);
      if (path) return path[path.length - 1];
    }
  }
  return undefined;
}

/** Parameter names of a function, including those bound inside destructuring patterns. */
export function parameterNames(fn: Node): string[] {
  const names: string[] = [];
  const params = fn['params'];
  if (!Array.isArray(params)) return names;
  for (const param of params) {
    if (isNode(param)) collectPatternNames(param, names);
  }
  return names;
}

export function collectPatternNames(pattern: Node, into: string[]): void {
  switch (pattern.type) {
    case 'Identifier':
      into.push(pattern['name'] as string);
      return;
    case 'AssignmentPattern': {
      const left = pattern['left'];
      if (isNode(left)) collectPatternNames(left, into);
      return;
    }
    case 'RestElement': {
      const argument = pattern['argument'];
      if (isNode(argument)) collectPatternNames(argument, into);
      return;
    }
    case 'ArrayPattern': {
      const elements = pattern['elements'];
      if (Array.isArray(elements)) {
        for (const element of elements) if (isNode(element)) collectPatternNames(element, into);
      }
      return;
    }
    case 'ObjectPattern': {
      const properties = pattern['properties'];
      if (Array.isArray(properties)) {
        for (const property of properties) {
          if (!isNode(property)) continue;
          if (property.type === 'RestElement') {
            collectPatternNames(property, into);
            continue;
          }
          const value = property['value'];
          if (isNode(value)) collectPatternNames(value, into);
        }
      }
      return;
    }
    default:
      return;
  }
}

/**
 * Memoised, because the analyser asks for the descendants of the same function body
 * from several rules and from the guard analysis. Without this, a large bundled file
 * turns the scan quadratic.
 */
const descendantCache = new WeakMap<Node, Node[]>();

/** Every descendant of `root`, inclusive, in source order. */
export function descendants(root: Node): Node[] {
  const cached = descendantCache.get(root);
  if (cached) return cached;
  const computed = computeDescendants(root);
  descendantCache.set(root, computed);
  return computed;
}

function computeDescendants(root: Node): Node[] {
  const seen = new Set<Node>();
  const out: Node[] = [];
  try {
    walk.full(root as unknown as acorn.Node, (node) => {
      const current = node as unknown as Node;
      if (seen.has(current)) return;
      seen.add(current);
      out.push(current);
    });
  } catch {
    out.length = 0;
    seen.clear();
    const stack: Node[] = [root];
    while (stack.length > 0) {
      const node = stack.pop();
      if (!node || seen.has(node)) continue;
      seen.add(node);
      out.push(node);
      for (const child of childNodes(node)) stack.push(child);
    }
  }
  if (!seen.has(root)) out.unshift(root);
  return out.sort((a, b) => a.start - b.start || b.end - a.end);
}

export function findDescendants(root: Node, predicate: (node: Node) => boolean): Node[] {
  return descendants(root).filter(predicate);
}

export function isStringLiteral(node: unknown): node is Node {
  return isNode(node) && node.type === 'Literal' && typeof node['value'] === 'string';
}

/** A literal, or a template literal with no interpolation: either way a fixed string. */
export function literalStringValue(node: unknown): string | undefined {
  if (isStringLiteral(node)) return node['value'] as string;
  if (isNode(node) && node.type === 'TemplateLiteral') {
    const expressions = node['expressions'];
    const quasis = node['quasis'];
    if (Array.isArray(expressions) && expressions.length === 0 && Array.isArray(quasis)) {
      const first = quasis[0];
      if (isNode(first)) {
        const cooked = (first['value'] as { cooked?: unknown } | undefined)?.cooked;
        if (typeof cooked === 'string') return cooked;
      }
    }
  }
  return undefined;
}

/** True when the expression is fixed at author time: a string, an array of strings, etc. */
export function isLiteralish(node: unknown): boolean {
  if (!isNode(node)) return false;
  if (node.type === 'Literal') return true;
  if (literalStringValue(node) !== undefined) return true;
  if (node.type === 'ArrayExpression') {
    const elements = node['elements'];
    if (!Array.isArray(elements)) return false;
    return elements.every((element) => !isNode(element) || isLiteralish(element));
  }
  return false;
}
