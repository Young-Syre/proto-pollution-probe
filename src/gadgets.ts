import {
  type Node,
  type ParsedFile,
  ancestors,
  calleePath,
  descendants,
  enclosingFunction,
  identifierName,
  isNode,
  literalStringValue,
  memberPath,
  nodeText,
  parameterNames,
  rootIdentifier,
  staticPropertyName,
} from './ast.js';
import { makeFinding, relatedAt } from './finding.js';
import { REACH_SEVERITY, type Finding, type GadgetReach } from './types.js';

/**
 * Builtins and prototype members. A read of one of these is not a gadget however the
 * rest of the analysis turns out, because the value does not come from a plain object
 * the attacker can reach.
 */
const BUILTIN_ROOTS = new Set([
  'Array', 'ArrayBuffer', 'Atomics', 'BigInt', 'Boolean', 'Buffer', 'DataView', 'Date', 'Error',
  'EvalError', 'FinalizationRegistry', 'Float32Array', 'Float64Array', 'Function', 'Infinity',
  'Int8Array', 'Int16Array', 'Int32Array', 'Intl', 'JSON', 'Map', 'Math', 'NaN', 'Number', 'Object',
  'Promise', 'Proxy', 'RangeError', 'ReferenceError', 'Reflect', 'RegExp', 'Set', 'SharedArrayBuffer',
  'String', 'Symbol', 'SyntaxError', 'TypeError', 'URIError', 'URL', 'URLSearchParams', 'Uint8Array',
  'Uint16Array', 'Uint32Array', 'WeakMap', 'WeakRef', 'WeakSet', 'console', 'document', 'exports',
  'global', 'globalThis', 'module', 'process', 'require', 'self', 'undefined', 'window',
  '__dirname', '__filename',
]);

const COMMON_MEMBERS = new Set([
  'length', 'name', 'message', 'stack', 'cause', 'constructor', 'prototype', '__proto__', 'then',
  'catch', 'finally', 'map', 'filter', 'forEach', 'reduce', 'reduceRight', 'flat', 'flatMap', 'push',
  'pop', 'shift', 'unshift', 'slice', 'splice', 'concat', 'join', 'indexOf', 'lastIndexOf', 'includes',
  'find', 'findIndex', 'findLast', 'some', 'every', 'sort', 'reverse', 'fill', 'at', 'keys', 'values',
  'entries', 'toString', 'toJSON', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'call', 'apply',
  'bind', 'trim', 'trimStart', 'trimEnd', 'split', 'replace', 'replaceAll', 'match', 'matchAll',
  'test', 'exec', 'charAt', 'charCodeAt', 'codePointAt', 'startsWith', 'endsWith', 'padStart',
  'padEnd', 'repeat', 'toLowerCase', 'toUpperCase', 'normalize', 'size', 'add', 'delete', 'get',
  'set', 'has', 'clear', 'next', 'done', 'byteLength', 'buffer', 'on', 'once', 'emit', 'off',
  'addListener', 'removeListener', 'pipe', 'write', 'end', 'close', 'destroy', 'then', 'all',
  'race', 'resolve', 'reject', 'default',
]);

/**
 * Reach analysis, and why it insists on knowing where a function came from.
 *
 * The obvious implementation matches the callee's name: anything called `exec` spawns a
 * process, anything called `resolve` resolves a path. Measured against a real dependency
 * tree that implementation is wrong more often than it is right, because `regex.exec(s)`
 * is a RegExp match and `resolve(value)` is a promise being settled. Both produced
 * confident "reaches command execution" findings in an early version of this tool.
 *
 * So a bare call only counts when the name was imported from a module that really does
 * that thing, and a dotted call only counts when its root is a binding for such a module
 * or the method name is one that nothing else uses.
 */
const EXEC_METHODS = new Set([
  'exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork',
  'execa', 'execaSync', 'execaCommand', 'command', 'shellExec',
]);
const EXEC_MODULES = /^(node:)?child_process$|^(execa|cross-spawn|shelljs|zx|shell-exec)$/;
const EXEC_ROOTS = /^(child_process|childProcess|cp|execa|shell|shelljs|sh|\$)$/;
const EXEC_OPTION_KEYS = new Set(['shell', 'env', 'cwd', 'uid', 'gid', 'argv0', 'execPath', 'execArgv']);

/** Path builders: every argument is a path segment. */
const PATH_BUILDERS = new Set(['join', 'resolve', 'normalize', 'relative']);
/** Filesystem calls: only the first argument is a path. The rest is content. */
const FS_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'createReadStream', 'createWriteStream', 'sendFile', 'readdir', 'readdirSync', 'stat',
  'statSync', 'lstat', 'unlink', 'unlinkSync', 'open', 'openSync', 'realpath', 'realpathSync',
  'access', 'accessSync', 'copyFile', 'rename', 'rm', 'rmSync', 'mkdir', 'mkdirSync',
]);
const PATH_METHODS = new Set([...PATH_BUILDERS, ...FS_METHODS]);
const PATH_MODULES = /^(node:)?(path|fs)(\/promises)?$|^(fs-extra|graceful-fs|fs\.promises)$/;
const PATH_ROOTS = /^(path|fs|fsp|fsPromises|promises|posix|win32|nodePath|nodeFs|fse)$/;

/** Methods that only a template engine has, so the root does not have to be known. */
const TEMPLATE_METHODS = new Set([
  'compile', 'precompile', 'template', 'renderString', 'renderFile', 'compileFile',
  'runInNewContext', 'runInThisContext', 'runInContext',
]);
/** Methods common enough that the root must be a known template module. */
const TEMPLATE_LOOSE_METHODS = new Set(['render', 'renderToString', 'renderToStaticMarkup']);
const TEMPLATE_MODULES =
  /^(handlebars|ejs|pug|jade|mustache|hogan\.js|nunjucks|dot|dustjs-linkedin|eta|liquidjs|twig|art-template|squirrelly|lodash|underscore|(node:)?vm)$/;
const GLOBAL_EVAL = new Set(['eval', 'Function']);

const HTML_SINKS = new Set(['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML', 'insertAdjacentHTML']);

/**
 * Property names that exist only to carry an authorisation decision, anchored at both
 * ends. An unanchored pattern matched `ownerDocument` and `debugLocation` on the way to
 * 118 confident false positives, which is how this regex earned its `$`.
 */
const AUTH_NAME = new RegExp(
  '^(?:is|can|has|allow|allows|should|skip|disable|enable|bypass|force|trust|require)?[_-]?' +
    '(?:admin|administrator|superuser|super_?user|root_?user|role|roles|perm|perms|permission|' +
    'permissions|acl|acls|privilege|privileges|privileged|elevated|sudo|impersonate|' +
    'impersonation|authenticated|authorized|authorised|authorization|authorisation|' +
    'moderator|staff|god_?mode)(?:s|ed)?$',
  'i',
);

/** ALL_CAPS reads are constant lookups, never attacker-forged defaults. */
const CONSTANT_NAME = /^[A-Z][A-Z0-9_]*$/;

/**
 * Properties of an object destructuring pattern.
 *
 * `acorn-walk`'s base visitor descends straight into each property's value with a
 * `Pattern` override, so the `Property` nodes themselves never reach a callback. They
 * have to be read off the pattern by hand.
 */
function patternProperties(
  pattern: Node,
): Array<{ node: Node; name: string | undefined; defaulted: boolean; local: string | undefined }> {
  const properties = pattern['properties'];
  if (!Array.isArray(properties)) return [];
  const out: Array<{ node: Node; name: string | undefined; defaulted: boolean; local: string | undefined }> = [];
  for (const property of properties) {
    if (!isNode(property) || property.type !== 'Property') continue;
    if (property['computed'] === true) continue;
    const key = property['key'];
    const value = property['value'];
    const name = isNode(key) ? identifierName(key) ?? literalStringValue(key) : undefined;
    const defaulted = isNode(value) && value.type === 'AssignmentPattern';
    const local = isNode(value) ? identifierName(value) ?? identifierName(value['left']) : undefined;
    out.push({ node: property, name, defaulted, local });
  }
  return out;
}

/** Property names assigned anywhere in the scan. A written property is not a gadget. */
export function collectWrittenProperties(parsed: ParsedFile, into: Set<string>): void {
  for (const node of parsed.nodes) {
    switch (node.type) {
      case 'AssignmentExpression': {
        const left = node['left'];
        if (!isNode(left)) break;
        if (left.type === 'MemberExpression') {
          const name = staticPropertyName(left);
          if (name !== undefined) into.add(name);
        }
        break;
      }
      case 'Property': {
        // An object literal key is a write: somewhere in this codebase the property is set.
        if (parsed.parents.get(node)?.type !== 'ObjectExpression') break;
        const key = node['key'];
        if (!isNode(key)) break;
        const name = identifierName(key) ?? literalStringValue(key);
        if (name !== undefined) into.add(name);
        break;
      }
      case 'ObjectPattern': {
        // A destructuring default supplies a value, so the read behind it is defended and
        // the name counts as assigned. acorn-walk does not yield Property nodes inside a
        // pattern, so the properties are read off the pattern directly.
        for (const property of patternProperties(node)) {
          if (property.defaulted && property.name !== undefined) into.add(property.name);
        }
        break;
      }
      case 'PropertyDefinition':
      case 'MethodDefinition': {
        const key = node['key'];
        if (!isNode(key)) break;
        const name = identifierName(key) ?? literalStringValue(key);
        if (name !== undefined) into.add(name);
        break;
      }
      case 'CallExpression': {
        const path = calleePath(node);
        const joined = path?.join('.');
        if (joined !== 'Object.defineProperty' && joined !== 'Reflect.set' && joined !== 'Reflect.defineProperty') {
          break;
        }
        const args = node['arguments'];
        const key = Array.isArray(args) ? args[1] : undefined;
        const name = isNode(key) ? literalStringValue(key) : undefined;
        if (name !== undefined) into.add(name);
        break;
      }
      default:
        break;
    }
  }
}

interface Candidate {
  /** The read site: a MemberExpression, or the Property of a destructuring pattern. */
  node: Node;
  /**
   * Node to scope guard and use lookups to. Pattern properties are not yielded by the
   * traversal, so they have no parent entry; the enclosing pattern does.
   */
  scopeNode?: Node;
  property: string;
  /** Text of the object being read, for the message. */
  objectText: string;
  /** Local name the value is bound to, when the read is immediately stored. */
  binding?: string;
}

function isWriteTarget(parsed: ParsedFile, node: Node): boolean {
  const parent = parsed.parents.get(node);
  if (!parent) return false;
  if (parent.type === 'AssignmentExpression' && parent['left'] === node) return true;
  if (parent.type === 'UpdateExpression') return true;
  if (parent.type === 'UnaryExpression' && parent['operator'] === 'delete') return true;
  return false;
}

function isCallee(parsed: ParsedFile, node: Node): boolean {
  const parent = parsed.parents.get(node);
  if (!parent) return false;
  return (
    (parent.type === 'CallExpression' || parent.type === 'NewExpression' || parent.type === 'TaggedTemplateExpression') &&
    parent['callee'] === node
  );
}

/** Locals and parameters in scope, so module imports and builtins can be excluded. */
function localBindings(parsed: ParsedFile): Set<string> {
  const names = new Set<string>();
  for (const node of parsed.nodes) {
    if (node.type === 'VariableDeclarator') {
      const id = node['id'];
      if (isNode(id) && id.type === 'Identifier') names.add(id['name'] as string);
      continue;
    }
    if (
      node.type === 'FunctionDeclaration' ||
      node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression'
    ) {
      for (const name of parameterNames(node)) names.add(name);
    }
  }
  return names;
}

/** Local name -> module it was imported from, for both ESM and `require`. */
interface Imports {
  /** Every locally bound import name, used to exclude module namespaces as gadget objects. */
  names: Set<string>;
  /** Local name -> source module, for named imports and destructured requires. */
  bindings: Map<string, string>;
  /** Local name -> source module, for namespace and default imports. */
  namespaces: Map<string, string>;
}

function importedBindings(parsed: ParsedFile): Imports {
  const names = new Set<string>();
  const bindings = new Map<string, string>();
  const namespaces = new Map<string, string>();

  for (const node of parsed.nodes) {
    if (node.type === 'ImportDeclaration') {
      const source = literalStringValue(node['source']);
      const specifiers = node['specifiers'];
      if (!Array.isArray(specifiers)) continue;
      for (const specifier of specifiers) {
        if (!isNode(specifier)) continue;
        const local = identifierName(specifier['local']);
        if (!local) continue;
        names.add(local);
        if (source === undefined) continue;
        if (specifier.type === 'ImportSpecifier') bindings.set(local, source);
        else namespaces.set(local, source);
      }
      continue;
    }
    if (node.type === 'VariableDeclarator') {
      const init = node['init'];
      if (!isNode(init) || init.type !== 'CallExpression') continue;
      if (calleePath(init)?.join('.') !== 'require') continue;
      const args = init['arguments'];
      const source = Array.isArray(args) && isNode(args[0]) ? literalStringValue(args[0]) : undefined;
      const id = node['id'];
      if (!isNode(id)) continue;
      if (id.type === 'Identifier') {
        const local = id['name'] as string;
        names.add(local);
        if (source !== undefined) namespaces.set(local, source);
      } else if (id.type === 'ObjectPattern') {
        for (const property of patternProperties(id)) {
          if (property.local === undefined) continue;
          names.add(property.local);
          if (source !== undefined) bindings.set(property.local, source);
        }
      }
    }
  }
  return { names, bindings, namespaces };
}

/** Does a call reach the kind of function this reach class is about? */
function matchesReach(
  imports: Imports,
  path: string[] | undefined,
  kind: 'exec' | 'path' | 'template',
): boolean {
  if (!path || path.length === 0) return false;
  const method = path[path.length - 1];
  const root = path[0];
  if (method === undefined || root === undefined) return false;

  if (kind === 'exec') {
    if (!EXEC_METHODS.has(method)) return false;
    if (path.length === 1) {
      const source = imports.bindings.get(method) ?? imports.namespaces.get(method);
      return source !== undefined && EXEC_MODULES.test(source);
    }
    const source = imports.namespaces.get(root);
    return (source !== undefined && EXEC_MODULES.test(source)) || EXEC_ROOTS.test(root);
  }

  if (kind === 'path') {
    if (!PATH_METHODS.has(method)) return false;
    if (path.length === 1) {
      const source = imports.bindings.get(method);
      return source !== undefined && PATH_MODULES.test(source);
    }
    const source = imports.namespaces.get(root);
    return (source !== undefined && PATH_MODULES.test(source)) || PATH_ROOTS.test(root);
  }

  if (TEMPLATE_METHODS.has(method)) return true;
  if (path.length === 1) return GLOBAL_EVAL.has(method) && !imports.names.has(method);
  if (!TEMPLATE_LOOSE_METHODS.has(method)) return false;
  const source = imports.namespaces.get(root);
  return source !== undefined && TEMPLATE_MODULES.test(source);
}

function bindingFor(parsed: ParsedFile, node: Node): string | undefined {
  const parent = parsed.parents.get(node);
  if (!parent) return undefined;
  if (parent.type === 'VariableDeclarator' && parent['init'] === node) return identifierName(parent['id']);
  if (parent.type === 'AssignmentExpression' && parent['right'] === node) {
    const left = parent['left'];
    return isNode(left) ? identifierName(left) : undefined;
  }
  if (parent.type === 'LogicalExpression' || parent.type === 'ConditionalExpression') {
    return bindingFor(parsed, parent);
  }
  return undefined;
}

function collectCandidates(parsed: ParsedFile, written: Set<string>): Candidate[] {
  const locals = localBindings(parsed);
  const imports = importedBindings(parsed);
  const imported = imports.names;
  const out: Candidate[] = [];

  for (const node of parsed.nodes) {
    if (node.type === 'MemberExpression') {
      if (node['optional'] === true) continue; // `a?.b` already tolerates absence
      const property = staticPropertyName(node);
      if (property === undefined) continue;
      if (written.has(property) || COMMON_MEMBERS.has(property)) continue;
      if (CONSTANT_NAME.test(property)) continue;
      if (isWriteTarget(parsed, node) || isCallee(parsed, node)) continue;
      // Only the outermost read in a chain, so `a.b.c` reports once.
      const parent = parsed.parents.get(node);
      if (parent?.type === 'MemberExpression' && parent['object'] === node) continue;
      const object = node['object'];
      if (!isNode(object)) continue;
      const root = rootIdentifier(node);
      if (root === undefined) continue;
      if (root === 'this' || BUILTIN_ROOTS.has(root) || imported.has(root) || !locals.has(root)) continue;
      const candidate: Candidate = { node, property, objectText: nodeText(parsed, object, 40) };
      const binding = bindingFor(parsed, node);
      if (binding) candidate.binding = binding;
      out.push(candidate);
      continue;
    }

    if (node.type === 'ObjectPattern') {
      // `const { shell } = opts` reads a property just as `opts.shell` does.
      const parent = parsed.parents.get(node);
      if (parent?.type !== 'VariableDeclarator') continue;
      const init = parent['init'];
      if (!isNode(init)) continue;
      const root = rootIdentifier(init);
      if (root === undefined || BUILTIN_ROOTS.has(root) || imported.has(root) || !locals.has(root)) continue;
      const objectText = nodeText(parsed, init, 40);
      for (const property of patternProperties(node)) {
        if (property.defaulted || property.name === undefined) continue;
        if (written.has(property.name) || COMMON_MEMBERS.has(property.name)) continue;
        if (CONSTANT_NAME.test(property.name)) continue;
        const candidate: Candidate = {
          node: property.node,
          scopeNode: node,
          property: property.name,
          objectText,
        };
        candidate.binding = property.local ?? property.name;
        out.push(candidate);
      }
    }
  }
  return out;
}

function candidateScope(parsed: ParsedFile, candidate: Candidate): Node {
  const anchor = candidate.scopeNode ?? candidate.node;
  return enclosingFunction(parsed, anchor) ?? parsed.program;
}

/** Is this property own-checked somewhere in the function that reads it? */
function ownChecked(parsed: ParsedFile, candidate: Candidate): boolean {
  const scope = candidateScope(parsed, candidate);
  for (const node of descendants(scope)) {
    if (node.type !== 'CallExpression') continue;
    const path = calleePath(node);
    const method = path?.[path.length - 1];
    const tail = path?.slice(-2).join('.');
    if (method !== 'hasOwn' && method !== 'hasOwnProperty' && tail !== 'hasOwnProperty.call') continue;
    const args = node['arguments'];
    if (!Array.isArray(args)) continue;
    for (const arg of args) {
      if (isNode(arg) && literalStringValue(arg) === candidate.property) return true;
      if (isNode(arg) && identifierName(arg) !== undefined) return true;
    }
  }
  return false;
}

/** Is this property tested with `in`? A weaker check, reported as such. */
function inChecked(parsed: ParsedFile, candidate: Candidate): Node | undefined {
  const scope = candidateScope(parsed, candidate);
  for (const node of descendants(scope)) {
    if (node.type !== 'BinaryExpression' || node['operator'] !== 'in') continue;
    const left = node['left'];
    if (isNode(left) && literalStringValue(left) === candidate.property) return node;
  }
  return undefined;
}

interface Reach {
  reach: GadgetReach;
  evidence: Node;
  detail: string;
}

/**
 * Which argument of `call` contains `child`, or -1.
 *
 * Argument position is what separates a path from a payload. `fs.appendFileSync(file, text)`
 * writes `text` into `file`; a polluted default landing in `text` is not path traversal,
 * however much the callee's name suggests it. Without this check the analyser reported
 * TypeScript's own log-line template as reaching the filesystem.
 */
function argumentIndex(call: Node, child: Node | undefined): number {
  if (!child) return -1;
  const args = call['arguments'];
  if (!Array.isArray(args)) return -1;
  return args.indexOf(child);
}

/** Argument positions at which a value genuinely influences the call's effect. */
function positionAllows(kind: 'exec' | 'path' | 'template', method: string, index: number): boolean {
  if (index < 0) return false;
  if (kind === 'path') return PATH_BUILDERS.has(method) ? true : index === 0;
  return index <= 1;
}

/** Nodes the candidate's value can be at: the read itself and every use of its binding. */
function usesOf(parsed: ParsedFile, candidate: Candidate): Node[] {
  const uses: Node[] = [candidate.node];
  if (candidate.binding === undefined) return uses;
  const scope = candidateScope(parsed, candidate);
  for (const node of descendants(scope)) {
    if (node === candidate.node) continue;
    if (node.type !== 'Identifier' || node['name'] !== candidate.binding) continue;
    const parent = parsed.parents.get(node);
    if (parent?.type === 'VariableDeclarator' && parent['id'] === node) continue;
    if (parent?.type === 'Property' && parent['key'] === node && parent['computed'] !== true) continue;
    if (parent?.type === 'MemberExpression' && parent['property'] === node && parent['computed'] !== true) continue;
    uses.push(node);
  }
  return uses;
}

function classifyReach(parsed: ParsedFile, imports: Imports, candidate: Candidate): Reach | undefined {
  for (const use of usesOf(parsed, candidate)) {
    const chain = [use, ...ancestors(parsed, use).slice(0, 6)];
    for (let i = 0; i < chain.length; i += 1) {
      const node = chain[i];
      if (!node) continue;

      if (node.type === 'CallExpression' || node.type === 'NewExpression') {
        const path = calleePath(node);
        const joined = path?.join('.') ?? '';
        const method = path?.[path.length - 1] ?? '';
        const index = argumentIndex(node, chain[i - 1]);
        if (matchesReach(imports, path, 'exec') && positionAllows('exec', method, index)) {
          return { reach: 'command-execution', evidence: node, detail: `the value reaches ${joined}` };
        }
        if (matchesReach(imports, path, 'template') && positionAllows('template', method, index)) {
          return { reach: 'template-render', evidence: node, detail: `the value reaches ${joined}` };
        }
        if (matchesReach(imports, path, 'path') && positionAllows('path', method, index)) {
          return { reach: 'path-resolution', evidence: node, detail: `the value reaches ${joined}` };
        }
      }

      // An options object handed to a spawn call: the key matters as much as the callee.
      if (node.type === 'Property') {
        const key = identifierName(node['key']) ?? literalStringValue(node['key']);
        if (key !== undefined && EXEC_OPTION_KEYS.has(key)) {
          const call = ancestors(parsed, node)
            .slice(0, 4)
            .find((ancestor) => ancestor.type === 'CallExpression');
          if (call) {
            const callPath = calleePath(call);
            const joined = callPath?.join('.') ?? '';
            if (matchesReach(imports, callPath, 'exec')) {
              return {
                reach: 'command-execution',
                evidence: call,
                detail: `the value becomes the "${key}" option of ${joined}`,
              };
            }
          }
        }
      }

      if (node.type === 'AssignmentExpression') {
        const left = node['left'];
        const name = isNode(left) ? staticPropertyName(left) : undefined;
        if (name !== undefined && HTML_SINKS.has(name)) {
          return { reach: 'template-render', evidence: node, detail: `the value is written to ${name}` };
        }
      }

      if (
        (node.type === 'IfStatement' && node['test'] === chain[i - 1]) ||
        (node.type === 'ConditionalExpression' && node['test'] === chain[i - 1]) ||
        node.type === 'LogicalExpression' ||
        (node.type === 'UnaryExpression' && node['operator'] === '!')
      ) {
        if (AUTH_NAME.test(candidate.property)) {
          return {
            reach: 'auth-decision',
            evidence: node,
            detail: `"${candidate.property}" decides a branch`,
          };
        }
      }
    }
  }
  if (AUTH_NAME.test(candidate.property)) {
    return {
      reach: 'auth-decision',
      evidence: candidate.node,
      detail: `"${candidate.property}" names a privilege`,
    };
  }
  return undefined;
}

const REACH_RULE: Record<GadgetReach, string> = {
  'command-execution': 'PP-G01',
  'path-resolution': 'PP-G02',
  'template-render': 'PP-G03',
  'auth-decision': 'PP-G04',
  'framework-default': 'PP-G05',
};

export function scanGadgets(parsed: ParsedFile, written: Set<string>): Finding[] {
  const out: Finding[] = [];
  const imports = importedBindings(parsed);
  for (const candidate of collectCandidates(parsed, written)) {
    if (ownChecked(parsed, candidate)) continue;
    const weak = inChecked(parsed, candidate);
    const reach = classifyReach(parsed, imports, candidate);
    const kind = reach?.reach ?? 'framework-default';
    const ruleId = REACH_RULE[kind];
    let severity = REACH_SEVERITY[kind];
    const related = reach ? [relatedAt(parsed, reach.evidence, reach.detail)] : [];
    let message =
      `"${candidate.property}" is read from ${candidate.objectText} but is never assigned anywhere ` +
      'in the scanned source and never own-checked, so a polluted Object.prototype supplies its ' +
      'value.';
    if (reach) message += ` From there ${reach.detail}.`;
    if (weak) {
      severity = severity === 'critical' ? 'high' : severity;
      message +=
        ' An `in` check is present, which does not help: `in` walks the prototype chain and so' +
        ' returns true for a polluted property.';
      related.push(relatedAt(parsed, weak, '`in` check, which inherited properties satisfy'));
    }
    out.push(
      makeFinding(parsed, {
        ruleId,
        node: candidate.node,
        message,
        severity,
        related,
        reach: kind,
        property: candidate.property,
      }),
    );
  }
  return out;
}

export { memberPath };
