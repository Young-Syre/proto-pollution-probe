import { createRequire } from 'node:module';

/**
 * TypeScript support is type *erasure*, not transpilation.
 *
 * The analyser needs an ES2024 program acorn can parse, and it needs every
 * character of that program to sit at the same offset it occupied in the original
 * `.ts` file — otherwise every reported line and column is a lie. Node's built-in
 * `module.stripTypeScriptTypes` in `strip` mode does exactly that: it overwrites
 * type syntax with spaces and leaves the rest of the file untouched, so the output
 * is byte-for-byte the same length as the input and newlines are preserved.
 *
 * That is the whole of the TypeScript story here. There is no bundled parser, no
 * hand-rolled tokeniser and no second code path, because a type stripper that is
 * subtly wrong would move finding locations without anyone noticing.
 *
 * Two consequences, both reported rather than hidden:
 *
 *  - `module.stripTypeScriptTypes` landed in Node 22.13. On Node 20 a `.ts` file is
 *    skipped and recorded as PP-E02.
 *  - Strip-only mode cannot erase syntax that carries runtime behaviour. It rejects
 *    `enum` declarations, `namespace` / `module` bodies, and constructor parameter
 *    properties (`constructor(private x: T) {}`). Those files are skipped and
 *    recorded as PP-E02 with the stripper's own message.
 */

const require_ = createRequire(import.meta.url);

type Stripper = (code: string, options: { mode: 'strip' }) => string;

let cached: Stripper | null | undefined;

function stripper(): Stripper | null {
  if (cached !== undefined) return cached;
  try {
    const mod = require_('node:module') as { stripTypeScriptTypes?: unknown };
    cached = typeof mod.stripTypeScriptTypes === 'function' ? (mod.stripTypeScriptTypes as Stripper) : null;
  } catch {
    cached = null;
  }
  return cached;
}

export function typeErasureAvailable(): boolean {
  return stripper() !== null;
}

/**
 * Node prints `ExperimentalWarning: stripTypeScriptTypes` on first use. Scanning a
 * TypeScript project is not an experiment the user needs telling about, and the warning
 * lands on stderr in the middle of a report, so it is filtered — and only that one
 * warning, only while the call is in flight.
 */
function withoutExperimentalWarning<T>(fn: () => T): T {
  const original = process.emitWarning;
  process.emitWarning = ((warning: unknown, ...rest: unknown[]): void => {
    const text = typeof warning === 'string' ? warning : (warning as Error | undefined)?.message ?? '';
    if (text.includes('stripTypeScriptTypes')) return;
    (original as (...args: unknown[]) => void).call(process, warning, ...rest);
  }) as typeof process.emitWarning;
  try {
    return fn();
  } finally {
    process.emitWarning = original;
  }
}

export const TYPESCRIPT_EXTENSIONS = new Set(['.ts', '.mts', '.cts']);

export type EraseResult =
  | { ok: true; code: string }
  | { ok: false; reason: string };

/**
 * Erase TypeScript type syntax while preserving every offset.
 *
 * The length invariant is asserted rather than assumed: if a future Node release
 * changes strip-mode behaviour, the file is skipped with a clear reason instead of
 * producing findings at shifted positions.
 */
export function eraseTypes(code: string): EraseResult {
  const strip = stripper();
  if (!strip) {
    return {
      ok: false,
      reason:
        'TypeScript type erasure requires module.stripTypeScriptTypes, available from Node 22.13; ' +
        `this process runs Node ${process.versions.node}`,
    };
  }
  let stripped: string;
  try {
    stripped = withoutExperimentalWarning(() => strip(code, { mode: 'strip' }));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `type erasure rejected the file: ${message}` };
  }
  if (stripped.length !== code.length) {
    return {
      ok: false,
      reason:
        'type erasure changed the file length, so reported positions would not match the source ' +
        `(${code.length} bytes in, ${stripped.length} bytes out)`,
    };
  }
  return { ok: true, code: stripped };
}
