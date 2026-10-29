// TypeScript: generics, an interface, optional members, `as`, `satisfies` and a
// non-null assertion. Types are erased to spaces before parsing, so the line and
// column of the finding below are the line and column in this file.
export interface MergeOptions<T> {
  readonly deep?: boolean;
  onConflict?: (key: string, left: T, right: T) => T;
}

const fallback = { deep: true } satisfies MergeOptions<Record<string, unknown>>;

export function deepMerge<T extends Record<string, unknown>>(
  target: T,
  source: Partial<T>,
  options: MergeOptions<T> = fallback as MergeOptions<T>,
): T {
  for (const key in source) {
    const incoming = source[key] as unknown;
    if (incoming !== null && typeof incoming === 'object') {
      deepMerge(
        target[key] as Record<string, unknown>,
        incoming as Record<string, unknown>,
        options!,
      );
    } else {
      (target as Record<string, unknown>)[key] = incoming;
    }
  }
  return target;
}
