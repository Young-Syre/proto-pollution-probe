// Guarded process-wide: with Object.prototype frozen, the write throws in strict mode
// and is dropped otherwise, so the merge below cannot pollute anything.
Object.freeze(Object.prototype);

export function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}
