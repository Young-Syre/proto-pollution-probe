// Guarded by construction: a Map has no [[Prototype]] write path for its keys, and
// there is no bracket assignment for a key name to be interpreted by.
export function indexBy(source) {
  const index = new Map();
  for (const key of Object.keys(source)) {
    index.set(key, source[key]);
  }
  return index;
}

export function mergeIntoMap(target, source) {
  for (const key of Object.keys(source)) {
    target.set(key, source[key]);
  }
  return target;
}
