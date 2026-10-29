// Guarded: a denylist covering all three names. "__proto__" alone would not be enough,
// because a deep merge recurses through an own "constructor" into "prototype".
const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (UNSAFE_KEYS.has(key)) continue;
    const incoming = source[key];
    if (incoming !== null && typeof incoming === 'object') {
      if (typeof target[key] !== 'object' || target[key] === null) {
        target[key] = {};
      }
      safeMerge(target[key], incoming);
    } else {
      target[key] = incoming;
    }
  }
  return target;
}
