// Guarded, badly. "__proto__" is rejected and "constructor" is not, so
// { constructor: { prototype: { polluted: 1 } } } walks past the check.
export function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;
    const incoming = source[key];
    if (incoming !== null && typeof incoming === 'object') {
      if (typeof target[key] !== 'object' || target[key] === null) {
        target[key] = {};
      }
      merge(target[key], incoming);
    } else {
      target[key] = incoming;
    }
  }
  return target;
}
