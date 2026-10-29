// PP-S03: a shallow copy. It cannot add a property to Object.prototype, but assigning
// the key "__proto__" replaces the target's prototype outright.
export function copyOwn(target, source) {
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
  return target;
}
