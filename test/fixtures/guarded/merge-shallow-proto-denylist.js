// Guarded, and sufficiently so. This is a one-level copy, and for a one-level copy the
// only key that reaches a prototype is the literal "__proto__": writing
// target.constructor merely shadows an inherited property. Rejecting __proto__ is
// therefore complete here, which is not true of the recursive merge in
// weak/merge-proto-only-denylist.js.
export function copyOwn(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;
    target[key] = source[key];
  }
  return target;
}
