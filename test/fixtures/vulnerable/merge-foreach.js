// PP-S01 written with a callback instead of a loop. The shape is the same and so is
// the bug; a regex looking for `for (... in ...)` would miss it.
export function assignDeep(target, source) {
  Object.keys(source).forEach((key) => {
    if (source[key] && typeof source[key] === 'object') {
      assignDeep(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  });
  return target;
}
