// PP-S01: the textbook deep merge. Every key of the source is copied onto the target,
// including "__proto__", and the function recurses into whatever is already there.
function isObject(value) {
  return value !== null && typeof value === 'object';
}

export function deepMerge(target, source) {
  for (const key in source) {
    if (isObject(source[key]) && isObject(target[key])) {
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
