// PP-S02 despite Object.create(null).
//
// The root is prototype-less, which is the advice everyone gives, but the intermediate
// levels are created as plain {}. A path of "a.constructor.prototype.polluted" walks
// into the plain object at "a", finds its inherited "constructor", and carries on.
export function buildIndex(path, value) {
  const store = Object.create(null);
  const parts = path.split('.');
  let cursor = store;
  for (const part of parts.slice(0, -1)) {
    cursor[part] ??= {};
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
  return store;
}
