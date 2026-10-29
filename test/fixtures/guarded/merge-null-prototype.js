// Guarded: the destination has no prototype and nothing creates a plain intermediate,
// so a "__proto__" key is an ordinary own property with nothing behind it.
export function collect(source) {
  const target = Object.create(null);
  for (const key of Object.keys(source)) {
    target[key] = source[key];
  }
  return target;
}
