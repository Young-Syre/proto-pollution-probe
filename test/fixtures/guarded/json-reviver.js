// Guarded: the reviver drops the one key that matters, so the parsed value cannot
// carry an own "__proto__" into anything downstream.
export function parseSafely(raw) {
  return JSON.parse(raw, (key, value) => (key === '__proto__' ? undefined : value));
}
