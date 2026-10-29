// Guarded for now, by an own-property filter and nothing else. No parser in this file
// can mint an own "__proto__" key, so the filter holds. Run with --min-severity note
// to see PP-Q02 say how narrow that is.
export function assignOwn(target, source) {
  for (const key in source) {
    if (!Object.hasOwn(source, key)) continue;
    target[key] = source[key];
  }
  return target;
}
