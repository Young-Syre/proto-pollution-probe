// PP-S06: flat text in, nested objects out. "a[__proto__][polluted]=1" is one string.
export function parseNested(query) {
  const result = {};
  for (const pair of query.split('&')) {
    const [rawKey, rawValue] = pair.split('=');
    const segments = rawKey.replace(/\]/g, '').split('[');
    let cursor = result;
    for (const segment of segments.slice(0, -1)) {
      cursor[segment] = cursor[segment] || {};
      cursor = cursor[segment];
    }
    cursor[segments[segments.length - 1]] = rawValue;
  }
  return result;
}
