// PP-S02: a dotted path setter. "__proto__.polluted" and
// "constructor.prototype.polluted" both arrive at Object.prototype.
export function setPath(root, path, value) {
  const parts = path.split('.');
  let cursor = root;
  for (const part of parts.slice(0, -1)) {
    if (typeof cursor[part] !== 'object' || cursor[part] === null) {
      cursor[part] = {};
    }
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
  return root;
}
