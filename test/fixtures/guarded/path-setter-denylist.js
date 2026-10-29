// Guarded: every segment is checked before any object is walked or created.
const RESERVED = ['__proto__', 'constructor', 'prototype'];

export function setPath(root, path, value) {
  const parts = path.split('.');
  if (parts.some((part) => RESERVED.includes(part))) {
    throw new Error('refusing to write a reserved key');
  }
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
