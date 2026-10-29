// PP-S07: defineProperty with a computed key. It ignores setters and writability, so
// it writes where plain assignment would not.
export function define(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return target;
}

export function reflectWrite(target, key, value) {
  return Reflect.set(target, key, value);
}
