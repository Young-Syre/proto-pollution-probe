// Not a gadget: the read is behind an own-property check, which a polluted
// Object.prototype does not satisfy.
export function readFlag(options) {
  if (!Object.hasOwn(options, 'allowShell')) {
    return false;
  }
  return options.allowShell;
}
