// Not a sink: the key is written here, so no caller chooses it.
export function hide(target) {
  Object.defineProperty(target, 'internalId', { value: 1, enumerable: false });
  return target;
}
