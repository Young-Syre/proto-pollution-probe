// The own-property filter that does not filter. JSON.parse creates "__proto__" as an
// own property, so hasOwnProperty.call returns true for it and the key goes through.
export function applyPatch(target, rawJson) {
  const patch = JSON.parse(rawJson);
  for (const key in patch) {
    if (!Object.prototype.hasOwnProperty.call(patch, key)) continue;
    target[key] = patch[key];
  }
  return target;
}
