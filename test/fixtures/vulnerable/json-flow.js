// PP-S08: JSON.parse is what turns the text "__proto__" into an own property of a real
// object, and here it flows straight into a merge.
const settings = {};

function applyAll(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

export function loadConfig(raw) {
  const parsed = JSON.parse(raw);
  return applyAll(settings, parsed);
}
