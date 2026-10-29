// PP-S04: the target outlives the call, so whatever the caller passed becomes the
// default every later reader sees.
const defaults = { retries: 3, timeoutMs: 2000 };

export function configure(incoming) {
  Object.assign(defaults, incoming);
  return defaults;
}

export function readDefaults() {
  return defaults;
}
