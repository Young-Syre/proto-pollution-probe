// Not a sink: the target is a fresh object literal, so nothing shared is written and
// the result's own prototype is the only thing the caller could affect.
export function withDefaults(incoming) {
  return Object.assign({}, { retries: 3, timeoutMs: 1000 }, incoming);
}
