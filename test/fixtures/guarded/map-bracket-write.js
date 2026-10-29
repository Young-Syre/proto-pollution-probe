// Guarded, though not deliberately: the destination is a Map, so these writes land on
// the Map instance rather than becoming defaults other plain objects read. (The Map
// also stays empty, which is a different bug and not this tool's business.)
export function tally(source) {
  const seen = new Map();
  for (const key of Object.keys(source)) {
    seen[key] = true;
  }
  return seen;
}
