// Strip-only type erasure cannot remove an enum, because an enum has runtime
// behaviour. This file is expected to be skipped and reported as PP-E02, not analysed
// and not silently dropped.
export enum Mode {
  Safe,
  Unsafe,
}

export function describe(mode: Mode): string {
  return Mode[mode];
}
