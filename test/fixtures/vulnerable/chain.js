// PP-C01: both halves in one file. The merge can place a key on Object.prototype and
// the hook runner reads a property nothing assigns, straight into a shell.
import { execSync } from 'node:child_process';

export function mergeInto(target, source) {
  for (const key in source) {
    if (source[key] !== null && typeof source[key] === 'object') {
      mergeInto((target[key] ??= {}), source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

export function runHook(hook) {
  return execSync(hook.shellCommand);
}
