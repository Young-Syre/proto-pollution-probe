// An `in` check looks like a guard and is not: `in` walks the prototype chain, so it
// returns true for exactly the property an attacker just planted there.
import { execSync } from 'node:child_process';

export function runPlugin(plugin) {
  if ('bootstrapCommand' in plugin) {
    return execSync(plugin.bootstrapCommand);
  }
  return null;
}
