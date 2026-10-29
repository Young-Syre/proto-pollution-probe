// PP-G01: none of these properties is assigned anywhere, and all three end up in a
// process spawn. A polluted Object.prototype supplies every one of them.
import { execFile } from 'node:child_process';

export function runTask(task) {
  const binary = task.launcher;
  const argv = task.launchArgv;
  execFile(binary, argv, { cwd: task.workingRoot });
}
