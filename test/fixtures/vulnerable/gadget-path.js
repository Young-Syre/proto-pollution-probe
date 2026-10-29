// PP-G02: an unassigned property becomes the base of a filesystem read.
import { join } from 'node:path';
import { readFileSync } from 'node:fs';

export function loadLayout(request) {
  const base = request.layoutRoot;
  return readFileSync(join(base, 'layout.html'), 'utf8');
}
