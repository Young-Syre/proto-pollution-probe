// PP-S06: the query-string parser's one defence, turned off on purpose.
import qs from 'qs';

export function parseFilters(raw) {
  return qs.parse(raw, { allowPrototypes: true, depth: 10 });
}
