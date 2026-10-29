// Not a sink: the key path and the merge sources are written here, not supplied.
import _ from 'lodash';

export function bumpVersion(record) {
  _.set(record, 'meta.version', 2);
  return _.merge({}, { enabled: false }, { enabled: true });
}
