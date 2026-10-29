// PP-S05: lodash helpers that walk into nested keys, called with values the caller
// chose rather than literals written here.
const _ = require('lodash');
const { defaultsDeep } = require('lodash');

function applyPatch(record, patch) {
  return _.merge(record, patch);
}

function writeAt(record, keyPath, value) {
  return _.set(record, keyPath, value);
}

function fillDefaults(record, fallback) {
  return defaultsDeep(record, fallback);
}

module.exports = { applyPatch, writeAt, fillDefaults };
