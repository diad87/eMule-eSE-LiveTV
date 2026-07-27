// The legacy in-place updater is deliberately disabled for v9.1.
//
// Release packages are downloaded and installed manually so the user can
// verify the published SHA-256, keep the previous directory as a rollback
// point and decide which configuration to migrate.  This module preserves the
// old API shape without performing network access or spawning a helper.

'use strict';

const UPDATES_DISABLED = true;
const DISABLED_REASON = 'manual_updates_only';

function getStatus() {
  return {
    has_update: false,
    checked_at: 0,
    disabled: UPDATES_DISABLED,
    reason: DISABLED_REASON,
  };
}

function start() {
  return false;
}

function stop() {
  return false;
}

function check() {
  return getStatus();
}

function runInteractive(cb) {
  const error = new Error(DISABLED_REASON);
  error.code = 'UPDATER_DISABLED';
  if (typeof cb === 'function') {
    queueMicrotask(() => cb(error));
  }
  return false;
}

module.exports = {
  UPDATES_DISABLED,
  start,
  stop,
  getStatus,
  check,
  runInteractive,
};
