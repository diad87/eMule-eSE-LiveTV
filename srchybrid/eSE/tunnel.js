'use strict';

// v9.1 RC is deliberately localhost-only. Keep this module as the single
// owner of the local dashboard access token, but do not publish addresses,
// generate remote-launcher files, schedule heartbeats or contact any lookup
// service. Remote access belongs to a later release.
const fs = require('fs');
const crypto = require('crypto');
const runtimeDir = require('./runtime_dir');

const REMOTE_ACCESS_DISABLED = true;
const CONFIG_PATH = runtimeDir.join('config.json');

function writeConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), {
    encoding: 'utf8',
    mode: 0o600
  });
}

function loadConfig() {
  let raw = null;
  try {
    raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  if (raw !== null) {
    const config = JSON.parse(raw);
    let changed = false;
    if (!config.secretId) {
      config.secretId = crypto.randomBytes(8).toString('hex');
      changed = true;
    }
    if (!config.encKey) {
      config.encKey = crypto.randomBytes(32).toString('hex');
      changed = true;
    }
    if (!config.accessToken) {
      config.accessToken = crypto.randomBytes(16).toString('hex');
      changed = true;
    }
    if (changed) writeConfig(config);
    return config;
  }

  const config = {
    secretId: crypto.randomBytes(8).toString('hex'),
    encKey: crypto.randomBytes(32).toString('hex'),
    accessToken: crypto.randomBytes(16).toString('hex'),
    createdAt: new Date().toISOString()
  };
  writeConfig(config);
  console.log('[config] Generated local dashboard credentials');
  return config;
}

const CONFIG = loadConfig();

function init() {
  return false;
}

function publishUrl() {
  return false;
}

module.exports = {
  init,
  CONFIG,
  REMOTE_ACCESS_DISABLED,
  LOOKUP_TOPIC: null,
  LOOKUP_URL: null,
  publishUrl,
  get tunnelUrl() { return null; },
  get publicUrl() { return null; },
  get active() { return false; }
};
