// filepath: srchybrid/eSE/api_keys.js
// ─── Single Source of Truth for external API keys ────────────────────────────
// All external API credentials MUST be loaded through this module.
// DO NOT hardcode keys inline in other files.
'use strict';

const fs   = require('fs');
const path = require('path');
const runtimeDir = require('./runtime_dir');

// In pkg mode this is %APPDATA%\eSE\config.json (writable, shared with
// tunnel.js). In dev it's the source-tree path.
const CONFIG_PATH = runtimeDir.join('config.json');

/**
 * Return a non-empty credential string without retaining surrounding
 * whitespace.  Credentials are deliberately not validated or logged here:
 * TMDB owns the accepted format and may change it independently of eSE.
 */
function _credential(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function _getConfiguredCredential(environmentName, configName, options = {}) {
  const environment = options.environment || process.env;
  const fileSystem = options.fileSystem || fs;
  const configPath = options.configPath || CONFIG_PATH;

  const environmentKey = _credential(environment[environmentName]);
  if (environmentKey) return environmentKey;

  try {
    if (!fileSystem.existsSync(configPath)) return null;
    const cfg = JSON.parse(fileSystem.readFileSync(configPath, 'utf8'));
    return _credential(cfg && cfg[configName]);
  } catch (_) {
    return null;
  }
}

/**
 * Loads the TMDB v3 application credential from local configuration.
 * ESE_TMDB_API_KEY takes precedence over config.json's `tmdbKey`.
 */
function getTmdbKey(options = {}) {
  return _getConfiguredCredential('ESE_TMDB_API_KEY', 'tmdbKey', options);
}

/**
 * Loads the OMDb application credential from local configuration.
 * ESE_OMDB_API_KEY takes precedence over config.json's `omdbKey`.
 */
function getOmdbKey(options = {}) {
  return _getConfiguredCredential('ESE_OMDB_API_KEY', 'omdbKey', options);
}

module.exports = { getTmdbKey, getOmdbKey };
