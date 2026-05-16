// filepath: srchybrid/eSE/api_keys.js
// ─── Single Source of Truth for external API keys ────────────────────────────
// All API keys MUST be imported from this module.
// DO NOT hardcode keys inline in other files.
'use strict';

const fs   = require('fs');
const path = require('path');
const runtimeDir = require('./runtime_dir');

// In pkg mode this is %APPDATA%\eSE\config.json (writable, shared with
// tunnel.js). In dev it's the source-tree path.
const CONFIG_PATH = runtimeDir.join('config.json');

/**
 * Loads TMDB API key from config.json.
 * Falls back to built-in default if config is missing or key is empty.
 */
function getTmdbKey() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (cfg.tmdbKey && cfg.tmdbKey.length > 0) {
        return cfg.tmdbKey;
      }
    }
  } catch (e) {
    console.warn('[api_keys] Failed to read config.json:', e.message);
  }
  // Default key — move to env var in production
  return '2dca580c2a14b55200e784d157207b4d';
}

/** Cached TMDB key — loaded once at module init */
const TMDB_KEY = getTmdbKey();

module.exports = { TMDB_KEY };
