/**
 * eSE Live — Favorites Manager
 * Manages favorite channels with localStorage sync and file persistence.
 * Max ~150 lines.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const runtimeDir = require('../runtime_dir');

// Writable runtime path (pkg-snapshot is read-only).
const FAVORITES_FILE = path.join(runtimeDir.get(), 'eSE-live', 'favorites.json');

// In-memory favorites cache
let favorites = [];
loadFromDisk();

/**
 * Load favorites from disk.
 */
function loadFromDisk() {
  try {
    if (fs.existsSync(FAVORITES_FILE)) {
      favorites = JSON.parse(fs.readFileSync(FAVORITES_FILE, 'utf8'));
    }
  } catch (e) {
    favorites = [];
  }
}

/**
 * Save favorites to disk.
 */
function saveToDisk() {
  try {
    fs.writeFileSync(FAVORITES_FILE, JSON.stringify(favorites, null, 2), 'utf8');
  } catch (e) {
    console.error('[eSE Live] Failed to save favorites:', e.message);
  }
}

/**
 * Get all favorites.
 * @returns {Array} List of favorite channels.
 */
function getAll() {
  return favorites;
}

/**
 * Add a channel to favorites.
 * @param {Object} channel - Channel info {streamKey, title, category, language, broadcasterHash}
 * @returns {boolean} true if added, false if already exists
 */
function add(channel) {
  if (!channel || !channel.streamKey) return false;

  // Check if already exists
  const exists = favorites.some(f => f.streamKey === channel.streamKey);
  if (exists) return false;

  favorites.push({
    streamKey: channel.streamKey,
    title: channel.title || 'Sin titulo',
    category: channel.category || 'general',
    language: channel.language || 'es',
    broadcasterHash: channel.broadcasterHash || '',
    addedAt: new Date().toISOString(),
    lastSeen: null,
    lastOnline: false
  });

  saveToDisk();
  return true;
}

/**
 * Remove a channel from favorites.
 * @param {string} streamKey - Stream key to remove.
 * @returns {boolean} true if removed
 */
function remove(streamKey) {
  const before = favorites.length;
  favorites = favorites.filter(f => f.streamKey !== streamKey);
  if (favorites.length < before) {
    saveToDisk();
    return true;
  }
  return false;
}

/**
 * Check if a channel is in favorites.
 * @param {string} streamKey
 * @returns {boolean}
 */
function isFavorite(streamKey) {
  return favorites.some(f => f.streamKey === streamKey);
}

/**
 * Update the online status of a favorite.
 * @param {string} streamKey
 * @param {boolean} online
 */
function updateStatus(streamKey, online) {
  const fav = favorites.find(f => f.streamKey === streamKey);
  if (fav) {
    fav.lastSeen = new Date().toISOString();
    fav.lastOnline = online;
    saveToDisk();
  }
}

/**
 * Sync favorites from browser localStorage (merge).
 * @param {Array} browserFavs - Favorites from browser.
 * @returns {Array} Merged list.
 */
function syncFromBrowser(browserFavs) {
  if (!Array.isArray(browserFavs)) return favorites;

  for (const bf of browserFavs) {
    if (bf.streamKey && !isFavorite(bf.streamKey)) {
      add(bf);
    }
  }

  return favorites;
}

module.exports = { getAll, add, remove, isFavorite, updateStatus, syncFromBrowser };
