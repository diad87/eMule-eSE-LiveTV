/**
 * eSE Live — Channel Search
 * Bridge between Kad DHT channel discovery and webapp search.
 * For now uses local channel registry; will connect to Kad via C++ later.
 * Max ~200 lines.
 */
'use strict';

const rating = require('./channel_rating');
const pipeline = require('./ffmpeg_pipeline');

// Local channel registry (will be populated by Kad in Phase 4)
// For now, the local broadcaster's own stream is registered here
let channels = {};

/**
 * Register a channel (called when broadcaster starts streaming).
 * @param {Object} info - Channel info
 */
function registerChannel(info) {
  if (!info || !info.streamKey) return;

  channels[info.streamKey] = {
    streamKey: info.streamKey,
    title: info.title || 'Sin titulo',
    category: info.category || 'general',
    language: info.language || 'es',
    bitrate: info.bitrate || 3000,
    viewers: info.viewers || 0,
    started: info.started || new Date().toISOString(),
    broadcasterHash: info.broadcasterHash || 'local',
    meshHealth: 100,
    reports: 0,
    broadcasterReputation: 100,
    isLocal: true,
    lastUpdate: Date.now()
  };
}

/**
 * Unregister a channel (called when broadcaster stops).
 * @param {string} streamKey
 */
function unregisterChannel(streamKey) {
  delete channels[streamKey];
}

/**
 * Add a remote channel discovered via Kad (future).
 * @param {Object} info - Channel metadata from Kad DHT
 */
function addRemoteChannel(info) {
  if (!info || !info.streamKey) return;
  if (channels[info.streamKey]) {
    // Update existing
    Object.assign(channels[info.streamKey], info, { lastUpdate: Date.now() });
  } else {
    channels[info.streamKey] = { ...info, isLocal: false, lastUpdate: Date.now() };
  }
}

/**
 * Search channels with filters.
 * @param {Object} filters
 * @param {string} [filters.query] - Search title
 * @param {string} [filters.category] - Category filter
 * @param {string} [filters.language] - Language filter
 * @param {number} [filters.minRating] - Minimum rating (0-100)
 * @param {string} [filters.quality] - Minimum quality (SD, 480p, 720p, 1080p, 4K)
 * @param {string} [filters.sortBy] - Sort: 'rating', 'viewers', 'newest'
 * @returns {Array} Matching channels with rating info
 */
function search(filters) {
  const f = filters || {};
  let results = Object.values(channels);

  // Prune stale channels (no update in 5 min for remote, check pipeline/external for local)
  const now = Date.now();
  const pipeStatus = pipeline.getStatus().status;
  const pipelineActive = (pipeStatus === 'streaming' || pipeStatus === 'starting');
  // Also check if external ffmpeg is producing HLS segments (freshness, not just existence)
  const hlsDir = require('path').join(require('os').tmpdir(), 'eMule_RTMP');
  const STALE_MS = 15000;
  let externalActive = false;
  try {
    const fs = require('fs');
    const candidates = [
      require('path').join(hlsDir, 'stream_0.m3u8'),
      require('path').join(hlsDir, 'stream.m3u8')
    ];
    for (const c of candidates) {
      try {
        if ((Date.now() - fs.statSync(c).mtimeMs) < STALE_MS) { externalActive = true; break; }
      } catch (e) {}
    }
  } catch (e) {}
  const localActive = pipelineActive || externalActive;

  results = results.filter(ch => {
    if (ch.isLocal) {
      // Local channels: keep if pipeline or external stream is active
      if (!localActive) {
        delete channels[ch.streamKey];
        return false;
      }
      return true;
    }
    // Remote channels: 5 min staleness
    return (now - ch.lastUpdate) < 300000;
  });

  // Text search
  if (f.query) {
    const q = f.query.toLowerCase();
    results = results.filter(ch =>
      (ch.title || '').toLowerCase().includes(q) ||
      (ch.category || '').toLowerCase().includes(q)
    );
  }

  // Category filter
  if (f.category && f.category !== 'all') {
    results = results.filter(ch => ch.category === f.category);
  }

  // Language filter
  if (f.language && f.language !== 'all') {
    results = results.filter(ch => ch.language === f.language);
  }

  // Quality filter
  if (f.quality) {
    const minBitrate = qualityToBitrate(f.quality);
    results = results.filter(ch => (ch.bitrate || 0) >= minBitrate);
  }

  // Calculate ratings
  results = results.map(ch => {
    const r = rating.calculateRating({
      viewers: ch.viewers || 0,
      bitrate: ch.bitrate || 0,
      uptimeMinutes: Math.floor((now - new Date(ch.started).getTime()) / 60000),
      meshHealth: ch.meshHealth || 50,
      reports: ch.reports || 0,
      broadcasterReputation: ch.broadcasterReputation || 50
    });

    return {
      ...ch,
      rating: r.score,
      ratingBreakdown: r.breakdown,
      experience: r.experience,
      experienceEmoji: r.emoji,
      experienceBars: r.bars,
      qualityLabel: rating.qualityLabel(ch.bitrate || 0),
      uptimeMinutes: Math.floor((now - new Date(ch.started).getTime()) / 60000)
    };
  });

  // Min rating filter
  if (f.minRating) {
    results = results.filter(ch => ch.rating >= f.minRating);
  }

  // Sort
  const sortBy = f.sortBy || 'rating';
  if (sortBy === 'rating') {
    results.sort((a, b) => b.rating - a.rating);
  } else if (sortBy === 'viewers') {
    results.sort((a, b) => (b.viewers || 0) - (a.viewers || 0));
  } else if (sortBy === 'newest') {
    results.sort((a, b) => new Date(b.started) - new Date(a.started));
  }

  return results;
}

/**
 * Get count of active channels.
 */
function getCount() {
  return Object.keys(channels).length;
}

function qualityToBitrate(q) {
  const map = { 'SD': 0, '480p': 1500, '720p': 3000, '1080p': 5000, '4K': 8000 };
  return map[q] || 0;
}

module.exports = {
  registerChannel,
  unregisterChannel,
  addRemoteChannel,
  search,
  getCount
};
