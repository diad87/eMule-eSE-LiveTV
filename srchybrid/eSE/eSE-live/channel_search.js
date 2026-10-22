/**
 * eSE Live — Channel Search
 * Bridge between C++/Kad channel discovery and webapp search.
 * Max ~200 lines.
 */
'use strict';

const rating = require('./channel_rating');
const pipeline = require('./ffmpeg_pipeline');

// In-memory view of channels polled from the C++ Kad/discovery backend.
let channels = {};

function normalizedKey(value) {
  return String(value || '').trim().toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function canonicalStreamKey(value) {
  return String(value || '').trim().toLowerCase();
}

function canonicalCategory(value) {
  const key = normalizedKey(value);
  const aliases = {
    general: 'general', sports: 'sports', sport: 'sports', deportes: 'sports',
    gaming: 'gaming', games: 'gaming', videojuegos: 'gaming',
    movies: 'movies', movie: 'movies', cine: 'movies', peliculas: 'movies',
    music: 'music', musica: 'music',
    education: 'education', educacion: 'education',
    talk: 'talk', talks: 'talk', charla: 'talk', charlas: 'talk', webcam: 'talk',
    '24/7': '24/7', '24h': '24/7', '24x7': '24/7'
  };
  return aliases[key] || key || 'general';
}

function canonicalLanguage(value) {
  const key = normalizedKey(value);
  const aliases = {
    es: 'es', espanol: 'es', spanish: 'es',
    en: 'en', ingles: 'en', english: 'en',
    fr: 'fr', frances: 'fr', francais: 'fr', french: 'fr',
    de: 'de', aleman: 'de', deutsch: 'de', german: 'de',
    pt: 'pt', portugues: 'pt', portuguese: 'pt'
  };
  return aliases[key] || key || 'es';
}

/**
 * Register a channel (called when broadcaster starts streaming).
 * @param {Object} info - Channel info
 */
function registerChannel(info) {
  if (!info || !info.streamKey) return;
  const streamKey = canonicalStreamKey(info.streamKey);
  if (!streamKey) return;

  // v7.1.9 — only one local broadcast at a time on this machine. Sweep any
  // stale isLocal entries (local_<ts>, obs_<ts>, external_<ts>, prior
  // streamKeys from earlier broadcasts) before inserting the new one.
  // Otherwise the local channel directory accumulates ghosts forever; the
  // search() pipeline-active flag is global, not per-streamKey, so it kept
  // every stale local entry visible.
  for (const k of Object.keys(channels)) {
    if (channels[k] && channels[k].isLocal && k !== streamKey) {
      delete channels[k];
    }
  }

  channels[streamKey] = {
    streamKey,
    title: info.title || 'Sin titulo',
    category: canonicalCategory(info.category),
    language: canonicalLanguage(info.language),
    bitrate: info.bitrate || 3000,
    viewers: info.viewers || 0,
    started: info.started || new Date().toISOString(),
    broadcasterHash: info.broadcasterHash || 'local',
    meshHealth: 100,
    reports: 0,
    broadcasterReputation: 100,
    isLocal: true,
    source: info.source || 'local',
    lastUpdate: Date.now()
  };
}

function syncEmuleChannels(items) {
  const list = Array.isArray(items) ? items : [];
  const liveKeys = new Set(list
    .map(item => canonicalStreamKey(item && item.streamKey))
    .filter(Boolean));
  for (const key of Object.keys(channels)) {
    if (channels[key] && channels[key].source === 'emule' && !liveKeys.has(key))
      delete channels[key];
  }
  for (const item of list)
    registerChannel({ ...item, source: 'emule' });
}

/**
 * Unregister a channel (called when broadcaster stops).
 * @param {string} streamKey
 */
function unregisterChannel(streamKey) {
  delete channels[canonicalStreamKey(streamKey)];
}

/**
 * Add a remote channel discovered via Kad (future).
 * @param {Object} info - Channel metadata from Kad DHT
 */
function addRemoteChannel(info) {
  if (!info || !info.streamKey) return;
  const streamKey = canonicalStreamKey(info.streamKey);
  if (!streamKey) return;
  const normalizedInfo = {
    ...info,
    streamKey,
    category: canonicalCategory(info.category),
    language: canonicalLanguage(info.language)
  };
  if (channels[streamKey]) {
    // v7.1.9 — preserve the original `started` across updates. The C++ Kad
    // side doesn't emit a stable start timestamp; each poll passed
    // new Date().toISOString() through, resetting uptime to "0min" on
    // every refresh. Honor the existing one if we already have it.
    const preserved = { lastUpdate: Date.now() };
    if (channels[streamKey].started) preserved.started = channels[streamKey].started;
    Object.assign(channels[streamKey], normalizedInfo, preserved);
  } else {
    channels[streamKey] = { ...normalizedInfo, isLocal: false, lastUpdate: Date.now() };
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

  return filterChannels(results, filters, now);
}

// Apply the same filters and ordering to a merged local/Kad directory without
// registering channels, pruning discovery state, or starting a media pipeline.
function filterChannels(items, filters, now = Date.now()) {
  const f = filters || {};
  let results = (Array.isArray(items) ? items : []).filter(ch => ch && typeof ch === 'object');

  // Text search
  if (f.query) {
    const q = normalizedKey(f.query);
    results = results.filter(ch =>
      normalizedKey(ch.title).includes(q) ||
      normalizedKey(ch.category).includes(q)
    );
  }

  // Category filter
  if (f.category && f.category !== 'all') {
    const category = canonicalCategory(f.category);
    results = results.filter(ch => canonicalCategory(ch.category) === category);
  }

  // Language filter
  if (f.language && f.language !== 'all') {
    const language = canonicalLanguage(f.language);
    results = results.filter(ch => canonicalLanguage(ch.language) === language);
  }

  // Quality filter
  if (f.quality) {
    const minBitrate = qualityToBitrate(f.quality);
    results = results.filter(ch => (ch.bitrate || 0) >= minBitrate);
  }

  // Calculate ratings
  results = results.map(ch => {
    const started = channelStartTime(ch);
    const uptimeMinutes = started ? Math.max(0, Math.floor((now - started) / 60000)) : 0;
    const r = rating.calculateRating({
      viewers: ch.viewers || 0,
      bitrate: ch.bitrate || 0,
      uptimeMinutes,
      meshHealth: ch.meshHealth || 50,
      reports: ch.reports || 0,
      broadcasterReputation: ch.broadcasterReputation || 50
    });

    return {
      ...ch,
      category: canonicalCategory(ch.category),
      language: canonicalLanguage(ch.language),
      rating: r.score,
      ratingBreakdown: r.breakdown,
      experience: r.experience,
      experienceEmoji: r.emoji,
      experienceBars: r.bars,
      qualityLabel: rating.qualityLabel(ch.bitrate || 0),
      uptimeMinutes
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
    results.sort((a, b) => channelStartTime(b) - channelStartTime(a));
  }

  return results;
}

function channelStartTime(channel) {
  const time = new Date(channel.started || (Number(channel.startedAt) * 1000) || 0).getTime();
  return Number.isFinite(time) && time > 0 ? time : 0;
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
  syncEmuleChannels,
  search,
  filterChannels,
  getCount,
  canonicalStreamKey,
  canonicalCategory,
  canonicalLanguage
};
