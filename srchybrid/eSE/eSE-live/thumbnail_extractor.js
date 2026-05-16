/**
 * eSE Live — Thumbnail Extractor
 * Periodically extracts a frame from active HLS streams using FFmpeg.
 * Stores thumbnails as JPEG files for the channel directory.
 */
'use strict';

const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const runtimeDir = require('../runtime_dir');

// Thumbnails MUST live in a writable location. In pkg-bundled mode
// __dirname is C:\snapshot\eSE\eSE-live which is read-only; runtimeDir
// returns %APPDATA%\eSE in that case (and __dirname in dev).
const THUMB_DIR = path.join(runtimeDir.get(), 'eSE-live', 'thumbs');
const EMULE_HLS_DIR = path.join(os.tmpdir(), 'eMule_RTMP');
const INTERVAL_MS = 20000; // Extract every 20 seconds
let timer = null;
let ffmpegPath = null;

// Ensure thumb directory exists
try { if (!fs.existsSync(THUMB_DIR)) fs.mkdirSync(THUMB_DIR, { recursive: true }); } catch (e) {}

/**
 * Start periodic thumbnail extraction.
 * @param {string} ffmpeg - Path to ffmpeg executable
 */
function start(ffmpeg) {
  ffmpegPath = ffmpeg;
  if (timer) return;
  console.log('[Thumbnails] Starting extractor (every', INTERVAL_MS / 1000, 's)');
  timer = setInterval(extractAll, INTERVAL_MS);
  // First extraction immediately
  setTimeout(extractAll, 2000);
}

function stop() {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

/**
 * Extract thumbnails from all active streams.
 */
function extractAll() {
  // 1. Extract from eMule broadcasts (local HLS files)
  extractFromEmuleHLS();
  
  // 2. Extract from Node.js live streams (local live dir)
  const liveDir = path.join(__dirname, 'live');
  if (fs.existsSync(liveDir)) {
    extractFromDir(liveDir, 'local');
  }
}

/**
 * Extract thumbnail from eMule's HLS output directory.
 */
function extractFromEmuleHLS() {
  if (!fs.existsSync(EMULE_HLS_DIR)) return;
  
  try {
    const files = fs.readdirSync(EMULE_HLS_DIR);
    
    // Find latest VIDEO .ts segment (seg_0_* or seg_video_*, not audio-only like seg_eng_/seg_spa_)
    const audioLangs = ['eng', 'spa', 'fre', 'ger', 'ita', 'por', 'jpn', 'kor', 'chi', 'rus', 'ara', 'und'];
    const allSegments = files.filter(f => f.endsWith('.ts')).sort().reverse();
    
    // Prefer video segments: seg_0_* or seg_video_* or plain seg_NNNNN.ts
    const videoSegments = allSegments.filter(s => {
      // Exclude audio-only segments
      for (const lang of audioLangs) {
        if (s.startsWith('seg_' + lang + '_')) return false;
      }
      return true;
    });
    
    const segments = videoSegments.length > 0 ? videoSegments : allSegments;
    if (segments.length === 0) return;
    
    const latestSeg = path.join(EMULE_HLS_DIR, segments[0]);
    // Skip stale segments (older than 60s = no active stream here)
    const age = Date.now() - fs.statSync(latestSeg).mtimeMs;
    if (age > 60000) return;

    // Always write the legacy 'emule_broadcast.jpg' for backwards-compat
    // fallback (used by getThumbPath when no per-key file exists).
    extractFrame(latestSeg, 'emule_broadcast');

    // ALSO write per-stream-key thumbnails so multiple discovered streams
    // each have their own image in the grid. Fetch the active broadcast
    // hash from the C++ /api/live/channels endpoint (best-effort, silent
    // on failure — extractor keeps working with the legacy file alone).
    fetchOwnStreamKey((streamKey) => {
      if (streamKey && /^[a-fA-F0-9]{32}$/.test(streamKey)) {
        extractFrame(latestSeg, streamKey.toLowerCase());
      }
    });
  } catch (e) {
    // Silent fail
  }
}

// Fetch the local broadcaster's stream hash from C++ side. Cached briefly
// so we don't fire an HTTP request every 20 s — the hash doesn't change
// during a broadcast.
let cachedHash = null;
let cachedHashAt = 0;
function fetchOwnStreamKey(cb) {
  const now = Date.now();
  if (cachedHash && (now - cachedHashAt) < 60000) {
    cb(cachedHash);
    return;
  }
  const http = require('http');
  const req = http.get('http://127.0.0.1:4711/api/live/channels', { timeout: 1500 }, (res) => {
    let body = '';
    res.on('data', (c) => body += c);
    res.on('end', () => {
      try {
        const json = JSON.parse(body);
        if (json && json.channels && json.channels.length > 0 && json.channels[0].hash) {
          cachedHash = json.channels[0].hash;
          cachedHashAt = now;
          cb(cachedHash);
        } else {
          cb(null);
        }
      } catch (_) { cb(null); }
    });
  });
  req.on('error', () => cb(null));
  req.on('timeout', () => { req.destroy(); cb(null); });
}

/**
 * Extract thumbnail from a directory containing HLS segments.
 * Skips if the newest segment is older than 60 seconds (stale).
 */
function extractFromDir(dir, prefix) {
  try {
    const files = fs.readdirSync(dir);
    const segments = files.filter(f => f.endsWith('.ts')).sort().reverse();
    if (segments.length === 0) return;
    const latest = path.join(dir, segments[0]);
    // Skip stale segments (older than 60s = no active stream here)
    const age = Date.now() - fs.statSync(latest).mtimeMs;
    if (age > 60000) return;
    extractFrame(latest, prefix);
  } catch (e) {}
}

/**
 * Extract a single frame from a .ts segment using FFmpeg.
 * @param {string} tsFile - Path to the .ts segment
 * @param {string} key - Thumbnail key name
 */
function extractFrame(tsFile, key) {
  if (!ffmpegPath || !fs.existsSync(tsFile)) return;
  
  // Check file size (skip empty segments)
  try {
    const stat = fs.statSync(tsFile);
    if (stat.size < 1000) return; // Skip tiny/empty segments
  } catch (e) { return; }
  
  const outFile = path.join(THUMB_DIR, key + '.jpg');
  const tempFile = path.join(THUMB_DIR, key + '_tmp.jpg');
  
  // FFmpeg: extract 1 frame at 1 second into the segment, scale to 320px wide
  const args = [
    '-y',                        // Overwrite
    '-loglevel', 'error',
    '-i', tsFile,                // Input: latest .ts segment
    '-vframes', '1',             // Just one frame
    '-ss', '0.5',                // Half second in (avoid black frame)
    '-vf', 'scale=384:-2',      // 384px wide, maintain aspect ratio
    '-q:v', '5',                 // JPEG quality (2=best, 31=worst)
    tempFile
  ];
  
  execFile(ffmpegPath, args, { timeout: 8000 }, (err, stdout, stderr) => {
    if (err) {
      console.log('[Thumbnails] FFmpeg error for', key, ':', err.message);
      if (stderr) console.log('[Thumbnails] stderr:', stderr.substring(0, 200));
      return;
    }
    // Atomic rename to avoid serving partial files
    try {
      if (fs.existsSync(tempFile)) {
        fs.renameSync(tempFile, outFile);
        console.log('[Thumbnails] Extracted:', key + '.jpg', '(' + Math.round(fs.statSync(outFile).size / 1024) + ' KB)');
      }
    } catch (e) {
      console.log('[Thumbnails] Rename error:', e.message);
    }
  });
}

/**
 * Get the thumbnail path for a channel hash.
 * @param {string} hash - Channel hash or key
 * @returns {string|null} Path to thumbnail file, or null
 */
function getThumbPath(hash) {
  // Try exact hash match first
  const exact = path.join(THUMB_DIR, hash + '.jpg');
  if (fs.existsSync(exact)) return exact;
  
  // Pick the most recently modified between emule_broadcast and local
  const candidates = [
    path.join(THUMB_DIR, 'emule_broadcast.jpg'),
    path.join(THUMB_DIR, 'local.jpg')
  ].filter(f => fs.existsSync(f));
  
  if (candidates.length === 0) return null;
  if (candidates.length === 1) return candidates[0];
  
  // Return the freshest one
  const stats = candidates.map(f => ({ path: f, mtime: fs.statSync(f).mtimeMs }));
  stats.sort((a, b) => b.mtime - a.mtime);
  return stats[0].path;
}

/**
 * Get thumbnail directory path.
 */
function getThumbDir() {
  return THUMB_DIR;
}

module.exports = { start, stop, getThumbPath, getThumbDir, extractAll };
