/**
 * utils.js — Shared utility functions
 * ffmpeg detection, hardware encoder, formatting, settings management
 */
const fs = require('fs');
const path = require('path');

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

function bodyTooLargeError(limit) {
  const err = new Error('Request body exceeds ' + limit + ' bytes');
  err.code = 'BODY_TOO_LARGE';
  err.statusCode = 413;
  return err;
}

function readBodyLimited(req, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  const limit = Number.isSafeInteger(options.limit) && options.limit > 0
    ? options.limit
    : DEFAULT_MAX_BODY_BYTES;
  const declaredLength = Number(req.headers && req.headers['content-length']);
  let settled = false;
  let total = 0;
  const chunks = [];

  function cleanup() {
    req.removeListener('data', onData);
    req.removeListener('end', onEnd);
    req.removeListener('error', onError);
    req.removeListener('aborted', onAborted);
  }

  function finish(err, body) {
    if (settled) return;
    settled = true;
    cleanup();
    callback(err, body);
  }

  function rejectTooLarge() {
    if (settled) return;
    settled = true;
    cleanup();
    // Drain the socket so keep-alive connections remain usable. Suppress a
    // late stream error after the response callback has already completed.
    req.on('error', () => {});
    req.resume();
    callback(bodyTooLargeError(limit));
  }

  function onData(chunk) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > limit) return rejectTooLarge();
    chunks.push(buffer);
  }

  function onEnd() {
    finish(null, Buffer.concat(chunks, total).toString('utf8'));
  }

  function onError(err) {
    finish(err);
  }

  function onAborted() {
    const err = new Error('Request body aborted');
    err.code = 'REQUEST_ABORTED';
    finish(err);
  }

  if (Number.isFinite(declaredLength) && declaredLength > limit) {
    return process.nextTick(rejectTooLarge);
  }

  req.on('data', onData);
  req.on('end', onEnd);
  req.on('error', onError);
  req.on('aborted', onAborted);
}

// ─── FFMPEG ────────────────────────────────────────────────────

function findFileRecursive(dir, filename) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.toLowerCase() === filename.toLowerCase()) return fullPath;
      if (entry.isDirectory()) { const f = findFileRecursive(fullPath, filename); if (f) return f; }
    }
  } catch(e) {}
  return null;
}

function findFfmpeg() {
  // pkg's __dirname is a read-only snapshot; portable binaries live beside the executable.
  if (process.pkg) {
    const portable = path.join(path.dirname(process.execPath), 'ffmpeg.exe');
    if (fs.existsSync(portable)) return portable;
  }
  // 1. Look in the current user's WinGet packages (dynamic, cross-user)
  try {
    const userProfile = process.env.USERPROFILE || process.env.HOME || '';
    if (userProfile) {
      const wingetDir = path.join(userProfile, 'AppData', 'Local', 'Microsoft', 'WinGet', 'Packages');
      if (fs.existsSync(wingetDir)) {
        const found = findFileRecursive(wingetDir, 'ffmpeg.exe');
        if (found) return found;
      }
    }
  } catch(e) {}

  // 2. Look next to the server script (bundled ffmpeg in the package)
  try {
    const bundled = path.join(__dirname, 'ffmpeg' + '.exe');
    if (fs.existsSync(bundled)) return bundled;
  } catch(e) {}

  // 3. Look next to emule.exe in the portable package root.
  try {
    const bundledRoot = path.join(__dirname, '..', 'ffmpeg' + '.exe');
    if (fs.existsSync(bundledRoot)) return bundledRoot;
  } catch(e) {}

  // 4. Fallback: rely on system PATH
  return 'ffmpeg';
}

// ─── FORMATTING ────────────────────────────────────────────────

function fmtTime(s) {
  if (!s || !isFinite(s)) return '0:00';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return h > 0 ? h + ':' + String(m).padStart(2, '0') + ':' + String(sec).padStart(2, '0') : m + ':' + String(sec).padStart(2, '0');
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function cleanTitle(f) {
  let t = f.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i, '').replace(/\./g, ' ').replace(/_/g, ' ');
  t = t.replace(/[\(\[\{].*$/, '');
  t = t.replace(/\s+(19|20)\d{2}\s*.*$/, '');
  // Strip TV episode codes: S01E01, T01E01, 1x01, S01, E01, etc.
  t = t.replace(/\s+[Ss]\d{1,2}[Ee]\d{1,2}\b.*/i, '');
  t = t.replace(/\s+[Tt]\d{1,2}[Ee]\d{1,2}\b.*/i, '');
  t = t.replace(/\s+\d{1,2}[xX]\d{1,2}\b.*/i, '');
  t = t.replace(/\s+[Ss]\d{1,2}\b.*/i, '');
  t = t.replace(/\s+(BDrip|BluRay|HDRip|DVDRip|WEBRip|WEB-DL|HDTV|CAM|TS|720p|1080p|2160p|4K|HEVC|H264|H265|x264|x265|AAC|AC3|DTS|DUAL|MULTI|ESP|ENG|SPA|FRENCH|GERMAN|HDR|10b|10bit)\b.*/i, '');
  return t.replace(/\s*-\s*$/, '').trim();
}

function getBestMP4(partNum, tempDir) {
  for (const mb of [600, 300, 150, 90, 60, 30]) {
    const p = path.join(tempDir, 'ese_' + partNum + '_' + mb + '.mp4');
    if (fs.existsSync(p) && fs.statSync(p).size > 1000) return { path: p, mb };
  }
  return null;
}

// ─── PATH SAFETY ────────────────────────────────────────────────
//
// SECURITY: the server is publicly reachable via UPnP-opened port 8080 (the
// Cloudflare Quick Tunnel fallback was removed in v7.4.0). Any HTTP parameter
// that ends up in path.join() / path.resolve() must be sanitized before touching
// the filesystem or an attacker can read arbitrary files (CWE-22 Path Traversal).
//
// Use safeBasename() at the entry of every function that takes an external
// filename and uses it on disk. It strips directory components and rejects
// the input outright if it contained any path separator, drive prefix, NUL,
// or '..' segment — which is what we want for filenames coming over HTTP.
//
//   const safe = safeBasename(userFileName);
//   if (!safe) { res.writeHead(400); res.end('Bad file name'); return; }
//   const fullPath = path.join(BASE_DIR, safe);
//
// For defence-in-depth where you also have a known base directory, additionally
// resolve and verify with isPathWithin(fullPath, BASE_DIR).

function safeBasename(fileName) {
  if (typeof fileName !== 'string' || !fileName) return null;
  // NUL bytes can truncate paths in some legacy syscalls; reject outright.
  if (fileName.indexOf('\0') !== -1) return null;
  // Reject special directory names — these are valid basenames but represent
  // the current/parent directory and have no business being treated as files.
  // (path.basename('..') === '..', so the equality check below would let them
  //  through.) Also reject any sequence that is purely dots.
  if (/^\.+$/.test(fileName)) return null;
  // Strict reject anything that looks like a parent-dir hop or absolute path.
  // path.basename() alone would silently rewrite e.g. '../../etc/passwd' to
  // 'passwd' — that masks the attack rather than refusing it. We want a hard
  // 400 so callers can log/alert on attempted traversal.
  const base = path.basename(fileName);
  if (base !== fileName) return null;
  // Reject if it still contains separators or drive prefixes (Windows
  // 'C:foo.txt' is allowed by path.basename on POSIX but not what we want).
  if (/[\\\/]/.test(base) || /^[A-Za-z]:/.test(base)) return null;
  return base;
}

function isPathWithin(resolvedPath, baseDir) {
  const normalizedBase = path.resolve(baseDir) + path.sep;
  const normalizedTarget = path.resolve(resolvedPath);
  return normalizedTarget.startsWith(normalizedBase) || normalizedTarget === path.resolve(baseDir);
}

// ─── SETTINGS ──────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  quality: 'auto',
  language: 'spanish',
  searchMethod: 'server',
  minSizeMB: 300,
  emulePassword: '',
  autoPlay: true
};

function loadSettings(settingsFile) {
  try { return Object.assign({}, DEFAULT_SETTINGS, JSON.parse(fs.readFileSync(settingsFile, 'utf8'))); }
  catch(e) { return Object.assign({}, DEFAULT_SETTINGS); }
}

function saveSettings(s, settingsFile) {
  try { fs.writeFileSync(settingsFile, JSON.stringify(s, null, 2)); } catch(e) {}
}

module.exports = {
  findFfmpeg,
  findFileRecursive,
  fmtTime,
  escapeHtml,
  cleanTitle,
  getBestMP4,
  loadSettings,
  saveSettings,
  DEFAULT_SETTINGS,
  DEFAULT_MAX_BODY_BYTES,
  readBodyLimited,
  safeBasename,
  isPathWithin
};
