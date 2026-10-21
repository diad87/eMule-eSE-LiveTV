/**
 * emule_api.js — eMule WebServer integration
 * Handles: login, session management, search, download, password detection
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { runFile } = require('./bounded_process');

// ─── EMULE PROCESS WATCHDOG ────────────────────────────────────
let _emuleExePath = null;

function getEmuleExePath() {
  if (_emuleExePath) return _emuleExePath;
  // Same folder as server.js
  const localPath = path.join(__dirname, 'emule' + '.exe');
  if (fs.existsSync(localPath)) { _emuleExePath = localPath; return localPath; }
  // Fallback: known build path
  const buildPath = path.join(
    __dirname, '..', '..', 'srchybrid', 'x64', 'Release', 'emule' + '.exe');
  const abs = path.resolve(buildPath);
  if (fs.existsSync(abs)) { _emuleExePath = abs; return abs; }
  return null;
}

function isEmuleRunning() {
  return _emuleWasAlive;
}

async function probeEmuleRunning() {
  try {
    const result = await runFile(
      'tasklist',
      ['/FI', 'IMAGENAME eq emule.exe', '/NH', '/FO', 'CSV'],
      { timeoutMs: 3000, maxOutputBytes: 256 * 1024 }
    );
    return result.stdout.includes('emule.exe');
  } catch(e) { return false; }
}

function ensureEmuleRunning() {
  if (_emuleWasAlive) return true;
  const exe = getEmuleExePath();
  if (!exe) { console.log('[eMule] ⚠ Cannot find emule.exe to auto-restart'); return false; }
  console.log('[eMule] 🔄 Process not found — auto-restarting: ' + exe);
  try {
    const child = spawn(exe, [], { detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
    return true;
  } catch(e) {
    console.log('[eMule] ❌ Failed to restart emule.exe:', e.message);
    return false;
  }
}

// ─── LIFECYCLE WATCHDOG ─────────────────────────────────────────────────────
// Kills FFmpeg orphans launched by eMule when eMule dies.
// eMule spawns ffmpeg.exe from its install folder (e.g. C:\Program Files (x86)\eMule\ffmpeg.exe)
// and does NOT kill it on exit. This watchdog cleans up every 10s.
//
// v7.4.0 — also tracks revival: when eMule transitions dead→alive, we bump a
// monotonic library epoch (in-memory, NOT persisted to disk — front-end
// detects epoch=0 on cold-start and refreshes naturally) and notify handlers
// registered with onRevived(). Used by smart_play.js to know when a stale
// .part file is still playable from a fresh eMule process.
let _emuleWasAlive = false;
let _emuleRestartedAt = 0;     // ms epoch when alive last flipped false→true
let _emuleLibraryEpoch = 0;    // monotonic counter — NOT persisted
const _onEmuleRevivedHandlers = [];
function onRevived(handler) {
  if (typeof handler === 'function') _onEmuleRevivedHandlers.push(handler);
}
function getLibraryEpoch() { return _emuleLibraryEpoch; }
function getRestartedAt()  { return _emuleRestartedAt; }

async function killEmuleFFmpegOrphans() {
  try {
    const result = await runFile(
      'wmic',
      ['process', 'where', 'name="ffmpeg.exe"', 'get', 'ProcessId,ExecutablePath', '/format:csv'],
      { timeoutMs: 4000, maxOutputBytes: 1024 * 1024 }
    );
    if (!result.stdout) return;
    const lines = result.stdout.split('\n').filter(l => l.includes('ffmpeg.exe'));
    await Promise.all(lines.map(async line => {
      const parts = line.trim().split(',');
      const exePath = (parts[1] || '').toLowerCase();
      const pid = parseInt(parts[2] || parts[1], 10);
      if (!pid || Number.isNaN(pid)) return;
      if (exePath.includes('emule') && exePath.includes('ffmpeg.exe')) {
        try {
          await runFile('taskkill', ['/F', '/PID', String(pid)], {
            timeoutMs: 3000,
            maxOutputBytes: 256 * 1024
          });
          console.log('[eMule] Killed orphan FFmpeg PID:', pid, 'path:', exePath);
        } catch(e) {}
      }
    }));
  } catch(e) {}
}

// Watchdog: check every 10s. On dead→alive, bump epoch and notify handlers.
// On alive→dead, kill orphan ffmpeg children.
let _watchdogRunning = false;
async function refreshEmuleLifecycle(emitTransitions = true) {
  if (_watchdogRunning) return;
  _watchdogRunning = true;
  try {
    const alive = await probeEmuleRunning();
    if (emitTransitions && _emuleWasAlive && !alive) {
      console.log('[eMule] Process died — cleaning up orphan FFmpeg broadcasts...');
      void killEmuleFFmpegOrphans();
      emuleSession = null;
    } else if (emitTransitions && !_emuleWasAlive && alive) {
      _emuleRestartedAt = Date.now();
      _emuleLibraryEpoch++;
      console.log('[eMule] Process back online (epoch=' + _emuleLibraryEpoch + ')');
      for (const handler of _onEmuleRevivedHandlers) {
        try { handler(_emuleLibraryEpoch); }
        catch(e) { console.warn('[watchdog] revived handler error:', e.message); }
      }
    }
    _emuleWasAlive = alive;
  } finally {
    _watchdogRunning = false;
  }
}
// Isolated dashboard tests must not enumerate or clean up user processes.
// Ordinary dashboard lifecycle monitoring is unchanged.
if (process.env.ESE_TEST_MODE !== '1') {
  setInterval(() => { void refreshEmuleLifecycle(true); }, 10000);
  void refreshEmuleLifecycle(false);
}

const zlib = require('zlib');

const EMULE_WS_PORT = require('./emule_web_port').resolveWebPort(process.env);
if (process.env.ESE_TEST_MODE === '1') console.log('[eMule test] WebUI port=' + EMULE_WS_PORT);

let emuleSession = null;
let emulePassword = null;
let loginFlight = null;
let authStatus = { reason: 'not_connected', message: 'eSE aún no ha iniciado sesión en eMule.' };
let autoLoginTimer = null;
let autoLoginRetryAt = 0;
let autoLoginRunning = false;
let autoLoginGeneration = 0;
let autoLoginStopped = null;

// ─── SEARCH-RESULT METADATA CACHE ──────────────────────────────
// Maps ed2k hash → { name, size } for every result eMule has ever returned to
// us. This is the Node process's OWN memory of what was found, INDEPENDENT of
// eMule's volatile in-app search list.
//
// Why this exists: eMule's `w=search&downloads=<hash>` command only works while
// <hash> is still present in eMule's current search results. But SmartSearch
// runs several query variants back-to-back, and every new `tosearch` wipes the
// previous results (WEBGUIIA_DELETEALLSEARCHES). So by the time the user picks a
// source, its hash is usually gone from eMule's list → the download silently
// never starts (AddFileToDownloadByHash is a no-op on a miss). Symptom: the UI
// sits on "Esperando que eMule reciba datos…" until it gives up.
//
// With this cache we can rebuild the full ed2k link (name+exact size+hash) and
// add it via `w=transfer&ed2k=<link>`, which does NOT depend on the search list.
const _resultMetaCache = new Map();   // HASH(upper) → { name, size }
const _RESULT_META_CACHE_MAX = 4000;  // hard cap; oldest entries evicted (LRU-ish)

function cacheResultMeta(hash, name, size) {
  const key = String(hash || '').toUpperCase();
  if (!/^[A-F0-9]{32}$/.test(key) || !size || size <= 0) return;
  if (_resultMetaCache.has(key)) _resultMetaCache.delete(key); // refresh recency
  _resultMetaCache.set(key, { name: name || '', size });
  if (_resultMetaCache.size > _RESULT_META_CACHE_MAX) {
    _resultMetaCache.delete(_resultMetaCache.keys().next().value); // evict oldest
  }
}

// Build a canonical ed2k link from parts. The name is URL-encoded so eMule's
// CED2KFileLink (which URLDecodes it back) reconstructs it exactly, including
// Unicode. encodeURIComponent also escapes '|', keeping the link tokenizable.
function buildEd2kLink(name, size, hash) {
  const encName = encodeURIComponent(String(name || hash));
  return 'ed2k://|file|' + encName + '|' + size + '|' + String(hash).toUpperCase() + '|/';
}

// External dependency: settings (injected)
let _loadSettings = () => ({});
let _saveSettings = () => {};
let configuredPasswordInitialized = false;

function setSettingsFunctions(load, save) {
  _loadSettings = load;
  _saveSettings = save;
  // Seed before routes accept Settings saves, not on a delayed first login.
  getConfiguredPassword();
}

// ─── HTTP REQUEST ──────────────────────────────────────────────

function emuleRequest(urlPath, callback) {
  // Use the IPv4 literal explicitly. On Windows, `localhost` resolves to ::1
  // first (IPv6); eMule's WebServer binds INADDR_ANY (IPv4-only, see
  // WebSocket.cpp:449). Node 18 doesn't auto-fall-back to IPv4, so a
  // `localhost` request hits ::1, fails ECONNREFUSED, and the UI shows
  // "eMule WebServer no responde" even when the WebServer is fully up.
  const fullUrl = 'http://127.0.0.1:' + EMULE_WS_PORT + '/' + urlPath;
  const urlObj = new URL(fullUrl);
  
  const options = {
    hostname: urlObj.hostname,
    port: urlObj.port,
    path: urlObj.pathname + urlObj.search,
    headers: { 'Accept-Encoding': 'gzip, deflate, identity' }
  };
  
  let settled = false;
  let request;
  const finish = (error, html, metadata) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
    callback(error, html, metadata);
  };
  const deadline = setTimeout(() => {
    const error = new Error('eMule WebServer agotó el tiempo de respuesta.');
    error.code = 'ETIMEDOUT';
    finish(error, null);
    if (request) request.destroy();
  }, 10000);
  try { request = http.get(options, (res) => {
    const chunks = [];
    const encoding = res.headers['content-encoding'];
    let stream = res;
    if (encoding === 'gzip') stream = res.pipe(zlib.createGunzip());
    else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());
    
    stream.on('data', d => { if (!settled) chunks.push(d); });
    stream.on('end', () => {
      if (settled) return;
      const metadata = { statusCode: res.statusCode || 200 };
      if (metadata.statusCode >= 400) {
        const error = new Error('eMule WebServer respondió HTTP ' + metadata.statusCode + '.');
        error.code = 'EHTTPSTATUS'; error.statusCode = metadata.statusCode;
        finish(error, null, metadata);
        return;
      }
      const buf = Buffer.concat(chunks);
      finish(null, buf.toString('latin1'), metadata);
    });
    stream.on('error', error => finish(error, null));
    res.on('aborted', () => {
      const error = new Error('eMule WebServer interrumpió la respuesta.');
      error.code = 'ECONNRESET'; finish(error, null);
    });
  });
    request.on('error', error => finish(error, null));
  } catch (error) { finish(error, null); }
}

// ─── PASSWORD (unique per-installation, zero-config) ──────────
//
// Initial priority order:
//   1. ESE_EMULE_PASSWORD env var — set by emule.exe when the user clicks the
//      eSE toolbar button. emule.exe also calls SetWSPass with the same value
//      in-memory, so login is guaranteed to work without restart.
//   2. settings.json `emulePassword` — persisted from a previous run.
// Seed from the environment once. Later settings changes must survive resync,
// because a running process retains its original environment after a password
// is explicitly corrected in Settings.
// A standalone launch cannot change the running eMule password. If neither
// source exists, report missing credentials instead of generating a mismatch.

function usablePassword(value) {
  return typeof value === 'string' && value.length > 0 && value !== '********';
}
function getConfiguredPassword() {
  const s = _loadSettings();
  if (!configuredPasswordInitialized) {
    configuredPasswordInitialized = true;
    const envPw = process.env.ESE_EMULE_PASSWORD;
    if (usablePassword(envPw)) {
      if (s.emulePassword !== envPw) {
        s.emulePassword = envPw;
        _saveSettings(s);
      }
      return envPw;
    }
  }
  return usablePassword(s.emulePassword) ? s.emulePassword : null;
}

// ─── LOGIN ─────────────────────────────────────────────────────

function authenticationError(reason, message, retryable = false) {
  const error = new Error(message);
  error.reason = reason; error.retryable = retryable;
  return error;
}
function cancelAutoLoginRetry() {
  if (autoLoginTimer !== null) clearTimeout(autoLoginTimer);
  autoLoginTimer = null; autoLoginRetryAt = 0;
  autoLoginGeneration++;
}
function emuleLogin(password, callback) {
  // Resolve the initial environment even for an explicit first login, so a
  // subsequent Settings save cannot be overwritten by a delayed first resync.
  const configuredPassword = getConfiguredPassword();
  const pw = usablePassword(password) ? password : configuredPassword;
  if (loginFlight) {
    if (pw === loginFlight.password) loginFlight.callbacks.push(callback);
    else callback(authenticationError('login_in_progress', 'Ya se está comprobando la conexión. Inténtalo de nuevo cuando termine.'));
    return;
  }
  cancelAutoLoginRetry();
  autoLoginStopped = null;
  if (!pw) {
    const error = authenticationError('password_missing', 'Falta la contraseña del WebServer de eMule. Configúrala en Ajustes o abre eSE desde eMule.');
    emuleSession = null; emulePassword = null;
    authStatus = { reason: error.reason, message: error.message };
    callback(error);
    return;
  }
  const flight = loginFlight = { password: pw, callbacks: [callback] };
  authStatus = { reason: 'connecting', message: 'Comprobando la conexión con eMule…' };
  emuleRequest('?w=password&p=' + encodeURIComponent(pw), (err, html) => {
    let error = err, session = null;
    if (err) {
      if (err.code === 'ETIMEDOUT') error = authenticationError('login_timeout', 'eMule no respondió a tiempo. Se volverá a comprobar la conexión.', true);
      else if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH'].includes(err.code)) error = authenticationError('webserver_down', 'El WebServer de eMule no está disponible en el puerto 4711.', true);
      else if (err.code === 'EHTTPSTATUS') error = authenticationError('webserver_http_error', 'eMule WebServer respondió HTTP ' + err.statusCode + '.', err.statusCode >= 500);
      else error = authenticationError('webserver_response_error', 'No se pudo leer la respuesta del WebServer de eMule.');
    } else {
      const sesMatch = html && html.match(/[?&]ses=(\d+)\b/);
      if (sesMatch && Number(sesMatch[1]) > 0) session = sesMatch[1];
      else if (/access\s+denied|acceso\s+denegado|zugriff\s+verweigert|accès\s+refusé/i.test(html || '')) error = authenticationError('access_denied', 'eMule ha bloqueado temporalmente el acceso. Espera antes de reintentar y comprueba la contraseña.');
      else if (/w=password|name\s*=\s*["'](?:p|password)["']|name\s*=\s*["']w["'][^>]*value\s*=\s*["']password["']/i.test(html || '')) error = authenticationError('password_mismatch', 'eMule rechazó la contraseña. Corrígela en Ajustes; no se reintentará automáticamente.');
      else error = authenticationError('invalid_login_response', 'eMule respondió sin una sesión válida. Comprueba el WebServer antes de reintentar.');
    }
    loginFlight = null;
    emuleSession = session;
    emulePassword = session ? pw : null;
    authStatus = { reason: error ? error.reason : null, message: error ? error.message : 'Conectado a eMule WebServer.' };
    if (session) _autoLoginAttempts = 0;
    for (const done of flight.callbacks) done(error, session);
  });
}

// BUG-051 FIX: retry limit + exponential backoff
var _autoLoginAttempts = 0;
var _autoLoginMaxRetries = 5;
var _autoLoginBaseDelay = 10000;

function autoLoginEmule() {
  if (autoLoginRunning || autoLoginTimer !== null) return;
  const pw = getConfiguredPassword();
  if (autoLoginStopped && autoLoginStopped.password === pw && autoLoginStopped.epoch === _emuleLibraryEpoch) return;
  _autoLoginAttempts = 0;
  runAutoLoginAttempt();
}
function runAutoLoginAttempt() {
  autoLoginRunning = true;
  _autoLoginAttempts++;
  const pw = getConfiguredPassword();
  emuleLogin(pw, (err, session) => {
    autoLoginRunning = false;
    if (!err && session) {
      _autoLoginAttempts = 0;
      console.log('[eMule] Logged in');
    } else {
      if (!err || !err.retryable) {
        autoLoginStopped = { password: pw, epoch: _emuleLibraryEpoch };
        console.warn('[eMule] Login stopped: ' + (err && err.reason || 'invalid_login_response'));
        return;
      }
      if (_autoLoginAttempts >= _autoLoginMaxRetries) {
        autoLoginStopped = { password: pw, epoch: _emuleLibraryEpoch };
        console.error('[eMule] Login stopped after ' + _autoLoginMaxRetries + ' attempts: ' + err.reason);
        return;
      }
      var delay = Math.min(_autoLoginBaseDelay * Math.pow(2, _autoLoginAttempts - 1), 300000);
      console.log('[eMule] Login unavailable (' + err.reason + ', attempt ' + _autoLoginAttempts + '/' + _autoLoginMaxRetries + '). Retrying in ' + (delay/1000) + 's...');
      autoLoginRetryAt = Date.now() + delay;
      const generation = autoLoginGeneration;
      autoLoginTimer = setTimeout(() => {
        if (generation !== autoLoginGeneration) return;
        autoLoginTimer = null; autoLoginRetryAt = 0; runAutoLoginAttempt();
      }, delay);
    }
  });
}

function ensureEmuleSession(onReady, query, settings, callback) {
  if (!emuleSession) {
    console.log('[eMule] No session — logging in...');
    autoLoginAndRetry(query, settings, callback);
    return;
  }
  emuleRequest('?ses=' + emuleSession + '&w=transfer', (err, html) => {
    if (err || !html || html.includes('w=password') || html.length < 200) {
      console.log('[eMule] ⚠ Session ' + emuleSession + ' is dead. Re-logging in...');
      emuleSession = null;
      autoLoginAndRetry(query, settings, callback);
    } else {
      onReady();
    }
  });
}

function autoLoginAndRetry(query, settings, callback) {
  const pw = getConfiguredPassword();
  emuleLogin(pw, (err, session) => {
    if (err) {
      console.log('[eMule] ❌ Auto-relogin failed');
      callback(new Error('eMule login failed'), []);
    } else {
      emulePassword = pw;
      console.log('[eMule] Re-logged in');
      emuleSearch(query, settings, callback);
    }
  });
}

// ─── SEARCH ────────────────────────────────────────────────────

function emuleSearch(query, settings, callback) {
  const doSearch = () => {
    if (!emuleSession) { callback(new Error('Not logged in')); return; }
    const s = settings || _loadSettings();
    
    let searchQuery = query;
    if (s.quality && s.quality !== 'auto') {
      searchQuery += ' ' + (s.quality === '4k' ? '2160p' : s.quality);
    }
    
    const method = s.searchMethod === 'global' ? 'global' : (s.searchMethod === 'server' ? '' : 'kademlia');
    
    let safeSearchQuery = searchQuery;

    const searchUrl = '?ses=' + emuleSession + '&w=search&tosearch=' + encodeURIComponent(safeSearchQuery) + '&type=Video' + (method ? '&method=' + method : '');
    
    console.log('[eMule] Starting new search: "' + searchQuery + '" -> safe: "' + safeSearchQuery + '" method=' + (method || 'server'));
    console.log('[eMule] EXACT URI: ' + searchUrl);
    
    emuleRequest(searchUrl, (err2, html) => {
      if (err2) { callback(err2, []); return; }
      
      if (html.includes('w=password') || html.includes('Login') && !html.includes('tosearch')) {
        console.log('[eMule] ⚠ Session expired during search! Re-logging in...');
        emuleSession = null;
        autoLoginAndRetry(query, settings, callback);
        return;
      }
      
      const immediateResults = parseEmuleSearchResults(html, s, query);
      if (immediateResults.length > 0) {
        console.log('[eMule] Found ' + immediateResults.length + ' results in immediate response');
        callback(null, immediateResults);
        return;
      }
      
      let attempt = 0;
      const maxAttempts = 5;   // Reduced: less hammering on WebServer
      const pollInterval = 6000; // Increased: give eMule more breathing room
      
      const poll = () => {
        // Abort if eMule died during polling
        if (!isEmuleRunning()) {
          console.log('[eMule] ⚠ eMule died during search poll — aborting');
          ensureEmuleRunning(); // Try to restart it
          callback(new Error('eMule process died during search'), []);
          return;
        }
        attempt++;
        emuleRequest('?ses=' + emuleSession + '&w=search', (err3, html2) => {
          if (err3) { callback(err3, []); return; }
          if (html2.includes('w=password')) {
            emuleSession = null;
            autoLoginAndRetry(query, settings, callback);
            return;
          }
          
          const results = parseEmuleSearchResults(html2, s, query);
          const ed2kCount = (html2.match(/ed2k:\/\//g) || []).length;
          console.log('[eMule] Poll ' + attempt + ': ed2k=' + ed2kCount + ' parsed=' + results.length);
          
          if (results.length > 0 || attempt >= maxAttempts) {
            callback(null, results);
          } else {
            setTimeout(poll, pollInterval);
          }
        });
      };
      setTimeout(poll, 3000);
    });
  };
  ensureEmuleSession(doSearch, query, settings, callback);
}

// ─── SEARCH RESULT PARSING ─────────────────────────────────────

function parseEmuleSearchResults(html, settings, searchQuery) {
  const results = [];
  
  const ed2kRegex = /ed2k:\/\/\|file\|([^|]+)\|(\d+)\|([A-Fa-f0-9]{32})\|/gi;
  const ed2kMap = {};
  let ed2kMatch;
  while ((ed2kMatch = ed2kRegex.exec(html)) !== null) {
    const fileName = decodeURIComponent(ed2kMatch[1].replace(/\+/g, ' '));
    const fileSize = parseInt(ed2kMatch[2]);
    const hash = ed2kMatch[3];
    ed2kMap[hash.toUpperCase()] = { fileName, fileSize, hash };
  }
  
  const checkboxRegex = /value="([A-Fa-f0-9]{32})"/gi;
  let cbMatch;
  while ((cbMatch = checkboxRegex.exec(html)) !== null) {
    const hash = cbMatch[1].toUpperCase();
    if (!ed2kMap[hash]) ed2kMap[hash] = { hash: cbMatch[1] };
  }
  
  const srcRegex = /(\d+)\((\d+)\)/g;
  const srcData = [];
  let srcMatch;
  while ((srcMatch = srcRegex.exec(html)) !== null) {
    srcData.push({ sources: parseInt(srcMatch[1]), complete: parseInt(srcMatch[2]) });
  }
  
  const sizeRegex = /([\d.,]+)\s*(GB|MB|KB|Bytes)/gi;
  const sizeData = [];
  let sizeMatch;
  while ((sizeMatch = sizeRegex.exec(html)) !== null) {
    let sizeMB = parseFloat(sizeMatch[1].replace(',', '.'));
    const unit = sizeMatch[2].toUpperCase();
    if (unit === 'GB') sizeMB *= 1024;
    else if (unit === 'KB') sizeMB /= 1024;
    else if (unit === 'BYTES') sizeMB /= (1024 * 1024);
    sizeData.push({ sizeMB });
  }
  
  let srcIdx = 0, sizeIdx = 0;
  for (const hash in ed2kMap) {
    const entry = ed2kMap[hash];
    if (!entry.fileName) continue;
    
    let sources = 0, completeSources = 0;
    if (srcIdx < srcData.length) { sources = srcData[srcIdx].sources; completeSources = srcData[srcIdx].complete; srcIdx++; }
    
    let sizeMB = entry.fileSize ? Math.round(entry.fileSize / (1024 * 1024)) : 0;
    if (sizeMB === 0 && sizeIdx < sizeData.length) { sizeMB = Math.round(sizeData[sizeIdx].sizeMB); sizeIdx++; }
    
    // Remember this file's exact metadata regardless of score — a later
    // /api/emule/download by hash needs the exact byte size to build a valid
    // ed2k link, and eMule's own search list may no longer hold it by then.
    cacheResultMeta(entry.hash || hash, entry.fileName, entry.fileSize);

    const score = scoreResult(entry.fileName, sizeMB, sources, completeSources, settings, searchQuery);
    if (score > -900) {
      results.push({
        fileName: entry.fileName, sizeMB, sizeBytes: entry.fileSize || 0,
        sources, completeSources,
        hash: entry.hash || hash, score,
        quality: detectQuality(entry.fileName),
        language: detectLanguage(entry.fileName),
        isFake: score < -100   // Threshold raised: only obvious fakes get the label
      });
    }
  }
  
  results.sort((a, b) => b.score - a.score);
  return results;
}

// ─── SCORING & DETECTION ───────────────────────────────────────

function scoreResult(fileName, sizeMB, sources, completeSources, settings, searchQuery) {
  let score = 0;
  const fn = fileName.toLowerCase();
  const s = settings || _loadSettings();
  const query = (searchQuery || '').toLowerCase().trim();
  
  // Anti-fake
  if (fn.match(/\.(rar|zip|exe|iso|bat|cmd|scr|com|dll|msi)$/)) return -999;
  if (fn.includes('password') || fn.includes('protected') || fn.includes('contraseña')) return -999;
  
  // Title relevance
  if (query) {
    const queryWords = query.split(/\s+/).filter(w => w.length > 2);
    let titleMatchCount = 0;
    queryWords.forEach(w => { if (fn.includes(w)) titleMatchCount++; });
    const titleMatchRatio = queryWords.length > 0 ? titleMatchCount / queryWords.length : 0;
    if (titleMatchRatio < 0.3) return -999;
    if (titleMatchRatio < 0.5) score -= 80;
    else if (titleMatchRatio >= 0.8) score += 30;
    else score += 10;
  }
  
  // Fake patterns
  const fakePatterns = ['pack', 'collection', 'discografia', 'discography', 'temporada completa',
    'serie completa', 'coleccion', 'mega pack', 'xxx', 'porn', 'adulto',
    'keygen', 'crack', 'patch', 'serial', 'activator', 'loader'];
  for (const pat of fakePatterns) { if (fn.includes(pat)) score -= 100; }
  
  if (fn.includes('sample') && sizeMB < 100) return -999;
  if (fn.includes('trailer') && sizeMB < 200) score -= 80;
  if (fn.includes('teaser')) score -= 80;
  if (sizeMB > 0 && sizeMB < 50) return -999;
  if (sizeMB > 0 && sizeMB < s.minSizeMB) score -= 60;
  // Sources penalty — calibrated: low sources on a large file is NOT a fake indicator.
  // A 4GB BDRip with 0 complete sources is just a rare file, not a virus.
  if (completeSources === 0) {
    if (sizeMB > 500)       score -= 20;  // Large file + no complete: mild penalty
    else if (sizeMB > 100)  score -= 60;  // Medium file: moderate penalty
    else                    score -= 120; // Small file with no sources: suspicious
  }
  if (completeSources < 1 && completeSources > 0) score -= 20; // partial sources, minor
  
  // Positive scoring
  score += Math.min(sources, 30) * 2;
  score += Math.min(completeSources, 15) * 5;
  
  const quality = detectQuality(fn);
  if (s.quality === 'auto') {
    if (quality === '4k') score += 35;
    else if (quality === '1080p') score += 30;
    else if (quality === '720p') score += 15;
    else if (quality === '480p') score += 5;
  } else {
    if (quality === s.quality) score += 50;
    const qOrder = { '480p': 1, '720p': 2, '1080p': 3, '4k': 4 };
    if (qOrder[quality] > (qOrder[s.quality] || 0)) score += 20;
  }
  
  if (quality === '4k' && sizeMB > 10000) score += 15;
  else if (quality === '4k' && sizeMB < 3000) score -= 30;
  if (quality === '1080p' && sizeMB > 2000 && sizeMB < 25000) score += 15;
  else if (quality === '1080p' && sizeMB < 700) score -= 30;
  if (quality === '720p' && sizeMB > 700 && sizeMB < 6000) score += 10;
  
  const lang = detectLanguage(fn);
  if (lang === s.language) score += 40;
  
  if (fn.endsWith('.mkv')) score += 8;
  if (fn.endsWith('.mp4')) score += 7;
  if (fn.endsWith('.avi')) score += 3;
  if (fn.endsWith('.wmv')) score -= 5;
  
  if (fn.includes('x264') || fn.includes('h264') || fn.includes('h.264') || fn.includes('avc')) score += 25;
  if (fn.includes('x265') || fn.includes('h265') || fn.includes('h.265') || fn.includes('hevc')) score += 20;
  if (fn.includes('xvid') || fn.includes('divx')) score -= 15;
  
  if (fn.includes('bluray') || fn.includes('blu-ray') || fn.includes('bdrip')) score += 15;
  if (fn.includes('remux')) score += 20;
  if (fn.includes('web-dl') || fn.includes('webdl') || fn.includes('webrip')) score += 10;
  if (fn.includes('hdtv')) score += 5;
  if (fn.includes('cam') || fn.includes('ts ') || fn.includes('telesync') || fn.includes('telecine')) score -= 40;
  if (fn.includes('screener') || fn.includes('scr ')) score -= 30;
  
  if (fn.includes('dts') || fn.includes('truehd') || fn.includes('atmos')) score += 10;
  if (fn.includes('aac')) score += 12;
  if (fn.includes('ac3') || fn.includes('eac3')) score += 5;
  if (fn.includes('mp3')) score -= 5;
  
  return score;
}

function detectQuality(fileName) {
  const fn = fileName.toLowerCase();
  if (fn.includes('2160p') || fn.includes('4k') || fn.includes('uhd')) return '4k';
  if (fn.includes('1080p') || fn.includes('fullhd') || fn.includes('full hd')) return '1080p';
  if (fn.includes('720p') || fn.includes('hd ')) return '720p';
  if (fn.includes('480p') || fn.includes('dvdrip')) return '480p';
  return 'unknown';
}

function detectLanguage(fileName) {
  const fn = fileName.toLowerCase();
  if (fn.includes('spanish') || fn.includes('español') || fn.includes('castellano') || fn.includes('spa')) return 'spanish';
  if (fn.includes('latino') || fn.includes('lat')) return 'latino';
  if (fn.includes('english') || fn.includes('eng') || fn.includes('en ')) return 'english';
  if (fn.includes('french') || fn.includes('fra') || fn.includes('français')) return 'french';
  if (fn.includes('german') || fn.includes('ger') || fn.includes('deu') || fn.includes('deutsch')) return 'german';
  return 'unknown';
}

// ─── DOWNLOAD ──────────────────────────────────────────────────

function emuleDownload(hash, callback, meta) {
  if (!emuleSession) { callback(new Error('Not logged in')); return; }
  const key = String(hash || '').toUpperCase();

  function finishDownloadRequest(err, html) {
    if (err) { callback(err, false); return; }
    if (!html) { callback(new Error('Empty response from eMule'), false); return; }
    if (html.includes('w=password')) {
      emuleSession = null;
      callback(new Error('eMule session expired before the download was queued'), false);
      return;
    }
    callback(null, true);
  }

  // Prefer explicit metadata from the caller, else our own result cache.
  const m = (meta && meta.size > 0) ? meta : _resultMetaCache.get(key);

  if (m && m.size > 0) {
    // Robust path: add by full ed2k link. Independent of eMule's search list,
    // so it works even after later searches wiped this hash from it.
    const link = buildEd2kLink(m.name, m.size, key);
    emuleRequest('?ses=' + emuleSession + '&w=transfer&ed2k=' + encodeURIComponent(link), finishDownloadRequest);
    return;
  }

  // Fallback: legacy by-hash add. Only succeeds while the hash is still present
  // in eMule's current search results.
  emuleRequest('?ses=' + emuleSession + '&w=search&downloads=' + key, finishDownloadRequest);
}

function withEmuleSession(callback) {
  if (emuleSession) return callback(null, emuleSession);
  const pw = getConfiguredPassword();
  emuleLogin(pw, (err, session) => {
    if (err) return callback(err);
    emulePassword = pw;
    callback(null, session);
  });
}

function buildTransferAction(params) {
  const hash = String(params.hash || '').trim().toUpperCase();
  if (!/^[A-F0-9]{32}$/.test(hash)) {
    throw new Error('Valid 32-character ed2k hash is required');
  }

  const action = String(params.action || params.op || '').trim().toLowerCase();
  let op = action;
  const extra = [];

  if (action === 'priority') {
    const value = String(params.priority || params.value || '').trim().toLowerCase();
    const map = { low: 'priolow', normal: 'prionormal', high: 'priohigh', auto: 'prioauto' };
    op = map[value];
  } else if (action === 'setcategory' || action === 'category' || action === 'setcat') {
    op = 'setcat';
    const category = parseInt(params.category ?? params.filecat ?? params.value, 10);
    if (Number.isNaN(category) || category < 0) throw new Error('Valid category index is required');
    extra.push('filecat=' + encodeURIComponent(String(category)));
  } else if (action === 'streamseek') {
    const part = parseInt(params.part ?? params.value, 10);
    if (Number.isNaN(part) || part < 0 || part > 65535) throw new Error('Valid part index is required');
    extra.push('part=' + encodeURIComponent(String(part)));
  } else if (action === 'rename') {
    const name = String(params.name || '').trim();
    if (!name) throw new Error('New name is required');
    extra.push('name=' + encodeURIComponent(name));
  }

  const allowed = new Set([
    'stop', 'pause', 'resume', 'cancel', 'getflc', 'rename',
    'priolow', 'prionormal', 'priohigh', 'prioauto', 'setcat', 'streamseek'
  ]);
  if (!allowed.has(op)) throw new Error('Unsupported transfer action');

  return '?ses={session}&w=transfer&op=' + encodeURIComponent(op) +
    '&file=' + encodeURIComponent(hash) +
    (extra.length ? '&' + extra.join('&') : '');
}

function emuleTransferAction(params, callback) {
  let pathTemplate;
  try {
    pathTemplate = buildTransferAction(params || {});
  } catch (e) {
    return callback(e);
  }

  const run = (retry) => {
    withEmuleSession((err, session) => {
      if (err) return callback(err);
      const reqPath = pathTemplate.replace('{session}', encodeURIComponent(session));
      emuleRequest(reqPath, (err2, html) => {
        if (err2) return callback(err2);
        if (html && html.includes('w=password') && retry) {
          emuleSession = null;
          return run(false);
        }
        callback(null, {
          ok: true,
          hash: String((params || {}).hash || '').trim().toUpperCase(),
          action: String((params || {}).action || (params || {}).op || '').trim().toLowerCase()
        });
      });
    });
  };
  run(true);
}

// ─── ED2K LINK DOWNLOAD ────────────────────────────────────────
// Acepta un enlace ed2k completo, extrae el hash y lo añade a la cola de eMule.
// Formato esperado: ed2k://|file|<nombre>|<tamaño>|<hash32hex>|/
function emuleAddEd2kLink(ed2kLink, callback) {
  if (!ed2kLink || typeof ed2kLink !== 'string') {
    return callback(new Error('Enlace vacío'));
  }

  const cleaned = ed2kLink.trim();

  // Validación del formato básico ed2k
  const ed2kRegex = /^ed2k:\/\/\|file\|([^|]+)\|(\d+)\|([A-Fa-f0-9]{32})\|/i;
  const match = cleaned.match(ed2kRegex);
  if (!match) {
    return callback(new Error('Formato de enlace ed2k inválido. Asegúrate de que tiene el formato: ed2k://|file|nombre|tamaño|hash|'));
  }

  const fileName = decodeURIComponent(match[1].replace(/\+/g, ' '));
  const fileSize = parseInt(match[2], 10);
  const hash     = match[3].toUpperCase();

  if (!hash || hash.length !== 32) {
    return callback(new Error('Hash ed2k inválido (debe tener 32 caracteres hex)'));
  }

  console.log('[eMule] Adding ed2k link — file: "' + fileName + '", size: ' + Math.round(fileSize / (1024*1024)) + ' MB, hash: ' + hash);

  // We already have the full link (name+size+hash) — remember it so a later
  // by-hash download of the same file also works.
  cacheResultMeta(hash, fileName, fileSize);

  const doAdd = () => {
    if (!emuleSession) { return callback(new Error('Sin sesión activa en eMule')); }
    // Add via the full ed2k link (w=transfer&ed2k=…), NOT w=search&downloads=hash.
    // The by-hash path only works when the hash is still in eMule's live search
    // list; a freshly-pasted link never is, so it would silently do nothing.
    const link = buildEd2kLink(fileName, fileSize, hash);
    emuleRequest('?ses=' + emuleSession + '&w=transfer&ed2k=' + encodeURIComponent(link), (err, html) => {
      if (err) { return callback(err); }
      if (html && html.includes('w=password')) {
        emuleSession = null;
        return callback(new Error('Sesión expirada — reintenta en unos segundos'));
      }
      callback(null, { hash, fileName, sizeMB: Math.round(fileSize / (1024 * 1024)) });
    });
  };

  if (!emuleSession) {
    const pw = getConfiguredPassword();
    emuleLogin(pw, (err, session) => {
      if (err) { return callback(new Error('eMule login fallido: ' + err.message)); }
      emulePassword = pw;
      doAdd();
    });
  } else {
    doAdd();
  }
}

// ─── KEEPALIVE ─────────────────────────────────────────────────

function startKeepalive() {
  setInterval(() => {
    if (emuleSession) {
      emuleRequest('?ses=' + emuleSession + '&w=transfer', (err, html) => {
        if (err || !html || html.includes('w=password')) {
          console.log('[eMule] Keepalive: session expired, re-logging in...');
          autoLoginEmule();
        }
      });
    }
  }, 5 * 60 * 1000);
}

// ─── GETTERS ───────────────────────────────────────────────────

function getSession() { return emuleSession; }
function getPassword() { return emulePassword; }
function getAuthStatus() {
  return { ...authStatus, retrying: autoLoginTimer !== null, retryAfterMs: Math.max(0, autoLoginRetryAt - Date.now()) };
}

module.exports = {
  emuleRequest,
  emuleLogin,
  emuleSearch,
  emuleDownload,
  emuleTransferAction,
  emuleAddEd2kLink,
  autoLoginEmule,
  parseEmuleSearchResults,
  scoreResult,
  detectQuality,
  detectLanguage,
  setSettingsFunctions,
  startKeepalive,
  getSession,
  getPassword,
  getAuthStatus,
  isEmuleRunning,
  killEmuleFFmpegOrphans,
  onRevived,
  getLibraryEpoch,
  getRestartedAt,
  EMULE_WS_PORT
};
