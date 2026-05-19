/**
 * emule_api.js — eMule WebServer integration
 * Handles: login, session management, search, download, password detection
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, spawn } = require('child_process');

// ─── EMULE PROCESS WATCHDOG ────────────────────────────────────
let _emuleExePath = null;

function getEmuleExePath() {
  if (_emuleExePath) return _emuleExePath;
  // Same folder as server.js
  const localPath = path.join(__dirname, 'emule.exe');
  if (fs.existsSync(localPath)) { _emuleExePath = localPath; return localPath; }
  // Fallback: known build path
  const buildPath = path.join(__dirname, '..', '..', 'srchybrid', 'x64', 'Release', 'emule.exe');
  const abs = path.resolve(buildPath);
  if (fs.existsSync(abs)) { _emuleExePath = abs; return abs; }
  return null;
}

function isEmuleRunning() {
  try {
    const result = spawnSync('tasklist', ['/FI', 'IMAGENAME eq emule.exe', '/NH', '/FO', 'CSV'], {
      timeout: 3000,
      windowsHide: true,   // ← prevents the black console window from flashing
      encoding: 'utf8'
    });
    return (result.stdout || '').includes('emule.exe');
  } catch(e) { return false; }
}

function ensureEmuleRunning() {
  if (isEmuleRunning()) return true;
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

function killEmuleFFmpegOrphans() {
  try {
    // Query all running ffmpeg processes with their executable path
    const result = spawnSync(
      'wmic',
      ['process', 'where', 'name="ffmpeg.exe"', 'get', 'ProcessId,ExecutablePath', '/format:csv'],
      { encoding: 'utf8', windowsHide: true, timeout: 4000 }
    );
    if (!result.stdout) return;
    const lines = result.stdout.split('\n').filter(l => l.includes('ffmpeg.exe'));
    for (const line of lines) {
      const parts = line.trim().split(',');
      // CSV format: Node,ExecutablePath,ProcessId
      const exePath = (parts[1] || '').toLowerCase();
      const pid = parseInt(parts[2] || parts[1], 10);
      if (!pid || isNaN(pid)) continue;
      // Only kill ffmpeg launched from eMule's install folder (not our own pipeline)
      if (exePath.includes('emule') && exePath.includes('ffmpeg.exe')) {
        try {
          spawnSync('taskkill', ['/F', '/PID', String(pid)], { windowsHide: true });
          console.log('[eMule] 🔪 Killed orphan FFmpeg (eMule launch) PID:', pid, 'path:', exePath);
        } catch(e) {}
      }
    }
  } catch(e) {}
}

// Watchdog: check every 10s. On dead→alive, bump epoch and notify handlers.
// On alive→dead, kill orphan ffmpeg children.
setInterval(function emuleLifecycleWatchdog() {
  const alive = isEmuleRunning();
  if (_emuleWasAlive && !alive) {
    console.log('[eMule] Process died — cleaning up orphan FFmpeg broadcasts...');
    killEmuleFFmpegOrphans();
    emuleSession = null;
  } else if (!_emuleWasAlive && alive) {
    _emuleRestartedAt = Date.now();
    _emuleLibraryEpoch++;
    console.log('[eMule] Process back online (epoch=' + _emuleLibraryEpoch + ')');
    // Auto-login is called by server.js initialisation; the autoLoginEmule
    // function declared later in this file picks up immediately. We just
    // notify external listeners.
    for (const h of _onEmuleRevivedHandlers) {
      try { h(_emuleLibraryEpoch); }
      catch(e) { console.warn('[watchdog] revived handler error:', e.message); }
    }
  }
  _emuleWasAlive = alive;
}, 10000);
// Initialise state without triggering cleanup on first run
_emuleWasAlive = isEmuleRunning();

const zlib = require('zlib');

const EMULE_WS_PORT = 4711;

let emuleSession = null;
let emulePassword = null;

// External dependency: settings (injected)
let _loadSettings = () => ({});
let _saveSettings = () => {};

function setSettingsFunctions(load, save) {
  _loadSettings = load;
  _saveSettings = save;
}

// ─── HTTP REQUEST ──────────────────────────────────────────────

// v8.0.2 — emuleRequest now enforces an 8 s timeout.
//
// Previously, if the eMule WebServer thread deadlocked or its accept loop got
// wedged (rare but observed during privacy stress tests), http.get() waited
// indefinitely for headers, hanging the JS event loop on every UI poll.
// Eight seconds is generous for a local round-trip but short enough to keep
// the dashboard responsive; the timeout error bubbles up via callback the
// same way as ECONNREFUSED, so existing call sites already handle it.
const EMULE_REQUEST_TIMEOUT_MS = 8000;

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
    headers: { 'Accept-Encoding': 'gzip, deflate, identity' },
    timeout: EMULE_REQUEST_TIMEOUT_MS,
  };

  let cbFired = false;
  const fire = (err, body) => {
    if (cbFired) return;
    cbFired = true;
    callback(err, body);
  };

  const req = http.get(options, (res) => {
    const chunks = [];
    const encoding = res.headers['content-encoding'];
    let stream = res;
    if (encoding === 'gzip') stream = res.pipe(zlib.createGunzip());
    else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());

    stream.on('data', d => chunks.push(d));
    stream.on('end', () => {
      const buf = Buffer.concat(chunks);
      _emuleWsLastOkAt = Date.now();
      fire(null, buf.toString('latin1'));
    });
    stream.on('error', (err) => fire(err, null));
  });
  req.on('timeout', () => {
    req.destroy(new Error('emuleRequest timeout after ' + EMULE_REQUEST_TIMEOUT_MS + ' ms'));
  });
  req.on('error', (err) => fire(err, null));
}

// v8.0.2 — HTTP-level WebServer watchdog.
//
// The process-level watchdog at the top of this file checks `tasklist` to
// see whether emule.exe is alive. That's a coarse signal: the process can
// be alive but the WebServer thread can be stuck (deadlock, blocked I/O,
// hung TLS handshake). This HTTP watchdog complements it by pinging the
// /?w=stats endpoint (the cheapest no-auth path) every 30 s. After three
// consecutive failures the dashboard surfaces "WS unresponsive" instead of
// silently spinning. We never kill the process — the user owns that.
let _emuleWsLastOkAt = 0;
let _emuleWsConsecFails = 0;
let _emuleWsResponsive = true;
function emuleWsIsResponsive() { return _emuleWsResponsive; }
function emuleWsLastOkAt()     { return _emuleWsLastOkAt; }

setInterval(function emuleWebServerWatchdog() {
  if (!isEmuleRunning()) return;  // process-level watchdog handles this case
  const req = http.get({
    hostname: '127.0.0.1', port: EMULE_WS_PORT, path: '/',
    timeout: 3000, headers: { 'Connection': 'close' },
  }, (res) => {
    // Any 2xx/3xx (or even 401 — WS is alive and answering) counts as "up".
    res.resume();  // discard body
    if (res.statusCode && res.statusCode < 500) {
      _emuleWsConsecFails = 0;
      _emuleWsLastOkAt = Date.now();
      if (!_emuleWsResponsive) {
        console.log('[ws-watchdog] WebServer back up (status=' + res.statusCode + ')');
        _emuleWsResponsive = true;
      }
    } else {
      _emuleWsConsecFails++;
    }
  });
  req.on('timeout', () => { req.destroy(new Error('ws-watchdog ping timeout')); });
  req.on('error', (err) => {
    _emuleWsConsecFails++;
    if (_emuleWsConsecFails === 3 && _emuleWsResponsive) {
      _emuleWsResponsive = false;
      const _msg = String(err && err.message).replace(/[\r\n\t]+/g, ' ');
      console.log('[ws-watchdog] WebServer unresponsive after 3 pings (last: ' + _msg + ')');
    }
  });
}, 30000);

// ─── PASSWORD (unique per-installation, zero-config) ──────────
//
// Priority order (v8.0.4):
//   1. eSE_pass.bin on disk — the authoritative source written by
//      eSEHelpers::EnsureSharedPassword on the C++ side. We stat the file on
//      every call and re-read if the mtime changed. This way, if the user
//      reinstalls / migrates / changes the file manually, the next eMule
//      request picks up the new password without a server restart.
//   2. ESE_EMULE_PASSWORD env var — set by emule.exe at spawn. Useful when
//      eSE_pass.bin can't be located (non-standard eMule install path).
//   3. settings.json `emulePassword` — persisted from a previous run.
//   4. Fresh random password — for standalone launches when none of the
//      above is available (user double-clicked ese-server.exe directly).

// Candidate paths for eSE_pass.bin. The C++ side writes to <configDir>\eSE_pass.bin
// where configDir is thePrefs.GetMuleDirectory(EMULE_CONFIGDIR) — usually
// %APPDATA%\eMule\config but it can be %LOCALAPPDATA% or the install dir on
// older / portable setups. We check the most-likely paths in order.
function _candidatePassFiles() {
  const candidates = [];
  const home = process.env.USERPROFILE || process.env.HOME || '';
  if (process.env.APPDATA)      candidates.push(path.join(process.env.APPDATA,      'eMule', 'config', 'eSE_pass.bin'));
  if (process.env.LOCALAPPDATA) candidates.push(path.join(process.env.LOCALAPPDATA, 'eMule', 'config', 'eSE_pass.bin'));
  if (home) candidates.push(path.join(home, 'AppData', 'Roaming', 'eMule', 'config', 'eSE_pass.bin'));
  if (home) candidates.push(path.join(home, 'AppData', 'Local',   'eMule', 'config', 'eSE_pass.bin'));
  // Override file alongside ese-server.exe for users with custom install layouts.
  candidates.push(path.join(__dirname, '..', 'config', 'eSE_pass.bin'));
  return candidates;
}

// Cache: { path, mtimeMs, value }. Re-read when stat.mtimeMs differs.
let _passCache = { path: null, mtimeMs: 0, value: null };

function _readPassFromDisk() {
  for (const p of _candidatePassFiles()) {
    let st;
    try { st = fs.statSync(p); } catch (e) { continue; }
    if (!st || !st.isFile()) continue;
    // Fast path: same file + same mtime as cached.
    if (_passCache.path === p && _passCache.mtimeMs === st.mtimeMs && _passCache.value) {
      return _passCache.value;
    }
    let raw;
    try { raw = fs.readFileSync(p, 'utf8'); } catch (e) { continue; }
    const pw = String(raw).trim();
    // Same validation the C++ side enforces: 8-64 printable ASCII chars.
    if (pw.length < 8 || pw.length > 64) continue;
    if (!/^[\x20-\x7E]+$/.test(pw)) continue;
    _passCache = { path: p, mtimeMs: st.mtimeMs, value: pw };
    return pw;
  }
  return null;
}

function getOrCreatePassword() {
  // 1. eSE_pass.bin — authoritative, picks up live edits via mtime check.
  const fromDisk = _readPassFromDisk();
  if (fromDisk) {
    // Keep settings.json in sync so legacy code paths that read it still work.
    const s = _loadSettings();
    if (s.emulePassword !== fromDisk) {
      s.emulePassword = fromDisk;
      _saveSettings(s);
    }
    return fromDisk;
  }

  // 2. ENV var injected by emule.exe at spawn time.
  const envPw = process.env.ESE_EMULE_PASSWORD;
  if (envPw) {
    const s = _loadSettings();
    if (s.emulePassword !== envPw) {
      s.emulePassword = envPw;
      _saveSettings(s);
    }
    return envPw;
  }

  // 3. settings.json from a previous run.
  const s = _loadSettings();
  if (s.emulePassword) return s.emulePassword;

  // 4. Fresh random — standalone mode.
  const pw = crypto.randomBytes(16).toString('hex');
  s.emulePassword = pw;
  _saveSettings(s);
  console.log('[eMule] Generated unique installation password (standalone mode)');
  return pw;
}

// ─── LOGIN ─────────────────────────────────────────────────────

function emuleLogin(password, callback) {
  emuleRequest('?w=password&p=' + encodeURIComponent(password), (err, html) => {
    if (err) {
      if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
        const e = new Error('eMule WebServer no responde (¿eMule cerrado?)');
        e.reason = 'webserver_down';
        return callback(e);
      }
      return callback(err);
    }
    const sesMatch = html && html.match(/ses=(\d+)/);
    if (sesMatch) {
      emuleSession = sesMatch[1];
      callback(null, emuleSession);
    } else {
      const e = new Error('eMule rechazó la password (settings.json desincronizado)');
      e.reason = 'password_mismatch';
      callback(e);
    }
  });
}

// BUG-051 FIX: retry limit + exponential backoff
var _autoLoginAttempts = 0;
var _autoLoginMaxRetries = 15;
var _autoLoginBaseDelay = 10000;

// v8.0.3 — error_codes.js is required lazily here to avoid a circular dep
// at module load time (error_codes.js's probes read emuleApi.getSession).
let _errorCodes = null;
function _errCode(name) {
  try {
    if (!_errorCodes) _errorCodes = require('./error_codes');
    return _errorCodes.buildCode(name);
  } catch (e) { return '[ESE ?] E00'; }
}

// Most-recent login failure code, exposed via getLastErrorCode() for the
// UI's "copy this code" affordance.
let _lastErrorCode = null;
function getLastErrorCode() { return _lastErrorCode; }

function autoLoginEmule() {
  const pw = getOrCreatePassword();
  emuleLogin(pw, (err, session) => {
    if (!err && session) {
      emulePassword = pw;
      _autoLoginAttempts = 0;
      _lastErrorCode = null;
      console.log('[eMule] Logged in, session: ' + session);
    } else {
      _autoLoginAttempts++;
      // Classify: timeout vs unreachable vs auth-failure. emuleLogin's err
      // message is typically "ECONNREFUSED" (WS off), "timeout" (deadlock),
      // or a parse error (WS responded but rejected the password).
      const msg = String(err && err.message || '').toLowerCase();
      let codeName = 'emule_ws_login_failed';
      if (msg.indexOf('econnrefused') >= 0) codeName = 'emule_ws_unreachable';
      else if (msg.indexOf('timeout')     >= 0) codeName = 'emule_ws_timeout';
      _lastErrorCode = _errCode(codeName);
      if (_autoLoginAttempts >= _autoLoginMaxRetries) {
        console.error('[eMule] Login failed after ' + _autoLoginMaxRetries + ' attempts. Giving up. ' + _lastErrorCode);
        return;
      }
      var delay = Math.min(_autoLoginBaseDelay * Math.pow(2, _autoLoginAttempts - 1), 300000);
      console.log('[eMule] Login failed (attempt ' + _autoLoginAttempts + '/' + _autoLoginMaxRetries + '). Retrying in ' + (delay/1000) + 's... ' + _lastErrorCode);
      setTimeout(autoLoginEmule, delay);
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
  const pw = getOrCreatePassword();
  emuleLogin(pw, (err, session) => {
    if (err) {
      console.log('[eMule] ❌ Auto-relogin failed');
      callback(new Error('eMule login failed'), []);
    } else {
      emulePassword = pw;
      console.log('[eMule] ✅ Re-logged in, session: ' + session);
      emuleSearch(query, settings, callback);
    }
  });
}

// ─── SEARCH ────────────────────────────────────────────────────

// v8.0.9 — fallback is now UNIVERSAL.
//
// Old behaviour (v8.0.6): only `searchMethod === 'auto'` triggered the
// server-then-Kad retry. Users with a persisted settings.json from an
// older build had `searchMethod: 'server'` saved explicitly — that path
// never fell back to Kad, so users on Kad-only nets saw 0 results even
// though Kad would have answered. Observed in real-world log
// (avatar 2009 + Oppenheimer 2023 both returned 0 with method=server,
// no fallback).
//
// New behaviour:
//   - 'auto'   → server first, fallback to Kad if 0.
//   - 'server' → server first, fallback to Kad if 0.
//   - 'kad'    → Kad first, fallback to server if 0.
//   - 'global' → global first, fallback to Kad if 0.
//   Any 0-result primary leg now retries with the OTHER network. If both
//   end up empty there really are no sources. Explicit user choices still
//   control WHICH network is tried first; only the empty-result behaviour
//   changed.
//
// Plus a one-shot settings migration in autoLoginEmule's settings path:
// any persisted searchMethod === 'server' from a pre-v8.0.6 install is
// quietly migrated to 'auto' on first run, so the dropdown also reflects
// the smart default.
function _wsMethodFor(name) {
  if (name === 'global')   return 'global';
  if (name === 'server')   return '';           // empty = server (eMule WS default)
  if (name === 'kad')      return 'kademlia';
  if (name === 'kademlia') return 'kademlia';
  // anything else (including 'auto', undefined) → start with server, the
  // caller knows to fallback to kademlia on empty.
  return '';
}

// Pick the fallback method when the primary returned 0 results. Going
// server→Kad is the default; if the user explicitly picked Kad, we fall
// back to server (the inverse) so a Kad query that hit no peers can still
// pick up server-indexed files.
function _fallbackMethodFor(primaryWsMethod) {
  if (primaryWsMethod === 'kademlia') return '';        // kad → server
  return 'kademlia';                                    // server/global/auto → kad
}

// v8.0.9 one-shot migration: rewrite a persisted searchMethod='server'
// (left over from a pre-v8.0.6 install where 'server' was the default)
// to 'auto' so the new fallback logic engages and the settings dropdown
// reflects the recommended choice. Fires once per install — tracked by
// the marker file in the same dir as settings.json.
function _maybeMigrateSearchMethod() {
  try {
    const s = _loadSettings();
    if (s.__v809_searchMethodMigrated) return;
    if (s.searchMethod === 'server') {
      s.searchMethod = 'auto';
      console.log('[eMule] One-shot: persisted searchMethod=server migrated to auto (v8.0.9). User can still pick server explicitly in Settings.');
    }
    s.__v809_searchMethodMigrated = true;
    _saveSettings(s);
  } catch (e) { /* settings unavailable — skip silently */ }
}

function emuleSearch(query, settings, callback) {
  // v8.0.9 — migrate stale persisted searchMethod once before reading.
  _maybeMigrateSearchMethod();

  const doSearch = () => {
    if (!emuleSession) { callback(new Error('Not logged in')); return; }
    const s = settings || _loadSettings();

    let searchQuery = query;
    if (s.quality && s.quality !== 'auto') {
      searchQuery += ' ' + (s.quality === '4k' ? '2160p' : s.quality);
    }

    const firstMethod = _wsMethodFor(s.searchMethod);

    runOnce(searchQuery, firstMethod, /*alreadyRetried=*/false);

    function runOnce(safeSearchQuery, method, alreadyRetried) {
      const searchUrl = '?ses=' + emuleSession + '&w=search&tosearch=' + encodeURIComponent(safeSearchQuery) + '&type=Video' + (method ? '&method=' + method : '');
      const displayMethod = method || 'server';
      console.log('[eMule] Starting new search: "' + safeSearchQuery + '" method=' + displayMethod + ' retried=' + alreadyRetried);

      emuleRequest(searchUrl, (err2, html) => {
        if (err2) { callback(err2, []); return; }

        if (html.includes('w=password') || (html.includes('Login') && !html.includes('tosearch'))) {
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
        // First leg gets a shorter poll budget (3 polls × 4 s = 12 s) so the
        // fallback to the other network kicks in fast. Second leg gets the
        // full budget because by then we've committed to the result.
        const maxAttempts = alreadyRetried ? 5 : 3;
        const pollInterval = alreadyRetried ? 6000 : 4000;

        const poll = () => {
          if (!isEmuleRunning()) {
            console.log('[eMule] ⚠ eMule died during search poll — aborting');
            ensureEmuleRunning();
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

            if (results.length > 0) {
              callback(null, results);
              return;
            }
            if (attempt >= maxAttempts) {
              // v8.0.9: universal fallback. If the primary leg returned 0
              // results, ALWAYS try the other network — regardless of which
              // method the user picked. Users on Kad-only get Kad results
              // even if their settings says "server"; users on server-only
              // get server results even if their settings says "kad".
              if (!alreadyRetried) {
                const fbMethod = _fallbackMethodFor(method);
                const fbDisplay = fbMethod || 'server';
                console.log('[eMule] ' + displayMethod + ' search returned 0. Falling back to ' + fbDisplay + '.');
                runOnce(safeSearchQuery, fbMethod, true);
                return;
              }
              console.log('[eMule] Both ' + displayMethod + ' and fallback returned 0 results — giving up.');
              callback(null, results);
              return;
            }
            setTimeout(poll, pollInterval);
          });
        };
        setTimeout(poll, 3000);
      });
    }
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
    
    const score = scoreResult(entry.fileName, sizeMB, sources, completeSources, settings, searchQuery);
    if (score > -900) {
      results.push({
        fileName: entry.fileName, sizeMB, sources, completeSources,
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

function emuleDownload(hash, callback) {
  if (!emuleSession) { callback(new Error('Not logged in')); return; }
  emuleRequest('?ses=' + emuleSession + '&w=search&downloads=' + hash, (err, html) => {
    callback(err, !err);
  });
}

function withEmuleSession(callback) {
  if (emuleSession) return callback(null, emuleSession);
  const pw = getOrCreatePassword();
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

  const doAdd = () => {
    if (!emuleSession) { return callback(new Error('Sin sesión activa en eMule')); }
    // eMule WebServer accepts downloads by hash via the search page
    emuleRequest('?ses=' + emuleSession + '&w=search&downloads=' + hash, (err, html) => {
      if (err) { return callback(err); }
      if (html && html.includes('w=password')) {
        emuleSession = null;
        return callback(new Error('Sesión expirada — reintenta en unos segundos'));
      }
      callback(null, { hash, fileName, sizeMB: Math.round(fileSize / (1024 * 1024)) });
    });
  };

  if (!emuleSession) {
    const pw = getOrCreatePassword();
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
  isEmuleRunning,
  killEmuleFFmpegOrphans,
  onRevived,
  getLibraryEpoch,
  getRestartedAt,
  emuleWsIsResponsive,
  emuleWsLastOkAt,
  getLastErrorCode,
  EMULE_WS_PORT
};
