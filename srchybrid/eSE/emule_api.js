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
let _emuleWasAlive = false;

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

// Watchdog: check every 10s if eMule is alive; if it just died, kill its FFmpeg children
setInterval(function emuleLifecycleWatchdog() {
  const alive = isEmuleRunning();
  if (_emuleWasAlive && !alive) {
    console.log('[eMule] Process died — cleaning up orphan FFmpeg broadcasts...');
    killEmuleFFmpegOrphans();
  }
  _emuleWasAlive = alive;
}, 10000);
// Initialise state without triggering cleanup on first run
_emuleWasAlive = isEmuleRunning();

const zlib = require('zlib');

// eMule is a Unicode (UTF-16LE) MFC build. MD5Sum::Calculate() hashes
// (LPCTSTR)sSource with sSource.GetLength() * sizeof(TCHAR), where
// sizeof(TCHAR) = 2. We must replicate this in Node.js.
function md5utf16le(str) {
  return crypto.createHash('md5').update(Buffer.from(str, 'utf16le')).digest('hex').toUpperCase();
}

const EMULE_WS_PORT = 4711;

// ─── PORTABLE-FIRST CONFIG DETECTION ───────────────────────────
// Mirrors eMule C++ logic (Preferences.cpp::GetDefaultDirectory):
//   1. If <exe_dir>/config/preferences.ini exists → portable mode
//   2. Else → %LOCALAPPDATA%\eMule\config (standard multi-user mode)
function resolveEmuleConfigDir() {
  // Portable: config/ folder alongside this script (same dir as emule.exe)
  const portableConfig = path.join(__dirname, 'config');
  const portablePrefs = path.join(portableConfig, 'preferences.ini');
  if (fs.existsSync(portablePrefs)) {
    console.log('[eMule] Config mode: PORTABLE (' + portableConfig + ')');
    return portableConfig;
  }

  // Standard: %LOCALAPPDATA%\eMule\config
  const localAppData = process.env.LOCALAPPDATA ||
    path.join(process.env.USERPROFILE || path.join('C:', 'Users', process.env.USERNAME || 'Default'), 'AppData', 'Local');
  const standardConfig = path.join(localAppData, 'eMule', 'config');
  console.log('[eMule] Config mode: STANDARD (' + standardConfig + ')');
  return standardConfig;
}

const EMULE_CONFIG_DIR = resolveEmuleConfigDir();
const EMULE_PREFS_INI = path.join(EMULE_CONFIG_DIR, 'preferences.ini');
const KNOWN_PASSWORDS = ['eSE', 'emule', 'admin', '12345', 'password', ''];

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

function emuleRequest(urlPath, callback) {
  const fullUrl = 'http://localhost:' + EMULE_WS_PORT + '/' + urlPath;
  const urlObj = new URL(fullUrl);
  
  const options = {
    hostname: urlObj.hostname,
    port: urlObj.port,
    path: urlObj.pathname + urlObj.search,
    headers: { 'Accept-Encoding': 'gzip, deflate, identity' }
  };
  
  http.get(options, (res) => {
    const chunks = [];
    const encoding = res.headers['content-encoding'];
    let stream = res;
    if (encoding === 'gzip') stream = res.pipe(zlib.createGunzip());
    else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());
    
    stream.on('data', d => chunks.push(d));
    stream.on('end', () => {
      const buf = Buffer.concat(chunks);
      callback(null, buf.toString('latin1'));
    });
    stream.on('error', (err) => callback(err, null));
  }).on('error', (err) => callback(err, null));
}

// ─── PASSWORD (unique per-installation, zero-config) ──────────

function getOrCreatePassword() {
  const s = _loadSettings();
  if (s.emulePassword) return s.emulePassword;
  // First run: generate unique password for this installation
  const pw = crypto.randomBytes(16).toString('hex');
  s.emulePassword = pw;
  _saveSettings(s);
  console.log('[eMule] Generated unique installation password');
  return pw;
}

// ─── INI SECTION HELPERS ───────────────────────────────────────
// eMule's CIni reads/writes keys under specific [Section] headers.
// We must respect that to avoid cross-section key collisions.

/**
 * Extracts the value of `key` from a specific [section] in an INI string.
 * Returns null if section or key is not found.
 */
function iniGetValue(ini, section, key) {
  const sectionRegex = new RegExp('\\[' + section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\]', 'i');
  const sectionMatch = ini.match(sectionRegex);
  if (!sectionMatch) return null;

  const afterSection = ini.substring(sectionMatch.index + sectionMatch[0].length);
  const nextSection = afterSection.search(/^\[/m);
  const sectionBody = nextSection >= 0 ? afterSection.substring(0, nextSection) : afterSection;

  const keyRegex = new RegExp('^' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=(.*)$', 'mi');
  const keyMatch = sectionBody.match(keyRegex);
  return keyMatch ? keyMatch[1].trim() : null;
}

/**
 * Sets a key=value under a specific [section]. Creates the section if missing.
 * Replaces the key if it already exists within that section.
 */
function iniSetValue(ini, section, key, value) {
  const sectionHeader = '[' + section + ']';
  const sectionRegex = new RegExp('\\[' + section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\]', 'i');
  const sectionMatch = ini.match(sectionRegex);

  if (!sectionMatch) {
    // Section doesn't exist — append it
    return ini.trimEnd() + '\n\n' + sectionHeader + '\n' + key + '=' + value + '\n';
  }

  const afterSection = ini.substring(sectionMatch.index + sectionMatch[0].length);
  const nextSection = afterSection.search(/^\[/m);
  const sectionBody = nextSection >= 0 ? afterSection.substring(0, nextSection) : afterSection;

  const keyRegex = new RegExp('^' + key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=.*$', 'mi');
  const keyMatch = sectionBody.match(keyRegex);

  if (keyMatch) {
    // Replace existing key within the section
    const absolutePos = sectionMatch.index + sectionMatch[0].length + keyMatch.index;
    return ini.substring(0, absolutePos) + key + '=' + value + ini.substring(absolutePos + keyMatch[0].length);
  }

  // Key doesn't exist in section — insert after section header
  const insertPos = sectionMatch.index + sectionMatch[0].length;
  return ini.substring(0, insertPos) + '\n' + key + '=' + value + ini.substring(insertPos);
}

function detectEmulePassword() {
  try {
    const ourPassword = getOrCreatePassword();

    if (!fs.existsSync(EMULE_PREFS_INI)) return ourPassword;
    let ini = fs.readFileSync(EMULE_PREFS_INI, 'utf8');

    // Ensure [WebServer] section exists and Enabled=1
    const wsEnabled = iniGetValue(ini, 'WebServer', 'Enabled');
    if (wsEnabled !== '1') {
      console.log('[eMule] Enabling WebServer in [WebServer] section...');
      ini = iniSetValue(ini, 'WebServer', 'Enabled', '1');
      fs.writeFileSync(EMULE_PREFS_INI, ini);
    }

    // Read Password from [WebServer] section specifically
    const storedHash = (iniGetValue(ini, 'WebServer', 'Password') || '').toUpperCase();

    // No password in eMule → write ours
    if (!storedHash) {
      const hash = md5utf16le(ourPassword);
      ini = iniSetValue(ini, 'WebServer', 'Password', hash);
      fs.writeFileSync(EMULE_PREFS_INI, ini);
      console.log('[eMule] Password hash written to [WebServer] in preferences.ini');
      return ourPassword;
    }

    // Fast path: our password matches
    if (md5utf16le(ourPassword) === storedHash) {
      console.log('[eMule] Password OK (from settings)');
      return ourPassword;
    }

    // Try known passwords (user had eMule before eSE)
    for (const pw of KNOWN_PASSWORDS) {
      if (md5utf16le(pw) === storedHash) {
        // BUG-049 FIX: never log passwords, even common ones
        console.log('[eMule] Detected existing legacy password (matched hash)');
        const s = _loadSettings();
        s.emulePassword = pw;
        _saveSettings(s);
        return pw;
      }
    }

    // No match → overwrite with ours (requires eMule restart to take effect)
    const hash = md5utf16le(ourPassword);
    ini = iniSetValue(ini, 'WebServer', 'Password', hash);
    fs.writeFileSync(EMULE_PREFS_INI, ini);
    console.log('[eMule] ⚠️  Password updated in [WebServer]. Restart eMule to apply.');
    return ourPassword;

  } catch(e) {
    console.log('[eMule] Password setup error:', e.message);
    return getOrCreatePassword();
  }
}

// ─── LOGIN ─────────────────────────────────────────────────────

function emuleLogin(password, callback) {
  emuleRequest('?w=password&p=' + encodeURIComponent(password), (err, html) => {
    if (err) { callback(err); return; }
    const sesMatch = html.match(/ses=(\d+)/);
    if (sesMatch) {
      emuleSession = sesMatch[1];
      callback(null, emuleSession);
    } else {
      callback(new Error('Login failed - wrong password?'));
    }
  });
}

// BUG-051 FIX: retry limit + exponential backoff
var _autoLoginAttempts = 0;
var _autoLoginMaxRetries = 15;
var _autoLoginBaseDelay = 10000;

function autoLoginEmule() {
  const pw = detectEmulePassword();
  emuleLogin(pw, (err, session) => {
    if (!err && session) {
      emulePassword = pw;
      _autoLoginAttempts = 0;
      console.log('[eMule] Logged in, session: ' + session);
    } else {
      _autoLoginAttempts++;
      if (_autoLoginAttempts >= _autoLoginMaxRetries) {
        console.error('[eMule] Login failed after ' + _autoLoginMaxRetries + ' attempts. Giving up.');
        return;
      }
      var delay = Math.min(_autoLoginBaseDelay * Math.pow(2, _autoLoginAttempts - 1), 300000);
      console.log('[eMule] Login failed (attempt ' + _autoLoginAttempts + '/' + _autoLoginMaxRetries + '). Retrying in ' + (delay/1000) + 's...');
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
  const pw = detectEmulePassword();
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
  const pw = detectEmulePassword();
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
    const pw = detectEmulePassword();
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
  detectEmulePassword,
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
  EMULE_WS_PORT
};
