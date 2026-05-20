'use strict';
const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Estado compartido — se inyecta vía init()
let _activeStreams = {};
let _tempDir       = '';
let _shutdownInProgress = false;

/**
 * Inicializa el módulo con las referencias compartidas de server.js.
 * Debe llamarse UNA VEZ antes de que llegue cualquier petición.
 * @param {object} activeStreams  Referencia al objeto activeStreams de server.js
 * @param {string} tempDir        Directorio temporal (TEMP_DIR)
 */
function init(activeStreams, tempDir) {
  _activeStreams = activeStreams;
  _tempDir       = tempDir;
  registerShutdownHooks();
}

/** Mata todos los procesos ffmpeg activos y borra temporales ese_*. */
function cleanupAll() {
  console.log('[cleanup] Cleaning temp files...');

  // Matar procesos ffmpeg activos
  for (const key in _activeStreams) {
    try { _activeStreams[key].kill(); } catch (e) {}
    delete _activeStreams[key];
  }

  // Borrar todos los archivos ese_* del directorio temporal
  try {
    const files = fs.readdirSync(_tempDir);
    let count = 0;
    for (const f of files) {
      if (f.startsWith('ese_')) {
        try { fs.unlinkSync(path.join(_tempDir, f)); count++; } catch (e) {}
      }
    }
    if (count > 0) console.log('[cleanup] Deleted ' + count + ' temp files');
  } catch (e) {}
}

/** Borra archivos ese_* más antiguos que maxAgeMinutes. */
function cleanupOld(maxAgeMinutes) {
  try {
    const files = fs.readdirSync(_tempDir);
    const now   = Date.now();
    let count   = 0;
    for (const f of files) {
      if (!f.startsWith('ese_')) continue;
      const fp  = path.join(_tempDir, f);
      const age = (now - fs.statSync(fp).mtimeMs) / 60000;
      if (age > maxAgeMinutes) {
        try { fs.unlinkSync(fp); count++; } catch (e) {}
      }
    }
    if (count > 0) console.log('[cleanup] Removed ' + count + ' old files (>' + maxAgeMinutes + 'min)');
  } catch (e) {}
}

/**
 * UX-004: Graceful shutdown — kill ALL child FFmpeg processes on exit.
 * Prevents orphaned ffmpeg.exe processes that consume CPU/RAM indefinitely.
 * Works on both Windows (taskkill /T) and POSIX (SIGTERM → SIGKILL).
 */
function gracefulShutdown(signal) {
  if (_shutdownInProgress) return;
  _shutdownInProgress = true;
  console.log('[cleanup] Graceful shutdown initiated (' + signal + ')...');

  // 1. Stop eSE Live subsystems (pipeline, RTMP, tunnel)
  try {
    const pipeline = require('./eSE-live/ffmpeg_pipeline');
    pipeline.stop();
    console.log('[cleanup] FFmpeg pipeline stopped.');
  } catch (e) { console.warn('[cleanup] Pipeline stop error:', e.message); }

  try {
    const rtmpServer = require('./eSE-live/rtmp_server');
    rtmpServer.stop();
    console.log('[cleanup] RTMP server stopped.');
  } catch (e) { console.warn('[cleanup] RTMP stop error:', e.message); }

  try {
    const wsTunnel = require('./eSE-live/ws_tunnel');
    wsTunnel.stopServer();
    console.log('[cleanup] WS tunnel stopped.');
  } catch (e) { console.warn('[cleanup] Tunnel stop error:', e.message); }

  try {
    const thumbExtractor = require('./eSE-live/thumbnail_extractor');
    thumbExtractor.stop();
    console.log('[cleanup] Thumbnail extractor stopped.');
  } catch (e) { console.warn('[cleanup] Thumbnail stop error:', e.message); }

  // 2. Kill active streaming processes from the activeStreams registry
  cleanupAll();

  // 3. Platform-specific orphan sweep: kill any ffmpeg spawned by this Node.js PID
  killOrphanedFFmpeg();

  console.log('[cleanup] Shutdown complete.');
  removePidFile(); // BUG-016 FIX: clean up PID file on exit
}

/**
 * Kill ffmpeg.exe processes that are children of this Node.js process.
 * On Windows: uses `wmic` to find child processes by ParentProcessId.
 * On POSIX: uses `pkill -P` for child process tree.
 */
function killOrphanedFFmpeg() {
  const myPid = process.pid;
  try {
    if (process.platform === 'win32') {
      // BUG-016 FIX: Use Get-CimInstance instead of deprecated wmic
      const psCmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"Name=\'ffmpeg.exe\' AND ParentProcessId=' + myPid + '\\" | Select-Object -ExpandProperty ProcessId"';
      const output = execSync(psCmd, { encoding: 'utf8', timeout: 8000 });
      const pids = output.trim().split(/\r?\n/).filter(p => /^\d+$/.test(p.trim()));
      if (pids.length > 0) {
        pids.forEach(childPid => {
          try {
            execSync('taskkill /F /T /PID ' + childPid.trim(), { stdio: 'ignore', timeout: 3000 });
            console.log('[cleanup] Killed orphaned ffmpeg PID:', childPid.trim());
          } catch (e) { /* already dead */ }
        });
      }
    } else {
      // POSIX: kill child ffmpeg processes
      try {
        execSync('pkill -P ' + myPid + ' -f ffmpeg', { stdio: 'ignore', timeout: 3000 });
        console.log('[cleanup] Killed child ffmpeg processes.');
      } catch (e) { /* no matches or already dead */ }
    }
  } catch (e) {
    // Get-CimInstance/pkill may not be available — acceptable degradation
    console.warn('[cleanup] Orphan sweep unavailable:', e.message);
  }
}

// BUG-016 FIX: PID file heartbeat for external watchdog
const PID_FILE = path.join(_tempDir || require('os').tmpdir(), 'ese_server.pid');
function writePidFile() {
  try { fs.writeFileSync(PID_FILE, String(process.pid)); } catch (e) {}
}
function removePidFile() {
  try { fs.unlinkSync(PID_FILE); } catch (e) {}
}
// Write PID on init, update heartbeat every 30s
writePidFile();
setInterval(writePidFile, 30000);

/**
 * Register process-level hooks for clean shutdown.
 * Handles: Ctrl+C, SIGTERM, uncaughtException (last resort), Windows close.
 */
function registerShutdownHooks() {
  process.on('SIGINT',  () => { gracefulShutdown('SIGINT');  setTimeout(() => process.exit(0), 2000); });
  process.on('SIGTERM', () => { gracefulShutdown('SIGTERM'); setTimeout(() => process.exit(0), 2000); });
  process.on('beforeExit', () => gracefulShutdown('beforeExit'));

  // Windows: handle console close event
  if (process.platform === 'win32') {
    process.on('SIGHUP', () => { gracefulShutdown('SIGHUP'); setTimeout(() => process.exit(0), 2000); });
  }
}

// ── v8.0.27: ffmpeg leak guard ───────────────────────────────────────────────
// Root cause of the "ffmpeg.exe pile-up": cleanup of a streaming ffmpeg relied
// on a single req 'close' event firing. When it didn't (browser swapped
// video.src on a seek, the modal closed, a HEAD probe, ...) the ffmpeg was
// orphaned — Node still drained its stdout into the void, so it kept
// transcoding at full speed (~12% CPU + ~1 GB RAM EACH). Eight of those = a
// frozen PC, exactly what users reported.
//
// Fix: every streaming ffmpeg registers here with its HTTP response. The
// reaper runs every 25 s and kills any ffmpeg whose response is already
// closed/destroyed — i.e. nobody is watching it anymore. This is a safety net
// independent of the per-request close handlers: no ffmpeg can outlive its
// viewer by more than ~25 s, even if every close event is missed.
const _ffWatch = new Set();

function watchFfmpeg(ff, res) {
  if (!ff) return null;
  const entry = { ff: ff, res: res, born: Date.now() };
  _ffWatch.add(entry);
  const drop = () => _ffWatch.delete(entry);
  ff.once('close', drop);
  ff.once('error', drop);
  return entry;
}

function _responseIsDead(res) {
  if (!res) return true;
  if (res.writableEnded || res.destroyed) return true;
  if (res.socket && res.socket.destroyed) return true;
  return false;
}

function reapStaleFfmpeg() {
  let reaped = 0;
  for (const e of _ffWatch) {
    // Grace period — a freshly spawned ffmpeg whose response is still wiring up.
    if (Date.now() - e.born < 8000) continue;
    if (_responseIsDead(e.res)) {
      try { e.ff.kill(); } catch (x) {}
      _ffWatch.delete(e);
      reaped++;
    }
  }
  if (reaped > 0) console.log('[cleanup] Reaper killed ' + reaped + ' orphaned ffmpeg (no live viewer)');
}
setInterval(reapStaleFfmpeg, 25000);

// Limpieza periódica: borrar archivos con más de 60 min cada 10 min
setInterval(() => cleanupOld(60), 10 * 60 * 1000);

module.exports = { init, cleanupAll, cleanupOld, gracefulShutdown, watchFfmpeg };
