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

// BUG-016 FIX: PID file heartbeat for external watchdog.
// Lives in the per-user eSE runtime dir, not the shared OS temp dir — a
// world-writable predictable path invites tampering, and _tempDir was always
// '' at module-load time anyway so the old `_tempDir ||` fallback never fired.
const PID_FILE = require('./runtime_dir').join('ese_server.pid');
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

// Limpieza periódica: borrar archivos con más de 60 min cada 10 min
setInterval(() => cleanupOld(60), 10 * 60 * 1000);

module.exports = { init, cleanupAll, cleanupOld, gracefulShutdown };
