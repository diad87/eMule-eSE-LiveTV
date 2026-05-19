// D6 — Auto-update notifier.
//
// Runs `tools/update_check.ps1 -CheckOnly` once at startup and every 6 h.
// Caches the JSON result. Two endpoints exposed via channel_api.js:
//   GET  /api/live/update_status   -> latest cached check (cheap, no I/O)
//   POST /api/live/update_run      -> spawns the interactive updater script
//
// Why a polled check instead of a webhook: this is a P2P binary, we should
// never reach out from the eMule client. The user pulls from GitHub on
// their own cadence; the dashboard just surfaces the result.

'use strict';

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const POLL_INTERVAL_MS = 6 * 60 * 60 * 1000;  // 6 hours

let cached = { has_update: false, checked_at: 0, error: 'never_checked' };
let timer = null;

// Resolve the path to update_check.ps1 in dev (sibling tools/) AND
// in pkg snapshot mode (the script ships alongside the install dir,
// not inside the snapshot).
function resolveScript() {
  const candidates = [
    // pkg installed layout: emule.exe + tools/ + ese-server.exe in same dir
    path.join(path.dirname(process.execPath), 'tools', 'update_check.ps1'),
    // dev layout: srchybrid/eSE/ -> repo_root/tools/
    path.resolve(__dirname, '..', '..', '..', 'tools', 'update_check.ps1'),
    // package layout where update_check sits beside ese-server.exe
    path.join(path.dirname(process.execPath), 'update_check.ps1'),
  ];
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch (_) {}
  }
  return null;
}

function check() {
  const script = resolveScript();
  if (!script) {
    cached = { has_update: false, checked_at: Date.now(), error: 'updater_script_not_found' };
    return;
  }
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script, '-CheckOnly'];
  const ps = spawn('powershell.exe', args, { windowsHide: true });
  let out = '';
  let err = '';
  ps.stdout.on('data', (d) => { out += d.toString(); });
  ps.stderr.on('data', (d) => { err += d.toString(); });
  ps.on('error', (e) => {
    cached = { has_update: false, checked_at: Date.now(), error: 'spawn_error: ' + e.message };
  });
  ps.on('close', (code) => {
    try {
      // Script prints a single line of JSON in -CheckOnly mode.
      const line = out.trim().split(/\r?\n/).pop();
      const j = JSON.parse(line);
      j.checked_at = Date.now();
      cached = j;
      if (j.has_update) console.log('[Updater] new version available:', j.latest_tag || j.latest_sha);
    } catch (e) {
      cached = {
        has_update: false,
        checked_at: Date.now(),
        error: 'parse_failed (exit=' + code + ', stderr=' + err.trim().slice(0, 200) + ')'
      };
    }
  });
}

function start() {
  if (timer) return;
  // First check ~30 s after boot so we don't slow startup.
  setTimeout(check, 30 * 1000);
  timer = setInterval(check, POLL_INTERVAL_MS);
}

function stop() {
  if (timer) { clearInterval(timer); timer = null; }
}

function getStatus() {
  return cached;
}

// Spawn the interactive updater (without -CheckOnly). The script will
// pop its own GUI prompt; we just fire-and-forget. The dashboard's
// "Update now" button calls this.
function runInteractive(cb) {
  const script = resolveScript();
  if (!script) {
    if (cb) cb(new Error('updater_script_not_found'));
    return;
  }
  const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script];
  try {
    const ps = spawn('powershell.exe', args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,    // user needs to see the GUI prompt
    });
    ps.unref();
    if (cb) cb(null);
  } catch (e) {
    if (cb) cb(e);
  }
}

module.exports = { start, stop, getStatus, runInteractive, check };
