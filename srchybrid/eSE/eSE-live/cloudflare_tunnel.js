/**
 * eSE Live — Cloudflare Tunnel wrapper (Tier 3.1)
 *
 * ⚠️  TOS WARNING — READ BEFORE USING ⚠️
 * Cloudflare's Acceptable Use Policy explicitly prohibits "tunnels that
 * repackage P2P file-sharing networks". Sustained heavy use of Quick Tunnels
 * for content distribution can result in URL/IP/account ban without notice.
 * This module is provided as a LAST-RESORT, OPT-IN diagnostic only:
 *   - User must click an explicit "Activate" button after reading the warning
 *   - Module never starts automatically
 *   - Best for personal/legal content (your own files, demos, testing)
 *   - For real LowID-LowID P2P, prefer UDP hole-punching (SendEseHolePunchReq)
 *
 * Spawns `cloudflared tunnel --url http://localhost:<port>` and parses its
 * stderr output to extract the public `https://<random>.trycloudflare.com`
 * URL. While the tunnel is up, any viewer with that URL can fetch the
 * broadcaster's HLS playlist and segments WITHOUT needing P2P, port-forwarding,
 * or Kad — even when both peers are behind hostile NATs.
 *
 * USAGE
 *   const tunnel = require('./cloudflare_tunnel');
 *   const r = tunnel.start({ port: 8080 });
 *   // ... wait for tunnel.getStatus().url to be non-null ...
 *   tunnel.stop();
 *
 * SECURITY NOTE
 *   The tunnel exposes localhost:<port> to the public internet. Anyone who
 *   guesses the trycloudflare.com URL can hit /api/* endpoints. We mitigate
 *   by only tunneling port 8080 (the Node.js dashboard) which exposes the
 *   HLS files but NOT the eMule control API. The C++ control API on 4711
 *   stays bound to localhost only.
 */
'use strict';

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

let tunnelProcess = null;
let tunnelStatus = 'idle';   // idle | starting | running | error | stopped
let tunnelURL = null;
let tunnelError = null;
let startedAt = null;

// Locate cloudflared.exe shipped next to the eSE/ folder, or in PATH.
function findCloudflared() {
  // 1. Same dir as this script's parent (eSE/)
  const localPath = path.join(__dirname, '..', 'cloudflared.exe');
  if (fs.existsSync(localPath)) return localPath;
  // 2. Same dir as emule.exe — check parent of eSE/
  const exeDirPath = path.join(__dirname, '..', '..', 'cloudflared.exe');
  if (fs.existsSync(exeDirPath)) return exeDirPath;
  // 3. PATH (let spawn resolve it)
  return 'cloudflared.exe';
}

/**
 * Start the tunnel.
 * @param {Object} opts
 * @param {number} [opts.port=8080] - Local port to expose
 * @returns {{success: boolean, error?: string, status: string}}
 */
function start(opts) {
  if (tunnelProcess) {
    return { success: false, error: 'Tunnel already running', status: tunnelStatus };
  }

  const port = (opts && opts.port) || 8080;
  const bin = findCloudflared();

  // Tunnel args: --url for quick tunnel, --no-autoupdate to avoid re-spawn,
  // --logfile /dev/null equivalent on Windows = NUL. Pretty output goes to stderr.
  const args = [
    'tunnel',
    '--no-autoupdate',
    '--url', 'http://localhost:' + port
  ];

  try {
    tunnelProcess = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    tunnelStatus = 'error';
    tunnelError = e.message;
    return { success: false, error: e.message, status: tunnelStatus };
  }

  tunnelStatus = 'starting';
  tunnelURL = null;
  tunnelError = null;
  startedAt = Date.now();

  // Cloudflared writes everything (including the URL) to stderr.
  // We look for the line containing the trycloudflare.com hostname.
  const onLine = function (line) {
    const m = line.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
    if (m && !tunnelURL) {
      tunnelURL = m[0];
      tunnelStatus = 'running';
      console.log('[eSE Tunnel] Cloudflare quick tunnel ready: ' + tunnelURL);
    }
    // Detect explicit errors so we can give the user actionable feedback.
    // Match only real failure markers (ERR/FATAL prefix) AND specific patterns.
    // Avoid INF/WRN noise like "does not support loading the system root certificate"
    // which is informational on Windows but contains the word "certificate".
    if (/\b(ERR|FATAL)\b/.test(line) ||
        /permission denied|cannot bind|address already in use|EADDRINUSE/i.test(line)) {
      tunnelError = line.trim();
    }
  };

  let bufErr = '';
  tunnelProcess.stderr.on('data', (chunk) => {
    bufErr += chunk.toString();
    let nl;
    while ((nl = bufErr.indexOf('\n')) >= 0) {
      onLine(bufErr.substring(0, nl));
      bufErr = bufErr.substring(nl + 1);
    }
  });
  let bufOut = '';
  tunnelProcess.stdout.on('data', (chunk) => {
    bufOut += chunk.toString();
    let nl;
    while ((nl = bufOut.indexOf('\n')) >= 0) {
      onLine(bufOut.substring(0, nl));
      bufOut = bufOut.substring(nl + 1);
    }
  });

  tunnelProcess.on('close', (code) => {
    console.log('[eSE Tunnel] Cloudflared exited with code ' + code);
    tunnelProcess = null;
    if (tunnelStatus !== 'stopped') {
      tunnelStatus = code === 0 ? 'idle' : 'error';
      if (code !== 0 && !tunnelError) tunnelError = 'cloudflared exited with code ' + code;
    }
  });

  tunnelProcess.on('error', (err) => {
    console.error('[eSE Tunnel] spawn error:', err.message);
    tunnelStatus = 'error';
    tunnelError = err.message;
    tunnelProcess = null;
  });

  return { success: true, status: tunnelStatus };
}

function stop() {
  if (!tunnelProcess) {
    return { success: true, was_running: false };
  }
  tunnelStatus = 'stopped';
  try { tunnelProcess.kill('SIGTERM'); }
  catch (e) { /* ignore */ }
  // Force-kill after 2 s if it didn't exit cleanly
  setTimeout(() => {
    if (tunnelProcess) {
      try { tunnelProcess.kill('SIGKILL'); } catch (e) {}
    }
  }, 2000);
  tunnelURL = null;
  return { success: true, was_running: true };
}

function getStatus() {
  return {
    status: tunnelStatus,
    url: tunnelURL,
    error: tunnelError,
    uptime_ms: startedAt ? (Date.now() - startedAt) : 0,
    binary: findCloudflared()
  };
}

module.exports = { start, stop, getStatus };
