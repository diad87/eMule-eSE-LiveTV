'use strict';
//
// eSE — tunnel.js (v8.0.1: third-party services purged)
//
// HISTORY
//   v7.4.0 dropped Cloudflare Quick Tunnel (AUP risk + project invariant).
//   v8.0.1 drops ntfy.sh discovery + Telegram notifications + public-IP
//          lookups via api.ipify.org / icanhazip.com / ifconfig.me.
//
// WHAT THIS FILE STILL DOES
//   - Generates and caches local secrets (encKey, accessToken) for HTTP auth
//     and the /api/connect-seed LAN pairing flow.
//   - Provides AES-256-CBC envelope encryption (encryptMsg) for that seed.
//   - Asks the local router via UPnP to forward our HTTP port, and asks the
//     same router for its WAN IP (zero third-party services involved).
//
// WHAT THIS FILE NO LONGER DOES
//   - Publishes anything to ntfy.sh.
//   - Sends Telegram messages.
//   - Calls api.ipify.org, icanhazip.com, ifconfig.me, or any similar third
//     party. If your router does not speak UPnP we simply have no public URL
//     and the UI says so honestly. Use Tailscale (100.64/10) or a Tor onion
//     service set up outside eSE if you need cross-NAT access.
//
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const runtimeDir = require('./runtime_dir');

// Local HTTP port — set by init() before setupUPnP().
let PORT = 8080;
function init(port) { PORT = port; }

// ─── Config / secrets ────────────────────────────────────────────────────────
// Writable runtime files MUST live outside the pkg snapshot (which is read-only).
// runtime_dir.js returns %APPDATA%\eSE in pkg mode, __dirname in dev.
const CONFIG_PATH = runtimeDir.join('config.json');

function loadConfig() {
  // Try-read instead of existsSync→read so we don't expose a TOCTOU window
  // where the file could disappear (or be swapped) between the two syscalls
  // (CodeQL js/file-system-race #47-48). Same fix as PR #11.
  let cfg = null;
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch (e) { /* missing / unreadable / not JSON */ }
  if (cfg) {
    let changed = false;
    if (!cfg.encKey)       { cfg.encKey       = crypto.randomBytes(32).toString('hex'); changed = true; }
    if (!cfg.accessToken)  { cfg.accessToken  = crypto.randomBytes(16).toString('hex'); changed = true; }
    if (changed) {
      try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2)); } catch (e) {}
    }
    return cfg;
  }
  const config = {
    secretId:    crypto.randomBytes(8).toString('hex'),
    encKey:      crypto.randomBytes(32).toString('hex'),
    accessToken: crypto.randomBytes(16).toString('hex'),
    createdAt:   new Date().toISOString()
  };
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2)); } catch (e) {}
  console.log('[config] Generated new secrets');
  return config;
}

const CONFIG = loadConfig();

// ─── Symmetric envelope (used by /api/connect-seed) ──────────────────────────

function encryptMsg(text) {
  const key    = Buffer.from(CONFIG.encKey, 'hex');
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(text, 'utf8', 'base64');
  enc += cipher.final('base64');
  return iv.toString('hex') + ':' + enc;
}

// ─── UPnP ─────────────────────────────────────────────────────────────────────
// We ask the local router to forward our port AND for its own WAN IP.
// No DNS lookups, no third-party HTTPS calls. The IP we display is whatever
// the router itself reports via GetExternalIPAddress (SSDP/SOAP, LAN-local).

let upnpClient = null;
let publicUrl  = null;  // computed once setupUPnP succeeds

function getExternalIpViaUpnp() {
  return new Promise((resolve) => {
    if (!upnpClient) return resolve(null);
    try {
      upnpClient.externalIp((err, ip) => {
        if (err || !ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return resolve(null);
        resolve(ip);
      });
    } catch (_) { resolve(null); }
  });
}

async function setupUPnP() {
  try {
    const natupnp = require('nat-upnp-2');
    upnpClient = natupnp.createClient();
    await new Promise((resolve, reject) => {
      upnpClient.portMapping({ public: PORT, private: PORT, ttl: 0, description: 'eSE Streaming' },
        (err) => err ? reject(err) : resolve());
    });
    console.log('[UPnP] Port ' + PORT + ' mapped on router');
    const ip = await getExternalIpViaUpnp();
    if (ip) {
      publicUrl = 'http://' + ip + ':' + PORT;
      console.log('');
      console.log('  ==========================================');
      console.log('  PUBLIC URL (P2P): ' + publicUrl);
      console.log('  ==========================================');
      console.log('  No third parties. Direct connection.');
      console.log('');
    } else {
      console.log('[UPnP] Port mapped but router did not report a WAN IP.');
      console.log('[UPnP] Use http://localhost:' + PORT + ' locally, or set up Tailscale / a Tor onion service for cross-NAT access.');
    }
  } catch (e) {
    // CodeQL js/log-injection — e.message can carry CR/LF from upstream
    // network errors. Same hardening PR #11 applied to publishUrl's [ntfy]
    // logger; that function is gone in v8.0.1 but UPnP still surfaces
    // network errors so apply the same sanitization here.
    const _safeMsg = String(e && e.message).replace(/[\r\n\t]+/g, ' ');
    console.log('[UPnP] Failed: ' + _safeMsg);
    console.log('[UPnP] No public URL available. Use LAN (http://localhost:' + PORT + '),');
    console.log('[UPnP] Tailscale (100.64/10), or a Tor onion service set up manually.');
  }
}

function removeUPnP() {
  if (upnpClient) {
    try { upnpClient.portUnmapping({ public: PORT }); console.log('[UPnP] Port ' + PORT + ' unmapped'); } catch (e) {}
    upnpClient = null;
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────
// Legacy fields LOOKUP_TOPIC / LOOKUP_URL / tunnelUrl / publishUrl removed in
// v8.0.1. Callers were updated; any leftover consumer reading them gets
// `undefined`, which the prior code already treated as "no remote URL".

module.exports = {
  init,
  CONFIG,
  encryptMsg,
  setupUPnP,
  removeUPnP,
  get tunnelUrl() { return null; },     // legacy stub — no third-party tunnel
  get publicUrl() { return publicUrl; },
  get active()    { return !!publicUrl; },
};
