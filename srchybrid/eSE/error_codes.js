'use strict';
//
// error_codes.js — Self-contained diagnostic code generator for bug reports.
//
// When something fails in the UI the user copies one short string like:
//     [ESE 8.0.3] E03-K1L0U1-h:ae9c-up:28m
// and pastes it in a forum reply or GitHub issue. Decoding it gives us:
//   ESE   — product
//   8.0.3 — version (so we know if their bug is already fixed)
//   E03   — which error path tripped (see ERROR_CODES below)
//   K0/K1 — Kademlia connected?
//   L0/L1 — logged in to eMule WebServer?
//   U0/U1 — UPnP port mapping succeeded?
//   h:xxxx — first 4 chars of the build hash (identifies the exact binary)
//   up:NNm — minutes since ese-server.exe boot (boot-loop detection)
//
// No PII. No IPs. No filenames. No tokens. Just version + state bits.

const fs   = require('fs');
const path = require('path');

// ─── Version ───────────────────────────────────────────────────────────────
// Hardcoded here AND read from package.json as a sanity check. The hardcoded
// value wins if package.json is missing or unreadable inside the pkg snapshot.
const VERSION = '8.0.9';

// ─── Build hash ────────────────────────────────────────────────────────────
// At build time `tools/bake_build_hash.js` writes a 40-char SHA into
// build_hash.txt. If absent (e.g. dev run via `node server.js`) we fall back
// to a stable hash derived from the current source root mtime so two
// different dev runs still produce distinguishable codes.
let _buildHash = null;
function getBuildHash() {
  if (_buildHash) return _buildHash;
  try {
    const p = path.join(__dirname, 'build_hash.txt');
    const txt = fs.readFileSync(p, 'utf8').trim();
    if (/^[0-9a-f]{4,}$/i.test(txt)) {
      _buildHash = txt.toLowerCase().substring(0, 8);
      return _buildHash;
    }
  } catch (e) { /* fall through */ }
  // Dev fallback: derive from server.js mtime so it's stable per build.
  try {
    const st = fs.statSync(path.join(__dirname, 'server.js'));
    const ms = Math.floor(st.mtimeMs).toString(16);
    _buildHash = ('dev0' + ms).slice(-8);
  } catch (e) { _buildHash = 'devx0000'; }
  return _buildHash;
}

// ─── Error code table ──────────────────────────────────────────────────────
// Numbers are STABLE. Never reuse a slot — if a path is retired, leave its
// number reserved with a comment. Adding a new path = append a new number.
const ERROR_CODES = {
  // 00–09: bootstrap / process lifecycle
  E00: 'unknown',                          // catch-all when we can't classify
  E01: 'emule_process_not_running',        // emule.exe is not in tasklist
  E02: 'emule_ws_login_failed',            // WS responded but auth was wrong (the orphan-bug symptom)
  E03: 'emule_ws_timeout',                 // WS accepted TCP but didn't respond in 8 s
  E04: 'emule_ws_unreachable',             // ECONNREFUSED / port 4711 closed
  E05: 'ese_port_busy',                    // server.listen(8080) EADDRINUSE after retry
  E06: 'ese_uncaught_exception',           // node crashed; we logged it before dying

  // 10–19: discovery / search
  E10: 'search_no_sources',                // eMule returned an empty result set
  E11: 'search_timeout',                   // emule_search waited too long
  E12: 'ed2k_link_invalid',                // pasted link didn't parse
  E13: 'kad_not_connected',                // requested an op that needs Kad before it joined
  E14: 'live_stream_not_found',            // /api/live/play/<hash> doesn't match anything we know

  // 20–29: media pipeline
  E20: 'ffmpeg_not_found',                 // findFfmpeg returned null
  E21: 'ffmpeg_spawn_failed',              // ffmpeg.exe didn't start (codec, permissions)
  E22: 'hls_reconstruction_stuck',         // live_chunks_received_total stays at 0
  E23: 'rtmp_ingest_failed',               // OBS connected but no chunks reached us

  // 30–39: network / NAT
  E30: 'upnp_failed',                      // router refused or doesn't speak UPnP
  E31: 'no_public_url',                    // UPnP mapped but couldn't read external IP
  E32: 'firewall_blocks_lan',              // we suspect the OS firewall (rough heuristic)
};
// (Future: 40–49 reserved for privacy/tunnel, 50–59 reserved for build/release.)

function codeFor(name) {
  // Reverse lookup; defaults to E00 if caller passes a name we don't know.
  for (const k of Object.keys(ERROR_CODES)) {
    if (ERROR_CODES[k] === name) return k;
  }
  return 'E00';
}

// ─── Runtime state probes ──────────────────────────────────────────────────
// These run synchronously and must NEVER throw — we want the code generator
// to work even when half the runtime is on fire.

const _bootedAt = Date.now();
function uptimeMinutes() {
  return Math.floor((Date.now() - _bootedAt) / 60000);
}

// Filled in by server.js via setRuntimeProbes(). Each probe is a function
// returning a boolean; we wrap them in try/catch.
const _probes = {
  kadConnected:  () => false,
  emuleLoggedIn: () => false,
  upnpActive:    () => false,
};
function setRuntimeProbes(probes) {
  if (probes && typeof probes.kadConnected  === 'function') _probes.kadConnected  = probes.kadConnected;
  if (probes && typeof probes.emuleLoggedIn === 'function') _probes.emuleLoggedIn = probes.emuleLoggedIn;
  if (probes && typeof probes.upnpActive    === 'function') _probes.upnpActive    = probes.upnpActive;
}

function _bit(fn) {
  try { return fn() ? '1' : '0'; } catch (e) { return '0'; }
}
function stateBits() {
  return 'K' + _bit(_probes.kadConnected)
       + 'L' + _bit(_probes.emuleLoggedIn)
       + 'U' + _bit(_probes.upnpActive);
}

// ─── Public API ────────────────────────────────────────────────────────────

function buildCode(codeNameOrId) {
  // Accept either an enum name ('emule_ws_login_failed') or a code id ('E02').
  let id;
  if (typeof codeNameOrId === 'string' && /^E\d{2}$/.test(codeNameOrId)) {
    id = codeNameOrId;
  } else {
    id = codeFor(codeNameOrId);
  }
  return '[ESE ' + VERSION + '] ' + id
       + '-' + stateBits()
       + '-h:' + getBuildHash().substring(0, 4)
       + '-up:' + uptimeMinutes() + 'm';
}

function summary() {
  return {
    version:    VERSION,
    buildHash:  getBuildHash(),
    uptimeMin:  uptimeMinutes(),
    state:      stateBits(),
    codes:      ERROR_CODES,
    sampleCode: buildCode('E00'),
  };
}

module.exports = {
  VERSION,
  ERROR_CODES,
  codeFor,
  buildCode,
  summary,
  setRuntimeProbes,
  getBuildHash,
  stateBits,
  uptimeMinutes,
};
