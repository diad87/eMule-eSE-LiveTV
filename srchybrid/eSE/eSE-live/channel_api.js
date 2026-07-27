/**
 * eSE Live — Channel API
 * HTTP route handlers for /api/live/* endpoints.
 * Manages start/stop streaming, status, source listing, and HLS serving.
 * Max ~250 lines.
 */
'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const pipeline = require('./ffmpeg_pipeline');
const deviceScanner = require('./device_scanner');
const channelSearch = require('./channel_search');
const favorites = require('./favorites_manager');
const rtmpServer = require('./rtmp_server');
const wsTunnel = require('./ws_tunnel');
const thumbExtractor = require('./thumbnail_extractor');
const updateNotifier = require('./update_notifier');  // D6: GitHub release polling
const nodesBootstrap = require('./nodes_bootstrap');
const utils = require('../utils');

const HLS_LIVE_DIR = path.join(os.tmpdir(), 'eMule_RTMP');
const LIVE_DIR = HLS_LIVE_DIR;
let HLS_JS_BUNDLE = path.join(__dirname, 'vendor', 'hls.min.js');
if (!fs.existsSync(HLS_JS_BUNDLE)) {
  try {
    HLS_JS_BUNDLE = require.resolve('hls.js/dist/hls.min.js');
  } catch (e) {
    HLS_JS_BUNDLE = '';
    console.warn('[eSE Live] Bundled hls.js not found:', e.message);
  }
}

// Ensure live segment directory exists
try { if (!fs.existsSync(LIVE_DIR)) fs.mkdirSync(LIVE_DIR, { recursive: true }); } catch (e) { console.warn('[eSE Live] Failed to create live dir:', e.message); }

// Stream metadata (title, category, language)
let streamMeta = { title: '', category: 'general', language: 'es' };

// Ghost-viewer fix (2026-06) — player-alive heartbeat relay.
// The watch pages fetch HLS from THIS server (/hls-local, /hls), so eMule's
// own ghost-viewer watchdog never sees those fetches. Relay a throttled
// "player is alive" ping to eMule's /api/live/player-alive so its 60 s
// idle auto-leave only fires when the browser really stopped fetching.
// Fire-and-forget; errors ignored (eMule offline just means nothing to do).
let lastAliveRelayMs = 0;
function relayPlayerAlive(streamKey) {
  const now = Date.now();
  if (now - lastAliveRelayMs < 10000) return;
  lastAliveRelayMs = now;
  try {
    const key = channelSearch.canonicalStreamKey(streamKey);
    const suffix = /^[a-f0-9]{32}$/.test(key) ? '?key=' + encodeURIComponent(key) : '';
    http.get('http://127.0.0.1:4711/api/live/player-alive' + suffix, { timeout: 3000 },
      (r) => r.resume()).on('error', () => {});
  } catch (e) { /* ignore */ }
}

// nodes.dat supply-chain hardening
// Hardened nodes.dat bootstrap. No third-party request or config write happens
// by default. Developers can
// opt in only by providing an HTTPS URL, its exact SHA-256 and an absolute
// destination. The helper validates the binary format before replacing it.
nodesBootstrap.startFromEnv().then(result => {
  if (result.status === 'installed') {
    console.log('[eSE Boot] Verified nodes.dat installed at ' + result.destination);
  }
}).catch(error => {
  console.warn('[eSE Boot] Explicit nodes.dat install rejected: ' + String(error.message).replace(/[\r\n]/g, ' '));
});

// Tier 2.1 — First-run flag persisted next to preferences.ini.
// The flag file just has to exist; its content is irrelevant. We store it
// under the user's eMule config dir so reinstalling doesn't reset the flag,
// but a fresh ZIP extraction (zero-config first run) shows the wizard.
const ESE_FLAG_FILE = path.join(os.homedir(), 'AppData', 'Roaming', 'eMule', 'config', 'eSE_seen.flag');
function isFirstRun() {
  try { return !fs.existsSync(ESE_FLAG_FILE); } catch (e) { return true; }
}
function markFirstRunSeen() {
  try {
    fs.mkdirSync(path.dirname(ESE_FLAG_FILE), { recursive: true });
    fs.writeFileSync(ESE_FLAG_FILE, String(Date.now()));
    return true;
  } catch (e) { return false; }
}

// Public IP detection — NO third parties.
// eMule learns the public IP from Kad's firewall test (v4) and from the
// in-band OP_PUBLICIP_ANSWER_V6 peer observation (v6, CFirewallProberV6).
// We rely ONLY on those, surfaced through /api/live/preflight. If eMule
// hasn't determined the address yet, the UI shows "detecting…" — we never
// fall back to a commercial echo service (api.ipify.org etc.), per the
// project's "100% free, discovery via IP/overlay only" constraint.
/**
 * Handle all /api/live/* routes.
 * @param {URL} url - Parsed URL object.
 * @param {http.IncomingMessage} req
 * @param {http.ServerResponse} res
 * @param {Object} ctx - Shared context {ffmpegPath, hwEncoder, hwEncoderOpts}
 * @returns {boolean} true if handled, false if not a live route
 */
// Auto-detect external ffmpeg streams (started outside eSE API)
let externalStreamDetected = false;
const STREAM_STALE_MS = 15000; // 15s sin actualización = stream muerto

/** Devuelve true si el .m3u8 fue escrito en los últimos STREAM_STALE_MS ms */
function isStreamFresh() {
  const candidates = [
    path.join(HLS_LIVE_DIR, 'stream_0.m3u8'),
    path.join(HLS_LIVE_DIR, 'stream.m3u8')
  ];
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate);
      if ((Date.now() - stat.mtimeMs) < STREAM_STALE_MS) return true;
    } catch (e) { /* no existe */ }
  }
  return false;
}

/** Borra archivos HLS obsoletos para evitar redetecciones fantasma */
function cleanHLSFiles(options) {
  const opts = options || {};
  const staleOnly = opts.staleOnly === true;
  const maxAgeMs = opts.maxAgeMs || STREAM_STALE_MS;
  try {
    const files = fs.readdirSync(HLS_LIVE_DIR);
    let deleted = 0;
    for (const f of files) {
      if (f.endsWith('.m3u8') || f.endsWith('.ts')) {
        const fp = path.join(HLS_LIVE_DIR, f);
        try {
          if (!staleOnly || (Date.now() - fs.statSync(fp).mtimeMs) > maxAgeMs) {
            fs.unlinkSync(fp);
            deleted++;
          }
        } catch (e) {}
      }
    }
    if (deleted > 0) console.log('[eSE Live] Limpiados', deleted, 'archivos HLS obsoletos');
  } catch (e) { /* ignorar si el directorio no existe */ }
}

function detectExternalStream() {
  try {
    const fresh = isStreamFresh();
    const pipelineStatus = pipeline.getStatus().status;
    const pipelineActive = pipelineStatus === 'streaming' || pipelineStatus === 'starting';

    if (fresh && !pipelineActive && !externalStreamDetected) {
      // The canonical C++ broadcaster writes into this same directory and is
      // imported with its real stream key by pollEmuleChannels(). Older code
      // also registered a synthetic external_<timestamp> channel here, so one
      // broadcast appeared twice and the fake entry could never be joined.
      externalStreamDetected = true;
      console.log('[eSE Live] HLS output detected; waiting for canonical eMule channel metadata');
    } else if (!fresh && externalStreamDetected) {
      // El .m3u8 no se actualiza — el stream ha muerto
      externalStreamDetected = false;
      console.log('[eSE Live] HLS output ended');
      cleanHLSFiles(); // evitar redetección en el próximo ciclo
    }
  } catch (e) { console.warn('[eSE Live] External stream detection error:', e.message); }
}
if (process.env.ESE_TEST_MODE !== '1') {
  setInterval(detectExternalStream, 5000);
  // Al arrancar: limpiar archivos HLS viejos antes de la primera detección
  cleanHLSFiles({ staleOnly: true, maxAgeMs: STREAM_STALE_MS });
  detectExternalStream();
}


function handleRoute(url, req, res, ctx) {
  const p = url.pathname;

  // Keep browser playback independent from Internet/CDN availability.  The
  // file is packaged with ese-server.exe and also works from a source checkout.
  if (p === '/live/vendor/hls.min.js') {
    if (!HLS_JS_BUNDLE || !fs.existsSync(HLS_JS_BUNDLE)) {
      res.writeHead(503, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end('/* bundled hls.js unavailable */');
      return true;
    }
    const stat = fs.statSync(HLS_JS_BUNDLE);
    res.writeHead(200, {
      'Content-Type': 'application/javascript; charset=utf-8',
      'Content-Length': stat.size,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'X-Content-Type-Options': 'nosniff'
    });
    fs.createReadStream(HLS_JS_BUNDLE).pipe(res);
    return true;
  }

  // --- eSE HLS Segment Serving ---
  // Two flavors:
  //   /hls/<file>             -> root HLS dir (broadcaster's own files, legacy)
  //   /hls-local/<HASH>/<file> -> per-stream viewer dir (works without eMule WebServer,
  //                               required on PC2 when its WebServer can't bind 4711)
  if (p.startsWith('/hls-local/')) {
    const parts = p.split('/').filter(Boolean); // ["hls-local", HASH, FILE]
    if (parts.length !== 3 || !/^[a-fA-F0-9]{32}$/.test(parts[1])) {
      res.writeHead(400); res.end('bad path'); return true;
    }
    const fileName = parts[2];
    const ext = require('path').extname(fileName).toLowerCase();
    if (ext !== '.m3u8' && ext !== '.ts') { res.writeHead(403); res.end('Forbidden'); return true; }
    relayPlayerAlive(parts[1]);  // key-scoped proof that this player lives
    const filePath = require('path').join(HLS_LIVE_DIR, parts[1].toLowerCase(), fileName);
    try {
      const fstat = require('fs').statSync(filePath);
      const mime = ext === '.m3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t';
      res.writeHead(200, { 'Content-Type': mime, 'Content-Length': fstat.size, 'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30', 'Access-Control-Allow-Origin': '*' });
      require('fs').createReadStream(filePath).pipe(res);
    } catch(e) { res.writeHead(404); res.end('Not found: ' + filePath); }
    return true;
  }
  if (p.startsWith('/hls/')) {
    const fileName = require('path').basename(p);
    const ext = require('path').extname(fileName).toLowerCase();
    if (ext !== '.m3u8' && ext !== '.ts') { res.writeHead(403); res.end('Forbidden'); return true; }
    const filePath = require('path').join(HLS_LIVE_DIR, fileName);
    try {
      const fstat = require('fs').statSync(filePath);
      const mime = ext === '.m3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t';
      res.writeHead(200, { 'Content-Type': mime, 'Content-Length': fstat.size, 'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30', 'Access-Control-Allow-Origin': '*' });
      require('fs').createReadStream(filePath).pipe(res);
    } catch(e) { res.writeHead(404); res.end('Not found'); }
    return true;
  }
  if (p === '/live/watch/local') {
    const html = require('../live_player_html')();
    // v7.1.7 — no-cache for the same reason as /live above.
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(html);
    return true;
  }

  // === GET /live/debug — Technical debug dashboard ===
  if (p === '/live/debug') {
    try {
      const debugPage = require('./live_tv_debug_page');
      const html = debugPage.render(pipeline.getStatus(), streamMeta);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Debug page error: ' + e.message);
    }
    return true;
  }

  // === GET /api/live/debug — Proxy P2P debug state from eMule C++ backend ===
  if (p === '/api/live/debug') {
    const debugReq = http.get('http://127.0.0.1:4711/api/live/debug', { timeout: 3000 }, (debugRes) => {
      let body = '';
      debugRes.on('data', d => body += d);
      debugRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
            'Access-Control-Allow-Origin': '*'
          });
          res.end(JSON.stringify(data));
        } catch (e) {
          jsonResponse(res, 200, { error: 'parse_error', raw: body.substring(0, 200) });
        }
      });
    });
    debugReq.on('error', () => {
      jsonResponse(res, 200, { error: 'offline', peers: {}, counters: {}, buffer: {} });
    });
    debugReq.on('timeout', () => {
      debugReq.destroy();
      jsonResponse(res, 200, { error: 'timeout', peers: {}, counters: {}, buffer: {} });
    });
    return true;
  }

  // === GET /api/live/join — Proxy join request to eMule C++ backend ===
  if (p === '/api/live/join') {
    const key = url.searchParams.get('key') || '';
    const title = url.searchParams.get('title') || 'Live';
    // Validate key: hex 32 chars only
    if (!/^[a-fA-F0-9]{32}$/.test(key)) {
      jsonResponse(res, 400, { error: 'invalid_key', message: 'Stream key must be 32 hex characters.' });
      return true;
    }
    const joinUrl = 'http://127.0.0.1:4711/api/live/join?key=' + encodeURIComponent(key) + '&title=' + encodeURIComponent(title);
    const joinReq = http.get(joinUrl, { timeout: 5000 }, (joinRes) => {
      let body = '';
      joinRes.on('data', d => body += d);
      joinRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          jsonResponse(res, 200, data);
        } catch (e) {
          jsonResponse(res, 200, { success: true, raw: body.substring(0, 200) });
        }
      });
    });
    joinReq.on('error', () => {
      jsonResponse(res, 200, { success: false, error: 'eMule offline' });
    });
    joinReq.on('timeout', () => {
      joinReq.destroy();
      jsonResponse(res, 200, { success: false, error: 'timeout' });
    });
    return true;
  }

  // === /api/live/leave — Proxy leave to eMule (ghost-viewer fix 2026-06) ===
  // Hit by the watch pages' pagehide beacon (sendBeacon POSTs; we accept any
  // method). Forwarded as GET to eMule's marshaled /api/live/leave.
  if (p === '/api/live/leave') {
    const leaveKey = channelSearch.canonicalStreamKey(url.searchParams.get('key'));
    const leaveSuffix = /^[a-f0-9]{32}$/.test(leaveKey)
      ? '?key=' + encodeURIComponent(leaveKey) : '';
    const leaveReq = http.get('http://127.0.0.1:4711/api/live/leave' + leaveSuffix, { timeout: 5000 }, (leaveRes) => {
      let body = '';
      leaveRes.on('data', d => body += d);
      leaveRes.on('end', () => {
        try { jsonResponse(res, 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, { success: true, raw: body.substring(0, 200) }); }
      });
    });
    leaveReq.on('error', () => {
      jsonResponse(res, 200, { success: false, error: 'eMule offline' });
    });
    leaveReq.on('timeout', () => {
      leaveReq.destroy();
      jsonResponse(res, 200, { success: false, error: 'timeout' });
    });
    return true;
  }

  // === /api/live/privacy — D2 (Sprint D): proxy mode read/set to eMule (4711).
  // GET reads current state; GET with ?mode=/?fallback= sets it (the eMule
  // endpoint parses query params regardless of method). The change persists on
  // eMule's side (mirrored into prefs, saved on exit).
  if (p === '/api/live/privacy') {
    const changesPrivacy = url.searchParams.has('mode') || url.searchParams.has('fallback');
    if (changesPrivacy && req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      jsonResponse(res, 405, { error: 'method_not_allowed', expected: 'POST' });
      return true;
    }
    // SSRF hardening (CodeQL js/request-forgery): pin the upstream host/port to the LOCAL
    // eMule via the options object (no user string in the host), and forward only the known
    // params re-encoded — so no user-controlled value can redirect the request.
    const fwd = new URLSearchParams();
    for (const k of ['mode', 'fallback']) { const v = url.searchParams.get(k); if (v != null) fwd.set(k, v); }
    const qs = fwd.toString();
    const preq = http.get({ host: '127.0.0.1', port: 4711, path: '/api/live/privacy' + (qs ? '?' + qs : ''), timeout: 4000 }, (pres) => {
      let body = '';
      pres.on('data', d => body += d);
      pres.on('end', () => {
        try { jsonResponse(res, 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, { error: 'parse_error', raw: body.substring(0, 200) }); }
      });
    });
    preq.on('error',   () => jsonResponse(res, 200, { error: 'offline' }));
    preq.on('timeout', () => { preq.destroy(); jsonResponse(res, 200, { error: 'timeout' }); });
    return true;
  }

  // === /api/live/privacy/* sub-paths (circuits, peers, test_circuit) — proxy to eMule.
  // The /privacy mode page polls /circuits to show handshake progress and posts to
  // /test_circuit to build a DELIBERATE test circuit (manual; never auto-engaged).
  // GET-only; eMule parses query params on any method. test_circuit blocks up to
  // ~2.5 s on eMule's side, so the timeout here is wider than the simple read above.
  // Trailing slash in the prefix so it never shadows the exact /api/live/privacy.
  if (p.startsWith('/api/live/privacy/')) {
    // SSRF hardening (CodeQL js/request-forgery): pin the host, ALLOWLIST the sub-path (so a
    // user can't reach an unintended local endpoint via path traversal) and re-encode the
    // query. Unknown sub-paths 404 instead of being proxied.
    const sub = p.slice('/api/live/privacy/'.length);
    if (!/^(circuits|peers|test_circuit)$/.test(sub)) { jsonResponse(res, 404, { error: 'not_found' }); return true; }
    const qs = url.searchParams.toString();
    const preq = http.get({ host: '127.0.0.1', port: 4711, path: '/api/live/privacy/' + sub + (qs ? '?' + qs : ''), timeout: 6000 }, (pres) => {
      let body = '';
      pres.on('data', d => body += d);
      pres.on('end', () => {
        try { jsonResponse(res, 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, { error: 'parse_error', raw: body.substring(0, 200) }); }
      });
    });
    preq.on('error',   () => jsonResponse(res, 200, { error: 'offline' }));
    preq.on('timeout', () => { preq.destroy(); jsonResponse(res, 200, { error: 'timeout' }); });
    return true;
  }

  // === GET /privacy — Sprint 4 J.2: privacy & data handling page ===
  if (p === '/privacy') {
    const html = '<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>eSE Live — Privacidad</title>' +
      '<style>body{background:#0a0a0e;color:#cbd5e1;font-family:system-ui,sans-serif;line-height:1.6;max-width:760px;margin:0 auto;padding:40px 20px}' +
      'h1{color:#fff;font-size:28px;margin-bottom:6px}h2{color:#a5b4fc;font-size:18px;margin-top:32px;border-bottom:1px solid #2a2a2e;padding-bottom:6px}' +
      'a{color:#818cf8}code{background:#13141a;padding:1px 6px;border-radius:3px;font-size:90%}' +
      '.warn{background:rgba(220,38,38,.08);border-left:3px solid #ef4444;padding:10px 14px;border-radius:4px;color:#fca5a5;margin:14px 0;font-size:13px}' +
      '.ok{background:rgba(16,185,129,.08);border-left:3px solid #10b981;padding:10px 14px;border-radius:4px;color:#86efac;margin:14px 0;font-size:13px}' +
      '</style></head><body>' +
      '<a href="/live" style="font-size:12px">← Volver a Live</a>' +
      '<h1>Privacidad y datos en eSE Live</h1>' +
      // D6 (Sprint D, web UI): the mode selector. Persists on eMule's side.
      '<div style="background:#13141a;border:1px solid #2a2a2e;border-radius:8px;padding:16px 18px;margin:18px 0">' +
      '<div style="color:#fff;font-weight:600;margin-bottom:8px">&#129529; Modo de enrutado privado (Kad / LiveTV)</div>' +
      '<select id="ese-mode" style="background:#0a0a0e;color:#e0e0e0;border:1px solid #3a3a3e;border-radius:6px;padding:8px 12px;font-size:14px;width:100%;box-sizing:border-box;margin-bottom:8px">' +
      '<option value="direct">Directo — sin túnel (máxima velocidad; tu IP es visible)</option>' +
      '<option value="adaptive">Adaptativo — túnel solo para canales privados / palabras sensibles</option>' +
      '<option value="tunneled">Tunelizado — el control (búsqueda/subscribe) va por túnel onion</option>' +
      '</select>' +
      '<div id="ese-mode-status" style="font-size:12px;color:#6b7280">Cargando estado…</div>' +
      '<div style="font-size:12px;color:#fbbf24;margin-top:10px;line-height:1.5">&#9888;&#65039; Honestidad: el anonimato real necesita <b>3+ nodos del fork</b> en la red. Con 2 nodos (hop1=hop2 = mismo equipo) el anonimato es 0. Además, en este modo los <b>chunks de vídeo siguen yendo directos</b> — tu IP es visible al emisor al pedir chunks. El plano de datos por túnel llega en una versión posterior.</div>' +
      // Manual tunnel-circuit tester + live circuit readout. This is the SAFE way
      // to validate the tunneled control plane on a 2-PC setup: nothing builds a
      // circuit on its own (no auto-engage of the untested path on your working
      // direct stream) — you click here on purpose and watch the handshake.
      '<div style="margin-top:12px;border-top:1px solid #2a2a2e;padding-top:12px">' +
      '<button id="ese-test-circ" style="background:#1e293b;color:#a5b4fc;border:1px solid #3a3a3e;border-radius:6px;padding:8px 14px;font-size:13px;cursor:pointer">Probar circuito de t&uacute;nel (2-hop)</button> ' +
      '<button id="ese-refresh-circ" style="background:#13141a;color:#9ca3af;border:1px solid #3a3a3e;border-radius:6px;padding:8px 12px;font-size:13px;cursor:pointer">Actualizar</button>' +
      '<div id="ese-circ-status" style="font-size:12px;color:#6b7280;margin-top:8px"></div>' +
      '<pre id="ese-circ-list" style="font-size:12px;color:#9ca3af;margin:6px 0 0;white-space:pre-wrap;font-family:ui-monospace,monospace"></pre>' +
      '<div style="font-size:11px;color:#6b7280;margin-top:6px">Construir un circuito necesita <b>otro nodo del fork conectado</b>. En un solo PC dir&aacute; &laquo;sin candidatos&raquo; &mdash; es lo esperado. Con el 2&ordm; equipo encendido ver&aacute;s el handshake (Pendiente&rarr;Activo). 2-hop con un solo peer reusa el mismo peer: prueba el protocolo, no da anonimato (eso necesita 3+ nodos).</div>' +
      '</div>' +
      '</div>' +
      '<p>eSE Live es una aplicación P2P descentralizada que se ejecuta enteramente en tu equipo. No hay servidor central que recopile datos. Aun así, conviene que entiendas qué información se expone.</p>' +
      '<h2>Datos que SÍ se exponen</h2>' +
      '<ul>' +
      '<li><b>Tu IP pública</b> es visible para los peers a los que te conectes (igual que en BitTorrent o eD2K). Los peers que descarguen tu emisión saben tu IP.</li>' +
      '<li>Si emites, tu <b>IP + puertos TCP/UDP</b> se publican en la red Kad (DHT pública). Cualquiera buscando "eselive" puede encontrarte.</li>' +
      '<li>Si usas un overlay externo (Tailscale, Tor, etc.) para acceso público, ese proveedor verá metadatos según su política.</li>' +
      '<li><code>nodes.dat</code> no se descarga en segundo plano. Una instalación de desarrollo solo puede habilitarla indicando explícitamente URL HTTPS, SHA-256 y destino. Tu IP pública se detecta sin terceros: vía Kad (v4) y observación de peer in-band (v6).</li>' +
      '<li>La comprobación e instalación de actualizaciones es manual; el panel no consulta servicios de releases en segundo plano.</li>' +
      '</ul>' +
      '<h2>Datos que NO se recogen</h2>' +
      '<div class="ok">' +
      '<ul style="margin:0">' +
      '<li>No hay analítica ni telemetría enviada a ningún servidor.</li>' +
      '<li>No hay cuenta de usuario, login ni cookies de seguimiento.</li>' +
      '<li>No se almacena tu historial de visualización en ningún sitio remoto.</li>' +
      '<li>No se comparte tu lista de archivos con nadie aparte del propio protocolo eD2K (que tú decides qué carpetas compartir).</li>' +
      '</ul></div>' +
      '<h2>Datos almacenados localmente</h2>' +
      '<ul>' +
      '<li><code>%LOCALAPPDATA%\\eMule\\config\\preferences.ini</code> — preferencias de eMule</li>' +
      '<li><code>%LOCALAPPDATA%\\eMule\\config\\nodes.dat</code> — caché de nodos Kad</li>' +
      '<li><code>%APPDATA%\\eMule\\config\\eSE_seen.flag</code> — flag del wizard ya visto</li>' +
      '<li><code>%TEMP%\\eMule_RTMP\\</code> — segmentos HLS temporales (auto-limpian al cerrar)</li>' +
      '</ul>' +
      '<h2>Riesgos a considerar</h2>' +
      '<div class="warn">' +
      '<ul style="margin:0">' +
      '<li>Cualquier red P2P expone tu IP. Si te preocupa, considera usar VPN.</li>' +
      '<li>El contenido que emitas/distribuyas es responsabilidad tuya. No verificamos legalidad.</li>' +
      '<li>Si usas Tailscale o Tor como overlay, su uso queda sujeto a las TOS de cada proveedor.</li>' +
      '<li>Las claves de stream son públicas en Kad; no son secretas. No emitas contenido confidencial sin cifrado adicional.</li>' +
      '</ul></div>' +
      '<h2>Cómo borrar todo</h2>' +
      '<ol>' +
      '<li>Cierra eMule y ese-server.exe.</li>' +
      '<li>Borra las carpetas listadas arriba.</li>' +
      '<li>Borra <code>%TEMP%\\eMule_RTMP\\</code> si quedan restos.</li>' +
      '</ol>' +
      '<p style="font-size:12px;color:#6b7280;margin-top:32px">eSE Live es software libre (GPL v2). Toda la lógica está en el código fuente abierto en <a href="https://github.com/diad87/eMule-eSE-LiveTV">GitHub</a>.</p>' +
      // D6 selector wiring: read current mode on load, set it on change. The
      // eMule endpoint parses query params on any method, so a GET suffices.
      '<script>(function(){' +
      'var sel=document.getElementById("ese-mode");var st=document.getElementById("ese-mode-status");' +
      'function show(d){if(d&&d.mode){sel.value=d.mode;var r=d.runtime||{};var c=r.circuitsActive||0;var rs=r.routeState||"?";' +
      'var rl=({kad6:"Kad6 activo",tunnel_kad2_compat:"túnel Kad2 compatible",kad2_fallback:"fallback Kad2",kad2_direct:"Kad2 directo",blocked_waiting_kad6:"bloqueado esperando Kad6"})[rs]||rs;' +
      'st.textContent="Modo: "+d.mode+" · fallback: "+(d.fallback||"?")+" · ruta: "+rl+" · circuitos túnel activos: "+c' +
      '+" · celdas TX/RX: "+(r.cellsSent||0)+"/"+(r.cellsRecv||0)+" · bytes túnel TX/RX: "+(r.bytesSent||0)+"/"+(r.bytesRecv||0)+" · RTT medio: "+(r.meanRttMs?r.meanRttMs+" ms":"—")}' +
      'else{st.textContent="No se pudo leer el estado (¿eMule abierto en este equipo?)"}}' +
      'function load(){fetch("/api/live/privacy").then(function(r){return r.json()}).then(show).catch(function(){st.textContent="eMule no responde"})}' +
      'sel.addEventListener("change",function(){st.textContent="Aplicando…";' +
      'fetch("/api/live/privacy?mode="+encodeURIComponent(sel.value),{method:"POST",headers:{"X-Requested-With":"eSE"}}).then(function(r){return r.json()}).then(function(d){show(d);if(d&&d.mode)st.textContent="Guardado: "+d.mode+" — persiste al cerrar eMule"}).catch(function(){st.textContent="eMule no responde"})});' +
      // Tunnel-circuit tester remains a manual diagnostic; Adaptive/Tunneled now auto-seed.
      'var tc=document.getElementById("ese-test-circ");var rc=document.getElementById("ese-refresh-circ");' +
      'var cstat=document.getElementById("ese-circ-status");var clist=document.getElementById("ese-circ-list");' +
      'function stES(s){return s==="Active"?"ACTIVO":s==="Pending"?"Pendiente":s==="HalfBuilt"?"Medio-construido":s==="Built"?"Construido":s==="Destroyed"?"Destruido":s}' +
      'function showCircs(d){if(!d||!d.circuits||d.total===0){clist.textContent="(0 circuitos)";return}' +
      'var t="";for(var i=0;i<d.circuits.length;i++){var c=d.circuits[i];' +
      'var au=c.role==="Relay"?"—":(c.auth_ok?(c.state==="Active"?"v2":"v2…"):(c.state==="Active"?"v1":"-"));' +
      't+=c.circ_id+"  "+stES(c.state)+"  "+c.hop_count+" hop  "+Math.round((c.age_ms||0)/1000)+"s  "+au+"  ("+c.role+")\\n"}clist.textContent=t}' +
      'function loadCircs(){fetch("/api/live/privacy/circuits").then(function(r){return r.json()}).then(showCircs).catch(function(){clist.textContent="(no se pudo leer circuitos)"})}' +
      'var pn=0,pt=null;function poll(){pn=0;if(pt)clearInterval(pt);pt=setInterval(function(){loadCircs();if(++pn>12){clearInterval(pt);pt=null}},1500)}' +
      'if(tc)tc.addEventListener("click",function(){cstat.textContent="Construyendo circuito…";' +
      'fetch("/api/live/privacy/test_circuit?hops=2").then(function(r){return r.json()}).then(function(d){' +
      'if(d&&d.ok){cstat.textContent="Circuito "+d.circuit_id+" iniciado — mira el handshake abajo";poll()}' +
      'else{cstat.textContent="Sin candidatos — "+((d&&d.reason)||"no hay peer del fork conectado")+" (normal en 1 solo PC)"}}).catch(function(){cstat.textContent="eMule no responde"})});' +
      'if(rc)rc.addEventListener("click",loadCircs);' +
      'load();loadCircs();})();</script>' +
      '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return true;
  }

  // v9.1 packages are installed manually after the published SHA-256 has
  // been verified. Keep the legacy route explicit and fail closed without
  // network access so an older dashboard cannot revive the removed updater.
  if (p === '/api/eSE/update/check') {
    jsonResponse(res, 410, {
      update_available: false,
      disabled: true,
      reason: 'manual_updates_only',
    });
    return true;
  }

  // === GET /api/live/logs/tail — Sprint 2 N.1: tail eMule.log live ===
  // Returns the last N lines of eMule.log (default 200). Used by /live/logs UI.
  if (p === '/api/live/logs/tail') {
    const n = Math.min(2000, parseInt(url.searchParams.get('n'), 10) || 200);
    // eMule.log is in the same dir as emule.exe (or its config). We'll search a
    // few well-known locations; the first hit wins. Same approach as nodes.dat.
    const candidates = [
      path.join(os.homedir(), 'AppData', 'Local',   'eMule', 'logs', 'eMule.log'),
      path.join(os.homedir(), 'AppData', 'Roaming', 'eMule', 'logs', 'eMule.log'),
      path.join(os.homedir(), 'AppData', 'Local',   'eMule', 'eMule.log'),
    ];
    let logPath = null;
    for (const c of candidates) { try { fs.statSync(c); logPath = c; break; } catch(e) {} }
    if (!logPath) { jsonResponse(res, 200, { lines: [], path: null, error: 'no_log_found' }); return true; }
    try {
      // Open first, then fstat the descriptor — no stat/open race on a file
      // that rotates while we read it.
      const fd = fs.openSync(logPath, 'r');
      let buf;
      try {
        const stat = fs.fstatSync(fd);
        // Read at most last 256 KB to keep the request snappy on huge logs
        const startAt = Math.max(0, stat.size - 256 * 1024);
        buf = Buffer.alloc(stat.size - startAt);
        fs.readSync(fd, buf, 0, buf.length, startAt);
      } finally {
        fs.closeSync(fd);
      }
      const lines = buf.toString('utf8').split(/\r?\n/);
      jsonResponse(res, 200, {
        lines: lines.slice(-n),
        path: logPath,
        size: stat.size,
        truncated: startAt > 0,
      });
    } catch (e) {
      jsonResponse(res, 200, { lines: [], path: logPath, error: e.message });
    }
    return true;
  }

  // === GET /live/logs — Sprint 2 N.1: HTML log viewer page ===
  if (p === '/live/logs') {
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>eSE Logs</title>' +
      '<style>body{background:#0a0a0e;color:#cbd5e1;font-family:monospace;font-size:12px;margin:0;padding:0}' +
      '.bar{position:sticky;top:0;background:#13141a;border-bottom:1px solid #2a2a2e;padding:8px 14px;display:flex;gap:12px;align-items:center;font-size:12px}' +
      '.bar a{color:#6b7280;text-decoration:none}.bar a:hover{color:#fff}' +
      '#status{color:#10b981;font-weight:700}' +
      '#logs{padding:10px 14px;white-space:pre-wrap;line-height:1.4;word-break:break-all}' +
      '.l-info{color:#94a3b8}.l-warn{color:#f59e0b}.l-err{color:#ef4444}.l-dbg{color:#475569}' +
      '</style></head><body>' +
      '<div class="bar"><a href="/live">← Live</a><span>📜 eMule logs</span><label><input type="checkbox" id="autoscroll" checked> Auto-scroll</label><label><input type="checkbox" id="autorefresh" checked> Auto-refresh (2s)</label><span id="status">Loading...</span></div>' +
      '<div id="logs">Loading...</div>' +
      '<script>(function(){var box=document.getElementById("logs"),s=document.getElementById("status"),ar=document.getElementById("autorefresh"),as=document.getElementById("autoscroll");function clr(t){if(/error|err |fatal/i.test(t))return"l-err";if(/warn|warning/i.test(t))return"l-warn";if(/debug/i.test(t))return"l-dbg";return"l-info";}function load(){fetch("/api/live/logs/tail?n=400").then(function(r){return r.json();}).then(function(d){if(d.error){s.textContent="error: "+d.error;s.style.color="#ef4444";return;}box.innerHTML="";(d.lines||[]).forEach(function(l){if(!l)return;var sp=document.createElement("span");sp.className=clr(l);sp.textContent=l+"\\n";box.appendChild(sp);});s.textContent=d.lines.length+" lines · "+(d.path||"?")+" · "+(d.size?Math.round(d.size/1024)+" KB":"-");if(as.checked)window.scrollTo(0,document.body.scrollHeight);}).catch(function(e){s.textContent="fetch error";s.style.color="#ef4444";});}load();var iv=setInterval(function(){if(ar.checked)load();},2000);})();</script>' +
      '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return true;
  }

  // === GET /api/holepunch/test — Proxy: manual hole-punch trigger ===
  // Used by the diagnostics UI in /live to verify uTP NAT traversal between
  // two specific endpoints (e.g. office ↔ home). Forwards to C++ backend.
  if (p === '/api/holepunch/test') {
    const qs = url.search || '';
    const proxyReq = http.get('http://127.0.0.1:4711/api/holepunch/test' + qs,
      { timeout: 5000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        try { jsonResponse(res, proxyRes.statusCode || 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, { success: false, error: 'parse_error' }); }
      });
    });
    proxyReq.on('error',   () => jsonResponse(res, 200, { success: false, error: 'eMule offline' }));
    proxyReq.on('timeout', () => { proxyReq.destroy(); jsonResponse(res, 200, { success: false, error: 'timeout' }); });
    return true;
  }

  // Remote access is postponed for v9.1. Keep every legacy Live TV tunnel
  // route present but fail closed so old clients receive an explicit answer.
  if (p === '/api/live/tunnel/start' ||
      p === '/api/live/tunnel/stop' ||
      p === '/api/live/tunnel/status') {
    jsonResponse(res, 410, {
      success: false,
      error: 'gone',
      reason: 'remote_access_postponed'
    });
    return true;
  }

  // === GET /api/live/first_run — Tier 2.1: should we show the wizard? ===
  if (p === '/api/live/first_run') {
    jsonResponse(res, 200, { first_run: isFirstRun() });
    return true;
  }

  // === POST /api/live/first_run/dismiss — User clicked "Got it" ===
  if (p === '/api/live/first_run/dismiss') {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      jsonResponse(res, 405, { error: 'method_not_allowed', expected: 'POST' });
      return true;
    }
    const ok = markFirstRunSeen();
    jsonResponse(res, 200, { success: ok });
    return true;
  }

  // Compatibility status for the updater removed from v9.1.
  if (p === '/api/live/update_status') {
    jsonResponse(res, 200, updateNotifier.getStatus());
    return true;
  }

  // Legacy updater routes fail closed and never spawn a process.
  if (p === '/api/live/update_check' && req.method === 'POST') {
    jsonResponse(res, 410, {
      success: false,
      disabled: true,
      reason: 'manual_updates_only',
    });
    return true;
  }

  if (p === '/api/live/update_run' && req.method === 'POST') {
    jsonResponse(res, 410, {
      success: false,
      disabled: true,
      reason: 'manual_updates_only',
    });
    return true;
  }

  // === POST /api/live/broadcast/start — Proxy: trigger broadcast from web ===
  // Source: testpattern (default) | screen | file | rtmp
  if (p === '/api/live/broadcast/start') {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      jsonResponse(res, 405, { error: 'method_not_allowed', expected: 'POST' });
      return true;
    }
    const qs = url.search || '';
    proxyEmuleJson(res, '/api/live/broadcast/start' + qs, 20000);
    return true;
  }

  // === POST /api/live/broadcast/stop — Proxy: stop broadcast ===
  if (p === '/api/live/broadcast/stop') {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      jsonResponse(res, 405, { error: 'method_not_allowed', expected: 'POST' });
      return true;
    }
    proxyEmuleJson(res, '/api/live/broadcast/stop', 5000);
    return true;
  }

  // === GET /api/live/preflight — Proxy for eMule's own public-IP detection ===
  // No third parties: we pass through ONLY what eMule itself detected —
  // public_ip (v4, from Kad's firewall test) and public_ip_v6 (from the in-band
  // OP_PUBLICIP_ANSWER_V6 peer observation). If neither is known yet, both stay
  // empty and the UI shows "detecting…" instead of querying a commercial echo
  // service. The Kad firewall test can take 30-90 s after launch.
  if (p === '/api/live/preflight') {
    const proxyReq = http.get('http://127.0.0.1:4711/api/live/preflight', { timeout: 3000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        let data;
        try { data = JSON.parse(body); }
        catch (e) { return jsonResponse(res, 200, { ready: false, error: 'parse_error' }); }

        // Tag the source as eMule's own detection so the UI can label it
        // honestly. Empty when eMule hasn't determined an address yet.
        if (data.public_ip)         data.public_ip_source = 'kad';
        else if (data.public_ip_v6) data.public_ip_source = 'kad6';
        jsonResponse(res, 200, data);
      });
    });
    proxyReq.on('error',   () => jsonResponse(res, 200, { ready: false, error: 'eMule offline' }));
    proxyReq.on('timeout', () => { proxyReq.destroy(); jsonResponse(res, 200, { ready: false, error: 'timeout' }); });
    return true;
  }

  // === GET /api/live/monitor — Proxy: live broadcast counters ===
  if (p === '/api/live/monitor') {
    const proxyReq = http.get('http://127.0.0.1:4711/api/live/debug', { timeout: 3000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        try { jsonResponse(res, 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, {}); }
      });
    });
    proxyReq.on('error',   () => jsonResponse(res, 200, {}));
    proxyReq.on('timeout', () => { proxyReq.destroy(); jsonResponse(res, 200, {}); });
    return true;
  }

  // === GET /api/live/direct_join — Bypass Kad: connect directly via paste link ===
  // Accepts ?link=ed2k%3A%2F%2F%7Clive%7C... or ?key=&ip=&port=&title=
  // Forwards verbatim to the C++ backend at :4711, which validates and dials.
  if (p === '/api/live/direct_join') {
    const qs = url.search || '';  // includes the leading '?' or empty string
    const proxyUrl = 'http://127.0.0.1:4711/api/live/direct_join' + qs;
    const proxyReq = http.get(proxyUrl, { timeout: 8000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          jsonResponse(res, proxyRes.statusCode || 200, data);
        } catch (e) {
          jsonResponse(res, 200, { success: false, error: 'parse_error', raw: body.substring(0, 200) });
        }
      });
    });
    proxyReq.on('error', () => {
      jsonResponse(res, 200, { success: false, error: 'eMule offline' });
    });
    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      jsonResponse(res, 200, { success: false, error: 'timeout' });
    });
    return true;
  }

  // === GET /api/live/connection-status — Check eMule connectivity ===
  if (p === '/api/live/connection-status') {
    const probe = http.get('http://127.0.0.1:4711/api/status', { timeout: 2000 }, (probeRes) => {
      let body = '';
      probeRes.on('data', d => body += d);
      probeRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          jsonResponse(res, 200, {
            connected: true,
            nodeCount: data.kadNodes || data.nodeCount || 0,
            lastScan: new Date().toISOString()
          });
        } catch (e) {
          jsonResponse(res, 200, { connected: true, nodeCount: 0, lastScan: new Date().toISOString() });
        }
      });
    });
    probe.on('error', () => {
      jsonResponse(res, 200, { connected: false, nodeCount: 0, lastScan: null });
    });
    probe.on('timeout', () => {
      probe.destroy();
      jsonResponse(res, 200, { connected: false, nodeCount: 0, lastScan: null });
    });
    return true;
  }

  // === GET /api/live/nat-health — NAT Traversal telemetry from eMule C++ backend ===
  if (p === '/api/live/nat-health') {
    const natProbe = http.get('http://127.0.0.1:4711/api/status', { timeout: 2000 }, (natRes) => {
      let body = '';
      natRes.on('data', d => body += d);
      natRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          const att = parseInt(data.hole_punch_attempts, 10) || 0;
          const suc = parseInt(data.hole_punch_success,  10) || 0;
          const sym = parseInt(data.hole_punch_sym_nat_fail, 10) || 0;
          jsonResponse(res, 200, {
            enabled:   data.utp_hole_punch_enabled === 'true' || data.utp_hole_punch_enabled === true,
            attempts:  att,
            success:   suc,
            symNatFail:sym,
            rate:      att > 0 ? Math.round((suc / att) * 100) : null
          });
        } catch (e) {
          jsonResponse(res, 200, { enabled: false, attempts: 0, success: 0, symNatFail: 0, rate: null, error: 'parse' });
        }
      });
    });
    natProbe.on('error', () => {
      jsonResponse(res, 200, { enabled: false, attempts: 0, success: 0, symNatFail: 0, rate: null, error: 'offline' });
    });
    natProbe.on('timeout', () => {
      natProbe.destroy();
      jsonResponse(res, 200, { enabled: false, attempts: 0, success: 0, symNatFail: 0, rate: null, error: 'timeout' });
    });
    return true;
  }

  if (p === '/api/live/status') {
    proxyEmuleJson(res, '/api/live/debug', 3000, (data) => ({
      status: data.broadcasting ? 'streaming' : (data.viewing ? 'viewing' : 'idle'),
      segments: data.chunks && Number.isFinite(data.chunks.count) ? data.chunks.count : 0,
      uptime: data.uptime || 0,
      broadcasting: !!data.broadcasting,
      viewing: !!data.viewing,
      backend: 'emule',
      meta: streamMeta
    }));
    return true;
  }

  // === GET /api/live/sources ===
  if (p === '/api/live/sources') {
    const sources = deviceScanner.getSourcesForAPI(ctx.ffmpegPath);
    jsonResponse(res, 200, { sources });
    return true;
  }

  // Compatibility endpoint.  The old implementation launched a second,
  // Node-only FFmpeg pipeline and reported a channel that never entered the
  // eMule P2P mesh.  Route supported sources through the canonical C++ engine.
  if (p === '/api/live/start' && req.method === 'POST') {
    readBody(req, (bodyErr, body) => {
      if (bodyErr) return bodyReadError(res, bodyErr);
      try {
        const config = JSON.parse(body);
        const source = String(config.sourceType || 'screen').toLowerCase();
        const supported = new Set(['testpattern', 'screen', 'file', 'rtmp']);
        if (!supported.has(source)) {
          return jsonResponse(res, 422, {
            success: false,
            error: 'source_not_supported_by_p2p',
            detail: 'Usa screen, file, rtmp o testpattern. Para webcam/capturadora, envía la señal mediante OBS a RTMP.'
          });
        }
        streamMeta.title = config.title || 'Sin t\u00edtulo';
        streamMeta.category = config.category || 'general';
        streamMeta.language = config.language || 'es';
        const params = new URLSearchParams({
          source,
          title: streamMeta.title,
          category: streamMeta.category,
          language: streamMeta.language,
          bitrate: String(config.bitrate || 3000)
        });
        if (source === 'file') params.set('file', config.sourceId || '');
        proxyEmuleJson(res, '/api/live/broadcast/start?' + params.toString(), 20000);
      } catch (e) {
        jsonResponse(res, 400, { success: false, error: 'Invalid JSON: ' + e.message });
      }
    });
    return true;
  }

  // === POST /api/live/stop ===
  if (p === '/api/live/stop' && req.method === 'POST') {
    // Broadcast OP_LIVE_END to all tunnel peers BEFORE stopping
    const tunnelStatus = wsTunnel.getStatus();
    if (tunnelStatus.connections > 0) {
      // OP_LIVE_END = 0xC8, reason 0x00 = normal shutdown
      const endSignal = Buffer.from([0xC8, 0x00]);
      wsTunnel.broadcast(endSignal);
      console.log('[eSE Live] Sent END signal to', tunnelStatus.connections, 'tunnel peers');
    }

    // Clean any legacy local process left by a previous version, then stop the
    // canonical C++ broadcaster (which also sends OP_LIVE_END to P2P peers).
    pipeline.stop();
    rtmpServer.stop();
    streamMeta = { title: '', category: 'general', language: 'es' };

    proxyEmuleJson(res, '/api/live/broadcast/stop', 5000);
    return true;
  }

  // === GET /api/live/channels — Search channels ===
  if (p === '/api/live/channels') {
    const filters = {
      query: url.searchParams.get('q') || '',
      category: url.searchParams.get('category') || 'all',
      language: url.searchParams.get('lang') || 'all',
      minRating: parseInt(url.searchParams.get('minRating') || '0', 10),
      quality: url.searchParams.get('quality') || '',
      sortBy: url.searchParams.get('sort') || 'rating'
    };
    const localResults = channelSearch.search(filters);
    let responded = false;
    const done = (kadStreams) => {
      if (responded) return;
      responded = true;
      const byKey = new Map();
      localResults.forEach(ch => {
        const key = channelSearch.canonicalStreamKey(ch.streamKey || ch.hash);
        if (key) byKey.set(key, Object.assign({}, ch, { streamKey: key }));
      });
      // BROWSE-S01 helpers — defined here so both kad-merge and the final
      // enrichment pass below can use them.
      const ipUintToStr = (n) => {
        if (!n || n === 0 || n === 0xFFFFFFFF) return '';
        return ((n >>> 0) & 255) + '.' +
               ((n >>> 8) & 255) + '.' +
               ((n >>> 16) & 255) + '.' +
               ((n >>> 24) & 255);
      };
      const REMOTE_HTTP_PORT = 8080;

      // Index Kad results by key so the post-merge enrichment can look up
      // wire-level metadata (broadcasterIP uint32, etc.) regardless of
      // whether the entry first appeared via localResults or kadStreams.
      const kadByKey = new Map();
      (kadStreams || []).forEach(s => {
        const k = channelSearch.canonicalStreamKey(s.streamKey || s.hash);
        if (k) kadByKey.set(k, s);
      });

      (kadStreams || []).forEach(s => {
        const key = channelSearch.canonicalStreamKey(s.streamKey || s.hash);
        if (!key || byKey.has(key)) return;
        byKey.set(key, {
          streamKey: key,
          hash: key,
          title: s.title || 'Live',
          category: s.category || 'general',
          language: s.language || 'es',
          bitrate: s.bitrate || 0,
          viewers: s.viewers || 0,
          quality: s.bitrate >= 5000 ? 'FHD' : (s.bitrate >= 3000 ? 'HD' : 'SD'),
          isLocal: !!s.own,
          source: 'kad',
          ed2kLink: buildAnonymousLiveLink(key, s.title || 'Live')
        });
      });

      // BROWSE-S01 final pass: for EVERY channel (local-registered, kad,
      // or merged) add broadcasterIP + httpPort + thumbnailUrl. Without
      // this single pass, channels that came from localResults skip the
      // kad-only enrichment and the grid shows empty thumbnailUrl.
      const results = Array.from(byKey.values()).map(ch => {
        const key = channelSearch.canonicalStreamKey(ch.streamKey || ch.hash);
        const kad = kadByKey.get(key);
        const isLocal = !!ch.isLocal
          || (kad && !!kad.own)
          || (ch.broadcasterHash === 'local');
        const remoteIp = isLocal ? '' : (kad ? ipUintToStr(kad.broadcasterIP) : '');
        // Local broadcasts: relative URL served by THIS Node instance.
        // Remote broadcasts: absolute URL to the remote broadcaster's :8080.
        // No URL (empty string) when remote IP is unknown -> grid falls back.
        const thumbnailUrl = isLocal
          ? `/live/thumb/${encodeURIComponent(key)}.jpg`
          : (remoteIp
              ? `http://${remoteIp}:${REMOTE_HTTP_PORT}/live/thumb/${encodeURIComponent(key)}.jpg`
              : '');
        return Object.assign({}, ch, {
          isLocal,
          broadcasterIP: remoteIp,
          broadcasterPort: kad ? (kad.broadcasterPort || 0) : (ch.broadcasterPort || 0),
          httpPort: REMOTE_HTTP_PORT,
          thumbnailUrl
        });
      });
      jsonResponse(res, 200, { channels: results, total: results.length });
    };
    const kadReq = http.get('http://127.0.0.1:4711/api/live/kad/streams', { timeout: 1200 }, (kadRes) => {
      let body = '';
      kadRes.on('data', d => body += d);
      kadRes.on('end', () => {
        try { done((JSON.parse(body).streams) || []); } catch (e) { done([]); }
      });
    });
    kadReq.on('error', () => done([]));
    kadReq.on('timeout', () => { kadReq.destroy(); done([]); });
    return true;
  }

  // === GET /api/live/favorites — List favorites ===
  if (p === '/api/live/favorites' && req.method === 'GET') {
    jsonResponse(res, 200, { favorites: favorites.getAll() });
    return true;
  }

  // === POST /api/live/favorites — Add/remove favorite ===
  if (p === '/api/live/favorites' && req.method === 'POST') {
    readBody(req, (bodyErr, body) => {
      if (bodyErr) return bodyReadError(res, bodyErr);
      try {
        const data = JSON.parse(body);
        if (data.action === 'add') {
          favorites.add(data.channel);
        } else if (data.action === 'remove') {
          favorites.remove(data.streamKey);
        }
        jsonResponse(res, 200, { success: true, favorites: favorites.getAll() });
      } catch (e) {
        jsonResponse(res, 400, { success: false, error: e.message });
      }
    });
    return true;
  }

  // === POST /api/live/rtmp/start — Start RTMP ingest for OBS ===
  if (p === '/api/live/rtmp/start' && req.method === 'POST') {
    readBody(req, (bodyErr, body) => {
      if (bodyErr) return bodyReadError(res, bodyErr);
      try {
        const config = JSON.parse(body);
        streamMeta.title = config.title || 'OBS Stream';
        streamMeta.category = config.category || 'general';
        streamMeta.language = config.language || 'es';

        if (config.port && Number(config.port) !== 1935) {
          return jsonResponse(res, 422, {
            success: false,
            error: 'unsupported_rtmp_port',
            detail: 'La ingesta P2P usa el puerto RTMP 1935.'
          });
        }
        const params = new URLSearchParams({
          source: 'rtmp',
          title: streamMeta.title,
          category: streamMeta.category,
          language: streamMeta.language,
          bitrate: String(config.bitrate || 3000)
        });
        proxyEmuleJson(res, '/api/live/broadcast/start?' + params.toString(), 5000,
          data => ({ ...data, rtmpUrl: 'rtmp://127.0.0.1:1935/live/stream' }));
      } catch (e) {
        jsonResponse(res, 400, { success: false, error: e.message });
      }
    });
    return true;
  }

  // === POST /api/live/rtmp/stop ===
  if (p === '/api/live/rtmp/stop' && req.method === 'POST') {
    rtmpServer.stop();
    streamMeta = { title: '', category: 'general', language: 'es' };
    proxyEmuleJson(res, '/api/live/broadcast/stop', 5000);
    return true;
  }

  // === GET /api/live/rtmp/status ===
  if (p === '/api/live/rtmp/status') {
    proxyEmuleJson(res, '/api/live/debug', 3000, data => ({
      running: !!data.broadcasting,
      status: data.broadcasting ? ((data.chunks && data.chunks.count > 0) ? 'receiving' : 'waiting') : 'stopped',
      segments: data.chunks ? data.chunks.count : 0,
      rtmpUrl: 'rtmp://127.0.0.1:1935/live/stream',
      backend: 'emule'
    }));
    return true;
  }

  // === GET /live/stream.m3u8 — HLS playlist ===
  if (p === '/live/stream.m3u8') {
    const m3u8 = path.join(LIVE_DIR, 'stream.m3u8');
    if (!fs.existsSync(m3u8)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Stream not active');
      return true;
    }
    res.writeHead(200, {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-cache, no-store',
      'Access-Control-Allow-Origin': '*'
    });
    fs.createReadStream(m3u8).pipe(res);
    return true;
  }

  // === GET /live/seg_XXXXX.ts — HLS segments ===
  if (p.startsWith('/live/') && p.endsWith('.ts')) {
    const segFile = path.join(LIVE_DIR, path.basename(p));
    if (!fs.existsSync(segFile)) {
      res.writeHead(404);
      res.end('Segment not found');
      return true;
    }
    const stat = fs.statSync(segFile);
    res.writeHead(200, {
      'Content-Type': 'video/mp2t',
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*'
    });
    fs.createReadStream(segFile).pipe(res);
    return true;
  }

  // === GET /live/thumb/{hash}.jpg — Channel thumbnail ===
  if (p.startsWith('/live/thumb/') && p.endsWith('.jpg')) {
    const key = path.basename(p, '.jpg');
    const thumbPath = thumbExtractor.getThumbPath(key);
    if (!thumbPath) {
      res.writeHead(404);
      res.end('No thumbnail');
      return true;
    }
    const stat = fs.statSync(thumbPath);
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': stat.size,
      'Cache-Control': 'public, max-age=10',
      'Access-Control-Allow-Origin': '*'
    });
    fs.createReadStream(thumbPath).pipe(res);
    return true;
  }

  // === GET /live/watch/{hash} — Cinema player for eMule broadcast ===
  if (p.startsWith('/live/watch/') && p.split('/').length === 4) {
    const hash = p.split('/')[3];
    if (hash.startsWith('local_') || hash.startsWith('external_') || hash.startsWith('obs_')) {
      const html = require('../live_player_html')();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return true;
    }
    if (/^[a-fA-F0-9]{32}$/.test(hash)) {
      const joinReq = http.get('http://127.0.0.1:4711/api/live/join?key=' + encodeURIComponent(hash) + '&title=Live', { timeout: 1200 }, (joinRes) => {
        joinRes.resume();
      });
      joinReq.on('error', () => {});
      joinReq.on('timeout', () => joinReq.destroy());
    } else {
      jsonResponse(res, 400, { error: 'invalid_stream_key', message: 'Stream key must be 32 hex characters.' });
      return true;
    }
    // Serve HLS straight from local disk (eMule's viewer writer drops .ts +
    // stream.m3u8 into %TEMP%\eMule_RTMP\<HASH>\ as chunks arrive). This
    // avoids the broken eMule WebServer hls-proxy on PC2.
    const hlsBase = '/hls-local/' + hash.toLowerCase();
    // v7.1.7 — no-cache: same justification as /live above.
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>eSE Live</title>
<script src="/live/vendor/hls.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;font-family:"Inter",sans-serif;overflow:hidden}
.cinema{position:fixed;inset:0;background:#000;display:flex;flex-direction:column}
video{width:100%;height:100%;object-fit:contain;cursor:pointer}
.top-bar{position:absolute;top:0;left:0;right:0;z-index:10;display:flex;align-items:center;gap:16px;padding:16px 24px;background:linear-gradient(rgba(0,0,0,.8),transparent);opacity:0;transition:opacity .3s}
.cinema:hover .top-bar{opacity:1}
.back-btn{background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);color:#fff;padding:8px 16px;border-radius:6px;font-size:13px;cursor:pointer;text-decoration:none;transition:all .2s;backdrop-filter:blur(10px)}
.back-btn:hover{background:rgba(255,107,53,.3);border-color:#ff6b35}
.title-bar{color:rgba(255,255,255,.7);font-size:16px;font-weight:500}
.live-dot{background:#e53e3e;color:#fff;font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.controls{position:absolute;bottom:0;left:0;right:0;z-index:12;padding:12px 16px;background:linear-gradient(transparent,rgba(0,0,0,.9));opacity:0;transition:opacity .3s}
.cinema:hover .controls{opacity:1}
.ctrl-row{display:flex;align-items:center;gap:12px}
.ctrl-btn{background:none;border:none;color:#fff;font-size:18px;cursor:pointer;padding:4px 8px;opacity:.85;transition:all .2s}
.ctrl-btn:hover{opacity:1;transform:scale(1.15)}
.time{color:rgba(255,255,255,.8);font-size:13px;font-variant-numeric:tabular-nums}
.vol-range{width:80px;height:4px;cursor:pointer;accent-color:#ff6b35}
.audio-sel{background:#222;color:#fff;border:1px solid rgba(255,255,255,.3);border-radius:6px;padding:6px 28px 6px 10px;font-size:13px;cursor:pointer;outline:none;font-family:inherit;min-width:130px;-webkit-appearance:menulist;appearance:menulist}
.audio-sel option{background:#1a1a2e;color:#fff;padding:4px}
.spacer{flex:1}
/* Phase 2 JOIN-3: State overlay */
.join-overlay{position:absolute;inset:0;z-index:20;display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(0,0,0,.92);transition:opacity .5s;pointer-events:none}
.join-overlay.hidden{opacity:0;pointer-events:none}
.join-spinner{width:48px;height:48px;border:3px solid rgba(255,107,53,.2);border-top-color:#ff6b35;border-radius:50%;animation:spin 1s linear infinite;margin-bottom:20px}
@keyframes spin{to{transform:rotate(360deg)}}
.join-state{color:#fff;font-size:18px;font-weight:600;text-align:center;margin-bottom:8px}
.join-detail{color:rgba(255,255,255,.5);font-size:13px;text-align:center;max-width:400px}
.join-peers{display:flex;gap:16px;margin-top:16px}
.join-stat{text-align:center}
.join-stat-val{color:#ff6b35;font-size:24px;font-weight:800}
.join-stat-label{color:rgba(255,255,255,.4);font-size:11px;text-transform:uppercase;letter-spacing:1px}
.join-retry{color:#ff6b35;font-size:12px;margin-top:12px;opacity:0;transition:opacity .3s}
</style></head><body>
<div class="cinema" id="cinema">
<div class="top-bar">
<a href="/live" class="back-btn">&larr; Canales</a>
<span class="live-dot">LIVE</span>
<span class="title-bar" id="ch-title">Cargando...</span>
</div>
<!-- Phase 2 JOIN-3: Connection state overlay -->
<div class="join-overlay" id="join-overlay">
<div class="join-spinner"></div>
<div class="join-state" id="join-state">Conectando al stream...</div>
<div class="join-detail" id="join-detail">Buscando peers en la red Kad</div>
<div class="join-peers">
<div class="join-stat"><div class="join-stat-val" id="jo-peers">0</div><div class="join-stat-label">Peers</div></div>
<div class="join-stat"><div class="join-stat-val" id="jo-chunks">0</div><div class="join-stat-label">Chunks</div></div>
<div class="join-stat"><div class="join-stat-val" id="jo-kad">—</div><div class="join-stat-label">Kad</div></div>
</div>
<div class="join-retry" id="join-retry"></div>
</div>
<video id="v" autoplay muted playsinline></video>
<div class="controls">
<div class="ctrl-row">
<button class="ctrl-btn" id="play-btn" onclick="togglePlay()">&#9646;&#9646;</button>
<button class="ctrl-btn" onclick="toggleMute()">&#128266;</button>
<input type="range" class="vol-range" id="vol" min="0" max="1" step="0.05" value="1" oninput="v.volume=this.value">
<span class="time" id="time">0:00</span>
<span class="spacer"></span>
<select class="audio-sel" id="audioSel" style="display:none"></select>
<button class="ctrl-btn" onclick="toggleFS()">&#x26F6;</button>
</div>
</div>
</div>
<script>
const v=document.getElementById('v');
const src='${hlsBase}/stream.m3u8';
const streamHash='${hash}';
const langNames={eng:'English',spa:'Spanish',fre:'French',ger:'German',ita:'Italian',por:'Portuguese',jpn:'Japanese',kor:'Korean',chi:'Chinese',rus:'Russian',ara:'Arabic',und:'Track'};
const langFlags={eng:'[EN]',spa:'[ES]',fre:'[FR]',ger:'[DE]',ita:'[IT]',por:'[PT]',jpn:'[JP]',rus:'[RU]',kor:'[KR]',chi:'[CN]',ara:'[AR]',und:''};

// === Phase 2 JOIN-3: State machine ===
const JOIN_STATES = {
  DISCOVERING: { text: 'Buscando stream en Kad...', detail: 'Consultando la red distribuida' },
  CONNECTING:  { text: 'Conectando a peers...', detail: 'Estableciendo conexión P2P' },
  BUFFERING:   { text: 'Recibiendo chunks...', detail: 'Rellenando buffer HLS' },
  PLAYING:     { text: '', detail: '' },
  FAILED:      { text: 'No se pudo conectar', detail: 'El stream puede no estar disponible' }
};
let joinState = 'DISCOVERING';
let joinRetryCount = 0;
const JOIN_RETRY_INTERVAL = 15000;
const JOIN_MAX_RETRIES = 5;
let joinStartTime = Date.now();

function updateJoinOverlay(state, peers, chunks, kadStatus) {
  joinState = state;
  const ov = document.getElementById('join-overlay');
  if (state === 'PLAYING') { ov.classList.add('hidden'); return; }
  ov.classList.remove('hidden');
  const s = JOIN_STATES[state] || JOIN_STATES.DISCOVERING;
  document.getElementById('join-state').textContent = s.text;
  document.getElementById('join-detail').textContent = s.detail;
  document.getElementById('jo-peers').textContent = peers || 0;
  document.getElementById('jo-chunks').textContent = chunks || 0;
  document.getElementById('jo-kad').textContent = kadStatus || '—';
  const retryEl = document.getElementById('join-retry');
  if (joinRetryCount > 0) {
    retryEl.textContent = 'Reintento ' + joinRetryCount + '/' + JOIN_MAX_RETRIES;
    retryEl.style.opacity = '1';
  }
}

// Phase 2 JOIN-3: Poll /api/live/debug for real P2P state
let lastDebugChunks = 0;

function pollJoinState() {
  if (joinState === 'PLAYING') return;
  fetch('/api/live/debug').then(r => r.json()).then(d => {
    if (d.error) return; // C++ offline, skip update
    const peers = (d.peers ? (d.peers.viewPeers || 0) + (d.peers.broadcastPeers || 0) : 0);
    const chunks = d.chunks ? (d.chunks.count || 0) : (d.counters ? d.counters.chunksReceived || 0 : 0);
    const kadOk = d.discovery && d.discovery.kadConnected ? 'OK' : 'OFF';
    const hasHls = d.hls ? (d.hls.playlistRefreshes || 0) > 0 || (d.hls.segmentsWritten || 0) >= 3 : chunks >= 3;
    lastDebugChunks = chunks;

    if (chunks > 0 || hasHls) {
      updateJoinOverlay('BUFFERING', peers, chunks, kadOk);
    } else if (peers > 0) {
      updateJoinOverlay('CONNECTING', peers, chunks, kadOk);
    } else {
      updateJoinOverlay('DISCOVERING', peers, chunks, kadOk);
    }
  }).catch(() => {});
}

// Phase 2 JOIN-4: Retry join if no chunks after interval
// Routes through Node proxy /api/live/join -> C++ 4711/api/live/join
function checkJoinRetry() {
  if (joinState === 'PLAYING' || joinState === 'FAILED') return;
  const elapsed = Date.now() - joinStartTime;
  if (joinRetryCount >= JOIN_MAX_RETRIES) {
    if (lastDebugChunks === 0 && elapsed > JOIN_RETRY_INTERVAL * (JOIN_MAX_RETRIES + 1)) {
      updateJoinOverlay('FAILED', 0, 0, 'OFF');
    }
    return;
  }
  if (elapsed > JOIN_RETRY_INTERVAL * (joinRetryCount + 1)) {
    joinRetryCount++;
    fetch('/api/live/join?key=' + encodeURIComponent(streamHash) + '&title=Live', { method: 'GET' })
      .then(r => r.json())
      .then(d => { if (d.error) console.warn('[eSE Join] Retry failed:', d.error); })
      .catch(() => {});
    updateJoinOverlay(joinState);
  }
}

const joinPollId = setInterval(() => { pollJoinState(); checkJoinRetry(); }, 3000);
pollJoinState();

if(window.Hls&&Hls.isSupported()){
const h=new Hls({liveSyncDurationCount:3,liveMaxLatencyDurationCount:8,liveDurationInfinity:true,maxBufferLength:30,maxMaxBufferLength:60,maxBufferHole:2,manifestLoadingMaxRetry:50,levelLoadingMaxRetry:50,fragLoadingMaxRetry:50});
h.loadSource(src);h.attachMedia(v);
// Phase 3: Transition to PLAYING only on FRAG_BUFFERED (actual data), not MANIFEST_PARSED (existence)
h.on(Hls.Events.MANIFEST_PARSED,()=>{v.play();updateJoinOverlay('BUFFERING',0,0,'OK')});
h.on(Hls.Events.FRAG_BUFFERED,()=>{if(joinState!=='PLAYING'){updateJoinOverlay('PLAYING',0,0,'OK');clearInterval(joinPollId)}});
// Audio-distortion fix (2026-06): two-step recovery per hls.js docs — a second
// fatal mediaError right after a recoverMediaError() means the audio codec is
// mis-signalled (AAC vs HE-AAC); call swapAudioCodec() first or the audio is
// re-appended at the wrong sample rate (the deep/slow audio after stalls).
let mErrAt=0;
h.on(Hls.Events.ERROR,(e,d)=>{if(!d.fatal)return;if(d.type==='mediaError'){const n=Date.now();if(n-mErrAt<6000){h.swapAudioCodec()}mErrAt=n;h.recoverMediaError()}else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}});
h.on(Hls.Events.AUDIO_TRACKS_UPDATED,()=>{
  const tracks=h.audioTrackController?h.audioTrackController.audioTracks:[];
  if(tracks.length<2)return;
  const sel=document.getElementById('audioSel');
  sel.style.display='';
  sel.innerHTML='';
  tracks.forEach((t,i)=>{
    const lang=t.lang||'und';
    const name=(langFlags[lang]||'')+' '+(langNames[lang]||lang);
    const selected=(i===(h.audioTrack>=0?h.audioTrack:0))?' selected':'';
    sel.innerHTML+='<option value="'+i+'"'+selected+'>'+name+'</option>';
  });
  sel.selectedIndex=h.audioTrack>=0?h.audioTrack:0;
  sel.onchange=()=>{h.audioTrack=parseInt(sel.value)};
});
}else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=src
}else{updateJoinOverlay('FAILED',0,0,'OFF');document.getElementById('join-detail').textContent='Reproductor HLS no disponible'}

setInterval(()=>{if(v.paused&&v.readyState>=2)v.play()},2000);
setInterval(()=>{const t=Math.floor(v.currentTime);const m=Math.floor(t/60);const s=t%60;document.getElementById('time').textContent=m+':'+String(s).padStart(2,'0')},500);

function togglePlay(){v.paused?v.play():v.pause();document.getElementById('play-btn').innerHTML=v.paused?'&#9654;':'&#9646;&#9646;'}
function toggleMute(){v.muted=!v.muted}
function toggleFS(){document.fullscreenElement?document.exitFullscreen():document.getElementById('cinema').requestFullscreen()}
v.addEventListener('click',togglePlay);
v.addEventListener('dblclick',toggleFS);

fetch('/api/live/emule-channels').then(r=>r.json()).then(d=>{
  const ch=(d.channels||[]).find(c=>c.hash==='${hash}');
  if(ch)document.getElementById('ch-title').textContent=ch.title;
}).catch(()=>{});

// Ghost-viewer fix (2026-06): tell eMule we left when the page goes away
// (navigation, back button, tab close). sendBeacon survives page unload; the
// Node /api/live/leave route relays it to eMule. The 60 s player-idle
// watchdog in eMule is the backstop for killed tabs where this never fires.
addEventListener('pagehide',()=>{try{const leave='/api/live/leave?key=${hash}';if(!navigator.sendBeacon||!navigator.sendBeacon(leave))fetch(leave,{keepalive:true}).catch(()=>{})}catch(_){}});
</script></body></html>`);
    return true;
  }

  // === GET /live — Live TV page ===
  if (p === '/live' || p === '/live/') {
    // Delegate to live_tv_page.js
    try {
      const livePage = require('./live_tv_page');
      const status = pipeline.getStatus();
      const html = livePage.render(status, streamMeta);
      // v7.1.7 — never cache /live. Page embeds an inline <script> that
      // changes between releases; cached copies survive ese-server.exe
      // hot-swaps and serve obsolete JS that breaks the UI silently.
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
      res.end(html);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Live TV page error: ' + e.message);
    }
    return true;
  }

  // === GET /live/player.js — Live TV player script ===
  if (p === '/live/player.js') {
    try {
      const playerModule = require('./live_tv_player');
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      res.end(playerModule.getScript());
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('// Error: ' + e.message);
    }
    return true;
  }

  // === GET /api/live/p2p/stats — P2P mesh topology stats ===
  if (p === '/api/live/p2p/stats') {
    // Query eMule WebServer for live stream manager state
    requestEmuleJson('/api/live/mesh', 2000, (err, data, statusCode) => {
      if (err || statusCode !== 200) {
        // Fallback: return local-only stats
        const tunnel = wsTunnel.getStatus();
        jsonResponse(res, 200, {
          meshPeers: tunnel.connections || 0,
          pendingRequests: 0,
          totalRedistributed: 0,
          trustLevels: { superSeeders: 0, middle: 0, leaf: 0 },
          uploadFloor: 0,
          emergencyMode: false,
          source: 'local-tunnel'
        });
      } else {
        jsonResponse(res, 200, data);
      }
    });
    return true;
  }

  // === GET /api/live/p2p/streams — Kad-discovered P2P streams ===
  if (p === '/api/live/p2p/streams') {
    requestEmuleJson('/api/live/kad/streams', 3000, (err, data, statusCode) => {
      if (err || statusCode !== 200) {
        // Fallback: return local channel directory
        const channels = channelSearch.search({});
        jsonResponse(res, 200, {
          streams: channels.map(ch => ({
            ...ch,
            source: 'local',
            ed2kLink: buildAnonymousLiveLink(ch.streamKey, ch.title)
          })),
          kadConnected: false
        });
      } else {
        // Add ed2k links to Kad streams
        if (data.streams) {
          data.streams.forEach(s => {
            s.ed2kLink = buildAnonymousLiveLink(s.streamKey, s.title || 'Live');
          });
        }
        jsonResponse(res, 200, data);
      }
    });
    return true;
  }

  // === GET /api/live/p2p/share — Generate share link ===
  if (p === '/api/live/p2p/share') {
    const requestedKey = url.searchParams.get('key') || '';
    const requestedTitle = url.searchParams.get('title') || streamMeta.title || 'Live';
    const dashboardPort = url.port || String(ctx.port || 8080);
    const buildShare = (key, title) => ({
      success: !!key,
      ed2kLink: buildAnonymousLiveLink(key, title),
      webLink: key ? `http://localhost:${dashboardPort}/live/watch/${encodeURIComponent(key)}` : '',
      streamKey: key,
      title
    });
    if (requestedKey) {
      jsonResponse(res, 200, buildShare(requestedKey, requestedTitle));
    } else {
      proxyEmuleJson(res, '/api/live/channels', 3000, data => {
        const channel = data.channels && data.channels[0];
        return channel
          ? buildShare(channel.hash || channel.streamKey || '', channel.title || requestedTitle)
          : { success: false, error: 'no_active_broadcast', ed2kLink: '', webLink: '', streamKey: '' };
      });
    }
    return true;
  }

  // === GET /api/live/emule-channels — Proxy to eMule WebServer (avoids CORS) ===
  if (p === '/api/live/emule-channels') {
    const emulePort = 4711;
    const emuleReq = http.get('http://127.0.0.1:' + emulePort + '/api/live/channels', { timeout: 3000 }, (emuleRes) => {
      let body = '';
      emuleRes.on('data', d => body += d);
      emuleRes.on('end', () => {
        try {
          const data = JSON.parse(body);
          // Merge into channel search
          const emuleChannels = (data.channels || []).map(ch => ({
                streamKey: ch.hash || ch.streamKey,
                title: ch.title || 'eMule Broadcast',
                category: ch.category || 'general',
                language: ch.language || 'es',
                bitrate: ch.bitrate || 3000,
                viewers: ch.viewers || 0,
                started: ch.started || (ch.startedAt ? new Date(ch.startedAt * 1000).toISOString() : new Date().toISOString())
              }));
          channelSearch.syncEmuleChannels(emuleChannels);
          jsonResponse(res, 200, data);
        } catch (e) {
          jsonResponse(res, 200, { channels: [], error: 'parse_error' });
        }
      });
    });
    emuleReq.on('error', () => {
      jsonResponse(res, 200, { channels: [], connected: false });
    });
    emuleReq.on('timeout', () => {
      emuleReq.destroy();
      jsonResponse(res, 200, { channels: [], connected: false });
    });
    return true;
  }

  // === GET /api/live/hls-proxy/{hash}/* — Proxy HLS from eMule WebServer (avoids CORS) ===
  // UX-005: SSRF Prevention — Only proxy to local eMule WebServer (127.0.0.1:4711).
  //         Validate hash/filename to prevent path traversal.
  if (p.startsWith('/api/live/hls-proxy/')) {
    const parts = p.replace('/api/live/hls-proxy/', '').split('/');
    const hash = parts[0];
    const file = parts.slice(1).join('/') || 'stream.m3u8';

    // SSRF Guard: reject path traversal attempts and non-HLS filenames
    const SAFE_HLS_FILE = /^[a-zA-Z0-9_\-]+\.(m3u8|ts)$/;
    const SAFE_HASH = /^[a-fA-F0-9]{32}$/;
    if (!SAFE_HASH.test(hash) || !SAFE_HLS_FILE.test(file)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_path', message: 'Hash or filename contains invalid characters.' }));
      return true;
    }

    // Hardcoded destination: only 127.0.0.1:4711 (eMule C++ WebServer)
    const emuleUrl = 'http://127.0.0.1:4711/api/live/' + hash + '/' + file;

    const proxyReq = http.get(emuleUrl, { timeout: 5000 }, (proxyRes) => {
      const ct = proxyRes.headers['content-type'] || 'application/octet-stream';
      const isM3u8 = file.endsWith('.m3u8');
      
      if (isM3u8) {
        let body = '';
        proxyRes.on('data', d => body += d);
        proxyRes.on('end', () => {
          // Rewrite any absolute URLs in the m3u8 to use our proxy
          const rewritten = body.replace(
            /http:\/\/[^\/]+\/api\/live\/([^\/]+)\//g,
            '/api/live/hls-proxy/$1/'
          );
          res.writeHead(proxyRes.statusCode, {
            'Content-Type': 'application/vnd.apple.mpegurl',
            'Cache-Control': 'no-cache, no-store',
            'Access-Control-Allow-Origin': '*'
          });
          res.end(rewritten);
        });
      } else {
        res.writeHead(proxyRes.statusCode, {
          'Content-Type': ct,
          'Cache-Control': 'no-cache',
          'Access-Control-Allow-Origin': '*'
        });
        proxyRes.pipe(res);
      }
    });
    proxyReq.on('error', () => {
      res.writeHead(502);
      res.end('eMule WebServer not reachable');
    });
    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      res.writeHead(504);
      res.end('eMule WebServer timeout');
    });
    return true;
  }

  return false; // Not a live route
}

// --- Helpers ---

function jsonResponse(res, code, data) {
  if (res.writableEnded) return;
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function buildAnonymousLiveLink(key, title) {
  return key ? `ed2k://|live|${key}||${encodeURIComponent(title || 'Live')}|/` : '';
}

function proxyEmuleJson(res, endpoint, timeoutMs, transform) {
  let completed = false;
  const finish = (code, data) => {
    if (completed) return;
    completed = true;
    jsonResponse(res, code, data);
  };
  requestEmuleJson(endpoint, timeoutMs || 5000, (err, data, statusCode) => {
    if (err) {
      const error = err.message || 'eMule offline';
      return finish(error === 'timeout' ? 504 : 502, { success: false, error });
    }
    try {
      finish(statusCode || 200, transform ? transform(data) : data);
    } catch (e) {
      finish(502, { success: false, error: 'transform_error' });
    }
  });
}

function requestEmuleJson(endpoint, timeoutMs, callback) {
  let completed = false;
  const finish = (err, data, statusCode) => {
    if (completed) return;
    completed = true;
    callback(err, data, statusCode);
  };
  const request = http.get('http://127.0.0.1:4711' + endpoint,
    { timeout: timeoutMs || 5000 }, (response) => {
      let body = '';
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 1024 * 1024) request.destroy(new Error('response_too_large'));
      });
      response.on('end', () => {
        try {
          finish(null, JSON.parse(body), response.statusCode || 200);
        } catch (e) {
          finish(new Error('parse_error'));
        }
      });
    });
  request.on('error', err => finish(new Error(
    err && err.message === 'response_too_large' ? 'response_too_large' : 'eMule offline'
  )));
  request.on('timeout', () => {
    finish(new Error('timeout'));
    request.destroy();
  });
}

function readBody(req, cb) {
  utils.readBodyLimited(req, cb);
}

function bodyReadError(res, err) {
  const tooLarge = err && err.code === 'BODY_TOO_LARGE';
  jsonResponse(res, tooLarge ? 413 : 400, {
    success: false,
    error: tooLarge ? 'request_body_too_large' : 'invalid_request_body'
  });
}

// Background poller to sync eMule channels with our local directory
function pollEmuleChannels() {
  const req = http.get('http://127.0.0.1:4711/api/live/channels', { timeout: 3000 }, (res) => {
    let body = '';
    res.on('data', d => body += d);
    res.on('end', () => {
      try {
        const data = JSON.parse(body);
        const emuleChannels = (data.channels || []).map(ch => ({
              streamKey: ch.hash || ch.streamKey,
              title: ch.title || 'eMule Broadcast',
              category: ch.category || 'general',
              language: ch.language || 'es',
              bitrate: ch.bitrate || 3000,
              viewers: ch.viewers || 0,
              started: ch.started || (ch.startedAt ? new Date(ch.startedAt * 1000).toISOString() : new Date().toISOString())
            }));
        channelSearch.syncEmuleChannels(emuleChannels);
      } catch (e) { console.warn('[eSE Live] pollEmuleChannels parse error:', e.message); }
    });
  });
  req.on('error', () => {});
  req.on('timeout', () => req.destroy());
}

// Background poller for Kad-discovered streams (works without UI activity).
// /api/live/kad/streams returns the current Kad-discovered directory on the
// C++ side. Mirroring it into channelSearch means opening /live shows other
// people's broadcasts even when nobody has the page open to drive a poll.
function pollKadStreams() {
  const req = http.get('http://127.0.0.1:4711/api/live/kad/streams', { timeout: 3000 }, (res) => {
    let body = '';
    res.on('data', d => body += d);
    res.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (!data.streams || data.streams.length === 0) return;
        data.streams.forEach(s => {
          if (!s.streamKey) return;
          // Skip own stream — the pipeline already registers it as isLocal.
          if (s.own) return;
          const startedIso = s.startedAt
            ? new Date(s.startedAt * 1000).toISOString()
            : new Date().toISOString();
          channelSearch.addRemoteChannel({
            streamKey: s.streamKey,
            title: s.title || 'Live',
            category: s.category || 'general',
            language: s.language || 'es',
            bitrate: s.bitrate || 3000,
            viewers: s.viewers || 0,
            started: startedIso,
            broadcasterIP: s.broadcasterIP,
            broadcasterPort: s.broadcasterPort
          });
        });
      } catch (e) { console.warn('[eSE Live] pollKadStreams parse error:', e.message); }
    });
  });
  req.on('error', () => {});
  req.on('timeout', () => req.destroy());
}

// Initial fetch + interval.
// During the first 60s after Node starts up we poll Kad fast (every 3s)
// so a freshly-launched eMule populates /live within seconds. Then we back
// off to the normal 10s cadence to avoid churn.
pollEmuleChannels();
pollKadStreams();
setInterval(pollEmuleChannels, 10000);

const __eseKadFastUntil = Date.now() + 60000;
const __eseKadFastId = setInterval(() => {
  pollKadStreams();
  if (Date.now() > __eseKadFastUntil) {
    clearInterval(__eseKadFastId);
    setInterval(pollKadStreams, 10000);
  }
}, 3000);

module.exports = { handleRoute };
