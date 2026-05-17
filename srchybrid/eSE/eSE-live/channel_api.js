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
const cfTunnel = require('./cloudflare_tunnel');
const updateNotifier = require('./update_notifier');  // D6: GitHub release polling

const HLS_LIVE_DIR = path.join(os.tmpdir(), 'eMule_RTMP');
const LIVE_DIR = HLS_LIVE_DIR;

// Ensure live segment directory exists
try { if (!fs.existsSync(LIVE_DIR)) fs.mkdirSync(LIVE_DIR, { recursive: true }); } catch (e) { console.warn('[eSE Live] Failed to create live dir:', e.message); }

// Stream metadata (title, category, language)
let streamMeta = { title: '', category: 'general', language: 'es' };
let localStreamKey = null;

// B.2 Sprint 1 — Auto-fetch nodes.dat watchdog
// If eMule's Kad layer is still not connected after 60 s of dashboard uptime,
// the user almost certainly has no nodes.dat or it's stale. We fetch a fresh
// one from a well-known mirror and drop it in the eMule config dir, then nudge
// the user to restart Kad. This is the recovery path when the bundled
// nodes.dat (added in Tier 1.2) didn't help.
const NODES_DAT_URL = 'https://www.nodes-dat.com/dl.php?load=nodes&trusted&clients';
const NODES_DAT_DEST_CANDIDATES = [
  path.join(os.homedir(), 'AppData', 'Local',   'eMule', 'config', 'nodes.dat'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'eMule', 'config', 'nodes.dat'),
];
let _nodesDatFetched = false;  // single-fire per process lifetime
let _bootStartedAt = Date.now();
function tryAutoFetchNodesDat() {
  if (_nodesDatFetched) return;
  _nodesDatFetched = true;  // even if it fails, don't loop
  console.log('[eSE Boot] Kad still not connected after 60 s, fetching fresh nodes.dat...');
  https.get(NODES_DAT_URL, { timeout: 30000 }, (r) => {
    if (r.statusCode !== 200) {
      console.warn('[eSE Boot] nodes.dat fetch HTTP ' + r.statusCode);
      return;
    }
    const chunks = [];
    r.on('data', d => chunks.push(d));
    r.on('end', () => {
      const buf = Buffer.concat(chunks);
      if (buf.length < 100 || buf.length > 5 * 1024 * 1024) {
        console.warn('[eSE Boot] nodes.dat size suspicious: ' + buf.length + ' bytes, skipping');
        return;
      }
      // Write to the FIRST writable destination (Local first; eMule typically uses one of these)
      for (const dest of NODES_DAT_DEST_CANDIDATES) {
        try {
          fs.mkdirSync(path.dirname(dest), { recursive: true });
          fs.writeFileSync(dest, buf);
          console.log('[eSE Boot] nodes.dat written to ' + dest + ' (' + buf.length + ' bytes). Restart Kad to apply.');
          return;
        } catch (e) {
          console.warn('[eSE Boot] cannot write ' + dest + ': ' + e.message);
        }
      }
    });
  }).on('error', (e) => console.warn('[eSE Boot] nodes.dat fetch error: ' + e.message))
    .on('timeout', function() { this.destroy(); console.warn('[eSE Boot] nodes.dat fetch timeout'); });
}
// Periodic check: every 15 s, if uptime > 60 s and Kad still down, fetch.
setInterval(() => {
  if (_nodesDatFetched) return;
  if ((Date.now() - _bootStartedAt) < 60000) return;
  // Probe eMule for Kad status
  http.get('http://127.0.0.1:4711/api/status', { timeout: 2000 }, (r) => {
    let body = '';
    r.on('data', d => body += d);
    r.on('end', () => {
      try {
        const s = JSON.parse(body);
        if (s.kad_connected === false || s.kad_connected === 'false')
          tryAutoFetchNodesDat();
      } catch(e) { /* ignore */ }
    });
  }).on('error', () => {/* eMule offline, can't help */})
    .on('timeout', function() { this.destroy(); });
}, 15000);

// Sprint 3 I.2 — Tiny semver comparator. Returns >0 if a > b, <0 if a < b, 0 equal.
// Handles "x.y.z" and "x.y.z-suffix" robustly enough for our release tags.
function cmpSemver(a, b) {
  var pa = String(a).replace(/^v/, '').split(/[.\-]/).map(function(x){ return parseInt(x,10) || 0; });
  var pb = String(b).replace(/^v/, '').split(/[.\-]/).map(function(x){ return parseInt(x,10) || 0; });
  for (var i = 0; i < Math.max(pa.length, pb.length); i++) {
    var d = (pa[i]||0) - (pb[i]||0);
    if (d !== 0) return d;
  }
  return 0;
}

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

// Tier 1.4 — Public IP cache (STUN/HTTP fallback)
// eMule learns the public IP from Kad's firewall test, which can take 30-90 s
// after launch. We provide an HTTP fallback (api.ipify.org) so the UI can
// generate a working ed2k://|live|... link within seconds. Cached for 10 min.
const https = require('https');
let _publicIPCache = { ip: null, fetchedAt: 0 };
const PUBLIC_IP_CACHE_MS = 10 * 60 * 1000;
function getCachedPublicIP(cb) {
  const now = Date.now();
  if (_publicIPCache.ip && (now - _publicIPCache.fetchedAt) < PUBLIC_IP_CACHE_MS) {
    return cb(_publicIPCache.ip);
  }
  const req = https.get('https://api.ipify.org?format=text', { timeout: 3000 }, (r) => {
    let body = '';
    r.on('data', d => body += d);
    r.on('end', () => {
      const ip = (body || '').trim();
      // Sanity check: dotted IPv4
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        _publicIPCache = { ip: ip, fetchedAt: now };
        cb(ip);
      } else {
        cb(null);
      }
    });
  });
  req.on('error',   () => cb(null));
  req.on('timeout', () => { req.destroy(); cb(null); });
}

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

    if (fresh && !pipelineActive && !localStreamKey) {
      // FFmpeg externo activo — registrar canal
      localStreamKey = 'external_' + Date.now().toString(36);
      channelSearch.registerChannel({
        streamKey: localStreamKey,
        title: streamMeta.title || 'Emisi\u00f3n local',
        category: streamMeta.category || 'general',
        language: streamMeta.language || 'es',
        bitrate: 8000,
        viewers: 0
      });
      externalStreamDetected = true;
      console.log('[eSE Live] Stream externo detectado, registrado como', localStreamKey);
    } else if (!fresh && externalStreamDetected && localStreamKey) {
      // El .m3u8 no se actualiza — el stream ha muerto
      channelSearch.unregisterChannel(localStreamKey);
      localStreamKey = null;
      externalStreamDetected = false;
      console.log('[eSE Live] Stream externo finalizado (m3u8 obsoleto), desregistrado');
      cleanHLSFiles(); // evitar redetección en el próximo ciclo
    }
  } catch (e) { console.warn('[eSE Live] External stream detection error:', e.message); }
}
setInterval(detectExternalStream, 5000);
// Al arrancar: limpiar archivos HLS viejos antes de la primera detección
cleanHLSFiles({ staleOnly: true, maxAgeMs: STREAM_STALE_MS });
detectExternalStream();


function handleRoute(url, req, res, ctx) {
  const p = url.pathname;

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
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
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
      '<p>eSE Live es una aplicación P2P descentralizada que se ejecuta enteramente en tu equipo. No hay servidor central que recopile datos. Aun así, conviene que entiendas qué información se expone.</p>' +
      '<h2>Datos que SÍ se exponen</h2>' +
      '<ul>' +
      '<li><b>Tu IP pública</b> es visible para los peers a los que te conectes (igual que en BitTorrent o eD2K). Los peers que descarguen tu emisión saben tu IP.</li>' +
      '<li>Si emites, tu <b>IP + puertos TCP/UDP</b> se publican en la red Kad (DHT pública). Cualquiera buscando "eselive" puede encontrarte.</li>' +
      '<li>Si activas el túnel HTTPS opcional, <b>Cloudflare ve los metadatos</b> de la conexión (IP, hostnames, volumen de tráfico).</li>' +
      '<li>El watchdog de auto-fetch de <code>nodes.dat</code> contacta con <code>nodes-dat.com</code> y <code>api.ipify.org</code> (este último solo si tu Kad no detecta tu IP).</li>' +
      '<li>El check de auto-update contacta con <code>api.github.com</code>.</li>' +
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
      '<li>El túnel Cloudflare opcional viola su AUP si lo usas para distribuir P2P file-sharing — solo úsalo para tu propio contenido legal.</li>' +
      '<li>Las claves de stream son públicas en Kad; no son secretas. No emitas contenido confidencial sin cifrado adicional.</li>' +
      '</ul></div>' +
      '<h2>Cómo borrar todo</h2>' +
      '<ol>' +
      '<li>Cierra eMule y ese-server.exe.</li>' +
      '<li>Borra las carpetas listadas arriba.</li>' +
      '<li>Borra <code>%TEMP%\\eMule_RTMP\\</code> si quedan restos.</li>' +
      '</ol>' +
      '<p style="font-size:12px;color:#6b7280;margin-top:32px">eSE Live es software libre (GPL v2). Toda la lógica está en el código fuente abierto en <a href="https://github.com/diad87/eMule-eSE-LiveTV">GitHub</a>.</p>' +
      '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return true;
  }

  // === GET /api/eSE/update/check — Sprint 3 I.2: GitHub Releases check ===
  // Returns whether a newer release exists (compared to bundled package.json
  // version). Read-only; the actual download is opened in a browser tab.
  if (p === '/api/eSE/update/check') {
    const localVersion = (function(){
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
        return pkg.version || '0.0.0';
      } catch(e) { return '0.0.0'; }
    })();
    const opts = {
      hostname: 'api.github.com',
      path: '/repos/diad87/eMule-eSE-LiveTV/releases/latest',
      headers: { 'User-Agent': 'eSE-Live-AutoUpdate/1.0', 'Accept': 'application/vnd.github+json' },
      timeout: 5000,
    };
    https.get(opts, (r) => {
      let body = '';
      r.on('data', d => body += d);
      r.on('end', () => {
        try {
          const rel = JSON.parse(body);
          const remote = (rel.tag_name || '').replace(/^v/, '');
          const isNewer = remote && cmpSemver(remote, localVersion) > 0;
          jsonResponse(res, 200, {
            local_version: localVersion,
            remote_version: remote,
            update_available: isNewer,
            release_url: rel.html_url || null,
            download_url: (rel.assets && rel.assets[0]) ? rel.assets[0].browser_download_url : null,
            published_at: rel.published_at || null,
            release_notes: (rel.body || '').substring(0, 800),
          });
        } catch(e) { jsonResponse(res, 200, { error: 'parse_error', local_version: localVersion }); }
      });
    }).on('error', (e) => jsonResponse(res, 200, { error: e.message, local_version: localVersion }))
      .on('timeout', function() { this.destroy(); jsonResponse(res, 200, { error: 'timeout', local_version: localVersion }); });
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
      const stat = fs.statSync(logPath);
      // Read at most last 256 KB to keep the request snappy on huge logs
      const startAt = Math.max(0, stat.size - 256 * 1024);
      const fd = fs.openSync(logPath, 'r');
      const buf = Buffer.alloc(stat.size - startAt);
      fs.readSync(fd, buf, 0, buf.length, startAt);
      fs.closeSync(fd);
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

  // === Tier 3.1 — Cloudflare Tunnel (OPT-IN HTTPS fallback) ===
  // Requires explicit ?ack_tos=true confirming the user has read the TOS
  // warning. Cloudflare's AUP prohibits tunnels for P2P file sharing — using
  // this for sustained content distribution risks URL/IP/account ban.
  // ALWAYS for personal use / testing / legal content only.
  if (p === '/api/live/tunnel/start') {
    if (url.searchParams.get('ack_tos') !== 'true') {
      jsonResponse(res, 400, {
        success: false,
        error: 'tos_acknowledgement_required',
        message: 'Cloudflare Tunnel violates Cloudflare AUP if used for P2P content distribution. Pass ack_tos=true after reading the warning.'
      });
      return true;
    }
    const r = cfTunnel.start({ port: 8080 });
    jsonResponse(res, r.success ? 200 : 400, r);
    return true;
  }
  if (p === '/api/live/tunnel/stop') {
    jsonResponse(res, 200, cfTunnel.stop());
    return true;
  }
  if (p === '/api/live/tunnel/status') {
    jsonResponse(res, 200, cfTunnel.getStatus());
    return true;
  }

  // === GET /api/live/first_run — Tier 2.1: should we show the wizard? ===
  if (p === '/api/live/first_run') {
    jsonResponse(res, 200, { first_run: isFirstRun() });
    return true;
  }

  // === POST /api/live/first_run/dismiss — User clicked "Got it" ===
  if (p === '/api/live/first_run/dismiss') {
    const ok = markFirstRunSeen();
    jsonResponse(res, 200, { success: ok });
    return true;
  }

  // === GET /api/live/update_status — D6: latest cached GitHub release check ===
  if (p === '/api/live/update_status') {
    jsonResponse(res, 200, updateNotifier.getStatus());
    return true;
  }

  // === POST /api/live/update_check — D6: force an immediate re-poll ===
  if (p === '/api/live/update_check' && req.method === 'POST') {
    updateNotifier.check();
    // The check is async; the caller should poll /update_status after a few seconds.
    jsonResponse(res, 202, { triggered: true });
    return true;
  }

  // === POST /api/live/update_run — D6: spawn the interactive updater script ===
  // The script opens its own GUI MessageBox; we don't block the request.
  if (p === '/api/live/update_run' && req.method === 'POST') {
    updateNotifier.runInteractive((err) => {
      if (err) jsonResponse(res, 500, { success: false, error: err.message });
      else      jsonResponse(res, 200, { success: true, hint: 'GUI prompt opened' });
    });
    return true;
  }

  // === GET /api/live/broadcast/start — Proxy: trigger broadcast from web ===
  // Source: testpattern (default) | screen | file | rtmp
  if (p === '/api/live/broadcast/start') {
    const qs = url.search || '';
    const proxyReq = http.get('http://127.0.0.1:4711/api/live/broadcast/start' + qs,
      { timeout: 8000 }, (proxyRes) => {
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

  // === GET /api/live/broadcast/stop — Proxy: stop broadcast ===
  if (p === '/api/live/broadcast/stop') {
    const proxyReq = http.get('http://127.0.0.1:4711/api/live/broadcast/stop',
      { timeout: 5000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        try { jsonResponse(res, 200, JSON.parse(body)); }
        catch (e) { jsonResponse(res, 200, { success: false }); }
      });
    });
    proxyReq.on('error',   () => jsonResponse(res, 200, { success: false, error: 'eMule offline' }));
    proxyReq.on('timeout', () => { proxyReq.destroy(); jsonResponse(res, 200, { success: false, error: 'timeout' }); });
    return true;
  }

  // === GET /api/live/preflight — Proxy + STUN fallback for public IP ===
  // Tier 1.4: if eMule's Kad firewall test hasn't completed yet, public_ip
  // comes back empty. We then fall back to a public HTTP echo service
  // (api.ipify.org) so the user gets their IP within seconds of launching,
  // not minutes. The result is cached in-memory for 10 minutes.
  if (p === '/api/live/preflight') {
    const proxyReq = http.get('http://127.0.0.1:4711/api/live/preflight', { timeout: 3000 }, (proxyRes) => {
      let body = '';
      proxyRes.on('data', d => body += d);
      proxyRes.on('end', () => {
        let data;
        try { data = JSON.parse(body); }
        catch (e) { return jsonResponse(res, 200, { ready: false, error: 'parse_error' }); }

        // STUN fallback: if eMule doesn't know our public IP yet, ask ipify.
        if (!data.public_ip) {
          getCachedPublicIP(function (ip) {
            if (ip) {
              data.public_ip = ip;
              data.public_ip_source = 'ipify';
            }
            jsonResponse(res, 200, data);
          });
        } else {
          data.public_ip_source = 'kad';
          jsonResponse(res, 200, data);
        }
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
    const status = pipeline.getStatus();
    jsonResponse(res, 200, { ...status, meta: streamMeta });
    return true;
  }

  // === GET /api/live/sources ===
  if (p === '/api/live/sources') {
    const sources = deviceScanner.getSourcesForAPI(ctx.ffmpegPath);
    jsonResponse(res, 200, { sources });
    return true;
  }

  // === POST /api/live/start ===
  if (p === '/api/live/start' && req.method === 'POST') {
    // Guard: eMule must be running to publish on the P2P network
    const emuleApi = require('../emule_api');
    if (!emuleApi.isEmuleRunning()) {
      jsonResponse(res, 503, {
        success: false,
        error: 'eMule no está activo. Inicia eMule antes de emitir para que el broadcast sea visible en la red P2P.'
      });
      return true;
    }

    readBody(req, (body) => {
      try {
        const config = JSON.parse(body);
        // Update metadata
        streamMeta.title = config.title || 'Sin t\u00edtulo';
        streamMeta.category = config.category || 'general';
        streamMeta.language = config.language || 'es';

        const result = pipeline.start({
          source: {
            type: config.sourceType || 'screen',
            id: config.sourceId || 'desktop',
            audioDevice: config.audioDevice || null,
            width: config.width || 0,
            height: config.height || 0,
            fps: config.fps || 30
          },
          ffmpegPath: ctx.ffmpegPath,
          outputDir: LIVE_DIR,
          hwEncoder: ctx.hwEncoder,
          hwEncoderOpts: ctx.hwEncoderOpts,
          bitrate: config.bitrate || 3000,
          segmentDuration: 4
        });

        // Register channel in directory
        localStreamKey = 'local_' + Date.now().toString(36);
        channelSearch.registerChannel({
          streamKey: localStreamKey,
          title: streamMeta.title,
          category: streamMeta.category,
          language: streamMeta.language,
          bitrate: config.bitrate || 3000,
          viewers: 0
        });

        jsonResponse(res, result.success ? 200 : 400, result);
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

    // Stop Node.js pipeline
    const result = pipeline.stop();
    if (localStreamKey) {
      channelSearch.unregisterChannel(localStreamKey);
      localStreamKey = null;
    }
    streamMeta = { title: '', category: 'general', language: 'es' };

    // Also kill any eMule-spawned FFmpeg orphans and clean HLS files
    const emuleApi = require('../emule_api');
    if (typeof emuleApi.killEmuleFFmpegOrphans === 'function') {
      emuleApi.killEmuleFFmpegOrphans();
    }
    cleanHLSFiles();

    jsonResponse(res, 200, result);
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
      localResults.forEach(ch => byKey.set(ch.streamKey || ch.hash, ch));
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
        const k = s.streamKey || s.hash;
        if (k) kadByKey.set(k, s);
      });

      (kadStreams || []).forEach(s => {
        const key = s.streamKey || s.hash;
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
          ed2kLink: `ed2k://|stream|${encodeURIComponent(s.title || 'Live')}|${key}|/`
        });
      });

      // BROWSE-S01 final pass: for EVERY channel (local-registered, kad,
      // or merged) add broadcasterIP + httpPort + thumbnailUrl. Without
      // this single pass, channels that came from localResults skip the
      // kad-only enrichment and the grid shows empty thumbnailUrl.
      const results = Array.from(byKey.values()).map(ch => {
        const key = ch.streamKey || ch.hash;
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
    readBody(req, (body) => {
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
    readBody(req, (body) => {
      try {
        const config = JSON.parse(body);
        streamMeta.title = config.title || 'OBS Stream';
        streamMeta.category = config.category || 'general';
        streamMeta.language = config.language || 'es';

        const result = rtmpServer.start({
          ffmpegPath: ctx.ffmpegPath,
          outputDir: LIVE_DIR,
          hwEncoder: ctx.hwEncoder,
          hwEncoderOpts: ctx.hwEncoderOpts,
          port: config.port || 1935,
          bitrate: config.reencode ? (config.bitrate || 3000) : 0,
          onStatus: (status) => {
            if (status === 'receiving' && !localStreamKey) {
              localStreamKey = 'obs_' + Date.now().toString(36);
              channelSearch.registerChannel({
                streamKey: localStreamKey,
                title: streamMeta.title,
                category: streamMeta.category,
                language: streamMeta.language,
                bitrate: config.bitrate || 6000
              });
            }
          }
        });

        jsonResponse(res, result.success ? 200 : 400, result);
      } catch (e) {
        jsonResponse(res, 400, { success: false, error: e.message });
      }
    });
    return true;
  }

  // === POST /api/live/rtmp/stop ===
  if (p === '/api/live/rtmp/stop' && req.method === 'POST') {
    rtmpServer.stop();
    if (localStreamKey) {
      channelSearch.unregisterChannel(localStreamKey);
      localStreamKey = null;
    }
    streamMeta = { title: '', category: 'general', language: 'es' };
    jsonResponse(res, 200, { success: true });
    return true;
  }

  // === GET /api/live/rtmp/status ===
  if (p === '/api/live/rtmp/status') {
    jsonResponse(res, 200, rtmpServer.getStatus());
    return true;
  }

  // === POST /api/live/tunnel/start — Start WebSocket tunnel ===
  if (p === '/api/live/tunnel/start' && req.method === 'POST') {
    readBody(req, (body) => {
      try {
        const config = JSON.parse(body);
        const result = wsTunnel.startServer({
          port: config.port || 8443,
          onConnection: (id) => console.log('[eSE Tunnel] New peer:', id),
          onMessage: (id, opcode, data) => {
            console.log('[eSE Tunnel] Message from', id, 'opcode:', opcode);
          }
        });
        jsonResponse(res, result.success ? 200 : 400, result);
      } catch (e) {
        jsonResponse(res, 400, { success: false, error: e.message });
      }
    });
    return true;
  }

  // === POST /api/live/tunnel/stop ===
  if (p === '/api/live/tunnel/stop' && req.method === 'POST') {
    jsonResponse(res, 200, wsTunnel.stopServer());
    return true;
  }

  // === GET /api/live/tunnel/status ===
  if (p === '/api/live/tunnel/status') {
    jsonResponse(res, 200, wsTunnel.getStatus());
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
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>eSE Live</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
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
<video id="v" autoplay playsinline></video>
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

if(Hls.isSupported()){
const h=new Hls({liveSyncDurationCount:3,liveMaxLatencyDurationCount:8,liveDurationInfinity:true,maxBufferLength:30,maxMaxBufferLength:60,maxBufferHole:2,manifestLoadingMaxRetry:50,levelLoadingMaxRetry:50,fragLoadingMaxRetry:50});
h.loadSource(src);h.attachMedia(v);
// Phase 3: Transition to PLAYING only on FRAG_BUFFERED (actual data), not MANIFEST_PARSED (existence)
h.on(Hls.Events.MANIFEST_PARSED,()=>{v.play();updateJoinOverlay('BUFFERING',0,0,'OK')});
h.on(Hls.Events.FRAG_BUFFERED,()=>{if(joinState!=='PLAYING'){updateJoinOverlay('PLAYING',0,0,'OK');clearInterval(joinPollId)}});
h.on(Hls.Events.ERROR,(e,d)=>{if(!d.fatal)return;if(d.type==='mediaError'){h.recoverMediaError()}else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}});
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
}else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=src}

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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
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
    const needle = require('needle');
    needle.get('http://127.0.0.1:4711/api/live/mesh', { timeout: 2000 }, (err, resp) => {
      if (err || !resp || resp.statusCode !== 200) {
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
        jsonResponse(res, 200, resp.body);
      }
    });
    return true;
  }

  // === GET /api/live/p2p/streams — Kad-discovered P2P streams ===
  if (p === '/api/live/p2p/streams') {
    const needle = require('needle');
    needle.get('http://127.0.0.1:4711/api/live/kad/streams', { timeout: 3000 }, (err, resp) => {
      if (err || !resp || resp.statusCode !== 200) {
        // Fallback: return local channel directory
        const channels = channelSearch.search({});
        jsonResponse(res, 200, {
          streams: channels.map(ch => ({
            ...ch,
            source: 'local',
            ed2kLink: `ed2k://|stream|${encodeURIComponent(ch.title)}|${ch.streamKey}|/`
          })),
          kadConnected: false
        });
      } else {
        const data = resp.body;
        // Add ed2k links to Kad streams
        if (data.streams) {
          data.streams.forEach(s => {
            s.ed2kLink = `ed2k://|stream|${encodeURIComponent(s.title || 'Live')}|${s.streamKey}|/`;
          });
        }
        jsonResponse(res, 200, data);
      }
    });
    return true;
  }

  // === GET /api/live/p2p/share — Generate share link ===
  if (p === '/api/live/p2p/share') {
    const key = url.searchParams.get('key') || localStreamKey || '';
    const title = url.searchParams.get('title') || streamMeta.title || 'Live';
    const ed2kLink = `ed2k://|stream|${encodeURIComponent(title)}|${key}|/`;
    const webLink = `http://localhost:${url.port || 8080}/live/watch/${key}`;
    jsonResponse(res, 200, { ed2kLink, webLink, streamKey: key });
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
          if (data.channels && data.channels.length > 0) {
            data.channels.forEach(ch => {
              channelSearch.addRemoteChannel({
                streamKey: ch.hash || ch.streamKey,
                title: ch.title || 'eMule Broadcast',
                category: ch.category || 'general',
                language: ch.language || 'es',
                bitrate: ch.bitrate || 3000,
                viewers: ch.viewers || 0,
                started: ch.started || new Date().toISOString()
              });
            });
          }
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
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req, cb) {
  let body = '';
  req.on('data', d => body += d);
  req.on('end', () => cb(body));
}

// Background poller to sync eMule channels with our local directory
function pollEmuleChannels() {
  const req = http.get('http://127.0.0.1:4711/api/live/channels', { timeout: 3000 }, (res) => {
    let body = '';
    res.on('data', d => body += d);
    res.on('end', () => {
      try {
        const data = JSON.parse(body);
        if (data.channels && data.channels.length > 0) {
          data.channels.forEach(ch => {
            channelSearch.addRemoteChannel({
              streamKey: ch.hash || ch.streamKey,
              title: ch.title || 'eMule Broadcast',
              category: ch.category || 'general',
              language: ch.language || 'es',
              bitrate: ch.bitrate || 3000,
              viewers: ch.viewers || 0,
              started: ch.started || new Date().toISOString()
            });
          });
        }
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
