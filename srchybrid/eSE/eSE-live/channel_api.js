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

const HLS_LIVE_DIR = path.join(os.tmpdir(), 'eMule_RTMP');
const LIVE_DIR = HLS_LIVE_DIR;

// Ensure live segment directory exists
try { if (!fs.existsSync(LIVE_DIR)) fs.mkdirSync(LIVE_DIR, { recursive: true }); } catch (e) { console.warn('[eSE Live] Failed to create live dir:', e.message); }

// Stream metadata (title, category, language)
let streamMeta = { title: '', category: 'general', language: 'es' };
let localStreamKey = null;

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
      const results = Array.from(byKey.values());
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
    const hlsBase = '/api/live/hls-proxy/' + hash;
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

// Initial fetch + interval
pollEmuleChannels();
setInterval(pollEmuleChannels, 10000);

module.exports = { handleRoute };
