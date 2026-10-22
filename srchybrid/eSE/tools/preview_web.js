'use strict';

// Source-page preview only. This entry point never loads server.js, starts
// discovery, launches eMule/FFmpeg, or forwards playback/control operations.
// Usage: node tools/preview_web.js (optional ESE_PREVIEW_PORT, default 8091).
// Regenerate the browser bundle with node tools/bundle_client.js after edits.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const { escapeHtml, cleanTitle } = require('../utils');
const port = Number(process.env.ESE_PREVIEW_PORT || 8091);
if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 8080) {
  throw new Error('ESE_PREVIEW_PORT must be a valid port other than the live dashboard port 8080.');
}

// Exact read endpoints and accepted query keys. In particular, fetchinfo,
// eMule searches, login, cleanup, streams, pairing and controls are excluded.
const reads = new Map([
  ['/api/emule/downloads', []],
  ['/api/stream/completed/list', []],
  ['/api/emule/status', []],
  ['/api/status', []],
  ['/api/settings', []],
  ['/api/tunnel/status', []],
  ['/api/nat-health', []],
  ['/api/v1/lifecycle', []],
  ['/api/movies/search', ['q']],
  ['/api/movies/detail', ['id']],
  ['/api/movies/poster', ['title']],
  ['/api/movies/trailer', ['q']],
  ['/api/live/connection-status', []],
  ['/api/live/preflight', []],
  ['/api/live/monitor', []],
  ['/api/live/channels', ['q', 'category', 'lang', 'minRating', 'quality', 'sort']],
  ['/api/live/first_run', []]
]);
const tmdbReads = [
  /^\/api\/tmdb\/trending\/(all|movie|tv)\/(day|week)$/,
  /^\/api\/tmdb\/(movie|tv)\/(popular|top_rated|now_playing|on_the_air)$/,
  /^\/api\/tmdb\/(movie|tv)\/\d+(\/(external_ids|videos|credits|images))?$/,
  /^\/api\/tmdb\/search\/(movie|tv|multi)$/,
  /^\/api\/tmdb\/find\/tt\d+$/,
  /^\/api\/tmdb\/discover\/(movie|tv)$/,
  /^\/api\/tmdb\/genre\/(movie|tv)\/list$/
];
const tmdbQuery = ['language', 'page', 'query', 'external_source', 'sort_by',
  'with_genres', 'include_adult', 'vote_count.gte', 'year', 'primary_release_year'];

function allowedRead(url) {
  const keys = reads.get(url.pathname) ||
    (tmdbReads.some(pattern => pattern.test(url.pathname)) ? tmdbQuery : null);
  return !!keys && [...url.searchParams.keys()].every(key => keys.includes(key));
}

function json(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(value));
}

function upstream(url) {
  if (!allowedRead(url)) return Promise.reject(new Error('Preview read is not allowlisted.'));
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port: 8080,
      path: url.pathname + url.search, method: 'GET', timeout: 12000,
      headers: { Accept: 'application/json, image/jpeg', 'User-Agent': 'eSE-source-preview' }
    }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 8 * 1024 * 1024) {
          req.destroy(new Error('Preview upstream response exceeds 8 MiB.'));
        } else chunks.push(chunk);
      });
      response.on('end', () => resolve({ status: response.statusCode || 502,
        type: response.headers['content-type'] || 'application/json',
        body: Buffer.concat(chunks) }));
      response.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Live dashboard read timed out.')));
    req.on('error', reject);
  });
}

async function readList(route) {
  try {
    const result = await upstream(new URL(route, 'http://127.0.0.1:8080'));
    if (result.status !== 200) throw new Error('HTTP ' + result.status);
    const data = JSON.parse(result.body.toString('utf8'));
    if (!Array.isArray(data)) throw new Error('Expected a library array.');
    return { data, available: true };
  } catch (error) {
    console.warn('[preview] Real library unavailable at ' + route + ': ' + error.message);
    return { data: [], available: false };
  }
}

// Reload renderer modules on navigation so CSS/markup edits appear on refresh.
function loadPage(name) {
  for (const id of Object.keys(require.cache)) {
    if (id.startsWith(path.join(root, 'shared') + path.sep)) delete require.cache[id];
  }
  const file = require.resolve(path.join(root, name));
  delete require.cache[file];
  return require(file);
}

function previewHTML(html, unavailable) {
  const note = unavailable ? ' · Biblioteca real no disponible' : '';
  const banner = '<aside aria-label="Modo vista previa" style="position:fixed;bottom:12px;left:12px;z-index:9999;padding:8px 12px;border:1px solid #555;border-radius:8px;background:#161920ed;color:#ddd;font:12px system-ui;pointer-events:none">Vista previa · Solo lectura' + note + '</aside>';
  return html.replace(/<\/body>/i, banner + '</body>');
}

function renderPage(module, url, req, res, ctx, unavailable) {
  if (module.init) module.init(ctx);
  const capture = {
    writeHead(status, headers) { res.writeHead(status, headers); },
    end(body) { res.end(previewHTML(String(body || ''), unavailable)); }
  };
  module.handle(url, req, capture);
}

const pages = new Map([
  ['/', 'pages/main_page.js'], ['/index.html', 'pages/main_page.js'],
  ['/explore', 'pages/explore_page.js'], ['/mylist', 'pages/mylist_page.js'],
  ['/search', 'pages/search_page.js']
]);
const assets = new Map([
  ['/player.js', ['_player_bundle.js', 'application/javascript; charset=utf-8']],
  ['/emule_mascot.svg', ['emule_mascot.svg', 'image/svg+xml']],
  ['/favicon.ico', ['favicon.ico', 'image/x-icon']],
  ['/live/player.js', ['eSE-live/live_tv_player.js', 'application/javascript; charset=utf-8']],
  ['/live/vendor/hls.min.js', ['eSE-live/vendor/hls.min.js', 'application/javascript; charset=utf-8']]
]);

const server = http.createServer(async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-ESE-Preview', 'read-only');
  const hosts = ['127.0.0.1:' + port, 'localhost:' + port];
  if (!hosts.includes(req.headers.host) ||
      (req.headers.origin && !hosts.some(host => req.headers.origin === 'http://' + host)) ||
      req.headers['sec-fetch-site'] === 'cross-site') {
    return json(res, 403, { error: 'preview_local_origin_required' });
  }
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return json(res, 405, { error: 'preview_read_only', message: 'Vista previa: acciones desactivadas.' });
  }
  try {
    const url = new URL(req.url, 'http://127.0.0.1:' + port);
    if (allowedRead(url) && url.pathname.startsWith('/api/tmdb/')) {
      // Use the source API configuration for the source UI, not the installed binary.
      return require('../routes/movies_routes').handle(url, req, res);
    }
    if (allowedRead(url)) {
      const result = await upstream(url);
      // Never follow upstream redirects, copy cookies, or expose control URLs.
      if (result.status >= 300 && result.status < 400) {
        return json(res, 502, { error: 'preview_upstream_redirect_blocked' });
      }
      res.writeHead(result.status, { 'Content-Type': result.type });
      return res.end(result.body);
    }
    if (assets.has(url.pathname)) {
      const [relative, type] = assets.get(url.pathname);
      const body = fs.readFileSync(path.join(root, relative));
      res.writeHead(200, { 'Content-Type': type });
      return res.end(body);
    }
    const ctx = { PORT: port, __dirname: root, __dir: root, escapeHtml, cleanTitle,
      getDownloads: () => [], getCompletedFiles: () => [] };
    if (pages.has(url.pathname)) {
      let unavailable = false;
      if (url.pathname === '/' || url.pathname === '/index.html') {
        const [downloads, completed] = await Promise.all([
          readList('/api/emule/downloads'), readList('/api/stream/completed/list')
        ]);
        unavailable = !downloads.available || !completed.available;
        ctx.getDownloads = () => downloads.data.filter(item => typeof item.fileName === 'string')
          .map(item => ({ fileName: item.fileName, sizeMB: Number(item.sizeMB) || 0, sizeBytes: Number(item.sizeBytes) || 0,
            partNum: String(item.partNum || item.partFile || '').replace(/\.part$/, ''), completed: false }));
        ctx.getCompletedFiles = () => completed.data.filter(item => typeof item.fileName === 'string')
          .map(item => ({ fileName: item.fileName, sizeMB: Number(item.sizeMB) || 0, completed: true }));
      }
      return renderPage(loadPage(pages.get(url.pathname)), url, req, res, ctx, unavailable);
    }
    if (url.pathname === '/live' || url.pathname === '/live/') {
      const page = loadPage('eSE-live/live_tv_page.js');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(previewHTML(page.render(), false));
    }
    if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/live/') ||
        url.pathname.startsWith('/pair/') || ['/connect', '/app', '/remote'].includes(url.pathname)) {
      return json(res, 403, { error: 'preview_read_only', message: 'Vista previa: reproducción, conexión y acciones desactivadas.' });
    }
    json(res, 404, { error: 'preview_route_not_found' });
  } catch (error) {
    console.warn('[preview] ' + error.message);
    if (!res.headersSent) json(res, 502, { error: 'preview_read_unavailable', message: error.message });
    else res.end();
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log('[preview] VISTA PREVIA SOLO LECTURA: http://127.0.0.1:' + port);
  console.log('[preview] Páginas fuente + _player_bundle.js. Biblioteca/metadata: GET permitidos de 127.0.0.1:8080.');
  console.log('[preview] Sin arranque de eMule, descubrimiento, emisiones, reproducción, pairing ni mutaciones.');
});
server.on('error', error => { console.error('[preview] ' + error.message); process.exitCode = 1; });
