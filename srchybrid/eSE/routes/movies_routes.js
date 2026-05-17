'use strict';
const fs    = require('fs');
const https = require('https');
const path  = require('path');
const { TMDB_KEY } = require('../api_keys');

let _ctx = {};

function init(ctx) { _ctx = ctx; }

// ── /api/tmdb/* proxy ──────────────────────────────────────────────────────────
// Forwards any TMDB v3 path to api.themoviedb.org, injecting the server-side
// key. Keeps the key out of the client bundle (was previously hardcoded in
// poster_hero.js and search_ui.js, exposing it to public scrape).
//
// Examples:
//   GET /api/tmdb/trending/movie/week?language=es-ES
//   GET /api/tmdb/movie/123/external_ids
//   GET /api/tmdb/search/movie?query=Matrix&language=es-ES
//
// Path is anything after /api/tmdb/. Query params are forwarded as-is.
// Allowlist on path prefix prevents abusing this as a generic outbound proxy.
const _TMDB_ALLOW = /^(trending|movie|search|find|tv|discover|configuration|genre)(\/|$)/;

function _handleTmdbProxy(url, req, res) {
  // Strip /api/tmdb/ and validate
  const tmdbPath = url.pathname.replace(/^\/api\/tmdb\//, '');
  if (!_TMDB_ALLOW.test(tmdbPath)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'forbidden' }));
    return true;
  }

  // Build outbound URL: forward query string, inject api_key
  const params = new URLSearchParams(url.search);
  params.set('api_key', TMDB_KEY);
  const target = 'https://api.themoviedb.org/3/' + tmdbPath + '?' + params.toString();

  https.get(target, { headers: { 'User-Agent': 'eSE-LiveTV/7.0' } }, (tmdbRes) => {
    res.writeHead(tmdbRes.statusCode || 502, {
      'Content-Type': tmdbRes.headers['content-type'] || 'application/json',
      'Cache-Control': 'public, max-age=300'  // 5min client cache
    });
    tmdbRes.pipe(res);
  }).on('error', (e) => {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'tmdb_unreachable', detail: e.message }));
  });

  return true;
}

function handle(url, req, res) {
  // TMDB proxy
  if (url.pathname.startsWith('/api/tmdb/')) {
    return _handleTmdbProxy(url, req, res);
  }

  if (!url.pathname.startsWith('/api/movies/')) return false;

  if (url.pathname === '/api/movies/poster') {
    const title    = url.searchParams.get('title') || '';
    const safeName = title.replace(/[^a-z0-9]/gi, '_').substring(0, 60);
    const posterPath = path.join(_ctx.CACHE_DIR, safeName + '.jpg');
    if (fs.existsSync(posterPath)) {
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=86400' });
      fs.createReadStream(posterPath).pipe(res);
    } else {
      res.writeHead(404); res.end('');
    }
    return true;
  }

  if (url.pathname === '/api/movies/fetchinfo') {
    const title       = url.searchParams.get('title') || '';
    const rawFilename = url.searchParams.get('raw')   || '';   // optional: original P2P filename for AI fallback
    if (!title) { res.writeHead(400); res.end('{}'); return true; }
    const settings = _ctx.loadSettings ? _ctx.loadSettings() : {};
    _ctx.fetchAndCacheMovie(title, _ctx.CACHE_DIR, (info) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(info || { Response: 'False' }));
    }, rawFilename, settings);

    return true;
  }

  if (url.pathname === '/api/movies/search') {
    const q = url.searchParams.get('q') || '';
    if (!q) { res.writeHead(400); res.end('{}'); return true; }
    _ctx.proxyOMDB('s=' + encodeURIComponent(q), res);
    return true;
  }

  if (url.pathname === '/api/movies/detail') {
    const id = url.searchParams.get('id') || '';
    _ctx.proxyOMDB('i=' + encodeURIComponent(id) + '&plot=full', res);
    return true;
  }

  if (url.pathname === '/api/movies/trailer') {
    const q = url.searchParams.get('q') || '';
    if (!q) { res.writeHead(400); res.end('{}'); return true; }
    const ytUrl = 'https://www.youtube.com/results?search_query=' + encodeURIComponent(q + ' official trailer');
    https.get(ytUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } }, (ytRes) => {
      let html = '';
      ytRes.on('data', d => html += d);
      ytRes.on('end', () => {
        const match = html.match(/"videoId":"([a-zA-Z0-9_-]{11})"/);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ videoId: match ? match[1] : null }));
      });
    }).on('error', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ videoId: null }));
    });
    return true;
  }

  return false;
}

module.exports = { init, handle };
