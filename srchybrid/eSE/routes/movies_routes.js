'use strict';
const fs    = require('fs');
const https = require('https');
const path  = require('path');
const apiKeys = require('../api_keys');
const { validateRouteContext } = require('./route_context');

/** @type {Pick<import('./route_context').SharedRouteContext, 'CACHE_DIR'|'loadSettings'> & Record<string, Function|string>} */
let _ctx = {};

function init(ctx) {
  _ctx = validateRouteContext(ctx, 'movies', {
    CACHE_DIR: 'string', loadSettings: 'function', fetchAndCacheMovie: 'function', proxyOMDB: 'function',
  });
}

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
// Path is anything after /api/tmdb/. Safe query params are forwarded and the
// configured credential is injected server-side.
// Allowlist on path prefix prevents abusing this as a generic outbound proxy.
const _TMDB_ALLOW = /^(trending|movie|search|find|tv|discover|configuration|genre)(\/|$)/;
const _TMDB_RESPONSE_LIMIT = 5 * 1024 * 1024;
const _TMDB_TIMEOUT_MS = 15000;

function _json(res, statusCode, payload) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(payload));
}

function _requireOmdbKey(res) {
  const omdbKey = apiKeys.getOmdbKey();
  if (omdbKey) return omdbKey;
  _json(res, 503, { error: 'omdb_not_configured' });
  return null;
}

function _redactCredential(value, credential) {
  if (typeof value !== 'string') {
    if (Array.isArray(value)) return value.map(item => _redactCredential(item, credential));
    if (value && typeof value === 'object') {
      const output = Object.create(null);
      for (const [key, item] of Object.entries(value)) {
        const safeKey = _redactCredential(key, credential);
        if (Object.prototype.hasOwnProperty.call(output, safeKey)) continue;
        output[safeKey] = _redactCredential(item, credential);
      }
      return output;
    }
    return value;
  }
  const formEncoded = new URLSearchParams([['api_key', credential]])
    .toString().slice('api_key='.length);
  const variants = new Set([credential, encodeURIComponent(credential), formEncoded]);
  let text = value;
  for (const variant of variants) {
    if (variant) text = text.split(variant).join('[redacted]');
  }
  return text;
}

function _forwardTmdbResponse(tmdbRes, res, credential) {
  const chunks = [];
  let total = 0;
  let finished = false;

  function fail(error) {
    if (finished) return;
    finished = true;
    _json(res, 502, { error });
  }

  tmdbRes.on('data', (chunk) => {
    if (finished) return;
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > _TMDB_RESPONSE_LIMIT) {
      fail('tmdb_response_too_large');
      if (typeof tmdbRes.destroy === 'function') tmdbRes.destroy();
      return;
    }
    chunks.push(bytes);
  });

  tmdbRes.on('end', () => {
    if (finished) return;
    finished = true;
    if (res.headersSent || res.writableEnded) return;
    const statusCode = Number.isInteger(tmdbRes.statusCode) && tmdbRes.statusCode >= 100 && tmdbRes.statusCode <= 599
      ? tmdbRes.statusCode : 502;
    let body;
    try {
      const parsed = JSON.parse(Buffer.concat(chunks, total).toString('utf8'));
      body = Buffer.from(JSON.stringify(_redactCredential(parsed, credential)), 'utf8');
    } catch (_) {
      _json(res, 502, { error: 'tmdb_unreachable' });
      return;
    }
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'public, max-age=300'
    });
    res.end(body);
  });

  tmdbRes.on('error', () => fail('tmdb_unreachable'));
}

function _handleTmdbProxy(url, req, res) {
  // Resolve authentication before validating or constructing an outbound URL.
  // Missing local configuration must never result in network traffic.
  const tmdbKey = apiKeys.getTmdbKey();
  if (!tmdbKey) {
    _json(res, 503, { error: 'tmdb_not_configured' });
    return true;
  }

  // Strip /api/tmdb/ and validate
  const tmdbPath = url.pathname.replace(/^\/api\/tmdb\//, '');
  if (!_TMDB_ALLOW.test(tmdbPath)) {
    _json(res, 403, { error: 'forbidden' });
    return true;
  }

  // Never accept credentials supplied by a caller.  Remove every casing of
  // api_key before injecting the locally configured value exactly once.
  const params = new URLSearchParams(url.search);
  for (const name of [...params.keys()]) {
    if (name.toLowerCase() === 'api_key') params.delete(name);
  }
  params.set('api_key', tmdbKey);
  const target = 'https://api.themoviedb.org/3/' + tmdbPath + '?' + params.toString();

  let request;
  try {
    request = https.get(target, {
      headers: { 'User-Agent': 'eSE-LiveTV/7.0' },
      signal: AbortSignal.timeout(_TMDB_TIMEOUT_MS)
    }, (tmdbRes) => {
      _forwardTmdbResponse(tmdbRes, res, tmdbKey);
    });
    request.on('error', () => _json(res, 502, { error: 'tmdb_unreachable' }));
    if (typeof request.setTimeout === 'function') {
      request.setTimeout(_TMDB_TIMEOUT_MS, () => {
        _json(res, 502, { error: 'tmdb_unreachable' });
        request.destroy();
      });
    }
  } catch (_) {
    _json(res, 502, { error: 'tmdb_unreachable' });
  }

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
    fs.promises.access(posterPath).then(() => {
      res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'public, max-age=86400' });
      fs.createReadStream(posterPath).pipe(res);
    }).catch(() => {
      res.writeHead(404); res.end('');
    });
    return true;
  }

  if (url.pathname === '/api/movies/fetchinfo') {
    const title       = url.searchParams.get('title') || '';
    const rawFilename = url.searchParams.get('raw')   || '';   // optional: original P2P filename for AI fallback
    if (!title) { res.writeHead(400); res.end('{}'); return true; }
    const omdbKey = _requireOmdbKey(res);
    if (!omdbKey) return true;
    const settings = _ctx.loadSettings ? _ctx.loadSettings() : {};
    _ctx.fetchAndCacheMovie(title, _ctx.CACHE_DIR, (info, error) => {
      if (error) {
        const notConfigured = error === 'omdb_not_configured';
        _json(res, notConfigured ? 503 : 502, {
          error: notConfigured ? 'omdb_not_configured' : 'omdb_unreachable'
        });
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(info || { Response: 'False' }));
    }, rawFilename, settings, omdbKey);

    return true;
  }

  if (url.pathname === '/api/movies/search') {
    const q = url.searchParams.get('q') || '';
    if (!q) { res.writeHead(400); res.end('{}'); return true; }
    const omdbKey = _requireOmdbKey(res);
    if (!omdbKey) return true;
    _ctx.proxyOMDB('s=' + encodeURIComponent(q), res, omdbKey);
    return true;
  }

  if (url.pathname === '/api/movies/detail') {
    const id = url.searchParams.get('id') || '';
    const omdbKey = _requireOmdbKey(res);
    if (!omdbKey) return true;
    _ctx.proxyOMDB('i=' + encodeURIComponent(id) + '&plot=full', res, omdbKey);
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
