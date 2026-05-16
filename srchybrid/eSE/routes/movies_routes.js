'use strict';
const fs    = require('fs');
const https = require('https');
const path  = require('path');

let _ctx = {};

function init(ctx) { _ctx = ctx; }

function handle(url, req, res) {
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
