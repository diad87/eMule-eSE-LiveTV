'use strict';

let _ctx = {};

function init(ctx) {
  _ctx = ctx || {};
}

function json(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

function rewrite(url, pathname) {
  const next = new URL(url.toString());
  next.pathname = pathname;
  return next;
}

function delegate(handler, url, req, res, pathname) {
  if (!handler || !handler.handle) return false;
  return handler.handle(rewrite(url, pathname), req, res);
}

function handle(url, req, res) {
  const p = url.pathname;
  if (!p.startsWith('/api/v1/')) return false;

  if (p === '/api/v1/status') {
    json(res, 200, {
      ok: true,
      apiVersion: 1,
      uptime: Math.round(process.uptime()),
      auth: { enabled: !!(_ctx.security && _ctx.security.isReady()) },
      emule: {
        loggedIn: !!(_ctx.getSession && _ctx.getSession()),
        running: !!(_ctx.emuleApi && _ctx.emuleApi.isEmuleRunning && _ctx.emuleApi.isEmuleRunning())
      },
      live: { coreStats: '/api/v1/live/p2p/stats', streams: '/api/v1/live/p2p/streams' }
    });
    return true;
  }

  // v7.4.0 — lifecycle endpoint. Surfaces eMule alive/dead + monotonic library
  // epoch so the front-end can detect a process restart and refresh stale
  // state (e.g. smart_play's .part-still-playable heuristic).
  if (p === '/api/v1/lifecycle') {
    const alive = !!(_ctx.emuleApi && _ctx.emuleApi.isEmuleRunning && _ctx.emuleApi.isEmuleRunning());
    json(res, 200, {
      alive,
      epoch: _ctx.emuleApi && _ctx.emuleApi.getLibraryEpoch ? _ctx.emuleApi.getLibraryEpoch() : 0,
      restartedAt: _ctx.emuleApi && _ctx.emuleApi.getRestartedAt ? _ctx.emuleApi.getRestartedAt() : 0
    });
    return true;
  }

  if (p === '/api/v1/capabilities') {
    json(res, 200, {
      localControl: [
        'status', 'lifecycle', 'settings', 'search', 'smartsearch', 'download', 'download-actions',
        'ed2klink', 'downloads', 'completed-library', 'streaming', 'live-p2p'
      ],
      compatibility: {
        liveP2P: 'ese-only',
        classicEmule: 'unchanged',
        fallback: ['upnp', 'local-hls']
      },
      pendingNativeCoverage: [
        'server-list mutations', 'kad bootstrap mutations', 'upload queue controls',
        'friends/messages/irc ui', 'remote dashboard access'
      ]
    });
    return true;
  }

  if (p === '/api/v1/settings') return delegate(_ctx.emuleRoutes, url, req, res, '/api/settings');

  if (p === '/api/v1/search') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/search');
  }

  if (p === '/api/v1/search/smart') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/smartsearch');
  }

  if (p === '/api/v1/downloads') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/downloads');
  }

  if (p === '/api/v1/downloads/add') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/download');
  }

  if (p === '/api/v1/downloads/action') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/download/action');
  }

  const downloadAction = p.match(/^\/api\/v1\/downloads\/([A-Fa-f0-9]{32})\/(pause|resume|stop|cancel|getflc)$/);
  if (downloadAction) {
    const next = rewrite(url, '/api/emule/download/action');
    next.searchParams.set('hash', downloadAction[1]);
    next.searchParams.set('action', downloadAction[2]);
    return delegate(_ctx.emuleRoutes, next, req, res, next.pathname);
  }

  const downloadPriority = p.match(/^\/api\/v1\/downloads\/([A-Fa-f0-9]{32})\/priority\/(low|normal|high|auto)$/);
  if (downloadPriority) {
    const next = rewrite(url, '/api/emule/download/action');
    next.searchParams.set('hash', downloadPriority[1]);
    next.searchParams.set('action', 'priority');
    next.searchParams.set('priority', downloadPriority[2]);
    return delegate(_ctx.emuleRoutes, next, req, res, next.pathname);
  }

  const downloadCategory = p.match(/^\/api\/v1\/downloads\/([A-Fa-f0-9]{32})\/category\/(\d+)$/);
  if (downloadCategory) {
    const next = rewrite(url, '/api/emule/download/action');
    next.searchParams.set('hash', downloadCategory[1]);
    next.searchParams.set('action', 'setcat');
    next.searchParams.set('category', downloadCategory[2]);
    return delegate(_ctx.emuleRoutes, next, req, res, next.pathname);
  }

  if (p === '/api/v1/ed2k' || p === '/api/v1/downloads/ed2k') {
    return delegate(_ctx.emuleRoutes, url, req, res, '/api/emule/ed2klink');
  }

  if (p.startsWith('/api/v1/emule/')) {
    return delegate(_ctx.emuleRoutes, url, req, res, p.replace('/api/v1/emule/', '/api/emule/'));
  }

  if (p === '/api/v1/library/completed') {
    return delegate(_ctx.streamCompleted, url, req, res, '/api/stream/completed/list');
  }

  if (p.startsWith('/api/v1/stream/')) {
    const legacyPath = p.replace('/api/v1/stream/', '/api/stream/');
    if (delegate(_ctx.streamCompleted, url, req, res, legacyPath)) return true;
    if (delegate(_ctx.streamPart, url, req, res, legacyPath)) return true;
  }

  if (p.startsWith('/api/v1/tunnel/')) {
    return delegate(_ctx.systemRoutes, url, req, res, p.replace('/api/v1/tunnel/', '/api/tunnel/'));
  }

  if (p.startsWith('/api/v1/live/')) {
    const livePath = p.replace('/api/v1/live/', '/api/live/');
    if (_ctx.liveApi && _ctx.liveApi.handleRoute) {
      return _ctx.liveApi.handleRoute(rewrite(url, livePath), req, res, _ctx.liveRouteCtx || {});
    }
  }

  json(res, 404, { error: 'not_implemented', path: p });
  return true;
}

module.exports = { init, handle };
