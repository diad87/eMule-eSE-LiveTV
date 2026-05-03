'use strict';
const aiAssistant = require('../ai_assistant');
const aiOAuth     = require('../ai_oauth');

let _ctx = {};

function init(ctx) {
  _ctx = ctx;
  aiOAuth.init(ctx.loadSettings, ctx.saveSettings);
}

function handle(url, req, res) {
  // ── AI: Test API key connectivity ──────────────────────────────────────────
  if (url.pathname === '/api/ai/test' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const { provider, apiKey } = JSON.parse(body);
        if (!provider || !apiKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ ok: false, message: 'provider and apiKey are required' }));
        }
        aiAssistant.testConnection(provider, apiKey, (err, result) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        });
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, message: 'Invalid request body' }));
      }
    });
    return true;
  }

  // ── AI: Google OAuth — start flow ─────────────────────────────────────────
  // Returns { authUrl, state }. Frontend opens authUrl in a new tab.
  if (url.pathname === '/api/ai/oauth/start' && req.method === 'GET') {
    try {
      const result = aiOAuth.buildGoogleAuthUrl(_ctx.PORT);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return true;
  }

  // ── AI: Google OAuth — callback (browser redirect target) ─────────────────
  if (url.pathname === aiOAuth.REDIRECT_PATH) {
    aiOAuth.handleCallback(url, res, _ctx.PORT);
    return true;
  }

  // ── AI: Google OAuth — poll for result (frontend short-polls this) ─────────
  if (url.pathname === '/api/ai/oauth/status' && req.method === 'GET') {
    const state = url.searchParams.get('state') || '';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(aiOAuth.pollStatus(state)));
    return true;
  }

  // ── AI: Google OAuth — disconnect / revoke ─────────────────────────────────
  if (url.pathname === '/api/ai/oauth/disconnect' && req.method === 'POST') {
    aiOAuth.revokeGoogle((err, result) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result || { ok: true }));
    });
    return true;
  }

  // ── Misc system routes ─────────────────────────────────────────────────────
  if (url.pathname === '/api/cleanup') {
    _ctx.cleanup.cleanupAll();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ cleaned: true }));
    return true;
  }

  if (url.pathname === '/api/tunnel/start') {
    _ctx.tunnel.startTunnel(res);
    return true;
  }

  if (url.pathname === '/api/tunnel/status') {
    const t = _ctx.tunnel;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ url: t.tunnelUrl, publicUrl: t.publicUrl, active: t.active, lookupUrl: t.LOOKUP_URL }));
    return true;
  }

  if (url.pathname === '/api/tunnel/stop') {
    _ctx.tunnel.stopTunnel();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ stopped: true }));
    return true;
  }

  return false;
}

module.exports = { init, handle };
