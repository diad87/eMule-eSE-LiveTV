'use strict';
const aiAssistant = require('../ai_assistant');
const aiOAuth     = require('../ai_oauth');
const utils       = require('../utils');

let _ctx = {};

function init(ctx) {
  _ctx = ctx;
  aiOAuth.init(ctx.loadSettings, ctx.saveSettings);
}

function handle(url, req, res) {
  // ── AI: Test API key connectivity ──────────────────────────────────────────
  if (url.pathname === '/api/ai/test' && req.method === 'POST') {
    utils.readBodyLimited(req, (bodyErr, body) => {
      if (bodyErr) {
        const code = bodyErr.code === 'BODY_TOO_LARGE' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          ok: false,
          message: code === 413 ? 'Request body too large' : 'Invalid request body'
        }));
      }
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
  // v7.5.0 — /api/cleanup deletes server state; require POST so an <img src>
  // / DNS-rebinding hit can't trigger it from a malicious page (CSRF #29).
  if (url.pathname === '/api/cleanup') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'POST' });
      res.end(JSON.stringify({ error: 'method_not_allowed', expected: 'POST' }));
      return true;
    }
    _ctx.cleanup.cleanupAll();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ cleaned: true }));
    return true;
  }

  // v7.4.0 — /api/tunnel/start and /api/tunnel/stop kept as legacy stubs so
  // existing front-ends that still post to them get a clean response instead
  // of a 404. Cloudflare Quick Tunnel is gone; UPnP runs unconditionally
  // at startup. Front-end will be cleaned up to drop these calls in v7.5.
  if (url.pathname === '/api/tunnel/start') {
    res.writeHead(410, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'gone', reason: 'cloudflare-removed', publicUrl: _ctx.tunnel.publicUrl || null }));
    return true;
  }

  if (url.pathname === '/api/tunnel/status') {
    const t = _ctx.tunnel;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ url: null, publicUrl: t.publicUrl, active: t.active, lookupUrl: t.LOOKUP_URL }));
    return true;
  }

  if (url.pathname === '/api/tunnel/stop') {
    res.writeHead(410, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'gone', reason: 'cloudflare-removed' }));
    return true;
  }

  return false;
}

module.exports = { init, handle };
