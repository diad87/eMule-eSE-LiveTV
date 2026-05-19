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
    // v8.0.1: lookupUrl removed (ntfy.sh dropped). The only public URL we
    // surface is whatever UPnP gave us. tunnelUrl stays null permanently.
    const t = _ctx.tunnel;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ url: null, publicUrl: t.publicUrl, active: t.active, lookupUrl: null }));
    return true;
  }

  // v8.0.1 — /api/system/network: surface the network overlays this machine
  // can reach over without going through a third-party tunnel. Tailscale
  // assigns addresses in 100.64.0.0/10 (CGNAT range); if the user has it
  // installed and signed in, those addresses appear on a local interface.
  // This is the cleanest way to do "P2P access outside my LAN, free, no
  // domains" — see project memory feedback_gratis_no_barato.md.
  if (url.pathname === '/api/system/network') {
    const os = require('os');
    const all = Object.values(os.networkInterfaces()).flat().filter(i => !i.internal);
    const cgnat100 = all.filter(i => i.family === 'IPv4' && /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(i.address));
    const v4 = all.filter(i => i.family === 'IPv4').map(i => i.address);
    const v6 = all.filter(i => i.family === 'IPv6' && !i.scopeid).map(i => i.address);
    const t = _ctx.tunnel;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      lan_v4: v4,
      lan_v6: v6,
      tailscale: {
        active: cgnat100.length > 0,
        ips: cgnat100.map(i => i.address),
        // Note: detection is heuristic. Any tool that assigns a 100.64/10
        // address (Tailscale, Headscale, ZeroTier with custom range) trips it.
        note: cgnat100.length ? 'IPv4 in 100.64.0.0/10 detected on a local interface — likely Tailscale or compatible overlay.' : null
      },
      upnp: {
        active: !!t.publicUrl,
        publicUrl: t.publicUrl || null
      }
    }));
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
