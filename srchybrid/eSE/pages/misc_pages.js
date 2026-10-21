'use strict';
const appPage = require('./app_page');
const http = require('http');

let _ctx = null;
let _security = null;
function init(ctx) {
  _ctx = ctx;
  // Security module is loaded lazily to avoid circular dependency
  try { _security = require('../security'); } catch (e) { /* fallback: no auth check */ }
}

function handle(url, req, res) {
  const { PORT, tunnel, HW_ENCODER } = _ctx;

  // CORS for remote ping — UX-003: strip sensitive tunnel URLs from public response
  if (url.pathname === '/api/status') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET'
    });
    res.end(JSON.stringify({
      status: 'ok',
      version: require('../package.json').version,
      uptime: Math.round(process.uptime()),
      encoder: HW_ENCODER,
      hasPublicUrl: !!(tunnel.publicUrl),
      hasTunnel: !!(tunnel.tunnelUrl)
    }));
    return true;
  }

  // UX-007: Connection seed for mobile pairing — REQUIRES authentication
  // This endpoint exposes secrets (encKey, accessToken, LOOKUP_TOPIC),
  // so it MUST be gated behind a valid token.
  if (url.pathname === '/api/connect-seed') {
    if (!_security || !_security.isValidToken(url, req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized', message: 'Authentication required to access connection seed.' }));
      return true;
    }
    const localIPs = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    const seed = {
      name: 'eSE',
      n: 'eSE',
      version: require('../package.json').version,
      port: PORT,
      p: PORT,
      localIPs: localIPs,
      l: localIPs,
      publicIP: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      e: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      tunnel: tunnel.tunnelUrl || null,
      t: tunnel.tunnelUrl || null,
      secret: tunnel.LOOKUP_TOPIC,
      s: tunnel.LOOKUP_TOPIC,
      k: tunnel.CONFIG.encKey,
      a: tunnel.CONFIG.accessToken,
      ts: Date.now()
    };
    // Remove wildcard CORS — only allow same-origin for security-sensitive data
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(seed));
    return true;
  }

  // PWA manifest
  if (url.pathname === '/manifest.json') {
    res.writeHead(200, { 'Content-Type': 'application/manifest+json' });
    res.end(JSON.stringify({
      name: 'eSE',
      short_name: 'eSE',
      description: 'Tu cine P2P',
      start_url: '/app',
      display: 'standalone',
      background_color: '#0d0d12',
      theme_color: '#0d0d12',
      icons: [{ src: '/emule_mascot.svg', sizes: 'any', type: 'image/svg+xml' }]
    }));
    return true;
  }

  // Retain old bookmarks through the single connection flow. Only a validated
  // seed is forwarded; arbitrary destinations and query credentials are dropped.
  if (url.pathname === '/qr' || url.pathname === '/remote' || url.pathname === '/go' || url.pathname === '/go/' + tunnel.CONFIG.secretId) {
    if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD' }); res.end(); return true;
    }
    res.writeHead(302, {
      Location: url.pathname === '/qr' ? '/connect' : appPage.appDestination(url),
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer'
    });
    res.end();
    return true;
  }

  // NAT Traversal Health — proxy to C++ backend (port 4711)
  if (url.pathname === '/api/nat-health') {
    const natProbe = http.get('http://127.0.0.1:4711/api/status', { timeout: 2000 }, (natRes) => {
      let body = '';
      natRes.on('data', (chunk) => { body += chunk; });
      natRes.on('end', () => {
        try {
          const raw = JSON.parse(body);
          const payload = {
            hole_punch_attempts:     raw.hole_punch_attempts     || 0,
            hole_punch_success:      raw.hole_punch_success      || 0,
            hole_punch_sym_nat_fail: raw.hole_punch_sym_nat_fail || 0,
            hole_punch_encrypted:    raw.hole_punch_encrypted    || 0,
            hole_punch_plaintext:    raw.hole_punch_plaintext    || 0,
            kad_connected:           raw.kad_connected           || false,
            kad_configured_mask:     raw.kad_configured_mask     || 0,
            kad_running_mask:        raw.kad_running_mask        || 0,
            kad2_running:            raw.kad2_running            || false,
            kad2_connected:          raw.kad2_connected          || false,
            kad6_running:            raw.kad6_running            || false,
            kad6_connected:          raw.kad6_connected          || false,
            kad6_verified_contacts:  raw.kad6_verified_contacts  || 0,
            upnp_critical_error:     raw.upnp_critical_error     || false,
            upnp_ports_forwarded:    raw.upnp_ports_forwarded    || 'unknown'
          };
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify(payload));
        } catch (_) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end('{"error":"parse_failed"}');
        }
      });
    });
    natProbe.on('error', () => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end('{"error":"backend_unreachable"}');
    });
    return true;
  }

  return false;
}

module.exports = { init, handle };
