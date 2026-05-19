'use strict';
const fs   = require('fs');
const path = require('path');
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
      version: '7.5.2',
      uptime: Math.round(process.uptime()),
      encoder: HW_ENCODER,
      hasPublicUrl: !!(tunnel.publicUrl),
      hasTunnel: !!(tunnel.tunnelUrl)
    }));
    return;
  }

  // UX-007: Connection seed for mobile pairing — REQUIRES authentication.
  // The seed lets a phone on the same LAN find this server and authenticate.
  // v8.0.1: removed `secret`/`s` (ntfy.sh LOOKUP_TOPIC, gone) and `tunnel`/`t`
  // (third-party tunnel URL, gone). Pairing is LAN-only now; for cross-NAT
  // access set up Tailscale (100.64/10) or a Tor onion service manually.
  if (url.pathname === '/api/connect-seed') {
    if (_security && !_security.isValidToken(url, req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized', message: 'Authentication required to access connection seed.' }));
      return;
    }
    const ifaces = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal);
    const localIPs = ifaces.map(i => i.address);
    // Surface Tailscale 100.64/10 separately so the UI can prefer it for
    // cross-network pairing without leaking that the user has it installed.
    const tailscaleIPs = ifaces
      .filter(i => /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(i.address))
      .map(i => i.address);
    const seed = {
      name: 'eSE',
      n: 'eSE',
      version: '8.0.1',
      port: PORT,
      p: PORT,
      localIPs: localIPs,
      l: localIPs,
      tailscaleIPs: tailscaleIPs,
      publicIP: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      e: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      k: tunnel.CONFIG.encKey,
      a: tunnel.CONFIG.accessToken,
      ts: Date.now()
    };
    // Remove wildcard CORS — only allow same-origin for security-sensitive data
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(seed));
    return;
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
      icons: [{ src: '/emule_mascot.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any maskable' }]
    }));
    return;
  }

  // v8.0.1 — /go, /go/<secretId>, /remote, /qr removed.
  // Previous behaviour relied on ntfy.sh (server lookup) and api.qrserver.com
  // (QR image generator). Both are third-party services that contradict the
  // "100% gratis, sin dominios" project invariant. Pairing is LAN-only now.
  if (url.pathname === '/go'
      || (tunnel.CONFIG && url.pathname === '/go/' + tunnel.CONFIG.secretId)
      || url.pathname === '/remote'
      || url.pathname === '/qr') {
    const ifaces = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    const lanList = ifaces.length
      ? ifaces.map(ip => '<li><code>http://' + ip + ':' + PORT + '/</code></li>').join('')
      : '<li><em>No se encontró ninguna IP de LAN.</em></li>';
    const pubLine = tunnel.publicUrl
      ? '<p>Acceso público (mismo PC tras UPnP): <code>' + tunnel.publicUrl + '</code></p>'
      : '<p>UPnP no abrió ningún puerto. Para acceso fuera de tu red: Tailscale o Tor onion service.</p>';
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">' +
      '<title>eSE - Acceso</title><link rel="icon" href="/emule_mascot.svg" />' +
      '<style>*{margin:0;padding:0}body{background:#0d0d12;color:#fff;font-family:system-ui;padding:40px;line-height:1.6}' +
      '.box{max-width:600px;margin:0 auto}h1{color:#ff6b35;margin-bottom:16px}' +
      'code{background:#16161e;padding:2px 6px;border-radius:4px;color:#2ecc71;font-family:monospace}' +
      'ul{margin:12px 0 12px 24px}p{margin-bottom:12px;color:#ccc}' +
      '.note{background:#16161e;border-left:3px solid #ff6b35;padding:12px;margin-top:16px;color:#aaa;font-size:13px}' +
      '</style></head><body><div class="box">' +
      '<h1>eSE</h1>' +
      '<p>El acceso remoto basado en ntfy.sh fue eliminado en v8.0.1 (terceros / TOS risk).</p>' +
      '<p>Abre eSE desde la LAN usando una de estas URLs:</p><ul>' + lanList + '</ul>' +
      pubLine +
      '<div class="note">Para uso desde fuera de tu red, instala <a href="https://tailscale.com/" style="color:#ff6b35">Tailscale</a> (gratis, P2P) o expón eSE como Tor onion service. eSE no depende de ningún servicio de terceros para funcionar.</div>' +
      '</div></body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
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
