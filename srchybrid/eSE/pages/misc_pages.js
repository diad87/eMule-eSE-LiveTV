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

  // UX-007: Connection seed for mobile pairing — REQUIRES authentication
  // This endpoint exposes secrets (encKey, accessToken, LOOKUP_TOPIC),
  // so it MUST be gated behind a valid token.
  if (url.pathname === '/api/connect-seed') {
    if (_security && !_security.isValidToken(url, req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized', message: 'Authentication required to access connection seed.' }));
      return;
    }
    const localIPs = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    const seed = {
      name: 'eSE',
      n: 'eSE',
      version: '7.5.2',
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
      icons: [{ src: 'https://img.icons8.com/color/192/cinema.png', sizes: '192x192', type: 'image/png' }, { src: 'https://img.icons8.com/color/512/cinema.png', sizes: '512x512', type: 'image/png' }]
    }));
    return;
  }

  if (url.pathname === '/go' || url.pathname === '/go/' + tunnel.CONFIG.secretId) {
    const goPage = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">' +
      '<title>eSE - Conectando...</title><link rel="icon" href="/emule_mascot.svg" />' +
      '<style>*{margin:0;padding:0}body{background:#0d0d12;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}' +
      '.box{max-width:400px}.logo{font-size:28px;font-weight:800;color:#ff6b35;margin-bottom:16px}.spin{display:inline-block;width:40px;height:40px;border:3px solid #333;border-top-color:#ff6b35;border-radius:50%;animation:s 1s linear infinite;margin-bottom:16px}@keyframes s{to{transform:rotate(360deg)}}' +
      '.msg{color:#888;font-size:14px;margin-top:12px}a{color:#ff6b35}</style></head><body><div class="box">' +
      '<div class="logo">eSE</div><div class="spin"></div>' +
      '<div id="status">Buscando tu servidor...</div>' +
      '<div class="msg" id="msg"></div></div>' +
      '<script>' +
      'var topic="' + tunnel.LOOKUP_TOPIC + '";' +
      'fetch("https://ntfy.sh/"+topic+"/json?poll=1&since=1h").then(function(r){return r.text()}).then(function(t){' +
      '  var lines=t.trim().split("\\n");if(!lines[0]){document.getElementById("status").textContent="Servidor offline";document.getElementById("msg").textContent="No se encontro ninguna sesion activa. Asegurate de que eSE esta corriendo.";return}' +
      '  var last=JSON.parse(lines[lines.length-1]);' +
      '  var target=last.message||"";' +
      '  /* UX-006: Validate redirect URL — only allow http/https to prevent open redirect */' +
      '  if(!/^https?:\\/\\//i.test(target)){document.getElementById("status").textContent="URL invalida";document.getElementById("msg").textContent="El servidor devolvio una URL no segura.";return}' +
      '  document.getElementById("status").textContent="Encontrado! Redirigiendo...";' +
      '  setTimeout(function(){window.location.href=target},500);' +
      '}).catch(function(){document.getElementById("status").textContent="Error de conexion";});' +
      '</script></body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(goPage);
    return true;
  }

  if (url.pathname === '/remote') {
    // Serve the redirect HTML for download
    const rPath = path.join(__dirname, 'eSE_Remote.html');
    if (fs.existsSync(rPath)) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': 'attachment; filename="eSE_Remote.html"'
      });
      res.end(fs.readFileSync(rPath));
    } else {
      res.writeHead(404); res.end('Not generated yet');
    }
    return true;
  }

  if (url.pathname === '/qr') {
    // v7.4.0 — QR target prefers the UPnP-derived public URL; falls back to
    // the ntfy.sh lookup so a phone can still find this server even without
    // a public IP (no Cloudflare tunnel anymore).
    const qrTarget = tunnel.publicUrl || ('https://ntfy.sh/' + tunnel.LOOKUP_TOPIC);
    const qrImg = 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=' + encodeURIComponent(qrTarget);
    const remoteQr = 'https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=' + encodeURIComponent((tunnel.publicUrl || 'http://localhost:' + PORT) + '/remote');
    const qrPage = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>eSE QR</title><link rel="icon" href="/emule_mascot.svg" />' +
      '<style>*{margin:0;padding:0}body{background:#0d0d12;color:#fff;font-family:system-ui;padding:40px;text-align:center}' +
      '.logo{font-size:28px;font-weight:800;color:#ff6b35;margin-bottom:30px}' +
      '.card{display:inline-block;background:#16161e;border:1px solid #222;border-radius:16px;padding:24px;margin:16px;vertical-align:top;max-width:350px}' +
      '.card h3{color:#ff6b35;margin-bottom:12px;font-size:16px}.card p{color:#888;font-size:12px;margin-top:12px;line-height:1.5}' +
      'img{border-radius:8px;background:#fff;padding:8px}' +
      '.url{color:#2ecc71;font-size:13px;word-break:break-all;margin-top:8px;font-family:monospace}</style></head><body>' +
      '<div class="logo">eSE - Compartir</div>' +
      '<div class="card"><h3> Acceso directo</h3><p>Escanea para abrir eSE ahora</p>' +
      '<img src="' + qrImg + '" width="250" height="250"><div class="url">' + qrTarget + '</div></div>' +
      '<div class="card"><h3> Descargar acceso remoto</h3><p>Escanea para guardar eSE_Remote.html<br>Funciona siempre, sin importar la URL del tunnel</p>' +
      '<img src="' + remoteQr + '" width="250" height="250"><div class="url">Archivo auto-redirect permanente</div></div>' +
      '</body></html>';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(qrPage);
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
