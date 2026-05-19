'use strict';
const crypto = require('crypto');

// Short pairing codes that authorize a phone (or another browser) to grab a
// seed for this server. Codes live in memory for 10 min and are single-use.
const pairingCodes = {};

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function handle(url, req, res) {
  const { PORT, tunnel } = _ctx;

  // v8.0.1: the previous /connect page rendered a QR via api.qrserver.com.
  // That leaks the pairing URL (containing the single-use code) to a third
  // party every render. Dropped for the hotfix; pairing is now manual: phone
  // user types the URL or pairing code by hand.
  if (url.pathname === '/connect') {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    pairingCodes[code] = { ts: Date.now(), ttl: 600000 };
    for (const c in pairingCodes) {
      if (Date.now() - pairingCodes[c].ts > pairingCodes[c].ttl) delete pairingCodes[c];
    }

    // Build candidate base URLs (prefer LAN — same network as the phone).
    const ifaces = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    const lanItems = ifaces.length
      ? ifaces.map(ip => '<li><a href="http://' + ip + ':' + PORT + '/pair/' + code + '">http://' + ip + ':' + PORT + '/pair/' + code + '</a></li>').join('')
      : '<li><em>No se encontró ninguna IP de LAN.</em></li>';
    const pubLine = tunnel.publicUrl
      ? '<p>Acceso público (via UPnP): <a href="' + tunnel.publicUrl + '/pair/' + code + '">' + tunnel.publicUrl + '/pair/' + code + '</a></p>'
      : '';

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
      + '<title>Conectar Movil - eSE</title><link rel="icon" href="/emule_mascot.svg" />'
      + '<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0d0d12;color:#fff;font-family:system-ui;padding:32px 20px;line-height:1.6}'
      + '.box{max-width:600px;margin:0 auto}.logo{font-size:32px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}'
      + '.sub{color:#888;font-size:14px;margin-bottom:24px}'
      + '.code-display{font-family:monospace;font-size:36px;font-weight:800;letter-spacing:8px;color:#ff6b35;margin:16px 0;text-align:center;background:#16161e;padding:24px;border-radius:12px}'
      + '.timer{color:#666;font-size:13px;margin-bottom:20px;text-align:center}'
      + 'ul{margin:8px 0 16px 24px}a{color:#2ecc71;font-family:monospace;font-size:13px;word-break:break-all}'
      + '.info{background:#16161e;border:1px solid #222;border-radius:12px;padding:16px;margin-top:16px;font-size:13px;color:#aaa}'
      + '.back{margin-top:24px;color:#666;font-size:13px;text-decoration:none;display:inline-block}.back:hover{color:#ff6b35}'
      + '</style></head><body><div class="box">'
      + '<div class="logo">Conectar Movil</div>'
      + '<div class="sub">Codigo de un solo uso valido 10 minutos. v8.0.1 ya no usa servicios de terceros para generar QRs; escribe la URL en tu telefono o copialo desde otra app.</div>'
      + '<div class="code-display">' + code + '</div>'
      + '<div class="timer" id="timer">Expira en 10:00</div>'
      + '<p>Abre cualquiera de estas URLs en tu telefono (misma red Wi-Fi):</p>'
      + '<ul>' + lanItems + '</ul>'
      + pubLine
      + '<div class="info">Pairing es de un solo uso. Tras conectarse, el codigo se invalida. El telefono guarda el <code>encKey</code> y <code>accessToken</code> localmente; eSE no envia nada fuera de tu red.</div>'
      + '<a class="back" href="/">Volver a eSE</a>'
      + '</div>'
      + '<script>'
      + 'var exp=Date.now()+600000;setInterval(function(){var left=Math.max(0,exp-Date.now());var m=Math.floor(left/60000),s=Math.floor((left%60000)/1000);document.getElementById("timer").textContent=left>0?"Expira en "+m+":"+String(s).padStart(2,"0"):"Codigo expirado - recarga la pagina";},1000);'
      + '</script></body></html>');
    return;
  }

  // Pairing endpoint — phone hits this URL (no QR, manual entry)
  if (url.pathname.startsWith('/pair/')) {
    const code = url.pathname.split('/').pop();
    if (!pairingCodes[code] || Date.now() - pairingCodes[code].ts > pairingCodes[code].ttl) {
      res.writeHead(410, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><body style="background:#0d0d12;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1 style="color:#ff6b35">Codigo expirado</h1><p style="color:#888;margin-top:12px">Genera un nuevo codigo en eSE - Conectar Movil</p></div></body></html>');
      return;
    }
    // Single-use: delete the code so a second visit fails.
    delete pairingCodes[code];
    const localIPs = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    // v8.0.1: removed `t` (tunnelUrl, gone) and `s` (LOOKUP_TOPIC / ntfy, gone).
    // Phone now uses `l` (LAN IPs) or `e` (UPnP-derived public IP) only.
    const seed = {
      n: 'eSE', p: PORT, l: localIPs,
      e: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      k: tunnel.CONFIG.encKey, a: tunnel.CONFIG.accessToken
    };
    const seedB64 = Buffer.from(JSON.stringify(seed)).toString('base64');
    const appUrl = (tunnel.publicUrl || 'http://localhost:' + PORT) + '/app?seed=' + seedB64;
    res.writeHead(302, { 'Location': appUrl });
    res.end();
    console.log('[pair] Device paired successfully via code ' + code);
    return;
  }

  return false;
}

module.exports = { init, handle };
