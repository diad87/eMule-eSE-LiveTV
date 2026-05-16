'use strict';
const crypto = require('crypto');

const pairingCodes = {}; // Temporary QR pairing codes

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function handle(url, req, res) {
  const { PORT, tunnel } = _ctx;

  // QR code pairing page
  if (url.pathname === '/connect') {
    // Generate short pairing code (valid 10 min)
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    pairingCodes[code] = { ts: Date.now(), ttl: 600000 }; // 10 min TTL
    // Clean expired codes
    for (const c in pairingCodes) { if (Date.now() - pairingCodes[c].ts > pairingCodes[c].ttl) delete pairingCodes[c]; }
    
    const baseUrl = tunnel.tunnelUrl || tunnel.publicUrl || ('http://localhost:' + PORT);
    const pairUrl = baseUrl + '/pair/' + code;
    
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Conectar Móvil ââ¬â eSE</title><link rel="icon" href="/emule_mascot.svg" />
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0d0d12;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:20px}
.box{max-width:480px}.logo{font-size:32px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.sub{color:#888;font-size:14px;margin-bottom:32px}
#qr{margin:0 auto 24px;background:#fff;padding:16px;border-radius:16px;display:inline-block;min-width:200px;min-height:200px}
#qr img{display:block;width:250px;height:250px}
.code-display{font-family:monospace;font-size:36px;font-weight:800;letter-spacing:8px;color:#ff6b35;margin:16px 0;text-shadow:0 0 20px rgba(255,107,53,.3)}
.timer{color:#666;font-size:13px;margin-bottom:20px}
.info{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:16px;margin-top:16px;text-align:left;font-size:13px;color:#888;line-height:1.8}
.info strong{color:#ff6b35}
.step{display:flex;gap:12px;align-items:flex-start;margin:8px 0}.step-num{background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0}.step-text{color:#ccc;font-size:14px;padding-top:3px}
.security{display:flex;align-items:center;gap:8px;background:rgba(46,204,113,.06);border:1px solid rgba(46,204,113,.15);border-radius:8px;padding:10px 14px;margin-top:16px;font-size:12px;color:#2ecc71}
.back{margin-top:24px;color:#666;font-size:13px;text-decoration:none;display:inline-block}.back:hover{color:#ff6b35}</style>
</head><body><div class="box">
<div class="logo"> Conectar Móvil</div>
<div class="sub">Escanea el QR o introduce el código en tu dispositivo</div>
<div id="qr"><img src="https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(pairUrl)}&bgcolor=ffffff&color=0d0d12" alt="QR"></div>
<div class="code-display">${code}</div>
<div class="timer" id="timer">Expira en 10:00</div>
<div class="info">
<div class="step"><div class="step-num">1</div><div class="step-text">Escanea el QR con la cámara de tu móvil</div></div>
<div class="step"><div class="step-num">2</div><div class="step-text">Se vinculará automáticamente con tu servidor</div></div>
<div class="step"><div class="step-num">3</div><div class="step-text">Toca <strong>"Añadir a pantalla de inicio"</strong> para instalar como app</div></div>
</div>
<div class="security"> Conexión cifrada AES-256 Â· Código de un solo uso</div>
<a class="back" href="/">ââ  Volver a eSE</a>
</div>
<script>
var exp = Date.now() + 600000;
setInterval(function() {
  var left = Math.max(0, exp - Date.now());
  var m = Math.floor(left/60000), s = Math.floor((left%60000)/1000);
  document.getElementById('timer').textContent = left > 0 ? 'Expira en ' + m + ':' + String(s).padStart(2,'0') : 'Código expirado ââ¬â recarga la página';
}, 1000);
</script></body></html>`);
    return;
  }

  // Pairing endpoint ââ¬â phone visits this from QR
  if (url.pathname.startsWith('/pair/')) {
    const code = url.pathname.split('/').pop();
    if (!pairingCodes[code] || Date.now() - pairingCodes[code].ts > pairingCodes[code].ttl) {
      res.writeHead(410, { 'Content-Type': 'text/html' });
      res.end('<html><body style="background:#0d0d12;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1 style="color:#ff6b35">Código expirado</h1><p style="color:#888;margin-top:12px">Genera un nuevo código en eSE ââ â Conectar Móvil</p></div></body></html>');
      return;
    }
    // Code valid ââ¬â delete it (single use) and send seed
    delete pairingCodes[code];
    const localIPs = Object.values(require('os').networkInterfaces()).flat()
      .filter(i => i.family === 'IPv4' && !i.internal).map(i => i.address);
    const seed = {
      n: 'eSE', p: PORT, l: localIPs,
      e: tunnel.publicUrl ? tunnel.publicUrl.replace('http://', '').split(':')[0] : null,
      t: tunnel.tunnelUrl || null, s: tunnel.LOOKUP_TOPIC,
      k: tunnel.CONFIG.encKey, a: tunnel.CONFIG.accessToken
    };
    const seedB64 = Buffer.from(JSON.stringify(seed)).toString('base64');
    const appUrl = (tunnel.tunnelUrl || tunnel.publicUrl || 'http://localhost:' + PORT) + '/app?seed=' + seedB64;
    res.writeHead(302, { 'Location': appUrl });
    res.end();
    console.log('[pair] Device paired successfully via code ' + code);
    return;
  }

  return false;
}

module.exports = { init, handle };
