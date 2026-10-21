'use strict';
const crypto = require('crypto');
const navbar = require('../shared/navbar');

const connectCSS = `
.connect-main{max-width:1120px;margin:0 auto;padding:40px var(--ese-page-padding,40px) 56px}
.connect-eyebrow{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#ff9a85;margin-bottom:10px}
.connect-title{font-size:clamp(30px,3.2vw,44px);font-weight:800;letter-spacing:-1.2px;line-height:1.12;color:#fff}
.connect-subtitle{color:#aaaab8;font-size:15px;line-height:1.7;max-width:580px;margin-top:14px}
.connect-card{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.1fr);gap:40px;align-items:center;margin-top:32px;padding:36px;border:1px solid rgba(255,255,255,.11);border-radius:22px;background:radial-gradient(ellipse at 0 0,rgba(255,107,80,.07),transparent 65%),#121218}
.connect-code{text-align:center;min-width:0}
#qr{background:#fff;padding:16px;border-radius:16px;display:inline-block;max-width:100%;line-height:0}
#qr img{display:block;width:250px;height:auto;max-width:100%;aspect-ratio:1}
.code-label{margin-top:24px;color:#aaaab8;font-size:12px}
.code-display{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:clamp(23px,3vw,32px);font-weight:700;letter-spacing:4px;color:#ff9a85;margin:6px 0 10px;overflow-wrap:anywhere}
.timer{color:#c6c6d0;font-size:13px;font-variant-numeric:tabular-nums}
.connect-guide h2{font-size:22px;line-height:1.3;letter-spacing:-.5px;margin-bottom:22px;color:#f4f4f7}
.connect-steps{list-style:none;display:grid;gap:22px}
.connect-step{display:flex;gap:14px;align-items:flex-start}
.step-num{background:rgba(255,128,107,.12);border:1px solid rgba(255,128,107,.22);color:#ff9a85;width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0}
.step-text{color:#b8b8c6;font-size:14px;line-height:1.65;padding-top:3px}
.step-text strong{color:#f1f1f6;font-weight:600}
.connect-note{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:14px 16px;margin-top:28px;font-size:13px;color:#aaaab8;line-height:1.7}
.connect-actions{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:24px}
.connect-refresh,.connect-back{min-height:44px;display:inline-flex;align-items:center;justify-content:center;text-decoration:none;font-size:13px;font-weight:600;border-radius:9px}
.connect-refresh{padding:12px 18px;background:#f5f5f8;color:#101015}
.connect-refresh:hover{background:#fff}
.connect-back{color:#c1c1cd;padding:10px 0}
.connect-back:hover{color:#ff9a85}
.connect-expired{max-width:620px;margin:48px auto;padding:32px;border:1px solid rgba(255,255,255,.11);border-radius:20px;background:#121218}
@media(max-width:760px){.connect-main{padding-top:28px}.connect-card{grid-template-columns:1fr;gap:32px;padding:24px 20px;margin-top:26px}.connect-guide{border-top:1px solid rgba(255,255,255,.09);padding-top:28px}.connect-title{letter-spacing:-.7px}.connect-expired{margin:16px auto;padding:24px}}
`;

const pairingCodes = new Map();
const security = require('../security');
const bind = require('../dashboard_bind');
const os = require('os');

let _ctx = null;
function init(ctx) { _ctx = ctx; }
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function page(res, status, title, content) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  res.end(navbar.getHead(title + ' — eSE', connectCSS + '.connect-link{width:100%;padding:14px;background:#09090f;border:1px solid #666;border-radius:8px;color:#eee;font:13px ui-monospace,monospace;min-height:48px}.connect-code button{margin-top:16px;border:0;cursor:pointer;font:inherit}.connect-card p{line-height:1.7}') + navbar.getHTML('connect') +
    '<main class="connect-main" id="main-content"><p class="connect-eyebrow">eSE en tus dispositivos</p><h1 class="connect-title">' + escapeHTML(title) + '</h1>' + content + '</main></body></html>');
}
function connectionOrigin() {
  const host = bind.normalizeBindHost(_ctx.bindHost);
  if (bind.isLoopbackBindHost(host)) return null;
  const interfaces = Object.values(os.networkInterfaces()).flat().filter(i => i && !i.internal && (i.family === 'IPv4' || i.family === 4));
  const address = host === '0.0.0.0' || host === '::' ? (interfaces[0] && interfaces[0].address) : host;
  if (!address) return null;
  return 'http://' + (address.includes(':') ? '[' + address + ']' : address) + ':' + _ctx.PORT;
}
function handle(url, req, res) {
  if (url.pathname !== '/connect' && !url.pathname.startsWith('/pair/')) return false;
  if (req.method && req.method !== 'GET') {
    res.writeHead(405, { Allow: 'GET', 'Cache-Control': 'no-store' }); res.end(); return true;
  }
  const { PORT, tunnel } = _ctx;
  if (url.pathname === '/connect') {
    // Only the owner at the PC can issue credentials. In particular a remote
    // visitor cannot request their own pairing code and bypass API auth.
    if (!security.isLocalRequest(req) || security.isCrossSiteBrowserRequest(req)) {
      page(res, 403, 'Vincula desde el PC de eSE', '<p class="connect-subtitle">Abre Conectar dispositivo en el PC donde se ejecuta eSE. Desde allí podrás generar un enlace temporal para este dispositivo.</p><div class="connect-actions"><a class="connect-back" href="/">Ir al inicio &rarr;</a><a class="connect-back" href="/app">Abrir acceso guardado &rarr;</a></div>');
      return true;
    }
    const origin = connectionOrigin();
    if (!origin) {
      page(res, 200, 'Conectar dispositivo', '<section class="connect-expired"><h2>Disponible sólo en este PC</h2><p class="connect-subtitle">eSE acepta conexiones locales. El móvil todavía no puede acceder a esta dirección.</p><p class="connect-note">Para usar otro dispositivo, configura primero el acceso de eSE a tu red local o red privada. Cuando esté habilitado, aquí aparecerá un enlace temporal de vinculación. Un enlace a localhost abriría el propio móvil.</p><div class="connect-actions"><a class="connect-back" href="/">Volver a eSE &rarr;</a></div></section>');
      return true;
    }
    if (!tunnel.CONFIG || !/^[A-Za-z0-9_-]{16,512}$/.test(tunnel.CONFIG.accessToken || '')) {
      page(res, 503, 'Acceso no disponible', '<p class="connect-subtitle">No hay un acceso remoto configurado. Revisa la configuración en el PC de eSE antes de vincular otro dispositivo.</p>');
      return true;
    }
    const now = Date.now();
    for (const [key, entry] of pairingCodes) if (now >= entry.expires) pairingCodes.delete(key);
    const code = crypto.randomBytes(16).toString('hex').toUpperCase();
    pairingCodes.set(code, { expires: now + 600000 });
    const pairUrl = origin + '/pair/' + code;
    page(res, 200, 'Conectar dispositivo', `
<p class="connect-subtitle">Abre este enlace temporal en el dispositivo que quieras vincular.</p>
<section class="connect-card" aria-label="Vincular un dispositivo"><div class="connect-code">
<label class="code-label" for="pair-link">Enlace privado de vinculación</label>
<input class="connect-link" id="pair-link" readonly value="${escapeHTML(pairUrl)}">
<button class="connect-refresh" type="button" id="copy-pair">Copiar enlace</button>
<p class="timer" id="timer" aria-live="off">Expira en 10:00</p><p id="copy-status" role="status"></p>
</div><div class="connect-guide"><h2>Tu biblioteca, en otra pantalla</h2>
<ol class="connect-steps"><li class="connect-step"><span class="step-num" aria-hidden="true">1</span><div class="step-text"><strong>Conecta ambos dispositivos a la misma red</strong><br>También puedes usar la red privada que hayas configurado.</div></li>
<li class="connect-step"><span class="step-num" aria-hidden="true">2</span><div class="step-text"><strong>Abre el enlace en el otro dispositivo</strong><br>El enlace da acceso a tu eSE. Compártelo sólo con ese dispositivo.</div></li>
<li class="connect-step"><span class="step-num" aria-hidden="true">3</span><div class="step-text"><strong>Guarda el acceso</strong><br>Añade eSE a tus favoritos o a la pantalla de inicio.</div></li></ol>
<p class="connect-note">El enlace se puede usar una vez y caduca en 10 minutos.</p>
<div class="connect-actions"><a class="connect-refresh" href="/connect">Generar otro enlace</a><a class="connect-back" href="/">Volver a eSE &rarr;</a></div></div></section>
<script>
var expiry = ${now + 600000};
var timer = setInterval(function() {
  var left = Math.max(0, expiry - Date.now());
  document.getElementById('timer').textContent = left ? 'Expira en ' + Math.floor(left / 60000) + ':' + String(Math.floor(left / 1000) % 60).padStart(2, '0') : 'Enlace expirado. Genera otro para continuar.';
  if (!left) { clearInterval(timer); document.getElementById('copy-pair').disabled = true; }
}, 1000);
document.getElementById('copy-pair').addEventListener('click', function() {
  var input = document.getElementById('pair-link');
  var status = document.getElementById('copy-status');
  function selectLink() { input.focus(); input.select(); status.textContent = 'Enlace seleccionado. Cópialo con el menú del navegador.'; }
  if (!navigator.clipboard || !navigator.clipboard.writeText) { selectLink(); return; }
  navigator.clipboard.writeText(input.value).then(function() { status.textContent = 'Enlace copiado'; }, selectLink);
});
</script>`);
    return true;
  }
  const match = /^\/pair\/([A-F0-9]{32})$/.exec(url.pathname);
  const code = match && match[1];
  const entry = code && pairingCodes.get(code);
  if (!entry || Date.now() >= entry.expires) {
    if (code) pairingCodes.delete(code);
    page(res, 410, 'Enlace expirado', '<p class="connect-subtitle">Este enlace ya se ha usado o ha caducado. Genera otro desde Conectar dispositivo en el PC de eSE.</p><div class="connect-actions"><a class="connect-back" href="/app">Abrir acceso guardado &rarr;</a><a class="connect-back" href="/">Volver al inicio &rarr;</a></div>');
    return true;
  }
  pairingCodes.delete(code);
  const seed = { n: 'eSE', p: PORT, a: tunnel.CONFIG.accessToken };
  const seedB64 = Buffer.from(JSON.stringify(seed)).toString('base64');
  // A relative redirect retains the reachable LAN/overlay origin used by the phone.
  res.writeHead(302, { Location: '/app?seed=' + encodeURIComponent(seedB64), 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  res.end();
  return true;
}

module.exports = { init, handle };
