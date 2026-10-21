'use strict';
const navbar = require('../shared/navbar');

// Preserve old bookmarks without sending credentials to another origin.
function normalizeSeed(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.a !== 'string' || !/^[A-Za-z0-9_-]{16,512}$/.test(value.a)) return null;
  const seed = { n: typeof value.n === 'string' ? value.n.slice(0, 120) : 'eSE', a: value.a };
  if (Number.isInteger(value.p) && value.p > 0 && value.p <= 65535) seed.p = value.p;
  if (Array.isArray(value.l)) seed.l = value.l.filter(ip => typeof ip === 'string' && /^[a-fA-F0-9.:]{1,64}$/.test(ip)).slice(0, 16);
  for (const key of ['e', 's', 'k']) {
    if (typeof value[key] === 'string' && value[key].length <= 256 && !/[\s<>]/.test(value[key])) seed[key] = value[key];
  }
  if (typeof value.t === 'string' && value.t.length <= 2048) {
    try {
      const target = new URL(value.t);
      if (/^https?:$/.test(target.protocol) && !target.username && !target.password) seed.t = target.origin;
    } catch (_) {}
  }
  return seed;
}
function decodeSeed(encoded) {
  if (typeof encoded !== 'string' || encoded.length > 16384 || !/^[A-Za-z0-9+/_=-]+$/.test(encoded)) return null;
  try { return normalizeSeed(JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'))); }
  catch (_) { return null; }
}
function appDestination(url) {
  const seed = decodeSeed(url.searchParams.get('seed'));
  return '/app' + (seed ? '?seed=' + encodeURIComponent(Buffer.from(JSON.stringify(seed)).toString('base64')) : '');
}

function init() {}
function handle(url, req, res) {
  if (url.pathname !== '/app') return false;
  if (req.method && req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' }); res.end(); return true;
  }
  const seed = decodeSeed(url.searchParams.get('seed'));
  const css = '.connection-main{max-width:700px;margin:0 auto;padding:64px var(--ese-page-padding)}.connection-main h1{font-size:clamp(30px,4vw,44px);letter-spacing:-1px}.connection-card{margin-top:28px;padding:28px;background:#15151d;border:1px solid #ffffff18;border-radius:18px}.connection-card p{color:#b4b4c3;line-height:1.7;margin-top:12px}.connection-actions{display:flex;gap:14px;flex-wrap:wrap;margin-top:24px}.connection-actions a,.connection-actions button{display:inline-flex;align-items:center;min-height:44px;padding:12px 18px;border:1px solid #ffffff24;border-radius:9px;background:#24242f;color:#eee;text-decoration:none;font:inherit;cursor:pointer}.connection-actions .primary{background:#ff875f;border:0;color:#170e0a;font-weight:700}.connection-state{font-size:20px;font-weight:700}.connection-save{font-size:13px}.connection-busy{display:inline-block;width:16px;height:16px;margin-right:8px;border:2px solid #666;border-top-color:#ff875f;border-radius:50%;animation:connection-spin 1s linear infinite}.connection-busy[hidden]{display:none}.connection-actions [hidden]{display:none}@keyframes connection-spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.connection-busy{animation:none}}';
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  res.end(navbar.getHead('Abrir eSE', css).replace('</head>', '<link rel="manifest" href="/manifest.json"></head>') + navbar.getHTML('connect') + `
<main class="connection-main" id="main-content"><h1>eSE en este dispositivo</h1>
<section class="connection-card" aria-labelledby="connection-status">
<h2 class="connection-state" id="connection-status" role="status"><span class="connection-busy" id="connection-busy" hidden></span><span id="connection-message">Abre tu biblioteca</span></h2>
<p id="connection-detail">Para vincular este dispositivo, abre Conectar dispositivo en el PC donde se ejecuta eSE y usa su enlace temporal.</p>
<p class="connection-save" id="connection-save"></p>
<div class="connection-actions"><button class="primary" id="connection-retry" type="button" hidden>Reintentar</button><a href="/" id="connection-home">Ir al inicio</a><a href="/connect">Conectar dispositivo</a></div>
</section></main><script>
history.replaceState(null, '', '/app');
${normalizeSeed.toString()}
var incoming = ${JSON.stringify(url.searchParams.has('seed'))};
var seed = ${JSON.stringify(seed).replace(/</g, '\\u003c')};
var saveMessage = document.getElementById('connection-save');
if (!incoming) { try { seed = normalizeSeed(JSON.parse(localStorage.getItem('ese_seed'))); } catch (_) {} }
if (incoming && seed) {
  try { localStorage.setItem('ese_seed', JSON.stringify(seed)); }
  catch (_) { saveMessage.textContent = 'La vinculación funcionará en esta sesión. El navegador no permite guardar el acceso para la próxima vez.'; }
}
var attempt = 0;
function connect() {
  if (!seed) return;
  var ownAttempt = ++attempt;
  var controller = new AbortController();
  var busy = document.getElementById('connection-busy');
  var retry = document.getElementById('connection-retry');
  var message = document.getElementById('connection-message');
  var detail = document.getElementById('connection-detail');
  busy.hidden = false; retry.hidden = true;
  message.textContent = 'Conectando con eSE…'; detail.textContent = 'Comprobando el acceso a tu biblioteca.';
  var timer = setTimeout(function() { controller.abort(); }, 10000);
  fetch('/api/auth/session', { signal: controller.signal, credentials: 'same-origin', headers: { 'X-ESE-Token': seed.a } })
    .then(function(response) {
      if (!response.ok) throw new Error(response.status === 401 ? 'expired' : 'unavailable');
      return response.json();
    }).then(function(result) {
      if (ownAttempt !== attempt) return;
      if (!result || result.ok !== true) throw new Error('unavailable');
      clearTimeout(timer); busy.hidden = true;
      message.textContent = 'Dispositivo conectado';
      window.location.replace('/');
    }).catch(function(error) {
      if (ownAttempt !== attempt) return;
      clearTimeout(timer); busy.hidden = true; retry.hidden = false;
      message.textContent = error.message === 'expired' ? 'Vuelve a vincular este dispositivo' : 'No se ha podido conectar';
      detail.textContent = error.message === 'expired' ? 'El acceso guardado ya no es válido. Genera un enlace nuevo desde el PC de eSE.' : 'Comprueba que eSE sigue abierto y que este dispositivo puede acceder al servidor. Puedes reintentarlo o volver al inicio.';
    });
}
document.getElementById('connection-retry').addEventListener('click', connect);
if (incoming && !seed) {
  document.getElementById('connection-message').textContent = 'Enlace de vinculación no válido';
  document.getElementById('connection-detail').textContent = 'Solicita un enlace nuevo desde Conectar dispositivo en el PC de eSE.';
} else if (seed) connect();
</script></body></html>`);
  return true;
}

module.exports = { init, handle, normalizeSeed, decodeSeed, appDestination };
