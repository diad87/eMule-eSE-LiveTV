'use strict';

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function handle(url, req, res) {
  // PWA Mobile App
  if (url.pathname === '/app') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0d0d12">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="manifest" href="/manifest.json">
<title>eSE</title><link rel="icon" href="/emule_mascot.svg" />
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0d0d12;color:#fff;font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;text-align:center}
.box{max-width:400px;width:100%}.logo{font-size:36px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78,#c840e9);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:24px}
.spin{display:inline-block;width:48px;height:48px;border:3px solid #222;border-top-color:#ff6b35;border-radius:50%;animation:s .8s linear infinite;margin-bottom:16px}@keyframes s{to{transform:rotate(360deg)}}
#status{font-size:17px;margin-bottom:8px;font-weight:500}#detail{color:#666;font-size:13px;line-height:1.6;min-height:40px;margin-bottom:16px}
.step{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;margin:4px 0;font-size:13px;text-align:left;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);transition:all .3s}
.step .icon{font-size:18px;min-width:24px;text-align:center}.step .label{flex:1;color:#aaa}
.step.ok{border-color:rgba(46,204,113,.3);background:rgba(46,204,113,.06)}.step.ok .label{color:#2ecc71}
.step.fail{border-color:rgba(231,76,60,.2)}.step.fail .label{color:#555}
.step.try{border-color:rgba(255,107,53,.3);background:rgba(255,107,53,.06)}.step.try .label{color:#ff6b35}
.retry{margin-top:20px;background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 28px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;display:none}
.saved{background:rgba(46,204,113,.08);border:1px solid rgba(46,204,113,.2);border-radius:8px;padding:10px;margin:12px 0;font-size:12px;color:#2ecc71}
.install-box{margin-top:20px;border-top:1px solid #222;padding-top:16px}
.install-btn{background:linear-gradient(135deg,#2ecc71,#27ae60);border:none;color:#fff;padding:14px 28px;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;width:100%;margin-bottom:10px;display:none}
.install-hint{color:#666;font-size:12px;line-height:1.6;display:none}
.install-hint b{color:#ff6b35}</style>
</head><body><div class="box">
<div class="logo">eSE</div>
<div class="spin" id="spinner"></div>
<div id="status">Conectando...</div>
<div id="detail"></div>
<div id="steps"></div>
<div class="saved" id="saved" style="display:none"></div>
<button class="retry" id="retry" onclick="connect()"> Reintentar</button>
<div class="install-box">
<button class="install-btn" id="install-btn" onclick="installPWA()"> Instalar como App</button>
<div class="install-hint" id="install-hint"></div>
</div>
</div>
<script>
// Parse seed from URL or localStorage
var seed = null;
var params = new URLSearchParams(location.search);
if (params.get('seed')) {
  try { seed = JSON.parse(atob(params.get('seed'))); localStorage.setItem('ese_seed', JSON.stringify(seed)); } catch(e) {}
}
if (!seed) {
  try { seed = JSON.parse(localStorage.getItem('ese_seed')); } catch(e) {}
}

function setStep(id, state, text) {
  var el = document.getElementById('step-' + id);
  if (!el) { el = document.createElement('div'); el.id = 'step-' + id; el.className = 'step'; el.innerHTML = '<span class="icon"></span><span class="label"></span>'; document.getElementById('steps').appendChild(el); }
  el.className = 'step ' + state;
  el.querySelector('.icon').textContent = state==='ok'?'':state==='fail'?'':'â³';
  el.querySelector('.label').textContent = text;
}

// AES-256-CBC decrypt using Web Crypto API
function hexToBytes(hex) {
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}
function decryptMsg(encrypted, keyHex) {
  var parts = encrypted.split(':');
  if (parts.length !== 2) return Promise.reject('bad format');
  var iv = hexToBytes(parts[0]);
  var data = Uint8Array.from(atob(parts[1]), function(c) { return c.charCodeAt(0); });
  return crypto.subtle.importKey('raw', hexToBytes(keyHex), { name: 'AES-CBC' }, false, ['decrypt'])
    .then(function(key) { return crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, data); })
    .then(function(buf) { return JSON.parse(new TextDecoder().decode(buf)); });
}

function authToken() {
  return seed && seed.a ? String(seed.a) : '';
}
function addAuthParam(rawUrl) {
  var token = authToken();
  if (!token) return rawUrl;
  return rawUrl + (rawUrl.indexOf('?') === -1 ? '?' : '&') + 'a=' + encodeURIComponent(token);
}
function authFetch(rawUrl, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (authToken()) opts.headers['X-ESE-Token'] = authToken();
  return fetch(addAuthParam(rawUrl), opts);
}
function updateSeedFromServer(ns) {
  if (!ns) return;
  if (ns.publicIP || ns.e) seed.e = ns.publicIP || ns.e;
  if (ns.localIPs || ns.l) seed.l = ns.localIPs || ns.l;
  if (ns.tunnel || ns.t) seed.t = ns.tunnel || ns.t;
  if (ns.a) seed.a = ns.a;
  localStorage.setItem('ese_seed', JSON.stringify(seed));
}
function enterServer(baseUrl) {
  var target = baseUrl.replace(/\/$/, '') + '/';
  window.location.href = addAuthParam(target);
}

function tryUrl(url, timeout) {
  return new Promise(function(resolve) {
    var ctrl = new AbortController();
    var timer = setTimeout(function() { ctrl.abort(); resolve(null); }, timeout || 4000);
    authFetch(url + '/api/status', { signal: ctrl.signal })
      .then(function(r) { clearTimeout(timer); return r.ok ? r.json() : null; })
      .then(function(data) { resolve(data ? url : null); })
      .catch(function() { clearTimeout(timer); resolve(null); });
  });
}

function connect() {
  document.getElementById('spinner').style.display = 'inline-block';
  document.getElementById('retry').style.display = 'none';
  document.getElementById('steps').innerHTML = '';
  
  if (!seed) {
    document.getElementById('status').textContent = 'Sin configuración';
    document.getElementById('detail').textContent = 'Escanea el QR desde eSE para vincular este dispositivo.';
    document.getElementById('spinner').style.display = 'none';
    return;
  }
  
  document.getElementById('status').textContent = 'Buscando servidor...';
  document.getElementById('saved').style.display = 'block';
  document.getElementById('saved').textContent = ' Servidor vinculado: ' + (seed.e || seed.l[0] || '?') + ':' + seed.p;
  
  // v8.0.1: discovery is LAN-only. Removed ntfy.sh fallback that was used
  // when all direct URLs failed; it leaked the encrypted topic to a third
  // party on every reconnect. Tailscale IPs (100.64/10) and the UPnP-
  // derived public IP are tried as part of the normal URL list.
  var urls = [];
  if (seed.l) seed.l.forEach(function(ip) { urls.push({ url: 'http://' + ip + ':' + seed.p, label: 'Red local (' + ip + ')', id: 'local-' + ip.replace(/\./g,'-') }); });
  if (seed.tailscaleIPs) seed.tailscaleIPs.forEach(function(ip) { urls.push({ url: 'http://' + ip + ':' + seed.p, label: 'Tailscale (' + ip + ')', id: 'tailscale-' + ip.replace(/\./g,'-') }); });
  if (seed.e) urls.push({ url: 'http://' + seed.e + ':' + seed.p, label: 'IP publica (' + seed.e + ')', id: 'public' });

  var tryNext = function(idx) {
    if (idx >= urls.length) {
      document.getElementById('status').textContent = 'Servidor no accesible';
      document.getElementById('detail').textContent = 'Comprueba que el PC esta encendido, eSE corriendo, y que estas en la misma red Wi-Fi (o conectado por Tailscale).';
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('retry').style.display = 'inline-block';
      return;
    }
    var u = urls[idx];
    setStep(u.id, 'try', u.label + '...');
    tryUrl(u.url, 5000).then(function(result) {
      if (result) {
        setStep(u.id, 'ok', u.label + ' ');
        document.getElementById('status').textContent = 'Â¡Conectado!';
        // Update seed with latest info from server
        authFetch(result + '/api/connect-seed').then(function(r){return r.json()}).then(updateSeedFromServer).catch(function(){});
        setTimeout(function() { enterServer(result); }, 800);
      } else {
        setStep(u.id, 'fail', u.label + ' ââ¬â sin respuesta');
        tryNext(idx + 1);
      }
    });
  };
  tryNext(0);
}
connect();

// PWA Install
var deferredPrompt = null;
window.addEventListener('beforeinstallprompt', function(e) {
  e.preventDefault();
  deferredPrompt = e;
  document.getElementById('install-btn').style.display = 'block';
});

function installPWA() {
  if (deferredPrompt) {
    deferredPrompt.prompt();
    deferredPrompt.userChoice.then(function(r) {
      if (r.outcome === 'accepted') document.getElementById('install-btn').style.display = 'none';
      deferredPrompt = null;
    });
  }
}

// Show install hint for browsers that don't support beforeinstallprompt (Brave, Safari)
setTimeout(function() {
  if (!deferredPrompt && !window.matchMedia('(display-mode: standalone)').matches) {
    var hint = document.getElementById('install-hint');
    var ua = navigator.userAgent.toLowerCase();
    if (ua.includes('brave') || ua.includes('chrome')) {
      hint.innerHTML = ' Para instalar: toca <b>ââ¹® menú</b> ââ â <b>"Añadir a pantalla de inicio"</b>';
    } else if (ua.includes('safari') || ua.includes('iphone')) {
      hint.innerHTML = ' Para instalar: toca <b> Compartir</b> ââ â <b>"Pantalla de inicio"</b>';
    } else {
      hint.innerHTML = ' Para instalar: abre el menú del navegador ââ â <b>"Añadir a pantalla de inicio"</b>';
    }
    hint.style.display = 'block';
  }
}, 3000);
</script></body></html>`);
    return;
  }

  return false;
}

module.exports = { init, handle };
