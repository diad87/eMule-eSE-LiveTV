'use strict';
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const runtimeDir = require('./runtime_dir');

// Puerto del servidor — se configura con init()
let PORT = 8080;

/** Configura el puerto. Llamar antes de setupUPnP. */
function init(port) { PORT = port; }

// ─── Config / secrets ────────────────────────────────────────────────────────
// Writable runtime files MUST live outside the pkg snapshot (which is read-only).
// See runtime_dir.js: returns %APPDATA%\eSE in pkg mode, __dirname in dev.
const CONFIG_PATH = runtimeDir.join('config.json');

function loadConfig() {
  // Try-read instead of existsSync→read so we don't expose a TOCTOU window
  // where the file could disappear (or be swapped) between the two syscalls
  // (CodeQL js/file-system-race #47-48).
  let cfg = null;
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch (e) { /* missing / unreadable / not JSON */ }
  if (cfg) {
    let changed = false;
    if (!cfg.encKey)       { cfg.encKey       = crypto.randomBytes(32).toString('hex'); changed = true; }
    if (!cfg.accessToken)  { cfg.accessToken  = crypto.randomBytes(16).toString('hex'); changed = true; }
    if (changed) {
      try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2)); } catch (e) {}
    }
    return cfg;
  }
  // Primera ejecución: generar todos los secretos
  const config = {
    secretId:    crypto.randomBytes(8).toString('hex'),
    encKey:      crypto.randomBytes(32).toString('hex'),
    accessToken: crypto.randomBytes(16).toString('hex'),
    createdAt:   new Date().toISOString()
  };
  try { fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2)); } catch (e) {}
  console.log('[config] Generated new secrets');
  return config;
}

const CONFIG       = loadConfig();
const LOOKUP_TOPIC = 'ese-' + CONFIG.secretId;
const LOOKUP_URL   = 'https://ntfy.sh/' + LOOKUP_TOPIC;

// ─── Redirect HTML (se genera una sola vez) ───────────────────────────────────

const redirectHtml = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>eSE</title><link rel="icon" href="data:image/svg+xml;base64,PHN2ZyBjbGFzcz0iZW11bGUtbG9nbyIgd2lkdGg9IjI4IiBoZWlnaHQ9IjI4IiB2aWV3Qm94PSIwIDAgMTAwIDEwMCIgZmlsbD0ibm9uZSIgc3R5bGU9Im1hcmdpbi1yaWdodDoxMHB4O3ZlcnRpY2FsLWFsaWduOm1pZGRsZTsiPjxjaXJjbGUgY3g9IjUwIiBjeT0iNTAiIHI9IjQ4IiBmaWxsPSJ1cmwoI2dyYWQpIiBzdHJva2U9IiNmZjZiMzUiIHN0cm9rZS13aWR0aD0iMiIvPjxwYXRoIGQ9Ik03MCAzNWMtNS01LTE1LTUtMjAgMC01LTUtMTUtNS0yMCAwLTMgMy0zIDEwIDAgMTUgNSA1IDIwIDE1IDIwIDE1czE1LTEwIDIwLTE1YzMtNSAzLTEyIDAtMTV6IiBmaWxsPSIjZmZmIi8+PGNpcmNsZSBjeD0iNDIiIGN5PSI0MiIgcj0iMyIgZmlsbD0iIzAwMCIvPjxjaXJjbGUgY3g9IjU4IiBjeT0iNDIiIHI9IjMiIGZpbGw9IiMwMDAiLz48cGF0aCBkPSJNNDUgNTVxNSA1IDEwIDAiIHN0cm9rZT0iI2ZmMmQ3OCIgc3Ryb2tlLXdpZHRoPSIzIiBmaWxsPSJub25lIiBzdHJva2UtbGluZWNhcD0icm91bmQiLz48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9ImdyYWQiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPjxzdG9wIG9mZnNldD0iMCUiIHN0b3AtY29sb3I9IiNmZjZiMzUiLz48c3RvcCBvZmZzZXQ9IjUwJSIgc3RvcC1jb2xvcj0iI2ZmMmQ3OCIvPjxzdG9wIG9mZnNldD0iMTAwJSIgc3RvcC1jb2xvcj0iI2M4NDBlOSIvPjwvbGluZWFyR3JhZGllbnQ+PC9kZWZzPjwvc3ZnPg==" />
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0d0d12;color:#fff;font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.box{max-width:400px;padding:20px}.logo{font-size:32px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:20px}
.spin{display:inline-block;width:44px;height:44px;border:3px solid #222;border-top-color:#ff6b35;border-radius:50%;animation:s .8s linear infinite;margin-bottom:16px}@keyframes s{to{transform:rotate(360deg)}}
#status{font-size:16px;margin-bottom:8px}.msg{color:#666;font-size:13px;margin-top:12px;line-height:1.6}a{color:#ff6b35}
.retry{margin-top:16px;background:#ff6b35;border:none;color:#fff;padding:10px 24px;border-radius:8px;font-size:14px;cursor:pointer;display:none}</style></head>
<body><div class="box"><div class="logo">eSE</div><div class="spin" id="spinner"></div>
<div id="status">Buscando tu servidor...</div><div class="msg" id="msg"></div>
<button class="retry" id="retry" onclick="go()">Reintentar</button></div>
<script>
function go(){
document.getElementById("status").textContent="Buscando tu servidor...";
document.getElementById("spinner").style.display="inline-block";
document.getElementById("retry").style.display="none";
fetch("https://ntfy.sh/${LOOKUP_TOPIC}/json?poll=1&since=1h")
.then(function(r){return r.text()})
.then(function(t){
  var lines=t.trim().split("\\n");
  if(!lines[0]||!lines[0].startsWith("{")){
    document.getElementById("status").textContent="Servidor offline";
    document.getElementById("spinner").style.display="none";
    document.getElementById("msg").innerHTML="eSE no esta corriendo ahora.<br>Enciende tu PC e inicia eSE.";
    document.getElementById("retry").style.display="inline-block";
    return;
  }
  var last=JSON.parse(lines[lines.length-1]);
  document.getElementById("status").textContent="Encontrado! Redirigiendo...";
  setTimeout(function(){window.location.href=last.message},500);
}).catch(function(){
  document.getElementById("status").textContent="Error de conexion";
  document.getElementById("spinner").style.display="none";
  document.getElementById("retry").style.display="inline-block";
});
}
go();
</script></body></html>`;

// Generar archivo de acceso remoto si no existe (writable runtime dir).
// Use the 'wx' (write exclusive) flag so the create-if-absent decision is
// atomic in the kernel — eliminates the TOCTOU between existsSync and
// writeFileSync (CodeQL js/file-system-race #49).
(function generateRemoteHtml() {
  const redirectPath = runtimeDir.join('eSE_Remote.html');
  try {
    fs.writeFileSync(redirectPath, redirectHtml, { flag: 'wx' });
    console.log('[config] Generated eSE_Remote.html at ' + redirectPath);
  } catch (e) {
    if (e.code !== 'EEXIST') {
      console.log('[config] Could not write eSE_Remote.html: ' + e.message);
    }
  }
})();

// ─── Cifrado AES-256-CBC ──────────────────────────────────────────────────────

function encryptMsg(text) {
  const key    = Buffer.from(CONFIG.encKey, 'hex');
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc = cipher.update(text, 'utf8', 'base64');
  enc += cipher.final('base64');
  return iv.toString('hex') + ':' + enc;
}

// ─── Estado interno ───────────────────────────────────────────────────────────

// v7.4.0 — Cloudflare Quick Tunnel removed. We rely on UPnP for public
// reachability or LAN for trusted networks; users wanting cross-NAT access
// over a third-party overlay are expected to set up Tailscale or Tor
// manually (see README).
let upnpClient    = null;
let publicUrl     = null;

// ─── Publicación de URL (ntfy.sh + Telegram) ─────────────────────────────────

function publishUrl(url, isHeartbeat) {
  const urlInfo = { tunnel: null, p2p: publicUrl || null, ts: Date.now() };
  try { fs.writeFileSync(runtimeDir.join('current_url.txt'), JSON.stringify(urlInfo)); } catch (e) {}

  const encryptedPayload = encryptMsg(JSON.stringify(urlInfo));
  const postData = JSON.stringify({ topic: LOOKUP_TOPIC, title: 'eSE', message: encryptedPayload, tags: ['lock'] });

  const req = https.request(
    { hostname: 'ntfy.sh', path: '/', method: 'POST', headers: { 'Content-Type': 'application/json' } },
    (res) => {
      if (res.statusCode === 200) {
        if (!isHeartbeat) {
          console.log('[ntfy] URL published!');
          console.log('');
          console.log('   ACCESO REMOTO (bookmark esto):');
          console.log('  ' + LOOKUP_URL);
          console.log('');
        }
      } else {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => console.log('[ntfy] Error: ' + res.statusCode + ' ' + body));
      }
    }
  );
  // CodeQL js/log-injection #61 — e.message comes from network/DNS, strip CR/LF.
  req.on('error', (e) => console.log('[ntfy] Failed: ' + String(e && e.message).replace(/[\r\n\t]+/g, ' ')));
  req.write(postData);
  req.end();

  // Telegram (solo en publicación inicial, no en heartbeats)
  if (!isHeartbeat) {
    const cfgPath = runtimeDir.join('telegram.json');
    if (fs.existsSync(cfgPath)) {
      try {
        const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
        if (cfg.token && cfg.chatId) {
          const msg = ' eSE activo!\n\n' + (url || 'Sin URL') + '\n\nAbre en cualquier navegador.';
          const td  = JSON.stringify({ chat_id: cfg.chatId, text: msg });
          const tr  = https.request(
            { hostname: 'api.telegram.org', path: '/bot' + cfg.token + '/sendMessage', method: 'POST', headers: { 'Content-Type': 'application/json' } },
            () => {}
          );
          tr.on('error', () => {});
          tr.write(td);
          tr.end();
        }
      } catch (e) {}
    }
  }
}

// Heartbeat: re-publicar URLs cada 5 minutos
setInterval(() => {
  if (publicUrl) publishUrl(publicUrl, true);
}, 5 * 60 * 1000);

// ─── UPnP ────────────────────────────────────────────────────────────────────

function getPublicIP() {
  return new Promise((resolve) => {
    const services = ['https://api.ipify.org', 'https://icanhazip.com', 'https://ifconfig.me/ip'];
    let tried = 0;
    for (const svc of services) {
      https.get(svc, { timeout: 5000 }, (res) => {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => {
          const ip = data.trim();
          if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) resolve(ip);
          else { tried++; if (tried >= services.length) resolve(null); }
        });
      }).on('error', () => { tried++; if (tried >= services.length) resolve(null); });
    }
  });
}

async function setupUPnP() {
  try {
    const natupnp = require('nat-upnp-2');
    upnpClient = natupnp.createClient();
    await new Promise((resolve, reject) => {
      upnpClient.portMapping({ public: PORT, private: PORT, ttl: 0, description: 'eSE Streaming' },
        (err) => err ? reject(err) : resolve());
    });
    console.log('[UPnP] Port ' + PORT + ' mapped on router');
    const ip = await getPublicIP();
    if (ip) {
      publicUrl = 'http://' + ip + ':' + PORT;
      console.log('');
      console.log('  ==========================================');
      console.log('  PUBLIC URL (P2P): ' + publicUrl);
      console.log('  ==========================================');
      console.log('  No third parties. Direct connection.');
      console.log('');
    } else {
      console.log('[UPnP] Port mapped but could not detect public IP');
    }
  } catch (e) {
    console.log('[UPnP] Failed: ' + e.message);
    console.log('[UPnP] No public URL available. Use LAN (http://localhost:' + PORT + '),');
    console.log('[UPnP] Tailscale, or a Tor onion service set up manually.');
  }
}

function removeUPnP() {
  if (upnpClient) {
    try { upnpClient.portUnmapping({ public: PORT }); console.log('[UPnP] Port ' + PORT + ' unmapped'); } catch (e) {}
    upnpClient = null;
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  init,
  CONFIG,
  LOOKUP_TOPIC,
  LOOKUP_URL,
  encryptMsg,
  publishUrl,
  setupUPnP,
  removeUPnP,
  get tunnelUrl()  { return null; },   // legacy stub — no third-party tunnel anymore
  get publicUrl()  { return publicUrl; },
  get active()     { return !!publicUrl; },
};
