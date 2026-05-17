/**
 * eSE Live — Live TV Page (viewer-only)
 * Renders /live with 3-state UI: disconnected, empty, active channels.
 * 
 * REMOVED to /live/debug (Phase 2+3):
 *   - P2P Mesh Stats panel
 *   - Trust bar + legend
 *   - Emergency banner
 *   - Share ed2k:// button
 *   - Kad Discovery streams grid
 */
'use strict';

const directory = require('./live_tv_directory');
const channelSearch = require('./channel_search');
const navbar = require('../shared/navbar');

/**
 * Render the Live TV HTML page.
 * @param {Object} status - Pipeline status
 * @param {Object} meta - Stream metadata {title, category, language}
 * @returns {string} Full HTML page.
 */
function render(status, meta) {
  const channels = channelSearch.search({});
  const channelCount = channels.length;

  const liveCSS = `
.main{max-width:1200px;margin:0 auto;padding:80px 40px 40px}

/* Header */
.live-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;flex-wrap:wrap;gap:12px}
.live-title{font-size:28px;font-weight:800;color:#fff;display:flex;align-items:center;gap:12px}
.live-status{display:flex;align-items:center;gap:8px;font-size:13px;color:#888}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.status-dot.connected{background:#2ecc71;box-shadow:0 0 8px rgba(46,204,113,.5)}
.status-dot.disconnected{background:#e74c3c}
.status-dot.checking{background:#f39c12;animation:pulse 1.5s infinite}

/* Empty state */
.live-empty{text-align:center;padding:100px 20px 80px}
.live-empty-icon{font-size:64px;opacity:.3;margin-bottom:24px}
.live-empty h2{font-size:22px;color:#888;margin-bottom:8px;font-weight:600}
.live-empty p{color:#555;font-size:14px;max-width:400px;margin:0 auto}
.live-empty-spinner{display:flex;align-items:center;justify-content:center;gap:10px;margin-top:24px;color:#555;font-size:13px}
.spinner{width:16px;height:16px;border:2px solid rgba(255,255,255,.1);border-top-color:#ff6b35;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.live-empty-cta{display:inline-block;margin-top:32px;padding:14px 32px;background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;border-radius:10px;font-weight:700;text-decoration:none;transition:all .2s;font-size:14px}
.live-empty-cta:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(255,107,53,.3)}

/* Network footer */
.live-net-footer{max-width:1200px;margin:40px auto 0;padding:16px 40px;border-top:1px solid rgba(255,255,255,.06);display:flex;gap:16px;font-size:12px;color:#555;flex-wrap:wrap;align-items:center}
.live-net-footer a{color:#ff6b35;text-decoration:none;font-weight:600;margin-left:auto}
.live-net-footer a:hover{text-decoration:underline}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

${directory.getCSS()}
`;

  let html = navbar.getHead('Live TV \u2014 eSE', liveCSS);
  html += navbar.getHTML('live');
  html += '<div class="main">';

  // Header
  html += `
<div class="live-header">
  <h1 class="live-title">Live TV</h1>
  <div class="live-status">
    <span class="status-dot checking" id="status-dot"></span>
    <span id="status-text">Comprobando conexi\u00f3n...</span>
  </div>
</div>`;

  // Sprint 3 I.2 \u2014 Update banner (hidden until check finds a newer release)
  html += `
<div id="update-banner" style="display:none;margin:0 0 16px;padding:10px 16px;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.35);border-radius:10px;font-size:13px;color:#86efac">
  <span id="update-text" style="margin-right:12px"></span>
  <a id="update-link" href="#" target="_blank" style="color:#10b981;font-weight:700;text-decoration:underline">Descargar</a>
</div>`;

  // Pre-flight check panel (Phase 5.1 \u2014 surfaces blockers before broadcasting)
  html += `
<div id="preflight-panel" style="margin:0 0 16px;padding:12px 16px;background:rgba(20,30,50,.5);border:1px solid #1f2937;border-radius:10px">
  <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:12px">
    <div style="font-weight:700;color:#9ca3af;min-width:100px">\ud83d\udd0d Pre-flight</div>
    <div id="pf-kad" style="color:#888">\u23f3 Kad...</div>
    <div id="pf-id"  style="color:#888">\u23f3 HighID...</div>
    <div id="pf-up"  style="color:#888">\u23f3 Subida...</div>
    <div id="pf-ff"  style="color:#888">\u23f3 FFmpeg...</div>
    <div id="pf-ip"  style="margin-left:auto;color:#666;font-family:monospace;font-size:11px"></div>
  </div>
</div>`;

  // Mini-monitor (Phase 5.2 \u2014 only visible while broadcasting/viewing)
  html += `
<div id="live-monitor" style="display:none;margin:0 0 16px;padding:12px 16px;background:rgba(46,204,113,.05);border:1px solid rgba(46,204,113,.25);border-radius:10px">
  <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;font-size:12px">
    <div style="font-weight:700;color:#2ecc71;min-width:100px">\ud83d\udcca En vivo</div>
    <div>Modo: <b id="mon-mode">\u2014</b></div>
    <div>Buffer: <b id="mon-buf">\u2014</b></div>
    <div>Viewers: <b id="mon-viewers">\u2014</b></div>
    <div>Servidos: <b id="mon-served">\u2014</b></div>
    <div>Recibidos: <b id="mon-recv">\u2014</b></div>
    <div>Faltan: <b id="mon-missing">\u2014</b></div>
    <div>Mesh: <b id="mon-mesh">\u2014</b></div>
  </div>
</div>`;

  // Hole-punch test panel (diagnostic \u2014 verify LowID-LowID uTP traversal)
  html += `
<div id="hp-test-panel" style="margin:0 0 16px;padding:12px 16px;background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.25);border-radius:10px">
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <div style="font-weight:700;color:#f59e0b;min-width:180px;font-size:13px">\ud83c\udfaf Hole-punch test</div>
    <input id="hp-target-ip" type="text" placeholder="IP (ej. 88.11.22.161)" style="flex:1;min-width:140px;padding:8px 12px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:6px;color:#ddd;font-size:12px;font-family:monospace">
    <input id="hp-target-port" type="text" placeholder="UDP port (4672)" style="width:130px;padding:8px 12px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:6px;color:#ddd;font-size:12px;font-family:monospace">
    <button id="hp-test-btn" style="padding:8px 18px;background:#f59e0b;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px">Disparar</button>
  </div>
  <div id="hp-test-result" style="margin-top:8px;font-size:11px;color:#888;font-family:monospace"></div>
</div>`;

  // Cloudflare Tunnel panel \u2014 OPT-IN with TOS warning (avoids Cloudflare ban risk)
  html += `
<details id="cf-tunnel-panel" style="margin:0 0 16px;padding:12px 16px;background:rgba(220,38,38,.04);border:1px solid rgba(220,38,38,.25);border-radius:10px">
  <summary style="cursor:pointer;display:flex;align-items:center;gap:10px;font-weight:700;color:#f87171;font-size:13px">
    \u26a0\ufe0f T\u00fanel HTTPS de emergencia (avanzado, leer antes)
  </summary>
  <div style="margin-top:14px;padding:12px;background:rgba(220,38,38,.08);border-left:3px solid #ef4444;border-radius:4px;font-size:12px;color:#fca5a5;line-height:1.5">
    <b>\u26a0\ufe0f Advertencia importante:</b> El t\u00fanel Cloudflare expone tu servidor local
    a internet via HTTPS. Es \u00fatil cuando tu router bloquea TODO el P2P, pero:
    <ul style="margin:6px 0 6px 18px;padding:0">
      <li>El AUP de Cloudflare proh\u00edbe t\u00faneles para P2P file sharing</li>
      <li>Uso sostenido o reportes pueden cancelar tu URL/IP sin aviso</li>
      <li>Cloudflare ve metadatos de toda la conexi\u00f3n</li>
      <li>Solo usar para contenido propio/legal (demos, tus archivos, testing)</li>
      <li>NO usar para distribuci\u00f3n masiva ni contenido con copyright</li>
    </ul>
    Para LowID-LowID normal usa el hole-punch P2P (panel naranja arriba) que
    es 100% descentralizado y sin riesgos de ban.
  </div>
  <div style="margin-top:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <label style="font-size:12px;color:#cbd5e1;display:flex;align-items:center;gap:6px;cursor:pointer">
      <input type="checkbox" id="cf-ack-tos">
      He le\u00eddo los riesgos y acepto la responsabilidad
    </label>
    <div id="cf-tunnel-status" style="flex:1;min-width:200px;font-size:12px;color:#9ca3af">Apagado</div>
    <button id="cf-tunnel-toggle" disabled style="padding:8px 18px;background:#374151;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:not-allowed;font-size:12px;opacity:.5">Activar</button>
  </div>
  <div id="cf-tunnel-url" style="display:none;margin-top:10px;padding:8px 12px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:6px;font-family:monospace;font-size:12px;color:#a5b4fc;word-break:break-all"></div>
</details>`;

  // Direct Join panel (Phase 1 \u2014 paste an ed2k://|live|... link to bypass Kad)
  html += `
<div id="direct-join-panel" style="margin:0 0 24px;padding:14px 18px;background:rgba(255,107,53,.06);border:1px solid rgba(255,107,53,.25);border-radius:10px">
  <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
    <div style="font-size:13px;color:#ff9b66;font-weight:700;min-width:180px">\u26a1 Conectar directo por link</div>
    <input id="direct-join-link" type="text" placeholder="ed2k://|live|HEXKEY|IP:PUERTO|TITULO|/" style="flex:1;min-width:280px;padding:8px 12px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:6px;color:#ddd;font-size:12px;font-family:monospace">
    <button id="direct-join-btn" style="padding:8px 18px;background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px">Conectar</button>
  </div>
  <div id="direct-join-msg" style="margin-top:8px;font-size:11px;color:#888"></div>
</div>`;

  // Content: empty state or channel grid
  if (channelCount === 0) {
    // Render filters AND an (initially empty) channel-list anyway so that when
    // streams appear via background Kad discovery we can populate the grid
    // in-place without needing the user to reload the page.
    html += `
<div class="live-empty" id="live-empty">
  <div class="live-empty-icon">
    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/>
      <circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/>
      <path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/>
    </svg>
  </div>
  <h2>No hay emisiones en directo</h2>
  <p>Escaneando la red P2P en busca de streams activos...</p>
  <div class="live-empty-spinner">
    <div class="spinner"></div>
    <span id="last-scan">Buscando...</span>
  </div>
  <a href="/explore" class="live-empty-cta">Explorar cat\u00e1logo \u2192</a>
</div>
<div id="filters-host" style="display:none">${directory.renderFilters()}</div>
<div id="channel-list" style="display:none"></div>`;
  } else {
    html += `
<div class="live-empty" id="live-empty" style="display:none">
  <div class="live-empty-icon">
    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/>
      <circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/>
      <path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/>
    </svg>
  </div>
  <h2>No hay emisiones en directo</h2>
  <p>Escaneando la red P2P en busca de streams activos...</p>
  <div class="live-empty-spinner">
    <div class="spinner"></div>
    <span id="last-scan">Buscando...</span>
  </div>
</div>`;
    html += directory.renderFilters();
    html += '<div id="channel-list">';
    html += directory.renderGrid(channels, {});
    html += '</div>';
  }

  html += '</div>'; // .main

  // Network footer (discrete)
  html += `
<div class="live-net-footer" id="net-footer">
  <span>Red: <b id="net-state">\u2014</b></span>
  <span>\u00b7</span>
  <span>Nodos: <b id="node-count">\u2014</b></span>
  <span>\u00b7</span>
  <span>Actualizado: <b id="last-refresh">\u2014</b></span>
  <a href="/live/debug">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:4px">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
    </svg>
    Debug
  </a>
  <a href="/debug" style="margin-left:14px">📜 Logs</a>
  <a href="/privacy" style="margin-left:14px">🔒 Privacidad</a>
</div>`;

  // Inline JS: polling
  html += `
<script src="/live/player.js?v=\${Date.now()}"></script>
<script>
// Connection status polling
function checkConnection(){
  fetch('/api/live/connection-status').then(r=>r.json()).then(d=>{
    var dot=document.getElementById('status-dot');
    var text=document.getElementById('status-text');
    var net=document.getElementById('net-state');
    var nodes=document.getElementById('node-count');
    if(d.connected){
      dot.className='status-dot connected';
      text.textContent='Conectado a la red';
      if(net)net.textContent='Online';
    }else{
      dot.className='status-dot disconnected';
      text.textContent='eMule no detectado';
      if(net)net.textContent='Offline';
    }
    if(nodes)nodes.textContent=d.nodeCount||'\\u2014';
  }).catch(()=>{
    var dot=document.getElementById('status-dot');
    if(dot)dot.className='status-dot disconnected';
  });
}

// Channel refresh polling
function refreshChannels(){
  fetch('/api/live/channels').then(r=>r.json()).then(d=>{
    var grid=document.getElementById('channel-list');
    var empty=document.getElementById('live-empty');
    var filters=document.getElementById('filters-host');
    var lr=document.getElementById('last-refresh');
    if(lr)lr.textContent='ahora';
    if(!d.channels||d.channels.length===0){
      if(grid)grid.style.display='none';
      if(filters)filters.style.display='none';
      if(empty)empty.style.display='';
      return;
    }
    // Channels available: hide empty state, reveal filters + grid and
    // populate the grid via filterChannels() so the user sees streams
    // appear live as background discovery surfaces them.
    if(empty)empty.style.display='none';
    if(filters)filters.style.display='';
    if(grid){
      grid.style.display='';
      if(typeof filterChannels==='function')filterChannels();
    }
  }).catch(()=>{});
}

// Pre-flight + live monitor pollers (Phase 5 / Tier 1.4-1.5)
function paintCheck(elId, state, label, hint) {
  // state: 'ok' | 'fail' | 'checking'
  var el = document.getElementById(elId);
  if (!el) return;
  var icon = state === 'ok' ? '✅' : (state === 'checking' ? '⏳' : '❌');
  var color = state === 'ok' ? '#2ecc71' : (state === 'checking' ? '#f39c12' : '#e74c3c');
  el.textContent = icon + ' ' + label + (hint ? ' (' + hint + ')' : '');
  el.style.color = color;
}
function refreshPreflight() {
  fetch('/api/live/preflight').then(function(r){return r.json();}).then(function(d){
    paintCheck('pf-kad', d.kad_connected ? 'ok' : 'fail', 'Kad');
    // Tier 1.5: while UDP firewall test still running, show "checking" not "fail"
    var idState = d.high_id ? 'ok' : (d.firewall_checking ? 'checking' : 'fail');
    var idLabel = d.high_id ? 'HighID'
                : d.firewall_checking ? 'Comprobando NAT...'
                : 'LowID/firewalled';
    paintCheck('pf-id', idState, idLabel);
    // max_upload_kbs == 0xFFFFFFFF (4294967295) is eMule's UNLIMITED sentinel,
    // not a literal 4 GB/s cap. Show it as "ilimitada" instead of the raw uint.
    var isUnlimited = !d.max_upload_kbs || d.max_upload_kbs >= 0xFFFFFFFF;
    var upOK = isUnlimited || d.max_upload_kbs >= 200;
    paintCheck('pf-up', upOK ? 'ok' : 'fail',
      'Subida ' + (isUnlimited ? 'ilimitada' : d.max_upload_kbs + ' KB/s'));
    paintCheck('pf-ff', d.ffmpeg_found ? 'ok' : 'fail', 'FFmpeg');
    var ipEl = document.getElementById('pf-ip');
    if (ipEl) {
      var src = d.public_ip_source === 'ipify' ? ' (via ipify)'
              : d.public_ip_source === 'kad'   ? ''
              : '';
      ipEl.textContent = (d.public_ip ? d.public_ip + ':' + d.port + src : '');
    }
  }).catch(function(){
    paintCheck('pf-kad', 'fail', 'Kad', 'eMule offline');
  });
}
function refreshMonitor() {
  fetch('/api/live/monitor').then(function(r){return r.json();}).then(function(d){
    var box = document.getElementById('live-monitor');
    if (!box) return;
    var active = d.broadcasting || d.viewing;
    box.style.display = active ? '' : 'none';
    if (!active) return;
    var setT = function(id, v){ var e = document.getElementById(id); if (e) e.textContent = v; };
    setT('mon-mode',    d.broadcasting ? 'EMITIENDO' : 'VIENDO');
    setT('mon-buf',     (d.bufCount||0) + ' segs [' + (d.oldestSeq||0) + '..' + (d.newestSeq||0) + ']');
    setT('mon-viewers', d.broadcastPeers||0);
    setT('mon-served',  (d.counters && d.counters.chunksServed)  || d.chunksServed || 0);
    setT('mon-recv',    (d.counters && d.counters.chunksReceived)|| 0);
    setT('mon-missing', (d.counters && d.counters.chunksMissing) || 0);
    setT('mon-mesh',    (d.meshPeers||0) + ' (S:' + (d.superSeeders||0) + ' M:' + (d.middlePeers||0) + ' L:' + (d.leafPeers||0) + ')');
  }).catch(function(){});
}

checkConnection();
refreshPreflight();
refreshMonitor();
refreshChannels();
setInterval(checkConnection, 15000);
setInterval(refreshPreflight, 8000);
setInterval(refreshMonitor, 2000);
// First minute: poll channels every 3s for snappy discovery; then back off to 10s.
var __ese_channelsFastUntil = Date.now() + 60000;
var __ese_channelsPollId = setInterval(function(){
  refreshChannels();
  if (Date.now() > __ese_channelsFastUntil) {
    clearInterval(__ese_channelsPollId);
    setInterval(refreshChannels, 10000);
  }
}, 3000);

// Sprint 3 I.2 — Auto-update check (silent, once per page load)
fetch('/api/eSE/update/check').then(function(r){return r.json();}).then(function(d){
  if (!d || !d.update_available || !d.release_url) return;
  var b = document.getElementById('update-banner');
  var t = document.getElementById('update-text');
  var a = document.getElementById('update-link');
  if (!b || !t || !a) return;
  t.textContent = '🆕 Nueva versión disponible: ' + d.remote_version + ' (tienes ' + d.local_version + ').';
  a.href = d.download_url || d.release_url;
  b.style.display = '';
}).catch(function(){});

// Sprint 2 D.2 — Browser Notifications
// Sends a desktop toast when a new viewer joins (broadcaster) or when a watched
// stream goes live again (viewer). Requires user to grant permission once.
(function(){
  if (typeof Notification === 'undefined') return;  // unsupported browser
  var lastViewers = -1;
  var lastBroadcasting = false;
  var permRequested = false;
  function ensurePerm() {
    if (permRequested) return;
    permRequested = true;
    if (Notification.permission === 'default') {
      // Lazy-request only after the user has interacted with the page.
      var onClick = function(){
        Notification.requestPermission().catch(function(){});
        document.removeEventListener('click', onClick, true);
      };
      document.addEventListener('click', onClick, true);
    }
  }
  function notify(title, body) {
    if (Notification.permission !== 'granted') return;
    try { new Notification(title, { body: body, icon: '/favicon.ico', silent: false }); }
    catch(e) {}
  }
  setInterval(function(){
    ensurePerm();
    fetch('/api/live/monitor').then(function(r){return r.json();}).then(function(d){
      if (!d) return;
      // Broadcaster: new viewer joined
      if (d.broadcasting) {
        var v = d.broadcastPeers || 0;
        if (lastViewers >= 0 && v > lastViewers) {
          notify('🎥 Nuevo viewer conectado', 'Total: ' + v + ' viewer(s)');
        }
        lastViewers = v;
      }
      // Viewer: stream that was off is now broadcasting (e.g. local restart)
      if (!lastBroadcasting && d.broadcasting) {
        notify('🔴 Tu emisión está en directo', 'eSE Live activo');
      }
      lastBroadcasting = !!d.broadcasting;
    }).catch(function(){});
  }, 5000);
})();

// Hole-punch diagnostic panel
(function(){
  var btn = document.getElementById('hp-test-btn');
  var ipIn = document.getElementById('hp-target-ip');
  var portIn = document.getElementById('hp-target-port');
  var out = document.getElementById('hp-test-result');
  if (!btn || !ipIn || !portIn || !out) return;
  // Default the UDP port to eMule's standard
  if (!portIn.value) portIn.value = '4672';
  function setOut(t, ok) {
    out.textContent = t;
    out.style.color = ok ? '#10b981' : '#ef4444';
  }
  btn.addEventListener('click', function(){
    var ip = (ipIn.value || '').trim();
    var port = (portIn.value || '').trim();
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
      setOut('IP no válida.', false); return;
    }
    if (!/^\d+$/.test(port) || parseInt(port,10) === 0) {
      setOut('Puerto UDP no válido.', false); return;
    }
    btn.disabled = true; btn.textContent = '⏳';
    setOut('Enviando HOLEPUNCH_REQ a ' + ip + ':' + port + '...');
    fetch('/api/holepunch/test?ip=' + encodeURIComponent(ip) + '&udp_port=' + encodeURIComponent(port))
      .then(function(r){return r.json();})
      .then(function(d){
        btn.disabled = false; btn.textContent = 'Disparar';
        if (!d.success) {
          setOut('❌ ' + (d.error || 'fallo desconocido'), false);
          return;
        }
        // Schedule a follow-up read in 3 s to see if a success counter went up
        setOut('✅ REQ enviado a ' + ip + ':' + port + '. Counters: attempts=' + (d.counters && d.counters.attempts) + ', success=' + (d.counters && d.counters.success) + ', symNATfail=' + (d.counters && d.counters.sym_nat_fail) + '. Volviendo a leer en 3 s...', true);
        setTimeout(function(){
          fetch('/api/status').then(function(r){return r.json();}).then(function(s){
            var att = parseInt(s.hole_punch_attempts, 10) || 0;
            var suc = parseInt(s.hole_punch_success,  10) || 0;
            var sym = parseInt(s.hole_punch_sym_nat_fail, 10) || 0;
            var prevAtt = (d.counters && d.counters.attempts) || 0;
            var prevSuc = (d.counters && d.counters.success) || 0;
            var deltaSuc = suc - prevSuc;
            if (deltaSuc > 0) {
              setOut('🎉 ÉXITO: ACK recibido del peer remoto. Hole-punch funciona entre vosotros. Counters: attempts=' + att + ', success=' + suc + ' (+' + deltaSuc + '), symNATfail=' + sym, true);
            } else if (sym > (d.counters && d.counters.sym_nat_fail || 0)) {
              setOut('⚠️ NAT simétrico detectado. Tu router asigna puerto distinto en cada conexión saliente. Necesitarás Cloudflare Tunnel como fallback. Counters: attempts=' + att + ', symNATfail=' + sym, false);
            } else {
              setOut('⏳ Sin respuesta aún. Posibles causas: el peer remoto no está corriendo eMule, su Kad no tiene Hole-Punch enabled, o su firewall bloquea UDP entrante. Counters: attempts=' + att + ', success=' + suc + ', symNATfail=' + sym, false);
            }
          });
        }, 3000);
      })
      .catch(function(){
        btn.disabled = false; btn.textContent = 'Disparar';
        setOut('❌ Error de red contactando con eSE.', false);
      });
  });
})();

// Tier 3.1 — Cloudflare Tunnel (OPT-IN, requires TOS acknowledgement)
(function(){
  var btn = document.getElementById('cf-tunnel-toggle');
  var stat = document.getElementById('cf-tunnel-status');
  var urlBox = document.getElementById('cf-tunnel-url');
  var ackBox = document.getElementById('cf-ack-tos');
  if (!btn || !stat || !urlBox || !ackBox) return;

  // Button disabled until user checks the TOS acknowledgement
  ackBox.addEventListener('change', function(){
    btn.disabled = !ackBox.checked;
    btn.style.cursor = ackBox.checked ? 'pointer' : 'not-allowed';
    btn.style.opacity = ackBox.checked ? '1' : '.5';
    btn.style.background = ackBox.checked ? '#4f46e5' : '#374151';
  });

  var watchHandle = null;
  function paintStatus(d) {
    if (!d || d.status === 'idle' || d.status === 'stopped') {
      btn.textContent = 'Activar';
      btn.disabled = false;
      btn.style.background = '#4f46e5';
      stat.textContent = 'Apagado — actívalo si tu router bloquea P2P';
      stat.style.color = '#9ca3af';
      urlBox.style.display = 'none';
    } else if (d.status === 'starting') {
      btn.textContent = '⏳ Arrancando...';
      btn.disabled = true;
      stat.textContent = 'Conectando con Cloudflare...';
      stat.style.color = '#f59e0b';
      urlBox.style.display = 'none';
    } else if (d.status === 'running' && d.url) {
      btn.textContent = 'Apagar';
      btn.disabled = false;
      btn.style.background = '#dc2626';
      stat.textContent = '✅ Activo — comparte la URL de abajo con cualquiera';
      stat.style.color = '#10b981';
      urlBox.style.display = '';
      // Live HLS link viewers can paste in any browser
      urlBox.innerHTML = '<div style="margin-bottom:6px;color:#9ca3af;font-size:11px">URL pública (válida solo mientras esté activo):</div>' +
        '<a href="' + d.url + '/live/watch/local" target="_blank" style="color:#a5b4fc;text-decoration:underline">' +
        d.url + '/live/watch/local</a>';
    } else if (d.status === 'error') {
      btn.textContent = 'Reintentar';
      btn.disabled = false;
      btn.style.background = '#dc2626';
      stat.textContent = '❌ Error: ' + (d.error || 'desconocido');
      stat.style.color = '#ef4444';
      urlBox.style.display = 'none';
    }
  }
  function poll() {
    fetch('/api/live/tunnel/status').then(function(r){return r.json();}).then(paintStatus).catch(function(){});
  }
  btn.addEventListener('click', function(){
    var stopping = btn.textContent === 'Apagar';
    btn.disabled = true;
    // Pass ack_tos=true so the C++ endpoint knows the user has consented
    var url = stopping ? '/api/live/tunnel/stop' : '/api/live/tunnel/start?ack_tos=true';
    fetch(url).then(function(r){return r.json();}).then(function(){
      poll();
      if (!stopping) {
        // Poll every 1.5 s during startup until URL appears or it errors
        if (watchHandle) clearInterval(watchHandle);
        watchHandle = setInterval(function(){
          fetch('/api/live/tunnel/status').then(function(r){return r.json();}).then(function(d){
            paintStatus(d);
            if (d.status === 'running' || d.status === 'error' || d.status === 'idle') {
              clearInterval(watchHandle); watchHandle = null;
            }
          });
        }, 1500);
      }
    }).catch(function(){
      btn.disabled = false;
      stat.textContent = 'Error de red contactando con eSE.';
      stat.style.color = '#ef4444';
    });
  });
  // Initial state + slow refresh
  poll();
  setInterval(poll, 10000);
})();

// ═══════════════════════════════════════════════════════════════════
// Tier 2.1 — First-run wizard + 2.3 actionable error messages
// ═══════════════════════════════════════════════════════════════════
(function(){
  // Inject the wizard modal once on first run.
  fetch('/api/live/first_run').then(function(r){return r.json();}).then(function(d){
    if (!d.first_run) return;

    var modal = document.createElement('div');
    modal.id = 'ese-wizard';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)';
    // IMPORTANT: this single-quoted string is embedded in the outer template
    // literal that builds the inline script. The outer template converts a
    // backslash-n escape into a real newline; a real newline inside a
    // single-quoted browser-side string is a SyntaxError. So every newline
    // escape here is doubled: the outer template emits a literal
    // backslash-n (2 chars), which the browser then interprets as a valid
    // newline escape inside the single-quoted string.
    modal.innerHTML = '\\n<div style="background:#13141a;border:1px solid #1f2937;border-radius:14px;max-width:580px;width:90%;padding:32px;color:#ddd;box-shadow:0 20px 60px rgba(0,0,0,.6);max-height:90vh;overflow-y:auto">\\n  <div style="font-size:26px;font-weight:800;color:#fff;margin-bottom:8px">👋 Bienvenido a eSE Live</div>\\n  <div style="color:#9ca3af;font-size:14px;margin-bottom:20px">Vamos a comprobar tu equipo en 30 segundos. No hay que tocar nada manualmente.</div>\\n\\n  <details style="margin-bottom:20px;padding:10px 14px;background:rgba(99,102,241,.06);border-left:3px solid #818cf8;border-radius:4px;font-size:12px;color:#cbd5e1">\\n    <summary style="cursor:pointer;font-weight:600;color:#818cf8">🔒 Privacidad y datos (GDPR) — léelo antes de continuar</summary>\\n    <div style="margin-top:10px;line-height:1.6">\\n      eSE Live es una red P2P. Para que funcione necesita exponer cierta información a otros usuarios:\\n      <ul style="margin:6px 0;padding-left:20px">\\n        <li><b>Tu IP pública</b> es visible para los peers a los que te conectes (igual que en cualquier red P2P).</li>\\n        <li>Si emites, tu IP + puerto se publican en Kad (red descentralizada).</li>\\n        <li>Si activas el túnel HTTPS, Cloudflare ve metadatos de tu conexión.</li>\\n        <li>No recopilamos analítica. No hay servidor central.</li>\\n      </ul>\\n      eMule + eSE Live se ejecutan localmente en tu equipo. Los datos compartidos están bajo tu control directo.\\n    </div>\\n  </details>\\n\\n  <div id="wiz-checks" style="background:#0e0e10;border:1px solid #2a2a2e;border-radius:8px;padding:16px;margin-bottom:20px">\\n    <div id="wiz-c-kad"     style="margin:6px 0;font-size:13px">⏳ Conectando a la red Kad...</div>\\n    <div id="wiz-c-id"      style="margin:6px 0;font-size:13px">⏳ Comprobando NAT/firewall...</div>\\n    <div id="wiz-c-ffmpeg"  style="margin:6px 0;font-size:13px">⏳ Buscando FFmpeg...</div>\\n    <div id="wiz-c-ip"      style="margin:6px 0;font-size:13px">⏳ Detectando IP pública...</div>\\n  </div>\\n\\n  <div id="wiz-tip" style="margin-bottom:18px;padding:10px 14px;background:rgba(243,156,18,.08);border-left:3px solid #f39c12;border-radius:4px;font-size:12px;color:#f39c12;display:none"></div>\\n\\n  <div id="wiz-actions" style="display:flex;gap:10px;justify-content:flex-end;align-items:center">\\n    <a id="wiz-skip" href="#" style="color:#6b7280;font-size:12px;text-decoration:none;margin-right:auto">Saltar wizard</a>\\n    <button id="wiz-test"  disabled style="padding:10px 18px;background:#2ecc71;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:13px;opacity:.5">🎬 Crear emisión de prueba</button>\\n    <button id="wiz-close" style="padding:10px 18px;background:#374151;color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;font-size:13px">Acepto y cerrar</button>\\n  </div>\\n</div>';
    document.body.appendChild(modal);

    function dismiss() {
      fetch('/api/live/first_run/dismiss', {method:'POST'}).catch(function(){});
      modal.remove();
    }
    document.getElementById('wiz-close').addEventListener('click', dismiss);
    document.getElementById('wiz-skip' ).addEventListener('click', function(e){ e.preventDefault(); dismiss(); });

    function setLine(id, ok, text, hint) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = (ok === true ? '✅ ' : ok === false ? '❌ ' : '⏳ ') + text;
      el.style.color = ok === true ? '#2ecc71' : ok === false ? '#e74c3c' : '#9ca3af';
      if (hint) el.title = hint;
    }
    function showTip(text) {
      var t = document.getElementById('wiz-tip');
      if (!t) return;
      t.textContent = text;
      t.style.display = '';
    }

    function poll() {
      fetch('/api/live/preflight').then(function(r){return r.json();}).then(function(d){
        setLine('wiz-c-kad',    !!d.kad_connected, 'Red Kad', 'Necesario para descubrir broadcasters');
        var idOk = d.high_id ? true : (d.firewall_checking ? null : false);
        setLine('wiz-c-id',     idOk,
          idOk === true ? 'Puerto abierto (HighID)' :
          idOk === null ? 'Comprobando NAT...' :
          'Puerto cerrado (LowID)');
        setLine('wiz-c-ffmpeg', !!d.ffmpeg_found, d.ffmpeg_found ? 'FFmpeg disponible' : 'FFmpeg no encontrado');
        setLine('wiz-c-ip',     !!d.public_ip,   d.public_ip ? 'IP pública: ' + d.public_ip : 'IP pública desconocida');

        // Tier 2.3: contextual actionable tips
        var tip = '';
        if (!d.kad_connected) {
          tip = 'Kad aún no conecta. Espera 30 s. Si no arranca, comprueba que el puerto UDP 4672 no esté bloqueado.';
        } else if (d.high_id === false && !d.firewall_checking) {
          tip = '⚠️ Tu router parece bloquear el puerto 4662. Activa UPnP en el router o configura port-forwarding TCP 4662 + UDP 4672. Mientras tanto, podrás ver streams pero no emitir a viewers remotos.';
        } else if (!d.ffmpeg_found) {
          tip = 'FFmpeg no está. Descárgalo en https://www.gyan.dev/ffmpeg/builds/ y copia ffmpeg.exe junto a emule.exe.';
        } else if (!d.public_ip) {
          tip = 'No hemos podido detectar tu IP pública. Sin internet o doble NAT. Intenta reiniciar tu conexión.';
        }
        if (tip) showTip(tip);
        else { var t = document.getElementById('wiz-tip'); if (t) t.style.display = 'none'; }

        // Enable the "Test broadcast" button when ready
        var btn = document.getElementById('wiz-test');
        if (btn && d.kad_connected && d.ffmpeg_found) {
          btn.disabled = false;
          btn.style.opacity = '1';
        }
      }).catch(function(){});
    }
    poll();
    var pollHandle = setInterval(poll, 3000);

    // "Crear emisión de prueba" launches a Test Pattern broadcast and shows the link.
    document.getElementById('wiz-test').addEventListener('click', function(){
      var btn = this;
      btn.disabled = true;
      btn.textContent = '⏳ Iniciando...';
      fetch('/api/live/broadcast/start?source=testpattern&title=eSE+Demo&bitrate=1500')
        .then(function(r){return r.json();})
        .then(function(d){
          clearInterval(pollHandle);
          if (d.success) {
            modal.querySelector('#wiz-checks').style.display = 'none';
            var actions = document.getElementById('wiz-actions');
            if (actions) actions.style.display = 'none';
            var tip = document.getElementById('wiz-tip');
            if (tip) {
              tip.style.display = '';
              tip.style.color = '#2ecc71';
              tip.style.borderLeftColor = '#2ecc71';
              tip.style.background = 'rgba(46,204,113,.06)';
              // 17 May 2026 — share link defaults to anonymous (no IP).
              // The direct variant is hidden behind a <details> for the LAN-only
              // use case where Kad isn't available and viewers need the IP up-front.
              var anonLink = d.link_anonymous || d.link || '(error generando link)';
              var directLink = (d.link_direct && d.link_direct !== anonLink) ? d.link_direct : '';
              tip.innerHTML = '🔒 <b>Emisión activa (modo anónimo).</b> Comparte este link — no contiene tu IP:<br><br>' +
                '<input value="' + anonLink + '" readonly style="width:100%;padding:8px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:4px;color:#fff;font-family:monospace;font-size:11px" onclick="this.select()">' +
                (directLink ?
                  '<details style="margin-top:10px;font-size:11px;color:#9ca3af"><summary style="cursor:pointer">Link directo (incluye tu IP — solo necesario en LAN sin Kad)</summary>' +
                  '<input value="' + directLink + '" readonly style="width:100%;padding:6px;margin-top:6px;background:#0e0e10;border:1px solid #2a2a2e;border-radius:4px;color:#fff;font-family:monospace;font-size:10px" onclick="this.select()"></details>'
                  : '') +
                '<div style="margin-top:14px;display:flex;gap:8px"><button onclick="window.location.href=\\'/player\\'" style="padding:8px 18px;background:#ff6b35;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer">▶ Ver tu propia emisión</button>' +
                '<button onclick="document.getElementById(\\'ese-wizard\\').remove();fetch(\\'/api/live/first_run/dismiss\\',{method:\\'POST\\'})" style="padding:8px 18px;background:#374151;color:#fff;border:none;border-radius:6px;cursor:pointer">Cerrar wizard</button></div>';
            }
          } else {
            btn.disabled = false;
            btn.textContent = '🎬 Crear emisión de prueba';
            showTip('No se pudo iniciar: ' + (d.error || 'comprueba el log de eMule'));
          }
        })
        .catch(function(){
          btn.disabled = false;
          btn.textContent = '🎬 Crear emisión de prueba';
          showTip('Error de red contactando con eMule.');
        });
    });
  }).catch(function(){});
})();

// Direct Join (paste ed2k://|live|HEXKEY|IP:PORT|TITLE|/ link)
(function(){
  var btn = document.getElementById('direct-join-btn');
  var input = document.getElementById('direct-join-link');
  var msg = document.getElementById('direct-join-msg');
  if (!btn || !input) return;
  function setMsg(t, kind){
    if (!msg) return;
    msg.textContent = t;
    msg.style.color = kind === 'ok' ? '#2ecc71' : (kind === 'err' ? '#e74c3c' : '#888');
  }
  btn.addEventListener('click', function(){
    var link = (input.value || '').trim();
    if (!link) { setMsg('Pega aquí un link ed2k://|live|...', 'err'); return; }
    if (link.indexOf('|live|') < 0) { setMsg('Link no válido (debe contener |live|)', 'err'); return; }
    setMsg('Conectando...', '');
    btn.disabled = true;
    fetch('/api/live/direct_join?link=' + encodeURIComponent(link))
      .then(function(r){ return r.json(); })
      .then(function(d){
        btn.disabled = false;
        if (d && d.success) {
          // hint comes from the C++ backend and tells direct vs kad-search.
          var dest = (d.ip && d.port) ? (d.ip + ':' + d.port) : 'Kad';
          setMsg((d.hint || ('Conectado a ' + dest)) + ' — abriendo player...', 'ok');
          setTimeout(function(){ window.location.href = '/player'; }, 1500);
        } else {
          setMsg('Backend rechazó: ' + (d && (d.hint || d.error) ? (d.hint || d.error) : 'link inválido o eMule offline'), 'err');
        }
      })
      .catch(function(){
        btn.disabled = false;
        setMsg('Error de red — ¿está eMule arrancado?', 'err');
      });
  });
  input.addEventListener('keydown', function(e){
    if (e.key === 'Enter') btn.click();
  });
})();

// D6 — Update-available toast. Polls /api/live/update_status every 60 s
// and shows a non-blocking toast in the bottom-right corner when a newer
// release is published on GitHub. Click "Update now" -> POSTs to
// /api/live/update_run, which spawns tools/update_check.ps1 with its own
// GUI confirmation prompt.
(function(){
  var shown = false;
  function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];});}
  function show(d) {
    if (shown) return;
    shown = true;
    var t = document.createElement('div');
    t.id = 'ese-update-toast';
    t.style.cssText = 'position:fixed;bottom:18px;right:18px;z-index:9998;background:#13141a;border:1px solid #818cf8;border-radius:10px;padding:14px 18px;color:#ddd;box-shadow:0 8px 30px rgba(99,102,241,.25);max-width:340px;font-size:13px;font-family:system-ui,sans-serif';
    t.innerHTML =
      '<div style="font-weight:700;color:#a5b4fc;margin-bottom:6px">🆕 Nueva versión disponible</div>' +
      '<div style="color:#9ca3af;font-size:12px;margin-bottom:10px">' + esc(d.latest_tag || d.latest_sha || 'unknown') + '</div>' +
      '<div style="display:flex;gap:6px">' +
      '<button id="upd-now" style="padding:6px 12px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer;font-size:12px">Actualizar ahora</button>' +
      '<button id="upd-skip" style="padding:6px 12px;background:transparent;color:#6b7280;border:none;cursor:pointer;font-size:12px">Más tarde</button></div>';
    document.body.appendChild(t);
    document.getElementById('upd-now').onclick = function(){
      fetch('/api/live/update_run', {method:'POST'}).catch(function(){});
      t.remove();
    };
    document.getElementById('upd-skip').onclick = function(){ t.remove(); };
  }
  function poll() {
    fetch('/api/live/update_status').then(function(r){return r.json();}).then(function(d){
      if (d && d.has_update) show(d);
    }).catch(function(){});
  }
  setTimeout(poll, 5000);
  setInterval(poll, 60000);
})();
</script>
</body></html>`;

  return html;
}

module.exports = { render };
