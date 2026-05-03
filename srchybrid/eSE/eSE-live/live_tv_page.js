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

  // Content: empty state or channel grid
  if (channelCount === 0) {
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
    var lr=document.getElementById('last-refresh');
    if(lr)lr.textContent='ahora';
    if(!d.channels||d.channels.length===0){
      if(grid)grid.style.display='none';
      if(empty)empty.style.display='';
      return;
    }
    if(empty)empty.style.display='none';
    if(grid){
      grid.style.display='';
      // Re-render via filterChannels if available
      if(typeof filterChannels==='function')filterChannels();
    }
  }).catch(()=>{});
}

checkConnection();
setInterval(checkConnection, 15000);
setInterval(refreshChannels, 10000);
</script>
</body></html>`;

  return html;
}

module.exports = { render };
