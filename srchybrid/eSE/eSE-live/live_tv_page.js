/**
 * eSE Live — Live TV Page (viewer-only)
 * Renders /live as a Twitch/YouTube-style directory: category chips, featured
 * stream and channel grid. Diagnostics live in the footer's advanced section.
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
  const featured = directory.pickFeatured(channels);
  const featuredHtml = featured ? directory.renderFeatured(featured, Math.floor(Date.now() / 20000)) : '';

  const liveCSS = `
.main{max-width:1600px;margin:0 auto;padding:36px var(--ese-page-padding,40px) 48px}

/* Header */
.live-header{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:26px;flex-wrap:wrap;gap:18px}
.live-title{display:flex;align-items:center;gap:14px;font-size:clamp(30px,3vw,42px);font-weight:800;letter-spacing:-1.2px;line-height:1.1;color:#fff}
.live-title-dot{width:12px;height:12px;border-radius:50%;background:#ff3b30;box-shadow:0 0 0 0 #ff3b3099;animation:live-ping 2s infinite}
.live-intro{max-width:620px;margin-top:10px;color:#a9a9b7;font-size:15px;line-height:1.6}
.live-header-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.live-status{display:flex;align-items:center;gap:9px;min-height:44px;font-size:13px;color:#c8c8d2;padding:10px 14px;border:1px solid rgba(255,255,255,.12);border-radius:999px;background:rgba(255,255,255,.035)}
.status-dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.status-dot.connected{background:#2ecc71;box-shadow:0 0 8px rgba(46,204,113,.5)}
.status-dot.disconnected{background:#e74c3c}
.status-dot.checking{background:#f39c12;animation:pulse 1.5s infinite}
.live-link-toggle{display:inline-flex;align-items:center;gap:8px;min-height:44px;padding:10px 18px;border-radius:999px;border:1px solid #ffffff2b;background:#ffffff0d;color:#f4f4f7;font:inherit;font-size:13px;font-weight:700;cursor:pointer}
.live-link-toggle:hover,.live-link-toggle[aria-expanded="true"]{background:#ffffff1a;border-color:#ffffff40}

/* Empty state */
.live-empty{text-align:center;padding:64px 24px;margin-top:8px;background:radial-gradient(ellipse at 50% 0,rgba(255,107,80,.08),transparent 70%);border:1px solid rgba(255,255,255,.08);border-radius:20px}
.live-empty-icon{color:#ff9a85;margin-bottom:20px}
.live-empty h3{font-size:clamp(20px,2vw,25px);color:#f4f4f7;margin-bottom:12px;font-weight:700;letter-spacing:-.4px}
.live-empty p{color:#aaaab8;font-size:15px;line-height:1.7;max-width:460px;margin:0 auto}
.live-empty-actions{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:28px}
.spinner{width:16px;height:16px;border:2px solid rgba(255,255,255,.1);border-top-color:#ff6b35;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.live-empty-cta{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:14px 24px;background:#f5f5f8;color:#101015;border-radius:10px;font-weight:700;text-decoration:none;font-size:14px;border:0;font-family:inherit;cursor:pointer}
.live-empty-cta.secondary{background:transparent;color:#f4f4f7;border:1px solid #ffffff2b}
.live-empty-cta:hover{background:#fff}.live-empty-cta.secondary:hover{background:#ffffff0d}

/* Network footer */
.live-net-footer{max-width:1600px;margin:8px auto 0;padding:20px var(--ese-page-padding,40px) 32px;border-top:1px solid rgba(255,255,255,.09);display:flex;gap:12px;font-size:12px;color:#a4a4b3;flex-wrap:wrap;align-items:flex-start}
.live-net-footer a{color:#ff9a85;text-decoration:none;font-weight:600;display:inline-flex;align-items:center;min-height:40px}
.live-net-footer a:hover{text-decoration:underline}
.live-net-summary{display:flex;gap:12px;flex-wrap:wrap;align-items:center;min-height:44px}
.live-advanced{flex:1 1 100%;order:3}.live-advanced>summary{min-height:44px;display:list-item;align-content:center;color:#c1c1cd;font-weight:600;cursor:pointer;padding:10px 0}
.live-advanced-body{display:grid;gap:12px;padding:6px 0 8px}
.live-advanced-links{display:flex;gap:20px;flex-wrap:wrap}
.live-net-footer .live-privacy{margin-left:auto;min-height:44px}
.live-tools{margin:0;padding:0 18px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.09);border-radius:12px}
.live-tools summary{min-height:48px;padding:14px 0;color:#b7b7c5;cursor:pointer;font-size:13px;font-weight:600}
.live-tools[open] summary{color:#f4f4f7;margin-bottom:4px}
.live-tool-content{padding:0 0 18px}
.live-tools input,.live-tools button,.direct-join-row input,.direct-join-row button{min-height:44px;font:inherit}
.live-tools input::placeholder,.direct-join-row input::placeholder{color:#a3a3b3;opacity:1}
.live-panel-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px}
.live-panel-row input{flex:1;min-width:120px;padding:10px 12px;background:#101017;border:1px solid #42424f;border-radius:8px;color:#eee;font-family:monospace}
.live-panel-row button{padding:10px 18px;background:#f5f5f8;color:#16161c;border:none;border-radius:8px;font-weight:700;cursor:pointer}
#hp-target-port{flex:0 1 150px}
#preflight-panel #pf-ip{overflow-wrap:anywhere}
.direct-join-panel{margin:0 0 28px;padding:22px;background:linear-gradient(110deg,rgba(255,107,80,.08),rgba(255,255,255,.025));border:1px solid rgba(255,145,117,.22);border-radius:16px}
.direct-join-panel[hidden]{display:none}
.direct-join-label{display:block;font-size:15px;color:#f4f4f7;font-weight:700;margin-bottom:6px}
.direct-join-hint{font-size:13px;line-height:1.6;color:#aaaab8;margin-bottom:16px}
.direct-join-row{display:flex;align-items:stretch;gap:12px}
.direct-join-row input{flex:1;min-width:0;padding:12px 14px;background:#101017;border:1px solid #42424f;border-radius:9px;color:#eee;font-family:monospace;font-size:13px}
.direct-join-row button{padding:12px 22px;background:#ff806b;color:#170d0b;border:none;border-radius:9px;font-size:14px;font-weight:800;cursor:pointer}
.direct-join-row button:hover{background:#ff9a85}
.direct-join-row button:disabled{cursor:wait;opacity:.6}
.live-result{margin-top:10px;font-size:13px;color:#aaaab8;line-height:1.6;overflow-wrap:anywhere}
.live-freshness{font-size:12px;line-height:1.6;color:#aaaab8;margin-top:12px}
.live-monitor{margin:0 0 20px;padding:14px 18px;background:rgba(46,204,113,.05);border:1px solid rgba(46,204,113,.25);border-radius:12px}
.live-monitor-label{font-weight:700;color:#8ce1b0;min-width:100px}
.live-monitor-values{display:contents}
.live-monitor.is-stale,.live-tools.is-stale{border-color:rgba(255,190,100,.4);background:rgba(255,190,100,.04)}
.is-stale .live-freshness,.is-stale .live-monitor-label{color:#e7be84}
.live-monitor.is-stale .live-monitor-values{display:none}
.live-directory.only-featured .dir-head,.live-directory.only-featured #channel-list{display:none}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

${directory.getCSS()}
@media(max-width:760px){
  .main{padding-top:24px;padding-bottom:32px}
  .live-header{margin-bottom:20px;gap:14px;align-items:flex-start;flex-direction:column}
  .live-intro{font-size:14px}
  .live-status{font-size:12px}
  .live-tools{padding:0 14px}
  .direct-join-panel{padding:18px}
  .live-empty{padding:40px 18px}
  .live-net-footer{gap:10px;padding-top:16px}
}
@media(max-width:480px){
  .direct-join-row{flex-direction:column}
  .live-panel-row input{flex-basis:100%}
  #hp-target-port{flex:1 1 120px}
  .live-header-actions{width:100%}.live-link-toggle{flex:1;justify-content:center}
}
@media(prefers-reduced-motion:reduce){.spinner,.status-dot.checking,.live-title-dot{animation:none}}
`;

  let html = navbar.getHead('En directo \u2014 eSE', liveCSS);
  html += navbar.getHTML('live');
  html += '<main class="main" id="main-content">';

  // Header
  html += `
<div class="live-header">
  <div><h1 class="live-title"><span class="live-title-dot" aria-hidden="true"></span>En directo</h1><p class="live-intro">Emisiones de la red eSE, de persona a persona y sin servidores. Elige un canal o entra con un enlace.</p></div>
  <div class="live-header-actions">
    <div class="live-status" role="status">
      <span class="status-dot checking" id="status-dot" aria-hidden="true"></span>
      <span id="status-text">Comprobando conexi\u00f3n...</span>
    </div>
    <button type="button" class="live-link-toggle" id="direct-join-toggle" aria-expanded="false" aria-controls="direct-join-panel"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>Pegar enlace</button>
  </div>
</div>`;

  // Sprint 3 I.2 \u2014 Update banner (hidden until check finds a newer release)
  html += `
<div id="update-banner" style="display:none;margin:0 0 16px;padding:10px 16px;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.35);border-radius:10px;font-size:13px;color:#86efac">
  <span id="update-text" style="margin-right:12px"></span>
  <a id="update-link" href="#" target="_blank" style="color:#10b981;font-weight:700;text-decoration:underline">Descargar</a>
</div>`;

  // Direct Join panel (Phase 1 \u2014 paste an ed2k://|live|... link to bypass Kad).
  // Collapsed behind the header button; opens by itself when there are no channels.
  html += `
<div id="direct-join-panel" class="direct-join-panel" hidden>
  <label class="direct-join-label" for="direct-join-link">Entrar con un enlace de emisi&oacute;n</label>
  <p class="direct-join-hint" id="direct-join-hint">Pega el enlace eSE Live que te han compartido para abrir el canal.</p>
  <div class="direct-join-row">
    <input id="direct-join-link" type="text" aria-describedby="direct-join-hint direct-join-msg" placeholder="ed2k://|live|..." autocomplete="off" spellcheck="false">
    <button id="direct-join-btn">Conectar</button>
  </div>
  <div id="direct-join-msg" class="live-result" role="status"></div>
</div>`;

  // Mini-monitor (Phase 5.2 \u2014 only visible while broadcasting/viewing)
  html += `
<div id="live-monitor" class="live-monitor" style="display:none">
  <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;font-size:12px">
    <div class="live-monitor-label" id="mon-label" role="status">En vivo</div>
    <div class="live-monitor-values">
    <div>Modo: <b id="mon-mode">\u2014</b></div>
    <div>Buffer: <b id="mon-buf">\u2014</b></div>
    <div>Viewers: <b id="mon-viewers">\u2014</b></div>
    <div>Servidos: <b id="mon-served">\u2014</b></div>
    <div>Recibidos: <b id="mon-recv">\u2014</b></div>
    <div>Faltan: <b id="mon-missing">\u2014</b></div>
    <div>Mesh: <b id="mon-mesh">\u2014</b></div>
    </div>
  </div>
  <p class="live-freshness" id="mon-freshness">Esperando datos del monitor...</p>
</div>`;

  // Keep controls mounted while channels appear, disappear or fail to load.
  html += `
<section class="live-directory${featured && channelCount === 1 ? ' only-featured' : ''}" id="live-directory" aria-label="Canales en directo">
<div id="filters-host">${directory.renderFilters()}</div>
<div class="dir-feedback">
  <p class="dir-status" id="directory-status" role="status" aria-live="polite" aria-atomic="true" tabindex="-1">${channelCount ? channelCount + (channelCount === 1 ? ' canal en directo' : ' canales en directo') : 'Comprobando canales disponibles…'}</p>
  <button class="dir-retry" type="button" id="directory-retry" onclick="filterChannels()" hidden>Reintentar</button>
</div>
<div class="live-featured" id="live-featured"${featuredHtml ? '' : ' hidden'}>${featuredHtml}</div>
<div class="dir-head"><h2 class="dir-heading" id="live-directory-title">Todos los canales</h2></div>
<div class="live-empty" id="live-empty"${channelCount ? ' style="display:none"' : ''}>
  <div class="live-empty-icon" aria-hidden="true">
    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/>
      <circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/>
      <path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/>
    </svg>
  </div>
  <h3 id="live-empty-title">No hay emisiones en directo</h3>
  <p id="live-empty-text">Los canales aparecer&aacute;n aqu&iacute; cuando haya emisiones disponibles.</p>
  <div class="live-empty-actions"><button type="button" class="live-empty-cta" onclick="openDirectJoin()">Pegar un enlace</button><a href="/explore" class="live-empty-cta secondary">Explorar cat&aacute;logo</a></div>
</div>
<div id="channel-list" aria-busy="false"${channelCount ? '' : ' style="display:none"'}>${channelCount ? directory.renderGrid(channels, {}, featured ? featured.streamKey : '') : ''}</div>
</section>`;
  html += '</main>'; // .main

  // Network footer: status summary + diagnostics, out of the viewer's way.
  html += `
<div class="live-net-footer" id="net-footer">
  <div class="live-net-summary">
    <span>Red: <b id="net-state">\u2014</b></span>
    <span>\u00b7</span>
    <span>Nodos: <b id="node-count">\u2014</b></span>
    <span>\u00b7</span>
    <span>Actualizado: <b id="last-refresh">\u2014</b></span>
  </div>
  <a href="/privacy" class="live-privacy">Privacidad</a>
  <details class="live-advanced">
    <summary>Estado de la red y herramientas avanzadas</summary>
    <div class="live-advanced-body">
<details id="preflight-panel" class="live-tools">
  <summary>Estado t&eacute;cnico de la conexi&oacute;n<span id="pf-summary-state" role="status"></span></summary>
  <div class="live-tool-content">
  <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:12px">
    <div style="font-weight:700;color:#9ca3af;min-width:100px">\ud83d\udd0d Pre-flight</div>
    <div id="pf-kad" style="color:#888">\u23f3 Kad...</div>
    <div id="pf-id"  style="color:#888">\u23f3 HighID...</div>
    <div id="pf-up"  style="color:#888">\u23f3 Subida...</div>
    <div id="pf-ff"  style="color:#888">\u23f3 FFmpeg...</div>
    <div id="pf-ip"  style="margin-left:auto;color:#666;font-family:monospace;font-size:11px"></div>
  </div>
  <p class="live-freshness" id="pf-freshness">Esperando datos de conexi&oacute;n...</p>
</div></details>
<details id="hp-test-panel" class="live-tools">
  <summary>Prueba avanzada de conexi&oacute;n</summary>
  <div class="live-tool-content">
  <p class="direct-join-hint">Comprueba la conexi&oacute;n UDP con otro equipo (hole-punch).</p>
  <div class="live-panel-row">
    <input id="hp-target-ip" type="text" aria-label="Direcci&oacute;n IP del equipo remoto" placeholder="IP (ej. 88.11.22.161)">
    <input id="hp-target-port" type="text" inputmode="numeric" aria-label="Puerto UDP" placeholder="Puerto UDP (4672)">
    <button id="hp-test-btn">Disparar</button>
  </div>
  <div id="hp-test-result" class="live-result" role="status"></div>
</div></details>
      <div class="live-advanced-links"><a href="/live/debug">Diagn&oacute;stico Live</a><a href="/debug">Registro de actividad</a></div>
    </div>
  </details>
</div>`;

  // Inline JS: polling
  html += `
<script src="/live/player.js?v=\${Date.now()}"></script>
<script>
// Connection status polling
function checkConnection(){
  return fetch('/api/live/connection-status').then(r=>{if(!r.ok)throw new Error('connection unavailable');return r.json();}).then(d=>{
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
    if(nodes)nodes.textContent=d.nodeCount==null?'\\u2014':d.nodeCount;
  }).catch(()=>{
    var dot=document.getElementById('status-dot');
    if(dot)dot.className='status-dot disconnected';
    var text=document.getElementById('status-text');
    var net=document.getElementById('net-state');
    if(text)text.textContent='No se puede comprobar la conexión';
    if(net)net.textContent='Sin conexión';
    var nodes=document.getElementById('node-count');
    if(nodes)nodes.textContent='—';
  });
}

// Channel refresh polling
function refreshChannels(){
  if(typeof filterChannels==='function')return filterChannels({background:true});
}

// Pre-flight + live monitor pollers (Phase 5 / Tier 1.4-1.5)
var preflightLastUpdated = null;
var monitorLastUpdated = null;
var preflightRequest = 0;
var monitorRequest = 0;
function setLiveText(id, text) {
  var el = document.getElementById(id);
  if (el && el.textContent !== String(text)) el.textContent = text;
}
function showFreshness(panelId, textId, lastUpdated, stale) {
  var panel = document.getElementById(panelId);
  if (panel) panel.classList.toggle('is-stale', stale);
  var text = lastUpdated
    ? (stale ? 'Datos desactualizados · Última actualización: ' : 'Actualizado: ') + lastUpdated.toLocaleTimeString('es-ES')
    : 'Sin datos disponibles · Reintentando automáticamente';
  setLiveText(textId, text);
}
function paintCheck(elId, state, label, hint) {
  // state: 'ok' | 'fail' | 'checking' | 'stale'
  var el = document.getElementById(elId);
  if (!el) return;
  var icon = state === 'stale' ? '—' : state === 'ok' ? '✅' : (state === 'checking' ? '⏳' : '❌');
  var color = state === 'stale' ? '#aaaab8' : state === 'ok' ? '#2ecc71' : (state === 'checking' ? '#f39c12' : '#e74c3c');
  el.textContent = icon + ' ' + label + (hint ? ' (' + hint + ')' : '');
  el.style.color = color;
}
function refreshPreflight() {
  var request = ++preflightRequest;
  return fetch('/api/live/preflight').then(function(r){if(!r.ok)throw new Error('preflight unavailable');return r.json();}).then(function(d){
    if (request !== preflightRequest) return;
    if (!d || d.error || typeof d.kad_connected !== 'boolean') throw new Error('invalid preflight');
    preflightLastUpdated = new Date();
    showFreshness('preflight-panel', 'pf-freshness', preflightLastUpdated, false);
    setLiveText('pf-summary-state', '');
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
      // No third parties: show whatever eMule itself detected (v4 via Kad,
      // v6 via in-band peer observation). While neither is known, say so
      // honestly instead of leaking a query to a commercial echo service.
      if (d.public_ip)          ipEl.textContent = d.public_ip + ':' + d.port;
      else if (d.public_ip_v6)  ipEl.textContent = '[' + d.public_ip_v6 + ']:' + d.port;
      else                      ipEl.textContent = 'detectando…';
    }
  }).catch(function(){
    if (request !== preflightRequest) return;
    showFreshness('preflight-panel', 'pf-freshness', preflightLastUpdated, true);
    setLiveText('pf-summary-state', preflightLastUpdated ? ' · Datos desactualizados' : ' · Sin datos');
    paintCheck('pf-kad', 'stale', 'Kad', 'sin datos actuales');
    paintCheck('pf-id', 'stale', 'NAT', 'sin datos actuales');
    paintCheck('pf-up', 'stale', 'Subida', 'sin datos actuales');
    paintCheck('pf-ff', 'stale', 'FFmpeg', 'sin datos actuales');
    setLiveText('pf-ip', 'IP sin actualizar');
  });
}
function refreshMonitor() {
  var request = ++monitorRequest;
  return fetch('/api/live/monitor').then(function(r){if(!r.ok)throw new Error('monitor unavailable');return r.json();}).then(function(d){
    if (request !== monitorRequest) return;
    if (!d || d.error || (typeof d.broadcasting !== 'boolean' && typeof d.viewing !== 'boolean')) throw new Error('invalid monitor');
    var box = document.getElementById('live-monitor');
    if (!box) return;
    monitorLastUpdated = new Date();
    showFreshness('live-monitor', 'mon-freshness', monitorLastUpdated, false);
    setLiveText('mon-label', 'En vivo');
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
  }).catch(function(){
    if (request !== monitorRequest) return;
    var box = document.getElementById('live-monitor');
    if (box) box.style.display = '';
    showFreshness('live-monitor', 'mon-freshness', monitorLastUpdated, true);
    setLiveText('mon-label', 'Estado de la emisión sin confirmar');
    ['mon-mode','mon-buf','mon-viewers','mon-served','mon-recv','mon-missing','mon-mesh'].forEach(function(id){setLiveText(id, '—');});
  });
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
    if (!/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(ip)) {
      setOut('IP no válida.', false); return;
    }
    if (!/^\\d+$/.test(port) || parseInt(port,10) === 0) {
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
              setOut('⚠️ NAT simétrico detectado. Tu router asigna puerto distinto en cada conexión saliente. Sin hole-punch directo: usa Tailscale o una onion service Tor como overlay. Counters: attempts=' + att + ', symNATfail=' + sym, false);
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

// v7.4.0 — Tier 3.1 Cloudflare Tunnel IIFE removed. The endpoints
// /api/live/tunnel/{start,stop,status} return 410 Gone now; no DOM panel
// to wire up either.

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
    // v7.1.7: wizard HTML on a single source line with no newline escapes.
    // Earlier attempts (v7.1.3) tried double-escaping (backslash-backslash-n)
    // to make the outer template emit a literal escape that the browser would
    // re-interpret as a newline; that produced a real LF in some pkg-bundled
    // contexts (seen on PC2 with LowID), leaving the single-quoted string
    // unterminated and aborting the entire inline script. Solution: zero
    // newlines of any kind inside this string. Rendered HTML lays out fine.
    modal.innerHTML = '<div style="background:#13141a;border:1px solid #1f2937;border-radius:14px;max-width:580px;width:90%;padding:32px;color:#ddd;box-shadow:0 20px 60px rgba(0,0,0,.6);max-height:90vh;overflow-y:auto"><div style="font-size:26px;font-weight:800;color:#fff;margin-bottom:8px">👋 Bienvenido a eSE Live</div><div style="color:#9ca3af;font-size:14px;margin-bottom:20px">Vamos a comprobar tu equipo en 30 segundos. No hay que tocar nada manualmente.</div><details style="margin-bottom:20px;padding:10px 14px;background:rgba(99,102,241,.06);border-left:3px solid #818cf8;border-radius:4px;font-size:12px;color:#cbd5e1"><summary style="cursor:pointer;font-weight:600;color:#818cf8">🔒 Privacidad y datos (GDPR) — léelo antes de continuar</summary><div style="margin-top:10px;line-height:1.6">eSE Live es una red P2P. Para que funcione necesita exponer cierta información a otros usuarios:<ul style="margin:6px 0;padding-left:20px"><li><b>Tu IP pública</b> es visible para los peers a los que te conectes (igual que en cualquier red P2P).</li><li>Si emites, tu IP + puerto se publican en Kad (red descentralizada).</li><li>Si usas un overlay externo (Tailscale, Tor), su operador verá metadatos según su política.</li><li>No recopilamos analítica. No hay servidor central.</li></ul>eMule + eSE Live se ejecutan localmente en tu equipo. Los datos compartidos están bajo tu control directo.</div></details><div id="wiz-checks" style="background:#0e0e10;border:1px solid #2a2a2e;border-radius:8px;padding:16px;margin-bottom:20px"><div id="wiz-c-kad" style="margin:6px 0;font-size:13px">⏳ Conectando a la red Kad...</div><div id="wiz-c-id" style="margin:6px 0;font-size:13px">⏳ Comprobando NAT/firewall...</div><div id="wiz-c-ffmpeg" style="margin:6px 0;font-size:13px">⏳ Buscando FFmpeg...</div><div id="wiz-c-ip" style="margin:6px 0;font-size:13px">⏳ Detectando IP pública...</div></div><div id="wiz-tip" style="margin-bottom:18px;padding:10px 14px;background:rgba(243,156,18,.08);border-left:3px solid #f39c12;border-radius:4px;font-size:12px;color:#f39c12;display:none"></div><div id="wiz-actions" style="display:flex;gap:10px;justify-content:flex-end;align-items:center"><a id="wiz-skip" href="#" style="color:#6b7280;font-size:12px;text-decoration:none;margin-right:auto">Saltar wizard</a><button id="wiz-test" disabled style="padding:10px 18px;background:#2ecc71;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:13px;opacity:.5">🎬 Crear emisión de prueba</button><button id="wiz-close" style="padding:10px 18px;background:#374151;color:#fff;border:none;border-radius:8px;font-weight:600;cursor:pointer;font-size:13px">Acepto y cerrar</button></div></div>';
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
      fetch('/api/live/broadcast/start?source=testpattern&title=eSE+Demo&bitrate=1500', {
        method: 'POST',
        headers: { 'X-Requested-With': 'eSE' }
      })
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
                '<div style="margin-top:14px;display:flex;gap:8px"><button onclick="window.location.href=\\'/live/watch/local\\'" style="padding:8px 18px;background:#ff6b35;color:#fff;border:none;border-radius:6px;font-weight:700;cursor:pointer">▶ Ver tu propia emisión</button>' +
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
          // Player lives at /live/watch/local in the live_tv routes. The
          // standalone /player route exists only in the orphan
          // live_player_server.js (never wired into the request handler chain),
          // so redirecting there 404s. See PR #10 / v0.70b-eSE7.1.4 notes.
          setTimeout(function(){ window.location.href = '/live/watch/local'; }, 1500);
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

// Direct-join panel: collapsed behind the header button.
function openDirectJoin(){
  var panel=document.getElementById('direct-join-panel');
  var toggle=document.getElementById('direct-join-toggle');
  if(!panel)return;
  panel.hidden=false;
  if(toggle)toggle.setAttribute('aria-expanded','true');
  var input=document.getElementById('direct-join-link');
  if(input)input.focus();
}
(function(){
  var toggle=document.getElementById('direct-join-toggle');
  var panel=document.getElementById('direct-join-panel');
  if(!toggle||!panel)return;
  toggle.addEventListener('click',function(){
    if(panel.hidden)return openDirectJoin();
    panel.hidden=true;
    toggle.setAttribute('aria-expanded','false');
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
