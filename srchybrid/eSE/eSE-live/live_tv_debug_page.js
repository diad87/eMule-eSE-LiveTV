/**
 * eSE Live — Debug Page
 * Technical dashboard at /live/debug with P2P mesh stats, trust bar,
 * Kad discovery, ed2k share links, and pipeline status.
 * All technical noise removed from /live and preserved here.
 */
'use strict';

const navbar = require('../shared/navbar');

function render(status, meta) {
  const css = `
.main{max-width:900px;margin:0 auto;padding:80px 40px 40px}
.debug-header{display:flex;align-items:center;gap:16px;margin-bottom:32px}
.debug-header h1{font-size:22px;font-weight:700;color:#fff}
.back-link{color:#ff6b35;text-decoration:none;font-size:13px;font-weight:600}
.back-link:hover{text-decoration:underline}
.panel{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:24px;margin-bottom:20px}
.panel h3{font-size:15px;font-weight:600;margin-bottom:16px;color:#fff;display:flex;align-items:center;gap:8px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px}
.stat-item{background:rgba(0,0,0,.3);border-radius:8px;padding:14px;text-align:center;border:1px solid rgba(255,255,255,.05)}
.stat-val{font-size:24px;font-weight:800;color:#fff;font-variant-numeric:tabular-nums}
.stat-label{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.trust-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:rgba(255,255,255,.05);margin-bottom:12px}
.trust-segment{transition:flex .5s ease}
.trust-super{background:#2ecc71}.trust-middle{background:#f39c12}.trust-leaf{background:#e74c3c}
.trust-legend{display:flex;gap:16px;font-size:12px;color:#999}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px;vertical-align:middle}
.link-box{background:#111;border:1px solid #333;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:12px;color:#ff6b35;word-break:break-all;cursor:pointer;transition:background .2s;margin-top:8px}
.link-box:hover{background:#1a1a2e}
.btn-share{background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;border:none;padding:10px 24px;border-radius:8px;font-weight:700;cursor:pointer;font-size:13px;transition:all .2s}
.btn-share:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(255,107,53,.3)}
.emergency-banner{background:rgba(231,76,60,.15);border:1px solid rgba(231,76,60,.4);color:#e74c3c;padding:12px;border-radius:8px;font-weight:700;text-align:center;margin:16px 0;display:none}
.pipeline-row{display:flex;gap:20px;flex-wrap:wrap;font-size:13px;color:#ccc}
.pipeline-row b{color:#fff}
.kad-badge{font-size:11px;padding:2px 8px;border-radius:4px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);font-weight:600}
.stream-list{margin-top:12px}
.stream-item{background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:12px 16px;margin-bottom:8px;cursor:pointer;transition:all .2s}
.stream-item:hover{border-color:rgba(255,107,53,.3);background:rgba(255,107,53,.05)}
.stream-title{font-weight:600;color:#fff;font-size:14px}
.stream-meta{font-size:12px;color:#888;margin-top:4px}
.nat-bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:rgba(255,255,255,.05);margin-top:12px}
.nat-fill{transition:width .5s ease;border-radius:5px}
.nat-warn{font-size:11px;color:#e74c3c;margin-top:6px;display:none}
.sparkline-box{margin-top:14px;position:relative;height:48px;background:rgba(0,0,0,.2);border-radius:6px;overflow:hidden;border:1px solid rgba(255,255,255,.04)}
.sparkline-box svg{display:block;width:100%;height:100%}
.sparkline-label{position:absolute;top:4px;left:8px;font-size:9px;color:#555;text-transform:uppercase;letter-spacing:.5px}
.btn-export{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);color:#aaa;padding:8px 18px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px;margin-top:14px}
.btn-export:hover{background:rgba(255,107,53,.1);border-color:rgba(255,107,53,.3);color:#ff6b35}
`;

  let html = navbar.getHead('Debug \u2014 eSE Live', css);
  html += navbar.getHTML('live');

  html += `<div class="main">
<div class="debug-header">
  <a href="/live" class="back-link">\u2190 Volver a Live TV</a>
  <h1>
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-4px">
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
    </svg>
    Debug Panel
  </h1>
</div>

<!-- Pipeline Status -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/></svg>
    Pipeline
  </h3>
  <div class="pipeline-row">
    <span>Estado: <b id="pipe-status">${status.status || 'idle'}</b></span>
    <span>Uptime: <b id="pipe-uptime">${fmtDur(status.uptime || 0)}</b></span>
    <span>Segmentos: <b id="pipe-segs">${status.segments || 0}</b></span>
    <span>Fuente: <b>${status.source || '\u2014'}</b></span>
  </div>
</div>

<!-- NAT Traversal Health -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
    NAT Traversal Health <span class="kad-badge" id="nat-indicator" style="color:#666">\u25cf</span>
  </h3>
  <div class="stat-grid">
    <div class="stat-item"><div class="stat-val" id="nat-attempts">\u2014</div><div class="stat-label">Attempts</div></div>
    <div class="stat-item"><div class="stat-val" id="nat-success">\u2014</div><div class="stat-label">Success</div></div>
    <div class="stat-item"><div class="stat-val" id="nat-symfail">\u2014</div><div class="stat-label">SymNAT Fail</div></div>
    <div class="stat-item"><div class="stat-val" id="nat-rate">\u2014</div><div class="stat-label">Success Rate</div></div>
  </div>
  <div class="nat-bar"><div class="nat-fill" id="nat-fill" style="width:0;background:#666"></div></div>
  <div class="sparkline-box">
    <span class="sparkline-label">Rate % (last 60s)</span>
    <svg id="nat-sparkline" viewBox="0 0 200 48" preserveAspectRatio="none">
      <defs><linearGradient id="spark-grad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#2ecc71" stop-opacity=".3"/><stop offset="100%" stop-color="#2ecc71" stop-opacity="0"/></linearGradient></defs>
      <polygon id="spark-area" points="0,48 200,48" fill="url(#spark-grad)"/>
      <polyline id="spark-line" fill="none" stroke="#2ecc71" stroke-width="1.5" points=""/>
    </svg>
  </div>
  <div class="nat-warn" id="nat-warn">\u26a0 High symmetric NAT failure rate — consider enabling UPnP or switching network</div>
  <button class="btn-export" onclick="exportNatLogs()" title="Download NAT diagnostic report">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    Exportar Logs NAT
  </button>
</div>

<!-- P2P Mesh Stats -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    P2P Mesh <span class="kad-badge" id="p2p-indicator" style="color:#666">\u25cf</span>
  </h3>
  <div class="stat-grid">
    <div class="stat-item"><div class="stat-val" id="stat-peers">\u2014</div><div class="stat-label">Peers</div></div>
    <div class="stat-item"><div class="stat-val" id="stat-redistributed">\u2014</div><div class="stat-label">Redistribuido</div></div>
    <div class="stat-item"><div class="stat-val" id="stat-pending">\u2014</div><div class="stat-label">Pendientes</div></div>
    <div class="stat-item"><div class="stat-val" id="stat-upload-floor">\u2014</div><div class="stat-label">Upload m\u00edn</div></div>
  </div>
</div>

<!-- Trust Distribution -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    Trust Distribution
  </h3>
  <div class="trust-bar" id="trust-bar">
    <div class="trust-segment trust-super" id="trust-super" style="flex:0"></div>
    <div class="trust-segment trust-middle" id="trust-middle" style="flex:0"></div>
    <div class="trust-segment trust-leaf" id="trust-leaf" style="flex:0"></div>
  </div>
  <div class="trust-legend">
    <span><span class="dot" style="background:#2ecc71"></span> Super: <b id="cnt-super">0</b></span>
    <span><span class="dot" style="background:#f39c12"></span> Middle: <b id="cnt-middle">0</b></span>
    <span><span class="dot" style="background:#e74c3c"></span> Leaf: <b id="cnt-leaf">0</b></span>
  </div>
  <div id="emergency-banner" class="emergency-banner">\u26a0\ufe0f MODO EMERGENCIA</div>
</div>

<!-- Share Links -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
    Compartir
  </h3>
  <button class="btn-share" onclick="shareStream()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:4px"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
    Generar enlace ed2k://
  </button>
  <div id="share-result"></div>
</div>

<!-- Kad Streams -->
<div class="panel">
  <h3>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    Streams Kad <span class="kad-badge" id="kad-status">Buscando...</span>
  </h3>
  <div id="p2p-streams" class="stream-list">Conectando...</div>
</div>

</div>

<script>
function fmtBytes(b){
  if(!b||b===0)return '0 B';
  if(b<1024)return b+' B';
  if(b<1048576)return (b/1024).toFixed(1)+' KB';
  if(b<1073741824)return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}
function escH(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

// NAT sparkline ring buffer (20 samples × 3s = 60s window)
var NAT_HIST_MAX=20;
var natHistory=[];
function drawSparkline(data,color){
  if(!data.length)return;
  var W=200,H=48,pad=2;
  var step=W/(NAT_HIST_MAX-1);
  var pts=data.map(function(v,i){
    var x=Math.round(i*step);
    var y=Math.round(H-pad-(v/100)*(H-pad*2));
    return x+','+y;
  });
  var lineEl=document.getElementById('spark-line');
  var areaEl=document.getElementById('spark-area');
  var gradStops=document.querySelectorAll('#spark-grad stop');
  if(lineEl)lineEl.setAttribute('points',pts.join(' '));
  if(lineEl)lineEl.setAttribute('stroke',color);
  if(areaEl)areaEl.setAttribute('points','0,'+H+' '+pts.join(' ')+' '+(Math.round((data.length-1)*step))+','+H);
  if(areaEl)areaEl.setAttribute('fill','url(#spark-grad)');
  if(gradStops.length>=1)gradStops[0].setAttribute('stop-color',color);
}

function refreshStats(){
  fetch('/api/live/p2p/stats').then(r=>r.json()).then(d=>{
    document.getElementById('stat-peers').textContent=d.meshPeers||0;
    document.getElementById('stat-redistributed').textContent=fmtBytes(d.totalRedistributed||0);
    document.getElementById('stat-pending').textContent=d.pendingRequests||0;
    document.getElementById('stat-upload-floor').textContent=d.uploadFloor?fmtBytes(d.uploadFloor)+'/s':'\\u2014';
    var t=d.trustLevels||{};
    document.getElementById('cnt-super').textContent=t.superSeeders||0;
    document.getElementById('cnt-middle').textContent=t.middle||0;
    document.getElementById('cnt-leaf').textContent=t.leaf||0;
    var total=(t.superSeeders||0)+(t.middle||0)+(t.leaf||0)||1;
    document.getElementById('trust-super').style.flex=(t.superSeeders||0)/total;
    document.getElementById('trust-middle').style.flex=(t.middle||0)/total;
    document.getElementById('trust-leaf').style.flex=(t.leaf||0)/total;
    document.getElementById('emergency-banner').style.display=d.emergencyMode?'':'none';
    document.getElementById('p2p-indicator').style.color=d.meshPeers>0?'#2ecc71':'#666';
  }).catch(()=>{});

  fetch('/api/live/status').then(r=>r.json()).then(s=>{
    document.getElementById('pipe-status').textContent=s.status||'idle';
    document.getElementById('pipe-segs').textContent=s.segments||0;
  }).catch(()=>{});

  // NAT Health
  fetch('/api/live/nat-health').then(r=>r.json()).then(n=>{
    _lastNatSnapshot=n;
    document.getElementById('nat-attempts').textContent=n.attempts||0;
    document.getElementById('nat-success').textContent=n.success||0;
    document.getElementById('nat-symfail').textContent=n.symNatFail||0;
    var rate=n.rate;
    var rateEl=document.getElementById('nat-rate');
    var fillEl=document.getElementById('nat-fill');
    var indEl=document.getElementById('nat-indicator');
    var warnEl=document.getElementById('nat-warn');
    if(rate!==null){
      rateEl.textContent=rate+'%';
      fillEl.style.width=rate+'%';
      var color=rate>=70?'#2ecc71':rate>=40?'#f39c12':'#e74c3c';
      fillEl.style.background=color;indEl.style.color=color;
      warnEl.style.display=rate<30&&n.attempts>=5?'':'none';
      // Sparkline ring buffer
      natHistory.push(rate);
      if(natHistory.length>NAT_HIST_MAX)natHistory.shift();
      drawSparkline(natHistory,color);
    } else {
      rateEl.textContent='\\u2014';
      fillEl.style.width='0';
      indEl.style.color=n.enabled?'#666':'#555';
      warnEl.style.display='none';
    }
  }).catch(()=>{});
}

function refreshStreams(){
  fetch('/api/live/p2p/streams').then(r=>r.json()).then(d=>{
    var el=document.getElementById('p2p-streams');
    var kad=document.getElementById('kad-status');
    kad.textContent=d.kadConnected?'Conectado':'Local';
    kad.style.color=d.kadConnected?'#2ecc71':'#f39c12';
    if(!d.streams||d.streams.length===0){
      el.innerHTML='<div style="color:#555;font-size:13px">No hay streams P2P activos</div>';
      return;
    }
    el.innerHTML=d.streams.map(s=>
      '<div class="stream-item" onclick="location.href=\\'/live/watch/'+s.streamKey+'\\'">' +
      '<div class="stream-title">'+escH(s.title||'Stream')+'</div>' +
      '<div class="stream-meta">'+s.bitrate+'kbps \\u00b7 '+s.source+' \\u00b7 <span style="color:#ff6b35;cursor:pointer" onclick="event.stopPropagation();copyLink(\\''+s.ed2kLink+'\\')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> copiar</span></div>' +
      '</div>'
    ).join('');
  }).catch(()=>{});
}

function shareStream(){
  fetch('/api/live/p2p/share').then(r=>r.json()).then(d=>{
    document.getElementById('share-result').innerHTML=
      '<div class="link-box" onclick="copyLink(\\''+d.ed2kLink+'\\')">'+d.ed2kLink+'</div>'+
      '<div class="link-box" onclick="copyLink(\\''+d.webLink+'\\')">'+d.webLink+'</div>'+
      '<div style="font-size:11px;color:#888;margin-top:6px">Click para copiar</div>';
  }).catch(()=>{});
}
function copyLink(link){
  navigator.clipboard.writeText(link).then(()=>{
    var t=document.createElement('div');
    t.style.cssText='position:fixed;bottom:30px;right:30px;background:#2ecc71;color:#fff;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;z-index:9999';
    t.textContent='\\u2713 Copiado';
    document.body.appendChild(t);
    setTimeout(()=>t.remove(),2000);
  });
}

// NAT Log export — builds JSON report from live state + sparkline history
var _lastNatSnapshot=null;
function exportNatLogs(){
  var report={
    version:'1.0',
    generatedAt:new Date().toISOString(),
    userAgent:navigator.userAgent,
    currentSnapshot:_lastNatSnapshot||{},
    sparklineHistory:natHistory.slice(),
    sparklineSamples:natHistory.length,
    sparklineWindowSec:natHistory.length*3,
    thresholds:{warnBelow:30,minAttempts:5}
  };
  var blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
  var url=URL.createObjectURL(blob);
  var a=document.createElement('a');
  a.href=url;
  a.download='nat-health-'+new Date().toISOString().replace(/[:.]/g,'-').slice(0,19)+'.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  // Toast
  var t=document.createElement('div');
  t.style.cssText='position:fixed;bottom:30px;right:30px;background:#2ecc71;color:#fff;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:600;z-index:9999';
  t.textContent='\\u2713 Log NAT exportado';
  document.body.appendChild(t);
  setTimeout(function(){t.remove()},2500);
}

refreshStats();
refreshStreams();
setInterval(refreshStats, 3000);
setInterval(refreshStreams, 10000);
</script>
</body></html>`;

  return html;
}

function fmtDur(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
  return m + 'm ' + String(s).padStart(2, '0') + 's';
}

module.exports = { render };
