// filepath: pages/mylist_page.js
'use strict';
const navbar = require('../shared/navbar');
const { TMDB_KEY } = require('../api_keys');

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function getHTML() {
  // ── MyList-specific CSS ──
  const mlCSS =
  '.ml-page{padding:24px 40px 80px}' +
  '.ml-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}' +
  '.ml-title{font-size:32px;font-weight:800;color:#fff}' +
  '.ml-count{font-size:14px;color:#666;font-weight:400}' +
  '.ml-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:20px}' +
  '.ml-card{position:relative;border-radius:10px;overflow:hidden;cursor:pointer;transition:all .3s}' +
  '.ml-card:hover{transform:translateY(-6px) scale(1.03);box-shadow:0 12px 36px rgba(0,0,0,.5)}' +
  '.ml-card img{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#1a1a2e}' +
  '.ml-card-info{position:absolute;bottom:0;left:0;right:0;padding:10px;background:linear-gradient(transparent,rgba(0,0,0,.9))}' +
  '.ml-card-title{font-size:13px;font-weight:600;color:#fff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
  '.ml-card-meta{font-size:11px;color:#888;margin-top:2px}' +
  '.ml-card-remove{position:absolute;top:8px;right:8px;width:28px;height:28px;background:rgba(0,0,0,.7);border:none;border-radius:50%;color:#ff4757;font-size:14px;cursor:pointer;display:none;align-items:center;justify-content:center;transition:all .2s;backdrop-filter:blur(4px)}' +
  '.ml-card:hover .ml-card-remove{display:flex}' +
  '.ml-card-remove:hover{background:#ff4757;color:#fff;transform:scale(1.1)}' +
  '.ml-empty{text-align:center;padding:100px 20px;color:#555}' +
  '.ml-empty-icon{font-size:64px;margin-bottom:20px;opacity:.3}' +
  '.ml-empty-title{font-size:22px;font-weight:600;color:#888;margin-bottom:8px}' +
  '.ml-empty-sub{font-size:14px;color:#555;max-width:400px;margin:0 auto}' +
  '.ml-empty-btn{display:inline-block;margin-top:20px;padding:12px 28px;background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;border:none;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer;text-decoration:none;transition:opacity .2s}' +
  '.ml-empty-btn:hover{opacity:.85}' +
  // v7.4.0 — tab navigation between "Mi Lista" (saved bookmarks) and "Descargas" (live transfers).
  '.ml-tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid #222}' +
  '.ml-tab{padding:10px 20px;background:none;border:none;color:#888;font-size:14px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s}' +
  '.ml-tab.active{color:#ff6b35;border-bottom-color:#ff6b35}' +
  '.ml-tab:hover{color:#fff}' +
  '.dl-list{display:flex;flex-direction:column;gap:8px}' +
  '.dl-row{display:grid;grid-template-columns:1fr 200px 110px auto;gap:14px;align-items:center;background:#0f0f17;border:1px solid #1f1f29;border-radius:8px;padding:12px 16px}' +
  '.dl-row.dl-paused{opacity:.6}' +
  '.dl-name{font-size:13px;color:#fff;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
  '.dl-bar-wrap{height:6px;background:#1a1a26;border-radius:3px;overflow:hidden}' +
  '.dl-bar{height:100%;background:linear-gradient(90deg,#ff6b35,#ff2d78);transition:width .3s}' +
  '.dl-meta{font-size:12px;color:#888;font-family:monospace}' +
  '.dl-actions{display:flex;gap:4px}' +
  '.dl-actions button{background:#1a1a26;border:1px solid #2a2a38;color:#ccc;width:30px;height:30px;border-radius:4px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center}' +
  '.dl-actions button:hover{background:#2a2a38;color:#fff}' +
  '.dl-empty{padding:60px 20px;text-align:center;color:#555}';

  // ── Inline JS ──
  const inlineJS = `
function _e(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function _a(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function renderMyList(){
  var KEY="ese_mylist";
  var list=[];
  try{list=JSON.parse(localStorage.getItem(KEY)||"[]")}catch(e){}
  var container=document.getElementById("ml-content");
  var countEl=document.getElementById("ml-count");
  if(!container)return;
  if(countEl)countEl.textContent=list.length+" elemento"+(list.length!==1?"s":"");
  if(!list.length){
    container.innerHTML='<div class="ml-empty">'+
      '<div class="ml-empty-icon">\\ud83d\\udd16</div>'+
      '<div class="ml-empty-title">Tu lista est\\xe1 vac\\xeda</div>'+
      '<div class="ml-empty-sub">Explora el cat\\xe1logo y a\\xf1ade pel\\xedculas o series pulsando el bot\\xf3n \\ud83d\\udd16 Mi Lista en la ficha de cada t\\xedtulo.</div>'+
      '<a href="/explore" class="ml-empty-btn">Explorar cat\\xe1logo</a>'+
    '</div>';
    return;
  }
  container.innerHTML='<div class="ml-grid">'+list.map(function(item){
    var poster=item.poster||"";
    var detailUrl='/?detail='+encodeURIComponent(item.imdbId||"")+'&title='+encodeURIComponent(item.title||"");
    return '<div class="ml-card" data-detail-url="'+_a(detailUrl)+'">'
      +(poster?'<img src="'+_a(poster)+'" alt="" loading="lazy">':'<div style="width:100%;aspect-ratio:2/3;background:#1a1a2e"></div>')
      +'<button type="button" class="ml-card-remove" data-remove-imdb="'+_a(item.imdbId||"")+'">\u2716</button>'
      +'<div class="ml-card-info"><div class="ml-card-title">'+_e(item.title||"")+'</div>'
      +'<div class="ml-card-meta">'+_e(item.year||"")+(item.type==="tv"?" \\u00b7 Serie":"")+'</div></div></div>';
  }).join("")+'</div>';
  container.querySelectorAll('.ml-card').forEach(function(card){
    card.addEventListener('click',function(){window.location.href=card.getAttribute('data-detail-url')||'/';});
  });
  container.querySelectorAll('[data-remove-imdb]').forEach(function(button){
    button.addEventListener('click',function(event){
      event.stopPropagation();
      removeItem(button.getAttribute('data-remove-imdb')||'');
    });
  });
}
function removeItem(imdbId){
  var KEY="ese_mylist";
  var list=[];
  try{list=JSON.parse(localStorage.getItem(KEY)||"[]")}catch(e){}
  list=list.filter(function(x){return x.imdbId!==imdbId});
  localStorage.setItem(KEY,JSON.stringify(list));
  renderMyList();
}
renderMyList();

// v7.4.0 \u2014 tabs + downloads panel
var _dlTimer = null;
function switchTab(name) {
  document.querySelectorAll('.ml-tab').forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-tab') === name);
  });
  document.getElementById('ml-tab-mylist').style.display    = (name === 'mylist')    ? '' : 'none';
  document.getElementById('ml-tab-downloads').style.display = (name === 'downloads') ? '' : 'none';
  if (name === 'downloads') {
    renderDownloads();
    if (_dlTimer) clearInterval(_dlTimer);
    _dlTimer = setInterval(renderDownloads, 3000);
  } else if (_dlTimer) {
    clearInterval(_dlTimer); _dlTimer = null;
  }
}
function renderDownloads() {
  fetch('/api/emule/downloads').then(function(r){return r.json();}).catch(function(){return [];}).then(function(downloads) {
    var host = document.getElementById('downloads-content');
    if (!host) return;
    if (!downloads.length) {
      host.innerHTML = '<div class="dl-empty"><div style="font-size:48px;opacity:.3;margin-bottom:12px">\\u2b07</div><div style="font-size:16px;color:#888">No hay descargas activas</div></div>';
      return;
    }
    var rows = downloads.map(function(dl) {
      var fullSize = dl.sizeBytes ? Math.round(dl.sizeBytes / 1048576) : 0;
      var pct = fullSize > 0 ? Math.min(100, Math.round((dl.sizeMB / fullSize) * 100)) : 0;
      var stateClass = dl.active ? 'dl-active' : 'dl-paused';
      return '<div class="dl-row ' + stateClass + '">' +
        '<div class="dl-name" title="' + _a(dl.fileName || '') + '">' + _e(dl.fileName || 'sin nombre') + '</div>' +
        '<div class="dl-bar-wrap"><div class="dl-bar" style="width:' + pct + '%"></div></div>' +
        '<div class="dl-meta">' + dl.sizeMB + ' / ' + (fullSize || '?') + ' MB</div>' +
        '<div class="dl-actions">' +
          '<button type="button" data-dl-op="pause" data-hash="' + _a(dl.hash || '') + '" title="Pausar">\\u23f8</button>' +
          '<button type="button" data-dl-op="resume" data-hash="' + _a(dl.hash || '') + '" title="Reanudar">\\u25b6</button>' +
          '<button type="button" data-dl-op="priohigh" data-hash="' + _a(dl.hash || '') + '" title="Prio alta">\\u2b06</button>' +
          '<button type="button" data-dl-op="prionormal" data-hash="' + _a(dl.hash || '') + '" title="Prio normal">=</button>' +
          '<button type="button" data-dl-cancel data-hash="' + _a(dl.hash || '') + '" data-name="' + _a(dl.fileName || '') + '" style="color:#ff6b35" title="Cancelar y borrar">\\u2716</button>' +
        '</div>' +
      '</div>';
    }).join('');
    host.innerHTML = '<div class="dl-list">' + rows + '</div>';
    host.querySelectorAll('[data-dl-op]').forEach(function(button){
      button.addEventListener('click',function(){
        dlAct(button.getAttribute('data-hash')||'',button.getAttribute('data-dl-op')||'');
      });
    });
    host.querySelectorAll('[data-dl-cancel]').forEach(function(button){
      button.addEventListener('click',function(){
        dlCancel(button.getAttribute('data-hash')||'',button.getAttribute('data-name')||'');
      });
    });
  });
}
function dlAct(hash, op) {
  if (!hash) return;
  // v7.5.0 — X-Requested-With header marks this as same-origin fetch (CSRF defence).
  fetch('/api/emule/download/action?hash=' + encodeURIComponent(hash) + '&op=' + op,
        { headers: { 'X-Requested-With': 'eSE' } })
    .then(function(r){return r.json();}).catch(function(){return {};})
    .then(function(d){ if (d && d.success === false) console.warn('[dl] action failed:', d.error); renderDownloads(); });
}
function dlCancel(hash, name) {
  if (!hash) return;
  if (!confirm('\\u00bfCancelar "' + name + '" y borrar archivos parciales?')) return;
  fetch('/api/emule/download/action?hash=' + encodeURIComponent(hash) + '&op=cancel',
        { headers: { 'X-Requested-With': 'eSE' } })
    .then(function(){ setTimeout(renderDownloads, 500); });
}
window.switchTab  = switchTab;
window.dlAct      = dlAct;
window.dlCancel   = dlCancel;
window.renderDownloads = renderDownloads;
`;

  return navbar.getHead('Mi Lista \u2014 eSE', mlCSS) +
  navbar.getHTML('mylist') +
  '<div class="ml-page">' +
  '<div class="ml-header"><h1 class="ml-title">Mi Biblioteca</h1><span id="ml-count" class="ml-count"></span></div>' +
  '<div class="ml-tabs">' +
    '<button class="ml-tab active" data-tab="mylist" onclick="switchTab(\'mylist\')">Mi Lista</button>' +
    '<button class="ml-tab" data-tab="downloads" onclick="switchTab(\'downloads\')">Descargas activas</button>' +
  '</div>' +
  '<div id="ml-tab-mylist"><div id="ml-content"></div></div>' +
  '<div id="ml-tab-downloads" style="display:none"><div id="downloads-content"></div></div>' +
  '</div>' +
  '<script>' + inlineJS + '</script>' +
  '</body></html>';
}

// ── Route handler ──────────────────────────────────────────────────────────────
function handle(url, req, res) {
  if (url.pathname === '/mylist') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getHTML());
    return true;
  }
  return false;
}

module.exports = { init, handle };
