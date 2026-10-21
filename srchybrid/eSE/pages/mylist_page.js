// filepath: pages/mylist_page.js
'use strict';
const navbar = require('../shared/navbar');
const catalogStyle = require('../shared/catalog_style');

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function getHTML() {
  // ── MyList-specific CSS ──
  const mlCSS =
  '.ml-page{padding:40px var(--ese-page-padding,40px) 80px;max-width:1920px;margin:auto}' +
  '.ml-eyebrow{color:#ff927d;font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px}' +
  '.ml-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:12px}' +
  '.ml-title{font-size:clamp(32px,4vw,46px);line-height:1.1;letter-spacing:-1.5px;font-weight:800;color:#fff}' +
  '.ml-subtitle{color:#aeb0bf;font-size:15px;line-height:1.6;margin-bottom:28px}' +
  '.ml-panel-intro{color:#aeb0bf;font-size:13px;line-height:1.6;margin:-8px 0 24px}.ml-undo{font:inherit;font-weight:600;color:#ffb4a5;background:none;border:0;border-bottom:1px solid #ffb4a570;padding:8px 4px;margin-left:8px;min-height:44px;cursor:pointer}' +
  '.ml-count{font-size:13px;color:#b5b6c4;font-weight:400;white-space:nowrap;background:#ffffff08;border:1px solid #ffffff12;border-radius:20px;padding:8px 13px}' +
  '.ml-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(164px,1fr));gap:28px 20px}' +
  '.ml-card{position:relative;min-width:0;border-radius:10px;transition:transform .2s;align-self:start}' +
  '.ml-card:hover{transform:translateY(-4px)}' +
  '.ml-card-link{display:block;color:inherit;text-decoration:none;border-radius:10px}' +
  '.ml-card img,.ml-poster-empty{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#1b1b27;border:1px solid #ffffff12;border-radius:10px}' +
  '.ml-poster-empty{display:flex;align-items:center;justify-content:center;color:#aeb0bf;font-size:13px}' +
  '.ml-card-info{padding:12px 2px 4px}' +
  '.ml-card-title{font-size:14px;line-height:1.45;font-weight:600;color:#f2f1f5;overflow-wrap:anywhere}' +
  '.ml-card-meta{font-size:12px;line-height:1.5;color:#aeb0bf;margin-top:5px}' +
  '.ml-card-remove{position:absolute;top:8px;right:8px;width:44px;height:44px;background:#0a0a0fe0;border:1px solid #ffffff35;border-radius:50%;color:#fff;font-size:17px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background .2s}' +
  '.ml-card-remove:hover{background:#ff806b;color:#191013}' +
  '.ml-empty{text-align:center;padding:64px 24px;color:#b2b3c0;background:#ffffff03;border:1px solid #ffffff0f;border-radius:14px}' +
  '.ml-empty-icon{font-size:40px;margin-bottom:20px;color:#ff927d}' +
  '.ml-empty-title{font-size:24px;font-weight:600;color:#f2f1f5;margin-bottom:10px;letter-spacing:-.5px}' +
  '.ml-empty-sub{font-size:14px;line-height:1.7;color:#aeb0bf;max-width:440px;margin:0 auto}' +
  '.ml-empty-btn{display:inline-block;margin-top:24px;padding:13px 24px;background:#ff806b;color:#191013;border:none;border-radius:8px;font-weight:700;font-size:14px;cursor:pointer;text-decoration:none;transition:opacity .2s}' +
  '.ml-empty-btn:hover{opacity:.85}' +
  // v7.4.0 — tab navigation between "Mi Lista" (saved bookmarks) and "Descargas" (live transfers).
  '.ml-tabs{display:flex;gap:20px;margin-bottom:28px;border-bottom:1px solid #ffffff16}' +
  '.ml-tab{min-height:48px;padding:12px 0;background:none;border:none;color:#aeb0bf;font:inherit;font-size:14px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;transition:color .2s}' +
  '.ml-tab.active{color:#ff927d;border-bottom-color:#ff927d}' +
  '.ml-tab:hover{color:#fff}' +
  '.files-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:20px}.files-search{flex:1;min-width:160px}.files-search label{display:block;color:#b5b6c4;font-size:12px;margin-bottom:7px}.files-search input{width:100%;min-height:46px;padding:12px 14px;background:#15151f;color:#fff;border:1px solid #ffffff25;border-radius:8px;font:inherit;font-size:14px}.files-refresh{align-self:flex-end;min-height:46px;padding:10px 15px;color:#ddd;background:#ffffff08;border:1px solid #ffffff25;border-radius:8px;font:inherit;font-size:13px;cursor:pointer}.files-refresh:disabled{opacity:.6;cursor:wait}' +
  '.files-count{font-size:13px;color:#aeb0bf;margin-bottom:16px}.files-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}.file-card{display:flex;align-items:flex-start;gap:14px;padding:18px;background:#15151f;border:1px solid #ffffff16;border-radius:10px;color:#eee;text-decoration:none;min-width:0}.file-card:hover{border-color:#ff927d;background:#1b1b27}.file-icon{display:grid;place-items:center;flex:0 0 42px;height:48px;border-radius:7px;background:#ff927d12;color:#ffac8c}.file-copy{min-width:0}.file-name{font-size:14px;font-weight:600;line-height:1.5;overflow-wrap:anywhere}.file-meta{display:block;font-size:12px;line-height:1.5;color:#aeb0bf;margin-top:7px}.file-play{display:block;color:#ffac8c;font-size:12px;margin-top:9px}.files-empty[hidden]{display:none}' +
  '.dl-list{display:flex;flex-direction:column;gap:8px}' +
  '.dl-row{display:grid;grid-template-columns:minmax(0,1fr) 180px 120px auto;gap:16px;align-items:center;background:#14141d;border:1px solid #ffffff13;border-radius:10px;padding:16px}' +
  '.dl-name{font-size:13px;color:#fff;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
  '.dl-bar-wrap{height:6px;background:#1a1a26;border-radius:3px;overflow:hidden}' +
  '.dl-bar{height:100%;background:#ff806b;transition:width .3s}' +
  '.dl-meta{font-size:12px;color:#b5b6c4;font-variant-numeric:tabular-nums}.dl-status{display:block;color:#aeb0bf;font-size:12px;margin-top:5px}' +
  '.dl-actions{display:flex;gap:4px}' +
  '.dl-actions button{background:#1a1a26;border:1px solid #ffffff20;color:#ddd;width:44px;height:44px;border-radius:7px;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center}' +
  '.dl-actions button:hover{background:#2a2a38;color:#fff}' +
  '.dl-actions button:disabled{opacity:.4;cursor:not-allowed}.dl-progress-unknown{color:#aeb0bf;font-size:12px}' +
  '.dl-empty{padding:60px 20px;text-align:center;color:#b5b6c4;font-size:15px;line-height:1.7}.dl-notice{color:#ffb4a5;font-size:14px;line-height:1.6;margin-bottom:16px}.dl-notice:empty{display:none}' +
  '.ml-page :focus-visible{outline:2px solid #ffa18f;outline-offset:4px}' +
  '@media(max-width:1100px){.dl-row{grid-template-columns:minmax(0,1fr) auto}.dl-name{grid-column:1/-1}.dl-actions{grid-column:1/-1}.dl-bar-wrap{min-width:0}}' +
  '@media(max-width:760px){.ml-page{padding:28px 20px 60px}.ml-title{letter-spacing:-1px}.ml-header{align-items:flex-start;flex-direction:column}.ml-count{padding:0;border:0;background:none}.ml-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:24px 14px}.ml-empty{padding:44px 20px}.ml-empty-title{font-size:21px}.files-grid{grid-template-columns:minmax(0,1fr)}.ml-tabs{gap:18px}}' +
  '@media(prefers-reduced-motion:reduce){.ml-card,.ml-tab,.dl-bar{transition:none}}';

  // ── Inline JS ──
  const inlineJS = `
function _e(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function _a(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
var removedItem=null;
function readSavedList(){
  var list=JSON.parse(localStorage.getItem('ese_mylist')||'[]');
  if(!Array.isArray(list)||list.some(function(item){return !item||typeof item!=='object'||Array.isArray(item)||typeof item.imdbId!=='string'||!item.imdbId.trim()}))throw new Error('Invalid list');
  return list;
}
function renderMyList(){
  var KEY="ese_mylist";
  var list=[];
  var container=document.getElementById("ml-content");
  var countEl=document.getElementById("ml-count");
  if(!container)return;
  try{list=readSavedList()}catch(e){
    container.innerHTML='<div class="ml-empty" role="status"><h2 class="ml-empty-title">No se ha podido leer tu lista</h2><p class="ml-empty-sub">El almacenamiento del navegador no está disponible o contiene datos que no se pueden leer. Tus títulos no se han modificado.</p></div>';
    if(countEl)countEl.textContent='Lista no disponible';return;
  }
  if(countEl)countEl.textContent=list.length+" título"+(list.length!==1?"s":"");
  if(!list.length){
    container.innerHTML='<div class="ml-empty">'+
      '<div class="ml-empty-icon" aria-hidden="true"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg></div>'+
      '<div class="ml-empty-title">Tu lista est\\xe1 vac\\xeda</div>'+
      '<div class="ml-empty-sub">Usa el botón Guardar de cada ficha para recordar las películas y series que quieres ver. Las encontrarás aquí, en este navegador.</div>'+
      '<a href="/explore" class="ml-empty-btn">Explorar cat\\xe1logo</a>'+
    '</div>';
    return;
  }
  container.innerHTML='<div class="ml-grid">'+list.map(function(item){
    var poster=item.poster||"";
    var detailUrl='/?detail='+encodeURIComponent(item.imdbId||"")+'&title='+encodeURIComponent(item.title||"")+'&returnTo='+encodeURIComponent('/mylist?tab=mylist');
    return '<article class="ml-card"><a class="ml-card-link" href="'+_a(detailUrl)+'" title="'+_a(item.title||'Sin título')+'">'
      +'<span class="catalog-poster"><span class="catalog-poster-empty" aria-hidden="true">Sin cartel</span>'+(poster?'<img src="'+_a(poster)+'" alt="" loading="lazy">':'')+'</span>'
      +'<div class="ml-card-info"><div class="ml-card-title">'+_e(item.title||"Sin título")+'</div>'
      +'<div class="ml-card-meta">'+_e([item.year,item.type==='tv'||item.type==='series'?'Serie':item.type==='movie'?'Película':''].filter(Boolean).join(' · '))+'</div></div></a>'
      +'<button type="button" class="ml-card-remove" data-remove-imdb="'+_a(item.imdbId||"")+'" aria-label="Quitar '+_a(item.title||'título')+' de Guardados" title="Quitar de Guardados">&times;</button></article>';
  }).join("")+'</div>';
  container.querySelectorAll('img').forEach(function(img){img.addEventListener('error',function(){this.remove()})});
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
  var buttons=Array.from(document.querySelectorAll('[data-remove-imdb]'));
  var index=buttons.findIndex(function(button){return button.getAttribute('data-remove-imdb')===imdbId});
  try{
    list=readSavedList();
    var itemIndex=list.findIndex(function(x){return x&&x.imdbId===imdbId});
    var removed=itemIndex>=0?{item:list[itemIndex],index:itemIndex}:null;
    list=list.filter(function(x){return x&&x.imdbId!==imdbId});
    localStorage.setItem(KEY,JSON.stringify(list));
    removedItem=removed;
  }catch(e){document.getElementById('ml-notice').textContent='No se ha podido guardar el cambio. El título sigue en tu lista.';return}
  var notice=document.getElementById('ml-notice');
  notice.textContent='Título quitado de Guardados.';
  if(removedItem){var undo=document.createElement('button');undo.type='button';undo.className='ml-undo';undo.textContent='Deshacer';undo.onclick=undoRemove;notice.appendChild(undo)}
  renderMyList();
  var remaining=document.querySelectorAll('[data-remove-imdb]');
  var next=remaining[Math.min(index,remaining.length-1)]||document.querySelector('.ml-empty-btn');if(next)next.focus();
}
function undoRemove(){
  if(!removedItem)return;
  var item=removedItem.item;
  try{
    var list=readSavedList();
    if(!list.some(function(x){return x&&x.imdbId===item.imdbId}))list.splice(Math.min(removedItem.index,list.length),0,item);
    localStorage.setItem('ese_mylist',JSON.stringify(list));
  }catch(e){document.getElementById('ml-notice').textContent='No se ha podido restaurar el título. Inténtalo de nuevo desde su ficha.';return}
  removedItem=null;renderMyList();
  document.getElementById('ml-notice').textContent='Título restaurado en Guardados.';
  var restored=Array.from(document.querySelectorAll('[data-remove-imdb]')).find(function(button){return button.getAttribute('data-remove-imdb')===String(item.imdbId)});if(restored)restored.focus();
}
renderMyList();

// v7.4.0 \u2014 tabs + downloads panel
var _dlTimer = null;
var _dlBusy = false;
var _dlSignature = null;
var _activeTab = 'mylist';
var _files=null;
var _filesRequest=0;
var _filesAbort=null;
function tabFromUrl(){var tab=new URLSearchParams(window.location.search).get('tab');return tab==='files'||tab==='downloads'?tab:'mylist'}
function switchTab(name,fromHistory) {
  if(name!=='files'&&name!=='downloads')name='mylist';
  if(!fromHistory&&name!==_activeTab)history.pushState(null,'','/mylist?tab='+name);
  _activeTab=name;
  document.querySelectorAll('.ml-tab').forEach(function(t){
    t.classList.toggle('active', t.getAttribute('data-tab') === name);
    t.setAttribute('aria-pressed',String(t.getAttribute('data-tab') === name));
  });
  document.getElementById('ml-count').hidden=name!=='mylist';
  document.getElementById('ml-tab-mylist').style.display    = (name === 'mylist')    ? '' : 'none';
  document.getElementById('ml-tab-files').style.display = (name === 'files') ? '' : 'none';
  document.getElementById('ml-tab-downloads').style.display = (name === 'downloads') ? '' : 'none';
  if(name==='files')loadFiles();
  else {++_filesRequest;if(_filesAbort)_filesAbort.abort();}
  if (name === 'downloads') {
    renderDownloads();
    if (_dlTimer) clearInterval(_dlTimer);
    _dlTimer = setInterval(renderDownloads, 3000);
  } else if (_dlTimer) {
    clearInterval(_dlTimer); _dlTimer = null;
  }
}
function normalizeFileQuery(value){return String(value).normalize('NFD').replace(/[\\u0300-\\u036f]/g,'').toLowerCase()}
function renderFiles(){
  if(!_files)return;
  var query=normalizeFileQuery(document.getElementById('files-query').value.trim());
  var files=_files.filter(function(file){return normalizeFileQuery(file.fileName).indexOf(query)!==-1});
  document.getElementById('files-count').textContent=query?files.length+' de '+_files.length+' archivos':_files.length+' archivo'+(_files.length===1?'':'s')+' disponibles';
  var empty=document.getElementById('files-empty');empty.hidden=files.length>0;
  empty.innerHTML=query?'<h2 class="ml-empty-title">No hay archivos con ese nombre</h2><p class="ml-empty-sub">Prueba otro nombre o limpia el filtro.</p><button type="button" class="ml-empty-btn" onclick="clearFilesFilter()">Limpiar filtro</button>':'<h2 class="ml-empty-title">Todavía no hay archivos terminados</h2><p class="ml-empty-sub">Los vídeos de tu carpeta de entrada aparecerán aquí.</p><a href="/search" class="ml-empty-btn">Buscar en el catálogo</a>';
  document.getElementById('files-content').innerHTML=files.map(function(file){
    var size=Number(file.sizeMB);var sizeText=Number.isFinite(size)&&size>=0?(size>=1024?(size/1024).toFixed(1)+' GB':Math.round(size)+' MB'):'Tamaño no disponible';
    var playUrl='/?play='+encodeURIComponent(file.fileName)+'&returnTo='+encodeURIComponent('/mylist?tab=files');
    return '<a class="file-card" href="'+_a(playUrl)+'" aria-label="Reproducir '+_a(file.fileName)+'"><span class="file-icon" aria-hidden="true"><svg width="23" height="23" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="m10 8 6 4-6 4z"/></svg></span><span class="file-copy"><span class="file-name">'+_e(file.fileName)+'</span><span class="file-meta">Archivo local · '+_e(sizeText)+'</span><span class="file-play">Reproducir →</span></span></a>';
  }).join('');
}
function clearFilesFilter(){var input=document.getElementById('files-query');input.value='';renderFiles();input.focus()}
function loadFiles(){
  if(_activeTab!=='files')return;
  var request=++_filesRequest;if(_filesAbort)_filesAbort.abort();
  _filesAbort=new AbortController();
  var notice=document.getElementById('files-notice');var content=document.getElementById('files-content');var refresh=document.getElementById('files-refresh');
  notice.textContent=_files?'Actualizando archivos…':'Cargando archivos…';content.setAttribute('aria-busy','true');refresh.disabled=true;
  fetch('/api/stream/completed/list',{signal:_filesAbort.signal}).then(function(r){if(!r.ok)throw new Error('Files unavailable');return r.json()}).then(function(files){
    if(request!==_filesRequest||_activeTab!=='files')return;
    if(!Array.isArray(files)||files.some(function(file){return !file||typeof file.fileName!=='string'||!file.fileName||file.fileName==='.'||file.fileName==='..'||file.fileName.indexOf('/')!==-1||file.fileName.indexOf(String.fromCharCode(92))!==-1||file.fileName.indexOf(String.fromCharCode(0))!==-1}))throw new Error('Invalid files');
    _files=files;notice.textContent='';renderFiles();
  }).catch(function(error){
    if(request!==_filesRequest||_activeTab!=='files'||error.name==='AbortError')return;
    notice.textContent=_files?'No se han podido actualizar los archivos. Se conserva la última lista. Pulsa Actualizar para reintentar.':'No se han podido cargar los archivos. Pulsa Actualizar para reintentar.';
  }).finally(function(){if(request===_filesRequest){content.setAttribute('aria-busy','false');refresh.disabled=false}});
}
function renderDownloads() {
  if(_dlBusy||_activeTab!=='downloads')return;
  _dlBusy=true;
  var host=document.getElementById('downloads-content');
  if(!host.innerHTML)host.innerHTML='<div class="dl-empty" role="status">Cargando descargas...</div>';
  host.setAttribute('aria-busy','true');
  fetch('/api/emule/downloads').then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();}).then(function(downloads) {
    var host = document.getElementById('downloads-content');
    if (!host) return;
    if(!Array.isArray(downloads))throw new Error('Invalid download response');
    document.getElementById('dl-connection-notice').textContent='';
    var signature=JSON.stringify(downloads);
    if(signature===_dlSignature)return;
    _dlSignature=signature;
    if (!downloads.length) {
      host.innerHTML = '<div class="ml-empty" role="status"><h2 class="ml-empty-title">No hay descargas en esta lista</h2><p class="ml-empty-sub">Cuando añadas un título a descargar, podrás consultar aquí su estado.</p><a class="ml-empty-btn" href="/search">Buscar en el catálogo</a></div>';
      return;
    }
    var focused=document.activeElement;
    var focusHash=host.contains(focused)?focused.getAttribute('data-hash'):null;
    var focusOp=focusHash?(focused.getAttribute('data-dl-op')||'cancel'):null;
    var rows = downloads.map(function(dl) {
      // sizeBytes is the current .part size, not a total or completed-byte count.
      var fullSize = Number(dl.totalSizeBytes)>0 ? Math.round(Number(dl.totalSizeBytes) / 1048576) : 0;
      var sizeMB = Number.isFinite(Number(dl.sizeMB)) ? Math.max(0,Number(dl.sizeMB)) : 0;
      var hasProgress=Number(dl.totalSizeBytes)>0&&Number.isFinite(Number(dl.completedBytes))&&dl.completedBytes!==null;
      var pct = hasProgress ? Math.max(0,Math.min(100,Math.round(Number(dl.completedBytes)/Number(dl.totalSizeBytes)*100))) : 0;
      var stateClass = dl.active ? 'dl-active' : 'dl-paused';
      return '<div class="dl-row ' + stateClass + '">' +
        '<div class="dl-name" title="' + _a(dl.fileName || '') + '">' + _e(dl.fileName || 'Sin nombre') + '<span class="dl-status">'+(dl.active?'Actividad reciente':'Sin actividad reciente')+'</span></div>' +
        (hasProgress?'<div class="dl-bar-wrap" role="progressbar" aria-label="Progreso de descarga" aria-valuemin="0" aria-valuemax="100" aria-valuenow="'+pct+'"><div class="dl-bar" style="width:' + pct + '%"></div></div>':'<span class="dl-progress-unknown">Progreso no disponible</span>') +
        '<div class="dl-meta">' + (hasProgress ? Math.round(Number(dl.completedBytes)/1048576)+' / '+fullSize+' MB recibidos · '+pct+'%' : sizeMB+' MB de archivo parcial') + '</div>' +
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
    host.querySelectorAll('.dl-actions button').forEach(function(button){
      button.setAttribute('aria-label',button.title);
      if(!button.getAttribute('data-hash')){button.disabled=true;button.title='Control de esta descarga no disponible';}
      if(focusHash===button.getAttribute('data-hash')&&focusOp===(button.getAttribute('data-dl-op')||'cancel'))button.focus();
    });
  }).catch(function(){
    document.getElementById('dl-connection-notice').textContent='No se ha podido actualizar la conexión con eMule. Se reintentará automáticamente.';
    if(_dlSignature===null)host.innerHTML='';
  }).finally(function(){_dlBusy=false;host.setAttribute('aria-busy','false')});
}
function dlAct(hash, op) {
  if (!hash) return;
  document.getElementById('dl-action-notice').textContent='Aplicando cambio...';
  // v7.5.0 — X-Requested-With header marks this as same-origin fetch (CSRF defence).
  fetch('/api/emule/download/action?hash=' + encodeURIComponent(hash) + '&op=' + op,
        { headers: { 'X-Requested-With': 'eSE' } })
    .then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json();})
    .then(function(d){
      if(!d||d.success!==true)throw new Error('Action failed');
      document.getElementById('dl-action-notice').textContent='Cambio aplicado.';renderDownloads();
    }).catch(function(){document.getElementById('dl-action-notice').textContent='No se ha podido aplicar el cambio. Vuelve a intentarlo.'});
}
function dlCancel(hash, name) {
  if (!hash) return;
  if (!confirm('\\u00bfCancelar "' + name + '" y borrar archivos parciales?')) return;
  dlAct(hash,'cancel');
}
window.switchTab  = switchTab;
window.dlAct      = dlAct;
window.dlCancel   = dlCancel;
window.renderDownloads = renderDownloads;
document.getElementById('files-query').addEventListener('input',renderFiles);
document.getElementById('files-refresh').addEventListener('click',loadFiles);
window.addEventListener('popstate',function(){switchTab(tabFromUrl(),true)});
window.addEventListener('pagehide',function(){++_filesRequest;if(_filesAbort)_filesAbort.abort();if(_dlTimer)clearInterval(_dlTimer)});
window.addEventListener('pageshow',function(event){if(event.persisted)switchTab(tabFromUrl(),true)});
switchTab(tabFromUrl(),true);
`;

  return navbar.getHead('Biblioteca \u2014 eSE', mlCSS + catalogStyle) +
  navbar.getHTML('mylist') +
  '<main class="ml-page" id="main-content">' +
  '<div class="catalog-heading"><div class="catalog-heading-copy"><p class="ml-eyebrow">Tu colección</p>' +
  '<div class="ml-header"><h1 class="ml-title">Biblioteca</h1><span id="ml-count" class="ml-count"></span></div>' +
  '<p class="ml-subtitle">Tus archivos, títulos guardados y descargas, en un mismo lugar.</p></div><a class="catalog-link" href="/explore">Explorar catálogo <span aria-hidden="true">↗</span></a></div>' +
  '<div class="ml-tabs" aria-label="Secciones de Biblioteca">' +
    '<button class="ml-tab" data-tab="files" aria-pressed="false" aria-controls="ml-tab-files" onclick="switchTab(\'files\')">Archivos</button>' +
    '<button class="ml-tab active" data-tab="mylist" aria-pressed="true" aria-controls="ml-tab-mylist" onclick="switchTab(\'mylist\')">Guardados</button>' +
    '<button class="ml-tab" data-tab="downloads" aria-pressed="false" aria-controls="ml-tab-downloads" onclick="switchTab(\'downloads\')">Descargas</button>' +
  '</div>' +
  '<div id="ml-tab-files" style="display:none"><p class="ml-panel-intro">Vídeos terminados en este equipo. Elige un archivo para reproducirlo.</p><div class="files-toolbar"><div class="files-search"><label for="files-query">Buscar en tus archivos</label><input id="files-query" type="search" placeholder="Nombre del archivo" autocomplete="off" aria-describedby="files-count"></div><button type="button" class="files-refresh" id="files-refresh">Actualizar</button></div><p id="files-count" class="files-count" role="status"></p><p id="files-notice" class="dl-notice" role="status"></p><div id="files-content" class="files-grid"></div><div id="files-empty" class="ml-empty files-empty" hidden></div></div>' +
  '<div id="ml-tab-mylist"><p class="ml-panel-intro"><strong>Guardar un título no lo descarga.</strong> Tus favoritos se conservan en este navegador.</p><p id="ml-notice" class="dl-notice" role="status"></p><div id="ml-content"></div></div>' +
  '<div id="ml-tab-downloads" style="display:none"><p class="ml-panel-intro">El estado se actualiza automáticamente. Los archivos terminados están en <a href="/mylist?tab=files" style="color:#ffb4a5">Archivos</a>.</p><p id="dl-connection-notice" class="dl-notice" role="status"></p><p id="dl-action-notice" class="dl-notice" role="status"></p><div id="downloads-content"></div></div>' +
  '</main>' +
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
