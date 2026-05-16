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
  '.ml-empty-btn:hover{opacity:.85}';

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
    var safeImdbId=_a(item.imdbId||"");
    var safeTitle=_a(item.title||"");
    return '<div class="ml-card" onclick="window.location.href=\\'/?detail='+safeImdbId+'&title='+encodeURIComponent(item.title||"")+'\\'">'
      +(poster?'<img src="'+_a(poster)+'" alt="" loading="lazy">':'<div style="width:100%;aspect-ratio:2/3;background:#1a1a2e"></div>')
      +'<button class="ml-card-remove" onclick="event.stopPropagation();removeItem(\\''+safeImdbId+'\\')">\u2716</button>'
      +'<div class="ml-card-info"><div class="ml-card-title">'+_e(item.title||"")+'</div>'
      +'<div class="ml-card-meta">'+_e(item.year||"")+(item.type==="tv"?" \\u00b7 Serie":"")+'</div></div></div>';
  }).join("")+'</div>';
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
`;

  return navbar.getHead('Mi Lista \u2014 eSE', mlCSS) +
  navbar.getHTML('mylist') +
  '<div class="ml-page">' +
  '<div class="ml-header"><h1 class="ml-title">Mi Lista</h1><span id="ml-count" class="ml-count"></span></div>' +
  '<div id="ml-content"></div>' +
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
