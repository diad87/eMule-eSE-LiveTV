'use strict';
const navbar = require('../shared/navbar');
const catalogStyle = require('../shared/catalog_style');
let _ctx = null;
function init(ctx) { _ctx = ctx; }

function getHTML() {
  const css = `
.search-page{padding:40px var(--ese-page-padding,40px) 80px;max-width:1920px;margin:auto}
.search-eyebrow{color:#ff927d;font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px}
.search-title{font-size:clamp(32px,4vw,46px);line-height:1.1;letter-spacing:-1.5px;font-weight:800;color:#fff;margin-bottom:12px}
.search-subtitle{color:#aeb0bf;font-size:15px;line-height:1.6;margin-bottom:26px}
.search-form{max-width:920px;margin-bottom:30px}.search-entry{display:flex;align-items:stretch;gap:12px}.search-wrap{position:relative;flex:1;min-width:0}
.search-submit{padding:0 26px;min-height:48px;border:0;border-radius:10px;background:#ff806b;color:#191013;font:inherit;font-weight:700;cursor:pointer}.search-submit:hover{background:#ff9988}
.search-filters{display:flex;gap:8px;margin:20px 0 0}.search-filter{min-height:44px;padding:10px 17px;border:1px solid #ffffff20;border-radius:24px;background:#ffffff05;color:#c4c5ce;font:inherit;font-size:13px;font-weight:600;cursor:pointer}.search-filter[aria-pressed="true"]{background:#ff806b;border-color:#ff806b;color:#191013}.search-filter:hover{border-color:#ff927d}
.search-results-summary{color:#aeb0bf;font-size:13px;line-height:1.5;margin:-8px 0 24px}.search-results-summary:empty{display:none}
.search-input{width:100%;min-height:62px;padding:16px 60px 16px 54px;border-radius:12px;border:1px solid #ffffff25;background:#15151f;color:#fff;font-size:18px;font-family:inherit;transition:border-color .2s}
.search-input::placeholder{color:#9395a5}.search-input:focus{border-color:#ff927d;outline:2px solid #ff927d;outline-offset:3px}.search-input::-webkit-search-cancel-button{display:none}
.search-symbol{position:absolute;left:20px;top:50%;transform:translateY(-50%);color:#b6b6c3;pointer-events:none}
.search-clear{position:absolute;right:8px;top:50%;transform:translateY(-50%);width:44px;height:44px;background:none;border:none;border-radius:8px;color:#bbbcc8;font-size:24px;cursor:pointer}
.search-clear:hover{background:#ffffff10;color:#fff}.search-clear[hidden]{display:none}
.search-hint{color:#aeb0bf;font-size:12px;line-height:1.5;margin-top:12px}
.search-section-title{font-size:21px;font-weight:700;letter-spacing:-.4px;color:#f2f1f5;margin-bottom:20px}
.search-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(164px,1fr));gap:28px 20px}
.search-card{position:relative;min-width:0;border:0;background:none;color:inherit;font:inherit;text-align:left;cursor:pointer;border-radius:10px;align-self:start;transition:transform .2s}
.search-card:hover{transform:translateY(-4px)}
.search-card-img,.search-poster-empty{width:100%;aspect-ratio:2/3;object-fit:cover;background:#1b1b27;display:block;border-radius:10px;border:1px solid #ffffff12}
.search-poster-empty{display:flex;align-items:center;justify-content:center;color:#aeb0bf;font-size:13px}
.search-card-info{padding:12px 2px 4px}.search-card-title{font-size:14px;font-weight:600;line-height:1.45;overflow-wrap:anywhere;color:#f2f1f5}
.search-card-meta{font-size:12px;color:#aeb0bf;line-height:1.5;margin-top:5px}
.search-rating{position:absolute;top:10px;right:10px;background:#0a0a0fe0;color:#f1d58a;font-size:11px;font-weight:700;padding:5px 7px;border-radius:5px}
.search-state{color:#b2b3c0;font-size:15px;line-height:1.7;padding:48px 24px;text-align:center;background:#ffffff03;border:1px solid #ffffff0f;border-radius:12px}
.search-state[hidden],.search-retry[hidden]{display:none}.search-retry{display:block;margin:16px auto 0;min-height:44px;padding:10px 18px;color:#ff9a88;background:#ffffff09;border:1px solid #ffffff24;border-radius:8px;font:inherit;cursor:pointer}#results-first{margin:0 0 20px}
.search-section-head{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px 20px;margin-bottom:18px}.search-section-head .search-section-title{margin:0}.search-section-head a{color:#ffb4a5;font-size:13px;padding:10px 0;text-decoration:none}
.search-more{display:block;margin:24px auto 0;min-height:44px;padding:12px 24px;border:1px solid #ffffff30;border-radius:8px;background:#ffffff08;color:#f2f1f5;font:inherit;font-weight:600;cursor:pointer}.search-more:hover{border-color:#ff927d}.search-more:disabled{opacity:.6;cursor:wait}.search-more[hidden]{display:none}.search-more-status{color:#b9bac6;font-size:13px;line-height:1.6;text-align:center;margin-top:16px}.search-more-status:empty{display:none}
.search-page :focus-visible{outline:2px solid #ffa18f;outline-offset:4px}
@media(max-width:760px){.search-page{padding:28px 20px 60px}.search-title{letter-spacing:-1px}.search-input{font-size:16px;padding-left:46px;min-height:56px}.search-symbol{left:16px}.search-entry{flex-wrap:wrap}.search-submit{width:100%}.search-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:24px 14px}.search-section-title{font-size:19px}}
@media(prefers-reduced-motion:reduce){.search-card,.search-input{transition:none}}
`;
  return navbar.getHead('Buscar — eSE', css + catalogStyle) + navbar.getHTML('search') + `
<main class="search-page" id="main-content">
<div class="catalog-heading"><div class="catalog-heading-copy"><p class="search-eyebrow">Catálogo</p>
<h1 class="search-title">Buscar</h1>
<p class="search-subtitle">Encuentra una película o una serie por su título.</p></div><a class="catalog-link" href="/mylist?tab=files">Ir a mi biblioteca <span aria-hidden="true">↗</span></a></div>
<p class="catalog-context"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/></svg><span>Busca fichas del catálogo. <strong>La disponibilidad para reproducir depende de tus archivos y fuentes.</strong></span></p>
<form class="search-form" role="search" id="search-form">
<div class="search-entry">
<div class="search-wrap">
<svg class="search-symbol" aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m17 17 4 4"/></svg>
<input class="search-input" id="q" type="search" placeholder="Películas, series, documentales..." aria-label="Buscar películas y series" aria-describedby="search-hint" autocomplete="off" autofocus>
<button class="search-clear" id="search-clear" type="button" aria-label="Borrar búsqueda" hidden>&times;</button>
</div>
<button class="search-submit" type="submit">Buscar</button></div>
<p class="search-hint" id="search-hint">Escribe al menos 2 caracteres para buscar en el catálogo.</p>
<div class="search-filters" role="group" aria-label="Tipo de contenido">
<button class="search-filter" type="button" data-type="multi" aria-pressed="true">Todos</button>
<button class="search-filter" type="button" data-type="movie" aria-pressed="false">Películas</button>
<button class="search-filter" type="button" data-type="tv" aria-pressed="false">Series</button>
</div>
</form>
<section id="trending-section" aria-labelledby="trending-label">
<div class="search-section-head"><h2 class="search-section-title" id="trending-label">Ideas para empezar</h2><a href="/explore">Explorar todo el catálogo →</a></div>
<div class="search-state" id="trending-state" role="status">Cargando tendencias...</div>
<div class="search-grid" id="trending-grid" aria-busy="true"></div>
</section>
<section id="results-section" aria-labelledby="results-label" hidden>
<h2 class="search-section-title" id="results-label">Resultados</h2>
<p class="search-results-summary" id="results-summary" role="status"></p>
<button class="search-retry" id="results-first" type="button" hidden>Volver a la primera página</button>
<div class="search-state" id="results-state" role="status" hidden></div>
<div class="search-grid" id="results-grid"></div>
<p class="search-more-status" id="results-more-status" role="status"></p>
<button class="search-more" id="results-more" type="button" hidden>Mostrar más</button>
</section>
<p class="catalog-open-status" id="search-open-status" role="status"></p></main>
<script>
var searchTimer=null;
var searchRequest=0;
var searchController=null;
var searchType='multi';
var searchPage=0;
var searchStartPage=1;
var searchTotalPages=0;
var searchBusy=false;
var searchSeen={};
var searchCount=0;
var trendingRequest=0;
var q=document.getElementById('q');
window.addEventListener('pageshow',function(){document.getElementById('search-open-status').textContent=''});
function _e(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function readResponse(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()}
function catalogItems(d){if(!Array.isArray(d.results))throw new Error('Invalid catalog response');return d.results.filter(function(m){return m.media_type!=='person'})}
function showState(prefix,message,retry){
  var state=document.getElementById(prefix+'-state');
  state.textContent=message;state.hidden=!message;
  if(retry){var button=document.createElement('button');button.type='button';button.className='search-retry';button.textContent='Reintentar';button.onclick=retry;state.appendChild(button)}
}
function renderGrid(containerId,movies,append,resultPage){
  var grid=document.getElementById(containerId);if(!append)grid.innerHTML='';
  var first=null;
  movies.forEach(function(m){
    var title=m.title||m.name||'Sin título';
    var type=m.media_type||(m.first_air_date?'tv':'movie');
    var year=(m.release_date||m.first_air_date||'').slice(0,4);
    var rating=Number(m.vote_average)>0?Number(m.vote_average).toFixed(1):'';
    var card=document.createElement('button');
    card.type='button';card.className='search-card';card.title='Ver ficha de '+title;card.setAttribute('aria-label','Ver ficha de '+title);
    card._resultPage=resultPage||1;
    card.onclick=function(){openMovie(m,card)};
    card.innerHTML='<span class="catalog-poster"><span class="catalog-poster-empty" aria-hidden="true">Sin cartel</span>'+(m.poster_path?'<img class="search-card-img" src="https://image.tmdb.org/t/p/w342'+_e(m.poster_path)+'" alt="" loading="lazy">':'')+'</span>'+
      (rating?'<span class="search-rating">★ '+_e(rating)+'</span>':'')+
      '<div class="search-card-info"><div class="search-card-title">'+_e(title)+'</div><div class="search-card-meta">'+
      _e((year?year+' · ':'')+(type==='tv'?'Serie':'Película'))+'</div></div>';
    grid.appendChild(card);
    if(!first)first=card;
    var img=card.querySelector('img');if(img)img.addEventListener('error',function(){this.remove()});
  });
  return first;
}
function loadTrending(){
  var request=++trendingRequest;
  var type=searchType==='multi'?'all':searchType;
  document.getElementById('trending-label').textContent=searchType==='multi'?'Ideas para empezar':searchType==='movie'?'Algunas películas para descubrir':'Algunas series para descubrir';
  showState('trending','Cargando tendencias...');
  var grid=document.getElementById('trending-grid');grid.innerHTML='';grid.setAttribute('aria-busy','true');
  fetch('/api/tmdb/trending/'+type+'/week?language=es-ES').then(readResponse).then(function(d){
    if(request!==trendingRequest)return;
    var items=catalogItems(d).slice(0,6);renderGrid('trending-grid',items);
    showState('trending',items.length?'':'No hay tendencias disponibles en este momento.');
  }).catch(function(){if(request===trendingRequest)showState('trending','No se han podido cargar las tendencias. Comprueba la conexión e inténtalo de nuevo.',loadTrending)}).finally(function(){if(request===trendingRequest)grid.setAttribute('aria-busy','false')});
}
function openMovie(m,card){
  var title=m.title||m.name||'';var type=m.media_type||((m.first_air_date||(!m.title&&m.name))?'tv':'movie');
  if(!/^[1-9][0-9]{0,9}$/.test(String(m.id))||(type!=='movie'&&type!=='tv'))return;
  document.getElementById('search-open-status').textContent='Abriendo ficha de '+title+'…';
  var returnTo=encodeURIComponent(searchReturnTo(card?card._resultPage:searchStartPage));
  window.location.href='/?detail='+encodeURIComponent('tmdb:'+type+':'+m.id)+'&title='+encodeURIComponent(title)+'&returnTo='+returnTo;
}
function searchReturnTo(page){
  var params=new URLSearchParams();
  if(q.value.trim())params.set('q',q.value.trim());
  if(searchType!=='multi')params.set('type',searchType);
  if((page||searchStartPage)>1)params.set('page',page||searchStartPage);
  return '/search'+(params.toString()?'?'+params.toString():'');
}
function updateSearch(immediate,startPage){
  clearTimeout(searchTimer);var request=++searchRequest;
  if(searchController)searchController.abort();
  searchStartPage=Number.isInteger(startPage)&&startPage>0&&startPage<=10000?startPage:1;
  searchPage=0;searchTotalPages=0;searchBusy=false;searchSeen={};searchCount=0;
  document.getElementById('results-more').hidden=true;
  document.getElementById('results-more-status').textContent='';
  document.getElementById('results-first').hidden=searchStartPage===1;
  var val=q.value.trim();document.getElementById('search-clear').hidden=!q.value;
  history.replaceState(null,'',searchReturnTo());
  document.getElementById('trending-section').hidden=val.length>=2;
  document.getElementById('results-section').hidden=val.length<2;
  document.getElementById('search-hint').textContent=val.length===1?'Escribe 1 carácter más para buscar.':'Escribe al menos 2 caracteres para buscar en el catálogo.';
  document.getElementById('results-summary').textContent='';
  var grid=document.getElementById('results-grid');grid.innerHTML='';grid.setAttribute('aria-busy','false');
  if(val.length<2)return;
  document.getElementById('results-label').textContent='Resultados para “'+val+'”';
  grid.setAttribute('aria-busy','true');
  showState('results','Buscando títulos...');
  searchTimer=setTimeout(function(){
    loadSearchPage(request,val,searchType,searchStartPage);
  },immediate?0:300);
}
function loadSearchPage(request,val,type,page){
  if(request!==searchRequest||searchBusy)return;
  var append=searchPage>0;
  searchBusy=true;
  searchController=new AbortController();
  var grid=document.getElementById('results-grid');var more=document.getElementById('results-more');
  grid.setAttribute('aria-busy','true');more.disabled=true;more.textContent='Cargando…';
  document.getElementById('results-more-status').textContent=append?'Cargando más títulos…':'';
  fetch('/api/tmdb/search/'+type+'?language=es-ES&include_adult=false&query='+encodeURIComponent(val)+'&page='+page,{signal:searchController.signal})
      .then(readResponse).then(function(d){
        if(request!==searchRequest)return;
        if(d.page!==undefined&&Number(d.page)!==page)throw new Error('Unexpected result page');
        var items=catalogItems(d).filter(function(item){
          var key=(item.media_type||(item.first_air_date?'tv':'movie'))+':'+item.id;
          if(searchSeen[key])return false;searchSeen[key]=true;return true;
        });
        var first=renderGrid('results-grid',items,append,page);
        searchPage=page;searchCount+=items.length;
        searchTotalPages=Number.isInteger(Number(d.total_pages))?Math.max(page,Number(d.total_pages)):page;
        document.getElementById('results-summary').textContent=searchCount?'Se muestran '+searchCount+' título'+(searchCount===1?'':'s')+'.'+(searchStartPage>1?' Desde la página '+searchStartPage+'.':''):'';
        showState('results',searchCount?'':'No encontramos títulos con ese nombre. Prueba con otro título o revisa la ortografía.');
        document.getElementById('results-more-status').textContent=append?(items.length?items.length+' títulos añadidos.':'No hay nuevos títulos en esta página.'):(searchCount===0&&searchTotalPages>page?'Puedes mostrar más páginas de resultados.':'');
        more.hidden=searchPage>=searchTotalPages;
        if(append&&document.activeElement===more){var destination=first||document.getElementById('results-summary');if(!first)destination.setAttribute('tabindex','-1');destination.focus();}
      }).catch(function(error){
        if(request!==searchRequest||error.name==='AbortError')return;
        if(!append)showState('results','No se ha podido completar la búsqueda. Comprueba la conexión e inténtalo de nuevo.',function(){updateSearch(true,searchStartPage)});
        else document.getElementById('results-more-status').textContent='No se han podido cargar más títulos. Los anteriores siguen disponibles. Pulsa Mostrar más para reintentar.';
      }).finally(function(){if(request===searchRequest){searchBusy=false;grid.setAttribute('aria-busy','false');more.disabled=false;more.textContent='Mostrar más'}});
}
document.getElementById('results-more').addEventListener('click',function(){if(searchPage<searchTotalPages)loadSearchPage(searchRequest,q.value.trim(),searchType,searchPage+1)});
document.getElementById('results-first').addEventListener('click',function(){updateSearch(true);q.focus()});
q.addEventListener('input',function(){updateSearch(false)});
document.getElementById('search-form').addEventListener('submit',function(e){e.preventDefault();updateSearch(true)});
document.getElementById('search-clear').addEventListener('click',function(){q.value='';updateSearch(true);q.focus()});
document.querySelectorAll('.search-filter').forEach(function(button){button.addEventListener('click',function(){
  if(searchType===button.dataset.type)return;
  searchType=button.dataset.type;
  document.querySelectorAll('.search-filter').forEach(function(filter){filter.setAttribute('aria-pressed',String(filter.dataset.type===searchType))});
  updateSearch(true);loadTrending();
})});
var initialParams=new URLSearchParams(window.location.search);
var initialType=initialParams.get('type');
if(initialType==='movie'||initialType==='tv')searchType=initialType;
document.querySelectorAll('.search-filter').forEach(function(filter){filter.setAttribute('aria-pressed',String(filter.dataset.type===searchType))});
var initialQuery=initialParams.get('q');
if(initialQuery){q.value=initialQuery;updateSearch(true,Number(initialParams.get('page')))}
loadTrending();
</script></body></html>`;
}

function handle(url, req, res) {
  if (url.pathname !== '/search') return false;
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(getHTML());
  return true;
}
module.exports = { init, handle };
