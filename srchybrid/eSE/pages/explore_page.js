// filepath: pages/explore_page.js
'use strict';
const navbar = require('../shared/navbar');
const catalogStyle = require('../shared/catalog_style');

let _ctx = null;
function init(ctx) { _ctx = ctx; }

// ── Genre definitions ──────────────────────────────────────────────────────────
const GENRES = [
  { id: 'all',    label: 'Todos',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',  tmdbGenre: null,  type: 'movie' },
  { id: 'movie',  label: 'Pel\u00edculas', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"></rect><line x1="7" y1="2" x2="7" y2="22"></line><line x1="17" y1="2" x2="17" y2="22"></line><line x1="2" y1="12" x2="22" y2="12"></line><line x1="2" y1="7" x2="7" y2="7"></line><line x1="2" y1="17" x2="7" y2="17"></line><line x1="17" y1="17" x2="22" y2="17"></line><line x1="17" y1="7" x2="22" y2="7"></line></svg>', tmdbGenre: null,  type: 'movie' },
  { id: 'tv',     label: 'Series',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg>', tmdbGenre: null,  type: 'tv'    },
  { id: 'doc',    label: 'Documentales',    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>', tmdbGenre: 99,    type: 'movie' },
  { id: 'anim',   label: 'Animación',        icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>', tmdbGenre: 16,    type: 'movie' },
  { id: 'horror', label: 'Terror',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>', tmdbGenre: 27,    type: 'movie' },
  { id: 'scifi',  label: 'Sci-Fi',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"></circle><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"></path></svg>', tmdbGenre: 878,   type: 'movie' },
  { id: 'comedy', label: 'Comedia',         icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M8 13s1.5 2 4 2 4-2 4-2"></path><line x1="9" y1="9" x2="9.01" y2="9"></line><line x1="15" y1="9" x2="15.01" y2="9"></line></svg>', tmdbGenre: 35,    type: 'movie' },
  { id: 'drama',  label: 'Drama',           icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>', tmdbGenre: 18,    type: 'movie' },
  { id: 'action', label: 'Acci\u00f3n',     icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>', tmdbGenre: 28,    type: 'movie' },
];

// ── Sections per category ──────────────────────────────────────────────────────
function buildSections(genreId) {
  const g = GENRES.find(x => x.id === genreId) || GENRES[0];
  const type = g.type;
  const genreParam = g.tmdbGenre ? '&with_genres=' + g.tmdbGenre : '';
  const base = '/api/tmdb/';
  const key = '?language=es-ES&page=1';

  if (genreId === 'all') {
    return [
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Tendencias de la semana', url: base + 'trending/all/week' + key },
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="#f5c518" stroke="none" style="vertical-align:-2px;margin-right:6px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg> Mejor valoradas', url: base + 'movie/top_rated' + key },
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Estrenos recientes', url: base + 'movie/now_playing' + key },
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><rect x="2" y="7" width="20" height="15" rx="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg> Series populares', url: base + 'tv/popular' + key },
    ];
  }
  if (genreId === 'tv') {
    return [
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Series del momento', url: base + 'tv/popular' + key },
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="#f5c518" stroke="none" style="vertical-align:-2px;margin-right:6px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg> Mejor valoradas', url: base + 'tv/top_rated' + key },
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> En emisión', url: base + 'tv/on_the_air' + key },
    ];
  }
  return [
    { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg> Populares', url: base + 'discover/' + type + key + '&sort_by=popularity.desc' + genreParam + '&include_adult=false' },
    { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="#f5c518" stroke="none" style="vertical-align:-2px;margin-right:6px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg> Mejor valoradas', url: base + 'discover/' + type + key + '&sort_by=vote_average.desc&vote_count.gte=300' + genreParam + '&include_adult=false' },
    { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Recientes', url: base + 'discover/' + type + key + '&sort_by=release_date.desc&vote_count.gte=50' + genreParam + '&include_adult=false' },
  ];
}

// ── Inline JS (template literal — no escape issues) ────────────────────────────
function getInlineJS(sectionsJSON) {
  return `
var SECTIONS=${sectionsJSON};
var currentCat="all";
var sectionRequest=0;
function _e(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function _a(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function switchCategory(cat){
  if(!Object.prototype.hasOwnProperty.call(SECTIONS,cat))cat='all';
  currentCat=cat;
  history.replaceState(null,'','/explore'+(cat==='all'?'':'?cat='+encodeURIComponent(cat)));
  var genreSelected=cat!=='all'&&cat!=='movie'&&cat!=='tv';
  var label='';
  document.querySelectorAll(".ex-chip").forEach(function(c){
    var active=c.dataset.cat===cat||(genreSelected&&c.dataset.cat==='movie');
    c.classList.toggle("active",active);c.setAttribute("aria-pressed",String(active));
    if(c.dataset.cat===cat)label=c.textContent.trim();
  });
  document.getElementById('ex-filter-status').textContent='Selección: '+(genreSelected?'Películas · ':'')+label;
  loadSections(cat);
}

function loadSections(cat){
  var request=++sectionRequest;
  var container=document.getElementById("ex-content");
  var sections=SECTIONS[cat];
  if(!sections){container.innerHTML="<p>Categor\\xeda no encontrada</p>";return}
  container.innerHTML=sections.map(function(s,i){
    var label=_a(s.title.replace(/<[^>]*>/g,'').trim());
    return '<section class="ex-section" aria-labelledby="section-title-'+i+'"><div class="ex-section-head"><h2 class="ex-section-title" id="section-title-'+i+'">'+s.title+'</h2>'+
      '<div class="ex-carousel-controls"><button class="ex-scroll-btn left" id="carousel-prev-'+i+'" aria-label="Anteriores: '+label+'" aria-controls="carousel-'+i+'" onclick="scrollCarousel('+i+',-1)" disabled>&lsaquo;</button>'+
      '<button class="ex-scroll-btn right" id="carousel-next-'+i+'" aria-label="Siguientes: '+label+'" aria-controls="carousel-'+i+'" onclick="scrollCarousel('+i+',1)" disabled>&rsaquo;</button></div></div>'+
      '<div class="ex-scroll-wrap">'+
      '<div class="ex-carousel" id="carousel-'+i+'" aria-busy="true"><div class="ex-loading" role="status"><div class="ex-spinner" aria-hidden="true"></div>Cargando títulos...</div></div>'+
      '</div></section>'
  }).join("");
  sections.forEach(function(s,i){
    document.getElementById('carousel-'+i).addEventListener('scroll',function(){updateCarouselControls(i)},{passive:true});
    fetch(s.url).then(function(r){if(!r.ok)throw new Error('HTTP '+r.status);return r.json()}).then(function(data){
      if(request!==sectionRequest)return;
      if(!Array.isArray(data.results))throw new Error('Invalid catalog response');
      var items=data.results.filter(function(m){return m.media_type!=="person"});
      var el=document.getElementById("carousel-"+i);
      if(!el)return;
      el.setAttribute('aria-busy','false');
      if(!items.length){el.innerHTML='<div class="ex-state" role="status">Todavía no hay títulos en esta selección.</div>';return}
      el.innerHTML=items.map(function(m){
        var poster=m.poster_path?"https://image.tmdb.org/t/p/w342"+_a(m.poster_path):"";
        var title=m.title||m.name||"";
        var year=(m.release_date||m.first_air_date||"").slice(0,4);
        var rating=Number(m.vote_average)>0?Number(m.vote_average).toFixed(1):"";
        var mediaType=m.media_type||(m.first_air_date?"tv":"movie");
        return '<button type="button" class="ex-card" data-id="'+_a(m.id)+'" data-type="'+_a(mediaType)+'" data-title="'+_a(title)+'" title="Ver ficha de '+_a(title)+'" aria-label="Ver ficha de '+_a(title)+'">'
          +'<span class="catalog-poster"><span class="catalog-poster-empty" aria-hidden="true">Sin cartel</span>'+(poster?'<img src="'+poster+'" alt="" loading="lazy">':'')+'</span>'
          +(rating?'<div class="ex-card-rating">\\u2605 '+_e(rating)+'</div>':'')
          +'<div class="ex-card-info"><div class="ex-card-title">'+_e(title)+'</div>'
          +'<div class="ex-card-meta">'+_e((year?year+' · ':'')+(mediaType==="tv"?"Serie":"Película"))+'</div></div></button>'
      }).join("");
      el.querySelectorAll('.ex-card').forEach(function(card){
        card.addEventListener('click',function(){openTMDB(card.dataset.id,card.dataset.type,card.dataset.title,card)});
        var img=card.querySelector('img');if(img)img.addEventListener('error',function(){this.remove()});
      });
      updateCarouselControls(i);
    }).catch(function(){
      if(request!==sectionRequest)return;
      var el=document.getElementById("carousel-"+i);
      if(el){el.setAttribute('aria-busy','false');el.innerHTML='<div class="ex-state" role="status">No se ha podido cargar esta selección. <button type="button" class="ex-retry">Reintentar</button></div>';el.querySelector('.ex-retry').onclick=function(){loadSections(currentCat)}};
    });
  });
}

function scrollCarousel(idx,dir){
  var el=document.getElementById("carousel-"+idx);
  if(el)el.scrollBy({left:dir*el.clientWidth*.85,behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?"auto":"smooth"});
}
function updateCarouselControls(idx){
  var el=document.getElementById('carousel-'+idx);if(!el)return;
  document.getElementById('carousel-prev-'+idx).disabled=el.scrollLeft<=2;
  document.getElementById('carousel-next-'+idx).disabled=el.scrollLeft+el.clientWidth>=el.scrollWidth-2;
}
window.addEventListener('resize',function(){(SECTIONS[currentCat]||[]).forEach(function(_,i){updateCarouselControls(i)})});
window.addEventListener('pageshow',function(){document.getElementById('ex-open-status').textContent=''});

function openTMDB(tmdbId,mediaType,title,card){
  if(!/^[1-9][0-9]{0,9}$/.test(String(tmdbId))||(mediaType!=='movie'&&mediaType!=='tv'))return;
  document.getElementById('ex-open-status').textContent='Abriendo ficha de '+title+'…';
  var returnTo=encodeURIComponent('/explore'+(currentCat==='all'?'':'?cat='+encodeURIComponent(currentCat)));
  window.location.href='/?detail='+encodeURIComponent('tmdb:'+mediaType+':'+tmdbId)+'&title='+encodeURIComponent(title)+'&returnTo='+returnTo;
}

switchCategory(new URLSearchParams(window.location.search).get('cat')||'all');
`;
}

// ── HTML generation ────────────────────────────────────────────────────────────
function getHTML() {
  const makeChips = genres => genres.map(g =>
    '<button class="ex-chip' + (g.id === 'all' ? ' active' : '') +
    '" aria-pressed="' + (g.id === 'all') + '" data-cat="' + g.id + '" onclick="switchCategory(\'' + g.id + '\')">' +
    g.icon + ' ' + g.label + '</button>'
  ).join('');
  const chipsHTML='<div class="ex-filter-group"><span class="ex-filter-label">Contenido</span><div class="ex-chips" role="group" aria-label="Tipo de contenido">'+makeChips(GENRES.filter(g=>!g.tmdbGenre))+'</div></div>'+
    '<div class="ex-filter-group"><span class="ex-filter-label">Géneros de cine</span><div class="ex-chips" role="group" aria-label="Géneros de películas">'+makeChips(GENRES.filter(g=>g.tmdbGenre))+'</div></div>';

  const sectionsJSON = JSON.stringify(
    GENRES.reduce((acc, g) => { acc[g.id] = buildSections(g.id); return acc; }, {})
  );

  // ── Explore-specific CSS ──
  const exCSS =
  '.ex-page{padding:40px var(--ese-page-padding,40px) 80px;max-width:1920px;margin:auto}' +
  '.ex-eyebrow{color:#ff927d;font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:12px}' +
  '.ex-title{font-size:clamp(32px,4vw,46px);line-height:1.1;letter-spacing:-1.5px;font-weight:800;color:#fff;margin-bottom:12px}' +
  '.ex-subtitle{color:#aeb0bf;line-height:1.6;font-size:15px;margin-bottom:28px}' +
  '.ex-filters{display:flex;flex-wrap:wrap;gap:20px 32px;margin-bottom:16px}.ex-filter-group{min-width:0}.ex-filter-label{display:block;font-size:12px;color:#aeb0bf;margin-bottom:10px}.ex-filter-status{font-size:12px;color:#aeb0bf;min-height:18px;margin-bottom:22px}' +
  '.ex-chips{display:flex;flex-wrap:wrap;gap:8px}' +
  '.ex-chip{display:inline-flex;align-items:center;gap:6px;min-height:44px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);color:#c4c5ce;padding:10px 17px;border-radius:24px;font-size:13px;font-weight:600;cursor:pointer;transition:background .2s,color .2s;font-family:inherit}' +
  '.ex-chip:hover{background:rgba(255,107,53,.1);border-color:rgba(255,107,53,.3);color:#ff6b35}' +
  '.ex-chip.active{background:#ff806b;border-color:#ff806b;color:#191013}' +
  '.ex-section{margin-bottom:40px}' +
  '.ex-section-head{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:18px}.ex-carousel-controls{display:flex;flex-shrink:0;gap:8px}' +
  '.ex-section-title{font-size:21px;letter-spacing:-.4px;font-weight:700;color:#f2f1f5;line-height:1.35}' +
  '.ex-carousel{display:flex;gap:20px;overflow-x:auto;scroll-behavior:smooth;padding:6px 4px 14px;margin:-6px -4px 0;scrollbar-width:thin;scrollbar-color:#393944 transparent;scroll-snap-type:x proximity}' +
  '.ex-card{flex:0 0 clamp(154px,12.5vw,220px);min-width:0;cursor:pointer;transition:transform .2s;position:relative;border:0;background:none;color:inherit;font:inherit;text-align:left;border-radius:10px;scroll-snap-align:start;align-self:flex-start}' +
  '.ex-card:hover{transform:translateY(-4px)}' +
  '.ex-card img,.ex-poster-empty{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#1b1b27;border-radius:10px;border:1px solid #ffffff12}' +
  '.ex-poster-empty{display:flex;align-items:center;justify-content:center;color:#aeb0bf;font-size:13px}' +
  '.ex-card-info{padding:12px 2px 4px}' +
  '.ex-card-title{font-size:14px;font-weight:600;color:#f2f1f5;line-height:1.45;overflow-wrap:anywhere}' +
  '.ex-card-meta{font-size:12px;line-height:1.5;color:#aeb0bf;margin-top:5px}' +
  '.ex-card-rating{position:absolute;top:10px;right:10px;background:rgba(10,10,15,.88);color:#f1d58a;font-size:11px;font-weight:700;padding:5px 7px;border-radius:5px}' +
  '.ex-loading,.ex-state{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;min-height:180px;width:100%;padding:32px;gap:12px;color:#b2b3c0;font-size:14px;line-height:1.6}' +
  '.ex-retry{font:inherit;color:#ff9a88;background:#ffffff09;border:1px solid #ffffff24;padding:9px 16px;border-radius:8px;cursor:pointer}' +
  '.ex-spinner{width:24px;height:24px;border:3px solid #333;border-top-color:#ff6b35;border-radius:50%;animation:spin .8s linear infinite}' +
  '@keyframes spin{to{transform:rotate(360deg)}}' +
  '.ex-scroll-wrap{position:relative}' +
  '.ex-scroll-btn{width:44px;height:44px;background:#ffffff06;border:1px solid #ffffff24;border-radius:50%;color:#e8e7ed;font-size:28px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background .2s}' +
  '.ex-scroll-btn:hover:not(:disabled){background:#ffffff12;border-color:#ff927d}.ex-scroll-btn:disabled{opacity:.3;cursor:default}' +
  '.ex-page :focus-visible{outline:2px solid #ffa18f;outline-offset:4px}' +
  '@media(max-width:760px){.ex-page{padding:28px 20px 60px}.ex-title{letter-spacing:-1px}.ex-filters{display:block}.ex-filter-group+.ex-filter-group{margin-top:18px}.ex-chips{flex-wrap:nowrap;overflow-x:auto;padding:4px 4px 10px;margin:-4px -4px 0}.ex-chip{flex-shrink:0}.ex-carousel{gap:14px}.ex-card{flex-basis:150px}.ex-section-head{gap:12px}.ex-section-title{font-size:18px}}' +
  '@media(prefers-reduced-motion:reduce){.ex-card,.ex-chip{transition:none}.ex-carousel{scroll-behavior:auto}.ex-spinner{animation:none}}';

  return navbar.getHead('Explorar \u2014 eSE', exCSS + catalogStyle) +
  navbar.getHTML('explore') +
  '<main class="ex-page" id="main-content">' +
  '<div class="catalog-heading"><div class="catalog-heading-copy"><p class="ex-eyebrow">Catálogo</p>' +
  '<h1 class="ex-title">Explorar</h1>' +
  '<p class="ex-subtitle">Descubre películas y series. Elige una ficha para conocer sus detalles.</p></div><a class="catalog-link" href="/mylist?tab=files">Ir a mi biblioteca <span aria-hidden="true">↗</span></a></div>' +
  '<p class="catalog-context"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7v1"/></svg><span>Los títulos del catálogo <strong>no indican disponibilidad para reproducir</strong>. Tus archivos están en la biblioteca.</span></p>' +
  '<div class="ex-filters">' + chipsHTML + '</div><p class="ex-filter-status" id="ex-filter-status" role="status">Selección: Todos</p>' +
  '<div id="ex-content"><div class="ex-loading"><div class="ex-spinner"></div>Cargando cat&aacute;logo...</div></div>' +
  '<p class="catalog-open-status" id="ex-open-status" role="status"></p></main>' +
  '<script>' + getInlineJS(sectionsJSON) + '</script>' +
  '</body></html>';
}

// ── Route handler ──────────────────────────────────────────────────────────────
function handle(url, req, res) {
  if (url.pathname === '/explore') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(getHTML());
    return true;
  }
  return false;
}

module.exports = { init, handle };
