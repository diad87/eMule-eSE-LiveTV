// filepath: pages/explore_page.js
'use strict';
const navbar = require('../shared/navbar');
const { TMDB_KEY } = require('../api_keys');

let _ctx = null;
function init(ctx) { _ctx = ctx; }

// ── Genre definitions ──────────────────────────────────────────────────────────
const GENRES = [
  { id: 'all',    label: 'Todos',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>',  tmdbGenre: null,  type: 'movie' },
  { id: 'movie',  label: 'Pel\u00edculas', icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"></rect><line x1="7" y1="2" x2="7" y2="22"></line><line x1="17" y1="2" x2="17" y2="22"></line><line x1="2" y1="12" x2="22" y2="12"></line><line x1="2" y1="7" x2="7" y2="7"></line><line x1="2" y1="17" x2="7" y2="17"></line><line x1="17" y1="17" x2="22" y2="17"></line><line x1="17" y1="7" x2="22" y2="7"></line></svg>', tmdbGenre: null,  type: 'movie' },
  { id: 'tv',     label: 'Series',          icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="15" rx="2" ry="2"></rect><polyline points="17 2 12 7 7 2"></polyline></svg>', tmdbGenre: null,  type: 'tv'    },
  { id: 'doc',    label: 'Documentales',    icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>', tmdbGenre: 99,    type: 'movie' },
  { id: 'anim',   label: 'Infantil',        icon: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>', tmdbGenre: 16,    type: 'movie' },
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
  const base = 'https://api.themoviedb.org/3/';
  const key = '?api_key=' + TMDB_KEY + '&language=es-ES&page=1';

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
      { title: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> A\u00f1adidas recientemente', url: base + 'tv/on_the_air' + key },
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
function _e(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function _a(s){return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

function switchCategory(cat){
  currentCat=cat;
  document.querySelectorAll(".ex-chip").forEach(function(c){c.classList.toggle("active",c.dataset.cat===cat)});
  loadSections(cat);
}

function loadSections(cat){
  var container=document.getElementById("ex-content");
  var sections=SECTIONS[cat];
  if(!sections){container.innerHTML="<p>Categor\\xeda no encontrada</p>";return}
  container.innerHTML=sections.map(function(s,i){
    return '<div class="ex-section"><h2 class="ex-section-title">'+s.title+'</h2>'+
      '<div class="ex-scroll-wrap">'+
      '<button class="ex-scroll-btn left" onclick="scrollCarousel('+i+',-1)">&lsaquo;</button>'+
      '<div class="ex-carousel" id="carousel-'+i+'"><div class="ex-loading"><div class="ex-spinner"></div></div></div>'+
      '<button class="ex-scroll-btn right" onclick="scrollCarousel('+i+',1)">&rsaquo;</button>'+
      '</div></div>'
  }).join("");
  sections.forEach(function(s,i){
    fetch(s.url).then(function(r){return r.json()}).then(function(data){
      var items=data.results||[];
      var el=document.getElementById("carousel-"+i);
      if(!el)return;
      if(!items.length){el.innerHTML='<div style="color:#555;padding:20px">Sin resultados</div>';return}
      el.innerHTML=items.map(function(m){
        var poster=m.poster_path?"https://image.tmdb.org/t/p/w342"+_a(m.poster_path):"";
        var title=m.title||m.name||"";
        var year=(m.release_date||m.first_air_date||"").slice(0,4);
        var rating=m.vote_average?m.vote_average.toFixed(1):"";
        var mediaType=m.media_type||(m.first_air_date?"tv":"movie");
        var safe=_a(title);
        return '<div class="ex-card" onclick="openTMDB('+m.id+',\\''+_a(mediaType)+'\\',\\''+safe+'\\')">'
          +(poster?'<img src="'+poster+'" alt="" loading="lazy">':'<div style="width:170px;aspect-ratio:2/3;background:#1a1a2e;border-radius:10px"></div>')
          +(rating?'<div class="ex-card-rating">\\u2605 '+_e(rating)+'</div>':'')
          +'<div class="ex-card-info"><div class="ex-card-title">'+_e(title)+'</div>'
          +'<div class="ex-card-meta">'+_e(year)+(mediaType==="tv"?" \\u00b7 Serie":"")+'</div></div></div>'
      }).join("");
    }).catch(function(){
      var el=document.getElementById("carousel-"+i);
      if(el)el.innerHTML='<div style="color:#e74c3c;padding:20px">Error de conexi\\xf3n</div>';
    });
  });
}

function scrollCarousel(idx,dir){
  var el=document.getElementById("carousel-"+idx);
  if(el)el.scrollBy({left:dir*500,behavior:"smooth"});
}

function openTMDB(tmdbId,mediaType,title){
  var findUrl="https://api.themoviedb.org/3/"+mediaType+"/"+tmdbId+"/external_ids?api_key=${TMDB_KEY}";
  fetch(findUrl).then(function(r){return r.json()}).then(function(ids){
    if(ids.imdb_id){
      window.location.href="/?detail="+ids.imdb_id+"&title="+encodeURIComponent(title);
    }else{
      window.location.href="/?search="+encodeURIComponent(title);
    }
  }).catch(function(){
    window.location.href="/?search="+encodeURIComponent(title);
  });
}

loadSections("all");
`;
}

// ── HTML generation ────────────────────────────────────────────────────────────
function getHTML() {
  const chipsHTML = GENRES.map(g =>
    '<button class="ex-chip' + (g.id === 'all' ? ' active' : '') +
    '" data-cat="' + g.id + '" onclick="switchCategory(\'' + g.id + '\')">' +
    g.icon + ' ' + g.label + '</button>'
  ).join('');

  const sectionsJSON = JSON.stringify(
    GENRES.reduce((acc, g) => { acc[g.id] = buildSections(g.id); return acc; }, {})
  );

  // ── Explore-specific CSS ──
  const exCSS =
  '.ex-page{padding:24px 40px 80px}' +
  '.ex-title{font-size:32px;font-weight:800;color:#fff;margin-bottom:24px}' +
  '.ex-chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:32px}' +
  '.ex-chip{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#aaa;padding:8px 18px;border-radius:20px;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;font-family:Inter,sans-serif}' +
  '.ex-chip:hover{background:rgba(255,107,53,.1);border-color:rgba(255,107,53,.3);color:#ff6b35}' +
  '.ex-chip.active{background:linear-gradient(135deg,#ff6b35,#ff2d78);border-color:transparent;color:#fff}' +
  '.ex-section{margin-bottom:36px}' +
  '.ex-section-title{font-size:20px;font-weight:700;color:#fff;margin-bottom:14px;padding-left:4px}' +
  '.ex-carousel{display:flex;gap:14px;overflow-x:auto;scroll-behavior:smooth;padding-bottom:8px;-ms-overflow-style:none;scrollbar-width:none}' +
  '.ex-carousel::-webkit-scrollbar{display:none}' +
  '.ex-card{flex:0 0 170px;cursor:pointer;transition:all .3s;position:relative;border-radius:10px;overflow:hidden}' +
  '.ex-card:hover{transform:translateY(-6px) scale(1.03);box-shadow:0 12px 36px rgba(0,0,0,.5)}' +
  '.ex-card img{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#1a1a2e;border-radius:10px}' +
  '.ex-card-info{position:absolute;bottom:0;left:0;right:0;padding:10px;background:linear-gradient(transparent,rgba(0,0,0,.85));pointer-events:none}' +
  '.ex-card-title{font-size:12px;font-weight:600;color:#fff;line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
  '.ex-card-meta{font-size:10px;color:#aaa;margin-top:2px}' +
  '.ex-card-rating{position:absolute;top:8px;right:8px;background:rgba(0,0,0,.7);color:#ffd700;font-size:11px;font-weight:700;padding:2px 6px;border-radius:4px;backdrop-filter:blur(4px)}' +
  '.ex-loading{display:flex;align-items:center;justify-content:center;padding:60px;gap:12px;color:#555}' +
  '.ex-spinner{width:24px;height:24px;border:3px solid #333;border-top-color:#ff6b35;border-radius:50%;animation:spin .8s linear infinite}' +
  '@keyframes spin{to{transform:rotate(360deg)}}' +
  '.ex-scroll-wrap{position:relative}' +
  '.ex-scroll-btn{position:absolute;top:50%;transform:translateY(-50%);z-index:5;width:36px;height:36px;background:rgba(10,10,15,.85);border:1px solid rgba(255,255,255,.1);border-radius:50%;color:#fff;font-size:18px;cursor:pointer;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(8px);transition:all .2s;opacity:0}' +
  '.ex-scroll-wrap:hover .ex-scroll-btn{opacity:1}' +
  '.ex-scroll-btn:hover{background:rgba(255,107,53,.4);border-color:#ff6b35}' +
  '.ex-scroll-btn.left{left:-12px}' +
  '.ex-scroll-btn.right{right:-12px}';

  return navbar.getHead('Explorar \u2014 eSE', exCSS) +
  navbar.getHTML('explore') +
  '<div class="ex-page">' +
  '<h1 class="ex-title">Explorar</h1>' +
  '<div class="ex-chips">' + chipsHTML + '</div>' +
  '<div id="ex-content"><div class="ex-loading"><div class="ex-spinner"></div>Cargando cat&aacute;logo...</div></div>' +
  '</div>' +
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
