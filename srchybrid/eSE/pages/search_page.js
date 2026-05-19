'use strict';
const { TMDB_KEY } = require('../api_keys');

let _ctx = null;
function init(ctx) { _ctx = ctx; }

function handle(url, req, res) {
  // Full-page search (Disney+ style)
  if (url.pathname === '/search') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Buscar ââ¬â eSE</title><link rel="icon" href="/emule_mascot.svg" />
<!-- v8.0.1: Google Fonts CDN removed. Fallback chain in CSS uses system fonts. -->
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#fff;font-family:'Inter',system-ui,sans-serif;min-height:100vh}
.header{background:rgba(10,10,15,.95);position:fixed;top:0;left:0;right:0;z-index:100;padding:16px 40px;display:flex;align-items:center;gap:16px;backdrop-filter:blur(20px)}
.logo{font-size:22px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;cursor:pointer;text-decoration:none}
.search-wrap{flex:1;position:relative;max-width:800px}
.search-input{width:100%;padding:14px 20px 14px 48px;border-radius:12px;border:2px solid #222;background:rgba(255,255,255,.05);color:#fff;font-size:18px;font-family:inherit;outline:none;transition:border-color .3s}
.search-input:focus{border-color:#ff6b35}
.search-icon{position:absolute;left:16px;top:50%;transform:translateY(-50%);font-size:20px;color:#666}
.close-btn{background:none;border:none;color:#888;font-size:28px;cursor:pointer;padding:4px 12px;transition:color .2s}
.close-btn:hover{color:#fff}
.content{padding:90px 40px 40px}
.section-title{font-size:14px;color:#888;text-transform:uppercase;letter-spacing:2px;margin-bottom:20px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:20px}
.card{cursor:pointer;transition:all .3s;border-radius:12px;overflow:hidden;position:relative}
.card:hover{transform:scale(1.05);z-index:2}
.card:hover .card-overlay{opacity:1}
.card-img{width:100%;aspect-ratio:2/3;object-fit:cover;background:#1a1a2e;display:block;border-radius:12px}
.card-overlay{position:absolute;inset:0;background:linear-gradient(0deg,rgba(0,0,0,.9) 0%,transparent 50%);opacity:0;transition:opacity .3s;display:flex;flex-direction:column;justify-content:flex-end;padding:16px;border-radius:12px}
.card-title{font-size:14px;font-weight:700;margin-bottom:4px;line-height:1.3}
.card-meta{font-size:12px;color:#aaa;display:flex;flex-wrap:wrap;gap:4px;align-items:center}
.genre-pill{background:rgba(255,107,53,.15);color:#ff6b35;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}
.no-results{text-align:center;padding:80px 20px;color:#666;font-size:16px}
.trending-label{color:#ff6b35;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
@media(max-width:768px){.header{padding:12px 16px}.content{padding:80px 16px 16px}.grid{grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}.search-input{font-size:16px;padding:12px 16px 12px 44px}}
</style></head><body>
<div class="header">
<a class="logo" href="/">eSE</a>
<div class="search-wrap">
<span class="search-icon"></span>
<input class="search-input" id="q" type="text" placeholder="Buscar pel&#237;culas, series, documentales..." autofocus>
</div>
<button class="close-btn" onclick="location.href='/'">&#10005;</button>
</div>
<div class="content">
<div id="trending-section">
<div class="section-title"> Tendencias esta semana</div>
<div class="grid" id="trending-grid"></div>
</div>
<div id="results-section" style="display:none">
<div class="section-title" id="results-label">Resultados</div>
<div class="grid" id="results-grid"></div>
<div class="no-results" id="no-results" style="display:none">No se encontraron resultados</div>
</div>
</div>
<script>
var TMDB = '${TMDB_KEY}';
var GENRES = {};
var searchTimer = null;
function _e(s){return String(s).replace(/&/g,'\u0026amp;').replace(/</g,'\u0026lt;').replace(/>/g,'\u0026gt;').replace(/"/g,'\u0026quot;')}
function _a(s){return String(s).replace(/&/g,'\u0026amp;').replace(/"/g,'\u0026quot;').replace(/'/g,'\u0026#39;').replace(/</g,'\u0026lt;').replace(/>/g,'\u0026gt;')}

// Load genre map
fetch('https://api.themoviedb.org/3/genre/movie/list?api_key='+TMDB+'&language=es-ES')
  .then(function(r){return r.json()})
  .then(function(d){d.genres.forEach(function(g){GENRES[g.id]=g.name})});

// Load trending
fetch('https://api.themoviedb.org/3/trending/movie/week?api_key='+TMDB+'&language=es-ES')
  .then(function(r){return r.json()})
  .then(function(d){
    if(d.results) renderGrid('trending-grid', d.results);
  });

function renderGrid(containerId, movies) {
  var grid = document.getElementById(containerId);
  grid.innerHTML = '';
  movies.forEach(function(m) {
    if (!m.poster_path) return;
    var genres = (m.genre_ids||[]).slice(0,2).map(function(id){return GENRES[id]||''}).filter(Boolean);
    var rating = m.vote_average ? '⭐ ' + m.vote_average.toFixed(1) : '';
    var year = (m.release_date||'').substring(0,4);
    
    var card = document.createElement('div');
    card.className = 'card';
    card.onclick = function() { openMovie(m); };
    card.innerHTML = '<img class="card-img" src="https://image.tmdb.org/t/p/w342'+_a(m.poster_path)+'" alt="'+_a(m.title||m.name||'')+'" loading="lazy">' +
      '<div class="card-overlay">' +
      '<div class="card-title">'+_e(m.title||m.name)+'</div>' +
      '<div class="card-meta">' +
        (year ? '<span>'+_e(year)+'</span>' : '') +
        (rating ? '<span>'+_e(rating)+'</span>' : '') +
        genres.map(function(g){return '<span class="genre-pill">'+_e(g)+'</span>'}).join('') +
      '</div></div>';
    grid.appendChild(card);
  });
}

function openMovie(m) {
  var title = m.title || m.name;
  // Get IMDB ID directly from TMDB (more reliable than OMDB search)
  fetch('https://api.themoviedb.org/3/movie/'+m.id+'/external_ids?api_key='+TMDB)
    .then(function(r){return r.json()})
    .then(function(ids) {
      if (ids.imdb_id) {
        window.location.href = '/?detail=' + ids.imdb_id + '&ltitle=' + encodeURIComponent(title);
      } else {
        window.location.href = '/?search=' + encodeURIComponent(title);
      }
    })
    .catch(function() {
      window.location.href = '/?search=' + encodeURIComponent(title);
    });
}

// Live search with debounce
document.getElementById('q').addEventListener('input', function() {
  clearTimeout(searchTimer);
  var val = this.value.trim();
  if (val.length < 2) {
    document.getElementById('trending-section').style.display = '';
    document.getElementById('results-section').style.display = 'none';
    return;
  }
  searchTimer = setTimeout(function() {
    document.getElementById('trending-section').style.display = 'none';
    document.getElementById('results-section').style.display = '';
    document.getElementById('results-label').textContent = 'Resultados para "'+val+'"';
    
    fetch('https://api.themoviedb.org/3/search/movie?api_key='+TMDB+'&language=es-ES&query='+encodeURIComponent(val))
      .then(function(r){return r.json()})
      .then(function(d) {
        if (d.results && d.results.length > 0) {
          document.getElementById('no-results').style.display = 'none';
          renderGrid('results-grid', d.results);
        } else {
          document.getElementById('results-grid').innerHTML = '';
          document.getElementById('no-results').style.display = '';
        }
      });
  }, 300);
});
</script></body></html>`);
    return;
  }

  return false;
}

module.exports = { init, handle };
