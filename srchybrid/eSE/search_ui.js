// search_ui.js — catálogo OMDb, búsqueda, modal de detalle, búsqueda eMule

// ── Traducción de géneros OMDB (siempre en inglés) al español ─────────────────
var GENRE_ES = {
  'Action':'Acción','Adventure':'Aventura','Animation':'Animación','Biography':'Biografía',
  'Comedy':'Comedia','Crime':'Crimen','Documentary':'Documental','Drama':'Drama',
  'Family':'Familia','Fantasy':'Fantasía','Film-Noir':'Cine negro','History':'Historia',
  'Horror':'Terror','Music':'Música','Musical':'Musical','Mystery':'Misterio',
  'Romance':'Romance','Sci-Fi':'Ciencia ficción','Short':'Corto','Sport':'Deporte',
  'Superhero':'Superhéroes','Thriller':'Thriller','War':'Guerra','Western':'Western'
};
function translateGenres(genreStr) {
  if (!genreStr || genreStr === 'N/A') return genreStr;
  return genreStr.split(',').map(function(g) {
    var t = g.trim();
    return GENRE_ES[t] || t;
  }).join(', ');
}

// ── Obtiene sinopsis en español de TMDB y la parchea en el DOM ────────────────
function patchSpanishPlot(imdbId) {
  var TMDB_KEY = window.ESE_TMDB_KEY || '2dca580c2a14b55200e784d157207b4d';fetch('https://api.themoviedb.org/3/find/' + imdbId + '?api_key=' + TMDB_KEY + '&language=es-ES&external_source=imdb_id')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var results = (data.movie_results || []).concat(data.tv_results || []);
      if (!results.length || !results[0].overview) return;
      var overview = results[0].overview;
      var plotEl = document.querySelector('#modal-info-zone .modal-plot');
      if (plotEl && overview) plotEl.textContent = overview;
    }).catch(function() {});
}

// ── Catálogo de películas (OMDb) ───────────────────────────────────────────────
function renderMovieCard(m) {
  // XSS-safe: all external API data is escaped before injection
  var poster = sanitizeURL((m.Poster && m.Poster !== 'N/A') ? m.Poster : '');
  var title = escapeHTML(m.Title || 'Sin titulo');
  var year = escapeHTML(m.Year || '');
  var imdbId = escapeAttr(m.imdbID || '');
  var safeTitle = escapeAttr(m.Title || 'Sin titulo');
  return '<div class="card" onclick="showMovieDetail(\'' + imdbId + '\',null,\'' + safeTitle + '\')">' +
    '<div class="card-poster"' + (poster ? ' style="background-image:url(' + escapeHTML(poster) + ');"' : '') + '>' +
    (poster ? '' : '<div class="play-icon">&#9654;</div>') +
    '</div>' +
    '<div class="card-info"><h3 class="card-title">' + title + '</h3>' +
    '<div class="card-meta">' + year + '</div></div></div>';
}

function loadTrendingMovies() {
  var popular = ['Inception', 'Interstellar', 'Gladiator', 'Avatar', 'Titanic', 'Joker', 'Oppenheimer', 'Dune'];
  var container = document.getElementById('trending-grid');
  if (!container) {
    var section = document.createElement('div');
    section.innerHTML = '<h2 class="section-title" style="color:#ff6b35"> Populares</h2>' +
      '<div id="trending-grid" class="grid"></div>';
    var hero = document.getElementById('hero');
    if (hero) hero.after(section);
    container = document.getElementById('trending-grid');
  }
  if (!container) return;

  var cards = [];
  var loaded = 0;
  popular.forEach(function(title) {
    fetch('/api/movies/search?q=' + encodeURIComponent(title)).then(function(r) { return r.json(); }).then(function(data) {
      loaded++;
      if (data.Search && data.Search.length > 0) cards.push(renderMovieCard(data.Search[0]));
      if (loaded >= popular.length) container.innerHTML = cards.join('');
    }).catch(function() { loaded++; });
  });
}

// ── Búsqueda en catálogo ───────────────────────────────────────────────────────
function searchEd2k() {
  var input = document.getElementById('search-input');
  if (!input || !input.value.trim()) return;
  var query = input.value.trim();
  var resultDiv = document.getElementById('search-results');
  var grid = document.getElementById('search-grid');
  if (!resultDiv || !grid) return;

  resultDiv.style.display = 'block';
  grid.innerHTML = '<div style="color:#888;padding:40px;text-align:center"><div class="play-icon" style="animation:pulse 1s infinite;margin:0 auto 12px"></div>Buscando...</div>';

  doSmartSearch(query, grid, true);
}

// Netflix-style: auto-correct and show results, never "did you mean"
function doSmartSearch(query, grid, isOriginal) {
  fetch('/api/movies/search?q=' + encodeURIComponent(query)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.Search && data.Search.length > 0) {
      var header = '';
      if (!isOriginal) {
        var origQuery = document.getElementById('search-input').value.trim();
        header = '<div style="padding:12px 20px;color:#aaa;font-size:13px">' +
          'Mostrando resultados para <strong style="color:#ff6b35">"' + escapeHTML(query) + '"</strong>' +
          ' · <a href="#" onclick="forceSearch(\'' + escapeAttr(origQuery) + '\');return false" style="color:#888;text-decoration:underline">' +
          'Buscar exactamente "' + escapeHTML(origQuery) + '"</a></div>';
      }
      grid.innerHTML = header + data.Search.map(renderMovieCard).join('');
    } else if (isOriginal) {
      var alts = generateAlternatives(query);
      tryAlternativesSequentially(alts, 0, query, grid);
    } else {
      grid.innerHTML = '<div style="color:#888;padding:40px;text-align:center">' +
        '<p style="font-size:18px;margin-bottom:8px">Sin resultados para "' + escapeHTML(query) + '"</p>' +
        '<p style="font-size:13px">Prueba con el título en inglés</p></div>';
    }
  }).catch(function() {
    grid.innerHTML = '<div style="color:#e74c3c;padding:20px">Error de conexión</div>';
  });
}

function forceSearch(query) {
  var grid = document.getElementById('search-grid');
  if (!grid) return;
  fetch('/api/movies/search?q=' + encodeURIComponent(query)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.Search && data.Search.length > 0) {
      grid.innerHTML = data.Search.map(renderMovieCard).join('');
    } else {
      grid.innerHTML = '<div style="color:#888;padding:30px;text-align:center">Sin resultados para "' + escapeHTML(query) + '"</div>';
    }
  });
}

// ── Corrección automática de títulos ──────────────────────────────────────────
function generateAlternatives(query) {
  var alts = [];
  var lower = query.toLowerCase();

  // 1. Spanish → English translations (common movie titles)
  var dict = {
    'a todo gas': 'fast furious', 'rapido y furioso': 'fast furious',
    'rapidos y furiosos': 'fast furious', 'vengadores': 'avengers',
    'guerra de las galaxias': 'star wars', 'guerra galaxias': 'star wars',
    'el señor de los anillos': 'lord of the rings', 'señor anillos': 'lord rings',
    'el caballero oscuro': 'dark knight', 'caballero oscuro': 'dark knight',
    'el padrino': 'godfather', 'padrino': 'godfather',
    'rey leon': 'lion king', 'el rey leon': 'lion king',
    'buscando a nemo': 'finding nemo', 'buscando nemo': 'finding nemo',
    'piratas del caribe': 'pirates caribbean', 'piratas caribe': 'pirates caribbean',
    'hombre araña': 'spider-man', 'spiderman': 'spider-man',
    'capitan america': 'captain america', 'viuda negra': 'black widow',
    'mision imposible': 'mission impossible', 'juego de tronos': 'game of thrones',
    'el planeta de los simios': 'planet of the apes', 'planeta simios': 'planet apes',
    'regreso al futuro': 'back to the future', 'volver al futuro': 'back to the future',
    'en busca del arca perdida': 'raiders of the lost ark',
    'parque jurasico': 'jurassic park', 'mundo jurasico': 'jurassic world',
    'origen': 'inception', 'interestelar': 'interstellar', 'gladiador': 'gladiator',
    'el lobo de wall street': 'wolf of wall street', 'lobo wall street': 'wolf wall street',
    'cadena perpetua': 'shawshank redemption', 'el club de la lucha': 'fight club',
    'tiburon': 'jaws', 'alien el octavo pasajero': 'alien',
    'el resplandor': 'the shining', 'resplandor': 'the shining',
    'la lista de schindler': 'schindlers list', 'forrest gump': 'forrest gump',
    'el gran lebowski': 'big lebowski', 'pulp fiction': 'pulp fiction'
  };

  Object.keys(dict).forEach(function(k) {
    if (lower.indexOf(k) !== -1 || k.indexOf(lower) !== -1) alts.push(dict[k]);
  });

  // 2. Without accents
  var noAccent = query.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  if (noAccent !== query) alts.push(noAccent);

  // 3. Without trailing number ("A Todo Gas 1" → "A Todo Gas")
  var noNum = query.replace(/\s*\d+\s*$/, '').trim();
  if (noNum !== query && noNum.length > 2) alts.push(noNum);

  // 4. Longest individual word (>4 chars)
  var words = query.split(/\s+/).filter(function(w) { return w.length > 4; });
  words.sort(function(a, b) { return b.length - a.length; });
  if (words.length > 0 && words[0].toLowerCase() !== lower) alts.push(words[0]);

  // Deduplicate
  var unique = [];
  alts.forEach(function(a) { if (unique.indexOf(a) === -1 && a.toLowerCase() !== lower) unique.push(a); });
  return unique;
}

function tryAlternativesSequentially(alts, idx, originalQuery, grid) {
  if (idx >= alts.length) {
    grid.innerHTML = '<div style="color:#888;padding:40px;text-align:center">' +
      '<p style="font-size:18px;margin-bottom:8px">Sin resultados para "' + escapeHTML(originalQuery) + '"</p>' +
      '<p style="font-size:13px;color:#666">Prueba con el título en inglés</p></div>';
    return;
  }
  fetch('/api/movies/search?q=' + encodeURIComponent(alts[idx])).then(function(r) { return r.json(); }).then(function(data) {
    if (data.Search && data.Search.length > 0) {
      var header = '<div style="padding:12px 20px;color:#aaa;font-size:13px">' +
        'Mostrando resultados para <strong style="color:#ff6b35">"' + escapeHTML(alts[idx]) + '"</strong>' +
        ' · <a href="#" onclick="forceSearch(\'' + escapeAttr(originalQuery) + '\');return false" style="color:#888;text-decoration:underline">' +
        'Buscar exactamente "' + escapeHTML(originalQuery) + '"</a></div>';
      grid.innerHTML = header + data.Search.map(renderMovieCard).join('');
    } else {
      tryAlternativesSequentially(alts, idx + 1, originalQuery, grid);
    }
  }).catch(function() {
    tryAlternativesSequentially(alts, idx + 1, originalQuery, grid);
  });
}

// ── Modal de detalle de película ───────────────────────────────────────────────
function showMovieDetail(imdbId, localFileName, localizedTitle) {
  var TMDB_KEY = window.ESE_TMDB_KEY || '2dca580c2a14b55200e784d157207b4d';
  var old = document.getElementById('movie-modal');
  if (old) old.remove();

  var modal = document.createElement('div');
  modal.id = 'movie-modal';
  modal.className = 'movie-modal active';
  modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
    '<div style="display:flex;align-items:center;justify-content:center;height:100vh">' +
    '<div class="spinner"></div></div>';
  document.body.appendChild(modal);
  document.body.style.overflow = 'hidden';

  modal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
  document.addEventListener('keydown', modal._keyHandler);

  fetch('/api/movies/detail?id=' + encodeURIComponent(imdbId)).then(function(r) { return r.json(); }).then(function(m) {
    if (!m || m.Response === 'False') {
      modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
        '<div style="color:#888;text-align:center;padding:100px">No se encontró información</div>';
      return;
    }

    var poster = sanitizeURL((m.Poster && m.Poster !== 'N/A') ? m.Poster : '');
    var safeTitle = escapeAttr(m.Title || '');
    // Use localized title (from TMDB Spanish) for eMule searches
    var searchTitle = escapeAttr(localizedTitle || m.Title || '');

    // Fetch HD backdrop from TMDB (OMDB poster is only 300px)
    var backdropUrl = poster;
    fetch('https://api.themoviedb.org/3/find/' + imdbId + '?api_key=' + TMDB_KEY + '&external_source=imdb_id')
      .then(function(r){return r.json();})
      .then(function(find) {
        var results = (find.movie_results || []).concat(find.tv_results || []);
        if (results.length > 0 && results[0].backdrop_path) {
          backdropUrl = 'https://image.tmdb.org/t/p/w1280' + results[0].backdrop_path;
        } else if (results.length > 0 && results[0].poster_path) {
          backdropUrl = 'https://image.tmdb.org/t/p/w780' + results[0].poster_path;
        }
        var el = document.querySelector('.modal-backdrop');
        if (el) el.style.backgroundImage = 'url(' + sanitizeURL(backdropUrl) + ')';
      }).catch(function(){});

    // Build buttons — Play ALWAYS visible
    var buttons = '';
    var seriesUI = '';
    var movieYear = m.Year || '';

    if (m.Type === 'series' && !localFileName) {
      var tSeasons = parseInt(m.totalSeasons, 10) || 15;
      var seasonOpts = '';
      for(var s=1; s<=tSeasons; s++) seasonOpts += '<option value="'+s+'">Temporada '+s+'</option>';
      var epOpts = '';
      for(var ep=1; ep<=30; ep++) epOpts += '<option value="'+ep+'">Capítulo '+ep+'</option>';
      seriesUI = '<div style="display:flex;gap:12px;margin-bottom:20px;max-width:360px;background:rgba(255,255,255,.03);padding:16px;border-radius:12px;border:1px solid rgba(255,255,255,.08)">' +
        '<div style="flex:1"><label style="display:block;font-size:11px;text-transform:uppercase;color:#aaa;margin-bottom:6px;font-weight:600">Temporada</label>' +
        '<select id="tv-season" style="width:100%;background:#111;color:#fff;border:1px solid #333;padding:8px 12px;border-radius:6px;outline:none;cursor:pointer">' + seasonOpts + '</select></div>' +
        '<div style="flex:1"><label style="display:block;font-size:11px;text-transform:uppercase;color:#aaa;margin-bottom:6px;font-weight:600">Capítulo</label>' +
        '<select id="tv-ep" style="width:100%;background:#111;color:#fff;border:1px solid #333;padding:8px 12px;border-radius:6px;outline:none;cursor:pointer">' + epOpts + '</select></div>' +
        '</div>';
    }

    var playIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="margin-right:6px;vertical-align:-2px"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>';
    var dlIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';
    var trIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>';
    var searchIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>';
    var listIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"></path></svg>';

    var tEsc = searchTitle;
    var yArg = m.Type === 'series' ? '' : movieYear;

    // Store movie data globally so Mi Lista button avoids escaping issues
    window._modalMovie = { imdbId: imdbId, title: m.Title || searchTitle, poster: (m.Poster && m.Poster !== 'N/A') ? m.Poster : '', year: movieYear };

    if (localFileName) {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="playInModal(\'' + encodeURIComponent(localFileName) + '\')">' + playIcon + ' Reproducir local</button>';
    } else {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="smartPlay(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + playIcon + ' Reproducir</button>';
      buttons += '<button class="modal-btn btn-download" id="modal-download-btn" onclick="smartDownload(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + dlIcon + ' Descargar</button>';
    }
    buttons += '<button class="modal-btn btn-trailer" id="trailer-btn" onclick="loadTrailer(\'' + safeTitle + ' ' + movieYear + '\')">' + trIcon + ' Tráiler</button>';
    if (!localFileName) {
      buttons += '<button class="modal-btn btn-emule" onclick="startEmuleSearch(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + searchIcon + ' Búsqueda avanzada</button>';
    }
    // Mi Lista — usa global _modalMovie, sin infierno de escaping
    var inList = typeof isInMyList === 'function' && isInMyList(imdbId);
    buttons += '<button class="modal-btn btn-list' + (inList ? ' btn-list-active' : '') + '" id="modal-list-btn" onclick="toggleMyListBtn(this)">' + listIcon + (inList ? ' Quitar de Mi Lista' : ' Mi Lista') + '</button>';

    // Build detail cards
    var details = '';
    if (m.Director && m.Director !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Director</div><div class="detail-value">' + escapeHTML(m.Director) + '</div></div>';
    if (m.Actors && m.Actors !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Reparto</div><div class="detail-value">' + escapeHTML(m.Actors) + '</div></div>';
    if (m.Awards && m.Awards !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Premios</div><div class="detail-value">' + escapeHTML(m.Awards) + '</div></div>';
    if (m.BoxOffice && m.BoxOffice !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Taquilla</div><div class="detail-value">' + escapeHTML(m.BoxOffice) + '</div></div>';
    if (m.Country && m.Country !== 'N/A') details += '<div class="detail-item"><div class="detail-label">País</div><div class="detail-value">' + escapeHTML(m.Country) + '</div></div>';
    if (m.Language && m.Language !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Idioma</div><div class="detail-value">' + escapeHTML(m.Language) + '</div></div>';

    // Meta badges
    var meta = '';
    if (m.imdbRating && m.imdbRating !== 'N/A') meta += '<span class="modal-rating"><svg width="12" height="12" viewBox="0 0 24 24" fill="#f5c518" stroke="none" style="vertical-align:-1px;margin-right:3px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>' + escapeHTML(m.imdbRating) + '</span>';
    if (m.Year) meta += '<span class="modal-badge">' + escapeHTML(m.Year) + '</span>';
    if (m.Runtime && m.Runtime !== 'N/A') meta += '<span class="modal-badge">' + escapeHTML(m.Runtime) + '</span>';
    if (m.Rated && m.Rated !== 'N/A') meta += '<span class="modal-badge">' + escapeHTML(m.Rated) + '</span>';
    if (m.Genre && m.Genre !== 'N/A') {
      translateGenres(m.Genre).split(',').forEach(function(g) {
        meta += '<span class="modal-badge">' + escapeHTML(g.trim()) + '</span>';
      });
    }

    modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
      '<div id="modal-player-zone" style="display:none"></div>' +
      '<div id="modal-info-zone">' +
        '<div class="modal-backdrop" style="background-image:url(' + escapeHTML(poster) + ')"></div>' +
        '<div class="modal-content">' +
          '<h1 class="modal-title">' + escapeHTML(m.Title || '') + '</h1>' +
          '<div class="modal-meta">' + meta + '</div>' +
          seriesUI +
          '<div class="modal-buttons">' + buttons + '</div>' +
          '<div id="trailer-container"></div>' +
          '<p class="modal-plot">' + escapeHTML(m.Plot || 'Sin sinopsis disponible') + '</p>' +
          '<div class="modal-details">' + details + '</div>' +
        '</div>' +
      '</div>';
    // Parchar sinopsis con versión en español de TMDB
    patchSpanishPlot(imdbId);

  }).catch(function() {
    modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
      '<div style="color:#e74c3c;text-align:center;padding:100px">Error de conexión</div>';
  });
}

window.getTvQuery = function(baseTitle) {
  var s = document.getElementById('tv-season');
  var e = document.getElementById('tv-ep');
  if (s && e) {
    var sv = parseInt(s.value, 10) || 1;
    var ev = parseInt(e.value, 10) || 1;
    var sf = sv < 10 ? '0' + sv : '' + sv;
    var ef = ev < 10 ? '0' + ev : '' + ev;
    return baseTitle + ' ' + sf + 'x' + ef;  // formato: 01x01 (estándar español en ed2k)
  }
  return baseTitle;
};

function closeMovieModal() {
  // Save playback position for resume
  if (video && window._cinemaFileName) {
    var currentReal = (window._cinemaSeekOffset || 0) + (video.currentTime || 0);
    if (currentReal > 10) {
      var resumeData = JSON.parse(localStorage.getItem('ese_resume') || '{}');
      resumeData[window._cinemaFileName] = { time: Math.floor(currentReal), ts: Date.now() };
      localStorage.setItem('ese_resume', JSON.stringify(resumeData));
    }
  }
  // ALWAYS stop video
  try { video.pause(); video.removeAttribute('src'); video.load(); } catch(e) {}
  if (abortController) { try { abortController.abort(); } catch(e) {} }
  try { video.querySelectorAll('track').forEach(function(t) { t.remove(); }); } catch(e) {}

  var modal = document.getElementById('movie-modal');
  if (modal) {
    if (modal._keyHandler) document.removeEventListener('keydown', modal._keyHandler);
    modal.remove();
  }
  document.body.style.overflow = '';
}

// ── Búsqueda avanzada en eMule ─────────────────────────────────────────────────
function startEmuleSearch(title, year) {
  var searchDiv = document.getElementById('trailer-container');
  if (!searchDiv) { smartSearchOverlay(title); return; }

  var searchQuery = title + (year ? ' ' + year : '');
  searchDiv.innerHTML = '<div style="padding:20px">' +
    '<h3 style="color:#ff6b35;margin-bottom:12px"> Buscando en eMule: "' + escapeHTML(searchQuery) + '"</h3>' +
    '<div style="display:flex;align-items:center;gap:12px"><div class="spinner"></div>' +
    '<span style="color:#888">Buscando fuentes... (esto puede tardar unos segundos)</span></div></div>';

  fetch('/api/emule/search?q=' + encodeURIComponent(searchQuery)).then(function(r) { return r.json(); }).then(function(data) {
    if (!data.success) {
      searchDiv.innerHTML = '<div style="padding:20px">' +
        '<p style="color:#e74c3c"> ' + escapeHTML(data.error || 'Error de conexión') + '</p></div>';
      return;
    }

    if (!data.results || data.results.length === 0) {
      searchDiv.innerHTML = '<div style="padding:20px">' +
        '<p style="color:#888">No se encontraron resultados para "' + escapeHTML(title) + '"</p></div>';
      return;
    }

    var html = '<div style="padding:20px"><h3 style="color:#ff6b35;margin-bottom:16px"> Fuentes encontradas (' + data.results.length + ')</h3>' +
      '<div class="source-results">';

    data.results.forEach(function(r, i) {
      var safeFileName = escapeHTML(r.fileName || '');
      var safeQuality = escapeHTML(r.quality || 'unknown');
      var safeLang = escapeHTML(r.language || 'unknown');
      var safeScore = escapeHTML(String(r.score || 0));
      var safeSources = escapeHTML(String(r.sources || 0));
      var safeComplete = escapeHTML(String(r.completeSources || 0));
      var safeSizeMB = escapeHTML(String(r.sizeMB || 0));
      // Validate hash is hex-only to prevent injection
      var safeHash = /^[0-9a-fA-F]+$/.test(r.hash || '') ? r.hash : '';
      var safeTitleAttr = escapeAttr(title);

      var qualityBadge = r.quality !== 'unknown' ? '<span class="source-badge badge-quality">' + safeQuality.toUpperCase() + '</span>' : '';
      var langBadge = r.language !== 'unknown' ? '<span class="source-badge badge-lang">' + safeLang + '</span>' : '';
      var scoreBadge = '<span class="source-badge badge-score">⭐ ' + safeScore + '</span>';
      var sourcesBadge = '<span class="source-badge badge-sources">' + safeSources + '/' + safeComplete + ' fuentes</span>';
      var fakeBadge = r.isFake ? '<span class="source-badge" style="background:#e74c3c">FAKE</span>' : '';

      html += '<div class="source-item">' +
        '<div class="source-name">' + (i === 0 ? ' ' : '') + safeFileName + '<br><span style="color:#666;font-size:11px">' + safeSizeMB + ' MB</span></div>' +
        '<div class="source-meta">' + qualityBadge + langBadge + sourcesBadge + scoreBadge + fakeBadge + '</div>' +
        '<div class="source-actions">' +
          '<button class="source-btn source-btn-play" onclick="streamSource(\'' + safeHash + '\', \'' + safeTitleAttr + '\')" title="Reproducir ahora">▶ Reproducir</button>' +
          '<button class="source-btn source-btn-dl" onclick="downloadSource(\'' + safeHash + '\')" title="Descargar para ver luego"> Descargar</button>' +
        '</div>' +
      '</div>';
    });

    html += '</div></div>';
    searchDiv.innerHTML = html;

  }).catch(function(err) {
    searchDiv.innerHTML = '<div style="padding:20px"><p style="color:#e74c3c">Error: ' + escapeHTML(err.message) + '</p></div>';
  });
}

function smartSearchOverlay(title) {
  var overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:400;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = '<div style="background:#16161e;border-radius:16px;padding:32px;max-width:600px;width:90%;border:1px solid #333;max-height:80vh;overflow-y:auto">' +
    '<h3 style="color:#ff6b35;margin-bottom:16px;font-size:20px"> Buscar en eMule</h3>' +
    '<input type="text" id="emule-custom-query" value="' + escapeAttr(title) + '" class="setting-input" style="margin-bottom:12px">' +
    '<div style="display:flex;gap:12px">' +
    '<button onclick="var q=document.getElementById(\'emule-custom-query\').value;this.closest(\'div\').closest(\'div\').closest(\'div\').remove();startEmuleSearch(q)" style="flex:1;background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px;border-radius:8px;cursor:pointer;font-weight:600"> Buscar</button>' +
    '<button onclick="this.closest(\'div\').closest(\'div\').closest(\'div\').remove()" style="flex:1;background:#333;border:none;color:#fff;padding:12px;border-radius:8px;cursor:pointer">Cancelar</button>' +
    '</div></div>';
  document.body.appendChild(overlay);
}

// ── Acciones de descarga/streaming ────────────────────────────────────────────
function downloadSource(hash) {
  if (!hash) return;
  fetch('/api/emule/download?hash=' + encodeURIComponent(hash)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.success) {
      showNotification(' Descarga iniciada en eMule');
    } else {
      showNotification(' Error: ' + (data.error || 'No se pudo iniciar'));
    }
  }).catch(function() {
    showNotification(' Error de conexión con eMule');
  });
}

function streamSource(hash, movieTitle) {
  if (!hash) return;
  fetch('/api/emule/download?hash=' + encodeURIComponent(hash)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.success) {
      showNotification(' Descarga iniciada — preparando streaming...');

      var playerZone = document.getElementById('modal-player-zone');
      var infoZone = document.getElementById('modal-info-zone');
      if (playerZone) {
        if (infoZone) infoZone.style.display = 'none';
        playerZone.style.display = 'block';
        playerZone.innerHTML = '<div class="modal-player" id="cinema-player">' +
          '<div class="modal-player-header">' +
            '<button class="cinema-back-btn" onclick="backToDetail()">&larr; Volver</button>' +
          '</div>' +
          '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;gap:20px">' +
            '<div class="spinner" style="width:60px;height:60px;border-width:4px"></div>' +
            '<h2 style="color:#fff;font-size:24px;font-weight:600" id="smart-play-title">Monitorizando velocidad...</h2>' +
            '<p style="color:#888;font-size:14px;text-align:center;max-width:400px" id="smart-play-status">Esperando que eMule reciba datos... (15s)</p>' +
            '<div style="width:300px;height:4px;background:#222;border-radius:2px;overflow:hidden;margin-top:8px">' +
              '<div id="smart-play-progress" style="width:40%;height:100%;background:linear-gradient(90deg,#ff6b35,#ff2d78);transition:width .5s;border-radius:2px"></div>' +
            '</div>' +
          '</div>' +
        '</div>';
      }

      window._smartPlayTitle = movieTitle;
      monitorForFile(movieTitle, '', 0, 0);
    } else {
      showNotification(' Error: ' + (data.error || 'No se pudo iniciar'));
    }
  }).catch(function() {
    showNotification(' Error de conexión');
  });
}

function smartDownload(movieTitle, movieYear) {
  var searchQuery = movieTitle + (movieYear ? ' ' + movieYear : '');
  showNotification(' Buscando mejor fuente para descargar...');
  fetch('/api/emule/smartsearch?q=' + encodeURIComponent(searchQuery) + (movieYear ? '&year=' + movieYear : '')).then(function(r) { return r.json(); }).then(function(data) {
    if (data.results && data.results.length > 0) {
      var best = data.results[0];
      downloadSource(best.hash);
      showNotification(' Descargando: ' + best.fileName.substring(0, 50) + '...');
    } else {
      showNotification(' No se encontraron fuentes para descargar');
    }
  }).catch(function() {
    showNotification(' Error de conexión');
  });
}

// ── Inicialización ─────────────────────────────────────────────────────────────
setTimeout(loadTrendingMovies, 500);
