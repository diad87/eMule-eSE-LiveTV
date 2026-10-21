// search_ui.js — catálogo OMDb, búsqueda, modal de detalle, búsqueda eMule

// ── Traducción de géneros OMDB (siempre en inglés) al español ─────────────────
var GENRE_ES = {
  'Action':'Acción','Adventure':'Aventura','Animation':'Animación','Biography':'Biografía',
  'Comedy':'Comedia','Crime':'Crimen','Documentary':'Documental','Drama':'Drama',
  'Family':'Familia','Fantasy':'Fantasía','Film-Noir':'Cine negro','History':'Historia',
  'Horror':'Terror','Music':'Música','Musical':'Musical','Mystery':'Misterio',
  'Romance':'Romance','Sci-Fi':'Ciencia ficción','Short':'Corto','Sport':'Deporte',
  'Superhero':'Superhéroes','Thriller':'Thriller','War':'Guerra','Western':'Western',
  // TMDB TV genres are often returned in English even with language=es-ES.
  'Sci-Fi & Fantasy':'Ciencia ficción y fantasía','Action & Adventure':'Acción y aventura',
  'War & Politics':'Bélica y política','Kids':'Infantil','Soap':'Telenovela','Talk':'Entrevistas','News':'Noticias'
};
function translateGenres(genreStr) {
  if (!genreStr || genreStr === 'N/A') return genreStr;
  return genreStr.split(',').map(function(g) {
    var t = g.trim();
    return GENRE_ES[t] || t;
  }).join(', ');
}

// ── Obtiene sinopsis en español de TMDB y la parchea en el DOM ────────────────
// TMDB calls go through /api/tmdb/* proxy — key stays server-side.
function patchSpanishPlot(imdbId, owner) {
  fetch('/api/tmdb/find/' + encodeURIComponent(imdbId) + '?language=es-ES&external_source=imdb_id')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var results = (data.movie_results || []).concat(data.tv_results || []);
      if (!results.length || !results[0].overview) return;
      var overview = results[0].overview;
      if (owner && document.getElementById('movie-modal') !== owner) return;
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
  var imdbId = escapeAttr(m.catalogId || m.imdbID || '');
  var safeTitle = escapeAttr(m.Title || 'Sin titulo');
  return '<div class="card" role="button" tabindex="0" onkeydown="if(event.key===\'Enter\'||event.key===\' \'){event.preventDefault();this.click()}" onclick="showMovieDetail(\'' + imdbId + '\',null,\'' + safeTitle + '\')">' +
    '<div class="card-poster"' + (poster ? ' style="background-image:url(' + escapeHTML(poster) + ');"' : '') + '>' +
    (poster ? '' : '<div class="play-icon">&#9654;</div>') +
    '</div>' +
    '<div class="card-info"><h3 class="card-title">' + title + '</h3>' +
    '<div class="card-meta">' + year + '</div></div></div>';
}

function loadTrendingMovies() {
  var popular = ['Inception', 'Interstellar', 'Gladiator', 'Avatar', 'Titanic', 'Joker', 'Oppenheimer', 'Dune'];
  var container = document.getElementById('trending-grid');
  if (!container) return;
  container.innerHTML = '<div class="catalog-state" role="status">Cargando películas…</div>';
  Promise.all(popular.map(function(title) {
    return fetch('/api/movies/search?q=' + encodeURIComponent(title))
      .then(function(r) { if (!r.ok) throw new Error('catalog unavailable'); return r.json(); })
      .then(function(data) { return data.Search && data.Search.length ? renderMovieCard(data.Search[0]) : ''; })
      .catch(function() { return ''; });
  })).then(function(cards) {
    var found = cards.filter(Boolean);
    container.innerHTML = found.length ? found.join('') : '<div class="catalog-state" role="status">No se pudo cargar la selección. Puedes seguir usando tu biblioteca.<br><button type="button" onclick="loadTrendingMovies()">Reintentar</button></div>';
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
  var resultsTitle = document.getElementById('search-results-title');
  if (resultsTitle) resultsTitle.focus({ preventScroll: true });
  resultDiv.scrollIntoView({ block: 'start' });
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
function movieModalCloseButton() {
  return '<button type="button" class="modal-close" aria-label="Cerrar ficha" onclick="closeMovieModal()">&times;</button>';
}

function showMovieDetailError(modal, imdbId, localFileName, localizedTitle, unavailable) {
  if (document.getElementById('movie-modal') !== modal) return;
  modal.innerHTML = movieModalCloseButton() +
    '<div class="modal-message" style="max-width:640px;margin:0 auto;padding:140px 28px 60px">' +
    '<h1 class="modal-title">' + (unavailable ? 'Ficha no disponible' : 'No se ha podido cargar la ficha') + '</h1>' +
    '<p class="modal-plot" role="status">' + (unavailable
      ? 'No encontramos los datos de este título. Puedes volver al catálogo y probar con otro resultado.'
      : 'Comprueba la conexión e inténtalo de nuevo. Puedes cerrar esta ficha cuando quieras.') + '</p>' +
    '<div class="modal-buttons">' +
    (localFileName ? '<button type="button" class="modal-btn btn-play" id="modal-play-btn" onclick="playInModal(\'' + escapeAttr(encodeURIComponent(localFileName)) + '\')">Reproducir archivo local</button>' : '') +
    '<button type="button" class="modal-btn btn-trailer" id="modal-retry-btn">Reintentar</button>' +
    '<button type="button" class="modal-btn btn-list" onclick="closeMovieModal()">Volver al catálogo</button></div></div>' +
    '<div id="modal-player-zone" style="display:none"></div><div id="modal-info-zone" style="display:none"></div>';
  var retry = document.getElementById('modal-retry-btn');
  if (retry) retry.onclick = function() { showMovieDetail(imdbId, localFileName, localizedTitle); };
}

// ── Series: navegador de episodios ─────────────────────────────────────────────
// Temporadas como pestañas y episodios como filas con imagen, sinopsis y acciones
// propias. El último episodio abierto de cada serie se recuerda en este navegador.
var SERIES_PROGRESS_KEY = 'ese.seriesProgress.v1';

function pad2(n) { return n < 10 ? '0' + n : '' + n; }
function episodeCode(season, episode) { return season === 0 ? 'Especial ' + episode : 'T' + season + ' · E' + episode; }
function episodeQuery(base, season, episode) { return base + ' ' + pad2(season) + 'x' + pad2(episode); } // 01x01, estándar español en ed2k

function readSeriesProgress(catalogId) {
  try {
    var all = JSON.parse(window.localStorage.getItem(SERIES_PROGRESS_KEY) || '{}');
    var entry = all && all[catalogId];
    if (entry && Number.isInteger(entry.season) && entry.season >= 0 && Number.isInteger(entry.episode) && entry.episode >= 1) return entry;
  } catch (e) {}
  return null;
}

function saveSeriesProgress(catalogId, season, episode) {
  try {
    var all = JSON.parse(window.localStorage.getItem(SERIES_PROGRESS_KEY) || '{}');
    if (!all || typeof all !== 'object' || Array.isArray(all)) all = {};
    all[catalogId] = { season: season, episode: episode, at: Date.now() };
    Object.keys(all).sort(function(a, b) { return (all[b].at || 0) - (all[a].at || 0); })
      .slice(200).forEach(function(key) { delete all[key]; });
    window.localStorage.setItem(SERIES_PROGRESS_KEY, JSON.stringify(all));
  } catch (e) {}
}

function todayISO() {
  var d = new Date();
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
}
function isUpcoming(ep) { return !!(ep && ep.airDate && ep.airDate > todayISO()); }
function formatAirDate(iso) {
  var parts = String(iso || '').split('-');
  if (parts.length !== 3) return '';
  try {
    return new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]))
      .toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
  } catch (e) { return iso; }
}

// Regular seasons in order; specials (season 0) go last, as in most TV apps.
function orderedSeasons(seasons) {
  var list = (Array.isArray(seasons) ? seasons : []).filter(function(s) {
    return s && Number.isInteger(Number(s.number)) && Number(s.number) >= 0;
  });
  return list.filter(function(s) { return Number(s.number) > 0; })
    .concat(list.filter(function(s) { return Number(s.number) === 0; }));
}

function seriesState() {
  var modal = document.getElementById('movie-modal');
  return modal && modal._series ? modal._series : null;
}
function findEpisode(state, number) {
  if (!state || !Array.isArray(state.episodes) || number === null) return null;
  for (var i = 0; i < state.episodes.length; i++) if (Number(state.episodes[i].number) === number) return state.episodes[i];
  return null;
}
function defaultEpisode(state) {
  var progress = state.progress;
  if (progress && progress.season === state.season && findEpisode(state, progress.episode)) return progress.episode;
  for (var i = 0; i < state.episodes.length; i++) if (!isUpcoming(state.episodes[i])) return Number(state.episodes[i].number);
  return state.episodes.length ? Number(state.episodes[0].number) : null;
}

function renderSeasonTabs(state) {
  return state.seasons.map(function(s) {
    var n = Number(s.number);
    var selected = n === state.season;
    var name = s.name || (n === 0 ? 'Especiales' : 'Temporada ' + n);
    return '<button type="button" role="tab" class="ep-season" id="ep-season-' + n + '" aria-selected="' + selected + '" aria-controls="ep-list" tabindex="' + (selected ? '0' : '-1') + '" onclick="selectSeason(' + n + ')" onkeydown="seasonTabKey(event,' + n + ')">' +
      '<span class="ep-season-name">' + escapeHTML(name) + '</span>' +
      (Number(s.episodeCount) > 0 ? '<span class="ep-season-count" aria-label="' + Number(s.episodeCount) + ' episodios">' + Number(s.episodeCount) + '</span>' : '') + '</button>';
  }).join('');
}

function renderEpisodeRow(state, ep) {
  var n = Number(ep.number);
  var selected = n === state.episode;
  var expanded = selected && !state.collapsed;
  var upcoming = isUpcoming(ep);
  var resume = state.progress && state.progress.season === state.season && state.progress.episode === n;
  var title = ep.name && !/^(episodio|episode|cap[ií]tulo)\s+\d+$/i.test(ep.name.trim()) ? ep.name : 'Episodio ' + n;
  var still = sanitizeURL(ep.still || '');
  var meta = [];
  if (Number(ep.runtime) > 0) meta.push(Number(ep.runtime) + ' min');
  if (ep.airDate) meta.push((upcoming ? 'Se estrena el ' : '') + formatAirDate(ep.airDate));
  if (ep.rating) meta.push('★ ' + ep.rating);
  var play = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><polygon points="6 4 20 12 6 20 6 4"/></svg>';
  var down = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><path d="M12 4v11"/><path d="M7 11l5 5 5-5"/><path d="M5 20h14"/></svg>';
  var find = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>';
  var off = upcoming ? ' disabled' : '';
  return '<li class="ep-row' + (selected ? ' is-selected' : '') + (expanded ? ' is-expanded' : '') + (upcoming ? ' is-upcoming' : '') + '" id="ep-row-' + n + '">' +
    '<button type="button" class="ep-main" id="ep-btn-' + n + '" aria-expanded="' + expanded + '"' + (expanded ? ' aria-controls="ep-detail-' + n + '"' : '') + ' onclick="selectEpisode(' + n + ')">' +
      '<span class="ep-thumb">' + (still ? '<img src="' + escapeAttr(still) + '" alt="" loading="lazy" onerror="this.remove()">' : '') +
        '<span class="ep-thumb-num" aria-hidden="true">' + n + '</span>' +
        (upcoming ? '<span class="ep-flag ep-flag-soon">Próximamente</span>' : resume ? '<span class="ep-flag">Continuar</span>' : '') +
        '<span class="ep-thumb-play" aria-hidden="true">' + play + '</span></span>' +
      '<span class="ep-text"><span class="ep-title"><span class="ep-index">' + n + '.</span> ' + escapeHTML(title) + '</span>' +
        (meta.length ? '<span class="ep-meta">' + escapeHTML(meta.join(' · ')) + '</span>' : '') +
        (ep.overview ? '<span class="ep-overview">' + escapeHTML(ep.overview) + '</span>' : '') + '</span>' +
    '</button>' +
    (expanded ? '<div class="ep-detail" id="ep-detail-' + n + '"><div class="ep-actions">' +
      '<button type="button" class="ep-act ep-act-play" id="ep-play-' + n + '" onclick="episodeAction(\'play\',' + n + ')"' + off + '>' + play + (resume ? 'Continuar' : 'Reproducir') + '</button>' +
      '<button type="button" class="ep-act" id="ep-download-' + n + '" onclick="episodeAction(\'download\',' + n + ')"' + off + '>' + down + 'Descargar</button>' +
      '<button type="button" class="ep-act ep-act-ghost" id="ep-sources-btn-' + n + '" onclick="episodeAction(\'sources\',' + n + ')"' + off + '>' + find + 'Ver fuentes</button></div>' +
      '<p class="ep-note">' + (upcoming ? 'Este episodio aún no se ha emitido.' : 'Se buscará «' + escapeHTML(episodeQuery(state.base, state.season, n)) + '» en la red eMule.') + '</p>' +
      '<div class="ep-sources" id="ep-sources-' + n + '"></div></div>' : '') +
  '</li>';
}

function renderEpisodePanel(state) {
  var body;
  if (state.loading) {
    body = [0, 1, 2, 3].map(function() {
      return '<li class="ep-row ep-skeleton" aria-hidden="true"><span class="ep-main"><span class="ep-thumb"></span><span class="ep-text"><span class="ep-line"></span><span class="ep-line ep-line-short"></span></span></span></li>';
    }).join('');
  } else if (state.failed) {
    body = '<li class="ep-empty">No se han podido cargar los episodios de esta temporada.</li>';
  } else if (!state.episodes.length) {
    body = '<li class="ep-empty">Esta temporada todavía no tiene episodios publicados.</li>';
  } else {
    body = state.episodes.map(function(ep) { return renderEpisodeRow(state, ep); }).join('');
  }
  return '<ol class="ep-list" id="ep-list" role="tabpanel" aria-labelledby="ep-season-' + state.season + '" aria-busy="' + !!state.loading + '">' + body + '</ol>';
}

function syncSeriesActions(state) {
  var ep = findEpisode(state, state.episode);
  var ready = !!ep && !isUpcoming(ep) && !state.loading;
  ['modal-play-btn', 'modal-download-btn', 'modal-emule-btn'].forEach(function(id) {
    var button = document.getElementById(id);
    if (button) button.disabled = !ready;
  });
  var code = ep ? episodeCode(state.season, Number(ep.number)) : '';
  var resume = ep && state.progress && state.progress.season === state.season && state.progress.episode === Number(ep.number);
  var play = document.getElementById('modal-play-label');
  var download = document.getElementById('modal-download-label');
  if (play) play.textContent = state.loading ? 'Cargando episodios…' : !ep ? 'Elige un episodio' : isUpcoming(ep) ? 'Aún no disponible' : (resume ? 'Continuar ' : 'Reproducir ') + code;
  if (download) download.textContent = ready ? 'Descargar ' + code : 'Descargar';
}

function paintSeries(state, focusEpisode) {
  var tabs = document.getElementById('ep-seasons');
  var panel = document.getElementById('ep-panel');
  var status = document.getElementById('tv-picker-status');
  var retry = document.getElementById('tv-season-retry');
  if (tabs) tabs.innerHTML = renderSeasonTabs(state);
  if (panel) panel.innerHTML = renderEpisodePanel(state);
  if (retry) retry.hidden = !state.failed;
  if (status) {
    var season = state.season === 0 ? 'Especiales' : 'Temporada ' + state.season;
    var aired = state.episodes.filter(function(ep) { return !isUpcoming(ep); }).length;
    status.textContent = state.loading ? 'Cargando episodios de ' + season.toLowerCase() + '…'
      : state.failed ? 'No se han podido cargar los episodios. Reintenta o busca la serie completa.'
      : !state.episodes.length ? season + ' · sin episodios publicados'
      : season + ' · ' + state.episodes.length + (state.episodes.length === 1 ? ' episodio' : ' episodios') +
        (aired < state.episodes.length ? ' (' + (state.episodes.length - aired) + ' por estrenar)' : '');
  }
  syncSeriesActions(state);
  if (focusEpisode !== undefined && focusEpisode !== null) {
    var button = document.getElementById('ep-btn-' + focusEpisode);
    if (button && typeof button.focus === 'function') button.focus({ preventScroll: true });
  }
}

function loadSeriesSeason(modal) {
  var state = modal._series;
  var number = state.season;
  var current = ++state.request;
  if (modal._seasonAbort) modal._seasonAbort.abort();
  modal._seasonAbort = null;
  state.failed = false;
  state.collapsed = false;
  if (state.cache[number]) {
    state.loading = false;
    state.episodes = state.cache[number];
    state.episode = defaultEpisode(state);
    paintSeries(state);
    return;
  }
  state.loading = true;
  state.episodes = [];
  state.episode = null;
  paintSeries(state);
  modal._seasonAbort = typeof AbortController === 'function' ? new AbortController() : null;
  fetch('/api/movies/season?id=' + encodeURIComponent(state.catalogId) + '&season=' + encodeURIComponent(number), modal._seasonAbort ? { signal: modal._seasonAbort.signal } : undefined)
    .then(function(r) { if (!r.ok) throw new Error('season unavailable'); return r.json(); })
    .then(function(data) {
      if (current !== state.request || document.getElementById('movie-modal') !== modal) return;
      if (!data || !Array.isArray(data.episodes)) throw new Error('invalid season');
      var episodes = data.episodes.filter(function(ep) { return ep && Number.isInteger(Number(ep.number)) && Number(ep.number) > 0; });
      state.cache[number] = episodes;
      state.loading = false;
      state.episodes = episodes;
      state.episode = defaultEpisode(state);
      paintSeries(state);
    }).catch(function(error) {
      if (current !== state.request || document.getElementById('movie-modal') !== modal || (error && error.name === 'AbortError')) return;
      state.loading = false;
      state.failed = true;
      paintSeries(state);
    });
}

function configureSeriesPicker(modal, movie, searchBase) {
  var seasons = orderedSeasons(movie.seasons);
  if (!seasons.length || !movie.catalogId) return;
  var progress = readSeriesProgress(movie.catalogId);
  var hasProgressSeason = progress && seasons.some(function(s) { return Number(s.number) === progress.season; });
  modal._series = {
    catalogId: movie.catalogId, base: searchBase, seasons: seasons, progress: progress, cache: {}, request: 0,
    season: hasProgressSeason ? progress.season : Number(seasons[0].number), episodes: [], episode: null,
    loading: false, failed: false, collapsed: false
  };
  var retry = document.getElementById('tv-season-retry');
  if (retry) retry.onclick = function() { loadSeriesSeason(modal); };
  loadSeriesSeason(modal);
}

window.selectSeason = function(number) {
  var modal = document.getElementById('movie-modal');
  var state = modal && modal._series;
  if (!state || state.season === number || !state.seasons.some(function(s) { return Number(s.number) === number; })) return;
  state.season = number;
  loadSeriesSeason(modal);
};

window.seasonTabKey = function(event, number) {
  var state = seriesState();
  if (!state) return;
  var index = state.seasons.map(function(s) { return Number(s.number); }).indexOf(number);
  var next = event.key === 'ArrowRight' ? index + 1 : event.key === 'ArrowLeft' ? index - 1
    : event.key === 'Home' ? 0 : event.key === 'End' ? state.seasons.length - 1 : -2;
  if (next === -2) return;
  event.preventDefault();
  next = Math.max(0, Math.min(state.seasons.length - 1, next));
  window.selectSeason(Number(state.seasons[next].number));
  var tab = document.getElementById('ep-season-' + Number(state.seasons[next].number));
  if (tab && typeof tab.focus === 'function') tab.focus();
};

window.selectEpisode = function(number) {
  var state = seriesState();
  if (!state || state.loading || !findEpisode(state, number)) return;
  if (state.episode === number) state.collapsed = !state.collapsed;
  else { state.episode = number; state.collapsed = false; }
  paintSeries(state, number);
};

window.episodeAction = function(action, number) {
  var state = seriesState();
  var ep = findEpisode(state, number);
  if (!ep || isUpcoming(ep) || state.loading) return;
  var query = episodeQuery(state.base, state.season, number);
  if (action === 'sources') { startEmuleSearch(query, '', 'ep-sources-' + number); return; }
  state.episode = number;
  state.progress = { season: state.season, episode: number };
  saveSeriesProgress(state.catalogId, state.season, number);
  syncSeriesActions(state);
  if (action === 'play') smartPlay(query, '');
  else if (action === 'download') smartDownload(query, '');
};

// Main hero buttons act on the selected episode.
window.seriesHeroAction = function(action) {
  var state = seriesState();
  if (state && state.episode !== null) window.episodeAction(action, state.episode);
};

window.searchWholeSeries = function() {
  var state = seriesState();
  if (state) startEmuleSearch(state.base, '', 'ep-whole-sources');
};

function showMovieDetail(imdbId, localFileName, localizedTitle) {
  var old = document.getElementById('movie-modal');
  var previousOverflow = old && old._previousOverflow !== undefined ? old._previousOverflow : document.body.style.overflow;
  if (old) {
    if (old._detailAbort) old._detailAbort.abort();
    if (old._seasonAbort) old._seasonAbort.abort();
    if (old._detailTimer) clearTimeout(old._detailTimer);
    if (old._keyHandler) document.removeEventListener('keydown', old._keyHandler);
    old.remove();
  }

  var modal = document.createElement('div');
  modal.id = 'movie-modal';
  modal.className = 'movie-modal active';
  modal._previousOverflow = previousOverflow || '';
  modal.innerHTML = movieModalCloseButton() +
    '<div class="modal-loading" role="status" style="display:flex;flex-direction:column;gap:20px;align-items:center;justify-content:center;min-height:60vh;padding:32px;text-align:center">' +
    '<div class="spinner" aria-hidden="true"></div><p>Cargando ficha del título…</p></div>';
  document.body.appendChild(modal);
  document.body.style.overflow = 'hidden';

  modal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
  document.addEventListener('keydown', modal._keyHandler);

  modal._detailAbort = typeof AbortController === 'function' ? new AbortController() : null;
  modal._detailTimer = setTimeout(function() {
    modal._detailExpired = true;
    if (modal._detailAbort) modal._detailAbort.abort();
    if (modal._seasonAbort) modal._seasonAbort.abort();
    showMovieDetailError(modal, imdbId, localFileName, localizedTitle, false);
  }, 15000);
  fetch('/api/movies/detail?id=' + encodeURIComponent(imdbId), modal._detailAbort ? { signal: modal._detailAbort.signal } : undefined)
    .then(function(r) { if (r.ok === false) throw new Error('detail unavailable'); return r.json(); }).then(function(m) {
    if (document.getElementById('movie-modal') !== modal || modal._detailExpired) return;
    if (modal._detailTimer) clearTimeout(modal._detailTimer);
    if (!m || m.Response === 'False' || !m.Title) {
      showMovieDetailError(modal, imdbId, localFileName, localizedTitle, true);
      return;
    }

    var poster = sanitizeURL((m.Poster && m.Poster !== 'N/A') ? m.Poster : '');
    // Use localized title (from TMDB Spanish) for eMule searches
    var searchTitle = escapeAttr(localizedTitle || m.Title || '');

    var backdropUrl = sanitizeURL(m.Backdrop || '') || poster;

    // Build buttons — Play ALWAYS visible
    var buttons = '';
    var seriesUI = '';
    var movieYear = m.Year || '';

    var isSeries = m.Type === 'series';
    var seasons = isSeries ? orderedSeasons(m.seasons) : [];
    var episodeBrowser = isSeries && !localFileName && seasons.length > 0;
    if (isSeries && !localFileName) {
      seriesUI = episodeBrowser ? '<section class="ep-browser" aria-labelledby="ep-heading">' +
        '<div class="ep-head"><div><h2 class="ep-heading" id="ep-heading">Episodios</h2>' +
        '<p class="ep-sub" id="tv-picker-status" role="status">Cargando episodios…</p></div>' +
        '<button type="button" class="ep-whole" id="ep-whole-btn" onclick="searchWholeSeries()">Buscar serie completa</button></div>' +
        '<div class="ep-seasons" id="ep-seasons" role="tablist" aria-label="Temporadas"></div>' +
        '<div class="ep-sources ep-whole-sources" id="ep-whole-sources"></div>' +
        '<button type="button" id="tv-season-retry" class="ep-retry" hidden>Reintentar episodios</button>' +
        '<div id="ep-panel"></div></section>' :
        '<p class="modal-availability">No hay temporadas verificadas en esta ficha. La búsqueda usará el título de la serie.</p>';
    }

    var playIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none" style="margin-right:6px;vertical-align:-2px"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>';
    var dlIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>';
    var trIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>';
    var searchIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>';
    var listIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:6px;vertical-align:-2px"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"></path></svg>';

    var tEsc = searchTitle;
    var yArg = m.Type === 'series' ? '' : escapeAttr(movieYear);

    // Store movie data globally so Mi Lista button avoids escaping issues
    var savedId = m.imdbID || m.catalogId || imdbId;
    window._modalMovie = { imdbId: savedId, catalogId: m.catalogId || imdbId, type: m.Type === 'series' ? 'tv' : 'movie', title: m.Title || localizedTitle || '', poster: (m.Poster && m.Poster !== 'N/A') ? m.Poster : '', year: movieYear };

    if (localFileName) {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="playInModal(\'' + escapeAttr(encodeURIComponent(localFileName)) + '\')">' + playIcon + ' Reproducir local</button>';
    } else if (episodeBrowser) {
      // Episode actions resolve the selected episode when clicked.
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" disabled onclick="seriesHeroAction(\'play\')">' + playIcon + '<span class="btn-label" id="modal-play-label">Cargando episodios…</span></button>';
      buttons += '<button class="modal-btn btn-download" id="modal-download-btn" disabled onclick="seriesHeroAction(\'download\')">' + dlIcon + '<span class="btn-label" id="modal-download-label">Descargar</span></button>';
    } else {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="smartPlay(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + playIcon + ' Buscar y reproducir</button>';
      buttons += '<button class="modal-btn btn-download" id="modal-download-btn" onclick="smartDownload(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + dlIcon + ' Descargar</button>';
    }
    buttons += '<button class="modal-btn btn-trailer" id="trailer-btn" onclick="loadTrailer(\'' + escapeAttr((m.Title || '') + ' ' + movieYear) + '\')">' + trIcon + ' Tráiler</button>';
    if (!localFileName) {
      buttons += '<button class="modal-btn btn-emule" id="modal-emule-btn"' + (episodeBrowser ? ' disabled' : '') + ' onclick="startEmuleSearch(window.getTvQuery(\'' + tEsc + '\'), \'' + yArg + '\')">' + searchIcon + ' Fuentes</button>';
    }
    // Mi Lista — usa global _modalMovie, sin infierno de escaping
    var inList = typeof isInMyList === 'function' && isInMyList(savedId);
    buttons += '<button class="modal-btn btn-list' + (inList ? ' btn-list-active' : '') + '" id="modal-list-btn" aria-pressed="' + Boolean(inList) + '" aria-label="' + (inList ? 'Guardado. Quitar de Guardados' : 'Guardar en Biblioteca') + '" title="' + (inList ? 'Quitar de Guardados' : 'Guardar en Biblioteca') + '" onclick="toggleMyListBtn(this)">' + listIcon + (inList ? ' Guardado' : ' Guardar') + '</button>';

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
    var rating = m.Rating || m.imdbRating;
    if (rating && rating !== 'N/A') meta += '<span class="modal-rating"><svg width="12" height="12" viewBox="0 0 24 24" fill="#f5c518" stroke="none" style="vertical-align:-1px;margin-right:3px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>' + escapeHTML(rating) + ' · ' + escapeHTML(m.RatingSource || 'IMDb') + '</span>';
    if (m.Year) meta += '<span class="modal-badge">' + escapeHTML(m.Year) + '</span>';
    if (m.Runtime && m.Runtime !== 'N/A') meta += '<span class="modal-badge">' + escapeHTML(m.Runtime) + '</span>';
    if (m.Rated && m.Rated !== 'N/A') meta += '<span class="modal-badge">' + escapeHTML(m.Rated) + '</span>';
    if (m.Genre && m.Genre !== 'N/A') {
      translateGenres(m.Genre).split(',').forEach(function(g) {
        meta += '<span class="modal-badge">' + escapeHTML(g.trim()) + '</span>';
      });
    }

    var seasonCount = seasons.filter(function(s) { return Number(s.number) > 0; }).length;
    var longPlot = String(m.Plot || '').length > 320;
    var kicker = isSeries ? 'Serie' + (seasonCount ? ' · ' + seasonCount + (seasonCount === 1 ? ' temporada' : ' temporadas') : '') : 'Película';
    var availability = localFileName ? 'Archivo disponible en tu biblioteca.'
      : episodeBrowser ? 'Elige un episodio abajo. La reproducción depende de las fuentes de la red y puede iniciar una descarga.'
      : 'La reproducción depende de las fuentes disponibles y puede iniciar una descarga.';

    modal.className = 'movie-modal active ' + (backdropUrl ? 'has-artwork' : 'no-artwork') + (isSeries ? ' is-series' : '');
    modal.innerHTML = movieModalCloseButton() +
      '<div id="modal-player-zone" style="display:none"></div>' +
      '<div id="modal-info-zone">' +
        (backdropUrl ? '<div class="modal-backdrop" style="background-image:url(' + escapeHTML(backdropUrl) + ')"></div>' : '') +
        '<div class="modal-content">' +
          '<div class="title-hero">' +
            '<p class="title-kicker">' + escapeHTML(kicker) + '</p>' +
            '<h1 class="modal-title">' + escapeHTML(m.Title || '') + '</h1>' +
            '<div class="modal-meta">' + meta + '</div>' +
            '<p class="modal-plot' + (longPlot ? ' is-clamped' : '') + '">' + escapeHTML(m.Plot || 'Sin sinopsis disponible') + '</p>' +
            (longPlot ? '<button type="button" class="plot-more" onclick="this.previousElementSibling.classList.remove(\'is-clamped\');this.remove()">Leer más</button>' : '') +
            '<div class="modal-buttons">' + buttons + '</div>' +
            '<p class="modal-availability">' + availability + '</p>' +
          '</div>' +
          '<div id="trailer-container"></div>' +
          seriesUI +
          (details ? '<section class="title-details" aria-labelledby="title-details-heading"><h2 class="title-section-heading" id="title-details-heading">Detalles</h2>' +
            '<div class="modal-details">' + details + '</div></section>' : '') +
        '</div>' +
      '</div>';
    if (episodeBrowser) configureSeriesPicker(modal, m, localizedTitle || m.Title || '');

  }).catch(function() {
    if (modal._detailTimer) clearTimeout(modal._detailTimer);
    showMovieDetailError(modal, imdbId, localFileName, localizedTitle, false);
  });
}

window.getTvQuery = function(baseTitle) {
  var state = seriesState();
  var ep = state && !state.loading ? findEpisode(state, state.episode) : null;
  return ep && !isUpcoming(ep) ? episodeQuery(baseTitle, state.season, Number(ep.number)) : baseTitle;
};

function closeMovieModal() {
  if (typeof stopCinemaPlayback === 'function') stopCinemaPlayback();
  if (typeof stopSmartPlay === 'function') stopSmartPlay();
  // Fallback also covers a partially initialized player.
  try { video.pause(); video.removeAttribute('src'); video.load(); } catch(e) {}
  if (typeof abortController !== 'undefined' && abortController) { try { abortController.abort(); } catch(e) {} }
  try { video.querySelectorAll('track').forEach(function(t) { t.remove(); }); } catch(e) {}

  var modal = document.getElementById('movie-modal');
  if (modal) {
    if (modal._detailAbort) modal._detailAbort.abort();
    if (modal._seasonAbort) modal._seasonAbort.abort();
    if (modal._detailTimer) clearTimeout(modal._detailTimer);
    if (modal._keyHandler) document.removeEventListener('keydown', modal._keyHandler);
    modal.remove();
  }
  document.body.style.overflow = modal && modal._previousOverflow !== undefined ? modal._previousOverflow : '';
  if (modal && window._detailReturnTo) {
    var returnTo = window._detailReturnTo;
    window._detailReturnTo = null;
    if (/^\/(explore|search|mylist)(\?[^#\r\n]*)?$/.test(returnTo)) window.location.replace(returnTo);
  }
}

// ── Búsqueda avanzada en eMule ─────────────────────────────────────────────────
// targetId lets an episode row show its own results; the hero uses trailer-container.
function startEmuleSearch(title, year, targetId) {
  var searchDiv = document.getElementById(targetId || 'trailer-container');
  if (!searchDiv) { smartSearchOverlay(title); return; }

  var searchQuery = title + (year ? ' ' + year : '');
  var request = (searchDiv._searchRequest || 0) + 1;
  searchDiv._searchRequest = request;
  function current() { return searchDiv._searchRequest === request && document.getElementById(targetId || 'trailer-container') === searchDiv; }
  function panel(body) {
    return '<div class="src-panel"><div class="src-head"><p class="src-query">Búsqueda en eMule: <strong>' + escapeHTML(searchQuery) + '</strong></p>' +
      '<button type="button" class="src-close" aria-label="Cerrar resultados" onclick="this.closest(\'.src-panel\').remove()">&times;</button></div>' + body + '</div>';
  }
  searchDiv.innerHTML = panel('<div class="src-state" role="status"><div class="spinner" aria-hidden="true"></div><span>Buscando fuentes… puede tardar unos segundos.</span></div>');

  fetch('/api/emule/search?q=' + encodeURIComponent(searchQuery)).then(function(r) { return r.json(); }).then(function(data) {
    if (!current()) return;
    if (!data.success) {
      searchDiv.innerHTML = panel('<p class="src-state src-error" role="status">' + escapeHTML(data.error || 'Error de conexión') + '</p>');
      return;
    }

    if (!data.results || data.results.length === 0) {
      searchDiv.innerHTML = panel('<p class="src-state" role="status">No se encontraron fuentes para «' + escapeHTML(title) + '». Prueba más tarde o con otra temporada.</p>');
      return;
    }

    var html = '<div class="src-count" role="status">' + data.results.length + (data.results.length === 1 ? ' fuente encontrada' : ' fuentes encontradas') + '</div>' +
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
      var scoreBadge = '<span class="source-badge badge-score">Puntuación ' + safeScore + '</span>';
      var sourcesBadge = '<span class="source-badge badge-sources">' + safeSources + ' fuentes · ' + safeComplete + ' completas</span>';
      var fakeBadge = r.isFake ? '<span class="source-badge badge-fake">Posible falso</span>' : '';

      html += '<div class="source-item' + (i === 0 ? ' is-best' : '') + '">' +
        '<div class="source-name">' + (i === 0 ? '<span class="source-best">Mejor opción</span>' : '') + '<span class="source-file">' + safeFileName + '</span><span class="source-size">' + safeSizeMB + ' MB</span></div>' +
        '<div class="source-meta">' + qualityBadge + langBadge + sourcesBadge + scoreBadge + fakeBadge + '</div>' +
        '<div class="source-actions">' +
          '<button type="button" class="source-btn source-btn-play" onclick="streamSource(\'' + safeHash + '\', \'' + safeTitleAttr + '\')" title="Reproducir ahora">Reproducir</button>' +
          '<button type="button" class="source-btn source-btn-dl" onclick="downloadSource(\'' + safeHash + '\')" title="Descargar para ver luego">Descargar</button>' +
        '</div>' +
      '</div>';
    });

    html += '</div>';
    searchDiv.innerHTML = panel(html);

  }).catch(function(err) {
    if (!current()) return;
    searchDiv.innerHTML = panel('<p class="src-state src-error" role="status">Error: ' + escapeHTML(err.message) + '</p>');
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
  fetch('/api/emule/download?hash=' + encodeURIComponent(hash), { headers: { 'X-Requested-With': 'eSE' } }).then(function(r) { return r.json(); }).then(function(data) {
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
  var modal = document.getElementById('movie-modal');
  if (!hash || !modal) return;
  var operation = (modal._streamRequest || 0) + 1;
  modal._streamRequest = operation;
  function isCurrent() { return document.getElementById('movie-modal') === modal && modal._streamRequest === operation; }
  fetch('/api/emule/download?hash=' + encodeURIComponent(hash), { headers: { 'X-Requested-With': 'eSE' } }).then(function(r) { return r.json(); }).then(function(data) {
    if (!isCurrent()) return;
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
            '<p role="status" style="color:#b9bac6;font-size:14px;text-align:center;max-width:400px" id="smart-play-status">Esperando a que eMule reciba datos…</p>' +
            '<div id="smart-play-progress" hidden></div>' +
          '</div>' +
        '</div>';
      }

      window._smartPlayTitle = movieTitle;
      monitorForFile(movieTitle, '', 0, 0);
    } else {
      showNotification(' Error: ' + (data.error || 'No se pudo iniciar'));
    }
  }).catch(function() {
    if (!isCurrent()) return;
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
