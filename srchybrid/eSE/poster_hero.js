// poster_hero.js — posters locales, barra de progreso de visionado, hero TMDB
//
// NOTE: All TMDB calls go through the /api/tmdb/* proxy (see routes/movies_routes.js).
// The proxy injects the server-side API key, so the key is no longer exposed in
// the client bundle. Image CDN (image.tmdb.org) is public and used directly.

// ── Posters para archivos locales ─────────────────────────────────────────────
function fetchLocalPosters() {
  var cards = document.querySelectorAll('.card[data-title]');
  cards.forEach(function(card) {
    var raw = decodeURIComponent(card.getAttribute('data-filename') || '') || card.getAttribute('data-title');
    if (!raw) return;

    // Keep episodic filenames intact until a series/episode matcher is available.
    // A movie search must never turn a Breaking Bad episode into El Camino.
    if (/\bS\d{1,2}E\d{1,3}\b|\b\d{1,2}x\d{2,3}\b/i.test(raw)) return;
    var fileYear = raw.match(/\b((?:19|20)\d{2})\b/);
    card._posterYear = fileYear ? fileYear[1] : '';

    // Check if filename has embedded TMDB ID (e.g., [tmdbid-1297842])
    var embeddedId = raw.match(/\[tmdbid[- ]?(\d+)\]/i);
    var tmdbId = embeddedId ? embeddedId[1] : null;

    // Smart filename cleaning for P2P files
    var candidates = extractMovieTitles(raw);
    var displayTitle = card.getAttribute('data-title');
    if (displayTitle && candidates.indexOf(displayTitle) === -1) candidates.unshift(displayTitle);

    if (tmdbId) {
      // Direct TMDB lookup — guaranteed accurate
      fetch('/api/tmdb/movie/' + encodeURIComponent(tmdbId) + '?language=es-ES')
        .then(function(r) { return r.json(); })
        .then(function(m) {
          if (m && m.poster_path) {
            applyPosterToCard(card, {
              poster: 'https://image.tmdb.org/t/p/w500' + m.poster_path,
              title: m.title || m.original_title,
              year: (m.release_date || '').substring(0, 4),
              imdbId: m.imdb_id
            });
          } else if (candidates.length > 0) {
            tryTMDBCandidate(candidates, 0, card);
          }
        }).catch(function() { if (candidates.length > 0) tryTMDBCandidate(candidates, 0, card); });
    } else if (candidates.length > 0) {
      tryTMDBCandidate(candidates, 0, card);
    }
  });
}

function tryTMDBCandidate(candidates, idx, card) {
  if (idx >= candidates.length) return;
  var query = candidates[idx].replace(/\b(?:19|20)\d{2}\b/g, '').trim();
  fetch('/api/tmdb/search/movie?language=es-ES&query=' + encodeURIComponent(query) +
    (card._posterYear ? '&primary_release_year=' + card._posterYear : ''))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var m = matchLibraryMovie(data.results, candidates, card._posterYear);
      if (m) {
        // Get IMDB ID for detailed modal
        fetch('/api/tmdb/movie/' + encodeURIComponent(m.id) + '/external_ids')
          .then(function(r) { return r.json(); })
          .then(function(ids) {
            applyPosterToCard(card, {
              poster: m.poster_path ? 'https://image.tmdb.org/t/p/w500' + m.poster_path : null,
              title: m.title || m.original_title,
              year: (m.release_date || '').substring(0, 4),
              imdbId: ids.imdb_id || null
            });
          }).catch(function() {
            applyPosterToCard(card, {
              poster: m.poster_path ? 'https://image.tmdb.org/t/p/w500' + m.poster_path : null,
              title: m.title, year: (m.release_date || '').substring(0, 4), imdbId: null
            });
          });
      } else {
        tryTMDBCandidate(candidates, idx + 1, card);
      }
    }).catch(function() { tryTMDBCandidate(candidates, idx + 1, card); });
}

function normalizeLibraryText(value) {
  return String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

function matchLibraryMovie(results, candidates, year) {
  var normalizeTitle = function(value) {
    return normalizeLibraryText(value).replace(/\b(?:19|20)\d{2}\b/g, '').replace(/[^a-z0-9]/g, '');
  };
  var names = candidates.map(normalizeTitle).filter(Boolean);
  var matches = (Array.isArray(results) ? results : []).filter(function(movie) {
    if (year && String(movie.release_date || '').slice(0, 4) !== year) return false;
    return [movie.title, movie.original_title].some(function(title) {
      return title && names.indexOf(normalizeTitle(title)) !== -1;
    });
  });
  // Ambiguous titles stay attached to the original file, not the first result.
  return matches.length === 1 ? matches[0] : null;
}

function filterLibrary(query) {
  var count = 0;
  var cards = document.querySelectorAll('#library-grid .card');
  var term = normalizeLibraryText(query).trim();
  cards.forEach(function(card) {
    var text = (card.getAttribute('data-title') || '') + ' ' +
      (card.getAttribute('data-display-title') || '') + ' ' +
      decodeURIComponent(card.getAttribute('data-filename') || '');
    card.hidden = normalizeLibraryText(text).indexOf(term) === -1;
    if (!card.hidden) count++;
  });
  var status = document.getElementById('library-count');
  if (status) status.textContent = term ? count + ' de ' + cards.length + ' archivos' : cards.length + ' archivos disponibles';
  var empty = document.getElementById('library-empty');
  if (empty) empty.hidden = count > 0;
}

function clearLibraryFilter() {
  var input = document.getElementById('library-query');
  if (input) { input.value = ''; filterLibrary(''); input.focus(); }
}

function applyPosterToCard(card, info) {
  if (info.poster) {
    var posterUrl = sanitizeURL(info.poster);
    if (posterUrl) {
      var posterDiv = card.querySelector('.card-poster');
      if (posterDiv) {
        posterDiv.style.backgroundImage = 'url(' + posterUrl.replace(/[()]/g, '') + ')';
        posterDiv.style.backgroundSize = 'cover';
        posterDiv.style.backgroundPosition = 'center';
        posterDiv.classList.add('has-poster');
        var playIcon = posterDiv.querySelector('.play-icon');
        if (playIcon) playIcon.style.display = '';
      }
    }
  }
  if (info.imdbId) card.setAttribute('data-imdbid', info.imdbId);
  if (info.title) card.setAttribute('data-display-title', info.title);
  var titleEl = card.querySelector('.card-title');
  if (titleEl && info.title) titleEl.textContent = info.title + (info.year ? ' (' + info.year + ')' : '');
  var libraryQuery = document.getElementById('library-query');
  if (libraryQuery && libraryQuery.value) filterLibrary(libraryQuery.value);
}

// Local file names are data, never executable inline JavaScript.
function playLibraryCard(card) {
  var encoded = card.getAttribute('data-filename') || '';
  var completed = card.getAttribute('data-completed') === 'true';
  var imdb = card.getAttribute('data-imdbid');
  if (imdb) {
    showMovieDetail(imdb, completed ? decodeURIComponent(encoded) : null,
      card.getAttribute('data-display-title') || card.getAttribute('data-title'));
  } else if (completed) {
    playCompleted(encoded);
  } else {
    playVideo(card.getAttribute('data-part'));
  }
}

// Resume positions are exact times; do not invent a percentage from a 2h film.
function addWatchProgressBars() {
  var resumeData;
  try { resumeData = JSON.parse(localStorage.getItem('ese_resume') || '{}'); } catch (_) { return; }
  if (!resumeData || typeof resumeData !== 'object') return;
  document.querySelectorAll('.card[data-filename]').forEach(function(card) {
    var data = resumeData[decodeURIComponent(card.getAttribute('data-filename'))];
    if (!data || !Number.isFinite(data.time) || data.time < 30 || card.querySelector('.watch-progress')) return;
    var note = document.createElement('span');
    note.className = 'card-meta-item watch-progress';
    note.textContent = 'Visto hasta ' + Math.floor(data.time / 60) + ' min';
    card.querySelector('.card-meta-row').appendChild(note);
  });
}
setTimeout(addWatchProgressBars, 3000);

// ── Limpieza de nombres de archivo P2P ────────────────────────────────────────
function extractMovieTitles(raw) {
  var candidates = [];
  var s = raw.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i, '');
  s = s.replace(/[._]/g, ' ');

  // Extract TMDB ID if present (e.g., [tmdbid-1297842])
  var tmdbMatch = s.match(/\[tmdbid[- ]?(\d+)\]/i);
  if (tmdbMatch) {
    window._tmdbFromFilename = window._tmdbFromFilename || {};
    window._tmdbFromFilename[raw] = tmdbMatch[1];
  }

  var yearMatch = s.match(/((?:19|20)\d{2})/);
  var year = yearMatch ? yearMatch[1] : '';

  // Strip leading site names in brackets: [PeliculasBluray Com], etc.
  s = s.replace(/^\s*\[.*?\]\s*/g, '');

  var noParen = s.replace(/\(.*?\)/g, ' ').replace(/\[.*?\]/g, ' ');

  var tags = /\b(HDRip|BRRip|DVDRip|WEBRip|WEB-DL|WEB|BluRay|BDRip|CAMRip|TS|HDTS|1080p|720p|480p|2160p|4K|x264|x265|HEVC|H264|H265|AVC|AAC|EAC3|AC3|DTS|Dolby|Digital|Plus|5\.1|7\.1|MP3|Xvid|DivX|EliteTorrent|YIFY|RARBG|net|com|org|Spanish|Castellano|Español|Latino|English|VOSE|Dual|Audio|HDR|10bit|Remux|IMAX|Directors\.?Cut|Extended|Unrated|Remastered|PROPER|REPACK|DVDRIP|DVDSCR|LasCositas|spa|eng|fre|ger|ita|por|jpn|chi|kor|SUB|Subtitulos)\b/gi;

  var cleaned = noParen.replace(tags, ' ')
    .replace(/\s*-\s*$/, '')
    .replace(/\s{2,}/g, ' ').trim();

  var beforeYear = cleaned;
  if (year) {
    var idx = cleaned.indexOf(year);
    if (idx > 0) beforeYear = cleaned.substring(0, idx).trim();
  }

  var parts = beforeYear.split(/\s*[-–—]\s*/).filter(function(p) { return p.trim().length > 2; });

  if (parts[0] && parts[0].trim().length > 2) {
    candidates.push(parts[0].trim() + (year ? ' ' + year : ''));
    candidates.push(parts[0].trim());
  }

  if (beforeYear.length > 2 && candidates.indexOf(beforeYear) === -1) {
    candidates.push(beforeYear + (year ? ' ' + year : ''));
    candidates.push(beforeYear);
  }

  if (parts[1] && parts[1].trim().length > 3) {
    candidates.push(parts[1].trim() + (year ? ' ' + year : ''));
  }

  return candidates;
}

setTimeout(fetchLocalPosters, 1000);

// ── Hero section (TMDB trending) ──────────────────────────────────────────────
var heroMovies = [];
var heroIndex = 0;
var heroInterval = null;

function toggleHeaderSearch() {
  var s = document.getElementById('header-search');
  if (s) {
    var visible = s.style.display !== 'none';
    s.style.display = visible ? 'none' : 'block';
    if (!visible) {
      var input = document.getElementById('search-input');
      if (input) input.focus();
    }
  }
}

function loadHero() {
  fetch('/api/tmdb/trending/movie/week?language=es-ES')
    .then(function(r) { if (!r.ok) throw new Error('catalog unavailable'); return r.json(); })
    .then(function(data) {
      heroMovies = (Array.isArray(data.results) ? data.results : []).filter(function(m) { return m.backdrop_path; }).slice(0, 8);
      if (heroMovies.length) showHeroMovie(0);
    })
    .catch(function() {
      var meta = document.getElementById('hero-meta');
      if (meta) meta.textContent = 'El catálogo no está disponible ahora. Tu biblioteca sigue aquí.';
    });
}

// Manual navigation keeps reading and keyboard focus stable.
function stepHero(direction) {
  if (!heroMovies.length) return;
  heroIndex = (heroIndex + direction + heroMovies.length) % heroMovies.length;
  showHeroMovie(heroIndex);
}

function showHeroMovie(idx) {
  var m = heroMovies[idx];
  if (!m) return;

  var hero = document.getElementById('hero');
  if (hero) hero.classList.add('hero-ready');
  var backdrop = document.getElementById('hero-backdrop');
  var title = document.getElementById('hero-title');
  var desc = document.getElementById('hero-desc');
  var meta = document.getElementById('hero-meta');
  var playBtn = document.getElementById('hero-play-btn');
  var infoBtn = document.getElementById('hero-info-btn');

  if (backdrop && m.backdrop_path && /^\/[a-zA-Z0-9]+\.\w{3,4}$/.test(m.backdrop_path)) {
    backdrop.style.backgroundImage = 'url(https://image.tmdb.org/t/p/w1280' + m.backdrop_path + ')';
  }
  if (title) title.textContent = m.title || m.name;
  var eyebrow = document.getElementById('hero-eyebrow');
  if (eyebrow) eyebrow.textContent = 'EN TENDENCIA · ESTA SEMANA';
  var fallback = document.getElementById('hero-explore-btn');
  if (fallback) fallback.style.display = 'none';
  var counter = document.getElementById('hero-counter');
  if (counter) counter.textContent = (idx + 1) + ' / ' + heroMovies.length;
  ['hero-prev', 'hero-next'].forEach(function(id) {
    var control = document.getElementById(id);
    if (control) control.disabled = heroMovies.length < 2;
  });
  if (desc) desc.textContent = (m.overview || '').substring(0, 200) + (m.overview && m.overview.length > 200 ? '...' : '');
  if (meta) meta.textContent = [m.vote_average ? '★ ' + Number(m.vote_average).toFixed(1) : '', (m.release_date || '').substring(0, 4), 'Disponibilidad según fuentes'].filter(Boolean).join(' · ');
  if (playBtn) { playBtn.style.display = 'inline-block'; playBtn.setAttribute('data-title', m.title || m.name); playBtn.setAttribute('data-id', m.id); }
  if (infoBtn) { infoBtn.style.display = 'inline-block'; infoBtn.setAttribute('data-title', m.title || m.name); infoBtn.setAttribute('data-id', m.id); }

  window._heroCurrentMovie = m;
}

function heroPlay() {
  var m = window._heroCurrentMovie;
  if (!m) return;
  var title = m.title || m.name;
  var year = (m.release_date || '').substring(0, 4);

  var old = document.getElementById('movie-modal');
  if (old) old.remove();
  var modal = document.createElement('div');
  modal.id = 'movie-modal';
  modal.className = 'movie-modal active';
  modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
    '<div id="modal-player-zone"></div>' +
    '<div id="modal-info-zone" style="display:none"></div>';
  document.body.appendChild(modal);
  document.body.style.overflow = 'hidden';
  modal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
  document.addEventListener('keydown', modal._keyHandler);

  smartPlay(title, year);
}

function heroInfo() {
  var m = window._heroCurrentMovie;
  if (!m) return;
  var title = m.title || m.name;
  var type = m.media_type || ((m.first_air_date || (!m.title && m.name)) ? 'tv' : 'movie');
  if (!/^[1-9][0-9]{0,9}$/.test(String(m.id)) || (type !== 'movie' && type !== 'tv')) return;
  showMovieDetail('tmdb:' + type + ':' + m.id, null, title);
}

setTimeout(loadHero, 500);
