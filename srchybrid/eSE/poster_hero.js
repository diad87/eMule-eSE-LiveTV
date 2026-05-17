// poster_hero.js — posters locales, barra de progreso de visionado, hero TMDB
//
// NOTE: All TMDB calls go through the /api/tmdb/* proxy (see routes/movies_routes.js).
// The proxy injects the server-side API key, so the key is no longer exposed in
// the client bundle. Image CDN (image.tmdb.org) is public and used directly.

// ── Posters para archivos locales ─────────────────────────────────────────────
function fetchLocalPosters() {
  var cards = document.querySelectorAll('.card[data-title]');
  cards.forEach(function(card) {
    var raw = card.getAttribute('data-title');
    if (!raw) return;

    // Check if filename has embedded TMDB ID (e.g., [tmdbid-1297842])
    var tmdbId = (window._tmdbFromFilename && window._tmdbFromFilename[raw]) || null;

    // Smart filename cleaning for P2P files
    var candidates = extractMovieTitles(raw);

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
  if (idx >= candidates.length) {
    tryOMDbFallback(candidates, card);
    return;
  }
  var query = candidates[idx];
  fetch('/api/tmdb/search/movie?language=es-ES&query=' + encodeURIComponent(query))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.results && data.results.length > 0) {
        var m = data.results[0];
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

function tryOMDbFallback(candidates, card) {
  if (!candidates || candidates.length === 0) return;
  fetch('/api/movies/fetchinfo?title=' + encodeURIComponent(candidates[0]))
    .then(function(r) { return r.json(); })
    .then(function(info) {
      if (info && info.Poster && info.Poster !== 'N/A') {
        applyPosterToCard(card, {
          poster: info.Poster, title: info.Title,
          year: info.Year, imdbId: info.imdbID
        });
      }
    }).catch(function() {});
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
        var playIcon = posterDiv.querySelector('.play-icon');
        if (playIcon) playIcon.style.display = 'none';
      }
    }
  }
  if (info.imdbId) {
    card.setAttribute('data-imdbid', info.imdbId);
    var origOnclick = card.getAttribute('onclick') || '';
    var fnMatch = origOnclick.match(/playCompleted\('([^']+)'\)/);
    var safeTitle = escapeAttr(info.title || '');
    var safeImdb = escapeAttr(info.imdbId || '');
    if (fnMatch) {
      var localFile = escapeAttr(decodeURIComponent(fnMatch[1]));
      card.setAttribute('onclick', "showMovieDetail('" + safeImdb + "','" + localFile + "','" + safeTitle + "')");
    } else {
      card.setAttribute('onclick', "showMovieDetail('" + safeImdb + "',null,'" + safeTitle + "')");
    }
  }
  var titleEl = card.querySelector('.card-title');
  if (titleEl && info.title) titleEl.textContent = info.title + (info.year ? ' (' + info.year + ')' : '');
}

// ── Barra de progreso de visionado (Netflix-style) ────────────────────────────
function addWatchProgressBars() {
  var resumeData = JSON.parse(localStorage.getItem('ese_resume') || '{}');
  var cards = document.querySelectorAll('.card[data-title]');
  cards.forEach(function(card) {
    var onclick = card.getAttribute('onclick') || '';
    var fnMatch = onclick.match(/playCompleted\('([^']+)'\)/) || onclick.match(/showMovieDetail\('[^']*','([^']+)'\)/);
    if (!fnMatch) return;
    var fileName = decodeURIComponent(fnMatch[1]);
    var data = resumeData[fileName];
    if (!data || data.time < 30) return;

    var progress = Math.min(95, (data.time / 7200) * 100); // assume 2h movie

    var existing = card.querySelector('.watch-progress');
    if (!existing) {
      var bar = document.createElement('div');
      bar.className = 'watch-progress';
      bar.style.cssText = 'position:absolute;bottom:0;left:0;right:0;height:4px;background:rgba(255,255,255,0.2);z-index:5';
      var fill = document.createElement('div');
      fill.style.cssText = 'height:100%;background:#e50914;border-radius:0 2px 2px 0;width:' + progress + '%';
      bar.appendChild(fill);
      card.style.position = 'relative';
      card.appendChild(bar);
    }
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
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.results || !data.results.length) return;
      heroMovies = data.results.filter(function(m) { return m.backdrop_path; }).slice(0, 8);
      if (heroMovies.length > 0) {
        showHeroMovie(0);
        heroInterval = setInterval(function() {
          heroIndex = (heroIndex + 1) % heroMovies.length;
          showHeroMovie(heroIndex);
        }, 10000);
      }
    })
    .catch(function() {});
}

function showHeroMovie(idx) {
  var m = heroMovies[idx];
  if (!m) return;

  var backdrop = document.getElementById('hero-backdrop');
  var title = document.getElementById('hero-title');
  var desc = document.getElementById('hero-desc');
  var meta = document.getElementById('hero-meta');
  var playBtn = document.getElementById('hero-play-btn');
  var infoBtn = document.getElementById('hero-info-btn');

  if (backdrop && m.backdrop_path && /^\/[a-zA-Z0-9]+\.\w{3,4}$/.test(m.backdrop_path)) {
    backdrop.style.backgroundImage = 'url(https://image.tmdb.org/t/p/original' + m.backdrop_path + ')';
  }
  if (title) title.textContent = m.title || m.name;
  if (desc) desc.textContent = (m.overview || '').substring(0, 200) + (m.overview && m.overview.length > 200 ? '...' : '');
  if (meta) meta.textContent = '⭐ ' + (m.vote_average || '').toString().substring(0, 3) + ' · ' + (m.release_date || '').substring(0, 4) + ' · Trending #' + (idx + 1);
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
  fetch('/api/tmdb/movie/' + encodeURIComponent(m.id) + '/external_ids')
    .then(function(r) { return r.json(); })
    .then(function(ids) {
      if (ids.imdb_id) {
        showMovieDetail(ids.imdb_id, null, title);
      } else {
        showNotification('No se encontró info para "' + title + '"');
      }
    })
    .catch(function() { showNotification('Error buscando info'); });
}

setTimeout(loadHero, 500);
