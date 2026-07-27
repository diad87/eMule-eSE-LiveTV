// hero_ui.js
    '<option value="auto"' + (s.quality === 'auto' ? ' selected' : '') + '>Auto (mejor disponible)</option>' +
    '<option value="720p"' + (s.quality === '720p' ? ' selected' : '') + '>720p HD</option>' +
    '<option value="1080p"' + (s.quality === '1080p' ? ' selected' : '') + '>1080p Full HD</option>' +
    '<option value="4k"' + (s.quality === '4k' ? ' selected' : '') + '>4K Ultra HD</option>' +
    '</select></div>' +
    '<div class="setting-row"><span class="setting-label">Idioma</span>' +
    '<select class="setting-select" id="set-language">' +
    '<option value="spanish"' + (s.language === 'spanish' ? ' selected' : '') + '>ES Español</option>' +
    '<option value="latino"' + (s.language === 'latino' ? ' selected' : '') + '> Latino</option>' +
    '<option value="english"' + (s.language === 'english' ? ' selected' : '') + '>EN English</option>' +
    '<option value="french"' + (s.language === 'french' ? ' selected' : '') + '>FR Français</option>' +
    '<option value="german"' + (s.language === 'german' ? ' selected' : '') + '>DE Deutsch</option>' +
    '</select></div></div>' +
    
    '<div class="settings-section"><h3> Búsqueda eMule</h3>' +
    '<div class="setting-row"><span class="setting-label">Método</span>' +
    '<select class="setting-select" id="set-method">' +
    '<option value="kad"' + (s.searchMethod === 'kad' ? ' selected' : '') + '>Kademlia (más fuentes)</option>' +
    '<option value="global"' + (s.searchMethod === 'global' ? ' selected' : '') + '>Global (más rápido)</option>' +
    '<option value="server"' + (s.searchMethod === 'server' ? ' selected' : '') + '>Servidor actual</option>' +
    '</select></div>' +
    '<div class="setting-row"><span class="setting-label">Tamaño mínimo</span>' +
    '<select class="setting-select" id="set-minsize">' +
    '<option value="100"' + (s.minSizeMB <= 100 ? ' selected' : '') + '>100 MB</option>' +
    '<option value="300"' + (s.minSizeMB === 300 ? ' selected' : '') + '>300 MB (recomendado)</option>' +
    '<option value="700"' + (s.minSizeMB === 700 ? ' selected' : '') + '>700 MB (DVD+)</option>' +
    '<option value="1500"' + (s.minSizeMB >= 1500 ? ' selected' : '') + '>1.5 GB (HD+)</option>' +
    '</select></div></div>' +
    
    '<div class="settings-section"><h3> Conexión eMule WebServer</h3>' +
    '<div style="margin-bottom:12px"><span class="setting-label">Contraseña</span>' +
    '<input type="password" class="setting-input" id="set-password" value="' + (s.emulePassword || '') + '" placeholder="Contraseña del WebServer (puerto 4711)" style="margin-top:6px"></div>' +
    '<button class="modal-btn btn-trailer" style="width:100%;justify-content:center" onclick="testEmuleConnection()"> Probar conexión</button>' +
    '<div id="emule-test-status"></div></div>' +
    
    '<div class="settings-section">' +
    '<button class="settings-save" onclick="saveSettingsPanel()"> Guardar Ajustes</button></div>';
  
  document.body.appendChild(panel);
  
  // Check eMule status on open
  fetch('/api/emule/status').then(function(r) { return r.json(); }).then(function(data) {
    var el = document.getElementById('emule-test-status');
    if (el && data.loggedIn) {
      el.innerHTML = '<div class="emule-status ok">Conectado a eMule WebServer</div>';
    }
  }).catch(function() {});
}

function testEmuleConnection() {
  var pw = document.getElementById('set-password').value;
  var status = document.getElementById('emule-test-status');
  if (status) status.innerHTML = '<div class="emule-status" style="color:#888;background:rgba(255,255,255,.05);border:1px solid #333"><div class="spinner" style="width:16px;height:16px;border-width:2px"></div> Conectando...</div>';
  
  fetch('/api/emule/login?p=' + encodeURIComponent(pw)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.success) {
      if (status) status.innerHTML = '<div class="emule-status ok"> Conectado correctamente (sesión: ' + data.session + ')</div>';
    } else {
      if (status) status.innerHTML = '<div class="emule-status err"> ' + (data.error || 'Fallo de conexión') + '</div>';
    }
  }).catch(function() {
    if (status) status.innerHTML = '<div class="emule-status err"> No se puede conectar al puerto 4711</div>';
  });
}

function saveSettingsPanel() {
  var newSettings = {
    quality: document.getElementById('set-quality').value,
    language: document.getElementById('set-language').value,
    searchMethod: document.getElementById('set-method').value,
    minSizeMB: parseInt(document.getElementById('set-minsize').value),
    emulePassword: document.getElementById('set-password').value
  };
  
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(newSettings)
  }).then(function(r) { return r.json(); }).then(function(saved) {
    showNotification(' Ajustes guardados');
    document.getElementById('settings-panel').remove();
    
    // Auto-login if password was set
    if (saved.emulePassword) {
      fetch('/api/emule/login?p=' + encodeURIComponent(saved.emulePassword));
    }
  }).catch(function() {
    showNotification(' Error al guardar');
  });
}

setTimeout(fetchLocalPosters, 1000);

// Play completed file - now delegates to modal player
function playCompleted(encodedName) {
  // If modal is open, play inside it
  var modal = document.getElementById('movie-modal');
  if (modal) {
    playInModal(encodedName);
    return;
  }
  // Fallback: open a quick modal with just the player
  var fileName = decodeURIComponent(encodedName);
  var quickModal = document.createElement('div');
  quickModal.id = 'movie-modal';
  quickModal.className = 'movie-modal active';
  quickModal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
    '<div id="modal-player-zone"></div>' +
    '<div id="modal-info-zone" style="display:none"></div>';
  document.body.appendChild(quickModal);
  document.body.style.overflow = 'hidden';
  quickModal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
  document.addEventListener('keydown', quickModal._keyHandler);
  playInModal(encodedName);
}

function startCompletedMSE(fileName, quality, seekSec) {
  // Direct video.src approach: server produces fragmented MP4,
  // browser handles chunked transfer natively. No MSE needed.
  if (abortController) abortController.abort();
  
  var streamUrl = '/api/stream/completed/' + encodeURIComponent(fileName) + '?q=' + quality + '&ss=' + seekSec;
  if (window._cinemaAudioTrack) streamUrl += '&audio=' + window._cinemaAudioTrack;
  // NO sub= parameter — subtitles are now loaded as WebVTT tracks (0% CPU)
  window._currentFileName = fileName;
  window._isPartFile = false;
  
  video.src = streamUrl;
  video.load();
  
  // Remove any existing subtitle tracks
  var existingTracks = video.querySelectorAll('track');
  existingTracks.forEach(function(t) { t.remove(); });
  
  // Add WebVTT subtitle track if requested
  if (window._cinemaSubTrack && window._cinemaSubTrack !== '-1') {
    var subUrl = '/api/stream/subtitle?name=' + encodeURIComponent(fileName) + '&track=' + window._cinemaSubTrack;
    var track = document.createElement('track');
    track.kind = 'subtitles';
    track.src = subUrl;
    track.srclang = 'es';
    track.label = 'Subtítulos';
    track.default = true;
    video.appendChild(track);
    // Activate the track after video loads
    video.addEventListener('loadedmetadata', function onMeta() {
      video.removeEventListener('loadedmetadata', onMeta);
      if (video.textTracks && video.textTracks.length > 0) {
        video.textTracks[0].mode = 'showing';
      }
    });
  }
  
  video.addEventListener('canplay', function onCanPlay() {
    video.removeEventListener('canplay', onCanPlay);
    if (!userWantsPause) {
      video.muted = true;
      video.play().then(function() { video.muted = false; }).catch(function() {});
    }
  });
  
  video.addEventListener('error', function onErr() {
    video.removeEventListener('error', onErr);
    console.log('[Player] Video error, retrying...');
    // Retry once after 2 seconds
    setTimeout(function() {
      video.src = streamUrl + '&retry=1';
      video.load();
      video.play().catch(function(){});
    }, 2000);
  });
}

// Load trending movies on page load
setTimeout(loadTrendingMovies, 500);

// Fetch posters for local files (completed + downloading)
function fetchLocalPosters() {
  var TMDB_KEY = window.ESE_TMDB_KEY || '2dca580c2a14b55200e784d157207b4d';var cards = document.querySelectorAll('.card[data-title]');
  cards.forEach(function(card) {
    var raw = card.getAttribute('data-title');
    if (!raw) return;
    
    // Check if filename has embedded TMDB ID (e.g., [tmdbid-1297842])
    var tmdbId = (window._tmdbFromFilename && window._tmdbFromFilename[raw]) || null;
    
    // Smart filename cleaning for P2P files
    var candidates = extractMovieTitles(raw);
    
    if (tmdbId) {
      // Direct TMDB lookup — guaranteed accurate
      fetch('https://api.themoviedb.org/3/movie/' + tmdbId + '?api_key=' + TMDB_KEY + '&language=es-ES')
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
            tryTMDBCandidate(candidates, 0, card, TMDB_KEY);
          }
        }).catch(function() { if (candidates.length > 0) tryTMDBCandidate(candidates, 0, card, TMDB_KEY); });
    } else if (candidates.length > 0) {
      tryTMDBCandidate(candidates, 0, card, TMDB_KEY);
    }
  });
}

function tryTMDBCandidate(candidates, idx, card, apiKey) {
  if (idx >= candidates.length) {
    // Last resort: try OMDb
    tryOMDbFallback(candidates, card);
    return;
  }
  var query = candidates[idx];
  fetch('https://api.themoviedb.org/3/search/movie?api_key=' + apiKey + '&language=es-ES&query=' + encodeURIComponent(query))
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.results && data.results.length > 0) {
        var m = data.results[0];
        // Get IMDB ID for detailed modal
        fetch('https://api.themoviedb.org/3/movie/' + m.id + '/external_ids?api_key=' + apiKey)
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
        tryTMDBCandidate(candidates, idx + 1, card, apiKey);
      }
    }).catch(function() { tryTMDBCandidate(candidates, idx + 1, card, apiKey); });
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
    var posterDiv = card.querySelector('.card-poster');
    if (posterDiv) {
      posterDiv.style.backgroundImage = 'url(' + info.poster + ')';
      posterDiv.style.backgroundSize = 'cover';
      posterDiv.style.backgroundPosition = 'center';
      var playIcon = posterDiv.querySelector('.play-icon');
      if (playIcon) playIcon.style.display = 'none';
    }
  }
  if (info.imdbId) {
    card.setAttribute('data-imdbid', info.imdbId);
    var origOnclick = card.getAttribute('onclick') || '';
    var fnMatch = origOnclick.match(/playCompleted\('([^']+)'\)/);
    var safeTitle = (info.title || '').replace(/'/g, "\\'");
    if (fnMatch) {
      var localFile = decodeURIComponent(fnMatch[1]).replace(/'/g, "\\'");
      card.setAttribute('onclick', "showMovieDetail('" + info.imdbId + "','" + localFile + "','" + safeTitle + "')");
    } else {
      card.setAttribute('onclick', "showMovieDetail('" + info.imdbId + "',null,'" + safeTitle + "')");
    }
  }
  var titleEl = card.querySelector('.card-title');
  if (titleEl && info.title) titleEl.textContent = info.title + (info.year ? ' (' + info.year + ')' : '');
}

// Show watch progress on movie cards (Netflix-style red bar)
function addWatchProgressBars() {
  var resumeData = JSON.parse(localStorage.getItem('ese_resume') || '{}');
  var cards = document.querySelectorAll('.card[data-title]');
  cards.forEach(function(card) {
    var onclick = card.getAttribute('onclick') || '';
    // Extract fileName from onclick
    var fnMatch = onclick.match(/playCompleted\('([^']+)'\)/) || onclick.match(/showMovieDetail\('[^']*','([^']+)'\)/);
    if (!fnMatch) return;
    var fileName = decodeURIComponent(fnMatch[1]);
    var data = resumeData[fileName];
    if (!data || data.time < 30) return;
    
    // Estimate movie duration (~120 min average, or use a rough size-based estimate)
    var progress = Math.min(95, (data.time / 7200) * 100); // assume 2h movie
    
    // Add or update progress bar
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

// Run after posters load
setTimeout(addWatchProgressBars, 3000);

function extractMovieTitles(raw) {
  var candidates = [];
  // Remove file extension
  var s = raw.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i, '');
  // Replace dots/underscores with spaces
  s = s.replace(/[._]/g, ' ');
  
  // Extract TMDB ID if present (e.g., [tmdbid-1297842])
  var tmdbMatch = s.match(/\[tmdbid[- ]?(\d+)\]/i);
  if (tmdbMatch) {
    // Store for direct TMDB lookup
    window._tmdbFromFilename = window._tmdbFromFilename || {};
    window._tmdbFromFilename[raw] = tmdbMatch[1];
  }
  
  // Extract year
  var yearMatch = s.match(/((?:19|20)\d{2})/);
  var year = yearMatch ? yearMatch[1] : '';
  
  // Strip leading site names in brackets: [PeliculasBluray Com], [EliteTorrent net], etc.
  s = s.replace(/^\s*\[.*?\]\s*/g, '');
  
  // Remove ALL content in brackets
  var noParen = s.replace(/\(.*?\)/g, ' ').replace(/\[.*?\]/g, ' ');
  
  // Tags to strip  
  var tags = /\b(HDRip|BRRip|DVDRip|WEBRip|WEB-DL|WEB|BluRay|BDRip|CAMRip|TS|HDTS|1080p|720p|480p|2160p|4K|x264|x265|HEVC|H264|H265|AVC|AAC|EAC3|AC3|DTS|Dolby|Digital|Plus|5\.1|7\.1|MP3|Xvid|DivX|EliteTorrent|YIFY|RARBG|net|com|org|Spanish|Castellano|Español|Latino|English|VOSE|Dual|Audio|HDR|10bit|Remux|IMAX|Directors\.?Cut|Extended|Unrated|Remastered|PROPER|REPACK|DVDRIP|DVDSCR|LasCositas|spa|eng|fre|ger|ita|por|jpn|chi|kor|SUB|Subtitulos)\b/gi;
  
  var cleaned = noParen.replace(tags, ' ')
    .replace(/\s*-\s*$/, '') // trailing dash
    .replace(/\s{2,}/g, ' ').trim();
  
  // Remove year and everything after from cleaned
  var beforeYear = cleaned;
  if (year) {
    var idx = cleaned.indexOf(year);
    if (idx > 0) beforeYear = cleaned.substring(0, idx).trim();
  }
  
  // Split on " - " for "Title - Subtitle" pattern
  var parts = beforeYear.split(/\s*[-–—]\s*/).filter(function(p) { return p.trim().length > 2; });
  
  // Add main part (before dash) with year — best candidate
  if (parts[0] && parts[0].trim().length > 2) {
    candidates.push(parts[0].trim() + (year ? ' ' + year : ''));
    candidates.push(parts[0].trim());
  }
  
  // Add full cleaned title (before year)
  if (beforeYear.length > 2 && candidates.indexOf(beforeYear) === -1) {
    candidates.push(beforeYear + (year ? ' ' + year : ''));
    candidates.push(beforeYear);
  }
  
  // Add subtitle part too (second part after dash)
  if (parts[1] && parts[1].trim().length > 3) {
    candidates.push(parts[1].trim() + (year ? ' ' + year : ''));
  }
  
  return candidates;
}
setTimeout(fetchLocalPosters, 1000);

// === DISNEY+ STYLE HERO ===
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
  // Use TMDB trending to get HD backdrops
  var TMDB_KEY = window.ESE_TMDB_KEY || '2dca580c2a14b55200e784d157207b4d';
  fetch('https://api.themoviedb.org/3/trending/movie/week?api_key=' + TMDB_KEY + '&language=es-ES')
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
    .catch(function() {
      // Fallback: just show default hero
    });
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
  
  if (backdrop) backdrop.style.backgroundImage = 'url(https://image.tmdb.org/t/p/original' + m.backdrop_path + ')';
  if (title) title.textContent = m.title || m.name;
  if (desc) desc.textContent = (m.overview || '').substring(0, 200) + (m.overview && m.overview.length > 200 ? '...' : '');
  if (meta) meta.textContent = '⭐ ' + (m.vote_average || '').toString().substring(0,3) + ' · ' + (m.release_date || '').substring(0,4) + ' · Trending #' + (idx + 1);
  if (playBtn) { playBtn.style.display = 'inline-block'; playBtn.setAttribute('data-title', m.title || m.name); playBtn.setAttribute('data-id', m.id); }
  if (infoBtn) { infoBtn.style.display = 'inline-block'; infoBtn.setAttribute('data-title', m.title || m.name); infoBtn.setAttribute('data-id', m.id); }
  
  // Store for heroPlay/heroInfo
  window._heroCurrentMovie = m;
}

function heroPlay() {
  var m = window._heroCurrentMovie;
  if (!m) return;
  var title = m.title || m.name;
  var year = (m.release_date || '').substring(0,4);
  
  // Create fullscreen modal directly — skip detail view
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
  
  // Go straight to smart play evaluation
  smartPlay(title, year);
}

function heroInfo() {
  var m = window._heroCurrentMovie;
  if (!m) return;
  var title = m.title || m.name;
  // Get IMDB ID from TMDB (reliable, since we already have the TMDB id)
  fetch('https://api.themoviedb.org/3/movie/' + m.id + '/external_ids?api_key=' + TMDB_KEY + '')
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

// Load hero on page load
setTimeout(loadHero, 500);

// Handle URL parameters (from /search page redirect)
(function() {
  var params = new URLSearchParams(window.location.search);
  var detailId = params.get('detail');
  var searchQuery = params.get('search');
  var localizedTitle = params.get('ltitle');
  if (detailId) {
    setTimeout(function() { showMovieDetail(detailId, null, localizedTitle); }, 800);
    history.replaceState(null, '', '/');
  } else if (searchQuery) {
    setTimeout(function() {
      var input = document.getElementById('search-input');
      if (input) { input.value = searchQuery; searchEd2k(); }
    }, 800);
    history.replaceState(null, '', '/');
  }
})();

// "Continue Watching" — check for saved session on page load
(function() {
  var session = getWatchSession();
  if (!session || !session.fileName) return;
  
  // Check if the file still exists (either in Incoming or Temp)
  Promise.all([
    fetch('/api/stream/completed/list').then(function(r){return r.json()}).catch(function(){return []}),
    fetch('/api/emule/downloads').then(function(r){return r.json()}).catch(function(){return []})
  ]).then(function(results) {
    var completed = results[0];
    var downloads = results[1];
    var found = null;
    var source = null;
    
    // Check completed files
    if (completed) {
      for (var i = 0; i < completed.length; i++) {
        if (completed[i].fileName === session.fileName) {
          found = completed[i]; source = 'completed'; break;
        }
      }
    }
    
    // Check active downloads
    if (!found && downloads) {
      for (var j = 0; j < downloads.length; j++) {
        if (downloads[j].fileName === session.fileName) {
          found = downloads[j]; source = 'downloading'; break;
        }
      }
    }
    
    if (!found) { clearWatchSession(); return; }
    
    // Show "Continue Watching" banner
    var sizeMB = found.sizeMB || Math.round((found.sizeBytes || 0) / (1024*1024));
    var posMin = Math.floor(session.position / 60);
    var posSec = session.position % 60;
    var posText = session.position > 0 ? posMin + ':' + String(posSec).padStart(2, '0') : '';
    var movieName = session.fileName.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm)$/i, '').replace(/\./g, ' ');
    
    var banner = document.createElement('div');
    banner.id = 'continue-banner';
    banner.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:500;background:linear-gradient(135deg,rgba(22,22,30,.97),rgba(30,20,40,.97));border:1px solid rgba(255,107,53,.4);border-radius:16px;padding:16px 24px;display:flex;align-items:center;gap:16px;max-width:600px;width:calc(100% - 40px);backdrop-filter:blur(20px);box-shadow:0 8px 32px rgba(0,0,0,.6);animation:slideUp .4s ease';
    
    var style = document.createElement('style');
    style.textContent = '@keyframes slideUp{from{transform:translateX(-50%) translateY(100px);opacity:0}to{transform:translateX(-50%) translateY(0);opacity:1}}';
    document.head.appendChild(style);
    
    banner.innerHTML = '<div style="flex:1;min-width:0"><div style="font-size:14px;color:#ff6b35;font-weight:700;margin-bottom:4px">▶ Seguir viendo</div>' +
      '<div style="font-size:13px;color:#fff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + movieName + '</div>' +
      '<div style="font-size:11px;color:#888;margin-top:2px">' + sizeMB + ' MB' + (posText ? ' · ' + posText : '') + (source === 'downloading' ? ' · Descargando...' : ' · Descargado') + '</div></div>' +
      '<button id="continue-play-btn" style="background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:700;font-size:14px;white-space:nowrap">▶ Continuar</button>' +
      '<button onclick="document.getElementById(\'continue-banner\').remove();clearWatchSession()" style="background:none;border:none;color:#555;font-size:20px;cursor:pointer;padding:4px">×</button>';
    
    document.body.appendChild(banner);
    
    document.getElementById('continue-play-btn').onclick = function() {
      banner.remove();
      // Direct resume — skip buffer wait, file already has data
      var seekPos = session.position || 0;
      // Open a minimal modal and play immediately
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
      
      // Start playing
      playInModal(encodeURIComponent(session.fileName));
      // Seek to last position after a short delay
      if (seekPos > 10) {
        setTimeout(function() {
          window._cinemaSeekOffset = seekPos;
          var q = document.getElementById('cinema-quality');
          var quality = q ? q.value : 'auto';
          startCompletedMSE(session.fileName, quality, seekPos);
        }, 2000);
      }
    };
  });
})();
