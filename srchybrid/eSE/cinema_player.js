// cinema_player.js — reproductor modal cinema, controles, subtítulos, sesión

// ── Reproductor modal cinema ───────────────────────────────────────────────────
function playInModal(encodedName) {
  var fileName = decodeURIComponent(encodedName);
  var playerZone = document.getElementById('modal-player-zone');
  var infoZone = document.getElementById('modal-info-zone');
  if (!playerZone) return;

  // Hide movie info, show player
  if (infoZone) infoZone.style.display = 'none';
  playerZone.style.display = 'block';

  var movieTitle = fileName.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm)$/i, '').replace(/\./g, ' ');

  // Create cinema mode player with CUSTOM controls (not native)
  playerZone.innerHTML = '<div class="modal-player" id="cinema-player">' +
    '<div class="modal-player-header">' +
      '<button class="cinema-back-btn" onclick="backToDetail()">&larr; Volver</button>' +
    '</div>' +
    '<span class="modal-player-title">' + escapeHTML(movieTitle) + '</span>' +
    '<video id="modal-video"></video>' +
    '<div class="cinema-controls" id="cinema-controls">' +
      '<div class="cinema-seek" id="cinema-seek">' +
        '<div class="cinema-buffer" id="cinema-buffer"></div>' +
        '<div class="cinema-progress" id="cinema-progress"></div>' +
      '</div>' +
      '<div class="cinema-controls-row">' +
        '<button class="cinema-ctrl-btn" id="cinema-play-btn" onclick="toggleCinemaPlay()">⏸</button>' +
        '<span class="cinema-time" id="cinema-time">0:00 / 0:00</span>' +
        '<div style="flex:1"></div>' +
        '<button class="cinema-ctrl-btn" id="cinema-vol-btn" onclick="toggleCinemaVol()"></button>' +
        '<input type="range" id="cinema-vol-slider" min="0" max="100" value="100" class="cinema-vol-range" oninput="setCinemaVol(this.value)">' +
        '<button class="cinema-ctrl-btn" id="cinema-settings-btn" onclick="toggleCinemaSettings()" style="font-size:18px" title="Ajustes">&#9881;</button>' +
        '<button class="cinema-ctrl-btn" onclick="toggleCinemaFS()">&#x26F6;</button>' +
      '</div>' +
      '<div id="cinema-settings-popup" style="display:none;position:absolute;bottom:56px;right:12px;background:rgba(15,15,20,.96);border:1px solid #333;border-radius:12px;padding:16px;min-width:240px;z-index:50;backdrop-filter:blur(12px)">' +
        '<div style="font-size:13px;font-weight:600;color:#fff;margin-bottom:12px">Ajustes del reproductor</div>' +
        '<div style="margin-bottom:10px"><label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Calidad</label>' +
        '<select id="cinema-quality" class="cinema-quality" onchange="changeCinemaQuality(this.value)" style="width:100%;margin-top:4px">' +
          '<option value="auto" selected>Auto</option>' +
          '<option value="480p">480p</option>' +
          '<option value="720p">720p</option>' +
          '<option value="1080p">1080p</option>' +
          '<option value="original">Original</option>' +
        '</select></div>' +
        '<div id="cinema-audio-row" style="margin-bottom:10px;display:none"><label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Audio</label>' +
        '<select id="cinema-audio" class="cinema-quality" onchange="changeCinemaAudio(this.value)" style="width:100%;margin-top:4px"></select></div>' +
        '<div id="cinema-subs-row" style="display:none"><label style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Subtítulos</label>' +
        '<select id="cinema-subs" class="cinema-quality" onchange="changeCinemaSubs(this.value)" style="width:100%;margin-top:4px"></select></div>' +
      '</div>' +
      '</div>' +
    '</div>' +
    '<div class="cinema-status" id="modal-player-status">Preparando streaming...</div>' +
  '</div>';

  // Assign video
  video = document.getElementById('modal-video');
  window._cinemaFileName = fileName;
  window._cinemaSeekOffset = 0;

  // Save watch session
  saveWatchSession(fileName, 0);

  // Save position every 5 seconds
  video.addEventListener('timeupdate', function() {
    if (video.currentTime > 0) {
      var realPos = (window._cinemaSeekOffset || 0) + video.currentTime;
      saveWatchSession(fileName, Math.floor(realPos));
    }
  });

  // Video click = play/pause
  video.addEventListener('click', toggleCinemaPlay);
  // Double-click = fullscreen
  video.addEventListener('dblclick', function(e) {
    e.preventDefault();
    toggleCinemaFS();
  });

  // Time update → custom progress bar
  video.addEventListener('timeupdate', function() {
    var currentReal = (window._cinemaSeekOffset || 0) + video.currentTime;
    var total = estTotalSec || video.duration || 0;
    if (total > 0) {
      var pEl = document.getElementById('cinema-progress');
      var tEl = document.getElementById('cinema-time');
      if (pEl) pEl.style.width = (currentReal / total * 100) + '%';
      if (tEl) tEl.textContent = fmtT(currentReal) + ' / ' + fmtT(total);
    }
    if (video.buffered.length > 0 && estTotalSec > 0) {
      var buffEnd = (window._cinemaSeekOffset || 0) + video.buffered.end(video.buffered.length - 1);
      var bEl = document.getElementById('cinema-buffer');
      if (bEl) bEl.style.width = (buffEnd / estTotalSec * 100) + '%';
    }
  });

  video.addEventListener('play', function() { var b = document.getElementById('cinema-play-btn'); if (b) b.textContent = '⏸'; });
  video.addEventListener('pause', function() { var b = document.getElementById('cinema-play-btn'); if (b) b.textContent = '▶'; });

  // Seek bar click
  document.getElementById('cinema-seek').addEventListener('click', function(e) {
    var rect = e.currentTarget.getBoundingClientRect();
    var pct = (e.clientX - rect.left) / rect.width;
    var targetSec = Math.floor(pct * (estTotalSec || video.duration || 0));
    if (targetSec >= 0 && window._cinemaFileName) {
      window._cinemaSeekOffset = targetSec;
      var status = document.getElementById('modal-player-status');
      var q = (document.getElementById('cinema-quality') || {}).value || currentQuality || 'auto';

      if (window._isPartFile && currentPartNum) {
        // .part file — tell eMule to download from this position + restart stream
        if (status) status.textContent = 'Seeking a ' + fmtT(targetSec) + '...';
        var seekUrl = '/api/stream/seek?name=' + encodeURIComponent(window._cinemaFileName) + '&time=' + targetSec;
        fetch(seekUrl).then(function(r) { return r.json(); }).then(function(data) {
          console.log('[Seek] eMule notified: part ' + data.targetPart + '/' + data.totalParts);
          if (status) status.textContent = 'eMule → part ' + data.targetPart + '/' + data.totalParts;
          switchStreamSeamless(q, targetSec);
        }).catch(function() {
          switchStreamSeamless(q, targetSec);
        });
      } else {
        // Completed file — restart ffmpeg from new position
        if (status) status.textContent = 'Seeking a ' + fmtT(targetSec) + '...';
        startCompletedMSE(window._cinemaFileName, q, targetSec);
      }
    }
  });

  // Fade title after 3s
  setTimeout(function() {
    var player = document.getElementById('cinema-player');
    if (player) player.classList.add('title-fade');
  }, 3000);

  // Hide modal close button
  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'none';
  var modal = document.getElementById('movie-modal');
  if (modal) { modal.style.overflow = 'hidden'; modal.scrollTop = 0; }

  // Start streaming — probe tracks first, then play
  window._cinemaAudioTrack = null;
  window._cinemaSubTrack = '-1'; // no subs by default

  // v7.4.0 - start streaming IMMEDIATELY with defaults instead of waiting for
  // /info + /tracks in series. ffprobe on partial HEVC can take 15-20s and
  // blocking the spinner there is what people perceive as "no arranca".
  // Both calls now run in parallel and patch the UI in place.
  estTotalSec = 7200;
  window._isPartFile = false;
  currentPartNum = null;
  currentQuality = 'auto';
  var status0 = document.getElementById('modal-player-status');
  if (status0) status0.textContent = 'Iniciando streaming...';
  startCompletedMSE(fileName, 'auto', 0);

  // Show transcoding hint as soon as response headers arrive.
  // Endpoint is /api/stream/completed/<encodedName>?quality=… (positional path,
  // not ?name=… — see stream_completed.js:129).
  fetch('/api/stream/completed/' + encodeURIComponent(fileName) + '?quality=auto', { method: 'HEAD' })
    .then(function(r) {
      var mode = r.headers.get('X-ESE-Transcoding');
      var s = document.getElementById('modal-player-status');
      if (s && mode === 'hevc-to-h264') s.textContent = 'Transcodificando HEVC en vivo — puede tardar hasta 60s en empezar';
      else if (s && mode === 'transcode') s.textContent = 'Transcodificando — puede tardar';
    }).catch(function(){});

  // /info enriches the UI when it is ready (true duration, part flag).
  fetch('/api/stream/completed/info?name=' + encodeURIComponent(fileName))
    .then(function(r){return r.json();}).catch(function(){return {};})
    .then(function(data) {
      estTotalSec = data.estimatedTotalSec || 7200;
      window._isPartFile = !!data.isPartFile;
      if (data.isPartFile && data.partNum) currentPartNum = data.partNum;
      var s = document.getElementById('modal-player-status');
      if (s && s.textContent.indexOf('Transcod') !== 0)
        s.textContent = 'Streaming iniciado — ' + fmtT(estTotalSec);
    });

  // /tracks patches the audio/subtitle selectors when ready.
  fetch('/api/stream/tracks?name=' + encodeURIComponent(fileName))
    .then(function(r){return r.json();}).catch(function(){return {audio:[],subtitles:[]};})
    .then(function(tracks) {
      var audioSel = document.getElementById('cinema-audio');
      if (audioSel && tracks.audio && tracks.audio.length > 1) {
        audioSel.innerHTML = '';
        tracks.audio.forEach(function(a, i) {
          var label = (a.lang || 'und').toUpperCase();
          if (a.title) label += ' \u2014 ' + a.title;
          if (a.channels) label += ' (' + a.channels + 'ch)';
          var opt = document.createElement('option');
          opt.value = a.index;
          opt.textContent = label;
          if (i === 0) opt.selected = true;
          audioSel.appendChild(opt);
        });
        var audioRow = document.getElementById('cinema-audio-row');
        if (audioRow) audioRow.style.display = '';
      }
      var subSel = document.getElementById('cinema-subs');
      if (subSel && tracks.subtitles && tracks.subtitles.length > 0) {
        subSel.innerHTML = '<option value="-1" selected>Desactivados</option>';
        tracks.subtitles.forEach(function(s, i) {
          var label = (s.lang || 'und').toUpperCase();
          if (s.title) label += ' \u2014 ' + s.title;
          if (s.forced) label += ' [Forzados]';
          var opt = document.createElement('option');
          opt.value = i;
          opt.textContent = label;
          subSel.appendChild(opt);
        });
        var subsRow = document.getElementById('cinema-subs-row');
        if (subsRow) subsRow.style.display = '';
      }
    });
}

// ── Controles del cinema player ────────────────────────────────────────────────
function toggleCinemaSettings() {
  var popup = document.getElementById('cinema-settings-popup');
  if (popup) popup.style.display = popup.style.display === 'none' ? 'block' : 'none';
}

function toggleCinemaPlay() {
  if (video.paused) { userWantsPause = false; video.play().catch(function(){}); }
  else { userWantsPause = true; video.pause(); }
}

function toggleCinemaVol() {
  video.muted = !video.muted;
  var btn = document.getElementById('cinema-vol-btn');
  if (btn) btn.textContent = video.muted ? '' : '';
}

function setCinemaVol(val) {
  video.volume = val / 100;
  video.muted = val == 0;
}

function toggleCinemaFS() {
  var el = document.getElementById('cinema-player');
  if (document.fullscreenElement) document.exitFullscreen();
  else if (el) el.requestFullscreen().catch(function(){});
}

function changeCinemaQuality(q) {
  if (!window._cinemaFileName) return;
  var currentReal = (window._cinemaSeekOffset || 0) + (video.currentTime || 0);
  window._cinemaSeekOffset = Math.floor(currentReal);
  var status = document.getElementById('modal-player-status');
  if (status) status.textContent = 'Cambiando calidad a ' + q + '...';
  startCompletedMSE(window._cinemaFileName, q, window._cinemaSeekOffset);
}

function changeCinemaAudio(trackIndex) {
  if (!window._cinemaFileName) return;
  window._cinemaAudioTrack = trackIndex;
  var currentReal = (window._cinemaSeekOffset || 0) + (video.currentTime || 0);
  window._cinemaSeekOffset = Math.floor(currentReal);
  var status = document.getElementById('modal-player-status');
  if (status) status.textContent = 'Cambiando audio...';
  var q = document.getElementById('cinema-quality');
  startCompletedMSE(window._cinemaFileName, q ? q.value : 'auto', window._cinemaSeekOffset);
}

function changeCinemaSubs(subIndex) {
  if (!window._cinemaFileName) return;
  window._cinemaSubTrack = subIndex;

  // Remove existing subtitle tracks
  var existingTracks = video.querySelectorAll('track');
  existingTracks.forEach(function(t) { t.remove(); });

  // Disable all text tracks
  if (video.textTracks) {
    for (var i = 0; i < video.textTracks.length; i++) {
      video.textTracks[i].mode = 'disabled';
    }
  }

  if (subIndex === '-1' || subIndex === -1) {
    var status = document.getElementById('modal-player-status');
    if (status) status.textContent = 'Subtítulos desactivados';
    setTimeout(function() { if (status) status.textContent = ''; }, 1500);
    return;
  }

  // Add new WebVTT track — NO stream restart needed!
  var subUrl = '/api/stream/subtitle?name=' + encodeURIComponent(window._cinemaFileName) + '&track=' + subIndex;
  var track = document.createElement('track');
  track.kind = 'subtitles';
  track.src = subUrl;
  track.srclang = 'es';
  track.label = 'Subtítulos';
  track.default = true;
  video.appendChild(track);

  // Activate track
  setTimeout(function() {
    if (video.textTracks && video.textTracks.length > 0) {
      video.textTracks[video.textTracks.length - 1].mode = 'showing';
    }
    var status = document.getElementById('modal-player-status');
    if (status) status.textContent = 'Subtítulos activados';
    setTimeout(function() { if (status) status.textContent = ''; }, 1500);
  }, 500);
}

// ── Volver a la ficha del film ─────────────────────────────────────────────────
function backToDetail() {
  // Save playback position for resume
  if (video && window._cinemaFileName) {
    var currentReal = (window._cinemaSeekOffset || 0) + (video.currentTime || 0);
    if (currentReal > 10) {
      var resumeData = JSON.parse(localStorage.getItem('ese_resume') || '{}');
      resumeData[window._cinemaFileName] = {
        time: Math.floor(currentReal),
        ts: Date.now()
      };
      localStorage.setItem('ese_resume', JSON.stringify(resumeData));
    }
  }

  // ALWAYS stop video — regardless of MSE or direct src
  try {
    video.pause();
    video.removeAttribute('src');
    video.load();
  } catch(e) {}
  if (abortController) { try { abortController.abort(); } catch(e) {} }

  // Remove subtitle tracks
  var tracks = video.querySelectorAll('track');
  tracks.forEach(function(t) { t.remove(); });

  var playerZone = document.getElementById('modal-player-zone');
  var infoZone = document.getElementById('modal-info-zone');
  if (playerZone) playerZone.style.display = 'none';
  if (infoZone) infoZone.style.display = 'block';
  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'flex';
  var modal = document.getElementById('movie-modal');
  if (modal) modal.style.overflow = 'auto';
  if (document.fullscreenElement) document.exitFullscreen();
}

// ── Tráiler ────────────────────────────────────────────────────────────────────
function loadTrailer(query) {
  var container = document.getElementById('trailer-container');
  var btn = document.getElementById('trailer-btn');
  if (!container) return;

  if (container.innerHTML) {
    container.innerHTML = '';
    if (btn) btn.innerHTML = '&#127916; Ver Tráiler';
    return;
  }

  container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;padding:40px"><div class="spinner"></div></div>';
  if (btn) btn.innerHTML = '&#127916; Cargando...';

  fetch('/api/movies/trailer?q=' + encodeURIComponent(query)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.videoId && /^[a-zA-Z0-9_-]{6,15}$/.test(data.videoId)) {
      container.innerHTML = '<div class="trailer-container"><iframe src="https://www.youtube.com/embed/' + escapeAttr(data.videoId) + '?autoplay=1&rel=0" allow="autoplay;encrypted-media" allowfullscreen></iframe></div>';
      if (btn) btn.innerHTML = '&#127916; Ocultar Tráiler';
    } else {
      container.innerHTML = '<p style="color:#888;padding:16px">No se encontró tráiler. <a href="https://www.youtube.com/results?search_query=' + encodeURIComponent(query + ' trailer') + '" target="_blank" style="color:#ff6b35">Buscar en YouTube</a></p>';
      if (btn) btn.innerHTML = '&#127916; Ver Tráiler';
    }
  }).catch(function() {
    container.innerHTML = '';
    if (btn) btn.innerHTML = '&#127916; Ver Tráiler';
  });
}

// ── Sesión de visionado ────────────────────────────────────────────────────────
function saveWatchSession(fileName, position) {
  try {
    localStorage.setItem('ese_session', JSON.stringify({
      fileName: fileName,
      position: position || 0,
      ts: Date.now()
    }));
  } catch(e) {}
}

function clearWatchSession() {
  localStorage.removeItem('ese_session');
}

function getWatchSession() {
  try {
    var s = JSON.parse(localStorage.getItem('ese_session'));
    // Sessions older than 48h are stale
    if (s && (Date.now() - s.ts) < 172800000) return s;
  } catch(e) {}
  return null;
}

// ── Helper: iniciar desde .part ────────────────────────────────────────────────
function playPartFile(partFile, displayName) {
  saveWatchSession(displayName, 0);
  playInModal(encodeURIComponent(displayName));
}

// ── requestMovie (delegación a showMovieDetail) ────────────────────────────────
function requestMovie(title, imdbId) {
  if (imdbId) {
    showMovieDetail(imdbId, null);
  }
}

// ── Reproducir archivo completado ─────────────────────────────────────────────
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

// ── Streaming de archivo completado (src directo, sin MSE) ─────────────────────
function startCompletedMSE(fileName, quality, seekSec) {
  if (abortController) abortController.abort();

  var streamUrl = '/api/stream/completed/' + encodeURIComponent(fileName) + '?q=' + encodeURIComponent(quality) + '&ss=' + encodeURIComponent(seekSec);
  if (window._cinemaAudioTrack) streamUrl += '&audio=' + encodeURIComponent(window._cinemaAudioTrack);
  // NO sub= parameter — subtitles are loaded as WebVTT tracks (0% CPU)
  window._currentFileName = fileName;
  window._isPartFile = false;

  video.src = streamUrl;
  video.load();

  // Remove any existing subtitle tracks
  var existingTracks = video.querySelectorAll('track');
  existingTracks.forEach(function(t) { t.remove(); });

  // Add WebVTT subtitle track if requested
  if (window._cinemaSubTrack && window._cinemaSubTrack !== '-1') {
    var subUrl = '/api/stream/subtitle?name=' + encodeURIComponent(fileName) + '&track=' + encodeURIComponent(window._cinemaSubTrack);
    var track = document.createElement('track');
    track.kind = 'subtitles';
    track.src = subUrl;
    track.srclang = 'es';
    track.label = 'Subtítulos';
    track.default = true;
    video.appendChild(track);
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

  // v7.4.0 — retry up to MAX_RETRIES on video errors, then surface a real
  // error state instead of looping forever. Previous code kept reissuing
  // `?retry=1` indefinitely if the underlying issue was a codec mismatch
  // or the stream genuinely had no data.
  var _retryCount = 0;
  var MAX_RETRIES = 3;
  video.addEventListener('error', function onErr() {
    _retryCount++;
    console.log('[Player] Video error, retry ' + _retryCount + '/' + MAX_RETRIES);
    if (_retryCount > MAX_RETRIES) {
      video.removeEventListener('error', onErr);
      var status = document.getElementById('modal-player-status');
      if (status) status.textContent = 'No se puede reproducir — codec incompatible o sin datos suficientes';
      showPlayerErrorActions();
      return;
    }
    setTimeout(function() {
      video.src = streamUrl + '&retry=' + _retryCount;
      video.load();
      video.play().catch(function(){});
    }, 2000);
  });
}

// v7.4.0 — show a clear error UI inside the player modal with two actions:
// retry from scratch (resets retry count + reloads) or close.
function showPlayerErrorActions() {
  var modal = document.getElementById('cinema-player');
  if (!modal) return;
  var existing = document.getElementById('modal-player-error-actions');
  if (existing) existing.remove();
  var bar = document.createElement('div');
  bar.id = 'modal-player-error-actions';
  bar.style.cssText = 'position:absolute;bottom:80px;left:50%;transform:translateX(-50%);display:flex;gap:12px;z-index:1000';
  var retry = document.createElement('button');
  retry.textContent = 'Reintentar';
  retry.style.cssText = 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:10px 22px;border-radius:8px;cursor:pointer;font-weight:600';
  retry.onclick = function() { bar.remove(); location.reload(); };
  var close = document.createElement('button');
  close.textContent = 'Volver';
  close.style.cssText = 'background:transparent;border:1px solid #444;color:#888;padding:10px 22px;border-radius:8px;cursor:pointer';
  close.onclick = function() { bar.remove(); var c = document.getElementById('cinema-player'); if (c) c.style.display = 'none'; };
  bar.appendChild(retry); bar.appendChild(close);
  modal.appendChild(bar);
}
