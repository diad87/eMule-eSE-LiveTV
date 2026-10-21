// cinema_player.js — reproductor modal cinema, controles, subtítulos, sesión

// Each dialog and each stream owns its asynchronous work. Closing, seeking or
// opening another title invalidates callbacks before they can touch a new video.
var cinemaSession = null;
function cinemaIsCurrent(session) {
  return !!session && session.active && cinemaSession === session && video === session.video &&
    (!session.modal || document.getElementById('movie-modal') === session.modal);
}
function cinemaListen(session, target, event, callback, stream) {
  var handler = function(e) {
    if (cinemaIsCurrent(session) && (!stream || session.stream === stream)) callback(e);
  };
  target.addEventListener(event, handler);
  (stream || session).listeners.push(function() { target.removeEventListener(event, handler); });
}
function cinemaLater(session, callback, delay, stream) {
  var owner = stream || session;
  var timer = setTimeout(function() {
    owner.timers = owner.timers.filter(function(id) { return id !== timer; });
    if (cinemaIsCurrent(session) && (!stream || session.stream === stream)) callback();
  }, delay);
  owner.timers.push(timer);
  return timer;
}
function cancelCinemaWork(owner) {
  if (!owner) return;
  owner.timers.forEach(clearTimeout);
  owner.timers = [];
  owner.listeners.forEach(function(remove) { remove(); });
  owner.listeners = [];
}
function saveCinemaPosition(session) {
  if (!session || !session.hasPlayed) return;
  if (session.duration > 0) session.position = Math.min(session.duration, session.position);
  saveWatchSession(session.fileName, session.position);
  if (session.position <= 10) return;
  try {
    var saved = JSON.parse(localStorage.getItem('ese_resume') || '{}');
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) saved = {};
    saved[session.fileName] = { time: Math.floor(session.position), ts: Date.now() };
    localStorage.setItem('ese_resume', JSON.stringify(saved));
  } catch (_) { /* Storage must never prevent stopping or leaving playback. */ }
}
function stopCinemaPlayback() {
  if (typeof stopSmartPlay === 'function') stopSmartPlay();
  var session = cinemaSession;
  if (session) {
    saveCinemaPosition(session);
    session.active = false;
    cinemaSession = null;
    cancelCinemaWork(session.stream);
    cancelCinemaWork(session);
    if (session.controller) session.controller.abort();
    try {
      session.video.pause();
      session.video.removeAttribute('src');
      clearCinemaSubtitles(session);
      session.video.load();
    } catch (_) {}
  }
  if (typeof stopLegacyPlayback === 'function') stopLegacyPlayback();
  else if (abortController) { try { abortController.abort(); } catch (_) {} }
}
function cinemaStatus(session, text) {
  if (!cinemaIsCurrent(session)) return;
  var status = document.getElementById('modal-player-status');
  if (status) { status.textContent = text; status.style.opacity = text === 'Reproduciendo' ? '' : '1'; }
}
function cinemaDuration(session) {
  if (session.duration > 0) return session.duration;
  var duration = Number(session.video.duration);
  return Number.isFinite(duration) && duration > 0 ? duration + session.offset : 0;
}
function cinemaPosition(session) {
  var position = Math.max(0, session.offset + (Number(session.video.currentTime) || 0));
  return session.duration > 0 ? Math.min(session.duration, position) : position;
}
function updateCinemaProgress(session) {
  if (!cinemaIsCurrent(session)) return;
  var total = cinemaDuration(session);
  var position = cinemaPosition(session);
  var progress = document.getElementById('cinema-progress');
  var time = document.getElementById('cinema-time');
  var seek = document.getElementById('cinema-seek');
  if (progress) progress.style.width = (total ? Math.min(100, position / total * 100) : 0) + '%';
  if (time) time.textContent = fmtT(position) + ' / ' + (total ? fmtT(total) : 'Duración desconocida');
  if (seek) {
    seek.setAttribute('aria-disabled', String(!total));
    seek.setAttribute('aria-valuemax', String(total || 0));
    seek.setAttribute('aria-valuenow', String(total ? Math.min(total, Math.floor(position)) : 0));
    seek.setAttribute('aria-valuetext', total ? fmtT(position) + ' de ' + fmtT(total) : 'Duración desconocida');
  }
  var buffered = session.video.buffered;
  var buffer = document.getElementById('cinema-buffer');
  if (buffer && buffered && buffered.length && total) {
    buffer.style.width = Math.min(100, (session.offset + buffered.end(buffered.length - 1)) / total * 100) + '%';
  }
}
function seekCinemaTo(target) {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  var duration = cinemaDuration(session);
  if (!duration || !Number.isFinite(target)) return;
  target = Math.max(0, Math.min(Math.max(0, duration - 1), Math.floor(target)));
  var quality = (document.getElementById('cinema-quality') || {}).value || currentQuality || 'auto';
  var request = ++session.seekRequest;
  cinemaStatus(session, 'Buscando ' + fmtT(target) + '…');
  var restart = function() {
    if (cinemaIsCurrent(session) && request === session.seekRequest) startCompletedMSE(session.fileName, quality, target);
  };
  if (session.isPartFile) {
    fetch('/api/stream/seek?name=' + encodeURIComponent(session.fileName) + '&time=' + target,
      session.controller ? { signal: session.controller.signal } : {}).then(restart, restart);
  } else restart();
}

// ── Reproductor modal cinema ───────────────────────────────────────────────────
function playInModal(encodedName, resumePosition) {
  var fileName = decodeURIComponent(encodedName);
  var playerZone = document.getElementById('modal-player-zone');
  var infoZone = document.getElementById('modal-info-zone');
  if (!playerZone) return;
  stopCinemaPlayback();

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
      '<div class="cinema-seek" id="cinema-seek" role="slider" tabindex="0" aria-label="Posición de reproducción" aria-valuemin="0" aria-valuemax="0" aria-valuenow="0" aria-disabled="true">' +
        '<div class="cinema-buffer" id="cinema-buffer"></div>' +
        '<div class="cinema-progress" id="cinema-progress"></div>' +
      '</div>' +
      '<div class="cinema-controls-row">' +
        '<button type="button" class="cinema-ctrl-btn" id="cinema-play-btn" aria-label="Reproducir" onclick="toggleCinemaPlay()">▶</button>' +
        '<span class="cinema-time" id="cinema-time">0:00 / Duración desconocida</span>' +
        '<div style="flex:1"></div>' +
        '<button type="button" class="cinema-ctrl-btn" id="cinema-vol-btn" aria-label="Silenciar" aria-pressed="false" onclick="toggleCinemaVol()">🔊</button>' +
        '<input type="range" id="cinema-vol-slider" aria-label="Volumen" min="0" max="100" value="100" class="cinema-vol-range" oninput="setCinemaVol(this.value)">' +
        '<button type="button" class="cinema-ctrl-btn" id="cinema-settings-btn" aria-label="Ajustes del reproductor" aria-controls="cinema-settings-popup" aria-expanded="false" onclick="toggleCinemaSettings()" style="font-size:18px" title="Ajustes">&#9881;</button>' +
        '<button type="button" class="cinema-ctrl-btn" id="cinema-fs-btn" aria-label="Pantalla completa" onclick="toggleCinemaFS()">&#x26F6;</button>' +
      '</div>' +
      '<div id="cinema-settings-popup" style="display:none;position:absolute;bottom:56px;right:12px;background:rgba(15,15,20,.96);border:1px solid #333;border-radius:12px;padding:16px;min-width:240px;z-index:50;backdrop-filter:blur(12px)">' +
        '<div style="font-size:13px;font-weight:600;color:#fff;margin-bottom:12px">Ajustes del reproductor</div>' +
        '<div style="margin-bottom:10px"><label for="cinema-quality" style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Calidad</label>' +
        '<select id="cinema-quality" class="cinema-quality" onchange="changeCinemaQuality(this.value)" style="width:100%;margin-top:4px">' +
          '<option value="auto" selected>Auto</option>' +
          '<option value="480p">480p</option>' +
          '<option value="720p">720p</option>' +
          '<option value="1080p">1080p</option>' +
          '<option value="original">Original</option>' +
        '</select></div>' +
        '<div id="cinema-audio-row" style="margin-bottom:10px;display:none"><label for="cinema-audio" style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Audio</label>' +
        '<select id="cinema-audio" class="cinema-quality" onchange="changeCinemaAudio(this.value)" style="width:100%;margin-top:4px"></select></div>' +
        '<div id="cinema-subs-row" style="display:none"><label for="cinema-subs" style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px">Subtítulos</label>' +
        '<select id="cinema-subs" class="cinema-quality" onchange="changeCinemaSubs(this.value)" style="width:100%;margin-top:4px"></select></div>' +
      '</div>' +
      '</div>' +
    '<div class="cinema-status" id="modal-player-status" role="status" aria-live="polite">Preparando vídeo…</div>' +
  '</div>';

  video = document.getElementById('modal-video');
  var initialPosition = Number(resumePosition);
  initialPosition = Number.isFinite(initialPosition) && initialPosition > 0 ? Math.floor(initialPosition) : 0;
  var session = cinemaSession = {
    active: true, video: video, modal: document.getElementById('movie-modal'), fileName: fileName,
    offset: initialPosition, position: initialPosition, duration: 0, hasPlayed: false,
    listeners: [], timers: [], stream: null, seekRequest: 0, isPartFile: false,
    controller: typeof AbortController === 'function' ? new AbortController() : null
  };
  window._cinemaFileName = fileName;
  window._cinemaSeekOffset = initialPosition;
  window._cinemaAudioTrack = null;
  window._cinemaSubTrack = '-1';
  window._isPartFile = false;
  currentPartNum = null;
  currentQuality = 'auto';
  estTotalSec = 0;
  userWantsPause = false;

  // Preserve saved progress until this stream has actually started playing.
  cinemaListen(session, video, 'timeupdate', function() {
    if (session.stream && session.stream.hasPlayed) {
      session.position = cinemaPosition(session);
      saveWatchSession(fileName, Math.floor(session.position));
    }
    updateCinemaProgress(session);
  });
  cinemaListen(session, video, 'loadedmetadata', function() { updateCinemaProgress(session); });
  cinemaListen(session, video, 'durationchange', function() { updateCinemaProgress(session); });
  cinemaListen(session, video, 'playing', function() {
    if (!session.stream) return;
    session.stream.hasPlayed = true;
    session.hasPlayed = true;
    session.position = cinemaPosition(session);
    saveWatchSession(fileName, Math.floor(session.position));
    cinemaStatus(session, 'Reproduciendo');
  });
  cinemaListen(session, video, 'waiting', function() { cinemaStatus(session, 'Cargando vídeo…'); });
  cinemaListen(session, video, 'stalled', function() { cinemaStatus(session, 'Esperando datos…'); });
  cinemaListen(session, video, 'ended', function() { cinemaStatus(session, 'Reproducción finalizada'); });
  function playButton(paused) {
    var button = document.getElementById('cinema-play-btn');
    if (button) { button.textContent = paused ? '▶' : '⏸'; button.setAttribute('aria-label', paused ? 'Reproducir' : 'Pausar'); }
  }
  cinemaListen(session, video, 'play', function() { playButton(false); });
  cinemaListen(session, video, 'pause', function() {
    playButton(true);
    if (session.hasPlayed && session.stream && session.stream.hasPlayed && !session.video.ended) cinemaStatus(session, 'En pausa');
  });
  cinemaListen(session, video, 'volumechange', syncCinemaVolume);
  cinemaListen(session, video, 'click', toggleCinemaPlay);
  cinemaListen(session, video, 'dblclick', function(e) { e.preventDefault(); toggleCinemaFS(); });
  cinemaListen(session, document, 'fullscreenchange', function() {
    var button = document.getElementById('cinema-fs-btn');
    if (button) button.setAttribute('aria-label', document.fullscreenElement ? 'Salir de pantalla completa' : 'Pantalla completa');
  });
  var seek = document.getElementById('cinema-seek');
  cinemaListen(session, seek, 'click', function(e) {
    var rect = seek.getBoundingClientRect();
    if (rect.width > 0) seekCinemaTo((e.clientX - rect.left) / rect.width * cinemaDuration(session));
  });
  cinemaListen(session, seek, 'keydown', function(e) {
    var position = session.offset + (Number(session.video.currentTime) || 0);
    var target = { ArrowLeft: position - 10, ArrowDown: position - 10, ArrowRight: position + 10,
      ArrowUp: position + 10, PageDown: position - 60, PageUp: position + 60, Home: 0, End: cinemaDuration(session) };
    if (Object.prototype.hasOwnProperty.call(target, e.key)) { e.preventDefault(); seekCinemaTo(target[e.key]); }
  });
  cinemaLater(session, function() {
    var player = document.getElementById('cinema-player');
    if (player) player.classList.add('title-fade');
  }, 3000);
  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'none';
  if (session.modal) { session.modal.style.overflow = 'hidden'; session.modal.scrollTop = 0; }
  updateCinemaProgress(session);
  syncCinemaVolume();
  startCompletedMSE(fileName, 'auto', initialPosition);

  var options = session.controller ? { signal: session.controller.signal } : {};
  fetch('/api/stream/completed/' + encodeURIComponent(fileName) + '?quality=auto',
    Object.assign({ method: 'HEAD' }, options)).then(function(r) {
    if (!cinemaIsCurrent(session) || session.hasPlayed || (session.stream && session.stream.failed) || r.ok === false) return;
    var mode = r.headers.get('X-ESE-Transcoding');
    if (mode === 'hevc-to-h264') cinemaStatus(session, 'Preparando vídeo HEVC — puede tardar hasta 60 s');
    else if (mode === 'transcode') cinemaStatus(session, 'Preparando vídeo — puede tardar');
  }).catch(function() {});

  fetch('/api/stream/completed/info?name=' + encodeURIComponent(fileName), options)
    .then(function(r) { if (r.ok === false) throw new Error('Info unavailable'); return r.json(); })
    .then(function(data) {
      if (!cinemaIsCurrent(session) || !data) return;
      var duration = Number(data.estimatedTotalSec);
      session.duration = data.durationKnown !== false && Number.isFinite(duration) && duration > 0 ? duration : 0;
      estTotalSec = session.duration;
      session.isPartFile = !!data.isPartFile;
      window._isPartFile = session.isPartFile;
      currentPartNum = data.isPartFile && data.partNum ? data.partNum : null;
      updateCinemaProgress(session);
    }).catch(function() { /* Unknown duration stays unknown; playback state comes from video events. */ });

  fetch('/api/stream/tracks?name=' + encodeURIComponent(fileName), options)
    .then(function(r) { if (r.ok === false) throw new Error('Tracks unavailable'); return r.json(); })
    .then(function(tracks) {
      if (!cinemaIsCurrent(session) || !tracks) return;
      var audioSel = document.getElementById('cinema-audio');
      if (audioSel && Array.isArray(tracks.audio) && tracks.audio.length > 1) {
        audioSel.innerHTML = '';
        tracks.audio.forEach(function(a, i) {
          var label = (a.lang || 'und').toUpperCase();
          if (a.title) label += ' — ' + a.title;
          if (a.channels) label += ' (' + a.channels + 'ch)';
          var option = document.createElement('option');
          option.value = a.index; option.textContent = label; option.selected = i === 0;
          audioSel.appendChild(option);
        });
        document.getElementById('cinema-audio-row').style.display = '';
      }
      var subSel = document.getElementById('cinema-subs');
      if (subSel && Array.isArray(tracks.subtitles) && tracks.subtitles.length) {
        subSel.innerHTML = '<option value="-1" selected>Desactivados</option>';
        tracks.subtitles.forEach(function(sub, i) {
          var label = (sub.lang || 'und').toUpperCase();
          if (sub.title) label += ' — ' + sub.title;
          if (sub.forced) label += ' [Forzados]';
          var option = document.createElement('option');
          option.value = i; option.textContent = label;
          subSel.appendChild(option);
        });
        document.getElementById('cinema-subs-row').style.display = '';
      }
    }).catch(function() {});
}

// ── Controles del cinema player ────────────────────────────────────────────────
function toggleCinemaSettings() {
  var popup = document.getElementById('cinema-settings-popup');
  var button = document.getElementById('cinema-settings-btn');
  if (!popup) return;
  var open = popup.style.display === 'none';
  popup.style.display = open ? 'block' : 'none';
  if (button) button.setAttribute('aria-expanded', String(open));
}
function syncCinemaVolume() {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  var muted = session.video.muted || session.video.volume === 0;
  var button = document.getElementById('cinema-vol-btn');
  if (button) {
    button.textContent = muted ? '🔇' : '🔊';
    button.setAttribute('aria-label', muted ? 'Activar sonido' : 'Silenciar');
    button.setAttribute('aria-pressed', String(muted));
  }
  var slider = document.getElementById('cinema-vol-slider');
  if (slider) slider.value = Math.round((muted ? 0 : session.video.volume) * 100);
}
function playCinemaVideo(session, stream) {
  if (!cinemaIsCurrent(session) || session.stream !== stream || userWantsPause) return;
  var result = session.video.play();
  if (result && result.catch) result.catch(function() {
    if (cinemaIsCurrent(session) && session.stream === stream) cinemaStatus(session, 'Pulsa Reproducir para iniciar el vídeo');
  });
}
function toggleCinemaPlay() {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  if (session.video.paused) { userWantsPause = false; playCinemaVideo(session, session.stream); }
  else { userWantsPause = true; session.video.pause(); }
}
function toggleCinemaVol() {
  if (!cinemaIsCurrent(cinemaSession)) return;
  video.muted = !video.muted;
  if (!video.muted && video.volume === 0) video.volume = 1;
  syncCinemaVolume();
}
function setCinemaVol(value) {
  if (!cinemaIsCurrent(cinemaSession)) return;
  var volume = Number(value);
  if (!Number.isFinite(volume)) return;
  video.volume = Math.max(0, Math.min(100, volume)) / 100;
  video.muted = video.volume === 0;
  syncCinemaVolume();
}
function toggleCinemaFS() {
  var element = document.getElementById('cinema-player');
  var result;
  if (document.fullscreenElement && document.exitFullscreen) result = document.exitFullscreen();
  else if (element && element.requestFullscreen) result = element.requestFullscreen();
  if (result && result.catch) result.catch(function() { cinemaStatus(cinemaSession, 'Pantalla completa no disponible en este navegador'); });
}
function changeCinemaQuality(quality) {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  ++session.seekRequest;
  startCompletedMSE(session.fileName, quality, session.offset + (session.video.currentTime || 0));
}
function changeCinemaAudio(trackIndex) {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  window._cinemaAudioTrack = trackIndex;
  ++session.seekRequest;
  var quality = document.getElementById('cinema-quality');
  startCompletedMSE(session.fileName, quality ? quality.value : 'auto', session.offset + (session.video.currentTime || 0));
}
function clearCinemaSubtitles(session) {
  var player = session.video;
  var previous = session.subtitleTrack;
  session.subtitleTrack = null;
  var tracks = [];
  if (player.textTracks) for (var i = 0; i < player.textTracks.length; i++) tracks.push(player.textTracks[i]);
  if (previous && previous.track && tracks.indexOf(previous.track) < 0) tracks.push(previous.track);
  // Disable and empty the TextTrack while it is still attached. Removing the
  // HTMLTrackElement first can leave its last active cue painted by Chromium.
  tracks.forEach(function(textTrack) {
    var cues = textTrack.cues ? Array.prototype.slice.call(textTrack.cues) : [];
    textTrack.mode = 'disabled';
    cues.forEach(function(cue) { try { textTrack.removeCue(cue); } catch (_) {} });
  });
  player.querySelectorAll('track').forEach(function(track) {
    track.default = false;
    track.removeAttribute('default');
    track.removeAttribute('src');
    track.remove();
  });
}
function applyCinemaSubtitles(session) {
  var player = session.video;
  clearCinemaSubtitles(session);
  if (window._cinemaSubTrack === '-1' || window._cinemaSubTrack == null) return;
  var track = document.createElement('track');
  session.subtitleTrack = track;
  track.kind = 'subtitles';
  track.src = '/api/stream/subtitle?name=' + encodeURIComponent(session.fileName) + '&track=' + encodeURIComponent(window._cinemaSubTrack) + '&ss=' + session.offset;
  track.srclang = 'es'; track.label = 'Subtítulos'; track.default = true;
  cinemaListen(session, track, 'load', function() {
    if (session.subtitleTrack !== track) return;
    if (track.track) track.track.mode = 'showing';
    cinemaStatus(session, 'Subtítulos activados');
  }, session.stream);
  cinemaListen(session, track, 'error', function() {
    if (session.subtitleTrack === track) cinemaStatus(session, 'No se han podido cargar los subtítulos. Selecciona otra pista o inténtalo de nuevo.');
  }, session.stream);
  player.appendChild(track);
}
function changeCinemaSubs(subIndex) {
  var session = cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  window._cinemaSubTrack = String(subIndex);
  applyCinemaSubtitles(session);
  cinemaStatus(session, String(subIndex) === '-1' ? 'Subtítulos desactivados' : 'Cargando subtítulos…');
}

// ── Volver a la ficha del film ─────────────────────────────────────────────────
function backToDetail() {
  stopCinemaPlayback();
  var infoZone = document.getElementById('modal-info-zone');
  if (!infoZone || !infoZone.innerHTML.trim()) {
    if (typeof closeMovieModal === 'function') closeMovieModal();
    return;
  }
  var playerZone = document.getElementById('modal-player-zone');
  if (playerZone) { playerZone.style.display = 'none'; playerZone.innerHTML = ''; }
  infoZone.style.display = 'block';
  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'flex';
  var modal = document.getElementById('movie-modal');
  if (modal) modal.style.overflow = 'auto';
  if (document.fullscreenElement && document.exitFullscreen) {
    var exit = document.exitFullscreen();
    if (exit && exit.catch) exit.catch(function() {});
  }
  var control = infoZone.querySelector('button, a[href]') || closeBtn;
  if (control) control.focus({ preventScroll: true });
}

// ── Tráiler ────────────────────────────────────────────────────────────────────
function loadTrailer(query) {
  var container = document.getElementById('trailer-container');
  var btn = document.getElementById('trailer-btn');
  if (!container) return;
  var request = container._trailerRequest = (container._trailerRequest || 0) + 1;

  if (container.innerHTML && !container._trailerFailed) {
    container.innerHTML = '';
    if (btn) btn.innerHTML = '&#127916; Ver Tráiler';
    return;
  }

  container._trailerFailed = false;
  container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;padding:40px"><div class="spinner"></div></div>';
  if (btn) btn.innerHTML = '&#127916; Cargando...';

  fetch('/api/movies/trailer?q=' + encodeURIComponent(query)).then(function(r) { return r.json(); }).then(function(data) {
    if (container._trailerRequest !== request || document.getElementById('trailer-container') !== container) return;
    if (data.videoId && /^[a-zA-Z0-9_-]{6,15}$/.test(data.videoId)) {
      container.innerHTML = '<div class="trailer-container"><iframe src="https://www.youtube.com/embed/' + escapeAttr(data.videoId) + '?autoplay=1&rel=0" allow="autoplay;encrypted-media" allowfullscreen></iframe></div>';
      if (btn) btn.innerHTML = '&#127916; Ocultar Tráiler';
    } else {
      container.innerHTML = '<p style="color:#888;padding:16px">No se encontró tráiler. <a href="https://www.youtube.com/results?search_query=' + encodeURIComponent(query + ' trailer') + '" target="_blank" style="color:#ff6b35">Buscar en YouTube</a></p>';
      if (btn) btn.innerHTML = '&#127916; Ver Tráiler';
    }
  }).catch(function() {
    if (container._trailerRequest !== request || document.getElementById('trailer-container') !== container) return;
    container._trailerFailed = true;
    container.innerHTML = '<p role="status">No se ha podido cargar el tráiler. Pulsa Tráiler para reintentar.</p>';
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
function playPartFile(partFile, displayName, resumePosition) {
  playInModal(encodeURIComponent(displayName), resumePosition);
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
  quickModal._previousOverflow = document.body.style.overflow || '';
  quickModal.innerHTML = '<button type="button" class="modal-close" aria-label="Cerrar reproducción" onclick="closeMovieModal()">&times;</button>' +
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
  if (typeof stopLegacyPlayback === 'function') stopLegacyPlayback();
  else if (abortController) abortController.abort();
  var session = cinemaSession;
  if (!session) {
    session = cinemaSession = { active: true, video: video, modal: document.getElementById('movie-modal'),
      fileName: fileName, offset: 0, position: 0, duration: 0, hasPlayed: false,
      listeners: [], timers: [], stream: null, seekRequest: 0 };
  }
  if (!cinemaIsCurrent(session) || session.fileName !== fileName) return;
  cancelCinemaWork(session.stream);
  var stream = session.stream = { listeners: [], timers: [], retries: 0, hasPlayed: false, retryTimer: null };
  var player = session.video;
  clearCinemaSubtitles(session);
  var offset = Number(seekSec);
  session.offset = Number.isFinite(offset) && offset > 0 ? Math.floor(offset) : 0;
  window._cinemaSeekOffset = session.offset;
  window._currentFileName = fileName;
  currentQuality = quality;
  var streamUrl = '/api/stream/completed/' + encodeURIComponent(fileName) + '?q=' + encodeURIComponent(quality) + '&ss=' + session.offset;
  if (window._cinemaAudioTrack != null) streamUrl += '&audio=' + encodeURIComponent(window._cinemaAudioTrack);
  var oldActions = document.getElementById('modal-player-error-actions');
  if (oldActions) oldActions.remove();
  cinemaStatus(session, session.offset ? 'Preparando vídeo desde ' + fmtT(session.offset) + '…' : 'Preparando vídeo…');
  cinemaListen(session, player, 'canplay', function() { playCinemaVideo(session, stream); }, stream);
  cinemaListen(session, player, 'error', function() {
    if (stream.retryTimer !== null) return;
    stream.retries++;
    if (stream.retries > 3) {
      stream.failed = true;
      cinemaStatus(session, 'No se puede reproducir: formato incompatible o datos insuficientes');
      showPlayerErrorActions(session);
      return;
    }
    cinemaStatus(session, 'No se ha podido cargar el vídeo. Reintentando (' + stream.retries + '/3)…');
    stream.retryTimer = cinemaLater(session, function() {
      stream.retryTimer = null;
      player.src = streamUrl + '&retry=' + stream.retries;
      player.load();
    }, 2000, stream);
  }, stream);
  player.src = streamUrl;
  player.load();
  applyCinemaSubtitles(session);
  updateCinemaProgress(session);
}

function showPlayerErrorActions(session) {
  session = session || cinemaSession;
  if (!cinemaIsCurrent(session)) return;
  var player = document.getElementById('cinema-player');
  if (!player) return;
  var existing = document.getElementById('modal-player-error-actions');
  if (existing) existing.remove();
  var bar = document.createElement('div');
  bar.id = 'modal-player-error-actions';
  bar.style.cssText = 'position:absolute;bottom:80px;left:50%;transform:translateX(-50%);display:flex;gap:12px;z-index:1000';
  var retry = document.createElement('button');
  retry.type = 'button'; retry.textContent = 'Reintentar';
  retry.style.cssText = 'background:#ff806b;border:none;color:#191013;padding:12px 22px;border-radius:8px;cursor:pointer;font-weight:600;min-height:44px';
  retry.onclick = function() {
    if (!cinemaIsCurrent(session)) return;
    bar.remove();
    startCompletedMSE(session.fileName, currentQuality || 'auto', session.hasPlayed ? session.position : session.offset);
    var control = document.getElementById('cinema-play-btn');
    if (control) control.focus();
  };
  var close = document.createElement('button');
  close.type = 'button'; close.textContent = 'Volver';
  close.style.cssText = 'background:#161620;border:1px solid #888;color:#fff;padding:12px 22px;border-radius:8px;cursor:pointer;min-height:44px';
  close.onclick = function() { if (cinemaIsCurrent(session)) backToDetail(); };
  bar.appendChild(retry); bar.appendChild(close);
  player.appendChild(bar);
}
