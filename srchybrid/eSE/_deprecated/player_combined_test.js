
// âââ player_core.js âââ
// player_core.js — estado global compartido, utilidades, cola MSE, controles básicos

// ── Estado global ──────────────────────────────────────────────────────────────
let estTotalSec = 0;
let mediaSource = null;
let sourceBuffer = null;
let currentPartNum = null;
let currentQuality = 'auto';
let abortController = null;
let pumpRunning = false;

// Bitrate tracking
let bytesReceived = 0;
let lastBitrateCheck = 0;
let currentBitrate = 0;

var video = document.getElementById('video-player');

// ── Utilidades ─────────────────────────────────────────────────────────────────
function fmtT(s) {
  if (!s || !isFinite(s)) return '0:00';
  var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = Math.floor(s % 60);
  return h > 0 ? h + ':' + String(m).padStart(2, '0') + ':' + String(sec).padStart(2, '0')
    : m + ':' + String(sec).padStart(2, '0');
}

function parseDur(s) {
  if (!s) return 0;
  var p = s.split(':').map(Number);
  return p.length === 3 ? p[0] * 3600 + p[1] * 60 + p[2] : p.length === 2 ? p[0] * 60 + p[1] : 0;
}

// ── Controles básicos del reproductor ──────────────────────────────────────────
var userWantsPause = false;
function togglePlay() {
  if (video.paused || video.readyState < 2) {
    userWantsPause = false;
    video.play().catch(function(){});
  } else {
    userWantsPause = true;
    video.pause();
  }
}

function toggleMute() { video.muted = !video.muted; }
function toggleFS() {
  var w = document.getElementById('video-wrap');
  document.fullscreenElement ? document.exitFullscreen() : w.requestFullscreen();
}

// ── Listeners del elemento <video> principal ───────────────────────────────────
video.addEventListener('timeupdate', function () {
  var total = estTotalSec || video.duration || 0;
  if (total > 0) {
    document.getElementById('progress-bar-inner').style.width = (video.currentTime / total * 100) + '%';
    document.getElementById('time-display').textContent = fmtT(video.currentTime) + ' / ' + fmtT(total);
  }
  if (video.buffered.length > 0 && estTotalSec > 0) {
    var buffEnd = video.buffered.end(video.buffered.length - 1);
    document.getElementById('buffer-bar').style.width = (buffEnd / estTotalSec * 100) + '%';
    document.getElementById('buffer-label').textContent = 'Buffer: ' + fmtT(buffEnd) + ' de ' + fmtT(estTotalSec);
  }
});

video.addEventListener('play', function () { document.getElementById('play-btn').textContent = '⏸'; });
video.addEventListener('pause', function () { document.getElementById('play-btn').textContent = '▶'; });

// ── Seek bar ───────────────────────────────────────────────────────────────────
document.getElementById('seek-container').addEventListener('click', function (e) {
  var rect = e.currentTarget.getBoundingClientRect();
  var pct = (e.clientX - rect.left) / rect.width;
  var target = pct * (estTotalSec || video.duration);

  // Check if target is within buffered range
  var isBuffered = false;
  if (video.buffered.length > 0) {
    for (var i = 0; i < video.buffered.length; i++) {
      if (target >= video.buffered.start(i) && target <= video.buffered.end(i)) {
        isBuffered = true;
        break;
      }
    }
  }

  if (isBuffered) {
    video.currentTime = target;
  } else {
    var fileName = window._cinemaFileName || window._currentFileName;
    if (!fileName) return;

    var bufLabel = document.getElementById('buffer-label');

    if (window._isPartFile) {
      // .part file — tell eMule to download from this position
      var seekUrl = '/api/stream/seek?name=' + encodeURIComponent(fileName) + '&time=' + Math.floor(target);
      console.log('[Seek] Requesting eMule download from t=' + Math.floor(target) + 's');
      if (bufLabel) bufLabel.textContent = 'Solicitando seek a ' + fmtT(target) + '...';

      fetch(seekUrl).then(function(r) { return r.json(); }).then(function(data) {
        console.log('[Seek] Response:', data);
        if (bufLabel) bufLabel.textContent = 'eMule descargando part ' + data.targetPart + '/' + data.totalParts + ' — reiniciando stream...';
        window._cinemaSeekOffset = target;
        var q = window._cinemaQuality || currentQuality || 'auto';
        if (typeof switchStreamSeamless === 'function' && currentPartNum) {
          switchStreamSeamless(q, Math.floor(target));
        }
      }).catch(function(err) {
        console.log('[Seek] Error:', err);
        if (bufLabel) bufLabel.textContent = 'Error al solicitar seek';
      });
    } else {
      // Completed file — restart ffmpeg stream from the new position
      console.log('[Seek] Restarting completed stream from t=' + Math.floor(target) + 's');
      if (bufLabel) bufLabel.textContent = 'Reiniciando desde ' + fmtT(target) + '...';
      window._cinemaSeekOffset = target;
      var q = window._cinemaQuality || currentQuality || 'auto';
      startCompletedMSE(fileName, q, Math.floor(target));
    }
  }
});

// ── Cola MSE (Media Source Extensions) ────────────────────────────────────────
var appendQueue = [];
var isAppending = false;

function processAppendQueue() {
  if (isAppending || appendQueue.length === 0) return;
  if (!sourceBuffer || sourceBuffer.updating) return;

  isAppending = true;
  var chunk = appendQueue.shift();

  // Remove old data to prevent QuotaExceeded
  try {
    if (video.currentTime > 60 && video.buffered.length > 0) {
      var removeEnd = video.currentTime - 30;
      if (removeEnd > video.buffered.start(0)) {
        sourceBuffer.remove(video.buffered.start(0), removeEnd);
        sourceBuffer.addEventListener('updateend', function onRemoved() {
          sourceBuffer.removeEventListener('updateend', onRemoved);
          doAppend(chunk);
        });
        return;
      }
    }
  } catch (e) { }

  doAppend(chunk);
}

function doAppend(chunk) {
  try {
    sourceBuffer.appendBuffer(chunk);
    sourceBuffer.addEventListener('updateend', function onDone() {
      sourceBuffer.removeEventListener('updateend', onDone);
      isAppending = false;

      if (!userWantsPause && video.paused && video.buffered.length > 0 && video.buffered.end(0) > 0.5) {
        video.muted = true;
        video.play().then(function () { video.muted = false; }).catch(function () { });
      }

      processAppendQueue();
    });
  } catch (e) {
    isAppending = false;
    if (e.name === 'QuotaExceededError') {
      appendQueue.unshift(chunk);
      try {
        if (video.buffered.length > 0 && !sourceBuffer.updating) {
          sourceBuffer.remove(video.buffered.start(0), video.currentTime - 5);
          sourceBuffer.addEventListener('updateend', function onCleared() {
            sourceBuffer.removeEventListener('updateend', onCleared);
            processAppendQueue();
          });
        }
      } catch (e2) { setTimeout(processAppendQueue, 500); }
    } else {
      setTimeout(processAppendQueue, 100);
    }
  }
}

// ── Display de bitrate ─────────────────────────────────────────────────────────
setInterval(function () {
  var el = document.getElementById('bitrate-display');
  if (el && currentBitrate > 0) {
    var qualityLabel = currentQuality === 'auto' ? 'auto' : currentQuality;
    el.textContent = (currentBitrate / 1000).toFixed(0) + ' kbps | ' + qualityLabel;
  }
}, 500);


// âââ mse_engine.js âââ
// mse_engine.js — ABR automático, cambio de calidad, streaming MSE, playVideo

// ── Estado ABR ─────────────────────────────────────────────────────────────────
var autoABRInterval = null;
var autoLevel = 0;
var qualityLevels = ['480p', '720p', 'original'];
var activeQualityStream = null; // Track what quality is currently streaming

// ── ABR automático ─────────────────────────────────────────────────────────────
function startAutoABR() {
  if (autoABRInterval) clearInterval(autoABRInterval);
  autoLevel = 0;

  autoABRInterval = setInterval(function () {
    if (video.buffered.length === 0 || autoLevel >= qualityLevels.length - 1) return;
    var buffEnd = video.buffered.end(video.buffered.length - 1);
    var bufferAhead = buffEnd - video.currentTime;

    // Upgrade when buffer > 30s ahead
    if (bufferAhead > 30) {
      autoLevel++;
      var newQ = qualityLevels[autoLevel];
      console.log('[ABR] Buffer: ' + bufferAhead.toFixed(0) + 's ahead. Upgrading to ' + newQ);
      activeQualityStream = newQ;
      switchStreamSeamless(newQ, buffEnd);
      if (autoLevel >= qualityLevels.length - 1) {
        clearInterval(autoABRInterval);
        autoABRInterval = null;
      }
    }
  }, 5000);
}

// ── Cambio manual de calidad ───────────────────────────────────────────────────
function changeQuality(q) {
  if (autoABRInterval) { clearInterval(autoABRInterval); autoABRInterval = null; }

  if (q === 'auto') {
    currentQuality = 'auto';
    // If already streaming, start auto logic from current buffer
    if (currentPartNum && sourceBuffer) {
      autoLevel = 0;
      activeQualityStream = '480p';
      switchStreamSeamless('480p', 0);
      startAutoABR();
    }
  } else {
    currentQuality = q;
    activeQualityStream = q;
    if (currentPartNum && sourceBuffer) {
      // Switch in place: start from current buffer end
      var bufEnd = 0;
      if (video.buffered.length > 0) bufEnd = video.buffered.end(video.buffered.length - 1);
      switchStreamSeamless(q, bufEnd);
    }
  }
}

// ── Cambio de calidad seamless ─────────────────────────────────────────────────
// Keeps same MediaSource & SourceBuffer — no interruption!
async function switchStreamSeamless(quality, startFromSec) {
  // Abort current stream
  if (abortController) abortController.abort();
  pumpRunning = false;

  // Kill server-side ffmpeg
  await fetch('/api/stream/kill/' + currentPartNum).catch(function(){});

  // Small delay to ensure ffmpeg is killed
  await new Promise(function(r) { setTimeout(r, 300); });

  // Clear pending queue
  appendQueue = [];
  isAppending = false;

  document.getElementById('player-status').textContent = 'Cambiando a ' + quality + '...';

  // Start new fetch from the right time position
  abortController = new AbortController();
  bytesReceived = 0;
  lastBitrateCheck = Date.now();

  try {
    var url = '/api/stream/data/' + currentPartNum + '?q=' + quality + '&ss=' + startFromSec.toFixed(1);
    var response = await fetch(url, { signal: abortController.signal });
    var reader = response.body.getReader();
    pumpRunning = true;

    // fMP4 with empty_moov generates a new moov for each stream
    // MSE handles this via the abort() method
    if (sourceBuffer.updating) {
      await new Promise(function(r) { sourceBuffer.addEventListener('updateend', r, {once:true}); });
    }
    sourceBuffer.abort();
    sourceBuffer.timestampOffset = startFromSec;

    async function pump() {
      while (pumpRunning) {
        var result;
        try {
          result = await reader.read();
        } catch(e) {
          if (e.name === 'AbortError') return;
          throw e;
        }
        if (result.done) {
          var checkDrain = setInterval(function () {
            if (appendQueue.length === 0 && !isAppending) {
              clearInterval(checkDrain);
              document.getElementById('player-status').textContent = 'Streaming completo (' + quality + ')';
            }
          }, 200);
          break;
        }

        // Track bitrate
        bytesReceived += result.value.byteLength;
        var now = Date.now();
        var elapsed = (now - lastBitrateCheck) / 1000;
        if (elapsed >= 1) {
          currentBitrate = (bytesReceived * 8) / elapsed;
          bytesReceived = 0;
          lastBitrateCheck = now;
        }

        appendQueue.push(result.value);
        processAppendQueue();

        if (appendQueue.length > 5) {
          await new Promise(function (r) { setTimeout(r, 100); });
        }
      }
    }

    pump().then(function() {
      document.getElementById('player-status').textContent = 'Streaming (' + quality + ')';
    }).catch(function (e) {
      if (e.name !== 'AbortError') console.error('Stream error:', e);
    });

  } catch (e) {
    if (e.name !== 'AbortError') console.error('Fetch error:', e);
  }
}

// ── Inicio de streaming desde archivo .part ────────────────────────────────────
async function playVideo(partNum) {
  currentPartNum = partNum;
  var loading = document.getElementById('loading');
  loading.classList.add('active');
  document.getElementById('loading-text').textContent = 'Preparando streaming...';
  document.getElementById('loading-sub').textContent = 'Copiando datos y transcodificando';

  try {
    var initRes = await fetch('/api/stream/start/' + partNum);
    var initData = await initRes.json();
    if (initData.error) throw new Error(initData.error);

    estTotalSec = initData.estimatedTotalSec || 0;
    document.getElementById('player-title').textContent = initData.fileName;
    window._currentFileName = initData.fileName;
    window._isPartFile = true; // streaming from .part file

    loading.classList.remove('active');
    document.getElementById('hero').style.display = 'none';
    document.getElementById('player-container').style.display = 'block';

    // Setup MSE once
    mediaSource = new MediaSource();
    video.src = URL.createObjectURL(mediaSource);

    mediaSource.addEventListener('sourceopen', function () {
      sourceBuffer = mediaSource.addSourceBuffer('video/mp4; codecs="avc1.640029, mp4a.40.2"');
      sourceBuffer.mode = 'segments';

      // Check quality selector
      var qSelect = document.getElementById('quality-select');
      var selectedQ = qSelect ? qSelect.value : 'auto';
      currentQuality = selectedQ;

      if (selectedQ === 'auto') {
        activeQualityStream = '480p';
        switchStreamSeamless('480p', 0);
        startAutoABR();
      } else {
        activeQualityStream = selectedQ;
        switchStreamSeamless(selectedQ, 0);
      }
    });

    // Stall recovery
    video.addEventListener('waiting', function () {
      if (video.buffered.length > 0) {
        var buffEnd = video.buffered.end(video.buffered.length - 1);
        if (buffEnd > video.currentTime + 1) {
          setTimeout(function () {
            if (video.readyState < 3) {
              video.currentTime = video.currentTime + 0.1;
            }
          }, 500);
        }
      }
    });

  } catch (e) {
    loading.classList.remove('active');
    alert('Error: ' + e.message);
  }
}


// âââ cinema_player.js âââ
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
    '<span class="modal-player-title">' + movieTitle + '</span>' +
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

  Promise.all([
    fetch('/api/stream/completed/info?name=' + encodeURIComponent(fileName)).then(function(r){return r.json();}),
    fetch('/api/stream/tracks?name=' + encodeURIComponent(fileName)).then(function(r){return r.json();}).catch(function(){return {audio:[],subtitles:[]};})
  ]).then(function(results) {
    var data = results[0];
    var tracks = results[1];
    estTotalSec = data.estimatedTotalSec || 7200;
    window._isPartFile = !!data.isPartFile;
    if (data.isPartFile && data.partNum) {
      currentPartNum = data.partNum;
    } else {
      currentPartNum = null;
    }
    currentQuality = 'auto';

    // Populate audio selector
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

    // Populate subtitle selector
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

    var status = document.getElementById('modal-player-status');
    if (status) status.textContent = 'Streaming iniciado — ' + fmtT(estTotalSec);
    startCompletedMSE(fileName, 'auto', 0);
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
    if (data.videoId) {
      container.innerHTML = '<div class="trailer-container"><iframe src="https://www.youtube.com/embed/' + data.videoId + '?autoplay=1&rel=0" allow="autoplay;encrypted-media" allowfullscreen></iframe></div>';
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

  var streamUrl = '/api/stream/completed/' + encodeURIComponent(fileName) + '?q=' + quality + '&ss=' + seekSec;
  if (window._cinemaAudioTrack) streamUrl += '&audio=' + window._cinemaAudioTrack;
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
    var subUrl = '/api/stream/subtitle?name=' + encodeURIComponent(fileName) + '&track=' + window._cinemaSubTrack;
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

  video.addEventListener('error', function onErr() {
    video.removeEventListener('error', onErr);
    console.log('[Player] Video error, retrying...');
    setTimeout(function() {
      video.src = streamUrl + '&retry=1';
      video.load();
      video.play().catch(function(){});
    }, 2000);
  });
}


// âââ search_ui.js âââ
// search_ui.js — catálogo OMDb, búsqueda, modal de detalle, búsqueda eMule

// ── Catálogo de películas (OMDb) ───────────────────────────────────────────────
function renderMovieCard(m) {
  var poster = (m.Poster && m.Poster !== 'N/A') ? m.Poster : '';
  var title = m.Title || 'Sin titulo';
  var year = m.Year || '';
  var imdbId = m.imdbID || '';
  var safeTitle = title.replace(/'/g, "\\'").replace(/"/g, '&quot;');
  return '<div class="card" onclick="requestMovie(\'' + safeTitle + '\',\'' + imdbId + '\')">' +
    '<div class="card-poster" style="' + (poster ? 'background-image:url(' + poster + ');' : '') + '">' +
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
          'Mostrando resultados para <strong style="color:#ff6b35">"' + query + '"</strong>' +
          ' · <a href="#" onclick="forceSearch(\'' + origQuery.replace(/'/g, "\\'") + '\');return false" style="color:#888;text-decoration:underline">' +
          'Buscar exactamente "' + origQuery + '"</a></div>';
      }
      grid.innerHTML = header + data.Search.map(renderMovieCard).join('');
    } else if (isOriginal) {
      // Auto-correct: try alternatives silently
      var alts = generateAlternatives(query);
      tryAlternativesSequentially(alts, 0, query, grid);
    } else {
      grid.innerHTML = '<div style="color:#888;padding:40px;text-align:center">' +
        '<p style="font-size:18px;margin-bottom:8px">Sin resultados para "' + query + '"</p>' +
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
      grid.innerHTML = '<div style="color:#888;padding:30px;text-align:center">Sin resultados para "' + query + '"</div>';
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
      '<p style="font-size:18px;margin-bottom:8px">Sin resultados para "' + originalQuery + '"</p>' +
      '<p style="font-size:13px;color:#666">Prueba con el título en inglés</p></div>';
    return;
  }
  fetch('/api/movies/search?q=' + encodeURIComponent(alts[idx])).then(function(r) { return r.json(); }).then(function(data) {
    if (data.Search && data.Search.length > 0) {
      var header = '<div style="padding:12px 20px;color:#aaa;font-size:13px">' +
        'Mostrando resultados para <strong style="color:#ff6b35">"' + alts[idx] + '"</strong>' +
        ' · <a href="#" onclick="forceSearch(\'' + originalQuery.replace(/'/g, "\\'") + '\');return false" style="color:#888;text-decoration:underline">' +
        'Buscar exactamente "' + originalQuery + '"</a></div>';
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

    var poster = (m.Poster && m.Poster !== 'N/A') ? m.Poster : '';
    var safeTitle = (m.Title || '').replace(/'/g, "\\'");
    // Use localized title (from TMDB Spanish) for eMule searches
    var searchTitle = (localizedTitle || m.Title || '').replace(/'/g, "\\'");

    // Fetch HD backdrop from TMDB (OMDB poster is only 300px)
    var backdropUrl = poster;
    fetch('https://api.themoviedb.org/3/find/' + imdbId + '?api_key=2dca580c2a14b55200e784d157207b4d&external_source=imdb_id')
      .then(function(r){return r.json();})
      .then(function(find) {
        var results = (find.movie_results || []).concat(find.tv_results || []);
        if (results.length > 0 && results[0].backdrop_path) {
          backdropUrl = 'https://image.tmdb.org/t/p/w1280' + results[0].backdrop_path;
        } else if (results.length > 0 && results[0].poster_path) {
          backdropUrl = 'https://image.tmdb.org/t/p/w780' + results[0].poster_path;
        }
        var el = document.querySelector('.modal-backdrop');
        if (el) el.style.backgroundImage = 'url(' + backdropUrl + ')';
      }).catch(function(){});

    // Build buttons — Play ALWAYS visible
    var buttons = '';
    var movieYear = m.Year || '';
    if (localFileName) {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="playInModal(\'' + encodeURIComponent(localFileName) + '\')">&#9654; Reproducir</button>';
    } else {
      buttons += '<button class="modal-btn btn-play" id="modal-play-btn" onclick="smartPlay(\'' + searchTitle + '\', \'' + movieYear + '\')">&#9654; Reproducir</button>';
      buttons += '<button class="modal-btn btn-download" id="modal-download-btn" onclick="smartDownload(\'' + searchTitle + '\', \'' + movieYear + '\')">&#128229; Descargar para ver luego</button>';
    }
    buttons += '<button class="modal-btn btn-trailer" id="trailer-btn" onclick="loadTrailer(\'' + safeTitle + ' ' + movieYear + '\')">&#127916; Ver Tráiler</button>';
    if (!localFileName) {
      buttons += '<button class="modal-btn btn-emule" onclick="startEmuleSearch(\'' + searchTitle + '\', \'' + movieYear + '\')">&#128269; Búsqueda avanzada</button>';
    }

    // Build detail cards
    var details = '';
    if (m.Director && m.Director !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Director</div><div class="detail-value">' + m.Director + '</div></div>';
    if (m.Actors && m.Actors !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Reparto</div><div class="detail-value">' + m.Actors + '</div></div>';
    if (m.Awards && m.Awards !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Premios</div><div class="detail-value">' + m.Awards + '</div></div>';
    if (m.BoxOffice && m.BoxOffice !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Taquilla</div><div class="detail-value">' + m.BoxOffice + '</div></div>';
    if (m.Country && m.Country !== 'N/A') details += '<div class="detail-item"><div class="detail-label">País</div><div class="detail-value">' + m.Country + '</div></div>';
    if (m.Language && m.Language !== 'N/A') details += '<div class="detail-item"><div class="detail-label">Idioma</div><div class="detail-value">' + m.Language + '</div></div>';

    // Meta badges
    var meta = '';
    if (m.imdbRating && m.imdbRating !== 'N/A') meta += '<span class="modal-rating">⭐ ' + m.imdbRating + '</span>';
    if (m.Year) meta += '<span class="modal-badge">' + m.Year + '</span>';
    if (m.Runtime && m.Runtime !== 'N/A') meta += '<span class="modal-badge">' + m.Runtime + '</span>';
    if (m.Rated && m.Rated !== 'N/A') meta += '<span class="modal-badge">' + m.Rated + '</span>';
    if (m.Genre && m.Genre !== 'N/A') {
      m.Genre.split(',').forEach(function(g) {
        meta += '<span class="modal-badge">' + g.trim() + '</span>';
      });
    }

    modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
      '<div id="modal-player-zone" style="display:none"></div>' +
      '<div id="modal-info-zone">' +
        '<div class="modal-backdrop" style="background-image:url(' + poster + ')"></div>' +
        '<div class="modal-content">' +
          '<h1 class="modal-title">' + (m.Title || '') + '</h1>' +
          '<div class="modal-meta">' + meta + '</div>' +
          '<div class="modal-buttons">' + buttons + '</div>' +
          '<div id="trailer-container"></div>' +
          '<p class="modal-plot">' + (m.Plot || 'Sin sinopsis disponible') + '</p>' +
          '<div class="modal-details">' + details + '</div>' +
        '</div>' +
      '</div>';
  }).catch(function() {
    modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
      '<div style="color:#e74c3c;text-align:center;padding:100px">Error de conexión</div>';
  });
}

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
    '<h3 style="color:#ff6b35;margin-bottom:12px"> Buscando en eMule: "' + searchQuery + '"</h3>' +
    '<div style="display:flex;align-items:center;gap:12px"><div class="spinner"></div>' +
    '<span style="color:#888">Buscando fuentes... (esto puede tardar unos segundos)</span></div></div>';

  fetch('/api/emule/search?q=' + encodeURIComponent(searchQuery)).then(function(r) { return r.json(); }).then(function(data) {
    if (!data.success) {
      searchDiv.innerHTML = '<div style="padding:20px">' +
        '<p style="color:#e74c3c"> ' + (data.error || 'Error de conexión') + '</p></div>';
      return;
    }

    if (!data.results || data.results.length === 0) {
      searchDiv.innerHTML = '<div style="padding:20px">' +
        '<p style="color:#888">No se encontraron resultados para "' + title + '"</p></div>';
      return;
    }

    var html = '<div style="padding:20px"><h3 style="color:#ff6b35;margin-bottom:16px"> Fuentes encontradas (' + data.results.length + ')</h3>' +
      '<div class="source-results">';

    data.results.forEach(function(r, i) {
      var qualityBadge = r.quality !== 'unknown' ? '<span class="source-badge badge-quality">' + r.quality.toUpperCase() + '</span>' : '';
      var langBadge = r.language !== 'unknown' ? '<span class="source-badge badge-lang">' + r.language + '</span>' : '';
      var scoreBadge = '<span class="source-badge badge-score">⭐ ' + r.score + '</span>';
      var sourcesBadge = '<span class="source-badge badge-sources">' + r.sources + '/' + r.completeSources + ' fuentes</span>';
      var fakeBadge = r.isFake ? '<span class="source-badge" style="background:#e74c3c">FAKE</span>' : '';

      html += '<div class="source-item">' +
        '<div class="source-name">' + (i === 0 ? ' ' : '') + r.fileName + '<br><span style="color:#666;font-size:11px">' + r.sizeMB + ' MB</span></div>' +
        '<div class="source-meta">' + qualityBadge + langBadge + sourcesBadge + scoreBadge + fakeBadge + '</div>' +
        '<div class="source-actions">' +
          '<button class="source-btn source-btn-play" onclick="streamSource(\'' + r.hash + '\', \'' + title.replace(/'/g, "\\'") + '\')" title="Reproducir ahora">▶ Reproducir</button>' +
          '<button class="source-btn source-btn-dl" onclick="downloadSource(\'' + r.hash + '\')" title="Descargar para ver luego"> Descargar</button>' +
        '</div>' +
      '</div>';
    });

    html += '</div></div>';
    searchDiv.innerHTML = html;

  }).catch(function(err) {
    searchDiv.innerHTML = '<div style="padding:20px"><p style="color:#e74c3c">Error: ' + err.message + '</p></div>';
  });
}

function smartSearchOverlay(title) {
  var overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:400;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML = '<div style="background:#16161e;border-radius:16px;padding:32px;max-width:600px;width:90%;border:1px solid #333;max-height:80vh;overflow-y:auto">' +
    '<h3 style="color:#ff6b35;margin-bottom:16px;font-size:20px"> Buscar en eMule</h3>' +
    '<input type="text" id="emule-custom-query" value="' + title + '" class="setting-input" style="margin-bottom:12px">' +
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


// âââ smart_play.js âââ
// smart_play.js — smartPlay, trySmartSource, monitorForFile

// ── Smart Play: evalúa → decide → actúa ───────────────────────────────────────
function smartPlay(movieTitle, movieYear) {
  var playerZone = document.getElementById('modal-player-zone');
  var infoZone = document.getElementById('modal-info-zone');
  if (!playerZone) return;

  if (infoZone) infoZone.style.display = 'none';
  playerZone.style.display = 'block';

  playerZone.innerHTML = '<div class="modal-player" id="cinema-player">' +
    '<div class="modal-player-header">' +
      '<button class="cinema-back-btn" onclick="backToDetail()">&larr; Volver</button>' +
    '</div>' +
    '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;gap:20px">' +
      '<div class="spinner" style="width:60px;height:60px;border-width:4px"></div>' +
      '<h2 style="color:#fff;font-size:24px;font-weight:600" id="smart-play-title">Evaluando disponibilidad...</h2>' +
      '<p style="color:#888;font-size:14px;text-align:center;max-width:400px" id="smart-play-status">Comprobando archivos locales y red eMule</p>' +
      '<div style="width:300px;height:4px;background:#222;border-radius:2px;overflow:hidden;margin-top:8px">' +
        '<div id="smart-play-progress" style="width:5%;height:100%;background:linear-gradient(90deg,#ff6b35,#ff2d78);transition:width .5s;border-radius:2px"></div>' +
      '</div>' +
      '<div id="smart-play-actions" style="display:none;flex-direction:column;gap:10px;margin-top:16px;align-items:center"></div>' +
    '</div>' +
  '</div>';

  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'none';
  var modal = document.getElementById('movie-modal');
  if (modal) modal.style.overflow = 'hidden';

  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var titleEl = document.getElementById('smart-play-title');
  var actionsEl = document.getElementById('smart-play-actions');

  function updateStatus(msg, pct) {
    if (statusEl) statusEl.textContent = msg;
    if (progressEl && pct >= 0) progressEl.style.width = pct + '%';
  }

  function hideSpinner() {
    var spinner = playerZone.querySelector('.spinner');
    if (spinner) spinner.style.display = 'none';
  }

  function showActions(buttons) {
    if (!actionsEl) return;
    actionsEl.innerHTML = '';
    actionsEl.style.display = 'flex';
    buttons.forEach(function(b) {
      var btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = b.primary
        ? 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:220px'
        : 'background:rgba(255,255,255,.08);border:1px solid #333;color:#aaa;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;min-width:220px';
      btn.onclick = b.action;
      actionsEl.appendChild(btn);
    });
  }

  // Store all results for "try another source"
  window._smartPlayResults = [];
  window._smartPlayIndex = 0;
  window._smartPlayTitle = movieTitle;
  window._smartPlayYear = movieYear;

  // Phase 1: Check if file already exists locally
  updateStatus('Comprobando archivos locales...', 10);
  var cleanTitle = movieTitle.replace(/[:\-–—\[\](){}]/g, ' ').replace(/\s+/g, ' ').trim();
  var movieWords = cleanTitle.toLowerCase().split(/\s+/).filter(function(w) { return w.length > 2; });

  function matchTitle(fn) {
    fn = fn.toLowerCase().replace(/[:\-–—\[\](){}]/g, ' ');
    var matchCount = 0;
    movieWords.forEach(function(w) { if (fn.includes(w)) matchCount++; });
    return matchCount >= Math.ceil(movieWords.length * 0.4);
  }

  Promise.all([
    fetch('/api/stream/completed/list').then(function(r){return r.json();}).catch(function(){return [];}),
    fetch('/api/emule/downloads').then(function(r){return r.json();}).catch(function(){return [];})
  ]).then(function(results) {
    var completed = results[0] || [];
    var downloads = results[1] || [];

    // Check completed files
    for (var i = 0; i < completed.length; i++) {
      if (matchTitle(completed[i].fileName)) {
        updateStatus('Archivo encontrado: ' + completed[i].fileName, 100);
        if (titleEl) titleEl.textContent = 'Listo para reproducir';
        setTimeout(function() { playInModal(encodeURIComponent(completed[i].fileName)); }, 1000);
        return;
      }
    }

    // Check active downloads with enough data
    for (var j = 0; j < downloads.length; j++) {
      if (matchTitle(downloads[j].fileName) && downloads[j].active && downloads[j].sizeMB > 50) {
        updateStatus('Descarga en progreso: ' + downloads[j].fileName + ' (' + downloads[j].sizeMB + ' MB)', 80);
        if (titleEl) titleEl.textContent = 'Datos disponibles';
        setTimeout(function() { playPartFile(downloads[j].partFile, downloads[j].fileName); }, 2000);
        return;
      }
    }

    // Phase 2: Search eMule
    updateStatus('Buscando fuentes en la red eMule...', 20);
    if (titleEl) titleEl.textContent = 'Evaluando disponibilidad...';

    fetch('/api/emule/smartsearch?q=' + encodeURIComponent(movieTitle) + (movieYear ? '&year=' + movieYear : ''))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (!data.success) {
          hideSpinner();
          if (titleEl) titleEl.textContent = 'Error de conexion';
          updateStatus(data.error || 'No se pudo conectar a eMule', 0);
          showActions([
            { text: 'Reintentar', primary: true, action: function() { smartPlay(movieTitle, movieYear); } },
            { text: 'Volver', primary: false, action: backToDetail }
          ]);
          return;
        }

        if (!data.results || data.results.length === 0) {
          hideSpinner();
          var filteredMsg = data.fakesFiltered > 0
            ? data.totalFound + ' resultado(s), pero ' + data.fakesFiltered + ' descartado(s) como fake'
            : 'No se encontraron fuentes para esta pelicula';
          if (titleEl) titleEl.textContent = 'Sin fuentes disponibles';
          updateStatus(filteredMsg, 0);
          showActions([
            { text: 'Busqueda avanzada', primary: true, action: function() { backToDetail(); startEmuleSearch(movieTitle, movieYear); } },
            { text: 'Volver', primary: false, action: backToDetail }
          ]);
          return;
        }

        window._smartPlayResults = data.results;
        window._smartPlayIndex = 0;
        trySmartSource(0);
      })
      .catch(function(err) {
        hideSpinner();
        if (titleEl) titleEl.textContent = 'Error';
        updateStatus('Error: ' + err.message, 0);
        showActions([{ text: 'Volver', primary: true, action: backToDetail }]);
      });
  });
}

// ── Prueba una fuente concreta ────────────────────────────────────────────────
function trySmartSource(index) {
  var results = window._smartPlayResults || [];
  if (index >= results.length) {
    var titleEl = document.getElementById('smart-play-title');
    var statusEl = document.getElementById('smart-play-status');
    var actionsEl = document.getElementById('smart-play-actions');
    var spinner = document.querySelector('#cinema-player .spinner');
    if (spinner) spinner.style.display = 'none';
    if (titleEl) titleEl.textContent = 'Ninguna fuente viable';
    if (statusEl) statusEl.textContent = 'Se probaron ' + results.length + ' fuentes sin exito';
    if (actionsEl) {
      actionsEl.innerHTML = '';
      actionsEl.style.display = 'flex';
      var btn = document.createElement('button');
      btn.textContent = 'Volver a la ficha';
      btn.style.cssText = 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600';
      btn.onclick = backToDetail;
      actionsEl.appendChild(btn);
    }
    return;
  }

  window._smartPlayIndex = index;
  var best = results[index];
  var titleEl = document.getElementById('smart-play-title');
  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var actionsEl = document.getElementById('smart-play-actions');

  var spinner = document.querySelector('#cinema-player .spinner');
  if (spinner) spinner.style.display = 'block';
  if (actionsEl) actionsEl.style.display = 'none';

  if (titleEl) titleEl.textContent = 'Evaluando fuente ' + (index + 1) + '/' + results.length;
  if (statusEl) statusEl.textContent = (best.quality || '?').toUpperCase() + ' | ' + (best.language || '?') + ' | ' + best.sources + '/' + best.completeSources + ' fuentes | Score: ' + best.score;
  if (progressEl) progressEl.style.width = '40%';

  setTimeout(function() {
    if (statusEl) statusEl.textContent = 'Iniciando descarga: ' + best.fileName.substring(0, 50) + '...';
    fetch('/api/emule/download?hash=' + encodeURIComponent(best.hash))
      .then(function(r) { return r.json(); })
      .then(function(dlData) {
        if (dlData.success) {
          if (progressEl) progressEl.style.width = '60%';
          if (titleEl) titleEl.textContent = 'Monitorizando velocidad...';
          monitorForFile(window._smartPlayTitle, best.fileName, best.sizeMB || 0, index);
        } else {
          if (statusEl) statusEl.textContent = 'Error al iniciar descarga';
          setTimeout(function() { trySmartSource(index + 1); }, 2000);
        }
      })
      .catch(function() {
        setTimeout(function() { trySmartSource(index + 1); }, 2000);
      });
  }, 1500);
}

// ── Monitoriza la descarga hasta que hay buffer suficiente ────────────────────
function monitorForFile(movieTitle, expectedFileName, totalSizeMB, sourceIndex) {
  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var titleEl = document.getElementById('smart-play-title');
  var actionsEl = document.getElementById('smart-play-actions');
  var checkCount = 0;

  function normalize(s) {
    return s.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ').trim();
  }

  var movieWords = normalize(movieTitle).split(' ').filter(function(w) { return w.length > 2; });
  var fileFirstSeen = 0;
  var activeChecks = 0;
  var BUFFER_WAIT_SEC = 15;
  var MAX_EVAL_CHECKS = 24; // 24 × 5s = 2 min max

  function matchTitle(fn) {
    fn = normalize(fn);
    var matchCount = 0;
    movieWords.forEach(function(w) { if (fn.includes(w)) matchCount++; });
    return matchCount >= Math.max(1, Math.ceil(movieWords.length * 0.3));
  }

  function buildButtons(remaining, onNextSource) {
    var buttons = [];
    if (remaining > 0) {
      buttons.push({ text: 'Probar otra fuente (' + remaining + ' disponibles)', primary: true, action: onNextSource });
    }
    buttons.push({
      text: remaining === 0 ? 'Descargar y avisar cuando este lista' : 'Dejar descargando',
      primary: remaining === 0,
      action: function() { backToDetail(); showNotification('La descarga continua en segundo plano'); }
    });
    buttons.push({ text: 'Volver', primary: false, action: backToDetail });
    return buttons;
  }

  function renderButtons(buttons) {
    if (!actionsEl) return;
    actionsEl.innerHTML = '';
    actionsEl.style.display = 'flex';
    buttons.forEach(function(b) {
      var btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = b.primary
        ? 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:220px'
        : 'background:rgba(255,255,255,.08);border:1px solid #333;color:#aaa;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;min-width:220px';
      btn.onclick = b.action;
      actionsEl.appendChild(btn);
    });
  }

  var checker = setInterval(function() {
    checkCount++;

    fetch('/api/stream/completed/list').then(function(r) { return r.json(); }).then(function(files) {
      if (files && files.length) {
        for (var i = 0; i < files.length; i++) {
          if (matchTitle(files[i].fileName)) {
            clearInterval(checker);
            if (progressEl) progressEl.style.width = '100%';
            if (titleEl) titleEl.textContent = 'Listo para reproducir';
            if (statusEl) statusEl.textContent = files[i].fileName;
            setTimeout(function() { playInModal(encodeURIComponent(files[i].fileName)); }, 1500);
            return;
          }
        }
      }

      fetch('/api/emule/downloads').then(function(r2) { return r2.json(); }).then(function(downloads) {
        if (downloads && downloads.length) {
          for (var j = 0; j < downloads.length; j++) {
            var dl = downloads[j];
            if (!matchTitle(dl.fileName)) continue;

            var isActive = dl.active;
            if (isActive) {
              if (fileFirstSeen === 0) fileFirstSeen = Date.now();
              activeChecks++;
            } else {
              activeChecks = Math.max(0, activeChecks - 1);
            }

            var waitingSec = fileFirstSeen > 0 ? Math.round((Date.now() - fileFirstSeen) / 1000) : 0;

            if (fileFirstSeen > 0) {
              var bufferPct = Math.min(waitingSec / BUFFER_WAIT_SEC * 100, 100);
              if (progressEl) progressEl.style.width = (60 + bufferPct * 0.4) + '%';
              if (isActive) {
                if (statusEl) statusEl.textContent = 'Recibiendo datos (' + dl.sizeMB + ' MB) | Buffer: ' + waitingSec + '/' + BUFFER_WAIT_SEC + 's';
              } else {
                if (statusEl) statusEl.textContent = 'Archivo detectado, esperando datos...';
              }
              if (titleEl) titleEl.textContent = 'Buffering... (' + Math.round(bufferPct) + '%)';
            }

            if (waitingSec >= BUFFER_WAIT_SEC && activeChecks >= 3) {
              clearInterval(checker);
              if (progressEl) progressEl.style.width = '100%';
              if (titleEl) titleEl.textContent = 'Reproduciendo';
              if (statusEl) statusEl.textContent = 'Buffer listo';
              setTimeout(function() { playPartFile(dl.partFile, dl.fileName); }, 1000);
              return;
            }

            if (checkCount >= MAX_EVAL_CHECKS && activeChecks < 2) {
              clearInterval(checker);
              var sp = document.querySelector('#cinema-player .spinner');
              if (sp) sp.style.display = 'none';
              if (titleEl) titleEl.textContent = 'Velocidad insuficiente';
              if (statusEl) statusEl.textContent = 'La descarga es demasiado lenta para streaming en directo';
              var remaining = (window._smartPlayResults || []).length - (sourceIndex + 1);
              renderButtons(buildButtons(remaining, function() { trySmartSource(sourceIndex + 1); }));
              return;
            }

            return;
          }
        }

        var dots = '.'.repeat((checkCount % 3) + 1);
        if (statusEl) statusEl.textContent = 'Esperando que eMule reciba datos' + dots + ' (' + (checkCount * 5) + 's)';
        if (progressEl) progressEl.style.width = Math.min(60 + checkCount, 75) + '%';

        if (checkCount >= MAX_EVAL_CHECKS) {
          clearInterval(checker);
          var sp2 = document.querySelector('#cinema-player .spinner');
          if (sp2) sp2.style.display = 'none';
          if (titleEl) titleEl.textContent = 'Sin datos recibidos';
          if (statusEl) statusEl.textContent = 'No se recibieron datos de esta fuente';
          var remaining2 = (window._smartPlayResults || []).length - (sourceIndex + 1);
          renderButtons(buildButtons(remaining2, function() { trySmartSource(sourceIndex + 1); }));
        }
      }).catch(function() {});
    }).catch(function() {});
  }, 5000);
}


// âââ hero_ui.js âââ
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
  
  // Load remote access info
  fetch('/api/connect-seed').then(function(r){return r.json()}).then(function(seed) {
    var ipEl = document.getElementById('set-public-ip');
    var tunnelEl = document.getElementById('set-tunnel-url');
    var ntfyEl = document.getElementById('set-ntfy-url');
    if (ipEl && seed.publicIP) ipEl.textContent = 'http://' + seed.publicIP + ':8080';
    else if (ipEl) ipEl.textContent = 'No disponible';
    if (tunnelEl && seed.tunnel) tunnelEl.textContent = seed.tunnel;
    else if (tunnelEl) tunnelEl.textContent = 'No disponible';
    if (ntfyEl && seed.ntfyTopic) ntfyEl.textContent = 'https://ntfy.sh/' + seed.ntfyTopic;
  }).catch(function() {});
  
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
  var TMDB_KEY = '2dca580c2a14b55200e784d157207b4d';
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
    if (fnMatch) {
      var localFile = decodeURIComponent(fnMatch[1]).replace(/'/g, "\\'");
      card.setAttribute('onclick', "showMovieDetail('" + info.imdbId + "','" + localFile + "')");
    } else {
      card.setAttribute('onclick', "showMovieDetail('" + info.imdbId + "',null)");
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
  var TMDB_KEY = '2dca580c2a14b55200e784d157207b4d'; // Free demo key
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
  fetch('https://api.themoviedb.org/3/movie/' + m.id + '/external_ids?api_key=2dca580c2a14b55200e784d157207b4d')
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

