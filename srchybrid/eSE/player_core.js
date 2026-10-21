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
var mainVideo = video;
var mainSeekRequest = 0;
var mainSeek = document.getElementById('seek-container');
mainSeek.setAttribute('role', 'slider');
mainSeek.setAttribute('tabindex', '0');
mainSeek.setAttribute('aria-label', 'Posición de reproducción');
mainSeek.setAttribute('aria-valuemin', '0');
mainSeek.setAttribute('aria-valuemax', '0');
mainSeek.setAttribute('aria-valuenow', '0');
mainSeek.setAttribute('aria-disabled', 'true');

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
mainVideo.addEventListener('timeupdate', function () {
  if (video !== mainVideo) return;
  var total = estTotalSec || (Number.isFinite(mainVideo.duration) ? mainVideo.duration : 0);
  if (total > 0) {
    document.getElementById('progress-bar-inner').style.width = (video.currentTime / total * 100) + '%';
    document.getElementById('time-display').textContent = fmtT(video.currentTime) + ' / ' + fmtT(total);
  }
  if (!total) document.getElementById('time-display').textContent = fmtT(mainVideo.currentTime) + ' / Duración desconocida';
  mainSeek.setAttribute('aria-disabled', String(!total));
  mainSeek.setAttribute('aria-valuemax', String(total || 0));
  mainSeek.setAttribute('aria-valuenow', String(total ? Math.min(total, mainVideo.currentTime) : 0));
  mainSeek.setAttribute('aria-valuetext', total ? fmtT(mainVideo.currentTime) + ' de ' + fmtT(total) : 'Duración desconocida');
  if (video.buffered.length > 0 && estTotalSec > 0) {
    var buffEnd = video.buffered.end(video.buffered.length - 1);
    document.getElementById('buffer-bar').style.width = (buffEnd / estTotalSec * 100) + '%';
    document.getElementById('buffer-label').textContent = 'Buffer: ' + fmtT(buffEnd) + ' de ' + fmtT(estTotalSec);
  }
});

mainVideo.addEventListener('play', function () { if (video === mainVideo) { var b = document.getElementById('play-btn'); b.textContent = '⏸'; b.setAttribute('aria-label', 'Pausar'); } });
mainVideo.addEventListener('pause', function () { if (video === mainVideo) { var b = document.getElementById('play-btn'); b.textContent = '▶'; b.setAttribute('aria-label', 'Reproducir'); } });
mainVideo.addEventListener('playing', function() { if (video === mainVideo) document.getElementById('player-status').textContent = 'Reproduciendo'; });
mainVideo.addEventListener('ended', function() { if (video === mainVideo) document.getElementById('player-status').textContent = 'Reproducción finalizada'; });

// ── Seek bar ───────────────────────────────────────────────────────────────────
mainSeek.addEventListener('click', function (e) {
  var rect = e.currentTarget.getBoundingClientRect();
  var total = estTotalSec || (Number.isFinite(mainVideo.duration) ? mainVideo.duration : 0);
  if (rect.width > 0) seekMainTo((e.clientX - rect.left) / rect.width * total);
});
mainSeek.addEventListener('keydown', function(e) {
  var pos = mainVideo.currentTime || 0;
  var total = estTotalSec || (Number.isFinite(mainVideo.duration) ? mainVideo.duration : 0);
  var targets = { ArrowLeft: pos - 10, ArrowDown: pos - 10, ArrowRight: pos + 10, ArrowUp: pos + 10,
    PageDown: pos - 60, PageUp: pos + 60, Home: 0, End: total };
  if (Object.prototype.hasOwnProperty.call(targets, e.key)) { e.preventDefault(); seekMainTo(targets[e.key]); }
});
function seekMainTo(target) {
  if (video !== mainVideo) return;
  var generation = typeof legacyPlaybackGeneration === 'number' ? legacyPlaybackGeneration : 0;
  var request = ++mainSeekRequest;
  var totalSec = estTotalSec || (Number.isFinite(video.duration) ? video.duration : 0);
  if (!totalSec || !Number.isFinite(target)) return;
  target = Math.max(0, Math.min(Math.max(0, totalSec - 1), target));

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
    var fileName = window._currentFileName;
    if (!fileName) return;

    var bufLabel = document.getElementById('buffer-label');

    if (window._isPartFile) {
      // .part file — tell eMule to download from this position
      var seekUrl = '/api/stream/seek?name=' + encodeURIComponent(fileName) + '&time=' + Math.floor(target);
      console.log('[Seek] Requesting eMule download from t=' + Math.floor(target) + 's');
      if (bufLabel) bufLabel.textContent = 'Solicitando seek a ' + fmtT(target) + '...';

      fetch(seekUrl).then(function(r) { return r.json(); }).then(function(data) {
        if (video !== mainVideo || generation !== legacyPlaybackGeneration || request !== mainSeekRequest) return;
        console.log('[Seek] Response:', data);
        if (bufLabel) bufLabel.textContent = 'eMule descargando part ' + data.targetPart + '/' + data.totalParts + ' — reiniciando stream...';
        window._cinemaSeekOffset = target;
        var q = window._cinemaQuality || currentQuality || 'auto';
        if (typeof switchStreamSeamless === 'function' && currentPartNum) {
          switchStreamSeamless(q, Math.floor(target));
        }
      }).catch(function(err) {
        if (video !== mainVideo || generation !== legacyPlaybackGeneration || request !== mainSeekRequest) return;
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
}

// ── Cola MSE (Media Source Extensions) ────────────────────────────────────────
var appendQueue = [];
var isAppending = false;

function processAppendQueue() {
  if (isAppending || appendQueue.length === 0) return;
  if (!sourceBuffer || sourceBuffer.updating) return;

  isAppending = true;
  var chunk = appendQueue.shift();
  var buffer = sourceBuffer;
  var player = video;
  var generation = typeof legacyPlaybackGeneration === 'number' ? legacyPlaybackGeneration : 0;
  var request = typeof legacySwitchGeneration === 'number' ? legacySwitchGeneration : 0;

  // Remove old data to prevent QuotaExceeded
  try {
    if (video.currentTime > 60 && video.buffered.length > 0) {
      var removeEnd = video.currentTime - 30;
      if (removeEnd > video.buffered.start(0)) {
        sourceBuffer.remove(video.buffered.start(0), removeEnd);
        // BUG-046 FIX: use {once:true} to prevent listener leak
        sourceBuffer.addEventListener('updateend', function () {
          if (sourceBuffer !== buffer || video !== player || generation !== legacyPlaybackGeneration || request !== legacySwitchGeneration) return;
          doAppend(chunk);
        }, { once: true });
        return;
      }
    }
  } catch (e) { }

  doAppend(chunk);
}

function doAppend(chunk) {
  var buffer = sourceBuffer;
  var player = video;
  var generation = typeof legacyPlaybackGeneration === 'number' ? legacyPlaybackGeneration : 0;
  var request = typeof legacySwitchGeneration === 'number' ? legacySwitchGeneration : 0;
  function current() { return sourceBuffer === buffer && video === player && generation === legacyPlaybackGeneration && request === legacySwitchGeneration; }
  if (!buffer) return;
  try {
    buffer.appendBuffer(chunk);
    // BUG-046 FIX: use {once:true} to prevent listener leak
    buffer.addEventListener('updateend', function () {
      if (!current()) return;
      isAppending = false;

      if (!userWantsPause && video.paused && video.buffered.length > 0 && video.buffered.end(0) > 0.5) {
        player.play().catch(function () {
          if (current()) document.getElementById('player-status').textContent = 'Pulsa Reproducir para iniciar el vídeo';
        });
      }

      processAppendQueue();
    }, { once: true });
  } catch (e) {
    isAppending = false;
    if (e.name === 'QuotaExceededError') {
      appendQueue.unshift(chunk);
      try {
        if (video.buffered.length > 0 && !sourceBuffer.updating) {
          sourceBuffer.remove(video.buffered.start(0), video.currentTime - 5);
          sourceBuffer.addEventListener('updateend', function onCleared() {
            buffer.removeEventListener('updateend', onCleared);
            if (!current()) return;
            processAppendQueue();
          }, { once: true });
        }
      } catch (e2) { setTimeout(function() { if (current()) processAppendQueue(); }, 500); }
    } else {
      setTimeout(function() { if (current()) processAppendQueue(); }, 100);
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
