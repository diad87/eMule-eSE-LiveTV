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
  // BUG-047 FIX: clamp pct and validate target
  pct = Math.max(0, Math.min(1, pct));
  var totalSec = estTotalSec || video.duration || 0;
  var target = pct * totalSec;
  if (!isFinite(target) || target < 0) return;

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
        // BUG-046 FIX: use {once:true} to prevent listener leak
        sourceBuffer.addEventListener('updateend', function () {
          doAppend(chunk);
        }, { once: true });
        return;
      }
    }
  } catch (e) { }

  doAppend(chunk);
}

function doAppend(chunk) {
  try {
    sourceBuffer.appendBuffer(chunk);
    // BUG-046 FIX: use {once:true} to prevent listener leak
    sourceBuffer.addEventListener('updateend', function () {
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
