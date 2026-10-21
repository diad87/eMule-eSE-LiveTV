// mse_engine.js — ABR automático, cambio de calidad, streaming MSE, playVideo

// ── Estado ABR y ciclo de vida del reproductor integrado ───────────────────────
var autoABRInterval = null;
var autoLevel = 0;
var qualityLevels = ['480p', '720p', 'original'];
var activeQualityStream = null;
var legacyPlaybackGeneration = 0;
var legacySwitchGeneration = 0;
var legacyTimers = [];
var legacyListeners = [];
var legacyVideo = null;
var legacyObjectURL = null;
function stopLegacyPlayback() {
  ++legacyPlaybackGeneration;
  ++legacySwitchGeneration;
  if (autoABRInterval) clearInterval(autoABRInterval);
  autoABRInterval = null;
  legacyTimers.forEach(function(id) { clearTimeout(id); clearInterval(id); });
  legacyTimers = [];
  legacyListeners.forEach(function(remove) { remove(); });
  legacyListeners = [];
  if (abortController) { try { abortController.abort(); } catch (_) {} }
  abortController = null;
  pumpRunning = false;
  appendQueue = [];
  isAppending = false;
  sourceBuffer = null;
  mediaSource = null;
  if (legacyVideo) {
    try { legacyVideo.pause(); legacyVideo.removeAttribute('src'); legacyVideo.load(); } catch (_) {}
    legacyVideo = null;
  }
  if (legacyObjectURL) { URL.revokeObjectURL(legacyObjectURL); legacyObjectURL = null; }
  var loading = document.getElementById('loading');
  if (loading) loading.classList.remove('active');
}
function legacyIsCurrent(generation, player) {
  return generation === legacyPlaybackGeneration && video === player && legacyVideo === player;
}
function legacyLater(generation, player, callback, delay) {
  var timer = setTimeout(function() {
    legacyTimers = legacyTimers.filter(function(id) { return id !== timer; });
    if (legacyIsCurrent(generation, player)) callback();
  }, delay);
  legacyTimers.push(timer);
  return timer;
}
function legacyStatus(text) {
  var status = document.getElementById('player-status');
  if (status) status.textContent = text;
}
function legacyWait(signal, delay) {
  return new Promise(function(resolve) {
    function finish() { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve(); }
    var timer = setTimeout(finish, delay);
    if (signal.aborted) finish();
    else signal.addEventListener('abort', finish, { once: true });
  });
}

function startAutoABR() {
  if (autoABRInterval) clearInterval(autoABRInterval);
  autoLevel = 0;
  var generation = legacyPlaybackGeneration;
  var player = video;
  autoABRInterval = setInterval(function() {
    if (!legacyIsCurrent(generation, player) || !player.buffered.length) return;
    var end = player.buffered.end(player.buffered.length - 1);
    var ahead = end - player.currentTime;
    if (ahead < 5 && autoLevel > 0) {
      --autoLevel; activeQualityStream = qualityLevels[autoLevel];
      switchStreamSeamless(activeQualityStream, end);
    } else if (ahead > 30 && autoLevel < qualityLevels.length - 1) {
      ++autoLevel; activeQualityStream = qualityLevels[autoLevel];
      switchStreamSeamless(activeQualityStream, end);
    }
  }, 5000);
}
function changeQuality(quality) {
  if (autoABRInterval) clearInterval(autoABRInterval);
  autoABRInterval = null;
  currentQuality = quality;
  if (!currentPartNum || !sourceBuffer) return;
  if (quality === 'auto') {
    autoLevel = 0; activeQualityStream = '480p';
    switchStreamSeamless('480p', video.currentTime || 0);
    startAutoABR();
  } else {
    activeQualityStream = quality;
    var end = video.buffered.length ? video.buffered.end(video.buffered.length - 1) : video.currentTime || 0;
    switchStreamSeamless(quality, end);
  }
}

// Keep the same MediaSource when changing quality, but never let an old fetch
// append into the next player or overwrite its status after any await boundary.
async function switchStreamSeamless(quality, startFromSec) {
  var generation = legacyPlaybackGeneration;
  var request = ++legacySwitchGeneration;
  var player = video;
  var part = currentPartNum;
  var buffer = sourceBuffer;
  function current() { return legacyIsCurrent(generation, player) && request === legacySwitchGeneration && sourceBuffer === buffer; }
  if (!buffer || !current()) return;
  if (abortController) abortController.abort();
  var controller = abortController = new AbortController();
  pumpRunning = false;
  try {
    await fetch('/api/stream/kill/' + part, { signal: controller.signal }).catch(function() {});
    if (!current()) return;
    // An aborted wait resolves too, so closing does not retain an async task.
    await legacyWait(controller.signal, 300);
    if (!current()) return;
    appendQueue = []; isAppending = false;
    legacyStatus('Cambiando a ' + quality + '…');
    bytesReceived = 0; lastBitrateCheck = Date.now();
    var response = await fetch('/api/stream/data/' + part + '?q=' + encodeURIComponent(quality) + '&ss=' + Number(startFromSec).toFixed(1), { signal: controller.signal });
    if (!current()) return;
    if (!response.ok) throw new Error('No se han recibido datos del vídeo');
    var reader = response.body.getReader();
    if (buffer.updating) {
      await new Promise(function(resolve) {
        function finish() { buffer.removeEventListener('updateend', finish); controller.signal.removeEventListener('abort', finish); resolve(); }
        buffer.addEventListener('updateend', finish, { once: true });
        controller.signal.addEventListener('abort', finish, { once: true });
      });
    }
    if (!current()) { reader.cancel().catch(function() {}); return; }
    buffer.abort(); buffer.timestampOffset = startFromSec;
    pumpRunning = true;
    while (current()) {
      var result = await reader.read();
      if (!current()) { reader.cancel().catch(function() {}); return; }
      if (result.done) {
        // Receiving all data is not evidence that the video has finished playing.
        legacyStatus('Datos del vídeo recibidos');
        break;
      }
      bytesReceived += result.value.byteLength;
      var now = Date.now(); var elapsed = (now - lastBitrateCheck) / 1000;
      if (elapsed >= 1) { currentBitrate = bytesReceived * 8 / elapsed; bytesReceived = 0; lastBitrateCheck = now; }
      appendQueue.push(result.value); processAppendQueue();
      if (appendQueue.length > 5) {
        await legacyWait(controller.signal, 100);
      }
    }
  } catch (error) {
    if (current() && error.name !== 'AbortError') legacyStatus('No se ha podido cargar el vídeo. Vuelve a abrirlo para reintentar.');
  }
}

async function playVideo(partNum) {
  if (typeof stopCinemaPlayback === 'function') stopCinemaPlayback();
  else stopLegacyPlayback();
  var player = document.getElementById('video-player');
  if (!player) return;
  video = player; legacyVideo = player;
  var generation = legacyPlaybackGeneration;
  var controller = abortController = new AbortController();
  currentPartNum = partNum;
  userWantsPause = false;
  estTotalSec = 0;
  var loading = document.getElementById('loading');
  loading.classList.add('active');
  document.getElementById('loading-text').textContent = 'Preparando vídeo…';
  document.getElementById('loading-sub').textContent = 'Leyendo los datos disponibles';
  try {
    var response = await fetch('/api/stream/start/' + partNum, { signal: controller.signal });
    if (!legacyIsCurrent(generation, player)) return;
    if (!response.ok) throw new Error('No se ha podido iniciar el vídeo');
    var data = await response.json();
    if (!legacyIsCurrent(generation, player)) return;
    if (data.error) throw new Error(data.error);
    var duration = Number(data.estimatedTotalSec);
    estTotalSec = Number.isFinite(duration) && duration > 0 ? duration : 0;
    document.getElementById('player-title').textContent = data.fileName;
    window._currentFileName = data.fileName;
    window._isPartFile = true;
    loading.classList.remove('active');
    document.getElementById('hero').style.display = 'none';
    document.getElementById('player-container').style.display = 'block';
    var source = mediaSource = new MediaSource();
    legacyObjectURL = URL.createObjectURL(source);
    player.src = legacyObjectURL;
    source.addEventListener('sourceopen', function() {
      if (!legacyIsCurrent(generation, player) || mediaSource !== source) return;
      sourceBuffer = source.addSourceBuffer('video/mp4; codecs="avc1.640029, mp4a.40.2"');
      sourceBuffer.mode = 'segments';
      var selector = document.getElementById('quality-select');
      currentQuality = selector ? selector.value : 'auto';
      activeQualityStream = currentQuality === 'auto' ? '480p' : currentQuality;
      switchStreamSeamless(activeQualityStream, 0);
      if (currentQuality === 'auto') startAutoABR();
    }, { once: true });
    var waiting = function() {
      if (!legacyIsCurrent(generation, player)) return;
      legacyStatus('Esperando datos…');
      if (player.buffered.length && player.buffered.end(player.buffered.length - 1) > player.currentTime + 1) {
        legacyLater(generation, player, function() { if (player.readyState < 3) player.currentTime += 0.1; }, 500);
      }
    };
    player.addEventListener('waiting', waiting);
    legacyListeners.push(function() { player.removeEventListener('waiting', waiting); });
  } catch (error) {
    if (!legacyIsCurrent(generation, player)) return;
    loading.classList.remove('active');
    if (error.name !== 'AbortError') showErrorToast('Error: ' + error.message);
  }
}

// BUG-045 FIX: Non-blocking toast for streaming errors
function showErrorToast(msg) {
  var toast = document.getElementById('ese-error-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'ese-error-toast';
    toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
      'background:rgba(220,53,69,0.95);color:#fff;padding:12px 24px;border-radius:8px;' +
      'font-family:sans-serif;font-size:14px;z-index:99999;max-width:80%;text-align:center;' +
      'box-shadow:0 4px 12px rgba(0,0,0,0.3);transition:opacity 0.3s';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = '1';
  toast.style.display = 'block';
  clearTimeout(toast._hideTimer);
  toast._hideTimer = setTimeout(function () {
    toast.style.opacity = '0';
    setTimeout(function () { toast.style.display = 'none'; }, 300);
  }, 6000);
}
