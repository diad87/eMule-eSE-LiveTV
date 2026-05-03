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
    if (video.buffered.length === 0) return;
    var buffEnd = video.buffered.end(video.buffered.length - 1);
    var bufferAhead = buffEnd - video.currentTime;

    // BUG-044 FIX: Downgrade when buffer < 5s ahead
    if (bufferAhead < 5 && autoLevel > 0) {
      autoLevel--;
      var newQ = qualityLevels[autoLevel];
      console.log('[ABR] Buffer: ' + bufferAhead.toFixed(0) + 's ahead. Downgrading to ' + newQ);
      activeQualityStream = newQ;
      switchStreamSeamless(newQ, buffEnd);
    }
    // Upgrade when buffer > 30s ahead
    else if (bufferAhead > 30 && autoLevel < qualityLevels.length - 1) {
      autoLevel++;
      var newQ = qualityLevels[autoLevel];
      console.log('[ABR] Buffer: ' + bufferAhead.toFixed(0) + 's ahead. Upgrading to ' + newQ);
      activeQualityStream = newQ;
      switchStreamSeamless(newQ, buffEnd);
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
    // BUG-045 FIX: non-blocking error toast instead of alert()
    showErrorToast('Error: ' + e.message);
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
