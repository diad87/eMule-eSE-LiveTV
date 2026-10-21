// filepath: srchybrid/eSE/live_player_html.js
// eSE Live Player HTML — exported as a function for use by server.js
// Same frame as the remote watch page (eSE-live/live_watch_page.js).
const navbar = require('./shared/navbar');

const LOCAL_CSS = `
body{padding-top:76px;background:#0a0a0f}
.watch{max-width:1280px;margin:0 auto;padding:24px var(--ese-page-padding,40px) 56px}
.player-wrap{position:relative;width:100%;aspect-ratio:16/9;max-height:calc(100vh - 150px);border-radius:14px;overflow:hidden;background:#000;box-shadow:0 20px 60px #0009}
.player-wrap video{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;background:#000}
.overlay{position:absolute;top:14px;left:14px;display:flex;gap:8px;align-items:center;pointer-events:none}
.live-tag{display:inline-flex;align-items:center;gap:7px;padding:4px 10px;border-radius:6px;background:#e91916;color:#fff;font-size:12px;font-weight:800;letter-spacing:.4px;text-transform:uppercase}
.live-dot{width:8px;height:8px;border-radius:50%;background:#fff;animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.watch-title{margin:16px 0 6px;font-size:clamp(19px,1.6vw,23px);font-weight:750;letter-spacing:-.4px;color:#f4f4f7}
#status{font-size:13px;color:#a9aab6;min-height:1.4em}
#status.connected{color:#8ce1b0}#status.buffering{color:#f5c26b}#status.error{color:#ff9d8f}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 4px}
.controls button,.controls a{display:inline-flex;align-items:center;gap:8px;min-height:40px;padding:9px 16px;border-radius:999px;border:0;background:#ffffff14;color:#f4f4f7;font:inherit;font-size:13px;font-weight:650;cursor:pointer;text-decoration:none}
.controls button:hover,.controls a:hover{background:#ffffff24}
.controls .btn-primary{background:#ff875f;color:#1b100c}
.controls .btn-primary:hover{background:#ffa07c}
.stats-box{margin-top:16px;padding:14px 16px;border-radius:12px;background:#ffffff0d}
.stats-box h2{font-size:12px;font-weight:650;color:#a9aab6;margin-bottom:8px}
.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px 18px}
.stats span{display:flex;flex-direction:column;gap:2px;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#8f909c}
.stats .val{font-size:14px;font-weight:650;letter-spacing:0;text-transform:none;color:#f4f4f7;font-variant-numeric:tabular-nums}
:focus-visible{outline:2px solid #ffac8c;outline-offset:3px}
@media(max-width:760px){body{padding-top:120px!important}.watch{padding:0 0 40px}.player-wrap{border-radius:0;max-height:none}.watch-info{padding:0 16px}.controls>*{flex:1 1 140px;justify-content:center}}
@media(prefers-reduced-motion:reduce){.live-dot{animation:none}}
`;

module.exports = function getLivePlayerHTML() {
  return navbar.getHead('Emisión local — eSE', LOCAL_CSS) + navbar.getHTML('live') + `
<script src="/live/vendor/hls.min.js"><\/script>
<main class="watch">
  <div class="player-wrap">
    <video id="video" controls autoplay muted playsinline></video>
    <div class="overlay"><span class="live-tag"><span class="live-dot" aria-hidden="true"></span>En directo</span></div>
  </div>
  <div class="watch-info">
    <h1 class="watch-title">Emisión local</h1>
    <div id="status" role="status">Conectando con la emisión...</div>
    <div class="controls">
      <button class="btn-primary" id="muteBtn" onclick="toggleMute()">🔇 Activar sonido</button>
      <button onclick="location.reload()">Reconectar</button>
      <button onclick="document.getElementById('video').requestFullscreen()">Pantalla completa</button>
      <a href="/live">Todos los directos</a>
    </div>
    <div class="stats-box">
      <h2>Estadísticas de la emisión</h2>
      <div class="stats">
        <span>Bitrate <span class="val" id="bitrate">—</span></span>
        <span>Búfer <span class="val" id="buffer">—</span></span>
        <span>Segmento <span class="val" id="segments">—</span></span>
        <span>Latencia <span class="val" id="latency">—</span></span>
      </div>
    </div>
  </div>
</main>
<script>
  const video = document.getElementById('video');
  const statusEl = document.getElementById('status');

  function toggleMute() {
    video.muted = !video.muted;
    document.getElementById('muteBtn').textContent = video.muted ? '\\ud83d\\udd07 Activar sonido' : '\\ud83d\\udd0a Silenciar';
  }

  function updateStats() {
    if (!window.hls) return;
    const level = window.hls.levels[window.hls.currentLevel];
    if (level) document.getElementById('bitrate').textContent = (level.bitrate/1000).toFixed(0) + ' kbps';
    if (video.buffered.length > 0) {
      const buf = video.buffered.end(video.buffered.length-1) - video.currentTime;
      document.getElementById('buffer').textContent = buf.toFixed(1) + 's';
    }
    const lat = window.hls.latency;
    if (lat !== undefined) document.getElementById('latency').textContent = lat.toFixed(1) + 's';
    try {
      document.getElementById('segments').textContent = window.hls.streamController.fragPlaying ? window.hls.streamController.fragPlaying.sn : '\\u2014';
    } catch(e) {}
  }

  if (window.Hls && Hls.isSupported()) {
    // Sprint 2 E.2 — Auto-reconnect with exponential backoff (no full page reload),
    // rewritten 2026-06. The old version created the player as a \`const hls\` and
    // the reconnect timer did \`hls = newHls\` → TypeError: Assignment to constant
    // variable. Worse, the new instance's ERROR handler was copied from the
    // already-destroyed emitter (always a no-op), so the FIRST reconnect attempt
    // that hit another 404 left the player dead forever. That is exactly the
    // pasted-link case: the page opens before the viewer has written
    // stream.m3u8 (needs 2 contiguous segments), the initial load 404s, and the
    // broken reconnect never recovered. Now a single startPlayer() wires the
    // full pipeline every time, so retry #N is identical to the first load.
    var hls = null;
    var __reconnectTry = 0;
    var __reconnectTimer = null;
    // Audio-distortion fix (2026-06): consecutive fatal mediaErrors within a
    // short window mean recoverMediaError() alone isn't sticking. Per hls.js
    // docs the 2nd strike needs swapAudioCodec() (AAC/HE-AAC mis-signal —
    // without it audio resumes at the wrong sample rate: the deep/slow
    // audio heard after stalls); the 3rd strike rebuilds the pipeline.
    var __mediaErrAt = 0;
    var __mediaErrRun = 0;
    var HLS_CONFIG = {
      liveSyncDurationCount: 3,
      liveMaxLatencyDurationCount: 6,
      liveDurationInfinity: true,
      enableWorker: true,
      lowLatencyMode: false,
      maxBufferLength: 30,
      maxMaxBufferLength: 60,
      maxBufferHole: 2,
      backBufferLength: 0,
      manifestLoadingMaxRetry: 50,
      levelLoadingMaxRetry: 50,
      fragLoadingMaxRetry: 50,
    };

    function __scheduleReconnect(reason) {
      if (__reconnectTimer) return;
      var delay = Math.min(16000, 1000 * Math.pow(2, __reconnectTry));
      __reconnectTry++;
      statusEl.textContent = '\\ud83d\\udd34 ' + reason + ' \\u2014 reintentando en ' + (delay/1000) + 's (#' + __reconnectTry + ')';
      statusEl.className = 'error';
      __reconnectTimer = setTimeout(function(){
        __reconnectTimer = null;
        try { if (hls) hls.destroy(); } catch(e) {}
        startPlayer();
      }, delay);
    }

    function startPlayer() {
      hls = new Hls(HLS_CONFIG);
      window.hls = hls;
      hls.on(Hls.Events.MANIFEST_PARSED, function(){
        statusEl.textContent = '\\ud83d\\udfe2 Recibiendo la emisión...';
        statusEl.className = 'connected';
        // Force seek to live edge
        if (hls.liveSyncPosition) {
          video.currentTime = hls.liveSyncPosition;
        }
        video.play().catch(function(){});
        __reconnectTry = 0;  // reset backoff on success
      });
      hls.on(Hls.Events.ERROR, function(e, data){
        if (data && data.fatal) {
          if (data.type === 'mediaError') {
            var nowMs = Date.now();
            __mediaErrRun = (nowMs - __mediaErrAt < 6000) ? __mediaErrRun + 1 : 1;
            __mediaErrAt = nowMs;
            if (__mediaErrRun >= 3) {
              __mediaErrRun = 0;
              __scheduleReconnect('mediaError');
              return;
            }
            if (__mediaErrRun === 2) {
              try { hls.swapAudioCodec(); } catch(err) {}
            }
            statusEl.textContent = '\\ud83d\\udfe1 Recuperando la reproducción...';
            try { hls.recoverMediaError(); } catch(err) { __scheduleReconnect('mediaError'); }
          } else {
            __scheduleReconnect(data.type || 'fatal error');
          }
        }
      });
      hls.on(Hls.Events.FRAG_BUFFERED, updateStats);
      hls.loadSource('/hls/stream.m3u8');
      hls.attachMedia(video);
    }

    startPlayer();

    // Ghost-viewer fix (2026-06): tell eMule we left when the page goes away.
    // sendBeacon survives unload; Node's /api/live/leave relays to eMule.
    // The 60 s player-idle watchdog covers killed tabs where this never fires.
    addEventListener('pagehide', function(){
      try {
        if (!navigator.sendBeacon || !navigator.sendBeacon('/api/live/leave'))
          fetch('/api/live/leave', {keepalive:true}).catch(function(){});
      } catch(_) {}
    });

    // Auto-catchup: if too far from live edge, re-seek
    setInterval(function(){
      if (hls && hls.liveSyncPosition && video.currentTime > 0) {
        var drift = hls.liveSyncPosition - video.currentTime;
        if (drift > 30) {
          video.currentTime = hls.liveSyncPosition;
          statusEl.textContent = '\\ud83d\\udfe2 Reproducción sincronizada';
        }
      }
      updateStats();
    }, 2000);
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = '/hls/stream.m3u8';
    statusEl.textContent = 'Reproduciendo emisión';
    statusEl.className = 'connected';
  } else {
    statusEl.textContent = 'El reproductor no está disponible';
    statusEl.className = 'error';
  }
<\/script>
</body>
</html>`;
};
