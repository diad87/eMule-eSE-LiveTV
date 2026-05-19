// filepath: srchybrid/eSE/live_player_html.js
// eSE Live Player HTML — exported as a function for use by server.js
module.exports = function getLivePlayerHTML() {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>eSE Live — P2P Stream</title>
<script src="/vendor/hls.min.js"><\/script>
<style>
  /* v8.0.1: Inter from fonts.googleapis.com dropped (third-party CDN). */
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    background:#0a0a0f;
    color:#e0e0e0;
    min-height:100vh;
    display:flex; flex-direction:column;
    align-items:center; justify-content:center;
  }
  .container { width:min(960px,95vw); }
  .header {
    display:flex; align-items:center; gap:12px;
    padding:16px 0; margin-bottom:8px;
  }
  .header .dot {
    width:14px; height:14px; border-radius:50%;
    background:#ff3b3b;
    box-shadow: 0 0 8px #ff3b3b88, 0 0 20px #ff3b3b44;
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { opacity:1; transform:scale(1); }
    50% { opacity:.6; transform:scale(.85); }
  }
  .header h1 { font-size:1.3rem; font-weight:700; color:#fff; }
  .header .badge {
    background:linear-gradient(135deg,#ff3b3b,#ff6b3b);
    color:#fff; font-size:.7rem; font-weight:700;
    padding:3px 10px; border-radius:20px;
    text-transform:uppercase; letter-spacing:1px;
  }
  .player-wrap {
    position:relative; width:100%;
    border-radius:12px; overflow:hidden;
    background:#000;
    box-shadow: 0 4px 40px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.05);
  }
  video { width:100%; display:block; background:#000; }
  .overlay {
    position:absolute; top:12px; left:12px;
    display:flex; gap:8px; align-items:center;
    pointer-events:none;
  }
  .overlay .live-tag {
    background:rgba(255,59,59,.9);
    color:#fff; font-size:.65rem; font-weight:700;
    padding:3px 8px; border-radius:4px;
    text-transform:uppercase; letter-spacing:1px;
    backdrop-filter:blur(4px);
  }
  .stats {
    display:flex; gap:20px; padding:16px 0;
    font-size:.85rem; color:#888;
    flex-wrap:wrap;
  }
  .stats span { display:flex; align-items:center; gap:4px; }
  .stats .val { color:#fff; font-weight:600; }
  .controls { display:flex; gap:10px; padding:8px 0 24px; flex-wrap:wrap; }
  .controls button {
    padding:8px 18px; border:none; border-radius:8px;
    font-family:inherit; font-size:.8rem; font-weight:600;
    cursor:pointer; transition:all .2s;
  }
  .btn-primary {
    background:linear-gradient(135deg,#6366f1,#8b5cf6);
    color:#fff;
  }
  .btn-primary:hover { transform:translateY(-1px); box-shadow:0 4px 16px #6366f166; }
  .btn-secondary {
    background:rgba(255,255,255,.06);
    color:#ccc; border:1px solid rgba(255,255,255,.1) !important;
  }
  .btn-secondary:hover { background:rgba(255,255,255,.1); color:#fff; }
  #status { font-size:.75rem; color:#666; padding:4px 0; transition:color .3s; }
  #status.connected { color:#22c55e; }
  #status.buffering { color:#f59e0b; }
  #status.error { color:#ef4444; }
  .no-stream {
    text-align:center; padding:80px 20px;
    color:#555; font-size:.95rem;
  }
  .no-stream h2 { color:#888; margin-bottom:12px; font-size:1.2rem; }
  .back-link {
    display:inline-block; margin-top:16px;
    color:#6366f1; text-decoration:none; font-weight:600;
  }
  .back-link:hover { text-decoration:underline; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="dot"></div>
    <h1>eSE Live Stream</h1>
    <span class="badge">P2P Broadcast</span>
  </div>
  <div class="player-wrap">
    <video id="video" controls autoplay muted></video>
    <div class="overlay">
      <span class="live-tag">\u25cf LIVE</span>
    </div>
  </div>
  <div class="stats">
    <span>\ud83d\udcca Bitrate: <span class="val" id="bitrate">\u2014</span></span>
    <span>\ud83c\udfac Buffer: <span class="val" id="buffer">\u2014</span></span>
    <span>\ud83d\udce6 Segments: <span class="val" id="segments">\u2014</span></span>
    <span>\u23f1\ufe0f Latency: <span class="val" id="latency">\u2014</span></span>
  </div>
  <div class="controls">
    <button class="btn-primary" id="muteBtn" onclick="toggleMute()">\ud83d\udd07 Unmute</button>
    <button class="btn-secondary" onclick="location.reload()">\ud83d\udd04 Reconnect</button>
    <button class="btn-secondary" onclick="document.getElementById('video').requestFullscreen()">\u26f6 Fullscreen</button>
    <a href="/" class="btn-secondary" style="text-decoration:none;display:inline-block">\u2190 Back to eSE</a>
  </div>
  <div id="status">Connecting...</div>
</div>
<script>
  const video = document.getElementById('video');
  const statusEl = document.getElementById('status');

  function toggleMute() {
    video.muted = !video.muted;
    document.getElementById('muteBtn').textContent = video.muted ? '\\ud83d\\udd07 Unmute' : '\\ud83d\\udd0a Muted';
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

  if (Hls.isSupported()) {
    const hls = new Hls({
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
    });
    window.hls = hls;
    hls.loadSource('/hls/stream.m3u8');
    hls.attachMedia(video);
    hls.on(Hls.Events.MANIFEST_PARSED, () => {
      statusEl.textContent = '\\ud83d\\udfe2 Connected \\u2014 Jumping to live...';
      statusEl.className = 'connected';
      // Force seek to live edge
      if (hls.liveSyncPosition) {
        video.currentTime = hls.liveSyncPosition;
      }
      video.play().catch(()=>{});
    });
    // Sprint 2 E.2 — Auto-reconnect with exponential backoff (no full page reload).
    // Previously a single fatal error reloaded the page (lost player state, scroll
    // position, video element, every wizard input). Now we rebuild ONLY the hls.js
    // pipeline with capped exponential backoff (1s → 2s → 4s → 8s → 16s, then 16s).
    var __reconnectTry = 0;
    var __reconnectTimer = null;
    function __scheduleReconnect(reason) {
      if (__reconnectTimer) return;
      var delay = Math.min(16000, 1000 * Math.pow(2, __reconnectTry));
      __reconnectTry++;
      statusEl.textContent = '\\ud83d\\udd34 ' + reason + ' \\u2014 reintentando en ' + (delay/1000) + 's (#' + __reconnectTry + ')';
      statusEl.className = 'error';
      __reconnectTimer = setTimeout(function(){
        __reconnectTimer = null;
        try { hls.destroy(); } catch(e) {}
        // Re-create with same config (HLS_CONFIG is the object literal above, captured)
        // Simpler: just re-loadSource on a brand new instance.
        var newHls = new Hls({
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
        });
        window.hls = newHls;
        // Re-attach the same event handlers
        newHls.on(Hls.Events.MANIFEST_PARSED, function(){
          statusEl.textContent = '\\ud83d\\udfe2 Reconnected — jumping to live...';
          statusEl.className = 'connected';
          if (newHls.liveSyncPosition) video.currentTime = newHls.liveSyncPosition;
          video.play().catch(function(){});
          __reconnectTry = 0;  // reset backoff on success
        });
        newHls.on(Hls.Events.ERROR, hls.listeners(Hls.Events.ERROR)[0] || function(){});
        newHls.loadSource('/hls/stream.m3u8');
        newHls.attachMedia(video);
        hls = newHls;
      }, delay);
    }
    hls.on(Hls.Events.ERROR, (e, data) => {
      if (data.fatal) {
        if (data.type === 'mediaError') {
          statusEl.textContent = '\\ud83d\\udfe1 Recovering media error...';
          try { hls.recoverMediaError(); } catch(err) { __scheduleReconnect('mediaError'); }
        } else {
          __scheduleReconnect(data.type || 'fatal error');
        }
      }
    });
    hls.on(Hls.Events.FRAG_BUFFERED, updateStats);
    // Auto-catchup: if too far from live edge, re-seek
    setInterval(() => {
      if (hls.liveSyncPosition && video.currentTime > 0) {
        const drift = hls.liveSyncPosition - video.currentTime;
        if (drift > 30) {
          video.currentTime = hls.liveSyncPosition;
          statusEl.textContent = '\\ud83d\\udfe2 Re-synced to live edge';
        }
      }
      updateStats();
    }, 2000);
  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
    video.src = '/hls/stream.m3u8';
    statusEl.textContent = 'Native HLS playback';
    statusEl.className = 'connected';
  }
<\/script>
</body>
</html>`;
};
