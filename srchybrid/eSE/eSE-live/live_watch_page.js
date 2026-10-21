/**
 * eSE Live — watch page for an eMule broadcast (/live/watch/{hash}).
 * YouTube/Twitch layout: player, channel info and a "more live" sidebar.
 * Rendering never joins: the viewer starts the P2P join with the play button.
 */
'use strict';

const navbar = require('../shared/navbar');
const directory = require('./live_tv_directory');

const ICONS = {
  play: '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><polygon points="7 4 20 12 7 20 7 4"/></svg>',
  pause: '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>',
  volume: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" fill="currentColor"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><path d="M19 5a10 10 0 0 1 0 14"/></svg>',
  muted: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5" fill="currentColor"/><path d="M22 9l-6 6"/><path d="M16 9l6 6"/></svg>',
  theater: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2" y="6" width="20" height="12" rx="2"/></svg>',
  fullscreen: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M16 3h3a2 2 0 0 1 2 2v3"/><path d="M8 21H5a2 2 0 0 1-2-2v-3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/></svg>',
  share: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>'
};

const CSS = `
body{padding-top:76px;background:#0a0a0f}
.watch{display:grid;grid-template-columns:minmax(0,1fr) 380px;grid-template-areas:"player side" "info side";grid-template-rows:auto 1fr;gap:20px 28px;max-width:1880px;margin:0 auto;padding:24px var(--ese-page-padding,40px) 56px}
.watch.is-theater{grid-template-areas:"player player" "info side"}
.watch-player{grid-area:player;min-width:0}
.watch-info{grid-area:info;min-width:0}
.watch-side{grid-area:side;min-width:0}

/* Player */
.cinema{position:relative;aspect-ratio:16/9;width:100%;max-height:calc(100vh - 150px);margin:0 auto;background:#000;border-radius:14px;overflow:hidden;box-shadow:0 20px 60px #0009}
.watch.is-theater .cinema{max-height:calc(100vh - 120px)}
.cinema:fullscreen{max-height:none;border-radius:0;aspect-ratio:auto}
.cinema[data-cat]{background:radial-gradient(130% 130% at 0% 0%,hsl(var(--cat-hue,225) 55% 34%),#08080c 72%)}
.cinema[data-cat="sports"]{--cat-hue:140}.cinema[data-cat="gaming"]{--cat-hue:265}.cinema[data-cat="movies"]{--cat-hue:12}.cinema[data-cat="music"]{--cat-hue:320}.cinema[data-cat="education"]{--cat-hue:200}.cinema[data-cat="talk"]{--cat-hue:40}.cinema[data-cat="24/7"]{--cat-hue:180}
.cinema[data-cat] .join-overlay:not(.hidden) ~ video{background:transparent}
.cinema video{position:absolute;inset:0;width:100%;height:100%;object-fit:contain;background:#000;cursor:pointer}
.controls{position:absolute;bottom:0;left:0;right:0;z-index:12;padding:28px 12px 10px;background:linear-gradient(transparent,rgba(0,0,0,.85));opacity:0;transition:opacity .25s}
.cinema:hover .controls,.cinema:focus-within .controls{opacity:1}
.ctrl-row{display:flex;align-items:center;gap:4px}
.ctrl-btn{display:inline-flex;align-items:center;justify-content:center;min-width:44px;min-height:44px;padding:0;background:none;border:0;border-radius:8px;color:#fff;cursor:pointer;opacity:.9}
.ctrl-btn:hover{opacity:1;background:#ffffff1a}
.ctrl-btn[aria-pressed="true"]{color:#ffac8c}
.vol-range{width:84px;height:4px;cursor:pointer;accent-color:#ff875f}
.ctrl-live{display:inline-flex;align-items:center;gap:7px;margin-left:10px;padding:4px 10px;border-radius:6px;background:#e91916;color:#fff;font-size:12px;font-weight:800;letter-spacing:.4px;text-transform:uppercase}
.time{margin-left:10px;color:#ffffffcc;font-size:13px;font-variant-numeric:tabular-nums}
.audio-sel{background:#1a1b24;color:#fff;border:1px solid #ffffff33;border-radius:8px;padding:6px 10px;font-size:13px;cursor:pointer;font-family:inherit;min-height:36px;margin-right:4px}
.spacer{flex:1}

/* Join overlay: poster + big play button, then honest connection progress */
.join-overlay{position:absolute;inset:0;z-index:20;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;padding:24px;text-align:center;background:radial-gradient(ellipse at center,rgba(10,10,15,.3) 0%,rgba(10,10,15,.82) 80%);transition:opacity .45s;pointer-events:none}
.join-overlay.hidden{opacity:0}
.join-overlay .join-start{pointer-events:auto}
.join-spinner{width:46px;height:46px;border:3px solid #ff875f33;border-top-color:#ff875f;border-radius:50%;animation:spin 1s linear infinite;margin-bottom:10px}
.join-spinner[hidden]{display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.join-state{color:#fff;font-size:clamp(16px,1.6vw,20px);font-weight:750}
.join-detail{max-width:440px;color:#ffffffa6;font-size:13px;line-height:1.55}
.join-start{display:inline-flex;align-items:center;gap:10px;margin:14px 0 4px;min-height:52px;padding:14px 28px;border:0;border-radius:999px;background:#ff875f;color:#1b100c;font:800 16px/1 Inter,system-ui,sans-serif;cursor:pointer;box-shadow:0 14px 40px #ff875f40;transition:transform .15s,background .15s}
.join-start:hover{background:#ffa07c;transform:scale(1.03)}
.join-start:disabled{opacity:.6;cursor:wait;transform:none}
.join-start[hidden]{display:none}
.join-peers{display:flex;gap:22px;margin-top:10px}
.join-overlay[data-state="IDLE"] .join-peers{display:none}
.join-stat{text-align:center}
.join-stat-val{color:#ffac8c;font-size:20px;font-weight:800;font-variant-numeric:tabular-nums}
.join-stat-label{color:#ffffff73;font-size:10px;text-transform:uppercase;letter-spacing:1px}
.join-retry{color:#ffac8c;font-size:12px;opacity:0;transition:opacity .3s}

/* Channel info */
.watch-title{margin:16px 0 12px;font-size:clamp(19px,1.6vw,23px);font-weight:750;letter-spacing:-.4px;line-height:1.3;color:#f4f4f7;overflow-wrap:anywhere}
.watch-bar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.watch-channel{display:flex;align-items:center;gap:12px;min-width:0}
.watch-channel .ch-avatar{flex-basis:44px;width:44px;height:44px;font-size:18px}
.watch-handle{display:block;font-size:15px;font-weight:700;color:#f4f4f7}
.watch-sub{display:flex;align-items:center;gap:7px;font-size:13px;color:#a9aab6;margin-top:2px}
.watch-actions{display:flex;gap:8px;flex-wrap:wrap}
.watch-action{display:inline-flex;align-items:center;gap:8px;min-height:40px;padding:9px 16px;border-radius:999px;border:0;background:#ffffff14;color:#f4f4f7;font:inherit;font-size:13px;font-weight:650;cursor:pointer;text-decoration:none}
.watch-action:hover{background:#ffffff24}
.watch-action[aria-pressed="true"]{background:#f4f4f7;color:#121218}
.watch-action[hidden]{display:none}
.watch-desc{margin-top:16px;padding:14px 16px;border-radius:12px;background:#ffffff0d}
.watch-facts{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:13px;font-weight:650;color:#e6e6ee}
.watch-facts span+span::before{content:"\\00b7";margin-right:14px;color:#77788a}
.watch-note{margin-top:8px;font-size:13px;line-height:1.6;color:#b9bac6}
.watch-nerd{margin-top:10px}
.watch-nerd summary{cursor:pointer;min-height:36px;display:list-item;align-content:center;font-size:12px;font-weight:650;color:#a9aab6}
.watch-nerd dl{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px 18px;padding:8px 0 4px}
.watch-nerd dt{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#8f909c}
.watch-nerd dd{font-size:14px;font-weight:650;color:#f4f4f7;font-variant-numeric:tabular-nums}
.share-status{font-size:12px;color:#8ce1b0;min-height:1em}

/* Sidebar */
.side-title{font-size:16px;font-weight:750;color:#f4f4f7;margin-bottom:12px}
.side-list{display:flex;flex-direction:column;gap:10px}
.side-item{display:grid;grid-template-columns:168px minmax(0,1fr);gap:10px;color:inherit;text-decoration:none;border-radius:10px;padding:4px}
.side-item:hover{background:#ffffff0a}
.side-item .ch-thumb{border-radius:8px}
.side-item .ch-thumb-fallback{font-size:15px}
.side-item:hover .ch-thumb{transform:none;box-shadow:none}
.side-item .ch-live-badge{top:6px;left:6px;font-size:9px;padding:2px 5px}
.side-item .ch-viewers{left:6px;bottom:6px;font-size:10px;padding:2px 6px}
.side-text{display:flex;flex-direction:column;gap:3px;min-width:0;padding-top:2px}
.side-name{font-size:14px;font-weight:650;line-height:1.35;color:#f4f4f7;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.side-item:hover .side-name{color:#ffac8c}
.side-meta{font-size:12px;color:#a9aab6}
.side-empty{padding:18px;border:1px dashed #ffffff21;border-radius:12px;color:#a9aab6;font-size:13px;line-height:1.6}
.side-empty a{color:#ffac8c}
.side-all{display:inline-flex;margin-top:14px;font-size:13px;font-weight:650;color:#ffac8c;text-decoration:none;min-height:40px;align-items:center}

:focus-visible{outline:2px solid #ffac8c;outline-offset:3px}
@media(max-width:1100px){
  .watch,.watch.is-theater{grid-template-columns:minmax(0,1fr);grid-template-areas:"player" "info" "side"}
  .side-item{grid-template-columns:200px minmax(0,1fr)}
}
@media(max-width:760px){
  body{padding-top:120px!important}
  .watch{padding:0 0 40px;gap:14px}
  .cinema{border-radius:0;max-height:none}
  .watch-info,.watch-side{padding:0 16px}
  .watch-title{margin-top:4px}
  .vol-range{display:none}
  .side-item{grid-template-columns:150px minmax(0,1fr)}
}
@media(hover:none),(pointer:coarse){.controls{opacity:1}}
@media(prefers-reduced-motion:reduce){.join-spinner,.ch-live-dot{animation:none}.controls,.join-start{transition:none}}
`;

function render(hash) {
  if (!/^[a-fA-F0-9]{32}$/.test(String(hash || ''))) throw new Error('invalid_stream_key');
  // Serve HLS straight from local disk (eMule's viewer writer drops .ts +
  // stream.m3u8 into %TEMP%\eMule_RTMP\<HASH>\ as chunks arrive). This
  // avoids the broken eMule WebServer hls-proxy on PC2.
  const hlsBase = '/hls-local/' + hash.toLowerCase();
  const head = navbar.getHead('En directo \u2014 eSE', directory.getCSS() + CSS);
  return head + navbar.getHTML('live') + `
<script src="/live/vendor/hls.min.js"></script>
<main class="watch" id="watch">
<section class="watch-player" aria-label="Reproductor en directo">
<div class="cinema" id="cinema">
<!-- Phase 2 JOIN-3: Connection state overlay -->
<div class="join-overlay" id="join-overlay" data-state="IDLE">
<div class="join-spinner" id="join-spinner" hidden></div>
<div class="join-state" id="join-state" role="status">Emisión P2P en directo</div>
<div class="join-detail" id="join-detail">Al conectar, eSE recibe la emisión de otros espectadores de la red.</div>
<button class="join-start" type="button" id="join-start">${ICONS.play}Ver en directo</button>
<div class="join-peers">
<div class="join-stat"><div class="join-stat-val" id="jo-peers">0</div><div class="join-stat-label">Peers</div></div>
<div class="join-stat"><div class="join-stat-val" id="jo-chunks">0</div><div class="join-stat-label">Chunks</div></div>
<div class="join-stat"><div class="join-stat-val" id="jo-kad">—</div><div class="join-stat-label">Kad</div></div>
</div>
<div class="join-retry" id="join-retry"></div>
</div>
<video id="v" autoplay muted playsinline></video>
<div class="controls">
<div class="ctrl-row">
<button class="ctrl-btn" id="play-btn" aria-label="Reproducir" title="Reproducir (k)" onclick="togglePlay()">${ICONS.play}</button>
<button class="ctrl-btn" id="mute-btn" aria-label="Activar sonido" title="Sonido (m)" onclick="toggleMute()">${ICONS.muted}</button>
<input type="range" class="vol-range" id="vol" aria-label="Volumen" min="0" max="1" step="0.05" value="1" oninput="v.volume=this.value">
<span class="ctrl-live"><span class="ch-live-dot" aria-hidden="true"></span>En directo</span>
<span class="time" id="time">0:00</span>
<span class="spacer"></span>
<select class="audio-sel" id="audioSel" aria-label="Pista de audio" style="display:none"></select>
<button class="ctrl-btn" id="theater-btn" aria-label="Modo cine" aria-pressed="false" title="Modo cine (t)" onclick="toggleTheater()">${ICONS.theater}</button>
<button class="ctrl-btn" aria-label="Pantalla completa" title="Pantalla completa (f)" onclick="toggleFS()">${ICONS.fullscreen}</button>
</div>
</div>
</div>
</section>
<section class="watch-info" aria-labelledby="ch-title">
<h1 class="watch-title" id="ch-title">Cargando emisión…</h1>
<div class="watch-bar">
<div class="watch-channel"><span id="ch-avatar">${directory.channelAvatar({ streamKey: hash, title: 'eSE' })}</span><div><span class="watch-handle" id="ch-handle">Canal ${hash.slice(0, 6).toUpperCase()}</span><span class="watch-sub"><span class="ch-live-dot" aria-hidden="true"></span><span id="ch-viewers">En directo</span></span></div></div>
<div class="watch-actions">
<button type="button" class="watch-action" id="share-btn">${ICONS.share}Copiar enlace</button>
<button type="button" class="watch-action" id="theater-action" aria-pressed="false" onclick="toggleTheater()">${ICONS.theater}Modo cine</button>
<a href="/live" class="watch-action">Todos los directos</a>
</div>
</div>
<p class="share-status" id="share-status" role="status"></p>
<div class="watch-desc">
<p class="watch-facts" id="ch-facts"><span>Emisión P2P</span></p>
<p class="watch-note">La emisión llega de otros espectadores de la red eSE, sin servidores. El enlace que copias es anónimo: no incluye tu IP.</p>
<details class="watch-nerd" id="watch-nerd">
<summary>Estadísticas de la conexión</summary>
<dl>
<div><dt>Peers</dt><dd id="st-peers">—</dd></div>
<div><dt>Chunks</dt><dd id="st-chunks">—</dd></div>
<div><dt>Kad</dt><dd id="st-kad">—</dd></div>
<div><dt>Búfer</dt><dd id="st-buffer">—</dd></div>
<div><dt>Resolución</dt><dd id="st-res">—</dd></div>
</dl>
</details>
</div>
</section>
<aside class="watch-side" aria-labelledby="side-title">
<h2 class="side-title" id="side-title">Más en directo</h2>
<div class="side-list" id="side-list"><p class="side-empty">Buscando otros canales…</p></div>
<a href="/live" class="side-all">Ver todos los canales &rarr;</a>
</aside>
</main>
<script>
const v=document.getElementById('v');
const src='${hlsBase}/stream.m3u8';
const streamHash='${hash}';
const langNames={eng:'English',spa:'Spanish',fre:'French',ger:'German',ita:'Italian',por:'Portuguese',jpn:'Japanese',kor:'Korean',chi:'Chinese',rus:'Russian',ara:'Arabic',und:'Track'};
const langFlags={eng:'[EN]',spa:'[ES]',fre:'[FR]',ger:'[DE]',ita:'[IT]',por:'[PT]',jpn:'[JP]',rus:'[RU]',kor:'[KR]',chi:'[CN]',ara:'[AR]',und:''};
const ICON_PLAY='${ICONS.play}';
const ICON_PAUSE='${ICONS.pause}';
const ICON_VOLUME='${ICONS.volume}';
const ICON_MUTED='${ICONS.muted}';

// === Phase 2 JOIN-3: State machine ===
const JOIN_STATES = {
  DISCOVERING: { text: 'Buscando la emisión en Kad…', detail: 'Consultando la red distribuida' },
  CONNECTING:  { text: 'Conectando con otros espectadores…', detail: 'Estableciendo conexión P2P' },
  BUFFERING:   { text: 'Recibiendo la emisión…', detail: 'Llenando el búfer de reproducción' },
  PLAYING:     { text: '', detail: '' },
  FAILED:      { text: 'No se pudo conectar', detail: 'El stream puede no estar disponible' }
};
let joinState = 'IDLE';
let joinStarted = false;
let joinPollId = null;
let activeHls = null;
let joinController = null;
let joinRetryCount = 0;
const JOIN_RETRY_INTERVAL = 15000;
const JOIN_MAX_RETRIES = 5;
let joinStartTime = 0;

function updateJoinOverlay(state, peers, chunks, kadStatus) {
  joinState = state;
  const ov = document.getElementById('join-overlay');
  ov.setAttribute('data-state', state);
  document.getElementById('join-spinner').hidden = state === 'FAILED' || state === 'PLAYING';
  const start = document.getElementById('join-start');
  start.hidden = state !== 'FAILED';
  if (state === 'FAILED') { start.disabled = false; start.textContent = 'Reintentar conexión'; }
  if (state === 'PLAYING') { ov.classList.add('hidden'); return; }
  ov.classList.remove('hidden');
  const s = JOIN_STATES[state] || JOIN_STATES.DISCOVERING;
  document.getElementById('join-state').textContent = s.text;
  document.getElementById('join-detail').textContent = s.detail;
  document.getElementById('jo-peers').textContent = peers || 0;
  document.getElementById('jo-chunks').textContent = chunks || 0;
  document.getElementById('jo-kad').textContent = kadStatus || '—';
  const retryEl = document.getElementById('join-retry');
  if (joinRetryCount > 0) {
    retryEl.textContent = 'Reintento ' + joinRetryCount + '/' + JOIN_MAX_RETRIES;
    retryEl.style.opacity = '1';
  }
}

// Phase 2 JOIN-3: Poll /api/live/debug for real P2P state
let lastDebugChunks = 0;

function pollJoinState() {
  if (!joinStarted || joinState === 'PLAYING' || joinState === 'FAILED') return;
  fetch('/api/live/debug').then(r => r.json()).then(d => {
    if (d.error) return; // C++ offline, skip update
    const peers = (d.peers ? (d.peers.viewPeers || 0) + (d.peers.broadcastPeers || 0) : 0);
    const chunks = d.chunks ? (d.chunks.count || 0) : (d.counters ? d.counters.chunksReceived || 0 : 0);
    const kadOk = d.discovery && d.discovery.kadConnected ? 'OK' : 'OFF';
    const hasHls = d.hls ? (d.hls.playlistRefreshes || 0) > 0 || (d.hls.segmentsWritten || 0) >= 3 : chunks >= 3;
    lastDebugChunks = chunks;

    if (chunks > 0 || hasHls) {
      updateJoinOverlay('BUFFERING', peers, chunks, kadOk);
    } else if (peers > 0) {
      updateJoinOverlay('CONNECTING', peers, chunks, kadOk);
    } else {
      updateJoinOverlay('DISCOVERING', peers, chunks, kadOk);
    }
  }).catch(() => {});
}

// Phase 2 JOIN-4: Retry join if no chunks after interval
// Routes through Node proxy /api/live/join -> C++ 4711/api/live/join
function checkJoinRetry() {
  if (!joinStarted || joinState === 'PLAYING' || joinState === 'FAILED') return;
  const elapsed = Date.now() - joinStartTime;
  if (joinRetryCount >= JOIN_MAX_RETRIES) {
    if (lastDebugChunks === 0 && elapsed > JOIN_RETRY_INTERVAL * (JOIN_MAX_RETRIES + 1)) {
      updateJoinOverlay('FAILED', 0, 0, 'OFF');
    }
    return;
  }
  if (elapsed > JOIN_RETRY_INTERVAL * (joinRetryCount + 1)) {
    joinRetryCount++;
    fetch('/api/live/join?key=' + encodeURIComponent(streamHash) + '&title=Live', { method: 'POST', headers: { 'X-Requested-With': 'eSE' } })
      .then(r => r.json())
      .then(d => { if (d.error) console.warn('[eSE Join] Retry failed:', d.error); })
      .catch(() => {});
    updateJoinOverlay(joinState);
  }
}

function startMedia() {
if(activeHls){activeHls.destroy();activeHls=null}
if(window.Hls&&Hls.isSupported()){
const h=new Hls({liveSyncDurationCount:3,liveMaxLatencyDurationCount:8,liveDurationInfinity:true,maxBufferLength:30,maxMaxBufferLength:60,maxBufferHole:2,manifestLoadingMaxRetry:50,levelLoadingMaxRetry:50,fragLoadingMaxRetry:50});
activeHls=h;
h.loadSource(src);h.attachMedia(v);
// Phase 3: Transition to PLAYING only on FRAG_BUFFERED (actual data), not MANIFEST_PARSED (existence)
h.on(Hls.Events.MANIFEST_PARSED,()=>{v.play();updateJoinOverlay('BUFFERING',0,0,'OK')});
h.on(Hls.Events.FRAG_BUFFERED,()=>{if(joinState!=='PLAYING'){updateJoinOverlay('PLAYING',0,0,'OK');clearInterval(joinPollId)}});
// Audio-distortion fix (2026-06): two-step recovery per hls.js docs — a second
// fatal mediaError right after a recoverMediaError() means the audio codec is
// mis-signalled (AAC vs HE-AAC); call swapAudioCodec() first or the audio is
// re-appended at the wrong sample rate (the deep/slow audio after stalls).
let mErrAt=0;
h.on(Hls.Events.ERROR,(e,d)=>{if(!d.fatal)return;if(d.type==='mediaError'){const n=Date.now();if(n-mErrAt<6000){h.swapAudioCodec()}mErrAt=n;h.recoverMediaError()}else{setTimeout(()=>{h.loadSource(src);h.attachMedia(v)},3000)}});
h.on(Hls.Events.AUDIO_TRACKS_UPDATED,()=>{
  const tracks=h.audioTrackController?h.audioTrackController.audioTracks:[];
  if(tracks.length<2)return;
  const sel=document.getElementById('audioSel');
  sel.style.display='';
  sel.innerHTML='';
  tracks.forEach((t,i)=>{
    const lang=t.lang||'und';
    const name=(langFlags[lang]||'')+' '+(langNames[lang]||lang);
    const selected=(i===(h.audioTrack>=0?h.audioTrack:0))?' selected':'';
    sel.innerHTML+='<option value="'+i+'"'+selected+'>'+name+'</option>';
  });
  sel.selectedIndex=h.audioTrack>=0?h.audioTrack:0;
  sel.onchange=()=>{h.audioTrack=parseInt(sel.value)};
});
}else if(v.canPlayType('application/vnd.apple.mpegurl')){v.src=src
}else{updateJoinOverlay('FAILED',0,0,'OFF');document.getElementById('join-detail').textContent='Reproductor HLS no disponible'}
}

document.getElementById('join-start').addEventListener('click', function() {
  const button = this;
  button.disabled = true;
  joinStarted = true; joinRetryCount = 0; lastDebugChunks = 0; joinStartTime = Date.now();
  clearInterval(joinPollId);
  if(joinController)joinController.abort();
  joinController = new AbortController();
  const controller = joinController;
  const timeout = setTimeout(() => controller.abort(), 10000);
  updateJoinOverlay('CONNECTING', 0, 0, '—');
  fetch('/api/live/join?key=' + encodeURIComponent(streamHash) + '&title=Live', {
    method: 'POST', headers: { 'X-Requested-With': 'eSE' }, signal: controller.signal
  }).then(r => { if(!r.ok)throw new Error(r.status === 401 ? 'Vincula este dispositivo desde el PC de eSE.' : 'No se pudo conectar al canal.');return r.json(); })
    .then(d => {
      if(controller !== joinController)return;
      if(!d || d.success === false || d.error)throw new Error('El canal no está disponible. Puedes reintentarlo.');
      clearTimeout(timeout);startMedia();
      joinPollId=setInterval(() => { pollJoinState(); checkJoinRetry(); },3000);
      pollJoinState();
    }).catch(error => {
      if(controller !== joinController)return;
      clearTimeout(timeout);joinStarted=false;
      updateJoinOverlay('FAILED',0,0,'—');
      document.getElementById('join-detail').textContent=error.name === 'AbortError' ? 'El servidor no respondió. Puedes reintentarlo.' : error.message;
    });
});

setInterval(()=>{const t=Math.floor(v.currentTime);const h=Math.floor(t/3600);const m=Math.floor((t%3600)/60);const s=t%60;document.getElementById('time').textContent=(h?h+':'+String(m).padStart(2,'0'):m)+':'+String(s).padStart(2,'0')},500);

function togglePlay(){if(!joinStarted){document.getElementById('join-start').focus();return}v.paused?v.play():v.pause()}
function syncPlay(){const b=document.getElementById('play-btn');b.innerHTML=v.paused?ICON_PLAY:ICON_PAUSE;b.setAttribute('aria-label',v.paused?'Reproducir':'Pausar')}
v.addEventListener('play',syncPlay);v.addEventListener('pause',syncPlay);
v.addEventListener('playing',()=>{if(joinStarted){updateJoinOverlay('PLAYING',0,0,'OK');clearInterval(joinPollId)}});
function toggleMute(){v.muted=!v.muted;const b=document.getElementById('mute-btn');b.setAttribute('aria-label',v.muted?'Activar sonido':'Silenciar');b.innerHTML=v.muted?ICON_MUTED:ICON_VOLUME}
function toggleFS(){document.fullscreenElement?document.exitFullscreen():document.getElementById('cinema').requestFullscreen()}
v.addEventListener('click',togglePlay);
v.addEventListener('dblclick',toggleFS);

// Ghost-viewer fix (2026-06): tell eMule we left when the page goes away
// (navigation, back button, tab close). sendBeacon survives page unload; the
// Node /api/live/leave route relays it to eMule. The 60 s player-idle
// watchdog in eMule is the backstop for killed tabs where this never fires.
addEventListener('pagehide',()=>{clearInterval(joinPollId);if(joinController){joinController.abort();joinController=null}if(activeHls){activeHls.destroy();activeHls=null}if(!joinStarted)return;try{const leave='/api/live/leave?key=${hash}';if(!navigator.sendBeacon||!navigator.sendBeacon(leave))fetch(leave,{method:'POST',keepalive:true}).catch(()=>{})}catch(_){}});
</script>
<script>
// Page chrome: channel info, "more live" sidebar, theater mode and shortcuts.
// Purely presentational; never joins or touches playback state.
${directory.clientSource()}
(function(){
  var $ = function(id) { return document.getElementById(id); };
  var current = null;
  function setText(id, text) { var el = $(id); if (el && el.textContent !== text) el.textContent = text; }
  function shareLink() {
    if (current && /^ed2k:\\/\\/\\|live\\|/.test(String(current.ed2kLink || ''))) return current.ed2kLink;
    return 'ed2k://|live|' + streamHash + '||' + encodeURIComponent((current && current.title) || 'Live') + '|/';
  }
  function renderSide(list) {
    var box = $('side-list');
    if (!box) return;
    var t = Math.floor(Date.now() / 20000);
    var html = list.map(function(ch) {
      var href = channelHref(ch.streamKey);
      if (!href) return '';
      return '<a class="side-item" href="' + href + '" aria-label="' + escH('Ver en directo: ' + (ch.title || 'Canal')) + '">' +
        '<span class="ch-thumb" data-cat="' + escClass(ch.category || 'general') + '"><span class="ch-thumb-fallback" aria-hidden="true">' + escH(categoryLabel(ch.category)) + '</span>' +
        '<img src="' + escH(channelThumb(ch, t)) + '" alt="" loading="lazy" onerror="this.remove()">' +
        '<span class="ch-live-badge">En directo</span><span class="ch-viewers"><span class="ch-live-dot" aria-hidden="true"></span>' + escH(formatViewers(ch.viewers)) + '</span></span>' +
        '<span class="side-text"><span class="side-name">' + escH(ch.title || 'Canal sin título') + '</span>' +
        '<span class="side-meta">' + escH(channelHandle(ch)) + '</span><span class="side-meta">' + escH(categoryLabel(ch.category)) + '</span></span></a>';
    }).join('');
    box.innerHTML = html || '<p class="side-empty">No hay otros canales en directo ahora mismo. <a href="/live">Volver al directorio</a></p>';
  }
  function paintChannel(ch) {
    current = ch;
    setText('ch-title', ch.title || 'Emisión en directo');
    setText('ch-handle', channelHandle(ch));
    setText('ch-viewers', formatViewers(ch.viewers) + ' · ' + formatUptime(ch.uptimeMinutes));
    var avatar = $('ch-avatar');
    if (avatar) avatar.innerHTML = channelAvatar(ch);
    var facts = $('ch-facts');
    if (facts) facts.innerHTML = [categoryLabel(ch.category), ch.language ? languageLabel(ch.language) : '', ch.qualityLabel || '', ch.experience ? 'Señal ' + String(ch.experience).toLowerCase() : '']
      .filter(Boolean).map(function(fact) { return '<span>' + escH(fact) + '</span>'; }).join('');
    if (v && !v.poster) v.poster = channelThumb(ch, Math.floor(Date.now() / 20000));
    var frame = $('cinema');
    if (frame && frame.setAttribute) frame.setAttribute('data-cat', escClass(ch.category || 'general'));
    if (ch.title) document.title = ch.title + ' \\u2014 eSE en directo';
  }
  function refresh() {
    return fetch('/api/live/channels').then(function(r) { return r.json(); }).then(function(d) {
      var list = (d && Array.isArray(d.channels) ? d.channels : []).filter(function(ch) { return ch && ch.streamKey; });
      var mine = list.filter(function(ch) { return String(ch.streamKey).toLowerCase() === streamHash.toLowerCase(); })[0];
      if (mine) paintChannel(mine);
      else if (!current) fetch('/api/live/emule-channels').then(function(r) { return r.json(); }).then(function(e) {
        var ch = ((e && e.channels) || []).filter(function(c) { return c && String(c.hash || '').toLowerCase() === streamHash.toLowerCase(); })[0];
        if (ch && !current) paintChannel({ streamKey: streamHash, title: ch.title });
      }).catch(function() {});
      renderSide(list.filter(function(ch) { return ch !== mine; }).slice(0, 12));
    }).catch(function() {});
  }
  refresh();
  setInterval(refresh, 15000);

  window.toggleTheater = function() {
    var page = $('watch');
    if (!page || !page.classList) return;
    var on = !page.classList.contains('is-theater');
    page.classList.toggle('is-theater', on);
    ['theater-btn', 'theater-action'].forEach(function(id) { var b = $(id); if (b) b.setAttribute('aria-pressed', String(on)); });
    try { localStorage.setItem('ese.liveTheater', on ? '1' : '0'); } catch (e) {}
  };
  try { if (localStorage.getItem('ese.liveTheater') === '1') window.toggleTheater(); } catch (e) {}

  var share = $('share-btn');
  if (share && share.addEventListener) share.addEventListener('click', function() {
    var link = shareLink();
    var done = function(ok) { setText('share-status', ok ? 'Enlace anónimo copiado. Pégalo en «Pegar enlace» de otro eSE.' : link); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(link).then(function() { done(true); }, function() { done(false); });
    else done(false);
  });

  // Connection stats, only while the panel is open.
  var nerd = $('watch-nerd');
  setInterval(function() {
    if (!nerd || !nerd.open) return;
    if (v && v.buffered && v.buffered.length) setText('st-buffer', Math.max(0, v.buffered.end(v.buffered.length - 1) - v.currentTime).toFixed(1) + ' s');
    if (v && v.videoWidth) setText('st-res', v.videoWidth + '×' + v.videoHeight);
    fetch('/api/live/debug').then(function(r) { return r.json(); }).then(function(d) {
      if (!d || d.error) return;
      setText('st-peers', String(d.peers ? (d.peers.viewPeers || 0) + (d.peers.broadcastPeers || 0) : 0));
      setText('st-chunks', String(d.chunks ? d.chunks.count || 0 : 0));
      setText('st-kad', d.discovery && d.discovery.kadConnected ? 'Conectado' : 'Sin conexión');
    }).catch(function() {});
  }, 2000);

  addEventListener('keydown', function(e) {
    var tag = e.target && e.target.tagName;
    if (e.ctrlKey || e.metaKey || e.altKey || tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
    var key = String(e.key || '').toLowerCase();
    if (key === 'f') toggleFS();
    else if (key === 'm') toggleMute();
    else if (key === 't') window.toggleTheater();
    else if (key === 'k' || (key === ' ' && tag !== 'BUTTON' && tag !== 'A')) { e.preventDefault(); togglePlay(); }
  });
})();
</script>
</body></html>`;
}

module.exports = { render };
