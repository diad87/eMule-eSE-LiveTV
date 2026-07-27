// Debug log first — hooks console.* so any startup log lines are captured.
const debugLog = require('./debug_log');
debugLog.install();
process.on('uncaughtException', err => { console.log('[Uncaught]', err); });
process.on('unhandledRejection', err => { console.log('[Unhandled]', err); });
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const APP_VERSION = require('./package.json').version;

// ━━━ REFACTORED MODULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const mediaResolver = require('./media_resolver');
const emuleApi = require('./emule_api');
const tmdbApi = require('./tmdb_api');
const utils = require('./utils');
const liveApi = require('./eSE-live/channel_api');
const thumbExtractor = require('./eSE-live/thumbnail_extractor');
const lanDiscovery = require('./eSE-live/lan_discovery');
const security = require('./security');

const requestedPort = Number.parseInt(process.env.ESE_PORT || '8080', 10);
const PORT = Number.isInteger(requestedPort) && requestedPort > 0 && requestedPort <= 65535
  ? requestedPort
  : 8080;
const TEST_MODE = process.env.ESE_TEST_MODE === '1';

// ━━━ AUTO-DETECT EMULE PATHS (portable across users/PCs) ━━━━━━━━━━━━━━━━━━━
function resolveEmulePaths() {
  const userProfile = process.env.USERPROFILE || process.env.HOME || 'C:\\Users\\Default';
  // Try to read custom paths from a local config override first
  const overrideFile = path.join(__dirname, 'emule_paths' + '.json');
  if (fs.existsSync(overrideFile)) {
    try {
      const ov = JSON.parse(fs.readFileSync(overrideFile, 'utf8'));
      if (ov.temp && ov.incoming) {
        console.log('[config] Using custom eMule paths from emule_paths.json');
        return { temp: ov.temp, incoming: ov.incoming };
      }
    } catch(e) {}
  }
  // Default: standard eMule folder under current user's Downloads
  const base = path.join(userProfile, 'Downloads', 'eMule');
  return {
    temp:     path.join(base, 'Temp'),
    incoming: path.join(base, 'Incoming')
  };
}

const { temp: EMULE_TEMP, incoming: EMULE_INCOMING } = resolveEmulePaths();
console.log('[config] EMULE_TEMP:    ', EMULE_TEMP);
console.log('[config] EMULE_INCOMING:', EMULE_INCOMING);

const FFMPEG_PATH = utils.findFfmpeg();
const TEMP_DIR = process.env.TEMP || process.env.TMP || require('os').tmpdir();
if (!TEST_MODE) {
  thumbExtractor.start(FFMPEG_PATH);
  // P2P stream discovery only: this advertises the native eMule peer port,
  // never the loopback-only dashboard/API port.
  lanDiscovery.start();
}

// Auto-detect hardware encoder at startup
const hwEncoderMod = require('./hw_encoder');
if (!TEST_MODE) hwEncoderMod.detect(FFMPEG_PATH, TEMP_DIR);
let HW_ENCODER      = hwEncoderMod.HW_ENCODER;
let HW_ENCODER_OPTS = hwEncoderMod.HW_ENCODER_OPTS;

const CACHE_DIR    = path.join(EMULE_INCOMING, 'film_cache');
const SETTINGS_FILE = path.join(CACHE_DIR, 'settings.json');


// Ensure cache dir exists
try { if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true }); } catch(e) {}

// ━━━ MODULE WRAPPERS (only wrappers used by routes/pages ctx) ━━━━━━━━━━━━━
function resolveMediaFile(fileName) { return mediaResolver.resolveMediaFile(fileName, EMULE_INCOMING, EMULE_TEMP); }
function getDownloads() { return mediaResolver.listDownloads(EMULE_TEMP); }

function loadSettings() { return utils.loadSettings(SETTINGS_FILE); }
function saveSettings(s) { return utils.saveSettings(s, SETTINGS_FILE); }
function getDuration(file) { return utils.getDuration(file, FFMPEG_PATH); }
function escapeHtml(s) { return utils.escapeHtml(s); }
function cleanTitle(f) { return utils.cleanTitle(f); }

// ━━━ eMule & TMDB Wrappers ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
emuleApi.setSettingsFunctions(loadSettings, saveSettings);

// Session/password proxies (getters so they always reflect module state)
Object.defineProperty(global, 'emuleSession', { get: () => emuleApi.getSession() });
Object.defineProperty(global, 'emulePassword', { get: () => emuleApi.getPassword() });
const OMDB_KEY = tmdbApi.OMDB_KEY;

function emuleRequest(url, cb)  { return emuleApi.emuleRequest(url, cb); }
function emuleSearch(q, s, cb)  { return emuleApi.emuleSearch(q, s, cb); }
function emuleDownload(h, cb, meta) { return emuleApi.emuleDownload(h, cb, meta); }
function emuleTransferAction(params, cb) { return emuleApi.emuleTransferAction(params, cb); }
function emuleAddEd2kLink(l, cb){ return emuleApi.emuleAddEd2kLink(l, cb); }
function autoLoginEmule()       { return emuleApi.autoLoginEmule(); }

// NOTE: pass-through to tmdb_api's full 5-arg signature
// (title, cacheDir, callback, rawFilename, settings). The old 2-arg wrapper
// shifted CACHE_DIR into `callback` when movies_routes called it with 5 args
// -> "TypeError: callback is not a function". Keep the arity aligned.
function fetchAndCacheMovie(title, cacheDir, cb, rawFilename, settings) { return tmdbApi.fetchAndCacheMovie(title, cacheDir, cb, rawFilename, settings); }
function getCompletedFiles() { return mediaResolver.getCompletedFiles(EMULE_INCOMING); }

// Auto-login eMule + keepalive
setTimeout(autoLoginEmule, 3000);
emuleApi.startKeepalive();

// v7.4.0 — react to eMule revival. The watchdog in emule_api.js bumps the
// library epoch and the front-end refreshes itself via /api/v1/lifecycle;
// this hook just logs. In v7.5+ this will also trigger a library re-scan.
emuleApi.onRevived(function(epoch) {
  console.log('[lifecycle] eMule revived (epoch=' + epoch + ').');
  setTimeout(autoLoginEmule, 2000);
});


// Pages (HTML + static routes)
const miscPages    = require('./pages/misc_pages');
const connectPage  = require('./pages/connect_page');
const searchPage   = require('./pages/search_page');
const appPage      = require('./pages/app_page');
const mainPage     = require('./pages/main_page');
const explorePage  = require('./pages/explore_page');
const mylistPage   = require('./pages/mylist_page');

//     Routes (API handlers)                                                  
const moviesRoutes   = require('./routes/movies_routes');
const emuleRoutes    = require('./routes/emule_routes');
const streamPart     = require('./routes/stream_part');
const streamCompleted = require('./routes/stream_completed');
const systemRoutes   = require('./routes/system_routes');
const v1Routes       = require('./routes/v1_routes');

// Init pages with shared context (done after all helpers are defined)
// See initPages() call at bottom of file




const activeStreams = {};

// Módulo de limpieza — movido a cleanup.js
const cleanup = require('./cleanup');
cleanup.init(activeStreams, TEMP_DIR);

// OMDb API proxy

function proxyOMDB(params, res) {
  const fullUrl = 'https://www.omdbapi.com/?' + params + '&apikey=' + OMDB_KEY + '&type=movie';
  https.get(fullUrl, (omdbRes) => {
    let data = '';
    omdbRes.on('data', d => data += d);
    omdbRes.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(data);
    });
  }).on('error', (e) => {
    res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
  });
}


// T�nel, UPnP, config y URL discovery  movidos a tunnel.js
const tunnel = require('./tunnel');
tunnel.init(PORT);
security.init({ tunnel });

// Wire page modules with shared context
const _pagesCtx = {
  PORT, tunnel, escapeHtml, cleanTitle, getDownloads, getCompletedFiles,
  HW_ENCODER,
  __dirname
};
miscPages.init(_pagesCtx);
connectPage.init(_pagesCtx);
searchPage.init(_pagesCtx);
appPage.init(_pagesCtx);
mainPage.init(_pagesCtx);
explorePage.init(_pagesCtx);
mylistPage.init(_pagesCtx);

const _routesCtx = {
  PORT, FFMPEG_PATH, EMULE_INCOMING, TEMP_DIR, HW_ENCODER, HW_ENCODER_OPTS,
  CACHE_DIR,
  activeStreams,
  tunnel, cleanup,
  loadSettings, saveSettings,
  getDownloads, getCompletedFiles, resolveMediaFile, getDuration,
  emuleLogin: (p, cb) => emuleApi.emuleLogin(p, cb),
  emuleSearch, emuleDownload, emuleTransferAction, emuleAddEd2kLink,
  emuleRequest,
  getSession: () => emuleApi.getSession(),
  proxyOMDB, fetchAndCacheMovie,
  security,
  __dirname,
};
moviesRoutes.init(_routesCtx);
emuleRoutes.init(_routesCtx);
streamPart.init(_routesCtx);
streamCompleted.init(_routesCtx);
systemRoutes.init(_routesCtx);
v1Routes.init({
  security,
  emuleApi,
  getSession: () => emuleApi.getSession(),
  emuleRoutes,
  streamCompleted,
  streamPart,
  systemRoutes,
  liveApi,
  liveRouteCtx: {
    ffmpegPath: FFMPEG_PATH,
    hwEncoder: HW_ENCODER,
    hwEncoderOpts: HW_ENCODER_OPTS
  }
});


// Init tunnel (must be before server handles requests that use tunnel.*)
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost:' + PORT);

  if (!security.apply(url, req, res)) return;

  // ━━━ Debug log endpoint + /debug viewer page (always-on, no auth) ━━━
  if (debugLog.handle(url, req, res)) return;
  if (url.pathname === '/debug' || url.pathname === '/debug/') {
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>eSE/eMule debug log</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;background:#111;color:#ddd}
header{padding:8px 14px;background:#1d1d1d;border-bottom:1px solid #333;display:flex;align-items:center;gap:18px}
h1{margin:0;font-size:14px;font-weight:600}
.tabs{display:flex;gap:4px}
.tabs button{background:#222;color:#ddd;border:1px solid #333;padding:4px 12px;cursor:pointer;font-size:12px}
.tabs button.active{background:#0066b3;border-color:#0088dd}
.controls{margin-left:auto;font-size:12px;display:flex;gap:10px;align-items:center}
.controls label{cursor:pointer}
pre{margin:0;padding:10px 14px;height:calc(100vh - 50px);overflow:auto;font-family:Consolas,monospace;font-size:11px;line-height:1.4;white-space:pre;color:#bbb}
pre b{color:#fff}
.hl-RTMP{color:#88c0ff}.hl-CHUNK{color:#9bd96b}.hl-RECV{color:#9bd96b}.hl-MGR{color:#fdd835}
.hl-KAD{color:#ce93d8}.hl-DIAL{color:#ffab40}.hl-HOLE{color:#ff7043}.hl-WARN{color:#ffb74d}.hl-ERR{color:#ef5350}
</style></head><body>
<header>
  <h1>Debug log</h1>
  <div class="tabs">
    <button id="t-emu" class="active" onclick="setSrc('emu')">eMule (C++)</button>
    <button id="t-ese" onclick="setSrc('ese')">eSE (Node)</button>
    <button id="t-both" onclick="setSrc('both')">Both</button>
  </div>
  <div class="controls">
    <label><input type="checkbox" id="auto" checked> auto-refresh 1s</label>
    <button onclick="load()">Refresh</button>
    <span id="status"></span>
  </div>
</header>
<pre id="log">loading...</pre>
<script>
let src='emu', timer=null;
function renderLog(pre,s){
  const tags=/^\\[(RTMP|CHUNK|RECV|MGR|KAD|DIAL|HOLE|WARN|ERR)\\]$/;
  const parts=String(s||'(empty)').split(/(\\[(?:RTMP|CHUNK|RECV|MGR|KAD|DIAL|HOLE|WARN|ERR)\\])/);
  pre.textContent='';
  for(let i=0;i<parts.length;i++){
    const match=parts[i].match(tags);
    if(match){
      const b=document.createElement('b');
      b.className='hl-'+match[1];
      b.textContent=parts[i];
      pre.appendChild(b);
    }else{
      pre.appendChild(document.createTextNode(parts[i]));
    }
  }
}
async function fetchOne(url, label){
  try{
    const r = await fetch(url, {cache:'no-store'});
    const j = await r.json();
    return (j.items||[]).map(l => label?(label+'  '+l):l);
  } catch(e){ return ['(fetch '+url+' failed: '+e.message+')']; }
}
async function load(){
  const st=document.getElementById('status'); st.textContent='loading...';
  let items=[];
  if(src==='emu')  items = await fetchOne('http://localhost:4711/api/live/log?n=200');
  else if(src==='ese') items = await fetchOne('/api/ese/log?n=200');
  else {
    const [e,s] = await Promise.all([
      fetchOne('http://localhost:4711/api/live/log?n=200', '[emu]'),
      fetchOne('/api/ese/log?n=200', '[ese]')]);
    items = e.concat(s).sort();
  }
  const pre=document.getElementById('log');
  renderLog(pre,items.join('\\n'));
  pre.scrollTop = pre.scrollHeight;
  st.textContent = items.length+' lines · '+new Date().toLocaleTimeString();
}
function setSrc(s){
  src=s;
  document.getElementById('t-emu').classList.toggle('active', s==='emu');
  document.getElementById('t-ese').classList.toggle('active', s==='ese');
  document.getElementById('t-both').classList.toggle('active', s==='both');
  load();
}
function startTimer(){ if(timer) clearInterval(timer); if(document.getElementById('auto').checked) timer=setInterval(load,1000); }
document.getElementById('auto').onchange=startTimer;
load(); startTimer();
</script>
</body></html>`);
    return;
  }

  // ━━━ eSE LIVE routes (/api/live/*, /live/*) ━━━

  // 2026-05-17: '/hls/' (with trailing slash) missed '/hls-local/...' so the
  // per-stream HLS endpoint in channel_api.js never fired and self-viewing on
  // the same PC failed silently with a generic 404. Use '/hls' to catch both.
  if (url.pathname.startsWith('/api/live/') || url.pathname.startsWith('/live') || url.pathname.startsWith('/hls') || url.pathname === '/privacy') {
    const handled = liveApi.handleRoute(url, req, res, {
      port: PORT,
      ffmpegPath: FFMPEG_PATH,
      hwEncoder: HW_ENCODER,
      hwEncoderOpts: HW_ENCODER_OPTS
    });
    if (handled) return;
  }
  
  
    

  // ── API routes ───────────────────────────────────
  if (v1Routes.handle(url, req, res))        return;
  if (moviesRoutes.handle(url, req, res))    return;
  if (emuleRoutes.handle(url, req, res))     return;
  if (streamCompleted.handle(url, req, res)) return;
  if (streamPart.handle(url, req, res))      return;
  if (systemRoutes.handle(url, req, res))    return;

  // ── Page modules ───────────────────────────────────
  if (miscPages.handle(url, req, res))   return;
  if (connectPage.handle(url, req, res)) return;
  if (searchPage.handle(url, req, res))  return;
  if (appPage.handle(url, req, res))     return;
  if (explorePage.handle(url, req, res)) return;
  if (mylistPage.handle(url, req, res))  return;
  if (mainPage.handle(url, req, res))    return;

  // ── Static assets ─────────────────────────────────
  if (url.pathname === '/emule_mascot.svg' || url.pathname === '/favicon.ico') {
    const svgPath = path.join(__dirname, 'emule_mascot.svg');
    if (fs.existsSync(svgPath)) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
      fs.createReadStream(svgPath).pipe(res);
      return;
    }
  }

  // 404 fallback
  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  eSE v' + APP_VERSION + ' - http://127.0.0.1:' + PORT);
  console.log('  ffmpeg: ' + FFMPEG_PATH);
  console.log('');

  // The dashboard port is deliberately never exposed with UPnP. eMule owns
  // the P2P port mappings; dashboard remote access is postponed.
  console.log('[security] Dashboard/API restricted to this PC');
});

// HLS files belong to the C++ broadcast/view session.  Deleting them when the
// dashboard restarts used to cut off an otherwise healthy eMule stream.  The
// C++ manager now removes its own root and per-stream output on Stop/Leave.
process.on('SIGINT',  () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
process.on('SIGHUP',  () => process.exit(0));
// Windows-specific: when parent (emule.exe) closes, child receives a CTRL_CLOSE
// which becomes SIGHUP via Node's compat layer. Above handlers cover it.
