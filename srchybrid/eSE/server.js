// Debug log first — hooks console.* so any startup log lines are captured.
const debugLog = require('./debug_log');
debugLog.install();
process.on('uncaughtException', err => { console.log('[Uncaught]', err); });
process.on('unhandledRejection', err => { console.log('[Unhandled]', err); });
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

// ━━━ REFACTORED MODULES ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const mediaResolver = require('./media_resolver');
const emuleApi = require('./emule_api');
const tmdbApi = require('./tmdb_api');
const utils = require('./utils');
const liveApi = require('./eSE-live/channel_api');
const thumbExtractor = require('./eSE-live/thumbnail_extractor');
const lanDiscovery = require('./eSE-live/lan_discovery');  // Capa 2 mDNS LAN
const updateNotifier = require('./eSE-live/update_notifier');  // D6 auto-update check
const security = require('./security');
const errorCodes = require('./error_codes');

// v8.0.4 — port becomes a runtime decision. We prefer 8080 but if another
// process holds it AND it isn't a sibling ese-server.exe (= can't be killed
// safely), we fall back through 8081..8089. The actual bound port is
// published to %APPDATA%\eSE\port.txt so emule.exe can open the browser at
// the right URL even after a fallback.
const PORT_PREFERRED   = 8080;
const PORT_FALLBACK_MAX = 8089;
let PORT = PORT_PREFERRED;

// ━━━ AUTO-DETECT EMULE PATHS (portable across users/PCs) ━━━━━━━━━━━━━━━━━━━
// v8.0.13 — read TempDir/IncomingDir straight from eMule's preferences.ini.
// Bug observed in real-world log: emule.exe ran in portable mode from
// OneDrive\Documentos\eSE-LiveTV-v0.70b-eSE8.0.10-x64\, with Temp/Incoming
// next to the binary, but ese-server.exe was still polling
// %USERPROFILE%\Downloads\eMule\Temp from the hardcoded fallback.
// /api/emule/downloads consequently returned an empty list and the
// monitor flagged "Sin datos recibidos" even though eMule was happily
// downloading.
function _readEmulePathsFromPrefs() {
  const candidates = [
    path.join(process.cwd(), 'config', 'preferences.ini'),  // portable, same dir as binary
    process.env.APPDATA      ? path.join(process.env.APPDATA,      'eMule', 'config', 'preferences.ini') : null,
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'eMule', 'config', 'preferences.ini') : null,
  ].filter(Boolean);
  for (const p of candidates) {
    let raw;
    try { raw = fs.readFileSync(p, 'utf8'); } catch (e) { continue; }
    // Simple INI parser: look for IncomingDir= and TempDir= under [eMule].
    // We don't try to be clever about sections — those keys only appear in
    // [eMule] in standard preferences.ini.
    const inc = (raw.match(/^IncomingDir\s*=\s*(.+)$/mi) || [])[1];
    const tmp = (raw.match(/^TempDir\s*=\s*(.+)$/mi) || [])[1];
    if (inc && tmp) {
      const incPath = inc.trim();
      const tmpPath = tmp.trim();
      if (fs.existsSync(incPath) && fs.existsSync(tmpPath)) {
        console.log('[config] Found Temp/Incoming in ' + p);
        return { temp: tmpPath, incoming: incPath };
      }
    }
  }
  return null;
}

function resolveEmulePaths() {
  const userProfile = process.env.USERPROFILE || process.env.HOME || 'C:\\Users\\Default';
  // Priority 1: explicit override file alongside the binary.
  const overrideFile = path.join(__dirname, 'emule_paths.json');
  if (fs.existsSync(overrideFile)) {
    try {
      const ov = JSON.parse(fs.readFileSync(overrideFile, 'utf8'));
      if (ov.temp && ov.incoming) {
        console.log('[config] Using custom eMule paths from emule_paths.json');
        return { temp: ov.temp, incoming: ov.incoming };
      }
    } catch(e) {}
  }

  // Priority 2: read eMule's own preferences.ini for IncomingDir/TempDir.
  const fromPrefs = _readEmulePathsFromPrefs();
  if (fromPrefs) return fromPrefs;

  // Priority 3: portable-mode convention. Many eMule portable ZIPs ship
  // with Temp/ and Incoming/ next to the binary. Check both subdir names.
  const portableCandidates = [
    { temp: path.join(process.cwd(), 'Temp'),     incoming: path.join(process.cwd(), 'Incoming') },
    { temp: path.join(process.cwd(), 'temp'),     incoming: path.join(process.cwd(), 'incoming') },
  ];
  for (const c of portableCandidates) {
    if (fs.existsSync(c.temp) && fs.existsSync(c.incoming)) {
      console.log('[config] Found Temp/Incoming next to binary at ' + process.cwd());
      return c;
    }
  }

  // Priority 4: classic legacy convention — ~/Downloads/eMule/*.
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
thumbExtractor.start(FFMPEG_PATH);
lanDiscovery.start();  // Capa 2 mDNS LAN announce + listener
updateNotifier.start();  // D6: poll GitHub releases every 6 h, surface to dashboard

// Auto-detect hardware encoder at startup
const hwEncoderMod = require('./hw_encoder');
hwEncoderMod.detect(FFMPEG_PATH, TEMP_DIR);
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
function emuleDownload(h, cb)   { return emuleApi.emuleDownload(h, cb); }
function emuleTransferAction(params, cb) { return emuleApi.emuleTransferAction(params, cb); }
function emuleAddEd2kLink(l, cb){ return emuleApi.emuleAddEd2kLink(l, cb); }
function autoLoginEmule()       { return emuleApi.autoLoginEmule(); }

// v8.0.17: forward the real (title, cacheDir, callback, rawFilename, settings)
// signature instead of dropping the last three args. The previous 2-arg
// wrapper `(title, cb)` made the route's actual callback land in CACHE_DIR
// (a STRING) on the way through, which made `aiFallback()` inside tmdb_api
// crash with "callback is not a function" whenever OMDB returned no match —
// surfacing as a noisy "[Uncaught]" each time a poster query missed.
// Accept the route's CACHE_DIR as a 2nd arg (ignored — we always use the
// server-side const, the route is just being explicit), keep the rest live.
function fetchAndCacheMovie(title, _cacheDirFromRoute, cb, rawFilename, settings) {
  return tmdbApi.fetchAndCacheMovie(title, CACHE_DIR, cb, rawFilename, settings);
}
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


//     Pages (HTML + static routes)                                              
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

// v8.0.17 — proxyOMDB with TMDB fallback on quota / network errors.
//
// The free OMDB key has a 1000-request/day cap. When we hit it, OMDB returns
// {"Response":"False","Error":"Request limit reached!"} and the trending grid
// + search results disappear from the UI (every card depends on data.Search).
//
// TMDB is on a different key and quota and is reliably available, so we
// translate OMDB's response shape into TMDB-as-OMDB whenever OMDB is sad:
//
//   GET /api/movies/search?q=...  → 's=' params  → TMDB /search/movie?query=
//   GET /api/movies/detail?id=ttN → 'i=ttN' params → TMDB /find/ttN with imdb_id
//
// Returns a SHAPED response that matches OMDB's wire format so the existing
// client (renderMovieCard, hero_ui, etc.) renders unchanged.
function proxyOMDB(params, res) {
  const fullUrl = 'https://www.omdbapi.com/?' + params + '&apikey=' + OMDB_KEY + '&type=movie';
  https.get(fullUrl, (omdbRes) => {
    let data = '';
    omdbRes.on('data', d => data += d);
    omdbRes.on('end', () => {
      // Try to detect "Request limit reached!" / "Invalid API key" /
      // generic Error responses so we can fall through to TMDB. Anything
      // else (a real hit, "Movie not found" etc.) we pass through verbatim.
      let parsed = null;
      try { parsed = JSON.parse(data); } catch (e) {}
      const hardErr = parsed && parsed.Response === 'False'
        && typeof parsed.Error === 'string'
        && /limit reached|invalid api|daily limit/i.test(parsed.Error);
      if (hardErr) {
        return _fallbackToTMDB(params, res, parsed.Error);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(data);
    });
  }).on('error', (e) => {
    _fallbackToTMDB(params, res, e.message);
  });
}

function _fallbackToTMDB(params, res, omdbReason) {
  // Parse the OMDB-style query string to figure out what kind of lookup we
  // need to do against TMDB.
  const usp = new URLSearchParams(params);
  const sQ  = usp.get('s');  // search by name
  const iId = usp.get('i');  // lookup by IMDB id
  const tQ  = usp.get('t');  // exact title

  // Helper: GET https + JSON.parse
  function tmdbGet(path, cb) {
    const tmdbKey = require('./api_keys').TMDB_KEY;
    if (!tmdbKey) return cb(new Error('TMDB key missing'));
    const url = 'https://api.themoviedb.org/3' + path +
      (path.indexOf('?') === -1 ? '?' : '&') +
      'api_key=' + tmdbKey;
    https.get(url, { headers: { 'User-Agent': 'eSE-LiveTV/8.0' } }, (r) => {
      let buf = '';
      r.on('data', d => buf += d);
      r.on('end', () => {
        try { cb(null, JSON.parse(buf)); }
        catch (e) { cb(e); }
      });
    }).on('error', cb);
  }
  // Translate a single TMDB movie record → OMDB-style Search row.
  function toOmdbSearchRow(m) {
    return {
      Title:  m.title || m.original_title || '',
      Year:   (m.release_date || '').substring(0, 4),
      imdbID: m._imdbID || '',   // populated by caller when available
      Type:   'movie',
      Poster: m.poster_path ? ('https://image.tmdb.org/t/p/w500' + m.poster_path) : 'N/A',
    };
  }
  function sendJson(obj) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  }
  function sendNone(extra) {
    sendJson(Object.assign({ Response: 'False', Error: 'No results' }, extra || {}));
  }

  console.log('[OMDB] fallback to TMDB: ' + omdbReason);

  if (sQ) {
    tmdbGet('/search/movie?language=es-ES&query=' + encodeURIComponent(sQ), (err, data) => {
      if (err || !data || !Array.isArray(data.results)) return sendNone();
      sendJson({
        Search: data.results.slice(0, 10).map(toOmdbSearchRow),
        totalResults: String(data.total_results || data.results.length),
        Response: 'True',
        _source: 'tmdb_fallback',
      });
    });
    return;
  }
  if (iId) {
    tmdbGet('/find/' + encodeURIComponent(iId) + '?language=es-ES&external_source=imdb_id', (err, data) => {
      if (err || !data || !data.movie_results || !data.movie_results.length) return sendNone();
      const m = data.movie_results[0];
      m._imdbID = iId;
      const row = toOmdbSearchRow(m);
      // Detail endpoint returns a single movie shape, not a Search array.
      sendJson(Object.assign({}, row, {
        Response: 'True',
        Plot: m.overview || '',
        _source: 'tmdb_fallback',
      }));
    });
    return;
  }
  if (tQ) {
    // Title lookup. Use search/movie + take the top result.
    tmdbGet('/search/movie?language=es-ES&query=' + encodeURIComponent(tQ), (err, data) => {
      if (err || !data || !Array.isArray(data.results) || !data.results.length) return sendNone();
      const m = data.results[0];
      sendJson(Object.assign({}, toOmdbSearchRow(m), {
        Response: 'True',
        Plot: m.overview || '',
        _source: 'tmdb_fallback',
      }));
    });
    return;
  }
  // Unknown query shape — give back the original OMDB error so callers know.
  sendNone({ Error: omdbReason || 'OMDB unavailable' });
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
function colorize(s){return s.replace(/\\[(RTMP|CHUNK|RECV|MGR|KAD|DIAL|HOLE|WARN|ERR)\\]/g,'<b class="hl-$1">[$1]</b>');}
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
  pre.innerHTML = colorize(items.join('\\n')) || '(empty)';
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
  if (url.pathname.startsWith('/api/live/') || url.pathname.startsWith('/live') || url.pathname.startsWith('/hls')) {
    const handled = liveApi.handleRoute(url, req, res, {
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

  // v8.0.3 — diagnostic code endpoints. Both unauth on purpose: they don't
  // expose anything except version + boolean state bits + build hash, and
  // we want bug reporters to be able to copy the code from any browser tab
  // without having to log in first. `/api/debug/code` is the user-facing
  // string; `/api/debug/codes` returns the full table for reference.
  if (url.pathname === '/api/debug/code') {
    const which = (url.searchParams.get('e') || 'E00').toUpperCase();
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(errorCodes.buildCode(which));
    return;
  }
  if (url.pathname === '/api/debug/codes') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(errorCodes.summary(), null, 2));
    return;
  }
  // /api/debug/last — most recent error code recorded by emule_api, or null.
  // The UI footer polls this every 3 s; on a non-null value it switches the
  // build code badge to red and shows the latest failure path.
  if (url.pathname === '/api/debug/last') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    const last = (emuleApi.getLastErrorCode && emuleApi.getLastErrorCode()) || null;
    res.end(JSON.stringify({ last: last, current: errorCodes.buildCode('E00') }));
    return;
  }

  // ── Static assets ─────────────────────────────────
  if (url.pathname === '/emule_mascot.svg' || url.pathname === '/favicon.ico') {
    const svgPath = path.join(__dirname, 'emule_mascot.svg');
    if (fs.existsSync(svgPath)) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' });
      fs.createReadStream(svgPath).pipe(res);
      return;
    }
  }

  // v8.0.1 — locally bundled hls.js. Previous releases loaded it from
  // cdn.jsdelivr.net at runtime; now ships in the pkg snapshot.
  if (url.pathname === '/vendor/hls.min.js') {
    const candidates = [
      path.join(__dirname, 'node_modules', 'hls.js', 'dist', 'hls.min.js'),
      path.join(__dirname, 'vendor', 'hls.min.js'),  // fallback if relocated by the build step
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=86400'
        });
        fs.createReadStream(p).pipe(res);
        return;
      }
    }
    res.writeHead(503, { 'Content-Type': 'text/plain' });
    res.end('hls.min.js not found in bundle — rebuild ese-server.exe with the v8.0.1+ build step.');
    return;
  }

  // 404 fallback. v8.0.9: guard against ERR_STREAM_WRITE_AFTER_END — when a
  // handler earlier in the chain already responded but didn't `return` (or
  // async-ended after we fell through), writeHead+end here throws an
  // uncaughtException visible in the log even though the request actually
  // succeeded. Skip the 404 if the response is already in flight.
  if (!res.headersSent && !res.writableEnded) {
    res.writeHead(404);
    res.end('Not found');
  }
});

// v8.0.4 — Port discovery with fallback range + orphan-aware retry.
//
// Two distinct failure modes for :8080 collide here:
//   (1) Sibling ese-server.exe holding the port (orphan after a crash). The
//       right answer is to kill the sibling — we own it — and re-listen on
//       the SAME port so emule.exe still finds us at :8080.
//   (2) Some unrelated app on :8080 (Jenkins, Tomcat, Grafana, qBittorrent
//       Web UI, ...). We must NOT kill the user's other software. The right
//       answer is to fall back: try 8081..8089, and publish the bound port
//       via %APPDATA%\eSE\port.txt so emule.exe opens the browser at the
//       correct URL.
//
// Heuristic: on the first EADDRINUSE for the preferred port, run the
// PowerShell Stop-Process for ese-server.exe (PID-filtered to skip us). If
// that didn't free the port, fall through to the next port. Subsequent
// EADDRINUSEs go straight to fallback. After 8089 we exit with diagnostic
// code E05 and a netstat dump of the holders so the user sees which app
// to stop.

let _killedSiblingOnce = false;

function _writePortFile(p) {
  try {
    const dir = path.join(process.env.APPDATA || process.env.HOME || __dirname, 'eSE');
    fs.mkdirSync(dir, { recursive: true });
    const f = path.join(dir, 'port.txt');
    fs.writeFileSync(f, String(p));
    console.log('[server] Published bound port to ' + f + ' (=' + p + ')');
  } catch (e) {
    console.log('[server] Could not write port.txt: ' + String(e && e.message).replace(/[\r\n\t]+/g, ' '));
  }
}

function _dumpPortHolders() {
  try {
    const { execSync } = require('child_process');
    const out = execSync('netstat -ano -p TCP | findstr ":808"',
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000, windowsHide: true }
    ).toString().split(/\r?\n/).filter(Boolean).slice(0, 12);
    if (out.length) {
      console.log('[server] Current TCP holders of :808x:');
      out.forEach((line) => console.log('  ' + line.replace(/[\r\n\t]+/g, ' ')));
    }
  } catch (e) { /* netstat missing or no matches */ }
}

function tryListen(p) {
  server.removeAllListeners('error');
  server.removeAllListeners('listening');

  server.once('error', (err) => {
    if (err.code !== 'EADDRINUSE') {
      console.error('[server] Listen error on :' + p + ' — ' + String(err && err.message).replace(/[\r\n\t]+/g, ' '));
      process.exit(1);
    }
    if (p === PORT_PREFERRED && !_killedSiblingOnce) {
      _killedSiblingOnce = true;
      console.log('[server] Port ' + p + ' busy. Killing sibling ese-server.exe (if any) and retrying...');
      try {
        const { execSync } = require('child_process');
        execSync(
          'powershell -NoProfile -Command "Get-Process ese-server -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne ' + process.pid + ' } | Stop-Process -Force"',
          { stdio: 'ignore', timeout: 3000, windowsHide: true }
        );
      } catch (e) {
        console.log('[server] Stop-Process failed: ' + String(e && e.message).replace(/[\r\n\t]+/g, ' '));
      }
      setTimeout(() => tryListen(p), 1000);
      return;
    }
    if (p < PORT_FALLBACK_MAX) {
      console.log('[server] Port ' + p + ' is held by another app. Trying :' + (p + 1) + '...');
      tryListen(p + 1);
      return;
    }
    console.error('[server] Ports ' + PORT_PREFERRED + '-' + PORT_FALLBACK_MAX + ' all busy. Giving up.');
    console.error('[server] diagnostic: ' + errorCodes.buildCode('ese_port_busy'));
    _dumpPortHolders();
    process.exit(1);
  });

  server.once('listening', () => {
    PORT = p;
    if (typeof _pagesCtx  !== 'undefined' && _pagesCtx)  _pagesCtx.PORT  = p;
    if (typeof _routesCtx !== 'undefined' && _routesCtx) _routesCtx.PORT = p;
    tunnel.init(p);
    _writePortFile(p);

    console.log('');
    console.log('  eSE v8.0.15 - http://localhost:' + p);
    console.log('  ffmpeg: ' + FFMPEG_PATH);
    console.log('  diagnostic: ' + errorCodes.buildCode('E00'));
    if (p !== PORT_PREFERRED) {
      console.log('  NOTE: port ' + PORT_PREFERRED + ' was busy. Bound to :' + p + ' instead.');
    }
    console.log('');

    if (security.isReady()) {
      tunnel.setupUPnP();
    } else {
      console.log('[security] Remote exposure disabled: missing access token');
    }
  });

  server.listen(p);
}

// v8.0.3 — wire state probes BEFORE the listener fires so /api/debug/code
// always returns up-to-date bits. Each probe is wrapped in try/catch inside
// error_codes.js so missing optionals (e.g. no Kad yet) don't blow up.
errorCodes.setRuntimeProbes({
  emuleLoggedIn: () => !!emuleApi.getSession(),
  kadConnected:  () => emuleApi.emuleWsIsResponsive && emuleApi.emuleWsIsResponsive(),
  upnpActive:    () => !!tunnel.active,
});

tryListen(PORT_PREFERRED);

// Sprint 2 E.4 — Cleanup HLS segments on graceful shutdown.
// Without this, the temp dir fills up with old .ts files between runs.
function cleanHlsOnExit() {
  try {
    const os = require('os');
    const hlsDir = path.join(os.tmpdir(), 'eMule_RTMP');
    if (!fs.existsSync(hlsDir)) return;
    const walk = function(dir) {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) { walk(full); try { fs.rmdirSync(full); } catch(e) {} }
        else if (/\.(ts|m3u8)$/i.test(entry.name)) {
          try { fs.unlinkSync(full); } catch(e) {}
        }
      }
    };
    walk(hlsDir);
    console.log('[shutdown] HLS temp cleaned.');
  } catch (e) { /* best-effort, ignore */ }
}
process.on('SIGINT',  () => { cleanHlsOnExit(); process.exit(0); });
process.on('SIGTERM', () => { cleanHlsOnExit(); process.exit(0); });
process.on('SIGHUP',  () => { cleanHlsOnExit(); process.exit(0); });
// Windows-specific: when parent (emule.exe) closes, child receives a CTRL_CLOSE
// which becomes SIGHUP via Node's compat layer. Above handlers cover it.

