'use strict';
const fs           = require('fs');
const path         = require('path');
const { execFile } = require('child_process');
const aiAssistant  = require('../ai_assistant');
const { safeBasename } = require('../utils');
// v8.0.20: .met parser extracted to its own module for unit testing.
// Local alias keeps the existing call sites (_parseMetGaps) unchanged.
const { parseMetGaps: _parseMetGaps } = require('../met_parser');
// v8.0.20: rolling-rate window also extracted for unit testing.
const rateWindow = require('../rate_window');

let _ctx = {};

// v8.0.16 — ffprobe cache for the smart-playback state machine.
// Keyed by partFile basename (e.g. "0042.part"). Each entry holds the parsed
// metadata plus an expiry timestamp. We re-probe every 60s during PROBE state
// because partial files grow and ffprobe's bitrate estimate sharpens as more
// of the moov/index becomes available.
const _probeCache = Object.create(null);
const PROBE_TTL_MS = 60 * 1000;

// v8.0.20 — playback event ring buffer. The S1..S7 state machine
// (playback_state.js) runs in the browser, so its console.log transitions
// never reach the backend debug log. It now POSTs each transition / decision
// to /api/emule/playback-log; we keep the last PLAYBACK_LOG_MAX entries in
// memory AND console.log a one-liner (which debug_log.js captures to disk +
// the /debug viewer). GET dumps the ring as JSON so a failed
// playback can be diagnosed without asking the user to reproduce it.
const _playbackLog = [];
const PLAYBACK_LOG_MAX = 300;

function _recordPlaybackEvent(ev) {
  // Whitelist + coerce — the body comes from the browser, never trust shapes.
  const e = {
    t: Date.now(),
    session: String(ev.session || '').slice(0, 40),
    from:    String(ev.from || '').slice(0, 20),
    to:      String(ev.to || '').slice(0, 20),
    reason:  String(ev.reason || '').slice(0, 60),
    partFile: String(ev.partFile || '').slice(0, 40),
    elapsedSec:  Number.isFinite(+ev.elapsedSec)  ? Math.round(+ev.elapsedSec)  : null,
    rateKBps:    Number.isFinite(+ev.rateKBps)    ? Math.round(+ev.rateKBps)    : null,
    bitrateKbps: Number.isFinite(+ev.bitrateKbps) ? Math.round(+ev.bitrateKbps) : null,
    headMB:      Number.isFinite(+ev.headMB)      ? Math.round(+ev.headMB)      : null,
    leadSec:     Number.isFinite(+ev.leadSec)     ? Math.round(+ev.leadSec)     : null,
  };
  _playbackLog.push(e);
  if (_playbackLog.length > PLAYBACK_LOG_MAX) {
    _playbackLog.splice(0, _playbackLog.length - PLAYBACK_LOG_MAX);
  }
  // One-liner to the backend console — debug_log.js hooks console.* so this
  // lands in %APPDATA%\eSE\debug.log and the /debug viewer for free.
  const bits = [];
  if (e.partFile)            bits.push(e.partFile);
  if (e.elapsedSec != null)  bits.push(e.elapsedSec + 's');
  if (e.rateKBps != null)    bits.push('rate=' + e.rateKBps + 'KB/s');
  if (e.bitrateKbps != null) bits.push('br=' + e.bitrateKbps + 'kbps');
  if (e.headMB != null)      bits.push('head=' + e.headMB + 'MB');
  if (e.leadSec != null)     bits.push('lead=' + e.leadSec + 's');
  if (e.reason)              bits.push('(' + e.reason + ')');
  console.log('[PLAYBACK] ' + (e.from || '?') + ' -> ' + (e.to || '?') +
              (bits.length ? '  ' + bits.join(' ') : ''));
  return e;
}

// v8.0.20 — torn-read guard for the .met file.
//
// eMule rewrites the .met every few seconds while a download is active. A
// poll can catch it mid-write and read a torn buffer — e.g. half the old
// gap list and half the new. The v8.0.19 parser walks the whole tag table
// happily (parseTruncated stays false) and computes a gapBytes that is
// neither the old nor the new truth: a lie the parser CANNOT detect.
//
// Defence: stat → read → stat. If mtimeMs AND size are identical before and
// after the read, no write occurred during our read window, so the buffer
// is a consistent on-disk snapshot. Retry up to 3× on a race; if all three
// attempts race a write (practically impossible — eMule writes a few-KB
// file in well under a millisecond), return the last buffer as best effort
// (the parser's parseTruncated path still handles a torn tail).
//
// The .met HEADER (bytes 0..20: version, date, MD4 hash) is fixed for the
// lifetime of the download, so the fileHash read from bytes 5..20 is always
// reliable even on a torn read — only the gap tags deeper in the file can
// be caught mid-rewrite.
function _readMetStable(metPath) {
  let last = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    let st1, buf, st2;
    try {
      st1 = fs.statSync(metPath);
      buf = fs.readFileSync(metPath);
      st2 = fs.statSync(metPath);
    } catch (e) {
      return last;   // file vanished / unreadable — return whatever we had
    }
    last = buf;
    if (st1.mtimeMs === st2.mtimeMs &&
        st1.size === st2.size &&
        buf.length === st2.size) {
      return buf;    // provably consistent snapshot
    }
    // else: eMule wrote during our read window — retry.
  }
  return last;       // 3 races (≈impossible) — best effort
}

function init(ctx) { _ctx = ctx; }

function readJsonBody(req, callback) {
  let body = '';
  req.on('data', d => body += d);
  req.on('end', () => {
    if (!body.trim()) return callback(null, {});
    try { callback(null, JSON.parse(body)); }
    catch (e) { callback(e); }
  });
}

function sendJson(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

function handle(url, req, res) {
  // Settings
  if (url.pathname === '/api/settings' && req.method === 'GET') {
    const settings = _ctx.security ? _ctx.security.redactSettings(_ctx.loadSettings()) : _ctx.loadSettings();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(settings));
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const newSettings = JSON.parse(body);
        const current = _ctx.loadSettings();
        if (_ctx.security) _ctx.security.mergeSettings(current, newSettings);
        else Object.assign(current, newSettings);
        _ctx.saveSettings(current);
        const safeSettings = _ctx.security ? _ctx.security.redactSettings(current) : current;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(safeSettings));
      } catch(e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return true;
  }

  if (!url.pathname.startsWith('/api/emule/')) return false;

  if (url.pathname === '/api/emule/login') {
    const password = url.searchParams.get('p') || _ctx.loadSettings().emulePassword || '';
    _ctx.emuleLogin(password, (err, session) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: !err, session: session || null, error: err ? err.message : null }));
    });
    return true;
  }

  if (url.pathname === '/api/emule/status') {
    const session = _ctx.getSession();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ loggedIn: !!session, session }));
    return true;
  }

  if (url.pathname === '/api/emule/resync' && req.method === 'POST') {
    // Fuerza un re-login con la password fresca de settings.json (o env var).
    // Útil cuando el usuario cierra eMule, lo reabre, y la sesión vieja murió.
    const pw = _ctx.loadSettings().emulePassword || '';
    _ctx.emuleLogin(pw, (err, session) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: !err,
        session: session || null,
        error:   err ? err.message  : null,
        reason:  err ? (err.reason || null) : null
      }));
    });
    return true;
  }

  if (url.pathname === '/api/emule/search') {
    const q = url.searchParams.get('q') || '';
    if (!q) { res.writeHead(400); res.end('{}'); return true; }
    const doSearch = () => {
      _ctx.emuleSearch(q, _ctx.loadSettings(), (err, results) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: !err, results: results || [], error: err ? err.message : null }));
      });
    };
    if (!_ctx.getSession()) {
      const pw = _ctx.loadSettings().emulePassword;
      if (pw) {
        _ctx.emuleLogin(pw, (err) => {
          if (err) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, results: [], error: err.message, reason: err.reason || null }));
          } else doSearch();
        });
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, results: [], error: 'No eMule password configured. Go to Settings.' }));
      }
    } else doSearch();
    return true;
  }

  if (url.pathname === '/api/emule/download') {
    const hash = url.searchParams.get('hash') || '';
    if (!hash) { res.writeHead(400); res.end('{}'); return true; }
    _ctx.emuleDownload(hash, (err, ok) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: ok, error: err ? err.message : null }));
    });
    return true;
  }

  if (url.pathname === '/api/emule/download/action') {
    const run = (params) => {
      if (!_ctx.emuleTransferAction) {
        return sendJson(res, 501, { success: false, error: 'transfer actions unavailable' });
      }
      _ctx.emuleTransferAction(params, (err, result) => {
        if (err) return sendJson(res, 400, { success: false, error: err.message });
        sendJson(res, 200, { success: true, result });
      });
    };

    // v7.5.0 — accept POST (preferred) OR GET with X-Requested-With header (which
    // a cross-origin <img src> / DNS-rebinding hit can't set without CORS preflight).
    // Breaks naive CSRF (<img src="/api/emule/download/action?hash=…&op=cancel">)
    // while staying same-origin friendly for the existing fetch()-based UI.
    if (req.method === 'POST') {
      readJsonBody(req, (err, body) => {
        if (err) return sendJson(res, 400, { success: false, error: 'Invalid JSON' });
        run(body || {});
      });
    } else if (req.method === 'GET' && req.headers['x-requested-with']) {
      run(Object.fromEntries(url.searchParams.entries()));
    } else {
      res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'POST' });
      res.end(JSON.stringify({ error: 'method_not_allowed', expected: 'POST or GET with X-Requested-With header' }));
    }
    return true;
  }

  if (url.pathname === '/api/emule/downloads') {
    const EMULE_TEMP = path.join(path.dirname(_ctx.EMULE_INCOMING), 'Temp');
    try {
      const partFiles = fs.readdirSync(EMULE_TEMP).filter(f => /^\d+\.part$/.test(f));
      const downloads = [];
      for (const pf of partFiles) {
        const metFile = path.join(EMULE_TEMP, pf + '.met');
        const partPath = path.join(EMULE_TEMP, pf);
        if (fs.existsSync(metFile)) {
          // v8.0.20: stable read — never parse a buffer caught mid-rewrite.
          const metBuf = _readMetStable(metFile);
          if (!metBuf) continue;   // .met vanished between readdir and read
          // .met layout: byte 0 = version (0xE0/0xE1), bytes 1..4 = date,
          // bytes 5..20 = 16-byte MD4 file hash. Required so the client can
          // identify a download by hash instead of fuzzy-matching its filename
          // (which collides across sequels — "a todo gas 6" vs "a todo gas 1").
          let fileHash = '';
          if (metBuf.length >= 21) {
            fileHash = metBuf.slice(5, 21).toString('hex').toUpperCase();
          }
          const metText = metBuf.toString('latin1');
          const fnMatch = metText.match(/[^\x00-\x1F\x7F-\x9F]{5,}\.(avi|mkv|mp4|wmv|mov|webm|flv)/i);
          const fileName = fnMatch ? fnMatch[0] : pf;
          const stat = fs.statSync(partPath);
          const isActive = (Date.now() - stat.mtimeMs) < 30000;

          // v8.0.14: parse the .met gap list to get REAL downloaded bytes.
          // stat.size lies when eMule pre-allocated the file at full size at
          // queue-add time (which it did with bPreallocate=1 / sparse-files),
          // so the monitor's "buffer listo" trigger fired on 0 bytes of
          // actual content. Parsing FT_FILESIZE + FT_GAPSTART/FT_GAPEND
          // pairs gives ground truth.
          const met = _parseMetGaps(metBuf);
          // v8.0.19: do NOT fall back to stat.size for downloaded/head when
          // the .met parser couldn't read the gap table. stat.size lies on
          // pre-allocated sparse .part files (it returns the LOGICAL full
          // size — exactly what fileSize is). The old fallback caused the
          // user-reported "39 GB de 39 GB" while eMule had 200 MB.
          //
          // When parser succeeds: use met values.
          // When parser bails before gaps: report 0 (we don't know — be
          // pessimistic). The state machine treats 0 as "keep waiting in
          // INIT" until eMule updates the .met and we can parse it cleanly.
          const totalSize       = met.fileSize   != null ? met.fileSize    : stat.size;
          const downloadedBytes = met.downloaded != null ? met.downloaded  : 0;
          const downloadedMB    = Math.round(downloadedBytes / (1024 * 1024));
          const totalMB         = Math.round(totalSize       / (1024 * 1024));
          const headContiguousBytes = met.headContiguousBytes != null
            ? met.headContiguousBytes
            : 0;
          const headContiguousMB = Math.round(headContiguousBytes / (1024 * 1024));
          // Backward-compat: `sizeMB`/`sizeBytes` keep meaning "logical size"
          // (what stat returns) so existing code that uses them for display
          // doesn't change. New fields totalMB/downloadedMB/downloadedBytes
          // are what the monitor should gate on.
          // v8.0.16: feed the rolling-rate window from the SAME truth the
          // state machine sees. The frontend used to keep its own sample
          // buffer in window._smartPlayRateSamples, but that gets reset on
          // every page reload and double-counts when two tabs poll at the
          // same time. Backend ownership = single source of truth.
          rateWindow.pushSample(pf, downloadedBytes);
          downloads.push({
            partFile: pf, fileName, fileHash,
            sizeMB: Math.round(stat.size / (1024 * 1024)), sizeBytes: stat.size,
            totalMB, totalBytes: totalSize,
            downloadedMB, downloadedBytes,
            headContiguousMB, headContiguousBytes,
            firstGapStart: met.firstGapStart,
            firstGapEnd:   met.firstGapEnd,
            gapCount:      met.gapCount,
            // v8.0.19: visibility into whether the .met parse was complete.
            // When false, downloadedBytes/headContiguousBytes default to 0
            // (pessimistic) — the state machine should keep waiting.
            metParseOk:    !met.parseTruncated && met.downloaded != null,
            progress: totalSize > 0 ? Math.round((downloadedBytes / totalSize) * 1000) / 10 : 0,
            partPath, lastModified: stat.mtimeMs, active: isActive,
          });
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(downloads));
    } catch(e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('[]');
    }
    return true;
  }

  // v8.0.16 — ffprobe wrapper. Returns the metadata the state machine needs
  // to compute the sustained-rate target (duration + bitrate) plus codec info
  // so we can surface honest "transcoding required" warnings in S2 instead of
  // discovering them only when ffmpeg pipes 500 the first time.
  //
  // Cached per partFile for 60s. Partial .part files are valid ffprobe
  // input as long as enough of the moov atom has arrived — that's typically
  // the case once headContiguousBytes >= ~5 MB. Below that we return a
  // not_ready response so the state machine can keep waiting in PROBE.
  if (url.pathname === '/api/emule/probe' && req.method === 'GET') {
    const fileParam = url.searchParams.get('file') || '';
    const safe = safeBasename(fileParam);
    if (!safe || !/^\d+\.part$/.test(safe)) {
      return sendJson(res, 400, { error: 'bad_file', expected: '<n>.part' });
    }
    const EMULE_TEMP = path.join(path.dirname(_ctx.EMULE_INCOMING), 'Temp');
    const partPath = path.join(EMULE_TEMP, safe);
    if (!fs.existsSync(partPath)) {
      return sendJson(res, 404, { error: 'not_found', file: safe });
    }
    const now = Date.now();
    // Refuse to probe a file that's too small — ffprobe will hang or return
    // "Invalid data found when processing input" and we'll just thrash retry
    // loops. Tell the caller to retry later.
    let stat;
    try { stat = fs.statSync(partPath); } catch(e) {
      return sendJson(res, 500, { error: 'stat_failed', message: e.message });
    }
    // Read the .met ONCE: it gives us both the head-contiguous readiness
    // check AND the file's MD4 hash. v8.0.20: the hash goes into the probe
    // cache key. eMule RECYCLES part-file numbers — '0042.part' can be
    // movie A today and movie B after a cancel+restart. Keying the cache by
    // basename alone would serve A's bitrate/duration for B within the 60 s
    // TTL, feeding a wrong bitrate into the SUSTAIN gate. Keying by
    // basename#hash makes a recycled part number a cache miss.
    //
    // Use head-contiguous bytes from the .met as the readiness check — that's
    // the bytes ffprobe will actually see at the start of the file. statSize
    // can be many GB on a pre-allocated sparse file with zero real content.
    let headContig = stat.size;
    let fileHash = '';
    try {
      const metPath = partPath + '.met';
      if (fs.existsSync(metPath)) {
        const metBuf = _readMetStable(metPath);   // v8.0.20: torn-read guard
        if (metBuf) {
          if (metBuf.length >= 21) {
            fileHash = metBuf.slice(5, 21).toString('hex');
          }
          const m = _parseMetGaps(metBuf);
          if (m.headContiguousBytes != null) headContig = m.headContiguousBytes;
        }
      }
    } catch(e) { /* fall back to stat.size */ }

    // Cache hit? Keyed by basename#hash so a recycled part number misses.
    const cacheKey = safe + '#' + fileHash;
    const cached = _probeCache[cacheKey];
    if (cached && cached.expires > now) {
      return sendJson(res, 200, Object.assign({ cached: true }, cached.data));
    }
    if (headContig < 5 * 1024 * 1024) {
      return sendJson(res, 200, {
        ready: false,
        reason: 'head_too_small',
        headContiguousBytes: headContig,
        minBytes: 5 * 1024 * 1024,
      });
    }
    const ffmpegPath = _ctx.FFMPEG_PATH || '';
    if (!ffmpegPath) {
      return sendJson(res, 500, { error: 'ffmpeg_path_missing' });
    }
    const ffprobePath = ffmpegPath.replace(/ffmpeg(\.exe)?$/i, 'ffprobe$1');
    // execFile (not exec) so the path is passed as a separate argv entry —
    // not parsed by a shell, so no quote-injection from filenames. The .part
    // basename has already been validated by safeBasename + the \d+\.part
    // regex, so partPath is built only from controlled segments, but execFile
    // is the right tool regardless.
    const args = [
      '-v', 'error',
      '-print_format', 'json',
      '-show_format',
      '-show_streams',
      partPath,
    ];
    execFile(ffprobePath, args, { timeout: 12000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        return sendJson(res, 200, {
          ready: false,
          reason: 'ffprobe_failed',
          message: String(err.message || err).slice(0, 200),
          stderr: String(stderr || '').slice(0, 400),
        });
      }
      let probe;
      try { probe = JSON.parse(stdout); }
      catch(e) {
        return sendJson(res, 200, { ready: false, reason: 'ffprobe_bad_json' });
      }
      const fmt   = probe.format  || {};
      const sList = probe.streams || [];
      const v = sList.find(s => s.codec_type === 'video');
      const a = sList.find(s => s.codec_type === 'audio');
      // Duration in seconds. ffprobe sometimes leaves it blank for .part files
      // mid-download; fall back to the stream-level value or null. Bitrate
      // likewise — when missing we'll compute it lazily in the state machine
      // as totalBytes / duration so we always have a number to gate on.
      const duration = parseFloat(fmt.duration) || (v && parseFloat(v.duration)) || null;
      const bitrate  = parseInt(fmt.bit_rate, 10) || (v && parseInt(v.bit_rate, 10)) || null;
      const data = {
        ready: true,
        container: (fmt.format_name || '').split(',')[0] || '',
        duration,                         // seconds
        bitrate,                          // bits/sec
        sizeBytes: parseInt(fmt.size, 10) || null,
        hasVideo: !!v,
        hasAudio: !!a,
        videoCodec: v ? (v.codec_name || '') : '',
        audioCodec: a ? (a.codec_name || '') : '',
        width:  v ? (v.width  || 0) : 0,
        height: v ? (v.height || 0) : 0,
        audioChannels: a ? (a.channels || 0) : 0,
        audioSampleRate: a ? (parseInt(a.sample_rate, 10) || 0) : 0,
      };
      _probeCache[cacheKey] = { data, expires: now + PROBE_TTL_MS };
      sendJson(res, 200, data);
    });
    return true;
  }

  // v8.0.16 — rolling-rate window. The state machine asks "how fast is this
  // download going over the last <windowSec> seconds?" and gets back a clean
  // KB/s number derived from the same backend-collected samples that feed
  // /api/emule/downloads. Default window 60s, min 5s, max 120s.
  if (url.pathname === '/api/emule/rate' && req.method === 'GET') {
    const fileParam = url.searchParams.get('file') || '';
    const safe = safeBasename(fileParam);
    if (!safe || !/^\d+\.part$/.test(safe)) {
      return sendJson(res, 400, { error: 'bad_file', expected: '<n>.part' });
    }
    // v8.0.20: slope computation moved to rate_window.computeRate (unit-tested).
    sendJson(res, 200, rateWindow.computeRate(safe, url.searchParams.get('windowSec') || 60));
    return true;
  }

  // v8.0.20 — playback event log. POST records one S1..S7 transition;
  // GET dumps the in-memory ring (newest last) for diagnosis.
  // Path is under /api/emule/ because handle() early-returns for anything
  // that isn't (see the prefix gate at the top of this function).
  if (url.pathname === '/api/emule/playback-log') {
    if (req.method === 'POST') {
      readJsonBody(req, (err, body) => {
        if (err) return sendJson(res, 400, { ok: false, error: 'bad_json' });
        try { _recordPlaybackEvent(body || {}); } catch (e) { /* never fail the client */ }
        sendJson(res, 200, { ok: true });
      });
      return true;
    }
    if (req.method === 'GET') {
      sendJson(res, 200, { count: _playbackLog.length, events: _playbackLog });
      return true;
    }
    res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'GET, POST' });
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return true;
  }

  if (url.pathname === '/api/emule/smartsearch') {
    const q = url.searchParams.get('q') || '';
    if (!q) { res.writeHead(400); res.end('{}'); return true; }

    const doSmartSearch = () => {
      const settings = _ctx.loadSettings();
      const year     = url.searchParams.get('year') || '';

      // Build the canonical primary query (same logic as before)
      const parts = q.split(/\s*[:]\s*/).filter(s => s.trim().length > 1);
      let mainTitle = parts[0] || q;
      if (mainTitle.length < 3) mainTitle = q.replace(/[:]/g, ' ').replace(/\s+/g, ' ').trim();
      const primaryQuery = mainTitle + (year ? ' ' + year : '');

      console.log('[SmartSearch] Primary query: "' + primaryQuery + '" (original: "' + q + '")');

      // ── Step 1: Generate query variants (AI or heuristic) ───────────────────
      aiAssistant.generateQueryVariants(primaryQuery, settings, (err1, variants) => {
        const queriesToRun = (variants && variants.length > 0) ? variants : [primaryQuery];
        console.log('[SmartSearch] Will run', queriesToRun.length, 'variant(s):', queriesToRun);

        // ── Step 2: Run searches sequentially, merge by ed2k hash ──────────────
        // eMule supports only one concurrent search — we exploit its sequential
        // nature. We stop early once we have ENOUGH_RESULTS good candidates.
        const ENOUGH_RESULTS = 8;
        const mergedByHash = {};  // hash(uppercase) → best result object
        let variantIdx = 0;

        const runNextVariant = () => {
          // Early-exit: enough high-quality results already gathered
          if (variantIdx > 0) {
            const goodSoFar = Object.values(mergedByHash)
              .filter(r => r.completeSources > 0 && r.score > 0).length;
            if (goodSoFar >= ENOUGH_RESULTS) {
              console.log('[SmartSearch] Early-exit: ' + goodSoFar + ' good results, skipping remaining variants');
              return finalize(Object.values(mergedByHash));
            }
          }

          if (variantIdx >= queriesToRun.length) {
            return finalize(Object.values(mergedByHash));
          }

          const currentQuery = queriesToRun[variantIdx++];
          console.log('[SmartSearch] Running variant', variantIdx, '/', queriesToRun.length + ': "' + currentQuery + '"');

          _ctx.emuleSearch(currentQuery, settings, (err2, results) => {
            let newCount = 0;
            (results || []).forEach(r => {
              const key = (r.hash || '').toUpperCase();
              if (!key) return;
              if (!mergedByHash[key] || r.score > mergedByHash[key].score) {
                mergedByHash[key] = { ...r, foundByQuery: currentQuery };
                newCount++;
              }
            });
            console.log(
              '[SmartSearch] Variant', variantIdx, ': found', (results || []).length,
              'results (+' + newCount + ' new), total unique:', Object.keys(mergedByHash).length
            );
            runNextVariant();
          });
        };

        // ── Step 3: AI re-rank + finalize ──────────────────────────────────────
        const finalize = (allResults) => {
          aiAssistant.rankResults(primaryQuery, allResults, settings, (err3, rankedResults) => {
            const ranked = rankedResults || allResults;

            // Filter: remove definitive fakes and hopeless files.
            // Rules (in priority order):
            //   1. score <= -900 → always drop (exe, password-protected, etc.)
            //   2. Large files (>500MB) → NEVER drop based on sources or heuristic alone;
            //      only a hard score (< -900) eliminates them.
            //   3. isFake (heuristic) AND AI confirms unsafe → drop
            //   4. 0 complete sources AND AI not approving AND small file → drop
            //   5. Anything with positive score OR AI blessing → keep
            const viable = ranked.filter(r => {
              if (r.score <= -900) return false;                     // hard fake (exe, pass-protected…)
              if (r.sizeMB > 500)  return true;                      // large file: always show, never hide
              if (r.isFake && !r.aiSafe) return false;               // heuristic fake, AI not overriding
              if (r.completeSources === 0 && !r.aiSafe) return false; // 0 seeds, not AI-approved, small
              return r.score > 0 || r.aiSafe || r.sizeMB > 200;     // positive score, AI blessing, or decent size
            });
            viable.sort((a, b) => b.score - a.score);

            const totalFound    = allResults.length;
            const fakesFiltered = totalFound - viable.length;

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              success:       true,
              query:         primaryQuery,
              originalQuery: q,
              variantsUsed:  queriesToRun,
              aiEnhanced:    aiAssistant.isEnabled(settings),
              totalFound,
              fakesFiltered,
              results:       viable
            }));
          });
        };

        runNextVariant();
      });
    };

    if (!_ctx.getSession()) {
      const pw = _ctx.loadSettings().emulePassword || '';
      _ctx.emuleLogin(pw, (err) => {
        if (err) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, results: [], error: err.message, reason: err.reason || null }));
        } else doSmartSearch();
      });
    } else doSmartSearch();
    return true;
  }

  if (url.pathname === '/api/emule/ed2klink' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      let link = '';
      try {
        const parsed = JSON.parse(body);
        link = (parsed.link || '').trim();
      } catch(e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'JSON inválido' }));
        return;
      }

      if (!link) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Enlace vacío' }));
        return;
      }

      _ctx.emuleAddEd2kLink(link, (err, result) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        if (err) {
          res.end(JSON.stringify({ success: false, error: err.message }));
        } else {
          res.end(JSON.stringify({ success: true, fileName: result.fileName, sizeMB: result.sizeMB, hash: result.hash }));
        }
      });
    });
    return true;
  }

  // v7.4.0 — delete a completed file from the Incoming folder. Used by the
  // "Mi Biblioteca" panel. Guarded by safeBasename + isPathWithin to refuse
  // any path-traversal attempts; the server is publicly reachable via UPnP.
  if (url.pathname === '/api/emule/completed/delete' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const { fileName } = JSON.parse(body || '{}');
        const utils = require('../utils');
        const safe = utils.safeBasename(fileName);
        if (!safe) return sendJson(res, 400, { success: false, error: 'bad_filename' });
        const incoming = _ctx.EMULE_INCOMING;
        const filePath = path.join(incoming, safe);
        if (typeof utils.isPathWithin === 'function' && !utils.isPathWithin(filePath, incoming)) {
          return sendJson(res, 400, { success: false, error: 'path_traversal' });
        }
        if (!fs.existsSync(filePath)) {
          return sendJson(res, 404, { success: false, error: 'not_found' });
        }
        fs.unlinkSync(filePath);
        console.log('[delete] Removed completed file: ' + safe);
        // eMule's sharedfiles list refreshes lazily; users who want the file
        // gone from search results can re-share or restart. Not auto-nudging
        // emuledlg here to keep this thread-safe.
        sendJson(res, 200, { success: true });
      } catch(e) { sendJson(res, 500, { success: false, error: e.message }); }
    });
    return true;
  }

  return false;
}

module.exports = { init, handle };
