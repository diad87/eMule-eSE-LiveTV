'use strict';
const fs           = require('fs');
const path         = require('path');
const { execFile } = require('child_process');
const aiAssistant  = require('../ai_assistant');
const { safeBasename } = require('../utils');

let _ctx = {};

// v8.0.16 — ffprobe cache for the smart-playback state machine.
// Keyed by partFile basename (e.g. "0042.part"). Each entry holds the parsed
// metadata plus an expiry timestamp. We re-probe every 60s during PROBE state
// because partial files grow and ffprobe's bitrate estimate sharpens as more
// of the moov/index becomes available.
const _probeCache = Object.create(null);
const PROBE_TTL_MS = 60 * 1000;

// v8.0.16 — rolling-rate samples per partFile. Each entry is an array of
// { t: ms-epoch, bytes: downloadedBytes-at-t }. We trim entries older than
// 120s to bound memory. The /api/emule/rate endpoint computes the slope
// over the requested windowSec.
const _rateSamples = Object.create(null);
const RATE_MAX_AGE_MS = 120 * 1000;

function _pushRateSample(partFile, bytes) {
  if (typeof bytes !== 'number' || bytes < 0) return;
  const now = Date.now();
  const arr = _rateSamples[partFile] || (_rateSamples[partFile] = []);
  arr.push({ t: now, bytes });
  // Trim old samples + cap length so a long-running monitor can't grow this
  // unbounded if rate is being polled aggressively.
  const cutoff = now - RATE_MAX_AGE_MS;
  while (arr.length && arr[0].t < cutoff) arr.shift();
  if (arr.length > 240) arr.splice(0, arr.length - 240);
}

// v8.0.14 — minimal eMule .met file parser focused on extracting the data the
// monitor needs to decide "is enough actually downloaded to start playing":
//
//   - FT_FILESIZE (tag id 0x02)        : true total file size in bytes
//   - FT_GAPSTART (0x09) / FT_GAPEND (0x0A) string-named tags : pairs of byte
//     offsets describing ranges that HAVE NOT been downloaded yet
//
// downloadedBytes = fileSize - sum(gapEnd - gapStart for each pair).
//
// v8.0.16 — extended return shape for the smart-playback state machine:
//   - headContiguousBytes : number of bytes contiguously downloaded starting
//                           at offset 0 (= firstGapStart, or fileSize if no
//                           gaps at all = file complete from head onward).
//                           This is the ground-truth "how much of the start
//                           of the movie is actually available to stream".
//   - firstGapStart       : byte offset where the FIRST missing range begins.
//                           Same as headContiguousBytes, exposed separately
//                           for symmetry with firstGapEnd.
//   - firstGapEnd         : byte offset where the FIRST missing range ends.
//                           Useful to know "after how big a hole does the
//                           next available chunk start".
//   - gapCount            : total number of unresolved gap pairs.
//
// .met header layout (matches PartFile.cpp::LoadPartFile):
//   byte 0       : version (0xE0 / 0xE1)
//   byte 1..4    : date (DWORD)
//   byte 5..20   : MD4 file hash (16 bytes)
//   byte 21..22  : part count (WORD LE)
//   byte 23..    : part count × 16 bytes of part hashes
//   then         : tag count (DWORD LE)
//   then         : tag count × CTag-serialised tags
//
// CTag serialisation (from eMule's OpCodes.h):
//   type byte. If bit 7 (0x80) set: 1-byte name id follows, type &= 0x7F.
//   Else: 2-byte LE namelen. namelen==1 → 1-byte name id; namelen>1 → ASCII name.
//   Value depends on type:
//     0x01 HASH16     16 bytes
//     0x02 STRING     2-byte LE length + bytes
//     0x03 UINT32     4 bytes LE
//     0x04 FLOAT32    4 bytes LE
//     0x05 BOOL       1 byte
//     0x06 BOOLARRAY  2-byte LE length-in-bits + ceil(n/8) bytes
//     0x07 BLOB       4-byte LE length + bytes              (NOT 1-byte!)
//     0x08 UINT16     2 bytes LE
//     0x09 UINT8      1 byte
//     0x0A BSOB       1-byte length + bytes                  (NOT 0x07!)
//     0x0B UINT64     8 bytes LE
//     0x11..0x20 STR1..STR16 fixed-length string
//
// v8.0.19 fix: previous version had 0x07 typed as "1-byte BSOB" (the
// correct shape for 0x0A) and never declared 0x0A. A real BLOB tag in
// the .met (FT_AICH_HASHSET, present in nearly every modern .met) would
// be parsed as a 1-byte payload, the parser would then advance way too
// few bytes, misread the next "type byte" as random payload data, and
// eventually hit an unrecognised type → break. fileSize had usually been
// captured by then but the gap tags (which come later) never were, so
// gapBytes=0 and downloaded was reported as fileSize. The user saw
// "headContiguous 39000 MB de 39000" while eMule had only 200 MB.
//
// Unknown types still abort the parse early, but now we set
// parseTruncated so the consumer knows the gap list is suspect. When
// truncated AND we found no gaps, we return downloaded/head as null
// rather than the misleading fileSize.
function _parseMetGaps(buf) {
  const out = {
    fileSize: null,
    downloaded: null,
    headContiguousBytes: null,
    firstGapStart: null,
    firstGapEnd: null,
    gapCount: 0,
    parseTruncated: false,
  };
  try {
    if (!buf || buf.length < 25) return out;
    let pos = 21;                                          // skip ver+date+hash
    const partCount = buf.readUInt16LE(pos); pos += 2;
    pos += partCount * 16;                                 // skip part hashes
    if (pos + 4 > buf.length) return out;
    const tagCount = buf.readUInt32LE(pos); pos += 4;

    let fileSize = null;
    const gapStarts = Object.create(null);
    const gapEnds   = Object.create(null);
    let tagsRead = 0;

    for (let i = 0; i < tagCount && pos < buf.length; i++) {
      let type = buf.readUInt8(pos++);
      let nameId = 0, nameStr = '';
      if (type & 0x80) {
        type &= 0x7F;
        if (pos >= buf.length) break;
        nameId = buf.readUInt8(pos++);
      } else {
        if (pos + 2 > buf.length) break;
        const namelen = buf.readUInt16LE(pos); pos += 2;
        if (pos + namelen > buf.length) break;
        if (namelen === 1) {
          nameId = buf.readUInt8(pos++);
        } else {
          nameStr = buf.slice(pos, pos + namelen).toString('latin1');
          pos += namelen;
        }
      }

      let value;
      if (type === 0x01) {           // HASH16
        if (pos + 16 > buf.length) break;
        pos += 16;                   // we don't use the value, skip
        value = null;
      } else if (type === 0x02) {    // STRING
        if (pos + 2 > buf.length) break;
        const slen = buf.readUInt16LE(pos); pos += 2;
        if (pos + slen > buf.length) break;
        value = buf.slice(pos, pos + slen).toString('latin1');
        pos += slen;
      } else if (type === 0x03) {    // UINT32
        if (pos + 4 > buf.length) break;
        value = buf.readUInt32LE(pos); pos += 4;
      } else if (type === 0x04) {    // FLOAT32
        if (pos + 4 > buf.length) break;
        pos += 4; value = null;
      } else if (type === 0x05) {    // BOOL  (v8.0.19)
        if (pos + 1 > buf.length) break;
        value = buf.readUInt8(pos++);
      } else if (type === 0x06) {    // BOOLARRAY  (v8.0.19)
        if (pos + 2 > buf.length) break;
        const nbits = buf.readUInt16LE(pos); pos += 2;
        const nbytes = Math.ceil(nbits / 8);
        if (pos + nbytes > buf.length) break;
        pos += nbytes; value = null;
      } else if (type === 0x07) {    // BLOB  (v8.0.19: 4-byte length, was wrong)
        if (pos + 4 > buf.length) break;
        const blen = buf.readUInt32LE(pos); pos += 4;
        if (pos + blen > buf.length) break;
        pos += blen; value = null;
      } else if (type === 0x08) {    // UINT16
        if (pos + 2 > buf.length) break;
        value = buf.readUInt16LE(pos); pos += 2;
      } else if (type === 0x09) {    // UINT8
        value = buf.readUInt8(pos++);
      } else if (type === 0x0A) {    // BSOB  (v8.0.19: 1-byte length, was missing)
        if (pos + 1 > buf.length) break;
        const blen = buf.readUInt8(pos++);
        if (pos + blen > buf.length) break;
        pos += blen; value = null;
      } else if (type === 0x0B) {    // UINT64
        if (pos + 8 > buf.length) break;
        const lo = buf.readUInt32LE(pos); pos += 4;
        const hi = buf.readUInt32LE(pos); pos += 4;
        value = hi * 4294967296 + lo;
      } else if (type >= 0x11 && type <= 0x20) {   // STR1..STR16
        const slen = type - 0x10;
        if (pos + slen > buf.length) break;
        pos += slen; value = null;
      } else {
        // Unknown type — bail rather than skip a payload of unknown size.
        // Flag the result as suspect so the consumer doesn't trust gap=0.
        break;
      }
      tagsRead++;

      // FT_FILESIZE (id 0x02). Could be UINT32 or UINT64 depending on version.
      if (nameId === 0x02 && typeof value === 'number') {
        fileSize = value;
      }
      // Gap pairs: stored as STRING name like '\x09<n>' / '\x0A<n>' with a
      // numeric value, where <n> is the pair index as ASCII digits.
      if (nameId === 0 && nameStr.length >= 2 && typeof value === 'number') {
        const code = nameStr.charCodeAt(0);
        const idx  = nameStr.substring(1);
        if      (code === 0x09) gapStarts[idx] = value;
        else if (code === 0x0A) gapEnds[idx]   = value;
      }
    }

    // Did we walk the whole tag table, or bail early?
    out.parseTruncated = tagsRead < tagCount;

    if (fileSize == null) return out;
    let gapBytes = 0;
    // Collect valid pairs, then find the one starting closest to offset 0.
    // headContiguousBytes = firstGapStart (everything before that offset is
    // contiguously downloaded).
    const pairs = [];
    for (const idx in gapStarts) {
      if (gapEnds[idx] != null && gapEnds[idx] >= gapStarts[idx]) {
        gapBytes += (gapEnds[idx] - gapStarts[idx]);
        pairs.push({ start: gapStarts[idx], end: gapEnds[idx] });
      }
    }
    out.fileSize   = fileSize;
    out.gapCount   = pairs.length;

    if (pairs.length === 0 && out.parseTruncated) {
      // v8.0.19: parser bailed before reaching the gap entries. We DO know
      // fileSize but downloaded/head are unknown — return null for both so
      // the caller doesn't trust "0 gaps → file complete" when it's really
      // "we couldn't read the .met past the first unknown tag". The state
      // machine treats null as "keep waiting in INIT, don't fast-forward
      // to PROBE".
      out.downloaded = null;
      out.headContiguousBytes = null;
      out.firstGapStart = null;
      out.firstGapEnd   = null;
      return out;
    }

    out.downloaded = Math.max(0, fileSize - gapBytes);
    if (pairs.length === 0) {
      // Genuine zero-gap result AND parser walked the full tag table → the
      // file IS complete from the .met's point of view. Head spans the
      // whole file. (Caller can still distinguish "freshly queued but no
      // chunks" vs "complete" because that scenario writes a single gap
      // pair start=0/end=fileSize — gapBytes would equal fileSize and
      // downloaded would be 0.)
      out.headContiguousBytes = fileSize;
      out.firstGapStart = null;
      out.firstGapEnd   = null;
    } else {
      pairs.sort((a, b) => a.start - b.start);
      const first = pairs[0];
      out.headContiguousBytes = first.start;
      out.firstGapStart       = first.start;
      out.firstGapEnd         = first.end;
    }
  } catch (e) { /* malformed .met — fall back to stat.size */ }
  return out;
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
          const metBuf = fs.readFileSync(metFile);
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
          _pushRateSample(pf, downloadedBytes);
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
    // Cache hit?
    const now = Date.now();
    const cached = _probeCache[safe];
    if (cached && cached.expires > now) {
      return sendJson(res, 200, Object.assign({ cached: true }, cached.data));
    }
    // Refuse to probe a file that's too small — ffprobe will hang or return
    // "Invalid data found when processing input" and we'll just thrash retry
    // loops. Tell the caller to retry later.
    let stat;
    try { stat = fs.statSync(partPath); } catch(e) {
      return sendJson(res, 500, { error: 'stat_failed', message: e.message });
    }
    // Use head-contiguous bytes from the .met as the readiness check — that's
    // the bytes ffprobe will actually see at the start of the file. statSize
    // can be many GB on a pre-allocated sparse file with zero real content.
    let headContig = stat.size;
    try {
      const metPath = partPath + '.met';
      if (fs.existsSync(metPath)) {
        const m = _parseMetGaps(fs.readFileSync(metPath));
        if (m.headContiguousBytes != null) headContig = m.headContiguousBytes;
      }
    } catch(e) { /* fall back to stat.size */ }
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
      _probeCache[safe] = { data, expires: now + PROBE_TTL_MS };
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
    let windowSec = parseInt(url.searchParams.get('windowSec') || '60', 10);
    if (!Number.isFinite(windowSec) || windowSec < 5)  windowSec = 5;
    if (windowSec > 120) windowSec = 120;
    const now = Date.now();
    const cutoff = now - windowSec * 1000;
    const arr = _rateSamples[safe] || [];
    // Pick the oldest sample inside the window as the anchor. If we have none
    // (cold start, or backend just restarted), use the oldest available; the
    // state machine will treat low-confidence rate as "still measuring".
    const windowed = arr.filter(s => s.t >= cutoff);
    if (windowed.length < 2) {
      return sendJson(res, 200, {
        ready: false,
        reason: 'insufficient_samples',
        samples: windowed.length,
        bytesPerSec: 0,
        windowSec,
      });
    }
    const first = windowed[0];
    const last  = windowed[windowed.length - 1];
    const dtSec = Math.max(0.001, (last.t - first.t) / 1000);
    // Clamp negative slopes to 0. A .part file shouldn't shrink, but if eMule
    // re-allocates or a .met rewrite happens to coincide with a poll, we
    // could see a transient drop. Returning a negative number would confuse
    // the state machine; 0 is the honest answer ("no progress measured").
    const bps = Math.max(0, (last.bytes - first.bytes) / dtSec);
    sendJson(res, 200, {
      ready: true,
      bytesPerSec: Math.round(bps),
      kbPerSec:    Math.round(bps / 1024),
      windowSec,
      samples:     windowed.length,
      firstSampleMsAgo: Math.round(now - first.t),
      lastSampleMsAgo:  Math.round(now - last.t),
    });
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
