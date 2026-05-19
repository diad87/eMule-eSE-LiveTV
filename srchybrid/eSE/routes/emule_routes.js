'use strict';
const fs           = require('fs');
const path         = require('path');
const aiAssistant  = require('../ai_assistant');

let _ctx = {};

// v8.0.14 — minimal eMule .met file parser focused on extracting the data the
// monitor needs to decide "is enough actually downloaded to start playing":
//
//   - FT_FILESIZE (tag id 0x02)        : true total file size in bytes
//   - FT_GAPSTART (0x09) / FT_GAPEND (0x0A) string-named tags : pairs of byte
//     offsets describing ranges that HAVE NOT been downloaded yet
//
// downloadedBytes = fileSize - sum(gapEnd - gapStart for each pair).
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
// CTag serialisation:
//   type byte. If bit 7 (0x80) set: 1-byte name id follows, type &= 0x7F.
//   Else: 2-byte LE namelen. namelen==1 → 1-byte name id; namelen>1 → ASCII name.
//   Value depends on type:
//     0x01 HASH16   16 bytes
//     0x02 STRING   2-byte LE length + UTF-8/ASCII bytes
//     0x03 UINT32   4 bytes LE
//     0x04 FLOAT32  4 bytes LE
//     0x07 BSOB     1-byte length + bytes
//     0x08 UINT16   2 bytes LE
//     0x09 UINT8    1 byte
//     0x0B UINT64   8 bytes LE
//     0x11..0x20 STR1..STR16 fixed-length string
//
// Unknown types abort the parse early; we never propagate garbage.
function _parseMetGaps(buf) {
  const out = { fileSize: null, downloaded: null };
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
      } else if (type === 0x07) {    // BSOB
        if (pos + 1 > buf.length) break;
        const blen = buf.readUInt8(pos++);
        if (pos + blen > buf.length) break;
        pos += blen; value = null;
      } else if (type === 0x08) {    // UINT16
        if (pos + 2 > buf.length) break;
        value = buf.readUInt16LE(pos); pos += 2;
      } else if (type === 0x09) {    // UINT8
        value = buf.readUInt8(pos++);
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
        break;
      }

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

    if (fileSize == null) return out;
    let gapBytes = 0;
    for (const idx in gapStarts) {
      if (gapEnds[idx] != null && gapEnds[idx] >= gapStarts[idx]) {
        gapBytes += (gapEnds[idx] - gapStarts[idx]);
      }
    }
    out.fileSize   = fileSize;
    out.downloaded = Math.max(0, fileSize - gapBytes);
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
          const totalSize       = met.fileSize   != null ? met.fileSize    : stat.size;
          const downloadedBytes = met.downloaded != null ? met.downloaded  : stat.size;
          const downloadedMB    = Math.round(downloadedBytes / (1024 * 1024));
          const totalMB         = Math.round(totalSize       / (1024 * 1024));
          // Backward-compat: `sizeMB`/`sizeBytes` keep meaning "logical size"
          // (what stat returns) so existing code that uses them for display
          // doesn't change. New fields totalMB/downloadedMB/downloadedBytes
          // are what the monitor should gate on.
          downloads.push({
            partFile: pf, fileName, fileHash,
            sizeMB: Math.round(stat.size / (1024 * 1024)), sizeBytes: stat.size,
            totalMB, totalBytes: totalSize,
            downloadedMB, downloadedBytes,
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
