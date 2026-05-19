'use strict';
const fs           = require('fs');
const path         = require('path');
const aiAssistant  = require('../ai_assistant');

let _ctx = {};

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
          const metText = fs.readFileSync(metFile).toString('latin1');
          const fnMatch = metText.match(/[^\x00-\x1F\x7F-\x9F]{5,}\.(avi|mkv|mp4|wmv|mov|webm|flv)/i);
          const fileName = fnMatch ? fnMatch[0] : pf;
          const stat = fs.statSync(partPath);
          const isActive = (Date.now() - stat.mtimeMs) < 30000;
          downloads.push({ partFile: pf, fileName, sizeMB: Math.round(stat.size / (1024 * 1024)), sizeBytes: stat.size, partPath, lastModified: stat.mtimeMs, active: isActive });
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

      // CodeQL js/log-injection #62 #63 — strip CR/LF so the user's q can't forge log lines.
      const _safePrimary = String(primaryQuery).replace(/[\r\n\t]+/g, ' ');
      const _safeQ       = String(q).replace(/[\r\n\t]+/g, ' ');
      console.log('[SmartSearch] Primary query: "' + _safePrimary + '" (original: "' + _safeQ + '")');

      // ── Step 1: Generate query variants (AI or heuristic) ───────────────────
      aiAssistant.generateQueryVariants(primaryQuery, settings, (err1, variants) => {
        const queriesToRun = (variants && variants.length > 0) ? variants : [primaryQuery];
        // CodeQL #64 — sanitize each variant for logging (joined to a string by console.log).
        const _safeVariants = queriesToRun.map(v => String(v).replace(/[\r\n\t]+/g, ' '));
        console.log('[SmartSearch] Will run', queriesToRun.length, 'variant(s):', _safeVariants);

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
          // CodeQL #65 — sanitize the variant string before logging.
          const _safeCurrent = String(currentQuery).replace(/[\r\n\t]+/g, ' ');
          console.log('[SmartSearch] Running variant', variantIdx, '/', queriesToRun.length + ': "' + _safeCurrent + '"');

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
