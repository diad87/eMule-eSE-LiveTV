// smart_play.js — smartPlay, trySmartSource, monitorForFile

// ── Smart Play: evalúa → decide → actúa ───────────────────────────────────────
function smartPlay(movieTitle, movieYear) {
  var playerZone = document.getElementById('modal-player-zone');
  var infoZone = document.getElementById('modal-info-zone');
  if (!playerZone) return;

  if (infoZone) infoZone.style.display = 'none';
  playerZone.style.display = 'block';

  playerZone.innerHTML = '<div class="modal-player" id="cinema-player">' +
    '<div class="modal-player-header">' +
      '<button class="cinema-back-btn" onclick="backToDetail()">&larr; Volver</button>' +
    '</div>' +
    '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;gap:20px">' +
      '<div class="spinner" style="width:60px;height:60px;border-width:4px"></div>' +
      '<h2 style="color:#fff;font-size:24px;font-weight:600" id="smart-play-title">Evaluando disponibilidad...</h2>' +
      '<p style="color:#888;font-size:14px;text-align:center;max-width:400px" id="smart-play-status">Comprobando archivos locales y red eMule</p>' +
      '<div style="width:300px;height:4px;background:#222;border-radius:2px;overflow:hidden;margin-top:8px">' +
        '<div id="smart-play-progress" style="width:5%;height:100%;background:linear-gradient(90deg,#ff6b35,#ff2d78);transition:width .5s;border-radius:2px"></div>' +
      '</div>' +
      '<div id="smart-play-actions" style="display:none;flex-direction:column;gap:10px;margin-top:16px;align-items:center"></div>' +
    '</div>' +
  '</div>';

  var closeBtn = document.querySelector('.modal-close');
  if (closeBtn) closeBtn.style.display = 'none';
  var modal = document.getElementById('movie-modal');
  if (modal) modal.style.overflow = 'hidden';

  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var titleEl = document.getElementById('smart-play-title');
  var actionsEl = document.getElementById('smart-play-actions');

  function updateStatus(msg, pct) {
    if (statusEl) statusEl.textContent = msg;
    if (progressEl && pct >= 0) progressEl.style.width = pct + '%';
  }

  function hideSpinner() {
    var spinner = playerZone.querySelector('.spinner');
    if (spinner) spinner.style.display = 'none';
  }

  function showActions(buttons) {
    if (!actionsEl) return;
    actionsEl.innerHTML = '';
    actionsEl.style.display = 'flex';
    buttons.forEach(function(b) {
      var btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = b.primary
        ? 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:220px'
        : 'background:rgba(255,255,255,.08);border:1px solid #333;color:#aaa;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;min-width:220px';
      btn.onclick = b.action;
      actionsEl.appendChild(btn);
    });
  }

  // Store all results for "try another source"
  window._smartPlayResults = [];
  window._smartPlayIndex = 0;
  window._smartPlayTitle = movieTitle;
  window._smartPlayYear = movieYear;

  // Phase 1: Check if file already exists locally
  updateStatus('Comprobando archivos locales...', 10);
  var cleanTitle = movieTitle.replace(/[:\-–—\[\](){}]/g, ' ').replace(/\s+/g, ' ').trim();
  var movieWords = cleanTitle.toLowerCase().split(/\s+/).filter(function(w) { return w.length > 2; });

  function matchTitle(fn) {
    fn = fn.toLowerCase().replace(/[:\-–—\[\](){}]/g, ' ');
    var matchCount = 0;
    movieWords.forEach(function(w) { if (fn.includes(w)) matchCount++; });
    return matchCount >= Math.ceil(movieWords.length * 0.4);
  }

  // v7.4.0 — check lifecycle BEFORE Phase 1 to detect a recent eMule restart.
  // If eMule just woke up, a large .part file from a previous session is
  // still playable even though its `active` flag is false (sources haven't
  // reconnected yet). This stops the player from falling through to a
  // pointless new Phase 2 search when the bytes are already on disk.
  fetch('/api/v1/lifecycle').then(function(r){return r.json();}).catch(function(){return { epoch: 0, restartedAt: 0 };})
    .then(function(lc) {
      var epochChanged = (window._emuleEpoch !== undefined && window._emuleEpoch !== lc.epoch);
      window._emuleEpoch = lc.epoch;
      var justRestarted = epochChanged && (Date.now() - lc.restartedAt < 60000);

      Promise.all([
        fetch('/api/stream/completed/list').then(function(r){return r.json();}).catch(function(){return [];}),
        fetch('/api/emule/downloads').then(function(r){return r.json();}).catch(function(){return [];})
      ]).then(function(results) {
        var completed = results[0] || [];
        var downloads = results[1] || [];

        // Check completed files
        for (var i = 0; i < completed.length; i++) {
          if (matchTitle(completed[i].fileName)) {
            updateStatus('Archivo encontrado: ' + completed[i].fileName, 100);
            if (titleEl) titleEl.textContent = 'Listo para reproducir';
            (function(fn){ setTimeout(function() { playInModal(encodeURIComponent(fn)); }, 1000); })(completed[i].fileName);
            return;
          }
        }

        // .part playable rules:
        //   - actively downloading and >50 MB                → play (live)
        //   - eMule just restarted, file >50 MB              → play (sources will reattach)
        //   - file >300 MB regardless of active state        → play (enough buffered)
        for (var j = 0; j < downloads.length; j++) {
          var dl = downloads[j];
          if (!matchTitle(dl.fileName)) continue;
          var isPlayable = (dl.active && dl.sizeMB > 50) ||
                           (justRestarted && dl.sizeMB > 50) ||
                           (dl.sizeMB > 300);
          if (isPlayable) {
            var msg = justRestarted
              ? 'eMule acaba de reiniciar — usando descarga existente'
              : (dl.active ? 'Descarga en progreso' : 'Reanudando descarga existente');
            updateStatus(msg + ': ' + dl.fileName + ' (' + dl.sizeMB + ' MB)', 80);
            if (titleEl) titleEl.textContent = justRestarted ? 'Reanudando' : 'Datos disponibles';
            (function(pf, fn){ setTimeout(function() { playPartFile(pf, fn); }, 2000); })(dl.partFile, dl.fileName);
            return;
          }
        }

    // Phase 2: Search eMule
    updateStatus('Buscando fuentes en la red eMule...', 20);
    if (titleEl) titleEl.textContent = 'Evaluando disponibilidad...';

    fetch('/api/emule/smartsearch?q=' + encodeURIComponent(movieTitle) + (movieYear ? '&year=' + movieYear : ''))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (!data.success) {
          hideSpinner();
          if (titleEl) titleEl.textContent = 'Error de conexion';
          updateStatus(data.error || 'No se pudo conectar a eMule', 0);

          var actions = [];
          if (data.reason === 'webserver_down') {
            actions.push({ text: 'He abierto eMule', primary: true, action: function() {
              updateStatus('Reintentando...', 10);
              setTimeout(function() { smartPlay(movieTitle, movieYear); }, 500);
            }});
          } else if (data.reason === 'password_mismatch') {
            actions.push({ text: 'Resincronizar', primary: true, action: function() {
              updateStatus('Resincronizando con eMule...', 10);
              fetch('/api/emule/resync', { method: 'POST' })
                .then(function(r) { return r.json(); })
                .then(function(d) {
                  if (d.success) smartPlay(movieTitle, movieYear);
                  else updateStatus('No se pudo resincronizar: ' + (d.error || ''), 0);
                });
            }});
          }
          actions.push({ text: 'Reintentar', primary: actions.length === 0, action: function() { smartPlay(movieTitle, movieYear); } });
          actions.push({ text: 'Volver', primary: false, action: backToDetail });
          showActions(actions);
          return;
        }

        if (!data.results || data.results.length === 0) {
          hideSpinner();
          var filteredMsg = data.fakesFiltered > 0
            ? data.totalFound + ' resultado(s), pero ' + data.fakesFiltered + ' descartado(s) como fake'
            : 'No se encontraron fuentes para esta pelicula';
          if (titleEl) titleEl.textContent = 'Sin fuentes disponibles';
          updateStatus(filteredMsg, 0);
          showActions([
            { text: 'Busqueda avanzada', primary: true, action: function() { backToDetail(); startEmuleSearch(movieTitle, movieYear); } },
            { text: 'Volver', primary: false, action: backToDetail }
          ]);
          return;
        }

        window._smartPlayResults = data.results;
        window._smartPlayIndex = 0;
        // v7.4.0 — only auto-pick when there's a single candidate. With >1
        // result we show a picker so the user owns the quality/language/size
        // trade-off instead of being silently routed to whatever scored best.
        if (data.results.length === 1) {
          trySmartSource(0);
        } else {
          showSourcePicker(data.results);
        }
      })
      .catch(function(err) {
        hideSpinner();
        if (titleEl) titleEl.textContent = 'Error';
        updateStatus('Error: ' + err.message, 0);
        showActions([{ text: 'Volver', primary: true, action: backToDetail }]);
      });
      });
    });
}

// ── Source picker (v7.4.0) ─────────────────────────────────────────────────
// Shown when smart-search returns >1 candidate. Lists up to 12 results
// (sorted by score) as clickable cards so the user picks the version
// (quality / language / file size / availability) they actually want.
function showSourcePicker(results) {
  var titleEl   = document.getElementById('smart-play-title');
  var statusEl  = document.getElementById('smart-play-status');
  var actionsEl = document.getElementById('smart-play-actions');
  var spinner   = document.querySelector('#cinema-player .spinner');
  if (spinner) spinner.style.display = 'none';
  if (titleEl)  titleEl.textContent  = 'Elige versión';
  if (statusEl) statusEl.textContent = results.length + ' fuentes disponibles — ordenadas por mejor coincidencia';
  if (!actionsEl) return;
  actionsEl.innerHTML = '';
  actionsEl.style.display = 'flex';
  actionsEl.style.flexDirection = 'column';
  actionsEl.style.gap = '8px';
  actionsEl.style.maxHeight = '60vh';
  actionsEl.style.overflowY = 'auto';
  actionsEl.style.alignItems = 'center';

  results.slice(0, 12).forEach(function(r, idx) {
    var btn = document.createElement('button');
    btn.style.cssText =
      'display:flex;flex-direction:column;align-items:flex-start;' +
      'background:rgba(255,255,255,.05);border:1px solid #333;' +
      'border-radius:8px;padding:12px 16px;color:#fff;cursor:pointer;' +
      'text-align:left;width:420px;transition:background .2s';
    btn.onmouseover = function() { btn.style.background = 'rgba(255,107,53,.15)'; };
    btn.onmouseout  = function() { btn.style.background = 'rgba(255,255,255,.05)'; };
    var shortName = r.fileName && r.fileName.length > 70 ? r.fileName.substring(0, 67) + '…' : (r.fileName || 'sin nombre');
    var sourceColor = (r.completeSources || 0) > 5 ? '#4caf50' : ((r.completeSources || 0) > 0 ? '#ff6b35' : '#888');
    btn.innerHTML =
      '<div style="font-size:13px;font-weight:600;margin-bottom:6px">' + escapeHTML(shortName) + '</div>' +
      '<div style="font-size:11px;color:#aaa;display:flex;gap:12px;flex-wrap:wrap">' +
        '<span><b>' + ((r.quality || '?') + '').toUpperCase() + '</b></span>' +
        '<span>' + ((r.language || '?') + '').toUpperCase() + '</span>' +
        '<span>' + (r.sizeMB || '?') + ' MB</span>' +
        '<span style="color:' + sourceColor + '">●  ' + (r.completeSources || 0) + '/' + (r.sources || 0) + ' fuentes</span>' +
        '<span style="color:#888">score ' + (r.score || 0) + '</span>' +
      '</div>';
    btn.onclick = function() {
      window._smartPlayIndex = idx;
      trySmartSource(idx);
    };
    actionsEl.appendChild(btn);
  });

  var back = document.createElement('button');
  back.textContent = 'Cancelar';
  back.style.cssText = 'background:transparent;border:1px solid #444;color:#888;padding:8px 16px;border-radius:8px;cursor:pointer;margin-top:8px;width:200px';
  back.onclick = backToDetail;
  actionsEl.appendChild(back);
}

// Local HTML-escape fallback (smart_play.js is bundled before escapeHTML is
// defined elsewhere in some load orders).
if (typeof escapeHTML !== 'function') {
  window.escapeHTML = function(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  };
}

// ── Prueba una fuente concreta ────────────────────────────────────────────────
function trySmartSource(index) {
  var results = window._smartPlayResults || [];
  if (index >= results.length) {
    var titleEl = document.getElementById('smart-play-title');
    var statusEl = document.getElementById('smart-play-status');
    var actionsEl = document.getElementById('smart-play-actions');
    var spinner = document.querySelector('#cinema-player .spinner');
    if (spinner) spinner.style.display = 'none';
    if (titleEl) titleEl.textContent = 'Ninguna fuente viable';
    if (statusEl) statusEl.textContent = 'Se probaron ' + results.length + ' fuentes sin exito';
    if (actionsEl) {
      actionsEl.innerHTML = '';
      actionsEl.style.display = 'flex';
      var btn = document.createElement('button');
      btn.textContent = 'Volver a la ficha';
      btn.style.cssText = 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600';
      btn.onclick = backToDetail;
      actionsEl.appendChild(btn);
    }
    return;
  }

  window._smartPlayIndex = index;
  var best = results[index];
  var titleEl = document.getElementById('smart-play-title');
  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var actionsEl = document.getElementById('smart-play-actions');

  var spinner = document.querySelector('#cinema-player .spinner');
  if (spinner) spinner.style.display = 'block';
  if (actionsEl) actionsEl.style.display = 'none';

  if (titleEl) titleEl.textContent = 'Evaluando fuente ' + (index + 1) + '/' + results.length;
  if (statusEl) statusEl.textContent = (best.quality || '?').toUpperCase() + ' | ' + (best.language || '?') + ' | ' + best.sources + '/' + best.completeSources + ' fuentes | Score: ' + best.score;
  if (progressEl) progressEl.style.width = '40%';

  setTimeout(function() {
    if (statusEl) statusEl.textContent = 'Iniciando descarga: ' + best.fileName.substring(0, 50) + '...';
    fetch('/api/emule/download?hash=' + encodeURIComponent(best.hash))
      .then(function(r) { return r.json(); })
      .then(function(dlData) {
        if (dlData.success) {
          if (progressEl) progressEl.style.width = '60%';
          if (titleEl) titleEl.textContent = 'Monitorizando velocidad...';
          // Pass the MD4 hash so monitorForFile binds to THIS download, not a
          // same-titled file already in the library (e.g. user has "a todo gas 1"
          // completed and started "a todo gas 6" — fuzzy-name would play the wrong one).
          monitorForFile(window._smartPlayTitle, best.fileName, best.sizeMB || 0, index, best.hash);
        } else {
          if (statusEl) statusEl.textContent = 'Error al iniciar descarga';
          setTimeout(function() { trySmartSource(index + 1); }, 2000);
        }
      })
      .catch(function() {
        setTimeout(function() { trySmartSource(index + 1); }, 2000);
      });
  }, 1500);
}

// ── Monitoriza la descarga hasta que hay buffer suficiente ────────────────────
// expectedHash (optional): MD4 hex string of the download. When present we
// match by hash, which is exact — fuzzy name matching would otherwise pick a
// pre-existing same-prefix file (e.g. "a todo gas 1" played instead of the
// "a todo gas 6" the user just started).
function monitorForFile(movieTitle, expectedFileName, totalSizeMB, sourceIndex, expectedHash) {
  var statusEl = document.getElementById('smart-play-status');
  var progressEl = document.getElementById('smart-play-progress');
  var titleEl = document.getElementById('smart-play-title');
  var actionsEl = document.getElementById('smart-play-actions');
  var checkCount = 0;
  var hashUpper = (expectedHash || '').toUpperCase();

  function normalize(s) {
    return s.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ').trim();
  }

  var movieWords = normalize(movieTitle).split(' ').filter(function(w) { return w.length > 2; });
  var fileFirstSeen = 0;
  var activeChecks = 0;
  var BUFFER_WAIT_SEC = 15;
  var MAX_EVAL_CHECKS = 24; // 24 × 5s = 2 min max

  function matchDownload(dl) {
    if (hashUpper && dl.fileHash) return (dl.fileHash || '').toUpperCase() === hashUpper;
    return matchTitle(dl.fileName);
  }

  function matchTitle(fn) {
    fn = normalize(fn);
    var matchCount = 0;
    movieWords.forEach(function(w) { if (fn.includes(w)) matchCount++; });
    return matchCount >= Math.max(1, Math.ceil(movieWords.length * 0.3));
  }

  function buildButtons(remaining, onNextSource) {
    var buttons = [];
    if (remaining > 0) {
      buttons.push({ text: 'Probar otra fuente (' + remaining + ' disponibles)', primary: true, action: onNextSource });
    }
    buttons.push({
      text: remaining === 0 ? 'Descargar y avisar cuando este lista' : 'Dejar descargando',
      primary: remaining === 0,
      action: function() { backToDetail(); showNotification('La descarga continua en segundo plano'); }
    });
    buttons.push({ text: 'Volver', primary: false, action: backToDetail });
    return buttons;
  }

  function renderButtons(buttons) {
    if (!actionsEl) return;
    actionsEl.innerHTML = '';
    actionsEl.style.display = 'flex';
    buttons.forEach(function(b) {
      var btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = b.primary
        ? 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:220px'
        : 'background:rgba(255,255,255,.08);border:1px solid #333;color:#aaa;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;min-width:220px';
      btn.onclick = b.action;
      actionsEl.appendChild(btn);
    });
  }

  var checker = setInterval(function() {
    checkCount++;

    // Skip the completed-files lookup when we know the download's hash: a
    // brand-new download by hash cannot be among files that were already in
    // Incoming/ before we started — and if a same-titled file IS there with a
    // different hash, fuzzy-matching it would auto-play the wrong movie
    // (the "a todo gas 1 vs 6" bug).
    var completedScan = hashUpper
      ? Promise.resolve([])
      : fetch('/api/stream/completed/list').then(function(r) { return r.json(); }).catch(function() { return []; });

    completedScan.then(function(files) {
      if (files && files.length) {
        for (var i = 0; i < files.length; i++) {
          if (matchTitle(files[i].fileName)) {
            clearInterval(checker);
            if (progressEl) progressEl.style.width = '100%';
            if (titleEl) titleEl.textContent = 'Listo para reproducir';
            if (statusEl) statusEl.textContent = files[i].fileName;
            setTimeout(function() { playInModal(encodeURIComponent(files[i].fileName)); }, 1500);
            return;
          }
        }
      }

      fetch('/api/emule/downloads').then(function(r2) { return r2.json(); }).then(function(downloads) {
        if (downloads && downloads.length) {
          for (var j = 0; j < downloads.length; j++) {
            var dl = downloads[j];
            if (!matchDownload(dl)) continue;

            var isActive = dl.active;
            if (isActive) {
              if (fileFirstSeen === 0) fileFirstSeen = Date.now();
              activeChecks++;
            } else {
              activeChecks = Math.max(0, activeChecks - 1);
            }

            var waitingSec = fileFirstSeen > 0 ? Math.round((Date.now() - fileFirstSeen) / 1000) : 0;

            if (fileFirstSeen > 0) {
              var bufferPct = Math.min(waitingSec / BUFFER_WAIT_SEC * 100, 100);
              if (progressEl) progressEl.style.width = (60 + bufferPct * 0.4) + '%';
              if (isActive) {
                if (statusEl) statusEl.textContent = 'Recibiendo datos (' + dl.sizeMB + ' MB) | Buffer: ' + waitingSec + '/' + BUFFER_WAIT_SEC + 's';
              } else {
                if (statusEl) statusEl.textContent = 'Archivo detectado, esperando datos...';
              }
              if (titleEl) titleEl.textContent = 'Buffering... (' + Math.round(bufferPct) + '%)';
            }

            if (waitingSec >= BUFFER_WAIT_SEC && activeChecks >= 3) {
              clearInterval(checker);
              if (progressEl) progressEl.style.width = '100%';
              if (titleEl) titleEl.textContent = 'Reproduciendo';
              if (statusEl) statusEl.textContent = 'Buffer listo';
              setTimeout(function() { playPartFile(dl.partFile, dl.fileName); }, 1000);
              return;
            }

            if (checkCount >= MAX_EVAL_CHECKS && activeChecks < 2) {
              clearInterval(checker);
              var sp = document.querySelector('#cinema-player .spinner');
              if (sp) sp.style.display = 'none';
              if (titleEl) titleEl.textContent = 'Velocidad insuficiente';
              if (statusEl) statusEl.textContent = 'La descarga es demasiado lenta para streaming en directo';
              var remaining = (window._smartPlayResults || []).length - (sourceIndex + 1);
              renderButtons(buildButtons(remaining, function() { trySmartSource(sourceIndex + 1); }));
              return;
            }

            return;
          }
        }

        var dots = '.'.repeat((checkCount % 3) + 1);
        if (statusEl) statusEl.textContent = 'Esperando que eMule reciba datos' + dots + ' (' + (checkCount * 5) + 's)';
        if (progressEl) progressEl.style.width = Math.min(60 + checkCount, 75) + '%';

        if (checkCount >= MAX_EVAL_CHECKS) {
          clearInterval(checker);
          var sp2 = document.querySelector('#cinema-player .spinner');
          if (sp2) sp2.style.display = 'none';
          if (titleEl) titleEl.textContent = 'Sin datos recibidos';
          if (statusEl) statusEl.textContent = 'No se recibieron datos de esta fuente';
          var remaining2 = (window._smartPlayResults || []).length - (sourceIndex + 1);
          renderButtons(buildButtons(remaining2, function() { trySmartSource(sourceIndex + 1); }));
        }
      }).catch(function() {});
    }).catch(function() {});
  }, 5000);
}
