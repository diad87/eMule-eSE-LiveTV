// init.js — parámetros URL, banner "Continuar viendo", logo SVG, favicon, filterCategory

// ── Parámetros URL (redirect desde /search) ────────────────────────────────────
(function() {
  var params = new URLSearchParams(window.location.search);
  var detailId = params.get('detail');
  var searchQuery = params.get('search');
  var localizedTitle = params.get('ltitle');
  if (detailId) {
    setTimeout(function() { showMovieDetail(detailId, null, localizedTitle); }, 800);
    history.replaceState(null, '', '/');
  } else if (searchQuery) {
    setTimeout(function() {
      var input = document.getElementById('search-input');
      if (input) { input.value = searchQuery; searchEd2k(); }
    }, 800);
    history.replaceState(null, '', '/');
  }
})();

// ── "Continuar viendo" — banner al cargar la página ───────────────────────────
(function() {
  var session = getWatchSession();
  if (!session || !session.fileName) return;

  Promise.all([
    fetch('/api/stream/completed/list').then(function(r){return r.json();}).catch(function(){return [];}),
    fetch('/api/emule/downloads').then(function(r){return r.json();}).catch(function(){return [];})
  ]).then(function(results) {
    var completed = results[0];
    var downloads = results[1];
    var found = null;
    var source = null;

    if (completed) {
      for (var i = 0; i < completed.length; i++) {
        if (completed[i].fileName === session.fileName) {
          found = completed[i]; source = 'completed'; break;
        }
      }
    }

    if (!found && downloads) {
      for (var j = 0; j < downloads.length; j++) {
        if (downloads[j].fileName === session.fileName) {
          found = downloads[j]; source = 'downloading'; break;
        }
      }
    }

    if (!found) { clearWatchSession(); return; }

    var sizeMB = found.sizeMB || Math.round((found.sizeBytes || 0) / (1024 * 1024));
    var posMin = Math.floor(session.position / 60);
    var posSec = session.position % 60;
    var posText = session.position > 0 ? posMin + ':' + String(posSec).padStart(2, '0') : '';
    var movieName = session.fileName.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm)$/i, '').replace(/\./g, ' ');

    var banner = document.createElement('div');
    banner.id = 'continue-banner';
    banner.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:500;background:linear-gradient(135deg,rgba(22,22,30,.97),rgba(30,20,40,.97));border:1px solid rgba(255,107,53,.4);border-radius:16px;padding:16px 24px;display:flex;align-items:center;gap:16px;max-width:600px;width:calc(100% - 40px);backdrop-filter:blur(20px);box-shadow:0 8px 32px rgba(0,0,0,.6);animation:slideUp .4s ease';

    var style = document.createElement('style');
    style.textContent = '@keyframes slideUp{from{transform:translateX(-50%) translateY(100px);opacity:0}to{transform:translateX(-50%) translateY(0);opacity:1}}';
    document.head.appendChild(style);

    banner.innerHTML = '<div style="flex:1;min-width:0"><div style="font-size:14px;color:#ff6b35;font-weight:700;margin-bottom:4px">▶ Seguir viendo</div>' +
      '<div style="font-size:13px;color:#fff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + escapeHTML(movieName) + '</div>' +
      '<div style="font-size:11px;color:#888;margin-top:2px">' + escapeHTML(String(sizeMB)) + ' MB' + (posText ? ' · ' + escapeHTML(posText) : '') + (source === 'downloading' ? ' · Descargando...' : ' · Descargado') + '</div></div>' +
      '<button id="continue-play-btn" style="background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:700;font-size:14px;white-space:nowrap">▶ Continuar</button>' +
      '<button onclick="document.getElementById(\'continue-banner\').remove();clearWatchSession()" style="background:none;border:none;color:#555;font-size:20px;cursor:pointer;padding:4px">×</button>';

    document.body.appendChild(banner);

    document.getElementById('continue-play-btn').onclick = function() {
      banner.remove();
      var seekPos = session.position || 0;
      var old = document.getElementById('movie-modal');
      if (old) old.remove();
      var modal = document.createElement('div');
      modal.id = 'movie-modal';
      modal.className = 'movie-modal active';
      modal.innerHTML = '<button class="modal-close" onclick="closeMovieModal()">&times;</button>' +
        '<div id="modal-player-zone"></div>' +
        '<div id="modal-info-zone" style="display:none"></div>';
      document.body.appendChild(modal);
      document.body.style.overflow = 'hidden';
      modal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
      document.addEventListener('keydown', modal._keyHandler);

      playInModal(encodeURIComponent(session.fileName));
      if (seekPos > 10) {
        setTimeout(function() {
          window._cinemaSeekOffset = seekPos;
          var q = document.getElementById('cinema-quality');
          var quality = q ? q.value : 'auto';
          startCompletedMSE(session.fileName, quality, seekPos);
        }, 2000);
      }
    };
  });
})();

// ── Logo SVG, favicon y filterCategory ────────────────────────────────────────
(function() {
  // 1. Logo eMule SVG (official mascot, served as static file)
  var logoLink = document.querySelector('.logo');
  if (logoLink && logoLink.textContent.trim().indexOf('eSE') !== -1) {
    var img = document.createElement('img');
    img.src = '/emule_mascot.svg';
    img.alt = 'eMule';
    img.width = 32;
    img.height = 32;
    img.style.cssText = 'margin-right:8px;vertical-align:middle;object-fit:contain;';
    logoLink.insertBefore(img, logoLink.firstChild);
  }

  // 2. Favicon (official eMule mascot SVG)
  var existingFavicon = document.querySelector('link[rel="icon"]');
  if (existingFavicon) existingFavicon.remove();
  var link = document.createElement('link');
  link.rel = 'icon';
  link.type = 'image/svg+xml';
  link.href = '/emule_mascot.svg';
  document.head.appendChild(link);

  // 3. Search Overlay — toggle, debounced TMDB suggestions, Enter → eMule search
  var _soTimer = null;

  window.toggleSearchOverlay = function() {
    var overlay = document.getElementById('search-overlay');
    if (!overlay) return;
    if (overlay.classList.contains('active')) {
      overlay.classList.remove('active');
      document.body.style.overflow = '';
    } else {
      overlay.classList.add('active');
      document.body.style.overflow = 'hidden';
      var input = document.getElementById('search-overlay-input');
      if (input) { input.value = ''; input.focus(); }
      var results = document.getElementById('search-overlay-results');
      if (results) results.innerHTML = '';
    }
  };

  window.onSearchOverlayInput = function(e) {
    var q = e.target.value.trim();
    var c = document.getElementById('search-overlay-results');
    if (!c) return;
    if (q.length < 2) { c.innerHTML = ''; return; }
    clearTimeout(_soTimer);
    _soTimer = setTimeout(function() {
      fetch('/api/movies/search?q=' + encodeURIComponent(q))
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (!data.Search || !data.Search.length) {
            c.innerHTML = '<div style="color:#555;text-align:center;padding:32px">Sin sugerencias para &quot;' + escapeHTML(q) + '&quot;</div>';
            return;
          }
          c.innerHTML = data.Search.slice(0, 8).map(function(m) {
            var poster = sanitizeURL((m.Poster && m.Poster !== 'N/A') ? m.Poster : '');
            var safe = escapeAttr(m.Title || '');
            var imdb = escapeAttr(m.imdbID || '');
            return '<div class="search-suggestion" onclick="toggleSearchOverlay();showMovieDetail(\'' + imdb + '\',null,\'' + safe + '\')">' +
              (poster
                ? '<img src="' + escapeHTML(poster) + '" alt="" loading="lazy">'
                : '<div style="width:45px;height:67px;background:#1a1a2e;border-radius:6px;flex-shrink:0"></div>') +
              '<div class="search-suggestion-info">' +
                '<div class="search-suggestion-title">' + escapeHTML(m.Title || '') + '</div>' +
                '<div class="search-suggestion-meta">' + escapeHTML(m.Year || '') + ' \u00b7 ' + escapeHTML(m.Type || '') + '</div>' +
              '</div></div>';
          }).join('');
        })
        .catch(function() {
          c.innerHTML = '<div style="color:#e74c3c;text-align:center;padding:20px">Error de conexi\u00f3n</div>';
        });
    }, 400);
  };

  window.onSearchOverlayKeydown = function(e) {
    if (e.key === 'Escape') { toggleSearchOverlay(); return; }
    if (e.key === 'Enter') {
      e.preventDefault();
      var q = e.target.value.trim();
      if (q.length < 2) return;
      toggleSearchOverlay();
      // Use existing search infrastructure
      var searchInput = document.getElementById('search-input');
      if (searchInput) {
        searchInput.value = q;
        if (typeof searchEd2k === 'function') searchEd2k();
        var resultsSection = document.getElementById('search-results');
        if (resultsSection) resultsSection.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  // Close overlay on click outside content
  document.addEventListener('click', function(e) {
    var overlay = document.getElementById('search-overlay');
    if (overlay && overlay.classList.contains('active') && e.target === overlay) {
      toggleSearchOverlay();
    }
  });

  // Keyboard shortcut: Ctrl+K or / to open search
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey && e.key === 'k') || (e.key === '/' && !e.target.closest('input, textarea, select'))) {
      e.preventDefault();
      toggleSearchOverlay();
    }
  });
})();

// ── Mi Lista — localStorage persistence ────────────────────────────────────────
(function() {
  var STORAGE_KEY = 'ese_mylist';

  window.getMyList = function() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
    catch(e) { return []; }
  };

  window.addToMyList = function(item) {
    if (!item || !item.imdbId) return;
    var list = getMyList();
    if (list.some(function(x) { return x.imdbId === item.imdbId; })) return;
    item.addedAt = Date.now();
    list.unshift(item);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  };

  window.removeFromMyList = function(imdbId) {
    var list = getMyList().filter(function(x) { return x.imdbId !== imdbId; });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
  };

  window.isInMyList = function(imdbId) {
    return getMyList().some(function(x) { return x.imdbId === imdbId; });
  };

  window.toggleMyList = function(imdbId, title, poster, year, type) {
    if (isInMyList(imdbId)) {
      removeFromMyList(imdbId);
      showNotification('\u2716 Eliminado de Mi Lista');
      return false;
    } else {
      addToMyList({ imdbId: imdbId, title: title, poster: poster, year: year, type: type || 'movie' });
      showNotification('\u2714 A\u00f1adido a Mi Lista');
      return true;
    }
  };

  // toggleMyListBtn \u2014 called by the "Mi Lista" button rendered inside the
  // movie-detail modal (see search_ui.js renderMovieCard / showMovieDetail).
  // Previously only existed in the legacy player.js monolith, NOT in the
  // modular bundle that users actually run. The inline onclick was therefore
  // throwing ReferenceError and the button did nothing.
  window.toggleMyListBtn = function(btn) {
    var m = window._modalMovie;
    if (!m) return;
    var added = (typeof toggleMyList === 'function')
      && toggleMyList(m.imdbId, m.title, m.poster, m.year);
    var listIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
      + 'stroke="currentColor" stroke-width="2" style="margin-right:6px;'
      + 'vertical-align:-2px"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 '
      + '0 0 1 2 2z"></path></svg>';
    if (added) {
      btn.classList.add('btn-list-active');
      btn.innerHTML = listIcon + ' Quitar de Mi Lista';
    } else {
      btn.classList.remove('btn-list-active');
      btn.innerHTML = listIcon + ' Mi Lista';
    }
  };
})();

// ── NAT Health Reactive Alert ─────────────────────────────────────────────────
(function() {
  var NAT_POLL_INTERVAL = 30000;  // 30s
  var NAT_MIN_ATTEMPTS  = 10;    // Don't alert until enough data
  var NAT_THRESHOLD     = 0.30;  // Alert when success rate < 30%
  var DISMISS_KEY       = 'ese_nat_alert_dismissed';

  function checkNatHealth() {
    if (sessionStorage.getItem(DISMISS_KEY)) return;

    fetch('/api/nat-health')
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        if (!data || data.error) return;

        var attempts = data.hole_punch_attempts || 0;
        var success  = data.hole_punch_success  || 0;
        var rate     = attempts > 0 ? success / attempts : 1;

        var existing = document.getElementById('nat-alert-banner');

        // Remove banner if health recovered
        if (attempts < NAT_MIN_ATTEMPTS || rate >= NAT_THRESHOLD) {
          if (existing) existing.remove();
          return;
        }

        // Already showing
        if (existing) return;

        var pct = Math.round(rate * 100);
        var upnpFwd = data.upnp_ports_forwarded || 'unknown';

        // Determine contextual advice based on UPnP state
        var advice, actionHtml;
        if (upnpFwd === 'false' || upnpFwd === 'unknown') {
          // UPnP not forwarding — suggest enabling it
          advice = 'UPnP no está redirigiendo puertos. Actívalo en Opciones > Conexión o configura <b>port forwarding</b> manual.';
          actionHtml =
            '<a href="/?cat=options&tab=connection" style="' +
              'display:inline-block;margin-top:8px;padding:6px 16px;border-radius:6px;' +
              'background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;font-size:11px;' +
              'font-weight:700;text-decoration:none;transition:all .2s' +
            '">⚡ Activar UPnP</a>';
        } else {
          // UPnP IS forwarding but still failing — likely CGNAT or symmetric NAT
          advice = 'UPnP activo pero NAT simétrico detectado. Considera cambiar de red o contactar a tu ISP.';
          actionHtml = '';
        }

        var banner = document.createElement('div');
        banner.id = 'nat-alert-banner';
        banner.style.cssText =
          'position:fixed;top:72px;left:50%;transform:translateX(-50%);z-index:450;' +
          'max-width:680px;width:calc(100% - 32px);' +
          'background:linear-gradient(135deg,rgba(40,30,10,.96),rgba(50,35,15,.96));' +
          'border:1px solid rgba(255,180,50,.4);border-radius:12px;' +
          'padding:14px 20px;display:flex;align-items:flex-start;gap:14px;' +
          'backdrop-filter:blur(16px);box-shadow:0 6px 24px rgba(0,0,0,.5);' +
          'animation:natSlideDown .4s ease;font-family:Inter,system-ui,sans-serif';

        // Inject animation keyframes once
        if (!document.getElementById('nat-alert-style')) {
          var style = document.createElement('style');
          style.id = 'nat-alert-style';
          style.textContent =
            '@keyframes natSlideDown{from{transform:translateX(-50%) translateY(-40px);opacity:0}' +
            'to{transform:translateX(-50%) translateY(0);opacity:1}}';
          document.head.appendChild(style);
        }

        banner.innerHTML =
          '<div style="font-size:22px;flex-shrink:0;margin-top:2px">⚠️</div>' +
          '<div style="flex:1;min-width:0">' +
            '<div style="font-size:13px;font-weight:700;color:#ffb432;margin-bottom:3px">' +
              'Conectividad NAT degradada (' + pct + '% \u00e9xito)' +
            '</div>' +
            '<div style="font-size:11px;color:#b89860;line-height:1.4">' +
              attempts + ' intentos hole-punch, solo ' + success + ' exitosos. ' +
              advice +
            '</div>' +
            actionHtml +
          '</div>' +
          '<button id="nat-alert-dismiss" style="' +
            'background:none;border:none;color:#886;font-size:18px;cursor:pointer;' +
            'padding:4px 8px;flex-shrink:0;transition:color .2s' +
          '">\u00d7</button>';

        document.body.appendChild(banner);

        document.getElementById('nat-alert-dismiss').onclick = function() {
          banner.remove();
          sessionStorage.setItem(DISMISS_KEY, '1');
        };
      })
      .catch(function() { /* backend offline, silent */ });
  }

  // Initial check after 8s (let page settle), then every 30s
  setTimeout(checkNatHealth, 8000);
  setInterval(checkNatHealth, NAT_POLL_INTERVAL);
})();
