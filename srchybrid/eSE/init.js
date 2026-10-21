// init.js — parámetros URL, banner "Continuar viendo", logo SVG, favicon, filterCategory

// ── Parámetros URL (redirect desde /search) ────────────────────────────────────
(function() {
  var params = new URLSearchParams(window.location.search);
  var detailId = params.get('detail');
  var searchQuery = params.get('search');
  var playName = params.get('play');
  var localizedTitle = params.get('ltitle') || params.get('title');
  var returnTo = params.get('returnTo');
  // Only known catalog pages are valid return destinations; never remote URLs.
  if ((detailId || searchQuery || playName) && returnTo && /^\/(explore|search|mylist)(\?[^#\r\n]*)?$/.test(returnTo)) {
    window._detailReturnTo = returnTo;
  }
  if (detailId) {
    setTimeout(function() { showMovieDetail(detailId, null, localizedTitle); }, 800);
    history.replaceState(null, '', '/');
  } else if (searchQuery) {
    window.location.replace('/search?q=' + encodeURIComponent(searchQuery));
  } else if (playName) {
    setTimeout(function() { playCompleted(encodeURIComponent(playName)); }, 0);
    history.replaceState(null, '', '/');
  }
  if (params.get('settings') === '1') setTimeout(function() { toggleSettings(); }, 0);
})();

// ── "Continuar viendo" — contexto de la biblioteca, sin tapar la página ──────
(function() {
  var slot = document.getElementById('home-resume-slot');
  var session = getWatchSession();
  if (!slot || !session || typeof session.fileName !== 'string' || !session.fileName) return;

  function readLibrary(url) {
    return fetch(url).then(function(r) {
      if (!r.ok) throw new Error('library unavailable');
      return r.json();
    }).then(function(files) {
      if (!Array.isArray(files)) throw new Error('invalid library');
      return files;
    }).catch(function() { return null; });
  }

  Promise.all([
    readLibrary('/api/stream/completed/list'),
    readLibrary('/api/emule/downloads')
  ]).then(function(results) {
    var completed = results[0];
    var downloads = results[1];
    var match = function(file) { return file && file.fileName === session.fileName; };
    var found = completed && completed.find(match);
    var source = found ? 'completed' : 'downloading';
    if (!found && downloads) found = downloads.find(match);
    // A failed request is unknown availability, never evidence to erase history.
    if (!found) return;

    var seekPos = Number.isFinite(Number(session.position)) ? Math.max(0, Math.floor(Number(session.position))) : 0;
    var posText = Math.floor(seekPos / 60) + ':' + String(seekPos % 60).padStart(2, '0');
    var movieName = session.fileName.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm)$/i, '').replace(/\./g, ' ');
    var banner = document.createElement('section');
    banner.id = 'continue-banner';
    banner.className = 'resume-card';
    banner.setAttribute('aria-label', 'Seguir viendo');
    banner.innerHTML = '<div class="resume-copy"><p>SEGUIR VIENDO</p><h2>' + escapeHTML(movieName) + '</h2>' +
      '<span>' + (seekPos ? 'Última posición: ' + escapeHTML(posText) + ' · ' : '') +
      (source === 'completed' ? 'En tu biblioteca' : 'Descarga en curso · Según los datos disponibles') + '</span></div>' +
      '<button type="button" id="continue-play-btn" class="resume-play">Continuar</button>' +
      '<button type="button" id="continue-dismiss-btn" class="resume-dismiss" aria-label="Ocultar Seguir viendo">&times;</button>';
    slot.appendChild(banner);

    document.getElementById('continue-dismiss-btn').onclick = function() {
      try { clearWatchSession(); } catch (_) {}
      banner.remove();
      var destination = document.getElementById('library-title');
      if (destination) { destination.setAttribute('tabindex', '-1'); destination.focus({ preventScroll: true }); }
    };
    document.getElementById('continue-play-btn').onclick = function() {
      var old = document.getElementById('movie-modal');
      if (old && typeof closeMovieModal === 'function') closeMovieModal();
      var modal = document.createElement('div');
      modal.id = 'movie-modal';
      modal.className = 'movie-modal active';
      modal._previousOverflow = document.body.style.overflow || '';
      modal.innerHTML = '<button type="button" class="modal-close" aria-label="Cerrar reproducción" onclick="closeMovieModal()">&times;</button>' +
        '<div id="modal-player-zone"></div><div id="modal-info-zone" style="display:none"></div>';
      document.body.appendChild(modal);
      document.body.style.overflow = 'hidden';
      modal._keyHandler = function(e) { if (e.key === 'Escape') closeMovieModal(); };
      document.addEventListener('keydown', modal._keyHandler);

      if (source === 'completed') playInModal(encodeURIComponent(session.fileName), seekPos);
      else playPartFile(found.partFile, session.fileName, seekPos);
    };
  });
})();

// ── Logo SVG, favicon y filterCategory ────────────────────────────────────────
(function() {
  // 1. Logo eMule SVG (official mascot, served as static file)
  var logoLink = document.querySelector('.logo');
  if (logoLink && !logoLink.querySelector('img') && logoLink.textContent.trim().indexOf('eSE') !== -1) {
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

  // The page route is the single catalog search entry, including shortcuts.
  window.toggleSearchOverlay = function() { window.location.href = '/search'; };
  document.addEventListener('keydown', function(e) {
    if (e.target && e.target.closest('input, textarea, select, [contenteditable="true"], [role="dialog"]')) return;
    if ((e.ctrlKey && e.key.toLowerCase() === 'k') || e.key === '/') {
      e.preventDefault();
      toggleSearchOverlay();
    }
  });
})();

// ── Mi Lista — localStorage persistence ────────────────────────────────────────
(function() {
  var STORAGE_KEY = 'ese_mylist';

  function readList() {
    try {
      var list = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
      if (!Array.isArray(list) || list.some(function(item) {
        return !item || typeof item !== 'object' || typeof item.imdbId !== 'string' || !item.imdbId;
      })) return null;
      return list;
    } catch (_) { return null; }
  }

  function writeList(list) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(list)); return true; }
    catch (_) {
      showNotification('No se ha podido guardar el cambio. Comprueba el espacio y los permisos del navegador.');
      return false;
    }
  }

  function editableList() {
    var list = readList();
    if (!list) showNotification('No se pueden leer tus títulos guardados. Los datos se han conservado.');
    return list;
  }

  window.getMyList = function() {
    return readList() || [];
  };

  window.addToMyList = function(item) {
    if (!item || typeof item.imdbId !== 'string' || !item.imdbId) return false;
    var list = editableList();
    if (!list) return false;
    if (list.some(function(x) { return x.imdbId === item.imdbId; })) return true;
    list.unshift(Object.assign({}, item, { addedAt: Date.now() }));
    return writeList(list);
  };

  window.removeFromMyList = function(imdbId) {
    var list = editableList();
    if (!list) return false;
    return writeList(list.filter(function(x) { return x.imdbId !== imdbId; }));
  };

  window.isInMyList = function(imdbId) {
    return getMyList().some(function(x) { return x.imdbId === imdbId; });
  };

  window.toggleMyList = function(imdbId, title, poster, year, type) {
    if (isInMyList(imdbId)) {
      if (!removeFromMyList(imdbId)) return null;
      showNotification('Título quitado de Guardados.');
      return false;
    } else {
      if (!addToMyList({ imdbId: imdbId, title: title, poster: poster, year: year, type: type || 'movie' })) return null;
      showNotification('Título guardado en Biblioteca.');
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
      && toggleMyList(m.imdbId, m.title, m.poster, m.year, m.type);
    if (added === null) return;
    btn.setAttribute('aria-pressed', String(added));
    btn.setAttribute('aria-label', added ? 'Guardado. Quitar de Guardados' : 'Guardar en Biblioteca');
    btn.setAttribute('title', added ? 'Quitar de Guardados' : 'Guardar en Biblioteca');
    var listIcon = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" '
      + 'stroke="currentColor" stroke-width="2" style="margin-right:6px;'
      + 'vertical-align:-2px"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 '
      + '0 0 1 2 2z"></path></svg>';
    if (added) {
      btn.classList.add('btn-list-active');
      btn.innerHTML = listIcon + ' Guardado';
    } else {
      btn.classList.remove('btn-list-active');
      btn.innerHTML = listIcon + ' Guardar';
    }
  };
})();

// Movie dialogs are created by several playback/detail entry points.
// Keep their keyboard behavior consistent without changing media handlers.
(function() {
  if (typeof MutationObserver === 'undefined') return;
  var activeModal = null;
  var returnFocus = null;
  var focusableSelector = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

  function controls() {
    return Array.prototype.filter.call(activeModal.querySelectorAll(focusableSelector), function(el) {
      return el.tabIndex >= 0 && !el.hidden && el.getClientRects().length > 0;
    });
  }

  function focusFirst() {
    var items = controls();
    (items[0] || activeModal).focus({ preventScroll: true });
  }

  function syncModal() {
    var modal = document.getElementById('movie-modal');
    if (modal && modal.inert) return;
    if (!modal) {
      if (activeModal) {
        activeModal = null;
        if (returnFocus && returnFocus.isConnected) returnFocus.focus({ preventScroll: true });
        returnFocus = null;
      }
      return;
    }
    if (modal !== activeModal) {
      if (!activeModal) returnFocus = document.activeElement;
      activeModal = modal;
      modal.setAttribute('role', 'dialog');
      modal.setAttribute('aria-modal', 'true');
      modal.setAttribute('tabindex', '-1');
    }
    var title = modal.querySelector('.modal-title');
    if (title) {
      if (!title.id) title.id = 'movie-modal-title';
      modal.setAttribute('aria-labelledby', title.id);
      modal.removeAttribute('aria-label');
    } else {
      modal.removeAttribute('aria-labelledby');
      modal.setAttribute('aria-label', 'Película y reproducción');
    }
    // Detail loading replaces innerHTML, including the focused close button.
    if (!modal.contains(document.activeElement)) focusFirst();
  }

  document.addEventListener('keydown', function(event) {
    if (event.key !== 'Tab' || !activeModal || !activeModal.isConnected || activeModal.inert) return;
    var items = controls();
    var first = items[0];
    var last = items[items.length - 1];
    if (!first) {
      event.preventDefault();
      activeModal.focus({ preventScroll: true });
    } else if (!activeModal.contains(document.activeElement) || document.activeElement === activeModal) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  new MutationObserver(syncModal).observe(document.body, { childList: true, subtree: true });
  syncModal();
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
