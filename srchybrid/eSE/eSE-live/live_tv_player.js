/**
 * eSE Live — Live TV Player (browser-side script)
 * Viewer-only: status polling, channel filtering, channel join.
 * Served as /live/player.js by channel_api.js.
 *
 * REMOVED (Phase 1.2 + 4):
 *   - initPlayer() + HLS.js loading (no <video> on /live)
 *   - loadSources() + webcam enumeration (viewer-only, no broadcaster)
 *   - startStream() / stopStream() (no broadcaster panel)
 *   - loadEmuleChannels() (duplicated by server-side channel_search)
 */
'use strict';

const directory = require('./live_tv_directory');

function getScript() {
  return `
// eSE Live — Viewer Controls (Phase 4 cleanup)

(function() {
  // --- Shared render helpers (same source as the server render) ---
${directory.clientSource()}

  function announce(text) {
    var status = document.getElementById('directory-status');
    if (status && status.textContent !== text) status.textContent = text;
  }

  function replaceChannels(list, html, featuredHtml) {
    var focused = document.activeElement;
    var featured = document.getElementById('live-featured');
    var card = focused && focused.closest ? focused.closest('.channel-card[data-key], .live-featured-card[data-key]') : null;
    var inFeatured = !!(card && featured && featured.contains && featured.contains(card));
    var key = card && (list.contains(card) || inFeatured) ? card.getAttribute('data-key') : null;
    list.innerHTML = html;
    if (featured) {
      featured.innerHTML = featuredHtml || '';
      featured.hidden = !featuredHtml;
    }
    if (key === null) return;
    var candidates = Array.prototype.slice.call(list.querySelectorAll('.channel-card[data-key]'));
    if (featured && featured.querySelectorAll) candidates = Array.prototype.slice.call(featured.querySelectorAll('.live-featured-card[data-key]')).concat(candidates);
    var replacement = candidates.find(function(el) {
      return el.getAttribute('data-key') === key && !(featured && el.getAttribute('data-featured'));
    });
    var target = replacement || document.getElementById('directory-status');
    if (target) target.focus({ preventScroll: true });
  }

  function fmtDur(secs) {
    var h = Math.floor(secs / 3600);
    var m = Math.floor((secs % 3600) / 60);
    var s = secs % 60;
    if (h > 0) return h + 'h ' + String(m).padStart(2, '0') + 'm';
    return m + 'm ' + String(s).padStart(2, '0') + 's';
  }

  // --- Status polling (detect stream start/stop) ---
  function pollStatus() {
    fetch('/api/live/status')
      .then(function(r) { return r.json(); })
      .then(function(s) {
        var el = document.getElementById('uptime');
        if (el) el.textContent = fmtDur(s.uptime || 0);
        var sc = document.getElementById('seg-count');
        if (sc) sc.textContent = s.segments || 0;
      })
      .catch(function() {});
  }
  setInterval(pollStatus, 5000);
  pollStatus();

  // --- Directory: filter channels ---
  var directoryRequest = 0;
  var directoryPending = false;
  window.filterChannels = function(options) {
    var background = !!(options && options.background);
    if (background && directoryPending) return;
    var list = document.getElementById('channel-list');
    if (!list) return;
    var request = ++directoryRequest;
    directoryPending = true;
    list.setAttribute('aria-busy', 'true');
    var retry = document.getElementById('directory-retry');
    if (!background) announce('Actualizando canales…');
    var q = (document.getElementById('dir-search') || {}).value || '';
    var cat = (document.getElementById('dir-category') || {}).value || 'all';
    var lang = (document.getElementById('dir-lang') || {}).value || 'all';
    var sort = (document.getElementById('dir-sort') || {}).value || 'rating';

    var hasFilters = !!q.trim() || cat !== 'all' || lang !== 'all';
    var reset = document.getElementById('dir-reset');
    if (reset) reset.hidden = !hasFilters;
    var url = '/api/live/channels?q=' + encodeURIComponent(q) +
      '&category=' + encodeURIComponent(cat) + '&lang=' + encodeURIComponent(lang) + '&sort=' + encodeURIComponent(sort);

    return fetch(url)
      .then(function(r) { if (!r.ok) throw new Error('directory unavailable'); return r.json(); })
      .then(function(data) {
        if (request !== directoryRequest) return;
        if (!data || !Array.isArray(data.channels) || data.error) throw new Error('invalid directory');
        if (retry) {
          if (document.activeElement === retry) document.getElementById('directory-status').focus({ preventScroll: true });
          retry.hidden = true;
        }
        var channels = data.channels.filter(function(ch) { return ch && channelHref(ch.streamKey); });
        var empty = document.getElementById('live-empty');
        var emptyTitle = document.getElementById('live-empty-title');
        var emptyText = document.getElementById('live-empty-text');
        if (emptyTitle) emptyTitle.textContent = 'No hay emisiones en directo';
        if (emptyText) emptyText.textContent = 'Los canales aparecerán aquí cuando haya emisiones disponibles.';
        if (empty) empty.style.display = channels.length || hasFilters ? 'none' : '';
        list.style.display = channels.length || hasFilters ? '' : 'none';
        var refreshed = document.getElementById('last-refresh');
        if (refreshed) refreshed.textContent = 'ahora';
        var section = document.getElementById('live-directory');
        var top = hasFilters ? null : pickFeatured(channels);
        // A lone featured channel replaces the grid; anything else shows the grid.
        if (section && section.classList) section.classList.toggle('only-featured', !!top && channels.length === 1);
        if (channels.length === 0) {
          announce(hasFilters ? 'No hay canales con estos filtros.' : 'Sin emisiones disponibles. La lista se actualiza automáticamente.');
          replaceChannels(list, hasFilters ? '<div class="dir-empty"><p>Prueba otro título o limpia los filtros para ver todos los canales.</p></div>' : '', '');
          return;
        }
        announce(channels.length + (channels.length === 1 ? ' canal en directo' : ' canales en directo'));
        var t = Math.floor(Date.now() / 20000);
        var featuredKey = top ? String(top.streamKey || '') : '';
        var html = '<div class="channel-grid">' + channels.map(function(ch) { return renderChannelCard(ch, t, featuredKey); }).join('') + '</div>';
        replaceChannels(list, html, top ? renderFeatured(top, t) : '');
      })
      .catch(function() {
        if (request !== directoryRequest) return;
        announce('No se pueden actualizar los canales. Comprueba la conexión e inténtalo de nuevo.');
        if (retry) retry.hidden = false;
        var empty = document.getElementById('live-empty');
        if (!list.querySelector('.channel-card')) {
          list.style.display = 'none';
          if (empty) empty.style.display = '';
          var title = document.getElementById('live-empty-title');
          var text = document.getElementById('live-empty-text');
          if (title) title.textContent = 'No podemos cargar los canales';
          if (text) text.textContent = 'Puedes reintentar la carga o explorar el catálogo mientras se recupera la conexión.';
        }
      })
      .finally(function() {
        if (request !== directoryRequest) return;
        directoryPending = false;
        list.setAttribute('aria-busy', 'false');
      });
  };

  function syncCategoryChips() {
    var group = document.getElementById('dir-category');
    if (!group || !group.querySelectorAll) return;
    Array.prototype.forEach.call(group.querySelectorAll('[data-category]'), function(chip) {
      chip.setAttribute('aria-pressed', String(chip.getAttribute('data-category') === (group.value || 'all')));
    });
  }
  (function() {
    var group = document.getElementById('dir-category');
    if (group && typeof group.value !== 'string') group.value = 'all';
  })();
  window.setChannelCategory = function(category) {
    var group = document.getElementById('dir-category');
    if (!group || !category) return;
    group.value = category;
    syncCategoryChips();
    return window.filterChannels();
  };

  window.resetChannelFilters = function() {
    if (window.__chDeb) clearTimeout(window.__chDeb);
    ['dir-search', 'dir-category', 'dir-lang', 'dir-sort'].forEach(function(id) {
      var input = document.getElementById(id);
      if (input) input.value = id === 'dir-search' ? '' : id === 'dir-sort' ? 'rating' : 'all';
    });
    syncCategoryChips();
    var search = document.getElementById('dir-search');
    if (search) search.focus();
    return window.filterChannels();
  };

  // --- Directory: join a channel ---
  // BUG-063 + BUG-065 FIX: Strict streamKey validation to prevent XSS/injection
  window.joinChannel = function(streamKey) {
    // Only allow alphanumeric, underscore, and hyphen in streamKey
    var href = channelHref(streamKey);
    if (!href) {
      console.warn('[eSE] Invalid streamKey rejected:', streamKey);
      return;
    }
    window.location.href = href;
  };
})();
`;
}

module.exports = { getScript };
