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

function getScript() {
  return `
// eSE Live — Viewer Controls (Phase 4 cleanup)

(function() {
  // --- Helpers ---
  function escH(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function escAttr(s) {
    return escH(s);
  }

  function escClass(s) {
    return String(s == null ? '' : s).replace(/[^a-zA-Z0-9_-]/g, '');
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
  window.filterChannels = function() {
    var q = (document.getElementById('dir-search') || {}).value || '';
    var cat = (document.getElementById('dir-category') || {}).value || 'all';
    var lang = (document.getElementById('dir-lang') || {}).value || 'all';
    var sort = (document.getElementById('dir-sort') || {}).value || 'rating';

    var url = '/api/live/channels?q=' + encodeURIComponent(q) +
      '&category=' + cat + '&lang=' + lang + '&sort=' + sort;

    fetch(url)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var list = document.getElementById('channel-list');
        if (!list) return;
        if (!data.channels || data.channels.length === 0) {
          list.innerHTML = '<div class="dir-empty"><p>No se encontraron canales</p></div>';
          return;
        }
        var t = Math.floor(Date.now() / 20000);
        var html = '<div class="channel-grid">';
        data.channels.forEach(function(ch) {
          var key = String(ch.streamKey || '');
          var rating = Number(ch.rating || 0);
          var bitrate = Number(ch.bitrate || 0);
          var uptimeMinutes = Math.max(0, Number(ch.uptimeMinutes || 0));
          var quality = escClass(ch.qualityLabel || 'SD');
          var rColor = rating >= 70 ? '#2ecc71' : rating >= 50 ? '#f39c12' : '#e74c3c';
          var uptime = uptimeMinutes < 60 ? uptimeMinutes + 'min' : Math.floor(uptimeMinutes/60) + 'h';
          var thumb = String(ch.thumbnailUrl || ('/live/thumb/' + encodeURIComponent(key) + '.jpg'));
          thumb += thumb.indexOf('?') >= 0 ? '&t=' + t : '?t=' + t;
          
          var count = ch.experienceBars || 3;
          var barsHtml = '';
          for (var i = 0; i < 5; i++) {
            barsHtml += i < count ? '&#9646;' : '<span style="opacity:.3">&#9646;</span>';
          }
          
          var lang = ch.language || '';
          var langFlag = String(lang).toUpperCase();

          html += '<div class="channel-card" data-key="' + escAttr(key) + '">' +
            '<div class="ch-thumb">' +
            '<img src="' + escAttr(thumb) + '" alt="" loading="lazy" onerror="this.style.display=\\'none\\'">' +
            '<div class="ch-thumb-overlay"><span class="ch-live-dot"></span>' +
            '<span class="ch-viewers">' + escH(ch.viewers || 0) + ' viewers</span>' +
            '<span class="ch-quality badge-' + quality + '">' + escH(ch.qualityLabel || 'SD') + '</span></div></div>' +
            '<div class="ch-body"><h4 class="ch-title">' + escH(ch.title || 'Stream') + '</h4>' +
            '<div class="ch-meta"><span class="ch-category">' + escH(ch.category || 'general') + '</span>' +
            '<span class="ch-lang">' + escH(langFlag) + '</span>' +
            '<span class="ch-uptime">' + uptime + '</span></div></div>' +
            '<div class="ch-footer"><div class="ch-rating" style="color:' + rColor + '">' +
            '<span class="ch-score">' + rating + '</span>' +
            '<span class="ch-bars">' + barsHtml + '</span>' +
            '<span class="ch-exp" style="color:#888;font-weight:400;font-size:11px;margin-left:auto">' + escH(ch.experience || '') + '</span></div>' +
            '<span class="ch-bitrate">' + bitrate + 'kbps</span></div></div>';
        });
        html += '</div>';
        list.innerHTML = html;
      })
      .catch(function() {});
  };

  // --- Directory: join a channel ---
  // BUG-063 + BUG-065 FIX: Strict streamKey validation to prevent XSS/injection
  window.joinChannel = function(streamKey) {
    // Only allow alphanumeric, underscore, and hyphen in streamKey
    var safeKey = String(streamKey || '').replace(/[^a-zA-Z0-9_-]/g, '');
    if (!safeKey || safeKey.length === 0 || safeKey.length > 128) {
      console.warn('[eSE] Invalid streamKey rejected:', streamKey);
      return;
    }
    if (safeKey.startsWith('local_') || safeKey.startsWith('external_') || safeKey.startsWith('obs_')) {
      window.location.href = '/live/watch/local';
    } else {
      window.location.href = '/live/watch/' + encodeURIComponent(safeKey);
    }
  };

  document.addEventListener('click', function(ev) {
    var card = ev.target && ev.target.closest ? ev.target.closest('.channel-card[data-key]') : null;
    if (!card) return;
    var key = card.getAttribute('data-key') || '';
    window.joinChannel(key);
  });
})();
`;
}

module.exports = { getScript };
