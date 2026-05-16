// filepath: srchybrid/eSE/shared/safe_dom.js
// ===================================================================
//  safe_dom.js — XSS-safe DOM helpers for eSE client-side rendering
// ===================================================================
//  Usage: <script src="/shared/safe_dom.js"></script>
//  All functions are global (window.*) for use in inline event handlers.
// ===================================================================

'use strict';

(function(w) {

  /**
   * Escape HTML special characters to prevent XSS injection.
   * Use this ALWAYS when inserting user/API text into innerHTML strings.
   * @param {string} str - Raw text to escape
   * @returns {string} HTML-safe string
   */
  function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  /**
   * Sanitize a URL — only allow http:, https:, and data:image/ schemes.
   * Blocks javascript:, vbscript:, data:text/html, etc.
   * @param {string} url - URL to validate
   * @returns {string} Safe URL or empty string
   */
  function sanitizeURL(url) {
    if (!url || typeof url !== 'string') return '';
    var trimmed = url.trim();
    // Allow relative URLs (start with / or .)
    if (trimmed.charAt(0) === '/' || trimmed.charAt(0) === '.') return trimmed;
    // Allow http/https
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    // Allow data:image/ for inline images
    if (/^data:image\//i.test(trimmed)) return trimmed;
    // Block everything else (javascript:, vbscript:, data:text/html, etc.)
    return '';
  }

  /**
   * Escape a string for safe use inside an onclick="fn('...')" attribute.
   * Handles both single-quote escaping and HTML entity encoding.
   * @param {string} str - Value to escape for inline JS attribute
   * @returns {string} Safe string for onclick attributes
   */
  function escapeAttr(str) {
    if (!str) return '';
    return String(str)
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /**
   * Create an element with safe attributes and text content.
   * @param {string} tag - HTML tag name
   * @param {Object} attrs - Key-value pairs for attributes
   * @param {string} [text] - Text content (set via textContent, NOT innerHTML)
   * @returns {HTMLElement}
   */
  function createElement(tag, attrs, text) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function(key) {
        if (key === 'className') {
          el.className = attrs[key];
        } else if (key === 'style' && typeof attrs[key] === 'object') {
          Object.keys(attrs[key]).forEach(function(prop) {
            el.style[prop] = attrs[key][prop];
          });
        } else if (key.startsWith('on')) {
          // Event handlers — only accept functions, never strings
          if (typeof attrs[key] === 'function') {
            el.addEventListener(key.slice(2).toLowerCase(), attrs[key]);
          }
        } else if (key === 'dataset') {
          Object.keys(attrs[key]).forEach(function(dk) {
            el.dataset[dk] = attrs[key][dk];
          });
        } else {
          el.setAttribute(key, attrs[key]);
        }
      });
    }
    if (text !== undefined && text !== null) {
      el.textContent = String(text);
    }
    return el;
  }

  /**
   * Safely set innerHTML with all dynamic values pre-escaped.
   * PREFER createElement() when possible. Use this only for complex templates.
   * @param {HTMLElement} el - Target element
   * @param {string} html - HTML string where all dynamic parts MUST be pre-escaped via escapeHTML()
   */
  function setHTML(el, html) {
    if (!el) return;
    el.innerHTML = html;
  }

  /**
   * Clear all children of an element safely.
   * @param {HTMLElement} el - Target element
   */
  function clearChildren(el) {
    if (!el) return;
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  /**
   * Build a movie card HTML string with all values properly escaped.
   * Centralized here to avoid XSS in the 4+ places that render movie cards.
   * @param {Object} m - Movie object from OMDb API
   * @returns {string} Safe HTML string
   */
  function renderSafeMovieCard(m) {
    var poster = (m.Poster && m.Poster !== 'N/A') ? sanitizeURL(m.Poster) : '';
    var title = escapeHTML(m.Title || 'Sin titulo');
    var year = escapeHTML(m.Year || '');
    var imdbId = escapeAttr(m.imdbID || '');
    var safeTitle = escapeAttr(m.Title || 'Sin titulo');

    return '<div class="card" onclick="showMovieDetail(\'' + imdbId + '\',null,\'' + safeTitle + '\')">' +
      '<div class="card-poster"' + (poster ? ' style="background-image:url(' + escapeHTML(poster) + ');"' : '') + '>' +
      (poster ? '' : '<div class="play-icon">&#9654;</div>') +
      '</div>' +
      '<div class="card-info"><h3 class="card-title">' + title + '</h3>' +
      '<div class="card-meta">' + year + '</div></div></div>';
  }

  /**
   * Build a safe search suggestion HTML string.
   * @param {Object} m - Movie object from OMDb API
   * @returns {string} Safe HTML string
   */
  function renderSafeSearchSuggestion(m) {
    var poster = (m.Poster && m.Poster !== 'N/A') ? sanitizeURL(m.Poster) : '';
    var title = escapeHTML(m.Title || '');
    var year = escapeHTML(m.Year || '');
    var type = escapeHTML(m.Type || '');
    var imdb = escapeAttr(m.imdbID || '');
    var safe = escapeAttr(m.Title || '');

    return '<div class="search-suggestion" onclick="toggleSearchOverlay();showMovieDetail(\'' + imdb + '\',null,\'' + safe + '\')">' +
      (poster
        ? '<img src="' + escapeHTML(poster) + '" alt="" loading="lazy">'
        : '<div style="width:45px;height:67px;background:#1a1a2e;border-radius:6px;flex-shrink:0"></div>') +
      '<div class="search-suggestion-info">' +
        '<div class="search-suggestion-title">' + title + '</div>' +
        '<div class="search-suggestion-meta">' + year + ' \u00b7 ' + type + '</div>' +
      '</div></div>';
  }

  /**
   * Build safe tunnel status HTML.
   * @param {Object} d - Tunnel status data from /api/tunnel/status
   * @returns {string} Safe HTML string
   */
  function renderSafeTunnelStatus(d) {
    var parts = [];
    if (d.url) {
      var urlDisplay = escapeHTML(String(d.url).replace('https://', ''));
      var urlAttr = escapeAttr(d.url);
      parts.push(' <span style="color:#2ecc71;text-decoration:underline;cursor:pointer" onclick="copyUrl(\'' + urlAttr + '\')">' + urlDisplay + '</span>');
    }
    if (d.publicUrl) {
      var pubDisplay = escapeHTML(String(d.publicUrl).replace('http://', ''));
      var pubAttr = escapeAttr(d.publicUrl);
      parts.push('• <span style="color:#ff6b35;cursor:pointer" onclick="copyUrl(\'' + pubAttr + '\')">' + pubDisplay + '</span>');
    }
    return parts.join(' <span style="color:#444">|</span> ');
  }

  // === Expose all helpers globally ===
  w.SafeDOM = {
    escapeHTML: escapeHTML,
    sanitizeURL: sanitizeURL,
    escapeAttr: escapeAttr,
    createElement: createElement,
    setHTML: setHTML,
    clearChildren: clearChildren,
    renderSafeMovieCard: renderSafeMovieCard,
    renderSafeSearchSuggestion: renderSafeSearchSuggestion,
    renderSafeTunnelStatus: renderSafeTunnelStatus
  };

  // Convenience aliases on window for backward-compat in inline scripts
  w.escapeHTML = escapeHTML;
  w.sanitizeURL = sanitizeURL;
  w.escapeAttr = escapeAttr;

})(window);
