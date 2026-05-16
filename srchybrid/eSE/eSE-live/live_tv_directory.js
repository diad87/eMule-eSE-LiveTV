/**
 * eSE Live — Live TV Directory
 * Renders the channel grid with search, filters, and ratings.
 * Injected into live_tv_page.js when there are channels available.
 * Max ~250 lines.
 */
'use strict';

/**
 * Render the channel directory grid HTML.
 * @param {Array} channels - Channel search results (with rating info)
 * @param {Object} favorites - Set of favorite streamKeys
 * @returns {string} HTML for the directory section
 */
function renderGrid(channels, favorites) {
  if (!channels || channels.length === 0) {
    return `<div class="dir-empty">
<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#555" stroke-width="1.5">
<path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/>
<circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/>
<path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/></svg>
<p>No hay canales en directo</p>
<p style="font-size:12px;color:#555">Emite tu propio canal o espera a que otros se conecten</p>
</div>`;
  }

  let html = '<div class="channel-grid">';

  for (const ch of channels) {
    const streamKey = String(ch.streamKey || '');
    const ratingScore = Number(ch.rating || 0);
    const viewers = Number(ch.viewers || 0);
    const bitrate = Number(ch.bitrate || 0);
    const qualityLabel = escClass(ch.qualityLabel || 'SD');
    const uptimeMinutes = Math.max(0, Number(ch.uptimeMinutes || 0));
    const isFav = favorites && favorites[ch.streamKey];
    const uptimeStr = uptimeMinutes < 60
      ? uptimeMinutes + 'min'
      : Math.floor(uptimeMinutes / 60) + 'h ' + (uptimeMinutes % 60) + 'm';

    const ratingColor = ratingScore >= 70 ? '#2ecc71'
      : ratingScore >= 50 ? '#f39c12'
      : '#e74c3c';

    const barsHtml = renderBars(ch.experienceBars || 3);
    const langFlag = langToFlag(ch.language);

    // BROWSE-S01: prefer the cross-peer thumbnailUrl when channel_api
    // provided it (absolute URL pointing to the remote broadcaster's
    // own Node :8080), otherwise fall back to the local relative path.
    // The browser caches the image and onerror hides on 404 / timeout.
    const thumbBase = (ch.thumbnailUrl && ch.thumbnailUrl.length > 0)
      ? ch.thumbnailUrl
      : ('/live/thumb/' + encodeURIComponent(streamKey) + '.jpg');
    const cacheBust = (thumbBase.indexOf('?') >= 0 ? '&' : '?') + 't=' + Math.floor(Date.now()/20000);

    html += `<div class="channel-card" data-key="${escH(streamKey)}">
<div class="ch-thumb">
<img src="${escH(thumbBase + cacheBust)}" alt="" loading="lazy" onerror="this.style.display='none'">
<div class="ch-thumb-overlay">
<span class="ch-live-dot"></span>
<span class="ch-viewers">${viewers} viewers</span>
<span class="ch-quality badge-${qualityLabel}">${escH(ch.qualityLabel || 'SD')}</span>
${isFav ? '<span class="ch-fav">&#9733;</span>' : ''}
</div>
</div>
<div class="ch-body">
<h4 class="ch-title">${escH(ch.title)}</h4>
<div class="ch-meta">
<span class="ch-category">${escH(ch.category)}</span>
<span class="ch-lang">${langFlag}</span>
<span class="ch-uptime">${uptimeStr}</span>
</div>
</div>
<div class="ch-footer">
<div class="ch-rating" style="color:${ratingColor}">
<span class="ch-score">${ratingScore}</span>
<span class="ch-bars">${barsHtml}</span>
<span class="ch-exp" style="color:#888;font-weight:400;font-size:11px;margin-left:auto">${escH(ch.experience || '')}</span>
</div>
<span class="ch-bitrate">${bitrate}kbps</span>
</div>
</div>`;
  }

  html += '</div>';
  return html;
}

/**
 * Render the search/filter bar HTML.
 * @returns {string}
 */
function renderFilters() {
  return `<div class="dir-filters">
<div class="dir-search-wrap">
<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#888" stroke-width="2">
<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
</svg>
<input type="text" id="dir-search" placeholder="Buscar canales..." oninput="(window.__chDeb&&clearTimeout(window.__chDeb),window.__chDeb=setTimeout(filterChannels,250))">
</div>
<select id="dir-category" onchange="filterChannels()">
<option value="all">Todas las categor&#237;as</option>
<option value="deportes">Deportes</option>
<option value="gaming">Gaming</option>
<option value="cine">Cine</option>
<option value="musica">M&#250;sica</option>
<option value="educacion">Educaci&#243;n</option>
<option value="webcam">Webcam</option>
<option value="24h">24/7</option>
<option value="general">General</option>
</select>
<select id="dir-lang" onchange="filterChannels()">
<option value="all">Todos los idiomas</option>
<option value="es">Espa&#241;ol</option>
<option value="en">English</option>
<option value="fr">Fran&#231;ais</option>
<option value="de">Deutsch</option>
<option value="pt">Portugu&#234;s</option>
</select>
<select id="dir-sort" onchange="filterChannels()">
<option value="rating">Mejor valorados</option>
<option value="viewers">M&#225;s vistos</option>
<option value="newest">M&#225;s recientes</option>
</select>
</div>`;
}

/**
 * Get the CSS for the directory components.
 * @returns {string}
 */
function getCSS() {
  return `
.dir-section{padding:0 40px 40px}
.dir-filters{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
.dir-search-wrap{flex:1;min-width:200px;position:relative;display:flex;align-items:center}
.dir-search-wrap svg{position:absolute;left:12px;pointer-events:none}
.dir-search-wrap input{width:100%;background:#1a1a2e;border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#fff;padding:12px 14px 12px 38px;font-size:14px;font-family:inherit;outline:none;transition:all .2s;box-shadow:inset 0 2px 4px rgba(0,0,0,.2)}
.dir-search-wrap input:focus{border-color:#ff6b35;background:#20203a;box-shadow:0 0 0 2px rgba(255,107,53,.2), inset 0 2px 4px rgba(0,0,0,.2)}
.dir-filters select{background:#1a1a2e;border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#fff;padding:12px 16px;font-size:13px;font-family:inherit;cursor:pointer;outline:none;transition:all .2s;font-weight:500;box-shadow:0 2px 4px rgba(0,0,0,.2)}
.dir-filters select:focus{border-color:#ff6b35;background:#20203a}
.dir-empty{text-align:center;padding:60px 20px;color:#666}
.dir-empty svg{margin-bottom:16px;opacity:.5}
.channel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:24px}
.channel-card{background:linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%);border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:hidden;cursor:pointer;transition:all .3s cubic-bezier(0.25, 0.8, 0.25, 1);box-shadow:0 4px 15px rgba(0,0,0,.2)}
.channel-card:hover{background:linear-gradient(180deg, rgba(255,107,53,0.05) 0%, rgba(255,255,255,0.02) 100%);border-color:rgba(255,107,53,.4);transform:translateY(-6px);box-shadow:0 12px 35px rgba(0,0,0,.4), 0 0 0 1px rgba(255,107,53,.2)}
.ch-thumb{position:relative;aspect-ratio:16/9;background:#111;overflow:hidden;border-bottom:1px solid rgba(255,255,255,.05)}
.ch-thumb img{width:100%;height:100%;object-fit:cover;transition:transform .5s ease}
.channel-card:hover .ch-thumb img{transform:scale(1.03)}
.ch-thumb-overlay{position:absolute;bottom:0;left:0;right:0;display:flex;align-items:center;gap:10px;padding:24px 16px 12px;background:linear-gradient(transparent,rgba(0,0,0,.9))}
.ch-live-dot{width:8px;height:8px;background:#ff2d55;border-radius:50%;box-shadow:0 0 8px rgba(255,45,85,.6);animation:pulse 2s infinite}
.ch-viewers{font-size:12px;color:#ccc;font-weight:600}
.ch-quality{font-size:10px;padding:3px 8px;border-radius:6px;font-weight:800;margin-left:auto;letter-spacing:0.5px}
.badge-4K{background:rgba(155,89,182,.2);color:#d291bc;border:1px solid rgba(155,89,182,.4);box-shadow:0 0 10px rgba(155,89,182,.2)}
.badge-1080p{background:rgba(52,152,219,.2);color:#5dade2;border:1px solid rgba(52,152,219,.4)}
.badge-720p{background:rgba(46,204,113,.2);color:#58d68d;border:1px solid rgba(46,204,113,.4)}
.badge-480p,.badge-SD{background:rgba(255,255,255,.08);color:#aaa;border:1px solid rgba(255,255,255,.1)}
.ch-fav{color:#f1c40f;font-size:16px;text-shadow:0 0 8px rgba(241,196,15,.5)}
.ch-body{padding:16px 20px}
.ch-title{font-size:16px;font-weight:700;color:#fff;margin-bottom:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;letter-spacing:-0.2px}
.ch-meta{display:flex;gap:12px;font-size:13px;color:#888;font-weight:500;align-items:center}
.ch-category{text-transform:capitalize;color:#aaa}
.ch-lang{font-size:14px}
.ch-uptime{margin-left:auto;font-size:12px;opacity:0.8}
.ch-footer{display:flex;justify-content:space-between;align-items:center;border-top:1px dashed rgba(255,255,255,.08);padding:12px 20px;background:rgba(0,0,0,.15)}
.ch-rating{display:flex;align-items:center;gap:8px;font-weight:600}
.ch-score{font-size:18px;font-variant-numeric:tabular-nums}
.ch-stars{font-size:12px;letter-spacing:1px;text-shadow:0 0 4px currentColor}
.ch-exp{font-size:12px;font-weight:500;color:#777}
.ch-bitrate{font-size:11px;color:#555;font-family:monospace}`;
}

// --- Helpers ---

function renderBars(count) {
  let s = '';
  // Convert 0-100 rating roughly to 1-5 bars. Or use the raw exp level
  // The original passed ch.experienceBars || 3. I'll use that logic.
  for (let i = 0; i < 5; i++) {
    s += i < count ? '&#9646;' : '<span style="opacity:.3">&#9646;</span>';
  }
  return s;
}

function langToFlag(lang) {
  return lang ? lang.toUpperCase() : '';
}

function escH(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escClass(s) {
  return String(s || '').replace(/[^a-zA-Z0-9_-]/g, '');
}

module.exports = { renderGrid, renderFilters, getCSS };
