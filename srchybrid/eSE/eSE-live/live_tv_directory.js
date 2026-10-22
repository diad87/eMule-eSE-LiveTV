/**
 * eSE Live — Live TV Directory
 * Twitch/YouTube-style channel cards, featured stream and category chips.
 *
 * The render helpers below run on the server (initial HTML) and in the browser
 * (/live/player.js receives their source through clientSource()), so both paths
 * produce identical markup. Keep them self-contained: no outer variables, only
 * calls to each other.
 */
'use strict';

function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function escClass(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[^a-zA-Z0-9_-]/g, '');
}

function channelHref(streamKey) {
  var key = String(streamKey || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!key || key.length > 128) return '';
  return '/live/watch/' + (/^(local_|external_|obs_)/.test(key) ? 'local' : encodeURIComponent(key));
}

function categoryLabel(category) {
  var labels = { sports: 'Deportes', gaming: 'Gaming', movies: 'Cine', music: 'Música', education: 'Educación',
    talk: 'Charlas', '24/7': '24/7', general: 'General' };
  var key = String(category || 'general');
  return labels[key] || key.charAt(0).toUpperCase() + key.slice(1);
}

function languageLabel(language) {
  var labels = { es: 'Español', en: 'English', fr: 'Français', de: 'Deutsch', pt: 'Português' };
  var key = String(language || '');
  return labels[key] || key.toUpperCase();
}

function formatViewers(count) {
  var n = Math.max(0, Math.floor(Number(count) || 0));
  var short = n >= 10000 ? Math.round(n / 1000) + ' mil' : n >= 1000 ? (n / 1000).toFixed(1).replace('.', ',') + ' mil' : String(n);
  return short + (n === 1 ? ' espectador' : ' espectadores');
}

function formatUptime(minutes) {
  var m = Math.max(0, Math.floor(Number(minutes) || 0));
  if (m < 1) return 'Recién empezado';
  if (m < 60) return m + ' min';
  return Math.floor(m / 60) + ' h' + (m % 60 ? ' ' + (m % 60) + ' min' : '');
}

function channelHandle(ch) {
  var key = String(ch && ch.streamKey || '');
  if (ch && ch.isLocal || /^(local_|external_|obs_)/.test(key)) return 'Tu emisión';
  return 'Canal ' + key.replace(/[^a-zA-Z0-9]/g, '').slice(0, 6).toUpperCase();
}

function channelAvatar(ch) {
  var key = String(ch && ch.streamKey || '');
  var hue = 0;
  for (var i = 0; i < key.length; i++) hue = (hue * 31 + key.charCodeAt(i)) % 360;
  var letter = (Array.from(String(ch && ch.title || '').trim())[0] || 'C').toUpperCase();
  return '<span class="ch-avatar" style="--ch-hue:' + hue + '" aria-hidden="true">' + escH(letter) + '</span>';
}

function channelThumb(ch, t) {
  var key = String(ch && ch.streamKey || '');
  var url = String(ch && ch.thumbnailUrl || '');
  if (!/^(https?:\/\/|\/)/i.test(url)) url = '/live/thumb/' + encodeURIComponent(key) + '.jpg';
  return url + (url.indexOf('?') >= 0 ? '&' : '?') + 't=' + (Number(t) || 0);
}

function channelSignal(ch) {
  var bars = Math.max(0, Math.min(5, Math.round(Number(ch && ch.experienceBars) || 0)));
  if (!bars) return '';
  var html = '<span class="ch-signal" title="' + escH('Calidad de la emisión: ' + (Number(ch.rating) || 0) + '/100') + '"><span class="ch-signal-bars" aria-hidden="true">';
  for (var i = 0; i < 5; i++) html += '<i' + (i < bars ? ' class="on"' : '') + '></i>';
  return html + '</span>' + escH(ch.experience || 'Señal ' + bars + '/5') + '</span>';
}

function renderMedia(ch, t) {
  var category = escClass(ch.category || 'general');
  var quality = escClass(ch.qualityLabel || 'SD');
  return '<span class="ch-thumb" data-cat="' + category + '">' +
    '<span class="ch-thumb-fallback" aria-hidden="true">' + escH(categoryLabel(ch.category)) + '</span>' +
    '<img src="' + escH(channelThumb(ch, t)) + '" alt="" loading="lazy" onerror="this.remove()">' +
    '<span class="ch-live-badge">En directo</span>' +
    '<span class="ch-quality badge-' + quality + '">' + escH(ch.qualityLabel || 'SD') + '</span>' +
    '<span class="ch-viewers"><span class="ch-live-dot" aria-hidden="true"></span>' + escH(formatViewers(ch.viewers)) + '</span>' +
    '<span class="ch-uptime">' + escH(formatUptime(ch.uptimeMinutes)) + '</span></span>';
}

function renderChannelCard(ch, t, featuredKey) {
  var key = String(ch.streamKey || '');
  var href = channelHref(key);
  if (!href) return '';
  var title = ch.title || 'Canal sin título';
  var tags = '<span class="ch-tag">' + escH(categoryLabel(ch.category)) + '</span>' +
    (ch.language ? '<span class="ch-tag">' + escH(String(ch.language).toUpperCase()) + '</span>' : '');
  return '<a class="channel-card" data-key="' + escH(key) + '"' + (featuredKey && key === featuredKey ? ' data-featured="true"' : '') +
    ' href="' + href + '" aria-label="' + escH('Ver en directo: ' + title) + '">' + renderMedia(ch, t) +
    '<span class="ch-body">' + channelAvatar(ch) + '<span class="ch-info">' +
    '<span class="ch-title">' + escH(title) + '</span>' +
    '<span class="ch-channel">' + escH(channelHandle(ch)) + '</span>' +
    '<span class="ch-tags">' + tags + channelSignal(ch) + '</span></span></span></a>';
}

function pickFeatured(channels) {
  var best = null;
  (channels || []).forEach(function(ch) {
    if (!ch || !channelHref(ch.streamKey)) return;
    if (!best || (Number(ch.viewers) || 0) > (Number(best.viewers) || 0) ||
        ((Number(ch.viewers) || 0) === (Number(best.viewers) || 0) && (Number(ch.rating) || 0) > (Number(best.rating) || 0))) best = ch;
  });
  return best;
}

function renderFeatured(ch, t) {
  var key = String(ch && ch.streamKey || '');
  var href = channelHref(key);
  if (!href) return '';
  var title = ch.title || 'Canal sin título';
  var meta = [categoryLabel(ch.category), ch.language ? languageLabel(ch.language) : '', formatUptime(ch.uptimeMinutes), ch.qualityLabel || '']
    .filter(Boolean).join(' · ');
  return '<a class="live-featured-card" data-key="' + escH(key) + '" href="' + href + '" aria-label="' + escH('Ver en directo: ' + title) + '">' +
    '<span class="lf-media">' + renderMedia(ch, t) + '<span class="lf-play" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><polygon points="7 4 20 12 7 20 7 4"/></svg></span></span>' +
    '<span class="lf-body"><span class="lf-kicker"><span class="ch-live-dot" aria-hidden="true"></span>Destacado ahora</span>' +
    '<span class="lf-channel">' + channelAvatar(ch) + '<span>' + escH(channelHandle(ch)) + '</span></span>' +
    '<span class="lf-title">' + escH(title) + '</span>' +
    '<span class="lf-meta">' + escH(meta) + '</span>' +
    '<span class="lf-stats"><span class="lf-viewers">' + escH(formatViewers(ch.viewers)) + '</span>' + channelSignal(ch) + '</span>' +
    '<span class="lf-cta"><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><polygon points="6 4 20 12 6 20 6 4"/></svg>Ver directo</span></span></a>';
}

/**
 * Render the channel grid HTML.
 * @param {Array} channels - Channel search results (with rating info)
 * @param {Object} _favorites - Reserved; favourites are not shown yet
 * @param {string} featuredKey - Stream key shown in the featured slot, hidden in the grid
 * @returns {string}
 */
function renderGrid(channels, _favorites, featuredKey) {
  var t = Math.floor(Date.now() / 20000);
  var cards = (channels || []).map(function(ch) { return ch ? renderChannelCard(ch, t, featuredKey) : ''; }).join('');
  return cards ? '<div class="channel-grid">' + cards + '</div>' : '';
}

const CLIENT_HELPERS = [escH, escClass, channelHref, categoryLabel, languageLabel, formatViewers, formatUptime,
  channelHandle, channelAvatar, channelThumb, channelSignal, renderMedia, renderChannelCard, pickFeatured, renderFeatured];

/** Source of the shared helpers for the browser script. */
function clientSource() {
  return CLIENT_HELPERS.map(fn => fn.toString()).join('\n');
}

const CATEGORIES = [['all', 'Todo'], ['gaming', 'Gaming'], ['sports', 'Deportes'], ['movies', 'Cine'], ['music', 'Música'],
  ['talk', 'Charlas'], ['education', 'Educación'], ['24/7', '24/7'], ['general', 'General']];

/**
 * Render the search/filter bar HTML.
 * @returns {string}
 */
function renderFilters() {
  const chips = CATEGORIES.map(([value, label]) =>
    '<button type="button" class="dir-chip" data-category="' + escH(value) + '" aria-pressed="' + (value === 'all') + '" onclick="setChannelCategory(this.getAttribute(\'data-category\'))">' + escH(label) + '</button>'
  ).join('');
  return `<div class="dir-filters">
<div class="dir-chips" id="dir-category" role="group" aria-label="Categor&iacute;a del canal" aria-controls="channel-list">${chips}</div>
<div class="dir-tools">
<div class="dir-search-wrap">
<svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#aaaab8" stroke-width="2">
<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
</svg>
<input type="search" id="dir-search" aria-label="Buscar canales" aria-controls="channel-list" placeholder="Buscar canales en directo" oninput="(window.__chDeb&&clearTimeout(window.__chDeb),window.__chDeb=setTimeout(filterChannels,250))">
</div>
<select id="dir-lang" aria-label="Idioma del canal" aria-controls="channel-list" onchange="filterChannels()">
<option value="all">Todos los idiomas</option>
<option value="es">Espa&#241;ol</option>
<option value="en">English</option>
<option value="fr">Fran&#231;ais</option>
<option value="de">Deutsch</option>
<option value="pt">Portugu&#234;s</option>
</select>
<select id="dir-sort" aria-label="Ordenar canales" aria-controls="channel-list" onchange="filterChannels()">
<option value="rating">Mejor se&#241;al</option>
<option value="viewers">M&#225;s vistos</option>
<option value="newest">M&#225;s recientes</option>
</select>
<button class="dir-reset" type="button" id="dir-reset" onclick="resetChannelFilters()" hidden>Limpiar filtros</button>
</div>
</div>`;
}

/**
 * Get the CSS for the directory components.
 * @returns {string}
 */
function getCSS() {
  return `
.dir-filters{display:flex;flex-direction:column;gap:14px;margin-bottom:22px}
.dir-chips{display:flex;gap:8px;overflow-x:auto;scrollbar-width:none;padding:2px 2px 4px;margin:0 -2px}
.dir-chips::-webkit-scrollbar{display:none}
.dir-chip{flex:0 0 auto;min-height:38px;padding:8px 16px;border-radius:999px;border:1px solid #ffffff1c;background:#ffffff0a;color:#d2d3dc;font:inherit;font-size:13px;font-weight:650;cursor:pointer;transition:background .15s,color .15s,border-color .15s}
.dir-chip:hover{background:#ffffff14;color:#fff}
.dir-chip[aria-pressed="true"]{background:#f4f4f7;border-color:#f4f4f7;color:#121218}
.dir-tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.dir-search-wrap{flex:1;min-width:220px;position:relative;display:flex;align-items:center}
.dir-search-wrap svg{position:absolute;left:14px;pointer-events:none}
.dir-search-wrap input{width:100%;min-height:44px;background:#14151c;border:1px solid #ffffff1f;border-radius:999px;color:#fff;padding:11px 16px 11px 40px;font-size:14px;font-family:inherit;outline:none;transition:border-color .2s,background .2s}
.dir-search-wrap input:focus{border-color:#ff875f;background:#181922}
.dir-search-wrap input::placeholder{color:#9d9eab;opacity:1}
.dir-tools select{min-height:44px;background:#14151c;border:1px solid #ffffff1f;border-radius:999px;color:#e6e6ee;padding:10px 16px;font-size:13px;font-family:inherit;font-weight:600;cursor:pointer;outline:none}
.dir-tools select:focus{border-color:#ff875f}
.dir-empty{text-align:center;padding:48px 20px;color:#aaaab8;line-height:1.7;border:1px dashed #ffffff21;border-radius:16px}
.dir-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.dir-heading{font-size:22px;font-weight:750;letter-spacing:-.5px;color:#f4f4f7}
.dir-feedback{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.dir-status{font-size:13px;color:#a9aab6;line-height:1.6}
.dir-retry,.dir-reset{min-height:44px;padding:10px 16px;border:1px solid #ffffff2b;border-radius:999px;color:#f4f4f7;background:transparent;font:inherit;font-size:13px;font-weight:600;cursor:pointer}
.dir-retry:hover,.dir-reset:hover{border-color:#ff9a85;background:#ffffff0a}
.dir-retry[hidden],.dir-reset[hidden]{display:none}
.dir-status:focus-visible,.channel-card:focus-visible,.live-featured-card:focus-visible,.dir-filters :focus-visible{outline:2px solid #ffac8c;outline-offset:4px}

.channel-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,290px),1fr));gap:28px 20px}
.channel-card{display:flex;flex-direction:column;gap:12px;min-width:0;color:inherit;text-decoration:none;border-radius:14px}
.channel-card[data-featured]{display:none}
.ch-thumb{position:relative;display:block;aspect-ratio:16/9;overflow:hidden;border-radius:12px;background:radial-gradient(120% 120% at 0% 0%,hsl(var(--cat-hue,20) 55% 30%),#111219 70%);transition:transform .2s,box-shadow .2s}
.ch-thumb[data-cat="sports"]{--cat-hue:140}.ch-thumb[data-cat="gaming"]{--cat-hue:265}.ch-thumb[data-cat="movies"]{--cat-hue:12}.ch-thumb[data-cat="music"]{--cat-hue:320}.ch-thumb[data-cat="education"]{--cat-hue:200}.ch-thumb[data-cat="talk"]{--cat-hue:40}.ch-thumb[data-cat="24/7"]{--cat-hue:180}.ch-thumb[data-cat="general"]{--cat-hue:225}
.ch-thumb img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.ch-thumb-fallback{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#ffffff38;font-size:clamp(22px,2.4vw,34px);font-weight:800;letter-spacing:-1px;text-transform:uppercase}
.channel-card:hover .ch-thumb,.channel-card:focus-visible .ch-thumb{transform:translate(4px,-4px);box-shadow:-6px 6px 0 #ff875f}
.ch-live-badge{position:absolute;top:10px;left:10px;padding:3px 7px;border-radius:5px;background:#e91916;color:#fff;font-size:11px;font-weight:800;letter-spacing:.4px;text-transform:uppercase}
.ch-quality{position:absolute;top:10px;right:10px;padding:3px 7px;border-radius:5px;background:#000000a6;color:#fff;font-size:10px;font-weight:800;letter-spacing:.4px}
.badge-4K{color:#e0b3ff}.badge-1080p{color:#9fd3ff}.badge-720p{color:#a9f0c3}.badge-480p,.badge-SD{color:#dcdce4}
.ch-viewers,.ch-uptime{position:absolute;bottom:10px;display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:5px;background:#000000b3;color:#fff;font-size:12px;font-weight:600}
.ch-viewers{left:10px}.ch-uptime{right:10px;font-variant-numeric:tabular-nums}
.ch-live-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#ff3b30;box-shadow:0 0 0 0 #ff3b3080;animation:live-ping 2s infinite}
@keyframes live-ping{0%{box-shadow:0 0 0 0 #ff3b3099}70%{box-shadow:0 0 0 6px #ff3b3000}100%{box-shadow:0 0 0 0 #ff3b3000}}
.ch-body{display:flex;gap:12px;min-width:0;padding:0 2px}
.ch-avatar{flex:0 0 40px;width:40px;height:40px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;background:hsl(var(--ch-hue,20) 60% 46%);color:#fff;font-size:16px;font-weight:800;box-shadow:inset 0 0 0 2px #ffffff26}
.ch-info{display:flex;flex-direction:column;gap:3px;min-width:0}
.ch-title{font-size:15px;font-weight:650;line-height:1.35;color:#f4f4f7;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}
.channel-card:hover .ch-title{color:#ffac8c}
.ch-channel{font-size:13px;color:#a9aab6}
.ch-tags{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-top:5px}
.ch-tag{padding:2px 9px;border-radius:999px;background:#ffffff12;color:#c9cad3;font-size:11px;font-weight:650}
.ch-signal{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:#a9aab6}
.ch-signal-bars{display:inline-flex;align-items:flex-end;gap:2px;height:11px}
.ch-signal-bars i{display:block;width:3px;border-radius:1px;background:#ffffff2e}
.ch-signal-bars i:nth-child(1){height:4px}.ch-signal-bars i:nth-child(2){height:6px}.ch-signal-bars i:nth-child(3){height:8px}.ch-signal-bars i:nth-child(4){height:10px}.ch-signal-bars i:nth-child(5){height:11px}
.ch-signal-bars i.on{background:#3ddc84}

.live-featured{margin:0 0 40px}
.live-featured[hidden]{display:none}
.live-featured-card{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,1fr);gap:0;overflow:hidden;border-radius:20px;background:#14151c;border:1px solid #ffffff14;color:inherit;text-decoration:none;transition:border-color .2s}
.live-featured-card:hover{border-color:#ff875f66}
.lf-media{position:relative;display:block}
.lf-media .ch-thumb{border-radius:0;height:100%;min-height:100%}
.live-featured-card:hover .ch-thumb{transform:none;box-shadow:none}
.lf-media .ch-live-badge{top:16px;left:16px;font-size:12px;padding:4px 9px}
.lf-media .ch-quality{top:16px;right:16px}
.lf-media .ch-viewers{left:16px;bottom:16px}.lf-media .ch-uptime{right:16px;bottom:16px}
.lf-play{position:absolute;inset:0;margin:auto;width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#ffffffe6;color:#121218;opacity:0;transform:scale(.9);transition:opacity .2s,transform .2s}
.live-featured-card:hover .lf-play,.live-featured-card:focus-visible .lf-play{opacity:1;transform:none}
.lf-body{display:flex;flex-direction:column;justify-content:center;gap:12px;padding:32px;min-width:0}
.lf-kicker{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase;color:#ff9a85}
.lf-channel{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:650;color:#d9dae2}
.lf-title{font-size:clamp(22px,2.2vw,30px);font-weight:800;letter-spacing:-.6px;line-height:1.15;color:#fff;overflow-wrap:anywhere;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.lf-meta{font-size:14px;color:#b4b5c1;line-height:1.5}
.lf-stats{display:flex;flex-wrap:wrap;align-items:center;gap:14px;font-size:13px;color:#e6e6ee;font-weight:600}
.lf-cta{align-self:flex-start;display:inline-flex;align-items:center;gap:9px;margin-top:8px;min-height:46px;padding:12px 22px;border-radius:10px;background:#ff875f;color:#1b100c;font-size:14px;font-weight:800}
.live-featured-card:hover .lf-cta{background:#ffa07c}
@media(max-width:900px){.live-featured-card{grid-template-columns:1fr}.lf-media .ch-thumb{aspect-ratio:16/9;height:auto}.lf-body{padding:20px 20px 24px}}
@media(max-width:600px){.channel-grid{gap:22px}.dir-tools select{flex:1 1 calc(50% - 5px);min-width:0}.dir-search-wrap{flex-basis:100%}.lf-cta{align-self:stretch;justify-content:center}}
@media(prefers-reduced-motion:reduce){.ch-live-dot{animation:none}.ch-thumb,.lf-play,.dir-chip{transition:none}.channel-card:hover .ch-thumb{transform:none}}
`;
}

module.exports = { renderGrid, renderFilters, renderFeatured, pickFeatured, getCSS, clientSource, channelAvatar, CATEGORIES };
