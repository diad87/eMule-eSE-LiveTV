'use strict';

// Isolated browser E2E host: production page renderers + production media route.
// Native eMule actions and catalogue responses are fixtures. Never load server.js,
// channel_api.js, discovery or the user's settings/download directories here.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const proof = path.resolve(root, '../../artifacts/ese-e2e-2026-10-11');
const media = path.join(proof, 'media');
const { escapeHtml, cleanTitle } = require('../utils');
const resolver = require('../media_resolver');
const stream = require('../routes/stream_completed');
const main = require('../pages/main_page');
const explore = require('../pages/explore_page');
const search = require('../pages/search_page');
const library = require('../pages/mylist_page');
const connect = require('../pages/connect_page');
const app = require('../pages/app_page');
const misc = require('../pages/misc_pages');
const live = require('../eSE-live/live_tv_page');
const PORT = 8092;
const activeStreams = Object.create(null);
const state = { scenario: 'normal', actions: [], settings: {}, requests: [], errors: [] };
fs.mkdirSync(media, { recursive: true });
const catalogue = Array.from({ length: 8 }, (_, index) => ({
  id: 100 + index, media_type: index === 1 ? 'tv' : 'movie',
  title: index === 1 ? undefined : 'Película de prueba ' + (index + 1),
  name: index === 1 ? 'Serie de prueba' : undefined,
  release_date: index === 1 ? undefined : '2026-01-01', first_air_date: index === 1 ? '2025-01-01' : undefined,
  poster_path: null, backdrop_path: null, overview: 'Título de ejemplo del entorno de pruebas E2E. No representa disponibilidad en la red.', vote_average: 7.4, vote_count: 120
}));
const downloads = () => state.scenario === 'empty' ? [] : [{
  fileName: 'Descarga de prueba.mp4', partNum: '001', partFile: '001.part',
  totalSizeBytes: 104857600, completedBytes: 26214400, sizeBytes: 104857600, sizeMB: 100,
  hash: 'AB'.repeat(16), active: false, metadataSource: 'fixture'
}];
const ctx = {
  PORT, bindHost: '127.0.0.1', __dirname: root, __dir: root, escapeHtml, cleanTitle,
  getDownloads: downloads, getCompletedFiles: () => state.scenario === 'empty' ? [] : resolver.getCompletedFiles(media),
  tunnel: { CONFIG: { secretId: 'fixture', accessToken: 'e2e-fixture-token-only', encKey: '00'.repeat(32) }, LOOKUP_TOPIC: 'e2e-fixture', publicUrl: null, tunnelUrl: null },
  HW_ENCODER: 'libx264'
};
for (const page of [main, explore, search, library, connect, app, misc]) page.init(ctx);
stream.init({ EMULE_INCOMING: media, FFMPEG_PATH: 'C:/tmp/emule-rc2/ffmpeg.exe', HW_ENCODER: 'libx264',
  HW_ENCODER_OPTS: ['-preset', 'ultrafast', '-crf', '23'], activeStreams,
  resolveMediaFile: name => resolver.resolveMediaFile(name, media, path.join(media, 'no-partials')),
  getSession: () => null, emuleRequest: (_url, callback) => callback(new Error('Native operations are isolated in E2E')) });
function json(res, status, data) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); }
function capture(res) {
  return { writeHead: (...args) => res.writeHead(...args), end(body) {
    const banner = '<footer style="position:static;background:#141a22;color:#eee;padding:10px;border:1px solid #657;font:12px system-ui"><a href="/__e2e" style="color:inherit">E2E · Datos de prueba</a></footer>';
    res.end(typeof body === 'string' && body.includes('</body>') ? body.replace('</body>', banner + '</body>') : body);
  } };
}
function fixturePage(page) {
  if (page !== 1 && page !== 2) return [];
  return catalogue.map(item => page === 1 ? { ...item } : { ...item, id: item.id + 1000,
    title: item.title ? item.title + ' · página 2' : undefined, name: item.name ? item.name + ' · página 2' : undefined });
}
function fixtureItem(id) {
  return fixturePage(1).concat(fixturePage(2)).find(item =>
    id === 'tmdb:' + item.media_type + ':' + item.id || id === 'tt' + (1000000 + item.id));
}
function fixtureDetail(id) {
  const item = fixtureItem(id);
  if (!item) return null;
  const series = item.media_type === 'tv';
  return { Response: 'True', catalogId: 'tmdb:' + item.media_type + ':' + item.id, tmdbId: item.id,
    imdbID: 'tt' + (1000000 + item.id), mediaType: item.media_type,
    Title: item.title || item.name, Year: (item.release_date || item.first_air_date).slice(0, 4), Type: series ? 'series' : 'movie',
    Poster: '', Plot: 'Ficha del entorno E2E. Sirve para comprobar navegación, favoritos y selección de capítulos.',
    Genre: 'Aventura', Runtime: '42 min', Actors: 'Reparto de ejemplo', Director: 'Dirección de ejemplo',
    Rating: '7.4', RatingSource: 'TMDB', seasons: series ? [{ number: 1, name: 'Temporada 1', episodeCount: 3 }, { number: 2, name: 'Temporada 2', episodeCount: 2 }] : [] };
}
function fixtureMetadata(url, req, res) {
  if (req.method !== 'GET') return json(res, 405, { error: 'read_only_fixture' });
  if (state.scenario === 'catalog-error') return json(res, 503, { error: 'e2e_catalog_unavailable' });
  const p = url.pathname;
  if (p === '/api/movies/detail') {
    const detail = fixtureDetail(url.searchParams.get('id') || '');
    return json(res, detail ? 200 : 404, detail || { Response: 'False', error: 'title_not_found' });
  }
  if (p === '/api/movies/season') {
    const detail = fixtureDetail(url.searchParams.get('id') || '');
    const number = Number(url.searchParams.get('season'));
    const season = detail && detail.seasons.find(item => item.number === number);
    if (!season) return json(res, 404, { Response: 'False', error: 'season_not_found' });
    // Season 2 ends with an unaired episode so the browser shows its upcoming state.
    const day = offset => new Date(Date.now() + offset * 86400000).toISOString().slice(0, 10);
    return json(res, 200, { catalogId: detail.catalogId, season: number,
      episodes: Array.from({ length: season.episodeCount }, (_, i) => ({ number: i + 1, name: 'Episodio de prueba ' + (i + 1),
        airDate: number === 2 && i === season.episodeCount - 1 ? day(21) : day(-400 + number * 120 + i * 7),
        overview: 'Sinopsis de ejemplo del episodio ' + (i + 1) + ' de la temporada ' + number + '. Sirve para revisar cómo se leen los textos largos en la lista de episodios.',
        runtime: 40 + ((i * 3) % 9), still: '', rating: '' })) });
  }
  if (p === '/api/movies/trailer') return json(res, 200, { videoId: null });
  if (p === '/api/movies/fetchinfo') return json(res, 200, { Response: 'False' });
  if (p === '/api/movies/poster') { res.writeHead(404); return res.end(); }
  const resource = p.match(/^\/api\/tmdb\/(movie|tv)\/(\d+)(\/external_ids)?$/);
  if (resource) {
    const item = fixtureItem('tmdb:' + resource[1] + ':' + resource[2]);
    if (!item) return json(res, 404, { error: 'title_not_found' });
    return json(res, 200, resource[3] ? { id: item.id, imdb_id: 'tt' + (1000000 + item.id) } :
      { ...item, imdb_id: 'tt' + (1000000 + item.id), runtime: 42, episode_run_time: [42], genres: [{ id: 12, name: 'Aventura' }] });
  }
  const find = p.match(/^\/api\/tmdb\/find\/(tt\d+)$/);
  if (find) {
    const item = fixtureItem(find[1]);
    return json(res, 200, { movie_results: item && item.media_type === 'movie' ? [item] : [], tv_results: item && item.media_type === 'tv' ? [item] : [] });
  }
  const listRoute = /^\/api\/tmdb\/(?:search\/(?:multi|movie|tv)|trending\/(?:all|movie|tv)\/(?:day|week)|discover\/(?:movie|tv)|(?:movie|tv)\/(?:popular|top_rated|now_playing|upcoming|on_the_air|airing_today))$/.test(p);
  if (p !== '/api/movies/search' && !listRoute) return json(res, 501, { error: 'metadata_fixture_not_available' });
  let items = state.scenario === 'empty' || /noexiste/i.test(url.searchParams.get('query') || url.searchParams.get('q') || '') ? [] : catalogue;
  if (/(?:^|\/)tv(?:\/|$)/.test(p)) items = items.filter(item => item.media_type === 'tv');
  if (/(?:^|\/)movie(?:\/|$)/.test(p)) items = items.filter(item => item.media_type === 'movie');
  if (p === '/api/movies/search') return json(res, 200, { Response: items.length ? 'True' : 'False', Search: items.map(item => fixtureDetail('tmdb:' + item.media_type + ':' + item.id)) });
  const page = Number(url.searchParams.get('page') || 1);
  if (!Number.isInteger(page) || page < 1) return json(res, 400, { error: 'invalid_page' });
  return json(res, 200, { page, total_pages: items.length ? 2 : 0, total_results: items.length * 2,
    results: fixturePage(page).filter(item => items.some(base => item.id === base.id + (page === 2 ? 1000 : 0))) });
}
const fixtureStreamKey = 'AB'.repeat(16);
const fixtureChannel = { streamKey: fixtureStreamKey, hash: fixtureStreamKey, title: 'Canal E2E · conexión simulada',
  language: 'es', category: 'general', qualityLabel: 'HD', rating: 80, bitrate: 1200, uptimeMinutes: 10, viewers: 0,
  experience: 'Datos de prueba', experienceBars: 4, fixture: true };
// Visual review only (scenario=showcase): several channels across categories.
const showcaseChannels = [
  ['C1', 'Final de copa en directo · comentarios en español', 'sports', 'es', 6200, 1840, 95, 5, 'Excelente'],
  ['C2', 'Speedrun nocturno: intento de récord', 'gaming', 'es', 3400, 312, 82, 4, 'Muy buena'],
  ['C3', 'Cineclub: clásicos del cine negro', 'movies', 'es', 2800, 96, 74, 4, 'Buena'],
  ['C4', 'Sesión de jazz desde casa', 'music', 'en', 1600, 41, 66, 3, 'Buena'],
  ['C5', 'Charla abierta sobre redes P2P y privacidad', 'talk', 'es', 1200, 23, 58, 3, 'Aceptable'],
  ['C6', 'Curso de electrónica básica · clase 4', 'education', 'es', 900, 9, 49, 2, 'Irregular'],
  ['C7', 'Webcam 24/7 del puerto', '24/7', 'pt', 600, 4, 40, 2, 'Irregular']
].map(([id, title, category, language, bitrate, viewers, rating, bars, experience], index) => ({
  streamKey: id.repeat(16), hash: id.repeat(16), title, category, language, bitrate, viewers, rating,
  qualityLabel: bitrate >= 5000 ? '1080p' : bitrate >= 3000 ? '720p' : bitrate >= 1500 ? '480p' : 'SD',
  uptimeMinutes: [134, 52, 18, 7, 240, 31, 1440][index], experienceBars: bars, experience, fixture: true
}));
function fixtureLive(url, req, res) {
  if (url.pathname === '/api/live/join' || url.pathname === '/api/live/leave') {
    if (req.method !== 'POST') return json(res, 405, { error: 'method_not_allowed', expected: 'POST' });
    state.actions.push({ method: req.method, path: url.pathname, key: url.searchParams.get('key'), fixture: true });
    return url.pathname.endsWith('/leave') ? json(res, 200, { success: true, fixture: true }) :
      json(res, 503, { success: false, error: 'e2e_no_live_broadcast', message: 'Prueba sin emisión real. Puedes reintentar.', fixture: true });
  }
  if (req.method !== 'GET') return json(res, 501, { error: 'native_action_not_available_in_e2e', fixture: true });
  if (state.scenario === 'live-error') return json(res, 503, { error: 'e2e_live_unavailable', fixture: true });
  let channels = state.scenario === 'empty' ? [] : state.scenario === 'showcase' ? showcaseChannels : [fixtureChannel];
  const query = (url.searchParams.get('q') || '').trim().toLocaleLowerCase('es');
  const category = url.searchParams.get('category') || 'all';
  const language = url.searchParams.get('lang') || 'all';
  channels = channels.filter(item => (!query || item.title.toLocaleLowerCase('es').includes(query)) &&
    (category === 'all' || item.category === category) && (language === 'all' || item.language === language));
  const metadata = {
    '/api/live/channels': { channels, kadConnected: true },
    '/api/live/emule-channels': { channels },
    '/api/live/status': { status: 'idle', segments: 0, uptime: 0, broadcasting: false, viewing: false, backend: 'fixture', meta: {} },
    '/api/live/connection-status': { connected: true, nodeCount: 42, lastScan: new Date().toISOString() },
    '/api/live/preflight': { ready: true, kad_connected: true, high_id: true, firewall_checking: false, max_upload_kbs: 1000, ffmpeg_found: true, public_ip: '192.0.2.10', public_ip_v6: '', public_ip_source: 'fixture', port: 4662 },
    '/api/live/monitor': { broadcasting: false, viewing: false, bufCount: 0, broadcastPeers: 0, meshPeers: 0, counters: { chunksServed: 0, chunksReceived: 0, chunksMissing: 0 } },
    '/api/live/debug': { broadcasting: false, viewing: false, peers: { viewPeers: 0, broadcastPeers: 0 }, chunks: { count: 0 }, discovery: { kadConnected: true } },
    '/api/live/first_run': { first_run: false },
    '/api/live/update_status': { has_update: false, latest_tag: null, latest_sha: null }
  };
  const data = metadata[url.pathname];
  return json(res, data ? 200 : 501, { ...(data || { error: 'native_action_not_available_in_e2e' }), fixture: true });
}
function renderFixtureWatch(hash) {
  if (!/^[a-fA-F0-9]{32}$/.test(hash)) throw new Error('Invalid fixture stream key');
  // Only the production page renderer; never channel_api's module or routes.
  return require('../eSE-live/live_watch_page').render(hash);
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1:' + PORT);
  state.requests.push({ method: req.method, path: url.pathname });
  res.setHeader('Cache-Control', 'no-store');
  res.on('finish', () => { if (res.statusCode >= 400) state.errors.push({ path: url.pathname, status: res.statusCode }); });
  try {
    if (req.headers.host !== '127.0.0.1:' + PORT && req.headers.host !== 'localhost:' + PORT) return json(res, 403, { error: 'local_test_only' });
    if (url.pathname === '/__e2e/report') return json(res, 200, state);
    if (url.pathname === '/__e2e') {
      const choice = url.searchParams.get('scenario');
      if (['normal', 'empty', 'catalog-error', 'library-error', 'live-error', 'showcase'].includes(choice)) state.scenario = choice;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><html lang="es"><title>Control E2E</title><body><h1>Entorno E2E aislado</h1><p>Vídeo local real. Catálogo, descargas y acciones nativas simuladas. Escenario: ' + escapeHtml(state.scenario) + '</p>' +
        ['normal', 'empty', 'catalog-error', 'library-error', 'live-error', 'showcase'].map(value => '<p><a href="?scenario=' + value + '">' + value + '</a></p>').join('') +
        '<p><a href="/">Abrir eSE</a></p><p><a href="/search">Buscar</a> · <a href="/mylist?tab=files">Biblioteca</a> · <a href="/live">Live TV</a> · <a href="/live/watch/' + fixtureStreamKey + '">Conexión Live simulada</a> · <a href="/live/watch/local">Player Live local (sin emisión)</a> · <a href="/connect">Conectar</a> · <a href="/app">App</a></p></body></html>');
    }
    if (url.pathname.startsWith('/api/tmdb/') || url.pathname.startsWith('/api/movies/')) return fixtureMetadata(url, req, res);
    if (url.pathname === '/api/stream/completed/list' && ['empty', 'library-error'].includes(state.scenario)) return json(res, state.scenario === 'empty' ? 200 : 503, state.scenario === 'empty' ? [] : { error: 'e2e_library_unavailable' });
    if (stream.handle(url, req, res)) return;
    if (url.pathname === '/api/emule/downloads') return json(res, state.scenario === 'library-error' ? 503 : 200, state.scenario === 'library-error' ? { error: 'unavailable' } : downloads());
    if (url.pathname === '/api/emule/download/action' || url.pathname === '/api/emule/download' || url.pathname === '/api/emule/ed2klink') {
      state.actions.push({ path: url.pathname, op: url.searchParams.get('op') }); return json(res, 200, { success: true, fixture: true });
    }
    if (url.pathname === '/api/emule/smartsearch' || url.pathname === '/api/emule/search') return json(res, 200, { success: true, results: [], reason: 'e2e_no_network_sources' });
    if (url.pathname === '/api/v1/lifecycle') return json(res, 200, { epoch: 1, restartedAt: 0 });
    if (url.pathname === '/api/nat-health') return json(res, 200, { hole_punch_attempts: 0, hole_punch_success: 0, fixture: true });
    if (url.pathname === '/api/settings') {
      if (req.method === 'POST') { for await (const chunk of req) {} state.actions.push({ path: url.pathname }); }
      return json(res, 200, { defaultQuality: 'auto', language: 'es', ...state.settings });
    }
    if (url.pathname === '/api/emule/status') return json(res, 200, { connected: true, loggedIn: true, webserverUp: true, status: 'connected' });
    if (url.pathname === '/api/tunnel/status') return json(res, 200, { active: false, publicUrl: null });
    if (url.pathname.startsWith('/api/live/')) return fixtureLive(url, req, res);
    if (url.pathname === '/api/eSE/update/check') return json(res, 200, { update_available: false, fixture: true });
    if (url.pathname === '/api/auth/session') return json(res, 200, { ok: true, fixture: true });
    if (url.pathname === '/api/status') return json(res, 200, { status: 'ok', version: 'E2E' });
    if (url.pathname.startsWith('/api/')) return json(res, 501, { error: 'native_action_not_available_in_e2e' });
    if (url.pathname === '/live') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return capture(res).end(live.render()); }
    if (url.pathname === '/live/player.js') { res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' }); return res.end(require('../eSE-live/live_tv_player').getScript()); }
    if (url.pathname === '/live/watch/local') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return capture(res).end(require('../live_player_html')()); }
    if (/^\/live\/watch\/[a-fA-F0-9]{32}$/.test(url.pathname)) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return capture(res).end(renderFixtureWatch(url.pathname.split('/')[3])); }
    const assets = { '/emule_mascot.svg': ['emule_mascot.svg', 'image/svg+xml'], '/favicon.ico': ['favicon.ico', 'image/x-icon'], '/live/vendor/hls.min.js': ['eSE-live/vendor/hls.min.js', 'application/javascript'] };
    if (assets[url.pathname]) { const [file, type] = assets[url.pathname]; res.writeHead(200, { 'Content-Type': type }); return res.end(fs.readFileSync(path.join(root, file))); }
    for (const page of [main, explore, search, library, connect, app, misc]) if (page.handle(url, req, capture(res)) || res.writableEnded) return;
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }); capture(res).end(require('../pages/not_found_page').render());
  } catch (error) { state.errors.push({ path: url.pathname, message: error.message }); if (!res.headersSent) json(res, 500, { error: error.message }); else res.end(); }
});
server.listen(PORT, '127.0.0.1', () => console.log('Isolated E2E: http://127.0.0.1:' + PORT + '/__e2e'));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { for (const child of Object.values(activeStreams)) child.kill(); server.close(() => process.exit(0)); });
