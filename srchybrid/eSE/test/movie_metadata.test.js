'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { createMetadataService, parseId, requestTmdb } = require('../movie_metadata');
const source = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const hasError = (code, status) => error => error.code === code && error.status === status;

test('a TMDB title without an IMDb ID opens directly with consistent, localized metadata', async () => {
  const calls = [];
  const service = createMetadataService({ request: async (...args) => {
    calls.push(args);
    return { id: 42, title: 'Una película', overview: 'Sinopsis en español.', release_date: '2026-10-01', runtime: 105,
      poster_path: '/poster.jpg', backdrop_path: '/backdrop.jpg', genres: [{ name: 'Drama' }],
      vote_count: 19, vote_average: 7.86, credits: { crew: [{ name: 'Directora', job: 'Director' }], cast: [{ name: 'Actor' }] } };
  } });
  const movie = await service.detail('tmdb:movie:42');
  assert.equal(calls.length, 1, 'Opening a canonical TMDB ID must not wait for IMDb/OMDb discovery');
  assert.equal(calls[0][0], 'movie/42');
  assert.equal(calls[0][1].language, 'es-ES');
  assert.equal(movie.catalogId, 'tmdb:movie:42');
  assert.equal(movie.imdbID, '');
  assert.equal(movie.Type, 'movie');
  assert.equal(movie.Title, 'Una película');
  assert.equal(movie.Plot, 'Sinopsis en español.');
  assert.equal(movie.Runtime, '105 min');
  assert.equal(movie.Rating, '7.9');
  assert.equal(movie.RatingSource, 'TMDB');
  assert.equal(movie.Director, 'Directora');
  assert.match(movie.Backdrop, /^https:\/\/image\.tmdb\.org\/t\/p\/w1280\/backdrop\.jpg$/);
  assert.deepEqual(movie.seasons, []);
});

test('home catalog search returns selectable movie and series IDs without OMDb or person results', async () => {
  const calls = [];
  const service = createMetadataService({ request: async (...args) => {
    calls.push(args);
    return { results: [{ id: 42, media_type: 'movie', title: 'Película', release_date: '2026-01-01' },
      { id: 77, media_type: 'tv', name: 'Serie', first_air_date: '2024-01-01' },
      { id: 1, media_type: 'person', name: 'Actor' }] };
  } });
  const data = await service.search('  Historia  ');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'search/multi');
  assert.equal(calls[0][1].query, 'Historia');
  assert.equal(calls[0][1].include_adult, false);
  assert.deepEqual(data.Search.map(item => [item.catalogId, item.Title, item.Type]), [
    ['tmdb:movie:42', 'Película', 'movie'], ['tmdb:tv:77', 'Serie', 'series']
  ]);
  assert.equal(data.Response, 'True');
  const ui = clientHarness();
  assert.match(ui.context.renderMovieCard(data.Search[0]), /showMovieDetail\('tmdb:movie:42'/);
  await assert.rejects(service.search(' '), hasError('invalid_query', 400));
  assert.equal(calls.length, 1);
});

test('legacy IMDb favorites resolve through TMDB and expose only verified series seasons', async () => {
  const calls = [];
  const service = createMetadataService({ request: async resource => {
    calls.push(resource);
    if (resource.startsWith('find/')) return { movie_results: [], tv_results: [{ id: 77 }] };
    return { id: 77, name: 'Una serie', first_air_date: '2024-05-01', external_ids: { imdb_id: 'tt1234567' },
      seasons: [null, { season_number: 2, name: 'Segunda temporada', episode_count: 6 },
        { season_number: 1, name: 'Primera temporada', episode_count: 4 },
        { season_number: 3, episode_count: 0 }, { season_number: '15', episode_count: 30 }],
      created_by: [{ name: 'Creadora' }], credits: { cast: null }, vote_average: 8, vote_count: 0 };
  } });
  const series = await service.detail('tt1234567');
  assert.deepEqual(calls, ['find/tt1234567', 'tv/77']);
  assert.equal(series.Type, 'series');
  assert.equal(series.imdbID, 'tt1234567');
  assert.equal(series.catalogId, 'tmdb:tv:77');
  assert.equal(series.Director, 'Creadora');
  assert.equal(series.totalSeasons, 2);
  assert.deepEqual(series.seasons.map(s => [s.number, s.episodeCount]), [[1, 4], [2, 6]]);
  assert.equal(series.Rating, '', 'An unrated title must not display a made-up score');
});

test('invalid IDs, ambiguous matches and mismatched provider metadata cannot open another title', async () => {
  let calls = 0;
  const noNetwork = createMetadataService({ request: async () => { calls++; return {}; } });
  for (const id of ['', 'tmdb:person:1', 'tmdb:movie:0', 'tmdb:tv:-1', 'tmdb:tv:01', 'tmdb:movie:1/credits', 'tt1', 'tt1234?extra=1']) {
    assert.throws(() => parseId(id), hasError('invalid_catalog_id', 400));
    await assert.rejects(noNetwork.detail(id), hasError('invalid_catalog_id', 400));
  }
  assert.equal(calls, 0);
  const ambiguous = createMetadataService({ request: async () => ({ movie_results: [{ id: 1 }], tv_results: [{ id: 2 }] }) });
  await assert.rejects(ambiguous.detail('tt1234'), hasError('title_not_found', 404));
  const mismatched = createMetadataService({ request: async () => ({ id: 43, title: 'Wrong title' }) });
  await assert.rejects(mismatched.detail('tmdb:movie:42'), hasError('invalid_metadata_response', 502));
});

test('season lookup returns the actual episode numbers and rejects invalid season requests before networking', async () => {
  const calls = [];
  const service = createMetadataService({ request: async resource => {
    calls.push(resource);
    return { season_number: 2, episodes: [null, { episode_number: 3, name: 'Final', air_date: '2026-10-03',
      overview: 'Todo termina.', runtime: 48, still_path: '/still.jpg', vote_average: 8.25, vote_count: 12 },
      { episode_number: 1, name: 'Inicio', air_date: '<b>', still_path: 'javascript:alert(1)', runtime: -4 }, { episode_number: 0 }, { episode_number: '30' }] };
  } });
  const result = await service.season('tmdb:tv:77', 2);
  assert.deepEqual(result.episodes.map(e => e.number), [1, 3]);
  assert.equal(result.episodes[1].name, 'Final');
  assert.deepEqual(result.episodes[1], { number: 3, name: 'Final', airDate: '2026-10-03', overview: 'Todo termina.',
    runtime: 48, still: 'https://image.tmdb.org/t/p/w300/still.jpg', rating: '8.3' });
  assert.deepEqual(result.episodes[0], { number: 1, name: 'Inicio', airDate: null, overview: '', runtime: 0, still: '', rating: '' });
  for (const [id, number] of [['tmdb:movie:77', 2], ['tt1234', 2], ['tmdb:tv:77', NaN], ['tmdb:tv:77', -1], ['tmdb:tv:77', 1.5]]) {
    await assert.rejects(service.season(id, number), hasError('invalid_season', 400));
  }
  assert.deepEqual(calls, ['tv/77/season/2']);
});

test('IMDb resolution and detail share one deadline instead of restarting the timeout', async () => {
  const calls = [];
  const service = createMetadataService({ timeoutMs: 5, request: async resource => {
    calls.push(resource);
    await new Promise(resolve => setTimeout(resolve, 15));
    return { movie_results: [{ id: 42 }] };
  } });
  await assert.rejects(service.detail('tt1234'), hasError('metadata_timeout', 504));
  assert.deepEqual(calls, ['find/tt1234']);
});

function fakeTransport(status, chunks, neverReply = false) {
  let destroyed = false;
  const get = (_url, _options, callback) => {
    const request = new EventEmitter();
    request.destroy = () => { destroyed = true; };
    if (!neverReply) process.nextTick(() => {
      const response = new EventEmitter();
      response.statusCode = status;
      response.resume = () => {};
      callback(response);
      for (const chunk of chunks) response.emit('data', chunk);
      response.emit('end');
    });
    return request;
  };
  return { get, destroyed: () => destroyed };
}

test('provider transport bounds dead connections, oversized bodies and invalid responses', async () => {
  const hanging = fakeTransport(200, [], true);
  await assert.rejects(requestTmdb('movie/42', {}, 10, hanging.get), hasError('metadata_timeout', 504));
  assert.equal(hanging.destroyed(), true);
  const oversized = fakeTransport(200, ['a'.repeat(2 * 1024 * 1024 + 1)]);
  await assert.rejects(requestTmdb('movie/42', {}, 100, oversized.get), hasError('metadata_response_too_large', 502));
  assert.equal(oversized.destroyed(), true);
  await assert.rejects(requestTmdb('movie/42', {}, 100, fakeTransport(200, ['not-json']).get), hasError('invalid_metadata_response', 502));
  await assert.rejects(requestTmdb('movie/42', {}, 100, fakeTransport(404, []).get), hasError('title_not_found', 404));
  await assert.rejects(requestTmdb('movie/42', {}, 100, fakeTransport(503, []).get), hasError('metadata_unavailable', 502));
});

function clientHarness() {
  const nodes = new Map();
  const pending = [];
  const notifications = [];
  const monitors = [];
  function element() {
    let html = '';
    const listeners = new Map();
    return { style: {}, value: '', disabled: false, hidden: false, listeners,
      set innerHTML(value) {
        html = value;
        this.value = '';
        for (const match of value.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>/g)) {
          const child = element();
          child.disabled = /\sdisabled(?:\s|>)/.test(match[0]);
          child.hidden = /\shidden(?:\s|>)/.test(match[0]);
          nodes.set(match[1], child);
        }
      },
      get innerHTML() { return html; },
      addEventListener(type, callback) { listeners.set(type, callback); },
      remove() { if (nodes.get(this.id) === this) nodes.delete(this.id); }
    };
  }
  const document = { getElementById: id => nodes.get(id) || null, querySelector: () => null,
    createElement: element, addEventListener() {}, removeEventListener() {},
    body: { style: {}, appendChild(node) { nodes.set(node.id, node); } } };
  const context = vm.createContext({ document, AbortController, setTimeout() { return 1; }, clearTimeout() {},
    fetch(url, options) { return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject })); },
    showNotification: text => notifications.push(text), monitorForFile: (...args) => monitors.push(args) });
  context.window = context;
  for (const file of ['shared/safe_dom.js', 'search_ui.js']) vm.runInContext(source(file), context, { filename: file });
  const respond = (index, data, ok = true) => pending[index].resolve({ ok, json: async () => data });
  return { context, document, nodes, pending, notifications, monitors, element, respond };
}

const seriesData = { Response: 'True', catalogId: 'tmdb:tv:77', Title: 'Una serie', Type: 'series', Year: '2026',
  seasons: [{ number: 1, name: 'Temporada 1', episodeCount: 2 }, { number: 2, name: 'Temporada 2', episodeCount: 3 }] };

test('detail reserves an artwork header only when the title has a usable image', async () => {
  for (const [Poster, expectedClass] of [['N/A', 'no-artwork'], ['javascript:alert(1)', 'no-artwork'], ['https://image.tmdb.org/t/p/w500/poster.jpg', 'has-artwork']]) {
    const ui = clientHarness();
    ui.context.showMovieDetail('tmdb:tv:77');
    ui.respond(0, Object.assign({}, seriesData, { Poster }));
    await flush();
    const modal = ui.nodes.get('movie-modal');
    assert.equal(modal.className, 'movie-modal active ' + expectedClass + ' is-series');
    assert.equal(modal.innerHTML.includes('class="modal-backdrop"'), expectedClass === 'has-artwork');
    assert.match(modal.innerHTML, /class="ep-browser"/);
    assert.doesNotMatch(modal.innerHTML, /background-image:url\(\)/);
  }
});

test('series open on the first season with its verified episodes listed and the first aired one ready', async () => {
  const ui = clientHarness();
  ui.context.showMovieDetail('tmdb:tv:77', null, 'Una serie');
  ui.respond(0, seriesData);
  await flush();
  assert.equal(ui.context._modalMovie.imdbId, 'tmdb:tv:77', 'No IMDb ID is needed to save a title');
  assert.equal(ui.context._modalMovie.type, 'tv');
  assert.match(ui.pending[1].url, /^\/api\/movies\/season\?id=tmdb%3Atv%3A77&season=1$/, 'the first season loads without asking');
  assert.equal(ui.nodes.get('modal-play-btn').disabled, true);
  assert.equal(ui.nodes.get('modal-play-label').textContent, 'Cargando episodios…');
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie');
  assert.match(ui.nodes.get('ep-seasons').innerHTML, /id="ep-season-1" aria-selected="true"/);
  assert.match(ui.nodes.get('ep-seasons').innerHTML, /id="ep-season-2" aria-selected="false"/);
  assert.doesNotMatch(ui.nodes.get('movie-modal').innerHTML, /Temporada 15|Capítulo 30/);
  ui.respond(1, { episodes: [{ number: 1, name: 'Inicio', airDate: '2020-01-01', overview: 'Empieza <b>todo</b>', runtime: 45 },
    { number: 2, name: 'Fin', airDate: '2999-01-01' }] });
  await flush();
  const panel = ui.nodes.get('ep-panel').innerHTML;
  assert.match(panel, /id="ep-row-1"/);
  assert.match(panel, /class="ep-row is-upcoming" id="ep-row-2"/);
  assert.match(panel, /Empieza &lt;b&gt;todo&lt;\/b&gt;/, 'episode synopses are data, not markup');
  assert.equal(ui.nodes.get('modal-play-btn').disabled, false);
  assert.equal(ui.nodes.get('modal-play-label').textContent, 'Reproducir T1 · E1');
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie 01x01');
  assert.match(ui.nodes.get('tv-picker-status').textContent, /^Temporada 1 · 2 episodios \(1 por estrenar\)$/);
  ui.context.selectEpisode(2);
  assert.equal(ui.nodes.get('modal-play-btn').disabled, true, 'an unaired episode cannot start a search');
  assert.equal(ui.nodes.get('modal-play-label').textContent, 'Aún no disponible');
  assert.equal(ui.nodes.get('ep-play-2').disabled, true);
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie');
});

test('switching seasons aborts stale requests, ignores unverified numbers and reuses loaded seasons', async () => {
  const ui = clientHarness();
  ui.context.showMovieDetail('tmdb:tv:77', null, 'Una serie');
  ui.respond(0, seriesData);
  await flush();
  ui.context.selectSeason(2);
  assert.equal(ui.pending[1].options.signal.aborted, true);
  assert.equal(ui.nodes.get('modal-play-btn').disabled, true);
  ui.respond(2, { episodes: [{ number: 1, name: 'Inicio' }, { number: 3, name: 'Final' }] });
  await flush();
  ui.respond(1, { episodes: [{ number: 99, name: 'Stale episode' }] });
  await flush();
  const panel = ui.nodes.get('ep-panel').innerHTML;
  assert.match(panel, /id="ep-row-3"/);
  assert.doesNotMatch(panel, /99|Stale/);
  assert.match(ui.nodes.get('ep-seasons').innerHTML, /id="ep-season-2" aria-selected="true"/);
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie 02x01');
  ui.context.selectEpisode(3);
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie 02x03');
  assert.equal(ui.nodes.get('modal-play-label').textContent, 'Reproducir T2 · E3');
  ui.context.selectEpisode(2);
  assert.equal(ui.context.getTvQuery('Una serie'), 'Una serie 02x03', 'numbers outside the verified list are ignored');
  ui.context.selectSeason(1);
  ui.respond(3, { episodes: [{ number: 1, name: 'Piloto' }] });
  await flush();
  ui.context.selectSeason(2);
  assert.equal(ui.pending.length, 4, 'a loaded season is not requested again');
  assert.match(ui.nodes.get('ep-panel').innerHTML, /id="ep-row-3"/);
});

test('episode actions search the exact episode, show its sources in place and resume from it later', async () => {
  const store = {};
  const storage = { getItem: key => store[key] || null, setItem: (key, value) => { store[key] = value; } };
  const episodes = { episodes: [{ number: 1, name: 'Inicio' }, { number: 2, name: 'Medio' }, { number: 3, name: 'Final' }] };
  const ui = clientHarness();
  const calls = [];
  ui.context.localStorage = storage;
  ui.context.smartPlay = (...args) => calls.push(['play', ...args]);
  ui.context.smartDownload = (...args) => calls.push(['download', ...args]);
  ui.context.showMovieDetail('tmdb:tv:77', null, 'Una serie');
  ui.respond(0, seriesData);
  await flush();
  ui.context.selectSeason(2);
  ui.respond(2, episodes);
  await flush();
  ui.context.selectEpisode(2);
  ui.context.episodeAction('sources', 2);
  assert.equal(ui.pending.at(-1).url, '/api/emule/search?q=' + encodeURIComponent('Una serie 02x02'));
  assert.match(ui.nodes.get('ep-sources-2').innerHTML, /Buscando fuentes/);
  assert.deepEqual(calls, [], 'looking at sources neither plays nor downloads');
  ui.context.episodeAction('play', 2);
  ui.context.seriesHeroAction('download');
  assert.deepEqual(calls, [['play', 'Una serie 02x02', ''], ['download', 'Una serie 02x02', '']]);
  const saved = JSON.parse(store['ese.seriesProgress.v1'])['tmdb:tv:77'];
  assert.deepEqual([saved.season, saved.episode], [2, 2]);

  const next = clientHarness();
  next.context.localStorage = storage;
  next.context.showMovieDetail('tmdb:tv:77', null, 'Una serie');
  next.respond(0, seriesData);
  await flush();
  assert.match(next.pending[1].url, /&season=2$/, 'the detail reopens on the season last watched');
  next.respond(1, episodes);
  await flush();
  assert.equal(next.nodes.get('modal-play-label').textContent, 'Continuar T2 · E2');
  assert.match(next.nodes.get('ep-panel').innerHTML, /<span class="ep-flag">Continuar<\/span>/);
  assert.equal(next.context.getTvQuery('Una serie'), 'Una serie 02x02');
});

test('unavailable episodes offer a retry without making up numbers, and replacement cancels the request', async () => {
  const ui = clientHarness();
  ui.context.showMovieDetail('tmdb:tv:77'); ui.respond(0, seriesData); await flush();
  ui.respond(1, {}, false); await flush();
  assert.equal(ui.nodes.get('tv-season-retry').hidden, false);
  assert.equal(ui.nodes.get('modal-play-btn').disabled, true);
  assert.match(ui.nodes.get('tv-picker-status').textContent, /No se han podido cargar/);
  assert.doesNotMatch(ui.nodes.get('ep-panel').innerHTML, /ep-row-/);
  ui.nodes.get('tv-season-retry').onclick();
  assert.equal(ui.nodes.get('tv-season-retry').hidden, true);
  const oldPanel = ui.nodes.get('ep-panel');
  ui.context.showMovieDetail('tmdb:movie:42');
  assert.equal(ui.pending[2].options.signal.aborted, true);
  ui.respond(2, { episodes: [{ number: 12, name: 'Late' }] }); await flush();
  assert.doesNotMatch(oldPanel.innerHTML, /Late/);
  assert.match(ui.nodes.get('movie-modal').innerHTML, /Cargando ficha/);
});

test('stream source responses cannot monitor after closing, replacement or choosing a newer source', async () => {
  for (const mode of ['close', 'replace', 'newer']) {
    const ui = clientHarness();
    ui.nodes.set('movie-modal', ui.element());
    ui.context.streamSource('old', 'Old title');
    if (mode === 'close') ui.nodes.delete('movie-modal');
    if (mode === 'replace') ui.nodes.set('movie-modal', ui.element());
    if (mode === 'newer') ui.context.streamSource('new', 'New title');
    ui.respond(0, { success: true }); await flush();
    assert.equal(ui.monitors.length, 0, mode);
    assert.equal(ui.notifications.length, 0, mode);
    if (mode === 'newer') {
      ui.respond(1, { success: true }); await flush();
      assert.deepEqual(ui.monitors, [['New title', '', 0, 0]]);
    }
  }
});

test('movie API routes preserve canonical IDs, reject invalid seasons and expose safe upstream errors', async () => {
  const calls = [];
  const module = { exports: {} };
  const service = {
    detail: async id => { calls.push(['detail', id]); return { Response: 'True', catalogId: id }; },
    search: async query => { calls.push(['search', query]); const error = new Error('private provider URL'); error.code = 'metadata_timeout'; error.status = 504; throw error; },
    season: async (id, season) => { calls.push(['season', id, season]); const error = new Error('invalid'); error.code = 'invalid_season'; error.status = 400; throw error; }
  };
  vm.runInNewContext(source('routes/movies_routes.js'), { module, Buffer, URL, console,
    require(name) {
      if (name === '../api_keys') return { TMDB_KEY: 'test-only' };
      if (name === '../movie_metadata') return { createMetadataService: () => service };
      return require(name);
    }
  });
  function response() { return { writeHead(status, headers) { this.status = status; this.headers = headers; }, end(body) { this.body = body; } }; }
  const detail = response();
  assert.equal(module.exports.handle(new URL('http://localhost/api/movies/detail?id=tmdb%3Atv%3A77'), {}, detail), true);
  await flush();
  assert.equal(detail.status, 200);
  assert.equal(JSON.parse(detail.body).catalogId, 'tmdb:tv:77');
  const invalidSeason = response();
  module.exports.handle(new URL('http://localhost/api/movies/season?id=tmdb%3Atv%3A77&season=1oops'), {}, invalidSeason);
  await flush();
  assert.equal(invalidSeason.status, 400);
  assert.equal(Number.isNaN(calls[1][2]), true);
  const failure = response();
  module.exports.handle(new URL('http://localhost/api/movies/search?q=Film'), {}, failure);
  await flush();
  assert.equal(failure.status, 504);
  assert.deepEqual(JSON.parse(failure.body), { Response: 'False', error: 'metadata_timeout' });
  assert.doesNotMatch(failure.body, /private|URL/);
  const disconnected = Object.assign(response(), { destroyed: true });
  module.exports.handle(new URL('http://localhost/api/movies/detail?id=tmdb%3Amovie%3A42'), {}, disconnected);
  await flush();
  assert.equal(disconnected.body, undefined);
});

test('Mi Lista preserves corrupted storage on read, remove and undo instead of silently replacing it', () => {
  let html;
  require('../pages/mylist_page').handle(new URL('http://localhost/mylist'), {}, { writeHead() {}, end(value) { html = value; } });
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]).find(text => text.includes('function readSavedList'));
  const listScript = script.slice(0, script.indexOf('// v7.4.0'));
  for (const stored of ['not-json', '{}', '[null]', '[{}]', '[{"imdbId":""}]', '[{"imdbId":"tmdb:movie:42"},{}]']) {
    const nodes = new Map(['ml-content', 'ml-count', 'ml-notice'].map(id => [id, { innerHTML: '', textContent: '' }]));
    let writes = 0;
    const context = vm.createContext({ document: { getElementById: id => nodes.get(id), querySelectorAll: () => [] },
      localStorage: { getItem: () => stored, setItem() { writes++; } } });
    vm.runInContext(listScript, context);
    assert.match(nodes.get('ml-content').innerHTML, /No se ha podido leer/);
    assert.equal(nodes.get('ml-count').textContent, 'Lista no disponible');
    context.removeItem('tmdb:movie:42');
    context.removedItem = { item: { imdbId: 'tmdb:movie:42' }, index: 0 };
    context.undoRemove();
    assert.equal(writes, 0, 'Malformed saved content must remain recoverable');
  }
});
