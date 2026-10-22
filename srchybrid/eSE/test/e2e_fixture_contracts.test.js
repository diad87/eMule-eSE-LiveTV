'use strict';

// Exercise the actual E2E request handler without opening sockets, spawning
// processes, importing channel_api/server.js, or writing fixture/user files.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');

const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'tools/e2e_server.js'), 'utf8');
const key = 'AB'.repeat(16);

function harness() {
  let handler, binding;
  const imported = [];
  const page = { init() {}, handle() { return false; } };
  const context = vm.createContext({
    __dirname: path.join(root, 'tools'), URL, URLSearchParams, console: { log() {} },
    process: { on() {} },
    require(name) {
      imported.push(name);
      if (name === 'node:path') return path;
      if (name === 'node:http') return { createServer(callback) {
        handler = callback;
        return { listen(port, host) { binding = { port, host }; }, close() {} };
      } };
      if (name === 'node:fs') return {
        mkdirSync(directory) { assert.equal(directory, path.resolve(root, '../../artifacts/ese-e2e-2026-10-11/media')); },
        readFileSync(file, encoding) {
          assert.equal(path.resolve(file), path.join(root, 'eSE-live/channel_api.js'));
          return fs.readFileSync(file, encoding);
        }
      };
      if (name === '../utils') return { escapeHtml: value => String(value), cleanTitle: value => value };
      if (name === '../media_resolver') return { getCompletedFiles: () => [], resolveMediaFile: () => null };
      if (name === '../routes/stream_completed') return { init() {}, handle: () => false };
      if (name.startsWith('../pages/')) return page;
      if (name === '../eSE-live/live_tv_page') return { render: () => '<html><body>Live renderer stub</body></html>' };
      if (name === '../eSE-live/live_tv_player') return require('../eSE-live/live_tv_player');
      if (name === '../live_player_html') return require('../live_player_html');
      if (name === '../eSE-live/live_watch_page') return require('../eSE-live/live_watch_page');
      throw new Error('Unapproved module in isolated E2E host: ' + name);
    }
  });
  vm.runInContext(source, context, { filename: 'tools/e2e_server.js' });
  return {
    binding, imported,
    async request(url, method = 'GET', host = '127.0.0.1:8092') {
      const response = new EventEmitter();
      response.statusCode = 200;
      response.headers = {};
      response.setHeader = (name, value) => { response.headers[name.toLowerCase()] = value; };
      response.writeHead = (code, headers = {}) => {
        response.statusCode = code;
        response.headersSent = true;
        for (const [name, value] of Object.entries(headers)) response.setHeader(name, value);
      };
      response.end = body => { response.body = body || ''; response.writableEnded = true; response.emit('finish'); };
      await handler({ url, method, headers: { host } }, response);
      assert.equal(response.writableEnded, true, 'request must settle');
      if ((response.headers['content-type'] || '').includes('application/json')) response.data = JSON.parse(response.body);
      return response;
    }
  };
}

test('E2E host binds loopback and denies foreign hosts and unsupported native operations', async () => {
  const host = harness();
  assert.deepEqual(host.binding, { port: 8092, host: '127.0.0.1' });
  assert.equal((await host.request('/api/status', 'GET', 'untrusted.example')).statusCode, 403);
  assert.equal((await host.request('/api/live/broadcast/start', 'POST')).statusCode, 501);
  assert.equal((await host.request('/api/live/direct_join?ip=192.0.2.20')).statusCode, 501);
  assert.equal((await host.request('/api/stream/cleanup', 'POST')).statusCode, 501);
  assert.ok(!host.imported.some(name => /(?:channel_api|server|child_process)/.test(name)));
});

test('every paginated catalogue card resolves to its own canonical detail and IMDb identity', async () => {
  const host = harness();
  const identifiers = new Set();
  for (const page of [1, 2]) {
    const list = await host.request('/api/tmdb/search/multi?query=prueba&page=' + page);
    assert.equal(list.data.results.length, 8);
    for (const item of list.data.results) {
      const id = 'tmdb:' + item.media_type + ':' + item.id;
      const detail = await host.request('/api/movies/detail?id=' + encodeURIComponent(id));
      assert.equal(detail.statusCode, 200);
      assert.equal(detail.data.catalogId, id);
      assert.equal(detail.data.Title, item.title || item.name);
      assert.equal(detail.data.tmdbId, item.id);
      assert.equal(identifiers.has(detail.data.imdbID), false);
      identifiers.add(detail.data.imdbID);
      const legacy = await host.request('/api/movies/detail?id=' + detail.data.imdbID);
      assert.equal(legacy.data.catalogId, id);
      const external = await host.request('/api/tmdb/' + item.media_type + '/' + item.id + '/external_ids');
      assert.equal(external.data.imdb_id, detail.data.imdbID);
    }
  }
  assert.equal(identifiers.size, 16);
  assert.equal((await host.request('/api/movies/detail?id=tmdb:movie:999')).statusCode, 404);
  assert.equal((await host.request('/api/movies/detail?id=tmdb:movie:101')).statusCode, 404);
});

test('series seasons preserve page-two identity and reject nonexistent episodes or movie seasons', async () => {
  const host = harness();
  const series = await host.request('/api/movies/detail?id=tmdb:tv:1101');
  assert.equal(series.data.Year, '2025');
  assert.equal(series.data.Title, 'Serie de prueba · página 2');
  const season = await host.request('/api/movies/season?id=tmdb:tv:1101&season=2');
  assert.equal(season.data.catalogId, 'tmdb:tv:1101');
  assert.deepEqual(season.data.episodes.map(episode => episode.number), [1, 2]);
  assert.equal((await host.request('/api/movies/season?id=tmdb:tv:1101&season=3')).statusCode, 404);
  assert.equal((await host.request('/api/movies/season?id=tmdb:movie:1100&season=1')).statusCode, 404);
  const find = await host.request('/api/tmdb/find/tt1001101?external_source=imdb_id');
  assert.deepEqual(find.data.tv_results.map(item => item.id), [1101]);
  assert.deepEqual(find.data.movie_results, []);
});

test('catalogue pagination, filters, empty and failed scenarios have distinct contracts', async () => {
  const host = harness();
  const page = await host.request('/api/tmdb/search/movie?query=prueba&page=2');
  assert.equal(page.data.results.length, 7);
  assert.equal(page.data.total_pages, 2);
  assert.equal(page.data.total_results, 14);
  assert.ok(page.data.results.every(item => item.media_type === 'movie' && item.id >= 1100));
  assert.deepEqual((await host.request('/api/tmdb/search/multi?page=3')).data.results, []);
  assert.equal((await host.request('/api/tmdb/search/multi?page=NaN')).statusCode, 400);
  assert.equal((await host.request('/api/tmdb/unsupported')).statusCode, 501);
  await host.request('/__e2e?scenario=empty');
  assert.deepEqual((await host.request('/api/tmdb/search/multi')).data.results, []);
  assert.deepEqual((await host.request('/api/stream/completed/list')).data, []);
  await host.request('/__e2e?scenario=catalog-error');
  assert.equal((await host.request('/api/movies/detail?id=tmdb:movie:100')).statusCode, 503);
  await host.request('/__e2e?scenario=library-error');
  assert.equal((await host.request('/api/stream/completed/list')).statusCode, 503);
});

test('Live status fixtures match production field types and report refresh failures honestly', async () => {
  const host = harness();
  const connection = await host.request('/api/live/connection-status');
  assert.equal(connection.data.connected, true);
  assert.equal(typeof connection.data.nodeCount, 'number');
  assert.equal(connection.data.fixture, true);
  const preflight = await host.request('/api/live/preflight');
  for (const field of ['kad_connected', 'high_id', 'firewall_checking', 'ffmpeg_found']) assert.equal(typeof preflight.data[field], 'boolean');
  const monitor = await host.request('/api/live/monitor');
  assert.equal(monitor.data.broadcasting, false);
  assert.equal(monitor.data.viewing, false);
  assert.equal((await host.request('/api/live/status')).data.status, 'idle');
  assert.equal((await host.request('/api/live/first_run')).data.first_run, false);
  assert.equal((await host.request('/api/live/update_status')).data.has_update, false);
  assert.equal((await host.request('/api/live/channels')).data.channels.length, 1);
  assert.equal((await host.request('/api/live/channels?lang=en')).data.channels.length, 0);
  await host.request('/__e2e?scenario=empty');
  assert.deepEqual((await host.request('/api/live/channels')).data.channels, []);
  await host.request('/__e2e?scenario=live-error');
  for (const endpoint of ['channels', 'connection-status', 'preflight', 'monitor', 'status']) {
    const result = await host.request('/api/live/' + endpoint);
    assert.equal(result.statusCode, 503);
    assert.equal(result.data.error, 'e2e_live_unavailable');
  }
});

test('production watch renders without joining; simulated join fails recoverably and records intent', async () => {
  const host = harness();
  const watch = await host.request('/live/watch/' + key);
  assert.equal(watch.statusCode, 200);
  assert.match(watch.body, /id="join-start"/);
  assert.match(watch.body, new RegExp("const streamHash='" + key + "'"));
  assert.deepEqual((await host.request('/__e2e/report')).data.actions, []);
  assert.equal((await host.request('/api/live/join?key=' + key)).statusCode, 405);
  const join = await host.request('/api/live/join?key=' + key, 'POST');
  assert.equal(join.statusCode, 503);
  assert.equal(join.data.success, false);
  assert.equal(join.data.error, 'e2e_no_live_broadcast');
  assert.equal((await host.request('/api/live/leave?key=' + key, 'POST')).data.success, true);
  assert.deepEqual((await host.request('/__e2e/report')).data.actions.map(action => [action.method, action.path, action.key]), [
    ['POST', '/api/live/join', key], ['POST', '/api/live/leave', key]
  ]);
  assert.ok(!host.imported.some(name => name.includes('channel_api')));
});

test('Live browser script and local player use production renderers; E2E banner cannot overlay controls', async () => {
  const host = harness();
  const script = await host.request('/live/player.js');
  assert.equal(script.body, require('../eSE-live/live_tv_player').getScript());
  const local = await host.request('/live/watch/local');
  assert.equal(local.statusCode, 200);
  assert.match(local.body, /hls\.loadSource\('\/hls\/stream\.m3u8'\)/);
  for (const endpoint of ['/live', '/live/watch/' + key, '/live/watch/local']) {
    const page = await host.request(endpoint);
    const footer = page.body.match(/<footer[^>]*>[\s\S]*?<\/footer>/);
    assert.ok(footer);
    assert.match(footer[0], /position:static/);
    assert.doesNotMatch(footer[0], /position:fixed|z-index/);
  }
});
