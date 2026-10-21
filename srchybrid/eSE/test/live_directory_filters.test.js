'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const vm = require('node:vm');
const search = require('../eSE-live/channel_search');

function directoryApi(local, kad) {
  const requests = [];
  const module = { exports: {} };
  const dirname = path.join(__dirname, '..', 'eSE-live');
  const context = vm.createContext({
    module, __dirname: dirname, process: { env: { ESE_TEST_MODE: '1' } }, console,
    setInterval() {}, clearInterval() {},
    require(name) {
      if (name === 'path' || name === 'os') return require(name);
      if (name === 'fs') return { existsSync: () => true };
      if (name === './channel_search') return { ...search, search: filters => search.filterChannels(local, filters) };
      if (name === './nodes_bootstrap') return { startFromEnv: () => Promise.resolve({ status: 'disabled' }) };
      if (name === 'http') return { get(url, _options, callback) {
        const request = new EventEmitter();
        request.destroy = () => {};
        requests.push({ url, respond() {
          const response = new EventEmitter();
          response.statusCode = 200;
          callback(response);
          response.emit('data', JSON.stringify({ streams: kad }));
          response.emit('end');
        } });
        return request;
      } };
      return {};
    }
  });
  vm.runInContext(fs.readFileSync(path.join(dirname, 'channel_api.js'), 'utf8'), context);
  requests.length = 0; // Initial directory syncs are inert mocks, never network calls.
  return query => {
    let status, data;
    const response = { writeHead(code) { status = code; }, end(body) { data = JSON.parse(body); } };
    assert.equal(module.exports.handleRoute(new URL('http://localhost/api/live/channels?' + query), { method: 'GET' }, response, {}), true);
    const request = requests.at(-1);
    assert.equal(request.url, 'http://127.0.0.1:4711/api/live/kad/streams');
    request.respond();
    assert.equal(status, 200);
    return data;
  };
}

function fixtures() {
  const now = Date.now();
  return {
    local: [
      { streamKey: 'DUP', title: 'Deportes locales', category: 'sports', language: 'es', bitrate: 8000, viewers: 1 },
      { streamKey: 'local_movie', title: 'Cine de casa', category: 'movies', language: 'es', bitrate: 3000, viewers: 5, started: new Date(now - 300000).toISOString() }
    ],
    kad: [
      { streamKey: 'dup', title: 'Cine duplicado', category: 'movies', language: 'es', bitrate: 8000, viewers: 100 },
      { streamKey: 'kad_movie', title: 'Ciné clásico', category: 'Cine', language: 'Español', bitrate: 5000, viewers: 25, startedAt: Math.floor(now / 1000) - 1800, broadcasterIP: 16777343 },
      { streamKey: 'kad_english', title: 'Cine en inglés', category: 'movies', language: 'en', bitrate: 8000, viewers: 100 },
      { streamKey: 'kad_sport', title: 'Cine y deporte', category: 'sports', language: 'es', bitrate: 5000, viewers: 10 },
      { streamKey: 'kad_sd', title: 'Cine pequeño', category: 'movies', language: 'es', bitrate: 600, viewers: 1 }
    ]
  };
}

test('merged channel endpoint applies query, category, language and quality to Kad and local channels', () => {
  const { local, kad } = fixtures();
  const get = directoryApi(local, kad);
  const result = get('q=%20cine%20&category=Pel%C3%ADculas&lang=Espa%C3%B1ol&quality=720p&sort=viewers');
  assert.deepEqual(result.channels.map(ch => ch.streamKey), ['kad_movie', 'local_movie']);
  assert.equal(result.total, 2);
  assert.ok(result.channels.every(ch => ch.category === 'movies' && ch.language === 'es'));
  assert.ok(result.channels.every(ch => Number.isFinite(ch.rating) && Number.isFinite(ch.uptimeMinutes)));
  assert.match(result.channels[0].thumbnailUrl, /^http:\/\//);
  assert.equal(get('q=does-not-exist').total, 0);
  assert.deepEqual(get('q=cine&category=movies&lang=es&quality=1080p').channels.map(ch => ch.streamKey), ['kad_movie']);
});

test('rating thresholds and ordering apply after the merged directory is scored', () => {
  const { local, kad } = fixtures();
  const get = directoryApi(local, kad);
  const filters = 'q=cine&category=movies&lang=es&quality=720p';
  const rated = get(filters + '&sort=rating').channels;
  assert.ok(rated[0].rating > rated[1].rating);
  const threshold = rated[1].rating + 1;
  assert.deepEqual(get(filters + '&minRating=' + threshold).channels.map(ch => ch.streamKey), [rated[0].streamKey]);
  assert.deepEqual(get(filters + '&sort=newest').channels.map(ch => ch.streamKey), ['local_movie', 'kad_movie']);
  assert.deepEqual(get(filters + '&sort=viewers').channels.map(ch => ch.streamKey), ['kad_movie', 'local_movie']);
});

test('filtering a merged snapshot is pure and treats unknown or invalid start times as unknown uptime', () => {
  const items = [{ streamKey: 'unknown', title: 'Canal', started: 'invalid', bitrate: 3000 }, { streamKey: 'known', title: 'Canal', startedAt: 1700000000, bitrate: 3000 }];
  const original = JSON.stringify(items);
  const result = search.filterChannels(items, { sortBy: 'newest' }, 1700000060000);
  assert.deepEqual(result.map(ch => ch.streamKey), ['known', 'unknown']);
  assert.equal(result[0].uptimeMinutes, 1);
  assert.equal(result[1].uptimeMinutes, 0);
  assert.equal(JSON.stringify(items), original);
});
