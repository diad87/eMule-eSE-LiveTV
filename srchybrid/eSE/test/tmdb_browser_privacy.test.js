'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const Module = require('node:module');
const { test } = require('node:test');
const root = path.resolve(__dirname, '..');
const fakeKey = 'FAKE_BROWSER_PRIVACY_FIXTURE_NOT_A_CREDENTIAL';

function renderPage(name) {
  const filename = path.join(root, 'pages', `${name}_page.js`);
  const originalLoader = Module._load;
  let credentialImports = 0;
  delete require.cache[filename];
  Module._load = function(request, parent, isMain) {
    if (request === '../api_keys') {
      credentialImports++;
      return { TMDB_KEY: fakeKey, getTmdbKey: () => fakeKey };
    }
    return originalLoader.call(this, request, parent, isMain);
  };
  let status;
  let body;
  try {
    const page = require(filename);
    page.handle(new URL(`http://127.0.0.1/${name}`), {}, {
      writeHead(value) { status = value; },
      end(value) { body = value; },
    });
  } finally { Module._load = originalLoader; }
  assert.equal(status, 200);
  assert.equal(credentialImports, 0, 'Browser page must not import authentication material');
  assert.equal(typeof body, 'string');
  assert.ok(!body.includes(fakeKey));
  assert.doesNotMatch(body, /TMDB_KEY|ESE_TMDB_KEY|api_key|api\.themoviedb\.org/);
  const scripts = [...body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1]).filter(Boolean);
  for (const source of scripts) new vm.Script(source, { filename: `${name}-rendered.js` });
  return scripts.find(source => source.includes(name === 'search' ? 'function fetchTmdb' : 'function loadSections'));
}

function browserHarness(source, configured, fixtureResults = []) {
  const elements = new Map();
  const requests = [];
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      hidden: true, innerHTML: '', textContent: '', value: '', style: {}, listeners: {}, children: [],
      classList: { toggle() {}, add() {}, remove() {} },
      addEventListener(name, callback) { this.listeners[name] = callback; },
      appendChild(child) { this.children.push(child); }, scrollBy() {},
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    document: {
      getElementById: element, querySelectorAll: () => [],
      createElement: () => ({ style: {} }),
    },
    window: { location: { href: '' } },
    fetch: async value => {
      const url = new URL(value, 'http://127.0.0.1');
      assert.equal(url.origin, 'http://127.0.0.1');
      assert.ok(url.pathname.startsWith('/api/tmdb/'));
      assert.equal(url.searchParams.has('api_key'), false);
      assert.ok(!url.href.includes(fakeKey));
      requests.push(url);
      return {
        ok: configured, status: configured ? 200 : 503,
        json: async () => configured ? { genres: [], results: fixtureResults, imdb_id: 'tt-test-fixture' }
          : { error: 'tmdb_not_configured' },
      };
    },
    setTimeout(callback) { callback(); return 1; }, clearTimeout() {},
    console: { log() {}, warn() {}, error() {} },
    URL, encodeURIComponent,
  });
  vm.runInContext(source, context, { timeout: 1000 });
  return { context, elements, requests, element };
}
async function flushPromises() {
  for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve));
}

test('search and explore render without importing or exposing a configured credential', () => {
  assert.ok(renderPage('search'));
  assert.ok(renderPage('explore'));
});

test('search uses only same-origin proxy including encoded user input and external-id lookup', async () => {
  const browser = browserHarness(renderPage('search'), true);
  await flushPromises();
  assert.equal(browser.requests.length, 2);
  const query = 'movie &api_key=CALLER_OVERRIDE';
  const input = browser.element('q');
  input.value = query;
  input.listeners.input.call(input);
  browser.context.openMovie({ id: 42, title: 'Fixture' });
  await flushPromises();
  assert.ok(browser.requests.some(url => url.searchParams.get('query') === query));
  assert.ok(browser.requests.some(url => url.pathname === '/api/tmdb/movie/42/external_ids'));
});

test('search shows a local setup message when metadata authentication is not configured', async () => {
  const browser = browserHarness(renderPage('search'), false);
  await flushPromises();
  assert.equal(browser.element('metadata-status').hidden, false);
  assert.match(browser.element('metadata-status').textContent, /Configura tu clave TMDB/);
  assert.equal(browser.requests.length, 2);
});

test('explore category URLs and external-id lookup stay on the local proxy', async () => {
  const browser = browserHarness(renderPage('explore'), true);
  await flushPromises();
  assert.ok(browser.requests.length >= 3);
  browser.context.openTMDB(42, 'tv', 'Fixture');
  await flushPromises();
  assert.ok(browser.requests.some(url => url.pathname === '/api/tmdb/tv/42/external_ids'));
});

test('explore handles missing credentials as setup state rather than an empty catalogue', async () => {
  const browser = browserHarness(renderPage('explore'), false);
  await flushPromises();
  assert.match(browser.element('carousel-0').textContent, /Configura tu clave TMDB/);
});

test('explore passes upstream titles and IDs as data instead of inline event-handler code', async () => {
  const title = "Director's cut');globalThis.injected=true;//<img src=x onerror=alert(1)>";
  const id = '42);globalThis.injected=true;//';
  const browser = browserHarness(renderPage('explore'), true, [{
    id, title, media_type: 'movie', poster_path: '/fixture.jpg',
  }]);
  await flushPromises();
  const card = browser.element('carousel-0').children[0];
  assert.ok(card);
  assert.equal(typeof card.onclick, 'function');
  assert.doesNotMatch(card.innerHTML, /<img src=x|onclick=/);
  let received;
  browser.context.openTMDB = (...args) => { received = args; };
  card.onclick();
  assert.deepEqual(received, [id, 'movie', title]);
  assert.equal(browser.context.injected, undefined);
});

test('legacy and fallback browser sources contain neither TMDB credentials nor direct API calls', () => {
  for (const relative of ['player.js', 'hero_ui.js', '_deprecated/player_combined_test.js',
    'pages/search_page.js', 'pages/explore_page.js', 'pages/mylist_page.js', 'pages/main_page.js']) {
    const source = fs.readFileSync(path.join(root, relative), 'utf8');
    assert.doesNotMatch(source, /TMDB_KEY|ESE_TMDB_KEY|api_key|api\.themoviedb\.org/, relative);
    // These two historical extraction fragments already fail standalone parsing
    // in A65 and are not packaged/bundled. Still remove credentials from their
    // tracked text without turning this security change into a fragment rewrite.
    if (!['hero_ui.js', '_deprecated/player_combined_test.js'].includes(relative)) {
      new vm.Script(source, { filename: relative });
    }
  }
});
