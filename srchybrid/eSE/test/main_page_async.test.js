'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { test } = require('node:test');

const filename = path.resolve(__dirname, '../pages/main_page.js');
const fakeKey = 'NOT_A_REAL_PROVIDER_CREDENTIAL_MAIN_PAGE_FIXTURE';

function loadPage(overrides = {}) {
  const module = { exports: {} };
  const localRequire = createRequire(filename);
  let credentialImports = 0;
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    module, exports: module.exports, __dirname: path.dirname(filename),
    require(name) {
      if (name === '../api_keys') {
        credentialImports++;
        return { TMDB_KEY: fakeKey, getTmdbKey: () => fakeKey };
      }
      return localRequire(name);
    },
  }, { filename, timeout: 1000 });
  module.exports.init({
    getDownloads: async () => [],
    getCompletedFiles: async () => [],
    // Match the production text escaper: attribute quotes need local handling.
    escapeHtml: value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'),
    cleanTitle: value => value,
    ...overrides,
  });
  return { page: module.exports, credentialImports: () => credentialImports };
}

function startResponse(page, pathname = '/') {
  let complete;
  const done = new Promise(resolve => { complete = resolve; });
  const response = {
    destroyed: false, writableEnded: false, headersSent: false,
    status: null, headers: null, body: null, writes: 0, ends: 0,
    writeHead(status, headers) {
      assert.equal(this.headersSent, false, 'headers may only be sent once');
      this.status = status;
      this.headers = headers;
      this.headersSent = true;
      this.writes++;
    },
    end(body) {
      assert.equal(this.writableEnded, false, 'response may only end once');
      this.body = body;
      this.writableEnded = true;
      this.ends++;
      complete(this);
    },
    destroy() { this.destroyed = true; complete(this); },
  };
  const handled = page.handle(new URL(pathname, 'http://127.0.0.1'), {}, response);
  return { handled, response, done };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function finish(started) {
  let timer;
  try {
    return await Promise.race([
      started.done,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('main page response did not end')), 1000);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

const flush = () => new Promise(resolve => setImmediate(resolve));
function decodeAttribute(value) {
  return value.replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

test('home waits for both asynchronous lists before sending success headers', async () => {
  const downloads = deferred();
  const completed = deferred();
  let startedLists = 0;
  const { page } = loadPage({
    getDownloads() { startedLists++; return downloads.promise; },
    getCompletedFiles() { startedLists++; return completed.promise; },
  });
  const started = startResponse(page);
  assert.equal(started.handled, true, 'router contract remains synchronous');
  assert.equal(startedLists, 2);
  assert.equal(started.response.headersSent, false);
  downloads.resolve([{ fileName: 'Downloading.mkv', partNum: '001', sizeMB: 12 }]);
  await flush();
  assert.equal(started.response.headersSent, false);
  completed.resolve([{ fileName: 'Completed.mp4', sizeMB: 23 }]);
  const response = await finish(started);
  assert.equal(response.status, 200);
  assert.equal(response.ends, 1);
  assert.match(response.body, /Downloading\.mkv/);
  assert.match(response.body, /Completed\.mp4/);
  assert.match(response.body, /onclick="playCompleted\(this\.dataset\.filename\)"/);
  assert.match(response.body, /onclick="playVideo\(this\.dataset\.partnum\)"/);
  assert.doesNotMatch(response.body, /playVideo\('undefined'\)/);
});

test('index alias renders empty async lists without provider imports or browser credential globals', async () => {
  const loaded = loadPage();
  const response = await finish(startResponse(loaded.page, '/index.html'));
  assert.equal(response.status, 200);
  assert.equal(response.headers['Content-Type'], 'text/html; charset=utf-8');
  assert.equal(loaded.credentialImports(), 0);
  assert.ok(!response.body.includes(fakeKey));
  assert.doesNotMatch(response.body, /TMDB_KEY|ESE_TMDB_KEY|OMDB_KEY|api_key|api\.themoviedb\.org/);
  for (const match of response.body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    new vm.Script(match[1], { filename: 'main-page-rendered.js' });
  }
});

for (const failedList of ['getDownloads', 'getCompletedFiles']) {
  test(`home closes a rejected ${failedList} with generic 500, not partial 200`, async () => {
    const { page } = loadPage({
      [failedList]: async () => { throw new Error(fakeKey + ' private filesystem path'); },
    });
    const response = await finish(startResponse(page));
    assert.equal(response.status, 500);
    assert.equal(response.writes, 1);
    assert.equal(response.ends, 1);
    assert.equal(response.body, 'No se pudo cargar la biblioteca.');
    assert.ok(!response.body.includes(fakeKey));
  });
}

test('home handles a synchronous list failure without an unhandled rejection', async () => {
  const { page } = loadPage({ getDownloads() { throw new Error(fakeKey); } });
  const response = await finish(startResponse(page));
  assert.equal(response.status, 500);
  assert.equal(response.ends, 1);
  assert.ok(!response.body.includes(fakeKey));
});

test('client disconnect while lists resolve does not write or end a closed response', async () => {
  const pending = deferred();
  const { page } = loadPage({ getDownloads: () => pending.promise });
  const started = startResponse(page);
  started.response.destroyed = true;
  pending.resolve([]);
  await flush();
  assert.equal(started.response.writes, 0);
  assert.equal(started.response.ends, 0);
});

test('card names and part identifiers are attribute data, never inline executable input', async () => {
  const hostileName = `O'Brien");globalThis.injected=true;//<img src=x onerror=alert(1)>.mp4`;
  const hostilePart = `001');globalThis.injected=true;//"`;
  const { page } = loadPage({
    getDownloads: async () => [{ fileName: 'Part.mkv', partNum: hostilePart }],
    getCompletedFiles: async () => [{ fileName: hostileName }],
  });
  const response = await finish(startResponse(page));
  assert.equal(response.status, 200);
  assert.doesNotMatch(response.body, /<img src=x/);
  const cards = [...response.body.matchAll(/<div class="card"\s[^>]*>/g)].map(match => match[0]);
  assert.equal(cards.length, 2);
  for (const card of cards) {
    const attributes = Object.fromEntries([...card.matchAll(/([\w-]+)="([^"]*)"/g)]
      .map(match => [match[1], decodeAttribute(match[2])]));
    let received;
    const context = vm.createContext({
      playCompleted: value => { received = ['completed', value]; },
      playVideo: value => { received = ['download', value]; },
      element: { dataset: { filename: attributes['data-filename'], partnum: attributes['data-partnum'] } },
    });
    vm.runInContext(`(function(){${attributes.onclick}}).call(element)`, context, { timeout: 1000 });
    assert.equal(context.injected, undefined);
    if (attributes['data-partnum'] !== undefined) {
      assert.deepEqual(received, ['download', hostilePart]);
    } else {
      assert.deepEqual(received, ['completed', encodeURIComponent(hostileName)]);
      assert.equal(attributes['data-title'], hostileName);
    }
  }
});

test('unrelated routes retain synchronous false without loading media lists', () => {
  const { page } = loadPage({ getDownloads() { throw new Error('unexpected media read'); } });
  const started = startResponse(page, '/not-main-page');
  assert.equal(started.handled, false);
  assert.equal(started.response.writes, 0);
  assert.equal(started.response.ends, 0);
});
