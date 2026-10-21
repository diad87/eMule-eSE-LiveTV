'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const mainPage = require('../pages/main_page');

function createHome(search) {
  mainPage.init({ getDownloads: () => [], getCompletedFiles: () => [], escapeHtml: s => s, cleanTitle: s => s });
  let html;
  mainPage.handle(new URL('http://localhost/'), {}, { writeHead() {}, end(value) { html = value; } });
  const nodes = new Map();
  const timers = [];
  const requests = [];
  let focused = null;
  let scrolled = null;
  for (const match of html.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const id = match[1];
    const classes = new Set((match[0].match(/class="([^"]*)"/) || ['', ''])[1].split(/\s+/));
    nodes.set(id, {
      id, value: '', style: {}, innerHTML: '',
      focus() { focused = id; },
      scrollIntoView() { scrolled = id; },
      classList: { contains: s => classes.has(s), add: s => classes.add(s), remove: s => classes.delete(s) }
    });
  }
  const context = vm.createContext({
    URLSearchParams,
    location: { search, replace(value) { this.href = value; } },
    history: { replaceState() {} },
    document: {
      getElementById: id => nodes.get(id) || null,
      querySelector: () => null,
      createElement: () => ({}),
      addEventListener() {},
      body: { style: {} },
      head: { appendChild() {} }
    },
    setTimeout(fn, delay) { timers.push({ fn, delay }); },
    clearTimeout() {}, setInterval() {},
    getWatchSession: () => null,
    localStorage: { getItem: () => null },
    sessionStorage: { getItem: () => null },
    fetch(url) {
      requests.push(url);
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ Search: [{ Title: 'Dune', Year: '2021', imdbID: 'tt1160419' }] }) });
    }
  });
  context.window = context;
  for (const file of ['shared/safe_dom.js', 'search_ui.js', 'init.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context, { filename: file });
  }
  return { context, html, nodes, timers, requests, focused: () => focused, scrolled: () => scrolled };
}

test('legacy home query redirects to the single catalog search preserving the query', () => {
  const home = createHome('?search=Dune');
  assert.equal(home.context.location.href, '/search?q=Dune');
  assert.deepEqual(home.requests, []);
});

test('the legacy search command opens the same page without a duplicate overlay', () => {
  const home = createHome('');
  home.context.toggleSearchOverlay();
  assert.equal(home.context.location.href, '/search');
  assert.equal(home.nodes.has('search-overlay'), false);
  assert.deepEqual(home.requests, []);
});

test('file links open the local player and retain a safe return to the Files tab', () => {
  const home = createHome('?play=' + encodeURIComponent('Un vídeo.mp4') + '&returnTo=' + encodeURIComponent('/mylist?tab=files'));
  const plays = [];
  home.context.playCompleted = name => plays.push(name);
  home.timers.find(timer => timer.delay === 0).fn();
  assert.deepEqual(plays, [encodeURIComponent('Un vídeo.mp4')]);
  assert.equal(home.context._detailReturnTo, '/mylist?tab=files');
});

test('detail return context accepts catalog routes and rejects external destinations', () => {
  for (const destination of ['/search?q=Dune&type=tv', '/explore?cat=series', '/mylist']) {
    const home = createHome('?detail=tt1234&returnTo=' + encodeURIComponent(destination));
    assert.equal(home.context._detailReturnTo, destination);
  }
  for (const destination of ['//example.com', 'https://example.com', '/connect', '/search/../../connect', '/search\n?x=1']) {
    const home = createHome('?detail=tt1234&returnTo=' + encodeURIComponent(destination));
    assert.equal(home.context._detailReturnTo, undefined);
  }
});
