'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const flush = () => new Promise(resolve => setImmediate(resolve));

function harness(page, search = '', saved = []) {
  let html;
  require('../pages/' + page + '_page').handle(new URL('http://localhost/' + (page === 'mylist' ? 'mylist' : 'search')), {}, { writeHead() {}, end(value) { html = value; } });
  const nodes = new Map(), timers = new Map(), events = new Map(), pending = [], historyEntries = [];
  let timer = 0;
  const document = { activeElement: null, getElementById: id => nodes.get(id) || null,
    querySelectorAll: selector => selector === '.ml-tab' ? tabs : selector === '.search-filter' ? filters : [],
    querySelector: () => null, createElement: () => element() };
  function element(attrs = {}) {
    let html = '', text = '';
    const listeners = new Map();
    const classes = new Set((attrs.class || '').split(' '));
    return { children: [], style: {}, dataset: { type: attrs['data-type'] }, value: '', hidden: false, disabled: false, listeners,
      set innerHTML(value) { html = value; this.children = []; }, get innerHTML() { return html; },
      set textContent(value) { text = value; this.children = []; }, get textContent() { return text; },
      setAttribute(key, value) { attrs[key] = value; }, getAttribute: key => attrs[key],
      classList: { toggle(key, enabled) { enabled ? classes.add(key) : classes.delete(key); } },
      appendChild(child) { this.children.push(child); }, addEventListener(type, listener) { listeners.set(type, listener); },
      querySelectorAll: () => [], querySelector: () => null, focus() { document.activeElement = this; }, contains: () => false
    };
  }
  const tabs = [], filters = [];
  for (const match of html.matchAll(/<[^>]+>/g)) {
    const attrs = Object.fromEntries([...match[0].matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
    if (!attrs.id && !attrs['data-tab'] && !attrs['data-type']) continue;
    const node = element(attrs); node.hidden = /\shidden(?:\s|>)/.test(match[0]);
    if (attrs.id) nodes.set(attrs.id, node);
    if (attrs['data-tab']) tabs.push(node);
    if (attrs['data-type']) filters.push(node);
  }
  const location = { search, href: 'http://localhost/' + page + search };
  const context = vm.createContext({ document, location, URLSearchParams, AbortController,
    localStorage: { getItem: () => JSON.stringify(saved), setItem() {} },
    history: { pushState(_state, _title, url) { historyEntries.push(url); location.search = new URL(url, 'http://localhost').search; }, replaceState(_state, _title, url) { location.search = new URL(url, 'http://localhost').search; } },
    setTimeout(fn) { timers.set(++timer, fn); return timer; }, clearTimeout(id) { timers.delete(id); }, setInterval() { return 1; }, clearInterval() {},
    addEventListener(type, listener) { events.set(type, listener); },
    fetch(url, options) { return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject })); }
  });
  context.window = context;
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]).find(s => page === 'mylist' ? s.includes('function readSavedList') : s.includes('var searchTimer'));
  vm.runInContext(script, context);
  function runTimers() { const calls = [...timers.values()]; timers.clear(); calls.forEach(fn => fn()); }
  async function reply(request, body, ok = true) { request.resolve({ ok, status: ok ? 200 : 503, json: async () => body }); await flush(); }
  return { context, nodes, pending, events, historyEntries, location, document, html, runTimers, reply, tabs, filters };
}
const movie = (id, title = 'Película ' + id) => ({ id, title, media_type: 'movie', release_date: '2026-01-01' });

test('search keeps discovery to six suggestions and a link to the full Explore catalog', async () => {
  const ui = harness('search');
  await ui.reply(ui.pending[0], { results: Array.from({ length: 9 }, (_, i) => movie(i + 1)) });
  assert.equal(ui.nodes.get('trending-grid').children.length, 6);
  assert.match(ui.html, /href="\/explore">Explorar todo el catálogo/);
});

test('load more appends unique titles, prevents double requests and retries the same failed page', async () => {
  const ui = harness('search', '?q=Película'); ui.runTimers();
  const first = ui.pending.find(p => p.url.includes('/search/'));
  assert.match(first.url, /page=1$/);
  await ui.reply(first, { page: 1, total_pages: 3, results: [movie(1), movie(2)] });
  const more = ui.nodes.get('results-more');
  assert.equal(more.hidden, false); more.focus(); more.listeners.get('click')(); more.listeners.get('click')();
  assert.equal(ui.pending.filter(p => p.url.includes('page=2')).length, 1);
  await ui.reply(ui.pending.at(-1), {}, false);
  assert.equal(ui.nodes.get('results-grid').children.length, 2);
  assert.match(ui.nodes.get('results-more-status').textContent, /Los anteriores siguen disponibles/);
  assert.equal(more.disabled, false); more.listeners.get('click')();
  assert.match(ui.pending.at(-1).url, /page=2$/);
  await ui.reply(ui.pending.at(-1), { page: 2, total_pages: 3, results: [movie(2), movie(3)] });
  assert.equal(ui.nodes.get('results-grid').children.length, 3);
  assert.equal(ui.document.activeElement, ui.nodes.get('results-grid').children[2]);
  assert.equal(ui.nodes.get('results-grid').children[2].getAttribute('tabindex'), undefined, 'An appended card stays in natural keyboard order');
  more.listeners.get('click')(); await ui.reply(ui.pending.at(-1), { page: 3, total_pages: 3, results: [movie(4)] });
  assert.equal(ui.nodes.get('results-grid').children.length, 4);
  assert.equal(more.hidden, true);
});

test('changing query aborts a pending next page and late results cannot append to the new search', async () => {
  const ui = harness('search', '?q=First'); ui.runTimers();
  await ui.reply(ui.pending.find(p => p.url.includes('/search/')), { page: 1, total_pages: 2, results: [movie(1)] });
  ui.nodes.get('results-more').listeners.get('click')(); const stale = ui.pending.at(-1);
  ui.nodes.get('q').value = 'Second'; ui.context.updateSearch(true); ui.runTimers();
  assert.equal(stale.options.signal.aborted, true);
  await ui.reply(ui.pending.at(-1), { page: 1, total_pages: 1, results: [movie(8, 'Second')] });
  await ui.reply(stale, { page: 2, total_pages: 2, results: [movie(9, 'Old response')] });
  assert.equal(ui.nodes.get('results-grid').children.length, 1);
  assert.match(ui.nodes.get('results-grid').children[0].innerHTML, /Second/);
  assert.doesNotMatch(ui.nodes.get('results-grid').children[0].innerHTML, /Old response/);
});

test('returning from an appended title restores its page directly and retains a route to the first page', async () => {
  const ui = harness('search', '?q=Film&type=movie&page=2'); ui.runTimers();
  const request = ui.pending.find(p => p.url.includes('/search/'));
  assert.match(request.url, /page=2$/);
  assert.equal(ui.pending.filter(p => p.url.includes('/search/')).length, 1, 'Return does not fetch every preceding page');
  await ui.reply(request, { page: 2, total_pages: 3, results: [movie(7)] });
  assert.match(ui.nodes.get('results-summary').textContent, /Desde la página 2/);
  assert.equal(ui.nodes.get('results-first').hidden, false);
  ui.nodes.get('results-grid').children[0].onclick();
  const detail = new URL(ui.location.href, 'http://localhost');
  assert.equal(detail.searchParams.get('returnTo'), '/search?q=Film&type=movie&page=2');
  ui.nodes.get('results-first').listeners.get('click')(); ui.runTimers();
  assert.match(ui.pending.at(-1).url, /page=1$/);
  assert.equal(ui.nodes.get('results-first').hidden, true);
});

test('saved title links explicitly return to Guardados within Biblioteca', () => {
  const ui = harness('mylist', '', [{ imdbId: 'tmdb:movie:42', title: 'Film' }]);
  const href = ui.nodes.get('ml-content').innerHTML.match(/href="([^"]+)"/)[1].replace(/&amp;/g, '&');
  assert.equal(new URL(href, 'http://localhost').searchParams.get('returnTo'), '/mylist?tab=mylist');
});

test('Biblioteca preserves the old default, pushes tab URLs and restores them with browser history', async () => {
  const ui = harness('mylist');
  assert.equal(ui.context._activeTab, 'mylist');
  assert.equal(ui.pending.length, 0);
  ui.context.switchTab('files');
  assert.equal(ui.historyEntries.at(-1), '/mylist?tab=files');
  const stale = ui.pending.at(-1);
  assert.equal(stale.url, '/api/stream/completed/list');
  ui.context.switchTab('mylist');
  assert.equal(ui.historyEntries.at(-1), '/mylist?tab=mylist');
  assert.equal(stale.options.signal.aborted, true);
  await ui.reply(stale, [{ fileName: 'Stale.mp4', sizeMB: 4 }]);
  assert.equal(ui.context._files, null);
  const changes = ui.historyEntries.length;
  ui.location.search = '?tab=files'; ui.events.get('popstate')();
  assert.equal(ui.context._activeTab, 'files');
  assert.equal(ui.historyEntries.length, changes);
  assert.equal(ui.nodes.get('ml-tab-mylist').style.display, 'none');
  assert.equal(ui.nodes.get('ml-tab-files').style.display, '');
});

test('local files filter accented names and keep hostile filenames as encoded playback data', async () => {
  const ui = harness('mylist', '?tab=files');
  const hostile = 'Película\' "><img src=x onerror=alert(1)>.mp4';
  await ui.reply(ui.pending[0], [{ fileName: hostile, sizeMB: 1536 }, { fileName: 'Otro.mkv', sizeMB: 50 }]);
  let html = ui.nodes.get('files-content').innerHTML;
  assert.match(html, /1\.5 GB/); assert.doesNotMatch(html, /<img src=x/);
  const href = [...html.matchAll(/href="([^"]+)"/g)][0][1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
  const url = new URL(href, 'http://localhost');
  assert.equal(url.searchParams.get('play'), hostile);
  assert.equal(url.searchParams.get('returnTo'), '/mylist?tab=files');
  ui.nodes.get('files-query').value = 'pelicula'; ui.context.renderFiles();
  assert.equal(ui.nodes.get('files-count').textContent, '1 de 2 archivos');
  assert.doesNotMatch(ui.nodes.get('files-content').innerHTML, /Otro/);
  ui.nodes.get('files-query').value = 'Missing'; ui.context.renderFiles();
  assert.equal(ui.nodes.get('files-empty').hidden, false);
  ui.context.clearFilesFilter(); assert.equal(ui.nodes.get('files-empty').hidden, true);
});

test('file failures remain distinct from empty storage and refresh preserves the last valid list', async () => {
  const ui = harness('mylist', '?tab=files');
  await ui.reply(ui.pending[0], {}, false);
  assert.match(ui.nodes.get('files-notice').textContent, /No se han podido cargar/);
  assert.equal(ui.nodes.get('files-empty').hidden, true);
  ui.context.loadFiles(); await ui.reply(ui.pending.at(-1), [{ fileName: 'Film.mp4', sizeMB: 20 }]);
  const previous = ui.nodes.get('files-content').innerHTML;
  ui.context.loadFiles(); await ui.reply(ui.pending.at(-1), [{ fileName: '../not-safe.mp4' }]);
  assert.equal(ui.nodes.get('files-content').innerHTML, previous);
  assert.match(ui.nodes.get('files-notice').textContent, /Se conserva la última lista/);
  ui.context.loadFiles(); await ui.reply(ui.pending.at(-1), []);
  assert.equal(ui.nodes.get('files-empty').hidden, false);
  assert.match(ui.nodes.get('files-empty').innerHTML, /Todavía no hay archivos terminados/);
});
