'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const directory = require('../eSE-live/live_tv_directory');
const player = require('../eSE-live/live_tv_player');

const channel = (key, title = key) => ({ streamKey: key, title, language: 'es', category: 'movies', viewers: 2 });

function viewer() {
  const nodes = {};
  const requests = [];
  const document = { activeElement: null, getElementById: id => nodes[id] || null };
  function node(id) {
    return { id, value: '', textContent: '', hidden: false, style: {}, attrs: {},
      setAttribute(name, value) { this.attrs[name] = value; },
      getAttribute(name) { return this.attrs[name] || null; },
      focus() { document.activeElement = this; },
      closest() { return null; }
    };
  }
  for (const id of ['dir-search', 'dir-category', 'dir-lang', 'dir-sort', 'dir-reset', 'directory-status', 'directory-retry', 'live-empty', 'live-empty-title', 'live-empty-text', 'last-refresh']) nodes[id] = node(id);
  nodes['dir-category'].value = nodes['dir-lang'].value = 'all';
  nodes['dir-sort'].value = 'rating';
  nodes['directory-retry'].hidden = true;
  const list = nodes['channel-list'] = node('channel-list');
  list.cards = [];
  Object.defineProperty(list, 'innerHTML', {
    get() { return this.html || ''; },
    set(value) {
      this.html = value;
      this.cards = [...value.matchAll(/<a class="channel-card"[^>]*>/g)].map(match => {
        const card = node('');
        for (const attr of match[0].matchAll(/([\w-]+)="([^"]*)"/g)) card.attrs[attr[1]] = attr[2];
        card.closest = () => card;
        return card;
      });
    }
  });
  list.querySelector = () => list.cards[0] || null;
  list.querySelectorAll = () => list.cards;
  list.contains = card => list.cards.includes(card);
  const context = vm.createContext({
    document, console, setInterval() {}, clearTimeout() {}, location: { href: '' },
    fetch(url) {
      if (url === '/api/live/status') return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
      return new Promise((resolve, reject) => requests.push({ url, resolve(data, ok = true) { resolve({ ok, json: () => Promise.resolve(data) }); }, reject }));
    }
  });
  context.window = context;
  vm.runInContext(player.getScript(), context);
  async function load(channels, options) {
    const pending = context.filterChannels(options);
    requests.at(-1).resolve({ channels });
    await pending;
  }
  return { nodes, document, list, context, requests, load };
}

test('server and browser cards expose native keyboard links with the same watch destinations', async () => {
  const channels = [channel('remote_123', 'Cine "en vivo"'), channel('local_123'), channel('external_123'), channel('obs_123')];
  const html = directory.renderGrid(channels, {});
  const ui = viewer();
  await ui.load(channels);
  for (const rendered of [html, ui.list.innerHTML]) {
    assert.match(rendered, /<a class="channel-card"[^>]*href="\/live\/watch\/remote_123"[^>]*aria-label="Ver en directo: Cine &quot;en vivo&quot;"/);
    assert.equal((rendered.match(/href="\/live\/watch\/local"/g) || []).length, 3);
    assert.doesNotMatch(rendered, /onclick=/);
  }
  assert.equal(ui.context.location.href, '', 'rendering a channel must not navigate or play');
  const filters = directory.renderFilters();
  for (const id of ['dir-search', 'dir-category', 'dir-lang', 'dir-sort']) assert.match(filters, new RegExp('id="' + id + '"[^>]*aria-label="[^"]+"'));
});

test('only the latest filter response is rendered and background polling does not interrupt pending input', async () => {
  const ui = viewer();
  ui.nodes['dir-search'].value = 'old';
  const old = ui.context.filterChannels();
  assert.equal(ui.list.attrs['aria-busy'], 'true');
  ui.nodes['dir-search'].value = 'new';
  const latest = ui.context.filterChannels();
  ui.context.filterChannels({ background: true });
  assert.equal(ui.requests.length, 2);
  ui.requests[1].resolve({ channels: [channel('new_result')] });
  await latest;
  ui.requests[0].resolve({ channels: [channel('old_result')] });
  await old;
  assert.match(ui.list.innerHTML, /new_result/);
  assert.doesNotMatch(ui.list.innerHTML, /old_result/);
  assert.equal(ui.list.attrs['aria-busy'], 'false');
});

test('background refresh preserves the focused channel and focuses status if that channel disappears', async () => {
  const ui = viewer();
  await ui.load([channel('one'), channel('two')]);
  ui.list.cards[1].focus();
  await ui.load([channel('two'), channel('one')], { background: true });
  assert.equal(ui.document.activeElement, ui.list.cards[0]);
  assert.equal(ui.document.activeElement.getAttribute('data-key'), 'two');
  await ui.load([channel('one')], { background: true });
  assert.equal(ui.document.activeElement, ui.nodes['directory-status']);
  ui.nodes['dir-search'].focus();
  await ui.load([channel('one')], { background: true });
  assert.equal(ui.document.activeElement, ui.nodes['dir-search']);
});

test('load failures keep existing channels, expose retry, and recover without leaving busy state', async () => {
  const ui = viewer();
  await ui.load([channel('one')]);
  const pending = ui.context.filterChannels();
  ui.requests.at(-1).reject(new Error('offline'));
  await pending;
  assert.match(ui.list.innerHTML, /one/);
  assert.equal(ui.nodes['directory-retry'].hidden, false);
  assert.match(ui.nodes['directory-status'].textContent, /No se pueden actualizar/);
  assert.equal(ui.list.attrs['aria-busy'], 'false');
  ui.nodes['directory-retry'].focus();
  await ui.load([channel('two')]);
  assert.equal(ui.nodes['directory-retry'].hidden, true);
  assert.equal(ui.document.activeElement, ui.nodes['directory-status']);
  assert.match(ui.list.innerHTML, /two/);
});

test('filtered empty state offers reset and first-load HTTP failures are not presented as an empty network', async () => {
  const ui = viewer();
  ui.nodes['dir-search'].value = 'missing';
  ui.nodes['dir-category'].value = 'movies';
  await ui.load([]);
  assert.equal(ui.nodes['dir-reset'].hidden, false);
  assert.equal(ui.nodes['live-empty'].style.display, 'none');
  assert.match(ui.nodes['directory-status'].textContent, /estos filtros/);
  const pending = ui.context.resetChannelFilters();
  assert.equal(ui.nodes['dir-search'].value, '');
  assert.equal(ui.nodes['dir-category'].value, 'all');
  assert.equal(ui.document.activeElement, ui.nodes['dir-search']);
  ui.requests.at(-1).resolve({ channels: [] });
  await pending;
  assert.equal(ui.nodes['dir-reset'].hidden, true);
  assert.equal(ui.nodes['live-empty'].style.display, '');
  const failed = ui.context.filterChannels();
  ui.requests.at(-1).resolve({}, false);
  await failed;
  assert.equal(ui.nodes['live-empty-title'].textContent, 'No podemos cargar los canales');
  assert.equal(ui.nodes['directory-retry'].hidden, false);
});

test('connection errors replace the checking text with an actionable disconnected state', async () => {
  const html = require('../eSE-live/live_tv_page').render({}, {});
  const script = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
  new vm.Script(script);
  const start = script.indexOf('// Connection status polling');
  const end = script.indexOf('// Channel refresh polling', start);
  const nodes = { 'status-dot': {}, 'status-text': { textContent: 'Comprobando conexión...' }, 'net-state': {} };
  const context = vm.createContext({ document: { getElementById: id => nodes[id] }, fetch: () => Promise.reject(new Error('offline')) });
  vm.runInContext(script.slice(start, end), context);
  await context.checkConnection();
  assert.equal(nodes['status-dot'].className, 'status-dot disconnected');
  assert.equal(nodes['status-text'].textContent, 'No se puede comprobar la conexión');
  assert.equal(nodes['net-state'].textContent, 'Sin conexión');
});

test('the featured slot spotlights the most watched channel and steps aside for filters', async () => {
  const ui = viewer();
  const classes = new Set();
  ui.nodes['live-directory'] = { classList: { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } } };
  ui.nodes['live-featured'] = { innerHTML: '', hidden: true, contains: () => false };
  await ui.load([channel('quiet'), { ...channel('popular', 'Final <en directo>'), viewers: 900 }]);
  assert.match(ui.nodes['live-featured'].innerHTML, /class="live-featured-card" data-key="popular"/);
  assert.match(ui.nodes['live-featured'].innerHTML, /Final &lt;en directo&gt;/);
  assert.equal(ui.nodes['live-featured'].hidden, false);
  assert.match(ui.list.innerHTML, /data-key="popular" data-featured="true"/, 'the grid copy is hidden, not removed');
  assert.doesNotMatch(ui.list.innerHTML, /data-key="quiet" data-featured/);
  assert.equal(classes.has('only-featured'), false);
  await ui.load([channel('solo')]);
  assert.equal(classes.has('only-featured'), true);
  ui.nodes['dir-search'].value = 'nada';
  await ui.load([]);
  assert.equal(classes.has('only-featured'), false, 'a filtered empty result stays visible');
  assert.equal(ui.nodes['live-featured'].hidden, true);
  ui.nodes['dir-search'].value = '';
  const pending = ui.context.setChannelCategory('gaming');
  assert.match(ui.requests.at(-1).url, /&category=gaming&/);
  ui.requests.at(-1).resolve({ channels: [channel('g1'), channel('g2')] });
  await pending;
  assert.equal(ui.nodes['live-featured'].hidden, true, 'filters hide the spotlight');
  assert.doesNotMatch(ui.list.innerHTML, /data-featured/);
  assert.equal(ui.nodes['dir-reset'].hidden, false);
});
