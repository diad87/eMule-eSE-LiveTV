'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function dialogHarness() {
  const source = fs.readFileSync(path.join(__dirname, '..', 'init.js'), 'utf8');
  const start = source.indexOf('// Movie dialogs are created');
  const end = source.indexOf('// ── NAT Health', start);
  let current = null;
  let observe;
  let onKey;
  const document = {
    body: {},
    getElementById: () => current,
    addEventListener(_type, handler) { onKey = handler; }
  };
  function element(hidden = false) {
    return { isConnected: true, tabIndex: 0, hidden, getClientRects: () => hidden ? [] : [{}], focus() { document.activeElement = this; } };
  }
  const invoker = element();
  invoker.focus();
  vm.runInNewContext(source.slice(start, end), {
    document,
    MutationObserver: class { constructor(callback) { observe = callback; } observe() {} }
  });
  function open() {
    const close = element();
    const hidden = element(true);
    const play = element();
    const modal = Object.assign(element(), {
      items: [close, hidden, play], attrs: {}, title: null,
      querySelector: () => modal.title,
      querySelectorAll: () => modal.items,
      contains: el => el === modal || modal.items.includes(el),
      setAttribute(key, value) { modal.attrs[key] = value; },
      removeAttribute(key) { delete modal.attrs[key]; }
    });
    if (current) current.isConnected = false;
    current = modal;
    observe();
    return { modal, close, play };
  }
  function key(shiftKey = false) {
    let prevented = false;
    onKey({ key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
    return prevented;
  }
  function remove() { current.isConnected = false; current = null; observe(); }
  return { document, invoker, open, key, remove, element, observe: () => observe() };
}

test('movie dialog labels itself, focuses close, traps Tab and restores its invoker', () => {
  const ui = dialogHarness();
  const { modal, close, play } = ui.open();
  assert.equal(modal.attrs.role, 'dialog');
  assert.equal(modal.attrs['aria-modal'], 'true');
  assert.ok(modal.attrs['aria-label']);
  assert.equal(ui.document.activeElement, close);
  assert.equal(ui.key(true), true);
  assert.equal(ui.document.activeElement, play);
  assert.equal(ui.key(), true);
  assert.equal(ui.document.activeElement, close);
  ui.remove();
  assert.equal(ui.document.activeElement, ui.invoker);
});

test('dialog focus survives asynchronous detail rendering and modal replacement', () => {
  const ui = dialogHarness();
  const { modal } = ui.open();
  const replacementClose = ui.element();
  modal.items = [replacementClose];
  modal.title = { id: '' };
  ui.document.activeElement = ui.document.body;
  ui.observe();
  assert.equal(ui.document.activeElement, replacementClose);
  assert.equal(modal.attrs['aria-labelledby'], 'movie-modal-title');
  assert.equal(modal.attrs['aria-label'], undefined);
  const next = ui.open();
  assert.equal(ui.document.activeElement, next.close);
  ui.remove();
  assert.equal(ui.document.activeElement, ui.invoker);
});

const clientSource = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function detailHarness() {
  const nodes = new Map();
  const pending = [];
  const keyHandlers = new Set();
  const timers = new Map();
  let nextTimer = 0;
  const document = {
    getElementById: id => nodes.get(id) || null,
    querySelector: () => null,
    addEventListener(_type, listener) { keyHandlers.add(listener); },
    removeEventListener(_type, listener) { keyHandlers.delete(listener); },
    body: { style: { overflow: '' }, appendChild(node) { nodes.set(node.id, node); } },
    createElement() {
      let html = '';
      return {
        style: {},
        set innerHTML(value) {
          html = value;
          for (const match of value.matchAll(/id="([^"]+)"/g)) nodes.set(match[1], { onclick: null });
        },
        get innerHTML() { return html; },
        remove() { if (nodes.get(this.id) === this) nodes.delete(this.id); }
      };
    }
  };
  const context = vm.createContext({
    document, AbortController,
    setTimeout(callback, ms) { timers.set(++nextTimer, { callback, ms }); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) { return new Promise(resolve => pending.push({ url, options, resolve })); },
    localStorage: { getItem() { throw new Error('Storage unavailable'); } },
    video: { currentTime: 90, pause() { this.paused = true; }, removeAttribute() {}, load() {}, querySelectorAll: () => [] }
  });
  context.window = context;
  vm.runInContext(clientSource('shared/safe_dom.js'), context);
  vm.runInContext(clientSource('search_ui.js'), context);
  const respond = (index, data, ok = true) => pending[index].resolve({ ok, json: () => Promise.resolve(data) });
  return { context, nodes, pending, keyHandlers, timers, respond };
}

test('detail loading has readable status and an unavailable local title keeps its playback action', async () => {
  const ui = detailHarness();
  ui.context.showMovieDetail('tt1', 'Local film.mp4', 'Local film');
  const modal = ui.nodes.get('movie-modal');
  assert.match(modal.innerHTML, /role="status"/);
  assert.match(modal.innerHTML, /Cargando ficha/);
  assert.match(modal.innerHTML, /aria-label="Cerrar ficha"/);
  ui.respond(0, {}, false);
  await flush();
  assert.match(modal.innerHTML, /No se ha podido cargar/);
  assert.match(modal.innerHTML, /Reproducir archivo local/);
  assert.match(modal.innerHTML, /Volver al catálogo/);
  ui.nodes.get('modal-retry-btn').onclick();
  assert.equal(ui.pending.length, 2);
  assert.equal(ui.keyHandlers.size, 1, 'Retry replaces, rather than accumulates, Escape handlers');
});

test('a slow previous detail cannot replace the current title or saved-list action', async () => {
  const ui = detailHarness();
  ui.context.showMovieDetail('tt1', null, 'First');
  ui.context.showMovieDetail('tt2', null, 'Second');
  ui.respond(1, { Title: 'Second', Year: '2025', Type: 'movie' });
  await flush();
  ui.respond(0, { Title: 'First', Year: '2024', Type: 'movie' });
  await flush();
  assert.equal(ui.context._modalMovie.imdbId, 'tt2');
  assert.match(ui.nodes.get('movie-modal').innerHTML, />Second<\/h1>/);
  assert.equal(ui.pending[0].options.signal.aborted, true);
});

test('closing works with unavailable storage and cancels outstanding detail work', () => {
  const ui = detailHarness();
  ui.context.showMovieDetail('tt1', null, 'Film');
  ui.context._cinemaFileName = 'Film.mp4';
  const detailTimer = [...ui.timers.values()].find(timer => timer.ms === 15000);
  assert.ok(detailTimer);
  assert.doesNotThrow(() => ui.context.closeMovieModal());
  assert.equal(ui.nodes.has('movie-modal'), false);
  assert.equal(ui.context.document.body.style.overflow, '');
  assert.equal(ui.context.video.paused, true);
  assert.equal(ui.pending[0].options.signal.aborted, true);
  assert.equal(ui.keyHandlers.size, 0);
  assert.ok(![...ui.timers.values()].some(timer => timer.ms === 15000));
  detailTimer.callback();
  assert.equal(ui.nodes.has('movie-modal'), false, 'A late callback must not reopen the dialog');
});

function resumeHarness(lists) {
  const source = clientSource('init.js');
  const start = source.indexOf('// ── "Continuar viendo"');
  const end = source.indexOf('// ── Logo SVG', start);
  const nodes = new Map();
  const calls = [];
  const listeners = new Map();
  const slot = { children: [], appendChild(node) { this.children.push(node); nodes.set(node.id, node); } };
  nodes.set('home-resume-slot', slot);
  function element() {
    let html = '';
    return { style: {}, setAttribute() {},
      set innerHTML(value) { html = value; for (const match of value.matchAll(/id="([^"]+)"/g)) nodes.set(match[1], {}); },
      get innerHTML() { return html; },
      remove() { nodes.delete(this.id); }
    };
  }
  const context = vm.createContext({
    document: { getElementById: id => nodes.get(id) || null, createElement: element,
      body: { style: {}, appendChild(node) { nodes.set(node.id, node); } }, addEventListener() {} },
    getWatchSession: () => ({ fileName: 'A film.mp4', position: 125 }),
    clearWatchSession: () => calls.push('clear'), escapeHTML: value => String(value),
    fetch(url) { const data = lists[url.includes('/completed/') ? 0 : 1]; return data instanceof Error ? Promise.reject(data) : Promise.resolve({ ok: true, json: () => Promise.resolve(data) }); },
    playInModal: (name, position) => calls.push(['complete', name, position]),
    playPartFile: (part, name, position) => calls.push(['partial', part, name, position]),
    startCompletedMSE: (...args) => calls.push(['seek', ...args]),
    video: { addEventListener(event, callback) { listeners.set(event, callback); } }
  });
  context.window = context;
  vm.runInContext(source.slice(start, end), context);
  return { context, nodes, slot, calls, listeners };
}

test('resume history survives failed library reads and never fabricates a playable entry', async () => {
  const ui = resumeHarness([new Error('offline'), []]);
  await flush();
  assert.deepEqual(ui.calls, []);
  assert.equal(ui.slot.children.length, 0);
});

test('resume passes the saved position into the verified partial-file session without a second restart', async () => {
  const ui = resumeHarness([[], [{ fileName: 'A film.mp4', partFile: '001.part' }]]);
  await flush();
  assert.equal(ui.slot.children[0].className, 'resume-card');
  assert.doesNotMatch(ui.slot.children[0].innerHTML, /position:fixed/);
  ui.nodes.get('continue-play-btn').onclick();
  assert.deepEqual(ui.calls, [['partial', '001.part', 'A film.mp4', 125]]);
  ui.context._cinemaFileName = 'A film.mp4';
  ui.nodes.delete('movie-modal');
  assert.equal(ui.listeners.has('loadedmetadata'), false);
  assert.equal(ui.calls.length, 1, 'Closing before metadata must not restart a stream');
});
