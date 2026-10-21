'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const read = name => fs.readFileSync(path.join(__dirname, '..', name), 'utf8');
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };

function harness({ engine = false } = {}) {
  const nodes = new Map();
  const timers = new Map();
  const pending = [];
  const data = new Map();
  let timerId = 0;
  let writeError = false;
  class Element {
    constructor(tag = 'div', id = '') {
      this.tagName = tag; this.id = id; this.style = {}; this.attrs = {}; this.listeners = new Map();
      this.children = []; this.generated = []; this.isConnected = true; this._html = ''; this.textContent = '';
      this.classList = { add() {}, remove() {} }; this.value = id.includes('quality') ? 'auto' : '';
      this.currentTime = 0; this.duration = Infinity; this.volume = 1; this.muted = false; this.paused = true;
      this.textTracks = []; this.buffered = { length: 0 }; this.loads = 0; this.plays = 0;
    }
    setAttribute(key, value) { this.attrs[key] = String(value); }
    getAttribute(key) { return this.attrs[key]; }
    removeAttribute(key) { delete this.attrs[key]; if (key === 'src') this.src = ''; }
    addEventListener(name, fn, options) {
      if (!this.listeners.has(name)) this.listeners.set(name, []);
      this.listeners.get(name).push({ fn, once: options && options.once });
    }
    removeEventListener(name, fn) { this.listeners.set(name, (this.listeners.get(name) || []).filter(item => item.fn !== fn)); }
    emit(name, extra = {}) {
      for (const item of [...(this.listeners.get(name) || [])]) {
        if (item.once) this.removeEventListener(name, item.fn);
        item.fn({ target: this, currentTarget: this, preventDefault() {}, ...extra });
      }
    }
    set innerHTML(html) {
      this.generated.forEach(node => { nodes.delete(node.id); node.isConnected = false; });
      this.generated = []; this._html = html;
      for (const match of html.matchAll(/<([a-z]+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
        const node = new Element(match[1], match[3]);
        for (const attr of match[2].matchAll(/([\w-]+)="([^"]*)"/g)) node.setAttribute(attr[1], attr[2]);
        nodes.set(node.id, node); this.generated.push(node); node.parent = this;
      }
    }
    get innerHTML() { return this._html; }
    appendChild(node) { this.children.push(node); node.parent = this; if (node.id) nodes.set(node.id, node); }
    querySelectorAll(selector) { return selector === 'track' ? this.children.filter(node => node.tagName === 'track') : []; }
    querySelector() { return this.children[0] || null; }
    remove() { this.isConnected = false; nodes.delete(this.id); if (this.parent) this.parent.children = this.parent.children.filter(node => node !== this); }
    focus() { document.activeElement = this; }
    pause() { this.paused = true; this.emit('pause'); }
    load() { this.loads++; this.currentTime = 0; }
    play() { this.plays++; this.paused = false; return Promise.resolve(); }
    getBoundingClientRect() { return { left: 0, width: 100 }; }
  }
  const document = new Element('document');
  document.body = new Element('body');
  document.createElement = tag => new Element(tag);
  document.getElementById = id => nodes.get(id) || null;
  const close = new Element('button', 'close');
  document.querySelector = () => close;
  for (const id of ['video-player', 'seek-container', 'play-btn', 'time-display', 'progress-bar-inner',
    'buffer-bar', 'buffer-label', 'player-status', 'loading', 'loading-text', 'loading-sub', 'player-title',
    'hero', 'player-container', 'quality-select']) nodes.set(id, new Element('div', id));
  const context = {
    document, console: { log() {}, error() {} }, AbortController, Date,
    URL: { createObjectURL: () => 'blob:fake', revokeObjectURL() {} },
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms, interval: true }); return id; },
    clearInterval(id) { timers.delete(id); },
    fetch(url, options = {}) { return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject })); },
    localStorage: {
      getItem: key => data.get(key) || null,
      setItem(key, value) { if (writeError) throw new Error('QuotaExceededError'); data.set(key, value); },
      removeItem: key => data.delete(key)
    },
    escapeHTML: text => String(text), escapeAttr: text => String(text),
    fmtT: seconds => Math.floor(seconds / 60) + ':' + String(Math.floor(seconds % 60)).padStart(2, '0'),
    video: null, abortController: null, currentPartNum: null, currentQuality: 'auto', estTotalSec: 0, userWantsPause: false
  };
  context.window = context;
  vm.createContext(context);
  if (engine) {
    vm.runInContext(read('player_core.js'), context);
    vm.runInContext(read('mse_engine.js'), context);
  }
  vm.runInContext(read('cinema_player.js'), context);
  function modal(detail = '') {
    const node = new Element('div', 'movie-modal'); nodes.set(node.id, node);
    nodes.set('modal-player-zone', new Element('div', 'modal-player-zone'));
    const info = new Element('div', 'modal-info-zone'); info.innerHTML = detail;
    if (detail) info.appendChild(new Element('button'));
    nodes.set(info.id, info);
    return node;
  }
  context.closeMovieModal = () => { context.stopCinemaPlayback(); const node = nodes.get('movie-modal'); if (node) node.remove(); };
  function open(name = 'Film.mkv', position, detail = '') {
    modal(detail); context.playInModal(encodeURIComponent(name), position);
    return nodes.get('modal-video');
  }
  function respond(request, body, ok = true) {
    request.resolve({ ok, headers: { get: () => null }, json: () => Promise.resolve(body) });
  }
  return { context, nodes, timers, pending, data, document, close, open, modal, respond, Element,
    evaluate: code => vm.runInContext(code, context),
    failWrites: () => { writeError = true; },
    runTimer(id) { const item = timers.get(id); timers.delete(id); if (item) item.fn(); }
  };
}

test('late retry cannot restart a closed or replacement video, even if its callback is already queued', () => {
  const h = harness();
  const first = h.open('First.mkv'); first.emit('error');
  const [id, queued] = [...h.timers].find(([, timer]) => timer.ms === 2000);
  h.context.closeMovieModal();
  assert.equal(h.timers.has(id), false);
  const second = h.open('Second.mkv');
  const source = second.src; const loads = second.loads;
  queued.fn(); first.emit('error'); first.emit('canplay');
  assert.equal(second.src, source); assert.equal(second.loads, loads);
  assert.equal(second.plays, 0); assert.equal(first.plays, 0);
});

test('quality changes remove previous error handlers and invalidate old retries in the same video', () => {
  const h = harness(); const player = h.open(); player.emit('error');
  const queued = [...h.timers.values()].find(timer => timer.ms === 2000);
  h.context.changeCinemaQuality('720p');
  const src = player.src; queued.fn();
  assert.equal(player.src, src); assert.match(src, /q=720p/);
  assert.equal(player.listeners.get('error').length, 1);
  player.emit('error'); player.emit('error');
  assert.equal([...h.timers.values()].filter(timer => timer.ms === 2000).length, 1);
});

test('late metadata and tracks from title A cannot change title B or claim it is playing', async () => {
  const h = harness(); h.open('First.mkv'); const old = [...h.pending];
  h.open('Second.mkv');
  h.respond(old.find(request => request.url.includes('/info')), { estimatedTotalSec: 900, isPartFile: true, partNum: '001' });
  h.respond(old.find(request => request.url.includes('/tracks')), { audio: [{ index: 0 }, { index: 1 }], subtitles: [{ lang: 'en' }] });
  old.find(request => request.options.method === 'HEAD').resolve({ ok: true, headers: { get: () => 'transcode' } });
  await flush();
  assert.equal(h.context.estTotalSec, 0); assert.equal(h.context._isPartFile, false);
  assert.equal(h.nodes.get('cinema-audio').children.length, 0);
  assert.equal(h.nodes.get('modal-player-status').textContent, 'Preparando vídeo…');
  assert.ok(old.every(request => request.options.signal.aborted));
});

test('Volver closes a quick player and returns to an existing detail despite malformed or unwritable storage', () => {
  const h = harness(); const quick = h.open(); quick.emit('playing'); quick.currentTime = 20; quick.emit('timeupdate');
  h.data.set('ese_resume', '{');
  assert.doesNotThrow(() => h.context.backToDetail());
  assert.equal(h.nodes.has('movie-modal'), false); assert.equal(quick.paused, true);
  const detail = h.open('Film.mkv', 0, '<h1>Film</h1>'); detail.emit('playing'); detail.currentTime = 25; detail.emit('timeupdate');
  h.failWrites(); assert.doesNotThrow(() => h.context.backToDetail());
  assert.equal(h.nodes.get('modal-info-zone').style.display, 'block');
  assert.equal(h.nodes.get('modal-player-zone').style.display, 'none');
  assert.equal(h.document.activeElement, h.nodes.get('modal-info-zone').children[0]);
});

test('resume starts at the saved offset once and preserves history until playback is confirmed', () => {
  const h = harness();
  const saved = JSON.stringify({ fileName: 'Film.mkv', position: 125, ts: Date.now() });
  h.data.set('ese_session', saved);
  const first = h.open('Film.mkv', 125);
  assert.match(first.src, /ss=125$/); assert.equal(first.loads, 1);
  first.emit('loadedmetadata'); first.emit('timeupdate');
  assert.equal(first.loads, 1); assert.equal(h.data.get('ese_session'), saved);
  h.context.closeMovieModal(); assert.equal(h.data.get('ese_session'), saved);
  const second = h.open('Film.mkv', 125); second.emit('playing'); second.currentTime = 5; second.emit('timeupdate');
  assert.equal(JSON.parse(h.data.get('ese_session')).position, 130);
  h.context.closeMovieModal(); assert.equal(JSON.parse(h.data.get('ese_resume'))['Film.mkv'].time, 130);
});

test('failed info keeps duration unknown and seeking disabled; finite duration enables keyboard seeking', async () => {
  const h = harness(); const player = h.open(); const seek = h.nodes.get('cinema-seek');
  h.pending.find(request => request.url.includes('/info')).reject(new Error('offline')); await flush();
  assert.match(h.nodes.get('cinema-time').textContent, /Duración desconocida/);
  assert.equal(seek.attrs['aria-disabled'], 'true');
  const src = player.src; seek.emit('keydown', { key: 'ArrowRight' }); assert.equal(player.src, src);
  player.duration = 90; player.currentTime = 25; player.emit('loadedmetadata');
  assert.equal(seek.attrs['aria-disabled'], 'false'); assert.equal(seek.attrs['aria-valuemax'], '90');
  let prevented = false; seek.emit('keydown', { key: 'ArrowRight', preventDefault() { prevented = true; } });
  assert.ok(prevented); assert.match(player.src, /ss=35$/);
  seek.emit('keydown', { key: 'Home' }); assert.match(player.src, /ss=0$/);
});

test('actual video events drive status and named volume/play controls reflect their state', async () => {
  const h = harness(); const player = h.open();
  h.respond(h.pending.find(request => request.url.includes('/info')), { estimatedTotalSec: 200, durationKnown: true }); await flush();
  assert.equal(h.nodes.get('modal-player-status').textContent, 'Preparando vídeo…');
  player.emit('play'); assert.equal(h.nodes.get('cinema-play-btn').attrs['aria-label'], 'Pausar');
  player.emit('playing'); assert.equal(h.nodes.get('modal-player-status').textContent, 'Reproduciendo');
  player.emit('waiting'); assert.match(h.nodes.get('modal-player-status').textContent, /Cargando/);
  h.context.toggleCinemaVol();
  assert.equal(h.nodes.get('cinema-vol-btn').attrs['aria-label'], 'Activar sonido');
  assert.equal(h.nodes.get('cinema-vol-btn').attrs['aria-pressed'], 'true');
  h.context.setCinemaVol(40); assert.equal(player.volume, 0.4); assert.equal(player.muted, false);
  assert.equal(h.nodes.get('cinema-vol-btn').attrs['aria-label'], 'Silenciar');
});

test('a failed player offers local retry at the same position and a working exit', () => {
  const h = harness(); const player = h.open('Film.mkv', 125);
  for (let i = 0; i < 4; i++) {
    player.emit('error');
    const retry = [...h.timers].find(([, timer]) => timer.ms === 2000);
    if (retry) h.runTimer(retry[0]);
  }
  let bar = h.nodes.get('modal-player-error-actions'); assert.ok(bar);
  bar.children[0].onclick(); assert.match(player.src, /ss=125$/);
  h.context.showPlayerErrorActions(); bar = h.nodes.get('modal-player-error-actions');
  bar.children[1].onclick(); assert.equal(h.nodes.has('movie-modal'), false);
});

test('a delayed MSE start cannot replace a subsequently opened cinema player', async () => {
  const h = harness({ engine: true });
  const start = h.context.playVideo('001'); const request = h.pending[0];
  const player = h.open('Film.mkv');
  h.respond(request, { fileName: 'Old.part', estimatedTotalSec: 999 });
  await start;
  assert.match(player.src, /Film.mkv/); assert.equal(h.context._cinemaFileName, 'Film.mkv');
  assert.equal(h.evaluate('estTotalSec'), 0); assert.equal(request.options.signal.aborted, true);
});

test('a delayed MSE quality-switch response cannot append to or change a replacement stream', async () => {
  const h = harness({ engine: true }); const main = h.nodes.get('video-player');
  h.context.fakeBuffer = { abort() { throw new Error('stale buffer touched'); } };
  h.evaluate('legacyVideo = mainVideo; sourceBuffer = fakeBuffer; currentPartNum = "001";');
  const switching = h.context.switchStreamSeamless('720p', 50);
  const kill = h.pending[0];
  const cinema = h.open('New.mkv');
  h.respond(kill, {}); await switching;
  assert.equal(h.pending.filter(request => request.url.includes('/stream/data/')).length, 0);
  assert.match(cinema.src, /New.mkv/); assert.equal(main.paused, true);
});

test('MSE still appends current data but drops pending reads and updateend callbacks after switching to cinema', async () => {
  const h = harness({ engine: true });
  const buffer = new h.Element('buffer');
  buffer.appended = []; buffer.updating = false;
  buffer.abort = () => {};
  buffer.appendBuffer = chunk => { buffer.appended.push(chunk); buffer.updating = true; };
  h.context.MediaSource = class extends h.Element { addSourceBuffer() { return buffer; } };
  const starting = h.context.playVideo('001');
  h.respond(h.pending[0], { fileName: 'Old.part', estimatedTotalSec: 100 });
  await starting;
  h.evaluate('mediaSource').emit('sourceopen');
  h.respond(h.pending.find(request => request.url.includes('/kill/')), {});
  await flush();
  const wait = [...h.timers].find(([, timer]) => timer.ms === 300); assert.ok(wait);
  h.runTimer(wait[0]); await flush();
  let readCount = 0; let finishPendingRead; let canceled = false;
  const reader = {
    read() { return ++readCount === 1 ? Promise.resolve({ value: new Uint8Array([1, 2]), done: false })
      : new Promise(resolve => { finishPendingRead = resolve; }); },
    cancel() { canceled = true; return Promise.resolve(); }
  };
  h.pending.find(request => request.url.includes('/data/')).resolve({ ok: true, body: { getReader: () => reader } });
  await flush();
  assert.equal(buffer.appended.length, 1, 'The current MSE stream must still append media data');
  const next = h.open('New.mkv');
  buffer.updating = false; buffer.emit('updateend');
  finishPendingRead({ value: new Uint8Array([3]), done: false }); await flush();
  assert.equal(buffer.appended.length, 1); assert.equal(next.plays, 0); assert.equal(canceled, true);
  assert.match(next.src, /New.mkv/);
});

test('partial seek responses and subtitle loads cannot revive an old player', async () => {
  const h = harness(); h.open('Old.mkv');
  h.respond(h.pending.find(request => request.url.includes('/info')), { estimatedTotalSec: 500, isPartFile: true, partNum: '001' });
  await flush();
  h.context.changeCinemaSubs('0'); const track = h.context.video.children[0];
  h.context.seekCinemaTo(100); const seek = h.pending.find(request => request.url.includes('/seek?'));
  const next = h.open('New.mkv'); const before = next.src;
  h.respond(seek, { targetPart: 1 }); track.emit('load'); await flush();
  assert.equal(next.src, before); assert.equal(next.loads, 1);
  assert.equal(h.nodes.get('modal-player-status').textContent, 'Preparando vídeo…');
});

test('subtitles use the current stream offset after resume and subsequent seek', () => {
  const h = harness(); const player = h.open('Film.mkv', 12);
  h.context.changeCinemaSubs('0');
  assert.match(player.children[0].src, /track=0&ss=12$/);
  h.context.startCompletedMSE('Film.mkv', 'auto', 25);
  assert.equal(player.children.length, 1);
  assert.match(player.children[0].src, /track=0&ss=25$/);
});

test('old subtitle cues are disabled and emptied before detaching or replacing the video source', () => {
  const h = harness(); const player = h.open('Film.mkv');
  h.context.changeCinemaSubs('0');
  const previous = player.children[0];
  const textTrack = { mode: 'showing', cues: [{ text: 'Stale first cue' }], removeCue(cue) { this.cues = this.cues.filter(item => item !== cue); } };
  previous.track = textTrack; player.textTracks = [textTrack];
  const remove = previous.remove.bind(previous);
  previous.remove = () => {
    assert.equal(textTrack.mode, 'disabled');
    assert.deepEqual(textTrack.cues, []);
    assert.equal(previous.default, false);
    remove();
  };
  const load = player.load.bind(player);
  player.load = () => {
    assert.equal(previous.isConnected, false, 'detach subtitles before resetting the media clock');
    load();
  };
  h.context.startCompletedMSE('Film.mkv', 'auto', 19);
  assert.equal(player.children.length, 1);
  assert.match(player.children[0].src, /ss=19$/);
  previous.emit('load');
  assert.equal(textTrack.mode, 'disabled', 'late old load cannot paint an obsolete cue');
});

test('displayed and saved progress cannot exceed the known file duration', async () => {
  const h = harness(); const player = h.open('Film.mkv', 19);
  h.respond(h.pending.find(request => request.url.includes('/info')), { estimatedTotalSec: 40, durationKnown: true });
  await flush();
  player.currentTime = 29.568;
  player.emit('playing'); player.emit('timeupdate');
  assert.equal(h.nodes.get('cinema-time').textContent, '0:40 / 0:40');
  assert.equal(h.nodes.get('cinema-seek').getAttribute('aria-valuenow'), '40');
  assert.equal(JSON.parse(h.data.get('ese_session')).position, 40);
  h.context.stopCinemaPlayback();
  assert.equal(JSON.parse(h.data.get('ese_resume'))['Film.mkv'].time, 40);
});
