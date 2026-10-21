'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const mainPage = require('../pages/main_page');

const source = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

// Event attributes are decoded by HTML before their JavaScript is evaluated.
// Decode once, including numeric entities, to exercise that browser boundary.
function decodeAttribute(value) {
  const named = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>' };
  return value.replace(/&(#x[\da-f]+|#\d+|amp|quot|apos|lt|gt);/gi, (_, entity) => {
    if (entity[0] !== '#') return named[entity.toLowerCase()];
    return String.fromCodePoint(entity[1].toLowerCase() === 'x' ? parseInt(entity.slice(2), 16) : Number(entity.slice(1)));
  });
}

function attributes(tag) {
  return Object.fromEntries(Array.from(tag.matchAll(/([\w-]+)="([^"]*)"/g), match => [match[1], decodeAttribute(match[2])]));
}

function buttonHandler(html, id) {
  const tag = Array.from(html.matchAll(/<button\b[^>]*>/g), match => match[0])
    .find(button => attributes(button).id === id);
  assert.ok(tag, 'Expected button ' + id);
  return attributes(tag).onclick;
}

function createModal(movie) {
  const nodes = new Map();
  const requests = [];
  const context = vm.createContext({
    document: {
      getElementById: id => nodes.get(id) || null,
      querySelector: () => null,
      createElement: () => ({ innerHTML: '', style: {}, remove() { nodes.delete(this.id); } }),
      addEventListener() {},
      body: { style: {}, appendChild(node) { nodes.set(node.id, node); } }
    },
    setTimeout() {},
    fetch(url) {
      requests.push(url);
      const result = url.startsWith('/api/movies/detail?') ? movie : { movie_results: [], tv_results: [] };
      return Promise.resolve({ ok: true, json: () => Promise.resolve(result) });
    }
  });
  context.window = context;
  for (const file of ['shared/safe_dom.js', 'search_ui.js']) {
    vm.runInContext(source(file), context, { filename: file });
  }
  return { context, nodes, requests };
}

test('local playback treats hostile and ordinary filenames as data', async t => {
  const filenames = [
    "A'-auditMarker()-'B.mp4",
    "L'été d'Oscar (2025).mkv",
    'Película & "versión" #1.mp4',
    'Nombre%20literal.mp4',
    'Película normal.mp4'
  ];
  for (const filename of filenames) {
    await t.test(filename, async () => {
      const modal = createModal({ Title: 'A film', Year: '2025', Type: 'movie', Poster: 'N/A' });
      const calls = [];
      let executions = 0;
      modal.context.playInModal = encoded => calls.push(encoded);
      modal.context.auditMarker = () => { executions++; return 1; };
      modal.context.showMovieDetail('tt1234', filename, 'A film');
      await settle();
      const handler = buttonHandler(modal.nodes.get('movie-modal').innerHTML, 'modal-play-btn');
      vm.runInContext(handler, modal.context, { filename: 'local-play-onclick.js' });
      assert.equal(executions, 0);
      assert.deepEqual(calls, [encodeURIComponent(filename)]);
      assert.equal(decodeURIComponent(calls[0]), filename);
      assert.ok(modal.requests.every(url => url.startsWith('/api/')));
    });
  }
});

test('detail actions preserve external title and year without executing them', async () => {
  const title = "Film'-auditMarker()-'Title & More";
  const year = "2026'-auditMarker()-'Year";
  const modal = createModal({ Title: title, Year: year, Type: 'movie', Poster: 'N/A' });
  const calls = [];
  let executions = 0;
  modal.context.auditMarker = () => { executions++; return 1; };
  modal.context.smartPlay = (...args) => calls.push(['play', ...args]);
  modal.context.smartDownload = (...args) => calls.push(['download', ...args]);
  modal.context.startEmuleSearch = (...args) => calls.push(['search', ...args]);
  modal.context.loadTrailer = (...args) => calls.push(['trailer', ...args]);
  modal.context.showMovieDetail('tt1234', null, title);
  await settle();
  const html = modal.nodes.get('movie-modal').innerHTML;
  for (const id of ['modal-play-btn', 'modal-download-btn', 'trailer-btn']) {
    vm.runInContext(buttonHandler(html, id), modal.context);
  }
  const advanced = Array.from(html.matchAll(/<button\b[^>]*>/g), match => attributes(match[0]))
    .find(button => button.class.includes('btn-emule'));
  vm.runInContext(advanced.onclick, modal.context);
  assert.equal(executions, 0);
  assert.deepEqual(calls, [
    ['play', title, year], ['download', title, year], ['trailer', title + ' ' + year], ['search', title, year]
  ]);
});

function renderHome(completed, downloads = []) {
  mainPage.init({
    getDownloads: () => downloads,
    getCompletedFiles: () => completed,
    cleanTitle: value => value,
    escapeHtml: value => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
  });
  let html = '';
  assert.equal(mainPage.handle(new URL('http://localhost/'), {}, { writeHead() {}, end(value) { html = value; } }), true);
  return html;
}

test('completed records without a completed flag use the completed playback route', () => {
  const filename = "A'-auditMarker()-'B.mp4";
  const file = { fileName: filename, sizeMB: 1500 };
  const html = renderHome([file], [{ fileName: 'Partial.part', partNum: '001', sizeMB: 15, sizeBytes: 15728640 }]);
  const cards = Array.from(html.matchAll(/<div\b[^>]*data-filename="[^"]*"[^>]*>/g), match => attributes(match[0]));
  const completed = cards.find(card => decodeURIComponent(card['data-filename']) === filename);
  const downloading = cards.find(card => card['data-part'] === '001');
  assert.equal(completed['data-completed'], 'true');
  assert.equal(downloading['data-completed'], 'false');
  assert.equal(file.completed, undefined, 'Rendering must not mutate source records');
  assert.ok(!html.includes('Descargando · 100%'), 'The size of a partial file is not download progress');
  const calls = [];
  const context = vm.createContext({
    setTimeout() {},
    playCompleted: encoded => calls.push(['completed', encoded]),
    playVideo: part => calls.push(['partial', part]),
    showMovieDetail: (...args) => calls.push(['detail', ...args])
  });
  context.window = context;
  vm.runInContext(source('poster_hero.js'), context, { filename: 'poster_hero.js' });
  context.playLibraryCard({ getAttribute: name => completed[name] || null });
  context.playLibraryCard({ getAttribute: name => downloading[name] || null });
  assert.deepEqual(calls, [['completed', encodeURIComponent(filename)], ['partial', '001']]);
  completed['data-imdbid'] = 'tt1234';
  context.playLibraryCard({ getAttribute: name => completed[name] || null });
  assert.deepEqual(calls[2], ['detail', 'tt1234', filename, filename]);
});

test('catalog pages use the same-origin TMDB proxy and emit valid client scripts', () => {
  for (const name of ['explore', 'search', 'mylist']) {
    const page = require('../pages/' + name + '_page');
    let html = '';
    assert.equal(page.handle(new URL('http://localhost/' + name), {}, { writeHead() {}, end(value) { html = value; } }), true);
    assert.ok(!html.includes('api_key='));
    assert.ok(!html.includes('api.themoviedb.org'));
    if (name !== 'mylist') assert.ok(html.includes('/api/tmdb/'));
    for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
      new vm.Script(match[1], { filename: name + '-inline.js' });
    }
  }
});
