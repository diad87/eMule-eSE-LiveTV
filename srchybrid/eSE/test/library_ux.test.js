'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

function libraryContext(cards = []) {
  const nodes = {
    'library-count': { textContent: '' },
    'library-empty': { hidden: true },
    'library-query': { value: '', focus() { this.focused = true; } }
  };
  const requests = [];
  const ctx = vm.createContext({
    setTimeout() {},
    document: { querySelectorAll: () => cards, getElementById: id => nodes[id] || null },
    fetch(url) { requests.push(url); return Promise.resolve({ ok: true, json: async () => ({ results: [] }) }); }
  });
  ctx.window = ctx;
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../poster_hero.js'), 'utf8'), ctx);
  return { ctx, nodes, requests };
}

function card(filename, title) {
  const attributes = { 'data-filename': encodeURIComponent(filename), 'data-title': title };
  return { hidden: false, getAttribute: key => attributes[key] || null };
}

test('library metadata respects release year and refuses ambiguous titles', () => {
  const { ctx } = libraryContext();
  const movies = [
    { id: 1, title: 'Parásito', original_title: 'Parasite', release_date: '1982-03-12' },
    { id: 2, title: 'Parásitos', original_title: 'Parasite', release_date: '2019-05-30' },
    { id: 3, title: 'Parasite in love', release_date: '2019-05-30' }
  ];
  assert.equal(ctx.matchLibraryMovie(movies, ['Parasite 2019', 'Parasite'], '2019').id, 2);
  assert.equal(ctx.matchLibraryMovie(movies, ['Parasite'], ''), null);
  assert.equal(ctx.matchLibraryMovie(movies, ['Unrelated film'], '2019'), null);
});

test('episodic files never use the movie metadata matcher', () => {
  const { ctx, requests } = libraryContext([
    card('Breaking.Bad.S01E01.1080p.mkv', 'Breaking Bad'),
    card('Breaking Bad 01x01.mkv', 'Breaking Bad')
  ]);
  ctx.fetchLocalPosters();
  assert.deepEqual(requests, []);
});

test('library search handles accents, original filenames, empty results and clearing', () => {
  const cards = [card('Parasite.2019.1080p.mkv', 'Parásitos'), card('Joker.2019.mkv', 'Joker')];
  const { ctx, nodes } = libraryContext(cards);
  ctx.filterLibrary('parasitos');
  assert.deepEqual(cards.map(item => item.hidden), [false, true]);
  assert.equal(nodes['library-count'].textContent, '1 de 2 archivos');
  ctx.filterLibrary('1080p');
  assert.deepEqual(cards.map(item => item.hidden), [false, true]);
  ctx.filterLibrary('No existe');
  assert.equal(nodes['library-empty'].hidden, false);
  nodes['library-query'].value = 'No existe';
  ctx.clearLibraryFilter();
  assert.deepEqual(cards.map(item => item.hidden), [false, false]);
  assert.equal(nodes['library-empty'].hidden, true);
  assert.equal(nodes['library-query'].focused, true);
});
