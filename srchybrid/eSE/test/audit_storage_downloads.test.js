'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { parsePartMetadata } = require('../part_metadata');
const { listDownloads } = require('../media_resolver');

function favorites(raw, failWrite = false) {
  const notices = [];
  let stored = raw;
  const context = vm.createContext({
    localStorage: { getItem: () => stored, setItem: (_, value) => { if (failWrite) throw new Error('QuotaExceededError'); stored = value; } },
    showNotification: text => notices.push(text)
  });
  context.window = context;
  const source = fs.readFileSync(path.join(__dirname, '../init.js'), 'utf8');
  vm.runInContext(source.slice(source.indexOf('// ── Mi Lista'), source.indexOf('// Movie dialogs')), context);
  return { context, notices, stored: () => stored };
}
test('invalid saved lists never throw, overwrite user data or claim a successful save', () => {
  for (const raw of ['{', '{}', 'null', '[null]', '[{"title":"no identity"}]']) {
    const ui = favorites(raw);
    assert.equal(ui.context.isInMyList('tt1'), false);
    assert.equal(ui.context.toggleMyList('tt1', 'Film', '', '2026'), null);
    assert.equal(ui.stored(), raw);
    assert.match(ui.notices.at(-1), /conservado/);
  }
});
test('quota failure preserves the previous saved item and announces the failure', () => {
  const raw = '[{"imdbId":"tmdb:tv:1","title":"A series","type":"series"}]';
  const ui = favorites(raw, true);
  assert.equal(ui.context.toggleMyList('tmdb:tv:1'), null);
  assert.equal(ui.context.isInMyList('tmdb:tv:1'), true);
  assert.equal(ui.stored(), raw);
  assert.match(ui.notices.at(-1), /No se ha podido guardar/);
});
test('canonical movie and TV identifiers survive adding and removing saved titles', () => {
  const ui = favorites('[]');
  assert.equal(ui.context.toggleMyList('tmdb:tv:1', 'Series', '', '2026', 'series'), true);
  assert.equal(JSON.parse(ui.stored())[0].type, 'series');
  assert.equal(ui.context.toggleMyList('tmdb:tv:1'), false);
  assert.equal(ui.stored(), '[]');
});

function u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; }
function u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; }
function tag(name, value) {
  name = typeof name === 'number' ? Buffer.from([name]) : Buffer.from(name, 'latin1');
  const large = typeof value === 'bigint';
  let type = typeof value === 'string' ? 2 : large ? 11 : 3;
  let payload;
  if (type === 2) { const text = Buffer.from('\ufeff' + value); payload = Buffer.concat([u16(text.length), text]); }
  else if (large) { payload = Buffer.alloc(8); payload.writeBigUInt64LE(value); }
  else payload = u32(value);
  return Buffer.concat([Buffer.from([type]), u16(name.length), name, payload]);
}
function metadata(size, gaps = [], extra = []) {
  const tags = [tag(1, 'Película de prueba.mp4'), tag(2, size), ...gaps.flatMap(([start, end], i) => [tag('\x09' + i, start), tag('\x0a' + i, end)]), ...extra];
  return Buffer.concat([Buffer.from([typeof size === 'bigint' ? 0xe2 : 0xe0]), u32(0), Buffer.alloc(16, 0xab), u16(0), u32(tags.length), ...tags]);
}
test('native metadata calculates downloaded bytes from gaps including 64-bit files and Unicode names', () => {
  const data = parsePartMetadata(metadata(6000000000n, [[1000n, 4000n], [5000n, 6000000000n]]));
  assert.equal(data.fileName, 'Película de prueba.mp4');
  assert.equal(data.totalSizeBytes, 6000000000);
  assert.equal(data.completedBytes, 2000);
  assert.equal(data.hash, 'AB'.repeat(16));
});
test('truncation, unsupported formats and inconsistent gaps are rejected instead of fabricated progress', () => {
  assert.throws(() => parsePartMetadata(metadata(1000).subarray(0, 24)));
  assert.throws(() => parsePartMetadata(Buffer.from([0xe1])));
  assert.throws(() => parsePartMetadata(metadata(1000, [[10, 600], [500, 700]])));
  assert.throws(() => parsePartMetadata(metadata(1000, [], [tag('\x090', 10)])));
});
test('download list uses saved metadata despite a preallocated file and reports inaccessible directory as an error', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ese-download-audit-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, '001.part'), Buffer.alloc(1000));
  fs.writeFileSync(path.join(dir, '001.part.met'), metadata(1000, [[100, 1000]]));
  const [download] = listDownloads(dir, { strict: true });
  assert.equal(download.sizeBytes, 1000);
  assert.equal(download.completedBytes, 100);
  assert.equal(download.totalSizeBytes, 1000);
  assert.equal(download.hash, 'AB'.repeat(16));
  assert.throws(() => listDownloads(path.join(dir, 'missing'), { strict: true }));
});
test('downloads endpoint reports unreadable storage with HTTP 503, not a false empty library', () => {
  const routes = require('../routes/emule_routes');
  routes.init({ EMULE_TEMP: path.join(os.tmpdir(), 'ese-missing-' + Date.now()), EMULE_INCOMING: os.tmpdir() });
  let status, body;
  routes.handle(new URL('http://localhost/api/emule/downloads'), {}, { writeHead(code) { status = code; }, end(value) { body = JSON.parse(value); } });
  assert.equal(status, 503);
  assert.equal(body.error, 'downloads_unavailable');
});

test('canceling preparation prevents a queued playback or poll from affecting the next modal', () => {
  const callbacks = new Map();
  let sequence = 0, plays = 0;
  const nodes = new Map([['movie-modal', {}], ['smart-play-title', {}]]);
  const context = vm.createContext({
    document: { getElementById: id => nodes.get(id), querySelector: () => null },
    setTimeout: fn => { callbacks.set(++sequence, fn); return sequence; },
    clearTimeout: id => callbacks.delete(id), clearInterval: id => callbacks.delete(id)
  });
  context.window = context;
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../smart_play.js'), 'utf8'), context);
  context.smartLater(() => plays++, 1000, context.smartPlayGuard());
  const late = [...callbacks.values()][0];
  context.stopSmartPlay();
  nodes.set('movie-modal', {});
  late();
  assert.equal(plays, 0);
  assert.equal(callbacks.size, 0);
  const firstSource = context.smartPlayGuard();
  context.smartLater(() => plays++, 1000, firstSource);
  const staleSource = [...callbacks.values()][0];
  context.trySmartSource(1);
  staleSource();
  assert.equal(firstSource(), false, 'Choosing another source invalidates its predecessor even in the same modal');
  assert.equal(plays, 0);
});
