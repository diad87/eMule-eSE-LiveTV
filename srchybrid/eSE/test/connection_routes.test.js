'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const app = require('../pages/app_page');
const misc = require('../pages/misc_pages');
const security = require('../security');

const fakeToken = 'fixture_access_token_only_123456';
const tunnel = { CONFIG: { accessToken: fakeToken, secretId: 'fixture' }, publicUrl: null, tunnelUrl: null };
const request = (remote = '127.0.0.1', method = 'GET', headers = {}) => ({ method, socket: { remoteAddress: remote }, headers: { host: 'localhost:8080', ...headers } });
function response() {
  return { headers: {}, ends: 0, writeHead(status, headers = {}) { this.status = status; Object.assign(this.headers, headers); }, setHeader(name, value) { this.headers[name] = value; }, end(body = '') { this.body = body; this.ends++; } };
}
function run(page, url, req = request()) {
  const res = response();
  assert.equal(page.handle(new URL(url, 'http://localhost:8080'), req, res), true);
  assert.equal(res.ends, 1);
  for (const match of res.body.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
  return res;
}
function pairing(bindHost = '192.168.1.5') {
  let generated = 0, now = 1000000;
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../pages/connect_page.js'), 'utf8'), {
    module, Buffer, Date: { now: () => now },
    require(name) {
      if (name === 'crypto') return { randomBytes(size) { generated++; return Buffer.alloc(size, 0xab); } };
      if (name === 'os') return { networkInterfaces: () => ({ fixture: [{ family: 'IPv4', internal: false, address: '192.168.1.5' }] }) };
      return require(path.join(__dirname, '../pages', name));
    }
  });
  module.exports.init({ PORT: 8080, tunnel, bindHost });
  return { page: module.exports, generated: () => generated, expire: () => now += 600001 };
}

test('remote, proxy and cross-site clients cannot issue their own pairing grant', () => {
  const p = pairing();
  for (const req of [request('192.168.1.40'), request('192.168.1.40', 'GET', { 'x-ese-token': fakeToken }), request('127.0.0.1', 'GET', { 'x-forwarded-for': '192.168.1.40' }), request('127.0.0.1', 'GET', { origin: 'https://other.example' })]) {
    assert.equal(run(p.page, '/connect', req).status, 403);
  }
  assert.equal(p.generated(), 0);
});
test('loopback-only bind gives useful instructions without generating unreachable links', () => {
  const p = pairing('127.0.0.1');
  const result = run(p.page, '/connect');
  assert.match(result.body, /Disponible sólo en este PC/);
  assert.doesNotMatch(result.body, /http:\/\/localhost|qrserver|id="pair-link"/);
  assert.equal(p.generated(), 0);
});
test('local owner can issue a one-use link, with relative phone redirect and no external QR', () => {
  const p = pairing();
  const result = run(p.page, '/connect');
  assert.match(result.body, /http:\/\/192\.168\.1\.5:8080\/pair\//);
  assert.doesNotMatch(result.body, /qrserver/);
  assert.equal(result.headers['Cache-Control'], 'no-store');
  const code = /\/pair\/([A-F0-9]{32})/.exec(result.body)[1];
  const paired = run(p.page, '/pair/' + code, request('192.168.1.40'));
  assert.equal(paired.status, 302);
  assert.match(paired.headers.Location, /^\/app\?seed=/);
  assert.equal(app.decodeSeed(new URL(paired.headers.Location, 'http://test').searchParams.get('seed')).a, fakeToken);
  assert.equal(run(p.page, '/pair/' + code).status, 410);
});
test('expired codes and non-GET requests do not consume or issue access', () => {
  const p = pairing();
  assert.equal(run(p.page, '/connect', request('127.0.0.1', 'POST')).status, 405);
  const code = /\/pair\/([A-F0-9]{32})/.exec(run(p.page, '/connect').body)[1];
  assert.equal(run(p.page, '/pair/' + code, request('127.0.0.1', 'HEAD')).status, 405);
  p.expire();
  assert.equal(run(p.page, '/pair/' + code).status, 410);
});
test('legacy routes preserve validated seed only and every handled route stops dispatch', () => {
  security.init({ tunnel });
  misc.init({ PORT: 8080, tunnel, HW_ENCODER: 'fixture' });
  const encoded = Buffer.from(JSON.stringify({ a: fakeToken, t: 'javascript:alert(1)', n: 'Fixture' })).toString('base64');
  for (const route of ['/remote', '/go', '/go/fixture']) {
    const result = run(misc, route + '?seed=' + encodeURIComponent(encoded) + '&redirect=https://other.example&a=discard');
    const target = new URL(result.headers.Location, 'http://test');
    assert.equal(target.pathname, '/app');
    assert.deepEqual([...target.searchParams.keys()], ['seed']);
    assert.equal(app.decodeSeed(target.searchParams.get('seed')).t, undefined);
    assert.equal(run(misc, route + '?seed=invalid').headers.Location, '/app');
  }
  assert.equal(run(misc, '/qr').headers.Location, '/connect');
  assert.equal(run(misc, '/api/status').status, 200);
  assert.equal(run(misc, '/manifest.json').status, 200);
  assert.equal(run(misc, '/api/connect-seed').status, 401);
  assert.equal(run(misc, '/api/connect-seed', request('127.0.0.1', 'GET', { 'x-ese-token': fakeToken })).status, 200);
});

async function client({ seed, stored = null, quota = false, status = 200 } = {}) {
  const target = '/app' + (seed ? '?seed=' + encodeURIComponent(Buffer.from(JSON.stringify(seed)).toString('base64')) : '');
  const html = run(app, target).body;
  const nodes = Object.fromEntries(['connection-save', 'connection-busy', 'connection-retry', 'connection-message', 'connection-detail'].map(id => [id, { hidden: true, textContent: '', addEventListener(event, fn) { this[event] = fn; } }]));
  const events = [], requests = [];
  const context = vm.createContext({
    document: { getElementById: id => nodes[id] }, URL, AbortController,
    history: { replaceState: (_, __, url) => events.push(['history', url]) },
    localStorage: { getItem: () => stored, setItem: (_, value) => { if(quota)throw new Error('QuotaExceeded');stored=value; } },
    setTimeout: () => 1, clearTimeout() {},
    fetch(url, options) { events.push(['fetch', url]);requests.push({ url, options }); return Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve({ ok: true }) }); },
    location: { replace: url => events.push(['navigate', url]) }
  });
  context.window = context;
  for(const m of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))vm.runInContext(m[1], context);
  await new Promise(setImmediate);
  return { nodes, events, requests, html, stored };
}
test('app without configuration or with corrupt storage gives navigation and no spinner/fetch loop', async () => {
  for(const stored of [null, '{', '{}', 'null', '[]']) {
    const ui = await client({ stored });
    assert.equal(ui.requests.length, 0);
    assert.equal(ui.nodes['connection-busy'].hidden, true);
    assert.match(ui.html, /href="\/connect"/);
    assert.match(ui.html, /href="\/"/);
  }
});
test('app validates seed, removes it before fetch and exchanges credentials only with its own server', async () => {
  const ui = await client({ seed: { a: fakeToken, t: 'https://other.example', n: '</script><img src=x>' }, quota: true });
  assert.equal(ui.events[0][0], 'history');
  assert.deepEqual(ui.requests.map(r => r.url), ['/api/auth/session']);
  assert.equal(ui.requests[0].options.headers['X-ESE-Token'], fakeToken);
  assert.ok(ui.events.some(e => e[0] === 'navigate' && e[1] === '/'));
  assert.match(ui.nodes['connection-save'].textContent, /esta sesión/);
  assert.doesNotMatch(ui.html, /<img src=x>/);
});
test('expired credentials show recovery without silently replacing saved access', async () => {
  const raw = JSON.stringify({ a: fakeToken });
  const ui = await client({ stored: raw, status: 401 });
  assert.equal(ui.stored, raw);
  assert.equal(ui.nodes['connection-busy'].hidden, true);
  assert.equal(ui.nodes['connection-retry'].hidden, false);
  assert.match(ui.nodes['connection-message'].textContent, /Vuelve a vincular/);
  assert.equal(ui.events.some(e => e[0] === 'navigate'), false);
});

