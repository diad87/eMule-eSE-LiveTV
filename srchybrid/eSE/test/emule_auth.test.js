'use strict';

// VM-only authentication tests: HTTP, process execution, timers and settings
// are controlled in memory. No credentials, native eMule or user files are read.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const zlib = require('node:zlib');
const utils = require('../utils');
const source = fs.readFileSync(path.join(__dirname, '../emule_api.js'), 'utf8');
const routeSource = fs.readFileSync(path.join(__dirname, '../routes/emule_routes.js'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const fixturePassword = 'memory-fixture-password';
const loginHtml = '<form><input type="password" name="p"><input name="w" value="password"></form>';
const successHtml = '<a href="?ses=12345&amp;w=transfer">Connected</a>';

function harness({ settings = { emulePassword: fixturePassword }, env = {} } = {}) {
  const requests = [], writes = [], logs = [], timers = new Map(), processCalls = [];
  let timerId = 0;
  const module = { exports: {} };
  vm.runInNewContext(source, {
    module, exports: module.exports, __dirname: 'C:/isolated-fixture', process: { env }, URL, Buffer,
    console: Object.fromEntries(['log', 'error', 'warn'].map(level => [level, (...args) => logs.push(args.join(' '))])),
    setInterval() {},
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    require(name) {
      if (name === 'path') return path;
      if (name === 'zlib') return zlib;
      if (name === './emule_web_port') return require('../emule_web_port');
      if (name === 'fs') return { existsSync: () => false };
      if (name === 'child_process') return { spawn() { throw new Error('Processes forbidden in auth test'); } };
      if (name === './bounded_process') return { runFile: async (...args) => { processCalls.push(args); return { stdout: '' }; } };
      if (name === 'http') return { get(options, callback) {
        const request = new EventEmitter();
        request.options = options;
        request.destroy = () => { request.destroyed = true; request.emit('error', Object.assign(new Error('closed'), { code: 'ECONNRESET' })); };
        request.respond = (body = successHtml, statusCode = 200, encoding) => {
          const response = new PassThrough(); response.statusCode = statusCode;
          response.headers = encoding ? { 'content-encoding': encoding } : {};
          request.response = response;
          callback(response);
          const bytes = Buffer.from(body);
          response.end(encoding === 'gzip' ? zlib.gzipSync(bytes) : encoding === 'deflate' ? zlib.deflateSync(bytes) : bytes);
          return response;
        };
        requests.push(request);
        return request;
      } };
      throw new Error('Unapproved auth dependency: ' + name);
    }
  });
  const api = module.exports;
  const loadSettings = () => ({ ...settings });
  const saveSettings = value => { writes.push({ ...value }); settings = { ...value }; };
  api.setSettingsFunctions(loadSettings, saveSettings);
  const routeModule = { exports: {} };
  vm.runInNewContext(routeSource, {
    module: routeModule, Buffer,
    require(name) {
      if (name === 'fs') return {};
      if (name === 'path') return path;
      if (name === '../utils') return utils;
      if (name === '../media_resolver' || name === '../ai_assistant') return {};
      throw new Error('Unapproved route dependency: ' + name);
    }
  });
  routeModule.exports.init({ emuleLogin: api.emuleLogin, getSession: api.getSession, getAuthStatus: api.getAuthStatus, loadSettings, saveSettings });
  return {
    api, requests, writes, logs, timers, processCalls,
    timer() { const [id, timer] = timers.entries().next().value; timers.delete(id); timer.callback(); return timer.delay; },
    login(password) { return new Promise(resolve => api.emuleLogin(password, (error, session) => resolve({ error, session }))); },
    route(url, method = 'GET', body) {
      const req = new EventEmitter(); req.method = method; req.headers = {};
      const res = { headers: {}, ends: 0, setHeader(name, value) { this.headers[name] = value; },
        writeHead(status, headers = {}) { this.status = status; Object.assign(this.headers, headers); },
        end(value) { this.body = value; this.data = JSON.parse(value); this.ends++; } };
      assert.equal(routeModule.exports.handle(new URL(url, 'http://127.0.0.1'), req, res), true);
      if (method === 'POST') { if (body !== undefined) req.emit('data', Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))); req.emit('end'); }
      return res;
    }
  };
}

test('standalone login without a configured credential neither generates nor sends a password', () => {
  const h = harness({ settings: {} });
  h.api.autoLoginEmule();
  assert.equal(h.requests.length, 0);
  assert.equal(h.writes.length, 0);
  assert.equal(h.timers.size, 0);
  assert.equal(h.api.getAuthStatus().reason, 'password_missing');
  assert.equal(h.api.getAuthStatus().retrying, false);
  h.api.autoLoginEmule();
  assert.equal(h.requests.length, 0);
});

test('environment, saved and explicit credentials preserve priority while the redacted marker uses the backend', async () => {
  const h = harness({ env: { ESE_EMULE_PASSWORD: 'memory-environment-fixture' } });
  let result = h.login('********');
  assert.equal(new URLSearchParams(h.requests[0].options.path.split('?')[1]).get('p'), 'memory-environment-fixture');
  h.requests[0].respond(); assert.equal((await result).session, '12345');
  assert.equal(h.writes.length, 1);
  result = h.login('memory-explicit-fixture');
  assert.equal(new URLSearchParams(h.requests[1].options.path.split('?')[1]).get('p'), 'memory-explicit-fixture');
  h.requests[1].respond(); assert.equal((await result).error, null);
  assert.equal(h.timers.size, 0);
  assert.doesNotMatch(h.logs.join('\n'), /memory-.*fixture|12345/);
});

test('an explicitly tested and saved correction survives resync with an old process environment', async () => {
  for (const resolveOnStartup of [true, false]) {
    const h = harness({ env: { ESE_EMULE_PASSWORD: 'memory-old-environment-fixture' } });
    if (resolveOnStartup) {
      const startup = h.login(); h.requests.at(-1).respond(); await startup;
      assert.equal(h.writes.at(-1).emulePassword, 'memory-old-environment-fixture');
    }
    const tested = h.route('/api/emule/login', 'POST', { password: 'memory-corrected-fixture' });
    assert.equal(new URLSearchParams(h.requests.at(-1).options.path.split('?')[1]).get('p'), 'memory-corrected-fixture');
    h.requests.at(-1).respond(); await flush();
    assert.equal(tested.data.success, true);
    assert.equal(h.route('/api/settings', 'POST', { emulePassword: 'memory-corrected-fixture' }).status, 200);
    const writesBeforeResync = h.writes.length;
    const resynced = h.route('/api/emule/resync', 'POST');
    assert.equal(new URLSearchParams(h.requests.at(-1).options.path.split('?')[1]).get('p'), 'memory-corrected-fixture');
    h.requests.at(-1).respond(); await flush();
    assert.equal(resynced.data.success, true);
    assert.equal(h.writes.length, writesBeforeResync, 'resync must not rewrite the saved correction');
  }
});

test('saving a correction before the first login also survives resync', async () => {
  const h = harness({ env: { ESE_EMULE_PASSWORD: 'memory-old-environment-fixture' } });
  assert.equal(h.route('/api/settings', 'POST', { emulePassword: 'memory-corrected-fixture' }).status, 200);
  const writesBeforeResync = h.writes.length;
  const resynced = h.route('/api/emule/resync', 'POST');
  assert.equal(new URLSearchParams(h.requests[0].options.path.split('?')[1]).get('p'), 'memory-corrected-fixture');
  h.requests[0].respond(); await flush();
  assert.equal(resynced.data.success, true);
  assert.equal(h.writes.length, writesBeforeResync);
});

test('rejected credentials stop automatic retries and concurrent calls share one login', async () => {
  const h = harness();
  h.api.autoLoginEmule(); h.api.autoLoginEmule();
  const same = h.login(fixturePassword);
  assert.equal(h.requests.length, 1);
  h.requests[0].respond(loginHtml);
  assert.equal((await same).error.reason, 'password_mismatch');
  assert.equal(h.requests.length, 1); assert.equal(h.timers.size, 0);
  assert.equal(h.api.getAuthStatus().retrying, false);
  assert.equal(h.api.getSession(), null);
  h.api.autoLoginEmule();
  assert.equal(h.requests.length, 1, 'unchanged rejected credentials stay stopped across automatic callers');
  assert.match(h.logs.join('\n'), /password_mismatch/);
  assert.doesNotMatch(h.logs.join('\n'), /memory-fixture-password/);
});

test('native lockout, malformed HTML and HTTP errors are not mislabeled as a wrong password', async () => {
  for (const [body, code, reason, retryable] of [
    ['Acceso denegado', 200, 'access_denied', false],
    ['Unexpected response', 200, 'invalid_login_response', false],
    ['Try later', 503, 'webserver_http_error', true],
    ['Forbidden', 403, 'webserver_http_error', false]
  ]) {
    const h = harness(); const result = h.login();
    h.requests[0].respond(body, code);
    const { error } = await result;
    assert.equal(error.reason, reason); assert.equal(error.retryable, retryable);
    assert.equal(h.timers.size, 0);
  }
});

test('temporary network failures have one bounded exponential retry chain', async () => {
  const h = harness(); h.api.autoLoginEmule();
  for (let attempt = 1; attempt <= 5; attempt++) {
    assert.equal(h.requests.length, attempt);
    h.requests.at(-1).emit('error', Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
    await flush();
    h.api.autoLoginEmule(); // Repeated callers must not add a parallel retry.
    if (attempt < 5) {
      assert.equal(h.timers.size, 1);
      assert.equal(h.api.getAuthStatus().retrying, true);
      assert.equal(h.timer(), 10000 * 2 ** (attempt - 1));
    }
  }
  assert.equal(h.requests.length, 5);
  assert.equal(h.timers.size, 0);
  assert.equal(h.api.getAuthStatus().retrying, false);
});

test('request deadline settles once even when destruction and late response events follow', async () => {
  const h = harness(); let calls = 0, reason;
  h.api.emuleLogin(undefined, error => { calls++; reason = error.reason; });
  assert.equal(h.timer(), 10000);
  const request = h.requests[0];
  assert.equal(request.destroyed, true);
  request.respond(); request.emit('error', Object.assign(new Error('late'), { code: 'ECONNRESET' }));
  await flush();
  assert.equal(calls, 1); assert.equal(reason, 'login_timeout'); assert.equal(h.api.getSession(), null);
});

test('compressed responses still authenticate and interrupted responses settle once', async () => {
  for (const encoding of ['gzip', 'deflate']) {
    const h = harness(); const result = h.login(); h.requests[0].respond(successHtml, 200, encoding);
    assert.equal((await result).session, '12345');
  }
  const h = harness(); let calls = 0;
  h.api.emuleRequest('?w=test', error => { calls++; assert.equal(error.code, 'ECONNRESET'); });
  const response = h.requests[0].respond(); response.emit('aborted');
  h.requests[0].emit('error', Object.assign(new Error('also closed'), { code: 'ECONNRESET' }));
  await flush(); assert.equal(calls, 1);
});

test('successful manual recovery cancels the pending automatic retry', async () => {
  const h = harness(); h.api.autoLoginEmule();
  h.requests[0].emit('error', Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }));
  assert.equal(h.api.getAuthStatus().retrying, true);
  const cancelledRetry = [...h.timers.values()][0].callback;
  const result = h.login(); h.requests[1].respond();
  assert.equal((await result).session, '12345');
  cancelledRetry();
  assert.equal(h.requests.length, 2, 'already queued stale retry cannot undo a successful recovery');
  assert.equal(h.timers.size, 0); assert.equal(h.api.getAuthStatus().reason, null);
});

test('login routes accept POST JSON and use stored credentials for empty or redacted values', async () => {
  for (const [url, method, body, expected] of [
    ['/api/emule/login', 'POST', {}, fixturePassword],
    ['/api/emule/login', 'POST', { password: '********' }, fixturePassword],
    ['/api/emule/login', 'POST', { password: 'new-memory-fixture' }, 'new-memory-fixture'],
    ['/api/emule/login?p=********', 'GET', undefined, fixturePassword],
    ['/api/emule/resync', 'POST', undefined, fixturePassword]
  ]) {
    const h = harness(); const response = h.route(url, method, body);
    assert.equal(new URLSearchParams(h.requests[0].options.path.split('?')[1]).get('p'), expected);
    h.requests[0].respond(); await flush();
    assert.equal(response.status, 200); assert.equal(response.data.success, true);
    assert.equal(response.headers['Cache-Control'], 'no-store');
    assert.doesNotMatch(response.body, /memory-fixture|new-memory/);
  }
});

test('invalid login bodies never reach eMule and status exposes only safe diagnostics', async () => {
  const h = harness();
  for (const body of ['{', { password: 3 }, []]) {
    assert.equal(h.route('/api/emule/login', 'POST', body).status, 400);
  }
  assert.equal(h.route('/api/emule/login', 'DELETE').status, 405);
  assert.equal(h.requests.length, 0);
  h.api.autoLoginEmule(); h.requests[0].respond(loginHtml); await flush();
  const status = h.route('/api/emule/status');
  assert.equal(status.data.loggedIn, false); assert.equal(status.data.reason, 'password_mismatch');
  assert.equal(status.data.retrying, false); assert.equal(status.data.retryAfterMs, 0);
  assert.doesNotMatch(status.body, /memory-fixture-password/);
});

test('isolated test mode does not start the process lifecycle watchdog', async () => {
  const isolated = harness({ env: { ESE_TEST_MODE: '1' } });
  await flush();
  assert.equal(isolated.processCalls.length, 0);
  const ordinary = harness();
  await flush();
  assert.equal(ordinary.processCalls.length, 1);
  assert.equal(ordinary.processCalls[0][0], 'tasklist');
});
