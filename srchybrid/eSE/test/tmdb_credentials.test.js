'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const test = require('node:test');

const apiKeys = require('../api_keys');
const moviesRoutes = require('../routes/movies_routes');
const https = require('node:https');

const FORBIDDEN_CREDENTIAL_SHA256 = new Set([
  '913514da0d20a5df29313a036247a3048619b9592e608243dd1eac2882f97ae2',
  'd6305f302d81de7ad56aa3c34d12507b187fe22ea31e6d5f13b883a969e0002b'
]);

class RecordedResponse {
  constructor() {
    this.statusCode = null;
    this.headers = null;
    this.headersSent = false;
    this.writableEnded = false;
    this.body = Buffer.alloc(0);
    this.done = new Promise((resolve) => { this._resolve = resolve; });
  }

  writeHead(statusCode, headers = {}) {
    assert.equal(this.headersSent, false, 'response headers written more than once');
    this.statusCode = statusCode;
    this.headers = headers;
    this.headersSent = true;
  }

  end(chunk = '') {
    assert.equal(this.writableEnded, false, 'response ended more than once');
    this.body = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    this.writableEnded = true;
    this._resolve();
  }

  json() {
    return JSON.parse(this.body.toString('utf8'));
  }
}

function fakeRequest() {
  const request = new EventEmitter();
  request.setTimeout = (milliseconds, callback) => {
    request.timeout = { milliseconds, callback };
    return request;
  };
  request.destroy = () => { request.destroyed = true; };
  return request;
}

async function withProxyStubs(keyProvider, outbound, run) {
  const originalGetTmdbKey = apiKeys.getTmdbKey;
  const originalHttpsGet = https.get;
  apiKeys.getTmdbKey = keyProvider;
  https.get = outbound;
  try {
    await run();
  } finally {
    apiKeys.getTmdbKey = originalGetTmdbKey;
    https.get = originalHttpsGet;
  }
}

function proxy(urlText) {
  const response = new RecordedResponse();
  const handled = moviesRoutes.handle(new URL(urlText), { method: 'GET' }, response);
  assert.equal(handled, true);
  return response;
}

test('TMDB credential loader prefers environment and never falls back to a built-in value', () => {
  let fileReads = 0;
  const environmentValue = 'fixture-environment-key';
  const key = apiKeys.getTmdbKey({
    environment: { ESE_TMDB_API_KEY: '  ' + environmentValue + '  ' },
    configPath: 'fixture-config.json',
    fileSystem: {
      existsSync: () => { fileReads += 1; return true; },
      readFileSync: () => { fileReads += 1; return JSON.stringify({ tmdbKey: 'fixture-file-key' }); }
    }
  });
  assert.equal(key, environmentValue);
  assert.equal(fileReads, 0, 'environment precedence must avoid reading the config file');

  assert.equal(apiKeys.getTmdbKey({
    environment: {},
    configPath: 'fixture-config.json',
    fileSystem: { existsSync: () => false, readFileSync: () => assert.fail('unexpected read') }
  }), null);
  assert.equal(Object.prototype.hasOwnProperty.call(apiKeys, 'TMDB_KEY'), false);
});

test('TMDB credential loader accepts local config and fails closed on malformed or unreadable config', () => {
  const fromConfig = apiKeys.getTmdbKey({
    environment: { ESE_TMDB_API_KEY: '   ' },
    configPath: 'fixture-config.json',
    fileSystem: {
      existsSync: () => true,
      readFileSync: () => JSON.stringify({ tmdbKey: '  fixture-file-key  ' })
    }
  });
  assert.equal(fromConfig, 'fixture-file-key');

  for (const readFileSync of [
    () => '{not-json',
    () => JSON.stringify({ tmdbKey: 123 }),
    () => { throw new Error('fixture read failure'); }
  ]) {
    assert.equal(apiKeys.getTmdbKey({
      environment: {},
      configPath: 'fixture-config.json',
      fileSystem: { existsSync: () => true, readFileSync }
    }), null);
  }
});

test('OMDb credential loader uses only its documented environment or config fields', () => {
  const environmentValue = 'fixture-omdb-environment-key';
  assert.equal(apiKeys.getOmdbKey({
    environment: { ESE_OMDB_API_KEY: '  ' + environmentValue + '  ' },
    configPath: 'fixture-config.json',
    fileSystem: {
      existsSync: () => true,
      readFileSync: () => JSON.stringify({ omdbKey: 'fixture-omdb-file-key' })
    }
  }), environmentValue);

  assert.equal(apiKeys.getOmdbKey({
    environment: {},
    configPath: 'fixture-config.json',
    fileSystem: {
      existsSync: () => true,
      readFileSync: () => JSON.stringify({ omdbKey: '  fixture-omdb-file-key  ', tmdbKey: 'wrong-service-key' })
    }
  }), 'fixture-omdb-file-key');

  assert.equal(apiKeys.getOmdbKey({
    environment: {},
    configPath: 'fixture-config.json',
    fileSystem: { existsSync: () => false, readFileSync: () => assert.fail('unexpected read') }
  }), null);
  assert.equal(Object.prototype.hasOwnProperty.call(apiKeys, 'OMDB_KEY'), false);
});

test('missing credential returns local 503 before validation and performs no outbound call', { concurrency: false }, async () => {
  let outboundCalls = 0;
  await withProxyStubs(
    () => null,
    () => { outboundCalls += 1; throw new Error('outbound call must not occur'); },
    async () => {
      const response = proxy('http://127.0.0.1/api/tmdb/not-allowed?api_key=caller');
      await response.done;
      assert.equal(response.statusCode, 503);
      assert.deepEqual(response.json(), { error: 'tmdb_not_configured' });
      assert.equal(outboundCalls, 0);
      assert.equal(response.body.includes(Buffer.from('caller')), false);
    }
  );
});

test('proxy discards caller credentials and injects the configured key exactly once', { concurrency: false }, async () => {
  const configuredKey = 'fixture-configured-tmdb-key';
  let capturedTarget = null;
  await withProxyStubs(
    () => configuredKey,
    (target, options, callback) => {
      capturedTarget = target;
      assert.equal(options.headers['User-Agent'], 'eSE-LiveTV/7.0');
      assert.equal(options.signal instanceof AbortSignal, true);
      assert.equal(options.signal.aborted, false);
      const request = fakeRequest();
      queueMicrotask(() => {
        const upstream = Readable.from([Buffer.from('{"ok":true}')]);
        upstream.statusCode = 200;
        callback(upstream);
      });
      return request;
    },
    async () => {
      const response = proxy('http://127.0.0.1/api/tmdb/search/movie?api_key=caller-one&API_KEY=caller-two&query=Matrix');
      await response.done;
      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.json(), { ok: true });
      const outboundUrl = new URL(capturedTarget);
      assert.equal(outboundUrl.origin, 'https://api.themoviedb.org');
      assert.equal(outboundUrl.pathname, '/3/search/movie');
      assert.deepEqual(outboundUrl.searchParams.getAll('api_key'), [configuredKey]);
      assert.equal(outboundUrl.searchParams.has('API_KEY'), false);
      assert.equal(outboundUrl.searchParams.get('query'), 'Matrix');
      assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
    }
  );
});

test('proxy redacts an upstream credential echo even when split across chunks', { concurrency: false }, async () => {
  const configuredKey = 'fixture sensitive/tmdb+key';
  const formEncodedKey = new URLSearchParams([['api_key', configuredKey]])
    .toString().slice('api_key='.length);
  const split = 9;
  await withProxyStubs(
    () => configuredKey,
    (_target, _options, callback) => {
      const request = fakeRequest();
      queueMicrotask(() => {
        const upstream = Readable.from([
          Buffer.from('{"echo":"' + formEncodedKey.slice(0, split)),
          Buffer.from(formEncodedKey.slice(split) + '"}')
        ]);
        upstream.statusCode = 401;
        callback(upstream);
      });
      return request;
    },
    async () => {
      const response = proxy('http://127.0.0.1/api/tmdb/movie/1');
      await response.done;
      assert.equal(response.statusCode, 401);
      assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
      assert.equal(response.body.includes(Buffer.from(formEncodedKey)), false);
      assert.equal(response.body.toString('utf8').includes('[redacted]'), true);
    }
  );
});

test('proxy parses JSON before recursively redacting escaped values and property names', { concurrency: false }, async () => {
  const configuredKey = 'fixture-unicode-escape-key';
  const escapedKey = [...configuredKey]
    .map(character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'))
    .join('');
  await withProxyStubs(
    () => configuredKey,
    (_target, _options, callback) => {
      const request = fakeRequest();
      queueMicrotask(() => {
        const upstream = Readable.from([
          Buffer.from('{"' + escapedKey + '":{"nested":"' + escapedKey + '"}}')
        ]);
        upstream.statusCode = 200;
        callback(upstream);
      });
      return request;
    },
    async () => {
      const response = proxy('http://127.0.0.1/api/tmdb/movie/1');
      await response.done;
      assert.equal(response.statusCode, 200);
      const serialized = response.body.toString('utf8');
      assert.equal(serialized.includes(configuredKey), false);
      assert.equal(serialized.includes(escapedKey), false);
      assert.deepEqual(response.json(), { '[redacted]': { nested: '[redacted]' } });
    }
  );
});

test('proxy exposes no credential or transport detail when the outbound request fails', { concurrency: false }, async () => {
  const configuredKey = 'fixture-sensitive-error-key';
  const logLines = [];
  const originalWarn = console.warn;
  const originalError = console.error;
  console.warn = (...args) => logLines.push(args.join(' '));
  console.error = (...args) => logLines.push(args.join(' '));
  try {
    await withProxyStubs(
      () => configuredKey,
      () => {
        const request = fakeRequest();
        queueMicrotask(() => request.emit('error', new Error('failure for ' + configuredKey)));
        return request;
      },
      async () => {
        const response = proxy('http://127.0.0.1/api/tmdb/movie/1');
        await response.done;
        assert.equal(response.statusCode, 502);
        assert.deepEqual(response.json(), { error: 'tmdb_unreachable' });
        assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
        assert.equal(logLines.join('\n').includes(configuredKey), false);
      }
    );
  } finally {
    console.warn = originalWarn;
    console.error = originalError;
  }
});

test('proxy wall-clock abort is wired independently of socket activity', { concurrency: false }, async () => {
  const configuredKey = 'fixture-wall-deadline-key';
  const originalAbortTimeout = AbortSignal.timeout;
  const controller = new AbortController();
  let requestedDeadline = null;
  AbortSignal.timeout = (milliseconds) => {
    requestedDeadline = milliseconds;
    return controller.signal;
  };
  try {
    await withProxyStubs(
      () => configuredKey,
      (_target, options) => {
        const request = fakeRequest();
        options.signal.addEventListener('abort', () => {
          request.emit('error', new Error('aborted fixture ' + configuredKey));
        }, { once: true });
        return request;
      },
      async () => {
        const response = proxy('http://127.0.0.1/api/tmdb/movie/1');
        assert.equal(requestedDeadline, 15000);
        controller.abort();
        await response.done;
        assert.equal(response.statusCode, 502);
        assert.deepEqual(response.json(), { error: 'tmdb_unreachable' });
        assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
      }
    );
  } finally {
    AbortSignal.timeout = originalAbortTimeout;
  }
});

test('OMDb-backed routes return local 503 and invoke no dependency when unconfigured', { concurrency: false }, async () => {
  const originalGetOmdbKey = apiKeys.getOmdbKey;
  let proxyCalls = 0;
  let fetchCalls = 0;
  apiKeys.getOmdbKey = () => null;
  moviesRoutes.init({
    CACHE_DIR: 'fixture-cache',
    loadSettings: () => ({}),
    proxyOMDB: () => { proxyCalls += 1; },
    fetchAndCacheMovie: () => { fetchCalls += 1; }
  });
  try {
    for (const urlText of [
      'http://127.0.0.1/api/movies/search?q=Matrix%26apikey%3Dcaller',
      'http://127.0.0.1/api/movies/detail?id=tt0133093%26apikey%3Dcaller',
      'http://127.0.0.1/api/movies/fetchinfo?title=Matrix'
    ]) {
      const response = proxy(urlText);
      await response.done;
      assert.equal(response.statusCode, 503);
      assert.deepEqual(response.json(), { error: 'omdb_not_configured' });
      assert.equal(response.body.includes(Buffer.from('caller')), false);
    }
    assert.equal(proxyCalls, 0);
    assert.equal(fetchCalls, 0);
  } finally {
    apiKeys.getOmdbKey = originalGetOmdbKey;
  }
});

test('OMDb-backed routes pass the configured credential separately from caller data', { concurrency: false }, async () => {
  const originalGetOmdbKey = apiKeys.getOmdbKey;
  const configuredKey = 'fixture-configured-omdb-key';
  const proxyCalls = [];
  const fetchCalls = [];
  apiKeys.getOmdbKey = () => configuredKey;
  moviesRoutes.init({
    CACHE_DIR: 'fixture-cache',
    loadSettings: () => ({ fixture: true }),
    proxyOMDB: (params, response, key) => {
      proxyCalls.push({ params, key });
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end('{}');
    },
    fetchAndCacheMovie: (...args) => {
      fetchCalls.push(args);
      args[2]({ Response: 'False' });
    }
  });
  try {
    const search = proxy('http://127.0.0.1/api/movies/search?q=Matrix%26apikey%3Dcaller');
    await search.done;
    const detail = proxy('http://127.0.0.1/api/movies/detail?id=tt0133093%26apikey%3Dcaller');
    await detail.done;
    const fetchInfo = proxy('http://127.0.0.1/api/movies/fetchinfo?title=Matrix&raw=fixture.mkv');
    await fetchInfo.done;

    assert.deepEqual(proxyCalls, [
      { params: 's=Matrix%26apikey%3Dcaller', key: configuredKey },
      { params: 'i=tt0133093%26apikey%3Dcaller&plot=full', key: configuredKey }
    ]);
    assert.equal(fetchCalls.length, 1);
    assert.equal(fetchCalls[0][0], 'Matrix');
    assert.equal(fetchCalls[0][4].fixture, true);
    assert.equal(fetchCalls[0][5], configuredKey);
  } finally {
    apiKeys.getOmdbKey = originalGetOmdbKey;
  }
});

test('fetchinfo preserves a downstream fail-closed OMDb configuration result', { concurrency: false }, async () => {
  const originalGetOmdbKey = apiKeys.getOmdbKey;
  const configuredKey = 'fixture-route-key';
  apiKeys.getOmdbKey = () => configuredKey;
  moviesRoutes.init({
    CACHE_DIR: 'fixture-cache',
    loadSettings: () => ({}),
    proxyOMDB: () => assert.fail('unexpected proxy call'),
    fetchAndCacheMovie: (_title, _cache, callback, _raw, _settings, receivedKey) => {
      assert.equal(receivedKey, configuredKey);
      callback(null, 'omdb_not_configured');
    }
  });
  try {
    const response = proxy('http://127.0.0.1/api/movies/fetchinfo?title=Matrix');
    await response.done;
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), { error: 'omdb_not_configured' });
    assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
  } finally {
    apiKeys.getOmdbKey = originalGetOmdbKey;
  }
});

test('fetchinfo maps every other downstream OMDb error to a stable credential-free 502', { concurrency: false }, async () => {
  const originalGetOmdbKey = apiKeys.getOmdbKey;
  const configuredKey = 'fixture-route-error-key';
  apiKeys.getOmdbKey = () => configuredKey;
  moviesRoutes.init({
    CACHE_DIR: 'fixture-cache',
    loadSettings: () => ({}),
    proxyOMDB: () => assert.fail('unexpected proxy call'),
    fetchAndCacheMovie: (_title, _cache, callback) => {
      callback(null, 'transport detail containing ' + configuredKey);
    }
  });
  try {
    const response = proxy('http://127.0.0.1/api/movies/fetchinfo?title=Matrix');
    await response.done;
    assert.equal(response.statusCode, 502);
    assert.deepEqual(response.json(), { error: 'omdb_unreachable' });
    assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
  } finally {
    apiKeys.getOmdbKey = originalGetOmdbKey;
  }
});

test('source text contains no token matching either known embedded credential hash', () => {
  const root = path.resolve(__dirname, '..');
  const textExtensions = new Set(['.css', '.h', '.html', '.js', '.json', '.md', '.ps1', '.txt']);
  const matches = [];

  function scan(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        scan(fullPath);
        continue;
      }
      if (!entry.isFile() || !textExtensions.has(path.extname(entry.name).toLowerCase())) continue;
      const text = fs.readFileSync(fullPath, 'utf8');
      for (const candidate of text.match(/(?<![0-9a-f])(?:[0-9a-f]{8}|[0-9a-f]{32})(?![0-9a-f])/gi) || []) {
        const digest = crypto.createHash('sha256').update(candidate, 'utf8').digest('hex');
        if (FORBIDDEN_CREDENTIAL_SHA256.has(digest)) matches.push(path.relative(root, fullPath));
      }
    }
  }

  scan(root);
  assert.deepEqual(matches, [], 'known credential remains embedded in: ' + [...new Set(matches)].join(', '));
});
