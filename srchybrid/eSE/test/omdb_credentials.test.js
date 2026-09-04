'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const test = require('node:test');

const apiKeys = require('../api_keys');
const tmdbApi = require('../tmdb_api');
const https = require('node:https');

const FORBIDDEN_OMDB_CREDENTIAL_SHA256 =
  'd6305f302d81de7ad56aa3c34d12507b187fe22ea31e6d5f13b883a969e0002b';

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

async function withOmdbStubs(keyProvider, outbound, run) {
  const originalGetOmdbKey = apiKeys.getOmdbKey;
  const originalHttpsGet = https.get;
  apiKeys.getOmdbKey = keyProvider;
  https.get = outbound;
  try {
    await run();
  } finally {
    apiKeys.getOmdbKey = originalGetOmdbKey;
    https.get = originalHttpsGet;
  }
}

function omdbRequest(params, type, key) {
  let request;
  const result = new Promise((resolve) => {
    request = tmdbApi.omdbRequest(params, (info, error) => resolve({ info, error }), type, key);
  });
  return { request, result };
}

test('direct OMDb calls without the configured credential fail locally with zero outbound traffic', { concurrency: false }, async () => {
  for (const scenario of [
    { configured: null, supplied: null },
    { configured: 'fixture-configured-omdb-key', supplied: 'fixture-caller-key' }
  ]) {
    let outboundCalls = 0;
    await withOmdbStubs(
      () => scenario.configured,
      () => { outboundCalls += 1; throw new Error('outbound call must not occur'); },
      async () => {
        let synchronous = true;
        const result = new Promise((resolve) => {
          const request = tmdbApi.omdbRequest('t=Matrix', (info, error) => {
            assert.equal(synchronous, false, 'failure callback must not re-enter the caller');
            resolve({ info, error });
          }, 'movie', scenario.supplied);
          assert.equal(request, null);
        });
        synchronous = false;
        assert.deepEqual(await result, { info: null, error: 'omdb_not_configured' });
        assert.equal(outboundCalls, 0);
      }
    );
  }
});

test('OMDb request strips caller credentials, injects the trusted key once, and redacts values and property names', { concurrency: false }, async () => {
  const configuredKey = 'fixture OMDb/+key?&=';
  const uriEncodedKey = encodeURIComponent(configuredKey);
  const formEncodedKey = new URLSearchParams([['apikey', configuredKey]])
    .toString().slice('apikey='.length);
  let capturedTarget = null;

  await withOmdbStubs(
    () => configuredKey,
    (target, options, callback) => {
      capturedTarget = target;
      assert.ok(options.signal instanceof AbortSignal);
      const request = fakeRequest();
      queueMicrotask(() => {
        const body = JSON.stringify({
          raw: configuredKey,
          uri: 'prefix-' + uriEncodedKey,
          form: 'prefix-' + formEncodedKey,
          nested: { [configuredKey]: configuredKey },
          list: [configuredKey]
        });
        const split = Math.max(1, Math.floor(body.length / 2));
        callback(Readable.from([
          Buffer.from(body.slice(0, split)),
          Buffer.from(body.slice(split))
        ]));
      });
      return request;
    },
    async () => {
      const callerTitle = 'Matrix&apikey=caller-inside-title';
      const params = new URLSearchParams([
        ['t', callerTitle],
        ['apikey', 'caller-one'],
        ['APIKEY', 'caller-two'],
        ['api_key', 'caller-three'],
        ['type', 'series']
      ]).toString();
      const { request, result } = omdbRequest(params, 'movie', configuredKey);
      const outcome = await result;

      assert.ok(request);
      assert.deepEqual(outcome.error, null);
      const target = new URL(capturedTarget);
      assert.equal(target.origin, 'https://www.omdbapi.com');
      assert.equal(target.searchParams.get('t'), callerTitle);
      assert.deepEqual(target.searchParams.getAll('apikey'), [configuredKey]);
      assert.equal([...target.searchParams.keys()].filter(name => name.toLowerCase() === 'api_key').length, 0);
      assert.equal([...target.searchParams.keys()].filter(name => name.toLowerCase() === 'apikey').length, 1);
      assert.equal(target.searchParams.get('type'), 'movie');

      const serialized = JSON.stringify(outcome.info);
      for (const variant of [configuredKey, uriEncodedKey, formEncodedKey]) {
        assert.equal(serialized.includes(variant), false, 'credential variant escaped redaction');
      }
      assert.equal(serialized.includes('[redacted]'), true);
      assert.deepEqual(Object.getPrototypeOf(outcome.info), null);
      assert.deepEqual(Object.getPrototypeOf(outcome.info.nested), null);
    }
  );
});

test('OMDb proxy returns only stable local errors and never leaks transport details', { concurrency: false }, async () => {
  const configuredKey = 'fixture-sensitive-omdb-error-key';
  const logLines = [];
  const originalWarn = console.warn;
  const originalError = console.error;
  console.warn = (...args) => logLines.push(args.join(' '));
  console.error = (...args) => logLines.push(args.join(' '));
  try {
    await withOmdbStubs(
      () => configuredKey,
      (_target, options) => {
        assert.ok(options.signal instanceof AbortSignal);
        const request = fakeRequest();
        queueMicrotask(() => request.emit('error', new Error('fixture failure ' + configuredKey)));
        return request;
      },
      async () => {
        const response = new RecordedResponse();
        tmdbApi.proxyOMDB('s=Matrix', response, configuredKey);
        await response.done;
        assert.equal(response.statusCode, 502);
        assert.deepEqual(response.json(), { error: 'omdb_unreachable' });
        assert.equal(response.body.includes(Buffer.from(configuredKey)), false);
        assert.equal(logLines.join('\n').includes(configuredKey), false);
      }
    );
  } finally {
    console.warn = originalWarn;
    console.error = originalError;
  }
});

test('OMDb proxy performs zero outbound traffic and returns 503 when configuration disappears', { concurrency: false }, async () => {
  let outboundCalls = 0;
  await withOmdbStubs(
    () => null,
    () => { outboundCalls += 1; throw new Error('outbound call must not occur'); },
    async () => {
      const response = new RecordedResponse();
      const request = tmdbApi.proxyOMDB('s=Matrix&apikey=caller', response, 'fixture-stale-route-key');
      assert.equal(request, null);
      await response.done;
      assert.equal(response.statusCode, 503);
      assert.deepEqual(response.json(), { error: 'omdb_not_configured' });
      assert.equal(outboundCalls, 0);
    }
  );
});

test('OMDb request timeout is bounded and reports no credential-bearing detail', { concurrency: false }, async () => {
  const configuredKey = 'fixture-timeout-omdb-key';
  let outboundRequest = null;
  await withOmdbStubs(
    () => configuredKey,
    (_target, options) => {
      assert.ok(options.signal instanceof AbortSignal);
      outboundRequest = fakeRequest();
      return outboundRequest;
    },
    async () => {
      const pending = omdbRequest('t=Matrix', 'movie', configuredKey);
      assert.ok(pending.request);
      assert.equal(outboundRequest.timeout.milliseconds, 15000);
      outboundRequest.timeout.callback();
      assert.deepEqual(await pending.result, { info: null, error: 'omdb_unreachable' });
      assert.equal(outboundRequest.destroyed, true);
    }
  );
});

test('OMDb request has an absolute wall deadline and aborts with a stable local error', { concurrency: false }, async () => {
  const configuredKey = 'fixture-wall-deadline-omdb-key';
  const controller = new AbortController();
  const originalSignalTimeout = AbortSignal.timeout;
  let deadlineMilliseconds = null;
  let outboundRequest = null;
  AbortSignal.timeout = (milliseconds) => {
    deadlineMilliseconds = milliseconds;
    return controller.signal;
  };
  try {
    await withOmdbStubs(
      () => configuredKey,
      (_target, options) => {
        assert.equal(options.signal, controller.signal);
        outboundRequest = fakeRequest();
        options.signal.addEventListener('abort', () => {
          outboundRequest.emit('error', new Error('fixture abort ' + configuredKey));
        }, { once: true });
        return outboundRequest;
      },
      async () => {
        const pending = omdbRequest('t=Matrix', 'movie', configuredKey);
        assert.ok(pending.request);
        assert.equal(deadlineMilliseconds, 15000);
        controller.abort();
        assert.deepEqual(await pending.result, { info: null, error: 'omdb_unreachable' });
      }
    );
  } finally {
    AbortSignal.timeout = originalSignalTimeout;
  }
});

test('movie lookup revalidates the credential at the outbound boundary', { concurrency: false }, async () => {
  const configuredKey = 'fixture-rotated-omdb-key';
  let keyReads = 0;
  let outboundCalls = 0;
  await withOmdbStubs(
    () => (++keyReads === 1 ? configuredKey : null),
    () => { outboundCalls += 1; throw new Error('outbound call must not occur'); },
    async () => {
      const outcome = await new Promise((resolve) => {
        tmdbApi.fetchAndCacheMovie(
          'fixture-title-without-cache',
          path.join(__dirname, 'fixture-cache-that-does-not-exist'),
          (info, error) => resolve({ info, error }),
          '',
          {},
          configuredKey
        );
      });
      assert.deepEqual(outcome, { info: null, error: 'omdb_not_configured' });
      assert.equal(keyReads, 2);
      assert.equal(outboundCalls, 0);
    }
  );
});

test('OMDb implementation exports no static credential and contains no known embedded credential', () => {
  assert.equal(Object.prototype.hasOwnProperty.call(tmdbApi, 'OMDB_KEY'), false);

  const sources = [
    path.resolve(__dirname, '..', 'tmdb_api.js'),
    path.resolve(__dirname, '..', 'server.js')
  ];
  const embeddedIn = [];
  for (const source of sources) {
    const text = fs.readFileSync(source, 'utf8');
    for (const candidate of text.match(/(?<![0-9a-f])(?:[0-9a-f]{8}|[0-9a-f]{32})(?![0-9a-f])/gi) || []) {
      const digest = crypto.createHash('sha256').update(candidate, 'utf8').digest('hex');
      if (digest === FORBIDDEN_OMDB_CREDENTIAL_SHA256) embeddedIn.push(path.basename(source));
    }
  }
  assert.deepEqual(embeddedIn, []);

  const serverText = fs.readFileSync(path.resolve(__dirname, '..', 'server.js'), 'utf8');
  assert.doesNotMatch(serverText, /\bOMDB_KEY\b/);
  assert.doesNotMatch(serverText, /omdbapi\.com/i);
  assert.doesNotMatch(serverText, /require\(['"]https['"]\)/);
});
