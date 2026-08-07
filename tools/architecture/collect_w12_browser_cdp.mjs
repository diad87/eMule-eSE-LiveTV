/* Import-only W12 collector: browser-client supplies the documented browser. */
import { createHash, randomUUID } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { lstat, link, open, realpath, unlink, writeFile } from 'node:fs/promises';
import { platform } from 'node:os';
import { dirname, isAbsolute, resolve, sep } from 'node:path';

const READY_SCHEMA = 'ese.v92.w12.browser-ready/v3';
const HANDOFF_SCHEMA = 'ese.v92.w12.browser-handoff/v3';
const RAW_SCHEMA = 'ese.v92.w12.browser-raw/v3';
const DONE_SCHEMA = 'ese.v92.w12.browser-done/v3';
const CLAIM_SCHEMA = 'ese.v92.w12.browser-collector-claim/v3';
const H40 = /^[0-9a-f]{40}$/;
const H64 = /^[0-9a-f]{64}$/;
const H32 = /^[0-9a-f]{32}$/;
const MAX_JSON = 128 * 1024;
const MAX_BODY = 48 * 1024;
const MAX_FORWARD = 2 * 1024 * 1024;

export const sha256 = (value) => createHash('sha256').update(value).digest('hex');

/* JSON.parse cannot reject duplicate names, so use a small complete parser. */
export function parseStrictJson(source, label = 'json') {
  if (typeof source !== 'string' || Buffer.byteLength(source) > MAX_JSON) {
    throw new Error(`${label}: size`);
  }
  let index = 0;
  const whitespace = () => {
    while (/\s/.test(source[index] ?? '')) index += 1;
  };
  const fail = () => { throw new Error(`${label}: JSON`); };
  const string = () => {
    if (source[index++] !== '"') fail();
    let output = '';
    for (;;) {
      const character = source[index++];
      if (character === '"') return output;
      if (character === undefined || character < ' ') fail();
      if (character !== '\\') {
        output += character;
        continue;
      }
      const escape = source[index++];
      const simple = {
        '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t',
      };
      if (escape === 'u') {
        const hex = source.slice(index, index + 4);
        if (!/^[0-9a-f]{4}$/i.test(hex)) fail();
        index += 4;
        output += String.fromCharCode(Number.parseInt(hex, 16));
      } else if (Object.hasOwn(simple, escape)) {
        output += simple[escape];
      } else {
        fail();
      }
    }
  };
  const value = () => {
    whitespace();
    const character = source[index];
    if (character === '"') return string();
    if (character === '{') {
      index += 1;
      whitespace();
      const object = Object.create(null);
      if (source[index] === '}') {
        index += 1;
        return object;
      }
      for (;;) {
        whitespace();
        const key = string();
        if (Object.hasOwn(object, key)) throw new Error(`${label}: duplicate`);
        whitespace();
        if (source[index++] !== ':') fail();
        object[key] = value();
        whitespace();
        if (source[index] === '}') {
          index += 1;
          return object;
        }
        if (source[index++] !== ',') fail();
      }
    }
    if (character === '[') {
      index += 1;
      whitespace();
      const array = [];
      if (source[index] === ']') {
        index += 1;
        return array;
      }
      for (;;) {
        array.push(value());
        whitespace();
        if (source[index] === ']') {
          index += 1;
          return array;
        }
        if (source[index++] !== ',') fail();
      }
    }
    if (source.startsWith('true', index)) {
      index += 4;
      return true;
    }
    if (source.startsWith('false', index)) {
      index += 5;
      return false;
    }
    if (source.startsWith('null', index)) {
      index += 4;
      return null;
    }
    const number = source.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!number) fail();
    index += number[0].length;
    return Number(number[0]);
  };
  const result = value();
  whitespace();
  if (index !== source.length) fail();
  return result;
}

function exact(value, keys, where) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${where}: object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    throw new Error(`${where}: grammar`);
  }
  return value;
}

function hexadecimal(value, expression, where) {
  if (typeof value !== 'string' || !expression.test(value)) {
    throw new Error(`${where}: hexadecimal`);
  }
  return value;
}

function boundedText(value, where, maximum = 512) {
  if (typeof value !== 'string' || !value || value.length > maximum || /[\0\r\n]/.test(value)) {
    throw new Error(`${where}: text`);
  }
  return value;
}

function candidate(value) {
  const item = exact(value, ['build_commit', 'emule_sha256', 'build_info_sha256', 'release'], 'candidate');
  hexadecimal(item.build_commit, H40, 'candidate.build_commit');
  hexadecimal(item.emule_sha256, H64, 'candidate.emule_sha256');
  hexadecimal(item.build_info_sha256, H64, 'candidate.build_info_sha256');
  boundedText(item.release, 'candidate.release', 96);
  return item;
}

function binding(value) {
  const item = exact(value, [
    'activation_commit', 'production_tree_sha256', 'toolset_sha256',
    'run_id_sha256', 'challenge_nonce_sha256', 'canary_sha256',
  ], 'binding');
  hexadecimal(item.activation_commit, H40, 'binding.activation_commit');
  for (const key of Object.keys(item).filter((key) => key !== 'activation_commit')) {
    hexadecimal(item[key], H64, `binding.${key}`);
  }
  return item;
}

export function assertLoopbackUrl(value) {
  const url = new URL(boundedText(value, 'base_url', 128));
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port
      || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('base_url: exact loopback');
  }
  return url;
}

export function validateReadyV3(value) {
  const ready = exact(value, [
    'schema', 'A', 'run_id_sha256', 'challenge_nonce_sha256', 'handoff_sha256', 'collector_sha256',
  ], 'ready');
  if (ready.schema !== READY_SCHEMA) throw new Error('ready: schema');
  hexadecimal(ready.A, H40, 'ready.A');
  for (const key of ['run_id_sha256', 'challenge_nonce_sha256', 'handoff_sha256', 'collector_sha256']) {
    hexadecimal(ready[key], H64, `ready.${key}`);
  }
  return ready;
}

export function validateHandoffV3(value) {
  const handoff = exact(value, [
    'schema', 'A', 'candidate', 'binding', 'base_url', 'login_password', 'stream_key', 'canary',
    'run_id', 'challenge_nonce', 'raw_path', 'done_path',
  ], 'handoff');
  if (handoff.schema !== HANDOFF_SCHEMA) throw new Error('handoff: schema');
  hexadecimal(handoff.A, H40, 'handoff.A');
  const handoffCandidate = candidate(handoff.candidate);
  const handoffBinding = binding(handoff.binding);
  if (handoff.A !== handoffCandidate.build_commit || handoff.A !== handoffBinding.activation_commit) {
    throw new Error('handoff: A binding');
  }
  assertLoopbackUrl(handoff.base_url);
  boundedText(handoff.login_password, 'handoff.login_password', 128);
  hexadecimal(handoff.stream_key, H32, 'handoff.stream_key');
  for (const key of ['canary', 'run_id', 'challenge_nonce']) {
    hexadecimal(handoff[key], H64, `handoff.${key}`);
  }
  if (sha256(handoff.run_id) !== handoffBinding.run_id_sha256
      || sha256(handoff.challenge_nonce) !== handoffBinding.challenge_nonce_sha256
      || sha256(handoff.canary) !== handoffBinding.canary_sha256) {
    throw new Error('handoff: secret binding');
  }
  for (const key of ['raw_path', 'done_path']) {
    if (!isAbsolute(boundedText(handoff[key], `handoff.${key}`, 1024))) {
      throw new Error(`handoff.${key}: absolute`);
    }
  }
  return handoff;
}

export function assertReadyHandoffBinding(ready, handoff) {
  if (ready.A !== handoff.A
      || ready.run_id_sha256 !== handoff.binding.run_id_sha256
      || ready.challenge_nonce_sha256 !== handoff.binding.challenge_nonce_sha256) {
    throw new Error('ready/handoff: binding');
  }
}

export function assertCapabilityPath(path, streamKey) {
  if (typeof path !== 'string' || !H32.test(streamKey)) throw new Error('capability: input');
  const match = path.match(/^\/h\/([0-9a-f]{64})\/([1-9][0-9]*)\/([0-9a-f]{32})\/stream\.m3u8$/);
  if (!match || match[3] !== streamKey) throw new Error('capability: grammar');
  return { token: match[1], generation: match[2], stream_key: match[3] };
}

function rawEvent(method, params) {
  return { method, params };
}

export function assertEventOrder(events) {
  const seen = new Map();
  const requestOrder = [];
  for (const event of events) {
    if (!event || typeof event !== 'object'
        || !['Network.requestWillBeSent', 'Network.responseReceived', 'Network.getResponseBody'].includes(event.method)
        || !event.params || typeof event.params !== 'object') {
      throw new Error('events: shape');
    }
    const requestId = event.params.requestId;
    if (typeof requestId !== 'string' || !requestId) throw new Error('events: request id');
    const record = seen.get(requestId) ?? { request: false, response: false, body: false };
    if (event.method === 'Network.requestWillBeSent') {
      if (record.request) throw new Error('events: duplicate request');
      const request = event.params.request;
      if (!request || typeof request.url !== 'string' || !request.url.startsWith('http://127.0.0.1:')
          || !['GET', 'POST'].includes(request.method) || !request.headers
          || typeof request.headers !== 'object') {
        throw new Error('events: request shape');
      }
      record.request = true;
      requestOrder.push(requestId);
    } else if (!record.request
        || event.method === 'Network.responseReceived' && (record.response || record.body)
        || event.method === 'Network.getResponseBody' && (!record.response || record.body)) {
      throw new Error('events: order');
    } else if (event.method === 'Network.responseReceived') {
      const response = event.params.response;
      if (!response || !Number.isInteger(response.status) || !response.headers
          || typeof response.headers !== 'object') {
        throw new Error('events: response shape');
      }
      record.response = true;
    } else {
      if (typeof event.params.body !== 'string' || event.params.base64Encoded !== false
          || Buffer.byteLength(event.params.body) > MAX_BODY) {
        throw new Error('events: body shape');
      }
      record.body = true;
    }
    seen.set(requestId, record);
  }
  if (!requestOrder.length || [...seen.values()].some((record) => !record.response)) {
    throw new Error('events: incomplete');
  }
}

export function assertScenario(events, { streamKey, canary }) {
  assertEventOrder(events);
  hexadecimal(streamKey, H32, 'scenario.stream');
  hexadecimal(canary, H64, 'scenario.canary');
  const records = [];
  const byId = new Map();
  for (const event of events) {
    const requestId = event.params.requestId;
    if (event.method === 'Network.requestWillBeSent') {
      const url = new URL(event.params.request.url);
      if (Object.keys(event.params.request.headers).some((key) => key.toLowerCase() === 'referer')
          || url.pathname === '/api/live/broadcast/start') {
        throw new Error('scenario: referer/broadcast');
      }
      const record = { url, request: event, response: null, body: null };
      byId.set(requestId, record);
      records.push(record);
    } else if (event.method === 'Network.responseReceived') {
      byId.get(requestId).response = event;
    } else {
      byId.get(requestId).body = event;
    }
  }
  const capability = records.find((record) => record.url.pathname.startsWith('/h/')
    && record.response?.params.response.status === 200)?.url.pathname;
  const capabilityInfo = capability && assertCapabilityPath(capability, streamKey);
  if (!capabilityInfo) throw new Error('scenario: capability');

  const paths = records.map((record) => record.url.pathname);
  const statuses = records.map((record) => record.response?.params.response.status);
  const variant = records.length === 9;
  const segmentIndex = variant ? 4 : 3;
  const forgedIndex = segmentIndex + 1;
  const expectedStatuses = variant
    ? '200,200,200,200,206,403,200,200,403'
    : '200,200,200,206,403,200,200,403';
  const variantPattern = new RegExp(
    `^/h/${capabilityInfo.token}/${capabilityInfo.generation}/${streamKey}/stream_[0-4]\\.m3u8$`,
  );
  if ((records.length !== 8 && records.length !== 9)
      || records[0].url.pathname !== '/' || records[0].url.searchParams.get('w') !== 'password'
      || paths[1] !== `/live/${streamKey}` || paths[2] !== capability
      || variant && !variantPattern.test(paths[3]) || !paths[segmentIndex].endsWith('.ts')
      || records[segmentIndex].request.params.request.headers.range !== 'bytes=0-15'
      || paths[forgedIndex] !== `/h/${canary}/${capabilityInfo.generation}/${streamKey}/stream.m3u8`
      || paths[forgedIndex + 1] !== '/api/live/log'
      || records[forgedIndex + 2].url.searchParams.get('w') !== 'logout'
      || paths[forgedIndex + 3] !== capability || statuses.join(',') !== expectedStatuses
      || !records[forgedIndex].body || !records[forgedIndex + 1].body
      || !records[forgedIndex + 3].body) {
    throw new Error('scenario: protocol');
  }
}

export function validateDoneV3(value, raw, ready, browserBindingSha) {
  const done = exact(value, [
    'schema', 'A', 'run_id_sha256', 'challenge_nonce_sha256', 'collector_sha256', 'ready_sha256',
    'handoff_sha256', 'raw_sha256', 'browser_binding_sha256', 'product_sha256', 'version_sha256',
    'user_agent_sha256',
  ], 'done');
  if (done.schema !== DONE_SCHEMA || done.A !== ready.A
      || done.run_id_sha256 !== ready.run_id_sha256
      || done.challenge_nonce_sha256 !== ready.challenge_nonce_sha256
      || done.collector_sha256 !== raw.collector_sha256
      || done.ready_sha256 !== raw.ready_sha256 || done.handoff_sha256 !== raw.handoff_sha256
      || done.browser_binding_sha256 !== browserBindingSha) {
    throw new Error('done: binding');
  }
  for (const key of ['raw_sha256', 'product_sha256', 'version_sha256', 'user_agent_sha256']) {
    hexadecimal(done[key], H64, `done.${key}`);
  }
  return done;
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function safeRead(path, label) {
  const lstatResult = await lstat(path);
  if (!lstatResult.isFile() || lstatResult.isSymbolicLink()) throw new Error(`${label}: unsafe`);
  const descriptor = await open(path, 'r');
  try {
    const initial = await descriptor.stat();
    if (!sameFile(lstatResult, initial)) throw new Error(`${label}: raced`);
    const data = await descriptor.readFile('utf8');
    const final = await descriptor.stat();
    if (!sameFile(initial, final)) throw new Error(`${label}: changed`);
    return data;
  } finally {
    await descriptor.close();
  }
}

async function safeParent(path, label) {
  const parent = dirname(path);
  const info = await lstat(parent);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`${label}: unsafe parent`);
  const canonical = await realpath(parent);
  const windows = platform() === 'win32';
  const actual = windows ? canonical.toLowerCase() : canonical;
  const expected = windows ? resolve(parent).toLowerCase() : resolve(parent);
  if (actual !== expected) throw new Error(`${label}: redirected parent`);
}

async function privatePath(path, handoffPath, label) {
  const full = resolve(path);
  const root = resolve(dirname(handoffPath));
  if (dirname(full) !== root || !full.startsWith(root + sep)) {
    throw new Error(`${label}: not handoff-private`);
  }
  await safeParent(full, label);
  return full;
}

export async function atomicCreateJson(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify(value), { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await link(temporary, path);
    await unlink(temporary);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function drainPending(drains, timeoutMs, abort) {
  if (!(drains instanceof Set) || !Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('drain: bounds');
  }
  let timer;
  const expired = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try {
        abort?.();
      } finally {
        reject(new Error('browser collector drain timeout'));
      }
    }, timeoutMs);
  });
  const wait = (async () => {
    while (drains.size) await Promise.all([...drains]);
  })();
  try {
    return await Promise.race([wait, expired]);
  } finally {
    clearTimeout(timer);
  }
}

function escapeScriptJson(value) {
  return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (character) => (
    `\\u${character.codePointAt(0).toString(16).padStart(4, '0')}`
  ));
}

function controlHtml(config) {
  return `<!doctype html><meta name="referrer" content="no-referrer">`
    + `<link rel="icon" href="data:,"><script>const config=${escapeScriptJson(config)};
const hard = response => response.headers.get('cache-control')?.toLowerCase()
  .split(',').map(item => item.trim()).includes('no-store')
  && response.headers.get('referrer-policy')?.toLowerCase() === 'no-referrer';
const call = (url, options = {}) => fetch(url, {
  ...options, credentials:'same-origin', cache:'no-store', referrerPolicy:'no-referrer',
});
async function must(url, status, options) {
  const response = await call(url, options);
  if (response.status !== status || !hard(response)) throw Error('status');
  return response;
}
async function main() {
  const login = await must('/?w=password&p=' + encodeURIComponent(config.password), 200);
  const csrf = login.headers.get('x-csrf-token');
  if (!csrf) throw Error('csrf');
  const headers = {'x-csrf-token':csrf};
  const player = await must('/live/' + config.stream_key, 200);
  const html = await player.text();
  const capability = new RegExp('/h/([0-9a-f]{64})/([1-9][0-9]*)/('
    + config.stream_key + ')/stream\\.m3u8').exec(html);
  if (!capability || capability[1] === config.canary) throw Error('capability');
  const cap = capability[0];
  let playlistPath = cap;
  let playlist = await must(playlistPath, 200);
  let contents = await playlist.text();
  const leaf = contents.split(/\\r?\\n/).find(item => /^stream_[0-4]\\.m3u8$/.test(item));
  if (leaf) {
    const variant = new URL(leaf, location.origin + playlistPath).pathname;
    const root = '/h/' + capability[1] + '/' + capability[2] + '/' + config.stream_key + '/';
    if (!variant.startsWith(root)) throw Error('variant');
    playlistPath = variant;
    playlist = await must(playlistPath, 200);
    contents = await playlist.text();
  }
  const segment = contents.split(/\\r?\\n/).find(item => /^[A-Za-z0-9_.-]+\\.ts$/.test(item));
  if (!segment) throw Error('segment');
  const asset = new URL(segment, location.origin + playlistPath).pathname;
  const root = '/h/' + capability[1] + '/' + capability[2] + '/' + config.stream_key + '/';
  if (!asset.startsWith(root)) throw Error('asset');
  await must(asset, 206, {headers:{Range:'bytes=0-15'}});
  const forged = '/h/' + config.canary + '/' + capability[2] + '/'
    + config.stream_key + '/stream.m3u8';
  await must(forged, 403);
  const log = await must('/api/live/log?n=500', 200, {headers});
  if ((await log.text()).includes(config.canary)) throw Error('canary log');
  await must('/?w=logout', 200, {headers});
  await must(cap, 403);
  await call('/__w12/complete', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body:JSON.stringify({
      product:navigator.product,
      version:navigator.appVersion,
      user_agent:navigator.userAgent,
    }),
  });
}
main().catch(() => fetch('/__w12/fail', {
  method:'POST', credentials:'same-origin', cache:'no-store', referrerPolicy:'no-referrer',
}));</script>`;
}

function headersObject(headers) {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [
    key,
    Array.isArray(value) ? value.join(', ') : String(value ?? ''),
  ]));
}

export async function collectW12BrowserEvidence({ browser, readyPath, timeoutMs = 120000 }) {
  if (!browser || typeof browser.browserId !== 'string' || !browser.tabs
      || typeof browser.tabs.new !== 'function') {
    throw new Error('browser: documented binding required');
  }
  const tab = await browser.tabs.new();
  let server;
  let timer;
  const sockets = new Set();
  const upstreamRequests = new Set();
  try {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 180000) {
      throw new Error('timeoutMs: bounds');
    }
    const collectorText = await safeRead(new URL(import.meta.url), 'collector');
    const collectorSha = sha256(collectorText);
    const readyText = await safeRead(readyPath, 'ready');
    const ready = validateReadyV3(parseStrictJson(readyText, 'ready'));
    if (ready.collector_sha256 !== collectorSha) throw new Error('ready: collector hash');
    const readySha = sha256(readyText);

    const handoffPath = resolve(dirname(readyPath), 'browser-handoff.json');
    const handoffText = await safeRead(handoffPath, 'handoff');
    if (sha256(handoffText) !== ready.handoff_sha256) throw new Error('handoff: hash');
    const handoff = validateHandoffV3(parseStrictJson(handoffText, 'handoff'));
    assertReadyHandoffBinding(ready, handoff);
    const rawPath = await privatePath(handoff.raw_path, handoffPath, 'raw_path');
    const donePath = await privatePath(handoff.done_path, handoffPath, 'done_path');
    const claimPath = await privatePath(
      resolve(dirname(handoffPath), 'browser-collector.claim.json'), handoffPath, 'claim_path',
    );
    await atomicCreateJson(claimPath, {
      schema: CLAIM_SCHEMA,
      A: ready.A,
      ready_sha256: readySha,
      handoff_sha256: ready.handoff_sha256,
      collector_sha256: collectorSha,
    });

    const events = [];
    const drains = new Set();
    let serial = 0;
    let finishedResolve;
    let finishedReject;
    let browserMeta;
    const finished = new Promise((resolveFinished, rejectFinished) => {
      finishedResolve = resolveFinished;
      finishedReject = rejectFinished;
    });
    const upstream = assertLoopbackUrl(handoff.base_url);
    const authority = `127.0.0.1:${upstream.port}`;

    server = createServer((request, response) => {
      const local = new URL(request.url, 'http://127.0.0.1');
      if (local.pathname === '/__w12/control') {
        response.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'referrer-policy': 'no-referrer',
        });
        response.end(controlHtml({
          password: handoff.login_password,
          stream_key: handoff.stream_key,
          canary: handoff.canary,
        }));
        return;
      }
      if (local.pathname === '/favicon.ico') {
        response.writeHead(204, { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
        response.end();
        return;
      }
      if (local.pathname === '/__w12/complete' || local.pathname === '/__w12/fail') {
        const chunks = [];
        let size = 0;
        request.on('data', (chunk) => {
          size += chunk.length;
          if (size <= 4096) chunks.push(chunk);
        });
        request.on('end', () => {
          try {
            if (local.pathname.endsWith('fail') || size > 4096 || request.method !== 'POST') {
              throw new Error('control failed');
            }
            const message = exact(parseStrictJson(Buffer.concat(chunks).toString('utf8'), 'control'), [
              'product', 'version', 'user_agent',
            ], 'control');
            browserMeta = {
              product: boundedText(message.product, 'navigator.product', 128),
              version: boundedText(message.version, 'navigator.version', 512),
              user_agent: boundedText(message.user_agent, 'navigator.user_agent', 1024),
            };
            response.writeHead(204, { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' });
            response.end();
            finishedResolve();
          } catch (error) {
            response.writeHead(400);
            response.end();
            finishedReject(error);
          }
        });
        return;
      }
      if (!['GET', 'POST'].includes(request.method)) {
        response.writeHead(405);
        response.end();
        return;
      }

      const requestId = String(++serial);
      const proxyUrl = `http://127.0.0.1:${server.address().port}${local.pathname}${local.search}`;
      events.push(rawEvent('Network.requestWillBeSent', {
        requestId,
        request: { url: proxyUrl, method: request.method, headers: headersObject(request.headers) },
      }));

      let settleDrain;
      const drained = new Promise((resolveDrained, rejectDrained) => {
        settleDrain = { ok: resolveDrained, no: rejectDrained };
      });
      drains.add(drained);
      drained.finally(() => drains.delete(drained)).catch(() => {});
      const forwarded = { ...request.headers, host: authority };
      const upstreamRequest = httpRequest({
        hostname: '127.0.0.1',
        port: upstream.port,
        path: local.pathname + local.search,
        method: request.method,
        headers: forwarded,
      }, (upstreamResponse) => {
        const chunks = [];
        let size = 0;
        upstreamResponse.on('data', (chunk) => {
          size += chunk.length;
          if (size <= MAX_FORWARD) chunks.push(chunk);
        });
        upstreamResponse.on('end', () => {
          const status = upstreamResponse.statusCode ?? 502;
          events.push(rawEvent('Network.responseReceived', {
            requestId,
            response: { status, headers: headersObject(upstreamResponse.headers) },
          }));
          const deniedHls = /^\/h\//.test(local.pathname) && status === 403;
          const log = local.pathname === '/api/live/log';
          if ((deniedHls || log) && size <= MAX_BODY) {
            events.push(rawEvent('Network.getResponseBody', {
              requestId,
              body: Buffer.concat(chunks).toString('utf8'),
              base64Encoded: false,
            }));
          }
          settleDrain.ok();
        });
        upstreamResponse.on('error', settleDrain.no);
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      });
      upstreamRequests.add(upstreamRequest);
      upstreamRequest.once('close', () => upstreamRequests.delete(upstreamRequest));
      upstreamRequest.on('error', (error) => {
        if (!response.headersSent) response.writeHead(502);
        response.end();
        settleDrain.no(error);
      });
      request.on('error', settleDrain.no);
      request.pipe(upstreamRequest);
    });

    server.on('connection', (socket) => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
    });
    await new Promise((resolveListening, rejectListening) => {
      server.once('error', rejectListening);
      server.listen(0, '127.0.0.1', resolveListening);
    });
    const control = `http://127.0.0.1:${server.address().port}/__w12/control`;
    const deadline = Date.now() + timeoutMs;
    timer = setTimeout(() => finishedReject(new Error('browser collector timeout')), timeoutMs);
    await tab.goto(control);
    await finished;
    await drainPending(drains, Math.max(1, deadline - Date.now()), () => {
      for (const request of upstreamRequests) request.destroy();
      for (const socket of sockets) socket.destroy();
    });
    assertScenario(events, { streamKey: handoff.stream_key, canary: handoff.canary });

    const browserBindingSha = sha256(browser.browserId);
    const raw = {
      schema: RAW_SCHEMA,
      A: ready.A,
      candidate: handoff.candidate,
      binding: handoff.binding,
      collector_sha256: collectorSha,
      ready_sha256: readySha,
      handoff_sha256: ready.handoff_sha256,
      browser_binding_sha256: browserBindingSha,
      proxy_authority: `127.0.0.1:${server.address().port}`,
      browser: { browser_id: browser.browserId, ...browserMeta },
      events,
    };
    await atomicCreateJson(rawPath, raw);
    const rawSha = sha256(await safeRead(rawPath, 'raw'));
    const done = {
      schema: DONE_SCHEMA,
      A: ready.A,
      run_id_sha256: ready.run_id_sha256,
      challenge_nonce_sha256: ready.challenge_nonce_sha256,
      collector_sha256: collectorSha,
      ready_sha256: readySha,
      handoff_sha256: ready.handoff_sha256,
      raw_sha256: rawSha,
      browser_binding_sha256: browserBindingSha,
      product_sha256: sha256(browserMeta.product),
      version_sha256: sha256(browserMeta.version),
      user_agent_sha256: sha256(browserMeta.user_agent),
    };
    await atomicCreateJson(donePath, done);
    return { rawPath, donePath, claimPath, raw_sha256: rawSha };
  } finally {
    if (timer) clearTimeout(timer);
    for (const request of upstreamRequests) request.destroy();
    for (const socket of sockets) socket.destroy();
    if (server) {
      server.closeAllConnections?.();
      await Promise.race([
        new Promise((resolveClose) => server.close(() => resolveClose())),
        new Promise((resolveTimeout) => setTimeout(resolveTimeout, 1000)),
      ]);
    }
    if (tab && typeof tab.close === 'function') await tab.close().catch(() => {});
  }
}
