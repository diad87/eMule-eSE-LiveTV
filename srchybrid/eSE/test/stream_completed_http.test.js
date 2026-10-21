'use strict';

// Real loopback HTTP + real isolated filesystem entries. FFmpeg/ffprobe are
// controlled process adapters: no eMule, user media, network services or codecs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { EventEmitter, once } = require('node:events');
const { PassThrough } = require('node:stream');
const completed = require('../routes/stream_completed');

const fixtureName = 'E2E clip.mp4';
const route = '/api/stream/completed/' + encodeURIComponent(fixtureName);
const defaultProbe = {
  format: { duration: '40.0' },
  streams: [
    { index: 0, codec_type: 'video', codec_name: 'h264' },
    { index: 1, codec_type: 'audio', codec_name: 'aac', tags: { language: 'spa' } },
    { index: 2, codec_type: 'audio', codec_name: 'ac3', tags: { language: 'eng' } }
  ]
};

async function host(t, options = {}) {
  const tempRoot = path.resolve(os.tmpdir());
  const directory = await fs.mkdtemp(path.join(tempRoot, 'ese-stream-http-'));
  const fixturePath = path.join(directory, fixtureName);
  const size = options.size === undefined ? 6 * 1024 * 1024 : options.size;
  await fs.writeFile(fixturePath, Buffer.alloc(size, 0x31));
  const processes = [];
  const requests = [];
  const clients = [];
  const activeStreams = Object.create(null);
  const ctx = {
    FFMPEG_PATH: 'isolated-ffmpeg', EMULE_INCOMING: options.missingDirectory ? path.join(directory, 'missing') : directory,
    HW_ENCODER: 'libx264', HW_ENCODER_OPTS: ['-preset', 'ultrafast'], activeStreams,
    resolveMediaFile(name) { return name === fixtureName ? { filePath: fixturePath, fileSize: size, isPartFile: !!options.partial } : null; },
    getSession: () => null,
    emuleRequest() { throw new Error('Native eMule calls are forbidden in this harness'); },
    async runMediaProbe() {
      if (options.probeGate) await options.probeGate;
      return { stdout: JSON.stringify(options.probe || defaultProbe) };
    },
    spawnMediaProcess(file, args, spawnOptions) {
      const child = new EventEmitter();
      child.stdout = new PassThrough(); child.stderr = new PassThrough();
      child.args = args; child.killCalls = [];
      child.kill = signal => { child.killCalls.push(signal || 'SIGTERM'); return true; };
      processes.push(child);
      // Keep the response open. Tests explicitly schedule close/error to model
      // callbacks from a replaced process arriving after its successor starts.
      setImmediate(() => child.stdout.write(Buffer.from(options.processOutput || 'fixture-media-data')));
      assert.equal(spawnOptions.windowsHide, true);
      return child;
    }
  };
  completed.init(ctx);
  const server = http.createServer((req, res) => {
    requests.push({ req, res });
    if (!completed.handle(new URL(req.url, 'http://127.0.0.1'), req, res)) { res.writeHead(404); res.end(); }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
  });
  t.after(async () => {
    for (const owner of Object.values(activeStreams)) owner.kill();
    for (const client of clients) client.destroy();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    for (const child of processes) { child.stdout.destroy(); child.stderr.destroy(); }
    // Delete only the fresh test-owned directory under the OS temporary root.
    assert.equal(path.dirname(path.resolve(directory)), tempRoot);
    assert.match(path.basename(directory), /^ese-stream-http-/);
    await fs.rm(directory, { recursive: true, force: true });
  });
  function open(method, requestPath) {
    return new Promise((resolve, reject) => {
      const req = http.request({ hostname: '127.0.0.1', port: server.address().port, method, path: requestPath, agent: false });
      clients.push(req);
      req.once('error', reject);
      req.once('response', res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        // Intentional cancellation is part of these tests, not an unhandled error.
        res.on('error', () => {});
        resolve({ req, res, chunks });
      });
      req.end();
    });
  }
  async function read(method, requestPath) {
    const result = await open(method, requestPath);
    if (!result.res.readableEnded) await once(result.res, 'end');
    return { status: result.res.statusCode, headers: result.res.headers, body: Buffer.concat(result.chunks).toString() };
  }
  return { ctx, server, processes, requests, clients, open, read, directory, activeStreams };
}

test('HEAD reports codec and quality metadata without spawning or registering a stream', { timeout: 5000 }, async t => {
  const h = await host(t);
  const head = await h.read('HEAD', route);
  assert.equal(head.status, 200); assert.equal(head.headers['x-ese-transcoding'], 'copy'); assert.equal(head.body, '');
  const scaled = await h.read('HEAD', route + '?quality=720p');
  assert.equal(scaled.headers['x-ese-transcoding'], 'transcode');
  const seek = await h.read('HEAD', route + '?q=auto&ss=19');
  assert.equal(seek.headers['x-ese-transcoding'], 'transcode');
  assert.equal(h.processes.length, 0); assert.deepEqual(Object.keys(h.activeStreams), []);
});

test('HEAD alongside GET and request completion do not kill the active video', { timeout: 5000 }, async t => {
  const h = await host(t);
  const stream = await h.open('GET', route);
  const child = h.processes[0]; const owner = h.activeStreams['completed_' + fixtureName];
  h.requests[0].req.emit('close');
  const head = await h.read('HEAD', route);
  assert.equal(head.status, 200); assert.equal(h.processes.length, 1);
  assert.equal(child.killCalls.length, 0); assert.equal(h.activeStreams['completed_' + fixtureName], owner);
  assert.equal(stream.res.destroyed, false);
});

test('seeking replaces only its own request and stale close/data cannot kill or erase the successor', { timeout: 5000 }, async t => {
  const h = await host(t);
  const old = await h.open('GET', route);
  const first = h.processes[0];
  const next = await h.open('GET', route + '?q=720p&ss=15&audio=2');
  const second = h.processes[1]; const owner = h.activeStreams['completed_' + fixtureName];
  assert.equal(first.killCalls.length, 1);
  assert.equal(second.args[second.args.indexOf('-ss') + 1], '15');
  old.req.destroy();
  h.requests[0].res.emit('close'); first.emit('close', 255); first.stdout.write('stale');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(second.killCalls.length, 0); assert.equal(h.activeStreams['completed_' + fixtureName], owner);
  assert.equal(next.res.destroyed, false);
  const disconnected = once(h.requests[1].res, 'close'); next.req.destroy(); await disconnected;
  assert.equal(second.killCalls.length, 1); assert.equal(h.activeStreams['completed_' + fixtureName], undefined);
});

test('seeking in auto quality transcodes video and audio to remove keyframe preroll', { timeout: 5000 }, async t => {
  const h = await host(t);
  await h.open('GET', route + '?q=auto&ss=19&audio=2');
  const args = h.processes[0].args;
  assert.equal(args[args.indexOf('-ss') + 1], '19');
  assert.ok(args.indexOf('-ss') < args.indexOf('-i'), 'input seek decodes and discards to the requested time');
  assert.equal(args[args.indexOf('-c:v') + 1], 'libx264');
  assert.equal(args[args.indexOf('-c:a') + 1], 'aac');
  assert.deepEqual(args.filter((value, index) => args[index - 1] === '-map'), ['0:v:0', '0:2?']);
});

test('the selected audio codec determines copying vs AAC conversion', { timeout: 5000 }, async t => {
  const h = await host(t);
  await h.open('GET', route + '?audio=1');
  assert.equal(h.processes[0].args[h.processes[0].args.indexOf('-c:a') + 1], 'copy');
  await h.open('GET', route + '?audio=2');
  const args = h.processes[1].args;
  assert.equal(args[args.indexOf('-c:a') + 1], 'aac'); assert.ok(args.includes('0:2?'));
});

test('a valid complete clip below 5 MiB can stream', { timeout: 5000 }, async t => {
  const h = await host(t, { size: 1024 });
  const response = await h.open('GET', route);
  assert.equal(response.res.statusCode, 200); assert.equal(h.processes.length, 1);
});

test('an undersized partial download and an invalid complete clip fail before spawn', { timeout: 5000 }, async t => {
  const h = await host(t, { size: 1024, partial: true });
  const response = await h.read('GET', route);
  assert.equal(response.status, 400); assert.equal(h.processes.length, 0);
  h.ctx.resolveMediaFile = name => name === fixtureName ? { filePath: path.join(h.directory, fixtureName), isPartFile: false } : null;
  h.ctx.runMediaProbe = async () => ({ stdout: JSON.stringify({ streams: [] }) });
  completed.init(h.ctx); // Clear only this test's probe cache after changing the adapter.
  const invalid = await h.read('GET', route);
  assert.equal(invalid.status, 415); assert.equal(h.processes.length, 0);
});

test('an unavailable library is reported as 503 rather than an empty collection', { timeout: 5000 }, async t => {
  const h = await host(t, { missingDirectory: true });
  const response = await h.read('GET', '/api/stream/completed/list');
  assert.equal(response.status, 503); assert.equal(JSON.parse(response.body).error, 'library_unavailable');
});

test('metadata endpoints report the fixture duration and both audio tracks', { timeout: 5000 }, async t => {
  const h = await host(t);
  const info = await h.read('GET', '/api/stream/completed/info?name=' + encodeURIComponent(fixtureName));
  assert.equal(JSON.parse(info.body).estimatedTotalSec, 40); assert.equal(JSON.parse(info.body).durationKnown, true);
  const tracks = await h.read('GET', '/api/stream/tracks?name=' + encodeURIComponent(fixtureName));
  assert.deepEqual(JSON.parse(tracks.body).audio.map(track => track.index), [1, 2]);
  assert.equal(h.processes.length, 0);
});

test('subtitle extraction uses the video seek offset and rejects invalid track indices before spawn', { timeout: 5000 }, async t => {
  const probe = { ...defaultProbe, streams: [...defaultProbe.streams, { index: 3, codec_type: 'subtitle', codec_name: 'mov_text' }] };
  const h = await host(t, { probe, processOutput: 'WEBVTT\n\n00:00.000 --> 00:05.000\nExpired cue\n\n00:10.000 --> 00:15.000\nCurrent cue\n\n' });
  const invalid = await h.read('GET', '/api/stream/subtitle?name=' + encodeURIComponent(fixtureName) + '&track=-1');
  assert.equal(invalid.status, 404); assert.equal(h.processes.length, 0);
  const subtitles = await h.open('GET', '/api/stream/subtitle?name=' + encodeURIComponent(fixtureName) + '&track=0&ss=12');
  assert.equal(subtitles.res.statusCode, 200);
  const args = h.processes[0].args;
  assert.equal(args.includes('-ss'), false, 'decode the entire text track so an overlapping cue is not dropped');
  assert.equal(args[args.indexOf('-map') + 1], '0:3'); assert.equal(args[args.indexOf('-f') + 1], 'webvtt');
  if (!subtitles.chunks.length) await once(subtitles.res, 'data');
  const body = Buffer.concat(subtitles.chunks).toString();
  assert.doesNotMatch(body, /Expired cue/);
  assert.match(body, /00:00:00\.000 --> 00:00:03\.000\nCurrent cue/);
  const closed = once(h.requests[1].res, 'close'); subtitles.req.destroy(); await closed;
  assert.equal(h.processes[0].killCalls.length, 1);
});

test('the completed-route wrapper leaves part-stream and unknown endpoints to subsequent handlers', () => {
  for (const pathname of ['/api/stream/start/001', '/api/stream/data/001', '/api/stream/kill/001', '/api/stream/unknown']) {
    assert.equal(completed.handle(new URL(pathname, 'http://127.0.0.1'), {}, {}), false, pathname);
  }
});
