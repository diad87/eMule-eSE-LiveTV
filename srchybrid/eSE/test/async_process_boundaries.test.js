"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PassThrough } = require("node:stream");
const test = require("node:test");

const deviceScanner = require("../eSE-live/device_scanner");
const v1Routes = require("../routes/v1_routes");

const runner = require("../bounded_process_runner");
const originalRunProcess = runner.runProcess;
const originalSpawnManaged = runner.spawnManaged;
let resolveProcess;
let managedSpawnCount = 0;
runner.runProcess = () => new Promise(resolve => { resolveProcess = resolve; });
runner.spawnManaged = () => {
  managedSpawnCount++;
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;
  return child;
};
const streamPart = require("../routes/stream_part");
const streamCompleted = require("../routes/stream_completed");

function responsePromise() {
  let finish;
  const completed = new Promise(resolve => { finish = resolve; });
  const response = {
    status: null,
    headers: null,
    body: null,
    writeHead(status, headers) {
      this.status = status;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
      finish(this);
    },
  };
  return { response, completed };
}

function eventedResponse() {
  const response = new EventEmitter();
  response.destroyed = false;
  response.headersSent = false;
  response.writableEnded = false;
  response.writeHead = function writeHead() { this.headersSent = true; };
  response.end = function end() { this.writableEnded = true; };
  return response;
}

test("DirectShow parsing preserves video and audio device selection", () => {
  const output = [
    "[dshow] DirectShow video devices",
    '[dshow]  "Camera One"',
    '[dshow]     Alternative name "@device_camera"',
    '[dshow]  "Capture Two"',
    "[dshow] DirectShow audio devices",
    '[dshow]  "Stereo Mix"',
  ].join("\n");
  assert.deepEqual(deviceScanner.parseDshowDevices(output, "video"), [
    { name: "Camera One", index: 0 },
    { name: "Capture Two", index: 1 },
  ]);
  assert.deepEqual(deviceScanner.parseDshowDevices(output, "audio"), [
    { name: "Stereo Mix", index: 0 },
  ]);
});

test("v1 status returns immediately and completes after async process state", async () => {
  let resolveRunning;
  v1Routes.init({
    security: { isReady: () => true },
    getSession: () => "session",
    emuleApi: {
      isEmuleRunning: () => new Promise(resolve => { resolveRunning = resolve; }),
    },
  });
  const { response, completed } = responsePromise();
  assert.equal(
    v1Routes.handle(
      new URL("http://localhost/api/v1/status"),
      { method: "GET" },
      response,
    ),
    true,
  );
  assert.equal(response.body, null);
  resolveRunning(true);
  await completed;
  const body = JSON.parse(response.body);
  assert.equal(response.status, 200);
  assert.equal(body.emule.running, true);
  assert.equal(body.emule.loggedIn, true);
});

test("v1 lifecycle fails closed when process state rejects", async () => {
  v1Routes.init({
    emuleApi: {
      isEmuleRunning: () => Promise.reject(new Error("probe failed")),
      getLibraryEpoch: () => 7,
      getRestartedAt: () => 11,
    },
  });
  const { response, completed } = responsePromise();
  assert.equal(
    v1Routes.handle(
      new URL("http://localhost/api/v1/lifecycle"),
      { method: "GET" },
      response,
    ),
    true,
  );
  await completed;
  assert.deepEqual(JSON.parse(response.body), {
    alive: false,
    epoch: 7,
    restartedAt: 11,
  });
});

test("part streaming observes disconnect before async filesystem preparation can spawn", async () => {
  managedSpawnCount = 0;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-mod42-"));
  const incoming = path.join(tempRoot, "Incoming");
  const temp = path.join(tempRoot, "Temp");
  await fs.promises.mkdir(incoming);
  await fs.promises.mkdir(temp);
  await fs.promises.writeFile(path.join(temp, "1.part"), Buffer.alloc(32));
  streamPart.init({
    EMULE_INCOMING: incoming,
    FFMPEG_PATH: "ffmpeg",
  });
  const request = new EventEmitter();
  request.destroyed = false;
  const response = eventedResponse();
  assert.equal(
    streamPart.handle(
      new URL("http://localhost/api/stream/part?file=1.part"),
      request,
      response,
    ),
    true,
  );
  response.emit("close");
  await new Promise(resolve => setTimeout(resolve, 25));
  assert.equal(managedSpawnCount, 0);
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("subtitle streaming observes disconnect before a delayed probe can spawn", async () => {
  managedSpawnCount = 0;
  streamCompleted.init({
    FFMPEG_PATH: "ffmpeg.exe",
    resolveMediaFile: () => ({ filePath: "movie.mkv" }),
  });
  const request = new EventEmitter();
  request.destroyed = false;
  const response = eventedResponse();
  assert.equal(
    streamCompleted.handle(
      new URL("http://localhost/api/stream/subtitle?name=movie.mkv&track=0"),
      request,
      response,
    ),
    true,
  );
  response.emit("close");
  resolveProcess({
    ok: true,
    stdout: JSON.stringify({
      streams: [{ index: 2, codec_name: "subrip" }],
    }),
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(managedSpawnCount, 0);
});

test.after(() => {
  runner.runProcess = originalRunProcess;
  runner.spawnManaged = originalSpawnManaged;
});
