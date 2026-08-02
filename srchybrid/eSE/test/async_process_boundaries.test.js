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
const originalKillProcessTree = runner.killProcessTree;
let managedSpawnCount = 0;
const processResolvers = [];
const processCalls = [];
const killResolvers = [];
const managedChildren = [];
runner.runProcess = (command, args, options) => new Promise(resolve => {
  processResolvers.push(resolve);
  processCalls.push({ command, args, options, resolve });
});
runner.spawnManaged = () => {
  managedSpawnCount++;
  const child = new EventEmitter();
  child.pid = 10000 + managedSpawnCount;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killCount = 0;
  child.kill = () => {
    child.killCount++;
    queueMicrotask(() => child.emit("close", 0));
    return true;
  };
  managedChildren.push(child);
  return child;
};
runner.killProcessTree = () => new Promise(resolve => { killResolvers.push(resolve); });
const streamPart = require("../routes/stream_part");
const streamCompleted = require("../routes/stream_completed");
const systemRoutes = require("../routes/system_routes");
const mediaResolver = require("../media_resolver");
const ffmpegPipeline = require("../eSE-live/ffmpeg_pipeline");
const rtmpServer = require("../eSE-live/rtmp_server");

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
  response.status = null;
  response.body = null;
  response.writeHead = function writeHead(status) {
    this.status = status;
    this.headersSent = true;
  };
  response.end = function end(body) {
    this.body = body;
    this.writableEnded = true;
  };
  response.write = function write() { return true; };
  return response;
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition not reached");
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

function securityContext(overrides = {}) {
  return {
    isReady: () => false,
    redactSettings: settings => settings,
    mergeSettings: (target, source) => Object.assign(target, source),
    ...overrides,
  };
}

function handlerContext() { return { handle: () => false }; }

function v1Context(overrides = {}) {
  const { security, emuleApi, ...rest } = overrides;
  return {
    security: securityContext(security),
    emuleApi: { isEmuleRunning: () => false, ...(emuleApi || {}) },
    getSession: () => null,
    emuleRoutes: handlerContext(), streamCompleted: handlerContext(), streamPart: handlerContext(), systemRoutes: handlerContext(),
    liveApi: { handleRoute: () => false }, liveRouteCtx: {},
    ...rest,
  };
}

function partContext(overrides = {}) {
  return {
    EMULE_INCOMING: path.join(os.tmpdir(), "Incoming"), FFMPEG_PATH: "ffmpeg", TEMP_DIR: os.tmpdir(),
    __dirname: path.join(os.tmpdir(), "ese-test"), HW_ENCODER: "libx264", HW_ENCODER_OPTS: [],
    activeStreams: {}, getDownloads: async () => [], ...overrides,
  };
}

function completedContext(overrides = {}) {
  return {
    FFMPEG_PATH: "ffmpeg", HW_ENCODER: "libx264", HW_ENCODER_OPTS: [], activeStreams: {},
    getCompletedFiles: async () => [], resolveMediaFile: async () => null, getDuration: async () => 0,
    getSession: () => null, emuleRequest: () => {}, ...overrides,
  };
}

function systemContext(overrides = {}) {
  return {
    PORT: 8080, cleanup: { cleanupAll: async () => {} }, loadSettings: () => ({}), saveSettings: () => {}, ...overrides,
  };
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
  v1Routes.init(v1Context({
    security: { isReady: () => true },
    getSession: () => "session",
    emuleApi: {
      isEmuleRunning: () => new Promise(resolve => { resolveRunning = resolve; }),
    },
  }));
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
  v1Routes.init(v1Context({
    emuleApi: {
      isEmuleRunning: () => Promise.reject(new Error("probe failed")),
      getLibraryEpoch: () => 7,
      getRestartedAt: () => 11,
    },
  }));
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
  streamPart.init(partContext({
    EMULE_INCOMING: incoming,
    FFMPEG_PATH: "ffmpeg",
  }));
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
  streamCompleted.init(completedContext({
    FFMPEG_PATH: "ffmpeg.exe",
    resolveMediaFile: () => ({ filePath: "movie.mkv" }),
  }));
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
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(managedSpawnCount, 0);
});

test("media resolver performs bounded async scans for completed and part files", async () => {
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-media-"));
  const incoming = path.join(tempRoot, "Incoming");
  const temp = path.join(tempRoot, "Temp");
  await fs.promises.mkdir(incoming);
  await fs.promises.mkdir(temp);
  await fs.promises.writeFile(path.join(incoming, "Completed.MKV"), Buffer.alloc(64));

  const met = Buffer.alloc(256);
  Buffer.from("00112233445566778899aabbccddeeff", "hex").copy(met, 5);
  met.write("Part Movie.mkv", 64, "latin1");
  await Promise.all([
    fs.promises.writeFile(path.join(temp, "1.part"), Buffer.alloc(128)),
    fs.promises.writeFile(path.join(temp, "1.part.met"), met),
  ]);

  const completed = await mediaResolver.resolveMediaFile(
    "completed.mkv",
    incoming,
    temp,
  );
  assert.equal(path.basename(completed.filePath).toLowerCase(), "completed.mkv");
  assert.equal(completed.isPartFile, false);

  const partial = await mediaResolver.resolveMediaFile(
    "Part Movie.mkv",
    incoming,
    temp,
  );
  assert.equal(path.basename(partial.filePath), "1.part");
  assert.equal(partial.isPartFile, true);
  assert.equal(partial.hash, "00112233445566778899AABBCCDDEEFF");

  const downloads = await mediaResolver.listDownloads(temp);
  assert.equal(downloads.length, 1);
  assert.equal(downloads[0].fileName, "Part Movie.mkv");
  const completedFiles = await mediaResolver.getCompletedFiles(incoming);
  assert.equal(completedFiles.length, 1);
  assert.equal(completedFiles[0].fileName, "Completed.MKV");

  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("media resolver rejects an aborted scan before retaining metadata", async () => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    mediaResolver.resolveMediaFile("movie.mkv", "Incoming", "Temp", {
      signal: controller.signal,
    }),
    error => error && error.name === "AbortError",
  );
});

test("completed list aborts its bounded scan when the client disconnects", async () => {
  let observedSignal;
  let finishScan;
  streamCompleted.init(completedContext({
    getCompletedFiles: options => {
      observedSignal = options.signal;
      return new Promise(resolve => { finishScan = resolve; });
    },
  }));
  const request = new EventEmitter();
  request.destroyed = false;
  const response = eventedResponse();
  assert.equal(
    streamCompleted.handle(
      new URL("http://localhost/api/stream/completed/list"),
      request,
      response,
    ),
    true,
  );
  response.emit("close");
  assert.equal(observedSignal.aborted, true);
  finishScan([]);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(response.writableEnded, false);
});

test("completed list does not expose internal filesystem paths", async () => {
  streamCompleted.init(completedContext({
    getCompletedFiles: async () => [{
      fileName: "movie.mkv",
      filePath: "C:\\private\\Incoming\\movie.mkv",
      sizeMB: 10,
      mtime: 123,
    }],
  }));
  const request = new EventEmitter();
  request.destroyed = false;
  const response = eventedResponse();
  streamCompleted.handle(
    new URL("http://localhost/api/stream/completed/list"),
    request,
    response,
  );
  await waitFor(() => response.writableEnded);
  assert.deepEqual(JSON.parse(response.body), [{
    fileName: "movie.mkv",
    sizeMB: 10,
    mtime: 123,
  }]);
});

test("legacy part lookup reads only bounded met metadata", async () => {
  managedSpawnCount = 0;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-met-bound-"));
  const incoming = path.join(tempRoot, "Incoming");
  const temp = path.join(tempRoot, "Temp");
  await fs.promises.mkdir(incoming);
  await fs.promises.mkdir(temp);
  const oversizedMet = Buffer.alloc((2 * 1024 * 1024) + 128);
  oversizedMet.write("Late Movie.mkv", 2 * 1024 * 1024 + 16, "latin1");
  await fs.promises.writeFile(path.join(temp, "9.part.met"), oversizedMet);
  await fs.promises.writeFile(path.join(incoming, "Late Movie.mkv"), Buffer.alloc(32));
  streamPart.init(partContext({
    EMULE_INCOMING: incoming,
    FFMPEG_PATH: "ffmpeg",
  }));
  const request = new EventEmitter();
  request.destroyed = false;
  const response = eventedResponse();
  streamPart.handle(
    new URL("http://localhost/api/stream/part?file=9.part"),
    request,
    response,
  );
  await waitFor(() => response.writableEnded);
  assert.equal(response.status, 404);
  assert.equal(managedSpawnCount, 0);
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("MSE data stream replacement preserves the new request owner", async () => {
  const spawnBase = managedChildren.length;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-mse-owner-"));
  await fs.promises.writeFile(path.join(tempRoot, "ese_mse_1.avi"), Buffer.alloc(32));
  const activeStreams = {};
  streamPart.init(partContext({
    TEMP_DIR: tempRoot,
    FFMPEG_PATH: "ffmpeg",
    HW_ENCODER: "libx264",
    HW_ENCODER_OPTS: ["-preset", "ultrafast"],
    activeStreams,
  }));
  const requestA = new EventEmitter();
  requestA.destroyed = false;
  const responseA = eventedResponse();
  streamPart.handle(
    new URL("http://localhost/api/stream/data/1"),
    requestA,
    responseA,
  );
  await waitFor(() => managedChildren.length === spawnBase + 1);
  const first = managedChildren[spawnBase];

  const requestB = new EventEmitter();
  requestB.destroyed = false;
  const responseB = eventedResponse();
  streamPart.handle(
    new URL("http://localhost/api/stream/data/1"),
    requestB,
    responseB,
  );
  await waitFor(() => managedChildren.length === spawnBase + 2);
  const second = managedChildren[spawnBase + 1];
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(first.killCount, 1);
  assert.equal(activeStreams["1"], second);

  responseA.emit("close");
  assert.equal(activeStreams["1"], second);
  responseB.emit("close");
  assert.equal(second.killCount, 1);
  assert.equal(activeStreams["1"], undefined);
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("MSE promotion serializes a superseded copy behind the newer output", async () => {
  const callBase = processCalls.length;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-copy-owner-"));
  const source = path.join(tempRoot, "1.part");
  const canonical = path.join(tempRoot, "ese_mse_1.avi");
  await fs.promises.writeFile(source, Buffer.alloc(32));
  await fs.promises.writeFile(canonical, "BASE");
  streamPart.init(partContext({
    __dirname: tempRoot,
    TEMP_DIR: tempRoot,
    getDownloads: async () => [{
      partNum: "1",
      partPath: source,
      fileName: "movie.mkv",
      fileSizeMB: 1,
    }],
  }));
  const requestA = new EventEmitter();
  requestA.destroyed = false;
  const responseA = eventedResponse();
  const requestB = new EventEmitter();
  requestB.destroyed = false;
  const responseB = eventedResponse();
  const originalUnlink = fs.promises.unlink;
  let releaseOldPromotion;
  let oldPromotionReached;
  const oldPromotionPaused = new Promise(resolve => { oldPromotionReached = resolve; });
  const oldPromotionRelease = new Promise(resolve => { releaseOldPromotion = resolve; });
  let heldCanonicalUnlink = false;
  fs.promises.unlink = async target => {
    if (target === canonical && !heldCanonicalUnlink) {
      heldCanonicalUnlink = true;
      oldPromotionReached();
      await oldPromotionRelease;
    }
    return originalUnlink.call(fs.promises, target);
  };
  try {
    streamPart.handle(new URL("http://localhost/api/stream/start/1"), requestA, responseA);
    await waitFor(() => processCalls.length === callBase + 1);
    const callA = processCalls[callBase];
    const targetA = callA.args[callA.args.indexOf("-Dest") + 1];
    await fs.promises.writeFile(targetA, "OLDER-A");
    callA.resolve({ ok: true, stdout: "7", stderr: "" });
    await oldPromotionPaused;

    // A already validated ownership and is paused inside canonical promotion.
    // B now becomes owner and completes its copy while A is still paused.
    streamPart.handle(new URL("http://localhost/api/stream/start/1"), requestB, responseB);
    await waitFor(() => processCalls.length === callBase + 2);
    const callB = processCalls[callBase + 1];
    const targetB = callB.args[callB.args.indexOf("-Dest") + 1];
    assert.notEqual(targetA, targetB);
    await fs.promises.writeFile(targetB, "NEWER-B");
    callB.resolve({ ok: true, stdout: "7", stderr: "" });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(responseB.writableEnded, false);

    releaseOldPromotion();
    await waitFor(() => responseA.writableEnded && responseB.writableEnded);
    assert.equal(responseA.status, 409);
    assert.equal(responseB.status, 200);
    assert.equal(await fs.promises.readFile(canonical, "utf8"), "NEWER-B");
    responseB.emit("close");
    assert.equal(await fs.promises.readFile(canonical, "utf8"), "NEWER-B");
  } finally {
    releaseOldPromotion();
    fs.promises.unlink = originalUnlink;
    await fs.promises.rm(tempRoot, { recursive: true, force: true });
  }
});

test("a disconnected preparation cannot kill another request's completed stream", async () => {
  managedSpawnCount = 0;
  managedChildren.length = 0;
  processResolvers.length = 0;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-owner-"));
  const movie = path.join(tempRoot, "movie.mkv");
  const file = await fs.promises.open(movie, "w");
  await file.truncate(6 * 1024 * 1024);
  await file.close();
  const activeStreams = {};
  streamCompleted.init(completedContext({
    FFMPEG_PATH: "ffmpeg.exe",
    HW_ENCODER: "libx264",
    HW_ENCODER_OPTS: ["-preset", "ultrafast"],
    activeStreams,
    resolveMediaFile: async () => ({
      filePath: movie,
      isPartFile: false,
      fileSize: 6 * 1024 * 1024,
    }),
  }));

  const requestA = new EventEmitter();
  requestA.destroyed = false;
  const responseA = eventedResponse();
  streamCompleted.handle(
    new URL("http://localhost/api/stream/completed/movie.mkv"),
    requestA,
    responseA,
  );
  await waitFor(() => processResolvers.length === 2);
  const codecResult = codec => ({ ok: true, stdout: codec, stderr: "" });
  processResolvers.shift()(codecResult("h264\n"));
  processResolvers.shift()(codecResult("aac\n"));
  await waitFor(() => managedSpawnCount === 1);
  const ownedByA = managedChildren[0];

  const requestB = new EventEmitter();
  requestB.destroyed = false;
  const responseB = eventedResponse();
  streamCompleted.handle(
    new URL("http://localhost/api/stream/completed/movie.mkv"),
    requestB,
    responseB,
  );
  responseB.emit("close");
  await new Promise(resolve => setImmediate(resolve));

  assert.equal(ownedByA.killCount, 0);
  assert.equal(activeStreams["completed_movie.mkv"], ownedByA);
  responseA.emit("close");
  assert.equal(ownedByA.killCount, 1);
  await new Promise(resolve => setImmediate(resolve));
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("pipeline stop cannot clear a newly started generation", async () => {
  killResolvers.length = 0;
  const childBase = managedChildren.length;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-pipeline-aba-"));
  const movie = path.join(tempRoot, "movie.mp4");
  const output = path.join(tempRoot, "hls");
  await fs.promises.writeFile(movie, Buffer.alloc(32));
  const options = {
    source: { type: "file", id: movie },
    ffmpegPath: "ffmpeg",
    outputDir: output,
    hwEncoder: "libx264",
    hwEncoderOpts: ["-preset", "ultrafast"],
  };
  assert.equal((await ffmpegPipeline.start(options)).success, true);
  const oldChild = managedChildren[childBase];
  const stopping = ffmpegPipeline.stop();
  await waitFor(() => killResolvers.length === 1);
  oldChild.emit("close", 0);
  const nextSource = { ...options.source, id: movie };
  assert.equal((await ffmpegPipeline.start({ ...options, source: nextSource })).success, true);
  const newChild = managedChildren[childBase + 1];
  killResolvers.shift()({ ok: true });
  await stopping;
  assert.equal(ffmpegPipeline.getStatus().status, "starting");
  assert.equal(ffmpegPipeline.getStatus().source, nextSource);
  newChild.emit("close", 0);
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("RTMP stop cannot clear a newly started generation", async () => {
  killResolvers.length = 0;
  const childBase = managedChildren.length;
  const tempRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "ese-rtmp-aba-"));
  const first = rtmpServer.start({
    ffmpegPath: "ffmpeg",
    outputDir: tempRoot,
    port: 19351,
  });
  assert.equal(first.success, true);
  const oldChild = managedChildren[childBase];
  const stopping = rtmpServer.stop();
  await waitFor(() => killResolvers.length === 1);
  oldChild.emit("close", 0);
  const second = rtmpServer.start({
    ffmpegPath: "ffmpeg",
    outputDir: tempRoot,
    port: 19352,
  });
  assert.equal(second.success, true);
  const newChild = managedChildren[childBase + 1];
  killResolvers.shift()({ ok: true });
  await stopping;
  assert.equal(rtmpServer.getStatus().status, "waiting");
  assert.equal(rtmpServer.getStatus().rtmpStreamKey, second.rtmpStreamKey);
  newChild.emit("close", 0);
  await fs.promises.rm(tempRoot, { recursive: true, force: true });
});

test("cleanup HTTP response waits for asynchronous bounded deletion", async () => {
  let finishCleanup;
  systemRoutes.init(systemContext({
    cleanup: {
      cleanupAll: () => new Promise(resolve => { finishCleanup = resolve; }),
    },
    loadSettings: () => ({}),
    saveSettings: () => {},
  }));
  const { response, completed } = responsePromise();
  assert.equal(
    systemRoutes.handle(
      new URL("http://localhost/api/cleanup"),
      { method: "POST" },
      response,
    ),
    true,
  );
  assert.equal(response.body, null);
  finishCleanup();
  await completed;
  assert.deepEqual(JSON.parse(response.body), { cleaned: true });
});

test.after(() => {
  runner.runProcess = originalRunProcess;
  runner.spawnManaged = originalSpawnManaged;
  runner.killProcessTree = originalKillProcessTree;
});
