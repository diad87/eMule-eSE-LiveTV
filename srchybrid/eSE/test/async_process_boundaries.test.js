"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const deviceScanner = require("../eSE-live/device_scanner");
const v1Routes = require("../routes/v1_routes");

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
