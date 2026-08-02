"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const emuleRoutes = require("../routes/emule_routes");
const moviesRoutes = require("../routes/movies_routes");
const streamPart = require("../routes/stream_part");
const streamCompleted = require("../routes/stream_completed");
const systemRoutes = require("../routes/system_routes");
const v1Routes = require("../routes/v1_routes");
const { createHttpDomainRouter } = require("../routes/http_domain_router");
const { createStaticRoutes } = require("../routes/static_routes");

const noop = () => {};
const handler = { handle: () => false };
const security = {
  isReady: () => false,
  redactSettings: value => value,
  mergeSettings: (target, source) => Object.assign(target, source),
};

function fullContext() {
  return {
    PORT: 8080, EMULE_INCOMING: "Incoming", FFMPEG_PATH: "ffmpeg", TEMP_DIR: "Temp", CACHE_DIR: "Cache", __dirname: "Root",
    HW_ENCODER: "libx264", HW_ENCODER_OPTS: [], activeStreams: {}, security,
    cleanup: { cleanupAll: async () => {} }, loadSettings: () => ({}), saveSettings: noop,
    getDownloads: async () => [], getCompletedFiles: async () => [], resolveMediaFile: async () => ({}), getDuration: async () => 0,
    emuleLogin: noop, emuleSearch: noop, emuleDownload: noop, emuleTransferAction: noop, emuleAddEd2kLink: noop,
    emuleRequest: noop, getSession: () => null, fetchAndCacheMovie: noop, proxyOMDB: noop,
    emuleApi: { isEmuleRunning: () => false }, emuleRoutes: handler, streamCompleted: handler,
    streamPart: handler, systemRoutes: handler, liveApi: { handleRoute: () => false }, liveRouteCtx: {},
  };
}

const routeInitializers = [
  ["emule", emuleRoutes.init], ["movies", moviesRoutes.init], ["stream part", streamPart.init],
  ["stream completed", streamCompleted.init], ["system", systemRoutes.init], ["v1", v1Routes.init],
];

function invalidContext(name) {
  return error => error && error.message === "invalid " + name + " route context";
}

test("route initialization rejects null, missing and prototype-inherited dependencies safely", () => {
  for (const [name, init] of routeInitializers) {
    assert.doesNotThrow(() => init(fullContext()));
    assert.throws(() => init(null), invalidContext(name));
    const inherited = Object.create(fullContext());
    assert.throws(() => init(inherited), invalidContext(name));
    assert.throws(() => init({}), invalidContext(name));
  }
});

test("routes retain a validated snapshot rather than the caller context object", () => {
  const context = fullContext();
  context.liveApi = { handleRoute: () => true };
  v1Routes.init(context);
  context.liveApi = null;
  const response = { writeHead: noop, end: noop };
  assert.equal(v1Routes.handle(new URL("http://localhost/api/v1/live/test"), { method: "GET" }, response), true);
});

test("HTTP dispatcher validates every domain dependency before a server is created", () => {
  const valid = {
    port: 8080, security: { apply: () => true }, debugLog: handler, debugPage: handler,
    liveApi: { handleRoute: () => false }, liveRouteContext: {}, apiRoutes: [], pageRoutes: [], staticRoutes: handler,
  };
  assert.equal(typeof createHttpDomainRouter(valid), "function");
  for (const invalid of [null, {}, { ...valid, staticRoutes: Object.create(handler) }]) {
    assert.throws(() => createHttpDomainRouter(invalid), invalidContext("HTTP dispatcher"));
  }
});

test("static route configuration rejects malformed own dependencies without changing its public fallback", () => {
  assert.throws(() => createStaticRoutes(null), invalidContext("static"));
  assert.throws(() => createStaticRoutes(Object.create({ rootDir: "Root" })), invalidContext("static"));
  assert.equal(typeof createStaticRoutes({ rootDir: "Root" }).handle, "function");
});
