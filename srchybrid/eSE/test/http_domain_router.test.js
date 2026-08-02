"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createHttpDomainRouter, isLivePath } = require("../routes/http_domain_router");
const { createStaticRoutes } = require("../routes/static_routes");

function marker(name, seen, { matches = () => true } = {}) {
  return {
    handle(url, _req, res) {
      seen.push(name);
      if (!matches(url)) return false;
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(name);
      return true;
    },
  };
}

async function withServer(router, body) {
  const server = http.createServer(router);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const { port } = server.address();
    await body(port);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

function request(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: pathname }, res => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", chunk => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.once("error", reject);
  });
}

function makeRouter({ securityAllow = true, seen = [], rootDir }) {
  const security = {
    apply(_url, _req, res) {
      seen.push("security");
      if (securityAllow) return true;
      res.writeHead(403); res.end("denied");
      return false;
    },
  };
  const debugLog = marker("debug-log", seen, { matches: url => url.pathname === "/api/logs" });
  const debugPage = marker("debug-page", seen, { matches: url => url.pathname === "/debug" });
  const liveApi = {
    handleRoute(url, _req, res) {
      seen.push("live");
      if (!url.searchParams.has("handled")) return false;
      res.writeHead(200); res.end("live");
      return true;
    },
  };
  return createHttpDomainRouter({
    port: 8080,
    security,
    debugLog,
    debugPage,
    liveApi,
    liveRouteContext: {},
    apiRoutes: [marker("api-first", seen, { matches: url => url.pathname === "/api/winner" }), marker("api-late", seen, { matches: url => url.pathname.startsWith("/api/") })],
    pageRoutes: [marker("page", seen, { matches: url => url.pathname === "/page" })],
    staticRoutes: createStaticRoutes({ rootDir }),
  });
}

test("real HTTP security denial short-circuits every later domain", async () => {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "ese-router-"));
  const seen = [];
  try {
    await withServer(makeRouter({ securityAllow: false, seen, rootDir }), async port => {
      const response = await request(port, "/api/winner");
      assert.equal(response.status, 403);
      assert.equal(response.body, "denied");
    });
    assert.deepEqual(seen, ["security"]);
  } finally { fs.rmSync(rootDir, { recursive: true, force: true }); }
});

test("real HTTP keeps debug, live, API and page precedence with no fallthrough", async () => {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "ese-router-"));
  try {
    for (const [pathname, expected, finalSeen] of [
      ["/debug", "debug-page", ["security", "debug-log", "debug-page"]],
      ["/api/live/source?handled=1", "live", ["security", "debug-log", "debug-page", "live"]],
      ["/api/winner", "api-first", ["security", "debug-log", "debug-page", "api-first"]],
      ["/page", "page", ["security", "debug-log", "debug-page", "api-first", "api-late", "page"]],
    ]) {
      const seen = [];
      await withServer(makeRouter({ seen, rootDir }), async port => {
        const response = await request(port, pathname);
        assert.equal(response.status, 200);
        assert.equal(response.body, expected);
      });
      assert.deepEqual(seen, finalSeen, pathname);
    }
  } finally { fs.rmSync(rootDir, { recursive: true, force: true }); }
});

test("live prefixes, static fallback and 404 are real HTTP responses", async () => {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "ese-router-"));
  fs.writeFileSync(path.join(rootDir, "emule_mascot.svg"), "<svg>ok</svg>");
  try {
    for (const pathname of ["/api/live/x?handled=1", "/live-any?handled=1", "/hls-local/a?handled=1", "/privacy?handled=1", "/api/eSE/update/check?handled=1"]) {
      const seen = [];
      await withServer(makeRouter({ seen, rootDir }), async port => {
        const response = await request(port, pathname);
        assert.equal(response.status, 200);
        assert.equal(response.body, "live");
      });
      assert.ok(seen.includes("live"), pathname);
    }
    await withServer(makeRouter({ rootDir }), async port => {
      const staticResponse = await request(port, "/favicon.ico");
      assert.equal(staticResponse.status, 200);
      assert.equal(staticResponse.headers["content-type"], "image/svg+xml");
      assert.equal(staticResponse.body, "<svg>ok</svg>");
      const missing = await request(port, "/not-found");
      assert.equal(missing.status, 404);
      assert.equal(missing.body, "Not found");
    });
  } finally { fs.rmSync(rootDir, { recursive: true, force: true }); }
});

test("live path predicate preserves the exact frozen prefixes", () => {
  for (const pathname of ["/api/live/", "/live", "/hls-local/x", "/privacy", "/api/eSE/update/check"]) assert.equal(isLivePath(pathname), true);
  for (const pathname of ["/api/live", "/api/eSE/update/check/extra", "/hl", "/private"]) assert.equal(isLivePath(pathname), false);
});
