"use strict";

/**
 * Creates the HTTP request dispatcher without loading the composition root.
 * The order below is a compatibility contract: a matching handler is final
 * and later domains must never observe that request.
 */
function createHttpDomainRouter(dependencies) {
  const {
    port,
    security,
    debugLog,
    debugPage,
    liveApi,
    liveRouteContext,
    apiRoutes,
    pageRoutes,
    staticRoutes,
  } = dependencies;

  if (!Number.isInteger(port) || port <= 0) throw new Error("port is required");
  if (!security || !debugLog || !debugPage || !liveApi || !staticRoutes) {
    throw new Error("router dependencies are incomplete");
  }

  const apiHandlers = apiRoutes || [];
  const pageHandlers = pageRoutes || [];

  return async function routeHttpRequest(req, res) {
    const url = new URL(req.url, "http://localhost:" + port);

    // Security always owns the first decision, including denied responses.
    if (!security.apply(url, req, res)) return;

    if (debugLog.handle(url, req, res)) return;
    if (debugPage.handle(url, req, res)) return;

    // Deliberately '/hls' rather than '/hls/': this also covers hls-local.
    if (isLivePath(url.pathname)) {
      const handled = liveApi.handleRoute(url, req, res, liveRouteContext);
      if (handled) return;
    }

    if (runHandlers(apiHandlers, url, req, res)) return;
    if (runHandlers(pageHandlers, url, req, res)) return;
    if (await staticRoutes.handle(url, req, res)) return;

    res.writeHead(404);
    res.end("Not found");
  };
}

function isLivePath(pathname) {
  return pathname.startsWith("/api/live/") ||
    pathname.startsWith("/live") ||
    pathname.startsWith("/hls") ||
    pathname === "/privacy" ||
    pathname === "/api/eSE/update/check";
}

function runHandlers(handlers, url, req, res) {
  for (const handler of handlers) {
    if (handler.handle(url, req, res)) return true;
  }
  return false;
}

module.exports = { createHttpDomainRouter, isLivePath };
