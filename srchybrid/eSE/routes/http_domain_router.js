"use strict";

const { validateRouteContext } = require("./route_context");

/**
 * @typedef {Object} HttpDomainRouterContext
 * @property {number} port
 * @property {{apply: Function}} security
 * @property {{handle: Function}} debugLog
 * @property {{handle: Function}} debugPage
 * @property {{handleRoute: Function}} liveApi
 * @property {object} liveRouteContext
 * @property {Array<{handle: Function}>} apiRoutes
 * @property {Array<{handle: Function}>} pageRoutes
 * @property {{handle: Function}} staticRoutes
 * @property {{render: Function}} [notFoundPage] Optional HTML 404 for non-API paths.
 */

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
    notFoundPage,
  } = validateRouteContext(dependencies, "HTTP dispatcher", {
    port: "port", security: "securityApply", debugLog: "handler", debugPage: "handler",
    liveApi: "liveApi", liveRouteContext: "object", apiRoutes: "handlers",
    pageRoutes: "handlers", staticRoutes: "handler",
  }, {
    notFoundPage: "object",
  });
  if (notFoundPage && typeof notFoundPage.render !== "function") {
    throw new Error("invalid HTTP dispatcher route context");
  }

  const apiHandlers = apiRoutes;
  const pageHandlers = pageRoutes;

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

    // API clients keep the plain historical 404; browsers get a navigable page.
    if (notFoundPage && !url.pathname.startsWith("/api/")) {
      res.writeHead(404, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(notFoundPage.render());
      return;
    }
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
