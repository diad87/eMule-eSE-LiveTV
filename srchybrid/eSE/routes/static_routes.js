"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Handles the two intentionally public application icons.  Keeping this
 * separate from the composition root makes the final routing fallback
 * explicit and allows it to be exercised through a real HTTP server.
 */
function createStaticRoutes({ rootDir, fileSystem = fs, pathModule = path }) {
  if (!rootDir) throw new Error("rootDir is required");

  return {
    async handle(url, _req, res) {
      if (url.pathname !== "/emule_mascot.svg" && url.pathname !== "/favicon.ico") {
        return false;
      }

      const svgPath = pathModule.join(rootDir, "emule_mascot.svg");
      try {
        await fileSystem.promises.access(svgPath);
        res.writeHead(200, {
          "Content-Type": "image/svg+xml",
          "Cache-Control": "public, max-age=86400",
        });
        fileSystem.createReadStream(svgPath).pipe(res);
        return true;
      } catch (_) {
        return false;
      }
    },
  };
}

module.exports = { createStaticRoutes };
