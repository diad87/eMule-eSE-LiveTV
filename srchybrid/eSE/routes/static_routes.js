"use strict";

const fs = require("fs");
const path = require("path");
const { validateRouteContext } = require("./route_context");

/**
 * Handles the two intentionally public application icons.  Keeping this
 * separate from the composition root makes the final routing fallback
 * explicit and allows it to be exercised through a real HTTP server.
 */
/**
 * @param {{rootDir: string, fileSystem?: typeof fs, pathModule?: typeof path}} dependencies
 */
function createStaticRoutes(dependencies) {
  const candidate = dependencies && typeof dependencies === "object"
    ? {
      rootDir: Object.prototype.hasOwnProperty.call(dependencies, "rootDir") ? dependencies.rootDir : undefined,
      fileSystem: Object.prototype.hasOwnProperty.call(dependencies, "fileSystem") ? dependencies.fileSystem : fs,
      pathModule: Object.prototype.hasOwnProperty.call(dependencies, "pathModule") ? dependencies.pathModule : path,
    }
    : dependencies;
  const { rootDir, fileSystem, pathModule } = validateRouteContext(candidate, "static", {
    rootDir: "string", fileSystem: "fileSystem", pathModule: "pathModule",
  });

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
