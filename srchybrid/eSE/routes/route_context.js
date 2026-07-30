"use strict";

/**
 * @typedef {Object} RouteHandler
 * @property {(url: URL, req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => boolean} handle
 */

/**
 * @typedef {Object} SharedRouteContext
 * @property {string} EMULE_INCOMING
 * @property {string} FFMPEG_PATH
 * @property {string} TEMP_DIR
 * @property {string} CACHE_DIR
 * @property {string} __dirname
 * @property {string} HW_ENCODER
 * @property {string[]} HW_ENCODER_OPTS
 * @property {Record<string, object>} activeStreams
 * @property {() => object} loadSettings
 * @property {(settings: object) => void} saveSettings
 * @property {(options?: object) => Promise<object[]>} getDownloads
 * @property {(options?: object) => Promise<object[]>} getCompletedFiles
 * @property {(fileName: string, options?: object) => Promise<object|null>} resolveMediaFile
 * @property {(filePath: string) => Promise<number>} getDuration
 */

/**
 * Checks a route's dependencies without mutating or retaining the caller's
 * object.  Dependencies must be own properties so inherited test doubles and
 * accidental prototype wiring never leak into the production composition.
 *
 * @param {unknown} context
 * @param {string} routeName
 * @param {Record<string, "function"|"object"|"string"|"array"|"port"|"handler"|"handlers"|"liveApi"|"security"|"securityApply"|"emuleApi"|"cleanup"|"fileSystem"|"pathModule">} schema
 * @returns {Record<string, unknown>}
 */
function validateRouteContext(context, routeName, schema) {
  if (!isObject(context) || Array.isArray(context)) fail(routeName);
  const validated = {};
  for (const [key, expected] of Object.entries(schema)) {
    if (!Object.prototype.hasOwnProperty.call(context, key) || !matches(context[key], expected)) {
      fail(routeName);
    }
    validated[key] = context[key];
  }
  return validated;
}

function isObject(value) {
  return typeof value === "object" && value !== null;
}

function hasFunction(value, name) {
  return isObject(value) && Object.prototype.hasOwnProperty.call(value, name) && typeof value[name] === "function";
}

function matches(value, expected) {
  switch (expected) {
    case "function": return typeof value === "function";
    case "object": return isObject(value) && !Array.isArray(value);
    case "string": return typeof value === "string" && value.length > 0;
    case "array": return Array.isArray(value);
    case "port": return Number.isInteger(value) && value > 0 && value <= 65535;
    case "handler": return hasFunction(value, "handle");
    case "handlers": return Array.isArray(value) && value.every(item => hasFunction(item, "handle"));
    case "liveApi": return hasFunction(value, "handleRoute");
    case "security": return hasFunction(value, "isReady") && hasFunction(value, "redactSettings") && hasFunction(value, "mergeSettings");
    case "securityApply": return hasFunction(value, "apply");
    case "emuleApi": return hasFunction(value, "isEmuleRunning");
    case "cleanup": return hasFunction(value, "cleanupAll");
    case "fileSystem": return hasFunction(value, "createReadStream") && isObject(value.promises) && typeof value.promises.access === "function";
    case "pathModule": return hasFunction(value, "join");
    default: return false;
  }
}

function fail(routeName) {
  throw new Error("invalid " + routeName + " route context");
}

module.exports = { validateRouteContext };
