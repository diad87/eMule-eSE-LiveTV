// Runtime-writable directory helper for pkg-bundled vs dev-script mode.
//
// In dev (`node server.js`), modules call path.join(__dirname, 'foo.json')
// which is the live srchybrid/eSE/ directory and is writable.
//
// In pkg-bundled mode (`ese-server.exe`), __dirname resolves to a virtual
// snapshot path (C:\snapshot\eSE\...) which is READ-ONLY — any fs.writeFileSync
// fails with ENOENT. Modules that need to persist state at runtime must
// use this helper instead of __dirname.
//
// The helper returns:
//   - dev mode:  __dirname of the caller (or fallback to dirname of this file)
//   - pkg mode:  %APPDATA%\eSE (created on first call, persists across runs)
//
// Read-only assets (HTML, SVG, .js, fixtures) keep using __dirname so pkg
// can find them inside the snapshot. Only writable state goes through here.
'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');

let cached = null;

function get() {
  if (cached) return cached;
  if (process.pkg) {
    const appData = process.env.APPDATA
      || process.env.LOCALAPPDATA
      || path.join(os.homedir(), 'AppData', 'Roaming');
    cached = path.join(appData, 'eSE');
    try { fs.mkdirSync(cached, { recursive: true }); } catch (_) {}
  } else {
    // Dev mode: srchybrid/eSE/ is writable and contains the source tree.
    cached = path.join(__dirname);
  }
  return cached;
}

// Helper: join the runtime dir with a subpath, ensuring parent dirs exist
// when the caller plans to write inside a subdirectory.
function join() {
  const args = [get()].concat(Array.prototype.slice.call(arguments));
  return path.join.apply(path, args);
}

module.exports = { get, join };
