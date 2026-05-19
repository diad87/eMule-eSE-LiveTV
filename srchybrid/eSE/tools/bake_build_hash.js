// bake_build_hash.js — Pre-build step. Computes a stable hash from the JS
// source tree and writes it to build_hash.txt next to server.js. error_codes.js
// reads that file at runtime to embed an identifier in user-facing
// diagnostic codes. Without this, dev builds and release builds with the
// same version string would be indistinguishable in bug reports.
//
// Hash inputs: every .js file inside srchybrid/eSE (excluding node_modules,
// _deprecated, dist, _player_bundle.js — that last one is itself generated
// from the same source so including it would be redundant) plus package.json.

'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.resolve(__dirname, '..');
const out  = path.join(root, 'build_hash.txt');

function walk(dir, acc) {
  for (const name of fs.readdirSync(dir)) {
    if (name === 'node_modules' || name === '_deprecated' || name === 'dist'
        || name === 'tools' || name === 'build_hash.txt'
        || name === '_player_bundle.js') continue;
    const p = path.join(dir, name);
    const st = fs.statSync(p);
    if (st.isDirectory()) walk(p, acc);
    else if (/\.(js|json|html)$/.test(name)) acc.push(p);
  }
  return acc;
}

const files = walk(root, []).sort();
const hash = crypto.createHash('sha256');
for (const f of files) {
  hash.update(path.relative(root, f).replace(/\\/g, '/'));
  hash.update('\0');
  hash.update(fs.readFileSync(f));
  hash.update('\0');
}
const digest = hash.digest('hex');
fs.writeFileSync(out, digest);
console.log('  [bake_build_hash] ' + files.length + ' files -> ' + digest.substring(0, 12) + '...');
