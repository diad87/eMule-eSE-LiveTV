'use strict';
//
// run.js — test entry point. `npm test` runs this.
//
// Requires the harness first (so describe/it register into its shared state),
// then loads every *.test.js file (each registers + runs its tests at require
// time), then prints the summary and sets the process exit code.
//
// Zero dependencies — no jest/mocha. Keeps the pkg snapshot lean and honours
// the project's "100 % gratis sin dominios / no external deps" constraint.

const fs   = require('fs');
const path = require('path');
const harness = require('./harness');

console.log('\n  eSE ese-server — test suite\n  ===========================');

const dir = __dirname;
const testFiles = fs.readdirSync(dir)
  .filter(f => f.endsWith('.test.js'))
  .sort();

if (testFiles.length === 0) {
  console.log('\n  (no *.test.js files found)\n');
  process.exit(1);
}

// A test file either runs synchronously at require time (met_parser,
// rate_window) OR exports an async runner function (playback_state, which
// needs to await a fake clock). We require all of them, then await any
// async runners before printing the summary.
(async () => {
  const asyncRunners = [];
  for (const f of testFiles) {
    const mod = require(path.join(dir, f));
    if (typeof mod === 'function') asyncRunners.push(mod);
  }
  for (const run of asyncRunners) {
    await run(harness);
  }
  process.exit(harness.summary());
})();
