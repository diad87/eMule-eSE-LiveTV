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

for (const f of testFiles) {
  require(path.join(dir, f));
}

process.exit(harness.summary());
