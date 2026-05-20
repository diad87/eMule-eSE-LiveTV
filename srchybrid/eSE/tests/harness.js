'use strict';
//
// harness.js — zero-dependency test harness for the eSE ese-server.
//
// v8.0.20: the project ships with "100 % gratis sin dominios" as a hard
// constraint, and the pkg snapshot must stay lean — so no jest / mocha /
// tape. This is ~80 lines that give describe/it/assert and a summary.
//
// Test files require('./harness'), call describe()/it() at module load time
// (synchronous), and run.js then prints the aggregate result and sets the
// process exit code.

const _state = {
  passed: 0,
  failed: 0,
  failures: [],   // { suite, test, error }
  suite: '(root)',
};

function describe(name, fn) {
  const prev = _state.suite;
  _state.suite = name;
  console.log('\n  ' + name);
  try {
    fn();
  } catch (e) {
    // A throw OUTSIDE an it() (e.g. in fixture setup) — record it so the
    // run still fails loudly instead of silently skipping the suite.
    _state.failed++;
    _state.failures.push({ suite: name, test: '(suite setup)', error: e });
    console.log('    ✗ (suite threw) — ' + e.message);
  }
  _state.suite = prev;
}

function it(name, fn) {
  try {
    fn();
    _state.passed++;
    console.log('    ok   ' + name);
  } catch (e) {
    _state.failed++;
    _state.failures.push({ suite: _state.suite, test: name, error: e });
    console.log('    FAIL ' + name + '  — ' + e.message);
  }
}

// Async variant — for tests that await a fake clock / promise chains.
// Returns a promise the caller must await (test files that use itAsync
// export an async runner; see run.js).
async function itAsync(name, fn) {
  try {
    await fn();
    _state.passed++;
    console.log('    ok   ' + name);
  } catch (e) {
    _state.failed++;
    _state.failures.push({ suite: _state.suite, test: name, error: e });
    console.log('    FAIL ' + name + '  — ' + e.message);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(
      (msg || 'assertEqual') +
      ': expected ' + JSON.stringify(expected) +
      ', got ' + JSON.stringify(actual)
    );
  }
}

function assertDeepEqual(actual, expected, msg) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error((msg || 'assertDeepEqual') + ':\n      expected ' + e + '\n      got      ' + a);
  }
}

// assertClose — for floating point / rounding tolerance.
function assertClose(actual, expected, tolerance, msg) {
  tolerance = tolerance || 0;
  if (Math.abs(actual - expected) > tolerance) {
    throw new Error(
      (msg || 'assertClose') +
      ': expected ' + expected + ' ±' + tolerance + ', got ' + actual
    );
  }
}

function assertThrows(fn, msg) {
  let threw = false;
  try { fn(); } catch (e) { threw = true; }
  if (!threw) throw new Error((msg || 'assertThrows') + ': expected function to throw');
}

// Print summary + return exit code (0 = all pass).
function summary() {
  const total = _state.passed + _state.failed;
  console.log('\n  ──────────────────────────────────────────');
  console.log('  ' + _state.passed + ' / ' + total + ' passed' +
    (_state.failed ? ('  ·  ' + _state.failed + ' FAILED') : ''));
  if (_state.failed) {
    console.log('\n  Failures:');
    for (const f of _state.failures) {
      console.log('    • [' + f.suite + '] ' + f.test);
      console.log('      ' + (f.error && f.error.stack ? f.error.stack.split('\n').slice(0, 3).join('\n      ') : f.error));
    }
  }
  console.log('');
  return _state.failed === 0 ? 0 : 1;
}

module.exports = {
  describe, it, itAsync,
  assert, assertEqual, assertDeepEqual, assertClose, assertThrows,
  summary,
};
