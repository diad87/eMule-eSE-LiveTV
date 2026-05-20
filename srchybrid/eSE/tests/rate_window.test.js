'use strict';
//
// rate_window.test.js — unit tests for rate_window.pushSample / computeRate.
//
// The rate window is the input to the sustained-rate playback gate (v8.0.15).
// A bug here means the system starts/stalls playback on a wrong rate number.

const { describe, it, assert, assertEqual } = require('./harness');
const rw = require('../rate_window');

const KEY = '0042.part';

describe('rate_window — insufficient data', () => {
  it('no samples → ready:false, insufficient_samples', () => {
    rw._reset();
    const r = rw.computeRate(KEY, 60, 100000);
    assertEqual(r.ready, false);
    assertEqual(r.reason, 'insufficient_samples');
    assertEqual(r.bytesPerSec, 0);
  });

  it('one sample → still ready:false', () => {
    rw._reset();
    rw.pushSample(KEY, 1000, 100000);
    const r = rw.computeRate(KEY, 60, 100000);
    assertEqual(r.ready, false);
    assertEqual(r.samples, 1);
  });
});

describe('rate_window — slope computation', () => {
  it('two samples 10 s apart, +5 MB → 500 KB/s', () => {
    rw._reset();
    const MB = 1024 * 1024;
    rw.pushSample(KEY, 0,        100000);
    rw.pushSample(KEY, 5 * MB,   110000);   // +5 MB in 10 s
    const r = rw.computeRate(KEY, 60, 110000);
    assertEqual(r.ready, true);
    assertEqual(r.bytesPerSec, Math.round(5 * MB / 10));   // 524288
    assertEqual(r.kbPerSec, 512);
  });

  it('many samples, steady 1 MB/s', () => {
    rw._reset();
    const MB = 1024 * 1024;
    for (let i = 0; i <= 30; i++) {
      rw.pushSample(KEY, i * MB, 100000 + i * 1000);   // 1 MB per second
    }
    const r = rw.computeRate(KEY, 60, 100000 + 30 * 1000);
    assertEqual(r.ready, true);
    // 30 MB over 30 s = 1 MB/s
    assertEqual(r.bytesPerSec, MB);
  });

  it('negative slope (bytes shrank) → clamped to 0', () => {
    rw._reset();
    rw.pushSample(KEY, 5000000, 100000);
    rw.pushSample(KEY, 3000000, 105000);   // shrank — should never happen, but
    const r = rw.computeRate(KEY, 60, 105000);
    assertEqual(r.ready, true);
    assertEqual(r.bytesPerSec, 0, 'negative rate clamped to 0');
  });
});

describe('rate_window — window filtering', () => {
  it('samples older than windowSec are excluded', () => {
    rw._reset();
    const MB = 1024 * 1024;
    // old sample at t=0, recent samples at t=100s and t=110s
    rw.pushSample(KEY, 0,         0);
    rw.pushSample(KEY, 100 * MB,  100000);
    rw.pushSample(KEY, 110 * MB,  110000);
    // window of 30 s ending at t=110s → only the last two samples count
    const r = rw.computeRate(KEY, 30, 110000);
    assertEqual(r.ready, true);
    assertEqual(r.samples, 2);
    // 10 MB over 10 s = 1 MB/s  (NOT 110MB/110s — the old sample is excluded)
    assertEqual(r.bytesPerSec, MB);
  });

  it('all samples outside window → ready:false', () => {
    rw._reset();
    rw.pushSample(KEY, 0,       0);
    rw.pushSample(KEY, 1000,    5000);
    // window of 10 s ending at t=100s → both samples are 90+ s old
    const r = rw.computeRate(KEY, 10, 100000);
    assertEqual(r.ready, false);
  });
});

describe('rate_window — sample trimming', () => {
  it('samples older than RATE_MAX_AGE_MS are dropped on push', () => {
    rw._reset();
    rw.pushSample(KEY, 0, 0);                              // very old
    rw.pushSample(KEY, 1000, rw.RATE_MAX_AGE_MS + 50000);  // 50s past max age
    // The first sample should have been trimmed by the second push.
    const peek = rw._peek(KEY);
    assertEqual(peek.length, 1, 'old sample trimmed');
  });

  it('MAX_SAMPLES cap respected', () => {
    rw._reset();
    // push more than MAX_SAMPLES, all within the age window
    const base = 1000000;
    for (let i = 0; i < rw.MAX_SAMPLES + 100; i++) {
      rw.pushSample(KEY, i * 100, base + i);
    }
    assert(rw._peek(KEY).length <= rw.MAX_SAMPLES, 'capped at MAX_SAMPLES');
  });
});

describe('rate_window — windowSec clamping', () => {
  it('windowSec below MIN clamps to MIN', () => {
    rw._reset();
    rw.pushSample(KEY, 0, 100000);
    rw.pushSample(KEY, 1000, 101000);
    const r = rw.computeRate(KEY, 1, 101000);   // 1 < MIN_WINDOW_SEC
    assertEqual(r.windowSec, rw.MIN_WINDOW_SEC);
  });

  it('windowSec above MAX clamps to MAX', () => {
    rw._reset();
    rw.pushSample(KEY, 0, 100000);
    rw.pushSample(KEY, 1000, 101000);
    const r = rw.computeRate(KEY, 9999, 101000);
    assertEqual(r.windowSec, rw.MAX_WINDOW_SEC);
  });

  it('non-numeric windowSec clamps to MIN', () => {
    rw._reset();
    rw.pushSample(KEY, 0, 100000);
    rw.pushSample(KEY, 1000, 101000);
    const r = rw.computeRate(KEY, 'banana', 101000);
    assertEqual(r.windowSec, rw.MIN_WINDOW_SEC);
  });
});

describe('rate_window — pushSample input validation', () => {
  it('negative bytes are ignored', () => {
    rw._reset();
    rw.pushSample(KEY, -500, 100000);
    assertEqual(rw._peek(KEY).length, 0);
  });

  it('NaN bytes are ignored', () => {
    rw._reset();
    rw.pushSample(KEY, NaN, 100000);
    assertEqual(rw._peek(KEY).length, 0);
  });

  it('non-string key is ignored, no throw', () => {
    rw._reset();
    rw.pushSample(null, 1000, 100000);
    rw.pushSample(123, 1000, 100000);
    assert(true, 'no throw on bad key');
  });

  it('two keys are independent', () => {
    rw._reset();
    rw.pushSample('a.part', 0, 100000);
    rw.pushSample('a.part', 1000, 101000);
    rw.pushSample('b.part', 0, 100000);
    const ra = rw.computeRate('a.part', 60, 101000);
    const rb = rw.computeRate('b.part', 60, 101000);
    assertEqual(ra.ready, true);
    assertEqual(rb.ready, false, 'b.part has only 1 sample');
  });
});
