'use strict';
//
// playback_state.test.js — integration tests for the S1..S7 smart-playback
// state machine (playback_state.js).
//
// playback_state.js is browser code, so we drive it through playback_env.js
// which shims window/document/fetch/setTimeout/Date.now. The fake clock lets
// us fast-forward through the timeout-based transitions deterministically.
//
// This file exports an async runner (run.js awaits it) because stepping the
// fake clock is inherently async.

const { createEnv } = require('./playback_env');

const MB = 1024 * 1024;

// The mock env must stay installed for the WHOLE duration of these tests:
// startSmartMonitor reads window/document/fetch/setTimeout/Date.now at call
// time, not at module-load time. So install() happens at the start of the
// exported async runner and uninstall() at the end (see bottom of file).
const env = createEnv();
let startSmartMonitor = null;

// A scriptable backend. Each field is the body the corresponding endpoint
// returns from r.json(). Tests mutate these between/within runs.
function backend(spec) {
  return function (url) {
    if (url.indexOf('/api/emule/downloads') !== -1)        return spec.downloads();
    if (url.indexOf('/api/emule/probe') !== -1)            return spec.probe();
    if (url.indexOf('/api/emule/rate') !== -1)             return spec.rate();
    if (url.indexOf('/api/stream/completed/list') !== -1)  return [];
    return {};
  };
}

// A "healthy" download row with everything the state machine reads.
function healthyDownload(hash, headBytes, totalBytes) {
  return {
    partFile: '0042.part',
    fileName: 'Test.Movie.1080p.mkv',
    fileHash: hash,
    active: true,
    totalBytes: totalBytes,
    totalMB: Math.round(totalBytes / MB),
    downloadedBytes: headBytes,
    downloadedMB: Math.round(headBytes / MB),
    headContiguousBytes: headBytes,
    headContiguousMB: Math.round(headBytes / MB),
    firstGapStart: headBytes,
    firstGapEnd: totalBytes,
    gapCount: 1,
    metParseOk: true,
    progress: Math.round((headBytes / totalBytes) * 1000) / 10,
  };
}

// Step the fake clock until predicate(state) is true or we run out of steps.
async function runUntil(ctrl, predicate, maxSteps) {
  let n = 0;
  const cap = maxSteps || 4000;
  while (n < cap) {
    if (predicate(ctrl.getState())) return true;
    const stepped = await env.clock.step();
    n++;
    if (!stepped) break;
  }
  return predicate(ctrl.getState());
}

module.exports = async function runPlaybackTests(h) {
  const { describe, itAsync, assert, assertEqual } = h;

  // Install the mock browser env, THEN require playback_state.js (its IIFE
  // reads `window` at load time). Uninstall in a finally at the end.
  env.install();
  try {
    require('../playback_state');
    startSmartMonitor = env.win.startSmartMonitor;
    if (typeof startSmartMonitor !== 'function') {
      throw new Error('playback_state.js did not expose window.startSmartMonitor');
    }
    await _runAll(h);
  } finally {
    env.uninstall();
  }
};

async function _runAll(h) {
  const { describe, itAsync, assert, assertEqual } = h;

  describe('playback_state — happy path INIT→PROBE→SUSTAIN→HEAD_BUFFER→PLAYING', () => {});

  await itAsync('reaches PLAYING and calls onPlay when rate is healthy', async () => {
    env.resetForNextTest();
    const HASH = 'AE9C00112233445566778899AABBCCDD';
    env.setFetchHandler(backend({
      downloads: () => [ healthyDownload(HASH, 50 * MB, 4000 * MB) ],
      probe: () => ({ ready: true, bitrate: 4000000, duration: 7200,
                      videoCodec: 'h264', audioCodec: 'aac', container: 'matroska' }),
      // required ≈ 650 KB/s (4 Mbit / 8 × 1.3). Give 1 MB/s — comfortably above.
      rate: () => ({ ready: true, bytesPerSec: 1 * MB, kbPerSec: 1024, windowSec: 30, samples: 8 }),
    }));

    let played = null;
    const ctrl = startSmartMonitor({
      movieTitle: 'Test Movie', expectedHash: HASH, sourceIndex: 0,
      totalSizeMB: 4000,
      onPlay: (partFile, fileName) => { played = { partFile, fileName }; },
      onFail: () => {},
    });

    const reached = await runUntil(ctrl, s => s === 'PLAYING' || s === 'FAIL', 200);
    assert(reached, 'should settle into PLAYING/FAIL within 200 steps');
    assertEqual(ctrl.getState(), 'PLAYING', 'final state');
    assert(played !== null, 'onPlay was called');
    assertEqual(played.partFile, '0042.part', 'onPlay got the right partFile');
    ctrl.stop();
  });

  describe('playback_state — no data → FAIL(no_data)', () => {});

  await itAsync('empty downloads list → fails with no_data after INIT timeout', async () => {
    env.resetForNextTest();
    env.setFetchHandler(backend({
      downloads: () => [],          // eMule never produces the .part
      probe: () => ({ ready: false }),
      rate: () => ({ ready: false }),
    }));

    let failReason = null;
    const ctrl = startSmartMonitor({
      movieTitle: 'Ghost Movie', expectedHash: 'DEADBEEF', sourceIndex: 0,
      onPlay: () => {},
      onFail: (reason) => { failReason = reason; },
    });

    const done = await runUntil(ctrl, s => s === 'FAIL', 400);
    assert(done, 'should reach FAIL');
    assertEqual(failReason, 'no_data', 'fail reason');
    ctrl.stop();
  });

  describe('playback_state — slow source → FAIL(low_rate)', () => {});

  await itAsync('head present, probe ok, but rate too low → low_rate', async () => {
    env.resetForNextTest();
    const HASH = 'BBBB1111222233334444555566667777';
    env.setFetchHandler(backend({
      downloads: () => [ healthyDownload(HASH, 50 * MB, 4000 * MB) ],
      probe: () => ({ ready: true, bitrate: 4000000, duration: 7200 }),
      // required ≈ 650 KB/s; give 50 KB/s — far below.
      rate: () => ({ ready: true, bytesPerSec: 50 * 1024, kbPerSec: 50, windowSec: 30, samples: 8 }),
    }));

    let failReason = null;
    const ctrl = startSmartMonitor({
      movieTitle: 'Slow Movie', expectedHash: HASH, sourceIndex: 0,
      onPlay: () => {},
      onFail: (reason) => { failReason = reason; },
    });

    const done = await runUntil(ctrl, s => s === 'FAIL', 400);
    assert(done, 'should reach FAIL');
    assertEqual(failReason, 'low_rate', 'fail reason');
    ctrl.stop();
  });

  describe('playback_state — hash matching (the "a todo gas 6" guard)', () => {});

  await itAsync('picks the download whose hash matches, ignores same-titled decoy', async () => {
    env.resetForNextTest();
    const WANT = 'CAFE0000111122223333444455556666';
    const DECOY = '0000DECOY1111222233334444555566FF';
    env.setFetchHandler(backend({
      downloads: () => [
        // decoy: same-ish title, DIFFERENT hash — must NOT be picked
        Object.assign(healthyDownload(DECOY, 50 * MB, 4000 * MB),
                      { partFile: '0001.part', fileName: 'Test Movie OLD.mkv' }),
        // the real one
        Object.assign(healthyDownload(WANT, 50 * MB, 4000 * MB),
                      { partFile: '0099.part', fileName: 'Test Movie NEW.mkv' }),
      ],
      probe: () => ({ ready: true, bitrate: 4000000, duration: 7200 }),
      rate: () => ({ ready: true, bytesPerSec: 1 * MB }),
    }));

    let playedPartFile = null;
    const ctrl = startSmartMonitor({
      movieTitle: 'Test Movie', expectedHash: WANT, sourceIndex: 0,
      onPlay: (partFile) => { playedPartFile = partFile; },
      onFail: () => {},
    });

    await runUntil(ctrl, s => s === 'PLAYING' || s === 'FAIL', 200);
    assertEqual(ctrl.getState(), 'PLAYING', 'should reach PLAYING');
    assertEqual(playedPartFile, '0099.part', 'played the hash-matched download, not the decoy');
    const dl = ctrl.getContext().download;
    assertEqual(dl.fileHash, WANT, 'bound to the right hash');
    ctrl.stop();
  });

  describe('playback_state — complete file fast-path', () => {});

  await itAsync('already-complete download promotes straight through SUSTAIN', async () => {
    env.resetForNextTest();
    const HASH = 'FFFF0000FFFF0000FFFF0000FFFF0000';
    const SIZE = 700 * MB;
    env.setFetchHandler(backend({
      // downloaded === total → alreadyComplete branch in doSustain
      downloads: () => [ Object.assign(healthyDownload(HASH, SIZE, SIZE),
                                       { downloadedBytes: SIZE, downloadedMB: 700 }) ],
      probe: () => ({ ready: true, bitrate: 3000000, duration: 5400 }),
      rate: () => ({ ready: false }),   // rate unknown — must not matter when complete
    }));

    let played = false;
    const ctrl = startSmartMonitor({
      movieTitle: 'Complete Movie', expectedHash: HASH, sourceIndex: 0,
      onPlay: () => { played = true; },
      onFail: () => {},
    });

    await runUntil(ctrl, s => s === 'PLAYING' || s === 'FAIL', 200);
    assertEqual(ctrl.getState(), 'PLAYING', 'complete file reaches PLAYING even with unknown rate');
    assert(played, 'onPlay called');
    ctrl.stop();
  });
};
