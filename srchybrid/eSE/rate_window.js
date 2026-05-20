'use strict';
//
// rate_window.js — rolling download-rate window for the smart-playback
// state machine.
//
// v8.0.20: extracted from routes/emule_routes.js so the slope computation
// can be unit-tested with injected timestamps (see tests/rate_window.test.js).
//
// Model: per partFile we keep a list of { t: ms-epoch, bytes } samples. The
// /api/emule/downloads poll feeds one sample per poll. computeRate() returns
// the average slope over the requested window — this is the SUSTAINED rate,
// which is what the playback gate needs (instantaneous rate oscillates 2-3×
// around the true mean as eMule upload slots open and close).
//
// All functions take an optional `now` so tests are deterministic. In
// production `now` defaults to Date.now().

// Trim samples older than this so a long session can't grow the buffer
// unbounded.
const RATE_MAX_AGE_MS = 120 * 1000;
// Hard cap on samples per key (defence against an aggressive poller).
const MAX_SAMPLES = 240;
// Window clamps for computeRate.
const MIN_WINDOW_SEC = 5;
const MAX_WINDOW_SEC = 120;

// key (partFile basename) -> [ { t, bytes }, ... ] ordered by t ascending.
const _samples = Object.create(null);

// Push a downloadedBytes observation for `key` at time `now`.
// Silently ignores non-numeric / negative byte counts (defensive: a malformed
// .met parse could yield NaN; we don't want NaN poisoning the window).
function pushSample(key, bytes, now) {
  if (typeof key !== 'string' || !key) return;
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) return;
  now = (typeof now === 'number') ? now : Date.now();
  const arr = _samples[key] || (_samples[key] = []);
  arr.push({ t: now, bytes });
  const cutoff = now - RATE_MAX_AGE_MS;
  while (arr.length && arr[0].t < cutoff) arr.shift();
  if (arr.length > MAX_SAMPLES) arr.splice(0, arr.length - MAX_SAMPLES);
}

// Compute the average rate over the last `windowSec` seconds for `key`.
// Returns a plain object ready to JSON-serialise:
//   { ready:false, reason, samples, bytesPerSec:0, windowSec }   — not enough data
//   { ready:true,  bytesPerSec, kbPerSec, windowSec, samples,
//                  firstSampleMsAgo, lastSampleMsAgo }            — slope computed
function computeRate(key, windowSec, now) {
  now = (typeof now === 'number') ? now : Date.now();
  windowSec = parseInt(windowSec, 10);
  if (!Number.isFinite(windowSec) || windowSec < MIN_WINDOW_SEC) windowSec = MIN_WINDOW_SEC;
  if (windowSec > MAX_WINDOW_SEC) windowSec = MAX_WINDOW_SEC;

  const arr = _samples[key] || [];
  const cutoff = now - windowSec * 1000;
  const windowed = arr.filter(s => s.t >= cutoff);

  if (windowed.length < 2) {
    return {
      ready: false,
      reason: 'insufficient_samples',
      samples: windowed.length,
      bytesPerSec: 0,
      windowSec,
    };
  }

  const first = windowed[0];
  const last  = windowed[windowed.length - 1];
  const dtSec = Math.max(0.001, (last.t - first.t) / 1000);
  // Clamp negative slopes to 0. A .part shouldn't shrink, but a .met rewrite
  // coinciding with a poll, or a parser hiccup, could momentarily report
  // fewer bytes. A negative rate would confuse the state machine; 0 is the
  // honest answer ("no forward progress measured this window").
  const bps = Math.max(0, (last.bytes - first.bytes) / dtSec);
  return {
    ready: true,
    bytesPerSec: Math.round(bps),
    kbPerSec:    Math.round(bps / 1024),
    windowSec,
    samples:     windowed.length,
    firstSampleMsAgo: Math.round(now - first.t),
    lastSampleMsAgo:  Math.round(now - last.t),
  };
}

// Test helpers — not used in production paths.
function _reset() {
  for (const k of Object.keys(_samples)) delete _samples[k];
}
function _peek(key) {
  return (_samples[key] || []).slice();
}

module.exports = {
  pushSample,
  computeRate,
  _reset,
  _peek,
  RATE_MAX_AGE_MS,
  MAX_SAMPLES,
  MIN_WINDOW_SEC,
  MAX_WINDOW_SEC,
};
