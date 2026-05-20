'use strict';
//
// playback_env.js — mock browser environment for driving playback_state.js
// (the S1..S7 smart-playback state machine) deterministically in Node.
//
// playback_state.js is browser code: it references window / document / fetch /
// setTimeout / Date.now. This module shims all of those with controllable
// fakes so a test can script the backend responses and step the clock by
// hand — no real timers, no real network, no flakiness.
//
// Usage:
//   const env = createEnv();
//   env.install();                       // patch globals
//   const { startSmartMonitor } = require('../playback_state');  // IIFE runs
//   env.setFetchHandler(url => ({...}));  // script the API
//   const ctrl = startSmartMonitor({...});
//   await env.clock.run();               // fire all pending ticks
//   ...assert...
//   env.uninstall();

const realSetImmediate = setImmediate;

function createEnv() {
  // ── Fake clock: setTimeout/clearTimeout/Date.now all read from `now`. ─────
  let now = 1000000;
  let timers = [];
  let nextId = 1;

  function flushMicrotasks() {
    // Let the fetch promise chains settle before firing the next timer.
    return new Promise(resolve => realSetImmediate(resolve));
  }

  const clock = {
    now: () => now,
    setTimeout(fn, delay) {
      const id = nextId++;
      timers.push({ id, at: now + (delay || 0), fn });
      return id;
    },
    clearTimeout(id) {
      timers = timers.filter(t => t.id !== id);
    },
    // Fire the soonest pending timer, advancing `now` to its scheduled time.
    //
    // Flush microtasks FIRST: the state machine's very first tick() runs
    // synchronously inside startSmartMonitor() and only schedules the next
    // timer once its fetch().then() chain settles — i.e. on a microtask. So
    // before we can see any timer we must let those microtasks run. Then we
    // fire the soonest timer and flush again so ITS fetch chain settles
    // (which schedules the timer after that). Returns false when, after a
    // flush, no timers remain.
    async step() {
      await flushMicrotasks();
      await flushMicrotasks();
      if (!timers.length) return false;
      timers.sort((a, b) => a.at - b.at);
      const t = timers.shift();
      now = t.at;
      try { t.fn(); } catch (e) { /* state machine swallows its own */ }
      await flushMicrotasks();
      await flushMicrotasks();   // two passes — fetch().then().then() chains
      return true;
    },
    async run(maxSteps) {
      let n = 0;
      const cap = maxSteps || 5000;
      while (timers.length && n < cap) { await this.step(); n++; }
      return n;
    },
    pending() { return timers.length; },
    clearAll() { timers = []; },
  };

  // ── Fake DOM element ─────────────────────────────────────────────────────
  function fakeEl() {
    return {
      textContent: '',
      innerHTML: '',
      style: {},
      appendChild() {},
      querySelector() { return null; },
    };
  }

  // ── Fake fetch — driven by a handler the test sets. ──────────────────────
  // handler(urlString) returns the object the caller will get from r.json().
  let fetchHandler = () => ({});
  const fetchCalls = [];
  function fetchShim(url) {
    const u = String(url);
    fetchCalls.push(u);
    let body;
    try { body = fetchHandler(u); }
    catch (e) { return Promise.reject(e); }
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve(body),
    });
  }

  const win = {};
  const doc = {
    getElementById: () => fakeEl(),
    querySelector: () => null,
  };

  return {
    clock, win, doc,
    fetchCalls,
    setFetchHandler(fn) { fetchHandler = fn; },
    resetForNextTest() {
      clock.clearAll();
      fetchCalls.length = 0;
      win._smartPlayResults = [];
      win._smartPlayMonitor = null;
    },
    install() {
      this._real = {
        setTimeout: global.setTimeout,
        clearTimeout: global.clearTimeout,
        dateNow: Date.now,
        window: global.window,
        document: global.document,
        fetch: global.fetch,
      };
      global.setTimeout   = clock.setTimeout.bind(clock);
      global.clearTimeout = clock.clearTimeout.bind(clock);
      Date.now            = clock.now;
      global.window       = win;
      global.document     = doc;
      global.fetch        = fetchShim;
    },
    uninstall() {
      global.setTimeout   = this._real.setTimeout;
      global.clearTimeout = this._real.clearTimeout;
      Date.now            = this._real.dateNow;
      global.window       = this._real.window;
      global.document     = this._real.document;
      global.fetch        = this._real.fetch;
    },
  };
}

module.exports = { createEnv };
