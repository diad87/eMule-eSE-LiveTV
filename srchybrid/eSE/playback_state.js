// playback_state.js — v8.0.16 Smart Playback state machine
//
// Replaces the ad-hoc monitorForFile() function that lived in both smart_play.js
// and player.js. Those two copies had drifted, shared a lot of broken assumptions
// (e.g. trusting stat.size on pre-allocated sparse .part files), and were full
// of in-page side effects making them hard to test or evolve. This module
// centralises every "should we start / keep playing?" decision into a single
// state machine driven by backend ground truth (.met gap-list, ffprobe, rolling
// rate window).
//
// States
// ──────
//   S1 INIT          — Poll /api/emule/downloads waiting for the matching
//                      download to appear and start receiving bytes.
//   S2 PROBE         — Run ffprobe on the .part file via /api/emule/probe.
//                      Need duration + bitrate so the sustained-rate target
//                      isn't a guess based on "average 90-min movie".
//   S3 SUSTAIN       — Wait until the rolling-rate window confirms the
//                      download rate ≥ playbackBitrate × safety. No point
//                      starting playback if it'll stall in 30s.
//   S4 HEAD_BUFFER   — Brief "we're ready, kicking off the player" pause
//                      that gives the UI one tick to render "Reproduciendo".
//   S5 PLAYING       — Call onPlay (which spawns the cinema player). Tick
//                      every 5s: compare bytesPlayed (currentTime × bitrate)
//                      against headContiguousBytes; if lead < 10s of buffer
//                      AND rate < bitrate × 0.8, transition to STALL.
//   S6 STALL         — Pause the video, increment stallCount. Poll buffer
//                      and rate; resume to PLAYING when both recover. After
//                      60s of unrecoverable stall, fail.
//   S7 COMPLETE      — Video ended cleanly. Wind down timers.
//   S0 FAIL          — Terminal. Call onFail(reason, remaining) so the
//                      caller can render source-switch / dismiss buttons.
//
// API
// ───
//   var ctrl = window.startSmartMonitor({
//     movieTitle, expectedFileName, totalSizeMB, sourceIndex, expectedHash,
//     ui: { statusEl, progressEl, titleEl, actionsEl },   // optional
//     onPlay:     function(partFile, fileName, probe) { ... },
//     onComplete: function(fileName) { ... },                          // optional
//     onFail:     function(reason, remainingSources, retryCallback) { ... },
//   });
//   ctrl.stop();
//   ctrl.getState() → 'PROBE'
//   ctrl.getContext() → { ... read-only snapshot ... }
//
// Notes
// ─────
//   • The .UI elements are reused as-is per user feedback "reutiliza" — no
//     redesign, just honest progress/status text driven by the state.
//   • Source switching (D in the v8.0.16 plan) is implemented by onFail
//     delegating to trySmartSource(sourceIndex + 1) in the caller. The state
//     machine just decides WHEN to give up on a source; the caller decides
//     what to do about it.

(function () {
  'use strict';

  // ── Constants tuned for typical eMule .part downloads ─────────────────────
  var MIN_HEAD_MB           = 15;     // before we even try to play
  var MIN_HEAD_BYTES        = MIN_HEAD_MB * 1024 * 1024;
  var SAFETY_FACTOR         = 1.3;    // require 30 % rate headroom over bitrate
  var MIN_REQUIRED_RATE_BPS = 256 * 1024; // 256 KB/s floor
  var BUFFER_AHEAD_SEC      = 10;     // pause-trigger in PLAYING
  var STALL_RATE_FRACTION   = 0.8;    // rate < bitrate × this → suspect stall
  var MAX_STALL_COUNT       = 2;      // 2× stalls in one session → fail
  var MAX_STATE_SEC = {
    INIT:        120,   // 2 min searching for the download
    PROBE:        45,
    SUSTAIN:      90,
    HEAD_BUFFER:   5,
    PLAYING:    Infinity,
    STALL:        60,
  };
  var TICK_MS = {
    INIT:        1500,
    PROBE:       3000,
    SUSTAIN:     2000,
    HEAD_BUFFER: 1000,
    PLAYING:     5000,
    STALL:       3000,
    COMPLETE:   30000,
  };

  // ── Helpers ───────────────────────────────────────────────────────────────
  function normalize(s) {
    return (s || '').toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\s+/g, ' ').trim();
  }
  function matchTitleWords(fn, words) {
    var nfn = normalize(fn);
    var matchCount = 0;
    for (var i = 0; i < words.length; i++) {
      if (nfn.indexOf(words[i]) !== -1) matchCount++;
    }
    return matchCount >= Math.max(1, Math.ceil(words.length * 0.3));
  }
  function fmtBitrate(bps) {
    if (!bps) return '?';
    return (bps / 1000).toFixed(0) + ' kbps';
  }
  function safeJson(r) {
    return r.json().catch(function () { return null; });
  }

  // ── Main entry ────────────────────────────────────────────────────────────
  function startSmartMonitor(args) {
    args = args || {};

    var ctx = {
      movieTitle:       args.movieTitle || '',
      expectedFileName: args.expectedFileName || '',
      totalSizeMB:      args.totalSizeMB || 0,
      sourceIndex:      args.sourceIndex || 0,
      expectedHash:     (args.expectedHash || '').toUpperCase(),
      ui:               args.ui || {},
      onPlay:           args.onPlay || function () {},
      onComplete:       args.onComplete || function () {},
      onFail:           args.onFail || function () {},

      // Lazy DOM lookup so callers don't have to pass elements every time.
      _statusEl:   args.ui && args.ui.statusEl   || document.getElementById('smart-play-status'),
      _progressEl: args.ui && args.ui.progressEl || document.getElementById('smart-play-progress'),
      _titleEl:    args.ui && args.ui.titleEl    || document.getElementById('smart-play-title'),
      _actionsEl:  args.ui && args.ui.actionsEl  || document.getElementById('smart-play-actions'),

      state:           'INIT',
      stateEnteredMs:  Date.now(),
      stoppedAt:       null,
      ticks:           0,

      download:        null,    // last seen row from /api/emule/downloads
      probe:           null,    // last successful /api/emule/probe response
      rate:            null,    // last /api/emule/rate response
      bitrateBps:      null,    // chosen target bitrate (probe.bitrate or estimate)
      requiredRateBps: null,    // bitrate × SAFETY_FACTOR with floor

      stallCount:      0,
      videoEl:         null,    // bound on PLAYING via onPlay's host

      _movieWords:     normalize(args.movieTitle || '').split(' ').filter(function (w) { return w.length > 2; }),
      _timer:          null,
    };

    function elapsedSec() { return (Date.now() - ctx.stateEnteredMs) / 1000; }

    function setState(next) {
      if (next === ctx.state) return;
      // Tiny audit trail in console — helps debug "why did it stall here".
      try { console.log('[PlaybackState] ' + ctx.state + ' → ' + next + ' (after ' + elapsedSec().toFixed(1) + 's)'); } catch (e) {}
      ctx.state = next;
      ctx.stateEnteredMs = Date.now();
      ctx.ticks = 0;
    }

    function stop(reason) {
      if (ctx.stoppedAt) return;
      ctx.stoppedAt = Date.now();
      if (ctx._timer) { clearTimeout(ctx._timer); ctx._timer = null; }
      try { console.log('[PlaybackState] stopped (' + (reason || ctx.state) + ')'); } catch (e) {}
    }

    function fail(reason) {
      setState('FAIL');
      stop(reason);
      var remaining = ((window._smartPlayResults || []).length - (ctx.sourceIndex + 1)) | 0;
      var retry = function () {
        if (typeof window.trySmartSource === 'function' && remaining > 0) {
          window.trySmartSource(ctx.sourceIndex + 1);
        }
      };
      try { ctx.onFail(reason, remaining, retry, ctx); } catch (e) { console.error('[PlaybackState] onFail threw', e); }
    }

    // ── Per-state logic. Each returns a promise (or undefined). ─────────────
    function doInit() {
      return findDownload().then(function (dl) {
        ctx.download = dl;
        renderUiInit(dl);
        if (dl && dl.active && (dl.headContiguousBytes || 0) > 0) {
          // We have a live download with at least some head bytes — promote.
          setState('PROBE');
          return;
        }
        if (elapsedSec() > MAX_STATE_SEC.INIT) {
          fail('no_data');
        }
      });
    }

    function doProbe() {
      var pf = ctx.download && ctx.download.partFile;
      if (!pf) {
        // Lost the download between ticks — back to INIT to re-find it.
        setState('INIT');
        return;
      }
      return fetch('/api/emule/probe?file=' + encodeURIComponent(pf))
        .then(safeJson)
        .then(function (p) {
          if (!p) {
            renderUiProbe('ffprobe sin respuesta');
            return;
          }
          if (p.ready) {
            ctx.probe = p;
            // Choose bitrate: prefer ffprobe (sharper), else estimate from
            // totalBytes / duration, else fall back to 90 min assumption.
            var br = p.bitrate || null;
            var dur = p.duration || null;
            if ((!br || br <= 0) && dur && ctx.download && ctx.download.totalBytes) {
              br = Math.round((ctx.download.totalBytes * 8) / dur);
            }
            if (!br && ctx.download && ctx.download.totalBytes) {
              br = Math.round((ctx.download.totalBytes * 8) / (90 * 60));
            }
            ctx.bitrateBps = br || (MIN_REQUIRED_RATE_BPS / SAFETY_FACTOR);
            ctx.requiredRateBps = Math.max(
              MIN_REQUIRED_RATE_BPS,
              Math.round(ctx.bitrateBps / 8 * SAFETY_FACTOR)
            );
            setState('SUSTAIN');
            return;
          }
          // Not ready yet — head too small, or ffprobe still parsing.
          renderUiProbe(p.reason || 'analizando archivo');
          if (elapsedSec() > MAX_STATE_SEC.PROBE) {
            // Bail to SUSTAIN with a guessed bitrate so we don't get stuck
            // forever waiting for a probe that may never succeed (some
            // codecs are very slow to identify on partial files).
            if (ctx.download && ctx.download.totalBytes) {
              ctx.bitrateBps = Math.round((ctx.download.totalBytes * 8) / (90 * 60));
            } else {
              ctx.bitrateBps = MIN_REQUIRED_RATE_BPS / SAFETY_FACTOR;
            }
            ctx.requiredRateBps = Math.max(
              MIN_REQUIRED_RATE_BPS,
              Math.round(ctx.bitrateBps / 8 * SAFETY_FACTOR)
            );
            setState('SUSTAIN');
          }
        });
    }

    function doSustain() {
      var pf = ctx.download && ctx.download.partFile;
      if (!pf) { setState('INIT'); return; }
      return Promise.all([
        findDownload(),
        fetch('/api/emule/rate?file=' + encodeURIComponent(pf) + '&windowSec=30').then(safeJson),
      ]).then(function (results) {
        var dl = results[0];
        var rate = results[1];
        if (dl) ctx.download = dl;
        ctx.rate = rate;
        var rateBps = (rate && rate.ready) ? rate.bytesPerSec : 0;
        var headBytes = (dl && dl.headContiguousBytes) || 0;
        var alreadyComplete = dl && dl.totalBytes > 0 && dl.downloadedBytes >= dl.totalBytes;
        renderUiSustain(rateBps, headBytes, alreadyComplete);
        if (alreadyComplete) {
          setState('HEAD_BUFFER');
          return;
        }
        var rateOk = rateBps >= ctx.requiredRateBps;
        var headOk = headBytes >= MIN_HEAD_BYTES;
        if (rateOk && headOk) {
          setState('HEAD_BUFFER');
          return;
        }
        if (elapsedSec() > MAX_STATE_SEC.SUSTAIN) {
          // Couldn't get up to speed within budget — fail so the caller can
          // offer to try a different source.
          fail(rateOk ? 'no_head' : 'low_rate');
        }
      });
    }

    function doHeadBuffer() {
      renderUiHeadBuffer();
      if (elapsedSec() > 1) {
        setState('PLAYING');
        // Hand off to the caller's playback function. Pass the probe so the
        // host can use codec info for transcoding decisions.
        try {
          ctx.onPlay(ctx.download.partFile, ctx.download.fileName, ctx.probe || null);
        } catch (e) {
          console.error('[PlaybackState] onPlay threw', e);
          fail('play_threw');
          return;
        }
        // Try to find the <video> element so we can drive the watchdog.
        // Most cinema-player layouts use a single <video> tag inside the
        // open modal; fall back to first <video> on the page.
        ctx.videoEl =
          document.querySelector('#cinema-player video') ||
          document.querySelector('video');
      }
    }

    function doPlaying() {
      var pf = ctx.download && ctx.download.partFile;
      if (!pf) { setState('INIT'); return; }
      // Detect file completion via the video element first (more reliable
      // than polling /downloads, since the video tells us when playback is
      // genuinely over).
      if (ctx.videoEl && ctx.videoEl.ended) {
        setState('COMPLETE');
        try { ctx.onComplete(ctx.download.fileName); } catch (e) {}
        stop('complete');
        return;
      }
      return Promise.all([
        findDownload(),
        fetch('/api/emule/rate?file=' + encodeURIComponent(pf) + '&windowSec=30').then(safeJson),
      ]).then(function (results) {
        var dl = results[0];
        var rate = results[1];
        if (dl) ctx.download = dl;
        ctx.rate = rate;
        var rateBps = (rate && rate.ready) ? rate.bytesPerSec : 0;
        var headBytes = (dl && dl.headContiguousBytes) || 0;
        var currentTimeSec = (ctx.videoEl && !isNaN(ctx.videoEl.currentTime))
          ? ctx.videoEl.currentTime : 0;
        var bytesPlayed = currentTimeSec * (ctx.bitrateBps / 8);
        var leadBytes = headBytes - bytesPlayed;
        var leadSec = ctx.bitrateBps > 0 ? leadBytes / (ctx.bitrateBps / 8) : 0;
        renderUiPlaying(rateBps, leadSec, currentTimeSec);
        // Stall trigger: buffer dangerously low AND download isn't keeping
        // pace. Both conditions together — a low buffer with a fast download
        // is fine, it'll catch up; a slow download with a big buffer is fine
        // too, we can ride it out.
        var lowBuffer = leadSec < BUFFER_AHEAD_SEC;
        var slowRate  = ctx.bitrateBps > 0 && rateBps < (ctx.bitrateBps / 8) * STALL_RATE_FRACTION;
        if (lowBuffer && slowRate) {
          setState('STALL');
          if (ctx.videoEl && !ctx.videoEl.paused) {
            try { ctx.videoEl.pause(); } catch (e) {}
          }
        }
      });
    }

    function doStall() {
      var pf = ctx.download && ctx.download.partFile;
      if (!pf) { setState('INIT'); return; }
      // First entry into STALL increments the counter exactly once.
      if (ctx.ticks === 1) ctx.stallCount++;
      if (ctx.stallCount > MAX_STALL_COUNT) {
        fail('repeated_stalls');
        return;
      }
      return Promise.all([
        findDownload(),
        fetch('/api/emule/rate?file=' + encodeURIComponent(pf) + '&windowSec=30').then(safeJson),
      ]).then(function (results) {
        var dl = results[0];
        var rate = results[1];
        if (dl) ctx.download = dl;
        ctx.rate = rate;
        var rateBps = (rate && rate.ready) ? rate.bytesPerSec : 0;
        var headBytes = (dl && dl.headContiguousBytes) || 0;
        var currentTimeSec = (ctx.videoEl && !isNaN(ctx.videoEl.currentTime))
          ? ctx.videoEl.currentTime : 0;
        var bytesPlayed = currentTimeSec * (ctx.bitrateBps / 8);
        var leadSec = ctx.bitrateBps > 0 ? (headBytes - bytesPlayed) / (ctx.bitrateBps / 8) : 0;
        renderUiStall(rateBps, leadSec);
        // Recovery condition: buffer comfortably ahead AND rate keeping up.
        var bufferOk = leadSec >= BUFFER_AHEAD_SEC * 2;     // require 2× the trigger
        var rateOk   = ctx.bitrateBps > 0 && rateBps >= (ctx.bitrateBps / 8);
        if (bufferOk && rateOk) {
          if (ctx.videoEl && ctx.videoEl.paused) {
            try { ctx.videoEl.play(); } catch (e) {}
          }
          setState('PLAYING');
          return;
        }
        if (elapsedSec() > MAX_STATE_SEC.STALL) {
          fail('stall_timeout');
        }
      });
    }

    // ── UI renderers — same DOM ids the old monitorForFile used. ────────────
    function setText(el, text) {
      if (!el) return;
      if (typeof el.textContent === 'string') el.textContent = text;
    }
    function setProgress(pct) {
      if (!ctx._progressEl) return;
      ctx._progressEl.style.width = Math.max(0, Math.min(100, pct)) + '%';
    }
    function renderUiInit(dl) {
      setText(ctx._titleEl, dl ? 'Buscando datos…' : 'Iniciando descarga…');
      if (dl) {
        var dlMB = Math.round((dl.downloadedBytes || 0) / (1024 * 1024));
        var totMB = Math.round((dl.totalBytes || 0) / (1024 * 1024));
        var hcMB = Math.round((dl.headContiguousBytes || 0) / (1024 * 1024));
        setText(ctx._statusEl, 'Descargando ' + dlMB + ' / ' + totMB + ' MB · inicio contiguo ' + hcMB + ' MB');
      } else {
        var dots = '.'.repeat((ctx.ticks % 3) + 1);
        setText(ctx._statusEl, 'Esperando que eMule reciba datos' + dots);
      }
      setProgress(Math.min(35, 5 + ctx.ticks * 2));
    }
    function renderUiProbe(reason) {
      setText(ctx._titleEl, 'Analizando archivo');
      setText(ctx._statusEl, 'ffprobe: ' + reason);
      setProgress(40);
    }
    function renderUiSustain(rateBps, headBytes, alreadyComplete) {
      if (alreadyComplete) {
        setText(ctx._titleEl, 'Listo (archivo completo)');
        setProgress(95);
        return;
      }
      var rateKB = Math.round(rateBps / 1024);
      var needKB = Math.round(ctx.requiredRateBps / 1024);
      var hcMB = Math.round(headBytes / (1024 * 1024));
      var bitrateLabel = ctx.bitrateBps ? fmtBitrate(ctx.bitrateBps) : '—';
      setText(ctx._titleEl, 'Comprobando velocidad…');
      setText(ctx._statusEl,
        '↓ ' + rateKB + ' KB/s · necesitas ≥ ' + needKB + ' KB/s · ' +
        'inicio ' + hcMB + '/' + MIN_HEAD_MB + ' MB · bitrate ' + bitrateLabel
      );
      var rateProgress  = ctx.requiredRateBps > 0 ? Math.min(rateBps / ctx.requiredRateBps, 1) * 30 : 0;
      var headProgress  = Math.min(headBytes / MIN_HEAD_BYTES, 1) * 25;
      setProgress(40 + rateProgress + headProgress);
    }
    function renderUiHeadBuffer() {
      setText(ctx._titleEl, 'Buffer listo');
      setText(ctx._statusEl, 'Iniciando reproducción…');
      setProgress(98);
    }
    function renderUiPlaying(rateBps, leadSec, currentTimeSec) {
      // The cinema player has its own visible UI; smart-play status is in
      // the background. We still keep statusEl fresh so the user can see
      // the playback health.
      var rateKB = Math.round(rateBps / 1024);
      setText(ctx._titleEl, 'Reproduciendo');
      setText(ctx._statusEl,
        '↓ ' + rateKB + ' KB/s · buffer ' + Math.max(0, Math.round(leadSec)) + 's · ' +
        'posición ' + Math.round(currentTimeSec) + 's'
      );
      setProgress(100);
    }
    function renderUiStall(rateBps, leadSec) {
      var rateKB = Math.round(rateBps / 1024);
      setText(ctx._titleEl, 'Buffering…');
      setText(ctx._statusEl,
        'Velocidad insuficiente · ↓ ' + rateKB + ' KB/s · buffer ' + Math.max(0, Math.round(leadSec)) + 's · ' +
        'intento ' + ctx.stallCount + '/' + MAX_STALL_COUNT
      );
    }

    // ── Download finder. Hash exact match first, then fuzzy title. ──────────
    function findDownload() {
      return fetch('/api/emule/downloads').then(safeJson).then(function (arr) {
        if (!Array.isArray(arr) || !arr.length) return null;
        if (ctx.expectedHash) {
          for (var i = 0; i < arr.length; i++) {
            if (arr[i].fileHash && arr[i].fileHash.toUpperCase() === ctx.expectedHash) return arr[i];
          }
          // Hash not found yet — return null so we keep waiting in INIT.
          // (We intentionally don't fall back to title-match when a hash was
          // provided: that's how the "a todo gas 6 → played 1" bug used to
          // happen.)
          return null;
        }
        // No hash — best-effort fuzzy match on the movie title.
        for (var j = 0; j < arr.length; j++) {
          if (matchTitleWords(arr[j].fileName || '', ctx._movieWords)) return arr[j];
        }
        return null;
      });
    }

    // ── Driver ──────────────────────────────────────────────────────────────
    function tick() {
      if (ctx.stoppedAt) return;
      ctx.ticks++;
      var p;
      try {
        switch (ctx.state) {
          case 'INIT':        p = doInit();        break;
          case 'PROBE':       p = doProbe();       break;
          case 'SUSTAIN':     p = doSustain();     break;
          case 'HEAD_BUFFER': p = doHeadBuffer();  break;
          case 'PLAYING':     p = doPlaying();     break;
          case 'STALL':       p = doStall();       break;
          case 'COMPLETE':    /* idle */           break;
          case 'FAIL':        /* terminal */       return;
        }
      } catch (e) {
        console.error('[PlaybackState] state ' + ctx.state + ' threw', e);
      }
      Promise.resolve(p).then(scheduleNext, scheduleNext);
    }
    function scheduleNext() {
      if (ctx.stoppedAt) return;
      var delay = TICK_MS[ctx.state] || 5000;
      ctx._timer = setTimeout(tick, delay);
    }

    // Kick off immediately.
    tick();

    return {
      stop: stop,
      getState: function () { return ctx.state; },
      getContext: function () {
        return {
          state: ctx.state, ticks: ctx.ticks,
          download: ctx.download, probe: ctx.probe, rate: ctx.rate,
          bitrateBps: ctx.bitrateBps, requiredRateBps: ctx.requiredRateBps,
          stallCount: ctx.stallCount,
        };
      },
    };
  }

  // ── Default onFail UI renderer ─────────────────────────────────────────────
  // Caller-supplied onFail can do whatever it wants; if it's missing or just
  // wants the standard "Probar otra fuente / Dejar descargando / Volver"
  // button row, exposing this helper keeps both monitorForFile wrappers DRY.
  function renderDefaultFailButtons(actionsEl, reason, remaining, retry, opts) {
    if (!actionsEl) return;
    opts = opts || {};
    var onBack = opts.onBack || function () {};
    var onLeaveDownloading = opts.onLeaveDownloading || function () {};
    var msgEl = opts.titleEl;
    if (msgEl) {
      var msg = {
        no_data:          'Sin datos recibidos',
        low_rate:         'Velocidad insuficiente',
        no_head:          'Inicio del archivo incompleto',
        repeated_stalls:  'La reproducción no es estable',
        stall_timeout:    'La descarga se ha detenido',
        play_threw:       'Error al iniciar reproducción',
      }[reason] || ('Reproducción no disponible (' + reason + ')');
      try { msgEl.textContent = msg; } catch (e) {}
    }
    actionsEl.innerHTML = '';
    actionsEl.style.display = 'flex';
    var buttons = [];
    if (remaining > 0) {
      buttons.push({
        text: 'Probar otra fuente (' + remaining + ' disponibles)',
        primary: true,
        action: retry,
      });
    }
    buttons.push({
      text: remaining === 0 ? 'Descargar y avisar cuando esté lista' : 'Dejar descargando',
      primary: remaining === 0,
      action: onLeaveDownloading,
    });
    buttons.push({ text: 'Volver', primary: false, action: onBack });
    buttons.forEach(function (b) {
      var btn = document.createElement('button');
      btn.textContent = b.text;
      btn.style.cssText = b.primary
        ? 'background:linear-gradient(135deg,#ff6b35,#ff2d78);border:none;color:#fff;padding:12px 24px;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:220px'
        : 'background:rgba(255,255,255,.08);border:1px solid #333;color:#aaa;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px;min-width:220px';
      btn.onclick = b.action;
      actionsEl.appendChild(btn);
    });
  }

  // Expose globally so the bundled smart_play.js / player.js can call us.
  window.startSmartMonitor = startSmartMonitor;
  window.PlaybackState = {
    renderDefaultFailButtons: renderDefaultFailButtons,
  };
})();
