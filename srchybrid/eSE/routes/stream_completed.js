'use strict';
const fs   = require('fs');
const path = require('path');
const { Transform } = require('node:stream');
const { StringDecoder } = require('node:string_decoder');
const {
  runProcess,
  spawnManaged,
} = require('../bounded_process_runner');
const { safeBasename } = require('../utils');
const { validateRouteContext } = require('./route_context');

/** @type {Pick<import('./route_context').SharedRouteContext, 'FFMPEG_PATH'|'HW_ENCODER'|'HW_ENCODER_OPTS'|'activeStreams'|'getCompletedFiles'|'resolveMediaFile'> & {getSession: Function, emuleRequest: Function, runMediaProbe?: Function, spawnMediaProcess?: Function}} */
let _ctx = {};
const probeCache = new Map();
const MAX_PROBE_CACHE_ENTRIES = 256;

function init(ctx) {
  _ctx = validateRouteContext(ctx, 'stream completed', {
    FFMPEG_PATH: 'string', HW_ENCODER: 'string', HW_ENCODER_OPTS: 'array', activeStreams: 'object',
    getCompletedFiles: 'function', resolveMediaFile: 'function',
    getSession: 'function', emuleRequest: 'function',
  }, {
    // Optional process adapters let the isolated HTTP tests exercise these
    // routes without eMule or real encoders. Production uses the bounded runner.
    runMediaProbe: 'function', spawnMediaProcess: 'function',
  });
  probeCache.clear();
}

function createDisconnectGuard(req, res, onDisconnect) {
  const controller = new AbortController();
  let disconnected = !!(req.destroyed || res.destroyed);
  if (disconnected) controller.abort();
  const markDisconnected = () => {
    if (disconnected) return;
    disconnected = true;
    controller.abort();
    if (onDisconnect) onDisconnect();
  };
  // IncomingMessage.close describes completion of the request, not the
  // lifetime of its streaming response. Only these events mean cancellation.
  req.once('aborted', markDisconnected);
  res.once('close', markDisconnected);
  return {
    signal: controller.signal,
    get disconnected() { return disconnected; },
    checkNow() {
      if (req.destroyed || res.destroyed) markDisconnected();
      return disconnected;
    },
  };
}

function ffprobePath() {
  return _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/i, 'ffprobe$1');
}

async function runBoundedProbe(file, args, options) {
  const result = await runProcess(file, args, options);
  if (!result.ok) throw new Error(result.error || result.stderr || 'ffprobe failed');
  return result;
}

// One bounded ffprobe per file version serves duration, tracks, subtitles and
// codec selection. The cache is keyed by size+mtime, so growing .part files
// are re-probed.
async function probeMedia(filePath, signal) {
  const stat = await fs.promises.stat(filePath);
  const cached = probeCache.get(filePath);
  if (cached && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) {
    // Refresh insertion order so pruning behaves like a small LRU.
    probeCache.delete(filePath);
    probeCache.set(filePath, cached);
    return cached.probe;
  }

  const result = await (_ctx.runMediaProbe || runBoundedProbe)(ffprobePath(), [
    '-v', 'error',
    '-print_format', 'json',
    '-show_format',
    '-show_streams',
    filePath
  ], { timeoutMs: 15000, maxOutputBytes: 2 * 1024 * 1024, signal });
  const probe = JSON.parse(result.stdout);
  probeCache.set(filePath, { size: stat.size, mtimeMs: stat.mtimeMs, probe });
  while (probeCache.size > MAX_PROBE_CACHE_ENTRIES) {
    probeCache.delete(probeCache.keys().next().value);
  }
  return probe;
}

function spawnMedia(args) {
  return (_ctx.spawnMediaProcess || spawnManaged)(_ctx.FFMPEG_PATH, args, { windowsHide: true });
}

// SECURITY: this route handles /api/stream/* endpoints that accept a fileName
// from URL query/path. Even though resolveMediaFile() also sanitizes, we
// validate at the route boundary too so we can reply 400 early and log
// traversal attempts. Without this, an attacker hitting the publicly
// reachable port 8080 (UPnP) could try paths like
// '../../Windows/System32/config/SAM' and waste server cycles before refusal.
function _safeOrReject(fileName, res) {
  const safe = safeBasename(fileName);
  if (!safe) {
    if (fileName) console.warn('[SEC] Rejected suspicious fileName: ' + JSON.stringify(fileName).slice(0, 120));
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'bad_filename' }));
    return null;
  }
  return safe;
}

// FFmpeg's subtitle seek does not consistently rebase mov_text/WebVTT times.
// Decode the whole text track, then map cues onto this response's video clock.
// This also preserves a cue spanning the seek point instead of dropping it.
function subtitleTimeline(offsetSeconds) {
  const offset = Math.max(0, Math.round(Number(offsetSeconds) * 1000) || 0);
  const decoder = new StringDecoder('utf8');
  let pending = '';
  const timing = /^((?:\d{2,}:)?\d{2}:\d{2}\.\d{3})\s+-->\s+((?:\d{2,}:)?\d{2}:\d{2}\.\d{3})([^\r\n]*)$/m;
  const millis = value => value.split(':').reduce((total, part) => total * 60 + Number(part), 0) * 1000;
  const stamp = value => {
    const ms = Math.max(0, Math.round(value));
    return String(Math.floor(ms / 3600000)).padStart(2, '0') + ':' +
      String(Math.floor(ms / 60000) % 60).padStart(2, '0') + ':' +
      String(Math.floor(ms / 1000) % 60).padStart(2, '0') + '.' + String(ms % 1000).padStart(3, '0');
  };
  function emitBlock(stream, block) {
    if (!block) return;
    const match = block.match(timing);
    if (!match) { stream.push(block + '\n\n'); return; }
    const end = millis(match[2]) - offset;
    if (end <= 0) return;
    const start = Math.max(0, millis(match[1]) - offset);
    stream.push(block.replace(timing, stamp(start) + ' --> ' + stamp(end) + match[3]) + '\n\n');
  }
  return new Transform({
    transform(chunk, encoding, callback) {
      pending += decoder.write(chunk);
      let boundary;
      while ((boundary = /\r?\n\r?\n/.exec(pending))) {
        emitBlock(this, pending.slice(0, boundary.index));
        pending = pending.slice(boundary.index + boundary[0].length);
      }
      callback();
    },
    flush(callback) {
      pending += decoder.end();
      emitBlock(this, pending.trimEnd());
      callback();
    }
  });
}

async function handleAsync(url, req, res) {
  if (url.pathname === '/api/stream/completed/list') {
    const disconnect = createDisconnectGuard(req, res);
    try {
      const records = await _ctx.getCompletedFiles({ signal: disconnect.signal, strict: true });
      if (disconnect.checkNow()) return true;
      // Keep filesystem paths internal: this public response historically
      // exposes only display metadata.
      const files = records.map(({ fileName, sizeMB, mtime }) => ({
        fileName,
        sizeMB,
        mtime,
      }));
      files.sort((a, b) => b.mtime - a.mtime);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(files));
    } catch(e) {
      if (disconnect.disconnected) return true;
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'library_unavailable', message: 'No se puede leer la carpeta de la biblioteca. Comprueba que está disponible e inténtalo de nuevo.' }));
    }
    return true;
  }

  if (url.pathname === '/api/stream/completed/info') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const disconnect = createDisconnectGuard(req, res);
    const resolved = await _ctx.resolveMediaFile(fileName, { signal: disconnect.signal });
    if (disconnect.checkNow()) return true;
    if (!resolved) { res.writeHead(404); res.end('{}'); return true; }
    let dur = 0;
    try {
      const probe = await probeMedia(resolved.filePath, disconnect.signal);
      dur = Number.parseFloat(probe.format && probe.format.duration) || 0;
    } catch (_) {}
    if (disconnect.checkNow()) return true;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fileName, estimatedTotalSec: Number.isFinite(dur) && dur > 0 ? Math.round(dur) : 0, durationKnown: Number.isFinite(dur) && dur > 0, isPartFile: !!resolved.isPartFile, partNum: resolved.isPartFile ? path.basename(resolved.filePath).replace('.part','') : null }));
    return true;
  }

  if (url.pathname === '/api/stream/tracks') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const disconnect = createDisconnectGuard(req, res);
    const resolved = await _ctx.resolveMediaFile(fileName, { signal: disconnect.signal });
    if (disconnect.checkNow()) return true;
    if (!resolved) { res.writeHead(404); res.end('{}'); return true; }
    try {
      const probe = await probeMedia(resolved.filePath, disconnect.signal);
      if (disconnect.checkNow()) return true;
      const audio = [], subtitles = [];
      (probe.streams || []).forEach(s => {
        if (s.codec_type === 'audio') audio.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', channels: s.channels || 0, title: (s.tags && (s.tags.title || s.tags.TITLE)) || '' });
        else if (s.codec_type === 'subtitle') subtitles.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', title: (s.tags && (s.tags.title || s.tags.TITLE)) || '', forced: s.disposition && s.disposition.forced === 1 });
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ audio, subtitles }));
    } catch(e) {
      if (disconnect.disconnected) return true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ audio: [], subtitles: [], error: e.message }));
    }
    return true;
  }

  if (url.pathname === '/api/stream/seek') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const seekTime = parseFloat(url.searchParams.get('time') || '0');
    const disconnect = createDisconnectGuard(req, res);
    const resolved = await _ctx.resolveMediaFile(fileName, { signal: disconnect.signal });
    if (disconnect.checkNow()) return true;
    if (!resolved) { res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' })); return true; }
    const PARTSIZE = 9728000;
    const fileSize = resolved.fileSize || 0;
    if (!fileSize || !resolved.isPartFile) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, seekTime, partFile: false, message: 'File complete, seek directly' }));
      return true;
    }
    const bytesPerSecond = fileSize / 7200;
    const seekBytes = Math.floor(seekTime * bytesPerSecond);
    const targetPart = Math.floor(seekBytes / PARTSIZE);
    if (_ctx.getSession() && resolved.hash) {
      const seekUrl = '?ses=' + _ctx.getSession() + '&w=transfer&op=streamseek&file=' + resolved.hash + '&part=' + targetPart;
      _ctx.emuleRequest(seekUrl, (err) => { if (err) console.log('[StreamSeek] Error:', err.message); });
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, seekTime, targetPart, totalParts: Math.ceil(fileSize / PARTSIZE), seekBytes, partFile: true }));
    return true;
  }

  if (url.pathname === '/api/stream/subtitle') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const trackIdx = parseInt(url.searchParams.get('track') || '0');
    const rawSubtitleSeek = Number(url.searchParams.get('ss') || 0);
    const subtitleSeek = Number.isFinite(rawSubtitleSeek) && rawSubtitleSeek > 0 ? rawSubtitleSeek : 0;
    let ffSub = null, timeline = null;
    const disconnect = createDisconnectGuard(req, res, () => {
      if (timeline) timeline.destroy();
      try { if (ffSub) ffSub.kill(); } catch (_) {}
    });
    try {
      const resolved = await _ctx.resolveMediaFile(fileName, { signal: disconnect.signal });
      if (disconnect.checkNow()) return true;
      if (!resolved) { res.writeHead(404); res.end('Not found'); return true; }
      const probe = await probeMedia(resolved.filePath, disconnect.signal);
      if (disconnect.checkNow()) return true;
      const subStreams = (probe.streams || []).filter(stream => stream.codec_type === 'subtitle');
      if (!Number.isInteger(trackIdx) || trackIdx < 0 || trackIdx >= subStreams.length) { res.writeHead(404); res.end('Track not found'); return true; }
      const subStream = subStreams[trackIdx];
      if (['dvd_subtitle','hdmv_pgs_subtitle','dvb_subtitle'].includes(subStream.codec_name || '')) {
        res.writeHead(400); res.end('Bitmap subtitles cannot be converted to WebVTT'); return true;
      }
      const subtitleArgs = ['-i', resolved.filePath, '-map', '0:' + subStream.index, '-f', 'webvtt', 'pipe:1'];
      const child = ffSub = spawnMedia(subtitleArgs);
      if (disconnect.checkNow()) {
        try { child.kill(); } catch (_) {}
        return true;
      }
      res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' });
      timeline = subtitleTimeline(subtitleSeek);
      child.stdout.pipe(timeline).pipe(res);
      child.stderr.on('data', () => {});
      child.once('error', () => { if (!res.writableEnded) res.end(); });
      child.on('close', () => { if (!res.writableEnded) res.end(); });
    } catch(e) {
      if (disconnect.disconnected) return true;
      if (!res.headersSent) res.writeHead(500);
      if (!res.writableEnded) res.end('Error extracting subtitle');
    }
    return true;
  }

  if (url.pathname.startsWith('/api/stream/completed/')) {
    // Endpoint format: /api/stream/completed/<urlEncodedFileName>
    let rawName;
    try { rawName = decodeURIComponent(url.pathname.replace('/api/stream/completed/', '')); }
    catch(e) { res.writeHead(400); res.end('Bad URL encoding'); return true; }
    const fileName = _safeOrReject(rawName, res);
    if (!fileName) return true;
    const streamKey = 'completed_' + fileName;
    let stopStream = null;
    // A disconnect during preparation must never replace another request's
    // stream; once registered, it stops only the stream this response owns.
    const disconnect = createDisconnectGuard(req, res, () => { if (stopStream) stopStream(); });
    const resolved = await _ctx.resolveMediaFile(fileName, { signal: disconnect.signal });
    if (disconnect.checkNow()) return true;
    if (!resolved) { res.writeHead(404); res.end('Not found'); return true; }
    const { filePath, isPartFile } = resolved;
    const quality = url.searchParams.get('q') || url.searchParams.get('quality') || 'auto';
    const seekSec = parseFloat(url.searchParams.get('ss')) || 0;
    const audioTrack = url.searchParams.get('audio');
    const subTrack = url.searchParams.get('sub');
    const presets = { 'auto': { scale: null, abr: '256k' }, '480p': { scale: '854:480', abr: '128k' }, '720p': { scale: '1280:720', abr: '192k' }, '1080p': { scale: '-2:1080', abr: '256k' }, 'original': { scale: null, abr: '256k' } };
    const q = presets[quality] || presets['auto'];

    // Probe codecs without blocking the request loop.
    let srcVideoCodec = '', srcAudioCodec = '', hasVideoStream = false;
    try {
      const probe = await probeMedia(filePath, disconnect.signal);
      const video = (probe.streams || []).find(stream => stream.codec_type === 'video');
      hasVideoStream = !!video;
      const audio = (probe.streams || []).find(stream => stream.codec_type === 'audio'
        && (!audioTrack || audioTrack === 'undefined' || String(stream.index) === audioTrack));
      srcVideoCodec = String(video && video.codec_name || '').toLowerCase();
      srcAudioCodec = String(audio && audio.codec_name || '').toLowerCase();
    } catch(e) {}
    if (disconnect.checkNow()) return true;

    const needsSubs = subTrack && subTrack !== '-1' && subTrack !== 'undefined';
    // Stream-copy seeks start at the preceding keyframe, so their zero clock
    // does not represent seekSec. Decode/discard preroll for an accurate seek;
    // the UI and external subtitles both rely on zero == requested offset.
    const canCopyVideo = srcVideoCodec === 'h264' && !q.scale && !needsSubs && seekSec === 0;
    const canCopyAudio = srcAudioCodec === 'aac' && seekSec === 0;
    console.log('[Stream] Codec: v=' + srcVideoCodec + ' a=' + srcAudioCodec + ' | Copy: v=' + canCopyVideo + ' a=' + canCopyAudio + ' | Part=' + isPartFile);

    // Single open + fstat on the descriptor: no stat/open race, and the same
    // probe detects both unreadable and locked files.
    try {
      const file = await fs.promises.open(filePath, 'r');
      let fileSize;
      try { fileSize = (await file.stat()).size; } finally { await file.close(); }
      if (disconnect.checkNow()) return true;
      // A complete clip can legitimately be only a few KiB. The buffering
      // threshold applies only to incomplete downloads, not valid short videos.
      if (fileSize === 0 || (isPartFile && fileSize < 5 * 1024 * 1024)) {
        res.writeHead(400); res.end(isPartFile ? 'Not enough partial data to stream' : 'File is empty'); return true;
      }
    } catch(e) {
      if (disconnect.disconnected) return true;
      if (e.code === 'EBUSY' || e.code === 'EPERM' || e.code === 'EACCES') { res.writeHead(503); res.end('File is locked by another process'); return true; }
      res.writeHead(500); res.end('Cannot read file'); return true;
    }

    if (!isPartFile && !hasVideoStream) {
      res.writeHead(415); res.end('No readable video stream found'); return true;
    }

    if (req.aborted || disconnect.checkNow()) return true;
    const transcodingMode = canCopyVideo
      ? 'copy'
      : (srcVideoCodec && /^(hevc|h265)$/i.test(srcVideoCodec) ? 'hevc-to-h264' : 'transcode');
    const responseHeaders = {
      'Content-Type': 'video/mp4',
      'Cache-Control': 'no-cache',
      'X-ESE-Transcoding': transcodingMode
    };
    // A metadata request must never launch, replace or cancel a media stream.
    // Browsers send this alongside GET to learn the transcoding mode.
    if (req.method === 'HEAD') {
      res.writeHead(200, responseHeaders);
      res.end();
      return true;
    }

    const ffArgs = ['-err_detect', 'ignore_err', '-fflags', '+genpts+igndts+discardcorrupt'];
    // v7.4.0 — reduced .part analyzeduration/probesize from 30s/50MB → 10s/20MB.
    // Previously, ffmpeg would spend the entire 30s dataTimeout window
    // analyzing the file before piping any frame, which caused the first
    // chunk to arrive AFTER the watchdog had already killed ffmpeg on HEVC
    // re-encode runs. Smaller probe = first byte sooner = player doesn't
    // bail. Trade-off: ffmpeg may miss some metadata, but for .part files
    // that's expected (the file is by definition incomplete).
    if (isPartFile) ffArgs.push('-analyzeduration', '10000000', '-probesize', '20000000', '-max_error_rate', '1.0');
    if (seekSec > 0) ffArgs.push('-ss', String(seekSec));
    ffArgs.push('-i', filePath, '-map', '0:v:0');
    if (audioTrack && audioTrack !== '' && audioTrack !== 'undefined') ffArgs.push('-map', '0:' + audioTrack + '?');
    else ffArgs.push('-map', '0:a:0?');
    if (canCopyVideo) {
      ffArgs.push('-c:v', 'copy');
    } else {
      ffArgs.push('-c:v', _ctx.HW_ENCODER, ..._ctx.HW_ENCODER_OPTS, '-pix_fmt', 'yuv420p');
      if (_ctx.HW_ENCODER === 'libx264') ffArgs.push('-profile:v', 'baseline', '-level', '3.1', '-threads', '2');
      const vfParts = [];
      if (q.scale) vfParts.push('scale=' + q.scale);
      if (needsSubs) {
        let ep = filePath.replace(/\\/g, '/').replace(/:/g, '\\:').replace(/'/g, "'\\\\''");
        vfParts.push("subtitles='" + ep + "':si=" + subTrack);
      }
      if (vfParts.length > 0) ffArgs.push('-vf', vfParts.join(','));
    }
    if (canCopyAudio) ffArgs.push('-c:a', 'copy');
    else ffArgs.push('-c:a', 'aac', '-b:a', q.abr, '-ac', '2');
    ffArgs.push('-movflags', 'frag_keyframe+empty_moov+default_base_moof', '-max_muxing_queue_size', '4096', '-frag_duration', '2000000', '-f', 'mp4', 'pipe:1');

    let currentSeekSec = seekSec, restartCount = 0, stopped = false;
    let currentProcess = null, dataTimeout = null, restartTimer = null, cpuFallbackUsed = false;
    const MAX_RESTARTS = 20;
    // Registry entries retain the public kill() contract used by cleanup.js,
    // but own a request, including delayed restarts, rather than just its child.
    const owner = { kill: signal => stop(signal) };
    const current = () => !stopped && _ctx.activeStreams[streamKey] === owner && !res.destroyed;
    function stop(signal) {
      if (stopped) return;
      stopped = true;
      if (dataTimeout) clearTimeout(dataTimeout);
      if (restartTimer) clearTimeout(restartTimer);
      dataTimeout = null; restartTimer = null;
      if (_ctx.activeStreams[streamKey] === owner) delete _ctx.activeStreams[streamKey];
      const child = currentProcess;
      currentProcess = null;
      if (child) { try { child.kill(signal); } catch (_) {} }
      if (!res.writableEnded && !res.destroyed) res.end();
    }
    const previous = _ctx.activeStreams[streamKey];
    if (previous) { try { previous.kill(); } catch (_) {} }
    _ctx.activeStreams[streamKey] = owner;
    stopStream = stop;
    res.writeHead(200, { ...responseHeaders, 'Transfer-Encoding': 'chunked' });

    const launchFfmpeg = (seekFrom) => {
      if (!current()) return;
      const currentArgs = [...ffArgs];
      const ssIdx = currentArgs.indexOf('-ss');
      if (ssIdx >= 0) currentArgs[ssIdx + 1] = String(seekFrom);
      else if (seekFrom > 0) { const iIdx = currentArgs.indexOf('-i'); currentArgs.splice(iIdx, 0, '-ss', String(seekFrom)); }
      const ff = spawnMedia(currentArgs);
      currentProcess = ff;
      const childIsCurrent = () => current() && currentProcess === ff;
      let gotData = false, lastErr = '';
      ff.stdout.on('data', chunk => {
        if (!childIsCurrent()) return;
        gotData = true;
        if (dataTimeout) { clearTimeout(dataTimeout); dataTimeout = null; }
        if (!res.writableEnded && !res.write(chunk)) ff.stdout.pause();
      });
      const onDrain = () => { if (childIsCurrent()) ff.stdout.resume(); };
      res.on('drain', onDrain);
      ff.stderr.on('data', data => {
        if (!childIsCurrent()) return;
        lastErr = data.toString().slice(-800);
        const match = lastErr.match(/time=(\d+):(\d+):(\d+)\.\d+/);
        if (match) currentSeekSec = seekFrom + Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3]);
      });
      ff.once('error', error => {
        if (!childIsCurrent()) return;
        console.warn('[Stream] Cannot start media process:', error.message);
        stop();
      });
      ff.once('close', async code => {
        res.removeListener('drain', onDrain);
        if (!childIsCurrent()) return;
        currentProcess = null;
        if (dataTimeout) { clearTimeout(dataTimeout); dataTimeout = null; }
        if (code && code !== 255) {
          const lines = lastErr.split('\n').filter(line => /error|invalid|cannot/i.test(line));
          console.log('[Stream] ffmpeg code=' + code + ' at ~' + Math.round(currentSeekSec) + 's: ' + lines.slice(0, 3).join(' | '));
        }
        if (!gotData && !cpuFallbackUsed && _ctx.HW_ENCODER !== 'libx264' && /Cannot load|No NVENC|InitializeEncoder|out of memory/.test(lastErr)) {
          cpuFallbackUsed = true;
          console.log('[Stream] GPU encoder failed, retrying with CPU...');
          const cpuArgs = ffArgs.map(arg => arg === _ctx.HW_ENCODER ? 'libx264' : arg).filter(arg => !_ctx.HW_ENCODER_OPTS.includes(arg));
          cpuArgs.splice(cpuArgs.indexOf('libx264') + 1, 0, '-preset', 'ultrafast', '-crf', '23', '-profile:v', 'baseline', '-level', '3.1', '-threads', '2');
          ffArgs.length = 0; ffArgs.push(...cpuArgs);
          launchFfmpeg(seekFrom);
          return;
        }
        if (isPartFile && gotData && restartCount < MAX_RESTARTS) {
          try {
            const currentSize = (await fs.promises.stat(filePath)).size;
            if (!current()) return;
            if (currentSize > currentSeekSec * 500000) {
              ++restartCount;
              console.log('[Stream] .part data exhausted at ~' + Math.round(currentSeekSec) + 's, waiting... (' + restartCount + '/' + MAX_RESTARTS + ')');
              restartTimer = setTimeout(async () => {
                restartTimer = null;
                if (!current()) return;
                try {
                  const stat = await fs.promises.stat(filePath);
                  if (!current()) return;
                  if (stat.size > currentSize) launchFfmpeg(currentSeekSec);
                  else stop();
                } catch (_) { if (current()) stop(); }
              }, 15000);
              return;
            }
          } catch (_) {}
        }
        if (current()) stop();
      });
      // v7.4.0 — .part needs longer dataTimeout because HEVC→H264 re-encode
      // (Interstellar etc.) routinely takes 30-50s to emit the first frame
      // when buffered data is still light. Completed files stay at 30s.
      const timeoutMs = isPartFile ? 60000 : 30000;
      dataTimeout = setTimeout(() => {
        if (!gotData && childIsCurrent()) {
          console.log('[Stream] No data from ffmpeg after ' + timeoutMs / 1000 + 's, killing');
          stop();
        }
      }, timeoutMs);
    };
    launchFfmpeg(seekSec);
    return true;
  }

  return false;
}

function handle(url, req, res) {
  if (!url.pathname.startsWith('/api/stream/completed/')
      && !['/api/stream/tracks', '/api/stream/seek', '/api/stream/subtitle'].includes(url.pathname)) return false;
  handleAsync(url, req, res).catch(error => {
    console.error('[stream] async route failed:', error && error.message ? error.message : error);
    if (res.destroyed || res.writableEnded) return;
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'stream_route_failed' }));
    } else {
      res.destroy(error);
    }
  });
  return true;
}

module.exports = { init, handle, _test: { probeMedia, subtitleTimeline } };
