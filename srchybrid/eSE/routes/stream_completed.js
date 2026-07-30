'use strict';
const fs   = require('fs');
const path = require('path');
const {
  runProcess,
  spawnManaged,
} = require('../bounded_process_runner');
const { safeBasename } = require('../utils');

let _ctx = {};

function init(ctx) { _ctx = ctx; }

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

function handle(url, req, res) {
  if (!url.pathname.startsWith('/api/stream/')) return false;

  if (url.pathname === '/api/stream/completed/list') {
    fs.promises.readdir(_ctx.EMULE_INCOMING).then(async names => {
      const files = await Promise.all(
        names
          .filter(f => /\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i.test(f))
          .map(async fileName => {
            const stat = await fs.promises.stat(path.join(_ctx.EMULE_INCOMING, fileName));
            return {
              fileName,
              sizeMB: Math.round(stat.size / (1024 * 1024)),
              mtime: stat.mtimeMs,
            };
          }),
      );
      files.sort((a, b) => b.mtime - a.mtime);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(files));
    }).catch(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('[]');
    });
    return true;
  }

  if (url.pathname === '/api/stream/completed/info') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const disconnect = createDisconnectGuard(req, res);
    void (async () => {
      const resolved = await _ctx.resolveMediaFile(fileName);
      if (disconnect.checkNow()) return;
      if (!resolved) { res.writeHead(404); res.end('{}'); return; }
      let dur = 0;
      try { dur = await _ctx.getDuration(resolved.filePath); } catch (_) {}
      if (disconnect.checkNow()) return;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ fileName, estimatedTotalSec: Math.round(dur) || 7200, isPartFile: !!resolved.isPartFile, partNum: resolved.isPartFile ? path.basename(resolved.filePath).replace('.part','') : null }));
    })().catch(error => {
      if (!disconnect.disconnected) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: error.message }));
      }
    });
    return true;
  }

  if (url.pathname === '/api/stream/tracks') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const disconnect = createDisconnectGuard(req, res);
    void (async () => {
      const resolved = await _ctx.resolveMediaFile(fileName);
      if (disconnect.checkNow()) return;
      if (!resolved) { res.writeHead(404); res.end('{}'); return; }
      const ffprobePath = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
      const result = await runProcess(
        ffprobePath,
        ['-v', 'quiet', '-print_format', 'json', '-show_streams', resolved.filePath],
        { timeoutMs: 15000, maxOutputBytes: 2 * 1024 * 1024, signal: disconnect.signal },
      );
      if (disconnect.checkNow()) return;
      if (!result.ok) throw new Error(result.error || result.stderr || 'ffprobe failed');
      const probe = JSON.parse(result.stdout);
      const audio = [], subtitles = [];
      (probe.streams || []).forEach(s => {
        if (s.codec_type === 'audio') audio.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', channels: s.channels || 0, title: (s.tags && (s.tags.title || s.tags.TITLE)) || '' });
        else if (s.codec_type === 'subtitle') subtitles.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', title: (s.tags && (s.tags.title || s.tags.TITLE)) || '', forced: s.disposition && s.disposition.forced === 1 });
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ audio, subtitles }));
    })().catch(e => {
      if (!disconnect.disconnected) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ audio: [], subtitles: [], error: e.message }));
      }
    });
    return true;
  }

  if (url.pathname === '/api/stream/seek') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const seekTime = parseFloat(url.searchParams.get('time') || '0');
    const disconnect = createDisconnectGuard(req, res);
    void (async () => {
    const resolved = await _ctx.resolveMediaFile(fileName);
    if (disconnect.checkNow()) return;
    if (!resolved) { res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' })); return; }
    const PARTSIZE = 9728000;
    const fileSize = resolved.fileSize || 0;
    if (!fileSize || !resolved.isPartFile) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, seekTime, partFile: false, message: 'File complete, seek directly' }));
      return;
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
    })().catch(error => {
      if (!disconnect.disconnected) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: error.message }));
      }
    });
    return true;
  }

  if (url.pathname === '/api/stream/subtitle') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const trackIdx = parseInt(url.searchParams.get('track') || '0');
    let ffSub = null;
    const disconnect = createDisconnectGuard(req, res, () => {
      try { if (ffSub) ffSub.kill(); } catch (_) {}
    });
    void (async () => {
      const resolved = await _ctx.resolveMediaFile(fileName);
      if (disconnect.checkNow()) return;
      if (!resolved) { res.writeHead(404); res.end('Not found'); return; }
      const ffprobePath = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
      const result = await runProcess(
        ffprobePath,
        ['-v', 'quiet', '-print_format', 'json', '-show_streams', '-select_streams', 's', resolved.filePath],
        { timeoutMs: 15000, maxOutputBytes: 2 * 1024 * 1024, signal: disconnect.signal },
      );
      if (disconnect.checkNow()) return;
      if (!result.ok) throw new Error(result.error || result.stderr || 'ffprobe failed');
      const subStreams = JSON.parse(result.stdout).streams || [];
      if (trackIdx >= subStreams.length) { res.writeHead(404); res.end('Track not found'); return true; }
      const subStream = subStreams[trackIdx];
      if (['dvd_subtitle','hdmv_pgs_subtitle','dvb_subtitle'].includes(subStream.codec_name || '')) {
        res.writeHead(400); res.end('Bitmap subtitles cannot be converted to WebVTT'); return true;
      }
      ffSub = spawnManaged(_ctx.FFMPEG_PATH, ['-i', resolved.filePath, '-map', '0:' + subStream.index, '-f', 'webvtt', 'pipe:1']);
      if (disconnect.checkNow()) {
        ffSub.kill();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' });
      ffSub.stdout.pipe(res);
      ffSub.stderr.on('data', () => {});
      ffSub.on('close', () => { if (!res.writableEnded) res.end(); });
    })().catch(() => {
      if (!disconnect.disconnected) {
        res.writeHead(500); res.end('Error extracting subtitle');
      }
    });
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
    let ownedProcess = null;
    const disconnect = createDisconnectGuard(req, res, () => {
      try { if (ownedProcess) ownedProcess.kill(); } catch (_) {}
      if (_ctx.activeStreams[streamKey] === ownedProcess) {
        delete _ctx.activeStreams[streamKey];
      }
    });
    void (async () => {
    const resolved = await _ctx.resolveMediaFile(fileName);
    if (disconnect.checkNow()) return;
    if (!resolved) { res.writeHead(404); res.end('Not found'); return; }
    const { filePath, isPartFile } = resolved;
    const quality = url.searchParams.get('q') || 'auto';
    const seekSec = parseFloat(url.searchParams.get('ss')) || 0;
    const audioTrack = url.searchParams.get('audio');
    const subTrack = url.searchParams.get('sub');
    const presets = { 'auto': { scale: null, abr: '256k' }, '480p': { scale: '854:480', abr: '128k' }, '720p': { scale: '1280:720', abr: '192k' }, '1080p': { scale: '-2:1080', abr: '256k' }, 'original': { scale: null, abr: '256k' } };
    const q = presets[quality] || presets['auto'];

    // Probe codecs without blocking the request loop.
    const fp = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
    const [videoProbe, audioProbe] = await Promise.all([
      runProcess(
        fp,
        ['-v', 'quiet', '-select_streams', 'v:0', '-show_entries', 'stream=codec_name', '-of', 'csv=p=0', filePath],
        { timeoutMs: 5000, maxOutputBytes: 64 * 1024, signal: disconnect.signal },
      ),
      runProcess(
        fp,
        ['-v', 'quiet', '-select_streams', 'a:0', '-show_entries', 'stream=codec_name', '-of', 'csv=p=0', filePath],
        { timeoutMs: 5000, maxOutputBytes: 64 * 1024, signal: disconnect.signal },
      ),
    ]);
    if (disconnect.checkNow()) return;
    const srcVideoCodec = videoProbe.ok
      ? videoProbe.stdout.trim().split('\n')[0].trim().toLowerCase()
      : '';
    const srcAudioCodec = audioProbe.ok
      ? audioProbe.stdout.trim().split('\n')[0].trim().toLowerCase()
      : '';

    const canCopyVideo = srcVideoCodec === 'h264' && !q.scale;
    const canCopyAudio = srcAudioCodec === 'aac';
    const needsSubs = subTrack && subTrack !== '-1' && subTrack !== 'undefined';
    console.log('[Stream] Codec: v=' + srcVideoCodec + ' a=' + srcAudioCodec + ' | Copy: v=' + canCopyVideo + ' a=' + canCopyAudio + ' | Part=' + isPartFile);

    // Single open + fstat on the descriptor: no stat/open race, and the same
    // probe detects both unreadable and locked files.
    try {
      const file = await fs.promises.open(filePath, 'r');
      let fileSize;
      try { fileSize = (await file.stat()).size; } finally { await file.close(); }
      if (disconnect.checkNow()) return;
      if (fileSize < 5 * 1024 * 1024) { res.writeHead(400); res.end('File too small to stream'); return true; }
    } catch(e) {
      if (disconnect.disconnected) return;
      if (e.code === 'EBUSY' || e.code === 'EPERM' || e.code === 'EACCES') { res.writeHead(503); res.end('File is locked by another process'); return true; }
      res.writeHead(500); res.end('Cannot read file'); return true;
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

    if (_ctx.activeStreams[streamKey]) { _ctx.activeStreams[streamKey].kill(); delete _ctx.activeStreams[streamKey]; }
    let currentSeekSec = seekSec, totalBytesSent = 0, restartCount = 0;
    const MAX_RESTARTS = 20;
    // v7.4.0 — expose transcoding mode so the client can show a friendlier
    // "transcodificando HEVC, hasta 60s" hint instead of a generic spinner.
    const transcodingMode = canCopyVideo
      ? 'copy'
      : (srcVideoCodec && /^(hevc|h265)$/i.test(srcVideoCodec) ? 'hevc-to-h264' : 'transcode');
    res.writeHead(200, {
      'Content-Type': 'video/mp4',
      'Transfer-Encoding': 'chunked',
      'Cache-Control': 'no-cache',
      'X-ESE-Transcoding': transcodingMode
    });

    const launchFfmpeg = (seekFrom) => {
      if (disconnect.checkNow()) return;
      const currentArgs = [...ffArgs];
      const ssIdx = currentArgs.indexOf('-ss');
      if (ssIdx >= 0) currentArgs[ssIdx + 1] = String(seekFrom);
      else if (seekFrom > 0) { const iIdx = currentArgs.indexOf('-i'); currentArgs.splice(iIdx, 0, '-ss', String(seekFrom)); }
      const ff = spawnManaged(_ctx.FFMPEG_PATH, currentArgs);
      ownedProcess = ff;
      _ctx.activeStreams[streamKey] = ff;
      if (disconnect.checkNow()) {
        ff.kill();
        if (_ctx.activeStreams[streamKey] === ff) delete _ctx.activeStreams[streamKey];
        return;
      }
      let gotData = false, dataTimeout = null, lastErr = '';
      ff.stdout.on('data', (chunk) => {
        gotData = true; totalBytesSent += chunk.length;
        if (dataTimeout) { clearTimeout(dataTimeout); dataTimeout = null; }
        if (!res.writableEnded && !disconnect.disconnected) res.write(chunk);
      });
      ff.stderr.on('data', (d) => {
        lastErr = d.toString().slice(-800);
        const m = lastErr.match(/time=(\d+):(\d+):(\d+)\.\d+/);
        if (m) currentSeekSec = seekFrom + parseInt(m[1])*3600 + parseInt(m[2])*60 + parseInt(m[3]);
      });
      ff.on('close', async (code) => {
        if (dataTimeout) clearTimeout(dataTimeout);
        if (code && code !== 0 && code !== 255) {
          const errLines = lastErr.split('\n').filter(l => /error|invalid|cannot/i.test(l));
          console.log('[Stream] ffmpeg code=' + code + ' at ~' + Math.round(currentSeekSec) + 's: ' + errLines.slice(0,3).join(' | '));
        }
        if (!gotData && _ctx.HW_ENCODER !== 'libx264' && /Cannot load|No NVENC|InitializeEncoder|out of memory/.test(lastErr)) {
          console.log('[Stream] GPU encoder failed, retrying with CPU...');
          const cpuArgs = ffArgs.map(a => a === _ctx.HW_ENCODER ? 'libx264' : a).filter(a => !_ctx.HW_ENCODER_OPTS.includes(a));
          cpuArgs.splice(cpuArgs.indexOf('libx264') + 1, 0, '-preset', 'ultrafast', '-crf', '23', '-profile:v', 'baseline', '-level', '3.1', '-threads', '2');
          ffArgs.length = 0; ffArgs.push(...cpuArgs);
          launchFfmpeg(seekFrom); return;
        }
        if (isPartFile && gotData && !disconnect.disconnected && restartCount < MAX_RESTARTS) {
          try {
            const currentSize = (await fs.promises.stat(filePath)).size;
            if (currentSize > currentSeekSec * 500000) {
              restartCount++;
              console.log('[Stream] .part data exhausted at ~' + Math.round(currentSeekSec) + 's, waiting... (' + restartCount + '/' + MAX_RESTARTS + ')');
              setTimeout(async () => {
                try {
                  if (!disconnect.disconnected && !res.writableEnded) {
                    const newSize = (await fs.promises.stat(filePath)).size;
                    if (newSize > currentSize) { launchFfmpeg(currentSeekSec); }
                    else {
                      if (_ctx.activeStreams[streamKey] === ff) delete _ctx.activeStreams[streamKey];
                      if (!res.writableEnded) res.end();
                    }
                  }
                } catch (_) {
                  if (_ctx.activeStreams[streamKey] === ff) delete _ctx.activeStreams[streamKey];
                  if (!res.writableEnded) res.end();
                }
              }, 15000);
              return;
            }
          } catch(e) {}
        }
        if (_ctx.activeStreams[streamKey] === ff) delete _ctx.activeStreams[streamKey];
        if (!res.writableEnded) res.end();
      });
      // v7.4.0 — .part needs longer dataTimeout because HEVC→H264 re-encode
      // (Interstellar etc.) routinely takes 30-50s to emit the first frame
      // when buffered data is still light. Completed files stay at 30s.
      const DATA_TIMEOUT_MS = isPartFile ? 60000 : 30000;
      dataTimeout = setTimeout(() => {
        if (!gotData && _ctx.activeStreams[streamKey] === ff) {
          console.log('[Stream] No data from ffmpeg after ' + (DATA_TIMEOUT_MS / 1000) + 's, killing');
          ff.kill();
          delete _ctx.activeStreams[streamKey];
        }
      }, DATA_TIMEOUT_MS);
    };

    launchFfmpeg(seekSec);
    })().catch(error => {
      console.warn('[Stream] Async preparation failed:', error.message);
      if (!disconnect.disconnected) {
        if (!res.headersSent) res.writeHead(500);
        if (!res.writableEnded) res.end('Cannot prepare stream');
      }
    });
    return true;
  }

  return false;
}

module.exports = { init, handle };
