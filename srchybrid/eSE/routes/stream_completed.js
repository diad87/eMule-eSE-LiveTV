'use strict';
const fs   = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');
const { safeBasename } = require('../utils');

let _ctx = {};

function init(ctx) { _ctx = ctx; }

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
    try {
      const files = fs.readdirSync(_ctx.EMULE_INCOMING)
        .filter(f => /\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i.test(f))
        .map(f => { const stat = fs.statSync(path.join(_ctx.EMULE_INCOMING, f)); return { fileName: f, sizeMB: Math.round(stat.size / (1024 * 1024)), mtime: stat.mtimeMs }; })
        .sort((a, b) => b.mtime - a.mtime);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(files));
    } catch(e) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('[]'); }
    return true;
  }

  if (url.pathname === '/api/stream/completed/info') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const resolved = _ctx.resolveMediaFile(fileName);
    if (!resolved) { res.writeHead(404); res.end('{}'); return true; }
    const dur = _ctx.getDuration(resolved.filePath);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ fileName, estimatedTotalSec: Math.round(dur) || 7200, isPartFile: !!resolved.isPartFile, partNum: resolved.isPartFile ? path.basename(resolved.filePath).replace('.part','') : null }));
    return true;
  }

  if (url.pathname === '/api/stream/tracks') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const resolved = _ctx.resolveMediaFile(fileName);
    if (!resolved) { res.writeHead(404); res.end('{}'); return true; }
    const ffprobePath = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
    try {
      const probeOut = execSync('"' + ffprobePath + '" -v quiet -print_format json -show_streams "' + resolved.filePath + '"', { timeout: 15000 }).toString();
      const probe = JSON.parse(probeOut);
      const audio = [], subtitles = [];
      (probe.streams || []).forEach(s => {
        if (s.codec_type === 'audio') audio.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', channels: s.channels || 0, title: (s.tags && (s.tags.title || s.tags.TITLE)) || '' });
        else if (s.codec_type === 'subtitle') subtitles.push({ index: s.index, lang: (s.tags && (s.tags.language || s.tags.LANGUAGE)) || 'und', codec: s.codec_name || '', title: (s.tags && (s.tags.title || s.tags.TITLE)) || '', forced: s.disposition && s.disposition.forced === 1 });
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ audio, subtitles }));
    } catch(e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ audio: [], subtitles: [], error: e.message }));
    }
    return true;
  }

  if (url.pathname === '/api/stream/seek') {
    const fileName = _safeOrReject(url.searchParams.get('name'), res);
    if (!fileName) return true;
    const seekTime = parseFloat(url.searchParams.get('time') || '0');
    const resolved = _ctx.resolveMediaFile(fileName);
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
    const resolved = _ctx.resolveMediaFile(fileName);
    if (!resolved) { res.writeHead(404); res.end('Not found'); return true; }
    const ffprobePath = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
    try {
      const probeOut = execSync('"' + ffprobePath + '" -v quiet -print_format json -show_streams -select_streams s "' + resolved.filePath + '"', { timeout: 15000 }).toString();
      const subStreams = JSON.parse(probeOut).streams || [];
      if (trackIdx >= subStreams.length) { res.writeHead(404); res.end('Track not found'); return true; }
      const subStream = subStreams[trackIdx];
      if (['dvd_subtitle','hdmv_pgs_subtitle','dvb_subtitle'].includes(subStream.codec_name || '')) {
        res.writeHead(400); res.end('Bitmap subtitles cannot be converted to WebVTT'); return true;
      }
      const ffSub = spawn(_ctx.FFMPEG_PATH, ['-i', resolved.filePath, '-map', '0:' + subStream.index, '-f', 'webvtt', 'pipe:1']);
      res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' });
      ffSub.stdout.pipe(res);
      ffSub.stderr.on('data', () => {});
      ffSub.on('close', () => { if (!res.writableEnded) res.end(); });
      req.on('close', () => { ffSub.kill(); });
    } catch(e) {
      res.writeHead(500); res.end('Error extracting subtitle');
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
    const resolved = _ctx.resolveMediaFile(fileName);
    if (!resolved) { res.writeHead(404); res.end('Not found'); return true; }
    const { filePath, isPartFile } = resolved;
    const quality = url.searchParams.get('q') || 'auto';
    const seekSec = parseFloat(url.searchParams.get('ss')) || 0;
    const audioTrack = url.searchParams.get('audio');
    const subTrack = url.searchParams.get('sub');
    const presets = { 'auto': { scale: null, abr: '256k' }, '480p': { scale: '854:480', abr: '128k' }, '720p': { scale: '1280:720', abr: '192k' }, '1080p': { scale: '-2:1080', abr: '256k' }, 'original': { scale: null, abr: '256k' } };
    const q = presets[quality] || presets['auto'];

    // Probe codec
    let srcVideoCodec = '', srcAudioCodec = '';
    try {
      const fp = _ctx.FFMPEG_PATH.replace(/ffmpeg(\.exe)?$/, 'ffprobe$1');
      srcVideoCodec = execSync('"' + fp + '" -v quiet -select_streams v:0 -show_entries stream=codec_name -of csv=p=0 "' + filePath + '"', { timeout: 5000 }).toString().trim().split('\n')[0].trim().toLowerCase();
      srcAudioCodec = execSync('"' + fp + '" -v quiet -select_streams a:0 -show_entries stream=codec_name -of csv=p=0 "' + filePath + '"', { timeout: 5000 }).toString().trim().split('\n')[0].trim().toLowerCase();
    } catch(e) {}

    const canCopyVideo = srcVideoCodec === 'h264' && !q.scale;
    const canCopyAudio = srcAudioCodec === 'aac';
    const needsSubs = subTrack && subTrack !== '-1' && subTrack !== 'undefined';
    console.log('[Stream] Codec: v=' + srcVideoCodec + ' a=' + srcAudioCodec + ' | Copy: v=' + canCopyVideo + ' a=' + canCopyAudio + ' | Part=' + isPartFile);

    // Open once, then stat the handle. Avoids the TOCTOU window between
    // fs.statSync(path) and fs.openSync(path) (CodeQL js/file-system-race #46).
    {
      let fd;
      try { fd = fs.openSync(filePath, 'r'); }
      catch (e) { res.writeHead(503); res.end('File is locked by another process'); return true; }
      let size = 0;
      try { size = fs.fstatSync(fd).size; }
      catch (e) { try { fs.closeSync(fd); } catch (ignored) {} res.writeHead(500); res.end('Cannot read file'); return true; }
      try { fs.closeSync(fd); } catch (ignored) {}
      if (size < 5 * 1024 * 1024) { res.writeHead(400); res.end('File too small to stream'); return true; }
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
        // The first replace already removes every backslash (Windows path → POSIX),
        // so the subsequent `'` → `'\\''` shell-style escape can't leave a dangling
        // backslash. CodeQL js/incomplete-sanitization #31 is a false positive here;
        // kept the form because ffmpeg's libavfilter parses this exact escape.
        let ep = filePath.replace(/\\/g, '/').replace(/:/g, '\\:').replace(/'/g, "'\\\\''");
        vfParts.push("subtitles='" + ep + "':si=" + subTrack);
      }
      if (vfParts.length > 0) ffArgs.push('-vf', vfParts.join(','));
    }
    if (canCopyAudio) ffArgs.push('-c:a', 'copy');
    else ffArgs.push('-c:a', 'aac', '-b:a', q.abr, '-ac', '2');
    ffArgs.push('-movflags', 'frag_keyframe+empty_moov+default_base_moof', '-max_muxing_queue_size', '4096', '-frag_duration', '2000000', '-f', 'mp4', 'pipe:1');

    const streamKey = 'completed_' + fileName;
    if (_ctx.activeStreams[streamKey]) { _ctx.activeStreams[streamKey].kill(); delete _ctx.activeStreams[streamKey]; }
    let currentSeekSec = seekSec, totalBytesSent = 0, restartCount = 0, clientDisconnected = false;
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
      const currentArgs = [...ffArgs];
      const ssIdx = currentArgs.indexOf('-ss');
      if (ssIdx >= 0) currentArgs[ssIdx + 1] = String(seekFrom);
      else if (seekFrom > 0) { const iIdx = currentArgs.indexOf('-i'); currentArgs.splice(iIdx, 0, '-ss', String(seekFrom)); }
      const ff = spawn(_ctx.FFMPEG_PATH, currentArgs);
      _ctx.activeStreams[streamKey] = ff;
      let gotData = false, dataTimeout = null, lastErr = '';
      ff.stdout.on('data', (chunk) => {
        gotData = true; totalBytesSent += chunk.length;
        if (dataTimeout) { clearTimeout(dataTimeout); dataTimeout = null; }
        if (!res.writableEnded && !clientDisconnected) res.write(chunk);
      });
      ff.stderr.on('data', (d) => {
        lastErr = d.toString().slice(-800);
        const m = lastErr.match(/time=(\d+):(\d+):(\d+)\.\d+/);
        if (m) currentSeekSec = seekFrom + parseInt(m[1])*3600 + parseInt(m[2])*60 + parseInt(m[3]);
      });
      ff.on('close', (code) => {
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
        if (isPartFile && gotData && !clientDisconnected && restartCount < MAX_RESTARTS) {
          try {
            const currentSize = fs.statSync(filePath).size;
            if (currentSize > currentSeekSec * 500000) {
              restartCount++;
              console.log('[Stream] .part data exhausted at ~' + Math.round(currentSeekSec) + 's, waiting... (' + restartCount + '/' + MAX_RESTARTS + ')');
              setTimeout(() => {
                if (!clientDisconnected && !res.writableEnded) {
                  const newSize = fs.statSync(filePath).size;
                  if (newSize > currentSize) { launchFfmpeg(currentSeekSec); }
                  else { delete _ctx.activeStreams[streamKey]; if (!res.writableEnded) res.end(); }
                }
              }, 15000);
              return;
            }
          } catch(e) {}
        }
        delete _ctx.activeStreams[streamKey];
        if (!res.writableEnded) res.end();
      });
      // v7.4.0 — .part needs longer dataTimeout because HEVC→H264 re-encode
      // (Interstellar etc.) routinely takes 30-50s to emit the first frame
      // when buffered data is still light. Completed files stay at 30s.
      const DATA_TIMEOUT_MS = isPartFile ? 60000 : 30000;
      dataTimeout = setTimeout(() => {
        if (!gotData && _ctx.activeStreams[streamKey]) {
          console.log('[Stream] No data from ffmpeg after ' + (DATA_TIMEOUT_MS / 1000) + 's, killing');
          _ctx.activeStreams[streamKey].kill();
          delete _ctx.activeStreams[streamKey];
        }
      }, DATA_TIMEOUT_MS);
    };

    launchFfmpeg(seekSec);
    req.on('close', () => { clientDisconnected = true; if (_ctx.activeStreams[streamKey]) { _ctx.activeStreams[streamKey].kill(); delete _ctx.activeStreams[streamKey]; } });
    return true;
  }

  return false;
}

module.exports = { init, handle };
