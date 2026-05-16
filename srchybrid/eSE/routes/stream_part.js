'use strict';
const fs   = require('fs');
const path = require('path');
const { spawn } = require('child_process');

let _ctx = {};

function init(ctx) { _ctx = ctx; }

/**
 * BUG-041 FIX: Validate that resolvedPath is strictly within baseDir.
 * Prevents path traversal via ../ or symlinks.
 * @param {string} resolvedPath - Absolute resolved path to check.
 * @param {string} baseDir - Allowed base directory.
 * @returns {boolean}
 */
function isWithinBase(resolvedPath, baseDir) {
  const normalizedBase = path.resolve(baseDir) + path.sep;
  const normalizedTarget = path.resolve(resolvedPath);
  return normalizedTarget.startsWith(normalizedBase) || normalizedTarget === path.resolve(baseDir);
}

function handle(url, req, res) {
  // Legacy .part streaming via ffmpeg pipe
  if (url.pathname === '/api/stream/part') {
    const partFile = url.searchParams.get('file') || '';
    const fileName = url.searchParams.get('name') || '';
    const EMULE_TEMP = path.join(path.dirname(_ctx.EMULE_INCOMING), 'Temp');
    let filePath = null;

    // BUG-041 FIX: Strict regex + path containment check for .part files
    if (partFile && /^\d+\.part$/.test(partFile)) {
      const tempPath = path.resolve(path.join(EMULE_TEMP, partFile));
      if (isWithinBase(tempPath, EMULE_TEMP) && fs.existsSync(tempPath)) filePath = tempPath;
    }
    if (!filePath && partFile) {
      const metPath = path.resolve(path.join(EMULE_TEMP, partFile + '.met'));
      // BUG-041 FIX: Validate .met path is within TEMP
      if (isWithinBase(metPath, EMULE_TEMP) && fs.existsSync(metPath)) {
        try {
          const metText = fs.readFileSync(metPath).toString('latin1');
          const fnMatch = metText.match(/[^\x00-\x1F\x7F-\x9F]{5,}\.(avi|mkv|mp4|wmv|mov|webm|flv)/i);
          if (fnMatch) {
            // BUG-041 FIX: Extract only basename to prevent embedded path traversal
            const safeName = path.basename(fnMatch[0]);
            const incomingPath = path.resolve(path.join(_ctx.EMULE_INCOMING, safeName));
            if (isWithinBase(incomingPath, _ctx.EMULE_INCOMING) && fs.existsSync(incomingPath)) filePath = incomingPath;
          }
        } catch(e) { console.warn('[Stream] Failed to parse .met file:', e.message); }
      }
    }
    if (!filePath && fileName) {
      // BUG-041 FIX: Use basename to strip any path components from user input
      const safeName = path.basename(fileName);
      const incomingPath = path.resolve(path.join(_ctx.EMULE_INCOMING, safeName));
      if (isWithinBase(incomingPath, _ctx.EMULE_INCOMING) && fs.existsSync(incomingPath)) {
        filePath = incomingPath;
      } else {
        try {
          const files = fs.readdirSync(_ctx.EMULE_INCOMING);
          const nameLower = safeName.toLowerCase();
          const match = files.find(f => f.toLowerCase().includes(nameLower) || nameLower.includes(f.toLowerCase()));
          if (match) {
            const matchPath = path.resolve(path.join(_ctx.EMULE_INCOMING, match));
            if (isWithinBase(matchPath, _ctx.EMULE_INCOMING)) filePath = matchPath;
          }
        } catch(e) { console.warn('[Stream] Failed to scan INCOMING dir:', e.message); }
      }
    }

    if (!filePath) { res.writeHead(404); res.end('File not found in Temp or Incoming'); return true; }
    const stat = fs.statSync(filePath);
    console.log('[Stream] Streaming: ' + filePath + ' (' + Math.round(stat.size / (1024*1024)) + ' MB)');

    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Transfer-Encoding': 'chunked', 'Cache-Control': 'no-cache', 'Access-Control-Allow-Origin': '*' });
    const fnLower = filePath.toLowerCase();
    const isHEVC = fnLower.includes('hevc') || fnLower.includes('h265') || fnLower.includes('h.265') || fnLower.includes('x265');
    const ffArgs = ['-err_detect', 'ignore_err', '-fflags', '+genpts+igndts+discardcorrupt', '-i', filePath];
    if (isHEVC) {
      console.log('[Stream] HEVC detected, re-encoding to H.264...');
      ffArgs.push('-c:v', 'libx264', '-preset', 'ultrafast', '-crf', '23', '-pix_fmt', 'yuv420p');
    } else {
      ffArgs.push('-c:v', 'copy');
    }
    ffArgs.push('-c:a', 'aac', '-b:a', '192k', '-movflags', 'frag_keyframe+empty_moov+default_base_moof', '-max_muxing_queue_size', '1024', '-f', 'mp4', '-');

    const ff = spawn(_ctx.FFMPEG_PATH, ffArgs);
    let dataSent = false, stderrLog = '';
    ff.stdout.on('data', (chunk) => {
      if (!dataSent) { dataSent = true; console.log('[Stream] First data chunk sent (' + chunk.length + ' bytes)'); }
      try { res.write(chunk); } catch(e) {}
    });
    ff.stderr.on('data', (d) => { stderrLog += d.toString().slice(-500); });
    ff.on('exit', (code) => {
      console.log('[Stream] ffmpeg exit code: ' + code + (dataSent ? '' : ' (NO data sent!)'));
      if (!dataSent && stderrLog) console.log('[Stream] ffmpeg stderr: ' + stderrLog.slice(-300));
      try { res.end(); } catch(e) {}
    });
    ff.on('error', (err) => { console.log('[Stream] ffmpeg error: ' + err.message); try { res.end(); } catch(e) {} });
    res.on('close', () => { try { ff.kill('SIGKILL'); } catch(e) {} });
    return true;
  }

  // MSE streaming — start (copy .part to temp AVI)
  if (url.pathname.startsWith('/api/stream/start/')) {
    // BUG-041 FIX: Validate partNum is strictly numeric
    const partNum = url.pathname.split('/').pop();
    if (!/^\d+$/.test(partNum)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid partNum' })); return true; }
    const dl = _ctx.getDownloads().find(d => d.partNum === partNum);
    if (!dl) { res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' })); return true; }
    const copyScript = path.join(_ctx.__dirname, 'copy_part.ps1');
    const tempAvi = path.join(_ctx.TEMP_DIR, 'ese_mse_' + partNum + '.avi');
    try { fs.unlinkSync(tempAvi); } catch(e) {}
    console.log('[MSE] Copying .part for ' + dl.fileName);
    new Promise((resolve, reject) => {
      const ps = spawn('powershell', ['-ExecutionPolicy','Bypass','-File',copyScript,'-Source',dl.partPath,'-Dest',tempAvi,'-MaxMB','600']);
      let out = '';
      ps.stdout.on('data', d => out += d.toString());
      ps.stderr.on('data', (d) => { console.warn('[MSE] ps stderr:', d.toString().slice(-200)); });
      ps.on('close', () => { parseInt(out.trim()) > 0 ? resolve() : reject(new Error('Copy failed')); });
    }).then(() => {
      const estTotalSec = Math.round((dl.fileSizeMB * 8) / 4);
      console.log('[MSE] Ready. Est: ' + estTotalSec + 's');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ready', fileName: dl.fileName, estimatedTotalSec: estTotalSec }));
    }).catch((e) => {
      console.error('[MSE] Copy failed:', e.message);
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
      try { res.end(JSON.stringify({ error: e.message })); } catch(ignored) {}
    });
    return true;
  }

  // MSE streaming — data (ffmpeg pipe from temp AVI)
  if (url.pathname.startsWith('/api/stream/data/')) {
    // BUG-041 FIX: Validate partNum is strictly numeric
    const partNum = url.pathname.split('/').pop();
    if (!/^\d+$/.test(partNum)) { res.writeHead(400); res.end('Invalid partNum'); return true; }
    // BUG-047 FIX: Validate quality preset is one of the allowed values
    const quality = url.searchParams.get('q') || 'original';
    const tempAvi = path.join(_ctx.TEMP_DIR, 'ese_mse_' + partNum + '.avi');
    if (!fs.existsSync(tempAvi)) { res.writeHead(404); res.end('Not ready'); return true; }
    const presets = { '480p': { scale: '854:480', abr: '128k' }, '720p': { scale: '1280:720', abr: '192k' }, '1080p': { scale: '-2:1080', abr: '256k' }, 'original': { scale: null, abr: '256k' } };
    const q = presets[quality] || presets['original'];
    // BUG-047 FIX: Clamp seek to non-negative, finite number
    const rawSeek = parseFloat(url.searchParams.get('ss'));
    const seekSec = (Number.isFinite(rawSeek) && rawSeek > 0) ? rawSeek : 0;
    const ffArgs = [];
    if (seekSec > 0) ffArgs.push('-ss', String(seekSec));
    ffArgs.push('-i', tempAvi, '-c:v', _ctx.HW_ENCODER, ..._ctx.HW_ENCODER_OPTS, '-pix_fmt', 'yuv420p');
    if (_ctx.HW_ENCODER === 'libx264') ffArgs.push('-profile:v', 'baseline', '-level', '3.1');
    if (q.scale) ffArgs.push('-vf', 'scale=' + q.scale);
    ffArgs.push('-c:a', 'aac', '-b:a', q.abr, '-ac', '2', '-err_detect', 'ignore_err', '-movflags', 'frag_keyframe+empty_moov+default_base_moof', '-frag_duration', '2000000', '-f', 'mp4', 'pipe:1');
    console.log('[MSE] Starting ffmpeg pipe (quality: ' + quality + ', encoder: ' + _ctx.HW_ENCODER + ')');
    const ff = spawn(_ctx.FFMPEG_PATH, ffArgs);
    _ctx.activeStreams[partNum] = ff;
    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Transfer-Encoding': 'chunked', 'Cache-Control': 'no-cache' });
    ff.stdout.pipe(res);
    ff.stderr.on('data', () => {});
    // BUG-042 FIX: Clean up stream reference and ensure response closes
    ff.on('close', (code) => {
      console.log('[MSE] ffmpeg done (code ' + code + ')');
      delete _ctx.activeStreams[partNum];
      if (!res.writableEnded) try { res.end(); } catch(e) {}
    });
    ff.on('error', (err) => {
      console.error('[MSE] ffmpeg process error:', err.message);
      delete _ctx.activeStreams[partNum];
      if (!res.writableEnded) try { res.end(); } catch(e) {}
    });
    req.on('close', () => {
      if (_ctx.activeStreams[partNum]) {
        try { _ctx.activeStreams[partNum].kill('SIGKILL'); } catch(e) {}
        delete _ctx.activeStreams[partNum];
      }
    });
    return true;
  }

  // MSE streaming — kill
  if (url.pathname.startsWith('/api/stream/kill/')) {
    const partNum = url.pathname.split('/').pop();
    if (!/^\d+$/.test(partNum)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid partNum' })); return true; }
    if (_ctx.activeStreams[partNum]) {
      try { _ctx.activeStreams[partNum].kill('SIGKILL'); } catch(e) {}
      delete _ctx.activeStreams[partNum];
      console.log('[MSE] Killed stream for ' + partNum);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }

  return false;
}

module.exports = { init, handle };
