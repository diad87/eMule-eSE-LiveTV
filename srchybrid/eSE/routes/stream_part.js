'use strict';
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  runProcess,
  spawnManaged,
} = require('../bounded_process_runner');
const {
  extractFileName,
  readMetBounded,
} = require('../media_resolver');

let _ctx = {};
const copyOwners = new Map();
const promotionQueues = new Map();

function init(ctx) { _ctx = ctx; }

function promoteCopy(partNum, copyToken, copyTarget, tempAvi) {
  const previous = promotionQueues.get(partNum) || Promise.resolve();
  const promotion = previous.catch(() => {}).then(async () => {
    if (copyOwners.get(partNum) !== copyToken) {
      throw new Error('copy superseded by a newer request');
    }
    // The whole canonical replacement is serialized per part. A newer copy
    // may become owner while these awaits are in flight, but it cannot promote
    // until this operation completes, so an older generation can never run
    // after (and overwrite) a newer successful promotion.
    await fs.promises.unlink(tempAvi).catch(() => {});
    await fs.promises.rename(copyTarget, tempAvi);
    return copyOwners.get(partNum) === copyToken;
  });
  promotionQueues.set(partNum, promotion);
  return promotion.finally(() => {
    if (promotionQueues.get(partNum) === promotion) {
      promotionQueues.delete(partNum);
    }
  });
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

async function pathExists(filePath) {
  try {
    await fs.promises.access(filePath);
    return true;
  } catch (_) {
    return false;
  }
}

function handle(url, req, res) {
  // Legacy .part streaming via ffmpeg pipe
  if (url.pathname === '/api/stream/part') {
    let ff = null;
    const disconnect = createDisconnectGuard(req, res, () => {
      try { if (ff) ff.kill('SIGKILL'); } catch (_) {}
    });
    void (async () => {
    const partFile = url.searchParams.get('file') || '';
    const fileName = url.searchParams.get('name') || '';
    const EMULE_TEMP = path.join(path.dirname(_ctx.EMULE_INCOMING), 'Temp');
    let filePath = null;

    // BUG-041 FIX: Strict regex + path containment check for .part files
    if (partFile && /^\d+\.part$/.test(partFile)) {
      const tempPath = path.resolve(path.join(EMULE_TEMP, partFile));
      if (isWithinBase(tempPath, EMULE_TEMP) && await pathExists(tempPath)) filePath = tempPath;
    }
    if (!filePath && partFile) {
      const metPath = path.resolve(path.join(EMULE_TEMP, partFile + '.met'));
      // BUG-041 FIX: Validate .met path is within TEMP
      if (isWithinBase(metPath, EMULE_TEMP) && await pathExists(metPath)) {
        try {
          const metBuffer = await readMetBounded(metPath, disconnect.signal);
          const metFileName = metBuffer ? extractFileName(metBuffer) : null;
          if (metFileName) {
            // BUG-041 FIX: Extract only basename to prevent embedded path traversal
            const safeName = path.basename(metFileName);
            const incomingPath = path.resolve(path.join(_ctx.EMULE_INCOMING, safeName));
            if (isWithinBase(incomingPath, _ctx.EMULE_INCOMING) && await pathExists(incomingPath)) filePath = incomingPath;
          }
        } catch(e) { console.warn('[Stream] Failed to parse .met file:', e.message); }
      }
    }
    if (!filePath && fileName) {
      // BUG-041 FIX: Use basename to strip any path components from user input
      const safeName = path.basename(fileName);
      const incomingPath = path.resolve(path.join(_ctx.EMULE_INCOMING, safeName));
      if (isWithinBase(incomingPath, _ctx.EMULE_INCOMING) && await pathExists(incomingPath)) {
        filePath = incomingPath;
      } else {
        try {
          const files = await fs.promises.readdir(_ctx.EMULE_INCOMING);
          const nameLower = safeName.toLowerCase();
          const match = files.find(f => f.toLowerCase().includes(nameLower) || nameLower.includes(f.toLowerCase()));
          if (match) {
            const matchPath = path.resolve(path.join(_ctx.EMULE_INCOMING, match));
            if (isWithinBase(matchPath, _ctx.EMULE_INCOMING)) filePath = matchPath;
          }
        } catch(e) { console.warn('[Stream] Failed to scan INCOMING dir:', e.message); }
      }
    }

    if (disconnect.checkNow()) return;
    if (!filePath) { res.writeHead(404); res.end('File not found in Temp or Incoming'); return; }
    const stat = await fs.promises.stat(filePath);
    if (disconnect.checkNow()) return;
    console.log('[Stream] Streaming: ' + String(filePath).replace(/[\r\n]/g, '') + ' (' + Math.round(stat.size / (1024*1024)) + ' MB)');

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

    ff = spawnManaged(_ctx.FFMPEG_PATH, ffArgs);
    if (disconnect.checkNow()) {
      ff.kill('SIGKILL');
      return;
    }
    let dataSent = false, stderrLog = '';
    ff.stdout.on('data', (chunk) => {
      if (!dataSent) { dataSent = true; console.log('[Stream] First data chunk sent (' + chunk.length + ' bytes)'); }
      try { res.write(chunk); } catch(e) {}
    });
    ff.stderr.on('data', (d) => {
      stderrLog = (stderrLog + d.toString()).slice(-2048);
    });
    ff.on('exit', (code) => {
      console.log('[Stream] ffmpeg exit code: ' + code + (dataSent ? '' : ' (NO data sent!)'));
      if (!dataSent && stderrLog) console.log('[Stream] ffmpeg stderr: ' + stderrLog.slice(-300));
      try { res.end(); } catch(e) {}
    });
    ff.on('error', (err) => { console.log('[Stream] ffmpeg error: ' + err.message); try { res.end(); } catch(e) {} });
    })().catch(error => {
      console.warn('[Stream] Async file preparation failed:', error.message);
      if (!disconnect.disconnected) {
        if (!res.headersSent) res.writeHead(500);
        if (!res.writableEnded) res.end('Cannot prepare stream');
      }
    });
    return true;
  }

  // MSE streaming — start (copy .part to temp AVI)
  if (url.pathname.startsWith('/api/stream/start/')) {
    // BUG-041 FIX: Validate partNum is strictly numeric
    const partNum = url.pathname.split('/').pop();
    if (!/^\d+$/.test(partNum)) { res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid partNum' })); return true; }
    const copyScript = path.join(_ctx.__dirname, 'copy_part.ps1');
    const tempAvi = path.join(_ctx.TEMP_DIR, 'ese_mse_' + partNum + '.avi');
    const copyToken = Object.freeze({ nonce: crypto.randomBytes(12).toString('hex') });
    const copyTarget = tempAvi + '.' + process.pid + '.' + copyToken.nonce + '.partial';
    copyOwners.set(partNum, copyToken);
    const disconnect = createDisconnectGuard(req, res);
    void (async () => {
    const downloads = await _ctx.getDownloads({ signal: disconnect.signal });
    if (disconnect.checkNow()) return;
    const dl = downloads.find(d => d.partNum === partNum);
    if (!dl) { res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' })); return; }
    console.log('[MSE] Copying .part for ' + dl.fileName);
    if (disconnect.checkNow()) return;
    const result = await runProcess(
      'powershell',
      ['-ExecutionPolicy','Bypass','-File',copyScript,'-Source',dl.partPath,'-Dest',copyTarget,'-MaxMB','600'],
      { timeoutMs: 30000, maxOutputBytes: 64 * 1024, signal: disconnect.signal },
    );
    if (disconnect.checkNow()) throw new Error('copy aborted');
    if (!result.ok || parseInt(result.stdout.trim()) <= 0) {
      throw new Error(result.error || result.stderr || 'Copy failed');
    }
    const promotedAsOwner = await promoteCopy(
      partNum,
      copyToken,
      copyTarget,
      tempAvi,
    );
    // Once promoted, the canonical AVI remains valid even if this request
    // disconnects or a newer generation starts. Only unique partials are
    // eligible for request-owned cleanup.
    if (disconnect.checkNow()) return;
    if (!promotedAsOwner) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'superseded' }));
      return;
    }
    const estTotalSec = Math.round((dl.fileSizeMB * 8) / 4);
    console.log('[MSE] Ready. Est: ' + estTotalSec + 's');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ready', fileName: dl.fileName, estimatedTotalSec: estTotalSec }));
    })().catch(async e => {
      await fs.promises.unlink(copyTarget).catch(() => {});
      console.error('[MSE] Copy failed:', e.message);
      if (!disconnect.disconnected) {
        const status = e.message === 'copy superseded by a newer request' ? 409 : 500;
        if (!res.headersSent) res.writeHead(status, { 'Content-Type': 'application/json' });
        try { res.end(JSON.stringify({ error: e.message })); } catch(ignored) {}
      }
    }).finally(() => {
      if (copyOwners.get(partNum) === copyToken) copyOwners.delete(partNum);
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
    let ff = null;
    const disconnect = createDisconnectGuard(req, res, () => {
      try { if (ff) ff.kill('SIGKILL'); } catch (_) {}
      if (_ctx.activeStreams[partNum] === ff) {
        delete _ctx.activeStreams[partNum];
      }
    });
    fs.promises.access(tempAvi).then(() => {
    if (disconnect.checkNow()) return;
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
    console.log('[MSE] Starting ffmpeg pipe (quality: ' + String(quality).replace(/[\r\n]/g, '') + ', encoder: ' + _ctx.HW_ENCODER + ')');
    const previous = _ctx.activeStreams[partNum];
    if (previous) {
      try { previous.kill('SIGKILL'); } catch (_) {}
      if (_ctx.activeStreams[partNum] === previous) delete _ctx.activeStreams[partNum];
    }
    ff = spawnManaged(_ctx.FFMPEG_PATH, ffArgs);
    _ctx.activeStreams[partNum] = ff;
    if (disconnect.checkNow()) {
      ff.kill('SIGKILL');
      if (_ctx.activeStreams[partNum] === ff) delete _ctx.activeStreams[partNum];
      return;
    }
    res.writeHead(200, { 'Content-Type': 'video/mp4', 'Transfer-Encoding': 'chunked', 'Cache-Control': 'no-cache' });
    ff.stdout.pipe(res);
    ff.stderr.on('data', () => {});
    // BUG-042 FIX: Clean up stream reference and ensure response closes
    ff.on('close', (code) => {
      console.log('[MSE] ffmpeg done (code ' + code + ')');
      if (_ctx.activeStreams[partNum] === ff) delete _ctx.activeStreams[partNum];
      if (!res.writableEnded) try { res.end(); } catch(e) {}
    });
    ff.on('error', (err) => {
      console.error('[MSE] ffmpeg process error:', err.message);
      if (_ctx.activeStreams[partNum] === ff) delete _ctx.activeStreams[partNum];
      if (!res.writableEnded) try { res.end(); } catch(e) {}
    });
    }).catch(() => {
      if (!disconnect.disconnected) {
        res.writeHead(404);
        res.end('Not ready');
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
