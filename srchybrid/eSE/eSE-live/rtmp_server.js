/**
 * eSE Live — RTMP Server (OBS Ingest)
 * Receives RTMP stream from OBS Studio and converts to HLS.
 * Uses ffmpeg in listen mode — no external dependencies.
 * Max ~150 lines.
 */
'use strict';

const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

let rtmpProcess = null;
let rtmpStatus = 'idle'; // idle | waiting | receiving | error
let rtmpPort = 1935;

/**
 * Start RTMP ingest server (ffmpeg listening for OBS).
 * OBS connects to rtmp://localhost:1935/live/stream
 * ffmpeg converts RTMP → HLS segments.
 *
 * @param {Object} opts
 * @param {string} opts.ffmpegPath - Path to ffmpeg
 * @param {string} opts.outputDir - HLS output directory
 * @param {string} opts.hwEncoder - Hardware encoder
 * @param {string[]} opts.hwEncoderOpts - Encoder options
 * @param {number} [opts.port=1935] - RTMP listen port
 * @param {number} [opts.bitrate=0] - Re-encode bitrate (0 = copy from OBS)
 * @param {Function} [opts.onStatus] - Status callback
 * @returns {{success: boolean, error?: string, rtmpUrl?: string}}
 */
function start(opts) {
  if (rtmpProcess) {
    return { success: false, error: 'RTMP server already running' };
  }

  const port = opts.port || 1935;
  rtmpPort = port;
  // BUG-061 FIX: bind to localhost only to prevent network exposure
  const rtmpUrl = `rtmp://127.0.0.1:${port}/live/stream`;
  const playlistPath = path.join(opts.outputDir, 'stream.m3u8');
  const segmentPattern = path.join(opts.outputDir, 'seg_%05d.ts');

  try {
    if (!fs.existsSync(opts.outputDir)) fs.mkdirSync(opts.outputDir, { recursive: true });
  } catch (e) {
    rtmpStatus = 'error';
    return { success: false, error: 'Cannot create HLS output directory: ' + e.message };
  }

  // Clean old segments
  try {
    const files = fs.readdirSync(opts.outputDir);
    for (const f of files) {
      if (f.endsWith('.ts') || f.endsWith('.m3u8')) {
        fs.unlinkSync(path.join(opts.outputDir, f));
      }
    }
  } catch (e) { console.warn('[eSE Live] RTMP: Failed to clean old segments:', e.message); }

  // Build ffmpeg args: listen for RTMP → HLS
  const args = [
    '-hide_banner',
    '-nostdin',
    '-y',
    '-listen', '1',
    '-i', rtmpUrl,
    // Copy video from OBS (OBS already encodes) — zero CPU
    '-c:v', 'copy',
    '-c:a', 'aac', '-b:a', '128k',
    '-f', 'hls',
    '-hls_time', '4',
    '-hls_list_size', '15',
    '-hls_flags', 'delete_segments+independent_segments+program_date_time',
    '-hls_segment_type', 'mpegts',
    '-hls_segment_filename', segmentPattern,
    playlistPath
  ];

  // If re-encoding is requested (e.g., OBS sends HEVC but we need H.264)
  if (opts.bitrate && opts.bitrate > 0) {
    // Replace -c:v copy with encode
    args[args.indexOf('-c:v') + 1] = opts.hwEncoder || 'libx264';
    args.splice(args.indexOf('-c:a'), 0, ...(opts.hwEncoderOpts || []), '-b:v', opts.bitrate + 'k');
  }

  console.log('[eSE Live] RTMP: Waiting for OBS on', rtmpUrl);

  try {
    rtmpProcess = spawn(opts.ffmpegPath, args, {
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (e) {
    rtmpStatus = 'error';
    return { success: false, error: e.message };
  }

  rtmpStatus = 'waiting';

  rtmpProcess.stderr.on('data', (data) => {
    const line = data.toString();

    // Detect OBS connection
    if (line.includes('Opening') && line.includes('.ts') && rtmpStatus === 'waiting') {
      rtmpStatus = 'receiving';
      console.log('[eSE Live] RTMP: OBS connected! Generating HLS segments.');
      if (opts.onStatus) opts.onStatus('receiving');
    }
  });

  rtmpProcess.on('close', (code) => {
    console.log('[eSE Live] RTMP server stopped (code', code + ')');
    rtmpProcess = null;
    if (rtmpStatus !== 'idle') {
      rtmpStatus = code === 0 ? 'idle' : 'error';
    }
    if (opts.onStatus) opts.onStatus(rtmpStatus);
  });

  rtmpProcess.on('error', (err) => {
    console.error('[eSE Live] RTMP error:', err.message);
    rtmpStatus = 'error';
    rtmpProcess = null;
  });

  return {
    success: true,
    rtmpUrl: `rtmp://localhost:${port}/live/stream`
  };
}

/**
 * Stop RTMP server.
 */
function stop() {
  if (!rtmpProcess) {
    rtmpStatus = 'idle';
    return { success: true };
  }
  try {
    const pid = rtmpProcess.pid;
    if (process.platform === 'win32' && pid) {
      try {
        execSync('taskkill /F /T /PID ' + pid, { stdio: 'ignore', timeout: 3000 });
      } catch (e) {
        console.warn('[eSE Live] RTMP: taskkill failed:', e.message);
      }
    } else {
      rtmpProcess.kill('SIGTERM');
    }
    const proc = rtmpProcess;
    setTimeout(() => {
      try {
        if (proc && !proc.killed) {
          if (process.platform === 'win32' && pid) {
            execSync('taskkill /F /T /PID ' + pid, { stdio: 'ignore', timeout: 3000 });
          } else {
            proc.kill('SIGKILL');
          }
        }
      } catch (e) {}
    }, 3000);
  } catch (e) { console.warn('[eSE Live] RTMP: Error killing process:', e.message); }
  rtmpProcess = null;
  rtmpStatus = 'idle';
  return { success: true };
}

/**
 * Get RTMP server status.
 */
function getStatus() {
  return {
    status: rtmpStatus,
    port: rtmpPort,
    rtmpUrl: `rtmp://localhost:${rtmpPort}/live/stream`
  };
}

module.exports = { start, stop, getStatus };
