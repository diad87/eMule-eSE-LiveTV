/**
 * eSE Live — FFmpeg Pipeline
 * Manages the ffmpeg process that converts any source into HLS segments.
 * Handles start, stop, status, and HW acceleration.
 * Max ~250 lines.
 */
'use strict';

const { spawn, execSync } = require('child_process');

// spawn & execSync imported above
const path = require('path');
const fs = require('fs');
const sourceSelector = require('./source_selector');

// Pipeline state
let ffmpegProcess = null;
let pipelineStatus = 'idle'; // idle | starting | streaming | error | stopped
let pipelineError = null;
let segmentCount = 0;
let startTime = null;
let currentSource = null;
let pipelineGeneration = 0; // BUG-057 FIX: monotonic ID to prevent race in stop() timeout

/**
 * Start the HLS pipeline for a given source.
 * @param {Object} opts
 * @param {import('./source_selector').SourceConfig} opts.source - Source config
 * @param {string} opts.ffmpegPath - Path to ffmpeg binary
 * @param {string} opts.outputDir - Directory for HLS segments (eSE-live/live/)
 * @param {string} opts.hwEncoder - HW encoder name (h264_nvenc, h264_qsv, libx264...)
 * @param {string[]} opts.hwEncoderOpts - HW encoder options
 * @param {number} [opts.bitrate=3000] - Target bitrate in kbps
 * @param {number} [opts.segmentDuration=4] - HLS segment duration in seconds
 * @param {Function} [opts.onStatus] - Callback for status changes
 * @returns {{success: boolean, error?: string}}
 */
function start(opts) {
  if (ffmpegProcess) {
    return { success: false, error: 'Pipeline already running. Stop it first.' };
  }

  // Validate source
  const validation = sourceSelector.validateSource(opts.source);
  if (!validation.valid) {
    return { success: false, error: validation.error };
  }
  if (opts.source.type === 'url' && !opts.source._resolvedUrl) {
    return { success: false, error: 'URL source must be DNS-resolved before use' };
  }

  const outputDir = opts.outputDir;
  const playlistPath = path.join(outputDir, 'stream.m3u8');
  const segmentPattern = path.join(outputDir, 'seg_%05d.ts');
  const bitrate = opts.bitrate || 3000;
  const segDuration = opts.segmentDuration || 4;

  try {
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  } catch (e) {
    return { success: false, error: 'Cannot create HLS output directory: ' + e.message };
  }

  // Clean old segments
  cleanSegments(outputDir);
  // Auto-detect audio loopback for screen capture (if no explicit audio device)
  if (opts.source.type === 'screen' && !opts.source.audioDevice) {
    const loopback = sourceSelector.findLoopbackDevice(opts.ffmpegPath);
    if (loopback) {
      opts.source._loopbackDevice = loopback;
    }
  }

  // Build ffmpeg command
  const inputArgs = sourceSelector.buildInputArgs(opts.source);

  // Build output args
  const outputArgs = buildOutputArgs({
    hwEncoder: opts.hwEncoder || 'libx264',
    hwEncoderOpts: opts.hwEncoderOpts || ['-preset', 'ultrafast'],
    bitrate,
    segDuration,
    playlistPath,
    segmentPattern,
    source: opts.source
  });

  const fullArgs = ['-hide_banner', '-nostdin', '-y', ...inputArgs, ...outputArgs];

  console.log('[eSE Live] Starting pipeline:', opts.ffmpegPath, fullArgs.join(' '));

  // Spawn ffmpeg
  try {
    ffmpegProcess = spawn(opts.ffmpegPath, fullArgs, {
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (e) {
    pipelineStatus = 'error';
    pipelineError = e.message;
    return { success: false, error: e.message };
  }

  pipelineStatus = 'starting';
  pipelineError = null;
  segmentCount = 0;
  startTime = Date.now();
  currentSource = opts.source;

  ffmpegProcess.stderr.on('data', (data) => {
    const line = data.toString();
    // Detect first segment written
    if (line.includes('.ts') && pipelineStatus === 'starting') {
      pipelineStatus = 'streaming';
      if (opts.onStatus) opts.onStatus('streaming');
      console.log('[eSE Live] First segment generated — streaming!');
    }
    // Count segments
    if (line.includes('Opening') && line.includes('.ts')) {
      segmentCount++;
    }
  });

  ffmpegProcess.on('close', (code) => {
    console.log('[eSE Live] ffmpeg exited with code', code);
    ffmpegProcess = null;
    if (pipelineStatus !== 'stopped') {
      pipelineStatus = code === 0 ? 'stopped' : 'error';
      pipelineError = code !== 0 ? 'ffmpeg exited with code ' + code : null;
    }
    if (opts.onStatus) opts.onStatus(pipelineStatus);
  });

  ffmpegProcess.on('error', (err) => {
    console.error('[eSE Live] ffmpeg error:', err.message);
    pipelineStatus = 'error';
    pipelineError = err.message;
    ffmpegProcess = null;
  });

  return { success: true };
}

/**
 * Resolve and pin URL sources before handing them to the synchronous starter.
 * Non-URL sources pass through unchanged.
 */
async function startResolved(opts) {
  const prepared = await sourceSelector.prepareSource(opts.source);
  if (!prepared.valid) return { success: false, error: prepared.error };
  return start({ ...opts, source: prepared.source });
}

/**
 * Stop the running pipeline.
 * @returns {{success: boolean}}
 */
function stop() {
  if (!ffmpegProcess) {
    pipelineStatus = 'idle';
    return { success: true };
  }

  pipelineStatus = 'stopped';
  const pid = ffmpegProcess.pid;
  console.log('[eSE Live] Stopping pipeline, ffmpeg PID:', pid);

  // On Windows SIGTERM is unreliable — use taskkill /F
  try {
    if (process.platform === 'win32' && pid) {
      try {
        execSync('taskkill /F /T /PID ' + pid, { stdio: 'ignore' });
        console.log('[eSE Live] taskkill sent to PID', pid);
      } catch (e) {
        // Process may already be dead
        console.log('[eSE Live] taskkill failed (process may be gone):', e.message);
      }
    } else {
      ffmpegProcess.kill('SIGTERM');
    }
  } catch (e) {
    console.log('[eSE Live] kill error:', e.message);
  }

  // BUG-057 FIX: capture generation ID instead of object reference to prevent race
  const stopGeneration = ++pipelineGeneration;
  const proc = ffmpegProcess;
  setTimeout(() => {
    try {
      if (proc && !proc.killed && pid) {
        if (process.platform === 'win32') {
          execSync('taskkill /F /T /PID ' + pid, { stdio: 'ignore' });
        } else {
          proc.kill('SIGKILL');
        }
        console.log('[eSE Live] Force-killed ffmpeg PID', pid);
      }
    } catch (e) {}
    // Only clean state if no new pipeline started since stop()
    if (pipelineGeneration === stopGeneration) {
      ffmpegProcess = null;
    }
  }, 5000);

  currentSource = null;
  return { success: true };
}

/**
 * Get current pipeline status.
 * @returns {Object} Status info.
 */
function getStatus() {
  return {
    status: pipelineStatus,
    error: pipelineError,
    segments: segmentCount,
    uptime: startTime ? Math.floor((Date.now() - startTime) / 1000) : 0,
    source: currentSource
  };
}

/**
 * Build ffmpeg output arguments for HLS.
 */
function buildOutputArgs(opts) {
  const args = [];
  const { hwEncoder, hwEncoderOpts, bitrate, segDuration, playlistPath, segmentPattern, source } = opts;
  const effectiveFps = Math.max(1, parseInt(source.fps || 30, 10) || 30);
  const gop = Math.max(1, Math.round(segDuration * effectiveFps));

  // Check if we can copy video (no transcode needed)
  const canCopy = source.type === 'file' && !source.width;

  if (canCopy) {
    // Copy mode — zero CPU for H.264 content
    args.push('-c:v', 'copy');
  } else {
    // Encode mode
    args.push('-c:v', hwEncoder);
    args.push(...hwEncoderOpts);
    args.push('-b:v', bitrate + 'k');
    args.push('-maxrate', (bitrate * 1.5) + 'k');
    args.push('-bufsize', (bitrate * 2) + 'k');
    // Keyframe every segment for clean HLS cuts
    args.push('-g', String(gop));
    args.push('-keyint_min', String(gop));
    args.push('-sc_threshold', '0');
  }

  // Audio: always AAC
  args.push('-c:a', 'aac', '-b:a', '128k', '-ar', '44100', '-ac', '2');

  // HLS output
  args.push(
    '-f', 'hls',
    '-hls_time', String(segDuration),
    '-hls_list_size', '15',       // Keep last 15 segments (60s at 4s each)
    '-hls_flags', 'delete_segments+independent_segments+program_date_time',
    '-hls_segment_type', 'mpegts',
    '-hls_segment_filename', segmentPattern,
    playlistPath
  );

  return args;
}

/**
 * Clean old HLS segments from the output directory.
 * @param {string} dir - Directory to clean.
 */
function cleanSegments(dir) {
  try {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const files = fs.readdirSync(dir);
    for (const f of files) {
      if (f.endsWith('.ts') || f.endsWith('.m3u8')) {
        fs.unlinkSync(path.join(dir, f));
      }
    }
  } catch (e) { console.warn('[eSE Live] cleanSegments error:', e.message); }
}

module.exports = { start, startResolved, stop, getStatus };
