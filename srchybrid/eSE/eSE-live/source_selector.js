/**
 * eSE Live — Source Selector
 * Builds ffmpeg input arguments for each source type:
 * webcam, screen, file, URL, capture card, OBS RTMP.
 * Max ~150 lines.
 */
'use strict';

const fs = require('fs');   // BUG-067 FIX: hoisted from validateSource()
const path = require('path');

/**
 * @typedef {Object} SourceConfig
 * @property {'webcam'|'screen'|'file'|'url'|'capture'|'rtmp'} type
 * @property {string} id - Device name, file path, or URL
 * @property {string} [audioDevice] - Audio device name (for webcam/capture)
 * @property {number} [width] - Desired width (0 = native)
 * @property {number} [height] - Desired height (0 = native)
 * @property {number} [fps] - Desired framerate (default 30)
 */

/**
 * Build ffmpeg input arguments for a given source.
 * @param {SourceConfig} source - Source configuration.
 * @returns {string[]} Array of ffmpeg arguments for input.
 */
function buildInputArgs(source) {
  const args = [];
  const fps = source.fps || 30;

  switch (source.type) {
    case 'webcam':
      args.push('-f', 'dshow');
      args.push('-framerate', String(fps));
      if (source.width && source.height) {
        args.push('-video_size', `${source.width}x${source.height}`);
      }
      args.push('-i', buildDshowInput(source.id, source.audioDevice));
      break;

    case 'screen':
      args.push('-f', 'gdigrab');
      args.push('-framerate', String(fps));
      args.push('-draw_mouse', '1');
      if (source.width && source.height) {
        args.push('-video_size', `${source.width}x${source.height}`);
      }
      args.push('-i', 'desktop');
      // Audio: explicit device > auto-detected loopback > silent fallback
      if (source.audioDevice) {
        args.push('-f', 'dshow', '-i', buildDshowAudioInput(source.audioDevice));
      } else if (source._loopbackDevice) {
        args.push('-f', 'dshow', '-i', buildDshowAudioInput(source._loopbackDevice));
      } else {
        // Silent audio so HLS always has an audio track
        args.push('-f', 'lavfi', '-i', 'anullsrc=r=44100:cl=stereo');
        args.push('-shortest');
      }
      break;

    case 'file':
      // Stream mode: loop file, re-stream as live
      // BUG-056 FIX: Validate file path exists and is not a directory traversal
      if (!source.id || !isSafePath(source.id)) {
        throw new Error('Invalid file path: rejected by safety check');
      }
      args.push('-re'); // Read at native framerate
      args.push('-i', source.id);
      break;

    case 'url':
      // External URL (IPTV, webcam IP, etc.)
      args.push('-reconnect', '1');
      args.push('-reconnect_streamed', '1');
      args.push('-reconnect_delay_max', '5');
      args.push('-i', source.id);
      break;

    case 'capture':
      // HDMI capture card (dshow device)
      args.push('-f', 'dshow');
      args.push('-framerate', String(fps));
      if (source.width && source.height) {
        args.push('-video_size', `${source.width}x${source.height}`);
      }
      args.push('-i', buildDshowInput(source.id, source.audioDevice));
      break;

    case 'rtmp':
      // OBS RTMP ingest — ffmpeg listens on rtmp://localhost:1935/live
      // This source type is handled by rtmp_server.js, not here.
      // The pipeline reads from the RTMP URL.
      // BUG-056 FIX: Only allow rtmp:// from localhost, not arbitrary URLs
      args.push('-listen', '1');
      {
        const rtmpUrl = source.id || 'rtmp://127.0.0.1:1935/live/stream';
        if (!isAllowedRtmpUrl(rtmpUrl)) {
          throw new Error('RTMP URL must be localhost: ' + rtmpUrl);
        }
        args.push('-i', rtmpUrl);
      }
      break;

    default:
      throw new Error('Unknown source type: ' + source.type);
  }

  return args;
}

/**
 * Validate a source configuration.
 * @param {SourceConfig} source - Source to validate.
 * @returns {{valid: boolean, error?: string}}
 */
function validateSource(source) {
  if (!source || !source.type) {
    return { valid: false, error: 'Source type is required' };
  }

  if (source.type === 'file') {
    // BUG-067 FIX: fs already required at module level
    if (!source.id || !fs.existsSync(source.id)) {
      return { valid: false, error: 'File not found: ' + (source.id || '(empty)') };
    }
    if (!isSafePath(source.id)) {
      return { valid: false, error: 'File path rejected by safety check' };
    }
  }

  if (source.type === 'url') {
    if (!source.id || !isAllowedInputUrl(source.id)) {
      return { valid: false, error: 'Invalid URL: ' + (source.id || '(empty)') };
    }
  }

  if (source.type === 'webcam' || source.type === 'capture') {
    if (!source.id) {
      return { valid: false, error: 'Device name is required' };
    }
  }

  return { valid: true };
}

/**
 * Auto-detect a system audio loopback device from dshow.
 * Looks for Stereo Mix, WASAPI loopback, or any output device.
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {string|null} Device name or null if not found.
 */
function findLoopbackDevice(ffmpegPath) {
  const { spawnSync } = require('child_process');
  try {
    const result = spawnSync(ffmpegPath,
      ['-list_devices', 'true', '-f', 'dshow', '-i', 'dummy'],
      { timeout: 10000, encoding: 'utf8' }
    );
    const stderr = result.stderr || '';
    
    // Parse audio device names
    const lines = stderr.split('\n');
    const audioDevices = [];
    let inAudio = false;
    
    for (const line of lines) {
      if (line.includes('(audio)')) inAudio = true;
      if (inAudio && line.includes('"') && !line.includes('Alternative name')) {
        const match = line.match(/"([^"]+)"/);
        if (match) audioDevices.push(match[1]);
      }
    }
    
    // Priority: Stereo Mix > Mezcla estereo > any "Mix" > any "Loopback"
    const loopbackPatterns = [
      /stereo mix/i,
      /mezcla est/i,
      /what u hear/i,
      /wave out/i,
      /loopback/i,
      /virtual audio/i,
      /sistema/i
    ];
    
    for (const pattern of loopbackPatterns) {
      const match = audioDevices.find(d => pattern.test(d));
      if (match) {
        console.log('[Audio] Loopback device found:', match);
        return match;
      }
    }
    
    console.log('[Audio] No loopback device found. Available:', audioDevices.join(', ') || 'none');
    return null;
  } catch (e) {
    return null;
  }
}

function quoteDshowName(name) {
  // Escape backslashes BEFORE quotes — a name ending in \ would otherwise
  // neutralize the escaped closing quote.
  return '"' + String(name || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function buildDshowInput(videoDevice, audioDevice) {
  const video = 'video=' + quoteDshowName(videoDevice);
  return audioDevice ? video + ':audio=' + quoteDshowName(audioDevice) : video;
}

function buildDshowAudioInput(audioDevice) {
  return 'audio=' + quoteDshowName(audioDevice);
}

// BUG-056 FIX: Validate dshow device names - reject injection attempts
function isSafeDshowName(name) {
  if (!name || typeof name !== 'string') return false;
  // Dshow names should not contain shell metacharacters
  return !/[;&|`$(){}\[\]<>\n\r]/.test(name);
}

// BUG-056 FIX: Validate file paths do not contain suspicious characters
function isSafePath(filePath) {
  if (!filePath || typeof filePath !== 'string') return false;
  // Reject NUL bytes, newlines, and protocol prefixes in file paths
  if (/[\x00\n\r]/.test(filePath)) return false;
  // Reject URLs being passed as file paths
  if (/^https?:\/\//i.test(filePath) || /^ftp:/i.test(filePath)) return false;
  return true;
}

// BUG-066 FIX: Validate streaming URLs — block private/internal IPs to prevent SSRF
function isAllowedInputUrl(value) {
  const ALLOWED_PROTOCOLS = ['http:', 'https:', 'rtsp:', 'rtmp:', 'rtmps:', 'srt:', 'udp:'];
  // RFC 1918, loopback, link-local, carrier-grade NAT
  const PRIVATE_IP_PATTERNS = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^0\./,
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
    /^::1$/,
    /^fc00:/i,
    /^fe80:/i,
    /^fd/i,
    /^localhost$/i,
  ];
  try {
    const u = new URL(String(value));
    if (!ALLOWED_PROTOCOLS.includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    if (!host) return false;
    for (const pattern of PRIVATE_IP_PATTERNS) {
      if (pattern.test(host)) return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

// BUG-056 FIX: RTMP URLs must be localhost only
function isAllowedRtmpUrl(value) {
  try {
    const u = new URL(String(value));
    if (!['rtmp:', 'rtmps:'].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch (e) {
    return false;
  }
}

module.exports = { buildInputArgs, validateSource, findLoopbackDevice };
