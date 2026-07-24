/**
 * eSE Live — Source Selector
 * Builds ffmpeg input arguments for each source type:
 * webcam, screen, file, URL, capture card, OBS RTMP.
 * Max ~150 lines.
 */
'use strict';

const fs = require('fs');   // BUG-067 FIX: hoisted from validateSource()
const path = require('path');
const dns = require('dns');
const net = require('net');

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
      // Hostnames are resolved and pinned before FFmpeg starts. Passing the
      // original hostname here would re-open the DNS-rebinding/TOCTOU gap.
      if (!source._resolvedUrl) {
        throw new Error('URL source must be DNS-resolved before use');
      }
      if (/^https?:/i.test(source._resolvedUrl)) {
        args.push('-max_redirects', '0');
        if (source._originalHost) {
          args.push('-headers', 'Host: ' + source._originalHost + '\r\n');
        }
        if (/^https:/i.test(source._resolvedUrl) && source._originalHostname) {
          args.push('-tls_verify', '1', '-verifyhost', source._originalHostname);
        }
      }
      args.push('-reconnect', '1');
      args.push('-reconnect_streamed', '1');
      args.push('-reconnect_delay_max', '5');
      args.push('-i', source._resolvedUrl);
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
    if (!isSafeDshowName(source.id)) {
      return { valid: false, error: 'Device name rejected by safety check' };
    }
    if (source.audioDevice && !isSafeDshowName(source.audioDevice)) {
      return { valid: false, error: 'Audio device name rejected by safety check' };
    }
  }

  if (source.type === 'screen' && source.audioDevice && !isSafeDshowName(source.audioDevice)) {
    return { valid: false, error: 'Audio device name rejected by safety check' };
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

const ALLOWED_INPUT_PROTOCOLS = new Set([
  'http:', 'https:', 'rtsp:', 'rtmp:', 'rtmps:', 'srt:', 'udp:'
]);

function normalizeHostname(value) {
  return String(value || '')
    .trim()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .split('%')[0]
    .toLowerCase();
}

function isPrivateIpv4(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function ipv6ToBigInt(address) {
  let input = normalizeHostname(address);
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const v4 = input.slice(lastColon + 1).split('.').map(Number);
    if (v4.length !== 4 || v4.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    input = input.slice(0, lastColon) + ':' +
      ((v4[0] << 8) | v4[1]).toString(16) + ':' +
      ((v4[2] << 8) | v4[3]).toString(16);
  }

  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const words = halves.length === 2
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left;
  if (words.length !== 8 || words.some(w => !/^[0-9a-f]{1,4}$/i.test(w))) return null;
  return words.reduce((acc, word) => (acc << 16n) | BigInt(parseInt(word, 16)), 0n);
}

function isPrivateOrLocalAddress(value) {
  const address = normalizeHostname(value);
  const family = net.isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family !== 6) return true;

  const numeric = ipv6ToBigInt(address);
  if (numeric === null || numeric === 0n || numeric === 1n) return true;
  if ((numeric >> 120n) === 0xffn) return true;       // multicast
  if ((numeric >> 121n) === 0x7en) return true;      // fc00::/7 unique-local
  if ((numeric >> 118n) === 0x3fan) return true;     // fe80::/10 link-local
  if ((numeric >> 118n) === 0x3fbn) return true;     // fec0::/10 site-local

  if ((numeric >> 32n) === 0xffffn) {
    const v4 = Number(numeric & 0xffffffffn);
    return isPrivateIpv4([
      (v4 >>> 24) & 255,
      (v4 >>> 16) & 255,
      (v4 >>> 8) & 255,
      v4 & 255
    ].join('.'));
  }
  return false;
}

function parseAllowedInputUrl(value) {
  try {
    const parsed = new URL(String(value));
    if (!ALLOWED_INPUT_PROTOCOLS.has(parsed.protocol)) return null;
    const hostname = normalizeHostname(parsed.hostname);
    if (!hostname || hostname === 'localhost') return null;
    if (net.isIP(hostname) && isPrivateOrLocalAddress(hostname)) return null;
    return parsed;
  } catch (e) {
    return null;
  }
}

function isAllowedInputUrl(value) {
  return !!parseAllowedInputUrl(value);
}

async function resolveAndPinInputUrl(value, lookup) {
  const parsed = parseAllowedInputUrl(value);
  if (!parsed) return { valid: false, error: 'Invalid or private URL' };

  const hostname = normalizeHostname(parsed.hostname);
  let addresses;
  try {
    if (net.isIP(hostname)) {
      addresses = [{ address: hostname, family: net.isIP(hostname) }];
    } else {
      const resolve = lookup || dns.promises.lookup;
      addresses = await resolve(hostname, { all: true, verbatim: true });
    }
  } catch (e) {
    return { valid: false, error: 'DNS lookup failed: ' + e.message };
  }

  if (!Array.isArray(addresses)) addresses = [addresses];
  if (!addresses.length || addresses.some(entry =>
    !entry || !net.isIP(normalizeHostname(entry.address)) ||
    isPrivateOrLocalAddress(entry.address)
  )) {
    return { valid: false, error: 'URL resolves to a private or invalid address' };
  }

  const selected = addresses[0];
  const pinned = new URL(parsed.href);
  pinned.hostname = Number(selected.family) === 6
    ? '[' + normalizeHostname(selected.address) + ']'
    : normalizeHostname(selected.address);
  return {
    valid: true,
    url: pinned.href,
    address: normalizeHostname(selected.address),
    originalHost: parsed.host,
    originalHostname: hostname
  };
}

async function prepareSource(source, lookup) {
  const validation = validateSource(source);
  if (!validation.valid) return validation;
  if (source.type !== 'url') return { valid: true, source: { ...source } };

  const resolved = await resolveAndPinInputUrl(source.id, lookup);
  if (!resolved.valid) return resolved;
  return {
    valid: true,
    source: {
      ...source,
      _resolvedUrl: resolved.url,
      _originalHost: resolved.originalHost,
      _originalHostname: resolved.originalHostname,
      _resolvedAddress: resolved.address
    }
  };
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

module.exports = {
  buildInputArgs,
  validateSource,
  findLoopbackDevice,
  isAllowedInputUrl,
  isPrivateOrLocalAddress,
  resolveAndPinInputUrl,
  prepareSource,
  isAllowedRtmpUrl,
  isSafeDshowName
};
