/**
 * eSE Live — Device Scanner
 * Detects available webcams, capture cards, and audio devices via ffmpeg/dshow.
 * Max ~150 lines.
 */
'use strict';

const { execSync } = require('child_process');

/**
 * List all DirectShow video devices (webcams, capture cards).
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Array<{name: string, index: number}>}
 */
function listVideoDevices(ffmpegPath) {
  try {
    const output = execSync(
      `"${ffmpegPath}" -list_devices true -f dshow -i dummy 2>&1`,
      { encoding: 'utf8', timeout: 10000 }
    ).toString();
    return parseDshowDevices(output, 'video');
  } catch (e) {
    // ffmpeg always exits with error when listing devices
    const stderr = (e.stderr || e.stdout || '').toString();
    return parseDshowDevices(stderr, 'video');
  }
}

/**
 * List all DirectShow audio devices.
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Array<{name: string, index: number}>}
 */
function listAudioDevices(ffmpegPath) {
  try {
    const output = execSync(
      `"${ffmpegPath}" -list_devices true -f dshow -i dummy 2>&1`,
      { encoding: 'utf8', timeout: 10000 }
    ).toString();
    return parseDshowDevices(output, 'audio');
  } catch (e) {
    const stderr = (e.stderr || e.stdout || '').toString();
    return parseDshowDevices(stderr, 'audio');
  }
}

/**
 * Parse ffmpeg dshow device listing output.
 * @param {string} output - Raw ffmpeg stderr output.
 * @param {'video'|'audio'} type - Device type to extract.
 * @returns {Array<{name: string, index: number}>}
 */
function parseDshowDevices(output, type) {
  const devices = [];
  const lines = output.split('\n');
  let inSection = false;
  let index = 0;

  for (const line of lines) {
    // Section headers: "DirectShow video devices" or "DirectShow audio devices"
    if (line.includes('DirectShow ' + type + ' devices')) {
      inSection = true;
      continue;
    }
    // End of section when we hit the other type
    if (inSection && line.includes('DirectShow') && !line.includes(type)) {
      break;
    }
    if (!inSection) continue;

    // Device names are in quotes: "Device Name"
    const match = line.match(/"([^"]+)"/);
    if (match && !line.includes('Alternative name')) {
      devices.push({ name: match[1], index: index++ });
    }
  }

  return devices;
}

/**
 * Get all available sources (video + audio devices + screen capture).
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {{video: Array, audio: Array, hasScreen: boolean}}
 */
function getAvailableSources(ffmpegPath) {
  const video = listVideoDevices(ffmpegPath);
  const audio = listAudioDevices(ffmpegPath);

  // Screen capture is always available on Windows via gdigrab
  const hasScreen = process.platform === 'win32';

  return { video, audio, hasScreen };
}

/**
 * Get all sources formatted for the API response.
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Object} JSON-serializable source list.
 */
function getSourcesForAPI(ffmpegPath) {
  const sources = getAvailableSources(ffmpegPath);
  const result = [];

  // Screen capture
  if (sources.hasScreen) {
    result.push({ type: 'screen', name: 'Pantalla completa', id: 'desktop' });
  }

  // Webcams / capture cards
  for (const dev of sources.video) {
    result.push({ type: 'webcam', name: dev.name, id: dev.name });
  }

  // Audio devices
  for (const dev of sources.audio) {
    result.push({ type: 'audio', name: dev.name, id: dev.name });
  }

  // File and URL sources are always available (user provides path)
  result.push({ type: 'file', name: 'Archivo local', id: 'file' });
  result.push({ type: 'url', name: 'URL externa', id: 'url' });

  return result;
}

module.exports = {
  listVideoDevices,
  listAudioDevices,
  getAvailableSources,
  getSourcesForAPI
};
