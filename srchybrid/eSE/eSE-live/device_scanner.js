/**
 * eSE Live — Device Scanner
 * Detects available webcams, capture cards, and audio devices via ffmpeg/dshow.
 * Max ~150 lines.
 */
'use strict';

const { runProcess } = require('../bounded_process_runner');

/**
 * List all DirectShow video devices (webcams, capture cards).
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Promise<Array<{name: string, index: number}>>}
 */
async function listVideoDevices(ffmpegPath) {
  try {
    const result = await runProcess(
      ffmpegPath,
      ['-list_devices', 'true', '-f', 'dshow', '-i', 'dummy'],
      { encoding: 'utf8', timeoutMs: 10000, maxOutputBytes: 1024 * 1024 },
    );
    const output = result.stderr || result.stdout || '';
    return parseDshowDevices(output, 'video');
  } catch (e) {
    return [];
  }
}

/**
 * List all DirectShow audio devices.
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Promise<Array<{name: string, index: number}>>}
 */
async function listAudioDevices(ffmpegPath) {
  try {
    const result = await runProcess(
      ffmpegPath,
      ['-list_devices', 'true', '-f', 'dshow', '-i', 'dummy'],
      { encoding: 'utf8', timeoutMs: 10000, maxOutputBytes: 1024 * 1024 },
    );
    const output = result.stderr || result.stdout || '';
    return parseDshowDevices(output, 'audio');
  } catch (e) {
    return [];
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
 * @returns {Promise<{video: Array, audio: Array, hasScreen: boolean}>}
 */
async function getAvailableSources(ffmpegPath) {
  const [video, audio] = await Promise.all([
    listVideoDevices(ffmpegPath),
    listAudioDevices(ffmpegPath),
  ]);

  // Screen capture is always available on Windows via gdigrab
  const hasScreen = process.platform === 'win32';

  return { video, audio, hasScreen };
}

/**
 * Get all sources formatted for the API response.
 * @param {string} ffmpegPath - Path to ffmpeg executable.
 * @returns {Promise<Object>} JSON-serializable source list.
 */
async function getSourcesForAPI(ffmpegPath) {
  const sources = await getAvailableSources(ffmpegPath);
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
  parseDshowDevices,
  getAvailableSources,
  getSourcesForAPI
};
