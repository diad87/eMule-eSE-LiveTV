'use strict';
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

let HW_ENCODER = 'libx264';
let HW_ENCODER_OPTS = ['-preset', 'ultrafast', '-crf', '23', '-threads', '4'];

/**
 * Detecta el encoder de hardware disponible (NVENC > QSV > AMF > CPU).
 * Muta HW_ENCODER y HW_ENCODER_OPTS con el mejor disponible.
 * @param {string} ffmpegPath  Ruta al ejecutable ffmpeg
 * @param {string} tempDir     Directorio temporal para el archivo de prueba
 */
function detect(ffmpegPath, tempDir) {
  const encoders = [
    { name: 'h264_nvenc', opts: ['-preset', 'p1', '-rc', 'vbr', '-cq', '23'], label: 'NVIDIA NVENC' },
    { name: 'h264_qsv',  opts: ['-preset', 'veryfast', '-global_quality', '23'], label: 'Intel QSV' },
    { name: 'h264_amf',  opts: ['-quality', 'speed', '-rc', 'cqp', '-qp_i', '23', '-qp_p', '23'], label: 'AMD AMF' },
  ];

  for (const enc of encoders) {
    try {
      const testOut = path.join(tempDir, 'ese_hwtest.mp4');
      const result = spawnSync(ffmpegPath, [
        '-f', 'lavfi', '-i', 'color=c=black:s=256x256:d=1:r=25',
        '-pix_fmt', 'yuv420p', '-c:v', enc.name, '-frames:v', '3', '-y', testOut
      ], { timeout: 10000, stdio: 'pipe' });

      if (result.status === 0) {
        HW_ENCODER = enc.name;
        HW_ENCODER_OPTS = enc.opts;
        console.log('   GPU Encoder: ' + enc.label + ' (' + enc.name + ')');
        try { fs.unlinkSync(testOut); } catch (e) {}
        return;
      }

      // Mostrar motivo del fallo si es por driver
      const stderr = (result.stderr || '').toString();
      const driverMsg = stderr.match(/minimum required.*driver.*is (\d+)/i);
      if (driverMsg) console.log('   ' + enc.label + ': need driver ' + driverMsg[1] + '+');
    } catch (e) {}
  }

  console.log('   GPU Encoder: none \u2192 CPU libx264 ultrafast (4 threads)');
  console.log('   Tip: actualiza driver NVIDIA a 570+ para NVENC');
}

module.exports = {
  detect,
  get HW_ENCODER()     { return HW_ENCODER; },
  get HW_ENCODER_OPTS(){ return HW_ENCODER_OPTS; },
};
