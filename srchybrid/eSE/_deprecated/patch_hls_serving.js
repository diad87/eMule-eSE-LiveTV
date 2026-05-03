// filepath: srchybrid/eSE/patch_hls_serving.js
// Add HLS segment serving to channel_api.js handleRoute function
const fs = require('fs');
const path = require('path');
const os = require('os');

const apiPath = path.join(__dirname, 'eSE-live', 'channel_api.js');
const buf = fs.readFileSync(apiPath);
const content = buf.toString('latin1');

if (content.includes("'/hls/'")) {
    console.log('Already patched!');
    process.exit(0);
}

// Find the start of handleRoute function
const marker = 'function handleRoute(url, req, res, ctx) {';
const idx = content.indexOf(marker);
if (idx < 0) {
    console.error('Cannot find handleRoute');
    process.exit(1);
}

const insertAt = idx + marker.length;

const hlsBlock = `
  // eSE: Serve HLS segments from local broadcast
  if (p.startsWith('/hls/')) {
    const HLS_DIR = require('path').join(require('os').tmpdir(), 'eMule_RTMP');
    const fileName = require('path').basename(p);
    const ext = require('path').extname(fileName).toLowerCase();
    if (ext !== '.m3u8' && ext !== '.ts') {
      res.writeHead(403); res.end('Forbidden'); return true;
    }
    const filePath = require('path').join(HLS_DIR, fileName);
    try {
      const stat = require('fs').statSync(filePath);
      const mime = ext === '.m3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t';
      res.writeHead(200, {
        'Content-Type': mime,
        'Content-Length': stat.size,
        'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30',
        'Access-Control-Allow-Origin': '*',
      });
      require('fs').createReadStream(filePath).pipe(res);
    } catch(e) {
      res.writeHead(404); res.end('Segment not found');
    }
    return true;
  }

  // eSE: Serve inline live player at /live/watch/local
  if (p === '/live/watch/local') {
    const html = require('../live_player_html')();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return true;
  }
`;

const result = content.substring(0, insertAt) + hlsBlock + content.substring(insertAt);
fs.writeFileSync(apiPath, Buffer.from(result, 'latin1'));
console.log('HLS serving + /live/watch/local patched into channel_api.js');
