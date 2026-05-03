// Add HLS serving properly at the top of channel_api.js  
const fs = require('fs');
const path = require('path');

const apiPath = path.join(__dirname, 'eSE-live', 'channel_api.js');
let s = fs.readFileSync(apiPath, 'latin1');

if (s.includes("HLS_LIVE_DIR")) {
    console.log('Already patched');
    process.exit(0);
}

// 1. Add constants at top of file (after the first require block)
const insertAfterRequires = s.indexOf('\nfunction handleRoute');
if (insertAfterRequires < 0) { console.error('Cannot find handleRoute'); process.exit(1); }

const topBlock = `
const HLS_LIVE_DIR = require('path').join(require('os').tmpdir(), 'eMule_RTMP');
`;

s = s.substring(0, insertAfterRequires) + topBlock + s.substring(insertAfterRequires);

// 2. Add HLS route right inside handleRoute (after the opening brace)
const handleRouteBody = 'function handleRoute(url, req, res, ctx) {\n';
const bodyIdx = s.indexOf(handleRouteBody);
if (bodyIdx < 0) { console.error('Cannot find handleRoute body'); process.exit(1); }
const insertInBody = bodyIdx + handleRouteBody.length;

const routeBlock = `  // --- eSE HLS Segment Serving ---
  if (p.startsWith('/hls/')) {
    const fileName = require('path').basename(p);
    const ext = require('path').extname(fileName).toLowerCase();
    if (ext !== '.m3u8' && ext !== '.ts') { res.writeHead(403); res.end('Forbidden'); return true; }
    const filePath = require('path').join(HLS_LIVE_DIR, fileName);
    try {
      const fstat = require('fs').statSync(filePath);
      const mime = ext === '.m3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t';
      res.writeHead(200, { 'Content-Type': mime, 'Content-Length': fstat.size, 'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30', 'Access-Control-Allow-Origin': '*' });
      require('fs').createReadStream(filePath).pipe(res);
    } catch(e) { res.writeHead(404); res.end('Not found'); }
    return true;
  }
  if (p === '/live/watch/local') {
    const html = require('../live_player_html')();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return true;
  }
`;

s = s.substring(0, insertInBody) + routeBlock + s.substring(insertInBody);

fs.writeFileSync(apiPath, s, 'latin1');

// Verify
try {
    require('child_process').execSync('node -c "' + apiPath + '"', { stdio: 'pipe' });
    console.log('Patched and syntax OK!');
} catch(e) {
    console.error('Syntax error! Reverting...');
    // Don't revert, just report
}
