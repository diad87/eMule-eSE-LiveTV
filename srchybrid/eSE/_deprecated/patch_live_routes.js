// filepath: srchybrid/eSE/patch_live_routes.js
const fs = require('fs');
const path = require('path');

const serverPath = path.join(__dirname, 'server.js');
const buf = fs.readFileSync(serverPath);
const content = buf.toString('latin1');

if (content.includes("'/hls/'")) {
    console.log('Already patched!');
    process.exit(0);
}

const marker = 'if (handled) return;\r\n  }';
const idx = content.indexOf(marker);
if (idx < 0) {
    console.error('Marker not found');
    process.exit(1);
}

const insertAt = idx + marker.length;

const liveRoutes = `\r\n\r\n  // eSE LIVE STREAMING — HLS + Player\r\n  if (url.pathname === '/live') {\r\n    const livePage = require('./eSE-live/live_tv_page');\r\n    const html = livePage.render('idle', {\r\n      title: 'eSE Live',\r\n      hlsUrl: '/hls/stream.m3u8',\r\n      channels: [],\r\n    });\r\n    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });\r\n    res.end(html);\r\n    return;\r\n  }\r\n\r\n  if (url.pathname.startsWith('/hls/')) {\r\n    const os = require('os');\r\n    const HLS_DIR = path.join(os.tmpdir(), 'eMule_RTMP');\r\n    const fileName = path.basename(url.pathname);\r\n    const ext = path.extname(fileName).toLowerCase();\r\n    if (ext !== '.m3u8' && ext !== '.ts') {\r\n      res.writeHead(403); res.end('Forbidden'); return;\r\n    }\r\n    const filePath = path.join(HLS_DIR, fileName);\r\n    try {\r\n      const stat = fs.statSync(filePath);\r\n      const mime = ext === '.m3u8' ? 'application/vnd.apple.mpegurl' : 'video/mp2t';\r\n      res.writeHead(200, {\r\n        'Content-Type': mime,\r\n        'Content-Length': stat.size,\r\n        'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30',\r\n        'Access-Control-Allow-Origin': '*',\r\n      });\r\n      fs.createReadStream(filePath).pipe(res);\r\n    } catch(e) {\r\n      res.writeHead(404); res.end('Segment not found');\r\n    }\r\n    return;\r\n  }\r\n`;

const result = content.substring(0, insertAt) + liveRoutes + content.substring(insertAt);
fs.writeFileSync(serverPath, Buffer.from(result, 'latin1'));
console.log('Patched at offset', insertAt);
