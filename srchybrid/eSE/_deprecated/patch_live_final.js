// filepath: srchybrid/eSE/patch_live_final.js
// Replace the /live route to serve a standalone HLS player HTML
const fs = require('fs');
const path = require('path');

const serverPath = path.join(__dirname, 'server.js');
const buf = fs.readFileSync(serverPath);
const content = buf.toString('latin1');

// Find the live page require block and replace with inline HTML
const oldBlock = "const livePage = require('./eSE-live/live_tv_page');";
const idx = content.indexOf(oldBlock);
if (idx < 0) {
    console.log('Live page require not found - checking if already patched...');
    if (content.includes('eSE Live Stream</h1>')) {
        console.log('Already patched with inline player!');
    } else {
        console.log('ERROR: Cannot find injection point');
    }
    process.exit(0);
}

// Replace the whole block from require to res.end(html)
const blockEnd = content.indexOf('res.end(html);', idx);
if (blockEnd < 0) {
    console.error('Cannot find res.end(html)');
    process.exit(1);
}
const endOfBlock = blockEnd + 'res.end(html);'.length;

const replacement = `// Inline HLS.js Live Player (proven working)
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(require('./live_player_html')());`;

const result = content.substring(0, idx) + replacement + content.substring(endOfBlock);
fs.writeFileSync(serverPath, Buffer.from(result, 'latin1'));
console.log('Patched /live route with inline player');
