// filepath: srchybrid/eSE/live_player_server.js
// eSE Live — Combined HLS Server + Directory + Player
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = 9090;
const HLS_DIR = path.join(os.tmpdir(), 'eMule_RTMP');

// Import the directory page renderer
let liveTvPage;
try {
    liveTvPage = require('./eSE-live/live_tv_page');
} catch(e) {
    console.warn('live_tv_page not found, directory will be unavailable');
}

// Import the player HTML
const getPlayerHTML = require('./live_player_html');

const MIME = {
    '.m3u8': 'application/vnd.apple.mpegurl',
    '.ts': 'video/mp2t',
};

// Check if a broadcast is active (HLS segments exist)
function getBroadcastStatus() {
    try {
        const m3u8 = path.join(HLS_DIR, 'stream.m3u8');
        if (!fs.existsSync(m3u8)) return null;
        const stat = fs.statSync(m3u8);
        // If m3u8 was updated in the last 30 seconds, broadcast is active
        // age check removed for testing
        // Count segments
        const files = fs.readdirSync(HLS_DIR).filter(f => f.endsWith('.ts'));
        return {
            active: true,
            segments: files.length,
            lastUpdate: stat.mtimeMs,
        };
    } catch(e) { return null; }
}

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const p = url.pathname;

    // Home page redirect to the main eSE server (running on 8085)
    if (p === '/') {
        res.writeHead(302, { 'Location': 'http://localhost:8080/' });
        res.end();
        return;
    }

    // Directory page
    if (p === '/live') {
        if (liveTvPage) {
            const broadcast = getBroadcastStatus();
            const status = broadcast ? 'broadcasting' : 'idle';
            const meta = {
                title: 'eSE Live',
                hlsUrl: '/hls/stream.m3u8',
                channels: [],
                localBroadcast: broadcast,
            };
            let html = liveTvPage.render(status, meta);
            // Inject local broadcast detection script
            if (broadcast) {
                const injectScript = `<script>
                setInterval(function() {
                    if (document.getElementById('ese-local-broadcast')) return; // already added

                    const main = document.querySelector('.main');
                    if (!main) return;
                    
                    const card = document.createElement('div');
                    card.id = 'ese-local-broadcast';
                    card.style.cssText = 'background:linear-gradient(135deg,#1a1a2e,#2a1a1e);border:2px solid #ff3b3b; animation:pulse-border 2s infinite; cursor:pointer; min-height:100px; border-radius:12px; display:flex; margin-bottom: 30px; overflow:hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);';
                    card.onclick = function(){ window.location.href='/player'; };
                    
                    card.innerHTML = \`
                        <div style="flex:0 0 160px;display:flex;flex-direction:column;align-items:center;justify-content:center;background:linear-gradient(135deg,#1a1a2e,#ff3b3b44);border-right:1px solid rgba(255,255,255,0.05);">
                            <div style="font-size:3rem;text-shadow:0 0 15px #ff3b3b">\ud83d\udce1</div>
                        </div>
                        <div style="flex:1;padding:20px;display:flex;flex-direction:column;justify-content:center;">
                            <div style="font-size:22px;font-weight:800;color:#fff;margin-bottom:8px;">\ud83c\udfa5 Tu emisi\xf3n P2P local est\xe1 ACTIVA</div>
                            <div style="color:#aaa;font-size:14px;display:flex;gap:12px;align-items:center;">
                                <span style="background:#ff3b3b;color:#fff;padding:2px 8px;border-radius:6px;font-weight:bold;font-size:11px;letter-spacing:1px;animation:pulse 2s infinite">\ud83d\udd34 LIVE</span>
                                <span>\xb7</span>
                                <span style="color:#2ecc71;font-weight:600">\${${broadcast.segments}} segmentos HLS</span>
                                <span>\xb7</span>
                                <span>Difundiendo en red Kademlia</span>
                            </div>
                        </div>
                        <div style="flex:0 0 150px;display:flex;align-items:center;justify-content:center;padding:20px;">
                            <button style="background:linear-gradient(135deg,#ff6b35,#ff2d78);color:white;border:none;padding:12px 24px;border-radius:8px;font-weight:bold;cursor:pointer;width:100%;">Ver canal ➔</button>
                        </div>
                    \`;
                    
                    main.insertBefore(card, main.firstChild);
                    
                    if (!document.getElementById('ese-pulse-style')) {
                        const style = document.createElement('style');
                        style.id = 'ese-pulse-style';
                        style.innerHTML = '@keyframes pulse-border{0%,100%{border-color:#ff3b3b;box-shadow:0 0 15px #ff3b3b88}50%{border-color:#ff3b3b44;box-shadow:none}}';
                        document.head.appendChild(style);
                    }
                }, 500);
                <\/script>`;
                html = html.replace('</body>', injectScript + '</body>');
            }
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' });
            res.end(html);
        } else {
            // Fallback to player
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' });
            res.end(getPlayerHTML());
        }
        return;
    }

    // Player page
    if (p === '/live/watch/local' || p === '/watch' || p === '/player') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(getPlayerHTML());
        return;
    }

    // API: broadcast status
    if (p === '/api/live/status') {
        const broadcast = getBroadcastStatus();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(broadcast || { active: false }));
        return;
    }

    // HLS files
    if (p.startsWith('/hls/')) {
        const fileName = path.basename(p);
        const ext = path.extname(fileName).toLowerCase();
        if (ext !== '.m3u8' && ext !== '.ts') {
            res.writeHead(403); res.end('Forbidden'); return;
        }
        const filePath = path.join(HLS_DIR, fileName);
        try {
            const stat = fs.statSync(filePath);
            res.writeHead(200, {
                'Content-Type': MIME[ext] || 'application/octet-stream',
                'Content-Length': stat.size,
                'Cache-Control': ext === '.m3u8' ? 'no-cache' : 'max-age=30',
            });
            fs.createReadStream(filePath).pipe(res);
        } catch(e) {
            res.writeHead(404); res.end('Not found');
        }
        return;
    }

    res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
    console.log(`\n  eSE Live TV running at:`);
    console.log(`  → http://localhost:${PORT}/live      (directory)`);
    console.log(`  → http://localhost:${PORT}/player     (player)`);
    console.log(`  → Serving HLS from: ${HLS_DIR}\n`);
});
