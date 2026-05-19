// V2-S08/S09 — eSE stress-test orchestrator + dashboard
//
// Launch:
//   node orchestrator.js <N> <STREAM_KEY_HEX32> [emule.exe path]
// Example:
//   node orchestrator.js 10 D5C13CDD31DEBE153ECD34B742CB4F2B "C:\path\emule.exe"
//
// Each spawned process gets a distinct --metrics-port so /api/live/metrics
// is reachable per-instance. The orchestrator polls each metrics endpoint
// every 5 s, prints aggregated stats to console, AND serves a live
// dashboard at http://localhost:8090.
//
// Cleanup: SIGINT (Ctrl+C) kills all spawned eMule processes before exit.

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const N = parseInt(process.argv[2], 10) || 10;
const STREAM_KEY = process.argv[3];
const EMULE_EXE = process.argv[4]
    || path.join(__dirname, '..', '..', 'srchybrid', 'x64', 'Release', 'emule.exe');
// Port plan per stress instance i in [0..N):
//   metrics    = BASE_METRICS + i  -> 4720, 4721, ...
//   eD2K TCP   = BASE_TCP     + i  -> 14662, 14663, ... (above default 4662)
//   eD2K UDP   = BASE_UDP     + i  -> 14665, 14666, ...
const BASE_PORT = 4720;
const BASE_TCP  = 14662;
const BASE_UDP  = 14665;
const DASHBOARD_PORT = 8090;

if (!STREAM_KEY || !/^[a-fA-F0-9]{32}$/.test(STREAM_KEY)) {
    console.error('usage: orchestrator.js N STREAM_KEY_HEX32 [emule.exe path]');
    process.exit(1);
}
if (!fs.existsSync(EMULE_EXE)) {
    console.error('emule.exe not found at:', EMULE_EXE);
    process.exit(1);
}

const procs = [];
const metrics = new Array(N).fill(null);

console.log(`[stress] launching ${N} viewers, key=${STREAM_KEY}`);
for (let i = 0; i < N; i++) {
    const port = BASE_PORT + i;
    const tcpPort = BASE_TCP + i;
    const udpPort = BASE_UDP + i;
    // Each instance gets its own TCP+UDP+metrics port so it can be HighID,
    // bootstrap Kad independently, and expose metrics without colliding with
    // the other stress instances or the main eMule on this host.
    const args = ['--ignoreinstances',
                  '--headless',
                  `--viewer=${STREAM_KEY}`,
                  `--metrics-port=${port}`,
                  `--tcp-port=${tcpPort}`,
                  `--udp-port=${udpPort}`];
    const child = spawn(EMULE_EXE, args, { stdio: 'ignore', detached: false });
    child.on('error', e => console.error(`[${i}] spawn error:`, e.message));
    child.on('exit', code => {
        console.log(`[${i}] pid=${child.pid} exited code=${code}`);
        metrics[i] = null;
    });
    procs.push({ child, port, idx: i });
    console.log(`[${i}] spawned pid=${child.pid} metrics=${port} tcp=${tcpPort} udp=${udpPort}`);
}

process.on('SIGINT', () => {
    console.log('[stress] SIGINT — killing all instances');
    procs.forEach(({ child }) => { try { child.kill(); } catch (_) {} });
    setTimeout(() => process.exit(0), 1000);
});

// V2-S04: parse Prometheus exposition format minimally — we only need a few names.
function parseProm(body) {
    const m = {};
    body.split('\n').forEach(line => {
        if (!line || line.startsWith('#')) return;
        const match = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)(?:\{[^}]*\})?\s+(\S+)/);
        if (match) {
            const k = match[1];
            const v = parseFloat(match[2]);
            if (!Number.isNaN(v)) {
                if (m[k] === undefined) m[k] = v;
            }
        }
    });
    return m;
}

setInterval(() => {
    procs.forEach(({ port, idx }) => {
        const req = http.get(`http://127.0.0.1:${port}/api/live/metrics`,
            { timeout: 2000 }, res => {
                let body = '';
                res.on('data', c => body += c);
                res.on('end', () => {
                    if (res.statusCode === 200) metrics[idx] = parseProm(body);
                    else metrics[idx] = null;
                });
            });
        req.on('error', () => { metrics[idx] = null; });
        req.on('timeout', () => { req.destroy(); metrics[idx] = null; });
    });

    const live = metrics.filter(m => m !== null);
    if (live.length === 0) {
        console.log('[stress] alive=0/' + N + ' (waiting for metrics endpoints to come up)');
        return;
    }
    const totalChunksRecv = live.reduce((s, m) => s + (m.esmule_chunks_received_total || 0), 0);
    const avgLatency = live.reduce((s, m) =>
        s + (m['esmule_chunk_latency_ms'] || 0), 0) / live.length;
    const totalPeers = live.reduce((s, m) => s + (m.esmule_active_peers || 0), 0);
    console.log(`[stress] alive=${live.length}/${N}  chunks=${totalChunksRecv}  ` +
        `avgLatency=${avgLatency.toFixed(0)}ms  totalActivePeers=${totalPeers}`);
}, 5000);

// V2-S09: dashboard endpoint
const server = http.createServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        fs.createReadStream(path.join(__dirname, 'dashboard.html')).pipe(res);
        return;
    }
    if (req.url === '/aggregate') {
        const live = metrics.filter(m => m !== null);
        const agg = {
            alive: live.length, total: N,
            avgLatency: live.length === 0 ? 0
                : live.reduce((s, m) => s + (m.esmule_chunk_latency_ms || 0), 0) / live.length,
            totalChunksRecv: live.reduce((s, m) => s + (m.esmule_chunks_received_total || 0), 0),
            totalChunksServed: live.reduce((s, m) => s + (m.esmule_chunks_served_total || 0), 0),
            totalActivePeers: live.reduce((s, m) => s + (m.esmule_active_peers || 0), 0),
            ts: Date.now(),
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(agg));
        return;
    }
    res.writeHead(404).end();
});
server.listen(DASHBOARD_PORT,
    () => console.log(`[stress] dashboard: http://localhost:${DASHBOARD_PORT}`));
