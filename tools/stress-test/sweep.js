// V2-S10 — automated sweep with N=10/50/100 viewers, generates JSON report.
//
// Usage:
//   node sweep.js <STREAM_KEY_HEX32> [emule.exe path]
//
// Strategy: spawn the orchestrator for each N (with TICK_SECONDS settle time),
// snapshot the dashboard /aggregate endpoint, kill the orchestrator, repeat.
// Output: sweep-report.json in the current dir.

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

const STREAM_KEY = process.argv[2];
const EMULE_EXE = process.argv[3]
    || path.join(__dirname, '..', '..', 'srchybrid', 'x64', 'Release', 'emule.exe');
const TICK_SECONDS = 60;  // settle window per N
const SWEEP_N = [10, 50, 100];
const DASHBOARD_PORT = 8090;

if (!STREAM_KEY || !/^[a-fA-F0-9]{32}$/.test(STREAM_KEY)) {
    console.error('usage: sweep.js STREAM_KEY_HEX32 [emule.exe path]');
    process.exit(1);
}

function fetchAgg() {
    return new Promise(resolve => {
        http.get(`http://127.0.0.1:${DASHBOARD_PORT}/aggregate`,
            { timeout: 3000 }, res => {
                let body = '';
                res.on('data', c => body += c);
                res.on('end', () => {
                    try { resolve(JSON.parse(body)); }
                    catch (_) { resolve(null); }
                });
            }).on('error', () => resolve(null));
    });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

(async () => {
    const results = [];
    for (const N of SWEEP_N) {
        console.log(`\n=== sweep N=${N} (settle ${TICK_SECONDS}s) ===`);
        const orch = spawn('node',
            [path.join(__dirname, 'orchestrator.js'), String(N), STREAM_KEY, EMULE_EXE],
            { stdio: 'inherit' });

        // Wait the settle window. Snapshot at t=settle - 5s so the dashboard is warm.
        await sleep((TICK_SECONDS - 5) * 1000);
        const snap = await fetchAgg();
        results.push({ N, snap, ts: new Date().toISOString() });
        console.log(`[sweep] N=${N} ->`, snap || 'no data');

        orch.kill();
        await sleep(5000);  // give time for spawned eMule procs to die
    }
    fs.writeFileSync('sweep-report.json', JSON.stringify(results, null, 2));
    console.log('\n=== sweep complete: sweep-report.json ===');
    console.log(JSON.stringify(results, null, 2));
})();
