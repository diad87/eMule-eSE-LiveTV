# Sprints v2 — del estado actual a 500-5000 viewers

Cada sprint = **1-3 días de trabajo**. Diseñado para que un programador novel
pueda ejecutarlo casi sin pensar. Lee `MASTER_PLAN.md` (sección referenciada)
para entender el "por qué" antes de cada sprint.

**Prerequisito antes de empezar**: tener el repo clonado, build pipeline funcionando
(MSBuild Visual Studio Build Tools 2022, Node 18+, ffmpeg.exe en PATH o paquete).

**Convención de naming**: sprints numerados `V2-SXX` para poder referenciarlos
en commits y discusiones.

---

## Bloque A — Observabilidad (V2-S01 a V2-S05)

Sin métricas reales no se puede mejorar nada. Esto va PRIMERO.

### V2-S01 — Counters por peer (bytes_in/out, latencia, RTT)

**Objetivo**: cada conexión peer-a-peer tiene contadores precisos.
**Tiempo**: 1 día.
**Prerequisito**: ninguno.
**Referencia**: MASTER_PLAN.md §4.10.

**Archivos a modificar**:
- `srchybrid/LiveStreamManager.h` — añadir struct `PeerCounters`
- `srchybrid/LiveStreamManager.cpp` — actualizar contadores en send/recv

**Código a añadir** en `LiveStreamManager.h`:
```cpp
struct PeerCounters {
    uint64 bytes_in_total       = 0;  // bytes recibidos del peer
    uint64 bytes_out_total      = 0;  // bytes enviados al peer
    uint64 bytes_in_window_60s  = 0;  // ventana móvil 60s para ratio
    uint64 bytes_out_window_60s = 0;
    DWORD  rtt_ms_ewma          = 0;  // EWMA de RTT en ms
    DWORD  last_chunk_recv_ms   = 0;  // timestamp último chunk recibido
    DWORD  last_chunk_sent_ms   = 0;
    int    chunks_served        = 0;
    int    chunks_received      = 0;
};

// En CLiveStreamManager class:
CMap<CUpDownClient*, CUpDownClient*, PeerCounters, PeerCounters> m_peerCounters;
```

**Modificar** los call sites en `OnChunkReceived` y `OnPeerRequest`:
```cpp
// En OnChunkReceived (después de aceptar chunk):
auto& c = m_peerCounters[peer];
c.bytes_in_total      += dataSize;
c.bytes_in_window_60s += dataSize;
c.chunks_received++;
c.last_chunk_recv_ms = GetTickCount();
```

```cpp
// En OnPeerRequest (después de enviar chunk):
auto& c = m_peerCounters[peer];
c.bytes_out_total      += chunk->dataSize;
c.bytes_out_window_60s += chunk->dataSize;
c.chunks_served++;
c.last_chunk_sent_ms = GetTickCount();
```

**Verificación**:
```powershell
# Lanza eMule, broadcast testpattern, conecta 1 viewer
# Espera 30s, mira:
Invoke-WebRequest 'http://127.0.0.1:4711/api/live/debug' -UseBasicParsing |
  Select -Expand Content | ConvertFrom-Json | Select -Expand counters
```
**Éxito**: ves `chunksReceived` y `chunksRequested` no-cero. Logs muestran updates de contadores.

**Gotcha**: el `bytes_*_window_60s` requiere ventana móvil; en V2-S02 lo implementamos. De momento déjalo creciendo cumulative.

---

### V2-S02 — Ventana móvil 60s para ratio

**Objetivo**: calcular ratio bytes_out/bytes_in de últimos 60s, no cumulative.
**Tiempo**: 1 día.
**Prerequisito**: V2-S01.

**Archivos**:
- `srchybrid/LiveStreamManager.h` — extender `PeerCounters`
- `srchybrid/LiveStreamManager.cpp` — método `TickWindowReset()`

**Código a añadir**:
```cpp
struct PeerCounters {
    // ... (lo de V2-S01)
    DWORD  window_start_tick    = 0;
    static const DWORD WINDOW_MS = 60000;

    void MaybeResetWindow() {
        DWORD now = GetTickCount();
        if (window_start_tick == 0 || now - window_start_tick > WINDOW_MS) {
            bytes_in_window_60s  = 0;
            bytes_out_window_60s = 0;
            window_start_tick    = now;
        }
    }

    float Ratio60s() const {
        if (bytes_in_window_60s == 0) return 1.0f; // bootstrap
        return (float)bytes_out_window_60s / (float)bytes_in_window_60s;
    }
};
```

Llamar `MaybeResetWindow()` antes de cada incremento.

**Verificación**:
- Conecta 1 viewer durante >60s
- Mira ratio en `/api/live/debug` — debe converger a un valor estable
- Para 1 viewer único, ratio será ~0 desde el broadcaster (no recibe nada del viewer) y ~∞ desde el viewer

**Éxito**: `MaybeResetWindow` se llama, valores window_60s se reinician al pasar 60s, ratio calculado correctamente.

---

### V2-S03 — RTT measurement con EWMA

**Objetivo**: medir RTT por peer con exponentially-weighted moving average.
**Tiempo**: 1 día.
**Prerequisito**: V2-S01.

**Archivos**:
- `srchybrid/LiveProtocol.cpp` — añadir OP_LIVE_PING/PONG
- `srchybrid/LivePackets.h` — define opcodes
- `srchybrid/LiveStreamManager.cpp` — handlers

**Código en LivePackets.h**:
```cpp
#define OP_LIVE_PING   0xE7  // body: uint32 ping_id, uint64 send_tick
#define OP_LIVE_PONG   0xE8  // body: uint32 ping_id, uint64 echo_tick
```

**Implementar PingPeer y handler**:
```cpp
void CLiveStreamManager::PingPeer(CUpDownClient* peer) {
    static uint32 next_ping_id = 0;
    uint32 id = ++next_ping_id;
    uint64 tick = GetTickCount64();
    Packet* pkt = new Packet(OP_EDONKEYPROT);
    pkt->opcode = OP_LIVE_PING;
    pkt->size = 12;
    pkt->pBuffer = new char[12];
    memcpy(pkt->pBuffer, &id, 4);
    memcpy(pkt->pBuffer+4, &tick, 8);
    peer->SendPacket(pkt);
    m_pendingPings[peer][id] = tick;
}

void CLiveStreamManager::OnPing(CUpDownClient* peer, uint32 id, uint64 echo_tick) {
    // Echo back as PONG
    Packet* pkt = new Packet(OP_EDONKEYPROT);
    pkt->opcode = OP_LIVE_PONG;
    pkt->size = 12;
    pkt->pBuffer = new char[12];
    memcpy(pkt->pBuffer, &id, 4);
    memcpy(pkt->pBuffer+4, &echo_tick, 8);
    peer->SendPacket(pkt);
}

void CLiveStreamManager::OnPong(CUpDownClient* peer, uint32 id, uint64 echo_tick) {
    auto it = m_pendingPings[peer].find(id);
    if (it == m_pendingPings[peer].end()) return;
    DWORD rtt = (DWORD)(GetTickCount64() - it->second);
    m_pendingPings[peer].erase(it);

    auto& c = m_peerCounters[peer];
    if (c.rtt_ms_ewma == 0) c.rtt_ms_ewma = rtt;
    else c.rtt_ms_ewma = (c.rtt_ms_ewma * 7 + rtt) / 8; // alpha=1/8 EWMA
}
```

**Llamar PingPeer cada 5s** desde `Process()`:
```cpp
if (now - m_lastPingTick > 5000) {
    POSITION pos = m_viewPeers.GetHeadPosition();
    while (pos) PingPeer(m_viewPeers.GetNext(pos));
    pos = m_broadcastPeers.GetHeadPosition();
    while (pos) PingPeer(m_broadcastPeers.GetNext(pos));
    m_lastPingTick = now;
}
```

**Verificación**:
- Conecta viewer, espera 30s
- En log debe aparecer "RTT" para el peer
- `/api/live/debug` debe mostrar `rtt_ms_ewma` en `peers[]`

**Éxito**: RTT estable (no varía >50% entre mediciones consecutivas), aprox = ping del sistema operativo.

---

### V2-S04 — Endpoint /api/live/metrics formato Prometheus

**Objetivo**: exponer métricas en formato consumible por Prometheus/Grafana.
**Tiempo**: 1 día.
**Prerequisito**: V2-S01, S02, S03.

**Archivos**:
- `srchybrid/WebServer.cpp` — nuevo endpoint en `_ProcessLiveAPI`

**Código a añadir** en `_ProcessLiveAPI` (cerca de `/api/live/log`):
```cpp
if (sURL == "/api/live/metrics") {
    CStringA body;
    body.Format(
        "# HELP esmule_chunks_received_total Total chunks received\n"
        "# TYPE esmule_chunks_received_total counter\n"
        "esmule_chunks_received_total %lld\n"
        "# HELP esmule_chunks_served_total Total chunks served to peers\n"
        "# TYPE esmule_chunks_served_total counter\n"
        "esmule_chunks_served_total %lld\n"
        "# HELP esmule_active_peers Currently connected peers\n"
        "# TYPE esmule_active_peers gauge\n"
        "esmule_active_peers{role=\"viewer\"} %d\n"
        "esmule_active_peers{role=\"broadcaster\"} %d\n"
        "# HELP esmule_chunk_buffer_count Current chunks in buffer\n"
        "# TYPE esmule_chunk_buffer_count gauge\n"
        "esmule_chunk_buffer_count %d\n",
        (long long)theApp.liveStreamManager->GetCounters().chunksReceived,
        (long long)m_meshManager.GetChunksServedCount(),
        (int)m_viewPeers.GetCount(),
        (int)m_broadcastPeers.GetCount(),
        m_chunkBuffer.GetCount());

    CStringA hdr;
    hdr.Format("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n"
               "Content-Length: %d\r\n\r\n", body.GetLength());
    Data.pSocket->SendData(hdr, hdr.GetLength());
    Data.pSocket->SendData(body, body.GetLength());
    return;
}
```

**Verificación**:
```powershell
Invoke-WebRequest 'http://127.0.0.1:4711/api/live/metrics' -UseBasicParsing |
  Select -Expand Content
```
**Éxito**: respuesta tipo:
```
esmule_chunks_received_total 47
esmule_chunks_served_total 12
esmule_active_peers{role="viewer"} 1
esmule_active_peers{role="broadcaster"} 0
esmule_chunk_buffer_count 16
```

**Validar con Prometheus**: `prometheus --scrape-config 'http://127.0.0.1:4711/api/live/metrics'` y query `esmule_chunks_received_total{}` en Grafana.

---

### V2-S05 — Histograma de latencia chunk arrival (p50/p95/p99)

**Objetivo**: medir distribución de latencia de chunks, no solo media.
**Tiempo**: 2 días.
**Prerequisito**: V2-S04.

**Archivos**:
- `srchybrid/LiveDebugLog.h` — añadir clase `LatencyHistogram`
- `srchybrid/LiveDebugLog.cpp` — implementación

**Código LatencyHistogram**:
```cpp
class LatencyHistogram {
public:
    void Record(DWORD latency_ms) {
        CSingleLock lock(&m_lock, TRUE);
        m_samples.push_back(latency_ms);
        if (m_samples.size() > MAX_SAMPLES) m_samples.pop_front();
    }

    void Percentiles(DWORD& p50, DWORD& p95, DWORD& p99) const {
        CSingleLock lock(&m_lock, TRUE);
        if (m_samples.empty()) { p50=p95=p99=0; return; }
        std::vector<DWORD> sorted(m_samples.begin(), m_samples.end());
        std::sort(sorted.begin(), sorted.end());
        size_t n = sorted.size();
        p50 = sorted[n*50/100];
        p95 = sorted[n*95/100];
        p99 = sorted[n*99/100];
    }

private:
    static const size_t MAX_SAMPLES = 1000;
    std::deque<DWORD> m_samples;
    mutable CCriticalSection m_lock;
};
```

**Instrumentar OnChunkReceived**:
```cpp
// Calculate latency: chunk timestamp vs current time
DWORD latency = (DWORD)(time(NULL) - timestamp) * 1000;
m_chunkArrivalLatency.Record(latency);
```

**Exponer en /api/live/metrics**:
```cpp
DWORD p50, p95, p99;
m_chunkArrivalLatency.Percentiles(p50, p95, p99);
body.AppendFormat(
    "esmule_chunk_latency_ms{quantile=\"0.5\"} %u\n"
    "esmule_chunk_latency_ms{quantile=\"0.95\"} %u\n"
    "esmule_chunk_latency_ms{quantile=\"0.99\"} %u\n",
    p50, p95, p99);
```

**Verificación**:
- Broadcast + 1 viewer durante 2 minutos
- p50 debe ser <3000ms, p99 <5000ms en condiciones normales
- Grafica con Grafana, debe verse curva monotónica

**Éxito**: p50/p95/p99 bien diferenciados (p99 > p95 > p50), valores razonables.

---

## Bloque B — Stress test simulator (V2-S06 a V2-S10)

Para validar mejoras necesitamos N viewers simulados.

### V2-S06 — Modo headless de eMule

**Objetivo**: lanzar emule.exe sin GUI con flags `--headless --viewer-mode`.
**Tiempo**: 2 días.
**Prerequisito**: ninguno.
**Referencia**: MASTER_PLAN.md §9.

**Archivos**:
- `srchybrid/emule.cpp` — parsear command line al startup
- `srchybrid/EmuleDlg.cpp` — bypass UI si headless

**Código en emule.cpp** `BOOL CemuleApp::InitInstance()`:
```cpp
// Parse command line
m_bHeadless = false;
m_strHeadlessJoinKey.Empty();
m_uHeadlessMetricsPort = 0;
for (int i = 1; i < __argc; i++) {
    CString arg = __targv[i];
    if (arg == _T("--headless"))
        m_bHeadless = true;
    else if (arg.Left(8) == _T("--viewer="))
        m_strHeadlessJoinKey = arg.Mid(8);
    else if (arg.Left(15) == _T("--metrics-port="))
        m_uHeadlessMetricsPort = (uint16)_ttoi(arg.Mid(15));
}
```

**En EmuleDlg.cpp `OnInitDialog`**, antes de `ShowWindow`:
```cpp
if (theApp.m_bHeadless) {
    ShowWindow(SW_HIDE);
    // Auto-join the configured stream
    if (!theApp.m_strHeadlessJoinKey.IsEmpty()) {
        // Wait 5s for Kad to bootstrap
        SetTimer(99001, 5000, [](HWND, UINT, UINT_PTR id, DWORD){
            uchar key[16];
            CStringA hex(theApp.m_strHeadlessJoinKey);
            if (EseHexToKey16A(hex, key) && theApp.liveStreamManager)
                theApp.liveStreamManager->JoinStream(key, _T("Headless"));
            KillTimer(NULL, id);
        });
    }
}
```

**Verificación**:
```powershell
Start-Process "C:\path\eMule.exe" -ArgumentList "--headless --viewer=ABCDEF1234567890ABCDEF1234567890 --metrics-port=4711"
Start-Sleep 10
# Debe haber proceso emule.exe sin ventana visible
Get-Process emule | Select Id, MainWindowHandle  # MainWindowHandle debe ser 0
```

**Éxito**: emule arranca, no muestra ventana, joinea el stream automáticamente.

---

### V2-S07 — Headless instance con metrics-port distinto por instancia

**Objetivo**: cada headless emule expone /metrics en puerto único, configurable.
**Tiempo**: 1 día.
**Prerequisito**: V2-S06.

**Archivos**:
- `srchybrid/Preferences.cpp` — override de WebServer port si flag presente

**Código en Preferences.cpp** después de leer WebServer section:
```cpp
if (theApp.m_uHeadlessMetricsPort > 0) {
    m_nWebPort = theApp.m_uHeadlessMetricsPort;
    m_bWebEnabled = true;  // forzar
    AddLogLine(false, _T("Headless: WebServer override port=%u"), m_nWebPort);
}
```

**Verificación**:
```powershell
# Lanza 3 instancias en puertos distintos
1..3 | ForEach-Object {
    Start-Process "C:\path\eMule.exe" -ArgumentList "--headless --viewer=KEY --metrics-port=$(4710+$_)"
    Start-Sleep 2
}
# Cada una debe responder en su puerto
@(4711,4712,4713) | ForEach-Object {
    Invoke-WebRequest "http://127.0.0.1:$_/api/live/metrics" -UseBasicParsing | Select StatusCode
}
```

**Éxito**: 3 procesos eMule distintos, cada uno responde en su puerto.

---

### V2-S08 — Orquestador Node.js para lanzar N instancias

**Objetivo**: script que lanza N viewers headless y agrega sus métricas.
**Tiempo**: 2 días.
**Prerequisito**: V2-S07.

**Archivos nuevos**:
- `tools/stress-test/orchestrator.js`
- `tools/stress-test/package.json`

**Código en `tools/stress-test/orchestrator.js`**:
```javascript
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');

const N = parseInt(process.argv[2]) || 10;
const STREAM_KEY = process.argv[3]; // hex 32 chars
const EMULE_EXE = process.argv[4] || 'C:\\path\\emule.exe';
const BASE_PORT = 4720;

if (!STREAM_KEY) { console.error("usage: orchestrator.js N STREAM_KEY [emule_exe_path]"); process.exit(1); }

const procs = [];
const metrics = new Array(N).fill(null);

for (let i = 0; i < N; i++) {
    const port = BASE_PORT + i;
    const args = ['--headless', `--viewer=${STREAM_KEY}`, `--metrics-port=${port}`];
    const proc = spawn(EMULE_EXE, args, { stdio: 'ignore', detached: true });
    procs.push({ proc, port, idx: i });
    console.log(`[${i}] launched pid=${proc.pid} port=${port}`);
}

// Cleanup on exit
process.on('SIGINT', () => {
    procs.forEach(({ proc }) => proc.kill());
    process.exit();
});

// Poll metrics every 5s
setInterval(() => {
    procs.forEach(({ port, idx }) => {
        http.get(`http://127.0.0.1:${port}/api/live/metrics`, (res) => {
            let body = '';
            res.on('data', c => body += c);
            res.on('end', () => {
                const lines = body.split('\n');
                const m = {};
                lines.forEach(l => {
                    const match = l.match(/^esmule_(\w+)(?:\{(.+)\})?\s+(\S+)/);
                    if (match) m[match[1]] = parseFloat(match[3]);
                });
                metrics[idx] = m;
            });
        }).on('error', () => { metrics[idx] = null; });
    });

    // Aggregate
    const live = metrics.filter(m => m !== null);
    if (live.length === 0) return;
    const totalChunksRecv = live.reduce((s,m) => s + (m.chunks_received_total||0), 0);
    const avgLatency = live.reduce((s,m) => s + (m.chunk_latency_ms||0), 0) / live.length;
    console.log(`[stress] alive=${live.length}/${N} totalChunks=${totalChunksRecv} avgLatency=${avgLatency.toFixed(0)}ms`);
}, 5000);
```

**`tools/stress-test/package.json`**:
```json
{ "name": "stress-test", "version": "1.0.0", "main": "orchestrator.js" }
```

**Verificación**:
```powershell
# Primero arranca un broadcaster
# Luego en otra terminal:
cd tools\stress-test
node orchestrator.js 10 ABCDEF1234567890ABCDEF1234567890 "C:\path\emule.exe"
# Debe lanzar 10 procesos eMule.exe
# Cada 5s imprime stats agregadas
```

**Éxito**: 10 procesos lanzados, log muestra `alive=10/10`, contadores crecen.

---

### V2-S09 — Dashboard agregador con grafico

**Objetivo**: web dashboard que muestra agregado de N viewers en tiempo real.
**Tiempo**: 1-2 días.
**Prerequisito**: V2-S08.

**Archivo nuevo**: `tools/stress-test/dashboard.html`

**Código** (servir desde orchestrator.js):
```html
<!DOCTYPE html><html><head><title>Stress Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script></head>
<body><h1>Stress Test Dashboard</h1>
<div id="stats"></div>
<canvas id="chart" width="800" height="300"></canvas>
<script>
const ctx = document.getElementById('chart').getContext('2d');
const chart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [
        { label: 'Avg Latency (ms)', data: [], borderColor: 'red' },
        { label: 'Alive Viewers', data: [], borderColor: 'green', yAxisID: 'y2' }
    ]},
    options: { scales: { y: {position:'left'}, y2:{position:'right'} } }
});

setInterval(async () => {
    const r = await fetch('/aggregate'); const d = await r.json();
    document.getElementById('stats').innerHTML = JSON.stringify(d, null, 2);
    const t = new Date().toLocaleTimeString();
    chart.data.labels.push(t);
    chart.data.datasets[0].data.push(d.avgLatency);
    chart.data.datasets[1].data.push(d.alive);
    if (chart.data.labels.length > 60) {
        chart.data.labels.shift();
        chart.data.datasets.forEach(ds => ds.data.shift());
    }
    chart.update();
}, 5000);
</script></body></html>
```

**En orchestrator.js añadir HTTP server**:
```javascript
const server = http.createServer((req, res) => {
    if (req.url === '/') {
        res.writeHead(200, {'Content-Type':'text/html'});
        fs.createReadStream(__dirname+'/dashboard.html').pipe(res);
    } else if (req.url === '/aggregate') {
        const live = metrics.filter(m => m !== null);
        res.writeHead(200, {'Content-Type':'application/json'});
        res.end(JSON.stringify({
            alive: live.length, total: N,
            avgLatency: live.reduce((s,m)=>s+(m.chunk_latency_ms||0),0)/Math.max(1,live.length),
            totalChunks: live.reduce((s,m)=>s+(m.chunks_received_total||0),0)
        }));
    }
});
server.listen(8090);
console.log("Dashboard: http://localhost:8090");
```

**Verificación**: abre `http://localhost:8090`, debe mostrar gráfico tiempo real.

**Éxito**: dashboard funcional, gráfico actualiza cada 5s.

---

### V2-S10 — Sweep automatizado N=10/50/100 con report

**Objetivo**: ejecutar tests con N progresivo y generar report HTML.
**Tiempo**: 1 día.
**Prerequisito**: V2-S09.

**Archivo nuevo**: `tools/stress-test/sweep.js`

**Código**:
```javascript
const { execSync, spawn } = require('child_process');
const http = require('http');
const fs = require('fs');

async function runSweep(STREAM_KEY) {
    const results = [];
    for (const N of [10, 50, 100]) {
        console.log(`\n=== Running with N=${N} viewers ===`);
        const orch = spawn('node', ['orchestrator.js', N, STREAM_KEY], { stdio: 'inherit' });
        await new Promise(r => setTimeout(r, 60000)); // 1 min de carga
        // Snapshot final
        const snap = await new Promise(resolve => {
            http.get('http://127.0.0.1:8090/aggregate', res => {
                let b = ''; res.on('data', c => b += c); res.on('end', () => resolve(JSON.parse(b)));
            });
        });
        results.push({ N, ...snap });
        orch.kill();
        await new Promise(r => setTimeout(r, 5000));
    }
    fs.writeFileSync('sweep-report.json', JSON.stringify(results, null, 2));
    console.log(JSON.stringify(results, null, 2));
}

runSweep(process.argv[2]);
```

**Verificación**:
```powershell
node sweep.js ABCDEF1234567890ABCDEF1234567890
# Tarda ~3 minutos, genera sweep-report.json
```

**Éxito**: report con resultados a N=10/50/100 viewers, latencia y % alive identificable.

---

## Bloque C — Auto-tier classification + ratio enforcement (V2-S11 a V2-S15)

Implementación del principio de contribución obligatoria (MASTER_PLAN §1bis).

### V2-S11 — Bandwidth probe al startup

**Objetivo**: medir upload del peer al arrancar (test de 3-5s).
**Tiempo**: 2 días.
**Referencia**: MASTER_PLAN §1bis.3.

**Archivos**:
- `srchybrid/LiveStreamManager.h` — declarar `MeasureUploadCapacity`
- `srchybrid/LiveStreamManager.cpp` — implementación

**Código**:
```cpp
class CLiveStreamManager {
    // ...
    DWORD m_measuredUploadKbps = 0;  // Resultado de probe inicial
    void MeasureUploadCapacity();    // Llama desde Init()
};

void CLiveStreamManager::MeasureUploadCapacity() {
    // Estrategia: enviar 1 MB de datos a un super-seeder conocido,
    // medir tiempo. Si no hay super-seeder, asumir capacity=0 (leaf).
    if (!Kademlia::CKademlia::IsConnected()) {
        m_measuredUploadKbps = 0;
        return;
    }

    // Por simplicidad inicial: usar el upload limit configurado en preferences
    // como proxy. En sprints posteriores hacer probe real.
    m_measuredUploadKbps = thePrefs.GetMaxUpload() * 8;  // KB/s → kbps
    if (m_measuredUploadKbps == 0) m_measuredUploadKbps = 999999;  // unlimited
    LIVE_LOG("TIER", "Measured upload: %u kbps", m_measuredUploadKbps);
}
```

**Llamar desde** `CLiveStreamManager::Init` (existe ya?, si no añadir).

**Verificación**:
```powershell
# Tras lanzar emule, log debe contener:
(Invoke-WebRequest 'http://127.0.0.1:4711/api/live/log?n=20' -UseBasicParsing).Content |
  ConvertFrom-Json | Select -Expand items | Where { $_ -like "*[TIER]*" }
```
**Éxito**: log muestra `[TIER] Measured upload: N kbps` con valor coherente con tu MaxUpload setting.

---

### V2-S12 — Auto-classification a tier (leaf-restricted/leaf/mid/super-seeder/mega-seeder)

**Objetivo**: clasificar el peer según upload medido y bitrate del stream.
**Tiempo**: 1 día.
**Prerequisito**: V2-S11.

**Código**:
```cpp
enum PeerTier {
    TIER_LEAF_RESTRICTED = 0,  // Solo recibe variant low
    TIER_LEAF             = 1,
    TIER_MID              = 2,
    TIER_SUPER_SEEDER     = 3,
    TIER_MEGA_SEEDER      = 4
};

PeerTier CLiveStreamManager::ComputeMyTier(uint16 stream_bitrate_kbps) {
    if (m_measuredUploadKbps == 0) return TIER_LEAF_RESTRICTED;
    float ratio = (float)m_measuredUploadKbps / stream_bitrate_kbps;
    if (ratio < 0.5)  return TIER_LEAF_RESTRICTED;
    if (ratio < 1.5)  return TIER_LEAF;
    if (ratio < 4.0)  return TIER_MID;
    if (ratio < 10.0) return TIER_SUPER_SEEDER;
    return TIER_MEGA_SEEDER;
}

const char* TierName(PeerTier t) {
    switch(t) {
        case TIER_LEAF_RESTRICTED: return "leaf-restricted";
        case TIER_LEAF:            return "leaf";
        case TIER_MID:             return "mid";
        case TIER_SUPER_SEEDER:    return "super-seeder";
        case TIER_MEGA_SEEDER:     return "mega-seeder";
    }
    return "unknown";
}
```

**Logging cuando join broadcast**:
```cpp
PeerTier myTier = ComputeMyTier(m_streamInfo.bitrate);
LIVE_LOG("TIER", "My tier: %s (upload=%u kbps, stream=%u kbps)",
    TierName(myTier), m_measuredUploadKbps, m_streamInfo.bitrate);
```

**Verificación**:
- Configura MaxUpload en eMule a 10 KB/s (= 80 kbps)
- Para stream 3000 kbps: ratio=80/3000=0.027, debe clasificarse como `leaf-restricted`
- Configura MaxUpload a 1500 KB/s (= 12000 kbps): ratio=4, clasifica como `super-seeder`

**Éxito**: tier coincide con cálculo manual.

---

### V2-S13 — Cap de uploads simultáneos según tier

**Objetivo**: rechazar SUBSCRIBE si ya estamos al cap del tier.
**Tiempo**: 2 días.
**Prerequisito**: V2-S12.

**Código** en `OnPeerJoin`:
```cpp
int CLiveStreamManager::MaxConcurrentUploads() const {
    PeerTier t = ComputeMyTier(m_streamInfo.bitrate);
    switch(t) {
        case TIER_LEAF_RESTRICTED: return 0;
        case TIER_LEAF:            return 1;
        case TIER_MID:             return 3;
        case TIER_SUPER_SEEDER:    return 10;
        case TIER_MEGA_SEEDER:     return 25;
    }
    return 0;
}

void CLiveStreamManager::OnPeerJoin(...) {
    if ((int)m_broadcastPeers.GetCount() >= MaxConcurrentUploads()) {
        LIVE_LOG("CAP", "Rejecting SUBSCRIBE from %S:%u — cap reached (%d)",
            (LPCWSTR)ipstr(peer->GetIP()), peer->GetUserPort(), MaxConcurrentUploads());
        // Send REJECT packet with redirect list
        SendRejectWithRedirect(peer);
        return;
    }
    // ... resto de OnPeerJoin como antes
}
```

**Implementar SendRejectWithRedirect**:
```cpp
void CLiveStreamManager::SendRejectWithRedirect(CUpDownClient* peer) {
    // Coleccionar IPs de los super-seeders conocidos
    CArray<DWORD> ips; CArray<uint16> ports;
    POSITION pos = m_broadcastPeers.GetHeadPosition();
    while (pos && ips.GetCount() < 5) {
        CUpDownClient* p = m_broadcastPeers.GetNext(pos);
        if (p && p->GetIP() != 0) {
            ips.Add(p->GetIP());
            ports.Add(p->GetUserPort());
        }
    }
    Packet* pkt = eSELive::CreatePeerListPacket(
        m_streamInfo.streamKey, ips.GetData(), ports.GetData(), (uint16)ips.GetCount());
    if (pkt) peer->SendPacket(pkt);
}
```

**Verificación**:
- Configura MaxUpload bajo (TIER_LEAF, cap=1)
- Conecta 2 viewers
- Segundo viewer debe ver REJECT/redirect en su log
- `[CAP] Rejecting SUBSCRIBE` debe aparecer en broadcaster log

**Éxito**: cap se respeta, viewers rechazados reciben lista alternativa.

---

### V2-S14 — Ratio enforcement gradient throttle

**Objetivo**: peer con ratio bajo recibe a velocidad reducida.
**Tiempo**: 2 días.
**Prerequisito**: V2-S02 (ventana 60s ya existe).

**Código** modificar `OnPeerRequest`:
```cpp
void CLiveStreamManager::OnPeerRequest(CUpDownClient* peer, ...) {
    // ... checks existentes (rate limit, etc.)

    // NUEVO: ratio gradient throttle
    auto& counters = m_peerCounters[peer];
    counters.MaybeResetWindow();
    float ratio = counters.Ratio60s();

    // Throttle policy:
    //  ratio >= 0.7  → full speed
    //  0.4 <= ratio < 0.7 → drop 1 of every 5 requests
    //  0.0 <= ratio < 0.4 → drop 4 of every 5 requests
    static thread_local int dropCounter = 0;
    if (ratio < 0.4f) {
        if ((++dropCounter % 5) != 0) {
            LIVE_LOG("RATIO", "Throttle (low ratio %.2f) drop seq=%u from %S",
                ratio, seqNum, (LPCWSTR)ipstr(peer->GetIP()));
            return;
        }
    } else if (ratio < 0.7f) {
        if ((++dropCounter % 5) == 0) {
            LIVE_LOG("RATIO", "Throttle (medium ratio %.2f) drop seq=%u",
                ratio, seqNum);
            return;
        }
    }

    // ... resto del código de OnPeerRequest (servir el chunk)
}
```

**Verificación**:
- Conecta viewer con MaxUpload=0 (no contribuye)
- Tras 60s, ratio < 0.4
- Log debe mostrar `[RATIO] Throttle ... drop`
- Viewer experiencia chunks perdidos / latencia mayor

**Éxito**: throttle aplicado proporcionalmente al ratio.

---

### V2-S15 — Bootstrap gracia para primeros 5 viewers

**Objetivo**: no aplicar ratio enforcement durante primeros 5 viewers (bootstrap).
**Tiempo**: 1 día.
**Prerequisito**: V2-S14.

**Código** en throttle policy:
```cpp
// Bootstrap grace: primeros 5 viewers no son throttled
int total_viewers = (int)m_broadcastPeers.GetCount();
float ratio_required;
if      (total_viewers <= 5)  ratio_required = 0.0f;
else if (total_viewers <= 20) ratio_required = (total_viewers - 5) / 15.0f * 0.7f;  // gradient
else                          ratio_required = 0.7f;

if (ratio < ratio_required - 0.3f) {
    // strong throttle
} else if (ratio < ratio_required) {
    // medium throttle
} else {
    // full speed
}
```

**Verificación**:
- Lanza broadcast solo (broadcasting peer = source)
- Conecta 1 viewer sin contribución
- Log NO debe mostrar throttle (bootstrap)
- Conecta 30 viewers → throttle aplica a los que no contribuyen

**Éxito**: bootstrap funciona, gradient suave.

---

## Bloque D — Tree formation + multi-parent (V2-S16 a V2-S22)

Implementación de §11.3.1 (tree con warm spares + mesh fallback).

### V2-S16 — Cap de viewers directos al broadcaster

**Objetivo**: broadcaster no acepta más de N viewers directos (default 10).
**Tiempo**: 1 día.
**Prerequisito**: V2-S13 (la lógica de cap ya existe).

**Código** — añadir constante específica para broadcaster:
```cpp
static const int BROADCASTER_MAX_DIRECT_VIEWERS = 10;

// En OnPeerJoin del broadcaster específicamente:
if (m_bBroadcasting && (int)m_broadcastPeers.GetCount() >= BROADCASTER_MAX_DIRECT_VIEWERS) {
    LIVE_LOG("CAP", "Broadcaster cap reached, redirecting peer to super-seeders");
    SendRejectWithRedirect(peer);
    return;
}
```

**Verificación**:
- Lanza broadcast
- Conecta 11 viewers
- Viewer #11 debe recibir redirect
- Broadcaster log: `[CAP] Broadcaster cap reached`

**Éxito**: viewers 1-10 conectan al broadcaster, viewer 11+ redirigidos.

---

### V2-S17 — Viewer publica su bitmap a Kad como source

**Objetivo**: cualquier peer con buffer >5 segs anuncia a Kad bajo `livehash:<HASH>`.
**Tiempo**: 2 días.
**Prerequisito**: ninguno.
**Referencia**: MASTER_PLAN §11.3.7.

**Código** en `LiveKadBridge.cpp`:
```cpp
// Nueva función: publicar como secondary source
void CLiveKadBridge::PublishAsSecondarySource(const uchar* streamKey, const LiveStreamInfo& info) {
    if (!Kademlia::CKademlia::IsConnected()) return;

    CString hashKeyword = _T("livehash:");
    for (int i = 0; i < 16; ++i) {
        CString h; h.Format(_T("%02x"), streamKey[i]);
        hashKeyword += h;
    }

    Kademlia::CUInt128 uTarget;
    Kademlia::CKadTagValueString wstrKw(hashKeyword);
    KadGetKeywordHash(wstrKw, &uTarget);

    Kademlia::CSearch* pSearch = Kademlia::CSearchManager::PrepareLookup(
        Kademlia::CSearch::STOREKEYWORD, false, uTarget);
    if (pSearch) {
        // Marca "secondary" para que viewers sepan que no es el broadcaster origen
        pSearch->SetLiveStreamPublish(streamKey, info.title, info.category,
            info.language, info.bitrate, 0, info.startedAt, thePrefs.GetPort());
        LIVE_LOG("KAD", "Secondary source publish: livehash:%s", (LPCSTR)CT2A(hashKeyword));
    }
}
```

**Llamar desde** `Process()` cuando viewer:
```cpp
// En CLiveStreamManager::Process(), si soy viewer y tengo buffer > 5:
if (m_bViewing && m_chunkBuffer.GetCount() > 5) {
    DWORD now = GetTickCount();
    if (now - m_dwLastSecondaryPublish > 30000) { // cada 30s
        m_kadBridge.PublishAsSecondarySource(m_streamInfo.streamKey, m_streamInfo);
        m_dwLastSecondaryPublish = now;
    }
}
```

**Verificación**:
- Broadcast PC1, viewer PC2
- Tras 60s, viewer PC2 con count >5
- En PC2 log debe aparecer: `[KAD] Secondary source publish`
- En tercer PC al hacer JoinStream debe encontrar PC1 + PC2 como sources

**Éxito**: viewers se anuncian a Kad, otros viewers les encuentran.

---

### V2-S18 — Viewer prefiere conectar a otros viewers antes que al broadcaster

**Objetivo**: peer nuevo busca super-seeders en Kad, conecta primero a ellos.
**Tiempo**: 2 días.
**Prerequisito**: V2-S17.

**Código** modificar `JoinStream`:
```cpp
bool CLiveStreamManager::JoinStream(const uchar* streamKey, const CString& title) {
    // ... código existente

    // Buscar PRIMERO peers en Kad (livehash) en vez de directo al broadcaster
    CString hashSearch(_T("livehash:"));
    for (int i = 0; i < 16; ++i) {
        CString h; h.Format(_T("%02x"), streamKey[i]);
        hashSearch += h;
    }

    // Trigger búsqueda y esperar 5s a resultados (TODO: hacer async no bloquear)
    m_kadBridge.SearchStreams(hashSearch);

    // Esperar a que lleguen al menos 3-5 candidates antes de conectar
    // (en sprint siguiente lo hacemos async; aquí síncrono simple)
    // Por ahora: si tras 5s no hay candidates, fallback a broadcaster

    return true;
}
```

**Verificación**:
- Setup: 1 broadcaster + 1 viewer (warming up)
- Lanza tercer viewer
- Log debe mostrar search por `livehash:...`
- Tercer viewer debería conectar a viewer #1, no a broadcaster (si Kad funciona)

**Éxito**: tercer viewer conecta a peer, no a broadcaster.

---

### V2-S19 — Multi-parent: mantener 3 conexiones simultáneas

**Objetivo**: cada viewer mantiene 3 sources activos (primario + 2 warm spare).
**Tiempo**: 3 días.
**Prerequisito**: V2-S18.

**Código** — extender `m_viewPeers` con concept de "primary/spare":
```cpp
enum ParentRole { PARENT_PRIMARY, PARENT_SPARE_1, PARENT_SPARE_2 };

struct ParentInfo {
    CUpDownClient* peer;
    ParentRole role;
    DWORD last_chunk_received_ms;
};

CMap<CUpDownClient*, CUpDownClient*, ParentInfo, ParentInfo> m_parents;

void CLiveStreamManager::EnsureMultiParent() {
    if (!m_bViewing) return;
    if (m_parents.GetCount() >= 3) return;

    // Buscar más sources en Kad
    CString hashSearch(_T("livehash:"));
    for (int i=0; i<16; ++i) { CString h; h.Format(_T("%02x"), m_streamInfo.streamKey[i]); hashSearch += h; }
    m_kadBridge.SearchStreams(hashSearch);
}

// Llamar desde Process() cada 5s
```

**Switching de primary cuando timeout**:
```cpp
void CLiveStreamManager::CheckParentHealth() {
    DWORD now = GetTickCount();
    POSITION pos = m_parents.GetStartPosition();
    while (pos) {
        CUpDownClient* p = nullptr; ParentInfo info;
        m_parents.GetNextAssoc(pos, p, info);
        if (info.role == PARENT_PRIMARY && now - info.last_chunk_received_ms > 5000) {
            // Primary timeout — promote spare to primary
            POSITION pos2 = m_parents.GetStartPosition();
            while (pos2) {
                CUpDownClient* sp = nullptr; ParentInfo si;
                m_parents.GetNextAssoc(pos2, sp, si);
                if (si.role == PARENT_SPARE_1) {
                    si.role = PARENT_PRIMARY;
                    info.role = PARENT_SPARE_2;
                    m_parents[sp] = si;
                    m_parents[p] = info;
                    LIVE_LOG("PARENT", "Failover: promoted spare to primary, RTT switch <500ms");
                    break;
                }
            }
        }
    }
}
```

**Verificación**:
- 1 broadcaster + 3 viewers (con multi-parent)
- Mata 1 viewer brutalmente
- Log debe mostrar `[PARENT] Failover: promoted spare`
- Otros viewers no deben tener pause >2s

**Éxito**: failover sub-segundo, sin freeze visible.

---

### V2-S20 — Mesh fallback: si gap en chunks, pull de cualquier peer

**Objetivo**: si llega chunk N+5 pero no N+1, pedir N+1 a otro peer (no esperar al primary).
**Tiempo**: 2 días.
**Prerequisito**: V2-S19.

**Código** en `RequestMissingSegments` (ya existe):
```cpp
// Modificar SelectPeerForSegment para que NO solo elija el primary,
// sino el peer con menor RTT que tenga ese seqNum

CUpDownClient* CLiveStreamManager::SelectPeerForSegment(uint32 seqNum) {
    CUpDownClient* best = nullptr;
    DWORD best_rtt = UINT_MAX;
    POSITION pos = m_peerBitmaps.GetStartPosition();
    while (pos) {
        CUpDownClient* p = nullptr; PeerBitmapInfo info;
        m_peerBitmaps.GetNextAssoc(pos, p, info);
        // Check if this peer has the chunk
        uint32 bit = seqNum - info.oldestSeq;
        if (bit < 16 && (info.bitmap & (1 << bit))) {
            DWORD rtt = m_peerCounters[p].rtt_ms_ewma;
            if (rtt > 0 && rtt < best_rtt) { best_rtt = rtt; best = p; }
        }
    }
    return best;
}
```

**Verificación**:
- Setup mesh con 3+ viewers y broadcaster
- Force packet loss (firewall block en 1 peer temporalmente)
- Viewer afectado debe pedir chunks faltantes a OTROS peers
- `[REQ] ASK seq=N -> X.X.X.X` debe variar de IP

**Éxito**: gap recovery funciona desde mesh, no solo desde primary.

---

### V2-S21 — Push proactivo: peer envía chunk a hijos cuando lo recibe

**Objetivo**: en vez de esperar request, peer empuja chunks a sus hijos.
**Tiempo**: 2 días.
**Prerequisito**: V2-S19.

**Código** — añadir en `OnChunkReceived` (lado viewer):
```cpp
void CLiveStreamManager::OnChunkReceived(...) {
    // ... código existente

    // NUEVO: si tengo "children" (peers que me han hecho SUBSCRIBE),
    // empujar este chunk a ellos sin esperar a que pidan
    if (m_chunksWeServeAsRelay.find(streamKey_hex) != m_chunksWeServeAsRelay.end()) {
        POSITION pos = m_broadcastPeers.GetHeadPosition(); // peers que NOS subscriben
        while (pos) {
            CUpDownClient* child = m_broadcastPeers.GetNext(pos);
            Packet* pkt = eSELive::CreateChunkPacket(/*chunk*/);
            if (pkt) {
                child->SendPacket(pkt, true);  // bVerifyConnection
                LIVE_LOG("RELAY", "Push seq=%u to child %S", seqNum, (LPCWSTR)ipstr(child->GetIP()));
            }
        }
    }
}
```

**Verificación**:
- 1 broadcaster + viewer A + viewer B (B subscribe a A)
- Chunk llega a A
- Log de A debe mostrar `[RELAY] Push seq=N to child <B>`
- B recibe sin tener que pedir

**Éxito**: relay funciona, B no envía REQUEST para chunks que A le push.

---

### V2-S22 — Anycast spare-capacity (SplitStream pattern)

**Objetivo**: peer huérfano (todos sus parents caídos) busca capacity disponible vía broadcast Kad.
**Tiempo**: 2 días.
**Prerequisito**: V2-S19.

**Código**:
```cpp
void CLiveStreamManager::AnycastForCapacity() {
    if (m_parents.GetCount() > 0) return;  // ya tengo parents

    // Publicar a Kad: "necesito un parent para streamKey X"
    CString anycastKw(_T("livehelp:"));
    for (int i=0; i<16; ++i) { CString h; h.Format(_T("%02x"), m_streamInfo.streamKey[i]); anycastKw += h; }

    Kademlia::CUInt128 uTarget;
    Kademlia::CKadTagValueString wstrKw(anycastKw);
    KadGetKeywordHash(wstrKw, &uTarget);
    // ... search publish con TTL corto (10s)
    LIVE_LOG("ANYCAST", "Searching for spare capacity (orphan)");
}

// Peers con capacity sobrante deben SUSCRIBIRSE a este keyword anycast
// y responder ofreciendo conexión
```

**Verificación**:
- Setup mesh, mata todos los parents de un viewer
- Viewer log: `[ANYCAST] Searching for spare capacity`
- Algún peer responde, viewer reconecta

**Éxito**: viewers huérfanos se recuperan automáticamente.

---

## Bloque E — NAT improvements (V2-S23 a V2-S26)

### V2-S23 — IPv6 awareness en Kad y peer connections

**Objetivo**: si peer tiene AAAA, preferir IPv6 (free HighID).
**Tiempo**: 3 días.
**Referencia**: MASTER_PLAN §11.3.8.

**Archivos**:
- `srchybrid/kademlia/io/IOBuffer.cpp` — leer IPv6 contacts
- Múltiples cambios en networking

**Esto es trabajo grande** — postponer a fase específica si no urgente.
**Verificación quick win**: detectar si OS tiene IPv6 y reportar en log:
```cpp
SOCKET s6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
bool hasV6 = (s6 != INVALID_SOCKET);
if (hasV6) closesocket(s6);
LIVE_LOG("NET", "IPv6 socket creation: %s", hasV6 ? "OK" : "FAILED");
```

---

### V2-S24 — miniupnpc al startup para NAT-PMP/PCP

**Objetivo**: pedir port forward via UPnP/PCP/NAT-PMP automáticamente.
**Tiempo**: 2 días.

**Bibliotecas**: miniupnpc ya está conocida en eMule. Verificar `srchybrid/upnplib/`
existe.

**Código** — llamar desde startup:
```cpp
#include "upnplib/miniupnpc.h"
void CLiveStreamManager::TryUPnPMapping() {
    int error = 0;
    UPNPDev* devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, &error);
    if (!devlist) { LIVE_LOG("UPNP", "No UPnP device found"); return; }

    UPNPUrls urls; IGDdatas data;
    char lanaddr[64];
    int igdfound = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (igdfound > 0) {
        char port[8]; snprintf(port, 8, "%u", thePrefs.GetPort());
        int r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
            port, port, lanaddr, "eMule eSE Live", "TCP", NULL, "0");
        if (r == UPNPCOMMAND_SUCCESS)
            LIVE_LOG("UPNP", "Port %u mapped successfully", thePrefs.GetPort());
    }
    FreeUPNPUrls(&urls);
    freeUPNPDevlist(devlist);
}
```

**Verificación**:
```powershell
# Después de lanzar emule:
(Invoke-WebRequest 'http://127.0.0.1:4711/api/live/log?n=20' -UseBasicParsing).Content |
  ConvertFrom-Json | Select -Expand items | Where { $_ -like "*[UPNP]*" }
```
**Éxito**: log indica port mapping. Verificar también con `netsh interface portproxy show all` o router UI.

---

### V2-S25 — Birthday-paradox UDP hole-punching

**Objetivo**: cuando hole-punch falla, intentar abrir múltiples sockets locales.
**Tiempo**: 3 días.
**Referencia**: MASTER_PLAN §11.3.8 (tailscale/danderson nat-birthday-paradox).

**Implementación**: complejo, requiere modificar stack de uTP/Kad.
**Resumen**: en vez de abrir 1 socket UDP, abrir 256 sockets a puertos secuenciales,
y disparar 1024 STUN-like probes en paralelo. Probabilidad colisión ~98%.

**Código skeleton**:
```cpp
bool CLiveStreamManager::BirthdayPunchHard(uint32 targetIP, uint16 targetPort) {
    const int N_SOCKETS = 256;
    const int N_PROBES = 1024;
    SOCKET sockets[N_SOCKETS];
    for (int i = 0; i < N_SOCKETS; ++i) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        // bind to local random port
    }
    // Send N_PROBES STUN binding requests to predicted target ports
    // Listen on all 256 sockets for response
    // Return true if any received
}
```

**Verificación**: difícil sin 2 LowID reales en NATs distintos. Postponer.

---

### V2-S26 — STUN classification al arranque

**Objetivo**: clasificar tipo de NAT (full cone / restricted / port-restricted / symmetric).
**Tiempo**: 2 días.

**Código**: usar libnice o miniupnpc o impl manual de STUN (RFC 5389):
```cpp
// Pseudo:
int CLiveStreamManager::ClassifyNAT() {
    // Llamar a stun.l.google.com o similar
    // Si dos requests dan distintas externIP → symmetric
    // Si dos requests dan misma externIP pero distintas externPORT → port-restricted
    // ... etc
    // Resultado: 0=open, 1=full-cone, 2=restricted, 3=port-restricted, 4=symmetric
}
```

**Loggear** y exponer en /api/live/debug:
```cpp
LIVE_LOG("STUN", "NAT type classified: %s", NatTypeName(natType));
```

**Verificación**: forzar peer detrás de NAT distintos, comparar.

---

## Bloque F — Hardening básico (V2-S27 a V2-S30)

### V2-S27 — Sanitizers ASAN+UBSAN en CI

**Objetivo**: cualquier PR con UB falla CI.
**Tiempo**: 1 día.

**Archivos**:
- `.github/workflows/sanitizers.yml` (o equivalente Azure Pipelines)

**Yaml ejemplo**:
```yaml
name: Sanitizers
on: [push, pull_request]
jobs:
  asan:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build with ASAN
        run: |
          msbuild srchybrid/emule.vcxproj /p:Configuration=Release /p:Platform=x64 /p:UseAddressSanitizer=true
      - name: Smoke test
        run: |
          .\srchybrid\x64\Release\emule.exe --headless --selftest
```

**Implementar** `--selftest`:
```cpp
if (m_bSelfTest) {
    // Basic smoke: init, broadcast 5s, stop, exit
    theApp.liveStreamManager->StartBroadcastWithSource(_T("testpattern"), ...);
    Sleep(5000);
    theApp.liveStreamManager->StopBroadcast();
    PostQuitMessage(0);
}
```

**Verificación**: corre CI, debe pasar verde. Si introduces UB intencional, debe fallar.

---

### V2-S28 — Fuzz testing protocol parsers con AFL++

**Objetivo**: descubrir bugs de parsing automáticamente.
**Tiempo**: 2-3 días setup.

**Crear** `tests/fuzz/fuzz_packet_parser.cpp`:
```cpp
#include "LivePackets.h"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 5) return 0;
    // Try to parse as each packet type
    eSELive::ParsePacket(data, size);
    return 0;
}
```

**Build con clang+libFuzzer**:
```bash
clang++ -fsanitize=fuzzer,address -g -O1 fuzz_packet_parser.cpp LivePackets.cpp -o fuzz_target
./fuzz_target -max_total_time=3600  # 1 hour
```

**Verificación**: fuzz corre 1h, debe NO crashear. Si crashea, fix el bug y re-fuzz.

---

### V2-S29 — Bounds checking en packet parsers

**Objetivo**: cada parsing valida tamaño antes de leer.
**Tiempo**: 3-5 días (auditoría completa).

**Patrón a aplicar**:
```cpp
// MAL:
uint32 seq = *(uint32*)(data + offset);
offset += 4;

// BIEN:
if (offset + 4 > size) return false;  // out of bounds
uint32 seq;
memcpy(&seq, data + offset, 4);  // memcpy = no UB
offset += 4;
```

**Aplicar en**: LivePackets.cpp, todos los `OP_LIVE_*` handlers de WebServer.cpp.

**Verificación**: re-correr fuzz V2-S28 después de fix; ya no debe crashear con inputs aleatorios.

---

### V2-S30 — Pinned dependencies + signed releases

**Objetivo**: prevenir supply chain attacks.
**Tiempo**: 1 día.

**Para Node.js (eSE)**:
```bash
cd srchybrid/eSE
npm install --package-lock-only
git add package-lock.json
```

**Para C++ deps**: vcpkg manifest:
```json
{
  "name": "emule-ese",
  "version": "0.70.1",
  "dependencies": [
    { "name": "miniupnpc", "version>=": "2.2.5" },
    { "name": "openssl", "version>=": "3.0.0" }
  ]
}
```

**Sign release**:
```powershell
# Generar GPG key una vez
gpg --gen-key
# Para cada release:
gpg --detach-sign --armor eMule.exe
gpg --detach-sign --armor eSE-Live-Portable.zip
```

Publicar `releases/v0.70.1/eMule.exe.asc` junto al .exe.

**Verificación**: usuario puede `gpg --verify eMule.exe.asc eMule.exe`.

---

## Resumen de Sprints v2

**Total: 30 sprints, ~2-3 meses calendario para 1 dev tiempo completo, 6 meses media jornada.**

| Bloque | Sprints | Output |
|---|---|---|
| A. Observabilidad | S01-S05 | Métricas reales, dashboard Prometheus |
| B. Stress simulator | S06-S10 | Validar escala automáticamente |
| C. Auto-tier + ratio | S11-S15 | Network effect arranca |
| D. Tree + multi-parent | S16-S22 | Topología real, no estrella |
| E. NAT improvements | S23-S26 | Más peers son HighID |
| F. Hardening básico | S27-S30 | Defensa contra bugs y supply chain |

## Cómo proceder día a día

1. **Cada mañana**: pick un sprint pendiente, leer su prerequisitos
2. **Trabajar en una rama**: `git checkout -b sprint/V2-SXX-titulo`
3. **Implementar** siguiendo código pegable
4. **Verificar** con los comandos del sprint
5. **Commit** con mensaje `[V2-SXX] <título>`
6. **PR a main**, CI corre sanitizers automáticamente
7. **Merge** cuando verde

## Cuando algo se rompe

- **Build no compila**: revisar incluyes y namespaces. Buscar el header del símbolo no resuelto.
- **eMule crashea al arrancar**: lanzar bajo VS debugger, breakpoint en CLiveStreamManager constructor.
- **Métricas no aparecen**: verificar WebServer está bindeado (sec 12 troubleshooting MASTER_PLAN).
- **Stress test no escala**: empezar con N=2 y bajar bitrate, ver dónde rompe.

## Métricas de éxito globales tras v2

Si todos los sprints implementados correctamente, deberías poder:
- ✅ Stress test 50 viewers sin caídas, latencia <5s p95
- ✅ Dashboard Prometheus + Grafana funcional
- ✅ CI fail si introduces UB (sanitizers detectan)
- ✅ Multi-parent failover sub-segundo
- ✅ Mesh fallback recupera gaps de chunks
- ✅ Free-riders throttled gradualmente
- ✅ Broadcaster solo sirve a 10 super-seeders, resto via tree
- ✅ Releases signed con GPG, deps pinned

**Siguiente fase**: SPRINTS_V3.md (SRT, RLNC FEC, WebRTC bridge, E2EE, anonimato relay-first).
