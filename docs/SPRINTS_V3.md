# Sprints v3 — de 5,000 a 50,000 viewers

**Prerequisito**: SPRINTS_V2.md completo y validado con stress test ≥500 viewers.

Cada sprint = **2-5 días de trabajo** (más complejo que v2). Algunos requieren
**decisiones de diseño** marcadas con ⚠️ — son sprints más "esqueleto" que
v2. Lee MASTER_PLAN.md §11.3 antes de empezar.

**Convención**: sprints `V3-SXX`. Más fundamentales que v2 (cambian transport,
añaden WebRTC, etc.) — esperar bugs de integración mayores.

---

## Bloque A — Transport switch a SRT (V3-S01 a V3-S05)

Reemplazar TCP eD2K por SRT en la live path. **Cambio mayor** — afecta a todo
el código de paquetes.

### V3-S01 — Integrar libsrt 1.5.4 al build

**Objetivo**: emule.exe linka contra libsrt.dll y puede crear sockets SRT.
**Tiempo**: 2-3 días.
**Prerequisito**: V2 completo.
**Referencia**: MASTER_PLAN §11.3.3.

**Bibliotecas externas**:
- libsrt 1.5.4 (https://github.com/Haivision/srt) — MIT
- Dependencia OpenSSL 3.x (probablemente ya en eMule)

**Setup vcpkg**:
```bash
cd vcpkg
.\vcpkg install srt:x64-windows-static
```

**Modificar emule.vcxproj** — añadir include + lib paths:
```xml
<AdditionalIncludeDirectories>vcpkg\installed\x64-windows-static\include;...</AdditionalIncludeDirectories>
<AdditionalDependencies>srt.lib;...</AdditionalDependencies>
```

**Crear** `srchybrid/SRTSocket.h` — wrapper minimal:
```cpp
#pragma once
#include <srt/srt.h>

class CSRTSocket {
public:
    CSRTSocket();
    ~CSRTSocket();
    bool BindAndListen(uint16 port);
    bool Connect(const char* ip, uint16 port);
    int  Send(const BYTE* data, int len);
    int  Recv(BYTE* buf, int len);
    void SetLatencyMs(int ms);  // SRTO_LATENCY
private:
    SRTSOCKET m_sock;
};
```

**Implementación básica**:
```cpp
CSRTSocket::CSRTSocket() : m_sock(SRT_INVALID_SOCK) {
    static bool inited = false;
    if (!inited) { srt_startup(); inited = true; }
    m_sock = srt_create_socket();
}

void CSRTSocket::SetLatencyMs(int ms) {
    srt_setsockopt(m_sock, 0, SRTO_LATENCY, &ms, sizeof(ms));
}
```

**Verificación**:
```cpp
// Test minimal en main()
CSRTSocket s;
bool ok = s.BindAndListen(9000);
LIVE_LOG("SRT", "Bound: %d", ok);
```
Compilar emule, lanzar, log debe mostrar `[SRT] Bound: 1`.

**Éxito**: build sin errores, log confirma SRT bind funciona.

---

### V3-S02 — Negociar SRT vs TCP en handshake

**Objetivo**: peers nuevos negocian si soporta SRT, downgrade a TCP si no.
**Tiempo**: 2 días.
**Prerequisito**: V3-S01.

**Diseño**:
- Añadir flag `SUPPORTS_SRT` en HELLO packet
- Si ambos peers soportan, usar SRT para chunks (TCP eD2K se mantiene para control)
- Versionado backward-compatible

**Código** — extender packet HELLO existente:
```cpp
// En LivePackets.cpp:
struct HelloExtended {
    uint8 version;        // 1 = SRT support
    uint8 capabilities;   // bit 0: SRT, bit 1: WebRTC, ...
    uint16 srt_port;     // puerto SRT del peer
};
```

**Negociación** en `OnPeerHello`:
```cpp
if ((peer_caps & CAP_SRT) && m_localSRTEnabled) {
    LIVE_LOG("NEGO", "Peer %S supports SRT, will use", (LPCWSTR)ipstr(peer->GetIP()));
    EstablishSRTConnection(peer);
} else {
    LIVE_LOG("NEGO", "Peer %S no SRT, fallback TCP", (LPCWSTR)ipstr(peer->GetIP()));
}
```

**Verificación**:
- 2 peers con build nuevo → SRT
- 2 peers mixed (uno viejo): viejo usa TCP, nuevo nota fallback
- Logs `[NEGO]` confirman path elegido

**Éxito**: backward compat preservada, SRT solo se usa cuando ambos lados lo soportan.

---

### V3-S03 — Mover chunk delivery a SRT

**Objetivo**: chunks fluyen por SRT en vez de TCP eD2K.
**Tiempo**: 3-4 días.
**Prerequisito**: V3-S02.

**Cambios**:
- `LiveStreamManager::OnPeerRequest` — usar `srt_send` en vez de `peer->SendPacket`
- `LiveStreamManager::OnChunkReceived` — datos vienen de SRT recv loop, no de PacketReceiver
- Nuevo thread `SRTReceiverThread` que poll SRT sockets

**Código skeleton**:
```cpp
// Thread por peer SRT
DWORD WINAPI SRTReceiverThread(LPVOID param) {
    PeerSRTContext* ctx = (PeerSRTContext*)param;
    BYTE buf[16384];
    while (!ctx->stop) {
        int n = ctx->sock->Recv(buf, sizeof(buf));
        if (n <= 0) break;
        // Parse chunk packet header + payload
        ProcessIncomingChunk(ctx->peer, buf, n);
    }
    return 0;
}
```

**Verificación**:
- 1 broadcaster + 1 viewer con SRT
- Chunks fluyen, log `[CHUNK] ACCEPT` aparece
- Latencia debería bajar 1-2s vs TCP (medible con `chunk_latency_ms` Prometheus)

**Éxito**: stream funciona via SRT, latencia mejora.

---

### V3-S04 — Configurar SRT para low-latency live

**Objetivo**: ajustar SRT options (latency window, ARQ) para nuestro perfil.
**Tiempo**: 1-2 días.
**Prerequisito**: V3-S03.

**Configuración recomendada** (MASTER_PLAN §11.3.3):
```cpp
void CSRTSocket::ConfigureForLive() {
    int latency = 120;  // ms
    srt_setsockopt(m_sock, 0, SRTO_LATENCY, &latency, sizeof(latency));

    int peerlat = 120;
    srt_setsockopt(m_sock, 0, SRTO_PEERLATENCY, &peerlat, sizeof(peerlat));

    int tlpktdrop = 1;  // drop late packets, don't stall
    srt_setsockopt(m_sock, 0, SRTO_TLPKTDROP, &tlpktdrop, sizeof(tlpktdrop));

    int rcvbuf = 8 * 1024 * 1024;  // 8 MB rcv buffer
    srt_setsockopt(m_sock, 0, SRTO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
}
```

**Verificación**:
- Inducir packet loss artificial (firewall drop 5%)
- Latency p99 NO debe explotar (TLPKTDROP cap a 120ms)
- ARQ debe recuperar dentro de la ventana

**Éxito**: stream sobrevive 5-10% packet loss sin freeze.

---

### V3-S05 — Migración rolling: peers viejos siguen funcionando

**Objetivo**: deploy gradual sin romper nada en producción.
**Tiempo**: 1-2 días.
**Prerequisito**: V3-S04.

**Estrategia**:
- Versión bumpada: 0.71.0 (anteriores 0.70.x)
- TCP path se mantiene como fallback FOREVER (nunca eliminar)
- Config preference `UseSRT=1` por defecto, usuario puede revertir
- Telemetría opt-in: cuántos peers usan SRT vs TCP

**Verificación**:
- Mix de peers nuevos + viejos en stress test
- Tasa de éxito de conexiones >95%
- Métrica `connections_by_transport{type="srt"}` y `{type="tcp"}` en Prometheus

**Éxito**: migración no rompe red existente.

---

## Bloque B — Sliding-window RLNC FEC (V3-S06 a V3-S09)

⚠️ **Sprints más densos** — implementación matemática requiere atención.

### V3-S06 — Integrar Intel ISA-L para Galois Field ops

**Objetivo**: linkar libisal, primitivas GF(2^8) disponibles.
**Tiempo**: 1 día.
**Bibliotecas**: Intel ISA-L (https://github.com/intel/isa-l) — BSD-3.

**Setup**:
```bash
git clone https://github.com/intel/isa-l
cd isa-l
nmake -f Makefile.nmake  # Windows MSVC
```

**Linkar isal.lib** en emule.vcxproj.

**Verificación**:
```cpp
#include <erasure_code.h>
unsigned char a = 5, b = 3;
unsigned char r = gf_mul(a, b);
LIVE_LOG("ISAL", "gf_mul(5,3) = %u (expected 15)", r);
```

**Éxito**: log muestra `gf_mul(5,3) = 15`.

---

### V3-S07 — Implementar SlidingWindowRLNC encoder/decoder

**Objetivo**: clase C++ que codifica/decodifica con sliding window 32 packets.
**Tiempo**: 5-7 días (matemática real).
**Referencia**: MASTER_PLAN §11.3.4.

**Archivo nuevo**: `srchybrid/RLNCCodec.h` y `.cpp`.

**Skeleton**:
```cpp
class RLNCEncoder {
public:
    RLNCEncoder(int window_size = 32, float repair_ratio = 1.3f);

    // Llamar al recibir un nuevo paquete source
    void AddSource(uint32 seq, const BYTE* data, int len);

    // Generar siguiente paquete repair (combinación lineal random de window)
    bool GenerateRepair(BYTE* out, int& out_len);

private:
    struct WindowEntry {
        uint32 seq;
        std::vector<BYTE> data;
    };
    std::deque<WindowEntry> m_window;
    int m_window_size;
    float m_repair_ratio;
    int m_source_count = 0;
    int m_repair_count = 0;
};

class RLNCDecoder {
public:
    void AddPacket(const BYTE* data, int len, bool is_repair, /* coefficients */);
    bool TryRecover(uint32 seq, BYTE* out, int& out_len);  // intenta decodificar
};
```

**⚠️ Implementación detallada**: requiere Gaussian elimination sobre GF(2^8).
~500-1000 líneas C++. Buscar referencia en Steinwurf Kodo (commercial) o
implementaciones académicas. Test extensivo con vectores conocidos.

**Verificación**:
- Tests unitarios: codificar 100 paquetes, perder 10 random, decodificar resto
- Should recover 100% si pérdida <repair_ratio - 1
- Benchmark: encoder >100 MB/s en CPU moderna

**Éxito**: tests unitarios pasan, recovery rate >99% con 10% loss.

---

### V3-S08 — Wirelo en stream: emisor genera repair packets

**Objetivo**: broadcaster envía 1 repair cada 3 source packets.
**Tiempo**: 2 días.
**Prerequisito**: V3-S07.

**Código** en `LiveStreamManager::FeedSegment`:
```cpp
void CLiveStreamManager::FeedSegment(...) {
    // ... código existente: añade chunk al buffer

    // NUEVO: alimentar al RLNC encoder
    m_rlncEncoder.AddSource(seqNum, data, dataSize);

    // Generar repair packets cada 3 source
    if (seqNum % 3 == 0) {
        BYTE repair[16384];
        int repair_len;
        if (m_rlncEncoder.GenerateRepair(repair, repair_len)) {
            BroadcastRepairPacket(repair, repair_len);
        }
    }
}
```

**Verificación**:
- Broadcasting + viewer
- Log debe mostrar repairs generados
- Bandwidth overhead ~30%

**Éxito**: repair packets fluyen, recovery rate alto incluso con loss simulado.

---

### V3-S09 — Decoder en viewer: recuperar chunks perdidos sin retransmit

**Objetivo**: viewer reconstruye source packets a partir de repairs.
**Tiempo**: 2-3 días.
**Prerequisito**: V3-S08.

**Código** en `OnChunkReceived`:
```cpp
void CLiveStreamManager::OnChunkReceived(...) {
    if (es_paquete_repair) {
        m_rlncDecoder.AddRepair(...);
        // Try to recover any missing chunks
        for (uint32 missing : ListMissingChunks()) {
            BYTE recovered[16384]; int len;
            if (m_rlncDecoder.TryRecover(missing, recovered, len)) {
                // Inject recovered chunk into buffer
                m_chunkBuffer.AddSegment(streamKey, missing, ...);
                LIVE_LOG("FEC", "Recovered seq=%u via RLNC", missing);
            }
        }
    } else {
        // Source packet — feed decoder + buffer normal
        m_rlncDecoder.AddSource(...);
        m_chunkBuffer.AddSegment(...);
    }
}
```

**Verificación**:
- Force 5% packet drop con firewall
- Log debe mostrar `[FEC] Recovered seq=N` ocasionalmente
- Stream sigue fluido (no freezes)

**Éxito**: pérdida aparente al viewer <0.5% incluso con 5% loss real.

---

## Bloque C — Cut-through packet-level forwarding (V3-S10 a V3-S13)

### V3-S10 — Identificar paquetes con (stream_id, packet_seq)

**Objetivo**: cada paquete tiene ID global único independiente de chunk.
**Tiempo**: 2 días.
**Referencia**: MASTER_PLAN §3.4.

**Diseño**:
- Cada chunk se trocea en N paquetes UDP de ~1300 bytes (MTU-safe)
- Header de cada paquete: `stream_id (16B) | packet_seq (4B) | flags (1B) | ...`
- Total header: ~24 bytes, payload ~1276 bytes

**Estructura**:
```cpp
struct PacketHeader {
    uchar  stream_id[16];
    uint32 packet_seq;     // global, monotonic
    uint16 chunk_seq;      // chunk this packet belongs to
    uint16 packet_in_chunk;// 0..N for that chunk
    uint8  flags;          // bit 0: is_repair (FEC), bit 1: is_keyframe
    uint8  reserved;
};
```

**Verificación**:
- Encoder produce paquetes con secuencia monotónica
- Header parse correctamente

**Éxito**: protocol design documentado, packet structure code-validated.

---

### V3-S11 — Forwarding inmediato (no buffer-then-send)

**Objetivo**: peer reenvía paquetes según los recibe, sin esperar chunk completo.
**Tiempo**: 3-4 días.
**Prerequisito**: V3-S10, V3-S03 (SRT).

**Código** en SRT receiver thread:
```cpp
void OnSRTPacket(const BYTE* data, int len) {
    PacketHeader hdr;
    memcpy(&hdr, data, sizeof(hdr));

    // INMEDIATO: si soy interior node (tengo children), reenvío
    if (m_isInterior) {
        for (auto* child : m_children) {
            child->Send(data, len);  // SRT send, fire and forget
        }
        // Latencia añadida: <5ms
    }

    // Procesar localmente (acumular para chunk completo)
    AccumulatePacketIntoChunk(hdr, data + sizeof(hdr), len - sizeof(hdr));
}
```

**Verificación**:
- 3-hop chain: broadcaster → peer1 → peer2 → peer3
- Latencia broadcaster→peer3 debe ser <500ms (vs 6s chunk-based)

**Éxito**: chain de 3 hops da latencia sub-segundo.

---

### V3-S12 — Reassembly en viewer (paquetes → chunk completo)

**Objetivo**: viewer junta paquetes y reconstruye chunk para HLS.
**Tiempo**: 2-3 días.

**Código**:
```cpp
class ChunkReassembler {
public:
    void AddPacket(uint16 chunk_seq, uint16 packet_in_chunk, const BYTE* data, int len);
    bool TryComplete(uint16 chunk_seq, std::vector<BYTE>& out);

private:
    struct PartialChunk {
        std::vector<std::vector<BYTE>> packets;  // por packet_in_chunk
        int packets_received = 0;
        int total_packets = 0;
        DWORD first_packet_time = 0;
    };
    std::map<uint16, PartialChunk> m_partials;
};
```

**Verificación**:
- Chunks reconstruidos byte-exact al original
- Timeout 500ms: si chunk incompleto tras 500ms, descartar (FEC ayudará)

**Éxito**: chunks completos disponibles en buffer, HLS funciona.

---

### V3-S13 — Adaptive FEC ratio según loss observada

**Objetivo**: subir FEC ratio en peers con loss alta, bajar si pocos drops.
**Tiempo**: 2 días.

**Código**:
```cpp
void CLiveStreamManager::AdaptFECRatio() {
    // Mirar loss rate de los últimos 60s
    float observed_loss = (float)m_chunksLostLast60s / m_chunksReceivedLast60s;

    float new_ratio;
    if      (observed_loss < 0.02) new_ratio = 1.1;  // 10% repair
    else if (observed_loss < 0.05) new_ratio = 1.3;  // 30% repair
    else if (observed_loss < 0.10) new_ratio = 1.5;  // 50% repair
    else                            new_ratio = 2.0;  // 100% repair

    m_rlncEncoder.SetRepairRatio(new_ratio);
    LIVE_LOG("FEC", "Adaptive ratio: %.1f (observed loss %.2f%%)",
        new_ratio, observed_loss * 100);
}
```

**Verificación**:
- Variar loss artificial 0-15%
- FEC ratio se ajusta dinámicamente
- Bandwidth overhead razonable según loss

**Éxito**: balance loss vs overhead automático.

---

## Bloque D — WebRTC bridge (V3-S14 a V3-S18)

⚠️ Sprints grandes. Cada uno potencialmente 1 semana.

### V3-S14 — Embed libdatachannel en eMule.exe

**Objetivo**: linkar libdatachannel, poder crear PeerConnection desde C++.
**Tiempo**: 3-5 días.
**Bibliotecas**: libdatachannel (https://github.com/paullouisageneau/libdatachannel) — MPL-2.0.

**Setup**:
```bash
git clone https://github.com/paullouisageneau/libdatachannel
cd libdatachannel
cmake -B build -DUSE_GNUTLS=0 -DUSE_NICE=0  # SRTP, OpenSSL, libjuice
cmake --build build --config Release
```

Linkar `datachannel-static.lib` + dependencias.

**Test minimal**:
```cpp
#include <rtc/rtc.hpp>
auto pc = std::make_shared<rtc::PeerConnection>();
LIVE_LOG("WRTC", "PeerConnection created");
```

**Verificación**: build OK, log confirma.

**Éxito**: libdatachannel linka, no crashes en init.

---

### V3-S15 — Signaling server simple en Node

**Objetivo**: WebSocket en Node coordina ofertas/answers entre peers.
**Tiempo**: 2 días.

**Archivo nuevo**: `srchybrid/eSE/signaling.js`

**Código**:
```javascript
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8081 });
const peers = new Map();  // peer_id → ws

wss.on('connection', (ws) => {
    ws.on('message', (msg) => {
        const m = JSON.parse(msg);
        if (m.type === 'register') {
            peers.set(m.id, ws);
        } else if (m.type === 'offer' || m.type === 'answer' || m.type === 'ice') {
            const target = peers.get(m.to);
            if (target) target.send(JSON.stringify(m));
        }
    });
});
```

**Verificación**:
- Node arranca, escucha port 8081
- 2 peers se registran, intercambian mensajes ofer/answer

**Éxito**: signaling funcional.

---

### V3-S16 — Browser viewer page con HLS via WebRTC datachannel

**Objetivo**: página HTML carga datachannel-wasm, recibe chunks via WebRTC.
**Tiempo**: 4-5 días.

**Archivo nuevo**: `srchybrid/eSE/eSE-live/wrtc_viewer.html`

**Código skeleton** (usa datachannel-wasm):
```html
<!DOCTYPE html><html><head><title>WebRTC Viewer</title></head>
<body>
<video id="v" controls></video>
<script type="module">
import { PeerConnection } from 'https://cdn.jsdelivr.net/npm/datachannel-wasm/dist/index.js';

const pc = new PeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]});
const dc = pc.createDataChannel('chunks');

const ws = new WebSocket('ws://localhost:8081');
ws.onopen = () => ws.send(JSON.stringify({type:'register', id:'browser_viewer_1'}));

pc.onicecandidate = e => ws.send(JSON.stringify({type:'ice', to:'broadcaster', candidate:e.candidate}));
const offer = await pc.createOffer();
await pc.setLocalDescription(offer);
ws.send(JSON.stringify({type:'offer', to:'broadcaster', sdp:offer}));

const chunks = [];
dc.onmessage = (e) => {
    chunks.push(e.data);
    // Reassemble + feed to MediaSource
};
</script></body></html>
```

**Verificación**: abrir en navegador, conectar al broadcaster, ver chunks llegando.

**Éxito**: video reproduce en navegador sin instalar nada.

---

### V3-S17 — Broadcaster acepta WebRTC offers

**Objetivo**: emule.exe acepta peers WebRTC, los trata como viewers normales.
**Tiempo**: 4-5 días.

**Código C++** usando libdatachannel:
```cpp
void CLiveStreamManager::OnWebRTCOffer(const std::string& sdp, const std::string& peer_id) {
    auto pc = std::make_shared<rtc::PeerConnection>(rtc_config);
    pc->setRemoteDescription(rtc::Description(sdp, "offer"));

    auto answer = pc->localDescription();
    SendSignaling("answer", peer_id, answer.value());

    pc->onDataChannel([this, peer_id](std::shared_ptr<rtc::DataChannel> dc) {
        // Treat as new viewer
        m_webrtcPeers[peer_id] = dc;
        SendChunksToWebRTCPeer(dc);
    });
}
```

**Verificación**: browser viewer desde V3-S16 conecta, recibe stream.

**Éxito**: end-to-end browser viewing funciona.

---

### V3-S18 — Browser viewers forman mesh entre sí

**Objetivo**: viewer en browser sirve chunks a otros viewers en browser (P2P browser-to-browser).
**Tiempo**: 5-7 días.

⚠️ **Sprint research-level**: ningún producto open source lo hace bien aún
para video. Inspirarse en Novage P2P-Media-Loader.

**Approach**: cada browser viewer también puede ser source (datachannel
puede enviar). Signaling server matchmaking.

**Verificación**: 3 browser viewers, 2do y 3ro reciben de 1ro, no del native broadcaster.

**Éxito**: mesh browser-to-browser funcional, network effect demostrado.

---

## Bloque E — E2EE de payload (V3-S19 a V3-S22)

### V3-S19 — Generar K (stream key encryption) y distribuirla

**Objetivo**: broadcaster genera AES key, viewer la recibe via signaling.
**Tiempo**: 1-2 días.
**Referencia**: MASTER_PLAN §13.2.

**Código**:
```cpp
// Broadcaster:
uchar K[32];  // AES-256
RAND_bytes(K, 32);
m_streamEncryptionKey.assign(K, K+32);

// Cuando broadcaster genera link:
CString K_b64 = Base64Encode(K, 32);
link += "&key=" + K_b64;
```

**Viewer**: parsear K del link, guardar.

**Verificación**: K aparece en link, viewer la extrae y almacena.

**Éxito**: key distribution via link funcional.

---

### V3-S20 — AES-256-GCM por chunk

**Objetivo**: cada chunk encriptado antes de entrar al mesh.
**Tiempo**: 2 días.

**Código** usando OpenSSL:
```cpp
bool EncryptChunk(const BYTE* plain, int plain_len,
                  const uchar* K, uint32 nonce_seed,
                  std::vector<BYTE>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uchar nonce[12];
    memcpy(nonce, &nonce_seed, 4);  // derive from seq num
    memset(nonce+4, 0, 8);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, K, nonce);
    out.resize(plain_len + 16);  // +16 for auth tag
    int out_len;
    EVP_EncryptUpdate(ctx, out.data(), &out_len, plain, plain_len);
    int final_len;
    EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len);

    uchar tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    memcpy(out.data() + plain_len, tag, 16);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
```

**Aplicar antes de enviar**:
```cpp
std::vector<BYTE> encrypted;
EncryptChunk(chunk->data, chunk->dataSize, m_streamEncryptionKey.data(), seqNum, encrypted);
// Send encrypted instead of chunk->data
```

**Verificación**:
- Wireshark sniffa los chunks: deben ser opacos (no se ve el .ts)
- Viewer descifra correctamente, video reproduce
- CPU overhead <5%

**Éxito**: chunks cifrados in-flight, decryption en viewer transparente.

---

### V3-S21 — Key rotation cada 60s con HKDF

**Objetivo**: clave maestra deriva subkeys que rotan, forward secrecy.
**Tiempo**: 2 días.

**Código** usando HKDF (RFC 5869):
```cpp
void DeriveSubkey(const uchar* master, uint32 epoch, uchar* subkey_out) {
    // HKDF-SHA256 expansion
    uchar info[16];
    memcpy(info, "stream", 6);
    memcpy(info+6, &epoch, 4);
    HKDF(EVP_sha256(), master, 32, NULL, 0, info, 10, subkey_out, 32);
}

// Each 60s, broadcaster + viewer derive new subkey
uint32 current_epoch = (uint32)(time(NULL) / 60);
DeriveSubkey(m_masterKey, current_epoch, m_currentSubkey);
```

**Verificación**:
- Tras 60s, nueva subkey usada
- Viewer no puede descifrar chunks de hace 5 min con subkey actual (forward secrecy)

**Éxito**: rotación automática, forward secrecy demostrado.

---

### V3-S22 — Verificar super-seeders no pueden descifrar

**Objetivo**: confirmar que relays ven blobs opacos.
**Tiempo**: 1 día (test).

**Test**:
- Setup: 1 broadcaster + 1 super-seeder + 1 viewer
- Modify super-seeder para que intente descifrar chunks que reenvía
- Sin la K, debe fallar → confirma E2EE

**Verificación**: super-seeder log muestra "decrypt failed", viewer log muestra "decrypt OK".

**Éxito**: E2EE validada empíricamente.

---

## Bloque F — Anonymity Relay-first (V3-S23 a V3-S26)

### V3-S23 — Broadcaster selecciona 3-5 entry relays

**Objetivo**: al iniciar broadcast, elegir top super-seeders como entry relays.
**Tiempo**: 2 días.
**Referencia**: MASTER_PLAN §14.6.

**Código**:
```cpp
std::vector<CUpDownClient*> SelectEntryRelays() {
    // Buscar super-seeders top-tier en Kad
    // Filtrar por: trust_score > 700, diferentes AS si posible
    // Devolver top 5
    std::vector<CUpDownClient*> candidates = QuerySuperSeeders();
    SortByTrustScore(candidates);
    DiversifyByAS(candidates);
    return std::vector<CUpDownClient*>(candidates.begin(), candidates.begin() + 5);
}
```

**Verificación**: log muestra selección de 5 relays distintos.

**Éxito**: relays elegidos con criterios.

---

### V3-S24 — Establecer tunnels TLS broadcaster ↔ relay

**Objetivo**: comunicación cifrada broadcaster-relay (no solo TLS transport).
**Tiempo**: 3 días.

**Código**: usar mbedTLS (ya en eMule).
- Mutual TLS auth (broadcaster cert + relay cert)
- Negociar K_stream sobre el tunnel

**Verificación**: tunnel establecido, certs validados.

**Éxito**: 5 tunnels activos.

---

### V3-S25 — Broadcaster solo emite a relays, NO al mesh

**Objetivo**: broadcaster nunca expone su IP al mesh general.
**Tiempo**: 2 días.

**Cambios**:
- Broadcaster NO publica a Kad como source
- Solo los 5 relays publican
- Viewers buscan en Kad, encuentran relays
- Mesh peers ven IP de relays, NO del broadcaster

**Verificación**:
- Wireshark en peer del mesh: no ve tráfico de IP del broadcaster
- Solo ve relay IPs

**Éxito**: anonimidad funcional contra observador en mesh.

---

### V3-S26 — Relay rotation cada 30 min

**Objetivo**: cambiar 1 de los 5 relays cada 30 min, evitar permanent linking.
**Tiempo**: 2 días.

**Código**:
```cpp
void CLiveStreamManager::RotateRelay() {
    DWORD now = GetTickCount();
    if (now - m_lastRelayRotation < 30 * 60 * 1000) return;

    // Pick relay with longest uptime, retire it
    auto* old_relay = OldestRelay();
    auto* new_relay = SelectFreshRelay();
    EstablishTunnel(new_relay);
    GracefulCloseTunnel(old_relay);
    m_lastRelayRotation = now;
    LIVE_LOG("ANON", "Rotated relay: removed %S, added %S",
        ipstr(old_relay->GetIP()), ipstr(new_relay->GetIP()));
}
```

**Verificación**: cada 30 min, log muestra rotación.

**Éxito**: rotación automática, no afecta a viewers (transparente).

---

## Bloque G — HyParView + Plumtree (V3-S27 a V3-S30)

⚠️ **Más research-level**. Considerar usar libp2p directamente.

### V3-S27 — HyParView membership protocol

**Objetivo**: cada peer mantiene active view (5 peers) + passive view (30 peers).
**Tiempo**: 5-7 días.
**Referencia**: MASTER_PLAN §11.3.7, paper Leitão DSN 2007.

**⚠️ Implementación compleja** — ~1000-2000 LOC. Alternativa: usar libp2p
gossipsub que ya implementa esto.

**Verificación**: peers establecen views correctas, sobreviven 80% failure.

**Éxito**: protocol robusto.

---

### V3-S28 — Plumtree epidemic broadcast tree

**Objetivo**: spanning tree implícito por encima de HyParView.
**Tiempo**: 5-7 días.

**Implementación**: paper Leitão SRDS 2007.

**Verificación**: mensaje propagado a todos los nodos en log_3(N) hops.

**Éxito**: latencia propagación sub-second a 1000 nodos.

---

### V3-S29 — Migrar discovery a tracker HTTPS + HyParView

**Objetivo**: bootstrap por tracker, mantenimiento por HyParView.
**Tiempo**: 3-4 días.

**Cambios**: tracker simple Node.js que devuelve seed list. HyParView toma desde ahí.

**Verificación**: nuevo viewer entra, encuentra peers <2s.

**Éxito**: discovery rápido a escala.

---

### V3-S30 — Métricas globales agregadas opt-in

**Objetivo**: peers reportan health a un agregador opcional.
**Tiempo**: 3-4 días.

**Diseño**:
- Toggle "Send anonymous metrics"
- Endpoint en Node aggregator, recibe + anonimiza
- Dashboard global mostrando salud de la red

**Verificación**: si activado, métricas aparecen en agregador.

**Éxito**: visibilidad global de red.

---

## Resumen Sprints v3

**Total: 30 sprints, ~4-6 meses calendario.**

| Bloque | Sprints | Output |
|---|---|---|
| A. SRT transport | S01-S05 | Reemplazo TCP eD2K en live path |
| B. RLNC FEC | S06-S09 | Resilencia 5-10% loss sin retransmit |
| C. Cut-through | S10-S13 | Latencia hop 50-100ms vs 2s |
| D. WebRTC bridge | S14-S18 | Browser viewers, 10× audiencia |
| E. E2EE payload | S19-S22 | Privacy real, super-seeders ven blobs |
| F. Anonymity Relay-first | S23-S26 | Broadcaster IP no expuesta |
| G. HyParView+Plumtree | S27-S30 | Discovery rápido a escala |

## Métricas de éxito globales tras v3

- ✅ 5,000-50,000 viewers concurrentes (con stress test validado)
- ✅ Latencia <2s p95
- ✅ Browser viewers funcionales (no requieren instalar eMule)
- ✅ Stream encriptado E2E (super-seeders no ven contenido)
- ✅ Broadcaster anónimo (IP no aparece en mesh)
- ✅ Recovery sub-segundo ante peer failure (multi-parent)
- ✅ Forward secrecy (key rotation 60s)

**Lo que aún quedará pendiente para v4**:
- SVC layered encoding
- Onion routing (anonymity nivel 2)
- Super-relays opt-in
- Geographic peer selection avanzado
- Reproducible builds
