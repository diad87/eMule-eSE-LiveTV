# Sprints v4 — exploratorio, 50,000-500,000 viewers

**Prerequisito**: SPRINTS_V3.md completo y validado a escala.

⚠️ **Esta fase es exploratoria**. La mayoría de las técnicas son investigación
abierta o requieren decisiones de diseño que no tomaremos hasta tener datos
reales del v3. Los sprints aquí son **esqueletos** con menos detalle que v2/v3
porque depende de lo aprendido en producción.

**Convención**: sprints `V4-SXX`. Estos requieren más decisiones humanas que
copy-paste — son guía estratégica, no instrucciones literales.

---

## Bloque A — SVC Layered Encoding (V4-S01 a V4-S05)

⚠️ Codecs SVC tienen soporte parcial. VP9 SVC funciona en Chrome; AV1 SVC
emerging. Decisión codec final pendiente de browser landscape v4 era.

### V4-S01 — Decidir codec SVC

**Objetivo**: elegir entre VP9 SVC, AV1 SVC, o LCEVC enhancement.
**Tiempo**: 1-2 semanas (research + benchmarks).
**Decisión clave**: depende de soporte browser cuando estemos en v4.

**Investigación necesaria**:
- VP9 SVC: bien soportado Chrome/FF, no Safari
- AV1 SVC: Chrome 102+, no maduro otros
- LCEVC: enhancement layer agnóstico al base codec

**Output**: documento de decisión con benchmarks reales.

---

### V4-S02 — Configurar FFmpeg para multi-stream output

**Objetivo**: FFmpeg produce 3 variants (500/1500/3000 kbps) con stripe ID.
**Tiempo**: 3-4 días.

**Comando ejemplo**:
```
ffmpeg -i input -map 0:v -map 0:v -map 0:v -map 0:a \
  -c:v libvpx-vp9 -row-mt 1 \
  -b:v:0 500k -s:v:0 854x480 \
  -b:v:1 1500k -s:v:1 1280x720 \
  -b:v:2 3000k -s:v:2 1920x1080 \
  -c:a aac -b:a 128k \
  -f hls -var_stream_map "v:0,a:0 v:1,a:0 v:2,a:0" \
  -master_pl_name master.m3u8 \
  -hls_segment_filename "stream_%v_%05d.ts" stream_%v.m3u8
```

**Verificación**: 3 archivos m3u8 + segmentos por variant generados.

---

### V4-S03 — LiveChunkBuffer multi-variant

**Objetivo**: buffer indexado por (stream_id, variant_id, seq).
**Tiempo**: 3-5 días.

**Cambio struct**: añadir `uint8 variant_id` a key del map.

**Verificación**: 3 buffers separados, peers eligen variant según bandwidth.

---

### V4-S04 — HLS.js auto-select variant según bandwidth

**Objetivo**: viewer cliente cambia variant dinámicamente.
**Tiempo**: 1 día (HLS.js soporta nativo).

**Verificación**: simular bandwidth bajo, cliente baja a 500 kbps.

---

### V4-S05 — Leaf-restricted forzado a variant low

**Objetivo**: peers con upload <bitrate solo reciben SD.
**Tiempo**: 2 días.

**Código**: en JoinStream, peer con tier `LEAF_RESTRICTED` solo subscribe a variant_id=0.

---

## Bloque B — Super-relay opt-in (V4-S06 a V4-S10)

### V4-S06 — Diseño del rol "voluntary super-relay"

**Objetivo**: doc técnico de cómo un peer ofrece relay capacity adicional.
**Tiempo**: 3-5 días planning.

**Conceptos**:
- Opt-in via UI ("Run as community relay")
- Anuncia capacity disponible (Mbps + max viewers)
- Relay sirve a múltiples streams concurrentes (no solo uno)
- Reward: badge premium, governance vote, optional crypto tip

---

### V4-S07 — Relay daemon mode

**Objetivo**: emule.exe puede arrancarse como relay-only sin viewer/broadcaster.
**Tiempo**: 3-4 días.

**Flag**: `--relay-mode --max-bandwidth=200Mbps`

---

### V4-S08 — Auto-discovery de relays en Kad

**Objetivo**: viewers/broadcasters encuentran community relays automáticamente.
**Tiempo**: 2-3 días.

**Tag Kad**: `eserelay:available` con capacity stats.

---

### V4-S09 — Health monitoring de relays

**Objetivo**: detectar relays caídos, reputación pública.
**Tiempo**: 3-4 días.

**Tracker centralizado opcional** que agregua uptime stats.

---

### V4-S10 — UI para gestión de relays

**Objetivo**: web UI mostrando relays disponibles, su uso, stats.
**Tiempo**: 2-3 días.

---

## Bloque C — Geographic peer selection (V4-S11 a V4-S13)

### V4-S11 — RTT measurement automático en peer selection

**Objetivo**: preferir peers <50ms RTT.
**Tiempo**: 2-3 días.
**Prerequisito**: V2-S03 (RTT EWMA).

**Código**: ya tenemos rtt_ms_ewma. Solo aplicar en `SelectPeerForSegment`.

---

### V4-S12 — GeoIP database para AS-level selection

**Objetivo**: agrupar peers por AS, preferir mismo AS.
**Tiempo**: 3-5 días.

**Bibliotecas**: MaxMind GeoLite2 (gratis con attribution).

**Database**: ASN database, lookup IP→AS_number.

---

### V4-S13 — Tree formation prefiere geographic clustering

**Objetivo**: árbol respeta locality (sub-trees por región).
**Tiempo**: 4-5 días.

**Algoritmo**: parent selection hace cluster-first, cross-cluster solo para
resilience (10% long edges según Pitfalls paper).

---

## Bloque D — Onion routing toggle (V4-S14 a V4-S18)

### V4-S14 — Diseño protocolo onion para broadcaster

**Objetivo**: especificación de 3-hop encrypted routing.
**Tiempo**: 1 semana (research + design).
**Referencia**: MASTER_PLAN §14.3.C.

**Output**: doc de protocolo con encryption layers, routing table, etc.

---

### V4-S15 — Implementar onion encryption layers

**Objetivo**: broadcaster envuelve datos en 3 capas AES.
**Tiempo**: 5-7 días.

**Reuso**: AES-256-GCM ya en E2EE (V3-S20).

---

### V4-S16 — Relay nodes peelan capa y reenvían

**Objetivo**: cada relay sabe solo prev + next hop.
**Tiempo**: 4-5 días.

---

### V4-S17 — Path selection diversa (3 AS distintos)

**Objetivo**: 3 hops en países/AS diferentes para resilience.
**Tiempo**: 2-3 días.
**Prerequisito**: V4-S12 (GeoIP).

---

### V4-S18 — UI toggle "Maximum anonymity"

**Objetivo**: usuario activa/desactiva onion routing en MFC y web.
**Tiempo**: 2 días.

**UI**: checkbox "Maximum anonymity (+400ms latency)".

---

## Bloque E — Reproducible builds (V4-S19 a V4-S21)

### V4-S19 — Containerized build environment

**Objetivo**: Dockerfile que construye emule.exe deterministicamente.
**Tiempo**: 1-2 semanas.

**Approach**:
- Pin MSVC version exacta
- Pin todos los SDKs
- Build hash debe ser reproducible byte-exact

---

### V4-S20 — Verification tool

**Objetivo**: usuario puede verificar `emule.exe == build_from_source`.
**Tiempo**: 2-3 días.

**Tool**: script que compara hash del .exe descargado vs hash del build local.

---

### V4-S21 — SBOM generation automatizada

**Objetivo**: cada release viene con SBOM SPDX.
**Tiempo**: 2-3 días.

**Tools**: syft / cdxgen.

---

## Bloque F — Aggregator metrics global (V4-S22 a V4-S24)

### V4-S22 — Aggregator backend opt-in

**Objetivo**: peers reportan stats anonimizadas a un agregador opcional.
**Tiempo**: 3-5 días.

**Backend simple**: Node.js + InfluxDB o ClickHouse.

---

### V4-S23 — Dashboard global de salud de red

**Objetivo**: web público mostrando: # streams activos, # viewers global, latencia P95 por región.
**Tiempo**: 3-5 días.

**Frontend**: Grafana o custom React.

---

### V4-S24 — Anomaly detection

**Objetivo**: detectar ataques o degradación coordinated.
**Tiempo**: 1 semana (depende complejidad).

**Algorithm**: análisis de outliers en métricas (latency spike, churn anormal, etc.)

---

## Resumen Sprints v4

**Total: 24 sprints, calendario impredecible (mucho research).**

| Bloque | Sprints | Tiempo aprox | Output |
|---|---|---|---|
| A. SVC encoding | S01-S05 | 3-4 sem | ABR adaptativo real |
| B. Super-relay opt-in | S06-S10 | 3-4 sem | Voluntary infrastructure |
| C. Geographic | S11-S13 | 2-3 sem | Latencia P95 por región |
| D. Onion routing | S14-S18 | 4-6 sem | Anonymity nivel 2 |
| E. Reproducible builds | S19-S21 | 3-4 sem | Hardened distribution |
| F. Aggregator metrics | S22-S24 | 2-3 sem | Visibilidad global |

## Métricas de éxito tras v4

- ✅ 50,000+ viewers concurrentes (empíricamente uncharted hoy)
- ✅ Latencia <1s p50 (con LL-HLS si añadido)
- ✅ Onion routing opcional disponible
- ✅ Super-relays voluntarios funcionando
- ✅ Reproducible builds verificables
- ✅ Visibilidad global de salud de red

## Decisiones pendientes que afectan v4

Estas no se pueden tomar hoy, requieren datos del v3:

1. **¿Codec SVC final?**: depende de browser landscape en momento de v4
2. **¿Super-relays con incentivos crypto?**: depende de demanda comunidad
3. **¿LL-HLS como adición?**: si v3 latencia ya es <2s, quizás no necesario
4. **¿Mainline merge con eMule original?**: si comunidad eMule lo acepta
5. **¿Mobile como contributor opt-in?**: depende de evolución carriers/OS

## Lo que sigue siendo investigación abierta tras v4

Cosas que NI v4 resuelve:
- Sub-500ms latencia P2P puro a 50k+
- 100% protección contra state-actor adversary
- Long-tail channels (<100 viewers)
- DRM compatibility
- Fully decentralized governance
- Mobile contribution real

Estos quedan para "vNext" (si llegamos).

---

# Roadmap consolidado de TODOS los sprints

## Vista global

```
v2 (foundation, 30 sprints, 2-3 meses)
├─ A Observability (S01-05)
├─ B Stress simulator (S06-10)
├─ C Auto-tier + ratio (S11-15)
├─ D Tree + multi-parent (S16-22)
├─ E NAT improvements (S23-26)
└─ F Hardening básico (S27-30)
   ↓
v3 (P2P real + privacy, 30 sprints, 4-6 meses)
├─ A SRT transport (S01-05)
├─ B RLNC FEC (S06-09)
├─ C Cut-through (S10-13)
├─ D WebRTC bridge (S14-18)
├─ E E2EE payload (S19-22)
├─ F Anonymity Relay-first (S23-26)
└─ G HyParView+Plumtree (S27-30)
   ↓
v4 (escala masiva, 24 sprints, 4-8 meses, exploratorio)
├─ A SVC encoding (S01-05)
├─ B Super-relay opt-in (S06-10)
├─ C Geographic (S11-13)
├─ D Onion routing (S14-18)
├─ E Reproducible builds (S19-21)
└─ F Aggregator metrics (S22-24)
```

## Total time/effort

- **84 sprints** total (v2: 30, v3: 30, v4: 24)
- **~10-15 meses calendario** para 1 dev tiempo completo
- **~20-30 meses** para 1 dev media jornada
- **~6-8 meses** con 2 devs paralelos

## Dependencias críticas

- v3 requiere v2 completo (especialmente stress simulator de B)
- v4 requiere v3 estable + datos reales de producción
- Algunos sprints v3 (WebRTC, RLNC) son opcionales — el sistema funciona sin ellos
- Anonimidad (v3 F) depende de tener super-seeders trustworthy

## Cómo usar estos docs

1. **Lee MASTER_PLAN.md secciones relevantes** ANTES de cada sprint
2. **Pick un sprint, sigue prerequisites**
3. **Branch por sprint** (`sprint/V2-SXX-titulo`)
4. **Implementa siguiendo código pegable**
5. **Verifica con comandos del sprint**
6. **Commit con tag** (`[V2-SXX] título`)
7. **CI verde antes de merge**
8. **Actualiza este doc** si descubres detalles importantes

## Cuando dudas

- **¿Por qué este sprint hace X?** → MASTER_PLAN.md sección de referencia
- **¿Por qué este orden?** → dependencies
- **¿Qué pasa si me salto sprints?** → riesgo de bugs no detectados
- **¿Puedo paralelizar bloques?** → sí, dentro de un bloque NO (orden estricto), entre bloques distintos SÍ

Suerte. Es mucho trabajo. Avanza paso a paso.
