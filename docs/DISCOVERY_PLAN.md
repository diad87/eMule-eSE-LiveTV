# Discovery Robustness Plan

**Objetivo**: que cualquier viewer pueda encontrar un broadcast en <30 s desde cualquier red,
con el broadcaster en cualquier estado de conectividad (alta ID, baja ID, recién arrancado,
post-crash). Sin esto, el resto de V2 no importa: si nadie descubre el stream, no hay P2P.

---

## 1. Estado real auditado (2026-05-16)

### Qué funciona bien

| Componente | Estado | Notas |
|---|---|---|
| `PublishStream` multi-keyword | ✅ | 4 keywords: `eselive`, primera palabra del título, categoría, `eselang:XX`, `livehash:HASH` |
| Burst inicial post-publish | ✅ | 5 s → 15 s → 60 s steady (LiveKadBridge.cpp `m_nPublishBurstCount`) |
| `PublishAsRelay` (V2-S17) | ✅ | Viewers se autopublican como secondary source cada 30 s si buffer ≥ 5 |
| `OnKadSearchResult` auto-dial | ✅ | Cada resultado dispara `TryConnectToStreamSource` inmediatamente |
| Filtros de IP en resultados | ✅ | IPFilter + `IsGoodIPPort` + self-public-IP guard |
| Stall failover 20 s (V2-S22) | ✅ | Si no llegan chunks 20 s → re-search Kad + dial todos los known sources |
| Orphan anycast (V2-S22) | ✅ | Si `m_viewPeers.Count() == 0` → search livehash cada 5 s |
| EnsureMultiParent (V2-S19) | ✅ | Mantiene ≥ 3 source connections, dialing extras de KadBridge |

### Gaps críticos confirmados

| # | Gap | Severidad | Por qué importa |
|---|-----|-----------|-----------------|
| **D-1** | `StopBroadcast` no se llama si emule crashea → entrada Kad queda fantasma 10 min | 🔴 CRÍTICO | Viewers descubren broadcasts muertos durante el TTL DHT, intentan dial, fallan, mala UX |
| **D-2** | `PublishStream` SOLO se llama una vez en `StartBroadcast`. Si Kad conecta DESPUÉS, no hay reintento hasta el republish (60 s steady, o 10 min si burst ya terminó) | 🔴 CRÍTICO | Broadcaster invisible 1-10 min tras arrancar |
| **D-3** | `JoinStream` dispara 3 búsquedas Kad pero **NO reintenta** si fallan. Si Kad está saturado/desconectado al segundo de JoinStream, viewer ciego permanente | 🔴 CRÍTICO | Anonymous links inutilizables si Kad coopera mal |
| **D-4** | `OnKadSearchResult` dialea cada IP **inmediatamente sin throttle**. Kad puede devolver 100+ resultados → 100 sockets simultáneos | 🟠 ALTO | DoS contra el viewer si búsqueda popular; agota fd/handles |
| **D-5** | No hay límite en `m_viewPeers.GetCount()`. Cada dial añade ahí. Puede crecer ilimitadamente | 🟠 ALTO | Memoria + sockets sin tope; viewer puede ahogarse |
| **D-6** | `SearchStreams` cooldown es **30 s por keyword**, no global. 100 keywords distintos = 100 búsquedas concurrentes a Kad | 🟠 ALTO | Spam a Kad network; nuestro nodo puede ser baneado por flood |
| **D-7** | `PruneStaleEntries` corre cada 60 s, TTL = 600 s. Entrada muerta puede aparecer en `GetKnownStreams` durante 10 min | 🟡 MEDIO | Viewers ven streams que no existen, intentan dial, fallan |
| **D-8** | El parser de links `ed2k://|live|HASH|IP:PORT|TITLE|/` existe pero **no hay logging si IP es inválida**. Si el parser falla silencioso, usuario ve "no pasa nada" | 🟡 MEDIO | Diagnóstico imposible cuando un link no funciona |
| **D-9** | Métricas: no sabemos cuántos resultados Kad ha devuelto por keyword, ni latencia de búsqueda | 🟡 MEDIO | No podemos optimizar lo que no medimos |
| **D-10** | `PublishStream` y `PublishAsRelay` no validan el viewer count que publican (`uint32` arbitrario) | 🟢 BAJO | Susceptible a inflación / spoofing en directorio |
| **D-11** | No hay distinción en wire entre "broadcaster origen" y "secondary source". El viewer no sabe si conecta al original o a un relay | 🟢 BAJO | Métricas confusas; potencial loop si A relayea de B que relayea de A |

---

## 2. Plan: sprints DISC-S01 a DISC-S15

Cada sprint = 1-3 días de trabajo, paste-ready code.
Orden = orden de implementación recomendado (depends-on respetado).

---

### Bloque A — Resilencia de publicación (DISC-S01 a DISC-S04)

#### DISC-S01 — Graceful unpublish via atexit + signal handler

**Gap**: D-1
**Tiempo**: 1 día
**Archivos**: `srchybrid/emule.cpp` (ExitInstance), `srchybrid/LiveStreamManager.cpp` (StopBroadcastFull)

**Cambios**:
- En `CemuleApp::ExitInstance`, llamar a `liveStreamManager->StopBroadcastFull()` si está broadcasting (esto ya invoca `m_kadBridge.UnpublishStream`).
- Añadir `SetConsoleCtrlHandler` para CTRL+C, CTRL+CLOSE: invocar el mismo cleanup antes de terminar.
- En el handler, también llamar a un nuevo `m_kadBridge.NotifyKadOfShutdown(streamKey)` que dispare un STOREKEYWORD con `viewerCount=0` y un nuevo tag `TAG_ESE_LIVE_BYE` para que peers descubran "este broadcaster se va".

**Verificación**:
- Abre eMule, broadcast, Ctrl+C en consola → en otro eMule, `livehash:HASH` debe dejar de devolver el broadcaster en <60 s (no en 10 min).
- Caso brutal (Task Manager kill): el broadcaster sigue siendo "fantasma" hasta TTL Kad (esto requiere DISC-S02).

---

#### DISC-S02 — Heartbeat de freshness en el directorio Kad

**Gap**: D-1, D-7
**Tiempo**: 2 días
**Archivos**: `srchybrid/LiveKadBridge.cpp` (`RepublishIfNeeded`, nuevo `IsStreamLive`)

**Cambios**:
- Cada `LiveStreamEntry` ya tiene `lastSeen`. Añadir campo `livenessCheckedAt`.
- Cada 30 s, para cada entrada del directorio (no propia), enviar un `OP_LIVE_PING` directo al `broadcasterIP:broadcasterPort` (UDP, no Kad). Si responde con `OP_LIVE_PONG` en 3 s, refrescar `livenessCheckedAt`.
- Si `livenessCheckedAt` está > 90 s atrás → marcar entry como "stale" en `GetKnownStreams` (no incluir en respuesta web).
- Reducir TTL del directorio de 600 s a 120 s.

**Verificación**:
- Mata broadcaster brutalmente (Task Manager). En viewer/otro nodo, `GetKnownStreams()` debe dejar de devolver el broadcaster en <120 s.
- Si broadcaster sigue vivo y solo NAT-pinged: el PING/PONG debe mantener entrada fresca.

---

#### DISC-S03 — Reintento de publicación tras Kad-late-connect

**Gap**: D-2
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveKadBridge.cpp` (`Process`)

**Cambios**:
- Añadir flag `m_bPublishRequested` que se setea a `true` en `PublishStream` (incluso si Kad off).
- En `Process()`, si `m_bPublishRequested && !m_bPublished && Kademlia::IsConnected()` → invocar `RepublishIfNeeded` con burst reset (`m_nPublishBurstCount=0`).
- Esto garantiza que el broadcaster eventualmente se publique aunque Kad tarde 5 min en conectar.

**Verificación**:
- Lanza eMule SIN red, broadcast → log "PublishStream QUEUED — Kad not connected".
- Conecta red → en <30 s, log "Republish OK" debe aparecer y entrada visible en otro nodo.

---

#### DISC-S04 — Persistencia del streamKey en preferences

**Gap**: D-1 (caso brutal kill)
**Tiempo**: 1 día
**Archivos**: `srchybrid/Preferences.cpp` (carga/guarda), `srchybrid/LiveStreamManager.cpp`

**Cambios**:
- Al `StartBroadcast`, escribir `LiveLastStreamKey=HEX32` a preferences.ini.
- Al arrancar eMule, si encuentra `LiveLastStreamKey` no vacío, llamar a `m_kadBridge.NotifyKadOfShutdown(key)` en startup (después de Kad bootstrap) para limpiar el fantasma de la sesión anterior.
- Al `StopBroadcast` exitoso, borrar la clave de preferences.

**Verificación**:
- Broadcast, kill brutal → reinicia eMule → en <60 s otro nodo deja de ver el fantasma.

---

### Bloque B — Resilencia de descubrimiento (DISC-S05 a DISC-S08)

#### DISC-S05 — Reintento periódico de búsqueda en JoinStream

**Gap**: D-3
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveStreamManager.cpp` (`Process`)

**Cambios**:
- Añadir `m_dwLastJoinSearchTick`. En `Process()`, si `m_bViewing && m_viewPeers.IsEmpty() && now - m_dwLastJoinSearchTick > 15000` → re-disparar las 3 búsquedas (`eselive`, title, `livehash:HASH`).
- Hard cap: máximo 10 reintentos. Después, marcar viewing como "failed" y emitir `[ANYCAST] Giving up after 10 search retries`.

**Verificación**:
- Lanza viewer con link, sin que el broadcaster esté en Kad todavía. En 15 s debe re-buscar; al aparecer el broadcaster, conexión en <60 s.

---

#### DISC-S06 — Throttle de auto-dial en OnKadSearchResult

**Gap**: D-4
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveKadBridge.cpp` (`OnKadSearchResult`)

**Cambios**:
- En vez de `TryConnectToStreamSource` síncrono, añadir a una cola `m_pendingDials` (CArray<DialReq>).
- En `Process()`, drenar la cola: máximo 3 dials por tick (= 3 por segundo).
- Si la cola supera 50 elementos, descartar las más antiguas (FIFO drop).

**Verificación**:
- Forzar resultados masivos (mock 100 entries Kad) → ver `[DIAL]` lines apareciendo paginadas a 3/s, no en burst.

---

#### DISC-S07 — Hard cap de m_viewPeers

**Gap**: D-5
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveStreamManager.cpp` (`TryConnectToStreamSource`)

**Cambios**:
- Constante `MAX_VIEW_PEERS = 8` (configurable via prefs).
- En `TryConnectToStreamSource`, antes de `m_viewPeers.AddTail`, si `m_viewPeers.GetCount() >= MAX_VIEW_PEERS` → no añadir, log `[CAP] viewPeers full (8), skipping dial X.X.X.X`.
- En `EnsureMultiParent`, hacer target = `min(3, MAX_VIEW_PEERS)`.

**Verificación**:
- Conectar a stream popular con muchos secondary sources → m_viewPeers nunca supera 8.

---

#### DISC-S08 — Rate limit global de SearchStreams

**Gap**: D-6
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveKadBridge.cpp` (`SearchStreams`)

**Cambios**:
- Token bucket: máximo 10 búsquedas por minuto (independiente de keyword).
- Si excedido, retornar `false` con log `[KAD] Search rate-limited (10/min), keyword=X skipped`.
- El cooldown 30 s por keyword se mantiene como segunda línea.

**Verificación**:
- Disparar 20 searches en 10 s vía debug API → solo 10 primeras pasan, 10 últimas rechazadas.

---

### Bloque C — Diagnóstico de links (DISC-S09 a DISC-S10)

#### DISC-S09 — Logging completo del parser de links live

**Gap**: D-8
**Tiempo**: 0.5 día
**Archivos**: `srchybrid/ED2KLink.cpp`, `srchybrid/WebServer.cpp` (`/api/live/direct_join`)

**Cambios**:
- En `CED2KStreamLink` ctor, loggear cada error de parseo (key inválida, IP malformada, etc.) con `LIVE_LOG("LINK", ...)`.
- En `_ProcessLiveAPI direct_join`, distinguir en JSON entre `success=false reason="bad_hash"`, `reason="bad_endpoint"`, `reason="kad_search_only"`.

**Verificación**:
- Pegar link basura `ed2k://|live|xxx|||/` → API responde con `reason` específico, log line clara.

---

#### DISC-S10 — Endpoint /api/live/diagnose para self-diagnosis

**Gap**: observabilidad
**Tiempo**: 1 día
**Archivos**: `srchybrid/WebServer.cpp`

**Cambios**:
- Nuevo endpoint `GET /api/live/diagnose?key=HASH` que ejecuta y reporta:
  - Si `key` está en `m_streamDirectory` (cuánto tiempo lleva ahí, cuándo último PING)
  - Si está publicada propia (`m_bPublished`, `m_dwLastPublishTime`)
  - Si Kad está conectado, número de nodos
  - Si UPnP mapeo activo
  - Si IPFilter bloquea algún rango relevante

**Verificación**:
- Curl al endpoint con hash de stream conocido → JSON con todo el contexto, útil para soporte.

---

### Bloque D — Observabilidad de Kad (DISC-S11 a DISC-S13)

#### DISC-S11 — Métricas de búsquedas Kad

**Gap**: D-9
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveStreamManager.h`, `srchybrid/LiveKadBridge.cpp`, `srchybrid/WebServer.cpp`

**Cambios**:
- Extender `LiveStreamCounters`:
  - `kadSearchesTotal` (ya existe)
  - `kadSearchLatencyMsTotal` (suma)
  - `kadSearchResultsTotal` (suma de hits)
  - `kadSearchEmpty` (cuántas búsquedas devolvieron 0 resultados)
- En `OnKadSearchResult`, incrementar `kadSearchResultsTotal`.
- En `SearchStreams`, registrar `t0`; en `OnKadSearchComplete` (si existe) o vía timer, sumar latencia.
- Exponer en `/api/live/metrics` como histograma.

**Verificación**:
- Tras 5 búsquedas, `/api/live/metrics` debe mostrar `esmule_kad_search_latency_ms_avg` y `esmule_kad_search_results_avg`.

---

#### DISC-S12 — Histograma de "tiempo desde search hasta primer chunk"

**Gap**: D-9
**Tiempo**: 1 día
**Archivos**: `srchybrid/LiveStreamManager.cpp`

**Cambios**:
- En `JoinStream`, guardar `m_dwJoinTick`.
- Al primer `OnChunkReceived` post-JoinStream, registrar `time_to_first_chunk_ms = now - m_dwJoinTick` en un `LatencyHistogram` dedicado (V2-S05 ya provee la clase).
- Exponer p50/p95/p99 en `/api/live/metrics` como `esmule_join_to_first_chunk_ms`.

**Verificación**:
- Tras 10 joins, ver percentiles. Target: p50 < 5 s, p95 < 15 s.

---

#### DISC-S13 — Dashboard panel "Discovery health"

**Gap**: UX
**Tiempo**: 1 día
**Archivos**: `srchybrid/eSE/eSE-live/public/*` (UI Node)

**Cambios**:
- Panel nuevo en la web UI: muestra
  - Streams Kad conocidos (tabla con tiempo desde último PING)
  - Búsquedas recientes (cuáles, cuántos resultados)
  - Métricas de DISC-S11/S12
  - Botón "Re-discover" que dispara `/api/live/diagnose?key=HASH`

**Verificación**:
- UX usable que muestra el estado del discovery sin abrir endpoints crudos.

---

### Bloque E — Anti-Sybil + seguridad en discovery (DISC-S14 a DISC-S15)

#### DISC-S14 — Validación de viewerCount publicado

**Gap**: D-10
**Tiempo**: 0.5 día
**Archivos**: `srchybrid/LiveKadBridge.cpp` (`OnKadSearchResult`)

**Cambios**:
- Si `viewerCount > 100000`, capear a 100000 (valor poco realista para v2; reactivar cap cuando V3 demuestre >50k).
- Si `bitrate > 50000` (50 Mbps) → rechazar como spam, log `[KAD] Bogus bitrate %u from %s — discard`.

**Verificación**:
- Inyectar resultado Kad con `viewerCount=999999999`, ver entry capeada o rechazada.

---

#### DISC-S15 — Distinción broadcaster/relay en wire

**Gap**: D-11
**Tiempo**: 2 días
**Archivos**: `srchybrid/kademlia/.../Search.cpp` (SetLiveStreamPublish), `srchybrid/LiveKadBridge.cpp`

**Cambios**:
- Añadir nuevo tag Kad `TAG_ESE_LIVE_ROLE` con valores `0=broadcaster_origin`, `1=relay`.
- `PublishStream` envía role=0; `PublishAsRelay` envía role=1.
- En `OnKadSearchResult`, propagar el role a `LiveStreamEntry`.
- En `EnsureMultiParent`, dar preferencia (50% peso) al broadcaster origen sobre relays.

**Verificación**:
- Setup 1 origin + 5 relays. Viewer log debe mostrar `[PARENT] Selected origin 1.2.3.4 (role=0)` o `[PARENT] Selected relay X.X.X.X (role=1)`.

---

## 3. Roadmap

**Sprint 1** (semana 1): DISC-S01, S03, S04 — broadcaster resilience (graceful unpublish, late-Kad retry, persistence)
**Sprint 2** (semana 2): DISC-S05, S06, S07 — viewer resilience (search retry, dial throttle, peer cap)
**Sprint 3** (semana 3): DISC-S02, S08 — Kad-network politeness (PING heartbeat, global rate limit)
**Sprint 4** (semana 4): DISC-S09, S10, S11, S12 — observability + diagnosis
**Sprint 5** (semana 5): DISC-S13, S14, S15 — UI + hardening

---

## 4. Métricas de éxito tras completar el plan

| Métrica | Target |
|---|---|
| Tiempo desde "Start Broadcast" hasta "visible en otro nodo via Kad" | < 30 s (p95) |
| Tiempo desde "Click link" hasta "primer chunk recibido" | < 10 s (p50), < 30 s (p95) |
| Broadcaster fantasma tras crash brutal visible | < 120 s (no 10 min) |
| Búsquedas Kad por minuto desde un nodo | ≤ 10 (rate-limited) |
| `m_viewPeers` máximo | ≤ 8 (capped) |
| Failover si stall > 20 s | ya implementado V2-S22 |
| Logs `[LINK]` claros sobre por qué un link no funciona | sí (DISC-S09) |
| Endpoint /api/live/diagnose útil | sí (DISC-S10) |

---

## 5. Lo que NO toca este plan (siguiente fase)

- **NAT-T avanzado**: birthday-paradox hole-punching (MASTER_PLAN §11.3.8) sigue postponed
- **IPv6**: V2-S23, postponed
- **DHT cache distribuida**: MASTER_PLAN §15.5
- **Tracker HTTPS como fallback de Kad**: V3-S29
- **Reputación de broadcasters**: V3+ (anti-spam más sofisticado)

Estos requieren cambios profundos en Kad core o stack networking, fuera del scope "estabilizar el discovery actual".
