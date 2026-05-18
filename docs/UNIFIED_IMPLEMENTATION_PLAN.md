# Plan unificado de implementación — eSE Live V1

> **Estado:** Borrador inicial 2026-05-18
> **Alcance:** convertir las dos tesis (`docs/thesis/` privacidad + `docs/thesis/kad-search-v2/`) en un plan ejecutable que respete las cuatro prioridades del proyecto, la compatibilidad obligatoria con eMule 0.70b, y el código actual (plan H1–H8 ya aterrizado).
> **Prioridades del proyecto, en orden:**
>   1. Seguridad
>   2. Anonimato
>   3. UX simple
>   4. Velocidad
> **Restricciones invariantes:** back-compat con 0.70b + forks previos (mandatorio), cero infraestructura propietaria (G7), cero coste para el usuario, no se sube nada a GitHub sin OK explícito.

---

## 0. Resumen ejecutivo

Hay dos tesis vivas que se cruzan:

| Tesis | Objetivo | LOC nueva | Duración estimada |
|---|---|---|---|
| Privacidad (`hungry-dhawan-84bd82`) | Onion tunnels 2-hop + canales firmados + cover traffic | ~6 000 | 4-5 meses |
| Kad Search v2 (`quizzical-newton-9aa3db`) | 6 mecanismos M1-M6 para destronar servidores eD2K | ~2 700 | sin estimación explícita |

**Hipótesis del plan unificado:** ambas se implementan en una secuencia coordinada de **12 fases** (F0.5 y F4b añadidas tras revisión crítica) que comparten un mismo eje de control de calidad (ProVerif + security review). El total agregado es **~9 300 LOC en ~7-9 meses** con 1 dev. La compresión viene de tres palancas:

1. **Plan H1–H8 ya implementado en código** (namespace isolation + dual-publish + adoption metrics) absorbe gran parte de M1 (subscriber pinning) y todo M0 (namespace) que la monografía no contempló explícitamente.
2. **Kad Search v2 M3/M5/M6** se hacen en paralelo a la Fase Foundation de privacidad — son ortogonales en código (Kad UDP layer vs LiveOnionCrypto sin red).
3. **Kad Search v2 M2/M4** se posponen post-V1 — son opt-in del usuario, no bloqueantes.

**Decisiones críticas que ya están tomadas y no se vuelven a abrir:**

- Verificación formal en ProVerif del handshake de tunnel es **bloqueante** para V1 (Cap 8 §8.1 + Cap 9 §9.4.4 tesis principal). **NO se solapa con codificación**: secuencial post-F4 código, 2-3 sem adicionales (si especialista) ó 4-6 sem (si dev aprende ProVerif).
- Security review externo es **bloqueante** para V1 (Cap 9 §9.3 tesis principal).
- M3 con `s_max = 6` shards máximos (Cap 4 §4.4 monografía).
- M4 off por default, on para canales LiveTV (Cap 4 §4.6 monografía).
- Cell size = 512 bytes Tor-style (Decisión 5.8 tesis principal).
- Multipath split: cada chunk consecutivo por circuito distinto (Decisión 5.1 tesis principal).
- **PST (Persistent Search Tunnel)** es BLOQUEANTE para V1 (Cap 6 §6.5 monografía). Sin PST, latencia búsqueda Modo B = ~6.2 s = UX inaceptable. Va dentro de F4b, no V2.
- **3 modos Kad v2** (Direct / Tunneled / Adaptive) con default Adaptive (Cap 6 §6.3 monografía). UI en F5.
- **`tunnel_fallback_policy`** STRICT_PRIVACY / BALANCED (default) / BEST_EFFORT (Cap 6 §6.7 monografía).
- **`KAD_V2_TUNNEL_FANOUT = 8`** para M3 sharded bajo tunnel (Cap 6 §6.4.3 monografía).
- **`OP_LIVE_T_CHUNK` (0xD9) envuelve `OP_LIVE_CHUNK_V2` (0xCC)** + capa onion. Decisión arquitectónica: no duplicar la firma + sha256; T_CHUNK contiene un CHUNK_V2 íntegro como payload tras pelar las capas del onion.
- **Capabilities unificadas en un solo tag `TAG_ESE_CAPS`** ("\x6C"). Bitmap único cubre M1-M6 (bits 0-5), tunneling (bit 8), sealed records (bit 9), gossip (bit 10), cover traffic (bit 11). Reemplaza ambos `TAG_KAD_V2_CAPS` (Cap 5 §5.4.1 monografía) y `TAG_ESE_LIVE_CAPS` (Cap 5 §5.9.3 tesis principal). Justificación: un cliente eSE moderno implementa AMBAS partes (Kad v2 y privacy), no tiene sentido distinguir negociación.

---

## 1. Inventario y estado actual del código

### 1.1 Trabajo ya en código (no spec, mergeable)

| Bloque | Worktree | Estado | Cobertura de la tesis |
|---|---|---|---|
| IPv6 dual-stack listener + Kad3 stub handlers | `focused-bohr-b819cf` | Built, dropped en `C:\emule\` | No documentado en tesis pero requisito de Sprint 4 |
| Plan H1-H8: `EseLiveGetKeywordHash` + dual-publish + dual-search + `knownStreamsClean/Legacy` | `focused-bohr-b819cf` | Built, dropped en `C:\emule\` | **Absorbe M0 (namespace isolation) y parcialmente M1 (republish)** — la monografía no lo contemplaba pero es un mecanismo ortogonal. Se documentará como M0 en una errata de la monografía. |
| Ed25519 self-cert (`streamKey = sha1(pubkey)[:16]`) + `OP_LIVE_END` signature + `OP_LIVE_CHUNK_V2` signed | `focused-bohr-b819cf` (v7.6.0 / v7.7.0) | Built, en producción local | Pre-requisito de Cap 5 §5.6 tesis principal (stream session key) |
| `server.met` v2 (ST_IPV6 BLOB) + `known.met` v0x10 (TAG_*_V6) | `focused-bohr-b819cf` | Built | Compat 0.70b preservada — base para Cap 5 §5.9 compat tag |
| CAddress wire format (1+1+N) | `focused-bohr-b819cf` | Built + Python unit tests | Pre-requisito de cualquier wire format con IPv6 |

### 1.2 Opcodes ocupados (validación de colisiones)

**Dispatcher `OP_EMULEPROT` (TCP eMule entre peers):**

| Rango | Asignados | Libres |
|---|---|---|
| 0xC0-0xC4 | `OP_LIVE_ANNOUNCE..UNSUBSCRIBE` | — |
| 0xC5 | `OP_EMULEPROT` (header byte, NO opcode) | — |
| 0xC6-0xCB | `HEARTBEAT, DENY, END, PING, PEER_LIST, PONG` | — |
| 0xCC-0xCF | `CHUNK_V2, PEER_LIST_V2, RELAY_REQ, RELAY_FWD` (plan IPv6) | — |
| **0xD0-0xDF** | — *(salvo 0xD4 = OP_PACKEDPROT header)* | **15 slots para tesis principal** |
| 0xE0-0xE2 | `PUBLICIP_ANSWER_V6, CALLBACK_V6, FOUNDSOURCES_V6` (IPv6) | — |

→ **Tesis principal Cap 5 §5.7.1 reserva 0xD0-0xDF saltándose 0xD4.** Cabe sin colisiones. La asignación es:

```
OP_LIVE_CHANNEL_GOSSIP      0xD0
OP_LIVE_CHANNEL_REQUEST     0xD1
OP_LIVE_CHANNEL_ANSWER      0xD2
OP_LIVE_CHANNEL_REVOKE      0xD3
[0xD4 reservado: OP_PACKEDPROT]
OP_LIVE_TUNNEL_CELL         0xD5
OP_LIVE_T_SUBSCRIBE         0xD6
OP_LIVE_T_UNSUBSCRIBE       0xD7
OP_LIVE_T_REQUEST           0xD8
OP_LIVE_T_CHUNK             0xD9
OP_LIVE_T_HEARTBEAT         0xDA
OP_LIVE_T_ANNOUNCE          0xDB
OP_LIVE_T_DENY              0xDC
OP_LIVE_T_END               0xDD
OP_LIVE_PEER_INVITE         0xDE
OP_LIVE_RENDEZVOUS_PEERS    0xDF
```

**Dispatcher `OP_KADEMLIAHEADER` (UDP Kad — namespace SEPARADO del anterior):**

| Rango | Asignados | Libres |
|---|---|---|
| 0x00-0x65 | Kad v1/v2 + Kad3 v6-aware (plan IPv6) | — |
| 0x66-0x6A | `KADEMLIA3_PING/HOLEPUNCH_*` (plan IPv6) | — |
| **0xCA-0xCF** | — | **6 slots para Kad Search v2** |

→ **Monografía Kad v2 Cap 5 reserva 0xCA-0xCF en este subspace.** NO colisiona con los `OP_LIVE_*` en `OP_EMULEPROT`. La asignación es:

```
OP_KADEMLIA2_KEY_SHARD_ANNOUNCE   0xCA   M3
OP_KADEMLIA2_PUBLISH_TRIGRAM_REQ  0xCB   M4
OP_KADEMLIA2_SEARCH_TRIGRAM_REQ   0xCC   M4
OP_KADEMLIA2_BLOOM_DIGEST_REQ     0xCD   M5
OP_KADEMLIA2_LOCAL_QUERY_REQ      0xCE   M5
OP_KADEMLIA2_LOCAL_QUERY_RES      0xCF   M5
```

**Tags Kad (namespace de TAG, distinto de opcodes):**

Audit del namespace tag (single-byte name `"\xXX"`) realizado 2026-05-18 con grep cross-tree. Estado:

| Byte | Uso actual | Disponibilidad |
|---|---|---|
| 0x01-0x55 | `FT_*` / `TAG_*` file metadata (scattered) | Ocupado parcial |
| 0x56-0x65 | sin uso confirmado | Libre |
| 0x66 | `TAG_SOURCEIP_V6` (Sprint 8 IPv6) | Ocupado por nosotros |
| 0x67 | `TAG_SERVERIP_V6` (Sprint 8 IPv6) | Ocupado por nosotros |
| **0x68-0x6B** | **sin uso confirmado** | **Libre — propuesta Kad v2** |
| 0x6C-0xCF | sin uso confirmado | Libre |
| 0xD0-0xD5 | `TAG_MEDIA_*` (file metadata) | Ocupado |
| 0xD6-0xF1 | sin uso confirmado | Libre |
| 0xF2-0xFF | `TAG_KADMISCOPTIONS..TAG_SOURCETYPE` (Kad/server/source tags estándar) | Ocupado, no tocar |

Las 4 asignaciones originales de la monografía Cap 5 (0xF4-0xF7) chocan con `TAG_USER_COUNT`, `TAG_FILE_COUNT`, `TAG_FILECOMMENT`, `TAG_FILERATING` respectivamente. **Asignación definitiva tras audit (autorizada por el user 2026-05-18):**

```c
// Tag namespace eSE (auditado y congelado 2026-05-18, F0)
#define TAG_K_EFFECTIVE              "\x69"   // M6; k_effective ∈ [4, 24]
#define TAG_SHARD_DEGREE             "\x6A"   // M3; s ∈ [0, 6]
#define TAG_PINNED_BY_SUBSCRIBER     "\x6B"   // M1; flag uint8 0/1
// TAG_ESE_CAPS UNIFICA capabilities Kad v2 + privacy. Bitmap uint32:
//   bit 0: M1 subscriber pinning
//   bit 1: M2 composite keys
//   bit 2: M3 sharding
//   bit 3: M4 trigrams
//   bit 4: M5 bloom gossip
//   bit 5: M6 k effective
//   bit 6-7: reservado Kad v2
//   bit 8: privacy tunneling
//   bit 9: sealed records
//   bit 10: gossip protocol
//   bit 11: cover traffic
//   bit 12-31: reservado privacy
// Reemplaza el TAG_KAD_V2_CAPS (Cap 5 §5.4.1 monografía) y el
// TAG_ESE_LIVE_CAPS (Cap 5 §5.9.3 tesis principal). Justificación de la
// unificación: un cliente eSE moderno implementa ambas capas juntas; no
// existe escenario realista donde un peer ofrezca Kad v2 sin privacy o
// viceversa. Erratas necesarias a ambas tesis (§7 de este plan).
#define TAG_ESE_CAPS                 "\x6C"   // global; uint32 bitmap unificado
```

Estas asignaciones quedan congeladas en la Fase 0. Ambas tesis se actualizan con la errata correspondiente (§7).

### 1.3 Estado de la tesis vs realidad del código

| Tesis | Capítulo | Implementado | Spec sólo | Gap |
|---|---|---|---|---|
| Privacidad | Cap 1 (threat model) | — | ✅ | conceptual, no código |
| Privacidad | Cap 4 (crypto toolkit) | ⚠ parcial — Ed25519 hecho | ✅ | falta X25519, ChaCha20-Poly1305 wiring, HKDF, Argon2id |
| Privacidad | Cap 5 (protocol architecture) | — | ✅ | todo wire format de tunneling, channels, cells |
| Privacidad | Cap 9 (roadmap) | — | ✅ | 4 fases (Foundation, Discovery, Tunneling, Integración) |
| Kad v2 | Cap 4 (M1-M6) | ⚠ M0 (plan H) + parcial M1 | ✅ | M1 completo, M2-M6 |
| Kad v2 | Cap 5 (impl) | — | ✅ | 18 archivos nuevos, opcodes Kad |
| Kad v2 | Cap 6 (privacidad) | — | ✅ | **PST + 3 modos + fallback policy + fanout 8 → integrados en F4b** |

### 1.4 Estado git real (verificado 2026-05-18)

`git worktree list` + `git status --short` revelan:

| Ubicación | Branch | Estado | Riesgo |
|---|---|---|---|
| `main` (raíz repo) | HEAD 07d09c1 | clean | — |
| `feature/ipv6-integration` (`C:\emule-ipv6-build`) | HEAD 3682586, dropped en `C:\emule\` | clean working tree | bajo |
| `focused-bohr-b819cf` (este worktree) | HEAD 6b11f0e (eSEHelpers viejo), **~50 archivos staged/modificados SIN COMMIT** | dirty | **alto** — plan H1-H8 + IPv6 + plan unificado sin guardar |
| `hungry-dhawan-84bd82` (tesis privacidad) | HEAD 07d09c1, `docs/` **untracked** | dirty | **alto** — tesis sin commit |
| `quizzical-newton-9aa3db` (tesis Kad v2) | HEAD 07d09c1, `docs/` **untracked** | dirty | **alto** — monografía sin commit |

**Implicación:** F0.5 (nueva, ver §3) tiene que consolidar todo lo no commiteado antes de empezar F0. Si no, un crash de disco pierde meses de trabajo.

---

## 2. Filosofía de ordenación

Tres principios:

**P1. Seguridad first, velocidad última.** Ningún atajo de velocidad de desarrollo cuenta más que un módulo cripto bien revisado. ProVerif y security review son bloqueantes — no negociables.

**P2. Mecánica antes que estética.** Primero protocolo funcionando entre 2 peers en LAN; UI viene al final. La tesis principal Cap 9 §9.4 lo respeta. La monografía Cap 5 §5.9 también (los mecanismos M1-M6 son opt-in en preferencias, sin UI nueva hasta integración).

**P3. Compatibilidad bidireccional siempre, en cada fase.** Cualquier release intermedio (alpha/beta) debe ser back-compat con 0.70b. No hay "phase X que rompe compat se arreglará en phase Y".

Y una **regla de oro de dependencias**: si un módulo A es prerequisito de B, A está en una fase anterior. Si A y B son ortogonales, pueden ir en paralelo en la misma fase (asumiendo recursos).

---

## 3. Plan por fases (12 fases, ~33 semanas)

### Fase 0.5 — Consolidación git (3-5 días)

**Objetivo:** asegurar que NADA del trabajo previo se pierde antes de tocar más código. Resuelve el riesgo "alto" de §1.4.

**Entregables:**

- [ ] **focused-bohr-b819cf**: commit del plan H1-H8 en commits temáticos (H1+H2 crypto/pref, H3+H4 publish-search, H5 metrics, H6 build, H7 livehash, H8 anti-leak). NO push aún (orden permanente del user).
- [ ] **focused-bohr-b819cf**: commit del trabajo IPv6 si no estaba ya (ListenSocket dual-stack, Process_KADEMLIA3_GENERIC, OnPeerListReceivedV6, server.met v2, CAddress, etc.). Verificar contra `feature/ipv6-integration` para evitar duplicar.
- [ ] **focused-bohr-b819cf**: commit del `docs/UNIFIED_IMPLEMENTATION_PLAN.md`.
- [ ] **hungry-dhawan-84bd82**: `git add docs/` + commit "thesis: privacy architecture initial draft (9 caps)". El worktree pertenece a `claude/hungry-dhawan-84bd82`.
- [ ] **quizzical-newton-9aa3db**: `git add docs/` + commit "thesis: kad search v2 monograph initial draft (10 caps + biblio)". Branch `claude/quizzical-newton-9aa3db`.
- [ ] **quizzical-newton-9aa3db**: aplicar errata M0 (Apéndice A de este plan) a `docs/thesis/kad-search-v2/04-diseno-kad-v2.md`, commit "thesis: add M0 namespace isolation as §4.1.1".
- [ ] **Verificación**: `git reflog` en cada branch confirma los commits visibles. Si OneDrive crashea, los commits están en `.git/`.

**Criterio de salida:**

- Tres branches con commits propios y mensajes claros.
- Nada perdible está untracked.
- Tag git temporal `pre-F0-snapshot` en main que apunte al estado actual (rollback point por si F0 introduce regresión inesperada).

**Coste:** 3-5 días. Cero LOC nueva, solo organización.

**Riesgo si se salta esta fase:** F0 toca opcodes en `Opcodes.h` (archivo modificado por el plan H y por IPv6 ya). Si el merge llega tarde, conflictos triviales que cuestan horas.

---

### Fase 0 — Plumbing y reservas (1 semana)

**Objetivo:** dejar el código preparado para los rangos de opcodes/tags que las dos tesis necesitan, SIN implementar funcionalidad. Solo `#define` reservas + `case` stubs vacíos en dispatchers + verificación de colisiones de tag namespace.

**Entregables:**

- [ ] **`Opcodes.h`:** añadir bloque comentado `// === eSE Live Tunneled — reservado 0xD0-0xDF` con los 15 `#define` de Cap 5 §5.7.1 (sin handler).
- [ ] **`Opcodes.h`:** añadir bloque `// === Kad v2 search — reservado 0xCA-0xCF en OP_KADEMLIAHEADER` con los 6 `#define`.
- [ ] **`Opcodes.h`:** añadir bloque `// === Tags eSE unificados` con `TAG_K_EFFECTIVE 0x69`, `TAG_SHARD_DEGREE 0x6A`, `TAG_PINNED_BY_SUBSCRIBER 0x6B`, `TAG_ESE_CAPS 0x6C` (capabilities unificadas — ver §0).
- [ ] **`ListenSocket.cpp`:** 15 `case` stubs para 0xD0-0xDF que solo hacen `DebugLog("[STUB] OP_LIVE_T_XXX — Phase 0 reservation; not yet implemented")` + return. Cliente 0.70b no los ve nunca (G6).
- [ ] **`KademliaUDPListener.cpp`:** 6 `case` stubs para 0xCA-0xCF idem.
- [ ] **Capabilities emit in handshake**: en `BaseClient.cpp` emit `TAG_ESE_CAPS = 0` (todos los bits a 0 en F0 — sin features). Solo se enciende bit correspondiente cuando la feature pasa criterio de salida de su fase. Esto evita "feature claim" antes de que la feature funcione.

**Criterio de salida:** build limpio, `nm` confirma las 21 funciones-stub, tests de regresión con cliente 0.70b en LAN pasan sin warnings. `TAG_ESE_CAPS` se emite (a 0) y se parsea correctamente en BaseClient.

**Coste:** ~200 LOC + verificación. 1 semana real.

---

### Fase 1 — Kad Search v2 base, MODO DIRECT (M3 + M5 + M6) (3-4 semanas)

**Objetivo:** los tres mecanismos *default-on* de la monografía, operando **solo en Modo Direct** (sin tunneling). M3 (sharding adaptativo), M5 (Bloom gossip), M6 (k efectivo). El soporte Modo Tunneled de estos mecanismos (PST, fanout 8, etc.) se añade en F4b — pero la arquitectura interna se diseña ya para acomodarlo (interfaces, no duplicación de lógica).

**Por qué arrancar por aquí:**

1. La carga de tráfico Kad agregado mejora antes de añadir más publishes (channels, subscriber pinning).
2. M5 (Bloom local) reduce latencia de búsqueda de keyword — beneficio inmediato.
3. El plan H ya implementó M0 → la integración con M3/M5 es natural.
4. **Diseño tunnel-ready desde F1**: cada operación Kad v2 acepta un `CKadV2Mode` enum (Direct/Tunneled/Adaptive). En F1 todas pasan `Direct`. En F4b se conecta el path Tunneled. Esto evita refactor masivo en F4b.

**Módulos nuevos:**

| Módulo | LOC | Tests |
|---|---|---|
| `KadV2Defines.h` | 80 | — |
| `KadV2BloomFilter.h/.cpp` (M5) | 180 | 140 |
| `KadV2Sharding.h/.cpp` (M3) | 280 | 90 |
| `KadV2KEffective.h/.cpp` (M6) | 140 | 60 |
| `KadV2Stats.h/.cpp` | 100 | — |

**Parches:**

- `Indexed.h/.cpp`: `m_mapShardState`, `m_mapKEffective`. +120 LOC.
- `Search.cpp`: planner con shard parallelism + k_eff lookup. +80 LOC.
- `KademliaUDPListener.cpp`: handlers reales para `OP_KADEMLIA2_KEY_SHARD_ANNOUNCE`, `BLOOM_DIGEST_REQ`, `LOCAL_QUERY_REQ/RES`. +110 LOC.
- `Prefs.cpp` + UI dialog: 3 checkboxes (M3, M5, M6) en config Kad. +30 LOC.

**Criterio de salida:**

- [ ] Un keyword con >50 000 entries dispara `OP_KADEMLIA2_KEY_SHARD_ANNOUNCE` automáticamente.
- [ ] Búsqueda de un keyword conocido vía Bloom de vecino devuelve resultados <200 ms.
- [ ] `TAG_K_EFFECTIVE` se anuncia en `KADEMLIA2_RES` y se usa al publicar.
- [ ] Compat: cliente 0.70b en LAN publica/busca sin afectación.
- [ ] Stats: `/api/live/debug` añade `bloomQueries`, `shardsActive`, `kEffectiveAvg`.

**Coste:** ~1 040 LOC. 3-4 semanas con 1 dev.

---

### Fase 2 — Privacy Foundation (Cap 9 Fase 0 tesis principal) (2-3 semanas)

**Objetivo:** primitivas criptográficas + ChannelRecord + Subscription store. **SIN RED.** Solo unit tests.

**Por qué en paralelo a Fase 1:** la Foundation no toca Kad ni red — son módulos cripto puros. Si hay un segundo dev, pueden ir simultáneas.

**Módulos:**

| Módulo | LOC | Tests |
|---|---|---|
| `LiveOnionCrypto.h/.cpp` | 300 | 30 vectores cripto |
| `LiveChannel.h/.cpp` | 400 | 20 unit + property tests |
| `LiveSubscriptionStore.h/.cpp` | 200 | 15 unit con DPAPI |

**Decisiones cripto (Cap 4 tesis principal):**

- Ed25519 ya está hecho (v7.6.0). Reutilizar.
- X25519 para handshake ntor-style: añadir en `LiveOnionCrypto.cpp`.
- ChaCha20-Poly1305 default (mejor sin AES-NI). CryptoPP ya lo tiene.
- HKDF-SHA-256 para derivación de claves.
- Argon2id pospuesto a V2 (no necesario para V1).

**Criterio de salida:**

- [ ] Generar keypair Ed25519, firmar ChannelRecord, verificar — pasa.
- [ ] Sellar record con AEAD + abrir + verificar firma → roundtrip ok.
- [ ] `subscriptions.dat` DPAPI roundtrip ok.
- [ ] Test vectors contra libsodium — pasan.
- [ ] **Code review estricto de los 3 módulos** (criterio Cap 9 §9.3 tesis principal).

**Coste:** ~900 LOC. 2-3 semanas con 1 dev.

---

### Fase 3 — Privacy Discovery + Kad v2 M1 (Cap 9 Fase 1 + monografía M1) (4-5 semanas)

**Objetivo:** clientes pueden publicar/descubrir channels firmados via Kad **sin tunneling todavía**. Dos "subscriber pinnings" distintos pero coordinados con scheduler común.

**Aclaración crítica — los dos subscriber pinnings NO son lo mismo:**

| Pinning | Qué se republica | Activador | Payload | Periodicidad |
|---|---|---|---|---|
| **M1 (monografía Cap 4 §4.2)** | metadata de archivo eD2K descargado | usuario completó descarga y tiene la opción "Help index files I download" ON | `CKeyEntry` con flag `TAG_PINNED_BY_SUBSCRIBER=1` | T_pin ∈ [3600, 7200] s |
| **Subscriber pinning de channels (tesis privacidad Cap 5 §5.3.4)** | `ChannelRecord` firmado de canal suscrito | usuario suscrito al canal en `my_subs` | `ChannelRecord` serializado | cada 6h ±60 min |

Comparten **patrón** (descargador/suscriptor reanuncia lo que tiene), no **código** (payload distinto, store distinto, validación distinta). El plan los implementa con **scheduler común** (`CSubscriberPinScheduler`) y **dos despachadores** distintos.

**Módulos nuevos privacidad:**

| Módulo | LOC | Tests |
|---|---|---|
| `LiveGossip.h/.cpp` | 250 | 80 |
| `LiveBootstrap.h/.cpp` (B1-B5) | 300 | 60 |
| `LiveSubscriberPinning.h/.cpp` (channels) | 150 | 40 |

**Módulo Kad v2 M1:**

| Módulo | LOC | Tests |
|---|---|---|
| `KadV2SubscriberPin.h/.cpp` (files) | 250 | 100 |

**Módulo compartido (factorizar el scheduler):**

| Módulo | LOC | Tests |
|---|---|---|
| `SubscriberPinScheduler.h/.cpp` (genérico, con dos tipos de payload) | 100 | 40 |

**Parches:**

- `LiveKadBridge.cpp`: extender con `PublishChannel`, `LookupChannel`, `SearchChannelsByKeyword`. +400 LOC.
- `LivePackets.cpp`: serializar `OP_LIVE_CHANNEL_GOSSIP/REQUEST/ANSWER/REVOKE` (0xD0-0xD3). +200 LOC.

**Wire formats nuevos (Cap 5 §5.2):**

- `ChannelRecord` (~400-500 bytes serializado)
- `ChannelRevocation`
- `RendezvousList`

**Criterio de salida:**

- [ ] Cliente A publica canal "MadridTV" → cliente B en otra máquina lo encuentra vía Kad search.
- [ ] Cliente C en LAN lo encuentra vía mDNS.
- [ ] **M1 files**: peer que descargó un fichero eD2K republica metadata; entry sobrevive a churn del publisher original.
- [ ] **Subscriber pinning channels**: cliente B suscrito a "MadridTV" republica cada 6h; A puede apagarse sin que el canal desaparezca.
- [ ] Ambos pinnings usan el mismo scheduler (`CSubscriberPinScheduler`) pero con dispatchers diferentes.
- [ ] Cover traffic en refreshes verificado (10 reales + 10 dummy random en cada ráfaga).
- [ ] Compat: cliente 0.70b ignora packets 0xD0-0xD3, sigue funcionando normal.
- [ ] **NO hay protección de IP todavía** — esto es solo discovery descentralizada; los tunnels llegan en Fase 4.
- [ ] `TAG_ESE_CAPS` bit 0 (M1) y bit 9 (sealed records) se encienden al pasar criterio de salida.

**Coste:** ~1 650 LOC. 4-5 semanas con 1 dev.

---

### Fase 4 — Privacy Tunneling, código (Cap 9 Fase 2 tesis principal) (6-8 semanas)

**Objetivo:** la pieza más grande. Tunnels 2-hop onion. **Sólo código en F4**; el ProVerif va en F4a (secuencial, no solapado).

**Módulos:**

| Módulo | LOC | Tests |
|---|---|---|
| `LiveTunnel.h/.cpp` | 1 500 | 200 |
| `LiveCircuit.h/.cpp` | 400 | 80 |
| `LiveCellQueue.h/.cpp` | 200 | 60 |
| `LiveCoverTraffic.h/.cpp` | 150 | 40 |

**Parches:**

- `LivePackets.cpp`: serializar `OP_LIVE_TUNNEL_CELL` (0xD5) y embebido. +100 LOC.

**Decisiones de Cap 5 §5.5:**

- Cell size 512 B fijo (Decisión 5.8).
- Pool 3-5 circuitos por viewer (Decisión 5.2).
- Rotación 30s ±10s jitter (Decisión 5.3).
- Cover traffic Poisson μ=50/s default, μ=200/s high-risk (Decisión 5.4).
- Multipath: chunks consecutivos por circuitos distintos (Decisión 5.1).
- Selección hops: anti-Sybil /24, /16 distintos (Decisión 5.5).

**Decisión arquitectónica `OP_LIVE_T_CHUNK` (0xD9) — congelada en este plan:**

- `OP_LIVE_T_CHUNK` ENVUELVE un `OP_LIVE_CHUNK_V2` (0xCC) íntegro como payload tras pelar las capas onion. Layout:
  ```
  Cell { circ_id, cmd=RELAY, length, encrypted_payload }
  encrypted_payload (después de peel) = OP_LIVE_CHUNK_V2 packet bytes
                                        (incluye sha256+sig ya verificables
                                         con la pubkey pineada — Cap 5 §5.6 stream session key
                                         + v7.6.0 self-cert)
  ```
- Justificación: no se duplica la verificación criptográfica (sha256 + Ed25519). El viewer recibe el T_CHUNK, peela capas, parsea el CHUNK_V2 embedded, verifica firma contra pubkey pineada exactamente igual que en streams públicos.
- Para streams privados, el CHUNK_V2 además se cifra con `K_stream` (Cap 5 §5.6.5) antes de envolverse en T_CHUNK. Esto da defense-in-depth: si un peel onion falla por bug, el chunk sigue cifrado e2e.

**Criterio de salida F4 código (Cap 9 §9.3.4 parcial):**

- [ ] Handshake 2-hop < 800 ms entre peers conocidos.
- [ ] Onion encrypt/decrypt pasa 1 000+ payloads aleatorios.
- [ ] Cover traffic μ=50/s histogram analysis verificado.
- [ ] Rotación 30s sin pérdida de chunks.
- [ ] 5 circuitos concurrentes 60 min sin fugas memoria.
- [ ] `OP_LIVE_T_CHUNK` wrap/unwrap roundtrip pasa tests vs `OP_LIVE_CHUNK_V2` directo.
- [ ] `TAG_ESE_CAPS` bit 8 (tunneling) y bit 11 (cover traffic) se encienden.

**Coste:** ~2 250 LOC. 6-8 semanas.

---

### Fase 4a — Verificación formal ProVerif (2-3 sem especialista / 4-6 sem dev aprende) (BLOQUEANTE V1)

**Objetivo:** demostrar formalmente las propiedades del handshake de tunnel. Decisión 8.1 + 9.2: **bloqueante para V1**.

**Decisión pendiente del user — abierta hasta F4 done:**

- (a) **Especialista contratado puntual** (2-3 semanas, ~3-5k€, calidad consistente).
- (b) **Dev principal aprende ProVerif** (4-6 semanas, coste cero, mayor riesgo de bug en modelo).
- (c) **Bounty público a comunidad cripto** (calendario impredecible — 4-12 semanas, calidad variable, alineado con `feedback_gratis_no_barato`).

Recomendación implícita del proyecto (feedback_gratis_no_barato): (c). Recomendación de seguridad: (a). Trade-off real, decisión del user al cierre de F4.

**Entregables:**

- Modelo ProVerif (`.pv`) del handshake CREATE/CREATED/EXTEND/EXTENDED (~500 líneas applied-pi).
- Verificación de las 4 propiedades:
  - **G1** Forward secrecy (Cap 1 tesis principal): si la pubkey de un peer se compromete después del handshake, las sesiones pasadas siguen confidenciales.
  - **G2** Authentication unilateral: el relay autentica al iniciador pero no al revés.
  - **G4** Confidentiality del payload bajo Dolev-Yao adversary.
  - **No replay** del handshake.
- Reporte público en `docs/audit/proverif-report.md`.

**Criterio de salida:**

- [ ] ProVerif termina con `RESULT ... is true.` para las 4 propiedades.
- [ ] Si ProVerif detecta fallo, **rediseñar handshake** y volver a F4 código (+ 2-3 sem). Riesgo R-2 del plan.

**Coste:** 2-6 semanas según opción (a)/(b)/(c). Cero LOC nueva sobre el código (puede requerir refactor pequeño si ProVerif sugiere cambio).

---

### Fase 4b — Kad v2 ↔ tunnels privacy (Cap 6 monografía) (2-3 semanas)

**Objetivo:** integrar los 6 mecanismos M1-M6 (que F1+F3 dejaron operando solo en Modo Direct) con la capa de tunnels de F4. Implementa PST (Persistent Search Tunnel), 3 modos, fallback policy y `KAD_V2_TUNNEL_FANOUT = 8`. Esta fase es **bloqueante para V1**: sin ella, las búsquedas Kad v2 en modo Tunneled son inviables por UX (~6.2 s mediana sin PST).

**Módulos nuevos:**

| Módulo | LOC | Tests |
|---|---|---|
| `KadV2TunnelPool.h/.cpp` (PST + successor make-before-break) | 280 | 100 |
| `KadV2ModeSelector.h/.cpp` (Direct/Tunneled/Adaptive + sensitive-keywords list) | 150 | 60 |

**Parches:**

- `KadV2Sharding.cpp`: añadir path Modo B con fanout 8 (KAD_V2_TUNNEL_FANOUT). +60 LOC.
- `KadV2SubscriberPin.cpp`: pool persistente de tunnels hacia top-k custodios (Cap 6 §6.4.1). +50 LOC.
- `LiveKadBridge.cpp`: enrutamiento por modo en `SearchStreams`, `PublishStream`, etc. +120 LOC.
- `Prefs.cpp` + UI dialog: pref `alwaysTunnelSearches`, lista `sensitiveKeywords`, enum `tunnel_fallback_policy`. +50 LOC.

**Decisiones de Cap 6 monografía (todas se aplican aquí):**

- **3 modos**: `KadV2Mode::Direct | Tunneled | Adaptive` (Cap 6 §6.3). Default Adaptive.
- **Reglas Adaptive** (Cap 6 §6.3 Modo C):
  ```
  IF query.includesPrivateChannelHash:        → Modo B
  IF query.terms.matchesSensitiveKeywordList: → Modo B
  IF prefs.alwaysTunnelSearches:              → Modo B
  ELSE:                                        → Modo A
  ```
- **PST** (Cap 6 §6.5): tunnel reusable durante su vida nominal (30 s); `successor tunnel` se construye proactivamente en background a partir del segundo 25. Reduce setup overhead 5× en sesiones interactivas.
- **`KAD_V2_TUNNEL_FANOUT = 8`** (Cap 6 §6.4.3): para M3 sharded query en Modo B, en lugar de 64 tunnels (uno por shard), 8 tunnels × 8 RPCs multiplexadas cada uno.
- **`tunnel_fallback_policy`** (Cap 6 §6.7): STRICT_PRIVACY / BALANCED (default) / BEST_EFFORT.
- **M4 nunca en Modo B** (Cap 6 §6.4.4): el fanout de trigramas es incompatible con UX <300ms; M4 solo opera sobre catálogo público.
- **M5 Bloom gossip directo, pero queries locales sí van por tunnel** (Cap 6 §6.4.5).

**Criterio de salida:**

- [ ] Lookup simple en Modo B+PST: latencia mediana ≤ 2.1 s (Cap 6 §6.6 tabla).
- [ ] Sharded M3 en Modo B+PST: latencia mediana ≤ 6.2 s, con `BALANCED` fallback funcionando.
- [ ] PST reusa setup en 4 de 5 queries consecutivas de una sesión simulada.
- [ ] Modo Adaptive selecciona Modo B automáticamente para queries con `includesPrivateChannelHash=true`.
- [ ] `tunnel_fallback_policy::STRICT_PRIVACY` aborta la operación con error visible cuando hay <2 relés disponibles.
- [ ] M4 nunca dispara tunnels (verificado).

**Coste:** ~710 LOC. 2-3 semanas.

---

### Fase 5 — Privacy Integration + UX (Cap 9 Fase 3 tesis principal) (4-6 semanas)

**Objetivo:** todo conectado. UI usable. Sistema end-to-end.

**Parches grandes:**

- `LiveMeshManager.cpp`: adaptar `PeerEndpoint` → `TunnelEndpoint`. +200 LOC.
- `LivePackets.cpp`: resto de opcodes `OP_LIVE_T_*` (0xD6-0xDF). +400 LOC.
- `LiveStreamDlg.cpp` + recursos: 4 pestañas (Subs / Browse / MyChannel / Search). ~+600 LOC + 300 LOC resource.
- Lang files (`.rc`): ~50 strings nuevos en ES/EN.
- **UI Kad v2 mode**: dropdown "Privacy mode" en barra de búsqueda (Direct/Tunneled/Adaptive) + dialog "Privacy settings" con lista editable de sensitiveKeywords + radio button para `tunnel_fallback_policy`. +150 LOC + 80 LOC resource.
- **UX peer legacy**: indicador en la lista de peers cuando un peer no advierte `TAG_ESE_CAPS` bit 8 (tunneling). Texto "⚠ Cliente legacy — no participa en streams privados". +30 LOC + 20 LOC resource.

**Criterio de salida (= V1 release-ready, Cap 9 §9.3 final):**

- [ ] Demo end-to-end: PC1 emite "MadridTV", PC2 se suscribe, ve stream.
- [ ] TTFF P50 < 5 s LAN (Cap 7 §7.4 tesis target 1.7s).
- [ ] TTFF P95 < 8 s WAN (Cap 7 §7.4 tesis target 4.2s).
- [ ] IP del viewer NUNCA aparece en logs del relay (con 2 hops).
- [ ] Cliente 0.70b en PC3 sigue descargando eD2K normal.
- [ ] Cliente 0.70b ve streams públicos (compat opcodes antiguos).
- [ ] Cliente 0.70b NO ve channels privados.
- [ ] Suite completa de tests passing.
- [ ] Documentación lista (README, CHANGELOG, security model).
- [ ] **`TAG_ESE_CAPS` bit 10 (gossip) se enciende.**

**Coste:** ~1 700 LOC. 4-6 semanas.

---

### Fase 5b — Migración v7.x → V1 (3-5 días)

**Objetivo:** los usuarios con v7.x.x del fork actual conservan estado al actualizar a V1.

**Archivos heredados a tener en cuenta:**

| Archivo | Origen | Acción V1 |
|---|---|---|
| `eselive_directory.dat` | v7.x.x `CLiveKadBridge` (texto plano, key=value) | leer al primer arranque, importar streams como "discovery cache"; mantener escritura durante transición; deprecar en V1.1 |
| `last_streams.json` | v7.x.x bootstrap cache | leer e importar; mantener escritura |
| Sin equivalente | — | **crear** `subscriptions.dat` (cifrado DPAPI) — vacío al instalar V1 |
| Sin equivalente | — | **crear** `my_channels/` dir con permisos restringidos para keypairs Ed25519 |

**Wire format migration:**

- streamKey (16 bytes) sigue siendo válido; v7.x.x streamKey continúa funcionando en V1 (broadcaster mantiene su key Ed25519 si lo guardó).
- Si el broadcaster v7.x.x NO tiene Ed25519 keypair persistido, V1 genera uno nuevo al primer arranque y advierte al usuario "se ha creado una nueva identidad de canal, los suscriptores anteriores no te encontrarán automáticamente".

**Criterio de salida:**

- [ ] Usuario en v7.x.x actualiza a V1 y mantiene su directorio de streams discovery.
- [ ] Si tenía broadcast activo en v7.x.x, V1 detecta su keypair y le mantiene el mismo streamKey.
- [ ] Si no tenía keypair, V1 genera uno y muestra dialog informativo.
- [ ] Tests de migración con `eselive_directory.dat` y `last_streams.json` de v7.7.0.

**Coste:** ~200 LOC + tests. 3-5 días.

---

### Fase 6 — Security review externo (2-3 semanas)

**Objetivo:** auditoría cripto externa. **BLOQUEANTE para V1.** Decisión 9.3 de la tesis.

**Alcance del review:**

- `LiveOnionCrypto`
- `LiveTunnel`
- `LiveChannel` (firma/verificación)
- Cualquier parser de input no confiable (cells, channel records, gossip)

**Idealmente:** contratado a alguien con experiencia en cryptographic protocol review. Si presupuesto cero (consistente con `feedback_gratis_no_barato`), comunidad cripto + bounty.

**Criterio de salida:**

- [ ] Issues críticos remediados.
- [ ] Reporte público en `docs/audit/`.

**Coste:** 2-3 semanas calendario (no necesariamente dev-time).

---

### Fase 7 — V1 RELEASE (1 semana)

**Objetivo:** release opt-in inicial (Decisión 9.4).

**Entregables:**

- Build separado `eSE Live 1.0`.
- README + CHANGELOG.
- Documentación de threat model accesible.
- Mecanismo opcional de check-version.

---

### Fase 8 — Kad Search v2 M2 + M4 (post-V1) (2-3 semanas)

**Objetivo:** los dos mecanismos opt-in de la monografía. **POST-V1** porque son opt-in del usuario y no bloquean release.

**Módulos:**

| Módulo | LOC | Tests |
|---|---|---|
| `KadV2Tokenizer.h/.cpp` (M2 composite + M4 trigrams) | 220 | 180 |
| `KadV2TrigramIndex.h/.cpp` (M4) | 200 | 80 |

**Parches:**

- `Search.cpp`: planner con composite key + trigram fallback. +80 LOC.
- `KademliaUDPListener.cpp`: handlers `PUBLISH_TRIGRAM_REQ`/`SEARCH_TRIGRAM_REQ`. +50 LOC.

**Decisión Cap 4 §4.6 monografía:** M4 default ON solo para canales LiveTV (alta UX, bajo volumen). Para file-sharing general es opt-in (7× publish cost).

**Coste:** ~810 LOC. 2-3 semanas.

---

### Fase 9 — V2 post-release (mes 2-3 post-V1)

Pendientes V2 según ambas tesis:

- P-1 PoW continuo anti-Sybil (tesis principal Cap 8 §8.13)
- P-3 NAT/CGNAT (STUN + Tailscale opcional)
- P-8 PQ hybrid crypto cuando NIST FIPS 203/204 maduren
- P-9 Obfs4 transport para DPI obfuscation
- PST (Persistent Search Tunnel) — Cap 6 §6.5 monografía
- Mediciones empíricas para sustituir proyecciones (†) de la monografía Cap 9

---

## 4. Timeline agregado

```
Semana   Fase     Pasa de spec a código
─────────────────────────────────────────────────
0.5      F0.5     Consolidación git (commits faltantes)
1        F0       Plumbing reservas opcodes + TAG_ESE_CAPS
2-5      F1       Kad v2 base MODO DIRECT (M3+M5+M6) [tunnel-ready interface]
2-5*     F2       Privacy Foundation (paralelo si 2 devs)
6-10     F3       Privacy Discovery + Kad v2 M1 + scheduler común
11-18    F4       Privacy Tunneling código (sin ProVerif aún)
19-21    F4a      ProVerif (especialista 2-3 sem ó dev aprende 4-6 sem)
22-24    F4b      Kad v2 ↔ tunnels (PST + 3 modos + fallback)
25-29    F5       Privacy Integration + UI Kad v2 + UX peer legacy
30       F5b      Migración v7.x → V1
31-33    F6       Security review externo (calendario, no dev-FT)
34       F7       V1 RELEASE
35-37    F8       Kad v2 opt-in (M2+M4) — post-release
38+      F9       V2 features

* F2 puede paralelizarse con F1 si hay segundo dev disponible
```

**Total V1: 34 semanas (~8 meses) con 1 dev.** Asumiendo F4a opción (a) especialista contratado (2-3 sem). Con opción (b) dev aprende ProVerif: **36-37 semanas (~8-9 meses)**. Con opción (c) bounty público: **34-42 semanas según respuesta de la comunidad**.

Realista incluyendo aprendizaje + debug + bugs sutiles: **36-44 semanas (8-10 meses)**.

Si hay 2 devs (paralelizando F1 y F2, F4 y F4a parcialmente): **Total V1: 26-30 semanas (~6-7 meses)**.

---

## 5. Hitos y entregables

| Hito | Fase | Semana | Entrega |
|---|---|---|---|
| **H0** | F0.5 done | 0.5 | 3 ramas con commits propios; tag pre-F0-snapshot |
| **H1** | F0 done | 1 | 21 stubs de opcodes; TAG_ESE_CAPS funcional |
| **H2** | F1 done | 5 | Kad v2 base default-on Modo Direct; benchmarks vs baseline 0.70b |
| **H3** | F2 done | 5 | Crypto module + ChannelRecord roundtrip; code review #1 |
| **H4** | F3 done | 10 | Demo cross-machine: A publica canal, B lo encuentra, sin tunneling. Ambos pinnings (files y channels) funcionando |
| **H5** | F4 alpha | 15 | Tunnels 2-hop código completo (sin ProVerif aún); fuzzing 48h sin crashes |
| **H6** | F4 + F4a done | 21 | **ProVerif aprobado** — G1/G2/G4 + no replay; security review puede empezar |
| **H6.5** | F4b done | 24 | Kad v2 ↔ tunnels integrado; PST funcionando; benchmarks Modo Tunneled <2.1s mediana |
| **H7** | F5 alpha | 27 | UI 4 pestañas con datos mock; flujo end-to-end demo LAN |
| **H8** | F5 done | 29 | Sistema E2E completo; tests passing; UI privacy mode + fallback policy expuestos |
| **H8.5** | F5b done | 30 | Migración v7.x → V1 verificada con users de prueba |
| **H9** | F6 done | 33 | Issues de review remediados; reporte público en `docs/audit/` |
| **H10** | F7 | 34 | **V1 RELEASE** |
| H11 | F8 done | 37 | M2/M4 disponibles opt-in |

---

## 6. Riesgos críticos y mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|
| **Pérdida del trabajo no commiteado** | **Alta** (worktrees en OneDrive) | **Catastrófico** (~50 archivos + 2 tesis) | **F0.5 obligatoria antes de F0**. Tag git pre-F0-snapshot. |
| Bug crítico en `LiveTunnel` post-release | Alta sin ProVerif | Privacidad rota | ProVerif bloqueante (F4a); fuzzing 48h; security review externo |
| ProVerif demuestra fallo del handshake | Media | 2-3 semanas extra rediseño | Tiempo amortiguado: F4a separada de F4 código, ya secuencial. Alternativas (Noise patterns) en backlog. |
| Nadie en comunidad sabe ProVerif | Media | F4a extiende a 6+ sem | Decisión user al cierre F4: opción (a) especialista pagado vs (b) dev aprende vs (c) bounty. Recomendación seguridad: (a). |
| Performance Modo B sharded > 6.2 s (Cap 6 §6.6) | Media | UX inaceptable para keywords hot | F4b implementa PST + fanout 8 + cache de resultados 10min |
| Performance TTFF P50 > 5s | Media | UX degradada | Benchmarks tempranos en F4; opción config a 1-hop con warning |
| Compat 0.70b rota | Baja | G6 violada | Tests regresión automáticos desde F0; PR review extra para tocar opcodes |
| Bootstrap falla nuevos usuarios | Media | Adopción cero | Múltiples paths B1-B5; mDNS LAN; invite tokens vía cualquier canal |
| Adopción baja → swarm pequeño | Alta lanzamiento | Anonimato real degradado | Graceful degrade 1-hop si M<10 peers; documentar trade-off; `tunnel_fallback_policy::BEST_EFFORT` |
| Tag namespace colisiones tardías | Resuelto | — | Audit completado 2026-05-18; TAG_ESE_CAPS unificado @ 0x6C |
| Confusión M1 files vs subscriber pinning channels | Resuelto | — | F3 los implementa con scheduler común pero dispatchers separados, documentado en plan |
| `OP_LIVE_T_CHUNK` duplica verificación cripto del CHUNK_V2 | Resuelto | — | T_CHUNK envuelve CHUNK_V2 íntegro, no duplica firma/sha256 |
| Plan H ya implementado y monografía con M0 no documentado | Resuelto | — | Errata M0 añadida (Apéndice A); aplicada a monografía en F0.5 |
| Migración v7.x → V1 pierde directorio | Media | Users updaters perderían streams cached | F5b explícita; tests con `eselive_directory.dat` y `last_streams.json` de v7.7.0 |

---

## 7. Erratas a las tesis

### 7.1 Errata 1 — Monografía Kad Search v2: añadir M0

El plan H1-H8 ya implementado introduce un mecanismo que la monografía no contemplaba:

**M0 — Namespace isolation por prefijo binario.**

- `EseLiveGetKeywordHash(kw) = MD4("\x00eSE\x00" || utf8(kw))`
- Aísla el espacio Kad eSE del espacio de búsqueda legacy.
- Dual-publish + dual-search con pref `m_bEseLivePublishLegacy` (default true durante transición).
- TAG_FILENAME y TAG_FILETYPE omitidos en publishes clean (anti-leak).

**Acción:** añadir §4.1.1 "M0 — Namespace isolation" a `04-diseno-kad-v2.md` con la misma estructura formal (a)-(e). Texto completo en Apéndice A. ~600 palabras.

### 7.2 Errata 2 — Monografía Kad Search v2: tag IDs

Cap 5 §5.4 reasignación de tag IDs (los originales 0xF4-0xF7 colisionan con eMule estándar):

```
ANTES:                          DESPUÉS:
TAG_KAD_V2_CAPS  0xF4    →     TAG_ESE_CAPS  0x6C    (UNIFICADO con privacy)
TAG_K_EFFECTIVE  0xF5    →     TAG_K_EFFECTIVE  0x69
TAG_SHARD_DEGREE 0xF6    →     TAG_SHARD_DEGREE 0x6A
TAG_PINNED_BY_SUBSCRIBER 0xF7 → TAG_PINNED_BY_SUBSCRIBER 0x6B
```

### 7.3 Errata 3 — Tesis privacidad: TAG_ESE_LIVE_CAPS se unifica

Cap 5 §5.9.3 tesis principal define `TAG_ESE_LIVE_CAPS` separado. Errata: **unificar con `TAG_ESE_CAPS = 0x6C`** descrito en §0 de este plan. El bitmap incluye tanto bits Kad v2 (0-7) como bits privacy (8-31). Justificación: no existe escenario realista donde un peer ofrezca Kad v2 sin privacy o viceversa — son features de un mismo cliente "eSE moderno".

### 7.4 Errata 4 — Ambas tesis: clarificación de subscriber pinnings

Cap 4 §4.2 monografía (M1 files) y Cap 5 §5.3.4 tesis principal (pinning channels) son **dos mecanismos distintos con patrón común**. Añadir nota cruzada explicando:

- Comparten patrón conceptual (descargador/suscriptor reanuncia).
- NO comparten código (payload distinto, validación distinta, periodicidad distinta).
- Comparten scheduler genérico en implementación (`CSubscriberPinScheduler`).

Esto previene confusión en futuras revisiones de cualquiera de las dos tesis.

---

## 8. Documento vivo

Este plan se actualiza al cierre de cada fase con:

- LOC real vs estimada
- Tiempo real vs estimado
- Decisiones tomadas durante implementación (link a issues/PRs)
- Cambios al alcance

Path: `docs/UNIFIED_IMPLEMENTATION_PLAN.md`. Convergerá a `main` cuando ambos worktrees (`hungry-dhawan-84bd82` y `quizzical-newton-9aa3db`) y este (`focused-bohr-b819cf`) se mergen.

---

## 9. Decisiones firmadas por el usuario 2026-05-18

1. ✅ **Tag namespace:** audit del rango 0x68-0xCF realizado. Tags Kad v2 fijados a `0x68-0x6B` (ver §1.2 de este plan).
2. ✅ **Errata M0:** se añade M0 (Namespace isolation por prefijo binario) a la monografía como §4.1.1, ver Apéndice A de este plan.
3. ✅ **Recursos:** 1 dev. Plan secuencial. **27 semanas + alpha/beta colchón = 30 semanas a V1 release**.
4. ✅ **Security review:** bounty público + comunidad cripto. Cero coste; 2-3 semanas calendario tras F5.

Una decisión que queda abierta porque NO bloquea F0:

- **Build cadence pública:** una alpha al final de F4 (sem 13) acelera feedback de tunnels antes de la UI. La decisión se toma al cerrar F4 (sem 13) con datos reales.

F0 desbloqueada. Próximo paso: arrancar.

---

## Apéndice A — Errata M0 para la monografía Kad Search v2

Texto listo para insertar como §4.1.1 inmediatamente tras §4.1 "Principios de diseño transversales" en `docs/thesis/kad-search-v2/04-diseno-kad-v2.md` del worktree `quizzical-newton-9aa3db`. Mantiene la estructura (a)-(e) del resto de mecanismos.

```markdown
## 4.1.1 Mecanismo M0 — Aislamiento de namespace por prefijo binario

> **Nota:** Este mecanismo no formaba parte del diseño original de los seis
> mecanismos M1-M6. Fue propuesto e implementado de forma independiente en
> el proyecto eMule eSE (plan H1-H8, mayo 2026) durante la transición a
> Kad v2. Por su ortogonalidad con M1-M6 y por estar ya en código de
> referencia, se documenta retroactivamente como M0.

### (a) Intuición

Los mecanismos M1-M6 mejoran la *eficiencia* del subsistema de búsqueda
Kad pero comparten el espacio de hashes de keyword con clientes legacy. Un
cliente eMule 0.70b clásico que busque la palabra "eselive" cae en el mismo
hash MD4 que un cliente eSE Live, y los nodos custodios mezclan ambos tipos
de entradas. Esta promiscuidad produce dos problemas:

1. **Contaminación social del directorio**: cualquier crawler legacy puede
   enumerar entradas eSE por simple búsqueda de keyword común.
2. **Saturación cruzada**: tráfico de búsqueda legacy puede expulsar
   entradas eSE de la caché LRU del custodio (CB-3 del Capítulo 3).

La intuición de M0 es trivial: **derivar un hash de destino distinto a
partir del mismo keyword usando un prefijo binario no escribible**. El
prefijo `"\x00eSE\x00"` (5 bytes) no es producible por ninguna interfaz
de usuario eMule legacy, por lo que el espacio resultante en el DHT es
inalcanzable para clientes no-eSE — pero perfectamente alcanzable de forma
determinista para clientes eSE que conozcan el prefijo.

### (b) Especificación formal

Sea `kw` un keyword normalizado UTF-8. Definimos:

```
ese_keyword_hash(kw) = MD4(ESE_LIVE_KEYWORD_PREFIX || utf8(kw))
ESE_LIVE_KEYWORD_PREFIX = 0x00 0x65 0x53 0x45 0x00   // "\x00eSE\x00", 5 bytes
```

El prefijo se elige con dos requisitos:

- **No tecleable**: contiene bytes NUL (0x00) que ningún campo de búsqueda
  produce.
- **Inyectivo**: `ese_keyword_hash(kw₁) = ese_keyword_hash(kw₂) ⟹ kw₁ = kw₂`
  con la misma probabilidad que MD4 ordinario (asumiendo MD4 resistente a
  colisiones para inputs benignos).

### (c) Wire format

Ningún opcode nuevo. La publicación y búsqueda usan los mismos opcodes
estándar `OP_KADEMLIA2_PUBLISH_KEY_REQ`, `KADEMLIA2_SEARCH_KEY_REQ`,
`KADEMLIA2_PUBLISH_NOTES_REQ`. El cambio es puramente en el cálculo del
target `CUInt128` que se pasa a `CSearchManager::PrepareLookup`. Por tanto
M0 es invisible al nivel de transporte.

### (d) Algoritmo

```
ON publishing eSE entry under keyword kw:
    target_clean = ese_keyword_hash(kw)
    publish(target_clean, entry)

    IF prefs.publishLegacy:   // transición dual obligatoria (cap 5 §5.7)
        target_legacy = MD4(utf8(kw))
        publish(target_legacy, entry)

ON searching eSE entries for keyword kw:
    target_clean = ese_keyword_hash(kw)
    target_legacy = MD4(utf8(kw))
    parallel_lookups([target_clean, target_legacy])
    // Resultados deduplicados naturalmente por streamKey en el directorio local
```

La preferencia `publishLegacy` (default `true` durante la transición) gobierna
si se mantiene la publicación dual o solo se emite en clean. Cuando una
versión futura del cliente decida que la adopción de M0 es suficiente, el
default se flippea a `false` y un release después se elimina la rama legacy
del cliente. Esta decisión se basa en métricas de adopción
(`knownStreamsClean` vs `knownStreamsLegacy` en /api/live/debug).

Además, en publishes clean se omiten los tags `TAG_FILENAME` ("eselive
<title>") y `TAG_FILETYPE` ("eSELive") para denegar a crawlers eSE-aware
un título legible del entry Kad. Los clientes eSE legítimos leen el título
de `TAG_ESE_LIVE_TITLE` (tag custom invisible para parsers legacy).

### (e) Análisis de coste

- **Bandwidth de publicación durante la transición**: 2× cada publish
  (clean + legacy). Para una cadencia de republish de 60 s con 4 keywords:
  8 STOREKEYWORD/min/broadcaster, despreciable.
- **Bandwidth de publicación tras transición** (legacy off): equivalente a
  Kad v1 (1× publish).
- **Bandwidth de búsqueda durante la transición**: 2× cada query (clean +
  legacy). Mitigado aplicando cooldown y token bucket a la pareja como
  unidad lógica (1 token consumido, no 2).
- **Adopción**: nodos nuevos se encuentran entre sí en clean; nodos
  nuevos siguen encontrando a viejos vía legacy; nodos viejos siguen
  encontrando a nuevos vía legacy (porque nuevos publican dual). Cero
  regresión durante la ventana de transición.

### Encaje con M1-M6

M0 es **ortogonal** a los seis mecanismos. M3 (sharding) opera sobre
`ese_keyword_hash(kw)` exactamente igual que sobre `MD4(utf8(kw))`. M2
(claves compuestas) podría componer prefijos binarios distintos para
2-tuples (e.g. `"\x00eSE\x02"`), pero la utilidad práctica es marginal y
queda fuera del alcance.

### Estado de implementación

Implementado en código bajo el plan H1-H8 (2026-05-18). Archivos:

- `srchybrid/kademlia/kademlia/Search.h` — declaración + constante
  `ESE_LIVE_KEYWORD_PREFIX`.
- `srchybrid/kademlia/kademlia/Kademlia.cpp` — `EseLiveGetKeywordHash`.
- `srchybrid/LiveKadBridge.cpp` — dual-publish en `RepublishIfNeeded`,
  `UnpublishStream`, `PublishTombstoneFor`, `PublishAsRelay`; dual-search en
  `SearchStreams`.
- `srchybrid/Preferences.h/.cpp` — pref `m_bEseLivePublishLegacy`.
- `srchybrid/LiveStreamManager.h` — `KadDebugSnapshot.knownStreamsClean/Legacy`.

```

**Acción para aplicar la errata:** el texto anterior se inserta en
`/c/Users/iunan/OneDrive/Desktop/eMule0.70b-Sources/.claude/worktrees/quizzical-newton-9aa3db/docs/thesis/kad-search-v2/04-diseno-kad-v2.md`
tras la línea que cierra §4.1 ("Antes de la especificación individual..."). El
índice del README de la monografía gana una línea para M0. La memoria
`project_ese_kad_search_v2_thesis.md` debe actualizar el conteo a "10 + M0".

