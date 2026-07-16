# Registro único de protocolo — eSE fork

> **Fuente única de verdad** de la superficie de protocolo **del fork** (no del eD2K/Kad
> clásico, que es de upstream y está **congelado**). Toda extensión de cable nueva se registra
> aquí *antes* de tocar `Opcodes.h`. Creado en P0 (Entregable 2), 2026-06-13.
>
> **CSV asociados:** [OPCODES.csv](OPCODES.csv) · [TAGS.csv](TAGS.csv) ·
> [CAPABILITIES.csv](CAPABILITIES.csv) · [TUNNEL_SERVICES.csv](TUNNEL_SERVICES.csv) ·
> [KRP_MESSAGES.csv](KRP_MESSAGES.csv)
> **Linter de CI:** [`tools/check_protocol_registry.py`](../../tools/check_protocol_registry.py)

---

## 0. Estado actual del gate

```
$ python tools/check_protocol_registry.py
protocol registry: 168 entries, 151 fork symbols in code
OK: registry is internally consistent and matches code.
exit=0
```

**El CI está en VERDE**: 0 colisiones, 0 sin registrar, 0 desajustes doc-vs-código — el registro
es un espejo fiel del código. La última colisión (`0xE0`, §2.1) quedó **resuelta**: el código movió
`OP_PUBLICIP_ANSWER_V6` de `0xE0` a `0xB3` (slot ratificado en §2.1) y el registro se sincronizó
con ese valor. El brinco de 96→99 entradas refleja además las reservas Kad3 IPv6 (`KADEMLIA3_*`)
añadidas en paralelo; ninguna colisiona.

---

## 1. Qué cubre y por qué los namespaces importan

El byte de opcode solo colisiona **dentro de su propio espacio de dispatch**. Por eso el registro
agrupa por `namespace`, y el linter solo marca duplicados dentro del mismo namespace:

| namespace | Espacio de dispatch | Header |
|---|---|---|
| `EMULEPROT-CC` | opcodes cliente↔cliente de protocolo extendido | `OP_EMULEPROT` (0xC5) |
| `KADEMLIA-UDP` | opcodes Kad por UDP | `OP_KADEMLIAHEADER` (0xE4) |
| `TUNNEL-CELL` | sub-comandos `TUN_OP_*` multiplexados dentro de `OP_LIVE_TUNNEL_CELL` (0xD5) | onion cell |
| `TAG-ED2K` | tags dentro de payloads (no el byte de opcode) | — |
| `SERVER-MET` | tags de `server.met` | — |
| `CAP-ESE` | bitmap `TAG_ESE_CAPS` (tag 0x6C) | — |
| `CAP-FORK` | bitmap `CT_FORK_CAPABILITIES` (tag 0xF0) | — |

**El clásico no se registra**: ~200 opcodes eD2K/Kad de upstream son de Merkur, están congelados
y el linter los ignora por diseño (solo gobierna prefijos del fork: `OP_LIVE_*`, `*_V6`,
`KADEMLIA3_*`, `TUN_OP_*`, `ESE_CAP_*`, `CAP_FORK_*`, `TAG_ESE_*`…). Los mensajes
`KRP_*` permanecen en `reserved-proposed`; desde P1 sus valores también se contrastan con el enum
de `librelaycore`. El gate local P2 transporta `KRP_PING/PONG` canónicos sobre WSS/TLS, pero el
runtime de producto no los emite todavía: la activación cliente↔edge empieza en P3 y no cambia el
estado del registro hasta superar su gate.

---

## 2. Informe de conflictos

### 2.1 ✅ RESUELTO (opcode) — `0xE0` doble en `EMULEPROT-CC`

| Símbolo | Valor | Estado | Definición |
|---|---|---|---|
| `OP_PUBLICIP_ANSWER_V6` | **0xB3** *(movido desde 0xE0)* | experimental, **ahora emitido** (detección v6 in-band, reemplaza api6.ipify.org; pendiente validación 2-PC) | `Opcodes.h:282` (IPv6 Sprint 3/6) |
| `OP_LIVE_CHUNK_FRAG` | **0xE0** | **stable, SHIPPED + validado 2-PC a 12000 kbps** | `Opcodes.h:331` (v8.1.x) |

**Causa (histórica):** el autor de `OP_LIVE_CHUNK_FRAG` comentó *"0xE0 is clear of the 0xC0-0xCF
Live block and the 0xD0-0xDF tunnel block"* sin ver que IPv6 Sprint 3 ya había **reservado** 0xE0
para `OP_PUBLICIP_ANSWER_V6`. Ambos eran opcodes cliente↔cliente del mismo dispatch → **bomba
latente**: si IPv6 Sprint 6 hubiera emitido 0xE0, un peer lo habría malinterpretado como un chunk
Live fragmentado → rotura silenciosa (viola la regla sagrada de compat).

**Resolución aplicada (compatible, riesgo cero):**
- `OP_LIVE_CHUNK_FRAG` **conserva 0xE0** (está shippeado y validado; mover lo que ya viaja en
  cable rompería compat con peers v8.1.x).
- `OP_PUBLICIP_ANSWER_V6` **se movió a `0xB3`** (banda `0xB3-0xBF` libre tras retirar el viejo
  bloque Live duplicado; `0xE3+` evitado por ser bytes de header de protocolo). Como **nunca se
  emitió en `0xE0`**, el movimiento fue invisible en el cable (ahora **sí se emite/maneja** en
  `0xB3`). Aplicado en código ([`Opcodes.h:282`](../../srchybrid/Opcodes.h)
  con bloque de comentario `MOVED 0xE0 -> 0xB3`) y sincronizado en [`OPCODES.csv`](OPCODES.csv);
  el linter pasa a **verde** (`exit=0`).
- **Limpieza completada (2026-06-14):** los docs narrativos de IPv6 (`IPV6_PLAN.md`,
  `IPV6_SPRINT_PLAN.md` S3.3) y el bloque de comentario de [`Opcodes.h`](../../srchybrid/Opcodes.h)
  ya citan `0xB3` (antes `0xE0`) y reflejan que el opcode **se emite/maneja** ahora; alineados con
  esta tabla §2.1 y `OPCODES.csv` (no es código ni registro, no afectaba al gate de CI).

### 2.2 🟠 CONFLICTO (capability, ya corregido en docs) — bits 13/14

El `LOWID_NAT_TRAVERSAL_PLAN.md` **reservaba** `ESE_CAP_HOLEPUNCH_RDV` = bit 13 (0x2000) y
`ESE_CAP_KAD_KEEPALIVE` = bit 14 (0x4000). Pero en **código** esos bits ya están ocupados:

| Bit | En código (shipped) | Reservaba el plan (mal) |
|---|---|---|
| 13 (0x2000) | `ESE_CAP_LIVE_CHUNK_FRAG` | ~~`ESE_CAP_HOLEPUNCH_RDV`~~ |
| 14 (0x4000) | `ESE_CAP_TUNNEL_BULK` | ~~`ESE_CAP_KAD_KEEPALIVE`~~ |

**Resuelto en este P0** (era colisión doc-vs-código, sin código que migrar): el registro reserva
los caps futuros en bits **libres** — `ESE_CAP_HOLEPUNCH_RDV` = bit 15 (0x8000),
`ESE_CAP_KAD_KEEPALIVE` = bit 16 (0x10000), `ESE_CAP_REACH_V2` = bit 17 (0x20000). Los docs
`LOWID_NAT_TRAVERSAL_PLAN.md` y `MODERNIZATION_ROADMAP.md` (Track R) se corrigieron a estos valores.

### 2.3 ✅ Falsas alarmas confirmadas (no son colisiones)

El registro también **descarta** sustos aparentes, demostrando consciencia de namespace:

- **`0xCA` aparece dos veces**: `OP_LIVE_PEER_LIST` (`EMULEPROT-CC`) y
  `KADEMLIA2_KEY_SHARD_ANNOUNCE` (`KADEMLIA-UDP`). **Namespaces distintos → sin colisión.**
- **`0x68`**: `KADEMLIA3_HOLEPUNCH_REQ` es un **opcode** (`KADEMLIA-UDP`); `TAG_ESE_REACH` (tesis)
  es un **tag** (`TAG-ED2K`). Espacios distintos → sin colisión. Además 0x68 está **libre** en
  `TAG-ED2K` (verificado: 0x66,0x67,0x69-0x6C usados, 0x68 hueco).
- **Kad3 ping/holepunch en 0x66-0x6A**: el equipo ya los movió desde 0x61-0x65 (que chocaban con
  `KADEMLIA2_PONG`/`FIREWALLUDP`/`ESE_HOLEPUNCH`). Correcto.

### 2.4 ℹ️ Semántica del bit 19 (`ESE_CAP_HOLEPUNCH_COOKIE`) — LOAD-BEARING en el gate de dos tiers

El cap bit 19 está `#define`-ado y la cookie cableada (`Process_ESE_HOLEPUNCH_REQ`/
`Process_ESE_HOLEPUNCH_CHALLENGE` + `EseHolePunchCookie`). **El bit es LOAD-BEARING** en el
gate de return-routability (`KademliaUDPListener.cpp:2272`):

- **TIER 1** — contacto conocido con IP verificada in-band (`IsIpVerified()`): reachability
  probada → ACK+seed legacy directo (sin RTT extra). Aquí el bit es informativo.
- **TIER 2** — zona gris (origen desconocido, **o** conocido pero NO verificado: entran por
  referidos `HELLO_RES` de terceros, y un origen spoofeado puede colisionar con la IP:port de
  un contacto conocido): sin prueba de IP → `0x65 CHALLENGE` stateless **SOLO si el emisor
  anuncia este bit** (`FindClientByIP_KadPort` + `SupportsEseHolePunchCookie`); si no (peer
  legacy/vanilla que no sabe responder un `0x65`), cae al ACK+seed legacy *floored* por el
  token-bucket per-IP + el tope de `g_expectedPeers`. Reconcilia anti-reflexión estricta con
  la retrocompat obligatoria.

El linter **no** detecta esta semántica (solo valida valor + presencia del símbolo), de ahí
esta nota. `Opcodes.h:557` y la columna `format` de `CAPABILITIES.csv` (status `experimental`)
están alineados a esta realidad de dos tiers.

### 2.5 🟢 RESERVA (opcode + cap) — chunk Live con digest BLAKE3 (V3)

Reserva de futuro para sustituir el digest SHA256 del chunk firmado por **BLAKE3-256** (motivación:
**CPU**, no seguridad — la integridad/autenticidad ya las da la firma Ed25519 de `OP_LIVE_CHUNK_V2`;
BLAKE3 solo abarata el hasheo por segmento a bitrate alto, con SIMD). `status = reserved-proposed`,
**aún sin símbolo en `Opcodes.h`** (registrado antes que el código, regla §5).

| Símbolo | Valor | Namespace | Notas |
|---|---|---|---|
| `OP_LIVE_CHUNK_V3` | `0xB4` | `EMULEPROT-CC` | Variante de `OP_LIVE_CHUNK_V2` (0xCC) con `blake3 32` en vez de `sha256 32`; firma sobre `StreamKey‖SeqNum‖blake3`. |
| `ESE_CAP_LIVE_BLAKE3` | bit 20 (`0x00100000`) | `CAP-ESE` | Anuncio por-pareja vía `TAG_ESE_CAPS` (0x6C). |

**Decisiones de diseño que fijan estos valores (no reabrir sin releer esto):**

- **⚠️ `0xC5` NO es usable como opcode** — es el byte de cabecera `OP_EMULEPROT` ([`Opcodes.h:140`](../../srchybrid/Opcodes.h)),
  el dispatch de TODO el protocolo cliente↔cliente. **El linter NO lo detectaría** (los bytes de
  header no son filas del registro, igual que el skip de `0xD4`/`OP_PACKEDPROT` en `Opcodes.h:340`).
  La banda Live `0xC0-0xCF` está agotada → V3 cae en la banda liberada `0xB4-0xBF` (el bloque Live
  duplicado `0xB3-0xB9` se eliminó; `0xB3` ya lo tomó `OP_PUBLICIP_ANSWER_V6`).
- **Sustitución, no adición.** Añadir un BLAKE3 *junto* al SHA256 sería redundancia pura (la firma ya
  cubre integridad). Por eso es un opcode nuevo con el digest sustituido, no un campo extra en 0xCC.
- **Opcode autodescriptivo + gate a nivel swarm.** Los chunks firmados se reenvían transitivamente por
  la malla, así que el algoritmo de digest no se puede negociar por-pareja sobre 0xCC (un viewer sin la
  cap calcularía SHA256 y lo tiraría). El opcode `0xB4` se autodescribe para cualquier relay; el bit 20
  es la *visibilidad* per-peer con la que el broadcaster decide si el swarm entero soporta V3. Por
  defecto el broadcaster sigue emitiendo V2 (compat máxima).

### 2.6 🟢 RESERVA (opcodes + cap + sub-ops túnel) — Swarm DVR (`SWARM_DVR_PLAN.md`)

Retención de segmentos históricos en disco (viewer + enjambre) para rebobinar 10-30 min de un directo.
Cuatro opcodes en la banda `EMULEPROT-CC` liberada (0xB5-0xB8, tras 0xB3/0xB4), un cap bit 22 y tres
sub-ops de túnel (0x60-0x62). `status = reserved-proposed`, **sin símbolo en código** (regla §5).

| Símbolo | Valor | Namespace | Notas |
|---|---|---|---|
| `OP_LIVE_DVR_OFFER` | `0xB5` | `EMULEPROT-CC` | Anuncio de rangos retenidos firmados (cadencia 10 s; nunca PEX/gossip) |
| `OP_LIVE_DVR_REQ` | `0xB6` | `EMULEPROT-CC` | Petición de chunk histórico |
| `OP_LIVE_DVR_DATA` | `0xB7` | `EMULEPROT-CC` | Cuerpo = record `OP_LIVE_CHUNK_V2/V3` LITERAL; >1,8 MB vía `OP_LIVE_CHUNK_FRAG` (`InnerOpcode=0xB7`) |
| `OP_LIVE_DVR_NACK` | `0xB8` | `EMULEPROT-CC` | 0=no-retenido 1=ocupado 2=throttled 3=terminado |
| `ESE_CAP_LIVE_DVR` | bit 22 (`0x00400000`) | `CAP-ESE` | Dormante; **implica bit 13** (`LIVE_CHUNK_FRAG`) en el emisor |
| `TUN_OP_DVR_FETCH` | `0x60` | `TUNNEL-CELL` | Viewer→exit (respuesta por plano bulk `0xD9` + `FLAG_DVR`) |
| `TUN_OP_DVR_NACK` | `0x61` | `TUNNEL-CELL` | Exit→viewer |
| `TUN_OP_DVR_OFFER` | `0x62` | `TUNNEL-CELL` | Exit→viewer: rangos alcanzables por el exit |

- **`FLAG_DVR` = bit 0 de `BulkDataHeader.flags`** (u8 sin uso, `LiveBulk.h`). **El linter NO lo gobierna**
  (no es una fila del registro, igual que `0xC5`/`0xD4`): esta prosa ES su registro. Enruta el plano bulk
  al sink DVR en vez de al pipeline vivo.
- **Autenticidad histórica reutiliza la firma existente:** `0xB7` transporta el record V2/V3 firmado tal
  cual (Ed25519 sobre `StreamKey‖SeqNum‖digest`), auto-autenticante contra la pubkey pineada. No se
  inventa cripto nueva. El agujero de replay entre sesiones (firma sin `epoch`) bloquea el default-on
  hasta que el `epoch` viaje con Live V3 (0xB4).

### 2.7 🟢 RESERVA (tags + cap + sub-ops túnel) — Manifiesto de canal (`CHANNEL_MANIFEST_PLAN.md`)

Canales estilo YouTube anclados a la pubkey Ed25519 ya existente (`streamKey = SHA1(pubkey)[:16]`):
manifiesto firmado + catálogo VOD como colecciones `.emulecollection` firmadas. Cuatro tags `TAG-ED2K`
(0x6F-0x72), un cap bit 23 y dos sub-ops de túnel de **celda-única** (0x24/0x25, banda 0x24-0x3F por
debajo del umbral multi-celda 0x40 — un fetch de manifiesto es diminuto). `status = reserved-proposed`.

| Símbolo | Valor | Namespace | Notas |
|---|---|---|---|
| `TAG_ESE_CHANNEL_PK` | `0x6F` | `TAG-ED2K` | Pubkey del canal (BSOB 32) en cabecera de colección |
| `TAG_ESE_COLL_SIG` | `0x70` | `TAG-ED2K` | Firma Ed25519 (BSOB 64) del transcript canónico de la colección |
| `TAG_ESE_COLL_REV` | `0x71` | `TAG-ED2K` | uint32 revisión del catálogo (anti-rollback) |
| `TAG_ESE_VOD_META` | `0x72` | `TAG-ED2K` | Blob por-fichero {ver,kind,date,duration,order,thumb} |
| `ESE_CAP_CHANNEL_MANIFEST` | bit 23 (`0x00800000`) | `CAP-ESE` | Gatea payload v2 de `0xD1/0xD2`. Dormante |
| `TUN_OP_CHANNEL_FETCH` | `0x24` | `TUNNEL-CELL` | Viewer→exit: fetch de manifiesto por pubkey (celda-única) |
| `TUN_OP_CHANNEL_DATA` | `0x25` | `TUNNEL-CELL` | Exit→viewer: bytes del manifiesto |

- **Por qué 0x24/0x25 y NO 0x63/0x64:** el dispatcher trata todo `sub_cmd >= 0x40` como **multi-celda**
  (exige cabecera de fragmento de 8 B + reensamblado). Un `CHANNEL_FETCH` es diminuto → pertenece a la
  banda de celda-única 0x24-0x3F. (Los DVR 0x60-0x62 sí van multi-celda: sus payloads son grandes.)
- **Tres secretos, no uno** (fallo fatal corregido en el plan): `sk_channel` (firma, solo emisor) ≠
  `read_secret` simétrico (sella/localiza, emisor+suscriptores privados) ≠ nada (público = claro firmado).
  El código actual confunde clave de firma y de lectura — ver `CHANNEL_MANIFEST_PLAN.md` §2.

### 2.8 Desconflicto DVR ↔ Canales (reservados el mismo día, 2026-07-03)

Ambos planes verificaron el cap bit 22 libre de forma independiente y ambos lo iban a reservar. Resuelto:
**DVR = bit 22**, **Canales = bit 23**. Siguiente cap-ESE libre: **bit 24**. Banda `EMULEPROT-CC` restante:
**0xB9-0xBF**. Túnel: DVR 0x60-0x62 + Canales 0x24/0x25 (no solapan). Verificado a mano contra `Opcodes.h`
y `LiveTunnel.h` (el linter ignora ~200 símbolos upstream y los bytes-cabecera: registro-libre ≠ wire-libre).

---

## 3. Esquema de los CSV

`name, value, namespace, intro_version, status, capability_gate, format, compat, file, line`

- **status**: `stable` · `experimental` · `reserved` · `reserved-proposed` · `deprecated` ·
  `DESIGN`. Las filas `reserved-proposed`/`DESIGN` pueden existir sin símbolo en código (reservas
  de futuro: p.ej. `TAG_ESE_REACH`, los tres caps de §2.2).
- **compat**: `additive` / `additive-ignorable` / `internal-tunnel`. Todo el fork es **aditivo**:
  un peer que no entiende el opcode/tag cae al comportamiento 0.70b.

---

## 4. Qué verifica el linter (gate de CI)

1. **Duplicados `(namespace, value)`** → colisión de cable.
2. **Símbolo del fork en código pero no en el registro** → `UNREGISTERED`.
3. **Valor del registro ≠ valor en código** → `DRIFT` (doc-vs-código).
4. **Fila `stable`/`experimental` sin `#define`** → `NOT-IN-CODE` (warning).

Falla (exit 1) ante 1-3. Wire en CI: `python tools/check_protocol_registry.py` como step
obligatorio (lo detallará el Entregable 1, `tools/doctor.ps1` / config CI).

## 5. Regla de mantenimiento

> **Ningún número de cable nuevo sin fila en el CSV correspondiente, y ninguna fila sin pasar el
> linter.** Antes de añadir un opcode/tag/cap: añade la fila, corre el linter, y solo entonces el
> `#define`. Nunca reutilices un número retirado (append-only). El código no gana automáticamente
> sobre el registro: si discrepan, es un `DRIFT` a resolver, no un hecho consumado.
