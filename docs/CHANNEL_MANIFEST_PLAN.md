# Plan técnico: Manifiesto de Canal firmado (canales estilo YouTube para eSE Live)

**Documento:** `docs/CHANNEL_MANIFEST_PLAN.md`
**Estado:** DISEÑO (plan fusionado tras 3 diseños independientes + crítica adversarial; 2 fallos fatales corregidos, 1 descopado)
**Calibre:** post-estabilización v9. Cada fase dormante/gateada por defecto.
**Regla madre:** un canal ES una pubkey Ed25519 (`streamKey = SHA1(pubkey)[:16]`, `srchybrid/LiveProtocol.h:262-276`). Este plan NO inventa una segunda identidad: añade UN documento (el manifiesto) y pegamento entre piezas que ya existen.

---

## 1. Objetivo y no-objetivos

### 1.1 Mapa honesto YouTube → eSE

| YouTube | eSE | Mecanismo |
|---|---|---|
| Canal | Pubkey Ed25519 persistida | `mychannels.dat` (DPAPI), plan invisibilidad §7-8 R1/R2 |
| Nombre + avatar + banner + descripción | `ChannelRecord` v2 + bloque TLV de manifiesto | `srchybrid/LiveChannel.h:48-66` extendido |
| Suscribirse | `CLiveSubscriptionStore` (ya existe) + sidecar v2 | `srchybrid/LiveSubscriptionStore.h:15-20` |
| Notificación "en directo" | Liveness DENTRO del payload firmado/sellado + poller con tráfico de cobertura | `PickCoverTrafficSet`, `LiveSubscriptionStore.cpp:236-259` |
| Catálogo de vídeos / playlists | `.emulecollection` binaria vanilla con tags Ed25519 | `srchybrid/Collection.cpp:131-146` (tags desconocidos ignorados) |
| Ver un VOD | Descarga eD2K normal + verificación de cadena | MD4/AICH existentes |
| Página de canal | Webserver embebido `/live/channel?pk=` + skin Node | `CWebServer::_ProcessLiveAPI`, `WebServer.cpp:4518` |
| **@handle único global** | **NO.** Sustituto honesto: nombre-etiqueta (no identificador) + huella corta de pubkey (8 hex) + identicon determinista cliente-side. Sin registro global no hay unicidad; no la fingimos. | — |
| **Comentarios persistentes** | **NO.** Sustituto honesto: los comentarios/valoraciones por-fichero de eMule vanilla (`FT_FILECOMMENT`/`FT_FILERATING`) siguen funcionando en cada VOD, tal cual son: efímeros y por-peer. | `CollectionFile.cpp:85-96` |
| **Contadores de vistas/likes** | **NO.** Sustituto honesto: `viewers` instantáneo del announce en directo (ya existe, ya es best-effort). Ningún contador acumulado: sería falsificable y un vector de correlación. | tag `ese.live.viewers` |
| Algoritmo de recomendación | **NO.** Grid de directorio Kad + suscripciones. Punto. | — |

### 1.2 Alcance
- Manifiesto de canal firmado, versionado (seq), con nombre/avatar/banner/descripción/catálogo VOD/playlists.
- Re-encuentro por pubkey entre sesiones (semántica del plan de invisibilidad offline), notificación al ponerse en directo, página de canal, VODs de emisiones pasadas.
- Modo público (enumerable por elección) y modo privado (sellado, solo suscriptores con secreto compartido) diseñados desde el principio, no atornillados después.

### 1.3 Fuera de alcance
Handles, comentarios, contadores, recomendador (arriba); rotación/revocación de clave de canal (el campo `successor[32]` queda como vía de escape sin protocolo); re-keying automático al expulsar un suscriptor privado (documentado como limitación honesta, ver §9); VOD anónimo garantizado en modo privado antes de C6.

---

## 2. Decisión criptográfica central: TRES secretos, no uno

**Fallo fatal detectado en 2 de los 3 diseños y corregido aquí.** El código actual (`srchybrid/LiveChannel.h:16-19`) tiene un solo `ChannelKey.secret[32]` que es la clave PRIVADA Ed25519, y `ChannelRecordSeal/Open` (`LiveChannel.h:101-110`, `LiveChannel.cpp:224-231`) derivan la clave AEAD por HKDF de ese mismo secreto (`info = "ese-kad-record-key-v1"`, string exacto en `LiveChannel.cpp:227` — OJO: los docs dicen `"kad-record-key-v1"`, el código manda). Distribuir "el secreto del canal" a los suscriptores entregaría la CLAVE DE FIRMA: cualquier suscriptor podría falsificar records, redirigir el rendezvous de los demás y suplantar el canal.

**Corrección (C0/C1):**

| Secreto | Quién lo tiene | Para qué | Dónde vive |
|---|---|---|---|
| `sk_channel` (Ed25519 privada) | SOLO el emisor | Firmar ChannelRecord, manifiesto TLV y catálogos | `ese\mychannels.dat` (DPAPI) — joya de la corona |
| `read_secret[32]` (simétrico aleatorio, NUEVO) | Emisor + suscriptores de canal PRIVADO | Sellar/abrir el record: `K_kad = HKDF(read_secret, "ese-kad-record-key-v1")`; localización: `K_lookup = SHA1("ese.live.priv." || HMAC-SHA256(key=read_secret, msg=hora))` | Emisor: `mychannels.dat`; suscriptor: sidecar `subscriptions2.dat` |
| (ninguno) canal público | — | Record público = texto plano firmado. Sin pseudo-sellado (rechazado: sería privacidad de cartón) | — |

Cambios de contrato: `ChannelRecordSeal/Open` ganan parámetro `ikm` explícito (el `secret[32]` deja de significar "clave Ed25519"); el comentario de `LiveChannel.h:86-96` y la especificación de la tesis §5.2.2 se actualizan. **Nota:** derivar `K_lookup` de `read_secret` (no de la pubkey como dice hoy `LiveChannel.h:88`) hace que ni siquiera quien conozca la pubkey pueda LOCALIZAR el record privado — mejora sobre el plan original, se retroalimenta a `docs/OFFLINE_INVISIBILITY_PLAN.md`.

Expulsar a un suscriptor privado = rotar `read_secret` y reinvitar (manual en v1, honesto en la UI).

---

## 3. Formato del manifiesto

### 3.1 Contenedor: ChannelRecord v2 con TLV inline (el record ES el manifiesto)

Se extiende el struct existente, NO se inventa documento paralelo. El bump v1→v2 es seguro porque 0xD0-0xD3 son stubs (`LiveGossip.cpp:111,118`) y ningún build publicado parsea records por el wire — **re-verificar contra release tags en el merge de C1** (`ESE_CAP_SEALED_RECORDS` figura "experimental" en `CAPABILITIES.csv:9`; `ChannelRecordParse` hoy rechaza version≠1, `LiveChannel.cpp:147`). Layout (LE, orden fijo):

```
version u8 = 2
channel_pubkey[32]
seq u32                  # contador de beacon: ++ en CADA publicación, on y off-air (R3/R4: bump-before-publish, persist max(disco+1, reloj))
timestamp_unix u64       # ±2h slack
name  u8len + ≤64B UTF-8         # etiqueta, NUNCA identificador
description u16len + ≤256B
category u8 / language[2]
icon_md4[16]             # compat v1; espejo del TLV 0x01
access_mode u8 (0=público 1=privado) / flags u8 (bit0 riesgo, bit1 nsfw, bit2 unlisted, NUEVO bit4 live)
rendezvous  u8 count + entradas   # como v1; VACÍO off-air = cero IP incluso para quien descifra
successor   u8 has + [32] opcional
--- añadidos v2 (antes de la firma) ---
live_epoch u32           # época de sesión (0 off-air); alimenta R5 (limpiar tombstone) y R6 (dedup de chunks)
live_streamkey[16]       # privado: streamKey EFÍMERA por sesión (resuelve R2: pubkey→sesión); público: == SHA1(pk)[:16]; ceros off-air
manifest_seq u32         # ++ SOLO en ediciones reales (nombre/avatar/catálogo); independiente de seq
manifest_len u16 + bloque TLV
signature[64]            # Ed25519 sobre TODO lo anterior; el byte version=2 dentro del transcript separa dominios v1/v2
```

**TLV** (`{type u8, len u16, value}`; tipo desconocido → skip obligatorio; duplicados rechazados salvo 0x04):
- `0x01 avatar_ref`  = md4[16] + sha256[32] + size u32 + mime u8 — fichero eD2K, cap 256 KB. **Solo modo público** (§5).
- `0x02 banner_ref`  = ídem, cap 1 MB. Solo público.
- `0x03 desc_long`   ≤1024 B UTF-8.
- `0x04 vod_collection` (repetible) = md4[16] + sha256[32] + size u32 + kind u8 (0=archivo-emisiones, 1=playlist) + rev u32 + title u8len ≤80B + item_count u32 + updated u64.
- `0x05 avatar_inline` ≤12 KB — **modo privado** (evita fetch eD2K, ver fallo fatal §5.2).
- `0x06 spill_ref`   = puntero a manifiesto extendido standalone (magic `eSEM`, mismo esquema de firma) si el catálogo desborda el presupuesto inline. Cap parse 16 KB.

**Presupuestos:** record base peor caso ≈ 700 B; TLV inline ≤ 1200 B (avatar+banner+desc+~10 colecciones). **Forma sellada: pad con ceros a EXACTAMENTE 2048 B antes del AEAD** → valor Kad constante 12 (nonce) + 2048 + 16 (tag) = 2076 B, indistinguible on/off-air y ante ediciones (Gate 2 del plan de invisibilidad). La constante 2048 se registra en `PROTOCOL_REGISTRY.md`. En claro (público) cabe holgado en el buffer de publish de 4 KB (`Search.cpp:770`).

### 3.2 Anti-rollback (endurecido tras la crítica)
- Record: aceptar sii firma OK ∧ `seq > seq_cacheado` (**estricto**, no ≥).
- Manifiesto: aplicar contenido sii `manifest_seq > cacheado`.
- Catálogo: reemplazar sii `rev > rev_cacheado`; `rev` viaja firmado en el TLV 0x04 Y dentro de la colección (tag 0x71) — deben coincidir.
- Los tres contadores viven dentro de la firma → terceros no pueden retroceder nada; el emisor no puede degradar selectivamente.
- **Residual documentado:** un suscriptor FRÍO (sin caché) puede ser eclipsado con un record antiguo válido. Mitigación barata: resolver hora actual Y anterior, quedarse con el `seq` máximo entre todos los holders respondientes. Cierre total = fuera de alcance (problema genérico de eclipse Kad).

---

## 4. Reservas de protocolo (verificadas libres a mano contra Opcodes.h, no solo contra CSV)

Regla de gobernanza: fila CSV PRIMERO (`reserved-proposed`), linter `tools/check_protocol_registry.py` en verde, y solo después el `#define` en `srchybrid/Opcodes.h` (único header de opcodes que el linter parsea). Todos los nombres con prefijo gobernado `TAG_ESE_`/`ESE_CAP_`/`TUN_OP_` (corrige el hueco `FT_ESE_*` de un diseño: sería invisible al linter). Minas evitadas: 0xE0 (OP_LIVE_CHUNK_FRAG), 0xB3/0xB4 reservados, 0xB5-0xB8 (SWARM_DVR_PLAN), bytes-cabecera 0xC5/0xD4/0xE3-0xE5/0xA3/0xB2, cap bits 15-21 ocupados/reservados y 22 = ESE_CAP_LIVE_DVR (SWARM_DVR_PLAN).

| Elemento | Valor | Namespace | Uso | Verificación |
|---|---|---|---|---|
| `TAG_ESE_CHANNEL_PK` | 0x6F | TAG-ED2K | Header de colección: pubkey del canal (BSOB 32) | grep 0x6F Opcodes.h = 0 hits; TAGS.csv acaba en 0x6E |
| `TAG_ESE_COLL_SIG` | 0x70 | TAG-ED2K | Header de colección: firma Ed25519 (BSOB 64). **Corrige la colisión 0x70 doble-reservado del diseño A** | ídem |
| `TAG_ESE_COLL_REV` | 0x71 | TAG-ED2K | Header: rev u32 del catálogo (anti-rollback espejo) | ídem |
| `TAG_ESE_VOD_META` | 0x72 | TAG-ED2K | Por-fichero: {ver u8, kind u8, date u32, duration u32, order u16, thumb_md4[16]+size u32} | ídem |
| `ESE_CAP_CHANNEL_MANIFEST` | 0x00800000 (bit 23) | CAP-ESE | Gatea 0xD1/0xD2 con payload v2; dormante (precedente `ESE_CAP_LIVE_RELAY`, Opcodes.h:558) | bit 21 es el más alto en código; bits 16/17/20 reservados en CSV; **bit 22 = `ESE_CAP_LIVE_DVR` (SWARM_DVR_PLAN.md, reservado el mismo día — colisión entre planes detectada y resuelta aquí)** |
| `TUN_OP_CHANNEL_FETCH` / `TUN_OP_CHANNEL_DATA` | 0x24 / 0x25 | TUNNEL-CELL | C6: fetch de manifiesto vía exit del túnel | banda 0x24-0x3F libre en `LiveTunnel.h:159-185`; 0x51/0x53 NO reutilizados |
| Prefijo keyword `esechan:` | — | prosa PROTOCOL_REGISTRY.md | Localización del record público: keyword `esechan:<64hex-pubkey>` SOLO en namespace limpio `EseLiveGetKeywordHash` (`Search.h:199-203`); sin publicación legacy | junto a familia `ese.live.*` |
| Tags string Kad `ese.live.chanpk` / `ese.live.chanseq` / `ese.live.chanrec` | — | prosa | Piggyback en announce (pk 32B + hint seq/manifest_seq 8B) y valor del record; coherente con la familia `ese.live.*` de `LiveProtocol.h:25-38` | — |
| Constante pad sellado 2048 B + HKDF info `"ese-kad-record-key-v1"` (existente en código) | — | prosa | fijar distribución de tamaños | `LiveChannel.cpp:227` |
| Nota de formato 0xD1/0xD2 (payload v2) y extensión 0xDE PeerInvite (pubkey+read_secret+nombre) | valores ya reservados | OPCODES.csv | sin números nuevos | `OPCODES.csv:17-20,30` |

**Sin opcodes EMULEPROT-CC nuevos:** 0xD0-0xD3 (gossip/request/answer/revoke) y 0xDE (PeerInvite) ya están reservados; este plan no toca la banda 0xB5-0xBF (0xB5-0xB8 quedan reservados por SWARM_DVR_PLAN.md; 0xB9-0xBF libres para el futuro).

---

## 5. Distribución y descubrimiento por modo de canal

### 5.1 Canal PÚBLICO (access_mode=0)
1. **Piggyback en el announce en vivo** (coste ~48 B, no ~700 B — corrige el riesgo de desborde del buffer de 4 KB señalado en crítica): `PrepareLivePacketForTags` (`Search.cpp:1634-1751`) añade `ese.live.chanpk` (64 hex) + `ese.live.chanseq` (seq+manifest_seq). El grid aprende pubkey y frescura con CERO rondas extra y CERO presión nueva sobre el flood-bucket del holder (4 req/min/IP, `PacketTracking.cpp:129-131`).
2. **Record de identidad** cada 30 min ± jitter, ON y OFF-air: ChannelRecord v2 EN CLARO firmado, como tag opaco `ese.live.chanrec` en una entrada STOREKEYWORD estándar bajo `esechan:<64hex>` (namespace limpio), con los hacks de aceptación de holder vanilla: `TAG_FILENAME` constante + `TAG_FILESIZE=1` (`Indexed.cpp:406`, precedente H8). **SIN tags de IP** (`TAG_SOURCEIP/ALTIP` no se adjuntan): el único endpoint viaja dentro del rendezvous firmado, y off-air va vacío. Los holders vanilla almacenan y devuelven tags desconocidos tal cual (`KademliaUDPListener.cpp:1573-1576`) — cero cambios en su lado. La ronda comparte el scheduler de `RepublishIfNeeded` (`LiveKadBridge.cpp:342-474`); es UNA entrada nueva (dilución de trust /24, `Entry.cpp:471-506`, presupuestada: +1 entrada por canal).
3. **División de responsabilidades** (resuelve la open question): el record = identidad+manifiesto (frescura 30 min); la liveness pública sigue montada en el announce de 60 s + poll `livehash:` limitado por el token-bucket existente (10/min, `LiveKadBridge.cpp:609-657`). Latencia de notificación pública honesta: 2-5 min.
4. **Assets** (avatar/banner/manifiesto-spill/colecciones/VODs): ficheros compartidos normales en Incoming, fetch eD2K por hash, verificación `sha256` del TLV OBLIGATORIA tras la descarga (el MD4 es solo clave de fetch). Colecciones < 50 KB saltan la cola de subida (`MAXPRIORITYCOLL_SIZE`, `Opcodes.h:128`). **Etiqueta honesta en la UI:** descargar assets de un canal público expone tu IP como cualquier descarga eD2K; re-compartir el manifiesto tras el fetch es **opt-in** (no default-ON: publica tu IP como fuente de un hash vinculable al canal).

### 5.2 Canal PRIVADO (access_mode=1)
- **Nunca texto plano:** ni keyword, ni PEX, ni mDNS, ni piggyback (`access_mode=1` no puede alcanzar `PrepareLivePacketForTags`: guard + assert = P0 de privacidad). Solo el record sellado bajo `K_lookup = SHA1("ese.live.priv." || HMAC-SHA256(read_secret, hora))`, AEAD con `HKDF(read_secret, "ese-kad-record-key-v1")`, bucket 2048 B, cadencia constante 30 min ± jitter idéntica on/off-air. La liveness vive SOLO dentro del ciphertext; desaparecer nunca es la señal.
- **CORRECCIÓN DEL FALLO FATAL de de-anonimización de suscriptores** (diseño C): en privado NINGÚN asset viaja por eD2K — una descarga eD2K publica la IP del descargante como fuente Kad bajo un hash que todos los co-suscriptores comparten, permitiendo a cualquier poseedor del manifiesto (incluso un ex-suscriptor) enumerar las IPs de los demás. Por tanto: avatar **inline** (TLV 0x05, ≤12 KB); manifiesto-spill y colecciones vía **0xD1/0xD2** (pull de peers del mesh/rendezvous, gateado cap bit 23 + bit 10, respuesta solo a quien demuestra posesión del secreto) o vía túnel (`TUN_OP_CHANNEL_FETCH`, C6); VOD privado SOLO por el data plane bulk de túnel v8.1.2 (C6), o descopado con aviso explícito "secreto ≠ anonimato" si el emisor lo activa por eD2K (hashes = capacidades al portador; nunca keyword-publicados — se salta la inyección de wordlist de `KnownFile.cpp:342-348`).
- **Distribución del secreto:** token PeerInvite 0xDE (pubkey + read_secret + nombre; QR/pegar), importación admin-only.
- streamKey efímera por sesión con identidad anclada en la pubkey (plan R2); el suscriptor la mapea desde `live_streamkey` dentro del record sellado.

### 5.3 Re-encuentro del suscriptor (ambos modos)
Al arrancar / cada N min / al abrir la página: `ResolveChannel(pubkey)` en `CLiveKadBridge` (la API que el plan de invisibilidad ya nombra, junto a `PublishSealedChannel`; hooks hoy inexistentes — grep vacío): derivar clave (privado: hora actual Y anterior), búsqueda Kad dual, `ChannelRecordOpen` si sellado, `ChannelRecordVerify` contra la pubkey suscrita, seq estricto, actualizar caché DPAPI. **Main-thread only** (aserciones `LiveKadBridge.cpp:666-674`); disparo desde workers vía `PostMessage(UM_LIVE_CHANNEL_RESOLVE)` (patrón `UM_LIVE_KAD_REFRESH`, `EmuleDlg.cpp:1744`). Cada ronda mezcla decoys de `PickCoverTrafficSet` (`LiveSubscriptionStore.cpp:236-259`) alimentados por el `m_channelDirectory` (el TODO de `LiveGossip.cpp:118-125`, sembrado desde tags `chanpk` observados) — **el llamante filtra a solo-no-suscritos** (contrato documentado en `.h:42-43`). **Honestidad:** hasta que C3 cablee de verdad `CLiveSubscriberPinning` (hoy `DoRepublish` es stub con cero call sites, `LiveSubscriberPinning.cpp:55-66`), NINGUNA afirmación de indistinguibilidad en UI ni docs.

### 5.4 Qué pasa al terminar una emisión (por modo)

| Evento | Público | Privado |
|---|---|---|
| Record siguiente | seq+1, `flags.live=0`, rendezvous vacío, al TICK regular (no inmediato) | ídem, misma cadencia sellada — indistinguible |
| Tombstone Kad | El bitrate=0 sin firmar existente, sin cambios (endurecimiento T2 + beacon R5 firmado = C6) | N/A: nunca hubo publicación en claro |
| Residuo | Entradas keyword ~24h con IP (`KademliaUDPListener.cpp:1536`) — igual que hoy, documentado, no vendible como privacidad | Cero artefactos nuevos; segmentos HLS de `%TEMP%\eMule_RTMP\` borrados al parar |
| Archivo VOD | Prompt "¿Publicar como VOD?" (opt-in) | Default OFF; si se activa, aviso explícito; bump de `manifest_seq` DIFERIDO al siguiente tick (anti-correlación fin-de-stream↔edición) |

---

## 6. Catálogo VOD: colecciones eMule firmadas

- **Contenedor:** `.emulecollection` binaria, byte de versión 0x01/0x02 INTOCADO (vanilla rechaza versiones desconocidas, `Collection.cpp:130`). Extensiones SOLO en tags que vanilla consume y descarta (`Collection.cpp:131-146`): header `TAG_ESE_CHANNEL_PK` 0x6F + `TAG_ESE_COLL_SIG` 0x70 + `TAG_ESE_COLL_REV` 0x71; por-fichero `TAG_ESE_VOD_META` 0x72 (incluye `order u16` para playlists). **La colección de canal NUNCA se firma con RSA** — esquiva por completo el peligro de los bytes finales (vanilla solo inspecciona EOF si hay `FT_COLLECTIONAUTHORKEY`, `Collection.cpp:157-174`); vanilla la abre como colección normal sin firmar: ficheros visibles y descargables, degradación cero.
- **Transcript canónico** (inmune al orden no-determinista del hash-map de entradas, y — corrección de la crítica — CON el orden de playlist dentro de la firma): `sig = Ed25519(sk_channel, SHA256("eSE.channel.collection.v1" || pubkey[32] || rev u32 || kind u8 || u8 nameLen||nombre || count u32 || entradas ORDENADAS ASC por MD4, cada una: md4[16] || size u64 || u16 nameLen||nombre || u16 order || u8 hasAich||aich || u8 hasMeta||meta))`. Prefijos ASCII de dominio (`eSE.channel.collection.v1` vs `eSE.channel.manifest.v1` vs el byte-version del record) impiden replay entre contextos con la misma clave.
- **Cadena de confianza:** pubkey suscrita → firma del record → TLV 0x04 fija (md4, sha256, size, rev) exactos de la colección → firma de la colección (cinturón y tirantes; permite compartirla fuera de banda) → MD4/AICH por fichero → bytes.
- **Política de verificación:** contexto-canal (llegó vía manifiesto) = **hard-fail** en firma mala, pubkey≠manifiesto o rev retrocedida; apertura casual por doble-click = soft-fail vanilla + badge "canal verificado: <nombre> (<8hex>)" en `CollectionViewDialog`. Nunca heredar el strip-and-continue silencioso para contenido reclamado por un canal.
- **Flujo de archivado:** fin de stream → prompt → worker en background: `ffmpeg -f concat -c copy` sobre los segmentos de `%TEMP%\eMule_RTMP\{hash}\` → un `.mp4` en Incoming → hash en el hilo de hashing existente → append al catálogo con meta (fecha, duración), rev++, re-firma, `WriteToFileAddShared` → nuevo md4 → TLV 0x04 actualizado, manifest_seq++, republish al siguiente tick. Revisión anterior des-compartida (mantener 1). Playlists = colecciones anidadas kind=1, profundidad máx 1. Catálogos < 50 KB (~350 entradas); desborde → colección "Archivo 2026" referenciada aparte.
- **Trampas conocidas cerradas:** `PartFile.utf8.cpp` espeja `PartFile.cpp` en los hooks de colección — parchear ambos o divergen (C4 checklist); firma de canal solo en formato binario (el formato texto queda sin firmar — decisión: no soportarlo para canales).

---

## 7. UI: página de canal, suscripción, VOD

### 7.1 Endpoints (embebido C++ PRIMERO — emule.exe debe funcionar sin ese-server.exe; el skin Node llega después proxyeando 127.0.0.1:4711)
Todos dentro de `CWebServer::_ProcessLiveAPI` (`WebServer.cpp:4518`), insertados ANTES del catch-all HLS `/api/live/{32hex}` (`WebServer.cpp:6713`); **pubkeys SIEMPRE como query param `?pk=<64hex>`, nunca segmento de ruta** (el router rebana `Mid(10,32)` y malparsearía 64 hex). Toda ruta nueva se registra en LAS DOS listas: dispatch de `WebSocket.cpp:101-110` Y gate loopback-o-token `bIsLiveOrHolepunch` (`WebServer.cpp:4577-4586`) — olvidar una es la clase de vuln del desktop-capture; test negativo obligatorio (fetch remoto sin token → 403).

| Endpoint | Tipo | Contrato de hilos |
|---|---|---|
| `GET /api/live/channel?pk=` | snapshot JSON del canal (nombre, desc, live, streamKey, seq, vods[], subscribed, verified) | copy-under-lock desde `ChannelDirectory` (disciplina `BuildDebugSnapshot`); si caduco → `PostMessage(UM_LIVE_CHANNEL_RESOLVE)` fire-and-forget |
| `GET /api/live/channel/avatar?pk=` `/thumb?md4=` | bytes desde caché disco `%APPDATA%\eMule\ese\chanmedia\` | solo disco, sin marshal; sniffing de content-type por magic bytes; C++ nunca decodifica imágenes (higiene anti-bomba); 404 → identicon cliente-side |
| `GET /api/live/channel/subscribe?pk=&name=` `/unsubscribe` | mutación | `CLiveSubscriptionStore` es worker-safe (CCriticalSection); después `PostMessage` para sincronizar el pin-scheduler (cierra el hueco de `WebServer.cpp:5441-5459` que hoy no notifica al pinning) |
| `GET /api/live/vod/fetch?pk=&md4=` | mutación (cola de descargas) | struct `LiveWebChannelReq` (junto a `LiveWebJoinReq`, `LiveStreamManager.h:233-262`) + `SendMessage(UM_LIVE_WEB_CHANNEL)`; el worker no sostiene ningún lock Live antes del SendMessage (contrato auditado `WebServer.cpp:4710-4712`) |
| `GET /api/live/vod/file?md4=` | HTTP Range/206 de ficheros COMPLETADOS | solo disco; es la rebanada mínima del `/api/files` diferido del plan móvil |
| `GET /api/live/subscriptions/status`, `/api/live/notifications` | lectura | snapshot; polling 30 s (auto-renueva la sesión de 300 s como el HLS) |
| `POST/GET /api/live/channel/my` (autoría), import de PeerInvite | mutación | **admin-only** bajo `/api/live/privacy/` |

**Matriz guest/admin:** navegar canal, avatar, ver, suscribirse y notificaciones = permitidos con token guest `/s/{tok}` (el token guest ES el móvil del dueño per MOBILE_VIEWER_PLAN — suscribirse desde el sofá es el objetivo); broadcast, autoría de manifiesto, import de secretos, privacy = admin-only 403. Toda URL de página construida desde la variable de prefijo `B` (`WebServer.cpp:6810-6813`) para no salir nunca del namespace del token.

**Blockers de saneamiento (propios de C0, no "de pasada"):** inyección JSON de nombres crudos (`WebServer.cpp:5474-5476` → `EseJsonEscapeA`) y clobber de `Save()` con `!m_loaded` (`LiveSubscriptionStore.cpp:171-191`) — pasan a ser explotables/remotamente influidos cuando nombres remotos de canales fluyan; se arreglan ANTES. Nombre/descripción por `esc()` en HTML (patrón y comentario de ataque `WebServer.cpp:6805-6809`).

### 7.2 Página `/live/channel?pk=`
Banner (o gradiente desde pubkey), avatar (o identicon determinista JS desde SHA-256(pubkey) — algoritmo único congelado para C++/Node/móvil), nombre + huella 8-hex, badge EN DIRECTO + "Ver ahora" → player `/live/{streamKey}` existente, botón Suscribirse (2 clicks desde el player: strip de canal en la tarjeta → página → botón), descripción, grid VOD (miniatura/placeholder, título, duración, fecha; playlists como carpetas). **Estado offline:** página idéntica sin badge + "Última emisión: <ts>", renderizada 100% desde cachés locales — nunca necesita al emisor online. Grid `/live`: las tarjetas ganan link de canal cuando el resultado Kad trajo `chanpk` (campo `channelPk` en `/api/live/kad/streams`).

### 7.3 Notificación "en directo"
Sin infra push (no existe gratis): (a) web/PWA: poll de `/api/live/notifications` cada 30 s → toast; (b) escritorio: el resolve en main thread que cambia live 0→1 dispara el `TaskbarNotifier` existente; (c) strip "Mis canales" con puntos rojos arriba de `/live`. Latencias honestas: pública 2-5 min, privada 15-30 min (ajustable contra presupuesto de tráfico).

### 7.4 Móvil (track M futuro)
Hereda todo por construcción: JSON gateado bajo `/s/{tok}/`, matriz guest, HLS nativo en vivo, mp4 por Range/206 para VOD, PWA sin nada nuevo (`docs/MOBILE_VIEWER_PLAN.md:43-45,147-149,195-209`).

---

## 8. Fases C0..C6 (independientes, dormantes, con receta de validación)

### C0 — Registro + identidad persistente + saneamiento (~4 días; 1-PC)
Filas CSV de §4 primero + sección en `PROTOCOL_REGISTRY.md` (plantilla BLAKE3 §2.5) → linter exit 0 → `#define`s. `CLiveChannelKeyStore` → `ese\mychannels.dat` (patrón DPAPI + rename atómico de `LiveSubscriptionStore.cpp:24-51,171-191`): keypair(s) Ed25519 + `read_secret` + contadores seq/manifest_seq/epoch crash-safe + **botón exportar/backup cifrado (load-bearing: custodia de la joya de la corona)**. `StartBroadcast` carga-o-crea en vez de generar (`LiveStreamManager.cpp:198-202`) y deja de borrar la privada (`:420`), pref `EseChannelIdentity` default OFF. Fix de los 2 bugs (inyección JSON, Save-clobber). Sidecar `subscriptions2.dat` (DPAPI) diseñado: {pk → read_secret/has_secret, last_seen_seq, last_manifest_seq, icon_md4, catalog rev} — `subscriptions.dat` v1 queda INTACTO (cero pérdida al downgrade a builds previos del fork; corrige la puerta-de-un-sentido de `SUB_VERSION`).
**Salida:** linter 0; pref ON → dos reinicios → misma streamKey; pref OFF → byte-idéntico a hoy; `mychannels.dat` ilegible desde otra cuenta Windows. **Validación 1-PC** (+ regresión 2-PC de join vanilla).

### C1 — Códec de manifiesto + colecciones firmadas, solo local (~1 semana; 1-PC + interop 2-PC)
ChannelRecord v2 serialize/parse (acepta {1,2}; **re-verificar antes del merge que ningún release intermedio emitió v1 activo**); TLV builder/parser (skip de desconocidos, caps por tipo); pad 2048; `ChannelRecordSeal/Open` con `ikm` explícito (contrato de `LiveChannel.h:86-110` y tesis §5.2.2 actualizados); firma/verificación de colección con el transcript canónico (orden de playlist DENTRO); editor de manifiesto admin (`/api/live/channel/my` + avatar import: hash en hilo de hashing). Harness de checks estilo LiveFec: round-trip v1/v2, tamper, rollback estricto, invariancia del bucket (on-air vs off-air = misma longitud), skip TLV, transcript estable entre re-guardados, dual-dominio de firmas.
**Salida:** harness verde (≥60 checks), /W4 limpio, captura de paquetes = cero tráfico nuevo. **Interop 2-PC vanilla:** un eMule 0.70b SIN modificar descarga la colección firmada por link ed2k, la abre, y descarga un fichero de ella — cero avisos (el money-shot de compat).

### C2 — Descubrimiento público (primera emisión wire, pref `EseChannelPublish` default OFF; 2-3 PC)
Piggyback `ese.live.chanpk`+`chanseq` en `PrepareLivePacketForTags` (assert de tamaño serializado); publish del record bajo `esechan:` a 30 min compartiendo scheduler (JAMÁS bucle paralelo: techo 4/min/IP); `ResolveChannel` público → `ChannelDirectory` (main-thread, snapshot para workers); fetch de manifiesto-spill/avatar por eD2K con verificación sha256 obligatoria post-descarga; caché DPAPI en `ese\channels\`.
**Salida:** PC2 suscrito SOLO con la pubkey resuelve nombre/avatar/seq; PC1 cierra el proceso y PC2 sigue resolviendo el record (rendezvous vacío, cero IP en la entrada — assert de crawler); pref OFF → captura byte-idéntica a la baseline. **Validación 2-PC mínimo, 3-PC preferido con holder vanilla 0.70b en medio** (almacena/sirve la entrada sin cambios).

### C3 — Página de canal + suscripción + notificaciones (~1 semana; 2-PC + móvil)
Endpoints y página de §7 (dos listas de rutas + test negativo 403); marshaling `LiveWebChannelReq`/`UM_LIVE_WEB_CHANNEL`; cableado real de `CLiveSubscriberPinning::Start/OnSubscriptionAdded` desde `EmuleDlg.cpp:939-951` y desde subscribe; primer `DoRepublish` real (resolve + decoys `PickCoverTrafficSet`, caller filtra no-suscritos); toast/balloon.
**Salida:** 2 clicks del player a suscrito; PC2 notificado ≤5 min tras el go-live de PC1; página offline renderiza con PC1 muerto; strings hostiles (`<script>`, comillas) inertes en HTML y JSON; guest desde móvil LAN por `/s/{tok}/` puede navegar/suscribirse/ver; superficies admin 403. **Validación 2-PC + navegador de móvil.**

### C4 — VOD end-to-end + archivado (~1.5 semanas; 2-PC + 1 vanilla)
Gestor de catálogo (append, rev++, re-firma, des-compartir revisión anterior); prompt "¿Publicar como VOD?" + remux ffmpeg en worker con finalización marshaled; verificación de cadena en UI (badge verde/rojo); `/api/live/vod/fetch|status|file` (Range/206); sincronía `PartFile.cpp`↔`PartFile.utf8.cpp`; presupuesto de disco: preview de tamaño en el prompt + borrar-VOD que también des-comparte.
**Salida:** PC2 ve el VOD nuevo tras el siguiente resolve (bump de manifest_seq observado), lo descarga, cadena verde, reproduce en navegador y VLC; colección con un byte volteado y catálogo con rev retrocedida → RECHAZADOS visiblemente; el mismo fichero abre en vanilla 0.70b como colección normal descargable. **Validación 2-PC + instancia vanilla; test de tamper scripteado.**

### C5 — Canales privados/sellados (~2 semanas; 3-PC + harness crawler). **DEPENDENCIA DURA: OFFLINE_INVISIBILITY Fase 0 + Fase 1 aterrizadas y con Gate 0 pasado** (no-publish + cachés DPAPI + plomería sealed publish/resolve). Esta fase MONTA esa maquinaria, no la construye.
Publish/resolve sellados con keying `read_secret` (§2); invite 0xDE (pegar/QR) admin-only; avatar inline; auditoría de guards: sin plaintext, sin PEX/mDNS, sin `last_streams.json`, `access_mode=1` inalcanzable desde el piggyback (assert), 0xD1/0xD2 solo a probadores del secreto, VOD default OFF con aviso.
**Salida (gates de crawler):** cero hits (keyword, IP, hash) vinculables al canal privado on Y off-air; tamaño de ciphertext CONSTANTE entre {off, on, edición de manifiesto}; distribución de cadencia idéntica on/off; PC2 con secreto resuelve el manifiesto con el canal APAGADO; PC3 sin secreto, con visibilidad Kad total, no encuentra ni la clave de lookup. **Validación 3-PC (emisor privado + suscriptor + holder vanilla con crawler) — la receta Gate-2 del plan de invisibilidad.**

### C6 — Túnel + gossip + VOD privado + endurecimiento (stretch; 3-PC)
`TUN_OP_CHANNEL_FETCH/DATA` 0x24/0x25 (el exit hace el fetch 0xD1 por el viewer, espejo de `TUN_OP_KAD_RESULT_V2`, `LiveTunnel.cpp:2157`); activación de 0xD0-0xD3 anunciando bits 10+23 (primer anuncio de capability de todo el plan); VOD privado por bulk de túnel (petición por (pubkey, md4), servida solo a probadores del secreto; re-serving entre suscriptores); alza de confianza del tombstone: bitrate=0 firmado o degradado a "sospecha" (T2) + beacon de re-attach con `live_epoch > last_seen` que limpia el tombstone de 30 min (`LiveKadBridge.cpp:966-977`, R5) — casi gratis ahora que los viewers pinean la pubkey.
**Salida 3-PC (V-X-B NATeados):** V obtiene un manifiesto privado por túnel y B solo ve la IP de X; tombstone forjado ignorado / END firmado honrado; re-attach limpia el tombstone; VOD privado jamás aparece en SharedFileList ni en índices Kad de ningún nodo (captura en el holder vanilla); peer del mesh sin secreto → rechazado.

---

## 9. KPIs

| KPI | Objetivo | Cómo se mide |
|---|---|---|
| Re-encuentro por pubkey (público, emisor off) | ≥95% de resolves fríos | C2, 20 intentos 2-PC |
| Re-encuentro privado (con secreto, emisor off) | ≥90% (hora actual+anterior) | C5, 3-PC |
| Latencia notificación en-directo | pública ≤5 min; privada ≤30 min | C3/C5 cronometrado |
| Residuo crawler canal privado | 0 artefactos (keyword/IP/hash) on y off-air | harness Gate-0/2 |
| Constancia de tamaño sellado | 2076 B exactos en {off, on, edición} | captura en holder |
| Presupuesto publish | ≤ techo de 4 req/min/IP con live+canal simultáneos; +1 entrada /24 por canal | contadores de `PacketTracking` |
| Interop vanilla | 100%: colección abre, VOD descarga, holder almacena tags opacos, cero regresión de join | C1/C2/C4 con 0.70b real |
| Regresión pref-OFF | captura de wire byte-idéntica a baseline | cada fase |
| Cadena de confianza | tamper de 1 byte en {colección, sha256, sig, rev} → 4/4 rechazos visibles | C4 scripteado |
| Fetch de manifiesto | página de canal completa <10 s en frío (público) | C3 |

---

## 10. Riesgos principales

1. **`mychannels.dat` = punto único de fallo catastrófico:** perderla = canal muerto para siempre; robarla = suplantación total (una clave firma record+manifiesto+catálogos). DPAPI es por-usuario/máquina (sin roaming). Mitigación: export/backup cifrado OBLIGATORIO en C0 + release notes honestas; `successor[32]` sin protocolo = deuda declarada.
2. **Presión de publish en DHT pequeña:** bucket de 4/min/IP con ban (`PacketTracking.cpp:129-131,219-226`) + dilución de trust /24 (`Entry.cpp:471-506`); el record es inherentemente una ronda nueva (clave Kad distinta) — cadencia 30 min, scheduler compartido, y el piggyback (que no añade entrada) lleva el peso del descubrimiento en caliente. Cualquier "publicar más" en revisión = P0.
3. **Sin revocación de suscriptores privados:** quien tuvo `read_secret` descifra para siempre hasta rotación manual + reinvitación. Documentado; automatizar = C7 futuro.
4. **Las propiedades de privacidad de C5/C6 montan maquinaria hoy inexistente** (sealed publish/resolve, pinning F3→F5, Fase 0/1 de invisibilidad): el orden de fases lo codifica; reordenar convierte las afirmaciones de cobertura/cadencia en falsas. Ninguna afirmación en UI antes del cableado real.
5. **Fragilidad del webserver:** router por prefijos + doble registro de rutas + split guest/admin = la clase de vuln histórica; test negativo por endpoint en cada fase.
6. **Residuo público de 24h imborrable** con tombstone forjable hasta C6: el modo público no se vende como privado, nunca.
7. **Meta-riesgo de scope:** cada no-objetivo tiene una versión "pequeña" tentadora; el TLV inline tiene presupuesto duro (1200 B) precisamente para que engordar el manifiesto rompa un gate medible (bucket fijo) y no pase en silencio.

---

## 11. Interacción con planes existentes

| Plan | Interacción |
|---|---|
| **OFFLINE_INVISIBILITY_PLAN** | C0 IMPLEMENTA su prerequisito §7-8 (R1/R2 keypair persistida) — trabajo compartido, no duplicado. C5 depende duro de sus Fases 0+1 y Gate 0. Este plan RETROALIMENTA una corrección de spec: separación `read_secret`/clave-de-firma y `K_lookup` derivado del secreto (no de la pubkey) — actualizar el plan y `LiveChannel.h:86-96`. R5 (beacon re-attach) y T2 (tombstone firmado) aterrizan en C6 casi gratis. |
| **Kad sellado** | Este plan MONTA la dirección decidida (STOREKEYWORD opaco bajo clave rotada, cero DHT nueva, cero tags wire nuevos en el camino sellado); no construye maquinaria paralela. El prefijo `ese.live.priv.` se registra como su Fase 1.3 ya pedía; se añade `esechan:` para el público. |
| **DVR de enjambre (SWARM_DVR_PLAN.md)** | El archivado C4 (HLS→mp4→hash→colección firmada) es el germen: el catálogo firmado es exactamente el índice que el Swarm DVR poblaría automáticamente ("¿Publicar como VOD?" = el puente natural D2→C4); la decisión de contenedor (.ts concat vs .mp4 faststart) se toma en C4 mirando a ese plan y al Range/206 móvil. Reservas des-conflictadas: DVR = 0xB5-0xB8 + cap bit 22 + TUN 0x60-0x62; canales = tags 0x6F-0x72 + cap bit 23 + TUN 0x24-0x25. Ninguna dependencia bloqueante en ningún sentido. |
| **MOBILE_VIEWER_PLAN (track M)** | Hereda por construcción: endpoints bajo `/s/{tok}/`, matriz guest (suscribir desde el móvil del dueño = sí), `/api/live/vod/file` Range/206 = la rebanada mínima de su `/api/files` diferido; patrones de marshaling exigidos en sus líneas 43-45 respetados. Open question compartida: scopes por token si los guest tokens se comparten con terceros. |
| **E-α / E-β (túneles y bulk)** | C6 reutiliza el data plane bulk v8.1.2 para VOD privado y el patrón de exit tunelizado (`TUN_OP_KAD_*`) para `TUN_OP_CHANNEL_FETCH`; identidad de mesh sigue siendo TunnelEndpoint, nunca IP. Nada de este plan toca el motor de chunks en vivo. |
| **Abolición LowID eD2K** | Los fetch de VOD/manifiesto por eD2K cabalgan `AskForDownload`, el mismo camino que ese plan toca: secuenciar C4 DESPUÉS de su validación para no validar dos veces. |
| **Empuje v9 / estabilizar-antes-de-features** | Todo el plan es post-estabilización v9; C0-C1 son trabajo local sin wire que puede prepararse antes sin riesgo; C2+ esperan. |
| **Registro de protocolo P0** | Todas las reservas de §4 verificadas libres a mano contra `Opcodes.h` (el linter ignora ~200 símbolos upstream: registro-libre ≠ wire-libre) y contra las minas de bytes-cabecera; CSV-primero, append-only. |
