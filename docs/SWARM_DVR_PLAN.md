# SWARM DVR — Plan técnico consolidado (rebobinado 10–30 min desde el enjambre, sin servidores)

**Estado:** DISEÑO (post-síntesis de 3 diseños independientes + crítica adversarial). Se implementa DESPUÉS de la estabilización v9.
**Regla madre:** compat hacia atrás obligatoria (vanilla 0.70b + todos los forks previos, byte-idéntico cuando la pref está OFF); todo dormante y gateado por capability hasta validación multi-PC (precedente bit 21 ESE_CAP_LIVE_RELAY).

---

## 1. Objetivo y no-objetivos

### 1.1 Objetivo
Un viewer de una emisión eSE Live puede rebobinar/buscar hacia atrás 10–30 minutos, y un late joiner puede empezar antes del borde en vivo, obteniendo los chunks antiguos del propio enjambre (broadcaster + buffers de otros viewers). Cero servidores, cero dominios, cero coste.

### 1.2 La observación que abarata todo
**Quien lleva N minutos viendo ya recibió todos los segmentos.** La retención local por sí sola (fases D1+D2, cero cambios de wire) entrega el rebobinado para el caso mayoritario. El plano de enjambre (D3+D4) existe solo para late joiners y relleno de huecos.

### 1.3 No-objetivos (descartados explícitamente)
- **DVR multi-stream**: hay exactamente un `CLiveChunkBuffer` por `CLiveStreamManager` (LiveStreamManager.h:528); un stream a la vez. Cambiar de canal destruye la ventana DVR (correcto para privacidad; la UI lo dirá).
- **Export/grabación persistente**: el almacén muere con la sesión. "Guardar esta emisión" es otra feature con otro modelo de amenazas (DPAPI, pins persistidos) — decisión separada.
- **DVR para canales privados en v1**: deshabilitado hasta resolver la cuestión DPAPI (§8.2) — la ley de cachés de disco de OFFLINE_INVISIBILITY_PLAN.md Fase 0.2 exige cifrado at-rest para residuo de canal privado.
- **Ampliar el ring de 16 slots**: `ESE_LIVE_MAX_SEGMENTS=16` está clavado por el bitmap uint16 del heartbeat (LiveProtocol.h:10-13). No se toca. Jamás.
- **Wall-clock en el wire**: los timestamps se ponen a cero deliberadamente (endurecimiento anti clock-skew, LiveStreamManager.cpp:463-474). No se reintroduce. Eje temporal = seqNum × 2 s relativo.
- **DVR vía relay buddy (0xCE/0xCF) para broadcasters CGNAT**: fuera de v1 (los viewers de esos streams se sirven DVR entre sí).
- **Scoring multi-fuente elaborado**: con mallas típicas de 2-3 peers, basta fetch-de-cualquier-anunciante + caché negativa. Sin economía de confianza DVR propia más allá de un contador de fiabilidad simple.

---

## 2. Decisiones de diseño clave (resolución de los fallos fatales de la crítica)

Los tres diseños independientes convergieron en la misma arquitectura de dos niveles; la crítica adversarial encontró 5 fallos fatales recurrentes. Cada uno queda resuelto o descopeado explícitamente:

| # | Fallo fatal (crítica) | Resolución en este plan |
|---|---|---|
| F1 | **Residuo de crash**: wipe solo en salidas limpias → GBs de records firmados (¡prueba criptográfica de visionado!) en %TEMP% tras un crash | **Barrido de arranque incondicional**: al iniciar la app, purgar todos los subdirectorios `dvr/` bajo `%TEMP%\eMule_RTMP\` antes de cualquier join. Criterio de salida de D1, no un afterthought. Además canales privados = DVR off (§1.3). |
| F2 | **La mayoría V1 destripa el enjambre**: los re-serves de malla son V1 sin firma (OnPeerRequest LiveStreamManager.cpp:1538-1545) → los stores de viewers serían mayoritariamente no-servibles | (a) flag `signed` **por-RECORD** (no por-stream); solo se anuncian/sirven spans firmados; (b) **promoción del re-serve V2 literal al plano LIVE**: cuando el store tiene el record firmado, OnPeerRequest sirve el 0xCC original en vez de degradar a V1 — cierra de paso el agujero "trust-the-transport" de la malla actual (los receptores ya verifican 0xCC venga de quien venga); (c) el sink de fetch DVR **rechaza V1** cuando existe pin (siempre, para fetch de enjambre). |
| F3 | **Replay entre sesiones**: la firma cubre solo streamKey‖seq‖sha256 (LivePackets.cpp:113-118) — sin epoch, records de una sesión muerta del mismo canal verifican como actuales | Tratamiento honesto: el ataque se limita a **contenido auténtico del mismo canal de una sesión anterior** (no falsificación arbitraria). Mitigación por capas: (i) campo `Epoch u32` reservado en 0xB5 desde ya (cero hasta que R5/R6 aterrice); (ii) plausibilidad del fetcher: solo acepta seqs en [borde_vivo − retención_max, borde_vivo+lookahead]; (iii) wipe local por regresión de seq; (iv) **prerequisito duro para status "stable"/default-on**: epoch en la identidad de chunk, coordinado con Live V3 (0xB4) y el beacon firmado de re-attach (plan R5/R6). Hasta entonces D4 es experimental opt-in con riesgo residual documentado. |
| F4 | **Truncado por END sin firmar**: OnStreamEnded hace leave inline + gossip para ENDs firmados Y sin firmar (LiveStreamManager.cpp:2484-2509); si LeaveStream purga el store, un insider trunca el DVR de toda la malla con un paquete | **Desacoplar purga de leave**: el ciclo de vida del store recibe el *motivo*. END sin firmar → dejar de anunciar/fetchear, **conservar** el store para replay local. Purga solo en: leave del usuario, join de otra key, salida de app, barrido de arranque. END firmado → congelar (ENDLIST, replay local legal bajo tombstone), purgar al leave. Es un toque mínimo y asumido al camino END (un parámetro de motivo), presupuestado en la validación de D1. |
| F5 | **Refactor de hot-path validado en fase "segura"**: unificar el camino 0xCC de paquete único (ListenSocket.cpp:1984-2048) a través de IngestChunkPayload ejecuta con pref OFF | **TAP, no unificación**: dos puntos de captura paralelos (IngestChunkPayload en LiveStreamManager.cpp:1672 y el camino ListenSocket.cpp:1984), copiar-y-encolar, dispatch intacto. Con pref OFF los taps son un if-false — comportamiento binario-idéntico. |

Otras correcciones de la crítica incorporadas: limpieza HLS-4 indexada (no sweep de directorio O(n), §3.1); keepalive de pausa acotado (§3.3); presupuesto de servicio escalado con bitrate (§3.2); bit 22 implica bit 13 (§3.2); bytes DVR fuera de Ratio60s en ambas direcciones (§3.2); semántica NACK de rango definida (§3.2); disciplina FILE_SHARE_DELETE (§3.1); snapshot con doble búfer, no interlocked mágico (§3.3).

---

## 3. Arquitectura

### 3.1 Almacén: dos niveles, ring intocado

**Nivel 1** = el `CLiveChunkBuffer` actual (ring de 16 slots, LiveChunkBuffer.h:57), byte-idéntico: bitmap uint16, guardia de llegadas viejas (LiveChunkBuffer.cpp:80-86), clamp del egress R.3 (LiveStreamManager.cpp:3304-3305) — todo intacto.

**Nivel 2** = nuevo `CLiveDvrStore`, en disco, por-stream, con ámbito de sesión.

**Qué se guarda:** el record **wire V2 crudo completo** — StreamKey(16)+Seq(4)+Ts(4)+DataSize(4)+Bitrate(2)+sha256(32)+SigEd25519(64)+Data = 126 B de cabecera + payload TS. Decisión estructural: la firma se descarta hoy en el ingest (LiveChunk no tiene campos digest/sig, LiveProtocol.h:102-141) y un archivo del contenido del ring sería criptográficamente inútil para re-servir. Como la sección Data ES el payload .ts, un solo almacén sirve tanto el re-serve de malla (record literal) como el HLS local (leer desde offset 126) — **sin doble almacenamiento**; el espejo `seg_NNNNN.ts` de la ventana viva y su limpieza HLS-4 no se tocan.

**Formato:** un fichero por segmento, `%TEMP%\eMule_RTMP\<streamkey-hex>\dvr\rec_%08u.rec` (sin asumir anchura de 5 dígitos). Eviction = DeleteFile O(1), tolerante a crash, sin compactación. Aperturas de lectura con FILE_SHARE_DELETE (o renombrar-y-borrar) para que la eviction nunca colisione con un serve HTTP en curso.

**Índice en RAM:** `std::map<uint32 seq, DvrIdxEntry{u32 size; u8 flags(bit0=signed); u32 epochReservado}>` bajo un **lock hoja propio** (disciplina m_proxyIngestLock: nunca se mantiene al tomar locks de manager/túnel, nunca a través de I/O). ~900 entradas (30 min) ≈ <100 KB con overhead de nodos x64. Contador agregado de bytes mantenido incrementalmente. **Cero FindFirstFile en hot paths** — el índice es autoritativo. Esto mata los hazards O(n) FindSlot / O(n²) sweep del recon.

**Puntos de captura (taps, F5):**
- Viewer: `IngestChunkPayload` (LiveStreamManager.cpp:1672) — recibe el record crudo completo antes de que la verificación descarte la firma — **más** un tap paralelo idéntico en el camino de paquete único (ListenSocket.cpp:1984-2048). Copiar-y-encolar; el resultado de la verificación fija el flag signed.
- Broadcaster: `FeedSegment` (LiveStreamManager.cpp:463-478), construyendo el record V2 con el layout de `CreateChunkPacketV2` (tiene la privkey) — el store del broadcaster es 100 % firmado, el ancla del enjambre.
- Records recibidos como V1 sin firma: `signed=false` → válidos para replay LOCAL, **nunca anunciados ni servidos**.

**Matemática de tamaño** (2 s/segmento; bytes ≈ kbps × 250):

| Bitrate | Por segmento | 10 min (300 seg) | 30 min (900 seg) |
|---|---|---|---|
| 2000 kbps | 500 KB | 150 MB | 450 MB |
| 6000 kbps | 1,5 MB | 450 MB | 1,35 GB |
| 12000 kbps | 3 MB | 900 MB | 2,7 GB |
| Peor caso VBR (tope 12 MB/chunk) | 12 MB | 3,6 GB | 10,8 GB |

Conclusión: **todo-RAM inviable**; nivel 2 es solo-disco. Prefs: `EseDvrEnabled` (default **FALSE** — feature entera dormante), `EseDvrMinutes` (default 10, máx 30), `EseDvrRetentionMB` (default 512, máx 4096), `EseDvrUpKBps` (default 0 = auto, §3.2). Ventana efectiva = min(ambos topes). A 12000 kbps el default da ~5,6 min — etiquetado honesto en la UI (expresar en minutos derivados del bitrate observado). Eviction = borrar-el-más-viejo-por-seq hasta cumplir ambos topes; el presupuesto agregado explícito reemplaza el límite implícito 16×12 MB del ring; el guard de 12 MB por-chunk drop-no-ban (LiveChunkBuffer.cpp:44-52) se mantiene. Toda aritmética (newest − ventana) repite el patrón de guardia de rampa uint32 del bug del 15-may.

**Threading:** todas las escrituras y lecturas frías van por un **DvrIoThread dedicado** (patrón PartFileWriteThread; cola acotada 16 records/64 MB; overflow = descartar la copia DVR + contador `dvrWriteDrops`, el vivo jamás se bloquea; los datos ya están heap-copiados, el handoff es un movimiento de puntero). Obligatorio, no opcional: el precedente del hilo de hashing dice que la I/O de disco síncrona en el hilo principal congela UI/red, y OnPeerRequest/Process son main-thread. Lecturas de serve: caché LRU de 2 records (≤24 MB peor caso) → hit se envía desde main; miss → lectura en DvrIoThread → PostMessage(UM_LIVE_DVR_IO_DONE) → main construye y encola el paquete.

**Limpieza HLS-4 indexada:** con pref ON, la limpieza de `.ts` fuera de ventana (LiveStreamManager.cpp:1076-1099) pasa a borrar exactamente el seq evictado desde el índice, sin enumerar el directorio (que con 900 ficheros retenidos sería un scan completo cada 2 s en main thread). Con pref OFF, código byte-idéntico.

**Ciclo de vida (acoplado a privacidad — véase F4 y §8.2):**

| Evento | Acción sobre el store |
|---|---|
| Arranque de la app | **Barrido incondicional** de todos los `dvr/` (F1) |
| JoinStream / StartBroadcast | Crear store para esa key |
| JoinStream de OTRA key | Purgar el anterior, crear nuevo |
| LeaveStream (usuario) / StopBroadcast / salida de app | **Purgar** (ficheros + índice) |
| OP_LIVE_END **firmado** (ListenSocket.cpp:2244-2284) | Congelar: ENDLIST en playlist DVR, replay local legal (gate de lectura del tombstone, LiveStreamManager.cpp:2474-2477), cero anuncio, cero fetch, cero dial; purga al leave |
| OP_LIVE_END **sin firmar** (hint suave, plan T3) | Dejar de anunciar/fetchear; **conservar** para replay local (F4) |
| Key tombstoned (IsStreamTombstoned) | Nunca fetch/anuncio/dial para esa key |
| Regresión de seq detectada (borde vivo < dvrNewest − 64) | Wipe del store (heurística R6 hasta que exista epoch) |
| Disco lleno / error de escritura | Dejar de retener + contador; el vivo no se ve afectado |

Nada sobrevive a la sesión → sin DPAPI en v1 (porque canales privados quedan excluidos, §1.3) y la invisibilidad offline se cumple por construcción **incluida la vía de crash** (barrido de arranque).

### 3.2 Wire: 4 opcodes nuevos en banda libre + 1 cap bit + 3 sub-ops de túnel

**Principio:** reutilizar el plano de datos validado (records 0xCC + fragmentación 0xE0); añadir solo el control mínimo: anuncio de disponibilidad, petición, datos, NACK. Se eligen **opcodes dedicados** (no trailers en 0xC6/0xC1): el HEARTBEAT ya lleva el trailer PEX de longitud variable (un segundo trailer es ambiguo), un opcode de datos dedicado evita ambigüedades de enrutado con el ingest vivo (m_bViewing-gated) y la burla del guard del ring, y el gating es más limpio. Todo verificado libre contra docs/protocol/*.csv el 2026-07-03.

**Registro (orden §5 de PROTOCOL_REGISTRY.md: fila CSV PRIMERO como reserved-proposed → `python tools/check_protocol_registry.py` exit 0 → #define en srchybrid/Opcodes.h o LiveTunnel.h → flip a experimental). Minas respetadas: 0xC5 (OP_EMULEPROT), 0xD4 (OP_PACKEDPROT), 0xE3+ = bytes de header invisibles al linter; 0xE0 = OP_LIVE_CHUNK_FRAG; símbolos fuera de esos dos headers escapan a la gobernanza.**

| Símbolo | Valor | Namespace | Formato |
|---|---|---|---|
| `OP_LIVE_DVR_OFFER` | 0xB5 | EMULEPROT-CC | `<StreamKey 16><Epoch 4 (=0 reservado)><Flags 1 (bit0=will-serve)><RangeCount 1 (≤4)><{StartSeq 4}{Count 2}>×N` |
| `OP_LIVE_DVR_REQ` | 0xB6 | EMULEPROT-CC | `<StreamKey 16><FromSeq 4><Count 1 (clamp servidor ≤4)>` |
| `OP_LIVE_DVR_DATA` | 0xB7 | EMULEPROT-CC | cuerpo byte-idéntico a un record OP_LIVE_CHUNK_V2 (o V3 cuando exista) servido LITERAL |
| `OP_LIVE_DVR_NACK` | 0xB8 | EMULEPROT-CC | `<StreamKey 16><FromSeq 4><Count 1><Reason 1>` (0=no-retenido, 1=ocupado, 2=throttled, 3=terminado) — cubre subrangos |
| `ESE_CAP_LIVE_DVR` | bit 22 (0x00400000) | CAP-ESE | dormante hasta D3-validado; **implica bit 13** (LIVE_CHUNK_FRAG) en el emisor |
| `TUN_OP_DVR_FETCH` | 0x60 | TUNNEL-CELL | viewer→exit: `<StreamKey 16><FromSeq 4><Count 1>` |
| `TUN_OP_DVR_NACK` | 0x61 | TUNNEL-CELL | exit→viewer |
| `TUN_OP_DVR_OFFER` | 0x62 | TUNNEL-CELL | exit→viewer: rangos alcanzables por el exit |
| `FLAG_DVR` | bit0 de BulkDataHeader.flags (u8 sin uso, LiveBulk.h:72) | — | **invisible al linter**: nota manual en prosa de TUNNEL_SERVICES.csv |

**Anuncio (0xB5):** cadencia ~10 s (no la del heartbeat de 1 s — la historia cambia despacio, 10× más barato), solo a peers eSE conectados que anuncien bit 22, solo mientras la sesión está viva y sin tombstone, **jamás gossipeado/PEX'd**. Solo spans **firmados y contiguos** (F2). Máx 4 rangos = grano grueso deliberado (privacidad: los huecos finos revelan continuidad de visionado). El receptor guarda rangos en `m_peerDvrRanges` con clave **LivePeerId durable** (sobrevive el swap de CUpDownClient* de ~6 s de LowID, LiveProtocol.h:145-168), con TTL.

**Petición/servicio (0xB6→0xB7/0xB8):** gating por-handler explícito `SupportsLiveP2P() + bit 22` (el gate de rango 0xC0..0xCC de ListenSocket.cpp:1005 NO cubre 0xB5-0xB8; patrón del handler 0xE0 en :2058). El servidor responde lo que tiene y NACKea el subrango faltante (semántica de rango resuelta). Records >1,8 MB por 0xE0 con `InnerOpcode=0xB7` (el formato frag ya lleva InnerOpcode — cero opcodes nuevos de frag), reensamblados por un **reensamblador DVR propio** (2 slots, 10 s TTL) que no toca el presupuesto vivo de 8 slots/4 s. Los caminos de paquete único hard-capean a 4 MB (ListenSocket.cpp:1976, :2006): por eso bit 22 implica bit 13 — sin frag no hay DVR.

**Subordinación estructural al borde vivo (la lección del espiral de carga a 12000 kbps, no negociable):**
- **Servidor:** limitador /24 DVR propio (20 req/5 s — separado del limitador vivo 50/5 s de LiveStreamManager.cpp:1458, que no se consume) + token bucket de bytes global (`EseDvrUpKBps`; en auto = min(25 % del upload ocioso, máx(384 KB/s, 1,25× la tasa de bytes del stream)) — así el catch-up sostiene ≥1,25× tiempo real cuando hay capacidad, respondiendo a la crítica del spinner perpetuo) + **1 record en vuelo por peticionario** + drenaje SOLO al final de Process() tras todo el trabajo vivo (patrón RelayPushNewSegments/m_testDeferredSends, LiveStreamManager.cpp:3176-3182) + skip si el socket no pasa IsBusyQuickCheck + **presupuesto a cero si la propia salud del borde vivo está degradada**. DVR obtiene sobras, estructuralmente. El head-of-line TCP residual queda acotado a un slice de frag (1,4 MB) por peer; si el gate de 12000 kbps de D4 falla, el siguiente palanca es pre-fragmentar todos los serves DVR a ≤512 KB, no más wire.
- **Cliente (fetcher):** mapa de peticiones **propio** (jamás m_inflightSegReqs, jamás ChargePunctualityFailure/failCount — el recon confirma que los timeouts DVR envenenarían la economía de puntualidad, LiveStreamManager.cpp:3534-3543), ≤2 REQs pendientes en total, cursor secuencial guiado por el playhead (pre-roll de 5 seg en el ancla, luego lookahead ≤60 s — el coste de malla sigue al visionado real, ~1× bitrate sostenible indefinidamente), backoff exponencial en NACK ocupado/throttled, caché negativa por (peer,seq), **pausa dura del fetch DVR cuando el borde vivo propio tiene huecos edge-critical**, y regla give-up-and-skip (3 fuentes fallidas → avanzar el ancla más allá del hueco).
- **Contabilidad segregada en ambas direcciones:** los serves DVR no incrementan trust.requestsServed ni el limitador /24 vivo; los bytes DVR recibidos no entran en Ratio60s (LiveStreamManager.cpp:1556-1599) — la contaminación cruzada de contadores es defecto bloqueante de review.
- Abuso: >30 REQs sobre-presupuesto en 60 s → ignore DVR de 10 min de ese peer (drops silenciosos). **Nunca ban** (precedente drop-no-ban: el tráfico de origen túnel no es atribuible).

**Compat hacia atrás:** vanilla 0.70b no negocia el mod-string eSE → jamás ve opcodes Live. Forks previos: sin bit 22 → jamás se les envía nada nuevo; si un peer malicioso envía 0xB5-0xB8 igualmente, cae en el default log inocuo (ListenSocket.cpp:2419-2421). Heartbeat, bitmap, announce, ring y clamp de relay quedan byte-idénticos porque la retención vive en un almacén aparte. Con pref OFF (default), ningún camino de código emite los elementos nuevos.

### 3.3 Player y webserver: segunda playlist, cero rutas nuevas

**`stream.m3u8` (borde vivo) intocado** — cero riesgo de regresión para viewers existentes. Nueva playlist hermana **`stream_dvr.m3u8`** en el mismo directorio por-stream: la whitelist `EseIsSafeHlsResourceA` ya admite `stream_*.m3u8` (WebServer.cpp:4485, verificado) y la ruta existente `/api/live/{hash}/` la sirve sin cambios de routing/auth (reclamar el nombre en el comentario de :6730 que reserva informalmente stream_* para renditions de audio).

**Forma:** ventana deslizante viva (EVENT rechazado: prohíbe quitar entradas → no puede honrar el presupuesto de bytes). `#EXT-X-MEDIA-SEQUENCE` = seq más viejo listado, entradas SOLO para segmentos presentes en el índice (playlist conservadora — cero juegos de 404 que VLC lleva mal), `#EXT-X-DISCONTINUITY` en huecos, sin ENDLIST en vivo (ENDLIST al congelar por END firmado). Generación en main thread desde el índice RAM (≤1 rebuild/2 s, incremental, cero sweeps), escritura vía DvrIoThread. Guardia de borde de retención: la playlist va 15 segs (30 s) por detrás del horizonte real para que la eviction nunca borre el segmento bajo el playhead.

**Servicio de segmentos:** el worker del webserver intenta `seg_NNNNN.ts` (ventana viva, como hoy); si no, resuelve `dvr/rec_NNNNN.rec` y **streamea el payload desde offset 126 en trozos de 64 KB** (patrón /hls/ de WebServer.cpp:5006-5011 — NO la ruta fichero-entero-en-RAM: un seg DVR de 12 MB por petición es una bomba de allocaciones). Lecturas puras de disco + lock hoja del índice → seguras en el worker según la regla auditada 2026-05-21.

**Flujo de seek:**
1. *Dentro de la ventana local* (mayoría): el JS de la página hace `currentTime -= 600` contra stream_dvr.m3u8 (hls.js con el `liveDurationInfinity:true` ya configurado en WebServer.cpp:6834-6847 expone la ventana como rango buscable). Instantáneo, cero red. **Entregable de D2.**
2. *Late joiner / objetivo no local*: `GET /api/live/dvr` (solo-lectura: {localOldest, localNewest, swarmRanges, cursor, retainedBytes} publicado por **doble búfer bajo el lock hoja** — no un InterlockedExchange mágico sobre una estructura variable) muestra la píldora "DVR disponible: 12:34"; `POST /api/live/dvr/seek?seq=N` marshalea por **SendMessage bloqueante con struct en pila** (nuevo `UM_LIVE_WEB_DVR` en UserMsgs.h, patrón exacto UM_LIVE_WEB_JOIN de EmuleDlg.cpp:1755-1771); el fetcher rellena el pre-roll de 5 segs, la playlist se re-ancla, el JS recarga la fuente y busca.

**Eje temporal:** "-MM:SS respecto al directo" = (seqBordeVivo − seqPlayhead) × 2 s. Sin wall-clock.

**Watchdog de viewer fantasma (acotado, respuesta a la crítica del dead letter):** los polls de playlist ya alimentan NotePlayerFetch; con DVR activo en la sesión, `ESE_PLAYER_IDLE_LEAVE_MS` sube 60→180 s **solo para esa sesión** (no global), y el poll-en-pausa de la página se corta a los **15 min de pausa** → auto-leave normal. Una pestaña abandonada no sostiene la malla para siempre. VLC crudo pausado >3 min pierde la sesión — limitación documentada.

**Viewers tunelizados** (D5): misma página, mismo store, misma playlist; solo cambia el transporte de fetch — `TUN_OP_DVR_FETCH` vía exit, **jamás un dial directo** (el fetcher comprueba el modo de transporte de la sesión y rehúsa 0xB6 directo en modo Tunelizado: un fetch directo re-expondría el interés viewer↔canal que el túnel existe para ocultar). Entrega por el plano bulk existente (OP_LIVE_BULK_CELL + FEC LiveFec) con `FLAG_DVR` para que `DeliverBulkData` (LiveTunnel.cpp:2880-2936) enrute al sink DVR en vez de inyectar en el pipeline vivo; el NACK de huecos (TUN_OP_BULK_NACK 0x52) funciona sin cambios porque el reensamblado va con clave (streamKey,seq) y el flag desambigua. Exit: handler vía `RegisterExitHandler`, lecturas lentas con `BeginExitOperation/CompleteExitOperation` (hechos a medida para esto, LiveTunnel.h:550-575); sirve de su propio store pequeño (ventana ~5 min, tope de bytes propio, alimentado por los taps ExitProxyOnWholeChunk/ExitProxyOnFragment que ya ven records completos pre-ring, LiveStreamManager.cpp:1686-1688/:1767-1768) o proxya UN 0xB6 a la malla con su propia identidad (patrón C7). Subordinación en el exit: símbolos DVR solo cuando no hay símbolos vivos pendientes, ≤1 record en vuelo por sesión, auto-ritmo bajo el tope 25 MB/5 s por-IP de celdas bulk (ListenSocket.cpp:959-997 — los drops son silenciosos, hay que medirlo). **Alcance honesto:** la vista de malla del exit es solo el broadcaster (una suscripción C7 compartida) → profundidad DVR tunelizada ≈ store del exit + store del broadcaster; con broadcaster anónimo (retain-off) la profundidad puede ser ~5 min o cero — se documenta, no se maquilla.

**Viewer móvil (track M):** stream_dvr.m3u8 es un recurso whitelisteado más bajo el prefijo `/s/{tok}/` del plan — herencia gratis.

---

## 4. Reservas de protocolo (acción inmediata en D0)

Filas exactas a añadir (esquema `name,value,namespace,intro_version,status,capability_gate,format,compat,file,line`):

**docs/protocol/OPCODES.csv** (4 filas):
```
OP_LIVE_DVR_OFFER,0xB5,EMULEPROT-CC,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"<StreamKey 16><Epoch 4=0><Flags 1><RangeCount 1<=4><{StartSeq 4}{Count 2}>xN -- anuncio rangos DVR retenidos firmados; cadencia 10s; nunca PEX/gossip; cesa en END/tombstone",additive,docs/SWARM_DVR_PLAN.md,0
OP_LIVE_DVR_REQ,0xB6,EMULEPROT-CC,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"<StreamKey 16><FromSeq 4><Count 1 (clamp<=4)>",additive,docs/SWARM_DVR_PLAN.md,0
OP_LIVE_DVR_DATA,0xB7,EMULEPROT-CC,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"cuerpo = record OP_LIVE_CHUNK_V2/V3 LITERAL (auto-autenticante vs pubkey pineada); >1.8MB via OP_LIVE_CHUNK_FRAG InnerOpcode=0xB7",additive,docs/SWARM_DVR_PLAN.md,0
OP_LIVE_DVR_NACK,0xB8,EMULEPROT-CC,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"<StreamKey 16><FromSeq 4><Count 1><Reason 1: 0=no-retenido 1=ocupado 2=throttled 3=terminado>",additive,docs/SWARM_DVR_PLAN.md,0
```
**docs/protocol/CAPABILITIES.csv** (1 fila):
```
ESE_CAP_LIVE_DVR,0x00400000,CAP-ESE,DESIGN,reserved-proposed,none,"bit 22 -- Swarm DVR (retencion+serve historia Live). IMPLICA bit 13 (LIVE_CHUNK_FRAG) en el emisor. Dormante hasta multi-PC (precedente bit 21). Gap 6/7 historico intacto. NOT in code yet.",additive,docs/SWARM_DVR_PLAN.md,0
```
**docs/protocol/TUNNEL_SERVICES.csv** (3 filas + nota):
```
TUN_OP_DVR_FETCH,0x60,TUNNEL-CELL,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"V->exit: <StreamKey 16><FromSeq 4><Count 1>; respuesta por plano bulk 0xD9 con BulkDataHeader.flags bit0=FLAG_DVR (flag NO gobernado por linter, esta nota es el registro)",internal-tunnel,docs/SWARM_DVR_PLAN.md,0
TUN_OP_DVR_NACK,0x61,TUNNEL-CELL,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"exit->V: mismos reason codes que 0xB8",internal-tunnel,docs/SWARM_DVR_PLAN.md,0
TUN_OP_DVR_OFFER,0x62,TUNNEL-CELL,DESIGN,reserved-proposed,ESE_CAP_LIVE_DVR,"exit->V: rangos DVR alcanzables por el exit",internal-tunnel,docs/SWARM_DVR_PLAN.md,0
```
Verificación 2026-07-03 contra los CSV: banda 0xB5-0xBF libre (0xB3=OP_PUBLICIP_ANSWER_V6, 0xB4=OP_LIVE_CHUNK_V3 reserved-proposed); bits CAP-ESE 22/23 libres (15-21 tomados/reservados; gap 6/7 no se rellena); TUNNEL-CELL 0x60+ enteramente libre (usados: 0x01,0x02,0x10,0x11,0x20-0x23,0x40-0x44,0x50,0x52,0x54). Lección bit-15: re-verificar dormancia en Opcodes.h en el momento de implementar, nunca fiarse de la prosa del CSV. **Nota de des-conflicto entre planes (mismo día):** CHANNEL_MANIFEST_PLAN.md reserva el cap bit 23 (0x00800000), los tags TAG-ED2K 0x6F-0x72 y TUN_OP 0x24/0x25 — el siguiente cap bit libre es el 24, y de la banda 0xB5-0xBF quedan libres 0xB9-0xBF.

---

## 5. Fases D0–D6

Cada fase es independientemente entregable, dormante/gateada hasta que su receta de validación pasa. **D1+D2 = MVP autónomo** (rebobinado local, cero wire): si D3+ no aterrizara jamás, D1+D2 siguen valiendo por sí solas.

### D0 — Reservas de registro + prefs + doc (sin comportamiento)
**Alcance:** filas CSV de §4; este documento como docs/SWARM_DVR_PLAN.md + fila en docs/INDEX.md; prefs `EseDvr*` en Preferences.cpp/.h (leídas por nadie aún, sin UI).
**Criterios de salida:** `python tools/check_protocol_registry.py` exit 0; build Release x64 verde; grep confirma que ningún opcode nuevo se emite; delta de comportamiento = cero.
**Validación:** 1-PC (build + linter).

### D1 — Almacén local: captura + retención + ciclo de vida (sin wire, sin UI)
**Alcance:** `CLiveDvrStore` (índice, formato rec_, presupuestos byte/tiempo, eviction, guardia uint32, lock hoja, FILE_SHARE_DELETE); DvrIoThread (cola acotada, drop-on-overflow, shutdown limpio); taps de captura en FeedSegment + IngestChunkPayload + camino ListenSocket.cpp:1984 (**taps paralelos, sin refactor de dispatch** — F5); flag signed por-record; ciclo de vida completo de la tabla §3.1 **incluidos el barrido de arranque (F1) y el desacople purga/motivo-de-END (F4** — toque mínimo a OnStreamEnded pasando el motivo al store); heurística de regresión de seq; limpieza HLS-4 indexada con pref ON; canales privados excluidos; contadores en /api/live/debug (dvrRetainedBytes, dvrWriteDrops, dvrEvictions).
**Criterios de salida:** pref OFF → comportamiento binario-idéntico (diff A/B de logs + soak de ingest a 12000 kbps 2-PC porque los taps tocan el hot path); pref ON 1-PC broadcaster 35 min @6000 → retención exacta, eviction correcta cruzando la rampa uint32, tiempo de tick de Process() y respuesta de UI sin cambio; **cada trigger de purga verificado** (incl. matar el proceso y comprobar que el barrido de arranque limpia); END sin firmar conserva el store, leave lo purga.
**Validación:** 1-PC + 2-PC (captura en viewer a bitrate, incluidos chunks fragmentados 0xE0).

### D2 — Rebobinado local: playlist DVR + UX del player (sin wire — **aquí se entrega la UX central**)
**Alcance:** generador stream_dvr.m3u8 (§3.3); serving por trozos de 64 KB desde offset 126 con fallback seg_→rec_; `GET /api/live/dvr` (doble búfer) + `POST /api/live/dvr/seek` (UM_LIVE_WEB_DVR); página del player: barra DVR, "−10 min"/"−1 min"/"EN VIVO", eje "-MM:SS", swap de fuente y vuelta; keepalive de pausa acotado a 15 min; idle-leave 180 s solo para sesiones DVR.
**Criterios de salida:** 2-PC @6000 — viewer que lleva 12 min pulsa "−10 min": reproducción en <2 s con **cero fetches de red**; lo mismo en VLC de escritorio contra stream_dvr.m3u8; soak de 30 min con playhead aparcado junto al borde de retención (el deslizamiento no mata la reproducción); pausa 5 min + resume OK; pausa >15 min → auto-leave; viewers del borde vivo en stream.m3u8 no afectados; generación de playlist con 900 segmentos <5 ms, cero FindFirstFile.
**Validación:** 2-PC. **Hito shippable: "DVR local" puede publicarse solo con D1+D2.**

### D3 — Plano de servicio: cap bit + OFFER/REQ/DATA/NACK + re-serve V2 literal (wire, solo lado servidor; cap dormante)
**Alcance:** flip CSV a experimental + #defines; 0xB5 emisor (10 s, spans firmados contiguos, will-serve, cesa en END/tombstone/leave) y receptor (m_peerDvrRanges por LivePeerId, TTL); handler 0xB6 (gate por-handler, clamp ≤4, limitador /24 DVR, 1-en-vuelo por peticionario, LRU-o-DvrIoThread, token bucket drenado al final de Process(), IsBusyQuickCheck, salud-vivo-a-cero); 0xB7 literal + 0xE0 InnerOpcode=0xB7; 0xB8 con subrangos; **promoción del re-serve V2 literal al camino LIVE** (OnPeerRequest LiveStreamManager.cpp:1538-1545: si el store tiene el record firmado del seq pedido, servir 0xCC original en vez de V1 — F2); contadores dvr.* totalmente segregados; bit 22 NO OR-eado en g_uEseCapsRuntime (EmuleDlg.cpp:1011-1040) — pref oculta lo anuncia solo en rigs de test. Auditar visibilidad del cap bit a través del swap AttachToAlreadyKnown antes del primer OFFER.
**Criterios de salida:** 2-PC — A emite 15 min con DVR; B (rig) ve los rangos de A; fetch de debug de un chunk de hace 10 min → **verify Ed25519 PASA** contra la pubkey pineada; petición de seq evictado → NACK(0); flood de 0xB6 → RTT vivo plano, contadores /24 vivos intactos, bucket respetado, ignore de 10 min tras abuso, cero bans; **interop legacy**: sesión con build fork previo + vanilla 0.70b sin delta alguno (captura de paquetes: jamás se les envía 0xB5-0xB8); el re-serve V2 vivo: viewer C recibe de B chunks V2 que verifican (primera vez que la malla relayed es verificable); linter exit 0.
**Validación:** 2-PC ×2 (nuevo-nuevo, nuevo-legacy).

### D4 — Fetcher del viewer: catch-up de late joiner (wire completo; **experimental hasta que exista epoch**)
**Alcance:** máquina de estados del cursor DVR en Process() (§3.2 lado cliente: pre-roll, lookahead 60 s, ≤2 en vuelo, mapa propio, timeout 8 s, backoff, caché negativa, rotación de fuentes sobre m_peerDvrRanges prefiriendo el broadcaster para el ancla, pausa dura por degradación del vivo, give-up-and-skip, chequeos tombstone/modo-transporte); enrutado de 0xB7 entrantes al sink DVR (**rechazo de V1 con pin presente** — F2; verificación sig; plausibilidad de seq [bordeVivo−retención, bordeVivo+lookahead] — F3); reensamblador frag DVR (2×12 MB/10 s); cableado del seek de D2 al fetcher; UX "empezar 10 min atrás".
**Criterios de salida:** 3-PC @6000 — A emite, B ve desde t0, C se une en t+10 min y busca t+2 min **obteniendo la historia de B, no de A** (atribución en logs — prueba real de viewer-a-viewer, posible gracias al re-serve V2 de D3); vivo en los 3 PCs en baseline; degradación inducida del vivo → pausa del fetch DVR en ≤2 ticks y recuperación; **gate obligatorio del espiral**: misma topología @12000 kbps con backfill de ventana completa concurrente → sin firma de espiral (RTT EWMA <200 ms sostenido, cero expulsiones/re-inyecciones HLS, contadores dup planos, ráfaga por tick acotada); tiempo-a-primer-frame tras seek de enjambre <15 s @6000.
**Validación:** 3-PC ×2 bitrates. **No se anuncia por defecto pase lo que pase** (F3: riesgo residual de replay entre sesiones documentado; status "stable" requiere epoch, §8.4).

### D5 — DVR tunelizado (paridad de anonimato; **prerequisito: E-α 2-hop bulk validado 3-PC** — stabilize-before-features, no arranca antes)
**Alcance:** TUN_OP 0x60-0x62 en LiveTunnel.h (CSV primero); handler exit vía RegisterExitHandler + BeginExitOperation; store DVR del exit (~5 min, tope propio, session-ephemeral, alimentado por los taps existentes) + proxy-fetch de UN 0xB6 con identidad del exit bajo los presupuestos de D3; entrega por plano bulk con FLAG_DVR → sink DVR en DeliverBulkData; subordinación estricta en el striper del exit; estado del fetch churn-safe frente a rotación de circuitos 5 min y session_id ~10 s (clave (streamKey,seq), no circ_id); rehúse de dial directo en modo Tunelizado forzado en código.
**Criterios de salida:** 3-PC onion (B broadcaster, X exit, V tunelizado) — V rebobina ≥5 min íntegramente por circuitos; **captura de paquetes prueba que B solo ve a X y X jamás aprende la IP de V ni V dialea a nadie**; topes de bytes por-IP del plano bulk no disparados (sin inanición por drops silenciosos — NACK-recovery observado); rotación de circuito a mitad de fetch se recupera; presupuesto de tiempo de Tick del exit @6000 aceptable (FEC+AEAD son main-thread; el offload E8.5 no existe aún); contención multi-viewer tras un mismo exit medida.
**Validación:** 3-PC con captura, nodos físicos distintos.

### D6 — Endurecimiento + decisión de encendido
**Alcance:** soak de 24 h (fugas del DvrIoThread, crecimiento de índice, huérfanos); churn (matar/re-unir peers a mitad de serve; swap LowID — todo estado DVR por LivePeerId verificado); presupuesto adaptativo (encoger cap DVR con upload >70 %); UI de prefs (PPgConnection o página live); notas de release + matriz compat.
**Decisión default-on, requisitos:** (1) D4 gate de 12000 pasado; (2) **epoch en identidad de chunk aterrizado** (coordinado Live V3 0xB4 / beacon R5-R6 — §8.4) → solo entonces CSV a stable y OR incondicional del bit 22; (3) postura de defaults decidida (propuesta: broadcaster-retain default ON en emisión directa — garantiza una fuente firmada profunda por stream — y OFF en modo anónimo/relay; viewers opt-in). Hasta cumplirse los tres, la feature vive como experimental opt-in.
**Validación:** 3-PC mixto (default-on + build fork previo + build era-D3) con interop limpio.

---

## 6. KPIs

| KPI | Objetivo | Dónde se mide | Gate |
|---|---|---|---|
| Delta de comportamiento con pref OFF | 0 (byte-idéntico, wire y disco) | diff A/B logs + captura | D1 |
| Residuo post-crash | 0 bytes tras barrido de arranque | kill -9 + reinicio + inspección %TEMP% | D1 |
| Tiempo de tick Process() con DVR activo | sin cambio vs baseline (±10 %) | telemetría de tick | D1/D3 |
| Latencia de seek local ("−10 min") | <2 s, 0 fetches de red | página player | D2 |
| Generación playlist 900 segs | <5 ms, 0 FindFirstFile | perf log | D2 |
| Verificación Ed25519 de chunk histórico | 100 % PASS en records servidos como 0xB7 | logs verify | D3/D4 |
| RTT EWMA del vivo durante backfill @12000 | <200 ms sostenido | contadores mesh | D4 (gate espiral) |
| Expulsiones/re-inyecciones HLS durante backfill | 0 | contadores HLS | D4 |
| Contadores duplicateChunksReceived / dup PUSH | planos vs baseline post-cb5cc28 | /api/live/metrics | D4 |
| Tiempo-a-primer-frame tras seek de enjambre | <15 s @6000 | cronómetro + logs | D4 |
| Ritmo de catch-up | ≥1,25× tiempo real con capacidad ociosa | bytes/s del fetcher | D4 |
| Fuga de IP del viewer tunelizado | 0 (B nunca ve a V; V nunca dialea) | captura de paquetes | D5 |
| Topes bulk por-IP (25 MB/5 s) disparados | 0 en operación normal | contadores drop | D5 |
| dvrWriteDrops en operación normal | ~0 (solo bajo estrés artificial) | /api/live/debug | D1–D6 |
| Interop legacy (fork previo + vanilla) | delta = 0 | captura de paquetes | D3/D6 |

---

## 7. Riesgos principales

1. **Recurrencia del espiral de carga vía head-of-line TCP**: un frag DVR de 1,4 MB ya encolado retrasa un chunk edge-critical en el mismo socket eD2K. Acotado (1-en-vuelo, IsBusyQuickCheck, drenaje post-vivo, pausa por salud) pero solo demostrable en el gate 3-PC @12000 de D4; fallback = pre-fragmentar serves DVR a ≤512 KB.
2. **Replay entre sesiones (F3)**: hasta que el epoch aterrice, un peer puede servir contenido firmado auténtico del mismo canal pero de una sesión anterior. Acotado a footage propio del canal (no falsificación), mitigado por plausibilidad de seq + wipe por regresión; **bloquea default-on**, no el desarrollo.
3. **Cuello de botella de validación multi-PC** (verdad del proyecto): D3/D4/D5 requieren 2-3 PCs físicos con NAT real; D4 @12000 es históricamente el escenario más difícil de agendar. Mitigación: el código aterriza dormante temprano; D1+D2 solo necesitan 1-2 PCs y entregan la mayoría del valor.
4. **D5 apila sobre el plano bulk 2-hop aún no validado 3-PC** (E-α): secuenciado duro detrás de esa validación; si E-α resbala, los tunelizados tienen rebobinado local (D2) sin backfill — degradación aceptable.
5. **%TEMP% es territorio hostil**: limpiadores/usuarios purgan a mitad de sesión y hay SSDs pequeños. La ventana encoge silenciosamente (el índice tolera ficheros ausentes → NACK no-retenido); tope de 512 MB por defecto + chequeo de espacio libre al habilitar; nunca crash.
6. **Fuga de metadatos del OFFER**: los rangos retenidos revelan cuándo se unió el viewer y cuánto lleva viendo. Mitigado (grano ≤4 rangos, solo a peers cap del mesh, will-serve, jamás gossip, cesa en END, tunelizados jamás OFFERean en plano directo); riesgo residual documentado en el modelo de amenazas.
7. **Profundidad tunelizada estructuralmente fina**: la vista del exit es solo el broadcaster (C7); con broadcaster anónimo retain-off la profundidad puede ser ~0. Se etiqueta honestamente en la UI; ampliarlo (relay-buddy DVR) es pregunta abierta.
8. **Coste main-thread residual**: una copia heap extra por record (~1,5 MB/s @12000) + FEC/AEAD del exit en Tick. Medido en gates D1/D5; el offload E8.5 es la válvula si falla.
9. **Suposiciones de player**: re-anclado de MEDIA-SEQUENCE en hls.js y seeking en VLC son dependientes de versión — el prototipo es criterio de salida de D2, antes de cualquier trabajo de wire.

---

## 8. Interacción con planes existentes

### 8.1 E-α / plano bulk tunelizado (V8.1.1_SPRINT_E_BREAKDOWN.md)
D5 **consume** el plano bulk sin modificarlo: FLAG_DVR en el u8 libre de BulkDataHeader (LiveBulk.h:72), sub-ops 0x60-0x62 junto al bloque 0x50-0x5F de Sprint E, NACK/FEC/striping intactos. Dependencia dura: D5 no arranca hasta que la validación 3-PC de E-α pase. El DVR jamás debe presionar atajos en esa validación.

### 8.2 Invisibilidad offline (OFFLINE_INVISIBILITY_PLAN.md)
- Invariante "sin inferencia de actividad pasada": cumplido por ciclo de vida de sesión + **barrido de arranque** (cubre crash, F1).
- Ley de cachés Fase 0.2: cero datos de endpoint/IP en el store o índice (verificado como criterio D1); canales privados excluidos hasta decisión DPAPI.
- Tombstone 30 min: gate de lectura respetado — replay local de lo ya retenido sí, fetch/dial/anuncio para key tombstoned jamás. NACK reason para post-end = "no-retenido" (un código "tombstoned" confirmaría actividad pasada).
- END sin firmar = hint suave (plan T3): conserva el store local (F4) — un insider no trunca las grabaciones de la malla.
- R5/R6 (beacon de re-attach + epoch): este plan **reserva** el campo epoch en 0xB5 y en el índice, y hace del epoch el prerequisito de "stable" (§8.4). La heurística de regresión de seq es el puente.

### 8.3 Modelo de amenazas del broadcaster (ANONYMOUS_BROADCAST.md)
- Cero caminos nuevos hacia el origen: el fetch DVR solo va a peers ya conectados del mesh o vía exit; jamás Kad plaintext para streams privados/anónimos, jamás re-dial ciego de IPs cacheadas (F3 del plan de invisibilidad), jamás HTTP externo.
- Modo Tunelizado: rehúse de 0xB6 directo forzado en código; el exit fronta con su identidad (contrato ExitProxySubscribe).
- No construir sobre los opcodes 0xE9-0xEC de ANONYMOUS_BROADCAST.md §4.2 (doc obsoleto pre-registro; el relay real es 0xCE/0xCF + bit 21).
- Broadcaster anónimo: propuesta retain-OFF por defecto en ese modo (menos data-at-rest en el origen); pendiente de firma del owner (§9).

### 8.4 Live V3 / BLAKE3 (0xB4, bit 20) — coordinación del epoch
0xB7 se define como "record V2 **o V3** literal" desde el día 0 (el CSV lo pre-declara) para no enmendar el formato. La adición del **epoch al mensaje firmado** (streamKey‖epoch‖seq‖digest) debe viajar con el rediseño V3 en vez de retrofitearse a V2 — un solo cambio de formato de chunk, no dos. Hasta entonces D4 = experimental (F3).

### 8.5 Viewer móvil (MOBILE_VIEWER_PLAN.md, track M)
stream_dvr.m3u8 y /api/live/dvr* heredan el gating por prefijo `/s/{tok}/` sin trabajo extra; el player móvil obtiene la barra DVR con la misma página embebida.

### 8.6 v9 / orden de llegada
Todo el plan se implementa tras la estabilización v9 (decreto). Excepción permitida: D0 (solo docs/CSV/prefs) puede aterrizar antes porque no cambia comportamiento y **fija las reservas de protocolo antes de que otra feature pise la banda 0xB5-0xB8 / bit 22 / 0x60-0x62**.

---

## 9. Preguntas abiertas (decisión del owner, no bloquean D0-D2)

1. **Retain del broadcaster por defecto**: ON en emisión directa (fuente firmada profunda garantizada) / OFF en modo anónimo — ¿confirmar?
2. **Persistencia entre re-joins de la MISMA key** dentro del TTL de tombstone (los cortes de red no borran tu buffer) vs. el invariante limpio "el store muere con la sesión". Propuesta: conservar sí y solo sí misma key + continuidad de borde vivo verificada.
3. **DPAPI para canales privados**: ¿levantar la exclusión de §1.3 sellando .rec + índice (coste CPU en DvrIoThread), o mantener DVR-off para privados indefinidamente?
4. **DVR vía relay-buddy (0xCE/0xCF)** para broadcasters CGNAT/anónimos: ¿sub-op DVR-forward en v2 del plan, o los viewers se bastan entre sí?
5. **Nivel de soporte VLC crudo**: ¿oficial con matriz de versiones, o "página embebida + móvil" oficial y VLC best-effort?
6. **Defaults de retención** (512 MB / 10 min): validar contra discos reales en D2/D4; ¿UI en minutos derivados del bitrate observado?
