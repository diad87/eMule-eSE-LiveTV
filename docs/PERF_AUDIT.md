# Auditoría de rendimiento y corrección — cpp a cpp

Objetivo: revisar los ~290 .cpp del proyecto por tiers de impacto (CPU, RAM, velocidad
de conexión), arreglando solo lo claramente roto o lo verificado con números.
Regla de oro: compat wire/fichero con eMule 0.70b vanilla y versiones previas del fork
es OBLIGATORIA; estabilizar, no reescribir.

Metodología: 6 agentes de revisión en paralelo con checklist (CPU/RAM/NET/BUG) por
grupo de ficheros; cada hallazgo "aplicable" se re-verifica a mano sobre el código
antes de tocar nada. Hallazgos especulativos o sin frecuencia real → descartados.

Estados: `APLICADO` (fix en el árbol) · `PENDIENTE` (fix claro, falta decisión o
diseño cuidadoso) · `DOC` (ineficiencia real pero solo se toca con números de
profiler) · `WONTFIX` (coste estructural, no compensa).

---

## Línea base de medición (pendiente de ejecutar — necesita máquina real)

Apuntar cifras ANTES de seguir aplicando optimizaciones (los bugfix no la necesitan):

1. **Idle conectado**: 10 min con Kad + servidor + compartidos típicos → RAM (private
   bytes), CPU media (Task Manager), nº hilos.
2. **Transferencia a tope**: descarga+subida saturadas 5 min → CPU, y perfil con
   VS Performance Profiler (Release x64) para ver el top-10 de funciones.
3. **Sesión LiveTV**: emitir + ver con túneles activos → RAM/CPU del proceso.

---

## Lote 1 — sockets + throttler (revisado 2026-06-11)

Ficheros: UploadBandwidthThrottler, EMSocket, ListenSocket, BaseClient(+UpdownClient.h),
EncryptedStreamSocket, EncryptedDatagramSocket, AsyncSocketEx, AsyncSocketExLayer,
ClientUDPSocket, Packets, SafeFile (+UploadQueue.cpp:494 por arrastre).

### APLICADO (2026-06-11, compila pendiente de validar en runtime)

| Fichero | Bug | Fix |
|---|---|---|
| ClientUDPSocket.cpp:474 | Fuga de `sendbuffer` en cada SendTo would-block (regresión del "BUG-013 FIX"; con uplink saturado fuga en cada tick del throttler) | `delete[] sendbuffer` antes del `break` |
| UploadQueue.cpp:494 | `GetWaitingClientByIP_UDP` perdió el `dwIP == cur_client->GetIP()` del segundo if (cf. gemelo DownloadQueue.cpp:1128): reasks UDP de IPs desconocidas se atribuían a otro cliente | restaurada la condición de IP |
| AsyncSocketEx.cpp:312 | `pSocket->m_nPendingEvents = 0` incondicional tras `OnConnect()` que puede borrar el socket → write-after-free (el guard netfinity solo cubría el dispatch) | clear movido dentro del guard de revalidación de slot; revalidación también entre OnReceive y OnSend |
| AsyncSocketEx.cpp:439-448 | Mismo patrón sin guard en el camino WM_SOCKETEX_TRIGGER (capas/proxy): GetState() + write tras posible borrado en OnConnect | mismo guard de revalidación de slot |
| EMSocket.cpp:259 | `static thread_local char[2000000]`: el TLS implícito committea 2 MB en CADA hilo del proceso (decenas de hilos → decenas de MB) | puntero thread_local con alloc perezosa; solo pagan los hilos que reciben |
| BaseClient.cpp:1591 | Comparación de ticks sin protección de wrap (49,7 días) en cooldown de hole-punch | patrón resta estándar (como la línea 1579) |
| UpdownClient.h:66 | `ResetConnectingState()` era stub vacío: tras error transitorio uTP el cliente quedaba fuera de la lista de connecting pero con estado CCS_* → "Already Connecting" para siempre (fuente inerte toda la sesión) | implementa `m_eConnectingState = CCS_NONE` |
| EncryptedStreamSocket.cpp:100 | Ofuscación de servidor ROTA desde el import pre-Claude (no documentado en CHANGES_FROM_EMULE_0.70b.md): DH subido a dh2048/256 bytes a medias cuando el wire eD2K es de 96 — el handshake nunca completaba y `ONS_BASIC_SERVER_DHANSWER` metía 160 B de heap sin inicializar en el material de clave | restauradas constantes upstream `dh768_p`/`PRIMESIZE_BYTES 96` (verificadas byte-exactas contra irwir/eMule); eliminado `dh2048_g` muerto |

### PENDIENTE — decisión del usuario o diseño cuidadoso

1. **EMSocket.cpp:1179-1191 (`CleanUpOverlappedSendOperation(true)`)** — espera sobre
   el hEvent COMPARTIDO del throttler, ignora el resultado de WSAGetOverlappedResult y
   libera `m_aBufferSend` con el CancelIo posiblemente aún en vuelo → UAF/corrupción.
   Fix: poll acotado de WSAGetOverlappedResult sin tocar el evento compartido; liberar
   solo cuando ya no esté WSA_IO_INCOMPLETE. Necesita diseño+prueba con cuidado.
2. **ListenSocket.cpp:81-92 — fuga del layer uTP por conexión** — `CUtpSocket` nunca
   se borra en la ruta de éxito (RemoveAllLayers solo anula punteros) y queda huérfano
   en `theApp.g_UtpSockets`, que se itera cada tick. Fix: override de
   `CClientReqSocket::RemoveAllLayers()` espejo del de CEMSocket (borra m_pProxyLayer).
3. **ListenSocket.cpp:2550 — bypass de filtro IP en accept condicional bajo dual-stack**
   — `AcceptConnectionCond` castea a SOCKADDR_IN sin mirar la familia: con listener v6
   el filtro evalúa 0.0.0.0. Mismo barrido que el fix GetPeerAddressV4 en curso —
   incorporarlo a la validación 2-PC de IPv6PreferredMode.
4. **Throttler a 15,6 ms** — UploadBandwidthThrottler.cpp:512-535: el bucle asume tick
   de 1 ms pero `HighresTimer` default=false → el caudal sale en ráfagas de rate×15ms.
   Opciones: timeBeginPeriod(1) dentro de RunInternal, o default a true. Tiene coste
   energético (timer global de Windows a 1 ms). Decisión de producto.

### DOC — optimizaciones reales, tocar solo con números de profiler

- UploadBandwidthThrottler.cpp:398-404: `IsBusyExtensiveCheck()` por slot y tick ≈
  N×1000 syscalls/s. Candidato nº1 si el profiler señala el hilo del throttler.
- UploadBandwidthThrottler.cpp:570-702: `sendLocker` retenido durante toda la fase de
  envío (incl. RC4) — acopla latencia de UI al envío; getters de stats podrían pasar a
  Interlocked*.
- UploadBandwidthThrottler.cpp:385-390: lectura sin lock de `IsViewingLive()`/bitrate
  desde el hilo del throttler (carrera benigna en x64; documentada).
- EMSocket.cpp:838-856: revert de contadores tras fallo de WSASend puede doble-contar
  créditos (ventana mínima, solo en error fatal).
- EMSocket.cpp:1201-1210: `IsEnoughFileDataQueued` recorre la cola sin `sendLocker`
  (carrera real heredada de upstream; fix barato = tomar el lock; medir coste).
- EMSocket.cpp:282-293: con WSAESHUTDOWN, `downloadLimit` puede dar la vuelta (uint32)
  y desactivar el límite de bajada de ese socket ~100 ms.
- BaseClient.cpp:1634: null-deref heredado si cliente Kad-lowID con `m_reqfile==NULL`
  recibe petición de chat/filelist (guard de una línea; aplicar en lote 1.1).
- BaseClient.cpp:88-93: `IsEseClient()` hace 2 allocs de CString por CADA paquete del
  rango Live (gate de ListenSocket.cpp:885) — cachear bool al asignar m_strModVersion.
- BaseClient.cpp:742-744: CString+Remove+MakeUpper por handshake cuyo consumidor está
  comentado desde upstream — borrar.
- BaseClient.cpp:1577-1588: `s_lastSymNatLog` static global infra-cuenta el contador
  de symmetric-NAT de /api/status.
- UpdownClient.h:58-75: stubs NAT-T (`IsHelloAnswerPending` false fijo, etc.) dejan
  muerto el retry NAT-T de UtpSocket.cpp:540-624 — pertenece al track
  LOWID_NAT_TRAVERSAL_PLAN, no tocar aquí.
- ListenSocket.cpp:1958-1961: cada OP_LIVE_HEARTBEAT construye hex string + lock + map
  lookup aunque no seas exit — early-out barato en LiveTunnel.
- ListenSocket.cpp:885-888: argumentos de DebugLogWarning (GetPeerName + Formats) se
  construyen aunque verbose esté apagado — envolver en `if (thePrefs.GetVerbose())`.
- ListenSocket.cpp:1846-1854: SHA-256 de chunks de hasta 4 MB en el hilo del pump —
  diferir a worker SOLO si se observan stalls.
- ListenSocket.cpp:1789 + opcodes.h:298,301: comentarios de formato wire NO coinciden
  con el código (seq→timestamp→chunkSize; no existe el campo Score) — corregir docs.
- EncryptedStreamSocket.cpp:206-217: si WSASend falla inmediato, el handshake diferido
  de servidor se pierde sin regeneración posible (conexión muerta hasta timeout).
- EncryptedDatagramSocket.cpp:399-400: `DecryptReceivedServer` corrompe el buffer in
  situ si el magic no casa (el camino cliente L232 lo hace bien con variable local).
- AsyncSocketEx.cpp:859-863: `FreeAsyncSocketExInstance` borra el TLS del hilo que
  destruye, no del que creó el socket (latente: destrucción cross-thread).
- AsyncSocketEx.cpp:793-820+497: `Close()` no retira de `layerCloseNotify` → FD_CLOSE
  espurio si el objeto se reutiliza en <10 ms; drenaje de 1 socket/tick (100/s máx).
- AsyncSocketEx.cpp:378-379, 210-211: fuga de `t_LayerNotifyMsg` en rutas casi
  inalcanzables (return/continue sin delete).
- AsyncSocketExLayer.cpp:344-345: avance incorrecto del cursor de direcciones en
  reintentos proxy+AF_UNSPEC (reintenta direcciones ya falladas).
- ClientUDPSocket.cpp:497: `ipstr()` + re-parseo de inet_addr por CADA datagrama
  enviado — pasar SOCKADDR_IN directo.
- ClientUDPSocket.cpp:459: heap alloc por paquete UDP enviado — buffer fijo candidato.
- ClientUDPSocket.cpp:453,533: cola UDP sin purga mientras IsBusy() (caducidad solo se
  evalúa al enviar) — tope/purga en SendPacket.
- ClientUDPSocket.cpp:250→UploadQueue.cpp:490: búsqueda O(cola) por REASKFILEPING
  (amplificable por flood) — índice por IP solo si el profiler lo señala.
- Packets.cpp:205: `PackPacket` con Z_BEST_COMPRESSION (nivel 9) en hilo principal
  para source-exchange/Kad; el camino de datos ya usa nivel 1 — bajar a 6 o 1 (zlib es
  autodescriptivo, compat OK). Candidato fácil tras medir.
- Packets.cpp:88: `new char[size+10]{}` zero-inicializa ~10 KB por paquete de upload
  que se sobreescribe entero — quitar `{}` tras verificar llamadores.
- SafeFile.cpp:251: `CSafeFile::Read` hace 2 syscalls extra por lectura (GetPosition+
  GetLength); AICH recorre known2.met con lecturas de 1-20 bytes → replicar el patrón
  de CSafeBufferedFile (el propio fichero lo llama "terrible slow").
- SafeFile.h:97: paso de crecimiento de CSafeMemFile = 512 B → reallocs encadenados al
  serializar KBs.

### WONTFIX

- Packets.cpp:107-109 (copia desde CSafeMemFile: el header de 6 bytes debe preceder al
  payload); Packets.cpp:462,477 (alloc por CTag string: lo impone la union);
  AsyncSocketEx GETHOST scan lineal (solo conexiones por hostname); RC4 byte a byte
  (es el algoritmo); descarte de 1024 bytes de keystream (lo manda el protocolo);
  serialización por ventana de mensajes (modelo WSAAsyncSelect estándar).

### Limpieza pendiente (denegada por permisos en sesión)

- Borrar `srchybrid/PartFile.utf8.cpp` y `srchybrid/WebServer_original.cpp`: no están
  en ningún .vcxproj ni los referencia nadie — restos muertos.

---

## Lote 2 — disco y hashing (revisado 2026-06-11)

Ficheros: PartFile, KnownFile(+List), SHAHashSet/AICHSyncThread, UploadDiskIOThread,
PartFileWriteThread, SharedFileList (+DirectoryWatcher eSE por arrastre).
NOTA: durante la revisión aterrizó en el working tree la implementación H1 del track H
(PartHashThread) desde otra sesión — los fixes que tocan PartFile.cpp quedan EN ESPERA
para no pisar ese trabajo.

### APLICADO (2026-06-11, ficheros no tocados por H1)

| Fichero | Bug | Fix |
|---|---|---|
| KnownFile.cpp:222 | Off-by-one upstream: la parte 0 nunca se acumulaba en m_AvailPartFrequency → el mínimo de fuentes completas era siempre 0 y la barra de disponibilidad pintaba mal la parte 0 | `--i >= 0` (como su gemelo PartFile.cpp:2594) |
| SHAHashSet.cpp:797+806 | LoadHashSet leía known2.met con CSafeFile sin búfer: 3 syscalls por hash ≈ 70.000 syscalls por petición AICH de un peer (fichero 4 GB), en el hilo principal, spameable | `CSafeBufferedFile` + `setvbuf` 16 KB (patrón KnownFileList.cpp:77); flags `modeRead` (sin modeCreate: semántica distinta en CStdioFile); reducción >2.000× de syscalls |
| SHAHashSet.cpp:672 | ReadRecoveryData (datos de peer NO confiables): el bucle iteraba nHashsToRead aunque el peer declarase 0 hashes → inserción de hojas basura en el árbol | límite del bucle = nHashesAvailable |
| SHAHashSet.cpp:866 | `nHashCount * HASHSIZE` desbordaba en uint32 con count corrupto y burlaba el check de EOF | cast `(ULONGLONG)` (como AICHSyncThread.cpp:83) |
| AICHSyncThread.cpp:70,88 | `nLastVerifiedPos` uint32: con known2.met >4 GB y corrupción detectada, SetLength truncaba a la posición módulo 2³² → pérdida masiva de hashsets válidos | `ULONGLONG` |
| SharedFileList.cpp:1306 | Publish Kad: deref del puntero a fichero ANTES de validarlo con IsFilePtrInList — UAF en Release con refs obsoletas (el JOHNTODO de la línea 1300 las admite) | orden invertido: validar primero |
| SharedFileList.cpp:220-225 | `SetNextPublishTime(MIN2S(30))` fijaba tiempo ABSOLUTO 1800 (= año 1970): cada fichero añadido/Reload marcaba sus keywords como "publicable ya" → republicación masiva en Kad tras cada Reload | `time(NULL) + MIN2S(30)` (en condición y asignación) |
| PartFileWriteThread.cpp:181 | ASSERT con `=` en vez de `==` (asignaba en Debug, no verificaba nada) | `==` |

### APLICADO (2026-06-11, paquete threading hilos de disco)

| Bug | Fix |
|---|---|
| GQCS FALSE mataba los hilos de disco (UploadDiskIOThread.cpp:94, PartFileWriteThread.cpp:79): I/O fallida/cancelada tratada como orden de terminar | helper `DequeueCompletionPacket` en ambos .cpp: paquete desencolado con FALSE → se enruta a la completion routine con 0 bytes; solo termina con dequeue vacío |
| Cleanup de shutdown liberaba OVERLAPPEDs con IRPs aún en vuelo (UploadDiskIOThread.cpp:129, PartFileWriteThread.cpp:112) | cerrar los handles (cancela las IRPs) y DRENAR el puerto (timeout 10 s) antes de liberar; las completion routines hacen ahora el RemoveAt de m_listPendingIO incondicionalmente |
| UAF al cancelar descarga con buffers: ~CPartFile liberaba buffers aún referenciados por el write thread | `m_iWrites` pasa a `volatile LONG` interlocked y se cuenta AL ENCOLAR en FlushBuffer (cierra la ventana de m_listToWrite); nuevo `CPartFileWriteThread::PurgeQueuedWrites()`; DeletePartFile purga + aplaza con m_bDelayDelete mientras `m_iWrites>0 \|\| nInUse>0` (retry vía StopPausedFile); purga también en ~CPartFile; guard m_bDelayDelete en ResumeFile (cerraba también el limbo del aplazamiento por file-op) |
| `--nInUse` al PRINCIPIO de ReadCompletionRoutine → UAF con lecturas en vuelo | decremento movido al final (último uso del objeto); DeletePartFile toca el lock de la uploadlist como barrera (las lecturas se emiten y cuentan bajo ese lock) y aplaza mientras nInUse>0 |
| `GetFileByID` sin lock desde el hilo de disco (UploadDiskIOThread.cpp:213) | `TryEnterCriticalSection(m_mutWriteList.m_sect)` — nunca bloquear con el lock de la uploadlist cogido (orden #2→#3 de DownloadQueue.h); si falla, return y reintento al siguiente wakeup |
| `SetLength` sobre m_hpartfile desde el write thread (PartFileWriteThread.cpp:186): movía el file pointer compartido bajo Seek/Read del principal y CFileException sin catch | truncado por `m_hWrite` propio (SetFilePointerEx+SetEndOfFile), error → log |
| m_hWrite cerrado desde 2 hilos (PartFileWriteThread.cpp:225 vs ~CPartFile) | resuelto por construcción: el destructor solo se alcanza con m_iWrites==0 (sin actividad del write thread para ese fichero); en shutdown los hilos paran antes de los dtors (EmuleDlg.cpp:2176) |
| Contador m_iWrites se filtraba en escrituras con error (sin decremento en PB_ERROR ni en rutas de error de WriteBuffers) → el fichero no completaba jamás tras un error de escritura | decremento en TODAS las rutas (completion ok/error/shutdown, WriteFile inmediato, AddFile fallido, purga); allocation-request ya no se fuga en rutas de error (delete si data==NULL) |

APLICADO (2026-06-12): **pérdida de datos en buffer al cerrar** — EndThread del
write thread (EmuleDlg.cpp, OnClose) corría ANTES del dtor de downloadqueue; el
FlushBuffer de ~CPartFile no puede encolar (IsRunning()==false) y los PB_READY se
descartaban (también lo ya encolado en m_FlushList/m_listToWrite, que EndThread
suelta sin escribir), pero FillGap se registró al BUFFERIZAR (WriteToBuffer) y
SavePartFile persistía el .met como si estuvieran en disco → corrupción silenciosa
de hasta ~FileBufferTimeLimit de datos por fichero al salir. Fix: en OnClose, antes
de EndThread, FlushBuffer(false,true,true) de todos los part files (espejo del dtor)
y drenaje del write thread esperando `m_iWrites == 0` en todos los ficheros (poll
10 ms, timeout 10 s). Sin contabilidad nueva: m_iWrites se cuenta al encolar y se
decrementa como último uso en todas las rutas (ok/error/purga), así que 0 en todos
≡ nada encolado ni en vuelo. Se descartó la alternativa (escritura síncrona en el
dtor): no cubre lo encolado que EndThread descarta y rescribir PB_PENDING con
referencias vivas en m_FlushList arriesga UAF contra PurgeQueuedWrites.

### PENDIENTE lote 2 — diseño cuidadoso o en espera de H1

4. **WebServer.cpp:1548-1586: operaciones de fichero en el hilo worker** —
   Stop/Pause/Resume/**Delete**/SetPriority/SetCategory ejecutados directamente en el
   worker del webserver (DeletePartFile hace `delete this`): mismo patrón que se
   remedió en /api/live (2026-05-21). Marshalear vía WEB_GUI_INTERACTION como el rename.
5. **PartFile.cpp:5209 CopyPartFile `min()` invertido** — `min(uStart - fill.end, …)`
   con operandos cambiados: copia basura al preview y posible bucle infinito al 100% de
   un core. Fix de una línea: `min(fill.end - uStart, (uint64)sizeof buffer)`.
   EN ESPERA de H1.
6. **PartHashThread.cpp:120-125 (H1, para la sesión del track H)** — si el
   PostMessage(TM_PARTHASHED) falla, la entrada de m_mapPendingHashParts queda huérfana:
   la parte no se re-encola jamás y el fichero no puede completarse.
7. **LoadHashSet sin m_mutKnown2File** (SHAHashSet.cpp:786) vs compactación del
   AICHSyncThread: lectura de fichero a medio compactar + data race sobre
   m_mapAICHHashsStored. Fix: Lock con timeout corto y return false.
8. **CKnownFileList sin lock** — AICHSyncThread escribe m_mapKnownFilesByAICH y lee
   m_Files_map mientras el hilo principal inserta (SafeAddKFile): crash esporádico.
   Fix: CCriticalSection alrededor de los dos mapas.

### DOC lote 2 — optimizaciones reales, tocar solo con números

- PartFile.cpp:1895: UpdateCompletedInfos (re-suma del gaplist COMPLETO) por CADA
  paquete recibido — redundante con la del timer cada 3 s. Candidato nº1 de CPU.
- PartFile.cpp:2211: FlushFileBuffers síncrono en hilo principal cada ~31 s por fichero
  (micro-congelaciones con muchas descargas) — mover al write thread.
- PartFile.cpp:4255: SavePartFile sin dirty-flag (reescritura .met + CopyFile del .bak
  cada ≤29-60 s aunque nada cambie).
- PartFile.cpp:4989-5012 (eSE): orden secuencial+última parte para TODO previewable —
  con SparsePartFiles=off, zero-fill del fichero ENTERO al inicio de cada vídeo, y
  anula rarest-first; condicionar a streaming activo.
- PartFile.h:296: ClearStreamSeek() sin llamadores — modo seek pegado para siempre.
- PartFile.cpp:4209/5509: hash ICH/AICH síncrono restante (extensión futura de track H).
- PartFile.cpp:2575: UpdatePartsInfo O(fuentes×partes) por file-status — throttle 1/s.
- PartFile.cpp:4052: sin backpressure de buffers con disco lento (USB/SMB) + re-flush
  completo por paquete al superar el umbral.
- KnownFile.cpp:218-228: acumulación de frecuencias O(cola×partes) en cada llamada
  (mover bajo bRefresh); :1055 CreateSrcInfoPacket O(cola×partes) por OP_REQUESTSOURCES
  (acotar candidatos); :643 m_AvailPartFrequency reservado para TODO known.met;
  :638 wordlist retenida por entrada; :692 clamp faltante en FT_KADLASTPUBLISHNOTES.
- KnownFileList.cpp:272: Save() reescribe known.met+cancelled.met cada 11 min sin
  dirty-flag; :198 truncado sin escritura atómica (corte de luz pierde known.met);
  :110 entrada corrupta aborta la carga del resto y el Save lo consolida (pérdida
  permanente — candidato a fix temprano); :209 sin purga de entradas + todo residente
  en RAM; :338 FindKnownFile lineal por fichero escaneado; :59 tabla hash 2063 fija.
- SHAHashSet.cpp:45: m_mapAICHHashsStored sin InitHashTable (17 cubetas); :586 árbol
  completo reconstruido por petición AICH (caché TTL opcional tras medir).
- AICHSyncThread.cpp:117-161: escenario upgrade hace scans lineales con m_mutWriteList
  retenido minutos; SaveHashSet con timeout 5 s pierde el hashset sin reintento.
- UploadDiskIOThread.cpp:422: compress2 init/end completo por bloque (z_stream
  persistente + deflateReset); :230 sin caché de bloques comprimidos — N peers = N
  lecturas+compresiones del MISMO bloque (relevante para fanout LiveTV); :148
  CreateFile síncrono bajo el lock del uploadlist (disco dormido congela la UI);
  FILE_FLAG_SEQUENTIAL_SCAN con patrón aleatorio multi-peer; :478 wakeup perdido
  (m_bNewData sin Interlocked) — micro-cortes.
- PartFileWriteThread.cpp:148/190: fuga del allocation-request en rutas de error.
- SharedFileList.cpp:194: FindKeyword lineal — arranque/Reload O(N·W·K), congelación de
  segundos con ~10k ficheros (índice CMap paralelo); :821 inserción ordenada O(k²) en
  SendListToServer; :1559 FindKnownFile lineal (índice en KnownFileList); :535 escaneo
  de directorios 100% síncrono en hilo principal; :493 buckets de m_Files_map (1031) y
  m_UnsharedFiles_map (17).
- eMuleAI/DirectoryWatcher.cpp:188 (eSE): hashea ficheros a medio copiar (hash inválido
  publicado o fichero sin compartir, sin reintento); :127 no detecta directorios
  añadidos en caliente.
- ListenSocket.cpp:706: OP_ASKSHAREDFILES sin rate-limit (mitigado por vsfaNobody).
- Packets.cpp:88: zero-init de ~190 KB/bloque en paquetes de upload (ya anotado lote 1).

## Lote 3 — colas y timers (revisado 2026-06-11)

Ficheros: DownloadQueue, UploadQueue, ClientList+ClientCredits, ServerList,
RoutingZone+Indexed (Kad). Frecuencia clave verificada: el timer global corre a
**100 ms** (UploadQueue.cpp:85), no 1/s — Process() de descargas/subidas va a 10 Hz.

### APLICADO (2026-06-11)

| Fichero | Bug | Fix |
|---|---|---|
| ClientCredits.cpp:215 | **Heap overflow real**: `nKeySize` (uint8, hasta 255) sin validar al cargar clients.met; `InitalizeIdent` hace memcpy de hasta 255 B sobre buffers de 80 B (y `CreateSignature` desborda un buffer de pila de 89 B) | clamp a MAXPUBKEYSIZE→0 tras el Read |
| ClientCredits.cpp:208 | `count` corrupto → `InitHashTable(count+5000)` de GB → CMemoryException no capturada (crash en arranque) | cap por tamaño real del fichero |
| ServerList.cpp:353 | UAF alcanzable desde la UI: "Quitar todos" no anulaba `cur_udpserver` (RemoveServer sí); `SendNextUDPPacket` lo deref'encia ≤1 s después | anular como RemoveServer (con guard de arranque) |
| ServerList.cpp:240-251 | El trigger zero-config eSE (fork) saltaba en CADA arranque: `AddServerMetToList` vacía la lista y el primer servidor parseado cumple `GetCount()==1` → conectaba a mitad de parseo saltándose la selección por prioridades + log falso de "discovered via Kad" | flag `m_bLoadingMet` durante el parseo |
| ServerList.cpp:876 | Wrap de ticks: cerca del wrap de 49,7 días reescribía server.met **cada segundo durante 17 min** | resta unsigned |
| DownloadQueue.cpp:364 | Poda de `average_dr_list` no wrap-safe: tras 49,7 días la lista crece ~10 entradas/s para siempre (30-50 MB/día) y falsea `m_datarate` | resta unsigned |
| DownloadQueue.cpp:405,413,420,1005 | Mismo patrón de wrap en stats UDP, búsqueda global, A4AF y check de disco (timers congelados hasta 49,7 días tras el wrap) | resta unsigned |
| DownloadQueue.cpp:670 | `UpdateAvailablePartsCount()` se ejecutaba para TODOS los ficheros de la cola en cada eliminación de fuente (solo cambia el que la pierde); RemoveSource corre continuamente | movido dentro del `if (pos2)` |
| DownloadQueue.cpp:922,990 | Violación del contrato de lock v7.4.0 del propio fork: la rotación de filelist (SendNextUDPPacket) y `SortByPriority` (3 call-sites) mutaban la lista SIN `m_csFilelistMainThrdWriteOtherThrdsRead` mientras los workers del webserver iteran bajo el lock → crash esporádico | lock en la rotación + lock dentro de SortByPriority (CS recursiva: AddDownload que ya lo tiene sigue bien) |
| RoutingZone.cpp:687,719,723 | UAF latente upstream: en Split/Consolidate, contacto rechazado por el bin fusionado se borraba sin comprobar `InUse()` — una CSearch activa que lo retiene queda con puntero colgante (exposición cada 45 min) | borrar solo si `!InUse()` (fuga diminuta en vez de UAF) |
| Indexed.cpp (AddSources) | Sin tope global del índice de fuentes: un remoto puede publicar keyIDs distintos sin límite (el cap KADEMLIAMAXENTRIES solo existía para keywords) | mismo check que AddKeyword:371 |
| Indexed.cpp (AddNotes+Clean) | `m_mapNotes` NUNCA expiraba (lifetime=0 y Clean() no recorría notas) → crecimiento monótono toda la sesión | lifetime = 24 h al añadir + pasada de notas en Clean() |
| Indexed.cpp:273 + Kademlia.cpp:Process | `Clean()` solo se disparaba al recibir búsquedas: un nodo con publishes pero pocas búsquedas se clava en el cap 30+ min rechazando todo | Clean() desde CKademlia::Process (auto-limitado 30 min) + guard m_bDataLoaded |
| Entry.cpp:390 | Paréntesis mal puesto upstream: `(tNow < X) + 14400` siempre true → todo republish era "FastRefresh" y el índice de popularidad de nombres no contaba nunca | `tNow < X + 14400` (lo aplicó el agente revisor; verificado) |

### PENDIENTE lote 3 — diseño con medición

1. **Índice IP→cliente en DownloadQueue/ClientList** — resuelve de una vez los 3
   barridos O(ficheros×fuentes) por evento de red (CheckAndAddSource por fuente nueva,
   GetDownloadClientByIP_UDP por paquete UDP spoofeable, RemoveSource por desconexión)
   y los lineales de ClientList (AttachToAlreadyKnown por HELLO, Add/RemoveClient por
   alta/baja, familia FindClientBy*). El mayor win de CPU del Tier 2; requiere
   mantener índices coherentes en todas las altas/bajas — sesión propia.
2. **clients.met / known.met sin escritura atómica + sin dirty-flag** — ambos se
   reescriben enteros por timer (13/11 min) aunque nada cambie, con `modeCreate`
   (truncado): un corte a mitad pierde el fichero; el .bak de credits nunca se
   restaura solo. Paquete "guardado atómico" para clients.met/known.met/server.met/
   nodes.dat/key_index.dat (todos el mismo patrón tmp+MoveFileEx).

### DOC lote 3 — optimizaciones con números

- UploadQueue.cpp:182-195: AddUpNextClient hace 2 pasadas O(cola≈6.250) por slot
  abierto (hasta 10/s con subida >100 KiB/s) — fusionar máximo-de-restantes en
  FindBestClientInQueue; :853 GetWaitingPosition 2×O(N) por reask (3 pasadas O(N) por
  paquete sumando GetWaitingClientByIP_UDP) — fusionar en una pasada; :122/443/828
  wraps de tick; :930 SearchClipboard cada 1 s (deuda upstream reconocida — pasar a
  AddClipboardFormatListener).
- ClientList.cpp:217: AttachToAlreadyKnown no corta al hacer match por hash (escanea
  los n clientes SIEMPRE); :825 CleanUpClientList O(k·n) cada 34 min; :198 (fork)
  RebuildPeersCache hace 2 GetConnectedSnapshot completos por segundo — fusionar en
  una pasada; :383 m_ItemsList por IP crece sin cap individual (NAT carrier/adversario).
- ClientCredits.cpp:287: SaveList cada 13 min sin dirty-flag; :275 mapa de créditos
  sin purga en sesión (~250 B × cientos de miles con churn alto).
- DownloadQueue.cpp:528: CheckAndAddSource O(N×ficheros×fuentes) por ráfaga de
  fuentes (cubierto por PENDIENTE 1); :616 CheckAndAddKnownSource ídem; :967
  SortByPriority O(n²·log n) por FindIndex sobre CList (solo importa con cientos de
  descargas); :534/621 A4AF sin límite (cap = GetMaxSources del fichero).
- ServerList.cpp:616: SaveServermetToFile O(n²) por FindIndex; :224 merge O(n²) en
  carga; :156 fuga de 1 CServer por entrada corrupta.
- Indexed.cpp:632: SendValidKeywordResult hasta 2 pasadas × 50k entradas por búsqueda
  entrante con uStartPosition hostil (clamp rompería paginación legítima — medir
  antes); :68 InitHashTable(1031) para mapas de hasta 60k claves; :479 publish de
  fuente recorre lista de hasta 1001 nodos.
- RoutingZone.cpp:342: nodes.dat truncado no atómico (1 vez por sesión, ~7 KB —
  bajo riesgo); índices .dat de CIndexed ídem pero de decenas de MB (en PENDIENTE 2).
- AICHSyncThread/SaveHashSet, FindKeyword, FindKnownFile: ver DOC lote 2.

## Arranque — congelón de UI antes de habilitar "Conectar" (revisado 2026-06-12)

Síntoma reportado: al arrancar la app "le cuesta, como si fuera a crashear" y el
botón de conectar tarda varios segundos en poder pulsarse.

### APLICADO (2026-06-12)

| Fichero | Bug | Fix |
|---|---|---|
| FirewallProberV6.cpp:51 | `ProbeAsync()` era 100% **síncrono** en el hilo de UI: GET HTTPS a api6.ipify.org (WinHTTP, timeouts 5 s por fase + DNS AAAA fría ~1 s + WPAD) dentro del paso 4 del StartupTimer, ANTES de `EnableButton(TBBTN_CONNECT)` (EmuleDlg.cpp:1035). Mientras corre no se bombean mensajes → ventana "No responde" + botón de conectar bloqueado. Corre por defecto (IPv6Mode default = Auto desde Sprint 9) | cascada movida a worker thread (`AfxBeginThread`, BELOW_NORMAL); guard de reentrada `InterlockedExchange`; `m_eLayer`/`m_detectedIP` bajo `CCriticalSection` (los leen UI/NetworkInfoDlg/WebServer); guard `theApp.IsClosing()` al loguear el veredicto |
| Preferences.h:728 | Comentario obsoleto ("default = IPv4Only") contradecía el flip deliberado a Auto del Sprint 9 (Preferences.cpp:74) — indujo a pensar que el default era un bug | comentario corregido; el default Auto se mantiene (decisión intencional documentada) |

Nota: el escalonado del StartupTimer (300 ms/paso, ~1 s mínimo hasta habilitar
Conectar) es diseño upstream y se mantiene. Contribuyentes menores no tocados:
auto-spawn de ese-server.exe en OnInitDialog (CreateProcess de ~40 MB + AV),
known.met/ipfilter.dat síncronos pre-ventana (hoy pequeños/ausentes), paquete
desplegado bajo OneDrive (IO amplificada).

## Próximos lotes

- **Lote 4 (código nuevo del fork)**: LiveTunnel, LiveCoverTraffic, LiveOnionCrypto,
  LiveMeshManager, WebServer (271 KB), KadV2TunnelPool. OJO: varios en edición activa
  por otras sesiones (WebServer, LiveTunnel, LiveStreamManager) — coordinar antes.
- **Lote 5 (Tier 3 UI)**: DownloadListCtrl, SharedFilesCtrl, StatisticsDlg, TransferWnd.
