# Plan adicional de extracción para desbloquear M2

Fecha: 30 de julio de 2026  
Estado: `BLOCKED` hasta cumplir los límites M2; este documento no rebaja ni
autoriza excepciones a los límites.  
Revisión de arranque: `PASS`, Sol/high independiente, 0 P0–P2.  
Ámbito: reducción mecánica y verificable de `CLiveTunnel`, `CWebServer` y
`CLiveStreamManager`, sin cambio de wire, persistencia ni comportamiento.

## 1. Decisión y evidencia que obliga al plan

`MOD-5.2` no puede cerrar con la extracción realizada hasta ahora. La métrica
contractual es **LOC físico de todos los bytes fuente**, igual que la usada por
MOD-0.1/MOD-0.4. No existe una exclusión para tablas, bloques generados,
strings grandes ni activos embebidos; por tanto no se puede descontar ninguno
para alcanzar el objetivo.

| Coordinador | Actual | Límite duro | Déficit | Campos mutables actuales/límite | Funciones >150 |
|---|---:|---:|---:|---:|---:|
| `LiveTunnel.cpp` | 10.361 | 4.000 | 6.361 | 87/20 | 11 |
| `LiveTunnel.h` | 1.248 | 900 | 348 | — | — |
| `WebServer.cpp` | 7.937 | 3.500 | 4.437 | 9/20 | 8 |
| `WebServer.h` | 390 | sin límite M2 | — | — | — |
| `LiveStreamManager.cpp` | 5.026 | 3.000 | 2.026 | 47/20 | 7 |
| `LiveStreamManager.h` | 677 | 700 | 0 | — | — |

El déficit mínimo es 13.172 líneas físicas entre fuentes y cabecera. Los
módulos existentes, sus límites de 1.500 LOC/8 dependencias y el SCC cero
pasan; también el Dashboard (`server.js` 250/300; ruta mayor 426/500). El
trabajo faltante es por tanto de integración real: los módulos ya creados no
han asumido suficiente ownership del monolito.

**Consecuencia:** `MOD-5.3`, `MOD-5.4` y el cierre M3 no deben pasar mientras
este programa no haya cerrado M2. Las tareas funcionales ajenas pueden seguir
en ramas separadas, pero no pueden declarar arquitectura 9.2 cerrada.

## 2. Reglas no negociables

1. Un único WIP: una tarjeta de esta tabla, su prueba y su revisión antes de
   comenzar la siguiente. No se hace una «gran limpieza».
2. Antes de mover una línea, congelar una prueba de caracterización que ejecute
   el mismo vector contra la implementación antigua y el colaborador nuevo.
3. Cada colaborador nuevo tiene `.h/.cpp`, owner explícito, API de valores o
   puerto estrecho, ≤1.200 LOC objetivo, ≤1.500 LOC duro y ≤8 dependencias
   resueltas por MOD-0.4. Una estructura que sólo esconda decenas de campos
   detrás de un único `m_state` es inválida: debe ser el owner real y publicar
   operaciones con invariantes, no referencias mutables.
4. El coordinador conserva únicamente composición, lifetime y delegación. Cada
   commit debe eliminar más LOC del coordinador de las que añade a su fachada.
5. Ningún callback externo se ejecuta con un lock interno; se mantiene el orden
   `registry -> pending -> queue -> timer_or_leaf`.
6. Ningún módulo de dominio incluye un coordinador, MFC/UI, socket o Kad
   concreto; esos cruces se modelan por un `*Port` o un adaptador `.cpp`.
7. No hay excepción para función >150. La lista de excepciones tabulares es
   explícitamente vacía: aun un dispatch se representa como tabla de datos y
   handlers pequeños, no como función monolítica.
8. Cada tarjeta ejecuta: test nuevo focal, test nativo propietario, los
   characterization afectados, `test_v92_mod01..mod51`, build Release x64 y
   MOD-0.4/MOD-5.1. La tarjeta que toca concurrencia añade race/cancelación y
   al menos 100 iteraciones deterministas con reloj/puerto falso.

## 3. Presupuesto reestimado

Unidad: 1 JP = 7 horas netas. Las cifras incluyen diseño de puerto, pruebas,
extracción, integración y verificación focal; la revisión independiente Sol y
la repetición por hallazgo se reserva aparte.

| Bloque | JP | Horas | % del programa adicional |
|---|---:|---:|---:|
| Preparación, medición y gates | 2,5 | 17,5 | 5,2 % |
| `LiveTunnel` | 18,0 | 126,0 | 37,7 % |
| `WebServer` | 16,5 | 115,5 | 34,6 % |
| `LiveStreamManager` | 9,5 | 66,5 | 19,9 % |
| Revisión M2, dos builds y contingencia de integración | 1,25 | 8,75 | 2,6 % |
| **Total adicional** | **47,75** | **334,25** | **100 %** |

Rango realista: 43–57 JP (301–399 h). Si una tarjeta precisa más de 2 JP de
retrabajo, se detiene, se restaura al último commit verde y se vuelve a
reestimar; no se amplía silenciosamente. El presupuesto original de `MOD-5.2`
(0,75 JP) sólo cubría la creación del gate, no las extracciones faltantes.

## 4. Preparación obligatoria (`M2A-00`, 2,5 JP)

| Subpaso | Acción verificable | Salida / parada |
|---|---|---|
| 00.1 | Congelar un **ratchet verde de migración** con el SHA inicial: ningún coordinador, campo mutable, función >150 ni SCC puede crecer; los módulos nuevos sí pueden crecer sólo contra su budget versionado y los topes 1.200 objetivo / 1.500 duro / 8 dependencias. | `artifacts/mod52-ratchet-<sha>.json`; debe pasar en cada tarjeta aunque el hard-stop final siga bloqueado. |
| 00.2 | Crear una matriz función→estado→lock→wire para los **134 campos completos**: 106 transferidos y 28 retenidos. | Cada fila tiene owner destino, prueba, puerto y presupuesto A/D/net; si falta, la tarjeta no empieza. |
| 00.3 | Publicar revisión versionada de MOD-0.3/MOD-0.4 **antes** de crear módulos: catálogo, ownership, capas, budgets y ratchet; conservar los contratos v1 como evidencia histórica. | Sol aprueba el contrato v2; no se autoautoriza un módulo ni una allowlist. |
| 00.4 | Partir cabeceras: DTOs inmutables y puertos públicos mínimos; añadir test de no-callback-bajo-lock y confirmar PCH/SCC. | MOD-0.4/MOD-5.1 y el ratchet verdes; el hard-stop M2 sólo se evalúa en `M2A-CLOSE`. |

## 5. Ola A — `LiveTunnel` (18,0 JP)

Objetivo de ola: quitar al menos 6.709 LOC (6.361 `.cpp` + 348 `.h`), mover
exactamente 76 campos y dejar cero de las once funciones >150 en
`CLiveTunnel`. Los nombres de fichero son destinos obligatorios propuestos;
un cambio exige ADR antes de codificar.

Ledger jerárquico obligatorio de los 87 campos actuales: el coordinador sólo
puede retener 11 colaboradores ya existentes (`m_pendingLock`,
`m_pendingRequests`, `m_relayDispatcher`, `m_exitServices`, `m_kadBridge`,
`m_scheduler`, `m_lock`, `m_circuitRegistry`, `m_handshake`, `m_peerState`,
`m_metrics`). Los 76 transferidos tienen owner real y budget exacto:
Bulk/Proxy 11; Search 2; GatewayLease 7; SourcePublisher/Ticket 6; StreamFlow 5;
QuotaAuthority (hardening/economy/cuota) 20; ReleaseGate 12; OriginService 8;
CoordinatorFacade (guard/RTT) 5. Total: 76 transferidos + 11 directos = 87.
Un owner no puede exponer sus contenedores mutables ni convertirse en una bolsa
opaca de estado; MOD-0.3 v2 enumera sus operaciones e invariantes.

Jerarquía física LT, sin campo, puntero ni referencia nuevos en
`CLiveTunnel`: `m_exitServices` es parent de `LiveTunnelBulkProxy`,
`LiveTunnelSourcePublisher` (y su `LiveTunnelTicketPolicy`) y
`LiveTunnelStreamFlow` (y su adaptador de transporte); `m_kadBridge` es parent
de `LiveTunnelGatewayLeaseState` y `LiveTunnelOriginService` (y su worker);
`m_scheduler` es parent de `LiveTunnelReleaseGate`, `LiveTunnelQuotaAuthority`
y `LiveTunnelCoordinatorFacade`; `m_relayDispatcher` es parent de
`LiveTunnelSearchService`. Los adaptadores/puertos se guardan sólo en su
servicio parent. Los once miembros retenidos son exactamente los colaboradores
enumerados arriba y se mantienen como referencias existentes; ninguno nuevo se
declara en el coordinador.

| Tarjeta | Owner y estado que sale de `CLiveTunnel` | Destinos y API/puertos | Funciones/LOC que debe vaciar | Test focal obligatorio | JP |
|---|---|---|---|---|---:|
| `M2A-LT1` | Release/aviso: `m_k6Release*`, challenge, evidencia y `m_k6ExitNoticeServer`; exactamente los 12 campos de la matriz. | `LiveTunnelReleaseGate.{h,cpp}` (domain_state) + `LiveTunnelReleaseStorePort`; sólo snapshots/decisiones y puertos, sin socket/Kad concreto. | `Load/Save/Refresh/ApplyK6PublicRelease`, challenge y aviso (≈300–400 LOC eliminables). | evidencia inválida, challenge de un uso, wrap de tiempo, lectura concurrente de snapshot. | 1,5 |
| `M2A-LT2` | Hardening/economía/cuota: controller, telemetría/mediciones, secreto, certificado, limiter, hierarchy, spent y grants; exactamente los 20 campos de la matriz. | `LiveTunnelQuotaAuthority.{h,cpp}` (domain_state), `QuotaCryptoPort` y `QuotaClockPort`. | `Ensure/K6QuotaPrincipal/K6QuotaIssuerTrusted/K6AcquireAnonymousQuota`, economy y métricas (≈900 LOC). | certificado inválido, replay/spent, cuota agotada, cancelación y secreto borrado. | 2,0 |
| `M2A-LT3` | Gateway/lease: sólo source leases, scheduler, budget, coalescer y epochs; no publica ni posee sombras. | `LiveTunnelGatewayLeaseState.{h,cpp}`; adaptador Kad6 separado. | `HandleK6SearchReply` (585), `ExitHandle_Kad6Gateway` (237), callbacks gateway (≈1.150 LOC). | resultado tardío tras cancel, epochs persistidos corruptos, lease duplicado y salida ordenada. | 2,0 |
| `M2A-LT4` | Publicación/tickets: `m_k6Publishes`, `m_k6ShadowPrimary`, targets y tickets; LT3 sólo recibe vista inmutable de leases. | `LiveTunnelSourcePublisher.{h,cpp}` y `LiveTunnelTicketPolicy.{h,cpp}`; `Kad6PublishPort`. | `ExitHandle_Kad6SourceBind` (241), `ExitHandle_Kad6Publish` (265), bind/unbind/ack (≈1.050 LOC). | bind/unbind idempotente, ticket replay, publicación shadow/nativa y orden de callbacks. | 2,0 |
| `M2A-LT5` | Streams y créditos: `m_k6ExitStreams`, `m_k6OriginStreams`, send/receive credits, mapas por circuito. | `LiveTunnelStreamFlow.{h,cpp}` (domain_state) + `Kad6StreamTransportAdapter.{h,cpp}`. | `ExitHandle_Kad6Dial` (203), `ActivateK6Inbound` (169), `OnK6ExitPacket` (172), close/data/credit (≈1.200 LOC). | half-close, crédito límite, socket cerrado durante callback, ABA de streamId y envío después de unlock. | 2,25 |
| `M2A-LT6` | Sweep, avisos, source lookups, activation y rutas origin. | `LiveTunnelOriginService.{h,cpp}` + `LiveTunnelOriginWorker.{h,cpp}`. | `SweepK6Gateway` (287), source lookup/advertise/download (≈1.000 LOC). | worker cancelado, resultado obsoleto, timer coalescido, rutas de lease y rollback de anuncio. | 2,0 |
| `M2A-LT7` | Proxy/bulk/reassembly: `m_bulk*`, `m_proxy*`, `m_reassembly`, `m_exitLiveSubs`. | `LiveTunnelBulkProxy.{h,cpp}` (domain_state) + `LiveTunnelBulkTransportAdapter`. | bulk cells, fragmentos, proxy de stream y subscribe (≈900 LOC). | fragmento fuera de orden, replay, presión de memoria, cierre remoto y callback reentrante. | 2,0 |
| `M2A-LT8` | Jobs/search/replies: `m_searchJobs`, `m_k6SearchReplies`; serialización de resultados. | `LiveTunnelSearchService.{h,cpp}` + `LiveTunnelSearchPort`. | `SendK6SearchResults` (156), finish/serialize/search y relay origin (≈750 LOC). | búsqueda vacía, límite de resultados, cancelación antes de respuesta y serialización byte exacta. | 1,5 |
| `M2A-LT9` | Ingreso/egreso y composición: campos residuales de guard, RTT, locks y puentes existentes. | `LiveTunnelCoordinatorFacade.{h,cpp}` sólo para composición; ampliar módulos anteriores, no crear bolsa de estado. | `OnCellReceived` (175), `Tick` (311), builders y fachada hasta ≤150 cada una (≈1.100 LOC). | matriz de opcode, tick con reloj falso, orden de locks, parada y compatibilidad wire completa. | 2,0 |
| `M2A-LT10` | Cierre de header y medición. | Mover DTOs/puertos a cabeceras de módulo, quitar miembros delegados; `LiveTunnel.h` contiene ≤20 campos reales. | Ninguna función >150; `.cpp` ≤4.000, `.h` ≤900. | compilación de consumidores, ABI interno, inventario MOD-0.1 y gate M2. | 0,75 |

Budget fijo por tarjeta (máximo LOC del módulo / A máximo / D mínimo / neto
máximo; todas las cifras son líneas): LT1 `800/1000/250/+350`, LT2
`1100/1300/275/+1000`, LT3 `1150/1350/1150/+200`, LT4
`1100/1300/1050/+250`, LT5 `1200/1450/1200/+250`, LT6
`1100/1300/1000/+300`, LT7 `1100/1300/950/+350`, LT8 `900/1100/800/+300`,
LT9 `1200/1450/1250/+200`, LT10 `700/800/500/+300`. Además, el coordinador
en cada tarjeta añade ≤80 líneas de fachada y elimina más de las que añade.
Todo valor se valida antes del commit; >1.500 LOC/net detiene la tarjeta.
Los máximos A/neto y el mínimo D son límites independientes; la autorización
del propietario de 2026-07-30 corrige LT1 sin relajar A, neto, fachada ni LOC.

La autorización adicional del propietario de 2026-07-30 corrige LT2 tras
medir el árbol verde posterior a LT1. El inventario alcanzable contiene 20
campos y 277 líneas eliminables de estado/operaciones directas; por tanto el
mínimo anterior de 1.000 eliminaciones no podía satisfacerse sin invadir
tarjetas LT3–LT6. LT2 conserva `A <= 1300`, módulo `<= 1100`, fachada
`A <= 80`, reducción neta obligatoria de la fachada y el STOP global de 1.500
líneas; sólo se ajustan `D >= 275` y neto `<= +1000` para permitir puertos,
serialización de ownership, locks propios y caracterización de replay.

Dependencias: LT1 puede iniciar; LT2 depende de LT1 para el estado de release;
LT3/LT4 dependen de LT2; LT5 depende de LT4; LT6 depende de LT3 y LT5; LT7
es paralelizable conceptualmente pero se ejecuta tras LT3 para conservar WIP;
LT8 tras LT3; LT9 tras LT1–LT8; LT10 tras LT9.

## 6. Ola B — `WebServer` (16,5 JP)

Objetivo de ola: quitar al menos 4.437 LOC de `WebServer.cpp`, eliminar las
ocho funciones >150 y mantener `CWebServer` como dueño de sockets/lifetime,
no de renderizado o acciones. Los controladores reciben request/response DTOs;
los cruces GUI se expresan por `WebGuiPort` y nunca por `SendMessage` desde un
controlador.

| Tarjeta | Owner / destino | Funciones que se reducen | Prueba focal | JP |
|---|---|---|---|---:|
| `M2A-W1` | `WebRequestDispatch.{h,cpp}` con `WebRouteTable` existente; tabla de método/ruta a handler pequeño. | `_ProcessURL` (309). | método/ruta desconocido, URL normalizada, excepción de handler y respuesta única. | 1,5 |
| `M2A-W2` | `WebTemplateRenderer.{h,cpp}` y `WebHeaderFooter.{h,cpp}`; plantillas/cabeceras en objetos de valor. | `_GetHeader` (229), footer y carga de template. | plantilla ausente, escaping, ETag y cabeceras exactas. | 1,5 |
| `M2A-W3` | `WebServerListController.{h,cpp}` + `WebGuiPort`. | `_GetServerList` (446). | lista vacía, orden, permisos y GUI mock sin socket directo. | 1,25 |
| `M2A-W4` | `WebTransferProjection.{h,cpp}`; snapshots de download/upload antes de renderizar. | primera mitad de `_GetTransferList` (658). | snapshot concurrente, orden y fichero parcial. | 1,5 |
| `M2A-W5` | `WebTransferActions.{h,cpp}`; comandos cancel/start/priority por puerto. | `_MakeTransferList` (551) y segunda mitad de transfer list. | permiso denegado, cancelación, acción duplicada y no mutación bajo render. | 1,5 |
| `M2A-W6` | `WebSharedFilesController.{h,cpp}` y `WebSearchProjection.{h,cpp}`. | `_GetSharedFilesList` (451), `_GetSearch` (274). | catálogo vacío, Unicode, resultado obsoleto y permiso. | 1,5 |
| `M2A-W7` | Inventario interno de `_ProcessLiveAPI`: tabla de todas las operaciones, inputs, auth, state owner y vector de regresión. No mueve todavía semántica. | descompone 3.091 LOC en familias cerradas y bloquea nombres de operación. | golden por operación, auth/CSRF, operación desconocida y redacción de secretos. | 1,0 |
| `M2A-W8` | `WebLiveApiStreamController.{h,cpp}` y `WebLiveApiStatusController.{h,cpp}`. | familia stream/status de `_ProcessLiveAPI` (≈700 LOC). | start/stop/join/leave, snapshot concurrente y secreto ausente. | 1,5 |
| `M2A-W9` | `WebLiveApiTransferController.{h,cpp}` y `WebLiveApiSearchController.{h,cpp}`. | familia transfer/search de `_ProcessLiveAPI` (≈700 LOC). | acción autorizada/no autorizada, cancelación y respuesta exacta. | 1,5 |
| `M2A-W10` | `WebLiveApiSettingsController.{h,cpp}` y `WebLiveApiDiagnosticsController.{h,cpp}`. | familia settings/diagnóstico de `_ProcessLiveAPI` (≈700 LOC). | validación, persistencia fallida, redacción y CORS. | 1,5 |
| `M2A-W11` | `WebLiveApiLegacyController.{h,cpp}` para operaciones restantes, con adaptadores separados. | resto de `_ProcessLiveAPI`, `_ProcessFileReq` y helpers (≈1.000 LOC). | matriz completa de API, rollback de error y ninguna llamada directa a socket/GUI. | 1,5 |
| `M2A-W12` | `WebServerFacade` mínimo y borrado de helpers duplicados. | todas ≤150; `WebServer.cpp` ≤3.500. | self-test WebServer, test de rutas, MOD-0.4/M2. | 0,75 |

Budget fijo (máximo LOC del módulo / A máximo / D mínimo / neto máximo): W1
`700/850/600/+250`, W2 `800/1000/750/+250`, W3 `700/800/600/+200`, W4
`1050/1250/900/+350`, W5 `1050/1250/900/+350`, W6 `900/1100/750/+350`, W7
`600/650/0/+650` (sólo inventario/tests, sin crecimiento del coordinador),
W8 `900/1100/800/+300`, W9 `900/1100/800/+300`, W10 `900/1100/800/+300`,
W11 `1100/1300/1050/+250`, W12 `700/800/600/+200`. Todos los módulos y
tarjetas quedan <1.500 LOC/net y la fachada añade ≤80/elimina más de lo que
añade dentro de `WebServer.cpp`.

Dependencias: W1 y W2 primero; W3–W6 después de W1; W7 después de W1–W6;
W8–W11 se ejecutan en orden de la tabla de operaciones congelada; W12 al final.
Una operación Live API no puede cambiar de familia durante la extracción: se
crea primero un caso de regresión y un adaptador explícito.

## 7. Ola C — `LiveStreamManager` (9,5 JP)

Objetivo de ola: quitar ≥2.026 LOC de `.cpp`, mover exactamente 30 campos reales y dejar
las siete funciones >150 en colaboradores. Los objetos ya existentes
(`LiveBroadcastSession`, `LiveViewerSession`, `LivePeerSet`, `LiveChunkWindow`,
`LiveStreamSecurity`, `LiveStreamFanout`, `LiveStreamRecovery`,
`LiveStreamAnnouncer` y `LiveStreamSnapshot`) deben recibir ownership efectivo
en lugar de coexistir con duplicados en el coordinador.

Ledger jerárquico: de los 47 campos actuales, se retienen como máximo 17
colaboradores/sesiones existentes y se mueven 30: LS2 posee 9
(relay/bitmaps/timestamps/counters), LS3 posee 2 (`m_fragReasm`,
`m_chunkArrivalLatency`), LS4 posee 3 (upload/multiparent/deferred sends),
LS5 posee 14 (pings, tombstones, recent, escalation/rate, ghost, bootstrap y
prune) y LS1 posee 2 flags de salida HLS. Total 30 + 17 = 47. El buffer de
chunks no se duplica: LS1 sólo controla ciclo de vida RTMP/HLS; LS3 es el
único que muta/reensambla chunks y entrega valores a las sesiones.

Jerarquía física LS, sin campo, puntero ni referencia nuevos en
`CLiveStreamManager`: `m_broadcastSession` es parent de `LiveHlsOutputAdapter`;
`m_peerSet` lo es de `LivePeerTransportAdapter`; `m_chunkBuffer` lo es de
`LiveFragmentReassembly`; `m_streamFanout`/`m_streamRecovery` contienen las
subpolíticas de LS4; y `m_kadBridge` es parent de `LiveReachabilityService`.
Los 17 retenidos son exactamente `m_broadcastSession`, `m_viewerSession`,
`m_streamInfo`, `m_broadcastStreamInfo`, `m_chunkBuffer`,
`m_broadcastChunkBuffer`, `m_peerSet`, `m_streamSecurity`, `m_streamFanout`,
`m_streamRecovery`, `m_streamAnnouncer`, `m_streamTrustAdapter`, `m_lock`,
`m_kadBridge`, `m_meshManager`, `m_counters` y `m_rtmpIngest`; todos son
colaboradores preexistentes. Los adaptadores viven en el parent y no en el
coordinador.

| Tarjeta | Ownership que se transfiere | Destinos / funciones | Test focal | JP |
|---|---|---|---|---:|
| `M2A-LS1` | Ciclo de vida RTMP y salida HLS: sólo flags HLS; no posee ni muta buffers/chunks. | ampliar `LiveBroadcastSession`/`LiveViewerSession`; nuevo `LiveHlsOutputAdapter`; `RunIsolatedLoopbackSelfTest` (183), start/stop/connect (≈850 LOC). | loopback aislado, directorio HLS, RTMP watcher cancelado y doble stop. | 1,75 |
| `M2A-LS2` | Peers y bitmaps: `m_peerSet`, bitmaps/counters, timestamps y trust. | ampliar `LivePeerSet` + `LivePeerTransportAdapter`; `OnPeerJoin` (366), peer list/replacement/disconnect (≈900 LOC). | churn, reemplazo, diversidad, bitmap obsoleto y callback tras unlock. | 1,75 |
| `M2A-LS3` | Ingest/reassembly: único owner de `m_fragReasm`, histograma y mutación de chunks; LS1 recibe sólo snapshots para HLS. | ampliar `LiveChunkWindow`, crear `LiveFragmentReassembly`; `OnPeerRequest` (190), `OnChunkReceived` (193) y fragmentos (≈850 LOC). | fragmentación adversarial, reorder/expiry, payload truncado y reentrada. | 1,75 |
| `M2A-LS4` | Fanout/recovery/proceso: relay tick, peer health, cuotas y selección. | ampliar `LiveStreamFanout`/`LiveStreamRecovery`; `Process` (423), `RequestMissingSegments` (155) (≈900 LOC). | reloj falso, cliente lento, NACK/FEC, shutdown durante tick y no doble envío. | 1,75 |
| `M2A-LS5` | Ping/bootstrap/reachability: pings, bootstrap cache, rate/escalation, upload y multiparent. | `LiveReachabilityService.{h,cpp}` + puertos Kad/filesystem; helpers de tick (≈650 LOC). | ping expirado, cache corrupta, rate limit y wrap `DWORD`. | 1,5 |
| `M2A-LS6` | Fachada/cabecera: sólo composición, lock de vida y puertos. | mover los campos residuales a sus owners; `.cpp` ≤3.000, `.h` ≤700, ≤20 campos. | inventario MOD-0.1, self-test live y M2 completo. | 1,0 |

Budget fijo (máximo LOC del módulo / A máximo / D mínimo / neto máximo): LS1
`1000/1200/850/+350`, LS2 `1100/1300/900/+400`, LS3 `1050/1250/850/+400`,
LS4 `1100/1300/900/+400`, LS5 `850/1050/650/+400`, LS6 `700/800/600/+200`.
Cada tarjeta añade ≤80 líneas de fachada y elimina más de las que añade en el
coordinador; todo módulo/tarjeta queda <1.500 LOC/net.

Dependencias: LS1 inicia; LS2 y LS3 dependen de que LS1 publique snapshots
correctos; LS4 depende de LS2/LS3; LS5 puede prepararse después de LS2; LS6
depende de LS1–LS5.

## 8. Cierre M2 (`M2A-CLOSE`, 1,25 JP)

1. Ejecutar el verificador M2 en modo estricto: ha de devolver `PASS`, no un
   informe con baseline autoaceptado.
2. Confirmar exactamente: 0 SCC nuevos, cada módulo ≤1.500 LOC/8 dependencias,
   coordinadores dentro de los cinco límites duros, 0 funciones >150 y cada
   clase coordinadora ≤20 campos mutables.
3. Crear dos builds limpios del mismo commit y ejecutar todos los self-tests
   nativos propietarios más Core/Integration relevante.
4. Entregar al revisor Sol un paquete independiente: diff por tarjeta,
   matriz owner/lock/wire, reporte M2, lista de funciones/campos y resultados
   negativos. Un P0–P2 devuelve sólo a la tarjeta causante.
5. Sólo después del `PASS` independiente se cambia el estado de M2 y se
   habilitan MOD-5.3/MOD-5.4.

## 9. Riesgos y criterios de parada

| Riesgo | Señal temprana | Respuesta obligatoria |
|---|---|---|
| API Kad6/Live mezcla socket, persistencia y estado | un módulo de dominio necesita `CUpDownClient`, `CKad*` o el coordinador | detener; crear puerto/adaptador y prueba de lifetime antes de continuar. |
| Callback tardío/UAF al sacar streams o RTMP | test con stop mientras llega resultado falla una vez | no integrar; introducir generación/cancelación/ownership explícito. |
| Función grande se “divide” dejando helpers privados gigantes | helper nuevo >150 o fachada vuelve a crecer | dividir por operación/estado, no por indentación. |
| El campo desaparece sólo del header pero el estado sigue global/duplicado | no hay owner ni test de invariantes | rechazo de revisión; transferir owner real o restaurar. |
| El slice excede 1.500 líneas netas o 2 JP de retrabajo | diff/estimación rebasa umbral | parar, revertir al commit verde y partir por estado/operación. |
| Cambio wire/persistencia oculto | golden binario o fixture de disco cambia | bloquear como defecto separado S1/S2, fuera de esta extracción. |

## 10. Secuencia de ejecución y checkpoints

```text
M2A-00
  -> LT1 -> LT2 -> LT3 -> LT4 -> LT5 -> LT6 -> LT7 -> LT8 -> LT9 -> LT10
  -> W1/W2 -> W3..W6 -> W7 -> W8 -> W9 -> W10 -> W11 -> W12
  -> LS1 -> LS2/LS3 -> LS4/LS5 -> LS6
  -> M2A-CLOSE -> revisión Sol independiente -> MOD-5.3/MOD-5.4
```

Tras LT10, W12 y LS6 se publica el porcentaje del programa adicional, los LOC
realmente eliminados, campos transferidos y funciones >150 restantes. Si el
avance cuantitativo no reduce el déficit del bloque correspondiente, se marca
`BLOCKED`; no se compensa con una modificación del gate.
