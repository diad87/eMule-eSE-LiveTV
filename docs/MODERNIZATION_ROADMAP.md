# Hoja de Ruta de Modernización — eMule eSE LiveTV

> **Estado:** plan vivo. Creado 2026-06-13; revisado **2026-07-16** contra el checkout real.
> La frontera y los gates de la próxima entrega viven en
> [`V9_ALPHA_RELEASE_PLAN.md`](V9_ALPHA_RELEASE_PLAN.md).
> **Alcance:** los 5 ejes del manifiesto de modernización (desacoplamiento/headless, buffer
> en tiempo real, proxy IPTV, Kad para live, multiplataforma) tratados como **una sola
> escalera** de fases con checkpoints estables.
> **Reglas que manda este plan (no negociables):**
> 1. **Estabilizar antes que features** — no se construye encima de WIP sin commitear.
> 2. **Compatibilidad hacia atrás obligatoria** — todo cambio de cable/fichero/formato debe
>    funcionar con upstream 0.70b **y** forks previos (triple-gating).
> 3. **Es ocio, no un producto** — etiquetado honesto sí; ceremonia de verificación pesada no.
> 4. **100% gratis, sin dominios/VPS** — discovery por IP/overlay, nada de coste recurrente.
> 5. **Anonimato por defecto en eSE** — la ruta privada no puede degradar silenciosamente
>    a una conexión directa que revele la IP. La compatibilidad directa con vanilla será un
>    modo explícito y etiquetado como no-anónimo.
> 6. **Identidad ≠ endpoint ≠ alcanzabilidad** — IP, puerto, NAT y LowID/HighID son estados
>    de transporte, nunca la identidad persistente de un nodo.

---

## 0. Resumen ejecutivo (la tesis)

El manifiesto de 5 puntos **describe en un 70-90% el sistema que este fork ya tiene**. La
auditoría de código (junio 2026) confirma que los puntos 2, 3 y 4 están mayormente
construidos. El trabajo *nuevo* real se concentra en: **(1) el desacoplamiento headless**,
**(3) el hueco del playlist IPTV**, y **(5) la portabilidad cross-platform**. El punto 4 no
necesita nada nuevo (y "meter Kad en el bucle de tiempo real" sería una regresión). Hay además
un requisito transversal que pasa a ser de primera clase: **alcanzabilidad anónima detrás de
CGNAT**, incluyendo NAT simétrico. Un relay simple no cumple el requisito de privacidad; la
solución debe separar guards, rendezvous y relay, y cifrar el plano de datos extremo a extremo.

| # | Eje del manifiesto | Estado real | Qué falta de verdad |
|---|---|---|---|
| 1 | Core headless + API local | API ✅ · Headless 🟡 · Desacoplar MFC ❌ | El *sink* (interfaz UI) + modo daemon |
| 2 | Buffer RAM 30-60s + secuencial + desalojo lentos | ✅ ~90% | Cablear FEC, backpressure, (¿ventana >16?) |
| 3 | Proxy IPTV → VLC/Kodi/Smart TV | 🟡 ~70% | Playlist `.m3u`, bind LAN, headers |
| 4 | Kad para live tracking / swarms | ✅ conceptualmente | Nada (Kad=bootstrap, malla=tiempo real) |
| 5 | Multiplataforma (Linux/RPi/NAS/Android) | ❌ | Erradicación de MFC del core (la bestia) |
| R | Alcanzabilidad sin LowID/HighID | 🟡 en construcción | IPv6, punch, rendezvous, relay y vector de rutas |
| P | Privacidad de transporte | 🟡 control parcial | Descubrimiento opaco, onion-rendezvous y data plane E2E |

**Evidencia ancla** (de la auditoría):
- Buffer RAM: `LiveChunkBuffer.h:56`, anillo de 16 segmentos × 2s = **32s**, separado de
  `CPartFile`, nunca toca disco. Entrega desde *live edge* + lookahead 3
  (`LiveStreamManager.cpp:3128`, `:3201`). Scoring por response-rate+RTT y **ban <20%**
  (`LiveStreamManager.cpp:3378`, `:3274`). Watchdog 180s (`:2627`).
- HLS externo ya servible: `WebServer.cpp:4935` (`/hls/`), `:6424` (`/api/live/{hash}/...`),
  Node `channel_api.js:265`. MIME `application/vnd.apple.mpegurl` + `video/mp2t`, CORS `*`
  en `/hls/`. **VLC ya abre `http://localhost:4711/hls/stream.m3u8` hoy.**
- API doble: WebServer C++ en **4711** (hilo propio, `WebSocket.cpp:501`) + ese-server Node
  en **8080** (`server.js:344`, hoy solo localhost).
- Headless parcial: `theApp.m_bHeadless` ya existe (`Emule.h:252`, `Emule.cpp:535`).
- Acoplamiento GUI: ~75 llamadas `theApp.emuledlg->...` en 5 ficheros core; motor late con
  `SetTimer`/`WM_TIMER` (`UploadQueue.cpp:85`), no tiene bucle propio.

---

## 1. Principios de diseño que atan todas las fases

- **El *sink* es la pieza maestra.** Una interfaz `IEngineSink` entre el motor y `CemuleDlg`
  desbloquea simultáneamente el headless (punto 1), prepara el cross-platform (punto 5) y
  deja la GUI MFC como "una implementación más" (decisión de jubilarla **diferida a coste
  cero**). Se introduce sin cambiar comportamiento (la impl GUI reenvía a `emuledlg` igual
  que hoy) y se migra call-site a call-site en commits pequeños verificables.
- **Kad = descubrimiento; malla = tiempo real.** Nunca poner el DHT en el hot path.
- **Kad = descubrimiento; malla = tiempo real; onion = privacidad.** Kad puede introducir
  peers y capacidades, pero no debe publicar endpoints privados ni transportar el contenido.
- **La ruta privada no hace fallback directo.** IPv6 directo, IPv4 directo y hole-punching solo
  pertenecen al modo compatible/no-anónimo; el modo privado usa circuitos y relay aunque exista
  una ruta directa.
- **Un relay simple no es anónimo.** Ningún nodo individual debe observar simultáneamente la IP
  de ambos extremos. La topología mínima es `A → Guard A → Rendezvous ← Guard B ← B`.
- **Anonimato honesto.** Dos PCs no demuestran anonimato: hacen falta al menos tres nodos
  independientes y pruebas de correlación, Sybil y relay malicioso.
- **Compatibilidad aislada.** MD4/AICH, OP_HELLO y LowID/HighID se conservan en adaptadores
  legacy; no deben contaminar el modelo eSE moderno.
- **Cada cambio de cable pasa por triple-gate** (vanilla 0.70b / fork previo / fork actual).
  El bitmap de disponibilidad Live es de **16 bits** → ampliarlo es un cambio de protocolo.
- **CString NO se toca para headless.** `CString`/`CObject`/MFC enlazan y corren en una app
  de consola/servicio Windows sin ventana. La migración a `std::string` **solo** es necesaria
  para el punto 5 (Linux/Android). No mezclar ambos esfuerzos.

---

## FASE 0 — Estabilización (prerrequisito, bloqueante)

**Objetivo actual:** convertir el checkout de integración v9 en una unidad de release limpia.
La fase ya no es solo «cerrar Sprint E»: el árbol auditado mezcla direct reachability, KRP,
Kad6, LiveTV hardening y trabajo de release en 87 entradas tracked + 32 untracked.

**Tareas**
- F0.1 — Clasificar todo el WIP como BASE/LAB/HOLD/OUT y commitearlo por subsistema; fijar
  `libutp` y dejar árbol/submódulos limpios.
- F0.2 — Cerrar defaults y caps: una función sin gate físico no se anuncia automáticamente
  como disponible; preservar el fail-closed de KRP y Kad6.
- F0.3 — Endurecer el pipeline: tag obligatorio, sin binarios de rescate, inputs fijados,
  build Release x64 limpio, manifiesto y SHA-256 del ZIP.
- F0.4 — Ejecutar el gate local completo y un smoke mínimo de dos nodos con alpha↔8.1.0↔vanilla.
- F0.5 — Publicar notas honestas, rollback y matriz de features para
  `v0.70b-eSE9.0.0-alpha.1`.

**Hecho cuando:** se cumplen todos los criterios de salida de `V9_ALPHA_RELEASE_PLAN.md`.
La matriz física completa de NAT/IPv6/relay/anonimato promueve a beta; no es un claim de alpha.

**Esfuerzo:** 3–5 días concentrados + smoke de dos equipos. · **Riesgo:** medio por integración.
· **Versión:** `v0.70b-eSE9.0.0-alpha.1`.

---

## FASE 1 — Quick win: Proxy IPTV local (punto 3 + el *valor* del punto 5)

**Objetivo:** que el stream P2P se vea en el televisor del salón / lo sirva un PC de la casa
**hoy**, sin reescribir nada. Mayor ROI del tablero.

**Tareas**
- F1.1 — Endpoint **`GET /api/live/playlist.m3u`**: genera `#EXTM3U` + un `#EXTINF` por cada
  canal activo (de `/api/live/channels` + descubiertos en Kad), cada uno apuntando a su
  `…/stream.m3u8`. Es el formato que VLC/Kodi/apps de Smart TV cargan como "fuente IPTV".
- F1.2 — **Bind LAN opcional** (`0.0.0.0`) detrás de un flag de preferencias, **default
  localhost**. Aplica a ambos servidores (Node `server.js:344` escucha solo localhost hoy;
  el C++ ya usa `INADDR_ANY` configurable, `WebSocket.cpp:522`).
- F1.3 — **Gate de seguridad para exposición LAN**: token por sesión o whitelist de IP
  (la infra ya existe: `_IsLoggedIn`, `GetAllowedRemoteAccessIPs`, prefijo `/s/{tok}/`).
  Exponer broadcast/privacy a la LAN **sin** gate = no.
- F1.4 — **CORS uniforme para players externos** en `/api/live/{hash}/...` (hoy restringido a
  `127.0.0.1`, `WebServer.cpp:6479`) → permitir el origen del player cuando bind-LAN está on.
- F1.5 — (Opcional) endpoint conveniencia `GET /watch/{hash}` → 302 al `.m3u8` (URL corta
  para teclear en una Smart TV).

**Hecho cuando:** desde un segundo dispositivo de la LAN (móvil/Smart TV/otro PC con VLC) se
abre `http://<ip-lan>:PORT/api/live/playlist.m3u`, aparece la lista de canales y reproduce uno
servido por la malla P2P.

**Compat:** ninguna — son endpoints nuevos, no tocan el protocolo de cable.
**Esfuerzo:** bajo (días). · **Riesgo:** bajo (el de seguridad lo cubre F1.3). · **Versión:** v8.2.

---

## FASE 2 — Afinado del buffer en tiempo real (punto 2, completar el 10% restante)

**Objetivo:** "rediseñar el buffer" es en realidad **afinar** el que ya existe. Cerrar las
piezas que faltan para bitrate nativo estable.

**Tareas**
- F2.1 — **Validar el datapath bulk/FEC ya cableado.** El carrier `OP_LIVE_BULK_CELL`, el
  stripe/FEC y el reenvío 2-hop están integrados y tienen tests unitarios, pero no han cerrado
  el gate runtime 3-PC. `ESE_CAP_TUNNEL_BULK` se anuncia hoy siempre: antes de la alpha debe
  quedar detrás de opt-in o pasar el gate que justifique ese anuncio.
- F2.2 — **Cerrar y validar backpressure/dedup**: auditar el lazo `BULK_ACK`/ventana-EWMA bajo
  pérdida y churn para evitar la espiral a 12000 kbps. El wiring en fuente no equivale a E-β.
- F2.3 — **(Opcional, con cuidado) ventana >32s.** La piden 30-60s; ya estás en 32s. Subir el
  cap de 16 segmentos **toca el bitmap de 16 bits → cambio de cable** (nuevo opcode/flag con
  triple-gate, negociación de capacidad). Solo si F2.1/F2.2 no bastan. No es gratis.
- F2.4 — Persistencia ligera de identidad/estado de peer tras churn (hoy TTL 120s, sin
  checkpoint) — mejora de robustez, no bloqueante.

**Hecho cuando:** 12000 kbps estable en malla 3-PC, FEC recupera pérdida sin cortes, sin
espiral de carga.

**Compat:** F2.1/F2.2 negociadas por capacidad (peers viejos siguen en camino sin-FEC).
F2.3 es cambio de protocolo (triple-gate). · **Esfuerzo:** medio. · **Riesgo:** medio.
**Hitos históricos reservados:** v8.1.1 = true 2-hop; v8.1.2 = bulk/FEC E-α;
v8.1.3 = backpressure/dedup E-β. El código adelantó esos hitos sin que se cortaran las releases;
la próxima entrega pública se gobierna como v9 alpha.

---

## FASE 3 — Desacoplamiento: el *sink* + headless Windows (punto 1, el corazón)

**Objetivo:** que el motor corra **sin ventana MFC** como daemon/servicio Windows, con la web
como UI. Habilita el punto 5 sin pagar todavía su coste.

**Tareas**
- F3.1 — **Definir `IEngineSink`**: interfaz con ~10-15 métodos que cubran los ~75 puntos
  motor→UI (`OnFileAdded/Completed`, `OnConnectionStateChanged`, `OnTransferRate`, `OnLog`,
  `OnNotify`, etc.).
- F3.2 — **`CGuiSink`**: implementación que reenvía a `theApp.emuledlg->...` **exactamente
  como hoy** (cero cambio de comportamiento, cero regresión). Migrar los 75 call-sites en
  commits pequeños (DownloadQueue, UploadQueue, PartFile, KnownFile, BaseClient).
- F3.3 — **`CHeadlessSink`**: no-op / vuelca a log + API. La GUI pasa a ser intercambiable.
- F3.4 — **Bucle/timer propio del motor**: en modo headless no hay `WM_TIMER`; sustituir el
  `SetTimer(UploadTimer)` (`UploadQueue.cpp:85`) por un hilo temporizador que llame
  `Process()` a la misma cadencia (10 Hz / 1 Hz).
- F3.5 — **`Log.cpp` → sink** (`AddLogLine` deja de asumir `emuledlg`).
- F3.6 — **Arranque headless completo**: `emule.exe --headless` instancia motor + WebServer
  **sin crear `CemuleDlg`**. Extender el `m_bHeadless` ya existente.
- F3.7 — `CClientUDPSocket` hereda de `CAsyncSocket` (MFC). Si se migra a
  `CAsyncSocketEx` para consolidar comportamiento en Windows, **no** se contará como
  portabilidad: la implementación actual de `CAsyncSocketEx` también hereda de `CObject`,
  usa estado AFX, una ventana auxiliar y `WSAAsyncSelect`. El pre-trabajo real del punto 5
  es separar el protocolo de esas clases mediante `INetworkReactor`.

**Hecho cuando:** un daemon Windows headless arranca, se conecta a Kad/eD2K, sirve un
broadcast y un visionado vía API/HLS, **sin abrir ninguna ventana**.

**Compat:** interna (no toca cable). La GUI sigue idéntica vía `CGuiSink`.
**Esfuerzo:** medio (decenas de horas, mecánico). · **Riesgo:** medio (regresión GUI si el
sink se desvía — mitigado por migración incremental). · **Versión:** v8.x.

---

## FASE 4 — La API como contrato estable + consolidar los dos servidores (punto 1, fachada)

**Objetivo:** convertir la frontera HTTP en un contrato versionado del que cuelgue cualquier
UI moderna (Electron/Flutter/React) con confianza.

**Tareas**
- F4.1 — **Decidir 4711 vs 8080.** Hoy hay API en C++ (`/api/live/*`) **y** en Node
  (`/api/v1/*`) solapándose. Definir: ¿ese-server es el *gateway* permanente (y el C++ solo
  habla con él) o se colapsa a uno? Esta decisión condiciona toda la fachada.
- F4.2 — **Cerrar los data-races**: el WebServer lee `theApp.downloadqueue/uploadqueue` sin
  lock desde su hilo. Marshalar al hilo del motor o bloquear. (Auditoría
  `project_ese_live_api_threadsafety` ya hizo parte; extender.)
- F4.3 — **Documentar el contrato** (OpenAPI o markdown): el inventario de ~30 endpoints
  `/api/*` + los `/api/v1/*` de Node. Es la línea de estabilidad para UIs externas.
- F4.4 — (Opcional) **WebSocket real RFC 6455** para push en tiempo real (el actual
  `CWebSocket` es solo un manejador de socket HTTP, no WS real) — útil para una UI reactiva.
- F4.5 — **Prueba de fuego**: un prototipo mínimo de UI (React o Flutter) que consuma la API
  documentada y haga play de un canal. Valida que la frontera es realmente reutilizable.

**Hecho cuando:** existe un doc de contrato + un cliente no-MFC (prototipo) reproduce un canal
contra la API sin tocar C++.

**Compat:** la API es aditiva; versionar (`/api/v2`) si se rompe algo.
**Esfuerzo:** medio. · **Riesgo:** bajo-medio. · **Versión:** v8.x. *(Puede solaparse con Fase 3.)*

---

## FASE 5 — Multiplataforma: el "eMule LiveTV Daemon" (punto 5, la bestia, opcional)

**Objetivo:** compilar el core fuera de Windows (Linux/RPi/NAS, luego Android). Es lo más
caro y lo último; **opcional e indefinidamente aplazable**. Solo abordable *después* de que la
Fase 3 haya desacoplado el motor de la GUI.

**Tareas**
- F5.1 — **Erradicar primitivas MFC del core** (lo que la Fase 3 *no* tocó):
  `CString → std::string`/capa de compat (~143 usos en 5 ficheros), `CFile → std::fstream`,
  sacar `CObject` de la jerarquía `CAbstractFile→CKnownFile→CPartFile`.
- F5.2 — **Sockets portables**: extraer un contrato `INetworkReactor` y mantener
  `CAsyncSocketEx` solo como backend/referencia Windows durante la transición. Implementar
  el backend Linux con sockets BSD + `epoll` sin exponer `HWND`, mensajes `WM_*`, AFX ni
  `WSAAsyncSelect` al core portable.
- F5.3 — **Build system portable**: CMake para el core (hoy `.vcxproj`/`.sln` solo Windows).
- F5.4 — **Target Linux ARM** (Raspberry Pi / NAS) → daemon que sirve HLS a la LAN.
- F5.5 — **Target Android** (NDK) para el core; el viewer ya está planificado aparte
  (`MOBILE_VIEWER_PLAN.md`).
- F5.6 — **ese-server (Node) ya es portable** — es el frontend natural del daemon en Linux,
  sin reescritura. Es un activo, no deuda, para esta fase.

**Hecho cuando:** el daemon compila y corre en Linux ARM (RPi), se une a Kad/eD2K y sirve un
canal P2P por HLS a la LAN doméstica.

**Compat:** el daemon habla el **mismo protocolo de cable** que el cliente Windows (mismo Kad,
mismo eD2K, mismo Live) — es un requisito, no un extra. · **Esfuerzo:** alto (200h+).
**Riesgo:** alto. · **Versión:** v9.0.

---

## TRACK R (transversal) — Alcanzabilidad: IPv6 + NAT-traversal + abolición de LowID

Las fases 0-5 modernizan el **plano de UI/arquitectura**. Este track, **paralelo e
independiente**, moderniza el **plano de transporte/alcanzabilidad** — y es lo que convierte
el daemon de F5 en algo *usable de verdad* (un NAS/RPi tras CGNAT es inalcanzable sin esto).
No es un sexto eje: es la columna que sostiene el valor remoto de todos los demás.

**Documentos que lo detallan** (no se duplican aquí, se enganchan):
- **`LOWID_NAT_TRAVERSAL_PLAN.md`** — el *mecanismo* (construye caminos). 5 fases, gating duro.
- **`THESIS_KAD_SIN_LOWID.md`** — el *cambio de modelo de datos* (hace que los caminos sean lo
  único que existe: vector de alcanzabilidad `TAG_ESE_REACH` 0x68 + cascada ICE `CReachPipeline`
  + muerte del concepto LowID en protocolo eSE y UI). Calibre **v9**, gated por el plan validado.
- **`DIRECT_HIGHID_AUTOMATIC_PLAN.md`** — alcance directo local-first y sus cierres D0–D6.
- **`RELAY_KRP_V05_DEVELOPMENT_PLAN.md`** — relay KRP opcional para TCP/High ID y fases posteriores.

> **La relación exacta:** el plan construye *caminos*; la tesis hace que los caminos sean *lo
> único que existe*. Parte de la mecánica y del modelo ya se adelantó en código, pero R.5 no se
> considera cerrado hasta que haya selector único, semántica de UI y matriz física. La Fase 0
> actual es el gate de integración para la alpha; la revalidación R.0 bloquea los claims de beta.

### R.0-R.4 — El mecanismo (de `LOWID_NAT_TRAVERSAL_PLAN.md`)

| Sub-fase | Qué | Estado de partida | Gate |
|---|---|---|---|
| **R.0** | Hole-punch 2-vías existente (uTP) | Pinhole UDP revalidado post-fix en dos NAT reales; identidad y transferencia eD2K directa revalidadas | enlazar ACK→uTP dentro de NET-02; el endpoint raw no lo demuestra |
| **R.1** | Rendezvous 3-vías | Implementado; control 3-PC Tailscale pasó | cerrar B-side E2E y matriz NAT real |
| **R.2** | KadKeepalive | Implementado, nonce-correlacionado, selección exclusiva de peers capaces, telemetría/API y default-OFF | gate 2-PC >60 s pendiente |
| **R.3** | Relay para el residuo simétrico↔simétrico | Buddy relay Live implementado default-OFF; KRP TCP P4 `G4-LAB` PASS | Live E2E físico + KRP `G-HID`; relay eD2K universal aún no existe |
| **R.4** | IPv6 directo y Kad6 | Public-IP in-band, fixes dual-stack y K6-0…K6-8 fuente/build | gates 2/3-PC; salida Kad6 pública sigue cerrada |

Caps ya registrados: `ESE_CAP_HOLEPUNCH_RDV` (**0x8000, bit 15**),
`ESE_CAP_KAD_KEEPALIVE` (**0x10000, bit 16**), `ESE_CAP_TUNNEL_DATAPLANE` (0x1000) y
`CAP_FORK_IPV6_DUALSTACK` (0x04). El registro es la fuente de verdad; el gate de alpha exige que
el anuncio runtime coincida con la disponibilidad real del handler.

### R.5 — El cambio de modelo (de `THESIS_KAD_SIN_LOWID.md`, v9)

R.5 **no se cierra** hasta que R.0-R.4 estén validados end-to-end. Ya existe código adelantado
para `TAG_ESE_REACH` y varias ramas de la cascada, pero faltan selector único, evidencia física
y la semántica final de UI. Tres niveles que ningún otro doc cubre:
- **Modelo de datos:** registro de fuente v2 con doble publicación — vista clásica intacta
  (bit-a-bit 0.70b) + `TAG_ESE_REACH` (vector `R` ignorable por vanilla). *Verificado:* los
  indexadores 0.70b **reenvían tags desconocidos** (`KademliaUDPListener.cpp:1565`,
  `Indexed.cpp:730`), así que la doble publicación funciona incluso en redes mixtas.
- **Política:** `CReachPipeline` como **único** selector de camino, con memoria por NodeID
  (no por IP) y dos políticas explícitas:
  - `PRIVATE`: Guard/rendezvous/relay onion únicamente; nunca fallback directo.
  - `COMPAT`: directo-v6 → directo-v4 → callback → punch-2w → punch-3w → relay → clásico.
- **Semántica:** el concepto LowID **se deja de modelar** entre nodos eSE; la UI pasa de
  semáforo amarillo a **estado de ruta** (`privado onion` / `relay` / `directo v6` /
  `perforado` / `inaccesible`).

### Dónde intersecta este track con las fases 1-5

- **F1 (IPTV/bind LAN):** el bind debe ser v6-aware (link-local/ULA). Trivial, incluir en F1.
- **F3.7 (aislar `CClientUDPSocket` tras `INetworkReactor`):** punto natural para consolidar
  la semántica de E/S dual-stack v4+v6; el adaptador Windows puede apoyarse temporalmente en
  `CAsyncSocketEx`, sin convertirlo en dependencia del core. R.4 y F3.7 se tocan.
- **F5 (daemon cross-platform):** **dependencia dura, no adorno.** Un daemon en NAS/RPi sin
  R.0-R.2 es inalcanzable tras CGNAT. F5.2 (sockets portables) nace dual-stack por R.4.
- **E-β (relay viewer-relays del roadmap Live):** R.3 y P.2 **amortizan** con E-β — misma
  cripto onion (`OP_LIVE_TUNNEL_CELL`), mismo cap (`ESE_CAP_TUNNEL_DATAPLANE`). No duplicar.

- **Track P:** P.0/P.1 deben preceder a cualquier claim de anonimato; P.2 reutiliza R.3, P.3
  cablea el data plane LiveTV y P.4/P.5 son gates de privacidad, no mejoras opcionales.

### El enganche estratégico (por qué v9 = convergencia)

R.5 (tesis) y F5 (daemon) son **las dos mitades de la misma visión v9**: un eMule que es a la
vez **portable** (F5) y **alcanzable desde cualquier topología** (R.5), con identidad estable
(NodeID→clave) desacoplada de la IP — exactamente el precedente que el mesh de Live ya sentó
(identidad = `circ_id`, nunca IP). IPv6 es el peldaño "directo sin punch" de esa cascada.

**Esfuerzo:** R.0-R.2 medio (wiring, sin opcodes nuevos) · R.3/P.2 alto (depende de E-β y
3-PC) · R.4 medio (gated por validación dual-stack) · R.5/P.3-P.5 alto (data plane, abuso y
auditoría). · **Compat:** todo tras `TAG_ESE_CAPS`/`CAP_FORK_*`; un vanilla cae a 0.70b intacto
(triple-gate), pero sin promesa de anonimato.

## TRACK P (transversal) — Privacidad de transporte y CGNAT simétrico

Este track convierte el anonimato en una **política de conexión**, no en una capa decorativa
que se pueda saltar cuando falla el hole-punch. Su objetivo es que dos peers eSE detrás de
CGNAT simétrico puedan comunicarse sin abrir puertos y sin revelar sus IP entre sí.

### Modos objetivo de operación

> Estos son contratos de producto, **no una descripción de los defaults actuales**. El checkout
> usa `Adaptive/Balanced` y todavía puede tomar rutas compatibles; no debe anunciarse como
> anónimo por defecto hasta cerrar P.0–P.5 y sus gates.

- **Privado (por defecto para eSE):** solo circuitos anónimos, rendezvous y relay onion. No
  usa conexión directa, aunque IPv6 o el hole-punch funcionen. Los enlaces y anuncios no llevan
  IP ni puerto del broadcaster.
- **Compatible:** permite eD2K/Kad directo, callback y LowID/HighID para hablar con vanilla.
  Debe aparecer claramente como **no-anónimo**; nunca es un fallback silencioso del modo privado.

### P.0-P.5 — piezas y gates

| Sub-fase | Qué | Estado de partida | Gate |
|---|---|---|---|
| **P.0** | Threat model, modos y contrato de privacidad | control de privacidad V1 parcial | API/UI no prometen anonimato sin data plane |
| **P.1** | Discovery opaco: descriptor firmado, stream ID cegado, invite token de un solo uso | enlaces anónimos; Kad aún puede transportar metadata de endpoint | ningún registro público contiene IP/puerto privado |
| **P.2** | Rendezvous onion para CGNAT: `A → Guard A → Rendezvous ← Guard B ← B` | control onion y relay diseñados; relay de datos incompleto | 3-PC: ambos extremos outbound, ninguna IP cruzada |
| **P.3** | Data plane E2E: subscribe, chunks, PEX y keepalive dentro del circuito | ping/search tunelizados; LiveTV aún tiene path directo | LiveTV funciona en modo privado sin conexión directa |
| **P.4** | Resistencia a correlación y abuso: padding, batching, cuotas, rate limits y anti-Sybil | cover traffic parcial | pruebas con relay honesto, curioso y malicioso |
| **P.5** | Validación de anonimato con 3+ nodos independientes y revisión externa | 2-PC solo demuestra transporte, no anonimato | checklist adversarial y auditoría antes de claims fuertes |

Reglas de P.2:

- El **Guard A** solo debe conocer a A; el **Guard B**, solo a B; el rendezvous debe ver
  únicamente los guards.
- El relay reenvía celdas cifradas y no recibe claves de stream, sesión o identidad final.
- La selección de guards y rendezvous debe evitar solapamiento de relay, misma subred/ASN
  cuando sea posible y concentración en un único operador.
- Kad puede servir para descubrir capacidades, pero la búsqueda privada debe viajar por un
  circuito o usar un descriptor opaco; no se publica la IP del broadcaster.
- El contenido LiveTV debe usar identidad de canal firmada y claves efímeras X25519/AEAD. La
  firma autentica el canal; no convierte una ruta directa en anónima.

**Trade-off explícito:** P.2 resuelve el CGNAT simétrico mediante relay; no existe solución
directa universal. P.4 reduce la correlación de tráfico, pero aumenta ancho de banda, latencia
y consumo de batería. El objetivo honesto es **ocultar IP y evitar que un peer, relay o nodo Kad
individual vincule ambos extremos**, no prometer invisibilidad frente a un observador global.

El estado actual no permite cerrar P.3: la privacidad V1 tiene control onion y pruebas de
`tunnel_ping`/`tunnel_search`, pero el path completo de suscripción y chunks LiveTV todavía
debe pasar por el circuito privado. Ver `RELEASE_NOTES_v8.0.0.md` para las limitaciones
documentadas.

---

## 2. Secuenciación y dependencias

```
PLANO UI/ARQUITECTURA:
FASE 0 (estabilizar) ──┬──> FASE 1 (IPTV quick win)   [independiente, ROI inmediato]
                       │
                       ├──> FASE 2 (buffer/FEC)        [= Sprint E en curso]
                       │
                       └──> FASE 3 (sink + headless) ──┬──> FASE 4 (contrato API) [solapable]
                                                       │
                                                       └──> FASE 5 (cross-platform) ──┐
                                                                                      │
PLANO TRANSPORTE/ALCANZABILIDAD (Track R, paralelo):                                  │
R.0 (validar 2-vías, GATE) ──> R.1 (3-vías) ──> R.2 (keepalive) ──┐                    │
        │                                                         ├──> R.5 (tesis: ───┴──> v9
        └──> R.4 (IPv6 directo) ◄─────────────────────────────────┘     abolir LowID)
                                       R.3 (relay onion) ──[depende de E-β]──┘

PLANO PRIVACIDAD (Track P, política por defecto eSE):
P.0 (threat model/modos) ──> P.1 (discovery opaco) ──> P.2 (rendezvous onion) ──> P.3 (data plane)
                                                               │
                                                               └──> P.4 (anti-correlación) ──> P.5 (3+ nodos/auditoría)
                                             P.2 reutiliza R.3; P.3 bloquea el claim de LiveTV anónimo.
```

- **Fase 1 y Fase 2 son independientes** y pueden ir en paralelo tras la Fase 0.
- **Fase 3 (el sink) es prerrequisito de la Fase 5.** Es la inversión de mayor apalancamiento.
- **Fase 4 puede solaparse con la Fase 3.**
- **Track R corre en paralelo a las fases 1-4** (plano distinto), pero **R.0-R.2 es
  prerrequisito DURO de que F5 sea útil en modo compatible** (daemon NAS/RPi inalcanzable
  tras CGNAT sin punch). El modo privado depende de P.2 aunque el hole-punch falle.
- **R.5 (tesis) y F5 (daemon) convergen en v9** — las dos mitades de la misma visión.
- **R.0 es un GATE** para la ruta directa compatible: valida el hole-punch ya escrito antes de
  construir encima. No bloquea P.2, porque la privacidad contra CGNAT simétrico depende del
  relay onion, no de hacer funcionar una ruta directa.
- **P.0/P.1 son GATES de privacidad:** hasta que el contrato de modos y el discovery opaco estén
  cerrados, no se debe presentar el producto como anónimo.
- **P.3 es GATE del LiveTV privado:** el control onion sin subscribe/chunks/PEX dentro del
  circuito solo demuestra un túnel de laboratorio, no anonimato del producto.
- **Fase 5 y R.5 son opcionales** y no bloquean ningún valor de las fases 1-4 / R.0-R.4.
- **P.5 es requisito para claims fuertes:** 2-PC puede validar transporte, pero no anonimato.

## 3. Mapa a versiones

El mapa anterior mezclaba números reservados con releases realmente publicadas. `v8.1.1`,
`v8.1.2` y `v8.1.3` siguen describiendo los hitos históricos true-2-hop, bulk/FEC y
backpressure/dedup, pero **no fueron cortados**. El código avanzó además por R, P, Kad6 y KRP;
por eso la siguiente entrega es una preview v9 y no `v8.9.9`.

| Versión | Definición de entrega | Transporte/alcanzabilidad | Privacidad y claims |
|---|---|---|---|
| `v0.70b-eSE8.1.0` | Última estable publicada | Baseline validada de su release | Solo claims de sus notas publicadas |
| `v0.70b-eSE9.0.0-alpha.1` | Integración trazable, defaults/caps cerrados, build reproducible y smoke mínimo | Código v9 disponible para opt-in; rutas sin gate físico OFF | **Sin** claim de LowID abolido, IPv6 completo, High ID universal o anonimato |
| `v0.70b-eSE9.0.0-beta.1` | Feature freeze + matriz física multi-PC/NAT/IPv6/relay | R.0–R.4 y KRP se abren solo según evidencia | Auth/bulk/Kad6/Live privados pasan gates adversariales aplicables |
| `v0.70b-eSE9.0.0-rc.1` | Defaults definitivos, compat completa, rollback y soak | Cero bloqueantes; switches de kill/drain probados | Claims redactados uno a uno desde evidencia reproducible |
| `v0.70b-eSE9.0.0` | Estable | Solo rutas con gate cerrado quedan soportadas | Claims limitados; Kad6 público exige además su evidencia de 30 días/revisión |

La definición ejecutable de alpha, beta y RC está en `V9_ALPHA_RELEASE_PLAN.md`. F1/F3/F4/F5
siguen siendo líneas de producto posteriores; no se meten en alpha solo para justificar el 9.

## 4. Riesgos transversales

- **Compatibilidad de cable** (la regla): F2.3 (ventana >16) y todo lo de Live nuevo pasan por
  triple-gate. El daemon (F5) debe hablar el protocolo idéntico.
- **Seguridad de exposición LAN** (F1.2/F1.3): bind a `0.0.0.0` abre el WebServer a la red
  local. Endpoints admin (broadcast/privacy/holepunch) **nunca** sin gate. Default = localhost.
  Modelo de amenazas del broadcaster: el IP/ALTIP en el announce ya es un vector (cubierto por
  E-α, ver `project_broadcaster_threat_model`).
- **Regresión de GUI** (F3): el sink debe reproducir el comportamiento actual bit a bit;
  mitigación = migración incremental con `CGuiSink` idéntico antes de introducir headless.
- **Superficie de abuso del plano rendezvous/relay** (Track R): el vector publicado + rdv +
  relay crean superficie nueva (poisoning de vector, rdv sybil, parasitismo de relay). Cubierto
  en `THESIS_KAD_SIN_LOWID.md` §11: el vector es hipótesis verificada en vivo con nonces CSPRNG,
  la autoridad de identidad sigue siendo el handshake eD2K (SecureIdent), relay capado y E2E-ciego.
- **Falsa sensación de anonimato** (Track P): ocultar la IP del peer no equivale a ocultar
  metadatos, timing o volumen. El modo privado no debe usar IP/puerto en Kad, enlaces o
  `PEER_LIST`; P.4 añade padding/batching y el producto debe describir claramente el límite
  frente a un observador global.
- **Relay que ve ambos extremos** (Track P): un TURN plano rompe el objetivo. P.2 exige guards
  separados, rendezvous sin endpoint final, circuitos sin solapamiento preferido y E2E real.
  Un relay individual no puede recibir una tabla `A-IP ↔ B-IP`.
- **Modo privado degradado** (Track P): si el circuito onion falla, el sistema debe informar
  `privado no disponible` y ofrecer al usuario cambiar explícitamente a compatible. Nunca debe
  caer automáticamente a IPv6 directo, punch o TCP legacy.
- **Prueba de anonimato insuficiente** (Track P): una prueba 2-PC con loopback valida el wire,
  no la propiedad de anonimato. El gate requiere 3+ nodos, relay curioso/malicioso, selección
  de paths y pruebas de correlación antes de cualquier claim de anonimato fuerte.
- **Concentración de la DHT** (Track R / R.5): si demasiados nodos son no-enrutables (mundo
  CGNAT), la DHT se concentra. Instrumentar la fracción de DHT-servers desde R.1; **no** usar v6
  como excusa para Kad v6 paralela (`project_ipv6_kad_shelved`).
- **No sobre-ingenierizar** (regla ocio): el daemon multiplataforma y la abolición de LowID son
  *north stars* (v9), no obligaciones. Si las fases 1-4 + R.0-R.2 dejan un sistema que da gusto
  usar en Windows + Smart TV de la casa **y conecta tras NAT doméstico**, eso ya es "éxito".

---

## 5. Próximo paso recomendado

La alpha ya fue cortada y el árbol contiene un candidato beta trazable. El
próximo hito no es añadir otro subsistema: es cerrar **NET-02, la transferencia
eD2K orgánica a través de la cascada**. Orden bloqueante actualizado:

1. **Fix orgánico desplegado en A/B:** el target anuncia `PUNCH_3W` por
   `TAG_ESE_REACH` antes de HELLO; el nonce conserva el cliente eD2K; R acepta
   peers conectados con SecureIdent y endpoint exacto. El candidato beta idéntico
   ya corre en local y Maria; falta desplegarlo en R.
2. **Topología física de 3 nodos:** A=requester LowID, B=source LowID y R=peer
   distinto, alcanzable, conectado a ambos y con R.1/R.2 activos. Dos nodos no
   bastan para punch3 y nunca deben reutilizar A o B como R.
3. **PASS de señalización:** observar en orden `req_sent`, `req_recv`,
   `challenge_sent`, `fwd` y `rdv_success`, con control negativo al apagar
   `EseKad3Rendezvous`.
4. **PASS de transporte:** `reach_connects.punch3 +1`, HELLO eD2K sobre uTP,
   entrada real en la cola del source y bytes del fichero en ambos sentidos.
   `PROCEED` o un ACK aislado no cuentan como transferencia.
5. **Decisión de defaults/promoción:** aunque el binario de laboratorio ya se
   identifica como `beta.1`, hasta que 3 y 4 pasen bajo NAT real punch3,
   predicción y relay permanecen LAB/OFF. Después se actualizan notas/artefacto
   y se promueve el candidato.

La evidencia R.0 de dos routers/Deco demuestra que el punch UDP básico funciona,
pero no sustituye NET-02. `V9_VALIDATION_CHECKLIST.md` conserva además los gates
IPv6, keepalive y túnel; P.0–P.5 sigue gobernando cualquier claim de privacidad.

> **Resumen de la convergencia:** el roadmap tiene ahora **tres planos coordinados** —
> UI/arquitectura (F0-F5), transporte/alcanzabilidad (R.0-R.5) y privacidad (P.0-P.5). La
> visión v9 es un eMule headless, portable, alcanzable desde cualquier NAT, con identidad
> desacoplada de la IP y un modo privado que nunca degrada silenciosamente a directo.
