# Reproducción al Vuelo sobre eD2K

## Monografía sobre el subsistema *Smart Playback* de eMule eSE LiveTV

**Fecha:** 2026-05-19
**Versión del código analizada:** v0.70b-eSE 8.0.19 (rama `claude/smart-playback-v8.0.16`)
**Autor:** diad87 / colaborador AI
**Estado:** primer pase completo, ~25.000 palabras, sin revisar académicamente

---

## Resumen

eMule fue diseñado en 2002 para **descargar y compartir ficheros completos**, no para reproducirlos mientras se transfieren. La pila eD2K + Kademlia que sustenta el ecosistema (todavía vivo, todavía con millones de fuentes, todavía 100 % gratis y sin dominios) selecciona piezas por rareza, distribuye chunks grandes (9.28 MB) de forma no contigua y carece de cualquier noción de "playhead" del lado del cliente. La promesa moderna del usuario, sin embargo, es la de Netflix: clicas → ves; nunca esperas a que termine; nunca te enteras de que detrás hay una descarga P2P.

Cerrar el abismo entre esos dos mundos es el objeto de esta monografía. Analizamos:

1. **El estado del arte** del streaming VOD/live, desde CDNs centralizadas hasta WebTorrent y los sistemas live P2P contemporáneos.
2. **La fricción inherente al substrato eD2K/Kademlia**: por qué no está pensado para esto y qué primitivas concretas tenemos disponibles.
3. **La arquitectura actual de eSE Smart Playback** tal como existe en v8.0.19 — máquina de estados S1..S7, gating por sustained-rate, parsing del `.met`, watchdog activo del `<video>`, source-switching cuando una fuente no aguanta.
4. **La matemática del sustained-rate** y por qué "tengo 10 minutos de buffer" no es la métrica correcta.
5. **Los casos de borde**: cliente LowID, conexión solo Kad o solo servidores, firewalls hostiles, pocas fuentes, ficheros muy grandes con bitrate alto, ficheros muy pequeños donde el overhead domina.
6. **La superficie de seguridad y privacidad**: integridad del contenido, envenenamiento por sources falsas, análisis de tráfico, qué aporta la V1 *Privacy* y qué le queda por aportar.
7. **El mundo ideal**: lo más cerca que matemáticamente se puede llegar a la sensación de "descarga directa", cota inferior teórica del tiempo a primer fotograma, prefetch predictivo.
8. **Una hoja de ruta priorizada** por (impacto en UX) × (coste de implementación) hasta el norte estelar de "Netflix sobre eD2K".

El hilo conductor es honesto: en el sistema actual sí se puede ver en streaming, pero el comportamiento es **frágil**. Funciona perfectamente cuando hay muchas fuentes y ancho de banda holgado; degrada a "buffering interminable" o "Sin datos recibidos" con la misma alegría con la que arranca cuando las condiciones se tuercen. La tesis es que la mayor parte de esa fragilidad **no** es inherente al substrato P2P — es producto de no tener instrumentación honesta de lo que está pasando. Las últimas seis hotfixes (v8.0.14 → v8.0.19) son evidencia experimental de esa afirmación: cada una destapa una clase de mentira que el sistema se hacía a sí mismo (tamaño preallocated en lugar de tamaño real, tasa instantánea en lugar de sostenida, tag-type mal codificado en el parser del `.met`...) y al sustituirla por verdad-de-disco el comportamiento mejora aunque ninguna línea de las pilas eD2K/Kad se haya tocado.

---

## Índice

- [Cap. 1 — Introducción y planteamiento del problema](#cap-1--introducción-y-planteamiento-del-problema)
- [Cap. 2 — Estado del arte: del CDN al P2P-VOD](#cap-2--estado-del-arte-del-cdn-al-p2p-vod)
- [Cap. 3 — El substrato eD2K + Kademlia](#cap-3--el-substrato-ed2k--kademlia)
- [Cap. 4 — Anatomía del eSE Smart Playback (v8.0.19)](#cap-4--anatomía-del-ese-smart-playback-v8019)
- [Cap. 5 — Matemática del sustained-rate gate](#cap-5--matemática-del-sustained-rate-gate)
- [Cap. 6 — Casos de borde: LowID, Kad-only, firewalls, fuentes escasas](#cap-6--casos-de-borde-lowid-kad-only-firewalls-fuentes-escasas)
- [Cap. 7 — Superficie de seguridad y privacidad](#cap-7--superficie-de-seguridad-y-privacidad)
- [Cap. 8 — El mundo ideal: cota inferior del *time to first frame*](#cap-8--el-mundo-ideal-cota-inferior-del-time-to-first-frame)
- [Cap. 9 — Hoja de ruta priorizada](#cap-9--hoja-de-ruta-priorizada)
- [Apéndice A — Léxico técnico](#apéndice-a--léxico-técnico)
- [Apéndice B — Referencias](#apéndice-b--referencias)

---

## Cap. 1 — Introducción y planteamiento del problema

### 1.1 Por qué este documento ahora

El subsistema de reproducción al vuelo ha sido el responsable mayoritario de las hotfixes del ciclo v8.0.x:

| Versión | Síntoma reportado | Diagnóstico |
|---|---|---|
| v8.0.5 | "A todo gas 6 me reproduce A todo gas 1" | Match por nombre fuzzy en lugar de por hash |
| v8.0.7, v8.0.11 | Velocidad limitada 80/90 KB/s persistente | Defaults heredados del eMule clásico |
| v8.0.9 | "Sin resultados" cuando estoy en Kad pero no en servidor | Búsqueda no caía a Kad |
| v8.0.12 | "Avatar 1 GB / 4 GB, no arranca" | Chunks no contiguos sin preview-priority |
| v8.0.13 | "Bufering 0 MB, buffer listo, no arranca emule" | ese-server polleando Temp incorrecto |
| v8.0.14 | "Buffer listo" en fichero vacío | `stat.size` mintiendo sobre sparse pre-allocated |
| v8.0.15 | "10 min de buffer no me sirven si descargo a 100 kbps" | Falta gate por sustained-rate |
| v8.0.16 | Estado del reproductor cambia a saltos, sin reaccionar a stalls | Falta máquina de estados real |
| v8.0.18 | Ficheros en Incoming etiquetados "DESCARGANDO", click → "Invalid partNum" | Flag `completed: true` perdido |
| v8.0.19 | "39 GB de 39 GB" cuando eMule llevaba 200 MB | Parser `.met` mal codificaba tag-type BLOB |

Diez clases de fallo distintas, todas en el camino crítico de un solo gesto: "pinchar Reproducir y ver vídeo". El usuario, con razón, lo planteó en la frontera de la rotura: *"venga, esto tienes que planificármelo bien de verdad, no puedo andar parcheando tonterías"*. La sospecha implícita es correcta: cada una de esas hotfixes destapa una **mentira local** (un dato que el código creía verdad y no lo era). Hace falta un análisis de fondo que ordene qué datos son ground truth, qué se infiere, qué se asume, y qué pasa cuando cada inferencia falla.

### 1.2 Hipótesis principal

> **La reproducción al vuelo sobre eD2K puede ofrecer experiencia equivalente a descarga directa con probabilidad cercana a 1 siempre que el ancho de banda sostenido de descarga sea ≥ bitrate × 1.3 y haya ≥ 2 fuentes con head bytes disponibles.** En el resto de escenarios la experiencia degrada de forma graceful (pausa explícita con causa, espera con barra honesta, cambio automático de fuente, fallback a "descargar y avisar"). Las fallas duras ("buffer listo" sobre sparse vacío, "Sin datos recibidos" sin diagnóstico, "Invalid partNum") son **defectos de instrumentación**, no de física.

Cada una de las tres cláusulas merece desglose:

- **"Ancho de banda sostenido"** es la tasa media observada sobre una ventana rodante de N segundos. Difiere del rate instantáneo (que oscila salvajemente con la entrada y salida de slots de upload de los pares) en hasta 2-3× con la misma "media verdadera". La elección de N (ahora 30 s en `playback_state.js`, 60 s en `/api/emule/rate`) es ya un compromiso.

- **"≥ 2 fuentes con head bytes disponibles"** porque el modo `preview_prio` de eMule sesga la elección de chunk **hacia el principio del fichero** pero no hacia un offset específico. Si todas las fuentes te están sirviendo el mismo chunk inicial, el agregado es 1×rate, no N×rate. La realidad: hay que diversificar.

- **"Degrada de forma graceful"** es la frontera de calidad. No es aceptable que el cliente entre en bucle de retries silenciosos. Tampoco es aceptable que mienta ("buffer listo" cuando no lo está). La única respuesta honesta a "tu descarga no aguanta" es **decírselo al usuario** con un número (la tasa observada, la tasa necesaria), un veredicto (¿podemos esperar?) y opciones (otra fuente, dejarlo en background, abandonar).

### 1.3 Por qué no es trivial

Hay seis tensiones físicas que hacen que esto no sea "yo me pongo un proxy delante de eMule y listo":

1. **Granularidad temporal del eD2K**: una **parte** son 9,28 MB. eMule no decide piezas inferiores a eso. Si la película es de 4 Mbps de bitrate, una parte son **18,5 segundos** de vídeo. La unidad básica de decisión-en-vuelo es esa, no 1 segundo como en HLS/DASH.

2. **Política de selección de chunks**: el algoritmo clásico de eMule busca **piezas raras primero** (rare-first / random-first) para mejorar la salud agregada del enjambre. Streaming quiere **piezas tempranas primero**. La instrucción `op=setpreview` invierte la política por hash; está hecha para esto. Pero solo aplica a UN hash a la vez y no es per-byte.

3. **Asimetría del slot upload**: cada par te sube a su ritmo cuando le toca tu turno en su cola. No tienes contrato. Las tasas pueden cambiar bruscamente cuando otro par entra/sale del mismo slot. Ningún sistema de admisión puede prometer ancho.

4. **LowID es la norma, no la excepción**: la mayoría de NATs domésticos sin UPnP exponen tus clientes como LowID, donde solo te alcanzan por callback. La pirámide de aceptación de callbacks se complica con doble LowID. Esto añade latencia variable al primer byte de cada fuente.

5. **El propio Kad puede no estar bootstrappeado**: arrancar eMule "limpio" puede tardar 30-60 segundos en tener una vista útil de la DHT. Si el usuario clica "Reproducir" antes, las búsquedas devuelven 0 fuentes y el sistema parece roto.

6. **El `.met` es la única verdad de disco**: el tamaño físico del `.part` puede mentir (sparse pre-allocated), el rate observado a nivel de OS no distingue chunks contiguos del head de chunks dispersos por el medio, ffprobe puede colgarse 15-20 s en un H.265 truncado, eMule en sí no expone una API rica al ese-server sobre "qué offset de bytes tengo realmente válido". Todo lo que sabemos lo deducimos parseando el `.met`. Si el parser tiene un bug (v8.0.19), el sistema entero miente.

### 1.4 Alcance del documento

**Dentro**:
- Reproducción **VOD** al vuelo de ficheros eD2K (películas, series, vídeo demand).
- Arquitectura, protocolos, máquina de estados, instrumentación.
- Análisis de escenarios fallo (LowID, pocas fuentes, etc.) y cómo el sistema reacciona.

**Fuera**:
- Live streaming P2P (eSE LiveTV, que es un sistema distinto con su propio protocolo OP_LIVE_*). Está cubierto en `docs/PAPER_eSE_Live_ES.md` y `docs/thesis/` (rama hungry-dhawan-84bd82).
- Política de discovery de fuentes (cubierto en `docs/DECENTRALIZED_DISCOVERY.md`).
- Búsqueda en Kad / servidor / global (cubierto en la tesis de Kad Search v2, rama quizzical-newton-9aa3db).

### 1.5 Notación

A lo largo del documento usamos:

- `B(t)`: bytes descargados a tiempo `t` desde el arranque.
- `B_head(t)`: bytes contiguos descargados desde el byte 0 (lo que el reproductor puede consumir sin seek).
- `B_total`: tamaño total del fichero.
- `r(t) = dB/dt`: tasa instantánea de descarga.
- `R(t, w)`: tasa media sobre ventana `[t-w, t]`.
- `BR`: bitrate del contenido (bytes/s, no bits/s salvo indicación contraria).
- `D`: duración total del fichero (segundos).
- `D_played(t)`: posición del playhead en segundos.
- `B_played(t) ≈ D_played(t) × BR`: bytes consumidos por el reproductor.
- `lead(t) = B_head(t) - B_played(t)`: buffer en bytes por delante del playhead.
- `lead_sec(t) = lead(t) / BR`: ídem expresado en segundos de reproducción.

---

## Cap. 2 — Estado del arte: del CDN al P2P-VOD

### 2.1 Streaming centralizado (Netflix, YouTube, Disney+, ...)

El gold standard que el usuario tiene como referencia mental funciona, en grueso, así:

```
Cliente ─HTTP─▶ CDN edge ─HTTP─▶ Origin storage
                  │
                  ├── manifest.mpd / master.m3u8     (lista de variantes)
                  └── seg_001.m4s, seg_002.m4s, ... (fragmentos de 2-6 s)
```

Componentes clave:

1. **Manifest declarativo**: el cliente sabe *de antemano* qué fragmentos existen, cuánto duran, qué codec usan, qué bitrate tiene cada variante. No hay descubrimiento. No hay sorpresas. El gating del reproductor es trivial: si tienes los fragmentos `[1..k]` y la red da abasto para uno cada `<segundo_duración>` segundos, vas servido.

2. **Edge CDN**: capacidad efectivamente infinita desde el punto de vista del cliente. Cada nodo edge agrupa miles de clientes y sirve desde RAM/SSD local con RTT sub-50 ms y ancho de banda del orden de Gbps. La conexión cliente-edge es siempre la última milla, el cuello de botella es el ISP del usuario.

3. **Adaptive bitrate (ABR)**: el manifest declara variantes a 480p/720p/1080p/4K, el cliente mide su throughput y elige dinámicamente. El gating es **híbrido buffer + throughput**: si el buffer baja de X o el throughput cae bajo el bitrate de la variante actual, baja de variante.

4. **Codec moderno + container fragmentado**: H.264/H.265/AV1 en fMP4 (fragmented MP4) o WebM. Cada fragmento es independientemente decodificable (empieza por un IDR/keyframe). El reproductor cliente (MSE en navegador, o nativo) puede combinar fragmentos de variantes distintas casi sin coste de inicialización.

5. **Lookahead generoso**: el reproductor mantiene 10-30 s de buffer adelantado y otros 10-15 s detrás (para rebobinado instantáneo). La política habitual es que mientras `buffer_ahead < 30s AND tasa_observada > 1.5 × bitrate_actual`, descargas más rápido que real-time.

6. **Métricas QoE telemétricas**: cada cliente reporta al backend rebuffers, bitrate elegido, abandono. El operador ajusta el CDN, el ABR ladder, el codec, en función de esos datos.

**Time to first frame** típico: 1-3 segundos. **Probabilidad de rebuffer en sesión** de 1h: < 2 %. **CDN cache hit ratio** > 95 %.

#### 2.1.1 ¿Qué de esto se puede portar a P2P?

| Pieza | Portabilidad a P2P-eD2K |
|---|---|
| Manifest declarativo | **Parcial**: el `.met` cumple un rol parecido pero es interno al cliente, no se anuncia. Podríamos publicar uno separado, pero ya hay análogo más limpio: tamaño + bitrate. |
| Edge CDN | **No portable**: el modelo de proximidad de Netflix se sustituye por el modelo de **diversidad de fuentes** del P2P. Probable pero distinto. |
| ABR | **Sí** con transcoding en el servidor local. ffmpeg ya hace transcoding bajo demanda en `stream_completed.js`. Se puede hacer ABR sobre la pieza descargada. |
| Container fragmentado | **Sí**: ffmpeg ya remuxa a fMP4 con `-movflags frag_keyframe+empty_moov`. El cliente recibe un fMP4 reproducible-en-progreso vía MSE. |
| Lookahead generoso | **Forzado por física**: la unidad mínima eD2K es la parte (9,28 MB). El "lookahead" mínimo es del orden de 1 parte ≈ 10-20 s de vídeo en función del bitrate. |
| Telemetría QoE | **No implementado**, pero podríamos. |

### 2.2 BitTorrent streaming: Popcorn Time / WebTorrent / Streamio

BitTorrent es más cercano a eD2K. Tiene la misma idea de "torrent + piezas" (típicamente 256 KB - 4 MB). Los proyectos que han logrado streaming-while-downloading en él dan tres pistas concretas:

#### 2.2.1 Sequential download mode

La mayoría de clientes BT incluyen un "modo secuencial" que cambia la política de selección de pieza de **rarest-first** a **earliest-first**. Es exactamente el equivalente al `preview_prio` de eMule. Limitaciones:

- Si lo activas en todos los clientes del enjambre simultáneamente, **rompes** la salud del swarm porque las piezas raras dejan de propagarse. Por eso es una preferencia local, no una negociada.
- Funciona bien con muchas fuentes; con pocas fuentes (< 5 seeds), el cliente queda esperando piezas tempranas que solo uno tiene y no puede saltar a las medias para "hacer tiempo".

#### 2.2.2 Piece-level priority hinting

Algunos clientes (libtorrent, qBittorrent) permiten asignar prioridades **por pieza** (alta / media / baja / no descargar). Esto es más fino que `preview_prio` de eMule, que opera por hash entero.

Popcorn Time aprovechaba esto: priorizaba la primera ventana de piezas para el reproductor, dejaba la siguiente como "media", y deshabilitaba el resto hasta acercarse al playhead. Esto **además** evitaba descargar el final cuando el usuario abandonaba la película a los 10 minutos.

eD2K no tiene una primitiva equivalente nativa. `op=setpreview` invierte la elección hacia el head globalmente pero no permite "y además priorizar esa ventana específica". Es una limitación que arrastra implicaciones — la discutimos en §4.

#### 2.2.3 Peer rotation por upload capacity

WebTorrent y los clientes BT modernos rotan agresivamente los slots de upload entre pares, eligiendo los que **dan más bytes/s a cambio** (optimistic unchoking, recíproco). En streaming, lo que se quiere es lo contrario: **bajar de** los pares lentos, **mantenerse en** los rápidos, aunque pagar más upload a cambio. eD2K usa un sistema de "credit" (el más antiguo) y "queue" (el cliente espera turno) que no se ajusta naturalmente a esto. Lo discutimos en §5.5.

### 2.3 IPFS streaming y WebRTC P2P

IPFS streamea bloques de 256 KB direccionables por hash sobre la red DHT global. Los nodos cachean bloques y los publican. El cliente:

1. Resuelve `/ipns/...` o `/ipfs/...` a un root CID.
2. Resuelve recursivamente los hijos hasta los bloques de datos.
3. Descarga bloques desde cualquier nodo que los anuncie.

**Para vídeo** la práctica habitual es:
- El productor sube los segmentos HLS al IPFS (igual que a un CDN, segmento = bloque grande).
- El productor publica el `master.m3u8` también en IPFS.
- El reproductor cliente (hls.js, video.js) usa un gateway IPFS o consume directamente vía Helia/js-ipfs.

**Limitación**: IPFS no es real-time. Los hops entre nodos pueden añadir 1-2 s de latencia por bloque. Para una sesión de live con baja latencia (< 5 s) **no sirve**. Para VOD sí, pero el gateway HTTP suele acabar siendo el cuello de botella.

WebTorrent en navegador resuelve esto con **DHT + WebRTC** para encontrar pares y transferir bloques peer-to-peer dentro del propio navegador. Es elegante pero requiere infraestructura tracker (WSS), y la mayoría de los proyectos acaban dependiendo de un servicio fijo (`wss://tracker.btorrent.xyz` o similar). Eso choca frontalmente con la directriz de "100 % gratis sin dominios" de este proyecto.

### 2.4 Live P2P streaming (PPLive, SopCast, OctoShape...)

La familia de los **mesh / pull P2P live streaming** (publicada en SIGCOMM 2007-2010 por Liu, Magharei, Rejaie y otros) introdujo conceptos directamente reaprovechables aquí:

- **Deadline-driven piece selection**: cada chunk de stream tiene un "deadline" (el momento en que el reproductor lo necesita). El cliente prioriza chunks cuyo deadline está más cerca, igual que un scheduler EDF.
- **Source diversity scoring**: el cliente puntúa cada par por su "utilidad esperada" — combinación de RTT, throughput pasado, fiabilidad. Pide chunks raros a pares fiables, comunes a pares lentos.
- **Adaptive deadline**: cuando el sistema detecta que no llega a los deadlines, **retrasa** la pretensión del reproductor (pre-buffer más alto, latencia de live aumentada). En VOD el equivalente es pausar antes de quedarse sin buffer.

eSE LiveTV implementa **algunos** de estos conceptos para su capa OP_LIVE (los chunks tienen secuencia y se piden con cierta urgencia), pero no tiene aún un scheduler EDF formal para la capa VOD. Lo discutimos en §9 como una mejora clave.

### 2.5 La línea base de eMule clásico (y por qué el "preview" del aMule no era esto)

aMule, eMule y derivados ya tenían desde hace años un **"preview while downloading"**. Funcionaba así:

1. El usuario hace click derecho → "Preview".
2. eMule copia la parte 0 (los primeros 9.28 MB) a un fichero temporal.
3. Abre el reproductor predeterminado sobre ese temporal.
4. Si el container del codec lo permite (AVI sobre todo), el reproductor enseña los primeros ~30 segundos.

Limitaciones:
- **Fichero estático**: el preview no crece con la descarga. Para ver más, hay que repetir el preview con la parte siguiente — manualmente.
- **Sin gating**: no comprueba si vas a tener suficiente velocidad para los siguientes 30 segundos. Si arranca, arranca.
- **Container-dependiente**: contenedores con metadata al final (MOV no fragmentado, algunos MKV) **no preview-ean**. El reproductor no puede saber dónde están los keyframes sin el atom de índice. ffmpeg-pipe con `-movflags +faststart` sintético no estaba disponible en aMule.
- **Sin información honesta**: no le dice al usuario "te quedan 5 minutos disponibles, después se cortará". Solo arranca y reza.

eSE Smart Playback es la generación siguiente: streaming continuo con `<video>` en HTML5 alimentado por ffmpeg-pipe sobre el `.part`, con gating por sustained-rate y máquina de estados que reacciona a la realidad.

### 2.6 Conclusión del estado del arte

El espacio de soluciones para "streaming sobre P2P" tiene tres lecciones aplicables aquí:

1. **El gating es híbrido buffer-throughput**, no uno u otro. Netflix lo hace; Popcorn Time lo hace mal y por eso rebufferea; los sistemas live P2P lo formalizan con deadlines.
2. **La selección de piezas debe estar acoplada al playhead**, no a la heurística genérica del swarm. eD2K lo permite parcialmente vía `preview_prio` pero la granularidad es por hash, no por pieza.
3. **El cliente debe ser honesto con el usuario** sobre lo que sabe y lo que no. Mostrar tasa observada vs tasa requerida, fuentes activas, tiempo a primer fotograma estimado. No "buffering..." indefinido.

Ninguno de estos tres puntos es un descubrimiento. El sistema actual ya implementa parcialmente los tres. La oportunidad está en **completarlos** y en **dejar de mentir** en los datos derivados (B_head, R, bitrate estimado).

---

## Cap. 3 — El substrato eD2K + Kademlia

### 3.1 El fichero como conjunto de partes

eD2K define un fichero como:

- Una **MD4 root hash** (16 bytes) que identifica el fichero a nivel ed2klink.
- Una **lista de MD4 part hashes**: una por cada bloque de **9.28 MB** (exactamente 9 728 000 bytes) del fichero, en orden lineal.
- El número de partes es `⌈ file_size / 9728000 ⌉`.
- Una **AICH master hash** (root de un árbol Merkle) para integridad fina por sub-bloque de 180 KB.

Cuando un cliente A pide la parte `n` a un cliente B, B envía:

- Cabeceras con el rango exacto (la parte puede no ser completa hasta el último bloque).
- 53 sub-bloques de 184 KB cada uno (la parte se serializa en bloques de ~180 KB para confirmaciones AICH).
- Hash AICH de cada bloque, opcionalmente.

La granularidad de **decisión** en eMule es la **parte**. Las primitivas de **transferencia** funcionan por bloques de 180 KB. El reproductor consume bytes individuales. Hay un mismatch de tres órdenes de magnitud entre "lo que decido" (9 MB) y "lo que consumo" (bytes).

### 3.2 El fichero `.part` y su `.met`

Cuando se inicia una descarga:

1. eMule crea `Temp\<N>.part` y, si `bPreallocate=1` (default), reserva el espacio en disco al tamaño total. En NTFS esto crea un **sparse file**: el espacio aparece como reservado pero los bloques no escritos no consumen disco físico hasta el primer write. La consecuencia: `stat.size` devuelve el tamaño lógico (total), no los bytes reales.

2. Crea `Temp\<N>.part.met` con el formato CTag-serializado descrito en `routes/emule_routes.js`. Este fichero contiene:
   - Versión (1 byte).
   - Date (4 bytes).
   - MD4 root hash (16 bytes).
   - PartCount (2 bytes) + PartCount × MD4 (16 bytes cada uno).
   - TagCount (4 bytes) + TagCount × CTag.
   - Los tags incluyen: `FT_FILESIZE` (id 0x02, valor en bytes), `FT_FILENAME`, `FT_AICH_HASHSET` (BLOB grande), y la **lista de gaps**: pares `FT_GAPSTART_n` / `FT_GAPEND_n` (n entero serializado como ASCII en el nombre del tag).

3. Cada vez que eMule recibe bloques y los escribe en disco, **actualiza** el `.met` reescribiéndolo con los gaps actualizados. La frecuencia de escritura es del orden de segundos; en cargas pesadas puede haber lag de varios segundos entre "tengo el byte" y "queda registrado en el .met".

#### 3.2.1 La lista de gaps como verdad-de-disco

Sea `[(s_1, e_1), ..., (s_k, e_k)]` la lista de gaps (rangos de bytes NO descargados todavía):

```
B_total    = file_size                            (de FT_FILESIZE)
B_gaps     = Σ (e_i - s_i)
B_received = B_total - B_gaps                     (bytes válidos en disco)
B_head     = min(s_1, ..., s_k) si existe gaps, B_total si no  (head contiguo desde byte 0)
```

`B_head` es la única métrica honesta que el reproductor puede gating: el `<video>` no puede saltar offsets vacíos. ffmpeg al leer el `.part` desde byte 0 hacia delante se detendrá (o producirá artefactos) cuando llegue al primer gap.

#### 3.2.2 La trampa del `stat.size`

```python
# Pseudocódigo del bug v8.0.14:
def is_ready_to_play(part_file):
    size = os.stat(part_file).st_size
    return size >= MIN_HEAD_BYTES   # 50 MB
```

Sobre un fichero de 4 GB pre-allocated, `stat.size = 4 000 000 000` desde el primer milisegundo, sin haber recibido nada todavía. El "Buffer listo" sobre fichero vacío del bug reportado en v8.0.14 era exactamente esto.

Solo el `.met` tiene la verdad. Pero parsear el `.met` correctamente es no-trivial (v8.0.19) — un bug de un solo byte en el tag-type confundía BLOB con BSOB y reportaba `B_head = B_total` aunque eMule solo llevara 200 MB.

#### 3.2.3 ¿Por qué no nos lo cuenta eMule directamente?

eMule tiene un WebServer interno (`WebServer.cpp`) que expone HTML básico y unas pocas operaciones via `?w=transfer&op=...`. **No** expone una API JSON de "dame el estado de mis descargas con offsets de chunk", al menos no en upstream 0.70b. Por eso ese-server polea el `.met` directamente: es más rico, más detallado, y no depende de que el WebServer interno sepa más cosas.

Esto significa que **el contrato entre eMule.exe y ese-server.exe sobre `Temp/` es de hecho un contrato basado en lectura del filesystem, no en una API**. Tiene la ventaja de no requerir cambios en eMule. Tiene la desventaja de que cualquier cambio en el formato del `.met` (por ejemplo, si en un futuro eMule añade un nuevo tag-type) rompe el parser. Lo que justamente pasó en v8.0.19.

### 3.3 Adquisición de fuentes

Cuando una descarga arranca, eMule busca fuentes de tres maneras:

1. **OP_GETSOURCES** al servidor eD2K conectado (si lo hay). El servidor responde con una lista de hasta ~200 IPs:puertos de pares que han anunciado tener el hash. Latencia: 100-500 ms.
2. **Kad publish/lookup**: si Kad está bootstrappeado, el cliente publica que tiene el hash y consulta por otros publicadores. La latencia es mayor (lookup de 5-15 s típico), pero la red es decentralizada.
3. **Source exchange (PEX)**: una vez conectado a un par, intercambian listas de OTROS pares que tienen el hash. Crecimiento exponencial.

Los tres se complementan. El sistema actual:
- Si solo hay servidor: dependes 100 % del servidor. Si el servidor cae, no hay nuevas fuentes.
- Si solo hay Kad: lookups más lentos pero descentralizado. PEX una vez conectado a 1 par compensa.
- Si hay los dos: óptimo.

Para Smart Playback la implicación es: **el time-to-first-byte depende fuertemente del tiempo de adquisición de fuentes**. Si Kad está frío y no hay servidor, el primer chunk no llega hasta que el lookup Kad complete (5-15 s + el tiempo de handshake con el primer par + el slot wait).

### 3.4 La transferencia: queue, slot, credit

eMule no es FIFO. Cada cliente B que tienes en cola para que te suba la parte que pidas mantiene una **cola** ordenada por un score que combina:

- **Credit ratio**: cuánto le has subido tú a ÉL en sesiones pasadas (persistente en `clients.met`). Cuanto más has subido, antes te toca.
- **Tiempo en cola**: cuanto más esperas, sube tu puesto.
- **QR (queue rank)**: posición efectiva calculada por el otro cliente.

Cuando llega tu turno, B abre un slot upload contigo y te empieza a transferir. El slot dura típicamente **120 s** o hasta que envías STARTUPLOAD para extenderlo. Durante el slot tu tasa con B es esencialmente "todo lo que su upstream te puede dar dividido entre cuántos slots abre B en total".

#### 3.4.1 Consecuencias para streaming

- La **tasa agregada** observada por A es `Σ rate_i` donde i va por cada slot abierto. Si A tiene 8 slots abiertos, la tasa puede ser muy estable. Si A tiene 1 o 2 (porque los otros pares aún están en cola), la tasa oscila con cada apertura/cierre.
- **No hay garantía de continuidad**: cuando un slot se cierra (otro par en cola toma su sitio), pasa un gap antes de que A retome con un nuevo par. Si la cola de A en otros pares es larga, el reloj corre.
- **Rate bursts iniciales**: los primeros segundos tras `op=setpreview` se ven tasas altas porque eMule promueve nuevas fuentes a la cola del head. Tras 30-60 s la tasa **baja a su nivel sostenido real**. Por eso una ventana de 30 s en lugar de 5 es importante: filtra el burst inicial.

### 3.5 LowID vs HighID

eMule define dos clases de cliente según conectividad TCP entrante:

- **HighID**: el cliente acepta conexiones entrantes en su puerto TCP (típicamente 4662) — bien por UPnP, port forwarding manual, IPv6 público, o estar en LAN sin NAT.
- **LowID**: el cliente **no** acepta conexiones entrantes. Otros pares que quieran conectar con él deben pedir al servidor que les haga **callback** ("oye, dile al cliente X que se conecte a mí en su sentido saliente").

El callback funciona pero añade ~100-500 ms de latencia al primer byte de cada nueva conexión. Y entre **dos LowIDs no se pueden conectar** vía servidor — depende exclusivamente de Kad relay o buddy-relay, que existe pero es más frágil.

#### 3.5.1 Tasa de LowID en la población

Datos del proyecto eMule sobre instalaciones recientes (estimación):
- ~65 % HighID en clientes con UPnP/IPv6.
- ~30 % LowID por NAT sin UPnP.
- ~5 % "ID=0" / sin conectividad útil.

Para streaming, una descarga con todas sus fuentes LowID puede llegar a tomar **el doble** de tiempo en alcanzar tasa sostenida que una con todas HighID. Es el peor caso silencioso del sistema actual: el usuario no lo ve, simplemente piensa "qué lento".

### 3.6 Kademlia: lo que aporta y lo que no

Kad sustituye al servidor eD2K como capa de:

- **Source publish/lookup**: publicar (keyword → fileHash) y (fileHash → IP:port).
- **Buddy relay**: ayudar a clientes LowID a relacionarse entre sí.
- **NAT traversal**: hole-punching coordinado por Kad.

Lo que **no** aporta:
- Bootstrap rápido. Un cliente que no haya cacheado `nodes.dat` puede tardar minutos en encontrar nodos vivos.
- API rica. Kad responde a las queries definidas, nada más.
- Garantía de presencia. Una keyword poco común puede tener todos sus publicadores caídos.

Las implicaciones para Smart Playback:
- Si Kad está frío, el primer `op=getsources` puede devolver 0 fuentes durante 30-60 s tras el bootstrap.
- Si el usuario lo intenta justo después de arrancar eMule, la UX es horrible aunque el sistema funcione perfectamente — simplemente Kad aún no está listo. Esto se reportó en v8.0.6 ("Sin resultados cuando estoy en Kad pero no en servidor") y se mitigó parcialmente con el fallback automático server→kad en v8.0.9, pero la causa profunda persiste: **el bootstrap de Kad es lento y no hay UX que lo explique**.

### 3.7 Conclusión del substrato

eD2K nos da:

- ✅ Verdad-de-disco fina (vía `.met` parseado correctamente).
- ✅ Inversión de política de chunk (`preview_prio`).
- ✅ Adquisición de fuentes multimodal (server + Kad + PEX).
- ✅ Integridad de contenido (MD4 chunks + AICH).

No nos da:

- ❌ Prioridad granular por pieza específica.
- ❌ Garantía de tasa.
- ❌ Garantía de latencia de primer byte.
- ❌ API rica de eMule.exe hacia la capa superior.

El reto del Smart Playback es **maximizar la información extraíble** del substrato disponible y **convertirla en UX honesta**.

---

## Cap. 4 — Anatomía del eSE Smart Playback (v8.0.19)

### 4.1 Mapa de componentes

```
┌──────────────────┐  TCP 8080  ┌─────────────────────────┐  TCP local  ┌──────────┐
│ Navegador HTML5  │───────────▶│ ese-server.exe (Node)   │────────────▶│ emule.exe│
│ <video> + MSE    │            │ - HTTP API              │   ?w=...    │ WebServer│
│ playback_state.js│◀───────────│ - ffmpeg-pipe stream    │             │ (C++)    │
└──────────────────┘            │ - .met parser           │             └──────────┘
                                │ - rolling rate window   │                  │
                                │ - ffprobe cache         │                  │ FS read
                                └─────────────────────────┘                  │
                                          │                                  ▼
                                          │ FS read                  Temp\NNN.part
                                          ▼                          Temp\NNN.part.met
                                  Temp\NNN.part(.met)                Incoming\<file>
                                  Incoming\<file>
```

Los actores:

1. **emule.exe (C++)**: descarga real. eMule clásico sin modificar (con preview-priority habilitado por `op=setpreview` que sí está parcheado en este fork).
2. **ese-server.exe (Node.js, vía pkg)**: cerebro. Polea `.met` cada 5 s, expone `/api/emule/downloads`, `/api/emule/probe`, `/api/emule/rate`, hace de proxy para `/api/stream/start/<n>` (que arranca un pipe ffmpeg → HTTP).
3. **Navegador**: el reproductor. Carga `playback_state.js` (la state machine), invoca `startSmartMonitor()` al pinchar Reproducir, y mantiene un `<video>` con un `src` que apunta a `/api/stream/start/<n>` o `/api/stream/completed/<name>`.

### 4.2 Flujo del usuario, pase a pase

#### Paso 0 — Discovery

El usuario hace una búsqueda ed2k o pincha una peli del grid Inicio. Si el fichero **no** existe en Incoming/Temp, el cliente llama a `/api/emule/smartsearch?q=<title>&year=<year>`. El backend lanza una búsqueda eD2K (server o Kad o ambos según el `searchMethod` configurado, default `auto`). Recibe resultados, los puntúa por sources/score, y devuelve los top N al cliente.

El cliente guarda esos resultados en `window._smartPlayResults` y arranca con el primero llamando a `trySmartSource(0)`.

#### Paso 1 — Iniciar descarga

`trySmartSource(idx)` hace POST a `/api/emule/download/start` con el `fileHash` MD4. El backend:

1. Invoca a eMule via `?w=transfer&op=ed2klink` para añadir el link.
2. Espera 1.5 s para que eMule cree el `.part` correspondiente.
3. Hace POST de `?w=transfer&op=setpreview&en=1&file=<hash>` para invertir la política de elección de chunk hacia el head.

A partir de aquí, eMule descarga normalmente — pero priorizando los primeros bloques del fichero.

#### Paso 2 — Monitor

El cliente invoca `monitorForFile(title, filename, sizeMB, sourceIdx, fileHash)`. Este es un wrapper delgado (v8.0.16) que delega en `startSmartMonitor()` del módulo `playback_state.js`.

`startSmartMonitor` crea un contexto:

```js
ctx = {
  movieTitle, expectedHash, sourceIndex,
  ui: { statusEl, progressEl, titleEl, actionsEl },
  state: 'INIT',
  stateEnteredMs: now(),
  ticks: 0,
  download: null,    // último row de /api/emule/downloads matched por hash
  probe: null,       // último response de /api/emule/probe
  rate: null,        // último response de /api/emule/rate
  bitrateBps: null,
  requiredRateBps: null,
  stallCount: 0,
  videoEl: null,
}
```

Y arranca el primer tick. Los ticks llaman al método `runState(ctx)` que despacha según `ctx.state` actual. Cada estado decide la transición y el siguiente delay del tick.

#### Paso 3 — Máquina de estados S1..S7

| S | Nombre | Cadencia | Salida |
|---|---|---|---|
| S1 | INIT | 1.5 s | → S2 PROBE cuando hay descarga activa con head > 0 |
| S2 | PROBE | 3 s | → S3 SUSTAIN cuando ffprobe da bitrate/duración fiable |
| S3 | SUSTAIN | 2 s | → S4 HEAD_BUFFER cuando rate ≥ required AND head ≥ 15 MB |
| S4 | HEAD_BUFFER | 1 s | → S5 PLAYING (grace tick) |
| S5 | PLAYING | 5 s | → S6 STALL si lead < 10s AND rate < bitrate×0.8 |
| S6 | STALL | 3 s | → S5 si recupera; → FAIL si stallCount>2 o timeout 60s |
| S7 | COMPLETE | terminal | onComplete invoked |
| FAIL | terminal | onFail invoked con reason + remaining + retry |

Cada estado renderiza UI honesta:

- INIT: "Descargando 0/4500 MB · inicio contiguo 0 MB"
- PROBE: "Analizando archivo · ffprobe: analizando container"
- SUSTAIN: "↓ 380 KB/s · necesitas ≥ 520 KB/s · inicio 12/15 MB · bitrate 4200 kbps"
- HEAD_BUFFER: "Buffer listo · Iniciando reproducción..."
- PLAYING: "↓ 580 KB/s · buffer 18 s · posición 5 s"
- STALL: "Velocidad insuficiente · ↓ 60 KB/s · buffer 2 s · intento 1/2"

### 4.3 Endpoints backend

Tres endpoints alimentan la state machine, todos sobre el ese-server local:

#### `GET /api/emule/downloads`

Lista todos los `.part` del Temp con campos parseados:

```json
[
  {
    "partFile": "0042.part",
    "fileName": "Avatar.2009.1080p.x264.mkv",
    "fileHash": "AE9C...DE",
    "sizeMB": 4500,           // logical (stat.size)
    "sizeBytes": 4718592000,
    "totalMB": 4500,          // de FT_FILESIZE (igual aquí)
    "totalBytes": 4718592000,
    "downloadedMB": 200,      // de gap-sum
    "downloadedBytes": 209715200,
    "headContiguousMB": 50,   // de min(gapStarts)
    "headContiguousBytes": 52428800,
    "firstGapStart": 52428800,
    "firstGapEnd": 4718592000,
    "gapCount": 1,
    "metParseOk": true,       // v8.0.19: si false, los campos arriba son 0/pesimistas
    "progress": 4.4,
    "partPath": "C:\\...\\Temp\\0042.part",
    "lastModified": 1715846400000,
    "active": true            // mtime < 30s
  }
]
```

#### `GET /api/emule/probe?file=NNNN.part`

Lanza ffprobe sobre el `.part` parcial:

```json
{
  "ready": true,
  "container": "matroska",
  "duration": 9000,
  "bitrate": 4192000,
  "sizeBytes": 4718592000,
  "hasVideo": true,
  "hasAudio": true,
  "videoCodec": "h264",
  "audioCodec": "ac3",
  "width": 1920,
  "height": 1080,
  "audioChannels": 6,
  "audioSampleRate": 48000
}
```

Cacheado 60 s. Si `headContiguousBytes < 5 MB`, devuelve `{ready:false, reason:"head_too_small"}` sin invocar ffprobe.

#### `GET /api/emule/rate?file=NNNN.part&windowSec=60`

Tasa media sobre ventana rodante:

```json
{
  "ready": true,
  "bytesPerSec": 520000,
  "kbPerSec": 508,
  "windowSec": 60,
  "samples": 12,
  "firstSampleMsAgo": 58432,
  "lastSampleMsAgo": 1245
}
```

Las muestras se rellenan automáticamente desde `/api/emule/downloads` (cada poll alimenta el buffer rolling con `(t, downloadedBytes)`). Trimming a 120 s para acotar memoria.

### 4.4 Verdad-de-disco vs verdad-de-experiencia

Hay una distinción semántica importante que el sistema actual a veces difumina:

- **Verdad-de-disco**: lo que el `.met` y `stat.blocks` dicen objetivamente.
- **Verdad-de-experiencia**: lo que el reproductor humano percibirá.

Ejemplos donde difieren:

- `B_head = 50 MB` (verdad-de-disco) pero el codec es H.265 cuyo decoder necesita un I-frame para arrancar, y el primer I-frame está en byte 8 MB. ffprobe puede leer container pero el `<video>` no decodea hasta byte 8 MB.
- El `.met` registra gaps correctamente pero hay corrupción de hash en el chunk justo antes del playhead. eMule re-pedirá ese chunk; durante el re-pedido el `<video>` se atascará. La verdad-de-disco dice "buffer ok", la verdad-de-experiencia dice "se ha colgado".
- Bitrate estimado por ffprobe es 4200 kbps (verdad-de-disco) pero la película es VBR y el momento `D_played(t)` está en un pico de 12000 kbps. La verdad-de-experiencia es "necesitas más buffer del que el bitrate medio te diría".

El sistema actual gestiona el primer caso al exigir que `B_head ≥ 15 MB` (margen para múltiples I-frames). El segundo y tercero **no** los detecta — son los responsables de los stalls "inexplicables" tras varios minutos de reproducción correcta.

### 4.5 Las fronteras del v8.0.19

Con la fixea de v8.0.19 al parser y el state machine de v8.0.16, lo que el sistema **sí** hace:

- Detecta head bytes reales (no logical size).
- Probe ffmpeg en cuanto hay >5 MB head para sacar bitrate real.
- Gating por tasa sostenida sobre ventana de 30 s.
- Pausa el `<video>` cuando el buffer cae bajo umbral simultáneo con tasa baja.
- Cambia automáticamente a la siguiente fuente cuando una sesión muestra 2 stalls.
- Reporta estados textualmente al usuario en cada tick.

Lo que **no** hace todavía:

- Predicción anticipada de stalls por varianza de bitrate VBR.
- Decisión de transcoding dinámico (bajar de 1080p a 720p si la red no aguanta).
- Selección de fuente por capacidad (sigue siendo orden de score de la búsqueda).
- Re-priming del `op=setpreview` cuando la descarga progresa y necesita head más profundo.
- Telemetría QoE.
- Recuperación automática de stalls por hash corrupto.

Estos son los puntos de mejora del Cap. 9.

---

## Cap. 5 — Matemática del sustained-rate gate

### 5.1 El problema en una línea

**¿Cuándo es seguro empezar a reproducir un `.part` parcialmente descargado de modo que la probabilidad de stall sea menor que ε?**

Equivalente: dado un fichero de duración `D` segundos a bitrate `BR` bytes/segundo, tamaño total `B_total = BR × D`, con `B_head(t)` bytes contiguos descargados y tasa observada sostenida `R̂(t)`, **¿podemos jugar todo el contenido sin que el playhead alcance el head?**

### 5.2 Condición necesaria (rate)

El playhead avanza a `BR` bytes/s. El head avanza a `R̂` bytes/s. Para que el playhead **no** alcance al head:

```
R̂ × t + B_head(t₀) ≥ BR × t + B_played(t₀)    para todo t ≥ t₀
```

Asumiendo `B_played(t₀) = 0` (empezamos en posición 0):

```
B_head(t₀) ≥ (BR - R̂) × t
```

Si `R̂ ≥ BR`, la cota es siempre satisfecha (la descarga gana al playhead). Si `R̂ < BR`, la película de duración `D` requiere head inicial:

```
B_head(t₀) ≥ (BR - R̂) × D
```

Y como `B_head ≤ B_total = BR × D`:

```
(BR - R̂) × D ≤ BR × D
⇒ R̂ ≥ 0     (trivialmente cierto)
```

Es decir: **si tienes ya todo el head reservado (B_head = B_total) puedes jugar a cualquier rate ≥ 0**, porque ya tienes el fichero entero. En el límite degenerado, "descarga primero, juega después" es solución pero no es la pregunta.

La pregunta interesante es: **¿con qué head mínimo puedo arrancar dado un rate observado R̂?**

```
B_head_min = max(0, (BR - R̂)) × D
```

Si `R̂ ≥ BR`: head_min = 0, puedes arrancar inmediatamente.
Si `R̂ = BR × 0.5`: head_min = 0.5 × B_total, necesitas medio fichero adelantado.
Si `R̂ = 0`: head_min = B_total, fichero entero.

### 5.3 Por qué "10 minutos de buffer no me sirven"

El usuario lo dijo claramente: *"de qué me sirve tener 10 minutos de reproducción disponible si luego descargo a 100 kbps y se me va a cortar"*. La intuición es correcta y la matemática de §5.2 la formaliza:

Película de 2h (D = 7200 s) a BR = 4000 kbps = 500 KB/s.
- B_total = 7200 × 500 KB = 3.6 GB.
- "10 min de buffer" = 10×60 × 500 KB = **300 MB de head**.
- Si la tasa observada es R̂ = 100 kbps = 12.5 KB/s:
  - head_min = (500 - 12.5) × 7200 = **3.51 GB** de head necesarios.
- 300 MB << 3.51 GB. La probabilidad de stall es **casi 1**.

El gate de v8.0.15 introdujo la condición correcta:

```
R̂_sostenida ≥ BR × safety_factor
con safety_factor = 1.3
y piso R̂_min = 256 KB/s
```

Que reescrito:

```
empezar si R̂ ≥ 1.3 × BR  ∨  B_head ≥ B_total
```

La interpretación: o **descargas más rápido de lo que reproduces** (con 30 % de margen), o **ya tienes el fichero**.

### 5.4 La factura del safety factor

¿Por qué 1.3 y no 1.0 o 1.5?

- **1.0** es el límite teórico de "descarga sin colchón". Cualquier perturbación menor (un par lento entra al slot, eMule re-pide un chunk corrupto, una fluctuación de tasa de 1 segundo) → stall.
- **1.3** da ~30 % de headroom. Sobrevive a una caída momentánea del 23 % de la tasa observada (porque `R̂ × 0.77 ≥ BR`).
- **1.5** sería más conservador pero alarga inútilmente el time-to-first-frame en el caso medio.

Empíricamente 1.3 funciona razonablemente con la varianza típica de eD2K (donde caídas del 30-40 % puntuales son frecuentes pero las del 50 % son raras).

Una mejora futura: hacer el safety_factor **adaptativo** a la varianza observada de R(t). Más en §9.

### 5.5 La ventana rodante: ¿cuántos segundos?

`R̂(t) = (B(t) - B(t - w)) / w` para alguna ventana `w`. La elección de `w` es un compromiso:

- **w pequeño (5-10 s)**: reactivo a cambios reales, pero contaminado por bursts. eMule, al recibir un chunk de 9 MB, puede mostrar tasa instantánea pico durante 30-60 s.
- **w grande (60-120 s)**: filtra bursts pero retrasa la detección de degradación. Si la tasa cae en t=60 y la ventana es 120 s, la respuesta del sistema llega en t=180 (3 ticks de 5 s).

El sistema actual usa:
- `playback_state.js` SUSTAIN/PLAYING tick: ventana de 30 s. Compromiso razonable.
- `/api/emule/rate` default: 60 s. Más conservador para gating del PROBE→SUSTAIN.

La ventana óptima es probablemente **función del bitrate**: a bitrates bajos (radio, podcast) basta 10 s; a 4K 25-50 Mbps necesitas 60-90 s para que el ruido de slot-switch no domine.

### 5.6 El umbral de stall en PLAYING

Durante PLAYING (S5), el watchdog cada 5 s evalúa:

```
lead_sec(t) = (B_head(t) - B_played(t)) / BR
trigger_stall = (lead_sec < 10 s) AND (R̂ < BR × 0.8)
```

Razonamiento:
- `lead_sec < 10 s`: hay menos de 10 s de buffer por delante. Si la tasa se mantuviera, el playhead alcanzaría el head en < 10 s.
- `R̂ < BR × 0.8`: además la tasa está bajo el bitrate (con margen del 20 %). No vamos a recuperar buffer.

Si **solo** uno de los dos se cumple, no es stall:
- `lead bajo + tasa alta` → estamos recuperando, el buffer crecerá → no pause.
- `lead alto + tasa baja` → tenemos colchón, podemos sobrevivir un rato a tasa baja → no pause aún.

Solo cuando **ambos** se cumplen, pausamos. Esto evita pausas espurias por oscilaciones momentáneas.

### 5.7 La condición de recuperación

En S6 STALL, la condición para volver a S5 PLAYING es:

```
recover = (lead_sec ≥ 20 s) AND (R̂ ≥ BR)
```

Doble margen sobre el trigger: requerimos 2× el lead mínimo y rate ≥ bitrate exacto (no × 0.8). La idea es **no hacer ping-pong** entre PLAYING y STALL si la tasa oscila alrededor del trigger.

Esto cumple los criterios de **hysteresis** clásica para sistemas con state-machine: distancia clara entre los dos thresholds.

### 5.8 El parámetro stallCount

`MAX_STALL_COUNT = 2`. La tercera vez que entramos en STALL en la misma sesión, fallamos con reason `repeated_stalls` y disparamos source-switch.

Razonamiento: una fuente que estalla repetidamente probablemente tiene un problema sistémico (capacidad limitada del par, congestion en su upstream). Cambiar a otra fuente es probablemente más productivo que esperar.

**Refinamiento futuro** (§9): contar stalls separados ≥ 60 s entre sí (no 2 en 30 s, que pueden ser el mismo evento), y considerar `stallCount` proporcional a la duración total de la sesión (1 stall en 2h vs 2 stalls en 10 min son escenarios distintos).

### 5.9 El time-to-first-frame

Llamamos `TTFF(t₀)` al tiempo desde que el usuario clica Reproducir (t₀) hasta que el primer fotograma aparece en pantalla. Se descompone:

```
TTFF = T_init + T_probe + T_sustain + T_head + T_player_init
     ≈ T_init + T_probe + T_sustain + ~1 s
```

con:

- `T_init`: tiempo en S1, hasta que `B_head > 0`. **Domina por el bootstrap eD2K** (búsqueda → conexión a primer par → primer chunk). Típicamente 5-30 s en condiciones normales, hasta 60-120 s en Kad frío.
- `T_probe`: tiempo en S2, hasta que `B_head ≥ 5 MB` AND ffprobe responde. Función de la tasa: si R = 500 KB/s, son 10 s solo de espera bytes; + el ffprobe que tarda 1-3 s sobre H.264.
- `T_sustain`: tiempo en S3, hasta que R̂ ≥ BR×1.3 AND B_head ≥ 15 MB. Domina la **estabilización del rate**: con ventana de 30 s, el sistema necesita ~30-45 s para tener una medida fiable.
- `T_head`: 1 s grace en S4.
- `T_player_init`: ~1 s para que el `<video>` reciba los primeros bytes via ffmpeg-pipe y decodee el primer keyframe.

**TTFF típico actual: 50-90 s**. Compárese con Netflix (1-3 s). La diferencia es ~30× — explicable por (a) bootstrap eD2K, (b) ventana de 30 s del rate gate, (c) necesidad de head ≥ 15 MB.

**TTFF teórico mínimo** sobre eD2K: 5-15 s. Lo discutimos en §8.

### 5.10 Recapitulación de la matemática

| Variable | Fórmula | Significado |
|---|---|---|
| `head_min` | `max(0, BR - R̂) × D` | Head necesario para garantizar reproducción si la tasa se mantuviera |
| `safety_factor` | 1.3 | Headroom sobre BR para sobrevivir caídas momentáneas |
| `stall_trigger` | `lead_sec < 10 AND R̂ < BR × 0.8` | Cuándo pausar |
| `recovery` | `lead_sec ≥ 20 AND R̂ ≥ BR` | Cuándo reanudar |
| `MAX_STALL_COUNT` | 2 | Cuántos stalls antes de cambiar fuente |
| `TTFF` | `T_init + T_probe + T_sustain + 1` | Tiempo a primer fotograma |

Estos son los parámetros tunables. Lo importante NO es que estos valores estén "calibrados óptimamente" (no lo están — son razonables). Lo importante es que **están explícitos en el código** y son tunables a posteriori basado en telemetría. Compárese con el pre-v8.0.15 donde el gating era `dlMB >= 50` (cinco bytes mágicos, sin relación con el bitrate).

---

## Cap. 6 — Casos de borde: LowID, Kad-only, firewalls, fuentes escasas

### 6.1 La taxonomía de fallos del substrato

Cuando algo va mal en la reproducción al vuelo, casi siempre la causa raíz es alguna de estas:

| Categoría | Síntoma típico | Diagnóstico |
|---|---|---|
| **A. Sin fuentes** | `T_init` muy largo, "Esperando que eMule reciba datos..." | Búsqueda devuelve poco / nada / fuentes muertas |
| **B. Fuentes lentas** | `T_sustain` infinito o falla con `low_rate` | Pocas fuentes activas, todas lentas |
| **C. Stalls intermitentes** | PLAYING → STALL repetido, `repeated_stalls` | Tasa oscila por slot-rotation |
| **D. NAT mutuo** | `T_init` muy largo, callbacks fallidos | Doble LowID, hole-punching fallido |
| **E. Kad frío** | "Sin resultados" durante minutos tras arranque | Kad no bootstrappeado |
| **F. Servidor caído** | Idem si solo servidor | No fallback automático a Kad si no está en `auto` |
| **G. Container exótico** | PROBE falla, `ffprobe_failed` permanente | Codec/container que ffprobe parcial no procesa |

Las cubrimos en orden.

### 6.2 Categoría A: pocas o nulas fuentes

**Detección**: el `/api/emule/downloads` no muestra el partFile como activo. `dl.active=false` (mtime > 30 s sin update).

**Causa raíz típica**: el `eD2K hash` que se pidió descargar (vía `op=ed2klink`) tiene ahora mismo 0 o pocos publicadores Kad y/o el servidor eD2K no devuelve sources.

**Comportamiento actual del state machine**:

- Estado S1 INIT. Polea `/api/emule/downloads`.
- Tras `MAX_STATE_SEC.INIT = 120 s` sin promoción a S2, llama `fail('no_data')`.
- UI: "Sin datos recibidos · Probar otra fuente (N disponibles) · Dejar descargando · Volver".

**Lo que funciona**:
- El fallback a otra fuente es automático.
- La UI es honesta sobre el problema.

**Lo que no funciona**:
- 120 s es **mucho tiempo** para descubrir que una fuente no tiene publicadores. eMule debería tener señales antes:
  - Si tras 15 s ningún par está conectado **y** estamos en HighID **y** Kad está bootstrappeado, casi seguro la fuente está muerta.
  - Si tras 30 s la cola en pares conectados es > 100 (estamos esperando turno), la fuente está saturada — distinto problema.

**Mejora futura propuesta**: nuevo endpoint `/api/emule/peers?file=<hash>` que devuelva número de pares conectados, número en cola, queue rank medio. El state machine podría decidir "fail fast" en < 30 s si las señales son inequívocas.

### 6.3 Categoría B: fuentes lentas

**Detección**: el estado avanza a S2 PROBE y posiblemente a S3 SUSTAIN, pero R̂ se queda crónicamente bajo `required_rate`. Tras `MAX_STATE_SEC.SUSTAIN = 90 s` se dispara `fail('low_rate')`.

**Causa raíz típica**: hay pares conectados pero su upstream agregado no llega al bitrate del contenido. Frecuente en archivos de baja popularidad (pocas fuentes) o de tamaño grande (4K) donde el bitrate domina.

**Comportamiento actual**: source-switch automático. Si la siguiente fuente tampoco aguanta, sigue rotando hasta agotar `_smartPlayResults`.

**Lo que funciona razonablemente**:
- El usuario ve el número de fuentes restantes y la opción de dejarlo en background.
- La rotación es ordenada (un fail por vez, no en paralelo).

**Lo que no funciona**:
- Las fuentes en `_smartPlayResults` están ordenadas por **score de la búsqueda** (completeSources × score). No por **velocidad esperada**, que es lo que importa aquí.
- Resultados con menos completeSources pero bitrate inferior (rip 720p vs el 1080p actual) podrían arrancar antes pero el sistema no los considera "siguiente fuente"; el usuario tendría que volver y elegir manualmente.

**Mejora futura propuesta**:
- Hint server-side: cuando un fail ocurre con `low_rate`, registrarlo y reordenar `_smartPlayResults` por una métrica combinada (sources × score × tamaño_inversamente_proporcional). Es decir: las próximas fuentes son las que combinan disponibilidad alta con bitrate bajo.
- Idea adicional: **transcoding al vuelo en el cliente**. Si la fuente tiene un bitrate de 8 Mbps que mi red de 5 Mbps no aguanta, ffmpeg-pipe puede transcodificar a 480p a 1.5 Mbps. El bitrate efectivo a consumir baja, el gating cambia. El downside: gasto de CPU local. Pero esto **convierte un fail en un éxito** y vale la pena.

### 6.4 Categoría C: stalls intermitentes

**Detección**: PLAYING → STALL → PLAYING → STALL en ciclos cortos. Tras 2 entradas a STALL, `repeated_stalls`.

**Causa raíz típica**: la tasa es marginal (justo en el umbral del safety_factor). Una caída temporal por slot-switch dispara el trigger; la recuperación reanuda; otro slot-switch pausa otra vez.

**Comportamiento actual**:
- Pausa el `<video>`.
- Reanuda cuando `lead_sec ≥ 20 AND R̂ ≥ BR`.
- Tras 2 stalls, source-switch.

**Lo que funciona**:
- La hysteresis evita ping-pong dentro del mismo stall.
- El conteo de stalls es honesto.

**Lo que no funciona**:
- Si el sistema arranca **justo en el umbral**, va a hacer stall→recover→stall→recover varias veces antes de fallar. Cada ciclo es 30-90 s. UX horrible aunque al final acabe haciendo lo correcto.
- El conteo `stallCount` no distingue "2 stalls en 10 min" de "2 stalls en 2 horas". La segunda situación es aceptable y NO debería disparar source-switch.

**Mejora futura propuesta**:
- Modificar `stallCount` para que sea una **media móvil exponencial** de stalls por unidad de tiempo. Si la frecuencia supera 1 stall / 10 min, source-switch. Si baja de eso, no.
- **Pre-emptive transcoding**: cuando el sistema detecta varianza alta de R̂ (incluso si la media supera required_rate), pre-iniciar un pipeline transcoding a bitrate menor en background. Si stall ocurre, switchear al pipeline transcoded sin re-buscar fuente.

### 6.5 Categoría D: NAT mutuo (doble LowID)

**Detección**: el `.part` se crea (eMule lo añade a la cola) pero `active=false` indefinidamente. eMule muestra "0/0 connecting" o "Source obtained, callback failed".

**Causa raíz**: ambos clientes (yo y la fuente) son LowID. El servidor no puede mediar el callback porque el callback va a otra ID también LowID. Sin un buddy-relay disponible, no se establece la conexión.

**Comportamiento actual**: state machine espera en INIT hasta el timeout. Igual que categoría A.

**Lo que no funciona**:
- El sistema no diagnostica que el problema es **doble-LowID**, lo trata como "fuente muerta".
- Si tuviera un buddy-relay disponible (Kad lo soporta), debería disparar el flow correspondiente.

**Mejora futura propuesta**:
- Endpoint `/api/emule/diag/conn?file=<hash>` que devuelva información rica: pares conocidos para este hash, su ID-type (HighID/LowID/Unknown), si el callback ha sido intentado, etc.
- Si todas las fuentes son LowID y nosotros también lo somos, ofrecer al usuario:
  - "Tu router no permite conexiones entrantes. Activa UPnP, abre el puerto 4662, o conecta vía Tailscale / Tor." (botones de acción).
- Si Kad-bootstrap está OK pero buddy-relay no se ha establecido, intentar más agresivamente.

### 6.6 Categoría E: Kad frío

**Detección**: arrancar eMule y darle a Reproducir inmediatamente. Kad muestra "Connecting" durante minutos. Las búsquedas devuelven 0 fuentes.

**Causa raíz**: el bootstrap de Kad requiere encontrar nodos vivos en `nodes.dat`. Si está stale (más de 30 días), muchos nodos están muertos y la búsqueda fan-out tarda.

**Comportamiento actual**:
- `smartsearch` devuelve 0.
- El usuario recibe "Sin resultados".
- v8.0.6 introdujo el default `auto` que fallback a Kad cuando server no responde, pero si **Kad tampoco**, sigue siendo 0.

**Lo que no funciona**:
- La UI no explica al usuario que Kad está bootstrappeando. Le dice "Sin resultados" como si la película no existiera.
- No hay un endpoint que diga "Kad status: bootstrapping (12 nodos vivos, esperando)".

**Mejora futura propuesta**:
- Endpoint `/api/emule/kad/status` que devuelva nodos conectados, lookups activos, edad del `nodes.dat`.
- UI de búsqueda: si Kad < 50 nodos vivos AND server no conectado, mostrar banner: "Conectando a Kad... reintentar en X s".
- Configuración: bootstrap automático contra una lista de fallback de nodos públicos en `data/kad_bootstrap.dat`.

### 6.7 Categoría F: servidor eD2K caído

**Detección**: el cliente está configurado con searchMethod=server y el servidor está caído (o el cliente fue desconectado). Búsqueda devuelve 0.

**Comportamiento actual**:
- v8.0.6+: default es `auto`, así que cae a Kad → suele funcionar.
- Si el usuario tiene `server` explícito, falla.

**Mejora futura propuesta**:
- Forzar `auto` siempre, ignorando configuración legacy (con migración silenciosa). El servidor explícito tendría sentido para "no quiero usar Kad" pero ya v8.0.1 priorizó "100% gratis sin dominios" y Kad es la mejor opción honesta.

### 6.8 Categoría G: contenedor / codec exótico

**Detección**: PROBE en S2 no avanza. `/api/emule/probe` devuelve `{ready:false, reason:"ffprobe_failed"}` repetidamente.

**Casos típicos**:
- H.265 (HEVC) con head parcial sin keyframe accesible. ffprobe puede tardar 10-30 s o fallar.
- MKV con headers al final (CRC32 al final del fichero). El head puede no tener metadata.
- AV1 con un codec config block que ffprobe no encuentra en el chunk inicial.
- Subtitle tracks comprimidos que ffprobe no entiende sin el container completo.

**Comportamiento actual**:
- v8.0.16 incluye un fallback en S2: si `MAX_STATE_SEC.PROBE = 45 s` se cumple sin éxito, se promueve a S3 con bitrate **estimado** (totalBytes × 8 / 90min, ó floor 256 KB/s).
- El estimado puede ser muy malo (típicamente subestima para 4K, sobreestima para 480p).

**Lo que no funciona**:
- El estimado de bitrate puede dar lugar a falsos OK o falsos fail en SUSTAIN.
- El usuario no ve que ffprobe está fallando — solo ve que tarda.

**Mejora futura propuesta**:
- ffprobe con timeout más corto (5 s) + fallback a estimación a partir de `B_total × 8 / D_estimada_por_resolución`.
- Tabla heurística de bitrate por resolución (extraída del filename si está): 480p=1500kbps, 720p=3000, 1080p=5000, 4K=20000.
- Si el container no se puede leer en absoluto, **transcoding upstream**: en lugar de servir el `.part` raw, lanzar ffmpeg para remuxar a fMP4 conforme lo va leyendo. Esto destapa todos los containers exóticos al coste de CPU.

---

## Cap. 7 — Superficie de seguridad y privacidad

### 7.1 Modelo de amenaza

¿De quién nos protegemos?

| Actor | Capacidad | Amenaza típica |
|---|---|---|
| **Par malicioso** | Conecta a mí como una fuente eD2K. | Envía chunks corruptos para envenenar la descarga (rare-poisoning). |
| **Servidor malicioso** | Está en mi lista de servidores. | Devuelve fuentes falsas o filtra mi actividad. |
| **Nodo Kad malicioso** | Está en mi tabla de routing. | Mismo. Más difícil de filtrar por volumen. |
| **ISP / observador pasivo de red** | Puede ver mis paquetes salida/entrada. | Asocia mi IP a contenidos vía inspección de tráfico. |
| **Adversario local LAN** | Está en mi red local. | Habla con ese-server vía HTTP. |
| **Adversario en mi máquina** | Tiene proceso ejecutándose en mi cuenta. | Lee `eSE_pass.bin`, lee `.met`, ataca la API. |

Para Smart Playback, los más relevantes son **par malicioso** (envenenamiento de chunks) y **observador pasivo** (análisis de qué se mira).

### 7.2 Integridad del contenido

eD2K incluye dos capas de hash:

- **MD4 root hash**: identifica el fichero entero. No basta para detectar corrupción intermedia.
- **MD4 part hash**: cada parte de 9.28 MB tiene su MD4. Se verifica cuando la parte completa entera. Si falla, eMule descarta la parte entera y la re-pide.
- **AICH (Advanced Intelligent Corruption Handling)**: hashes por sub-bloque de 180 KB en un árbol Merkle. Si una parte falla su MD4, AICH localiza el sub-bloque corrupto y solo re-pide ese.

Para Smart Playback:
- **Antes de que el watcher pueda decir "buffer listo"**, la parte 0 debe haber pasado verificación de hash. Eso garantiza que el inicio que servimos vía ffmpeg-pipe es íntegro.
- **Durante PLAYING**, si el watchdog detecta stall **y** el `.met` muestra que una parte previa ha sido revertida (re-pedida), podemos inferir que hubo corrupción y reportar al usuario "Reverificando integridad" en lugar de "Buffer bajo".

**Mejora futura**: monitorear la métrica de "partes revertidas por la verificación MD4" — si es alta para una fuente, banear esa fuente de futuros source-switches.

### 7.3 Envenenamiento por sources

Un par malicioso puede:

1. Anunciar tener un hash que no tiene → cuando se conectas, no entrega nada → el slot wait es eterno.
2. Enviarte chunks corruptos sistemáticamente → eMule los detecta y re-pide.

Las defensas eD2K:
- Score de pares en `clients.met`: si un par envía corrupción reiteradamente, su score baja, eMule deja de pedirle.
- Source diversity: las partes se piden a múltiples pares; si uno está corrupto, los otros no.

Para Smart Playback el impacto es:
- (1) afecta `T_init`. No tenemos defensa específica más allá del timeout.
- (2) afecta `T_sustain` por la sobre-descarga (chunks que vienen pero se descartan).

**Mejora futura**: telemetría de "chunks descartados por verificación" expuesta vía `/api/emule/diag`. Si > 10 % de los recibidos se descartan, sugerir al usuario que cambie de fuente.

### 7.4 Análisis de tráfico

Un observador pasivo (ISP, gobierno, vecino con WireShark) puede:

- Ver tu IP conectando a IPs de pares eD2K.
- Inferir qué hashes pides por las búsquedas Kad/server (que no van cifradas a nivel aplicación, aunque obfuscation existe).
- Correlar tu actividad temporal con catálogos públicos.

Defensas actuales del fork (V1 Privacy, en docs/thesis/ rama hungry-dhawan-84bd82):

- **Onion tunnels**: cuando privacy mode = onion, las búsquedas Kad pasan por 1-3 hops cifrados antes de salir.
- **Cover traffic**: tráfico falso (CELL_PADDING) inyectado para confundir análisis de timing.
- **Sealed channels**: para Live, no aplicable a VOD eD2K.

Para Smart Playback:
- **Si privacy mode = onion**, el `op=ed2klink` y `op=setpreview` salen por el cliente eMule (no por el túnel) — la conexión a las fuentes es directa-IP. Esto deja la metadata expuesta.
- **Para VOD privacy real**, las conexiones a fuentes eD2K tendrían que pasar también por el túnel. No implementado en v8.0.x; está en el roadmap v8.1.

### 7.5 Superficie de la propia API

`ese-server.exe` expone HTTP en :8080 (o 8081-8089 como fallback). Por defecto bindea a 0.0.0.0 (todas las interfaces), lo que significa:

- **Cualquier dispositivo en la LAN** puede llegar a `http://<mi-ip-local>:8080/`.
- Si UPnP está activo, **cualquier IP de internet** puede llegar a `http://<mi-ip-pública>:8080/`.

Defensas v7.5+:
- Autenticación obligatoria: contraseña por sesión (`eSE_pass.bin`). Sin pass, las requests sin sesión válida devuelven 403.
- Anti DNS-rebinding: verificación del Host header.
- Path traversal blocked en `/api/stream/*`.
- CSRF protection: `/api/emule/download/action` requiere POST o `X-Requested-With` header.

Para Smart Playback específicamente:
- `/api/emule/probe` y `/api/emule/rate` son **lectura**. Riesgo bajo. Pero filtran qué `.part` tengo activo a quien pregunte sin auth (currently anonymous-allowed). Considerar gate detrás de auth.
- `/api/emule/downloads` filtra **todos** mis downloads activos. Crítico.

**Mejora futura propuesta**: requerir auth para todos los endpoints `/api/emule/*`. Si la UI ya tiene sesión válida (todas las páginas la cargan), no hay UX impacto. Sí cierra al observador casual de LAN.

### 7.6 Recapitulación

| Amenaza | Defensa actual | Mejora propuesta |
|---|---|---|
| Chunks corruptos | MD4 + AICH (eMule) | Telemetría visible, banear fuentes envenenadas |
| Fuentes falsas | Score eMule | Timeout temprano, telemetría |
| Análisis de tráfico LAN | (ninguna) | Auth en endpoints `/api/emule/*` |
| Análisis de tráfico WAN | UPnP opcional + V1 onion (limitado a search) | VOD-onion: conexión a fuentes vía túnel |
| LAN spoofing | Anti DNS-rebinding | OK |
| Robo `eSE_pass.bin` | Permisos NTFS de la cuenta | OK pero no perfecto |

---

## Cap. 8 — El mundo ideal: cota inferior del *time to first frame*

### 8.1 Definición del óptimo

Sea `Σ` el conjunto de fuentes disponibles para un fichero con hash `h`. Sea `r_i` la tasa de subida sostenida de la fuente `i` (en bytes/s), y sea `BR` el bitrate del contenido (bytes/s). Asumamos:

- Round-trip time medio cliente↔fuente: `T_rtt`.
- Tiempo de discovery de la primera fuente: `T_disc`.
- Capacidad de descarga del cliente: `C_dl` (límite del ISP).
- `R_total = min(C_dl, Σ_i r_i)`.

**Cota inferior teórica del time-to-first-frame** asumiendo el reproductor más simple posible (1 keyframe en byte 0, ningún probe necesario, ningún gating de rate):

```
TTFF_min = T_disc + T_rtt + (B_keyframe / R_total)
```

Para una película H.264 típica con keyframe en los primeros 64 KB:
- T_disc ≈ 1-5 s (Kad lookup o server response).
- T_rtt ≈ 0.1-0.5 s.
- B_keyframe / R_total ≈ 0.5-2 s (depende de R_total).

**TTFF_min teórico**: ~2-8 s.

### 8.2 Lo que arrastra el actual TTFF a 50-90 s

Comparando con el modelo del Cap. 5:

```
TTFF_actual = T_init + T_probe + T_sustain + 1
            ≈ T_disc + T_rtt + (B_head_min / R_initial)        ← T_init
            + (B_5MB / R_initial + T_ffprobe)                  ← T_probe
            + 30 s (ventana de rate sostenido)                 ← T_sustain
            + 1 s                                              ← T_head_buffer
```

Donde:
- `B_head_min` en práctica está dominado por el gating de `head ≥ 15 MB` para SUSTAIN. A R = 1 MB/s son 15 s.
- `T_ffprobe` con ffprobe sobre `.part` parcial: 1-5 s.
- 30 s de ventana del SUSTAIN: dura **por defecto** porque la primera ventana confiable necesita 30 s de muestras.

**Las tres mejoras más impactantes**, en orden:

1. **Reducir la ventana de SUSTAIN** o **basar la decisión en muestras predictivas** en lugar de solo media empírica → ahorra 20-25 s.
2. **Eliminar el head ≥ 15 MB** sustituyéndolo por "head ≥ B_keyframe + B_buffer_de_ffmpeg" → 1 MB en lugar de 15 MB → ahorra 10-15 s a tasas típicas.
3. **Paralelizar ffprobe con la descarga inicial**: empezar ffprobe sobre lo que tenemos a B_head=2 MB y, si responde, no esperar a B_head=5 MB → ahorra 3-5 s.

Sumando: -33 a -45 s. Llegamos a TTFF ~ 15-30 s, no 2-8 s pero la mitad.

Para llegar al óptimo teórico (2-8 s) hay que ir más lejos:

### 8.3 La idea de "casi como descarga directa"

El usuario describió la sensación deseada: *"posible problemas... casi como descarga directa"*. La pregunta es **qué hace falta para que sea indistinguible**.

Descarga directa pura: clicas un URL HTTP → el primer byte llega tras 1 RTT → el video reproduce. Sin gating, sin probe, sin nada.

Para clonar eso sobre eD2K hace falta:

#### 8.3.1 Inversión total de prioridad de chunk hacia el head

Sin esperar al `setpreview` post-hoc, sino **declarar al añadir el fichero** que es para streaming. eMule debería:

- Asignar `m_bpreviewprio = true` desde el primer momento.
- En la rare-piece selection, fijar `priority(piece_i) = -i` (las primeras son las más prioritarias).
- En la cola de pares, abrir slots adicionales si el agregado de los actuales no alcanza el bitrate.

Esto requiere modificación a `WebServer.cpp` para añadir un `op=streamprio` o similar. Es un cambio pequeño en el binario eMule.

#### 8.3.2 Speculative ffprobe

Comenzar ffprobe **con un timeout corto (1 s)** en cuanto B_head > 256 KB. Repetir cada 500 ms hasta que responda. La mayoría de containers (MP4, MKV) tienen su `moov` o `Segment Info` en los primeros 100 KB. ffprobe puede responder con `duration` y `bitrate` aproximados sin haber leído todo.

#### 8.3.3 Inferencia de bitrate sin ffprobe

Heurística: a partir del **filename** y del **tamaño total**, estimar bitrate:

- `Movie.2023.1080p.BluRay.x264-GROUP.mkv` 8 GB → 1080p × 8 GB = ~5000 kbps (rip blu-ray típico).
- `Show.S01E01.720p.WEB-DL.mp4` 2 GB → 720p × 2 GB / 45min = ~6000 kbps.
- Tabla de regex + heurísticas.

Si la estimación está en el rango ±30 % de la real, el gating funciona. Y obviamos los 1-5 s de ffprobe en el camino crítico.

#### 8.3.4 Ventana de SUSTAIN reducida

Si la decisión de empezar se toma con muestras predictivas (no solo media), 30 s pasa a 10-15 s:

- A los 5 s tenemos 1-2 muestras. La media es ruido.
- A los 10 s tenemos 3-4 muestras. La media tiene ±50 % de varianza.
- A los 30 s tenemos 10-12 muestras. ±15 % de varianza.

Pero un **filtro Kalman** o un **EWMA** con pesos adaptativos puede dar una estimación útil mucho antes:

```
R̂(t) = α × r_inst(t) + (1-α) × R̂(t-1)
```

Con `α` proporcional al producto (incertidumbre actual × confidence del último burst). Decisión en 10-15 s con varianza efectiva similar a la media 30 s clásica.

#### 8.3.5 Head buffer = 1 keyframe

En lugar de exigir B_head ≥ 15 MB (15 segundos de vídeo a 1 MB/s), exigir solo:

- Container parseable (1-2 MB en el peor caso).
- Primer keyframe (32 KB - 512 KB).
- Cola de bytes suficiente para que ffmpeg no se quede sin input (~500 KB).

Total: **~1-2 MB** de head mínimo. A tasa de 1 MB/s, son 1-2 s. A 100 KB/s (caso límite), 10-20 s — pero entonces el gating de rate sostenido lo habría bloqueado antes.

#### 8.3.6 Bundle de optimizaciones: TTFF objetivo

| Mejora | Ahorro |
|---|---|
| Prio del head desde el primer momento | -5 s a -15 s en T_init |
| Speculative ffprobe | -3 s a -5 s en T_probe |
| Inferencia de bitrate sin ffprobe (fallback) | -1 s a -3 s |
| Ventana de SUSTAIN con Kalman | -15 s a -20 s |
| Head buffer = 1 keyframe (~1 MB) | -10 s a -15 s |
| **TOTAL** | **-34 s a -58 s** |

Partiendo de TTFF actual ~60 s → TTFF mejorado ~5-25 s.

**Caso óptimo** (HighID, ≥3 fuentes rápidas, Kad bootstrappeado): ~5-10 s. Indistinguible de descarga directa para el usuario.

**Caso medio** (HighID/LowID mezcla, 1-2 fuentes): ~15-25 s. Aceptable; con UI honesta el usuario espera con paciencia.

**Caso malo** (LowID, 1 fuente lenta): 60-120 s + warning. Sigue habiendo casos malos, pero ya con UI que los explica.

### 8.4 Más allá del TTFF: el "no buffering ever"

TTFF es solo el primer KPI. El segundo es **probabilidad de stall en sesión completa**.

Asumiendo R̂ medio con safety_factor 1.3 y varianza típica de eD2K (CoV ≈ 0.3), la probabilidad de un punto de la película donde R(t) < BR cae al ~5-10 %. La duración media de cada caída es ~30 s (slot rotation). Para una película de 2h hay ~10-20 caídas momentáneas.

Sin colchón, eso son 10-20 stalls. **Inaceptable**.

Con colchón de 30-60 s en el head, las caídas momentáneas no causan stall porque el playhead siempre está 30-60 s detrás del head. **Aceptable** (~1-2 stalls en 2h, indistinguible de un buen CDN).

La estrategia: **post-arranque, mantener invariante `lead_sec ≥ 60`**. Si el sistema detecta que el lead cae bajo 60 s, **acelera** la descarga (op=setpreview ya está activo, pero podríamos abrir más slots o priorizar más agresivamente). Si el lead vuelve a > 90 s, **relaja**.

Esto es esencialmente un controlador PID sobre el lead. Implementable; no implementado todavía.

### 8.5 Prefetch predictivo

Mirador final: el usuario que reproduce una serie probablemente reproducirá los siguientes episodios. ¿Y si el sistema **pre-descarga el siguiente** en background mientras este se reproduce?

- Mientras `lead_sec > 90 s` del actual, abrir un slot de descarga al hash del siguiente episodio.
- Cuando el actual termina, ese siguiente ya tiene B_head sustancial → TTFF ~ 1-3 s.

Hace falta:
- Detección de "siguiente episodio" (filename pattern matching, o catalog metadata).
- Política de quota: no más de X concurrent prefetch, no exceder Y MB en disco prefetched.
- UI: opcional, configurable.

Esto convierte la experiencia en **idéntica a Netflix** subjetivamente: el usuario nunca espera, porque la espera ocurre durante el rato anterior.

### 8.6 Recapitulación del mundo ideal

- **TTFF objetivo**: 5-25 s (caso típico), <60 s (caso malo con UI honesta).
- **Probabilidad de stall en sesión 2h**: <5 %.
- **Prefetch del siguiente episodio**: opcional, mejora subjetiva grande.
- **Compatibilidad**: cero cambios en el wire eD2K. Solo refactorización del state machine y un pequeño hook nuevo en `WebServer.cpp` (opcional, ya el sistema funcionará sin él).

---

## Cap. 9 — Hoja de ruta priorizada

Ordenamos las mejoras por **(impacto en UX) ÷ (coste de implementación)**, descendente. Las primeras son las que más bang por buck.

### 9.1 Tier S: alto impacto, bajo coste (1-3 días cada una)

#### S1. Head buffer reducido a `keyframe + 1 MB`

**Qué**: en `playback_state.js`, cambiar `MIN_HEAD_BYTES` de 15 MB a un valor calculado en función del codec detectado.

**Implementación**:
- En S2 PROBE, cuando ffprobe responde, calcular `min_head = max(1 MB, B_keyframe × 4)`.
- Si keyframe interval es conocido (por el codec), usar `B_keyframe = (keyframe_interval_sec × BR)`.
- Si no, default 1 MB.

**Impacto en TTFF**: -10 a -15 s.

**Coste**: 2 horas.

#### S2. Speculative ffprobe

**Qué**: lanzar ffprobe en cuanto B_head > 256 KB con timeout 1 s. Si no responde, reintentar cada 500 ms hasta success o B_head > 5 MB (fallback al gating actual).

**Implementación**:
- En `/api/emule/probe`, eliminar el guard `headContig < 5 MB`. Llamar ffprobe siempre.
- Añadir timeout 1 s.
- Cache no solo "success" sino también "still-failing-at-Xs" para evitar bombardear.

**Impacto en TTFF**: -3 a -5 s.

**Coste**: 4 horas.

#### S3. Inferencia heurística de bitrate por filename

**Qué**: si ffprobe falla repetidamente, estimar bitrate por regex sobre el filename + tamaño total.

**Implementación**:
- Nueva función `_estimateBitrate(fileName, totalBytes)` que:
  - Detecta resolución (1080p, 720p, 4K) por regex.
  - Detecta duración por keyword (S01E01 → asumir ~45 min, película → asumir ~110 min).
  - Devuelve bitrate estimado con un confidence flag.
- En S2 PROBE, si ffprobe falla pero la estimación heurística da algo con confidence > 0.5, promover a SUSTAIN.

**Impacto en TTFF**: en el caso "container exótico", -30 a -45 s (evita el timeout PROBE). En el caso medio, 0 s (ffprobe sigue ganando).

**Coste**: 1 día (regex robusto, mapa de heurísticas, tests).

#### S4. Endpoint `/api/emule/peers?file=<hash>`

**Qué**: exponer información rica sobre los pares conectados a una descarga para que la UI muestre diagnóstico.

**Implementación**:
- En `emule_api.js`, nueva función `getPeersForFile(hash, cb)` que invoca a eMule WebServer con la query correcta para listar pares por hash.
- Endpoint que devuelve `[{ip, port, idType, queueRank, downloadRate, status}, ...]`.
- UI: panel "Detalles técnicos" en la pantalla de "Buffering..." con el detalle.

**Impacto en UX**: el usuario entiende qué está pasando ("0 fuentes conectadas, 2 en cola" → "es lento") en lugar de "rueda girando hace 60 s".

**Coste**: 1-2 días (parser del HTML que devuelve WebServer + UI).

#### S5. Source-switch inteligente (reordenar por velocidad esperada)

**Qué**: cuando una fuente falla con `low_rate`, reordenar `_smartPlayResults` para preferir variantes con menor bitrate (o más completeSources) en el siguiente intento.

**Implementación**:
- En `onFail(reason)`, antes de invocar `retry()`, reordenar el array por una métrica `sources × score / sqrt(sizeMB)`.

**Impacto**: en el caso "primera fuente es 4K 25 Mbps y mi red es 5 Mbps", el siguiente intento será automáticamente el 720p que funcionará.

**Coste**: 2 horas.

#### S6. Ventana SUSTAIN reducida con EWMA

**Qué**: cambiar el cálculo de R̂ en SUSTAIN de "media sobre 30 s" a EWMA con factor adaptativo. Permite decidir en 10-15 s.

**Implementación**:
- Modificar `/api/emule/rate` para opcionalmente devolver `R̂_ewma` y `R̂_variance`.
- `playback_state.js` doSustain: usar EWMA con threshold de varianza ("si la varianza es < 20 %, suficiente confianza").

**Impacto en TTFF**: -15 a -20 s.

**Coste**: 1 día.

### 9.2 Tier A: medio-alto impacto, medio coste (1 semana cada una)

#### A1. Controlador PID sobre `lead_sec`

**Qué**: durante PLAYING, mantener invariante `60 ≤ lead_sec ≤ 120`. Si baja, acelerar (no implementable directamente en eD2K, pero podemos pedir al usuario que aumente max_connections). Si sube mucho, relajar.

**Implementación**:
- En `playback_state.js` doPlaying, calcular `lead_target = 90 s`, `error = lead_target - lead_sec(t)`.
- Si `error > 30 s` (lead bajo), llamar a `op=setpreview` repetidamente (re-prime).
- Si `error < -30 s` (lead alto), no hacer nada (estamos sobrados).

**Impacto**: previene stalls que aparecen tras 30+ min de reproducción cuando R̂ degrada gradualmente.

**Coste**: 3-5 días (incluye pruebas).

#### A2. Transcoding al vuelo a bitrate menor

**Qué**: si `low_rate` ocurre pero hay head suficiente y CPU disponible, lanzar ffmpeg en modo transcoding (1080p → 720p, AC3 → AAC) y servir desde ahí. Bitrate efectivo cae, gating pasa.

**Implementación**:
- En `/api/stream/start/<n>`, parámetro adicional `?transcode=480p|720p|1080p`.
- Nuevo módulo `transcode_pipeline.js` que orchestra ffmpeg con NVENC/QSV/x264.
- Detección automática de "necesito transcodificar" cuando rate < BR pero rate ≥ BR_target.

**Impacto**: convierte un fail en un éxito en el caso "fuente única pero rápida-en-su-bitrate".

**Coste**: 1 semana (pruebas de codec).

#### A3. Diagnóstico de doble-LowID y buddy-relay

**Qué**: detectar cuando todas las fuentes son LowID y nosotros también, y o bien forzar buddy-relay Kad o explicar al usuario.

**Implementación**:
- Endpoint `/api/emule/diag/connectivity` que devuelve mi ID-type, ID-types de las fuentes, intentos de callback fallidos.
- En `playback_state.js` S1 INIT, si elapsed > 30s y conectividad sugiere doble-LowID, mostrar banner accionable.

**Coste**: 1 semana (incluye revisar el código C++ de buddy-relay).

#### A4. Telemetría QoE local

**Qué**: log persistente local (no enviado a ningún servidor por la directriz "no dominios") con métricas por sesión: TTFF, número de stalls, tasa media, bitrate, fuente activa. UI: panel de "Historial de reproducción" en /diag.

**Implementación**:
- `playback_state.js` emite eventos a un endpoint `/api/qoe/log` que escribe a disco.
- UI separada de visualización.

**Impacto**: el desarrollador puede analizar comportamiento sobre el campo. El usuario tiene visibilidad.

**Coste**: 4-5 días.

### 9.3 Tier B: alto impacto, alto coste (2-4 semanas cada una)

#### B1. Pre-fetch del siguiente episodio

**Qué**: detección de pattern de series + pre-descarga en background del siguiente episodio cuando `lead_sec` del actual es generoso.

**Implementación**:
- Detector de "siguiente": regex sobre filename pattern + lookup en catálogo (TMDB/TVDB).
- Lógica de quota: no más de 1 prefetch concurrente, no exceder 5 GB de espacio prefetched.
- UI: configurable on/off, indicador de "Próximo episodio ya descargando".

**Coste**: 3 semanas.

**Impacto subjetivo**: enorme. El usuario nunca espera entre episodios.

#### B2. Onion tunnel para conexiones eD2K (no solo search)

**Qué**: extender V1 Privacy para que las conexiones a pares eD2K pasen por el túnel onion también, no solo las búsquedas Kad.

**Implementación**:
- Sustancialmente complejo: el wire eD2K es TCP; los túneles de eSE son TCP. Pueden integrarse.
- Requiere extensión del LiveTunnel para que pueda transportar streams TCP arbitrarios, no solo cells fijas.

**Coste**: 4-6 semanas.

**Impacto**: privacidad real frente a observador pasivo. Cierre del último gap del V1.

#### B3. State machine portado a Web Worker

**Qué**: mover el monitor a un worker dedicado. Aísla del thread UI, permite continuar el monitoreo si el usuario navega a otra pestaña/route.

**Impacto**: previene casos donde la UI se "olvida" del monitor por GC del browser, mejora la robustez frente a cambios de pestaña.

**Coste**: 1-2 semanas (refactorización de comunicación postMessage).

### 9.4 Tier C: nice-to-have

#### C1. Adaptación de safety_factor a varianza observada

Si CoV(R) ≈ 0.1 → safety_factor 1.1 suficiente.
Si CoV(R) ≈ 0.5 → safety_factor 1.5.

#### C2. Visualización de tasa en tiempo real

Mini-gráfico SVG en la UI mostrando R̂(t) durante la última hora.

#### C3. Detección de hash corrupto en sesión

Si eMule revierte una parte 2+ veces en una sesión, banear la fuente que la suministró.

### 9.5 Resumen tabular

| Tier | Mejora | Días estimados | Impacto (S/A/B) |
|---|---|---|---|
| S1 | Head buffer = keyframe + 1 MB | 0.5 | A |
| S2 | Speculative ffprobe | 0.5 | A |
| S3 | Bitrate por filename | 1 | A |
| S4 | /api/emule/peers | 1.5 | A |
| S5 | Source-switch inteligente | 0.25 | A |
| S6 | EWMA sostained rate | 1 | A |
| A1 | PID lead_sec | 4 | A |
| A2 | Transcoding al vuelo | 5 | A |
| A3 | Diagnóstico doble-LowID | 5 | M |
| A4 | Telemetría QoE | 4 | M |
| B1 | Prefetch siguiente episodio | 15 | A |
| B2 | Onion tunnel para eD2K | 25 | A |
| B3 | Worker para state machine | 7 | M |
| C1 | Safety_factor adaptativo | 1 | M |
| C2 | Gráfico tasa | 2 | L |
| C3 | Banear fuentes envenenadas | 3 | L |

**Total Tier S (todos)**: ~5 días, TTFF de 60s → 15-25s.
**Total Tier S + A**: ~25 días, sesión sin stalls + UX honesta.
**Total grande (S+A+B)**: ~75 días, indistinguible de Netflix subjetivamente.

### 9.6 La pregunta no técnica

Una pregunta filosófica que el roadmap eleva: **¿debería este sistema parecer Netflix?**

Argumentos a favor:
- El usuario espera Netflix; cualquier cosa peor frustra.
- Comparable a la calidad esperada de cualquier app moderna de streaming.

Argumentos en contra:
- Netflix está respaldado por miles de millones en CDN y contratos de contenido. Equiparar la UX puede crear expectativas que el substrato P2P no siempre puede cumplir.
- Una UI **honesta** ("hay 2 fuentes conectadas, ambas lentas, espera 30 s o cambia de fuente") puede educar al usuario sobre el modelo P2P, lo que tiene valor pedagógico/político (descentralización vs centralización).

Mi recomendación implícita en el roadmap: **target la calidad de Netflix técnicamente, pero sin esconder el modelo P2P en la UI**. La cinta de progreso muestra ETAs honestos; los detalles técnicos son accesibles en un panel "Detalles" pero no en el camino crítico. El usuario casual ve "Reproduciendo"; el power-user ve cuántas fuentes, cuánto rate, cuánto buffer.

---

## Apéndice A — Léxico técnico

| Término | Definición |
|---|---|
| **B_head** | Bytes contiguos descargados desde offset 0; lo que se puede leer secuencialmente |
| **B_played** | Bytes consumidos por el reproductor a tiempo t |
| **bitrate** | Bytes por segundo del contenido reproducido (no de la red) |
| **container** | Formato envolvente del fichero de vídeo (MP4, MKV, WebM, AVI) |
| **CTag** | Estructura serializada de tag de eMule (tipo+nombre+valor) |
| **EDF (Earliest Deadline First)** | Política de scheduling donde el trabajo con deadline más cercano va primero |
| **EWMA** | Exponentially Weighted Moving Average; media móvil con peso geométrico |
| **fMP4** | Fragmented MP4; cada fragmento es independientemente decodificable |
| **gap** | Rango de bytes NO descargados en un fichero parcial |
| **HighID** | Cliente eMule con TCP entrante; puede aceptar conexiones directas |
| **LowID** | Cliente sin TCP entrante; requiere callback via servidor o Kad |
| **MSE (Media Source Extensions)** | API browser para alimentar `<video>` con segmentos dinámicos |
| **moov atom** | Bloque MP4 con metadata; suele estar al inicio (faststart) o al final |
| **preview_prio** | Flag de eMule que invierte la política rare-first hacia head-first |
| **rare-first** | Política eMule de elegir piezas raras antes que comunes |
| **slot** | Asignación temporal de upload bandwidth de un par a otro |
| **stall** | Estado donde el reproductor se queda sin datos para decodificar |
| **TTFF (Time To First Frame)** | Tiempo desde click "Play" hasta primer fotograma en pantalla |
| **VBR** | Variable Bit Rate; el bitrate del contenido varía instante a instante |

## Apéndice B — Referencias

Lecturas que han influido este análisis (no exhaustivo):

### Streaming centralizado y CDN
- Stockhammer, T. (2011). "Dynamic adaptive streaming over HTTP." *Proceedings of the second annual ACM conference on Multimedia systems*.
- Akhshabi, S., Begen, A. C., & Dovrolis, C. (2011). "An experimental evaluation of rate-adaptation algorithms in adaptive streaming over HTTP." *Proceedings of the second annual ACM conference on Multimedia systems*.

### P2P live & VOD
- Liu, Y., Guo, Y., & Liang, C. (2008). "A survey on peer-to-peer video streaming systems." *Peer-to-peer Networking and Applications*, 1(1), 18-28.
- Magharei, N., & Rejaie, R. (2007). "PRIME: Peer-to-peer receiver-driven mesh-based streaming." *IEEE INFOCOM 2007*.
- Hei, X., Liang, C., Liang, J., Liu, Y., & Ross, K. W. (2007). "A measurement study of a large-scale P2P IPTV system." *IEEE Transactions on Multimedia*, 9(8), 1672-1687.

### BitTorrent VOD
- Vlavianos, A., Iliofotou, M., & Faloutsos, M. (2006). "BiToS: Enhancing BitTorrent for supporting streaming applications." *Proceedings of IEEE INFOCOM*.
- Mol, J. J. D., Pouwelse, J. A., Meulpolder, M., Epema, D. H. J., & Sips, H. J. (2008). "Give-to-Get: An algorithm for P2P video-on-demand." *Multimedia Computing and Networking*.

### eMule / eDonkey internals
- Heckmann, O., & Bock, A. (2002). "The eDonkey 2000 protocol." Technical Report KOM-TR-2002-08, Technical University of Darmstadt.
- Documentación oficial eMule: http://wiki.amule.org/wiki/EMule_protocol_specification

### Kademlia
- Maymounkov, P., & Mazieres, D. (2002). "Kademlia: A peer-to-peer information system based on the XOR metric." *International Workshop on Peer-to-Peer Systems*.

### Privacy
- Dingledine, R., Mathewson, N., & Syverson, P. (2004). "Tor: The second-generation onion router." *USENIX Security Symposium*.
- Goldberg, I., Stebila, D., & Ustaoglu, B. (2013). "Anonymity and one-way authentication in key exchange protocols." *Designs, Codes and Cryptography*.

### Documentación interna del proyecto
- `docs/PAPER_eSE_Live_ES.md` — paper sobre la pila Live (no VOD)
- `docs/DECENTRALIZED_DISCOVERY.md` — discovery de canales y streams
- `docs/SECURITY_AUDIT.md` — auditoría de seguridad
- `docs/UNIFIED_IMPLEMENTATION_PLAN.md` — plan unificado v8.1 Privacy
- `RELEASE_NOTES_v8.0.16.md` — release notes de la implementación de la state machine
- Otras tesis hermanas en branches:
  - `hungry-dhawan-84bd82`: tesis principal eSE LiveTV (Live, no VOD)
  - `quizzical-newton-9aa3db`: monografía sobre el rediseño de Kad Search v2

---

## Cierre

La reproducción al vuelo sobre eD2K **funciona**, hoy, v8.0.19. Lo prueba el hecho de que el sistema lleva semanas en uso real con éxito en los casos típicos. Lo que **no funciona perfectamente** son los casos de borde, y todos los casos de borde tienen origen identificado en una de tres clases de problema:

1. **Bugs de instrumentación**: el sistema cree algo que no es verdad. Resueltos uno por uno en las hotfixes v8.0.14 → v8.0.19. La diagonal natural es que cada hotfix destapa el siguiente; v8.0.19 (parser correcto) probablemente destapará otra capa de problema cuando la verdad-de-disco fluya limpia.

2. **Insuficiencia de información** del substrato eD2K hacia ese-server. eMule sabe cosas (qué pares están en cola, qué rates de slot, qué parts revertidas) que el WebServer interno no expone vía API. Hay que extender el binario C++ con uno o dos opcodes nuevos para que ese-server pueda ofrecer diagnóstico real.

3. **Decisiones de diseño conservadoras** que se quedan cortas en TTFF: head de 15 MB, ventana de 30 s, ffprobe pre-gating. Todas reducibles drásticamente sin sacrificar robustez si se sustituyen por inferencias predictivas.

El Roadmap del Cap. 9 ataca las tres clases. Cinco días de Tier S llevarían el TTFF de 60 s a 15-25 s. Veinticinco días de Tier S + A llevarían la probabilidad de stall en sesión 2h a <5 %. Setenta y cinco días (S + A + B) acercarían la experiencia al norte estelar de "indistinguible de Netflix" sin perder un solo gramo de descentralización ni introducir dependencia externa.

Es un objetivo alcanzable. La mayor parte del trabajo es **JS de tres dígitos de líneas**, no rediseños profundos. La pila eD2K/Kad subyacente, con sus limitaciones, es **suficientemente rica** para esta clase de UX. Lo único que ha faltado hasta ahora es tratarla con la disciplina de instrumentación que un sistema VOD merece — y dejar de mentirse sobre los datos.

— Fin —
