# eSE Live: Streaming en Vivo Descentralizado sobre una DHT Veterana de Intercambio de Archivos

**Autor:** Iñaki Unanue
**Afiliación:** Independiente
**Versión:** 1.0 — 2026-05-17
**Estado:** Pre-print
**Código:** [github.com/diad87/eMule-eSE-LiveTV](https://github.com/diad87/eMule-eSE-LiveTV)

---

## Resumen

Presentamos **eSE Live**, una extensión de eMule (un cliente de
intercambio de archivos longevo basado en eD2K + Kademlia [Kad])
que añade soporte de primera clase para **emisión en vivo P2P**. El
sistema comparte el mismo overlay, transporte y sustrato de
descubrimiento que el intercambio convencional de archivos — sin
trackers, sin CDN, sin indexador central — y aun así sostiene la
distribución de vídeo en tiempo real por chunks entre peers no
relacionados, con descubrimiento sub-segundo en la red local y
descubrimiento en 3 segundos a través de una mesh caliente.
Extendemos el protocolo wire de eD2K con cinco opcodes
retrocompatibles que introducen negociación de capacidad live,
medición de RTT y **gossip de peer-exchange de streams recientes**,
permitiendo que los directorios de live se propaguen viralmente en
`O(log N)` heartbeats. Complementamos el descubrimiento basado en
Kad con dos capas descentralizadas adicionales: un multicast UDP
estilo mDNS en la LAN y una caché de bootstrap por cliente,
eliminando la latencia de arranque en frío en los escenarios más
comunes. Describimos una implementación completa sobre una base de
código híbrida C++ (MFC) + Node.js que totaliza 20 archivos C++
nuevos, 64 módulos JavaScript nuevos, y la adición de 25 endpoints
HTTP API. Reportamos una verificación de extremo a extremo de una
emisión real que cruza dos hosts en ISPs distintos, con el receptor
reconstruyendo la lista de reproducción HTTP Live Streaming (HLS)
directamente a partir de chunks eD2K. Discutimos la economía de
ancho de banda que hace la arquitectura sostenible más allá de la
capacidad de subida del propio emisor, la topología por niveles que
limita el fanout directo de viewers, y un modelo de seguridad que
mantiene la superficie de administración local confinada al loopback.
Cerramos con una hoja de ruta para escalar de los 10–20 viewers por
stream actualmente validados a varios miles, usando técnicas tomadas
de la literatura reciente de P2P: transporte SRT, codificación
lineal aleatoria en red y protocolos de membresía por gossip.

**Palabras clave:** streaming en vivo peer-to-peer, Kademlia, eD2K,
DHT, sistemas descentralizados, HLS, resistencia a censura,
traversal de NAT, redes mesh, bitrate adaptativo.

---

## 1. Introducción

El vídeo en vivo en la Internet pública depende hoy casi
exclusivamente de **infraestructura centralizada**: Content Delivery
Networks (Akamai, Cloudflare, Fastly), plataformas propietarias
(Twitch, YouTube Live) o despliegues uni-tenant. Este modelo
concentra la confianza, el riesgo de censura y el coste operativo en
un pequeño número de fronteras administrativas. El mismo modelo
también domina el vídeo *grabado*, pero los medios grabados tienen
alternativas descentralizadas prósperas — sobre todo BitTorrent y sus
muchos derivados — que han sido operativamente significativas
durante más de dos décadas. **Los medios en vivo no tienen una
historia de éxito descentralizado equivalente a escala de
producción.**

Este trabajo plantea una pregunta concreta: *¿puede una red P2P de
intercambio de archivos diseñada en el año 2000 — eD2K más su DHT
Kademlia — adaptarse para transportar streams en vivo sin sacrificar
las propiedades que hicieron a la variante de intercambio de
archivos duradera (sin servidor central, resistencia a censura,
participación orgánica de peers)?*

Respondemos afirmativamente y presentamos **eSE Live**, un fork del
cliente eMule 0.70b (publicado el 2022-12-19 por el eMule Project)
que añade:

1. Un **subsistema de emisión en vivo** que ingiere RTMP desde
   cualquier encoder estándar (OBS, FFmpeg), transcodifica a HLS
   multi-bitrate, y publica los chunks resultantes como recursos
   eD2K.
2. Un **subsistema de viewer** que reensambla la playlist HLS
   localmente a partir de chunks obtenidos sobre el transporte
   eD2K existente, permitiendo que cualquier reproductor compatible
   con HLS (VLC, vídeo HTML5 del navegador) reproduzca el feed en
   vivo.
3. **Tres capas descentralizadas de descubrimiento** — publicación/
   búsqueda en DHT, gossip de peer-exchange en el heartbeat
   existente, y multicast UDP en LAN — que combinadas dan
   descubrimiento sub-segundo en LAN, descubrimiento de ~3 segundos
   en mesh caliente, y arranque en frío de <5 segundos cuando la
   caché de bootstrap no está vacía.
4. **Economía de ancho de banda** (clasificación por niveles según
   capacidad de subida, enforcement de ratio, publicación
   viewer-como-fuente-secundaria) que sostiene la capacidad de la
   red de forma sublineal en el número de viewers, en lugar de
   agotar la subida del emisor.
5. Un **dashboard web moderno** que reemplaza la UI legacy MFC como
   superficie de usuario principal para contenido en vivo,
   preservando la interfaz clásica para la funcionalidad de
   intercambio de archivos que proporciona el cliente upstream.

### 1.1 Contribuciones

- Diseñamos e implementamos cinco extensiones de protocolo wire
  **retrocompatibles** que convierten a los peers eD2K en peers
  conscientes de live sin romper la interoperabilidad con clientes
  upstream sin modificar (Sección 3.3).
- Caracterizamos una pila de **descubrimiento descentralizado de
  tres capas** que combina DHT, gossip de peer-exchange y multicast
  LAN, que empíricamente supera a cualquier capa por sí sola en el
  caso común (Sección 3.2).
- Documentamos una **implementación completa de extremo a extremo**
  en 20 archivos C++ nuevos (~5.800 LOC), 64 módulos Node.js
  nuevos (~12.000 LOC) y 25 endpoints HTTP nuevos, disponible bajo
  GPL-2.0 (Sección 4).
- Reportamos una **emisión cross-host verificada** (PC1 → PC2, ISPs
  distintos, 2026-05-15) y caracterizamos la latencia de
  descubrimiento por cada capa (Sección 5).
- Articulamos la **economía de ancho de banda** requerida para que
  la arquitectura escale más allá del enlace local del emisor
  (Sección 6).

### 1.2 No-objetivos

**No** afirmamos reemplazar al streaming en vivo respaldado por CDN
para audiencias de millones; la implementación actual ha sido
validada empíricamente hasta ~10–20 viewers por stream y somos
explícitos sobre los cambios de diseño (Sección 7) requeridos para
empujarlo a los miles. No proporcionamos moderación de contenido,
aplicación de copyright, ni ninguna función administrativa
centralizada — son no-características deliberadas heredadas del
sustrato eD2K.

### 1.3 Estructura del paper

La Sección 2 revisa el trabajo relacionado en streaming en vivo P2P
y el linaje eD2K / Kad. La Sección 3 presenta el diseño del sistema
a través de descubrimiento, transporte, topología, codificación y
economía. La Sección 4 describe la implementación. La Sección 5
evalúa el sistema desplegado. La Sección 6 discute limitaciones, la
Sección 7 trabajo futuro, y la Sección 8 concluye.

---

## 2. Antecedentes y Trabajo Relacionado

### 2.1 El sustrato eD2K / Kad

La red eDonkey 2000 (eD2K) fue lanzada en el año 2000 por Jed
McCaleb [1] y alcanzó su forma generalizada a través del cliente
eMule [2]. Los archivos se identifican por un hash jerárquico
basado en MD4 y se distribuyen a través de un swarm heterogéneo de
peers. A partir de 2004, eMule integró una tabla hash distribuida
**Kademlia** [3] (Kad) para reemplazar la arquitectura de servidores
eD2K original, proporcionando búsqueda de keywords y fuentes sin
servidor. El sistema combinado eD2K + Kad ha sido estudiado como
objetivo de medición (Steiner et al. [4]) y es operativamente
significativo incluso hoy, con el eMule Project continuando
publicando versiones de mantenimiento (la más reciente siendo 0.70b,
diciembre 2022).

Dos propiedades del sustrato eD2K + Kad son críticas para nuestro
trabajo:

- **Base de peers existente.** Cualquier nodo que ya esté ejecutando
  eMule puede reutilizarse — no hay un problema de bootstrap único
  para nuestra aplicación. La DHT está endurecida contra churn y
  ataques Sybil por veinte años de presión adversarial operativa.
- **Resistencia a censura.** Sin un índice central o trackers, no
  hay parte a la que se le pueda servir un aviso de retirada por
  descubrimiento de contenido. Peers individuales pueden bloquearse
  en la capa de red, pero el directorio mismo no tiene un único
  punto de fallo.

Las propiedades que *necesitamos añadir* se relacionan con
**liveness**: eD2K está optimizado para contenido que no cambia (un
archivo de película es constante una vez publicado), mientras que el
streaming en vivo requiere publicación continua de nuevos chunks,
invalidación rápida de freshness cuando un emisor se detiene, y
límites estrictos de latencia en la entrega de chunks.

### 2.2 Streaming en vivo descentralizado

La literatura sobre streaming en vivo P2P se agrupa en tres eras:

**(a) Sistemas de overlay en árbol (principios de los 2000).** Los
overlays de multicast de árbol único como ESM [5] y Narada [6]
mostraron que el multicast de capa de aplicación era factible pero
sufrían una pobre recuperación bajo churn: la pérdida de cualquier
nodo interior desconecta un subárbol completo.

**(b) Sistemas mesh-pull (mediados de los 2000).** Los sistemas
mesh basados en chunks como PPLive [7], SOPCast, CoolStreaming [8]
dominaron el despliegue práctico. Cada viewer mantiene un pequeño
conjunto de vecinos y obtiene chunks faltantes de forma reactiva.
PPLive en particular alcanzó millones de usuarios concurrentes en
eventos de broadcast en China durante 2006–2010. Sin embargo,
todos estos dependían de **trackers centrales** para el bootstrap
de la lista de peers; los protocolos en sí eran propietarios y
ninguno sobrevivió como infraestructura comunitaria abierta más
allá de unos pocos años.

**(c) Sistemas modernos basados en DHT y gossip (2010s–hoy).**
Tribler [9] integra streaming en vivo sobre la DHT mainline de
BitTorrent. PeerTube [10] usa WebTorrent federado para streaming
híbrido asistido por CDN. PULSE [11] usa gossip HyParView /
Plumtree [12,13] para construir un overlay de membresía parcial con
entrega de chunks sub-segundo cross-continente. Ninguno de estos ha
alcanzado la visibilidad mainstream de los sistemas basados en
trackers de los 2000, pero constituyen el espacio de diseño del que
tomamos referencia.

El pariente comercial más cercano es **BitTorrent Live**, el
producto de streaming en vivo de BitTorrent Inc. de 2013 basado en
el protocolo propietario "Mosaic"; fue discontinuado en 2017 y
nunca fue publicado como código abierto.

### 2.3 Alternativas modernas

Por completitud notamos tres aproximaciones contemporáneas que
explícitamente no adoptamos:

- Sistemas **basados en WebRTC** (Janus, Galène, peer.js)
  proporcionan latencia sub-segundo sobre SCTP/RTP mediado por
  navegador pero dependen de signaling centralizado y servidores
  TURN; el problema del descubrimiento queda sin resolver.
- **P2P asistido por CDN** (Peer5, Streamroot) descarga hasta un
  80% del egreso de viewers a peers pero requiere un CDN central
  como fuente de verdad — exactamente la centralización que
  buscamos eliminar.
- **Streaming federado** (PeerTube, Owncast) reemplaza un CDN
  único con una federación de servidores independientes. Es un
  paso hacia la descentralización, pero cada "instancia" sigue
  siendo una entidad administrativa única sujeta a presión local.

### 2.4 ¿Por qué reutilizar eD2K en lugar de diseñar desde cero?

Una reacción común es: *si quieres un nuevo sistema P2P de
streaming en vivo, ¿por qué no empezar desde un transporte y una
DHT modernos?* Tres razones:

1. **Base de usuarios existente.** La red eD2K aún tiene del orden
   de 10^5 peers concurrentes en todo el mundo. Un diseño greenfield
   empieza con cero.
2. **Atestación de confianza existente.** eMule ha sido compilado
   por decenas de millones de usuarios distintos desde 2002 y
   auditado (informalmente) por la comunidad de intercambio de
   archivos. El código greenfield no tiene nada de esa historia.
3. **Conocimiento institucional existente.** NAT traversal,
   intercambio de fuentes, reputación de peers, recuperación de
   partfile — todos están resueltos y probados en batalla en la
   base de código de eMule. Los heredamos gratis.

El coste de esta elección es que trabajamos dentro de una base de
código C++ MFC (Microsoft Foundation Classes) de una era anterior,
con el correspondiente overhead de mantenimiento y modernización
(ver Sección 6.2).

---

## 3. Diseño del Sistema

### 3.1 Visión general

La Figura 1 (conceptual) resume el flujo de datos en los lados del
emisor y del viewer:

```
  EMISOR                              MESH                  VIEWER

  ┌──────────┐    rtmp://127.0.0.1                       ┌──────────┐
  │   OBS    │ ─────────────────►                        │   VLC    │
  │ (o      │                                            │ o video   │
  │ cualquier│                                           │ HTML5     │
  │ encoder │                                            │ navegador │
  │ RTMP)   │                                            │           │
  └──────────┘                                           └──────────┘
       │                                                       ▲
       ▼                                                       │
  ┌──────────┐                                           ┌──────────┐
  │ Listener │                                           │ Servidor │
  │  RTMP    │ (puerto 1935)                             │ HLS      │
  │          │                                           │ local    │
  └──────────┘                                           └──────────┘
       │                                                       ▲
       ▼                                                       │
  ┌──────────┐    ┌──────────┐                                 │
  │ Pipeline │ -> │ Chunks   │                                 │
  │ FFmpeg   │    │ HLS en   │ (4s, ABR multi-bitrate)         │
  │ (HW enc) │    │ disco    │                                 │
  └──────────┘    └──────────┘                                 │
                        │                                      │
                        ▼                                      │
                  ┌──────────────────────────────────────┐    │
                  │ Publicar chunks como recursos eD2K   │    │
                  │ Publicar stream key en Kad DHT       │    │
                  │ Anunciar en multicast LAN (5354)     │    │
                  │ Embeber top-5 streams en gossip     │    │
                  │   PEX del heartbeat                  │    │
                  └──────────────────────────────────────┘    │
                                  │                            │
                                  │                            │
                                  ▼                            │
                  ┌──────────────────────────────────────┐    │
                  │           Mesh eD2K + Kad            │    │
                  │   (TCP + UDP, atravesado por NAT)    │    │
                  └──────────────────────────────────────┘    │
                                  │                            │
                                  │ Opcodes de petición /     │
                                  │ respuesta de chunk         │
                                  ▼                            │
                  ┌──────────────────────────────────────┐    │
                  │ Viewer: descubrir stream (3 capas)   │    │
                  │ Viewer: marcar emisor + relays       │    │
                  │ Viewer: reensamblar chunks HLS       │ ───┘
                  │ Viewer: servir m3u8 local            │
                  └──────────────────────────────────────┘
```

La arquitectura es convencional en su esquema (entrada RTMP / salida
HLS con chunk-pull P2P en el medio) y **novedosa solo en el
sustrato sobre el que opera** — todo sistema previo de streaming en
vivo chunk-pull ha usado un overlay a medida; somos los primeros, a
nuestro conocimiento, en desplegar este patrón sobre la red eD2K +
Kad.

### 3.2 Descubrimiento: tres capas descentralizadas

El descubrimiento de stream es la operación por la cual un viewer
aprende de la existencia y endpoint de red actual de un emisor,
dado solo la stream key del emisor (un identificador de 16 bytes).
Las tres capas que desplegamos en paralelo son:

**Capa 1 — Publicación/búsqueda en DHT (Kad).** El emisor publica
su IP:puerto bajo el keyword Kad `live:<HEXKEY>` con un TTL
deliberadamente corto de 60 segundos (vs el predeterminado de 5
horas para archivos), de modo que los emisores caídos o detenidos
desaparecen del directorio en un período de TTL. Los viewers emiten
búsquedas Kad; los resultados son validados (IP:puerto chequeados
por sanity, conteo de viewers y bitrate clampeados contra cotas
superiores plausibles para defenderse de ataques de Sybil-flooding).

Para acelerar el reclutamiento viewer-a-viewer añadimos un segundo
keyword Kad `livehash:<HEXKEY>` publicado por los **viewers** (no
emisores) una vez que su buffer local de chunks excede los 5
chunks. Un viewer fresco buscando el stream encuentra por tanto no
solo al emisor sino a cada viewer capaz de actuar como relay,
permitiendo que la topología de árbol (Sección 3.4) se forme
orgánicamente sin coordinación explícita.

**Capa 2 — Gossip peer-exchange en el heartbeat live.** Cada 60
segundos, cada peer que tiene el bit de capacidad live envía un
opcode `OP_LIVE_HEARTBEAT` a sus vecinos del mesh. Extendemos el
formato de payload de los 22 bytes originales a 23–133 bytes
variables que llevan los top-5 streams más recientemente observados
por el peer (sus claves, IPs y puertos). Los receptores fusionan
estas entradas en su directorio local de streams a través del mismo
path de código que los resultados de búsqueda Kad, heredando todo
el rate-limiting, deduplicación y lógica de IP-filter existente.

El formato wire está **marcado por bits para retrocompatibilidad**:
un cliente eMule upstream sin el bit de capacidad live ignora el
bloque PEX trailing como protocol slop. No medimos disrupción
observada en un mesh mixto de 6 peers ejecutando fork + clientes
upstream durante un soak de 24 horas.

Las dinámicas de propagación son virales: en un mesh de `N` peers
donde cada peer reporta los 5 streams que ha visto, cada peer se
entera de cada stream "popular" (uno observado por 5 o más peers)
en `O(log N)` heartbeats — empíricamente ~3 heartbeats (3 minutos)
para meshes de 50 peers en nuestro testing interno.

**Capa 3 — Multicast UDP en LAN (estilo mDNS).** Muchos
escenarios reales de viewers ocurren dentro de una sola LAN: una red
de casa compartiendo una emisión con familiares, una oficina
mostrando una presentación, una LAN party. Para estos casos
desplegamos un anuncio por emisor en el grupo multicast mDNS estándar
`224.0.0.251` (ya permitido en esencialmente cada router de
consumidor) pero en un puerto deliberadamente no-conflictivo `5354`
(Bonjour está en `5353`). El payload es un registro de 7 líneas en
texto plano:

```
eSE-LAN/1.0
hash: <32-hex-streamKey>
ip: <IP-LAN-del-emisor>
port: <puerto-TCP-eD2K-del-emisor>
title: <título-del-stream>
bitrate: <kbps>
category: <texto-libre>
language: <ISO-639-2>
```

Los anuncios se emiten cada 30 segundos con TTL=1 (nunca escapan de
la subred). Los listeners filtran sus propias IPs para evitar
loops. El descubrimiento cross-LAN sub-segundo es la norma.

**Capa 4 — Caché de bootstrap.** Una caché persistente por cliente
almacenada en `%APPDATA%\eMule\last_streams.json` registra los
últimos 20 streams a los que el usuario se unió con éxito,
incluyendo la IP:puerto más reciente para cada uno. En el arranque,
antes de que se complete el bootstrap de Kad, el cliente hace ping
a estos endpoints directamente. En el caso común donde el usuario
se está re-uniendo a un stream favorito y el emisor sigue en el
mismo endpoint, esto entrega el primer chunk en menos de 5 segundos
— versus los 30–120 segundos típicos de una búsqueda Kad en frío.

### 3.3 Transporte: extensiones del protocolo wire

Añadimos cinco nuevos opcodes al protocolo wire de eD2K:

| Opcode | Bytes | Propósito |
|---|---|---|
| `OP_LIVE_HEARTBEAT` | 23–133 | Estado periódico de peer + PEX (top-5 streams) |
| `OP_LIVE_CHUNK_REQUEST` | 20 | Petición del chunk *N* para el stream *K* |
| `OP_LIVE_CHUNK_RESPONSE` | variable | Payload del chunk (típicamente 1–8 KiB) |
| `OP_LIVE_PING` (0xE7) | 16 | Sonda de RTT — viewer a peer |
| `OP_LIVE_PONG` (0xE8) | 16 | Respuesta RTT — hace eco del timestamp |

Los cinco están condicionados por un bit de capacidad anunciado
durante el handshake hello de eD2K. A los peers sin el bit nunca se
les envían opcodes live, preservando compatibilidad hacia adelante y
hacia atrás total.

El transporte de chunks reutiliza el framing TCP existente de eD2K
para el contenido de los chunks y el framing UDP existente de Kad
para ping/pong. Evitamos deliberadamente introducir un tercer
transporte (por ejemplo data channels de WebRTC) en esta release;
la modernización del transporte está enumerada como trabajo futuro
en la Sección 7.

El traversal de NAT reutiliza la maquinaria existente de hole-punching
UDP de eMule, con una extensión: los payloads de signaling de
hole-punch ahora se cifran con una clave AES-128 derivada del peer
para prevenir que observadores pasivos correlacionen endpoints de
emisión con identificadores de stream.

### 3.4 Topología: árbol con multi-parent y fallback de mesh

Restringimos la topología con tres reglas:

1. **Tope de fanout directo.** Ningún emisor sirve más de 10
   viewers directos. El 11º y siguientes viewers deben ser servidos
   por otros viewers (relays).
2. **Multi-parent.** Cada peer no-emisor mantiene al menos 3
   parents en estado estacionario: un primario (RTT más bajo) y 2
   suplentes calientes. Los chunks faltantes disparan una petición
   a un suplente sin esperar a que el primario haga timeout.
3. **Fallback de mesh.** Cada peer publica un *bitmap* de los
   chunks que actualmente posee; cuando un viewer detecta un gap
   (por ejemplo debido a pérdida de paquetes o churn del parent),
   consulta los bitmaps de sus parents y de cualquier peer con el
   que haya intercambiado heartbeats recientemente, obteniendo el
   chunk faltante de quien sea que lo tenga con el RTT medido más
   bajo.

La combinación produce **recuperación mediana de 200 ms de la
pérdida de parent** en nuestros stress tests internos, versus los
5+ segundos típicos de los overlays de árbol único puros. Esta es
la principal lección arquitectónica que tomamos de la literatura
mesh-pull (Sección 2.2).

Pseudocódigo simplificado para el bucle de petición de chunks en el
viewer:

```
para cada chunk faltante c en ventana [tail, head + 3]:
    candidatos = parents ∪ peers_recientemente_pex
    candidatos = filtrar(candidatos, p => p.bitmap.tiene(c))
    candidatos = ordenar_por_rtt(candidatos)
    si candidatos está vacío:
        // Anycast: buscar livehelp:<streamKey> en Kad
        candidatos = kad_search("livehelp:" + streamKey)
    pick = candidatos.head
    enviar OP_LIVE_CHUNK_REQUEST(pick, c)
    programar_reintento(pick, c, timeout=300 ms)
```

### 3.5 Codificación y reproducción

El pipeline local del emisor ingiere RTMP en el puerto 1935 (el
estándar de facto), pipea el stream a través de FFmpeg para
transcodificación, y emite chunks HLS de 4 segundos cada uno en
hasta cuatro variantes de resolución (360p, 540p, 720p, 1080p). La
invocación de FFmpeg auto-detecta los encoders de hardware
disponibles en el arranque, prefiriendo (en orden): NVIDIA NVENC →
Intel QSV → AMD AMF → fallback de software x264. Si la detección
falla (por ejemplo en un servidor sin GPU) el sistema cae a un
encode CPU con tope 540p que preserva amplia compatibilidad a
expensas de la resolución.

Adoptamos tres detalles pequeños pero importantes de los sistemas
de live de producción:

- **Segmentos independientes.** Cada variante emite la directiva
  `EXT-X-INDEPENDENT-SEGMENTS`, asegurando que los límites de chunk
  estén alineados con I-frames y un viewer pueda cambiar de
  variante en cualquier límite de chunk sin un frame negro.
- **Prebuffer estilo YouTube.** El emisor no devuelve control al
  usuario desde `Start Broadcast` hasta que se han codificado y
  publicado 3 chunks (~12 segundos). Esto elimina el modo de fallo
  "live edge → buffer vacío → pantalla negra" que aflige a los
  despliegues live ingenuos.
- **Defaults de audio.** La master playlist HLS marca solo el
  primer track de audio como `DEFAULT=YES`, con tracks secundarios
  (por ejemplo dub de idioma) marcados `AUTOSELECT=NO`. Encontramos
  una regresión real donde múltiples tracks `DEFAULT=YES` causaban
  que VLC truncara el stream de audio después de 3,4 segundos.

El lado del viewer hospeda un pequeño servidor HLS local (el mismo
C++ WebServer usado para la legacy UI web de eMule), que sirve el
`master.m3u8` reensamblado y los archivos de chunk por variante a
cualquier reproductor HLS en la máquina local. Tanto `<video>` HTML5
del navegador como VLC funcionan sin configuración; el usuario
percibe un stream HLS normal.

### 3.6 Economía de ancho de banda

La habilidad de la arquitectura para escalar más allá del enlace
local del emisor depende de una **contribución de subida
obligatoria** de cada viewer. El mecanismo tiene tres partes:

1. **Clasificación por tier.** Al arranque, cada peer mide su
   capacidad de subida reciente desde la preferencia `MaxUpload`
   del usuario (un valor ya mantenido por eMule para intercambio
   de archivos) y se clasifica en uno de cinco tiers:

   | Tier | Subida mín | Máx uploads concurrentes servidos |
   |---|---|---|
   | LEAF_RESTRICTED | 0 | 0 (consumidor puro) |
   | LEAF | 128 kbps | 1 |
   | MID | 512 kbps | 3 |
   | SUPER_SEEDER | 2 Mbps | 10 |
   | MEGA_SEEDER | 8 Mbps | 25 |

2. **Enforcement de ratio.** Una ventana deslizante de 60 segundos
   rastrea el ratio de los bytes servidos a los bytes recibidos por
   cada peer. Los peers por debajo de 0,4 son throttleados a soltar
   4 de cada 5 peticiones de chunk; los peers entre 0,4 y 0,7 son
   throttleados a soltar 1 de cada 5. Los peers ≥0,7 no se ven
   afectados. El throttle *no* se aplica a los primeros 5 viewers
   de un stream, permitiendo el bootstrap antes de que el efecto
   de red se ponga en marcha.

3. **Viewer-como-fuente-secundaria.** Una vez que el buffer de
   chunks de un viewer excede los 5 chunks (~20 segundos), se
   publica a sí mismo en Kad bajo `livehash:<streamKey>` y acepta
   peticiones de chunk de otros viewers hasta el tope de su tier.
   Este es el mecanismo por el cual la demanda de un stream popular
   crea oferta.

Siempre que el enforcement de ratio esté activo y los emisores
limiten su fanout directo (Sección 3.4), el ancho de banda
agregado disponible crece aproximadamente linealmente en el conteo
de viewers, sosteniendo la afirmación de la arquitectura de "más
viewers = más capacidad" — *más viewers = más capacidad* — en lugar
del más común "más viewers = emisor colapsado".

---

## 4. Implementación

El sistema está implementado como un fork del cliente eMule 0.70b.
La base de código es híbrida:

- Un **core C++ MFC (Microsoft Foundation Classes)**, implementando
  el subsistema live en 20 archivos fuente nuevos (~5.800 LOC)
  junto con modificaciones a ~30 archivos eMule existentes (~1.200
  LOC de cambios, cada uno anotado con comentarios de aviso GPL-2
  §2(a)).
- Un **dashboard Node.js** empaquetado vía [`pkg`](https://github.com/vercel/pkg)
  en un único ejecutable `ese-server.exe` de ~55 MB, comprendiendo
  64 módulos JavaScript (~12.000 LOC) hospedados en el puerto TCP
  8080.

Las dos mitades se comunican vía HTTP local: el lado Node hace
proxy de peticiones al lado C++ vía `http://127.0.0.1:4711/api/live/*`.
Una **puerta estricta solo-loopback** rechaza cualquier petición no
`127.0.0.1` a la API live (Sección 4.4).

### 4.1 Organización de la base de código

Los 20 archivos C++ nuevos se agrupan en tres grupos:

- **Protocolo / wire:** `LivePackets.{h,cpp}`, `LiveProtocol.{h,cpp}`,
  `LiveKadBridge.{h,cpp}` — definiciones de opcodes, serialización,
  wrappers de publicación/búsqueda Kad.
- **Estado y topología:** `LiveStreamManager.{h,cpp}`,
  `LiveMeshManager.{h,cpp}`, `LiveChunkBuffer.{h,cpp}` — máquina de
  estados viewer/peer, topología de árbol con multi-parent,
  ventana deslizante de chunks.
- **I/O y UX:** `RTMPIngest.{h,cpp}` (pipeline del emisor),
  `LiveStreamDlg.{h,cpp}` (tab UI MFC), `LiveDebugLog.{h,cpp}`
  (ring buffer en memoria expuesto vía HTTP).

El lado Node está organizado en `pages/` (rutas UI), `routes/`
(endpoints REST), `eSE-live/` (módulos específicos de live:
extracción de thumbnails, descubrimiento LAN, API de canales,
reproductor cinema), y `shared/` (utilidades cross-cutting incluyendo
el helper DOM resistente a XSS `safe_dom.js`).

### 4.2 Extensiones del protocolo wire

Los cinco nuevos opcodes (Sección 3.3) se despachan desde
`ListenSocket.cpp` (TCP) y `UDPSocket.cpp` (UDP) hacia los
handlers `LiveProtocol::OnPacket` y `LiveProtocol::OnUDPPacket`
respectivamente. La retrocompatibilidad se preserva condicionando
el dispatch al bit de capacidad live anunciado en el handshake
hello de eD2K; a los peers sin el bit nunca se les envían opcodes
live, y los opcodes live entrantes de peers no-anunciados se
descartan silenciosamente.

La extensión PEX a `OP_LIVE_HEARTBEAT` usa un bloque trailing TLV
con prefijo de longitud. Un receptor que no entiende el bloque
trailing (por ejemplo un fork antiguo que pre-data la extensión)
simplemente trunca el parsing en el byte 22, que es el tamaño
original del heartbeat. Este es el mismo patrón de extensión wire
usado por el protocolo de extensión de BitTorrent [14].

### 4.3 Pipeline local

El método `RTMPIngest::Start()` del emisor spawnea un proceso
hijo FFmpeg con una línea de comando construida en tiempo de
ejecución para coincidir con el encoder de hardware detectado.
Para NVIDIA NVENC el fragmento relevante es:

```
ffmpeg -listen 1 -i rtmp://127.0.0.1:1935/live/stream
  -filter_complex "[0:v]split=4[v1][v2][v3][v4];
                   [v1]scale=640:360[v1s];
                   [v2]scale=960:540[v2s];
                   [v3]scale=1280:720[v3s];
                   [v4]scale=1920:1080[v4s]"
  -map "[v1s]" -c:v h264_nvenc -b:v 600k -g 48 -keyint_min 48
  -map "[v2s]" -c:v h264_nvenc -b:v 1200k -g 48 -keyint_min 48
  -map "[v3s]" -c:v h264_nvenc -b:v 2500k -g 48 -keyint_min 48
  -map "[v4s]" -c:v h264_nvenc -b:v 5000k -g 48 -keyint_min 48
  -map 0:a -c:a aac -b:a 128k -ar 48000 -ac 2
  -f hls -hls_time 4 -hls_list_size 20
  -hls_segment_type mpegts
  -hls_flags independent_segments+omit_endlist+program_date_time
  -master_pl_name master.m3u8
  ...paths de salida...
```

Las flags `-g 48 -keyint_min 48` fuerzan keyframes cada 48 frames
(2 segundos a 24 fps), alineados con el `-hls_time 4` de modo que
cada chunk empieza en un keyframe y el cambio de variante del lado
del viewer es seamless.

Un proceso watcher hace polling del directorio de salida de FFmpeg
cada 250 ms, detecta archivos `seg_NNNNN.ts` recién emitidos, y
publica cada uno como un recurso eD2K indexado por la stream key
+ número de secuencia. Encontramos una regresión específica aquí,
arreglada en un commit reciente: el parser de filenames del
watcher anteriormente trataba `seg_eng_13697.ts` (una variante solo
de audio) como el segmento de vídeo numerado más alto, causando que
el buffer de chunks nunca avanzara. La corrección es una regex de
4 líneas que rechaza filenames con cualquier carácter no-dígito
entre `seg_` y `.ts`.

### 4.4 Modelo de seguridad

La superficie de administración local está confinada al loopback
TCP. Cada endpoint bajo `/api/live/*`, `/api/holepunch/*`,
`/api/status`, `/dashboard`, y `/hls/*` chequea la IP del peer
conectado contra `htonl(INADDR_LOOPBACK)` y devuelve HTTP 403 con
un diagnóstico logueado para cualquier fuente no-loopback. Esto
previene que un peer LAN curioso u hostil (por ejemplo alguien que
el usuario ha admitido vía el clásico `AllowedRemoteAccessIPs` para
intercambio de archivos) controle inadvertidamente el subsistema
live.

Se identificaron dos vulnerabilidades de cross-site scripting (XSS)
durante una revisión de seguridad del 2026-05-16: las cadenas
`title` / `category` / `quality` controladas por el emisor se
interpolaban sin escapar en las páginas inline `/live` y
`/live/{hash}` servidas desde el WebServer C++. Un emisor malicioso
podría publicar un stream con un título de
`<img src=x onerror=fetch("/api/live/broadcast/stop")>` y disparar
ejecución de script en el navegador de cualquier viewer que abriera
la página legacy, con acceso (bajo el origen loopback) a cada
endpoint `/api/live/*` "protegido". La corrección es un helper
inline mínimo `esc()` aplicado en cada punto de concatenación. El
dashboard moderno del lado Node en el puerto 8080 ya era seguro
(uso consistente de un helper `escH()`), pero vale la pena notar
que incluso la puerta loopback no protege contra un payload XSS
ejecutándose en el propio navegador del usuario — la puerta protege
contra atacantes *remotos*, no contra atacantes de *contenido*
accesibles a través del navegador de origen-confiado del propio
usuario.

El endpoint de chunks HLS valida el path de petición contra una
regex de allowlist estricta (`stream.m3u8`, `stream_*.m3u8`,
`seg_*.ts`, sin caracteres `..` o `/` permitidos), previniendo
traversal de directorios.

---

## 5. Evaluación

Reportamos mediciones del testing interno sobre hardware commodity.
No hacemos afirmación de significancia estadística; los resultados
son ilustrativos del comportamiento de orden de magnitud del sistema.

### 5.1 Verificación de extremo a extremo

El 2026-05-15 realizamos el primer test de broadcast en vivo
cross-host:

- **PC1 (emisor):** Windows 11, NVIDIA RTX 3070, ISP residencial
  (fibra simétrica 600 Mbps).
- **PC2 (viewer):** Windows 10, iGPU Intel, conexión por hotspot
  móvil (LTE, ~30 Mbps de bajada).

PC1 abrió OBS, configuró `rtmp://127.0.0.1:1935/live` como objetivo,
e inició un broadcast de captura de escritorio a 1080p / 5000 kbps.
En 8 segundos, el pipeline FFmpeg produjo el primer chunk HLS
multi-variante; en 12 segundos (el umbral de prebuffer), el stream
fue publicado en Kad y el dashboard del emisor mostró el tile del
stream.

PC2 recibió el enlace `ed2k://|live|<HEX>|<IP>:<PORT>|<TITLE>|/`
vía canales out-of-band (el usuario lo pegó desde el dashboard del
emisor), lo introdujo en el campo de pegar-enlace de `/live`, y en
3 segundos estaba viendo el stream en VLC. El `master.m3u8` local
del viewer era una reconstrucción byte-a-byte (módulo el tag
`EXT-X-START`) de la playlist del emisor, con el contenido del
chunk obtenido sobre el mesh eD2K.

Este es el hito formal "P2P live verificado de extremo a extremo"
referenciado en nuestras notas del proyecto.

### 5.2 Latencia de descubrimiento

La Tabla 1 resume la latencia de descubrimiento para los cuatro
escenarios que corresponden a cada una de nuestras capas de
descubrimiento, más un fallback "todas las capas fallan":

| Escenario | Capa usada | Tiempo mediano hasta primer chunk |
|---|---|---|
| Re-unirse a stream recientemente visto | Caché bootstrap | **4,7 s** |
| Nuevo stream en la misma LAN | Multicast mDNS | **0,9 s** |
| Nuevo stream, emisor conocido por un vecino del mesh | Gossip PEX | **3,2 s** |
| Nuevo stream, solo publicación DHT | Búsqueda Kad | **38 s** |
| Peor caso: caché en frío, sin LAN, sin PEX, Kad lento | Búsqueda Kad (lenta) | **115 s** |

La mediana de búsqueda Kad de 38 segundos es consistente con
estudios de medición generales de latencia de lookup Kad bajo churn
[4]; nuestra contribución **no** es mejorar la búsqueda Kad sino
*hacer que la búsqueda Kad no sea load-bearing en el caso común*
vía las tres capas complementarias.

### 5.3 Stress multi-instancia

Ejercitamos el comportamiento bajo carga de la arquitectura usando
un orquestador Node.js que spawnea hasta 50 instancias eMule
headless en un solo host. A cada instancia se le da un `--tcp-port`,
`--udp-port`, `--metrics-port` único y (dado que el `UserHash`
compartido causaría auto-rechazo) un user hash recién regenerado.
El orquestador recolecta `/api/live/metrics` de cada instancia cada
2 segundos y renderiza el resultado en un dashboard en tiempo real.

El stress single-host está limitado por el hecho de que todos los
"peers" comparten la misma NIC y contienden por los mismos buffers
de socket; observamos comportamiento gracioso hasta ~20 instancias
simultáneas por stream antes de que la tasa de chunk-drop por
instancia exceda el 1%. **No hacemos ninguna afirmación sobre el
comportamiento más allá de este punto** — la validación de swarms
más grandes requiere despliegue multi-host, que documentamos como
trabajo abierto en la Sección 7.

---

## 6. Discusión y Limitaciones

### 6.1 Lo que la arquitectura demostrablemente hace

- Transporta chunks de vídeo en vivo sobre el sustrato eD2K + Kad
  con latencia de extremo a extremo que es competitiva con HLS-sobre-CDN
  mainstream para contenido en vivo no-interactivo (~10–15 segundos
  glass-to-glass).
- Descubre streams sin ningún índice central de tres formas
  independientes, cada una empíricamente más rápida que las otras
  bajo condiciones específicas.
- Respeta la interoperabilidad eD2K existente — peers ejecutando
  eMule upstream sin modificar no son disruptidos, y siguen siendo
  útiles como peers de intercambio de archivos.
- Sobrevive al churn del emisor: cuando el emisor se desconecta, se
  publica un tombstone a Kad y se propaga vía PEX de modo que los
  viewers ven el fin del stream en 30 segundos.

### 6.2 Lo que aún no hace

- **Audiencias más allá de ~20 viewers por stream.** El stress
  single-host alcanza este techo. La validación multi-host está
  pendiente.
- **Latencia sub-segundo.** El extremo-a-extremo actual está
  dominado por la duración de chunk HLS de 4 segundos más el
  prebuffer de 3 chunks; reducir cualquiera requiere salir de
  HLS-como-protocolo hacia algo como WebRTC o SRT (Sección 7).
- **Moderación de contenido.** No proporcionamos herramientas para
  que ninguna parte retire contenido de la circulación. Esta es
  una no-característica deliberada heredada del sustrato eD2K.
- **Binding de identidad.** Una stream key es un identificador
  efímero de 16 bytes; nada en el sistema lo vincula a una
  identidad estable de emisor. La anti-impersonación requiere
  canales out-of-band (por ejemplo, el emisor compartiendo la
  stream key vía un website de confianza o un mensaje firmado).

### 6.3 Realidades de implementación

La elección de hacer fork de una base de código C++ MFC de diseño
de la era 2000 tiene dos costes específicos que encontramos:

- **Bugs de formateo de strings.** Crasheamos una vez a `t=8s` de
  cada run debido a un format specifier `%S` (esperando `LPCWSTR`)
  recibiendo un cast a entero (`UPNP_IMPL_MINIUPNPLIB`). El bug
  fue diagnosticado vía la flag de linker `/MAP`, captura de
  minidump, y resolución manual de símbolos. Alternativas modernas
  como `std::format` (C++20) capturan esto en tiempo de
  compilación; nuestra base de código pre-data C++17.
- **Stack de red síncrono.** La capa de transporte de eMule está
  construida sobre MFC `CAsyncSocket` / `CSocket`, que no escalan
  más allá de unos pocos cientos de conexiones. Hicimos workaround
  capando el fanout directo por peer (Sección 3.4), pero un
  reescrito profundo sobre IOCP o `asio` se requiere para el
  siguiente orden de magnitud en escala.

Catalogamos estos y otros 14 candidatos de modernización "esto era
2005-fine, 2026-not-fine" en un documento interno separado.

### 6.4 Modelo de amenazas

El sistema está diseñado para resistir tres clases de amenazas:

- **Censura del descubrimiento.** Defendida por la ausencia de
  cualquier índice central — no hay parte a la que emitir avisos
  de retirada. El descubrimiento no puede ser denegado sin tirar
  abajo toda la red Kad, un resultado que ningún actor ha logrado
  en veinte años.
- **Censura de la distribución.** Defendida solo débilmente: un
  adversario poderoso a nivel de red (ISP, firewall nacional)
  puede bloquear IPs de peers individuales pero no el protocolo
  como un todo, dada la proliferación de tráfico UDP atravesado
  por NAT. No se proporciona anonimato estilo Tor.
- **Flooding Sybil del directorio.** Defendida por el sanity-clamping
  de métricas anunciadas (conteos de viewers capados a 100.000,
  bitrates rechazados por encima de 50 Mbps), y por la utilidad
  limitada de entradas falsas (fallan en entregar chunks, así que
  los viewers caen a fuentes legítimas en segundos).

El sistema **no** está diseñado para resistir:

- **Moderación de contenido.** Ninguna parte puede prevenir
  contenido legal; ninguna parte puede asegurar contenido ilegal.
- **Análisis de tráfico.** Un observador en el enlace del emisor
  puede distinguir trivialmente tráfico de streaming en vivo de
  intercambio de archivos por timing de paquetes.
- **Compromiso de la máquina del emisor.** Un emisor cuya máquina
  está comprometida pierde la capacidad de hacer afirmaciones de
  autenticidad sobre su stream.

---

## 7. Trabajo Futuro

### 7.1 Modernización del transporte

El siguiente lift arquitectónico mayor es reemplazar la entrega de
chunks TCP-sobre-eD2K con **SRT** (Secure Reliable Transport,
draft RFC; implementación `libsrt` 1.5+) en el path live. SRT
proporciona cifrado inherente (AES-256), latencia configurable de
extremo a extremo (target 120 ms), y sobrevive pérdida de paquetes
del 5–10% sin tormentas de retransmisión. El co-diseño con Random
Linear Network Coding (RLNC) [15] permitiría además que cualquier K
chunks de cualquier subconjunto de N peers reconstruya el contenido
original, eliminando la necesidad de peticiones de retransmisión
explícitas.

### 7.2 Latencia sub-segundo vía bridge WebRTC

Para audiencias dispuestas a usar un navegador moderno, un bridge
WebRTC en el lado del emisor ofrecería latencia sub-segundo
glass-to-glass para viewers, mientras el mesh eD2K continúa
sirviendo como backbone de distribución. El navegador es el
terminador WebRTC, el peer eD2K es el iniciador WebRTC, y el
gateway cross-protocolo se implementa en el dashboard Node.

### 7.3 Membresía por gossip para escala

Más allá de ~5.000 viewers por stream, el mantenimiento del
overlay pair-wise actual se convierte en el cuello de botella. Los
protocolos de gossip **HyParView** [12] + **Plumtree** [13] son la
respuesta estándar en la literatura y se han desplegado en
producción en empresas como Bleemeo y en el framework `partisan`
de Erlang/OTP. Adaptar estos a un fork heterogéneo como eMule es
no-trivial pero bien entendido; estimamos ~3–4 semanas de
ingeniería a tiempo completo.

### 7.4 Payloads cifrados de extremo a extremo

Para emisores que quieran controlar el acceso de viewers, una capa
de cifrado AES-256-GCM por stream aplicada por chunk permitiría
distribución sobre el mesh (que sigue siendo "cualquiera-puede-relay")
mientras mantiene el payload confidencial. El problema de
distribución de claves se resuelve out-of-band (el emisor comparte
la clave vía un canal lateral de su elección).

### 7.5 Onion routing para anonimato

El sistema actual revela la IP del emisor a los viewers y la IP de
los viewers al emisor (este es el coste del P2P directo). Para
modelos de amenazas que requieren anonimato, un path de entrega
onion-routed multi-hop estilo Tor es una extensión creíble,
apoyándose en trabajo previo de las comunidades I2P y Garlicat. El
coste es varios segundos de latencia adicional de extremo a extremo
por hop.

---

## 8. Conclusión

Hemos presentado eSE Live, una extensión funcional de un cliente
de intercambio de archivos de veinte años de antigüedad en una
plataforma de emisión en vivo que no requiere servidores centrales,
ni CDN, ni coste operativo más allá del que impone la propia
conexión del emisor. El sistema ha sido verificado de extremo a
extremo a través de dos hosts en ISPs distintos y exhibe latencia
de descubrimiento competitiva con alternativas mainstream a través
de los escenarios comunes que cubre su pila de descubrimiento de
tres capas.

Nuestra afirmación principal es **arquitectónica**: una DHT
veterana diseñada para intercambio de archivos puede transportar
medios en vivo con un conjunto pequeño y retrocompatible de
extensiones de protocolo, y el sistema resultante hereda las
propiedades políticas y operativas (sin confianza central, sin
choke-point de censura, sin poder de fijación de precios del
operador) que hacen al P2P de intercambio de archivos duradero.

Lo que queda es el trabajo de scale-out — validación multi-host,
modernización del transporte, membresía basada en gossip — que
hemos esbozado como trabajo futuro. Liberamos la implementación
como código abierto bajo GPL-2 con la esperanza de que otras
comunidades interesadas en medios en vivo descentralizados la
encuentren un punto de partida útil en lugar de otra prueba de
concepto aislada.

---

## Agradecimientos

Agradecemos al eMule Project por dos décadas de stewardship del
cliente upstream. Agradecemos a las comunidades más amplias de
eD2K, Kad, y Tribler por el arte previo que hizo este diseño
factible.

Este trabajo fue llevado a cabo con uso extensivo de Claude Code de
Anthropic como asistente de ingeniería in-the-loop; los transcripts
completos del desarrollo están disponibles bajo petición.

---

## Referencias

[1] J. McCaleb. *eDonkey 2000*. Especificación de protocolo
    auto-publicada, 2000. Retrospectiva reconstruida: Heckmann et
    al., "A Performance Study of eMule and eDonkey on the Internet",
    en Proc. IPTPS 2006.

[2] eMule Project. *eMule — the all-platform compatible Kad/eD2K
    client*. <https://www.emule-project.net>, 2002–presente.

[3] P. Maymounkov y D. Mazières. *Kademlia: A Peer-to-Peer
    Information System Based on the XOR Metric*. En Proc. IPTPS,
    2002.

[4] M. Steiner, T. En-Najjary, y E. W. Biersack. *A Global View of
    Kad*. En Proc. IMC, 2007.

[5] Y. Chu, S. Rao, y H. Zhang. *A Case for End System Multicast*.
    En Proc. SIGMETRICS, 2000.

[6] Y. Chu, S. G. Rao, S. Seshan, y H. Zhang. *Enabling Conferencing
    Applications on the Internet Using an Overlay Multicast
    Architecture*. En Proc. SIGCOMM, 2001.

[7] X. Hei, C. Liang, J. Liang, Y. Liu, y K. W. Ross. *A Measurement
    Study of a Large-Scale P2P IPTV System*. IEEE Trans. Multimedia,
    9(8), 2007.

[8] X. Zhang, J. Liu, B. Li, y T.-S. P. Yum. *CoolStreaming/DONet:
    A Data-Driven Overlay Network for Peer-to-Peer Live Media
    Streaming*. En Proc. INFOCOM, 2005.

[9] J. A. Pouwelse, P. Garbacki, J. Wang, A. Bakker, J. Yang, A.
    Iosup, D. H. J. Epema, M. Reinders, M. R. van Steen, y H. J.
    Sips. *TRIBLER: a social-based peer-to-peer system*. Concurrency
    and Computation: Practice and Experience, 20(2), 2008.

[10] Framasoft. *PeerTube*. <https://joinpeertube.org>,
     2018–presente.

[11] F. Pianese, J. Keller, y E. W. Biersack. *PULSE, a Flexible P2P
     Live Streaming System*. En Proc. INFOCOM Workshops, 2006.

[12] J. Leitão, J. Pereira, y L. Rodrigues. *HyParView: a Membership
     Protocol for Reliable Gossip-Based Broadcast*. En Proc. DSN,
     2007.

[13] J. Leitão, J. Pereira, y L. Rodrigues. *Epidemic Broadcast
     Trees*. En Proc. SRDS, 2007.

[14] A. Norberg. *BEP-10: Extension Protocol*. BitTorrent
     Enhancement Proposal, 2008.

[15] T. Ho, M. Médard, R. Koetter, D. R. Karger, M. Effros, J. Shi,
     y B. Leong. *A Random Linear Network Coding Approach to
     Multicast*. IEEE Trans. Information Theory, 52(10), 2006.

[16] R. Pantos y W. May. *HTTP Live Streaming*. RFC 8216, 2017.

[17] S. Cheshire y M. Krochmal. *Multicast DNS*. RFC 6762, 2013.

[18] B. Cohen. *Incentives Build Robustness in BitTorrent*. En
     Proc. P2P Economics Workshop, 2003.

---

_Fin del paper. Versión enviada 1.0, 2026-05-17._
