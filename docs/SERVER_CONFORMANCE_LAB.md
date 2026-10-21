# eSE — Laboratorio de conformidad de servidores y mods

**Aplicación vigente: v9.3 unificada, 30 de septiembre de 2026.** El
[plan único](V9.3_PLUS_RELEASE_TRAIN.md) incorpora este laboratorio a los
bloques **C** (QUIC peer y recepción) y **D** (servidores activos). Las
referencias a 9.7 y 9.8 de §§1–7 identifican esos dos bloques del diseño
original, no releases futuras ni una espera entre ellos. La aprobación del
alcance permite planificar ambos dentro de v9.3; no representa un `PASS` de
implementación o interoperabilidad.

El laboratorio sigue siendo una herramienta sin emisión productiva propia.
La promoción de cada emisor depende de recepción correcta, negociación y
autenticación verificadas. El inventario adicional y las pruebas vigentes de
§8 complementan los snapshots congelados de §2 sin reemplazarlos. La política
ligera de release del plan único prevalece sobre el calendario de §6 y la
campaña externa completa deja de ser una condición universal de publicación.

## Referencia de diseño conservada del 15 de agosto de 2026

Estado: carril transversal de herramientas y evidencia; cero emisión nueva  
Fecha: 15 de agosto de 2026  
Autoridad de identificadores eSE: `protocol/PROTOCOL_REGISTRY.md`

## 1. Decisión

El laboratorio puede construirse antes de 9.7 porque no cambia producción,
wire, preferencias ni UI. Su función es convertir documentación, PCAPs y
snapshots externos en contratos ejecutables. No autoriza interoperabilidad
activa y nunca asigna opcodes o tags.

El catálogo `protocol/EXTERNAL_INTEROP_CATALOG.csv` es observacional. Los CSV
existentes del registro de protocolo siguen siendo la única autoridad sobre
identificadores propiedad de eSE.

## 2. Snapshots congelados

| Implementación | Versión/commit | Papel en el laboratorio |
|---|---|---|
| eMule clásico 0.70b | base del repositorio | control negativo y compatibilidad legacy |
| eSE | commit de cada campaña | implementación bajo prueba |
| eMuleQt | `v0.3.0`, `0638dcc272d2ccc52b42018de26661541558f7e3` | cliente externo IPv6/ExtSX |
| eNode-go | `e901b44bd0f17ca880828a52a9d7e39c4dde21d0` | servidor externo IPv6 y referencia PR_NAT |
| JEmuleServer | snapshot por determinar | dialecto privado eSE existente |
| Lugdunum/servidor clásico | versión disponible y hash archivado | control de servidor clásico |
| ed2kNET | `UNVERIFIED` | watchlist; no entra en un gate sin fuente, build y licencia accesibles |

Actualizar un snapshot invalida sus golden packets y obliga a repetir la
campaña correspondiente. “Último upstream” no es una referencia reproducible.

## 3. Productos del laboratorio

1. catálogo namespaced con implementación, dirección, formato, endian,
   capability, downgrade, clasificación, commit y fuente;
2. golden packets byte a byte para recepción y emisión;
3. PCAPs saneados y manifiesto con SHA-256;
4. corpus truncado, sobredimensionado, reordered, tipo erróneo y tag desconocido;
5. fuzz y pruebas diferenciales contra modelos de los parsers externos;
6. matriz física IPv4-only, IPv6-only, dual-stack, LowID y UDP bloqueado;
7. informe por commit que distingue `PASS`, `FAIL`, `BLOCKED` y `NOT_APPLICABLE`.

Los perfiles descriptivos del harness son `CLASSIC`, `ESE_PRIVATE_V1` y
`EMULEQT_ENODE_IPV6_V1`. Sirven para seleccionar fixtures; en producción nunca
se decide por nombre de cliente, versión o banner, sino por capacidades y
mensajes realmente negociados.

## 4. Gates receptor-primero

| Gate | Requisito | Desbloquea |
|---|---|---|
| `SCL-G0-CATALOG` | esquema válido, IDs únicos, todos los commits presentes en fuentes HTTPS y clasificación explícita | crear fixtures |
| `SCL-G1-RX` | golden packets, truncación, límites, fuzz y cero desalineación/crash | integrar receptores apagados |
| `SCL-G2-NEGOTIATION` | capacidad positiva, ausencia, mentira, downgrade, control vanilla y `REG-DEBT-001` resuelto | hace elegible un emisor para su gate y autorización de release; no lo activa |
| `SCL-G3-SECURITY` | threat model, filtros IPv4/IPv6, anti-replay/abuso y logs saneados | pruebas físicas externas |
| `SCL-G4-PHYSICAL` | matriz fijada por commit y PCAPs con hash | propuesta de promoción |

Regla load-bearing: el laboratorio y 9.7 no conectan por IPv6 a un servidor ni
anuncian `CT_MOD_IP_V6 (0xAE)`/`SRVCAP_IPV6` en login. Que el parser del
sentinel `0xFFFFFFFF` pase `SCL-G1-RX` es necesario para recibir, pero no
autoriza esos emisores: permanecen en 9.8. Un fallo de stride puede desalinear
crypt flags, user hash y todas las fuentes que siguen.

## 5. Campañas mínimas

### 5.1 Servidor y fuentes IPv6

- login con y sin `0xAE`, con `SRVCAP_IPV6` solo y con ambos;
- flags `SRV_TCPFLG_IPV6/SRV_UDPFLG_IPV6 0x4000`; el flag NAT `0x8000` solo
  se observa y nunca habilita `PR_NAT v1`;
- `OP_SERVERIDENT` con tags en cualquier orden, tipos válidos e inválidos;
- `ST_IPV6_STATUS` en UINT8/16/32/64 y negativo para todo tipo no entero;
  congelar `HAVE=0x01`, `REACHABLE=0x02` y `PROBED=0x04`, con casos
  `0x00/01/02/03/04/05/06/07`, tag ausente y bits desconocidos. Ausente o
  `0x00` no emite veredicto; solo `PROBED=1 && REACHABLE=0` (`0x04/0x05`)
  suprime el anuncio, y el receptor ignora bits desconocidos;
- `CT_MOD_YOUR_IP 0xAD` de server-ident: negativos de reflexión sobre sesión
  IPv4, tipo UINT32/no-HASH16, dirección no global y valor no asignado a una
  interfaz local del receptor;
- servidor IPv6-only con campo IPv4 clásico a cero: el ident y todos sus tags
  deben emitirse, nunca omitirse por fallar la construcción IPv4;
- sentinel primero, en medio y último; múltiples fuentes y tails opcionales;
- separar por opcode el tail `_OBFU`; negativos de OBFU truncado y de un
  paquete normal que no debe interpretar bytes posteriores como crypt flags;
- en UDP, un sentinel ocupa un único file block por datagrama: negativo
  sentinel seguido de un segundo bloque `0xE3/0x9B` encadenado;
- callback `0x26`, `OP_CHANGE_CLIENT_IP 0xAC`, sentinel IPv6 de
  `OP_REASKCALLBACKTCP 0x9A`, server-list trailing block e IPv6-only;
- dialecto JEmuleServer eSE `0xF0/0xE2` en una campaña separada;
- control clásico byte-idéntico cuando no existe capacidad negociada.

### 5.2 Peer, ExtSX y Kad hints

- hello `0xAA/0xAD/0xAE` y unknown-tag skip;
- ExtSX v1 fijo: bits `MODMISC_EXTXS 0x01`, `MODMISC_IPV6 0x04` y
  `MODMISC_EXTXS_SKIPTAGS 0x20`, opcodes `0x83/0x84`, integer width, tags
  desconocidos y LowID con IPv6; golden hybrid
  `0x0A000001 → 0a 00 00 01`; `0xBC/0xBE` no se emiten sin bit `0x20`;
- tag hello buddy `0xA0` y tags Kad `ip6`/`bi6` como hints no autenticados,
  siempre validados antes de dial;
- negativos Kad para loopback, ULA, link-local, documentación, mapped-v4 y un
  receptor IPv4-firewalled que sí dispone de una ruta IPv6 aplicable;
- obfuscation UDP IPv6: material MD5 de 35 bytes, digest/clave RC4 de 16 bytes
  y magic en offset 32.

### 5.3 Rendezvous y callback entre servidores

El laboratorio puede reconocer y diseccionar `PR_NAT v1`, pero no emitirlo en
producción ni usarlo para registrar endpoints. La variante auditada permite
registro (`0xE4`/`0xE3`/`0xEC`), keepalive/ping (`0xE6`/`0xE2`),
`SYNC2 0xE9`, respuestas sync (`0xE1`/`0xE7`/`0xED`) y failed `0xE5` por hash
sin un binding suficiente a sesión/identidad y sin
protecciones de replay/cuota demostradas. Solo un `RendezvousV2` distinto,
autenticado y limitado puede pasar a 9.8.

Los subopcodes `0xE8/0xEA/0xEB/0xEF` permanecen reservados/no usados en el
snapshot: el dissector los etiqueta como desconocidos y no muta estado.

Una afirmación del foro o una implementación parcial no demuestra callback
entre servidores end-to-end. La campaña exige dos clientes, dos servidores,
redes distintas y correlación de una sola transacción hasta el DCO.

## 6. Encaje en releases

| Momento | Trabajo permitido |
|---|---|
| Ahora y 9.2–9.4 | catálogo, modelos, golden packets, PCAPs, fuzz y CI; cero producción/wire/UI |
| 9.5 | endpoint canónico, procedencia, TTL, dedupe y source cache necesarios por el lab |
| 9.6 | diagnóstico, preferencias, reset y privacidad de logs |
| 9.7 | recepción segura de servidor e interoperabilidad peer básica receptor-primero; sin login/dial IPv6 activo de servidor |
| 9.8 propuesta | interop activa de servidor, callback entre servidores, RendezvousV2, TLS/TCP y QUIC opcional |

El laboratorio no sustituye el `DirectConnectionOrchestrator`, Kad6, Punch2,
Punch3 ni el perfil `DirectOnlyV1`. Produce candidatos y evidencia; la
autoridad de ruta permanece donde la release normativa la haya definido.

## 7. Fuera de alcance

- asignar identificadores desde este documento o el foro;
- detectar capacidades por marca/modstring;
- copiar `PR_NAT v1` sin hardening;
- convertir el servidor en relay de archivos o LiveTV;
- prometer privacidad frente al propio servidor;
- hacer obligatorio TLS o QUIC;
- declarar compatible un proyecto que no pueda fijarse por versión/commit;
- introducir un segundo parser/emisor productivo antes de su gate receptor.

## 8. Ampliación vigente para v9.3: foro 167228

### 8.1 Inventario adicional, sin sustituir evidencia anterior

El [hilo 167228](https://forum.emule-project.net/index.php?showtopic=167228&st=20)
y su [post #36](https://forum.emule-project.net/index.php?showtopic=167228&view=findpost&p=1111137)
aportan candidatos al laboratorio. Los siguientes HEAD se fijaron el 30 de
septiembre de 2026 mediante consulta de los repositorios primarios. Son
**observaciones de código pendiente de conformidad**: tener un commit no
demuestra build, licencia adecuada de todas sus dependencias, corrección wire,
seguridad o interoperabilidad con eSE.

| Implementación | Snapshot adicional | Uso previsto en v9.3 |
|---|---|---|
| ed2k-server / ed2k-rust | [`78b1e4fde6a0e018975ab18e3d1d1f077e48c83a`](https://github.com/andrey23127/ed2k-server/tree/78b1e4fde6a0e018975ab18e3d1d1f077e48c83a) | extracción IPv6/NAT-T, contraste de parsers y negativos de namespace; NAT-T original no emisor |
| goed2k-server | [`a6dc0d64d896eb405a2db05b744a2f82605e415e`](https://github.com/chenjia404/goed2k-server/tree/a6dc0d64d896eb405a2db05b744a2f82605e415e) | inventario del wire realmente implementado; no asumir IPv6/NAT-T por aparecer en el hilo |
| eNode-go, observación nueva | [`d4ce0f04ee38cff1f67c286d07c4826bf09d77cb`](https://github.com/ModderMule/eNode-go/tree/d4ce0f04ee38cff1f67c286d07c4826bf09d77cb) | delta contra `e901b44bd0f17ca880828a52a9d7e39c4dde21d0`; fixtures independientes |

El eNode de Node.js se mantiene como
[referencia histórica](https://github.com/petermrg/eNode), sin convertir su
presencia en requisito. Los 43 contratos congelados del catálogo conservan su
proveniencia y sus targets históricos: `9.7` se aplica a C y `9.8` a D. Los
nuevos candidatos requieren extracción y fixtures propios antes de ampliar
el catálogo; no se declara que las filas existentes los hayan auditado.

### 8.2 Pruebas útiles incorporadas

| ID | Situación reproducible | Aceptación |
|---|---|---|
| `SCL93-Q01` | QUIC completa handshake, transfiere datos y después el bulk deja de avanzar mientras sigue vivo el control | watchdog de progreso útil confirmado, timeout acotado y fallback; el keepalive no oculta el atasco |
| `SCL93-Q02` | se activa fallback y QUIC vuelve a parecer disponible | cancelar el intento perdedor, una sola sesión y contabilidad; cooldown por ruta/generación, sin bucle de reselección |
| `SCL93-Q03` | cola sin datos disponibles, pausa del usuario o congestión transitoria | no confundir ausencia legítima de trabajo con transporte atascado; temporizador según trabajo pendiente y presupuesto documentado |
| `SCL93-Q04` | bloqueo UDP, blackhole de paquetes grandes/PMTU, pérdida o reordenación | completar una descarga con hash correcto por QUIC o fallback; no atribuir una causa de red a un único log |
| `SCL93-Q05` | NAT rebinding, cambio de red o suspensión/reanudación | validar criptográficamente la nueva ruta dentro de la conexión autenticada, invalidar la generación anterior y preservar una sola sesión; si falla, reconectar/fallback |
| `SCL93-V601` | el cliente establece conexión IPv6 saliente pero el puerto anunciado no recibe conexiones nuevas | no promover la salida a prueba de entrada; connect-back independiente, correlacionado y con TTL, antes de declarar alcanzabilidad entrante |
| `SCL93-N01` | llega un opcode peer Rust que coincide con una función local | no despachar bytes por coincidencia numérica; preservar protocolo, dirección, namespace y capability |
| `SCL93-R01` | datagrama NAT-T/PR_NAT con user hash ajeno, repetido o cambiado de sesión | diagnóstico sin registrar endpoints ni emitir la variante insegura; solo RendezvousV2 autenticado puede mutar estado |

El watchdog se aplica primero a QUIC peer del bloque C y se reutiliza en el
selector cliente-servidor de D, cuyo fallback no puede duplicar login,
publicación, búsqueda o callback. Las métricas distinguen handshake, bytes de
aplicación confirmados, motivo de fallback y transporte final; una conexión
abierta por sí sola no es éxito.

### 8.3 Decisiones de wire y seguridad

- Los opcodes peer propuestos por ed2k-rust bajo `OP_EMULEPROT` incluyen
  `0xB3` y `0xD0–0xD7`. Localmente `0xB3` es `OP_PUBLICIP_ANSWER_V6` y el
  intervalo D0–D7 pertenece a Live/túneles o reservas en
  [`Opcodes.h`](../srchybrid/Opcodes.h). El dialecto NAT Rust queda
  `wire-conflict / never-send`; no se reutilizan esas reservas aunque una
  función local esté apagada. El receptor clásico de un opcode local no se
  convierte automáticamente en receptor NAT Rust.
- Los mensajes TCP **de servidor** `0x60–0x62` y UDP **de servidor** `0x9F`
  tienen otro namespace: compartir un número con un mensaje peer no prueba
  colisión. Se extraen envoltura, dirección, capability y formato antes de
  compararlos. Ninguno se habilita por esta observación.
- `PR_NAT v1` y el NAT-T original de Rust son diagnóstico/`never-send` en
  v9.3. `user_hash`, puerto UDP o un flag NAT no autentican al cliente ni
  expresan consentimiento; no sustituyen `RendezvousV2`, prueba de posesión,
  binding de sesión/canal, anti-replay y límites de abuso.
- El [RUDP con cabecera uTP del post #27](https://forum.emule-project.net/index.php?showtopic=167228&view=findpost&p=1110927)
  no se incorpora: una cabecera BEP-29 no acredita interoperabilidad uTP y
  nonces públicos por sí solos no establecen una clave secreta autenticada.
  QUIC/uTP estándar y negociación explícita siguen siendo la base.
- La prueba IPv6 entrante debe observar un flujo nuevo hacia el puerto
  anunciado. Un login IPv6 saliente o una dirección reflejada no prueban esa
  capacidad. Se conservan los filtros y semántica de `ST_IPV6_STATUS` de §5.1.

### 8.4 Laboratorio propio y aceptación proporcionada

El bloque D incluye un servidor de referencia local reproducible, con ambos
extremos bajo control del proyecto. Permite probar login/fuentes, IPv6,
callback, RendezvousV2, TLS y QUIC sin un operador externo. Un callback
cross-server usa dos instancias de servidor y dos peers propios, correlaciona
una sola transacción y entrega candidatos al DCO; no requiere una federación
operada por terceros.

Para publicar las funciones habilitadas son obligatorios la descarga con hash
correcto, identidad y negociación, fallback post-handshake, ausencia de
sesiones duplicadas, límites del parser y compatibilidad clásica. Se ejecutan
las pruebas afectadas por cada cambio y se reutiliza evidencia vigente; un
cambio documental no obliga a repetir campañas de red. Se agrupan sesiones
reales y estabilidad según el plan único, sin trasladar aquí los antiguos
umbrales 30/30 o 72 h como condiciones universales.

La matriz adicional de mods, operadores, ISP y redes con filtrado amplía
cobertura, pero su disponibilidad no bloquea v9.3. Se publica el resultado
con su alcance: **validado con referencia propia**, **validado con snapshot
externo**, o **sin probar externamente**. La ausencia de validación externa no
se etiqueta `PASS` y un endpoint sin capability sigue el camino clásico sin
emisión experimental. Las rutas con integridad/autenticación/fallback
defectuosos siguen cerradas; declarar un hueco externo no subsana ese defecto.
