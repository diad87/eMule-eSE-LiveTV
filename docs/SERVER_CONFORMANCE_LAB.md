# eSE — Laboratorio de conformidad de servidores y mods

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
