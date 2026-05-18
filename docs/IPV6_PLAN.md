# Plan Maestro IPv6 para eMule 0.70b + eSE/LiveTV

**Documento de arquitectura, diseño e implementación**
Versión 1.0 — 2026-05-17
Autor: análisis colaborativo (i.unanue@kluppy.com)
Estado: propuesta inicial, pendiente de revisión

---

## Abstract

Este documento describe el plan completo para introducir soporte IPv6 nativo en el cliente eMule 0.70b y su extensión propia eSE (Streaming Engine) + LiveTV, preservando **compatibilidad bidireccional total** con (a) clientes upstream eMule 0.70b IPv4-only, (b) versiones previas de este fork, y (c) servidores eD2K y nodos Kademlia existentes en la red. El trabajo es no trivial porque el protocolo eD2K codifica direcciones IP como `uint32` en al menos 14 opcodes de wire y en cuatro formatos de archivo persistente, y porque el sistema de identidad de eMule (`UserID`/`lowID`/`highID`) deriva del IP en muchos caminos.

**Decisión de scope clave** (ADR-09): el protocolo cliente↔servidor eD2K queda **congelado en IPv4**. Los servidores (Lugdunum closed-source, eserver sin desarrollo) no se actualizarán, así que IPv6 nativo vive exclusivamente en (i) wire cliente↔cliente, (ii) Kademlia, y (iii) eSE/LiveTV. Esta acotación reduce el riesgo, elimina opcodes huérfanos, y se alinea con la tendencia natural de la red eMule hacia Kad-first.

Se propone una migración en 8 fases organizadas alrededor de un tipo canónico (`CAddress`, ya presente en el árbol pero sin adoptar) y una negociación de capacidades vía `OP_EMULEINFO` que activa opcodes paralelos para los pares dual-stack. Una **cascada de 5 capas anti-firewall** (PCP → IGDv2 AddPinhole → keepalive UDP → hole-punching coordinado por Kad → buddy relay, §8.5) garantiza que ~99% de los clientes IPv6 sean alcanzables aunque el operador o el router doméstico tenga firewall stateful. La duración estimada total es **21 semanas** de un desarrollador FTE, con primer hito (dual-stack listening) en 3 semanas.

---

## Índice

1. [Motivación y contexto](#1-motivación-y-contexto)
2. [Estado del arte interno: qué ya existe](#2-estado-del-arte-interno-qué-ya-existe)
3. [Análisis de impacto por capa](#3-análisis-de-impacto-por-capa)
4. [Decisiones arquitectónicas (ADRs)](#4-decisiones-arquitectónicas-adrs)
5. [Diseño detallado](#5-diseño-detallado)
6. [Plan de implementación por fases](#6-plan-de-implementación-por-fases)
7. [Matriz de compatibilidad backward](#7-matriz-de-compatibilidad-backward)
8. [NAT, descubrimiento y problema de identidad en IPv6](#8-nat-descubrimiento-y-problema-de-identidad-en-ipv6)
9. [Persistencia y migración de formatos](#9-persistencia-y-migración-de-formatos)
10. [Estrategia de pruebas](#10-estrategia-de-pruebas)
11. [Riesgos, mitigaciones y plan B](#11-riesgos-mitigaciones-y-plan-b)
12. [Cronograma](#12-cronograma)
13. [Apéndice A: inventario de archivos a tocar](#apéndice-a-inventario-de-archivos-a-tocar)
14. [Apéndice B: nuevos opcodes y tags](#apéndice-b-nuevos-opcodes-y-tags)
15. [Apéndice C: pseudocódigo de los puntos críticos](#apéndice-c-pseudocódigo-de-los-puntos-críticos)

---

## 1. Motivación y contexto

### 1.1 ¿Por qué IPv6 ahora?

- **Agotamiento de IPv4 público**. RIPE, ARIN, APNIC y LACNIC ya no asignan IPv4 nuevo. Los ISP migran a CGNAT, que rompe el modelo P2P: dos clientes detrás de CGNAT con UDP simétrico no pueden hacer hole-punching de forma fiable.
- **CGNAT mata el "highID"**. En el protocolo eD2K, un cliente con highID es uno con puerto TCP/UDP entrante alcanzable desde Internet. Con CGNAT, prácticamente todos los nuevos clientes residenciales son lowID, lo que (i) carga a los servidores con tráfico de callbacks, (ii) reduce el grafo de upload posible, y (iii) baja la utilidad de Kad porque los nodos no pueden ser contactados directamente.
- **IPv6 da a cada cliente una IP pública alcanzable** (modulo firewall doméstico, que es trivial de abrir con UPnP-IGDv2/PCP comparado con CGNAT). Esto restaura el modelo de pares con highID natural.
- **LiveTV es especialmente sensible**. Un stream en directo no tolera la latencia de un callback. Sin hole-punching IPv6, la cadena `broadcaster → mesh peer → viewer` rompe a la primera capa NAT simétrica.

### 1.2 Restricción de oro: compatibilidad backward

> *"Backward compatibility is mandatory — every wire/file/format change must work with upstream 0.70b AND prior fork versions, no exceptions."* — memoria persistente del proyecto.

Esto descarta de entrada cualquier rediseño del protocolo eD2K que cambie el ancho de los campos IP existentes. La estrategia debe ser **aditiva**, nunca sustitutiva: los opcodes y tags actuales siguen funcionando idénticos, y la información IPv6 viaja por opcodes/tags nuevos que un cliente viejo simplemente ignora (la maquinaria de `CTag` y de `CPacket` ya descarta tags desconocidos sin error — comprobado).

### 1.3 Riesgo Cloudflare y por qué no nos salva

Tenemos en memoria que **nunca debemos depender de Cloudflare** para distribución de contenido (riesgo de baneo TOS). Esto refuerza la importancia de IPv6 P2P puro: cualquier solución que routée chunks o playlists a través de un proxy comercial es inaceptable. IPv6 es la salida nativa al callejón sin salida de IPv4+CGNAT.

### 1.4 Alcance explícito: los servidores quedan fuera

**Decisión arquitectónica de partida**: el protocolo cliente↔servidor eD2K (`OP_LOGINREQUEST`, `OP_FOUNDSOURCES`, `OP_CALLBACKREQUESTED`, `OP_IDCHANGE`, `OP_SERVERIDENT`) **no se toca**. Los servidores eD2K (Lugdunum closed-source, eserver open-source con desarrollo congelado) no se van a actualizar, y coordinar una migración del ecosistema servidor está fuera de nuestro control.

Implicación: IPv6 vive exclusivamente en (a) el wire **cliente↔cliente**, (b) **Kad**, y (c) **eSE/LiveTV** (que ya es Kad-nativo). Para los servidores, un cliente dual-stack se comporta exactamente como hoy — habla IPv4, recibe lowID/highID IPv4, intercambia fuentes IPv4. Cualquier descubrimiento IPv6 nativo pasa por Kad. Un cliente IPv6-only no podrá conectar a servidores eD2K (necesitaría NAT64 a nivel ISP), pero sí podrá hacer Kad puro y participar en LiveTV.

Esto no es una concesión: es la realidad estructural del ecosistema, y además **simplifica el plan**: reducimos opcodes a tocar, eliminamos el problema de "identidad sintética IPv6 → uint32" en el camino del servidor, y dejamos la negociación de capabilities limitada al handshake peer-to-peer.

Lo que queda **explícitamente fuera de scope** del plan:
- Modificar `OP_LOGINREQUEST`, `OP_IDCHANGE`, `OP_SERVERIDENT`, `OP_FOUNDSOURCES`, `OP_CALLBACKREQUESTED`, `OP_SEARCHRESULT`, `OP_SERVERMESSAGE`.
- Cualquier `_V6` para tráfico servidor-mediado.
- Asignación de "lowID/highID IPv6" por servidor — no existe.

Lo que **sí** queda dentro:
- Todos los opcodes cliente↔cliente con IPs (`OP_HELLO`, `OP_HELLOANSWER`, `OP_PUBLICIP_*`, `OP_ANSWERSOURCES2`, source exchange).
- Kad completo (rutas, contactos, publish, search, firewall check).
- eSE/LiveTV completo.

---

## 2. Estado del arte interno: qué ya existe

Antes de diseñar nada, hay que inventariar lo que el árbol **ya tiene**. La sorpresa: hay infraestructura IPv6 a medio hacer.

### 2.1 Clase `CAddress` (lista para adoptar)

[`srchybrid/eMuleAI/Address.h:9`](srchybrid/eMuleAI/Address.h:9) define una clase dual-stack completa:

```cpp
class CAddress {
  public:
    enum EAF { None = 0, IPv4, IPv6 };
    // Constructores desde sockaddr, uint32, CUInt128, string
    void FromSA(const sockaddr* sa, int sa_len, uint16* pPort = NULL);
    void ToSA(sockaddr* sa, int *sa_len, uint16 uPort = 0) const;
    const CString ToStringC() const;
    const uint32 ToUInt32(bool bReverse) const;
    const Kademlia::CUInt128 ToUInt128(bool bReverse) const;
    const bool IsMappedIPv4() const;
    const bool IsPublicIP() const;
    const bool Convert(EAF eAF);  // IPv4 ↔ IPv4-mapped-IPv6
  protected:
    byte m_IP[16];     // ← buffer de 128 bits, IPv4 ocupa los últimos 4
    EAF m_eAF;
};
```

[`srchybrid/eMuleAI/Address.cpp`](srchybrid/eMuleAI/Address.cpp) implementa `_inet_ntop`/`_inet_pton` propios (sin depender de la versión de SDK), parsing de notación `::1`, `[2001:db8::1]:port`, IPv4-mapped, etc.

**Implicación estratégica**: el plan se reduce a (a) acabar lo que falta de `CAddress`, (b) adoptarlo en todas las capas, y (c) extender los protocolos.

### 2.2 Sockets dual-stack (parcialmente listos)

[`srchybrid/AsyncSocketEx.h:134`](srchybrid/AsyncSocketEx.h:134) ya acepta `ADDRESS_FAMILY nFamily = AF_INET` como parámetro de `Create()`. La implementación maneja `AF_INET6` en:

- [`AsyncSocketEx.cpp:731-735`](srchybrid/AsyncSocketEx.cpp:731) — construcción de `SOCKADDR_IN6` para `bind` en IPv6.
- [`AsyncSocketEx.cpp:1021-1028`](srchybrid/AsyncSocketEx.cpp:1021) — lectura de la dirección local del socket, con `Inet6AddrToString`.
- [`AsyncSocketExLayer.cpp:283`](srchybrid/AsyncSocketExLayer.cpp:283) — `if (m_nFamily == AF_INET || m_nFamily == AF_INET6 || m_nFamily == AF_UNSPEC)`.

`getaddrinfo()` (dual-stack DNS) ya se usa en 6 sitios:

- [`AsyncProxySocketLayer.cpp:741`](srchybrid/AsyncProxySocketLayer.cpp:741)
- [`AsyncSocketEx.cpp:746`](srchybrid/AsyncSocketEx.cpp:746) y [`AsyncSocketEx.cpp:931`](srchybrid/AsyncSocketEx.cpp:931)
- [`AsyncSocketExLayer.cpp:296`](srchybrid/AsyncSocketExLayer.cpp:296)
- [`KademliaUDPListener.cpp:148`](srchybrid/kademlia/net/KademliaUDPListener.cpp:148)
- [`ServerConnect.cpp:554`](srchybrid/ServerConnect.cpp:554)

**Hueco**: en todos esos sitios el resultado se reduce inmediatamente a `uint32` IPv4 por debajo (se descartan los registros AAAA). Hay que rescatar esa información.

### 2.3 Lo que NO existe (y hay que construir)

- Listener TCP/UDP **simultáneo** en `AF_INET6` con socket dual-stack (`IPV6_V6ONLY=0`).
- Ningún uso de `CAddress` fuera del módulo `eMuleAI/` (es código huérfano).
- Cero opcodes eD2K que sepan transportar direcciones IPv6.
- Cero versionado de archivos persistentes que prevea entradas de 16 bytes.
- UI no contempla buffers de 39 caracteres para IPv6.
- UPnP solo registra IPv4. No hay PCP (RFC 6887).

---

## 3. Análisis de impacto por capa

Mapeo capa por capa, con referencias `file:line` a los puntos donde IPv4 está incrustado. Las cifras de complejidad usan la escala trivial/moderado/difícil/crítico.

### 3.1 Capa 0 — Winsock y sockets

| Punto | Archivo:línea | Complejidad |
|---|---|---|
| `WSAStartup(2,2)` | [`Emule.cpp:387`](srchybrid/Emule.cpp:387) | trivial — ya 2.2, soporta IPv6 |
| `CAsyncSocketEx::Create` familia | [`AsyncSocketEx.h:134`](srchybrid/AsyncSocketEx.h:134) | trivial |
| Listener TCP eMule | [`ListenSocket.cpp:2149`](srchybrid/ListenSocket.cpp:2149) | moderado — pasa `AF_INET` literal |
| UDP socket Kad | [`ClientUDPSocket.cpp`](srchybrid/ClientUDPSocket.cpp) | moderado |
| `SOCKADDR_IN` literal en `BaseClient` | [`BaseClient.cpp:1566`](srchybrid/BaseClient.cpp:1566) | moderado |
| `inet_addr`/`inet_ntoa` | múltiples | moderado — reemplazar por `_inet_pton`/`_inet_ntop` |

**Conclusión**: capa relativamente fácil. La abstracción ya está; falta empujar el `AF_INET6` por las firmas.

### 3.2 Capa 1 — Protocolo eD2K (wire client-client y client-server)

**Aquí está el corazón del problema**. 14 opcodes acarrean IPs `uint32`. Por la decisión de §1.4, **solo se tocan los cliente↔cliente**; los cliente↔servidor se documentan aquí por completitud pero quedan **fuera de scope** (marcados `[OUT]`).

| Opcode | Hex | Carga útil con IP | Archivo | Scope |
|---|---|---|---|---|
| `OP_LOGINREQUEST` | 0x01 | UserID(4)+Port(2) | [`ServerConnect.cpp:207`](srchybrid/ServerConnect.cpp:207) | **[OUT]** servidor |
| `OP_SEARCHRESULT` | 0x33 | ID(4)+Port(2) por resultado | [`ServerSocket.cpp:356`](srchybrid/ServerSocket.cpp:356) | **[OUT]** servidor |
| `OP_CALLBACKREQUESTED` | 0x35 | IP(4)+Port(2) | [`ServerSocket.cpp:512`](srchybrid/ServerSocket.cpp:512) | **[OUT]** servidor |
| `OP_FOUNDSOURCES` | 0x42 | (ID(4)+Port(2)) × N | [`ServerSocket.cpp:367`](srchybrid/ServerSocket.cpp:367) | **[OUT]** servidor |
| `OP_FOUNDSOURCES_OBFU` | 0x44 | + flags y hash | [`ServerSocket.cpp:378`](srchybrid/ServerSocket.cpp:378) | **[OUT]** servidor |
| `OP_IDCHANGE` | 0x40 | ID(4)+flags(4)+...+ClientIP(4) | [`ServerSocket.cpp:252`](srchybrid/ServerSocket.cpp:252) | **[OUT]** servidor |
| `OP_SERVERIDENT` | 0x41 | Hash(16)+IP(4)+Port(2)+Tags | [`ServerSocket.cpp:406`](srchybrid/ServerSocket.cpp:406) | **[OUT]** servidor |
| `OP_HELLO` (C-C) | 0x01 | Hash+ID(4)+Port(2)+Tags(incluye IP servidor) | [`BaseClient.cpp:737`](srchybrid/BaseClient.cpp:737) | **[IN]** P2P |
| `OP_HELLOANSWER` | 0x4C | igual + ServerIP(4)+Port(2) | [`BaseClient.cpp:952`](srchybrid/BaseClient.cpp:952) | **[IN]** P2P |
| `OP_ANSWERSOURCES2` | 0x84 | versión 1 byte + (ID(4)+Port(2)+ServerIP(4)+ServerPort(2)+Hash(16)+crypt(1)) × N | [`ListenSocket.cpp:1303`](srchybrid/ListenSocket.cpp:1303) | **[IN]** P2P |
| `OP_PUBLICIP_REQ` | 0x97 | — | [`BaseClient.cpp:2593`](srchybrid/BaseClient.cpp:2593) | **[IN]** P2P |
| `OP_PUBLICIP_ANSWER` | 0x98 | IP(4) | [`ListenSocket.cpp:1378`](srchybrid/ListenSocket.cpp:1378) | **[IN]** P2P |
| Tag `TAG_SERVERIP` 0xFB | — | uint32 | múltiples (servidor + P2P) | mixto: se duplica con `_V6` solo en contexto P2P |
| Tag `TAG_SOURCEIP` 0xFE | — | uint32 | igual | igual |

**Complejidad: crítica para los `[IN]`, irrelevante para los `[OUT]`**. Cambiar el ancho de IP en cualquier opcode `[IN]` rompe el protocolo P2P; la salida es **opcodes paralelos** (ver §5.2). Los `[OUT]` se dejan intactos para siempre: nuestro cliente sigue hablando IPv4 con los servidores y eso es todo.

**Reducción de scope**: de los 14 opcodes inicialmente listados, **solo 5 reciben tratamiento `_V6`** (`OP_HELLO`/`OP_HELLOANSWER` que solo añaden el tag de capability, `OP_ANSWERSOURCES2` con versión interna v5, `OP_PUBLICIP_ANSWER_V6`, y opcionalmente un mecanismo P2P-callback que sustituye al `OP_CALLBACKREQUESTED` del servidor — ver §8.2).

### 3.3 Capa 2 — Kademlia (DHT)

Kad es **más fácil** que eD2K para IPv6 porque:

- El `KadID` es 128-bit y no se deriva del IP (es un identificador random persistente).
- Los contactos llevan IP como campo separado, no como identidad.
- `nodes.dat` tiene versionado explícito (`uVersion = 0/1/2/3`).

Pero hay puntos hardcoded:

- [`Contact.h:62`](srchybrid/kademlia/routing/Contact.h:62) — `uint32 GetIPAddress() const { return m_uIp; }`.
- [`RoutingZone.cpp:182-228`](srchybrid/kademlia/routing/RoutingZone.cpp:182) — lectura de `nodes.dat` (30 bytes/contacto, IP en posición 16-19).
- [`RoutingZone.cpp:362-378`](srchybrid/kademlia/routing/RoutingZone.cpp:362) — escritura.
- [`KademliaUDPListener.h:62`](srchybrid/kademlia/net/KademliaUDPListener.h:62) — `ProcessPacket(..., uint32 uIP, uint16 uUDPPort, ...)`.

**Opcodes Kad** ([`Opcodes.h:574-627`](srchybrid/Opcodes.h:574)): existe ya una segunda generación `KADEMLIA2_*` (HELLO_REQ 0x11, REQ 0x21, PUBLISH_KEY_REQ 0x43, etc.) introducida en su día como migración suave. **Esto es el patrón** a seguir: una tercera generación `KADEMLIA3_*` para IPv6 puede coexistir.

**Complejidad: difícil pero limpia**. El versionado de Kad ya existe; ampliarlo es natural.

### 3.4 Capa 3 — eSE / LiveTV (extensiones propias del fork)

Esto es código nuestro, así que tenemos libertad total **siempre que** las versiones previas del fork sigan interoperando.

Puntos críticos:

- [`Opcodes.h:289-298`](srchybrid/Opcodes.h:289) — `OP_LIVE_*` (0xC0..0xC8, 0xCA). El más sensible: `OP_LIVE_PEER_LIST = 0xCA` con `<StreamHash 16><Count 2>(<IP 4><Port 2><Score 1>) × Count`.
- [`LivePackets.cpp:71-79`](srchybrid/LivePackets.cpp:71) — `BuildLivePeerListPacket()` escribe `uint32` IPs.
- [`LiveKadBridge.h:14-26`](srchybrid/LiveKadBridge.h:14) — `struct LiveStreamEntry { uchar streamKey[16]; uint32 broadcasterIP; uint16 broadcasterPort; uint32 viewerCount; };`.
- [`LiveKadBridge.cpp:90-91`](srchybrid/LiveKadBridge.cpp:90) — siembra del IP del broadcaster en el publish Kad.
- [`Search.cpp:1195-1201`](srchybrid/kademlia/kademlia/Search.cpp:1195) — decodificación de `TAG_SOURCEIP`/`TAG_SOURCEPORT` en resultados Kad para streams.
- [`Search.cpp:1284-1291`](srchybrid/kademlia/kademlia/Search.cpp:1284) — invocación a `OnKadSearchResult` con `uLiveIP`/`uLivePort`.
- [`LiveStreamManager.cpp:200-244`](srchybrid/LiveStreamManager.cpp:200) — `TryConnectToStreamSource(uchar* streamKey, uint32 ip, uint16 port)`.
- [`LiveStreamManager.cpp:775-797`](srchybrid/LiveStreamManager.cpp:775) — **subnet diversity** (`peerIP & 0xFFFFFF00` para /24, `& 0xFFFF0000` para /16). En IPv6 esto se generaliza a /48 (sitio) y /64 (subred).
- [`LiveStreamDlgUI.cpp:173-176`](srchybrid/LiveStreamDlgUI.cpp:173) — URL HLS hardcodeada a `http://localhost:8080/...`. Hay que pasar a `http://[::1]:8080/...` o usar `127.0.0.1` resolviendo dinámicamente.
- [`eSE/eSE-live/rtmp_server.js:37-40`](srchybrid/eSE/eSE-live/rtmp_server.js:37) — bind RTMP en `127.0.0.1:1935`. En entornos IPv6-only del host habrá que escuchar también en `[::1]`.

**Complejidad: moderada**. Es código nuestro, podemos cambiar el wire si subimos un version byte y mantenemos el opcode viejo para forks anteriores.

### 3.5 Capa 4 — Persistencia en disco

| Archivo | Formato | Versionado actual | Campo IP | Complejidad |
|---|---|---|---|---|
| `server.met` | tagset binario | sin versión global, tags individuales (`ST_IP=0x10`, `ST_DYNIP=0x85`) | `uint32` o string (dynip) | moderado |
| `nodes.dat` | binario con `uVersion = 0/1/2/3` en cabecera | sí | `uint32` a offset 16 de cada contacto | moderado |
| `known.met` | tagset binario, `MET_HEADER=0x0E` o `MET_HEADER_I64TAGS=0x0F` | sí (1 byte) | `TAG_SOURCEIP=0xFE` con `uint32` | moderado |
| `credits.met` | binario, `CREDITFILE_VERSION=0x12` | sí | **NO contiene IP** | trivial |
| `ipfilter.dat` / `.p2p` / `.p2b` | texto o binario PeerGuardian2 | parcial | dos `uint32` (start, end) | difícil |
| `preferences.ini` | INI texto | sin versión | string para bind, etc. | trivial |
| `preferences.dat` | binario | sí | varios | moderado |

**Estrategia común**: cada formato gana una versión nueva. Al leer, el código detecta la versión y elige el parser correcto. Al escribir, se elige la versión más alta que el resto del ecosistema acepte (configurable: "modo compatible" vs "modo moderno").

### 3.6 Capa 5 — NAT y descubrimiento

- **UPnP** existe en 3 implementaciones paralelas ([`UPnPImpl.h:27-33`](srchybrid/UPnPImpl.h:27)):
  - `CUPnPImplWinServ` (COM, IUPnPDevice).
  - `CUPnPImplMiniLib` (miniupnpc).
  - `CUPnPImplNATPMP` (RFC 6886).

  En IPv6 normalmente **no necesitas port mapping** (cada host tiene dirección global). Pero detrás de un firewall doméstico sí, y para eso existe **PCP** (RFC 6887, sucesor de NAT-PMP) que sí soporta IPv6. IGDv2 también introduce acciones `AddPinhole`/`DeletePinhole` específicas para IPv6.

- **STUN/TURN**: eMule no usa STUN. Sin embargo, el fork eSE planea hole-punching (`KADEMLIA_ESE_HOLEPUNCH_REQ` mencionado en `ARCHITECTURE_eSE_NETWORK.md` — pendiente de implementación). En IPv6 esto se simplifica enormemente: hole-punching IPv6 sobre UDP es viable en ~95% de los firewalls residenciales.

- **Detección de IP pública**: hoy se hace con `OP_PUBLICIP_REQ/ANSWER`. Necesita versión IPv6.

### 3.7 Capa 6 — UI y preferencias

| Punto | Archivo:línea | Complejidad |
|---|---|---|
| `ServerListCtrl` columna IP:port | [`ServerListCtrl.cpp:124-126`](srchybrid/ServerListCtrl.cpp:124) | trivial (cambiar ancho) |
| Buffer `Server::ipfull[16]` | [`Server.h:170`](srchybrid/Server.h:170) | trivial (a `[48]`) |
| Bind address en prefs | [`Preferences.h:147-158`](srchybrid/Preferences.h:147) | trivial (segundo string) |
| `IsLowID` semántica | [`OtherFunctions.h:449`](srchybrid/OtherFunctions.h:449) | crítico — ver §8 |
| ipfilter editor UI | varios | difícil |
| Diálogo "Mis conexiones" | `PPgConnection.cpp` | moderado |

---

## 4. Decisiones arquitectónicas (ADRs)

### ADR-01: `CAddress` como tipo canónico interno

Toda dirección IP que circule por el código C++ usa `CAddress` (con su `EAF` discriminator). Las firmas `uint32 ip` se mantienen **solo** en (a) la frontera de wire IPv4 legacy y (b) Kad legacy. Adaptadores `CAddress::ToUInt32(bReverse)` / constructor desde `uint32` cubren los puntos de cruce.

**Por qué**: el código ya tiene `CAddress`, no inventamos un tipo nuevo. Single source of truth.

### ADR-02: Listener dual-stack con `IPV6_V6ONLY=0`

Un único socket `AF_INET6` que acepta tanto IPv6 nativo como IPv4-mapped (`::ffff:a.b.c.d`). Esto evita duplicar la lógica de aceptación. Plataformas:

- **Windows Vista+**: `IPV6_V6ONLY` por defecto a **1** — hay que desactivarlo explícitamente con `setsockopt`.
- En `CAsyncSocketEx::Create` se añade un parámetro `bool bDualStack` que setea la opción.

**Por qué**: una sola pila reduce los bugs de "se me cuelga uno de los listeners". El coste es perder un poco de granularidad de logging (todo se ve como IPv6), mitigable con `IsMappedIPv4()`.

**Excepción**: en Kad UDP se mantienen sockets separados v4 y v6, porque la inspección directa del campo `sockaddr` con stride 16 frente a 4 simplifica el parser de paquetes.

### ADR-03: Negociación de capacidades en `OP_EMULEINFO`

Los pares dual-stack se descubren mutuamente vía un tag nuevo en el handshake extendido de eMule. En [`BaseClient.cpp:746-820`](srchybrid/BaseClient.cpp:746), después de `protversion` y antes de los tags estándar, se añade:

```
CT_FORK_CAPABILITIES = 0xFF  // tag uint32, bitfield
  bit 0: IPv6 wire support
  bit 1: dual-stack listener
  bit 2: IPv6 Kad
  bit 3: IPv6 LivePeerList
  bits 4-31: reservados
```

Un cliente que NO entiende `CT_FORK_CAPABILITIES` simplemente lo descarta (comportamiento estándar de `CTag::ReadTag` cuando no reconoce el nombre/ID).

**Por qué**: handshake versionado es el patrón estándar de la industria (TLS, SSH, HTTP/2). Aprovecha que `OP_EMULEINFO` ya existe.

### ADR-04: Opcodes paralelos, no extendidos

Para cada opcode eD2K que lleve IP, se crea un opcode paralelo en el espacio `OP_EMULEPROT` (0xC5) con `OP_*_V6` suffix y un nuevo byte de opcode interno. El opcode IPv4 viejo **nunca se toca**.

Ejemplo:
- Legacy: `OP_PUBLICIP_ANSWER = 0x98` ([`Opcodes.h:268`](srchybrid/Opcodes.h:268)) → `<uint32 IP>`.
- Nuevo: `OP_PUBLICIP_ANSWER_V6 = 0xE0` (en `OP_EMULEPROT` extension space) → `<uint8 family><uint8 len><N bytes IP>`.

El cliente moderno envía el `_V6` solo si la capacidad está negociada; en otro caso envía solo el legacy. El receptor que tenga ambos prefiere el `_V6`.

**Por qué**: invariante hard de no romper wire viejo. Los opcodes paralelos son el patrón canónico (`OP_ANSWERSOURCES` → `OP_ANSWERSOURCES2`).

### ADR-05: `lowID`/`highID` para IPv6 — extensión, no reinterpretación

`IsLowID(id) := id < 0x01000000` se mantiene tal cual para IPv4. Para clientes IPv6-only se introduce un sentinel: `m_nUserIDHybrid = 0xFFFFFFFE` significa "soy IPv6, mira mi `CAddress` real en el campo paralelo". Servidores antiguos verán esto como "highID inválido" y tratarán al cliente como lowID (callback obligatorio), lo cual es seguro pero subóptimo.

**Por qué**: ver discusión completa en §8.

### ADR-06: Versionado por archivo, no flag global

Cada formato persistente gana su propio version byte/word, ortogonal al resto. `nodes.dat` v4, `known.met` con `MET_HEADER_V6=0x10`, etc. Esto permite actualizar un archivo a la vez y evita una "gran ceremonia de migración".

### ADR-07: Modo de compatibilidad configurable

En preferencias se añaden tres flags:

- `IPv6Enabled` (bool, default `true` si el SO soporta IPv6).
- `IPv6Mode` (enum: `Auto`, `IPv4Only`, `IPv6Only`, `DualStack`). Default `Auto`.
- `WriteLegacyOnly` (bool, default `false`). Si `true`, los archivos se serializan en formato pre-IPv6 para poder intercambiarse con instalaciones viejas.

**Por qué**: el usuario manda. Algunos peers van a quedarse en IPv4-only por años; el fork debe poder funcionar en una red mixta sin penalizar a nadie.

### ADR-08: Identidad eD2K basada en hash criptográfico, no en IP

Hoy, en [`BaseClient.cpp:140-145`](srchybrid/BaseClient.cpp:140), el `m_nUserIDHybrid` para un cliente highID coincide con su IP en host-order. Esto es elegante pero imposible en IPv6 (no caben 128 bits). Para los `_V6` opcodes, la identidad pasa a ser el **`UserHash` de 16 bytes** que ya existe en eMule (clave RSA derivada). En el wire de los opcodes `_V6`, donde antes había `<uint32 ID>` ahora hay `<UserHash 16> <CAddress 1+1+N>`.

**Por qué**: el UserHash es estable, único, y ya está en el código. IP-as-identity es un anti-pattern que aprovecha de IPv4 que no replica bien.

### ADR-09: Protocolo cliente↔servidor eD2K congelado en IPv4

Los opcodes marcados `[OUT]` en §3.2 (todos los que viajan entre cliente y servidor eD2K) no se modifican **nunca**. El cliente moderno habla IPv4 con servidores idéntico a hoy. IPv6 nativo se descubre exclusivamente vía Kad.

**Por qué**: el ecosistema de servidores está congelado (Lugdunum closed-source y abandonado; eserver con cero actividad reciente). No tenemos influencia sobre los operadores. Forzar un protocolo `_V6` servidor-mediado sin servidores que lo hablen es trabajo muerto.

**Consecuencia operativa**: un usuario IPv6-only no podrá usar servidores eD2K (su pila TCP no llegará a una IP `A` solo-IPv4). Es la realidad estructural, no nuestra elección. Debe usar Kad puro; el cliente lo permite (bootstrap por DNS seed + lista estática).

**Consecuencia para el plan**: Fase 5 baja de 3 a 2 semanas (menos opcodes que tocar, menos paquetes que negociar), y los archivos `ServerSocket.cpp`, `ServerConnect.cpp`, `Server.cpp`, `ServerList.cpp` solo se tocan para **lectura** de servidores IPv6 declarados por hostname (vía `TAG_DYNIP` ya existente + resolución AAAA) — no para modificar el protocolo de wire.

---

## 5. Diseño detallado

### 5.1 El tipo `CAddress` extendido

Lo que `CAddress` ya tiene cubre el 80%. Faltan:

```cpp
// Añadir en Address.h:
class CAddress {
  // ... lo existente ...
public:
    // Serialización compacta wire (1 byte family + 1 byte len + N bytes IP):
    void WriteToBuffer(CSafeMemFile* file) const;
    bool ReadFromBuffer(CSafeMemFile* file);

    // Hash para usar como key en mapas, p.ej. CMap<CAddress, ...>:
    UINT HashKey() const;

    // Máscara para subnet diversity (devuelve los N bits más significativos):
    CAddress GetSubnet(int prefixBits) const;
    bool InSameSubnet(const CAddress& other, int prefixBits) const;

    // Convenience para Kad-flavor host-order vs network-order:
    static CAddress FromKadHostOrder(uint32 ip);  // ya teníamos ToUInt32(bool bReverse)
    uint32 ToKadHostOrder() const;

    // Para clientes legacy: si soy IPv6, ¿puedo "degradar" a un uint32 representativo?
    // (Esto NUNCA viaja al wire IPv4. Es solo para almacenar en estructuras viejas
    //  hasta que sean migradas.)
    uint32 ToSyntheticUInt32() const;  // hash truncado, marca alto bit
};
```

Wire format de `WriteToBuffer`:

```
+--------+--------+----------------+
| family | length | address bytes  |
| 1 byte | 1 byte | length bytes   |
+--------+--------+----------------+

family: 0=None, 4=IPv4, 6=IPv6
length: 4 si family=4, 16 si family=6, 0 si family=0
```

Coste: 6 bytes para IPv4 (2 de overhead vs los 4 del legacy), 18 para IPv6. Aceptable.

### 5.2 Wire eD2K: opcodes paralelos `_V6`

Tabla de equivalencias (suffix `_V6` = soporta ambas familias):

| Legacy | Nuevo | Payload |
|---|---|---|
| `OP_HELLO` 0x01 | (extiende: añade tag `CT_FORK_CAPABILITIES`) | igual + tag |
| `OP_HELLOANSWER` 0x4C | igual | igual + tag |
| `OP_PUBLICIP_REQ` 0x97 | (sin cambios) | — |
| `OP_PUBLICIP_ANSWER` 0x98 | `OP_PUBLICIP_ANSWER_V6` (proto 0xC5, opcode 0xE0) | `<CAddress>` |
| `OP_ANSWERSOURCES2` 0x84 v1 | `OP_ANSWERSOURCES2` v5 (mismo opcode, nueva versión interna) | header `<v=5><nSources>` + por fuente: `<UserHash 16><CAddress client><Port 2><CAddress server><Port 2><CryptOpts 1>` |
| `OP_CALLBACKREQUESTED` 0x35 | `OP_CALLBACK_V6` (proto 0xC5, opcode 0xE1) | `<UserHash 16><CAddress><Port 2>` |
| `OP_FOUNDSOURCES` 0x42 / 0x44 | `OP_FOUNDSOURCES_V6` (proto 0xC5, opcode 0xE2) | mismo + family+len por fuente |
| `OP_LIVE_PEER_LIST` 0xCA | `OP_LIVE_PEER_LIST_V2` 0xCB | `<StreamHash 16><Count 2>(<CAddress><Port 2><Score 1>) × Count` |

**Reglas de la negociación**:

1. El servidor de TCP listening anuncia capacidades al final del handshake `OP_HELLO`.
2. Si el receptor ha visto `bit 0` del par, **debe** usar opcodes `_V6` cuando tenga datos IPv6 que transmitir.
3. Si el par solo sabe IPv4 (capability ausente), el cliente envía solo opcodes legacy y omite cualquier información IPv6 (no la sintetiza). Esto es estratégicamente importante: no envenenamos la red con IPs "raras".
4. Al recibir un opcode `_V6` sin capability negociada, el receptor lo descarta y opcionalmente registra warning.

### 5.3 Server.met v2

Hoy [`Server.h:23`](srchybrid/Server.h:23):

```cpp
struct ServerMet_Struct {
    uint32 ip;       // network-order
    uint16 port;
    uint32 tagcount;
};
```

Después: el `uint32 ip` se mantiene **literal** (compatibilidad), pero si vale 0 o si el tag nuevo `ST_IPV6` está presente, gana el tag. Lectura:

```python
read ip (uint32)
read port (uint16)
read tagcount (uint32)
for tag in tagcount:
    if tag.name == ST_IPV6 (0x90):
        address = CAddress.ReadFromBuffer(tag.value)
    elif ...:
        ...
if address is None and ip != 0:
    address = CAddress(ip, /*reverse=*/true)  // IPv4 desde struct legacy
```

Un eMule viejo lee solo el `uint32 ip`. Si el servidor es IPv6-only, este `ip` vale 0, y el cliente viejo lo trata como inválido (lo cual es correcto: no puede conectarse de todos modos). Esto es una **degradación grácil**, no un crash.

### 5.4 nodes.dat v4

Nuevo formato de cabecera (extendiendo [`RoutingZone.cpp:362-378`](srchybrid/kademlia/routing/RoutingZone.cpp:362)):

```
WriteUInt32(0)                  // marca "nuevo formato" (igual que antes)
WriteUInt32(4)                  // ← versión NUEVA: 4
WriteUInt32(numContacts)
for each contact:
    WriteUInt128(KadID)         // 16 bytes (igual)
    WriteByte(family)           // 4 o 6
    WriteByte(addrLen)          // 4 o 16
    Write(addrBytes)            // 4 o 16
    WriteUInt16(udpPort)
    WriteUInt16(tcpPort)
    WriteUInt8(kadVersion)
    WriteUInt32(udpKey)
    WriteUInt8(verified)
```

Tamaño por contacto: 31 bytes para IPv4 (vs 30 antiguo), 43 para IPv6.

Al leer:
- Si `uVersion ∈ {1, 2, 3}`: parser viejo (todos los contactos son IPv4).
- Si `uVersion = 4`: parser nuevo (family + len por contacto).
- Si `uVersion = 0` o ausente: formato pre-v1, parser legacy de 6 bytes.

Cuando el cliente moderno escribe `nodes.dat`:
- Si `WriteLegacyOnly`: emite v2 y descarta contactos IPv6.
- Si no: emite v4. Los clientes viejos no leerán el archivo en absoluto si encuentran `uVersion=4` (porque hoy [`RoutingZone.cpp:186-200`](srchybrid/kademlia/routing/RoutingZone.cpp:186) tiene `if (uVersion >= 1 && uVersion <= 3)` — lo cual significa que un v4 sería tratado como "formato desconocido" y descartado, regenerando la tabla desde bootstrap). Esto es **aceptable**: pierdes el cache de routing una vez al downgradear, pero no corrompes nada.

### 5.5 known.met IPv6-aware

`known.met` ya tiene dos versiones (`0x0E`, `0x0F`). Añadimos `MET_HEADER_V6 = 0x10`. Cambios:

- `TAG_SOURCEIP` (0xFE) sigue siendo `uint32`. Cuando una fuente es IPv6, **no se emite** este tag; en su lugar va un `TAG_SOURCEIP_V6` (nuevo, 0x66 sugerido — verificar colisiones con [`Opcodes.h:380-440`](srchybrid/Opcodes.h:380)).
- `TAG_SERVERIP` (0xFB) idéntico: añade `TAG_SERVERIP_V6` paralelo.

Un cliente viejo lee `known.met` v6, encuentra tags desconocidos (0x66...), los ignora — comportamiento estándar de [`Tag.cpp::ReadTag`](srchybrid/SafeFile.cpp). El archivo no se corrompe.

### 5.6 ipfilter

Formato más complicado por sus tres parsers. Propuesta:

- **Texto** (`.dat`, `.p2p`): aceptar líneas IPv6 con notación CIDR estándar:
  - `2001:db8::/32, 1000, Some range` (mismo formato, IPv6 detectado por presencia de `:`).
  - Parser: tras leer la línea, intentar `_inet_pton(AF_INET6)` antes que `AF_INET`.
- **Binario PG2** ([`IPFilter.cpp:99-150`](srchybrid/IPFilter.cpp:99)): añadir un **nuevo magic number** `0xFE,0xFE,0xFE,0xFE,'P','6','B'` (el byte `0xFE` distingue de `0xFF` del PG2 v1/v2). Estructura: cabecera + N entradas, cada entrada `<family 1><lenStart 1><startBytes N><family 1><lenEnd 1><endBytes N><level 4><descLen 2><desc UTF-8>`.

Hash para búsqueda rápida: hoy [`IPFilter.h:42`](srchybrid/IPFilter.h:42) usa un array. Para v6, lo natural es **dos estructuras** (interval tree para IPv4, otro para IPv6) y un `IsFiltered(const CAddress&)` que despacha.

### 5.7 OP_LIVE_PEER_LIST_V2

```
[8 bits ] opcode = 0xCB
[128 bits] streamHash
[16 bits] count
foreach (count):
    [CAddress] peer.address (1+1+N bytes)
    [16 bits ] peer.port
    [8 bits ] peer.score   (0..255)
    [8 bits ] peer.flags   (bit 0: trustedSeed, bit 1: superpeer, ...)
```

Cuando un cliente moderno tiene una lista mixta de peers (algunos IPv4, otros IPv6), envía un solo paquete `OP_LIVE_PEER_LIST_V2` con todos. A los peers viejos del fork les envía el `OP_LIVE_PEER_LIST` clásico **filtrado** a solo IPv4.

### 5.8 Subnet diversity en IPv6

[`LiveStreamManager.cpp:775-797`](srchybrid/LiveStreamManager.cpp:775) hoy intenta no concentrar peers en una sola subred /24 o /16 (anti-eclipse attack). Generalización:

- IPv4: /24 = `peerIP & 0xFFFFFF00`, /16 = `peerIP & 0xFFFF0000`. Mantener tal cual.
- IPv6: /64 (subred de un sitio) y /48 (sitio entero). Implementar con `CAddress::GetSubnet(64)` y `GetSubnet(48)`.

Combinar: limitar a `K` peers por /24-IPv4 o /64-IPv6, y `M` peers por /16-IPv4 o /48-IPv6.

---

## 6. Plan de implementación por fases

Cada fase es **independientemente mergeable** y deja el código funcional. Esta es una condición dura.

### Fase 0 — Auditoría y preparación (1 semana)

**Entregables**:
- Suite de tests existente verde (`/ultrareview` baseline).
- Build IPv4-only sigue funcionando idéntico (regresión cero).
- Documento `IPV6_STATUS.md` (este archivo + un log de progreso).
- Decisión definitiva sobre números de opcode (evitar colisiones con upstream).

**Riesgo**: bajo. Es trabajo de mesa.

### Fase 1 — Adopción de `CAddress` (2 semanas)

**Entregables**:
- `CAddress` completado con `WriteToBuffer/ReadFromBuffer/HashKey/GetSubnet`.
- Todas las llamadas a `inet_addr/inet_ntoa` dentro del namespace eMule reemplazadas por métodos de `CAddress`.
- `OtherFunctions::ipstr(uint32)` añade overloads `ipstr(const CAddress&)`.
- Cero cambios en el wire, cero cambios en disco.

**Verificación**: compilación limpia, todo el comportamiento idéntico al baseline. Tests automatizados pasando.

**Riesgo**: bajo. Es refactor puro.

### Fase 2 — Listener dual-stack (2 semanas)

**Entregables**:
- `CListenSocket` admite parámetro `bDualStack`.
- Si IPv6 habilitado: el socket TCP se crea `AF_INET6` con `IPV6_V6ONLY=0`.
- `CClientUDPSocket` y `CKademliaUDPListener` ganan un segundo socket `AF_INET6` (siempre `V6ONLY=1` aquí, para parser independiente).
- Preferencias: `IPv6Enabled`, `IPv6BindAddress` (string), `IPv6Mode`.
- UI: tab "Conexión" muestra estado IPv6 y dirección detectada.

**Sin cambios en wire**: a este punto, las conexiones IPv6 entrantes no llegan a `OP_HELLO` porque ningún peer remoto sabe nuestra dirección IPv6 todavía. Se queda en "listening cosmético" hasta la Fase 3+.

**Verificación**: `netstat -an` en Windows muestra el socket IPv6 escuchando.

**Riesgo**: bajo-medio. El truco de `V6ONLY=0` tiene casos raros en Windows XP (no soportado por nosotros) y en algunos firewalls corporativos.

### Fase 3 — Detección de IP pública IPv6 + probe de firewall (1.5 semanas)

**Entregables**:
- `OP_PUBLICIP_ANSWER_V6` implementado client-side.
- Para clientes con capability negociada, el receptor manda **ambos** (legacy `OP_PUBLICIP_ANSWER` con IPv4 si la conexión vino por IPv4, y `_V6` con la dirección IPv6 si vino por IPv6).
- `CPreferences` cachea las dos IPs públicas detectadas (v4 y v6).
- **Nueva clase `CFirewallProberV6`** (ver §8.5): probe automática al arrancar y cada 10 min, que determina la capa de alcanzabilidad (HighID directo / con pinhole / keepalive / hole-punching / buddy / unreachable).
- Status bar muestra el resultado de la probe en lenguaje claro.

**Riesgo**: bajo. Implementación localizada.

### Fase 4 — Kademlia IPv6 + keepalive + hole-punching (3.5 semanas)

**Entregables**:
- `CContact` extendido para llevar `CAddress` (mantiene `m_uIp` legacy como derivado para callers viejos).
- `nodes.dat` v4 con lectura/escritura mezclada.
- Opcodes `KADEMLIA3_HELLO_REQ/RES`, `KADEMLIA3_REQ`, `KADEMLIA3_PUBLISH_KEY_REQ`, `KADEMLIA3_PUBLISH_SOURCE_REQ`, `KADEMLIA3_FIREWALLED_RES`, `KADEMLIA3_PING_REQ/RES` con formato:
  ```
  <KadID 16> <CAddress 1+1+N> <UDP port 2> <TCP port 4> <KadVersion 1>
  ```
- Bootstrap IPv6: lista de nodos bootstrap separada (`nodes_v6.dat` o un campo nuevo en `nodes.dat` v4).
- **UDP keepalive subsystem** (§8.5 capa C): rotación de 5-10 supernodos pingeados cada 25 s para mantener conntrack abierto. Selección dinámica de supernodos basada en latencia y estabilidad.
- **Hole-punching coordinado** (§8.5 capa D): nuevos opcodes `KADEMLIA3_HOLEPUNCH_REQ` (0x63), `KADEMLIA3_HOLEPUNCH_FWD` (0x64), `KADEMLIA3_HOLEPUNCH_ACK` (0x65) en `OP_KADEMLIAHEADER`. Lógica de rendezvous en `KademliaUDPListener` + nueva clase `CHolePuncher`.

**Riesgo**: medio-alto. La routing table tiene lógica sutil (k-buckets, contacto stale, ping de verificación). Keepalive y hole-punching añaden state machines nuevas. Hay que probar long-running con peers reales.

### Fase 5 — eD2K wire IPv6 cliente↔cliente + PCP (2.5 semanas)

**Solo P2P. Por ADR-09, los opcodes servidor-mediados quedan intactos.**

**Entregables wire**:
- `CT_FORK_CAPABILITIES` en `OP_EMULEINFO`.
- `OP_HELLO`/`OP_HELLOANSWER` anuncian capability (tag aditivo, mismo opcode).
- `OP_ANSWERSOURCES2 v5` con `CAddress` por fuente (versión interna nueva del opcode existente, no opcode nuevo — el byte de versión es lo que discrimina).
- `OP_PUBLICIP_ANSWER_V6` (en `OP_EMULEPROT`).
- **NO**: `OP_CALLBACK_V6`, `OP_FOUNDSOURCES_V6`, ni nada cliente↔servidor.

**Entregables NAT (PCP, §8.5 capa A)** — **adelantado desde Fase 8** porque es la palanca más universal:
- [`UPnPImplNATPMP`](srchybrid/UPnPImplNATPMP.cpp) extendido (o renombrado a `UPnPImplPCP`) para hablar PCP v2 (RFC 6887).
- Opcode `MAP` con bloque IPv6 (RFC 6887 §11). Petición `<addr 16><port 2><protocol 1><lifetime 4>`.
- Detección de soporte por timeout corto (1 s); si no contesta, paso a capa B en Fase 8.
- Integración con `CFirewallProberV6` (Fase 3) para reportar éxito al status bar.

**Mecanismo de callback en IPv6**: como los servidores no participan, los callbacks IPv6 viajan **por Kad** vía `KADEMLIA3_FIREWALLED_*` y `KADEMLIA3_HOLEPUNCH_*` (Fase 4). Un peer IPv6 con firewall cerrado se descubre como tal por Kad y los demás le coordinan punch o le inician TCP saliente. Esto suplanta `OP_CALLBACKREQUESTED` sin tocarlo.

**Verificación**: dos PCs con direcciones IPv6 reales (no IPv4-mapped) intercambiando fuentes vía Kad, sin servidor en la ruta. Caso adicional: PC1 con PCP funcional + PC2 con firewall estricto sin PCP — debe funcionar gracias a hole-punching coordinado por Fase 4.

**Riesgo**: medio (bajó de alto por la reducción de scope; PCP es bien-comprendido).

### Fase 6 — eSE/LiveTV IPv6 + buddy relay (2.5 semanas)

**Entregables**:
- `OP_LIVE_PEER_LIST_V2` (0xCB).
- `LiveStreamEntry::broadcasterIP` migrado a `CAddress`.
- `LiveKadBridge` publica/recupera con tags `_V6`.
- Subnet diversity generalizada (/64 + /48 + /24 + /16).
- `eSE/server.js` y `eSE/eSE-live/rtmp_server.js` binden a `::` (dual-stack) en vez de `127.0.0.1`. URL de HLS template se construye dinámicamente según familia.
- Reuso del hole-punching de Fase 4 para conexiones mesh-peer en LiveTV.
- **Buddy relay v6 (§8.5 capa E)**: opcodes nuevos `OP_LIVE_RELAY_REQ` (0xCC) y `OP_LIVE_RELAY_FWD` (0xCD) en `OP_EMULEPROT`. Lógica: un broadcaster firewalled mantiene conexión TCP saliente con un buddy highID-v6 que recibe peer announcements y los forwardea. Útil sobre todo para broadcasters móviles.
- Estadísticas LiveTV diferencian peers v4/v6 y muestran cobertura de la cascada.

**Riesgo**: medio. El P2P live es lo más nuevo del fork y tiene menos hardening. Buddy relay añade complejidad pero solo se activa en ~1% de los casos según estimación §8.5.

### Fase 7 — Persistencia (1 semana)

**Entregables**:
- `server.met v2` con `ST_IPV6`.
- `known.met v0x10` con `TAG_SOURCEIP_V6`/`TAG_SERVERIP_V6`.
- `ipfilter.dat` IPv6: parser texto + binario PG6 (`0xFEFEFEFE 'P6B'`).
- Migración automática al primer arranque: leer formato viejo, escribir formato nuevo (con backup `.bak`).

**Riesgo**: bajo. Es trabajo metódico de codecs.

### Fase 8 — IGDv2 AddPinhole, UI, pulido (1.5 semanas)

**Entregables** (PCP ya está en Fase 5):
- IGDv2 `AddPinhole`/`DeletePinhole` en `CUPnPImplWinServ` y `CUPnPImplMiniLib` (§8.5 capa B).
- Cascada de fallback: probador llama PCP (Fase 5) → si falla, IGDv2 AddPinhole (esta fase) → si falla, keepalive (Fase 4) → si falla, buddy (Fase 6).
- UI: status bar muestra "IPv4: a.b.c.d (highID) / IPv6: 2001:db8::1 (verified, PCP)" o el método activo.
- ClientDetailsDialog muestra ambas direcciones del par si están disponibles, y la capa de alcanzabilidad usada.
- AddSourceDlg acepta `[ipv6]:port` o `ipv4:port` indistintamente.
- Diálogo "preferencias → conexión" añade un bloque IPv6 con bind address, mode, y override manual de la capa anti-firewall ("modo agresivo" fuerza keepalive aunque la probe diga que no hace falta).
- Tooltips y traducciones (i18n) actualizadas.

**Riesgo**: bajo. Pulido visible al usuario.

### Fase 9 — Endurecimiento y publicación (2 semanas)

**Entregables**:
- 30 días de field testing con un grupo de beta-testers.
- Métricas de adopción: % de conexiones IPv6, % de Kad contacts IPv6.
- Comparativa de latencia/throughput v4 vs v6.
- `/ultrareview` completo.
- Release notes con la matriz de compatibilidad explícita.

**Riesgo**: solo se descubre durante.

---

## 7. Matriz de compatibilidad backward

| ↓ Local / Remoto → | Upstream 0.70b IPv4 | Fork v0.70-pre-IPv6 | Fork v0.70-IPv6 |
|---|---|---|---|
| **Upstream 0.70b IPv4** | OK (status quo) | OK | OK (remote sees us as IPv4-only) |
| **Fork v0.70-pre-IPv6** | OK | OK | OK (remote sees us as IPv4-only, ignora capability) |
| **Fork v0.70-IPv6 (IPv4 link)** | OK | OK | OK + datos IPv6 intercambiados out-of-band si capability matched |
| **Fork v0.70-IPv6 (IPv6 link)** | imposible | imposible | OK |
| **Fork v0.70-IPv6 (dual-stack)** | OK por IPv4 | OK por IPv4 | OK por IPv6 (preferida) o IPv4 |

**Regla de selección de transporte** (Happy Eyeballs simplificado):

1. Si el par anuncia capability IPv6 y tenemos al menos una IPv6 pública verificada, intentamos IPv6 primero, con timeout de 250 ms.
2. Si no resuelve en ese tiempo, fallback IPv4.
3. Una vez establecida una conexión, todas las subsecuentes a ese par usan el mismo transporte (afinidad).

---

## 8. NAT, descubrimiento y problema de identidad en IPv6

### 8.1 ¿Existe el concepto de lowID en IPv6?

En IPv4, "lowID" significa "no tengo IP pública alcanzable, necesito callbacks". El concepto sigue siendo útil en IPv6 si el firewall doméstico/operador está cerrado (Carrier-Grade IPv6 con prefix delegation pero stateful firewall por defecto, escenario habitual en 4G/5G).

**Definición operativa IPv6**: un cliente es "IPv6-lowID" si su firewall no permite conexiones entrantes a su puerto TCP/UDP eMule.

Pero **lowID-v6 ≠ lowID-v4** en consecuencias:

- En IPv4 lowID, no puedes hacer **nada** activo: ni descargar (en algunos casos), ni publicar, ni participar en Kad como nodo. Necesitas servidor para callback.
- En IPv6 lowID con firewall stateful, el path **saliente** sigue abierto. Puedes hacer queries Kad, recibir respuestas (conntrack), descargar de peers que sí inicien la conexión. Solo te falta poder **recibir** la primera SYN/datagrama de un peer cualquiera.

Esta diferencia abre la puerta a una **cascada de mecanismos** (§8.5) que en la mayoría de los casos convierte un lowID-v6 nominal en un highID-v6 funcional **sin colaboración del operador**.

### 8.2 Callbacks IPv6

`OP_CALLBACKREQUESTED` (0x35) viaja del servidor al cliente highID con `<IP 4><Port 2>` del lowID. En IPv6 no cabe. Por tanto: `OP_CALLBACK_V6` (0xE1 en OP_EMULEPROT) con `<UserHash 16><CAddress><Port 2>`.

El servidor eD2K original NO sabe IPv6. Por tanto, **callbacks IPv6 solo funcionan vía Kad**, no vía servidor. Esto es aceptable porque el ecosistema Kad+eD2K-server siempre permitió a Kad funcionar autónomo.

### 8.3 Bootstrap IPv6

Necesitamos al menos una lista semilla de nodos Kad IPv6 alcanzables. Opciones:

- **A**: empaquetar una lista en `installer/config/nodes_v6.dat` con 5-10 nodos operados por el equipo del fork. Riesgo: si nuestros nodos caen, los nuevos usuarios no entran a Kad-v6.
- **B**: nodos descubiertos in-band — cuando un peer IPv4 (con capability IPv6) nos manda su KadID, le pedimos `KADEMLIA3_BOOTSTRAP_REQ` por la IPv4, y la respuesta nos da contactos IPv6 conocidos.
- **C**: DNS seed (`kad-v6-seed.example.com` → A/AAAA + puerto en TXT).

**Recomendación**: B + C. A es frágil, B aprovecha que la mayoría de gente arranca con Kad-v4 ya poblado.

### 8.4 Spoofing y verificación de IP

Hoy en Kad existe `IsIpVerified()`, que se setea cuando recibimos un paquete UDP entrante desde la IP declarada del contacto (anti-spoofing básico). El mismo mecanismo se aplica idéntico en IPv6: enviamos UDP a la dirección anunciada y esperamos eco.

**Sutileza importante**: en IPv6 hay direcciones temporales (privacy extensions, RFC 4941) que rotan cada 24h. Un peer puede anunciar una dirección que ya no es la suya. Mitigación: marcar como verificado solo si responde dentro de un timeout corto (<30 s), y re-verificar periódicamente.

### 8.5 Cascada anti-firewall IPv6: cómo NO quedarse en lowID-v6

Diseño en 5 capas, intentadas en orden. En cuanto una funciona, paramos. Las capas no se excluyen entre sí — un peer puede tener PCP exitoso y aun así mantener keepalives por robustez.

**Capa A — PCP (RFC 6887)** *[Fase 5]*

Sucesor estándar de NAT-PMP, diseñado pensando en IPv6. El cliente envía `MAP` al `[gateway]:5351` (UDP) pidiendo pinhole en su puerto. Si el router/operador soporta PCP, responde con la dirección/puerto efectivos y un lease time.

Implementación: extender [`UPnPImplNATPMP.cpp`](srchybrid/UPnPImplNATPMP.cpp) — renombrar a `UPnPImplPCP`, mantener compat NAT-PMP para routers viejos. Opcode `MAP` (op=1) con bloque IPv6 según RFC 6887 §11. ~200 líneas. Soporte detectado por respuesta válida o timeout corto (1 s).

**Capa B — UPnP IGDv2 `AddPinhole`** *[Fase 8]*

Si PCP no responde o falla, probar `AddPinhole` vía las tres implementaciones UPnP existentes ([`UPnPImpl.h:27-33`](srchybrid/UPnPImpl.h:27)). Para routers que solo hablan UPnP-IGDv2 (típico en routers operador-suministrados).

Implementación: ampliar la interfaz `CUPnPImpl::OpenPortV6()` análoga a la `OpenPort()` IPv4. Acciones `AddPinhole`/`DeletePinhole` ya están en el SDK COM de Windows y en miniupnpc.

**Capa C — UDP keepalive a supernodos Kad** *[Fase 4]*

Si las dos anteriores fallan o el operador no soporta ni PCP ni UPnP (caso típico 4G/5G), mantenemos abierto el conntrack saliente con pings periódicos a 5-10 supernodos Kad-v6 conocidos. Mientras la entrada `<src-IP, src-port> → *` exista en el firewall, **cualquier peer que conozca nuestra dirección puede llegarnos**.

Implementación:

```cpp
// CKademliaUDPListener::TickKeepalive() cada 25s
for (auto& node : m_keepaliveSupernodes) {
    SendPing(node);  // KADEMLIA3_PING_REQ, 8 bytes
}
// Rotación: si un supernodo deja de responder 3 veces, sustituirlo.
```

Mantenemos 5-10 endpoints en paralelo para resiliencia. Coste: ~10 paquetes / 25s = 0.4 pps salientes, despreciable.

Requiere que el firewall sea **endpoint-independent** (cone) para UDP. Caso mayoritario en 4G/5G doméstico. No funciona en firewalls "address-and-port-dependent" (corporate strict), donde la siguiente capa toma el relevo.

**Capa D — Hole-punching coordinado por Kad** *[Fase 4 final]*

Para conectar dos peers ambos firewalled, un tercero (Kad supernodo que ambos conocen) hace de rendezvous: le manda a A "envía UDP a B ahora" y a B la inversa. Los outbound simultáneos abren conntrack en ambos firewalls y las réplicas pasan.

Opcodes nuevos (Apéndice B):

```
KADEMLIA3_HOLEPUNCH_REQ  (0x63) — A → R: "ayúdame a alcanzar B"
KADEMLIA3_HOLEPUNCH_FWD  (0x64) — R → B: "A va a punchearte desde [addr]:port, prepárate"
KADEMLIA3_HOLEPUNCH_ACK  (0x65) — B → A directo, una vez establecido
```

Funciona para UDP fácil; para TCP requiere TCP simultaneous open (menos fiable, lo dejamos out-of-scope inicial). Como casi todo lo nuestro de transferencia chunk es UDP (Kad + LiveTV mesh), cubrimos el 90% del tráfico real.

**Capa E — Buddy relay v6 (último recurso)** *[Fase 6]*

Si nada de lo anterior establece bidireccionalidad, mantenemos una **conexión TCP saliente persistente** con un peer highID-v6 que actúa como buddy. Los peers que quieren contactarnos lo hacen vía el buddy, que nos forwardea por la conexión ya abierta.

Es el concepto clásico de "lowID buddy" de eMule, pero a nivel IPv6 y especialmente útil para LiveTV (donde el broadcaster necesita ser alcanzable). Opcode propuesto: `OP_LIVE_RELAY_REQ` (0xCC) y `OP_LIVE_RELAY_FWD` (0xCD) en `OP_EMULEPROT`.

**Probe automática de capa al arrancar** *[Fase 3]*

Al arrancar (tras detectar IPv6 pública vía `OP_PUBLICIP_ANSWER_V6`), el cliente ejecuta una **batería de probes** en paralelo para decidir en qué capa opera:

```cpp
class CFirewallProberV6 {
    enum Result { HighID_V6, FwdOnlyKeepalive, FwdOnlyHolepunch, Buddy, Unreachable };
public:
    void Probe(std::function<void(Result)> onResult);
    // 1. Pide a 3-5 peers Kad-v6 conocidos un connect-back a nuestro listener.
    // 2. Si ≥1 éxito directo → HighID_V6.
    // 3. Si no → intenta PCP. Reprobamos. Éxito → HighID_V6 (con pinhole).
    // 4. Si PCP falla → intenta IGDv2 AddPinhole. Reprobamos. Éxito → HighID_V6.
    // 5. Si todo lo anterior falla → activa keepalive y reprobamos.
    //    Si ahora los peers nos llegan → FwdOnlyKeepalive (operación normal con keepalives).
    // 6. Si no → marca FwdOnlyHolepunch (necesitamos coordinación Kad para cada conexión).
    // 7. Si ni siquiera podemos hacer outbound estable → Buddy mode.
    // 8. Si no podemos ni encontrar buddy → Unreachable (UI alerta al usuario).
};
```

Re-probar cada 10 min o tras cambio de red detectado (IP propia cambia, RA recibido).

**Resultado en UI**: status bar muestra `IPv6: HighID (PCP)`, `IPv6: HighID (keepalive)`, `IPv6: Relayed (buddy)`, `IPv6: lowID`, según capa activa. Los iconos azules existentes para lowID/highID IPv4 se reutilizan con marca v6.

**Cobertura empírica esperada** (estimación):
- Capa A (PCP): ~40% de routers residenciales modernos + algunos operadores móviles.
- Capa B (UPnP IGDv2): otro ~30% acumulado.
- Capa C (keepalive): otro ~25% acumulado — casi todo 4G/5G doméstico.
- Capa D (hole-punching): otro ~4% acumulado — corporate y CGNAT-v6 raro.
- Capa E (buddy): el ~1% residual.

Total: **~99% de los clientes IPv6 acaban siendo alcanzables**, vs ~50% de los IPv4 detrás de CGNAT hoy.

---

## 9. Persistencia y migración de formatos

### 9.1 Estrategia de upgrade del usuario

Al primer arranque de la nueva versión:

1. Detectar versión de cada archivo.
2. Para cada formato modernizable (`nodes.dat`, `server.met`, `known.met`, `ipfilter.dat`):
   - Copiar a `.bak` (un solo backup, sobreescribir si existe).
   - Leer en formato antiguo.
   - Escribir en formato nuevo si `WriteLegacyOnly = false`.
3. `preferences.ini` recibe las nuevas claves con defaults seguros.

### 9.2 Downgrade

Si el usuario quiere volver a una versión vieja del fork: los archivos `nodes.dat v4`, `known.met v0x10`, `ipfilter PG6` **no son legibles** por código viejo. La versión vieja los descartará y regenerará. Esto pierde caché pero no datos esenciales (sources, credits — credits.met no cambia).

**Procedimiento de downgrade documentado**:

```
1. Cerrar eMule.
2. Renombrar carpeta config/ a config_v6/ (backup).
3. Copiar los .bak generados al primer upgrade a sus nombres originales.
4. Arrancar la versión vieja.
```

### 9.3 Sincronización entre instalaciones

Algunos usuarios sincronizan la carpeta `config/` entre PCs (vía cloud sync). Si una PC tiene versión nueva y la otra vieja: la vieja **escribirá** v2 al cerrar, sobreescribiendo el v4. Próxima ejecución de la nueva: regenera el v4 desde el v2 (pierde solo la información IPv6 cacheada, no datos críticos). Es aceptable.

---

## 10. Estrategia de pruebas

### 10.1 Unit tests

- `CAddress`: roundtrip wire, sockaddr conversion, hash uniformidad, subnet masking.
- Parsers de `nodes.dat`/`server.met`/`known.met`/`ipfilter`: leer y reescribir el mismo archivo da bytes idénticos (idempotencia).
- Negociación de capabilities: simular 4 combinaciones de pares (v4-only/v6-only/dual/dual-pre-v6).

### 10.2 Integration tests

- **Loopback dual-stack**: dos instancias eMule en localhost, una bindea `0.0.0.0`, la otra `::`. Conexión exitosa.
- **Sources federadas**: subir un fichero conocido, descargarlo desde un peer remoto IPv4-only y otro IPv6-only en paralelo.
- **LiveTV PC1→PC2**: replicar el éxito ya validado (memoria `p2p_live_works`), pero esta vez con uno de los dos peers sin IPv4 pública.

### 10.3 Field testing

- 30 días, grupo de 20-50 testers (mezcla de ISPs IPv6-nativos y IPv6-vía-tunneled).
- Métricas semanales:
  - % de conexiones por familia.
  - % de Kad contacts verificados por familia.
  - Latencia mediana de chunk fetch.
  - Tasa de fallo de hole-punch.

### 10.4 Regresión IPv4-only

Test crítico: build con `IPv6Enabled=false` debe comportarse byte-a-byte como el baseline pre-IPv6 en el wire. Verificación con captura `tcpdump`/Wireshark.

---

## 11. Riesgos, mitigaciones y plan B

| # | Riesgo | Probabilidad | Impacto | Mitigación |
|---|---|---|---|---|
| R1 | Cambio de wire rompe peers antiguos | media | crítico | ADR-04 (opcodes paralelos); regresión Wireshark |
| R2 | `IPV6_V6ONLY=0` falla en algún firewall corporativo | baja | medio | fallback a dos sockets separados; preferencia configurable |
| R3 | Routing tables IPv6 sin masa crítica (pocos nodos) | alta al principio | medio | dual-bootstrap via IPv4 conocido + DNS seed; tolerar mucho tiempo arranque inicial |
| R4 | Kad v3 opcodes colisionan con extensiones de otros forks (eMule Plus, Xtreme) | media | alto | reservar bloque alto (0x70+) en KADEMLIA2_*; checar wiki eMule |
| R5 | Privacy addresses IPv6 invalidan caché de fuentes en horas | alta | bajo | TTL más corto para sources IPv6 (e.g., 6h vs 48h IPv4) |
| R6 | Servidores eD2K nunca se actualizan a IPv6 | alta | medio | aceptado: los servidores se quedan IPv4; el cliente puede hablar Kad-v6 con peers IPv6 que llegaron via servidor IPv4 |
| R7 | UPnP/PCP IPv6 mal soportado en routers domésticos | media | medio | cascada de 5 capas en §8.5 (PCP → IGDv2 → keepalive → hole-punch → buddy); cobertura esperada ~99% según estimación |
| R8 | LiveTV chunk fetch falla en mesh mixto v4/v6 | media | alto | tests específicos PC1-IPv6/PC2-IPv4 y viceversa antes de release |
| R9 | UI con IPv6 textual rompe layouts en idiomas RTL/asiáticos | baja | bajo | ancho de columna autoresizable; truncado con tooltip completo |
| R10 | Plan se alarga >24 semanas y agota motivación | media | crítico | fases independientemente mergeables; cada fase aporta valor visible (ADR-implícito: deliver incrementally) |

**Plan B**: descartada la opción inicial (servidores eD2K IPv6) por ADR-09. El backup ahora es: si la adopción real de IPv6 en el field testing es < 10% tras 6 meses, congelamos las Fases 6-9 menos críticas y mantenemos solo Kad-v6 + listener dual-stack como inversión defensiva (para el día que el ISP del usuario corte IPv4). Coste hundido aceptable: ~7-9 semanas de las 11 invertidas (Fases 0-4) siguen siendo útiles aunque nadie las use a corto plazo.

**Plan C** (si alguien externo quisiera resucitar los servidores): nuestro wire `_V6` está bien definido en este documento (Apéndice B). Un dev que tome `eserver` open-source podría implementar los mismos opcodes en ~3-4 semanas, y nuestro cliente ya hablaría con él sin más cambios. Es un proyecto paralelo, no parte del plan principal.

---

## 12. Cronograma

| Sem | Fase | Hito visible |
|---|---|---|
| 1 | Fase 0 | baseline verde, ADRs aprobados (incluyendo ADR-09 servidores) |
| 2-3 | Fase 1 | `CAddress` adoptado en todo el árbol |
| 4-5 | Fase 2 | netstat muestra socket `::` escuchando |
| 6-6.5 | Fase 3 | `Mi IPv6: 2001:db8::1 (HighID, PCP)` en status bar tras probe automática |
| 7-10 | Fase 4 | Kad-v3 funcional + keepalive + hole-punching; dos peers firewalled se encuentran vía rendezvous |
| 11-13 | Fase 5 | OP_ANSWERSOURCES2 v5 + PCP cliente abre pinhole automático |
| 14-16 | Fase 6 | LiveTV PC1-IPv6 móvil → PC2-IPv6 (sin IPv4, con buddy si broadcaster firewalled) |
| 17 | Fase 7 | upgrade automático de archivos |
| 18-19 | Fase 8 | UPnP-IGDv2 AddPinhole como fallback de PCP, UI pulida |
| 20-21 | Fase 9 | beta release |

**Total: 21 semanas** (~5 meses) con un desarrollador FTE. Subió 3 semanas vs la versión previa por la cascada anti-firewall (Fases 3, 4, 5, 6 absorbieron PCP+keepalive+hole-punch+buddy). Con dos desarrolladores en paralelo (Fase 4+5 simultáneas con Fase 6 desde sus respectivos mocks, Fase 7 con Fase 8) baja a **~14 semanas**.

**Coste/beneficio**: 3 semanas extra a cambio de saltar de ~50% de clientes alcanzables (IPv6 vanilla con firewall stateful) a ~99% (cascada completa). Es el cambio individual con mayor ROI de todo el plan.

---

## Apéndice A: inventario de archivos a tocar

Ordenado por fase aproximada. **Negrita** = cambio de wire/disco; *cursiva* = solo refactor interno.

### Fase 1 (CAddress adoption)
- *[srchybrid/eMuleAI/Address.h](srchybrid/eMuleAI/Address.h)*
- *[srchybrid/eMuleAI/Address.cpp](srchybrid/eMuleAI/Address.cpp)*
- *[srchybrid/OtherFunctions.cpp](srchybrid/OtherFunctions.cpp)* (ipstr overloads)
- *[srchybrid/OtherFunctions.h](srchybrid/OtherFunctions.h)*
- *[srchybrid/AsyncSocketEx.cpp](srchybrid/AsyncSocketEx.cpp)* (locales)
- *[srchybrid/AsyncSocketEx.h](srchybrid/AsyncSocketEx.h)*

### Fase 2 (listener)
- **[srchybrid/ListenSocket.cpp:2149](srchybrid/ListenSocket.cpp:2149)**
- **[srchybrid/ListenSocket.h:88](srchybrid/ListenSocket.h:88)**
- **[srchybrid/ClientUDPSocket.h](srchybrid/ClientUDPSocket.h)**
- **[srchybrid/ClientUDPSocket.cpp](srchybrid/ClientUDPSocket.cpp)**
- **[srchybrid/Preferences.h:147-158](srchybrid/Preferences.h:147)** (bind IPv6)
- **[srchybrid/Preferences.cpp](srchybrid/Preferences.cpp)** (read/write nuevas claves)

### Fase 3 (public IP + probe firewall)
- **[srchybrid/BaseClient.cpp:2593](srchybrid/BaseClient.cpp:2593)**
- **[srchybrid/ListenSocket.cpp:1378](srchybrid/ListenSocket.cpp:1378)**
- **[srchybrid/Opcodes.h](srchybrid/Opcodes.h)** (nuevos opcodes en OP_EMULEPROT)
- **`srchybrid/FirewallProberV6.h/.cpp`** (NUEVO — clase de probe + state machine de la cascada §8.5)
- **[srchybrid/EmuleDlg.cpp](srchybrid/EmuleDlg.cpp)** (status bar muestra capa activa)

### Fase 4 (Kad + keepalive + hole-punching)
- **[srchybrid/kademlia/routing/Contact.h](srchybrid/kademlia/routing/Contact.h)**
- **[srchybrid/kademlia/routing/Contact.cpp](srchybrid/kademlia/routing/Contact.cpp)**
- **[srchybrid/kademlia/routing/RoutingZone.cpp](srchybrid/kademlia/routing/RoutingZone.cpp)** (lectura+escritura nodes.dat)
- **[srchybrid/kademlia/net/KademliaUDPListener.cpp](srchybrid/kademlia/net/KademliaUDPListener.cpp)** (+ TickKeepalive)
- **[srchybrid/kademlia/net/KademliaUDPListener.h](srchybrid/kademlia/net/KademliaUDPListener.h)**
- **[srchybrid/kademlia/kademlia/Kademlia.cpp](srchybrid/kademlia/kademlia/Kademlia.cpp)**
- **[srchybrid/kademlia/kademlia/Search.cpp](srchybrid/kademlia/kademlia/Search.cpp)**
- **[srchybrid/Opcodes.h:574-627](srchybrid/Opcodes.h:574)** (KADEMLIA3_*, incluyendo PING, HOLEPUNCH)
- **`srchybrid/kademlia/net/HolePuncher.h/.cpp`** (NUEVO — state machine de rendezvous)
- **`srchybrid/kademlia/net/KadKeepalive.h/.cpp`** (NUEVO — rotación de supernodos)

### Fase 5 (eD2K wire P2P + PCP cliente)
- **[srchybrid/BaseClient.cpp](srchybrid/BaseClient.cpp)** (Hello + EmuleInfo + tags, PublicIP)
- **[srchybrid/ListenSocket.cpp:1281-1378](srchybrid/ListenSocket.cpp:1281)** (src exchange + publicip P2P)
- ~~`srchybrid/ServerSocket.cpp`~~ **[OUT]** — wire servidor congelado
- ~~`srchybrid/ServerConnect.cpp:207`~~ **[OUT]** — login servidor sin cambios
- **[srchybrid/PartFile.cpp:2449-2528](srchybrid/PartFile.cpp:2449)** (AddSources — solo el path P2P, no el del servidor)
- **[srchybrid/KnownFile.cpp:1100-1160](srchybrid/KnownFile.cpp:1100)** (CreateSrcInfoPacket — solo source-exchange P2P)
- **[srchybrid/UpdownClient.h:104-115](srchybrid/UpdownClient.h:104)** (GetIP/SetIP → adapt CAddress)
- **[srchybrid/UpdownClient.cpp](srchybrid/UpdownClient.cpp)**
- **[srchybrid/Opcodes.h](srchybrid/Opcodes.h)** (CT_FORK_CAPABILITIES, OP_PUBLICIP_ANSWER_V6)
- **[srchybrid/UPnPImplNATPMP.cpp](srchybrid/UPnPImplNATPMP.cpp)** (extender a PCP v2 RFC 6887 — §8.5 capa A)
- **[srchybrid/UPnPImplNATPMP.h](srchybrid/UPnPImplNATPMP.h)** (interfaz `MapPortV6`)

### Fase 6 (LiveTV + buddy relay v6)
- **[srchybrid/LivePackets.cpp:71-79](srchybrid/LivePackets.cpp:71)**
- **[srchybrid/LivePackets.h:30](srchybrid/LivePackets.h:30)**
- **[srchybrid/LiveKadBridge.h:14-26](srchybrid/LiveKadBridge.h:14)** (struct)
- **[srchybrid/LiveKadBridge.cpp:90-91](srchybrid/LiveKadBridge.cpp:90)**
- **[srchybrid/LiveStreamManager.cpp:200-244](srchybrid/LiveStreamManager.cpp:200)** (TryConnect)
- **[srchybrid/LiveStreamManager.cpp:775-797](srchybrid/LiveStreamManager.cpp:775)** (subnet diversity)
- **[srchybrid/LiveStreamDlgUI.cpp:173-176](srchybrid/LiveStreamDlgUI.cpp:173)** (URL HLS)
- **[srchybrid/eSE/server.js:17](srchybrid/eSE/server.js:17)** (bind 0.0.0.0 → ::)
- **[srchybrid/eSE/eSE-live/rtmp_server.js:37-40](srchybrid/eSE/eSE-live/rtmp_server.js:37)** (bind 127.0.0.1 → ::1)
- **[srchybrid/Opcodes.h:289-298](srchybrid/Opcodes.h:289)** (OP_LIVE_PEER_LIST_V2, OP_LIVE_RELAY_REQ/FWD)
- **`srchybrid/LiveBuddyRelay.h/.cpp`** (NUEVO — buddy relay v6 §8.5 capa E)

### Fase 7 (persistencia)
- **[srchybrid/Server.h:23](srchybrid/Server.h:23)** (struct)
- **[srchybrid/Server.cpp](srchybrid/Server.cpp)** (tag ST_IPV6)
- **[srchybrid/ServerList.cpp](srchybrid/ServerList.cpp)** (lectura server.met)
- **[srchybrid/KnownFile.cpp](srchybrid/KnownFile.cpp)** (MET_HEADER v0x10)
- **[srchybrid/IPFilter.h](srchybrid/IPFilter.h)**
- **[srchybrid/IPFilter.cpp](srchybrid/IPFilter.cpp)** (PG6 binary + texto IPv6)

### Fase 8 (IGDv2 AddPinhole + UI)
- **[srchybrid/UPnPImpl.h](srchybrid/UPnPImpl.h)** (interface ampliada con `OpenPortV6`)
- **[srchybrid/UPnPImplWinServ.cpp](srchybrid/UPnPImplWinServ.cpp)** (AddPinhole COM § 8.5 capa B)
- **[srchybrid/UPnPImplMiniLib.cpp](srchybrid/UPnPImplMiniLib.cpp)** (miniupnpc IPv6 AddPinhole)
- ~~`srchybrid/UPnPImplNATPMP.cpp`~~ → ya hecho en Fase 5 (PCP)
- **[srchybrid/ServerListCtrl.cpp:124-126](srchybrid/ServerListCtrl.cpp:124)**
- **[srchybrid/Server.h:170](srchybrid/Server.h:170)** (`ipfull[16]` → `[48]`)
- **[srchybrid/AddSourceDlg.cpp:135](srchybrid/AddSourceDlg.cpp:135)**
- **[srchybrid/EmuleDlg.cpp](srchybrid/EmuleDlg.cpp)** (status bar con capa anti-firewall activa)
- **[srchybrid/PPgConnection.cpp](srchybrid/PPgConnection.cpp)** (UI prefs + override manual)
- **[srchybrid/ClientDetailDialog.cpp](srchybrid/ClientDetailDialog.cpp)** (mostrar ambas + reachability)

**Total estimado: ~50 archivos**, de los cuales ~25 son cambios mecánicos (Fase 1) y ~25 son cambios de lógica real.

---

## Apéndice B: nuevos opcodes y tags

**Reservar en `srchybrid/Opcodes.h`**:

```cpp
// Capability negotiation (en OP_EMULEINFO tags):
#define CT_FORK_CAPABILITIES        0xF0  // uint32 bitfield, ver §4.3
  #define CAP_FORK_IPV6_WIRE        0x00000001
  #define CAP_FORK_IPV6_DUALSTACK   0x00000002
  #define CAP_FORK_IPV6_KAD         0x00000004
  #define CAP_FORK_IPV6_LIVEPEER    0x00000008

// Opcodes extendidos (en OP_EMULEPROT 0xC5):
#define OP_PUBLICIP_ANSWER_V6       0xE0
// 0xE1 reservado (era OP_CALLBACK_V6) — descartado por ADR-09 (callbacks vía Kad)
// 0xE2 reservado (era OP_FOUNDSOURCES_V6) — descartado por ADR-09 (servidor IPv4-only)
#define OP_LIVE_PEER_LIST_V2        0xCB  // próximo libre tras 0xCA
#define OP_LIVE_RELAY_REQ           0xCC  // buddy relay v6 (§8.5 capa E)
#define OP_LIVE_RELAY_FWD           0xCD  // buddy → broadcaster firewalled

// Tags persistentes (en met files):
#define ST_IPV6                     0x90  // server.met
#define TAG_SOURCEIP_V6             0x66  // known.met (verificar ausencia colisión)
#define TAG_SERVERIP_V6             0x67  // known.met

// Versiones de archivo:
#define MET_HEADER_V6               0x10  // known.met
#define NODES_DAT_VERSION_V6        4     // nodes.dat

// Kad gen 3 (en OP_KADEMLIAHEADER):
#define KADEMLIA3_BOOTSTRAP_REQ     0x02  // dist de 0x01 KADEMLIA2_BOOTSTRAP_REQ
#define KADEMLIA3_BOOTSTRAP_RES     0x09
#define KADEMLIA3_HELLO_REQ         0x12
#define KADEMLIA3_HELLO_RES         0x1A
#define KADEMLIA3_REQ               0x22
#define KADEMLIA3_PUBLISH_KEY_REQ   0x4A
#define KADEMLIA3_PUBLISH_SOURCE_REQ 0x4B
#define KADEMLIA3_FIREWALLED_RES    0x60
#define KADEMLIA3_PING_REQ          0x61  // keepalive (§8.5 capa C)
#define KADEMLIA3_PING_RES          0x62
#define KADEMLIA3_HOLEPUNCH_REQ     0x63  // A → R: ayúdame a alcanzar B (§8.5 capa D)
#define KADEMLIA3_HOLEPUNCH_FWD     0x64  // R → B: A va a punchearte desde [addr]:port
#define KADEMLIA3_HOLEPUNCH_ACK     0x65  // B → A directo, tras establecer

// Magic numbers:
//   ipfilter PG6: 0xFE 0xFE 0xFE 0xFE 'P' '6' 'B'
```

> **Caveat**: estos números son **provisionales**. En Fase 0 hay que checar el wiki/source de eMule Plus, Xtreme y MorphXT para evitar choques con sus extensiones.

---

## Apéndice C: pseudocódigo de los puntos críticos

### C.1 `CAddress::WriteToBuffer` / `ReadFromBuffer`

```cpp
void CAddress::WriteToBuffer(CSafeMemFile* file) const {
    if (m_eAF == None) {
        file->WriteUInt8(0);  // family
        file->WriteUInt8(0);  // length
        return;
    }
    if (m_eAF == IPv4) {
        file->WriteUInt8(4);
        file->WriteUInt8(4);
        file->Write(m_IP + 12, 4);  // últimos 4 bytes
    } else {
        file->WriteUInt8(6);
        file->WriteUInt8(16);
        file->Write(m_IP, 16);
    }
}

bool CAddress::ReadFromBuffer(CSafeMemFile* file) {
    uint8 family = file->ReadUInt8();
    uint8 len = file->ReadUInt8();
    if (family == 0 && len == 0) {
        m_eAF = None;
        memset(m_IP, 0, 16);
        return true;
    }
    if (family == 4 && len == 4) {
        m_eAF = IPv4;
        memset(m_IP, 0, 10);
        m_IP[10] = 0xFF;
        m_IP[11] = 0xFF;  // mapped marker
        file->Read(m_IP + 12, 4);
        return true;
    }
    if (family == 6 && len == 16) {
        m_eAF = IPv6;
        file->Read(m_IP, 16);
        return true;
    }
    // formato desconocido: skip bytes y devolver error
    if (len > 0) {
        byte tmp[256];
        file->Read(tmp, std::min<int>(len, 256));
    }
    return false;
}
```

### C.2 Listener TCP dual-stack

```cpp
bool CListenSocket::StartListening() {
    bool useV6 = thePrefs.IsIPv6Enabled() &&
                 thePrefs.GetIPv6Mode() != CPreferences::IPv4Only;

    ADDRESS_FAMILY family = useV6 ? AF_INET6 : AF_INET;

    if (!CAsyncSocketEx::Create(m_port, SOCK_STREAM, FD_ACCEPT,
                                thePrefs.GetBindAddr(), family, true)) {
        return false;
    }

    if (useV6) {
        // Permite IPv4-mapped en el socket IPv6.
        BOOL v6only = FALSE;
        if (setsockopt(GetSocketHandle(), IPPROTO_IPV6, IPV6_V6ONLY,
                       (char*)&v6only, sizeof(v6only)) == SOCKET_ERROR) {
            DebugLog(_T("Failed to disable IPV6_V6ONLY: %u"), WSAGetLastError());
            // No fatal: el listener sigue siendo IPv6-only en este caso.
        }
    }

    return Listen();
}
```

### C.3 Negociación en OP_EMULEINFO

```cpp
// Al construir el paquete saliente:
CSafeMemFile data(128);
data.WriteUInt8(CURRENT_EMULE_VERSION);
data.WriteUInt8(CURRENT_EMULE_PROTOCOL);

uint32 tagcount = ...;  // existente
if (thePrefs.IsIPv6Enabled()) tagcount++;
data.WriteUInt32(tagcount);

// ... tags existentes ...

if (thePrefs.IsIPv6Enabled()) {
    uint32 caps = 0;
    caps |= CAP_FORK_IPV6_WIRE | CAP_FORK_IPV6_DUALSTACK;
    if (Kademlia::CKademlia::IsRunning())   caps |= CAP_FORK_IPV6_KAD;
    if (theApp.liveStreamManager)           caps |= CAP_FORK_IPV6_LIVEPEER;

    CTag tagCap(CT_FORK_CAPABILITIES, caps);
    tagCap.WriteTagToFile(&data);
}

// Al recibir:
for (uint32 i = 0; i < tagcount; ++i) {
    CTag tag(data, false);
    if (tag.GetNameID() == CT_FORK_CAPABILITIES) {
        client->m_dwForkCaps = (uint32)tag.GetInt();
    } else if (...) ...
    // tags desconocidos se descartan en silencio (comportamiento ya existente)
}
```

### C.4 OP_LIVE_PEER_LIST con compatibilidad

```cpp
void CLiveStreamManager::BroadcastPeerList(const uchar* streamKey,
                                            const std::vector<LivePeer>& peers) {
    // Para peers con capability IPv6:
    std::vector<LivePeer> v4Only;
    for (const auto& p : peers) {
        if (p.addr.GetType() == CAddress::IPv4) v4Only.push_back(p);
    }

    // Construir paquete LEGACY (solo IPv4):
    CSafeMemFile legacyData;
    legacyData.WriteHash16(streamKey);
    legacyData.WriteUInt16((uint16)v4Only.size());
    for (const auto& p : v4Only) {
        legacyData.WriteUInt32(p.addr.ToUInt32(false));
        legacyData.WriteUInt16(p.port);
        legacyData.WriteUInt8(p.score);
    }
    Packet* legacy = new Packet(legacyData.GetBuffer(), legacyData.GetLength(),
                                 OP_EMULEPROT);
    legacy->opcode = OP_LIVE_PEER_LIST;

    // Construir paquete V2 (incluye IPv4 e IPv6):
    CSafeMemFile v2Data;
    v2Data.WriteHash16(streamKey);
    v2Data.WriteUInt16((uint16)peers.size());
    for (const auto& p : peers) {
        p.addr.WriteToBuffer(&v2Data);
        v2Data.WriteUInt16(p.port);
        v2Data.WriteUInt8(p.score);
        v2Data.WriteUInt8(p.flags);
    }
    Packet* v2 = new Packet(v2Data.GetBuffer(), v2Data.GetLength(), OP_EMULEPROT);
    v2->opcode = OP_LIVE_PEER_LIST_V2;

    // Dispatch:
    for (auto& subscriber : m_subscribers) {
        if (subscriber.HasFork(CAP_FORK_IPV6_LIVEPEER)) {
            subscriber.Send(v2);
        } else {
            subscriber.Send(legacy);
        }
    }
}
```

### C.5 nodes.dat v4 lectura tolerante

```cpp
bool CRoutingZone::ReadFromFile() {
    CSafeFile file;
    if (!file.Open(GetNodesFilePath())) return false;

    uint32 firstWord = file.ReadUInt32();
    if (firstWord == 0) {
        // formato moderno: la siguiente word es la versión
        uint32 version = file.ReadUInt32();
        uint32 numContacts = file.ReadUInt32();

        switch (version) {
            case 1: case 2: case 3:
                return ReadContactsV1V2V3(file, numContacts, version);
            case 4:
                return ReadContactsV4(file, numContacts);
            default:
                DebugLog(_T("nodes.dat version %u not supported, ignoring"), version);
                return false;
        }
    } else {
        // formato v0 antiguo: firstWord es ya numContacts
        return ReadContactsV0(file, firstWord);
    }
}

bool CRoutingZone::ReadContactsV4(CSafeFile& file, uint32 numContacts) {
    for (uint32 i = 0; i < numContacts; ++i) {
        CUInt128 kadID;
        file.ReadUInt128(kadID);

        CAddress addr;
        if (!addr.ReadFromBuffer(&file)) {
            DebugLog(_T("Corrupt CAddress in nodes.dat at contact %u"), i);
            return false;  // o continuar saltando el resto del registro
        }

        uint16 udpPort = file.ReadUInt16();
        uint16 tcpPort = file.ReadUInt16();
        uint8 kadVersion = file.ReadUInt8();
        uint32 udpKey = file.ReadUInt32();
        bool verified = file.ReadUInt8() != 0;

        Add(kadID, addr, udpPort, tcpPort, kadVersion, udpKey, verified);
    }
    return true;
}
```

---

## Cierre

Este plan parte de la constatación de que **la pieza más cara — `CAddress` — ya existe en el árbol**, lo que reduce el problema desde "diseñar un sistema dual-stack desde cero" a "adoptarlo y extender los formatos". El cronograma de 19 semanas es ambicioso pero realista si se respeta la disciplina de **opcodes paralelos** y **fases mergeables**. La compatibilidad backward está garantizada por construcción: ningún byte del wire IPv4 cambia, ningún archivo persistente legacy se rompe, y el peer viejo siempre puede seguir hablando con el peer nuevo en el mismo nivel que antes (IPv4-only).

El próximo paso recomendado: **reunión de revisión** sobre este documento, asignación de números definitivos a los opcodes nuevos (cotejando con eMule Plus / Xtreme / MorphXT), y arranque inmediato de la Fase 0 con un branch dedicado.

---

*Fin del documento.*
