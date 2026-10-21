# Núcleo mínimo de conectividad directa LowID ↔ LowID

Estado: diseño técnico propuesto  
Fecha: 26 de julio de 2026  
Base auditada: árbol actual `9.1.0-beta.2`, orientado a la futura RC  
Ámbito: descarga eD2K directa entre dos peers eSE, sin relay de datos  

## 0. Decisión ejecutiva

El núcleo mínimo no debe ser una VPN. Debe ser un pequeño plano de control de
conectividad que reutilice cuatro piezas ya presentes:

1. descubrimiento descentralizado mediante Kad;
2. descripción explícita de capacidades mediante `ReachVector`;
3. Punch2 con cookie de return-routability;
4. uTP sobre el mismo socket UDP de Kad, entregando después el flujo al
   protocolo eD2K existente.

La arquitectura propuesta añade un único propietario de cada intento:
`CDirectConnectionOrchestrator`. Ese componente decide la ruta, correlaciona
todos los eventos, nomina un único transporte ganador y solo declara éxito
cuando el peer ha quedado autenticado y se ha transferido el primer bloque
eD2K válido.

La cascada mínima es:

```text
IPv6 directa verificada
        ↓
IPv4 directa o mapeada y verificada
        ↓
callback clásico, si es realmente aplicable
        ↓
Punch2 autenticado sobre endpoint observado
        ↓
DIRECT_UNREACHABLE
```

No hay relay como último escalón. `DIRECT_UNREACHABLE` es un resultado normal,
acotado y medible.

Esta solución puede recuperar una parte muy importante del LowID ↔ LowID, pero
no puede garantizar un 70 %. El 70 % será un objetivo experimental medido sobre
intentos reales. Dos NAT con mapping dependiente del destino, dos firewalls que
no permiten tráfico de retorno o una red sin ninguna ruta IP directa siguen
siendo físicamente irresolubles sin cambiar alguna frontera, usar IPv6, obtener
un mapping explícito o transportar datos a través de un tercero.

## 1. Qué problema resuelve realmente

`LowID` mezcla demasiadas situaciones distintas:

- peer sin entrada TCP IPv4;
- peer con UDP saliente y retorno permitido;
- peer tras NAT doméstico con mapping estable;
- peer tras CGNAT;
- peer con IPv6 global pero firewall IPv4;
- peer con puerto creado por UPnP, NAT-PMP o PCP;
- peer completamente aislado por una política corporativa.

Tratar todos esos casos como un único booleano descarta rutas válidas. El
nuevo núcleo no convierte mágicamente un LowID en HighID. Sustituye la pregunta
«¿es LowID?» por:

> «¿Existe ahora un par de endpoints verificables que permita a estos dos peers
> abrir un transporte directo?»

El resultado pertenece a la pareja de peers, al instante y a la topología
actual. No es una propiedad global y permanente del usuario.

## 2. Límites físicos

El diseño parte de cuatro verdades:

1. Una LAN virtual no crea conectividad subyacente. TUN/TAP o una mini-VPN solo
   encapsulan paquetes después de que exista un camino entre los extremos.
2. UDP hole punching funciona bien cuando los mappings son reutilizables entre
   destinos. Con mappings dependientes del endpoint, el puerto observado por un
   testigo puede no ser el que el NAT asigna frente al peer.
3. Un firewall con estado que bloquea conexiones espontáneas puede permitir el
   tráfico que responde a una salida previa. Un firewall que descarta todo UDP
   y todo TCP hacia el peer no ofrece un agujero que perforar.
4. Si no existe ninguna ruta IP directa, ningún formato de paquete, raw socket,
   VPN o sincronización temporal puede crearla. Hace falta modificar el gateway,
   usar otra familia de red o aceptar un intermediario de datos.

Por tanto, el núcleo maximiza las rutas directas existentes; no afirma resolver
las combinaciones imposibles.

## 3. Alcance mínimo

### 3.1 Incluido

- IPv6 global directa, si ha sido comprobada.
- IPv4 TCP directa comprobada.
- IPv4/UDP mapeada explícitamente por UPnP IGD, NAT-PMP o PCP y verificada.
- Callback clásico cuando uno de los extremos conserva una ruta entrante
  utilizable.
- Descubrimiento de endpoint reflexivo mediante nodos Kad que ya reciben la
  publicación de fuente.
- Punch2 exacto, sin barrido de puertos.
- Cookie stateless antes de crear estado para un origen no verificado.
- Transporte uTP sobre el mismo puerto/socket UDP usado para descubrir y
  perforar.
- Hello, SecureIdent y transferencia eD2K existentes sobre ese transporte.
- Cancelación por cambio de red, apagado de la función o victoria de otra ruta.
- Contadores y evidencia local, sin telemetría central.
- Compatibilidad de lectura con peers antiguos y fallback clásico para ellos.

### 3.2 Excluido

- Relay de datos de cualquier clase.
- Punch3 o Direct Connection Upgrade through Relay.
- Predicción o spray de puertos.
- TURN, DERP, Tor, I2P, WebSocket proxy o túneles onion.
- Una interfaz TUN/TAP o mini-VPN.
- TCP simultaneous open.
- ICMP/DNS/raw-socket tunneling.
- Modificar routers mediante credenciales, TR-064, SNMP, DMZ o reinicio.
- Explotar ALGs, puertos de juegos, fragmentación o campos encubiertos.
- Cambiar el protocolo de partes, créditos, colas o hashes de eMule.
- Afirmar HighID global tras un éxito puntual.

Punch3 y predicción pueden estudiarse como extensiones posteriores, pero no
deben contaminar la medición del núcleo mínimo.

## 4. Base existente y brecha

El árbol ya contiene casi todos los átomos:

- `libreach` tiene codec v2, selector puro, C ABI, handles con generación y
  memoria de ruta nominada.
- `ReachabilityWire` conecta el codec con el host MFC.
- Kad publica y consume `TAG_ESE_REACH`.
- Punch2 implementa REQ, CHALLENGE, cookie y ACK.
- `CClientUDPSocket` alimenta libutp y puede iniciar uTP tras el ACK.
- `CUtpSocket` soporta expectativas, adopción y arbitraje de conexiones
  simultáneas.
- `CClientReqSocket` ya transporta Hello y tráfico eD2K sobre la capa uTP.
- `CDirectReachabilityManager` contiene una generación de topología y snapshots
  para rutas mapeadas.

La brecha no es «inventar otro transporte». Es convertir piezas actualmente
dispersas en un solo protocolo de intento.

Problemas concretos del estado actual:

- `CUpDownClient::TryToConnect` conserva política y contadores de Punch2.
- `libreach` conserva capas Punch3, relay y terminal Classic que no representan
  el perfil directo estricto.
- el bridge de `ReachVector` solo entrega versión y flags, perdiendo anchors y
  bytes futuros;
- las expectativas uTP se identifican principalmente por endpoint y puntero de
  propietario;
- existe fallback por IP y ventana de puerto que puede atribuir mal un socket;
- el ACK incrementa un contador llamado éxito antes de tener transporte;
- el transporte conectado tampoco demuestra aún que sea el peer eD2K esperado;
- un cambio de topología no invalida de forma uniforme todo el intento;
- descargas y otros consumidores pueden mantener políticas paralelas.

## 5. Arquitectura

```text
                         ┌────────────────────────────┐
Kad/source result ──────▶│ RemoteReachSnapshot       │
                         └──────────────┬─────────────┘
                                        │
Local snapshot/mappings ────────────────┤
                                        ▼
                         ┌────────────────────────────┐
solicitud de descarga ──▶│ DirectConnectionOrchestr. │
                         │  - identidad              │
                         │  - estado/deadline        │
                         │  - selector de ruta       │
                         │  - árbitro single-winner  │
                         └──────┬──────────┬──────────┘
                                │          │
                     TCP/v6/callback      Punch2 control
                                │          │
                                │          ▼
                                │   CClientUDPSocket
                                │          │ mismo socket UDP
                                │          ▼
                                └─────── CUtpSocket
                                           │
                                           ▼
                                  CClientReqSocket
                                           │
                                  Hello + SecureIdent
                                           │
                                           ▼
                               sesión eD2K ya existente
```

### 5.1 Regla de autoridad

Solo `CDirectConnectionOrchestrator`, abreviado DCO, decide:

- qué ruta se prueba;
- durante cuánto tiempo;
- qué eventos pertenecen al intento;
- qué transporte gana;
- cuándo se cancela el resto;
- por qué termina el intento.

Kad no decide que una conexión ha funcionado. uTP no decide qué peer eD2K es.
`CUpDownClient` no ejecuta una segunda cascada. Cada adaptador informa hechos al
DCO.

### 5.2 División library/host

`libreach` debe conservar:

- tipos independientes de MFC;
- selector determinista;
- reducer de estados;
- presupuestos;
- handles con generación;
- reason codes;
- single-winner;
- cero sockets y cero punteros a objetos del host.

El host debe conservar:

- Kad y sus paquetes;
- `CAddress` y conversiones de byte order;
- sockets TCP/UDP/uTP;
- mapeo de handle a cliente;
- Hello, SecureIdent, colas y archivos;
- preferencias, UI y logs.

## 6. Modelo de identidad

Una dirección IP no es una identidad.

### 6.1 Tipos separados

```cpp
struct AttemptId {
    uint64 high;
    uint64 low;
};

struct PeerKey {
    Optional<UserHash128> userHash;
    Optional<KadId128> kadId;
};

struct TopologyGeneration {
    uint64 value;
};

struct AttemptHandle {
    uint64 slotAndGeneration;
};
```

Reglas:

- `KadID` sirve para correlacionar señalización Kad.
- `UserHash` identifica el peer en el protocolo eD2K.
- un endpoint identifica una ruta efímera, no una persona;
- un `CUpDownClient*` nunca cruza hacia `libreach`;
- el host solo guarda un `AttemptHandle` y resuelve el objeto en el hilo de red;
- si el cliente desaparece, el handle queda stale y el evento se descarta;
- después de Hello/SecureIdent, el DCO comprueba que la identidad recibida es
  compatible con la fuente solicitada.

Antes de Hello puede existir una identidad parcial. En ese estado el socket es
`PROVISIONAL`: puede intercambiar autenticación, pero no solicitar ni aceptar
bloques.

## 7. Descriptores de reachability

### 7.1 Snapshot local

```cpp
enum class CandidateKind : uint8 {
    HostV6,
    DirectV4,
    MappedV4,
    ReflexiveUdp,
    ClassicCallback
};

enum class CandidateEvidence : uint8 {
    AdvertisedOnly,
    ObservedByKad,
    MappingGranted,
    InboundVerified
};

struct DirectCandidate {
    CandidateKind kind;
    Transport transport;        // TCP o UDP_UTP
    Endpoint endpoint;
    CandidateEvidence evidence;
    uint64 topologyGeneration;
    uint64 expiresAtMonotonicMs;
    MapperKind mapper;           // None, UPnP, NATPMP, PCP
};

struct LocalReachSnapshot {
    uint16 reachCaps;
    uint64 topologyGeneration;
    SmallVector<DirectCandidate, 6> candidates;
};
```

Solo se anuncia `V4_TCP_IN`, `V4_UDP_IN` o `V6_IN` cuando la evidencia lo
justifica. Solicitar un mapping no equivale a verificarlo.

### 7.2 Snapshot remoto

```cpp
struct EndpointObservation {
    Endpoint endpoint;
    KadId128 witness;
    uint64 observedAtMs;
};

struct RemoteReachSnapshot {
    uint8 vectorVersion;
    uint16 knownCaps;
    uint16 unknownCaps;
    Optional<KadId128> kadId;
    Optional<UserHash128> userHash;
    Optional<Endpoint> directV4Tcp;
    Optional<Endpoint> directV6Tcp;
    SmallVector<EndpointObservation, 4> udpObservations;
    ByteVector preservedTrailing;
    uint64 expiresAtMs;
};
```

El host lo construye a partir de:

- tags clásicos de fuente;
- `TAG_SOURCEIP_V6`;
- `TAG_ESE_REACH`;
- IP y puerto UDP observados por el nodo Kad indexador;
- identidad que ya posea la fuente local.

### 7.3 Por qué no meter todos los endpoints dentro de `ReachVector`

Para el primer núcleo no hace falta inventar otro wire. Los tags de fuente ya
transportan IPv4, puertos e IPv6, y el nodo indexador ya conoce la dirección
reflexiva desde la que recibe la publicación. `ReachVector` debe describir
capacidades y preservar sus campos versionados; el host compone el snapshot
completo.

Esto minimiza incompatibilidades. Una futura revisión podría introducir TLV de
candidatos, pero no es requisito para conectar dos builds actuales.

### 7.4 Testigos Kad descentralizados

Kad actúa como plano de señalización distribuido, no como relay:

1. B publica que posee una fuente usando su socket Kad.
2. El indexador W observa la IP:puerto real de origen.
3. W almacena esa observación con TTL junto a la fuente.
4. A consulta la fuente y recibe el endpoint observado de B.
5. Los bytes del archivo viajan A ↔ B; W no participa.

Si A obtiene observaciones de dos o más indexadores independientes:

- endpoints iguales aumentan la confianza en un mapping estable;
- mismo IP con puertos distintos indica mapping variable o rebinding;
- IPs distintas indican cambio de red o CGNAT con pool.

En el núcleo mínimo, una observación vigente basta para intentar Punch2.
Varias observaciones sirven para ordenar y diagnosticar, no para disparar un
barrido.

## 8. Perfil directo de `libreach`

Debe existir una configuración explícita:

```cpp
enum class ReachProfile {
    LegacyCompatible,
    DirectOnlyV1
};
```

En `DirectOnlyV1` las únicas capas posibles son:

```text
DIRECT_V6
DIRECT_V4
MAPPED_V4
CALLBACK
PUNCH_2W
DIRECT_UNREACHABLE
```

`RELAY` no se desprioriza: no forma parte del conjunto. Punch3 y predicción
tampoco.

El terminal no debe ser `CLASSIC` cuando eso signifique volver a ejecutar una
política exterior que pueda escoger relay. El resultado debe ser:

```cpp
REACH_RESULT_DIRECT_UNREACHABLE
```

Los peers antiguos continúan fuera de este perfil y usan el comportamiento
clásico ya existente.

## 9. Planificador de rutas

### 9.1 Filtros

Un candidato solo entra en la checklist si:

- su familia es soportada localmente;
- el puerto es distinto de cero;
- no está expirado;
- pertenece al peer buscado o fue observado desde su publicación;
- su generación coincide con la topología vigente;
- la capability necesaria está presente;
- el protocolo correspondiente está habilitado;
- no es dirección multicast, unspecified, broadcast ni loopback remota;
- una dirección privada solo se usa si ambos peers están realmente en la misma
  LAN descubierta localmente.

### 9.2 Prioridades

| Prioridad | Ruta | Condición |
|---:|---|---|
| 100 | IPv6 TCP directa | `V6_IN` remoto + `V6_OUT` local + endpoint verificado |
| 90 | IPv4 TCP directa | `V4_TCP_IN` remoto + endpoint verificado |
| 85 | IPv4 mapeada | lease vigente y endpoint verificado |
| 70 | Callback | semántica clásica aplicable |
| 50 | Punch2/uTP | ambos anuncian Punch2 + endpoint UDP observado |

No se debe abrir una tormenta de rutas. Se permite un pequeño Happy Eyeballs
entre una candidata IPv6 y una IPv4 verificadas, con 150–250 ms de separación.
Punch2 empieza después de que las rutas directas aplicables fallen.

### 9.3 Presupuesto

Propuesta inicial, configurable para laboratorio:

| Fase | Presupuesto |
|---|---:|
| gather/normalización | 250 ms |
| IPv6 directa | 1.200 ms |
| IPv4 directa/mapeada | 1.500 ms |
| callback | 2.500 ms |
| Punch2 cookie + ACK | 3.500 ms |
| conexión uTP | 4.000 ms |
| Hello/SecureIdent | 5.000 ms |
| deadline total | 12.000 ms |

No se suman ciegamente: algunas fases se solapan y el deadline total domina.
Los valores definitivos salen de percentiles físicos, no de intuición.

## 10. Máquina de estados

```text
CREATED
   │
   ▼
GATHERING ──────────────┐
   │                    │ snapshot inválido
   ▼                    ▼
CHECKING_DIRECT     DIRECT_UNREACHABLE
   │ fallo
   ▼
CHECKING_CALLBACK
   │ fallo/no aplicable
   ▼
PUNCH2_REQUESTING
   │ challenge
   ▼
PUNCH2_PROVING_RETURN
   │ ACK válido
   ▼
UTP_CONNECTING
   │ transporte
   ▼
AUTHENTICATING
   │ identidad válida
   ▼
NOMINATED
   │ primer bloque válido
   ▼
CONNECTED
```

Desde cualquier estado no terminal:

```text
kill switch / cierre del peer ─────────────▶ CANCELLED
cambio de topología ───────────────────────▶ STALE_TOPOLOGY
deadline ──────────────────────────────────▶ DIRECT_UNREACHABLE
```

`STALE_TOPOLOGY` cancela recursos y puede crear un intento nuevo con otra
generación; nunca reutiliza eventos antiguos.

### 10.1 Eventos

```cpp
enum class DirectEvent {
    SnapshotReady,
    RouteStarted,
    TcpConnected,
    TcpFailed,
    PunchRequestSent,
    PunchChallengeReceived,
    PunchAckReceived,
    UtpConnected,
    UtpFailed,
    HelloReceived,
    IdentityVerified,
    IdentityRejected,
    FirstValidBlock,
    TopologyChanged,
    DeadlineExpired,
    KillSwitch,
    PeerDestroyed
};
```

Todo evento incluye:

```cpp
AttemptHandle attempt;
uint64 topologyGeneration;
RouteId route;
uint64 monotonicTimestamp;
```

Si handle o generación no coinciden, el reducer devuelve `IGNORED_STALE`.

### 10.2 Single-winner

Una ruta no gana por haber enviado un SYN, recibido ACK o conectado uTP.

La nominación usa una transición atómica lógica:

```cpp
if (attempt.winner == NONE &&
    transport.isConnected &&
    identity.isVerified) {
    attempt.winner = routeId;
    cancelAllExcept(routeId);
}
```

Solo la ruta nominada puede alcanzar `CONNECTED`. Un callback tardío de otra
ruta cierra su socket sin alterar contadores de sesión.

## 11. Punch2 mínimo

### 11.1 Propósito de cada mensaje

- `REQ`: prueba que A puede emitir hacia el endpoint observado de B y solicita
  coordinación.
- `CHALLENGE`: obliga a A a demostrar que recibe en la dirección de origen,
  evitando reflexión y estado falso.
- `REQ+COOKIE`: eco de la prueba.
- `ACK`: confirma que B validó el retorno y que ambos NAT/firewalls han visto
  tráfico de salida hacia la pareja exacta.
- SYN uTP: crea el transporte real.

### 11.2 Flujo

```text
A                                              B
│ register pending attempt                      │
│ register exact expected B endpoint            │
│                                               │
│──── REQ(KadID_A, port_A, nonce, caps) ───────▶│
│                                               │ origen desconocido
│◀── CHALLENGE(nonce, cookie_B(A)) ─────────────│ sin crear expectativa uTP
│                                               │
│──── REQ(KadID_A, port_A, nonce, cookie) ─────▶│
│                                               │ cookie válida:
│                                               │ registra expectativa exacta A
│◀── ACK(KadID_B, port_B, nonce) ───────────────│
│                                               │
│ inicia uTP SYN por el mismo socket UDP ──────▶│ adopta socket provisional
│◀══════════════ flujo uTP/eD2K ═══════════════▶│
│ Hello + SecureIdent                           │
│ primer bloque verificado                      │
```

### 11.3 Reutilización del wire actual

El primer núcleo puede conservar las formas actuales:

```text
REQ clásico:    KadID[16] | UDPPort[2] | Nonce[4]                 = 22
REQ capable:    KadID[16] | UDPPort[2] | Nonce[4] | Caps[4]       = 26
REQ expanded:   KadID[16] | UDPPort[2] | Nonce[4] | Cookie[16]    = 38
CHALLENGE:      Nonce[4] | Cookie[16]                              = 20
ACK:            KadID[16] | UDPPort[2] | Nonce[4]                 = 22
```

El `AttemptId` interno de 128 bits se asocia al nonce CSPRNG y al endpoint
esperado. La clave mínima de correlación es:

```text
(remote IP, nonce, expected KadID, topology generation)
```

Esto evita romper el protocolo antes de demostrar la ruta física.

Antes de habilitarlo por defecto se recomienda Punch2 v2 con nonce de 64 bits y
cookie ligada a:

```text
epoch | IP_A | port_A | KadID_A | KadID_B | attempt_token
```

No es necesario para el primer gate físico, pero sí una mejora razonable para
escala masiva.

### 11.4 Mismo socket UDP

La publicación Kad, REQ/ACK y paquetes uTP deben salir por el mismo
`CClientUDPSocket` y el mismo puerto local. Abrir un socket distinto puede crear
otro mapping exterior y anular la observación.

El callback `on_utp_sendto` ya permite enviar los datagramas libutp a través del
socket UDP compartido. El DCO debe convertir esta propiedad en invariante
comprobada:

```text
candidate.baseLocalSocketId == punch.socketId == utp.socketId
```

### 11.5 Qué no cuenta como éxito

- REQ enviado: intento.
- CHALLENGE recibido: retorno parcial.
- ACK recibido: pinhole plausible.
- uTP conectado: transporte provisional.
- Hello recibido: identidad anunciada.
- SecureIdent correcto: peer autenticado.
- primer bloque cuyo hash/intervalo es válido: transferencia demostrada.

La métrica pública `lowid_direct_success` solo se incrementa en el último paso.

## 12. Expectativas uTP y adopción segura

La tabla actual debe evolucionar de:

```cpp
endpoint + TTL + CUtpSocket* owner
```

a:

```cpp
struct UtpExpectation {
    AttemptHandle attempt;
    uint64 topologyGeneration;
    Optional<KadId128> expectedKadId;
    Endpoint exactEndpoint;
    uint64 expiresAtMs;
    ExpectationState state;
};
```

Reglas:

1. Solo una cookie válida o un intento local autorizado crea una expectativa.
2. La búsqueda principal exige IP y puerto exactos.
3. El núcleo mínimo deshabilita adopción IP-only y ventana `±120`.
4. Dos expectativas que resulten ambiguas no adoptan nada.
5. La entrada se consume una sola vez.
6. El socket aceptado queda asociado al `AttemptHandle`, no a un puntero crudo.
7. Si el intento ya terminó, el SYN tardío se cierra.
8. Al expirar/cancelar se eliminan expectativa, socket, timers y pending nonce.

Al no usar predicción, no existe motivo funcional para aceptar una ventana de
120 puertos. Su retirada reduce atribuciones cruzadas entre varios usuarios
tras el mismo CGNAT.

### 12.1 Responder pasivo

El responder puede no tener todavía un `CUpDownClient` adecuado. Debe crear:

```text
ProvisionalTransport(attempt, endpoint)
```

y solo promoverlo a una sesión eD2K después de Hello. Hasta entonces:

- límite pequeño de bytes de preautenticación;
- deadline corto;
- ninguna petición de parte;
- ninguna asignación de créditos;
- ninguna actualización de «fuente conectada».

## 13. Integración con la sesión eD2K

No se crea un nuevo protocolo de archivos.

### 13.1 Salida

Tras conectar uTP:

1. `CClientReqSocket` queda asociado provisionalmente al intento.
2. Se encola Hello.
3. Se ejecuta la negociación existente.
4. Se valida UserHash y, cuando corresponda, SecureIdent.
5. El DCO recibe `IdentityVerified`.
6. La ruta se nomina y el resto se cancela.
7. La descarga continúa con los mensajes de partes actuales.

### 13.2 Entrada

Tras aceptar uTP:

1. se crea un socket provisional ligado a la expectativa;
2. se limita el tráfico previo a Hello;
3. Hello resuelve o crea el `CUpDownClient`;
4. se comprueba la coherencia con KadID/endpoint esperados;
5. se entrega la sesión al cliente;
6. si hay conflicto de identidad, se cierra y se registra
   `IDENTITY_MISMATCH`.

### 13.3 Confidencialidad

uTP aporta transporte fiable y control de congestión; no cifra por sí solo.
SecureIdent autentica identidad dentro del modelo eMule, pero no debe describirse
como una VPN cifrada general. El núcleo no debe prometer confidencialidad de
todo el flujo si la sesión eD2K elegida no la ofrece.

## 14. Cambios de topología

`CDirectReachabilityManager` ya contiene una generación. Debe publicar un
snapshot inmutable y un evento:

```cpp
OnTopologyGenerationChanged(oldGeneration, newGeneration)
```

Disparadores:

- cambia interfaz o gateway;
- cambia IPv4/IPv6;
- cambia el mapping externo;
- renueva o pierde una lease;
- se suspende/reanuda el equipo;
- cambia el puerto UDP local;
- Kad reinicia su socket.

Respuesta del DCO:

1. marca intentos antiguos `STALE_TOPOLOGY`;
2. cancela transportes;
3. elimina nonces y expectativas;
4. invalida candidatos y rutas recordadas;
5. opcionalmente reintenta con snapshot nuevo si la solicitud sigue viva.

Ningún ACK de la generación anterior puede reanimar el intento.

## 15. Seguridad

### 15.1 Activos

- ancho de banda UDP del peer;
- memoria de pending attempts y expectativas;
- slots uTP y sockets;
- asociación entre identidad y transferencia;
- privacidad de IP/puertos;
- estabilidad de Kad;
- integridad de créditos y bloques.

### 15.2 Atacantes considerados

- atacante off-path que falsifica IP de origen;
- peer Kad malicioso que publica endpoints falsos;
- peer que reenvía o duplica REQ/ACK;
- flood de nonces o puertos;
- varios usuarios tras una misma IP CGNAT;
- callback tardío tras destruir el cliente;
- peer que supera el punch pero anuncia otra identidad.

### 15.3 Controles

- CSPRNG para nonce e `AttemptId`;
- cookie stateless antes de reservar estado a desconocidos;
- cookie con secreto rotatorio y epochs actual/anterior;
- comprobación de KadID cuando existe contacto verificado;
- ACK aceptado solo para un pending local;
- respuesta a desconocido no mayor que la solicitud que la provoca;
- token bucket por IP, prefijo y PeerKey;
- límites globales y por origen;
- endpoint exacto para adopción uTP;
- identidad eD2K antes de datos;
- handles generacionales en vez de punteros persistentes;
- expiración monotónica;
- tamaños exactos y parser fail-closed;
- kill switch;
- logs sin cookie, nonce completo, UserHash completo ni IP pública persistente.

### 15.4 Presupuestos iniciales

| Recurso | Límite |
|---|---:|
| intentos activos globales | 256 |
| intentos por PeerKey | 1 |
| Punch2 pendientes globales | 512 |
| Punch2 por IP pública | 8 |
| expectativas uTP globales | 512 |
| expectativas por IP | 8 |
| TTL pending Punch2 | 15 s |
| TTL expectativa uTP | 12 s |
| challenge echoes por intento | 3 |
| datagramas Punch2 por intento | 6 |
| bytes preautenticación | 16 KiB |
| sockets provisionales por IP | 4 |

Los límites son configurables en tests, pero hard-capped en producción.

## 16. Reason codes

```cpp
enum class DirectFailure : uint16 {
    None,
    Disabled,
    PeerNotCapable,
    NoFreshCandidate,
    NoDirectFamily,
    DirectTcpTimeout,
    CallbackNotApplicable,
    PunchRequestLost,
    PunchChallengeInvalid,
    PunchChallengeLimit,
    PunchAckLost,
    PunchAckUnsolicited,
    PunchIdentityMismatch,
    UtpExpectationMissing,
    UtpAmbiguousEndpoint,
    UtpConnectTimeout,
    UtpTransportError,
    HelloTimeout,
    IdentityMismatch,
    SecureIdentFailed,
    TopologyChanged,
    CancelledByWinner,
    ResourceLimit,
    DirectUnreachable
};
```

El reason code debe describir la última evidencia fiable. No se etiqueta
«NAT simétrica» solo porque venció un timeout; eso es una hipótesis, no una
observación.

## 17. Matriz de cobertura

| Combinación | Núcleo mínimo | Observación |
|---|---|---|
| uno posee IPv6 entrante verificada | Sí, probable | ruta directa v6 |
| uno posee mapping TCP verificado | Sí, probable | conexión TCP normal |
| ambos tras NAT EIM con retorno UDP | Sí, probable | Punch2 |
| EIM + filtering dependiente de dirección/puerto | Sí, a menudo | tráfico coordinado exacto |
| doble NAT doméstico con mapping estable | Posible | depende de todos los niveles |
| mismo CGNAT con hairpin | Posible | se descubre empíricamente |
| un NAT dependiente del destino | Baja | endpoint observado puede cambiar |
| dos NAT simétricos/EDM | Muy baja o nula | sin mapping explícito/IPv6 |
| UDP bloqueado, TCP saliente permitido | No por Punch2 | solo ruta TCP aplicable |
| UDP y TCP entre peers bloqueados | No | no existe camino directo |
| PCP disponible en gateway/CGN | Sí tras mapping | debe verificarse |
| ambos sin conocerse y sin Kad/out-of-band | No | falta señalización |

## 18. El objetivo del 70 %

No debe codificarse una estimación como requisito de protocolo. Se miden dos
ratios distintos:

```text
coverage =
  intentos con al menos una ruta directa aplicable
  ------------------------------------------------
  intentos LowID ↔ LowID elegibles

success_rate =
  intentos con identidad + primer bloque válido
  ------------------------------------------------
  intentos LowID ↔ LowID iniciados
```

También:

```text
route_reliability(route) =
  éxitos autenticados por esa ruta / intentos de esa ruta
```

Un objetivo razonable de piloto es:

- `success_rate ≥ 70 %` en la cohorte de redes donde existe alguna ruta
  directa aplicable;
- publicar aparte el porcentaje de pares físicamente no alcanzables;
- no excluir silenciosamente los fallos difíciles del denominador global.

El porcentaje global solo será defendible con una matriz heterogénea y muchas
repeticiones. La base actual todavía no contiene esa demostración física.

## 19. Mini-VPN

La mini-VPN no forma parte del núcleo porque:

- necesita primero un transporte A ↔ B;
- no evita CGNAT ni abre un firewall;
- añade MTU, direccionamiento virtual, rutas, privilegios y superficie de
  ataque;
- eMule solo necesita un flujo fiable, que `CClientReqSocket` ya consume;
- simular una LAN puede introducir broadcast, spoofing local y conflictos que
  no aportan nada a la transferencia de partes.

Podría añadirse mucho después como API opcional para otras aplicaciones, encima
de una sesión directa ya autenticada. No mejoraría el porcentaje de conexión.

## 20. Cambios por componente

### 20.1 `libreach`

Modificar:

- `include/reach/reach.h`
- `include/reach/reach_types.h`
- `src/reach_engine.h`
- `src/reach_context.cpp`
- `src/reach_cascade.cpp`

Añadir:

- perfil `DirectOnlyV1`;
- `MappedV4`;
- terminal `DirectUnreachable`;
- evento/generación de topología;
- estado `Authenticating` y nominación;
- reason codes;
- API de cancelación de las rutas perdedoras;
- estadísticas por etapa, no solo `resolved_connected`.

El callback `open_transport` no debe reportar éxito final. Reporta
`TransportConnected`; otro callback reporta `IdentityVerified` y, para el gate
end-to-end, `FirstPayloadVerified`.

### 20.2 `ReachabilityWire`

Sustituir la proyección reducida por un DTO completo:

```cpp
bool EseDecodeReachVector(
    const byte* data,
    size_t length,
    EseReachVectorDto* out);
```

El DTO conserva:

- versión;
- caps conocidas;
- caps desconocidas;
- 0–3 anchors, aunque no los use el perfil mínimo;
- expiraciones/tokens;
- trailing bytes.

La reemisión debe ser byte-stable para campos preservados y estricta para
producción propia.

### 20.3 `Search.cpp`

En publicación:

- derivar caps desde snapshots verificados;
- mantener el puerto UDP observable por el indexador;
- publicar IPv6 solo si es global y válida;
- no anunciar Punch2 si uTP/socket/gate no están listos.

En lectura:

- crear `RemoteReachSnapshot`;
- conservar endpoint observado y su testigo;
- deduplicar observaciones;
- aplicar TTL;
- no convertir KadID en UserHash;
- entregar el snapshot al DCO.

### 20.4 `CDirectReachabilityManager`

- devolver snapshots por valor o referencia inmutable;
- emitir cambio de generación;
- exponer origen y evidencia de cada mapping;
- invalidar lease al expirar;
- no marcar «verified» solo por recibir respuesta de UPnP/NAT-PMP/PCP;
- permitir al DCO consultar candidates sin mutar estado.

La activación real de `libnatmap` exige terminar su gate D1; hoy su propia
documentación mantiene la integración de red de producción deshabilitada.

### 20.5 Nuevo `CDirectConnectionOrchestrator`

Archivos propuestos:

```text
srchybrid/DirectConnectionOrchestrator.h
srchybrid/DirectConnectionOrchestrator.cpp
srchybrid/DirectConnectionAdapters.h
srchybrid/DirectConnectionAdapters.cpp
```

API host:

```cpp
AttemptHandle Connect(
    const PeerKey& peer,
    const RemoteReachSnapshot& remote,
    ConnectionPurpose purpose);

void OnPunchMessage(...);
void OnTransportConnected(...);
void OnTransportFailed(...);
void OnIdentityVerified(...);
void OnFirstPayloadVerified(...);
void OnTopologyChanged(...);
void Cancel(...);
void Process(uint64 nowMs);
```

`ConnectionPurpose` permite que varias descargas reutilicen una conexión sin
crear varios Punch2 para el mismo peer.

### 20.6 `CUpDownClient`

- sustituir counters/timers Punch2 por un `AttemptHandle`;
- delegar la decisión desde `TryToConnect`;
- conservar presentación y estado de descarga;
- reportar Hello/SecureIdent al DCO;
- limpiar el handle en teardown;
- no ejecutar el hard-fail LowID ↔ LowID antes de consultar el DCO.

### 20.7 `KademliaUDPListener`

- mantener parsing exacto de 22/26/38 bytes;
- mover pending attempts al DCO o a un adapter identificado por handle;
- eliminar `CUpDownClient*` persistente del pending wire state;
- tratar CHALLENGE y ACK como eventos, no como éxito;
- conservar cookie y rate limits;
- no llamar directamente a `InitiateUtpConnect` fuera de la orden del DCO.

### 20.8 `CClientUDPSocket`

- registrar expectativa tipada;
- devolver un identificador/resultado;
- garantizar el mismo socket Kad/uTP;
- informar de fallo de envío;
- iniciar uTP con handle, no buscando el cliente por IP como autoridad.

### 20.9 `CUtpSocket`

- expectativas por intento y generación;
- exact-match en perfil mínimo;
- provisional socket;
- callback de transporte al DCO;
- tie-break determinista;
- cleanup idempotente;
- eliminar el contador Punch2 de `UTP_STATE_CONNECT`; el DCO lo contabiliza en
  el estado correcto.

### 20.10 Consumidores

La primera entrega debe integrar descargas normales. LiveTV puede consumir la
misma sesión después, pero no debe obligar a incluir su selector/relay en el
MVP. Mientras tanto, el gate del núcleo directo debe impedir que LiveTV se use
como ruta alternativa oculta.

## 21. Compatibilidad

### 21.1 Peer sin `TAG_ESE_REACH`

- no entra en `DirectOnlyV1`;
- conserva conexión/callback clásico;
- no recibe paquetes Punch2 modernos.

### 21.2 Peer con Punch2 antiguo

Durante laboratorio se puede usar el wire actual con cookie si ambos han
consentido NetLab. No se rebaja a una variante insegura para un origen
desconocido.

### 21.3 Vector futuro

- versión desconocida: parsear solo el prefijo permitido o rechazar de forma
  compatible;
- caps desconocidas nunca habilitan una ruta;
- trailing se preserva;
- límites de 255 bytes y número de anchors se mantienen.

### 21.4 Función desactivada

Con `DirectCoreEnabled=false`:

- no se anuncia capability nueva;
- no se emite Punch2;
- no se crean expectativas;
- el comportamiento clásico no cambia.

## 22. Preferencias y rollout

```text
DirectCoreEnabled             OFF en desarrollo inicial
DirectCorePunch2Enabled       OFF hasta pasar simulación
DirectCoreExactEndpointOnly   ON y no editable en producción
DirectCoreNetLabConsent       consentimiento explícito
```

No exponer al usuario:

- spread de puertos;
- límites de seguridad;
- «forzar éxito»;
- bypass de identidad.

Fases:

1. `Shadow`: el selector calcula qué haría, pero no abre rutas.
2. `Lab`: dos instancias controladas, Punch2 exacto.
3. `Private alpha`: consentimiento explícito y métricas locales.
4. `Beta`: capability pública solo para participantes.
5. `Default-on`: únicamente tras seguridad, compatibilidad y evidencia física.

El kill switch:

- retira la capability en el siguiente anuncio;
- cancela intentos en menos de cinco segundos;
- no cierra conexiones ya autenticadas salvo que el usuario lo solicite;
- impide nuevos REQ.

## 23. Pruebas

### 23.1 Unitarias puras

- todas las combinaciones de capabilities;
- orden exacto de rutas;
- terminal sin relay;
- deadlines;
- evento stale;
- single-winner;
- cierre reentrante;
- handle reutilizado;
- mapping expirado;
- vector malformed/futuro;
- reason codes.

### 23.2 Modelo Punch2

Inyectar:

- pérdida individual de REQ, CHALLENGE, REQ+cookie, ACK y SYN;
- duplicación y reorder;
- nonce equivocado;
- cookie vieja, de otra IP o de otro target;
- KadID distinto;
- ACK no solicitado;
- cambio de generación en cada transición;
- dos peers bajo la misma IP pública;
- intento cancelado antes de SYN;
- SYN después del deadline.

### 23.3 Integración de dos procesos

Topologías emuladas:

| ID | A | B | Resultado |
|---|---|---|---|
| N1 | pública | pública | directo |
| N2 | EIM/EIM | EIM/EIM | Punch2 |
| N3 | EIM/APDF | EIM/APDF | Punch2 |
| N4 | doble NAT estable | EIM | Punch2 posible |
| N5 | EDM | EIM | fallo directo acotado |
| N6 | EDM | EDM | `DIRECT_UNREACHABLE` |
| N7 | UDP bloqueado | EIM | no Punch2 |
| N8 | IPv6 global | CGNAT v4 | IPv6 |
| N9 | mapping PCP | CGNAT | mapeada |
| N10 | cambio de IP durante ACK | EIM | stale, reintento limpio |

Para cada una:

- 100 rondas por sentido;
- pérdida 0 %, 1 %, 5 % y 10 %;
- delay 20/100/500 ms;
- reorder y duplicación;
- cero sockets/handles al terminar.

### 23.4 Gate físico

Mínimo:

- fibra doméstica ↔ fibra doméstica;
- fibra ↔ tethering móvil CGNAT;
- dos operadores móviles;
- doble NAT ↔ doméstica;
- IPv6 dual-stack ↔ CGNAT IPv4;
- red que bloquea UDP;
- router con UPnP/NAT-PMP;
- red/ISP con PCP si se dispone.

Cuatro rondas por sentido no bastan para estimar el 70 %. Para el porcentaje:

- al menos 30 intentos por celda;
- repetir en días/horas distintos;
- registrar operador y clase de NAT de forma anonimizada;
- intervalos de confianza;
- separar incompatibilidad física de defecto de implementación.

### 23.5 Transferencia real

Un PASS end-to-end exige:

- identidad esperada;
- ruta nominada única;
- archivo de al menos 4 GiB;
- hash final correcto;
- reconexión tras pérdida;
- cero bloques duplicados en contabilidad;
- cero bytes de archivo en testigos Kad;
- memoria y handles estables en 100 ciclos.

## 24. Métricas locales

Por intento:

```json
{
  "attempt": "hash-efimero",
  "topology_generation": 42,
  "candidate_count": 2,
  "route": "punch2",
  "stage": "first_payload_verified",
  "elapsed_ms": 1834,
  "failure": "none",
  "relay_payload_bytes": 0
}
```

Contadores:

- `direct_attempts_total`;
- `direct_candidate_pairs`;
- `direct_v6_connected`;
- `direct_v4_connected`;
- `mapped_v4_connected`;
- `punch2_req_sent/received`;
- `punch2_challenge_sent/validated/rejected`;
- `punch2_ack_received`;
- `utp_transport_connected`;
- `identity_verified/rejected`;
- `first_payload_verified`;
- `cancelled_by_winner`;
- `stale_event_ignored`;
- `direct_unreachable`;
- `relay_payload_bytes`, que debe ser siempre cero.

No guardar IP pública completa ni identidad completa en informes exportables.

## 25. Gates de aceptación

### Gate A: arquitectura

- una sola autoridad de ruta;
- perfil directo sin relay;
- handles generacionales;
- DTO completo de vector;
- reason codes estables.

### Gate B: seguridad

- cookie hostil pasa;
- no hay estado antes de return-routability para desconocidos;
- endpoint exacto;
- límites bajo flood;
- identidad antes de datos;
- fuzz/parser verde.

### Gate C: transporte

- Punch2 abre uTP en simulación EIM;
- mismo socket UDP comprobado;
- ACK no cuenta como éxito;
- conexión perdedora se cancela;
- cambio de topología no deja huérfanos.

### Gate D: eD2K

- Hello/SecureIdent correctos;
- primer bloque válido;
- 4 GiB con hash correcto;
- exactly-once.

### Gate E: físico

- matriz real reproducible;
- éxito y fallo correctamente clasificados;
- ninguna afirmación de 70 % sin muestra suficiente;
- ningún byte de payload atraviesa terceros.

## 26. Orden de implementación

### M0 — Congelar semántica

- definir `AttemptId`, `PeerKey`, generaciones y éxito;
- añadir tests que demuestren los fallos actuales;
- congelar baseline.

### M1 — Snapshot completo

- ampliar `ReachabilityWire`;
- construir `RemoteReachSnapshot`;
- exponer `LocalReachSnapshot`;
- tests de codec/publicación/ingestión.

### M2 — DCO en shadow mode

- perfil `DirectOnlyV1`;
- reducer y reason codes;
- adapter host;
- comparar decisiones DCO con flujo actual sin actuar.

### M3 — Rutas directas

- IPv6/IPv4/mapped/callback gobernadas por DCO;
- generación y cancelación;
- single-winner.

### M4 — Punch2

- pending state por handle;
- CHALLENGE/ACK como eventos;
- expectativa uTP exacta;
- resultado uTP al DCO;
- retirar contador de éxito en ACK.

### M5 — Identidad y transferencia

- provisional sockets;
- Hello/SecureIdent;
- nominación;
- primer bloque válido;
- 4 GiB y reconexión.

### M6 — Laboratorio físico

- dos hosts;
- múltiples redes;
- informe por matriz;
- decisión basada en datos sobre Punch3 o mejoras posteriores.

## 27. Estimación del núcleo

Estimación orientativa para una persona senior que conozca el árbol:

| Bloque | JP |
|---|---:|
| contratos, tests rojos y baseline | 2–3 |
| snapshots/vector/wire | 4–6 |
| DCO y `libreach` directo | 7–10 |
| integración rutas directas | 4–6 |
| refactor Punch2 | 5–8 |
| uTP provisional + identidad | 6–9 |
| métricas, kill switch y compatibilidad | 3–5 |
| harness y pruebas | 7–11 |
| laboratorio físico y estabilización | 5–9 |
| **total** | **43–67 JP** |

Rango natural: unas 9–14 semanas de trabajo concentrado para una persona,
además del tiempo de espera de pruebas físicas. Si se incluye Punch3,
predicción, LiveTV y mini-VPN, deja de ser el núcleo mínimo.

## 28. Definition of Done

El núcleo está terminado cuando:

- [ ] `LowID->LowID` no provoca hard-fail antes del selector;
- [ ] el DCO es el único propietario de orden y ganador;
- [ ] el perfil directo no contiene relay, Punch3 ni predicción;
- [ ] todos los candidatos tienen evidencia, TTL y generación;
- [ ] Punch2 usa cookie y endpoint exacto;
- [ ] señalización y uTP usan el mismo socket UDP;
- [ ] pending state y expectativas no guardan punteros host persistentes;
- [ ] ACK no se presenta como éxito;
- [ ] transporte sin identidad no se presenta como éxito;
- [ ] solo el primer bloque válido demuestra transferencia;
- [ ] una sola ruta y una sola sesión ganan;
- [ ] eventos stale son inocuos;
- [ ] kill switch y cleanup son acotados;
- [ ] peers antiguos no empeoran;
- [ ] el archivo de 4 GiB conserva hash;
- [ ] 100 ciclos dejan cero recursos huérfanos;
- [ ] pruebas físicas separan éxito, incompatibilidad y defecto;
- [ ] `relay_payload_bytes == 0`;
- [ ] cualquier porcentaje publicado tiene muestra y denominador explícitos.

## 29. Conclusión

La idea potente no es «hacer que dos LowID crean estar en una LAN». Es dejar de
usar LowID como sentencia definitiva.

Kad ya puede proporcionar descubrimiento distribuido; el tráfico saliente puede
crear estado en NAT/firewalls; Punch2 ya puede coordinar ambos extremos; uTP ya
puede transportar un flujo; eMule ya sabe autenticar al peer y transferir
partes. El núcleo mínimo consiste en unir esas capacidades bajo una autoridad
determinista, con identidad, generación, un único ganador y una definición
honesta de éxito.

Eso no derrota las leyes de enrutamiento. Sí puede convertir muchas parejas
clasificadas hoy como imposibles en conexiones directas útiles, sin convertir la
red en una infraestructura centralizada y sin que ningún tercero transporte el
archivo.

## 30. Referencias técnicas

- RFC 5128, *State of Peer-to-Peer Communication across NATs*:
  https://www.rfc-editor.org/rfc/rfc5128
- RFC 4787, *NAT Behavioral Requirements for Unicast UDP*:
  https://www.rfc-editor.org/rfc/rfc4787
- RFC 8445, *Interactive Connectivity Establishment (ICE)*:
  https://www.rfc-editor.org/rfc/rfc8445
- RFC 8489, *Session Traversal Utilities for NAT (STUN)*:
  https://www.rfc-editor.org/rfc/rfc8489
- RFC 6887, *Port Control Protocol (PCP)*:
  https://www.rfc-editor.org/rfc/rfc6887
- BEP 29, *uTorrent transport protocol*:
  https://www.bittorrent.org/beps/bep_0029.html

