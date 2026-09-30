# La abolición del LowID: separación de identidad y alcanzabilidad en la red Kad de eSE

**Autor:** diad (mantenedor de eMule eSE)
**Afiliación:** Independiente
**Versión:** 1.0 — 2026-06-11
**Estado:** Tesis de diseño — **no implementado**. Documento para el futuro (calibre v9).
**Prerequisito:** [LOWID_NAT_TRAVERSAL_PLAN.md](LOWID_NAT_TRAVERSAL_PLAN.md) (fases 0–4) validado end-to-end.
**Relacionados:** IPV6_PLAN.md, IPV6_ANALYSIS.md, PAPER_eSE_Live_ES.md (§ identidad por túnel), monografía Kad Search v2.

---

## Resumen

El par LowID/HighID es la decisión de diseño más longeva y más dañina
heredada de eDonkey2000: codifica la **alcanzabilidad de red** de un nodo
dentro de su **identidad**, y la degrada a un bit. Un nodo o es su
dirección IPv4 (HighID) o es la confesión de que no la tiene (LowID), y
toda la red — publicación de fuentes, callbacks, tablas de rutas,
interfaz de usuario — está cosida alrededor de ese bit. Esta tesis
sostiene que el concepto puede **abolirse** en la red Kad del fork eSE
sin romper la compatibilidad con eMule 0.70b, sustituyéndolo por dos
nociones independientes: una **identidad estable** (el NodeID de 128
bits que Kad ya posee, reforzable con clave pública) y un **vector de
alcanzabilidad** multidimensional, temporal y negociable, consumido por
una **cascada de conexión** estilo ICE que elige en privado el mejor
camino entre dos peers cualesquiera. Demostramos que el fork ya ha
eliminado el concepto en su subsistema más nuevo (el mesh de Live se
indexa por `TunnelEndpoint`/`circ_id`, nunca por IP), que la fontanería
necesaria está parcialmente construida (uTP activo, hole-punch 2-vías
cableado, rendezvous 3-vías y keepalive en esqueleto, cascada
`FirewallProberV6` prevista, tags IPv6 reservados), y que el paso
restante no es un mecanismo más de traversal sino un **cambio de modelo
de datos**: publicar fuentes por identidad+capacidades en vez de por
IP+tipo, con doble publicación para los nodos upstream. Analizamos el
estado del arte (Tor, libp2p, ICE/WebRTC, BitTorrent DHT), el límite
físico ineliminable (un nodo no alcanzable no puede enrutar la DHT — y
por qué eso no importa), la matriz de compatibilidad, los vectores de
abuso del nuevo plano de rendezvous/relay, y una hoja de ruta con
*gates* medibles. Definimos además el **componente publicable** —
especificación abierta (KEP-1) más librería de referencia embebible al
estilo libutp, con registro de números y suite de conformidad — para
que otros clientes del ecosistema (mods de eMule, aMule, jed2k) adopten
la misma agnosticidad y evolucionen con ella sin flag-days. La
conclusión operativa: el LowID no se arregla — se deja de modelar.

**Palabras clave:** Kademlia, eD2K, LowID, NAT traversal, identidad
descentralizada, ICE, hole punching, uTP, rendezvous, relays
voluntarios, compatibilidad hacia atrás, especificación abierta,
interoperabilidad.

---

## Índice

1. Introducción: el bit que se comió la red
2. Anatomía del concepto en el código actual
3. Tesis central: identidad ≠ alcanzabilidad
4. Estado del arte: cómo lo eliminaron los demás
5. Inventario eSE: lo que ya está construido
6. Diseño I — el registro de fuente v2 y el vector de alcanzabilidad
7. Diseño II — la cascada de conexión
8. Diseño III — rendezvous generalizado y relays voluntarios
9. La DHT: lo que no se puede abolir (y por qué da igual)
10. Compatibilidad hacia atrás: doctrina y matriz de interoperabilidad
11. Análisis adversarial
12. Cuantificación: cobertura, coste y residuo
13. Más allá del fork: el componente publicable para el ecosistema
14. Hoja de ruta, gates y criterio de oportunidad
15. Conclusión

Apéndices: A) TLV del vector de alcanzabilidad · B) Pseudocódigo de la
cascada · C) Glosario · D) Mapa documental · E) Boceto de la superficie
de `libreach`

---

## 1. Introducción: el bit que se comió la red

### 1.1 Origen histórico

En 2002, eDonkey2000 necesitaba que los clientes se conectaran entre sí
y la mayoría de Internet doméstica aún no estaba detrás de NAT. La
solución fue directa: el servidor comprueba si puede abrir una conexión
TCP de vuelta hacia el cliente; si puede, le asigna como identificador
**su propia dirección IPv4** interpretada como entero de 32 bits
(HighID, valores > 0x00FFFFFF); si no puede, le asigna un número de
sesión arbitrario pequeño (LowID, < 16777216). El identificador del
nodo y su dirección de red quedaron fusionados en el mismo campo.

Cuando eMule añadió Kademlia (2004), la DHT eliminó el servidor pero
**heredó el binario**: un nodo Kad es "open" o "firewalled", y esa
distinción se propaga por todo el sistema — qué se publica, cómo se
conecta, quién enruta. El nombre cambió; el concepto no.

### 1.2 El coste real, veinte años después

En 2026 la mayoría de los usuarios domésticos está detrás de NAT, una
fracción creciente detrás de CGNAT (donde abrir puertos es imposible
por definición), y el binario LowID produce tres daños distintos que
conviene separar, porque tienen soluciones distintas:

1. **El bloqueo total LowID↔LowID.** Dos nodos no alcanzables no pueden
   intercambiar nada entre sí. Es el daño grave: a medida que crece la
   proporción de nodos NATeados, la fracción de pares inutilizables
   crece cuadráticamente.
2. **El estatus de segunda clase.** Un LowID necesita intermediarios
   (servidor, buddy) para ser contactado, consume recursos de terceros
   y aparece menos en los resultados.
3. **El estigma de interfaz.** La flecha amarilla / el semáforo LowID
   le dice al usuario "estás mal configurado", cuando en CGNAT no hay
   nada que él pueda configurar. El concepto culpa al usuario de la
   topología de su ISP.

### 1.3 Qué afirma (y qué no afirma) esta tesis

**Afirmamos** que el *concepto* LowID/HighID — la alcanzabilidad como
atributo binario de la identidad, visible en el modelo de datos, el
protocolo y la UI — puede eliminarse de la red Kad entre nodos eSE,
manteniendo intacta la interoperabilidad con clientes 0.70b.

**No afirmamos** que la física desaparezca. Un nodo detrás de un NAT
simétrico sin IPv6 sigue sin poder recibir paquetes no solicitados;
ningún protocolo cambia eso. Lo que cambia es que esa condición deja de
ser una *identidad* ("soy LowID") y pasa a ser una *propiedad temporal
de transporte* ("hoy se me alcanza vía punch o relay"), gestionada por
la pila y, en el caso ideal, invisible para el usuario y para el resto
de la red.

La diferencia no es cosmética. Es la misma que separa "este host es
inalcanzable" de "esta llamada eligió la ruta TURN": en WebRTC nadie
tiene LowID, y sin embargo los NATs son los mismos.

---

## 2. Anatomía del concepto en el código actual

Para abolir un concepto hay que saber dónde vive. Esta sección
inventaría los puntos de acoplamiento en la base de código del fork
(auditoría 2026-06-11). Es el "mapa de demolición": cada subsección es
un sitio donde el binario open/firewalled está cosido al sistema.

### 2.1 Detección: cómo un nodo aprende su propio bit

- **UDP.** `CUDPFirewallTester`
  (`srchybrid/kademlia/kademlia/UDPFirewallTester.cpp`) pide a 2
  contactos Kad aleatorios (`UDP_FIREWALLTEST_CLIENTSTOASK = 2`, línea
  37) que le envíen un paquete de prueba. Mantiene tres estados:
  `m_bFirewalledUDP`, `m_bIsFWVerifiedUDP` y `m_bTimedOut` (timeout a
  los 6 minutos). "Verificado" = al menos un resultado positivo, o
  ambos tests fallidos (líneas 79–166, 264–266).
- **TCP.** No hay test activo: `m_uFirewalled` en `Prefs` se infiere de
  conexiones entrantes fallidas/exitosas (`GetFirewalled()`).
- **Difusión.** El propio bit viaja en los hellos Kad dentro de
  `TAG_KADMISCOPTIONS` (bit 0x01 = UDP firewalled, bit 0x02 = TCP
  firewalled; `KademliaUDPListener.cpp:613–614`). Es decir: el nodo
  **se etiqueta a sí mismo** ante toda la red.

### 2.2 Publicación: el bit decide qué eres en el índice

Cuando un nodo se publica como fuente de un fichero, el *tipo* de
registro que emite está dictado por su bit (`Search.cpp:700–748`):

| Tipo | Condición | Contenido distintivo |
|---|---|---|
| 1 | HighID, ≤4 GB | `TAG_SOURCEPORT` (TCP directo) |
| 3 | LowID con buddy, ≤4 GB | `TAG_SERVERIP/PORT` (¡la IP del buddy!), `TAG_BUDDYHASH` |
| 4 | HighID, >4 GB | como 1 |
| 5 | LowID con buddy, >4 GB | como 3 |
| 6 | LowID con UDP abierto y verificado | `TAG_SOURCEPORT` + `TAG_SOURCEUPORT` (callback UDP directo) |

Obsérvese la asimetría conceptual: un HighID publica *su dirección*; un
LowID publica *la dirección de otro* (su buddy). La identidad del nodo
firewalled está literalmente expresada en términos de un tercero. Los
tags relevantes (`Opcodes.h:468–534`): `TAG_SOURCETYPE` (0xFF),
`TAG_SOURCEIP` (0xFE), `TAG_SOURCEPORT` (0xFD), `TAG_SERVERIP` (0xFB),
`TAG_SERVERPORT` (0xFA), `TAG_BUDDYHASH` (0xF8), `TAG_ENCRYPTION`
(0xF3). El fork ya reservó `TAG_SOURCEIP_V6` (0x66) y `TAG_SERVERIP_V6`
(0x67), con lado receptor reconocido y emisor pendiente
(`Search.cpp:1216–1228`).

### 2.3 Conexión: cuatro caminos, elegidos por el bit

El descargador decide cómo contactar una fuente según su
`TAG_SOURCETYPE` (`BaseClient.cpp`):

1. **Directo TCP** (tipos 1/4): conectar a `TAG_SOURCEIP:PORT`.
2. **Callback por servidor** (legacy, líneas 1620–1628):
   `OP_CALLBACKREQUEST` vía servidor eD2K común.
3. **Callback por buddy** (tipos 3/5, líneas 1630–1643):
   `KADEMLIA_CALLBACK_REQ` por UDP al buddy, que lo reenvía por su
   conexión TCP viva con el firewalled; éste conecta *hacia fuera*.
4. **Callback UDP directo** (tipo 6, líneas 1539–1554):
   `OP_DIRECTCALLBACKREQ` directo al puerto UDP abierto del LowID.

A esto el fork ya añadió un quinto camino extensión: **hole-punch
2-vías + uTP** (`OP_ESE_HOLEPUNCH_REQ`, `BaseClient.cpp:1556–1609`,
handlers en `KademliaUDPListener.cpp:2181–2340`), con backoff
adaptativo y diagnóstico de NAT simétrico a los 4 intentos.

Nótese que los caminos 2–4 comparten un requisito silencioso: **el que
llama debe ser alcanzable**, porque todos terminan con el firewalled
conectando hacia fuera, hacia el llamante. Por eso LowID↔LowID es un
bloqueo total en upstream: no hay extremo capaz de recibir.

### 2.4 Enrutado: el bit decide si existes para la DHT

`AddContact_KADEMLIA2` (`KademliaUDPListener.cpp:586–657`) descarta a
los nodos UDP-firewalled en la línea 652: **jamás entran en la tabla de
rutas de nadie**. Las búsquedas Kad nunca atraviesan un nodo
firewalled; éstos son consumidores puros de la DHT (publican y buscan,
no enrutan). Esta exclusión es correcta — un router que no recibe
paquetes no puede enrutar — pero es la única consecuencia del bit que
la física impone de verdad. Todas las demás son decisiones de diseño.

### 2.5 El buddy: un rol con tres defectos estructurales

El buddy system (`ClientList.cpp:602–627`) empareja cada nodo
firewalled con exactamente **un** nodo abierto (búsqueda Kad hacia el
ID invertido, `GetKadID() XOR ~0`). Defectos:

1. **Punto único de fallo:** si el buddy cae, el firewalled es
   inalcanzable hasta re-emparejar (segundos a minutos de sombra).
2. **Identidad delegada:** la IP del buddy se publica *como si fuera*
   la del firewalled (§2.2), acoplando la vida del registro de fuente a
   la vida de la pareja.
3. **Solo señalización TCP:** el buddy reenvía callbacks; nunca ayuda a
   abrir caminos UDP ni transporta datos. Es un recurso desaprovechado:
   mantiene exactamente la conexión viva que un rendezvous de hole
   punching necesita (el plan NAT-traversal, Fase 1, ya explota esto).

### 2.6 Interfaz: el bit como juicio moral

La UI hereda el semáforo: flecha/icono LowID, avisos de "revisa tu
router". Todo el lenguaje visual presenta la no-alcanzabilidad como un
defecto del usuario. En CGNAT es falso y, lo que es peor para la red,
**desincentiva compartir**: el usuario "LowID" interioriza que su nodo
es de segunda y aporta menos.

### 2.7 Síntesis del capítulo

El bit vive en seis sitios: autodetección difundida (§2.1), esquema de
publicación (§2.2), selección de camino (§2.3), admisión a la tabla de
rutas (§2.4), emparejamiento buddy (§2.5) y UI (§2.6). De los seis,
solo §2.4 refleja una restricción física. Los otros cinco son
abolibles. Ése es exactamente el perímetro de esta tesis.

---

## 3. Tesis central: identidad ≠ alcanzabilidad

### 3.1 Formulación

> **Tesis.** En una red P2P, la identidad de un nodo debe ser una clave
> estable e independiente del transporte; su alcanzabilidad debe ser un
> **vector de capacidades** multidimensional, temporal y negociable; y
> la conexión entre dos nodos debe ser el resultado de una
> **negociación de caminos** privada entre sus dos vectores, invisible
> para el resto de la red y para el modelo de datos.

El LowID/HighID es lo que resulta de violar las tres cláusulas a la
vez: identidad = dirección de transporte; alcanzabilidad = proyección a
un bit; conexión = lectura estática de ese bit por parte de extraños.

### 3.2 El vector de alcanzabilidad

Definimos el vector `R` de un nodo eSE como (detalle wire en Apéndice A):

```
R = {
  v4_tcp_in   : bool      # acepta TCP entrante por IPv4 (HighID clásico)
  v4_udp_in   : bool      # acepta UDP no solicitado (≈ tipo 6 / verificado)
  v6_in       : bool      # alcanzable por IPv6 (probe inbound real, no egress)
  punch_2w    : bool      # soporta hole-punch directo (OP_ESE_HOLEPUNCH_*)
  punch_3w    : bool      # acepta punch coordinado por rendezvous (KADEMLIA3_*)
  keepalive   : bool      # mantiene pinhole activo (Fase 2 del plan)
  relay_offer : bool      # se ofrece como relay/rendezvous (nodo abierto voluntario)
  rdv[≤3]     : lista     # puntos de rendezvous vivos: (KadID, IP:puerto UDP)
}
```

Propiedades deliberadas:

- **Es temporal.** `R` cambia cuando cambia la red (roaming, ISP, hora
  del día). Se publica con TTL corto y se re-verifica al conectar.
  Nada en el sistema puede cachearlo como atributo permanente.
- **Es multidimensional.** Un nodo CGNAT-v4 con buen IPv6 es
  perfectamente alcanzable (v6_in=1) aunque su proyección clásica sea
  "LowID". Un nodo v4-abierto sin v6 también lo es. La proyección a un
  bit destruía exactamente esta información.
- **Es par-relativa en su efecto.** La pregunta correcta nunca es
  "¿es alcanzable el nodo B?" sino "¿qué camino existe entre A y B?".
  Dos vectores pobres pueden componer un camino rico (ambos punchables
  vía un rendezvous común); el bit no podía expresar eso.

### 3.3 La identidad

Kad ya tiene el sustrato: el **NodeID de 128 bits**. La tesis lo adopta
como clave primaria del registro de fuente v2 (§6) y prevé el refuerzo
criptográfico — NodeID derivado de clave pública Ed25519, como ya hace
el subsistema Live con `remote_pubkey` en `TunnelEndpoint`
(`LiveTunnel.h:49–52`) — como extensión natural, necesaria en cuanto el
rendezvous/relay maneje terceros (anti-suplantación, §11). El precedente
interno es decisivo: **el fork ya abolió el concepto una vez**. El mesh
de Live se indexa por `circ_id`/`TunnelEndpoint` y la identidad de un
peer de streaming es su circuito, no su IP ([PAPER_eSE_Live_ES.md],
decisión registrada como "identidad de peer Live = TunnelEndpoint,
nunca IP"). Esta tesis es la generalización de esa decisión al
intercambio clásico.

### 3.4 Corolarios

1. **El LowID deja de publicarse.** Entre nodos eSE nadie declara "soy
   firewalled"; declara su `R`. La palabra desaparece del protocolo
   nuevo (sigue en el clásico por compatibilidad, §10).
2. **El estigma desaparece de la UI.** El usuario ve "Conectado:
   directo v6" o "Conectado: punch" o "Conectado: relay" — estados de
   ruta, no juicios de identidad (§7.5).
3. **El buddy se disuelve en dos roles limpios:** rendezvous (varios,
   baratos, para señalización) y relay (voluntario, capado, para datos
   residuales) — §8.

---

## 4. Estado del arte: cómo lo eliminaron los demás

Nadie eliminó la física; los sistemas maduros eliminaron el *concepto*.
Cuatro referencias, de más radical a más cercana:

### 4.1 Tor: rendezvous puro

Un onion service no tiene dirección pública en absoluto — su identidad
es una clave. Publica *introduction points* en una DHT; el cliente y el
servicio se citan en un *rendezvous point* al que **ambos conectan
hacia fuera**. Resultado: dos extremos firewalled se comunican sin que
el concepto "firewalled" exista en el protocolo. Coste: todo el tráfico
pasa por relays (latencia y ancho de banda donados). Lección para eSE:
el rendezvous-al-que-ambos-llaman es la única primitiva que funciona en
prácticamente cualquier red que permita conexiones salientes (que no es
el 100%: el egress filtering existe); resérvese para el residuo, no
para el caso común.
El fork ya tiene esta primitiva construida para el plano de control de
Live (túneles onion, `LiveTunnel.cpp`).

### 4.2 libp2p (IPFS): la pila que negocia

La referencia arquitectónica más directa para esta tesis:

- **PeerID** = hash de clave pública. Las direcciones son una *lista*
  de multiaddrs adjunta, versionada y temporal — exactamente la
  relación identidad/vector del §3.
- **AutoNAT** = el `UDPFirewallTester` generalizado: los pares te
  prueban desde fuera y te dicen qué eres.
- **DCUtR** (Direct Connection Upgrade through Relay): los dos peers se
  coordinan *a través de un relay ya conectado* para perforar y
  **promocionar** la conexión a directa. Es la Fase 1 del plan
  NAT-traversal con otro nombre: el buddy como coordinador de punch.
- **Circuit Relay v2**: relays voluntarios con reservas capadas — el
  diseño exacto del §8.2.
- **DHT client/server mode**: los nodos no alcanzables participan en la
  DHT como *clientes* (consultan, no enrutan) y **nadie lo considera un
  estigma**. Es la normalización formal de lo que Kad ya hace en
  `KademliaUDPListener.cpp:652` (§2.4 y §9).

### 4.3 ICE/WebRTC: la cascada estandarizada

ICE (RFC 8445) formaliza la negociación de caminos: reunir candidatos
(host, reflexivo, relay), probarlos por pares ordenados por prioridad,
quedarse con el mejor, mantenerlo con keepalives. La industria entera
de la videollamada corre sobre esto; "LowID" no existe en su
vocabulario. La cascada del §7 es ICE adaptado a Kad: candidatos = el
vector `R`, STUN = los propios peers Kad, TURN = relays voluntarios.

### 4.4 BitTorrent DHT: el contraejemplo

Mainline DHT *no* resolvió el problema: los nodos NATeados son
pasivos, los registros anuncian IP:puerto crudo y el traversal quedó en
extensiones dispares (uTP ayudó al transporte, no al rendezvous).
Resultado conocido: enjambres donde los peers NATeados se ven pero no
se conectan. Es el futuro que esta tesis quiere evitar: tener uTP y
punching *mecánicos* (el plan de fases) sin cambiar el *modelo de
datos* deja el concepto vivo y el residuo mal gestionado.

### 4.5 Síntesis

| Sistema | Identidad | Alcanzabilidad | Concepto "LowID" |
|---|---|---|---|
| eD2K/Kad clásico | IP (o sesión) | 1 bit público | central |
| BitTorrent DHT | IP:puerto | implícita | de facto |
| Tor | clave | no aplica (rendezvous) | inexistente |
| libp2p | clave (PeerID) | lista de multiaddrs + negociación | inexistente |
| WebRTC/ICE | sesión/identidad app | candidatos negociados | inexistente |
| **eSE (esta tesis)** | **NodeID (→ clave)** | **vector `R` + cascada** | **abolido entre eSE; emulado hacia upstream** |

---

## 5. Inventario eSE: lo que ya está construido

La tesis no parte de cero; parte de un fork que ya recorrió dos tercios
del camino sin nombrarlo. Auditoría (2026-06-11):

| Pieza | Estado | Evidencia |
|---|---|---|
| Identidad sin IP (precedente) | **Hecho en Live** | `TunnelEndpoint{circ_id, remote_pubkey}` (`LiveTunnel.h:49–52`); mesh por circuito |
| uTP (libutp) | **Activo** | submódulo `libutp/`, `eMuleAI/UtpSocket.cpp`, feed UDP en `ClientUDPSocket.cpp:93` |
| Hole-punch 2-vías | **Cableado, sin validar 2-PC** | `OP_ESE_HOLEPUNCH_REQ`, `BaseClient.cpp:1556–1609`, `KademliaUDPListener.cpp:2181–2340` |
| Hole-punch 3-vías (rendezvous) | Esqueleto | `HolePuncher.cpp` (TODOs líneas 62/84/105), `KADEMLIA3_HOLEPUNCH_*` (`Opcodes.h:727`) |
| Keepalive de pinhole | Esqueleto | `KadKeepalive.cpp` |
| Cascada de capas | Esqueleto | `FirewallProberV6.cpp` (`Try*()` stubs, líneas 163, 197–201) |
| Transporte dual-stack v6 | Activo opt-in | `ListenSocket.cpp:2441`, fix `GetPeerAddressV4` pendiente de validar |
| Tags v6 en registros Kad v4 | Reservados | `TAG_SOURCEIP_V6` 0x66 / `TAG_SERVERIP_V6` 0x67, RX reconocido (`Search.cpp:1216–1228`) |
| Relay onion (datos) | Arquitectura control completa; datos = Sprint E-β | `LiveTunnel.cpp`, `ESE_CAP_TUNNEL_DATAPLANE` (bit 12) |
| Cap bits de anuncio | Mecanismo en uso | `TAG_ESE_CAPS` / `CAP_FORK_*`; plan reserva bits 13–14 |
| Punto de tick | Disponible | `Kademlia.cpp:227` (loop ~1 s) |

Lectura: **toda la mecánica de la tesis o existe o está planificada**
en LOWID_NAT_TRAVERSAL_PLAN.md. Lo que ningún documento cubre todavía —
y es la contribución específica de esta tesis — son los tres niveles de
arriba: el **modelo de datos** (registro de fuente v2, §6), la
**política** (cascada como único selector de camino, §7) y la
**semántica** (muerte del concepto en protocolo eSE y UI, §3, §7.5).
La relación exacta entre ambos documentos: el plan construye *caminos*;
la tesis hace que los caminos sean *lo único que existe*.

---

## 6. Diseño I — el registro de fuente v2 y el vector de alcanzabilidad

### 6.1 Principio: doble publicación

Cada nodo eSE publica **dos vistas del mismo hecho**:

1. **Vista clásica (intacta):** el registro tipo 1/3/4/5/6 de siempre,
   bit-a-bit idéntico a 0.70b, para que cualquier cliente upstream siga
   funcionando exactamente igual. *No se toca ni un byte.*
2. **Vista v2 (tags adicionales sobre el mismo registro):** el vector
   `R` serializado en un tag nuevo `TAG_ESE_REACH` (valor propuesto:
   **0x68**, contiguo a los 0x66/0x67 ya reservados; el propio
   `Opcodes.h:485` documenta una auditoría del namespace de tags
   "0x68–0xCF libres" — queda la cautela menor de mods de terceros
   exóticos), más los tags v6 ya reservados cuando aplique. Un cliente
   que no conoce el tag lo ignora: es la propiedad que ya explota todo
   el mecanismo `TAG_ESE_CAPS`.

Esta es la misma doctrina del tag 0x66 y de los cinco opcodes Live:
extensión por tags ignorables, jamás por alteración de formato. La
regla de compatibilidad del proyecto la exige sin excepciones.

### 6.2 Contenido del tag (resumen; wire en Apéndice A)

`TAG_ESE_REACH` = TLV compacto, ≤ 64 bytes típicos:

- byte de versión;
- bitfield u16 de capacidades (`V4_TCP_IN`, `V4_UDP_IN`, `V6_IN`,
  `PUNCH_2W`, `PUNCH_3W`, `KEEPALIVE`, `RELAY_OFFER`, reservas);
- 0–3 entradas de rendezvous `{KadID(16B), IPv4(4B), puerto UDP(2B)}`
  — los nodos abiertos con los que el publicador mantiene pinhole vivo
  (generalización del buddy, §8.1);
- TTL implícito: el de re-publicación Kad estándar; los rendezvous se
  re-verifican siempre en vivo antes de usarse (§11.2).

La dirección IPv6, si existe y está **verificada inbound** (no solo
egress — exactamente la prueba `TryHighID()` v6 que la Fase 4 del plan
deja especificada), viaja en `TAG_SOURCEIP_V6` como ya está previsto.

### 6.3 Qué muere con esto

Entre nodos eSE, el `TAG_SOURCETYPE` pasa de ser *el* dato a ser un
artefacto de compatibilidad. El descargador eSE que ve `TAG_ESE_REACH`
ignora el tipo clásico y alimenta la cascada con el vector. La
pregunta "¿qué tipo de fuente es?" — la encarnación del concepto en el
modelo de datos — deja de formularse.

### 6.4 El supuesto crítico, verificado: los indexadores vanilla reenvían tags desconocidos

La doble publicación tiene una dependencia silenciosa que podría
hundirla: el vector no viaja de B a A directamente, sino a través del
**nodo indexador** donde B publica y A busca — y ese indexador puede
ser un cliente vanilla. Si los indexadores filtraran tags desconocidos,
`TAG_ESE_REACH` solo sobreviviría cuando el indexador fuese eSE, y la
cobertura del diseño se desplomaría en redes mixtas.

Verificado contra el código upstream-derivado (auditoría 2026-06-11):
**el indexador 0.70b almacena y reenvía los tags que no entiende.**

- *Almacenamiento:* en `Process2PublishSourceReq`, la rama final del
  bucle de tags es `else { //TODO: Filter tags → pEntry->AddTag(pTag) }`
  (`KademliaUDPListener.cpp:1565–1569`): todo tag no reconocido se
  guarda en la entrada. El comentario `TODO` es de upstream — el filtro
  nunca se escribió.
- *Reenvío:* al responder búsquedas de fuentes, el indexador serializa
  la lista de tags completa de cada entrada con `WriteTagList`
  (`Indexed.cpp:730`, `SendValidSourceResult`) dentro de
  `KADEMLIA2_SEARCH_RES`.

Dos consecuencias y una cautela:

1. La doble publicación funciona **incluso con indexadores vanilla** —
   el supuesto más arriesgado de la tesis resulta ser el más sólido.
2. Hay un coste de cortesía: cada fuente eSE ocupa ~70 bytes extra *en
   la memoria de indexadores ajenos* y reduce cuántas fuentes caben por
   paquete de respuesta (el packing contra `UDP_KAD_MAXFRAGMENT`,
   `Indexed.cpp:732`). Es la razón de diseño dura para mantener el TLV
   mínimo (§6.2, Apéndice A) — el vector grande no es solo peor
   privacidad: es parasitar RAM y ancho de banda de terceros.
3. Cautela: esto verifica el linaje eMule 0.70b. Implementaciones
   hermanas (aMule, jed2k, MLDonkey) derivan del mismo diseño pero no
   se han auditado; T1 debe incluir un test de paso a través de al
   menos aMule. **Fallback si algún indexador filtra:** la cascada
   funciona sin vector (proyección del registro clásico, §6.3) y lo
   obtiene en banda en el primer contacto logrado (hello eSE), cacheado
   por NodeID en la memoria de rutas (§7.1).

### 6.5 Self-assessment honesto del vector

El vector publicado es una *afirmación* del publicador, verificada por
los mismos mecanismos que hoy verifican el bit (firewall-checks
distribuidos, §2.1, generalizados por `FirewallProberV6`): `V4_TCP_IN`
solo se anuncia tras un test entrante positivo de un peer; `V6_IN` solo
tras probe inbound v6; `PUNCH_*` son capacidades de software (cap bits)
no de red. La cascada (§7) trata todo el vector como *hipótesis a
confirmar en vivo*, nunca como verdad — un vector falso solo le cuesta
milisegundos de fallback al llamante (§11.3).

---

## 7. Diseño II — la cascada de conexión

### 7.1 El selector único

Toda conexión saliente eSE→fuente pasa por una única máquina de
estados, `CReachPipeline` (nombre tentativo; es la culminación natural
del `FirewallProberV6` ya esbozado), que compone los caminos en orden
de coste y determinismo. El orden importa y tiene una sutileza que el
binario clásico ocultaba: los callbacks clásicos **no son simétricos**
— funcionan si y solo si *el llamante* es alcanzable (§2.3). Por eso la
cascada se bifurca según el vector *propio*, no solo el remoto:

```
dado mi vector A y el vector remoto B (o su registro clásico):

1. DIRECTO_V6      si B.v6_in y tengo v6            → TCP/uTP sobre v6
2. DIRECTO_V4      si B.v4_tcp_in                   → TCP clásico (tipo 1/4)
3. CALLBACK        si A.v4_tcp_in — o A.v6_in con B v6-capaz. No basta
                   "A alcanzable por cualquier vía": todo callback acaba
                   con B abriendo una conexión TCP hacia A, así que A
                   debe aceptar TCP entrante; un A solo-punchable no sirve.
     3a. UDP directo  si B.v4_udp_in                → OP_DIRECTCALLBACKREQ (tipo 6)
     3b. buddy/rdv    si B tiene rdv o buddy        → KADEMLIA_CALLBACK_REQ
     (determinista y gratis cuando aplica)
4. PUNCH_2W        si B.punch_2w y tengo ruta UDP a B  → OP_ESE_HOLEPUNCH + uTP
5. PUNCH_3W        si B.punch_3w y B.rdv no vacío      → KADEMLIA3_HOLEPUNCH vía rdv + uTP
6. RELAY           si B.rdv/relay y ambos CAP_TUNNEL_DATAPLANE
                                                     → circuito onion rendezvous (TURN propio)
7. CLÁSICO_PURO    (peer no-eSE)                     → comportamiento 0.70b intacto
```

Paradas tempranas, presupuesto de tiempo por capa (cientos de ms para
1–3; segundos para 4–5; el relay no tiene prisa porque es el final), y
**memoria por par**: el camino que funcionó se recuerda (keyed por
NodeID, no por IP) y se intenta primero la próxima vez, con
re-validación barata. ICE llama a esto *nominated pair*; nosotros lo
llamaremos simplemente la ruta del par.

### 7.2 Las dos mitades del problema, por fin separadas

El binario clásico confundía dos preguntas:

- **¿Puedo *contactar* a B?** (señalización: hacerle saber que quiero
  hablar) — resuelta por los pasos 3b/5 vía rendezvous: siempre hay un
  nodo abierto con conexión viva hacia B (su rdv/buddy) si B está
  online y publicado.
- **¿Puedo *transportar* datos con B?** (camino de datos) — resuelta
  por 1/2/4/5 (directo o perforado) o 6 (relay).

Con las dos mitades separadas, el "LowID↔LowID imposible" se revela
como lo que siempre fue: un fallo de *señalización* (ninguno podía
enterarse de que el otro llamaba) multiplicado por un fallo de
*transporte* (ninguno aceptaba SYN). El rendezvous arregla la primera
mitad para el 100% de los pares; el punching la segunda para la gran
mayoría; el relay cubre el resto.

### 7.3 Mantenimiento: keepalive como ciudadanía

La Fase 2 del plan (pings `KADEMLIA2_PING` cada ~25 s a 5–10
supernodos) es lo que convierte a un nodo NATeado en *contactable de
facto*: su pinhole UDP permanece abierto y sus rendezvous tienen ruta
viva hacia él. En el modelo de la tesis, el keepalive no es una
optimización: es el equivalente funcional de "estar escuchando", la
cuota de presencia que un nodo no alcanzable paga (<1 KB/s) para ser un
ciudadano pleno del plano de conexión.

### 7.4 Interacción con la identidad

La memoria de rutas, las colas de descarga, los créditos y el mesh se
indexan por NodeID/hash de usuario — nunca por IP. Para créditos y
colas eMule ya lo hace (hash de usuario); la novedad es extenderlo al
plano de conexión: si B cambia de IP (DHCP, roaming, failover v4→v6),
la ruta del par se invalida y la cascada renegocia, pero *B sigue
siendo B*: la cola no se pierde, el crédito no se pierde, el mesh de
Live ya sobrevive (circ_id). El LowID era, entre otras cosas, la
imposibilidad de expresar esta continuidad.

### 7.5 La interfaz de usuario

Donde hoy hay flecha amarilla y "LowID", la UI pasa a mostrar **estado
de ruta por conexión**: `directo` / `directo v6` / `perforado` /
`relay` / `clásico`, y a nivel de nodo un resumen honesto tipo "Tu nodo
acepta conexiones vía: v6 ✓, punch ✓" en lugar de un juicio binario. El
semáforo global desaparece para nodos eSE. (Frente a servidores eD2K
clásicos el cliente seguirá *recibiendo* un LowID — se muestra en el
contexto del servidor, como dato de esa conexión, no como identidad del
nodo.) Detalle no menor para la moral del usuario de CGNAT: por primera
vez su cliente le dirá algo verdadero — que funciona.

---

## 8. Diseño III — rendezvous generalizado y relays voluntarios

### 8.1 Del buddy (1) a los rendezvous (k)

El buddy upstream se conserva intacto hacia fuera (se publica
`TAG_BUDDYHASH`/`TAG_SERVERIP` como siempre — los vanilla lo necesitan)
y se generaliza hacia dentro: un nodo eSE no alcanzable mantiene
pinholes vivos con **k = 2–3 nodos abiertos** (su buddy clásico puede
ser uno de ellos) y los publica como `rdv[]` en su vector. Funciones de
un rendezvous, en coste creciente:

1. **Reenviar señalización** (FWD de punch 3-vías, callbacks): bytes
   sueltos, coste ≈ 0. Disponible para cualquier peer eSE que lo pida
   respetando el rate-limit.
2. **Coordinar punch** (DCUtR-style): dos mensajes y un timestamp de
   sincronización. Coste ≈ 0.
3. **Relay de datos** (§8.2): solo si lo anuncia (`RELAY_OFFER`), solo
   capado.

Con k>1 muere el defecto estructural del buddy único (§2.5): la caída
de un rendezvous degrada, no desconecta. La selección reutiliza el
criterio de pool del keepalive (contactos verified con buen RTT,
rotación por `consecutiveMisses`) — son literalmente los mismos nodos a
los que ya se pinguea, por lo que el coste marginal de mantenerlos como
rendezvous es cero.

### 8.2 Relays de datos: el TURN sin servidores

Para el residuo (simétrico↔simétrico sin v6, UDP bloqueado): nodos eSE
abiertos y voluntarios anuncian `RELAY_OFFER` + `ESE_CAP_TUNNEL_DATAPLANE`
y aceptan circuitos onion de datos con **presupuesto capado**
(configurable; analogía exacta con Circuit Relay v2 de libp2p, y misma
infraestructura que los viewer-relays de E-β, así que el trabajo se
amortiza con el roadmap existente). Propiedades:

- **Punto de encuentro definido en el modelo de datos:** la cascada
  necesita que A y B coincidan en *qué* relay usar. Regla: las entradas
  `rdv[]` del vector de B cuyo nodo anuncie `RELAY_OFFER` son sus
  **anclas de relay** — B ya mantiene circuito/pinhole hacia ellas; A
  abre circuito hacia la misma ancla y el encuentro se resuelve con una
  clave de cita derivada de `(NodeID_B, hash del fichero)` (el patrón
  `streamKey` ya previsto para el relay de Live). Sin esta regla el
  paso 6 de la cascada no tendría dónde citar a las partes.
- **Cifrado extremo a extremo:** el relay mueve celdas opacas
  (`OP_LIVE_TUNNEL_CELL`, cripto onion ya existente); no ve contenido.
  Esto importa también legalmente: un relay que *no puede* inspeccionar
  lo que reenvía es un mero conducto.
- **Voluntario y recíproco:** off por defecto razonable, on por
  defecto debatible; la tesis propone arrancar opt-in y medir. Sin
  relays suficientes el residuo simplemente cae al comportamiento
  clásico (no hay regresión posible).
- **Último de la cascada, siempre.** El orden ICE garantiza que el
  relay solo carga con lo que nada más pudo llevar; la experiencia de
  libp2p y WebRTC es consistente: con punch decente, el tráfico
  relayado queda en porcentaje de un dígito.

### 8.3 Anti-abuso del plano rendezvous/relay

Heredado del andamiaje existente y endurecido: rate-limit por /64 y
`MAX_SESSIONS=32` (ya en el 2-vías), nonces CSPRNG en todo punch (ya),
cifrado `CKadUDPKey` cuando el contacto está en la routing table (ya),
y dos reglas nuevas: un rendezvous solo reenvía FWD hacia nodos con los
que mantiene sesión establecida (no relay abierto de señalización — la
regla anti-spoofing de la Fase 1 del plan, generalizada de "su buddy" a
"sus suscriptores de keepalive"), y un relay de datos exige cap bit
mutuo + presupuesto. Análisis completo en §11.

---

## 9. La DHT: lo que no se puede abolir (y por qué da igual)

Un nodo que no recibe UDP no solicitado no puede responder consultas de
extraños, luego no puede ser contacto en tablas de rutas ajenas. Esta
exclusión (`KademliaUDPListener.cpp:652`) **se mantiene**: es física,
no concepto. La tesis la *renombra* y la *delimita*:

- **Renombrar:** siguiendo a libp2p, los nodos son *DHT servers* (los
  alcanzables, enrutan) o *DHT clients* (consultan y publican). Es
  vocabulario de rol de infraestructura, sin proyección a la identidad
  ni a la UI de usuario. Nadie ve "client mode" como estigma en IPFS;
  nadie debería verlo en eSE.
- **Delimitar:** esa es la *única* consecuencia del estado de red que
  se conserva. Con keepalive activo, además, un nodo NATeado *sí*
  recibe UDP de sus supernodos/rendezvous, así que participa en todo lo
  demás: publica, busca, es contactable vía rdv, transporta por punch.
  La frontera exacta de lo ineliminable es: **no enruta búsquedas de
  desconocidos**. Nada más.

Riesgo derivado a vigilar (medible, §14): si la fracción de DHT servers
cae demasiado (mundo mayoritariamente CGNAT), la DHT se concentra en
pocos nodos. Sobre las mitigaciones, una advertencia que esta tesis se
hace a sí misma: la tentación obvia — "que los nodos v6-alcanzables
cuenten como servers" — está **descartada** mientras siga vigente la
decisión de no construir Kad v6 paralela: las tablas de rutas se
comparten con peers vanilla vía `KADEMLIA2_RES`, y un contacto
enrutable solo por v6 sería una entrada muerta (o tóxica) para todo
cliente clásico — la isla fork-only por la puerta de atrás. Lo que sí
cabe sin romper nada: usar v6 como *transporte adicional* de contactos
que también son v4-alcanzables (robustez, no servers nuevos),
instrumentar la métrica de fracción de servers desde T1 para saber si
el riesgo es real antes de actuar, y — como idea exploratoria fuera del
alcance de esta tesis — que nodos con keepalive denso enruten para su
vecindario ya conocido.

---

## 10. Compatibilidad hacia atrás: doctrina y matriz de interoperabilidad

Regla del proyecto, sin excepciones: todo cambio wire funciona con
0.70b upstream y con versiones previas del fork. Instrumentos: tags
ignorables + cap bits + doble publicación. Cero opcodes que un vanilla
pueda recibir sin entender (los `KADEMLIA3_*` y `OP_ESE_*` solo se
emiten tras ver el cap correspondiente).

### Matriz de interoperabilidad

| Par (A descarga de B) | Qué ve A | Camino resultante |
|---|---|---|
| vanilla ↔ vanilla | tipos 1–6 clásicos | exactamente 0.70b (sin cambios) |
| eSE → vanilla HighID | registro clásico, sin `TAG_ESE_REACH` | directo TCP clásico (paso 2/7 de la cascada) |
| eSE → vanilla LowID | registro tipo 3/5/6 | callbacks clásicos si A TCP-alcanzable; si no: **bloqueado, como siempre** (no hay regresión; tampoco mejora — B no coopera) |
| vanilla → eSE alcanzable | tipo 1/4 normal | directo clásico |
| vanilla → eSE no alcanzable | tipo 3/5/6 con buddy real publicado | callback por buddy clásico — **por esto el buddy upstream se conserva** |
| eSE ↔ eSE | clásico + `TAG_ESE_REACH` (+0x66) | cascada completa §7 |
| eSE nuevo ↔ eSE viejo (pre-tesis) | caps parciales (p.ej. solo 2-vías) | la cascada usa los pasos que ambos anuncian; lo demás se salta |

Tres invariantes que la implementación debe poder demostrar en test:

1. **Inocuidad:** un sniffer no distingue a un nodo eSE hablando con un
   vanilla de un 0.70b hablando con un vanilla, salvo por tags extra
   ignorables en publicaciones y hellos.
2. **No-regresión:** desactivando todos los cap bits eSE, el
   comportamiento es bit-a-bit el clásico (los tests de framing de
   túnel ya siguen este patrón; replicarlo).
3. **Degradación honesta:** cuando la cascada agota capas, el resultado
   es el comportamiento clásico, nunca peor.

---

## 11. Análisis adversarial

El plano nuevo (vector publicado + rendezvous + relay) crea superficie
nueva. Vectores y mitigaciones:

### 11.1 Suplantación de vector (poisoning)

*Ataque:* publicar `TAG_ESE_REACH` falso para un NodeID ajeno (tercero
publica fuentes falsas — ya posible hoy con registros clásicos) o
inflar el propio vector. *Daño potencial:* dirigir SYNs/punches de la
víctima-descargador hacia terceros (reflexión) o degradar conexiones.
*Mitigación:* (a) el vector es hipótesis, no verdad — la cascada
verifica en vivo con nonces CSPRNG antes de transportar datos (el
2-vías ya lo hace); (b) los punches van a endpoints que respondieron al
nonce, nunca a ciegas más de N paquetes (sin amplificación: un REQ
produce a lo sumo un ACK pequeño); (c) el indexador ya dificulta
publicar fuentes con IP ajena: estampa `TAG_SOURCEIP` desde el origen
real del paquete UDP, no desde lo que el publicador declare
(`KademliaUDPListener.cpp:1512`); (d) la **autoridad final de identidad
no es el vector**: sigue siendo el handshake eD2K (hash de usuario +
SecureIdent), que ningún camino de conexión puede falsear — un vector
envenenado cuesta milisegundos de cascada, nunca una suplantación, y
por eso la firma del vector puede esperar a T6; (e) a medio plazo,
firmar el vector con la clave del NodeID (§3.3) cierra también la
suplantación por terceros del propio registro — ésta es la razón
técnica concreta para el refuerzo criptográfico de la identidad.

### 11.2 Rendezvous como infraestructura atacable

*Ataques:* agotamiento (inundar a un nodo abierto con sesiones rdv),
rdv sybil (atacante se ofrece como rdv para observar/cortar
señalización de víctimas), FWD spoofing. *Mitigaciones:* cupos
(`MAX_SESSIONS`, rate-limit /64, ya existentes); regla
solo-suscriptores para FWD (§8.3); k>1 rendezvous por nodo (un rdv
malicioso degrada, no aísla — y se rota por `consecutiveMisses` como
los supernodos de keepalive); la señalización relevante va cifrada
extremo a extremo cuando ambos lados son eSE (el rdv ve que A busca a
B — metadato inevitable en cualquier rendezvous, incluido el buddy
clásico de upstream, que ya filtra exactamente lo mismo).

### 11.3 Relay de datos

*Ataques:* parasitismo (usar relays como CDN gratis), relay malicioso
(corta/retrasa). *Mitigaciones:* presupuesto capado y configurable por
relay; relay solo como capa final de cascada (el parásito tendría que
fallar adrede el punch — posible pero costoso y detectable); celdas
E2E-cifradas hacen el relay ciego al contenido; fallback a otro relay o
a clásico ante corte. El modelo de amenaza completo del plano túnel
está en los documentos de Live; aquí solo se generaliza el consumidor.

### 11.4 Privacidad: el vector como huella

Riesgo sutil y específico de esta tesis: `R` revela topología del
usuario (tipo de NAT, tenencia de v6, ISP inferible). Es más metadato
del que un vanilla publica (aunque éste ya publica el bit firewalled en
`TAG_KADMISCOPTIONS` y su buddy en cada fuente). *Mitigaciones de
diseño:* publicar el vector **grueso** (bits de capacidad y rdv —
lo mínimo que la cascada necesita para arrancar) y negociar el detalle
en vivo por canal cifrado; TTL corto; y coherencia con la arquitectura
de privacidad del fork — en modos de privacidad altos (Kad sellada,
túneles always-on para Live), el intercambio clásico puede publicar un
vector mínimo `{rdv[]}` que convierte todo contacto en
rendezvous-first, el patrón Tor. La tesis es así *convergente* con la
línea de privacidad, no tangente: cuanto más se parece el plano de
conexión a "identidad-clave + rendezvous", más corto es el salto a los
modos anónimos.

### 11.5 Lo que esta tesis no empeora

Conviene decirlo explícitamente: el sistema clásico ya publica IP,
puerto, bit de firewall y buddy de cada fuente a cualquiera que
pregunte. La tesis reordena y enriquece esa información para los pares
cooperantes; no crea un canal de exposición cualitativamente nuevo,
y abre por primera vez la puerta (vector mínimo, §11.4) a publicar
*menos* que upstream.

---

## 12. Cuantificación: cobertura, coste y residuo

Órdenes de magnitud, con las advertencias de rigor (las distribuciones
de NAT varían por país e ISP; España va rezagada en IPv6 frente a la
media europea, lo que *aumenta* el peso relativo del punching aquí):

| Capa | Pares que cubre (acumulado, eSE↔eSE) | Coste |
|---|---|---|
| Directo v4/v6 | todos los pares con ≥1 extremo abierto o v6 mutuo | cero |
| Callbacks clásicos | + pares donde el llamante es alcanzable | cero (ya existe) |
| Punch 2/3-vías + uTP | + ambos NATeados cone/restricted (~70–85% de NATs domésticos) | keepalive <1 KB/s + rdv ≈ 0 |
| Relay onion | + residuo (simétrico↔simétrico sin v6, UDP capado): típicamente un dígito % | BW donado, capado |
| **Total** | **≈100% de pares eSE↔eSE online** | — |

El "≈" del 100% es honesto: relays insuficientes o políticas de red
exóticas (UDP bloqueado + sin v6 + sin relays disponibles) dejan pares
sin camino, que caen al comportamiento clásico. La diferencia con hoy:
el residuo pasa de ser una *clase de identidad* (todo par LowID↔LowID,
estructural y creciente) a ser una *cola estadística* (pares concretos,
en momentos concretos, decreciente con la adopción de v6).

Coste no obvio que conviene contabilizar: el vector viaja alojado en
**indexadores ajenos** (§6.4) — ~70 bytes por fuente en RAM de
terceros y menos fuentes por paquete `KADEMLIA2_SEARCH_RES`. Es
tolerable precisamente porque el TLV es mínimo; cualquier ampliación
futura del vector debe pasar por esta vara de medir, no solo por la de
privacidad.

Métricas a instrumentar para validar estas cifras con datos propios
(los contadores del 2-vías ya existen: `m_dwHolePunchAttempts/Success/
SymNATFail`): distribución de capa final por conexión, tasa de éxito
por tipo de NAT detectado, % de tráfico relayado, latencia añadida por
capa, fracción de DHT servers en la red (§9).

---

## 13. Más allá del fork: el componente publicable para el ecosistema

Todo lo anterior, implementado solo en eSE, acota el beneficio a los
pares eSE↔eSE. Pero la agnosticidad LowID es un bien de red: su valor
crece con el **cuadrado** de los nodos que la hablan. Un único cliente
más que la adopte (un mod de eMule, aMule, jed2k) no suma — multiplica
pares. Este capítulo define el artefacto que hace esa adopción barata:
una especificación abierta más una librería de referencia embebible,
publicadas para que cualquier desarrollador del ecosistema integre la
cascada, se mantenga al día sin flag-days, y haga a su cliente
agnóstico al LowID/HighID sin leer esta tesis ni nuestro código MFC.

### 13.1 Por qué publicar (y el precedente que ya vive en el repo)

- **Efecto red cuadrático.** Con solo eSE, un usuario CGNAT conecta
  con la fracción eSE de la red. Cada implementación adicional convierte
  pares muertos en pares vivos para *ambas* comunidades, sin que ningún
  usuario haga nada.
- **El precedente exacto es libutp.** BitTorrent, Inc. publicó su
  transporte uTP como librería C++ embebible con licencia permisiva y
  callbacks de I/O inyectados; quince años después está en este repo
  como submódulo dándonos el canal de datos del punching. Publicar
  nuestra capa de alcanzabilidad con el mismo molde es devolver la
  jugada al ecosistema — y es el formato cuya viabilidad está más
  demostrada en P2P.
- **Defensa contra dialectos.** El eD2K vivió la alternativa: protocolo
  documentado por ingeniería inversa, extensiones de mods pisándose
  tags y opcodes. Si el fork define el comportamiento wire en solitario
  y otros lo medio-implementan después leyendo paquetes, heredamos ese
  caos. Una spec publicada con registro de números es más barata que
  arbitrar dialectos a posteriori.
- **La historia de adopción correcta ya existe:** la ofuscación de
  protocolo, AICH y el propio Kad 2.0 se extendieron por la ruta
  mod→oficial→aMule. No hace falta que eMule upstream (casi parado)
  mueva ficha el primero.

El "cuadrático" del primer punto, en números, porque es el argumento
entero del capítulo. Sea `p` la fracción de la red que habla KEP-1:
entre los pares donde *ambos* extremos son v4-NATeados sin v6 (el caso
que hoy es bloqueo total), se rescatan `p²`:

| `p` (hablan KEP-1) | pares LowID↔LowID rescatados |
|---|---|
| 5% (solo eSE, hoy) | 0,25% |
| 25% (eSE + un mod grande) | 6,25% |
| 50% (+ aMule) | 25% |
| 75% | 56% |

Solos, vivimos en el ruido estadístico; con un único hermano grande
cambia el régimen. Por eso este capítulo no es un anexo simpático: es
donde se decide si la tesis arregla un fork o arregla una red.

### 13.2 Qué se publica: tres artefactos

1. **La especificación — "KEP-1" (Kad Enhancement Proposal,
   deliberadamente al estilo de los BEP de BitTorrent).** Contenido
   normativo mínimo: el TLV del vector de alcanzabilidad (Apéndice A),
   los cap bits, los opcodes de punch 2-vías/3-vías y keepalive, la
   semántica de la cascada (qué DEBE intentarse, en qué orden, qué
   PUEDE omitirse), las reglas de rendezvous y los mínimos anti-abuso
   (nonce obligatorio, límites de sesión). Más dos piezas que separan
   una spec útil de un README: **vectores de test** (paquetes golden,
   como ya hace `tests/test_tunnel_framing.py` para el framing de
   túnel) y un **registro público de números** (tags, bits, opcodes)
   donde cualquier implementador reserva sin colisionar — la lección
   aprendida del namespace audit de `Opcodes.h:485`. El lenguaje es
   normativo (MUST/SHOULD/MAY, RFC 2119), y los mínimos anti-abuso van
   como **MUST incondicional**: quien implementa rendezvous sin la
   regla solo-suscriptores, o punch sin nonce, no es una implementación
   parcial — es no-conforme, porque convertiría a sus usuarios en
   amplificadores. La spec protege a la red también de sus
   implementadores descuidados.
2. **`libreach` (nombre tentativo): la librería de referencia.**
   C++ portable sin MFC ni wxWidgets, con el patrón libutp llevado
   hasta el final: la librería **no abre sockets, no crea hilos y no
   conoce Kad** — el anfitrión inyecta callbacks (envío UDP, apertura
   TCP, señalización vía su propia Kad, CSPRNG, reloj) y un `tick()`
   de ~1 Hz, y la librería aporta exactamente lo difícil y lo propenso
   a dialectos: parser/serializador del TLV, máquina de estados de la
   cascada, codificación del punch, prober de capacidades,
   contabilidad anti-abuso (boceto de la superficie en Apéndice E).
   La disciplina mono-hilo no es estética: los clientes anfitriones
   tienen modelos de hilos hostiles — el nuestro el primero; toda la
   lección de marshaling de `/api/live` aplica — y una lib que crea
   hilos propios es una lib que nadie integra dos veces. La superficie
   pública es **C ABI** (`extern "C"`, como `utp.h`), de modo que
   jed2k (JNI) o cualquier cliente no-C++ lleguen por FFI. Fuera del
   alcance de la lib, explícitamente: routing Kad, transporte uTP (eso
   ya es libutp), cifrado de paquetes Kad y toda política de UI —
   frontera fija contra el scope creep. **Licencia:** lo publicable
   debe escribirse limpio (la cascada, el TLV y el puncher son código
   nuevo nuestro, no derivado de eMule) para poder elegir MIT —
   embebible sin fricción en los GPL del ecosistema; el pegamento
   dentro de cada cliente queda bajo la licencia de ese cliente. Y una
   jerarquía clara para quien no puede embeber C++: **la spec es lo
   normativo; la lib, la comodidad** — KEP-1 más los vectores de test
   bastan para una implementación nativa limpia en cualquier lenguaje
   (el formato wire no tiene dueño; el código sí).
3. **La suite de conformidad.** Harness local que valida una
   implementación contra los vectores golden y simula los escenarios de
   la matriz §10 (incluido "ignoro limpio lo que no entiendo") **y los
   casos de abuso**: la suite intenta usar al candidato como
   amplificador, como relay abierto de señalización y como objetivo de
   punch sin nonce, y suspende a quien coopere. Pasa la suite ⇒
   interopera *y no daña*. Sin servidores de prueba públicos (regla de
   coste cero): la suite es local y el banco real es cualquier nodo eSE.

### 13.3 Niveles de conformidad: adoptar no es todo-o-nada

El error clásico de las specs P2P ambiciosas es exigir la pila completa
para participar — y la pila completa de esta tesis incluye uTP, punch y
keepalive, que para un mod pequeño es un muro. KEP-1 define cuatro
niveles, cada uno útil por sí solo, interoperable con todos los demás y
certificable por separado en la suite:

| Nivel | Qué implementa | Esfuerzo | Qué gana |
|---|---|---|---|
| **N0 — Transparente** | Nada activo: su indexador almacena y reenvía tags desconocidos | cero — eMule y derivados ya lo cumplen de fábrica (§6.4); solo hay que *no romperlo* | la red moderna funciona a través de él |
| **N1 — Lector** | Parsea `TAG_REACH` al buscar: conecta directo por v6 cuando puede, usa los rdv del vector para callbacks | días | sus usuarios conectan mejor *hacia* los nodos modernos, sin uTP ni punch |
| **N2 — Pleno** | Publica su propio vector; punch 2-vías/3-vías con uTP; keepalive | semanas — el grueso es integrar libutp si no lo tiene | **abole el LowID para su comunidad**: sus NATeados conectan entre sí y con todo N2+ |
| **N3 — Ciudadano de infraestructura** | Sus nodos abiertos ofrecen rendezvous y, opt-in, relay capado | incremental sobre N2 | sostiene el plano común; reciprocidad de red |

La escalera importa más que cualquier peldaño: N0 ya está desplegado
sin que nadie lo decidiera (§6.4 lo demostró), N1 es la puerta de
entrada con coste de días, y N1 crea solo el incentivo para N2 — cuando
tus usuarios ven que conectan mejor con la parte moderna de la red,
pedir el punch es el paso natural, no un acto de fe. Los MUST
anti-abuso aplican en cada nivel a lo que ese nivel implementa.

### 13.4 Neutralidad de marca y evolución sin flag-days

- **Los nombres normativos no llevan marca.** En la spec, el tag es
  `TAG_REACH`, los bits `KAD_CAP_*`: nadie integra cómodamente un
  símbolo llamado `ESE_*` de otro proyecto. eSE mantiene sus alias
  internos y pasa a ser *implementación de referencia*, no dueño del
  protocolo. (Renombrar alias internos cuesta un `#define`; renombrar
  un protocolo desplegado cuesta una migración.)
- **"Que también se actualicen":** la actualización continua de
  terceros está resuelta por construcción, no por disciplina — el TLV
  versionado + los cap bits hacen que toda evolución sea aditiva (bits
  nuevos, TLVs opcionales al final), que un parser v1 siga funcionando
  para siempre y que dos versiones cualesquiera negocien la
  intersección de lo que ambas hablan. Es la misma doctrina §10
  aplicada al tiempo en vez de a los clientes: compatibilidad hacia
  atrás también entre versiones de la spec.
- **Gobernanza mínima, honesta con la escala del proyecto:** un repo
  público (la spec, la lib, la suite, el registro), cambios por pull
  request, números nuevos solo vía registro. Sin comité, sin proceso
  IETF — esto es ocio; el registro público ya elimina el 90% del caos
  que sufrieron los mods de los 2000.
- **KEP como serie, no como documento único:** KEP-0 fija el proceso y
  el registro; KEP-1 es el vector + cascada de esta tesis; la
  numeración queda abierta para las demás extensiones wire del fork que
  algún día merezcan cruzar la puerta (el modelo de resultados de la
  monografía Kad Search v2 es el candidato obvio a KEP-2). Fundar bien
  el cauce vale tanto como la primera spec: el borrador IPv6 de
  David_X murió en un pad efímero precisamente porque el eD2K nunca
  tuvo un sitio donde las extensiones pudieran vivir, numerarse y
  sobrevivir a su autor.
- **Nota de naming, por honestidad:** "KEP" colisiona con los
  Kubernetes Enhancement Proposals; los dominios no se tocan, pero el
  nombre definitivo (KEP, KadEP, …) se decide en T7 — lo normativo de
  esta tesis es la *forma* del cauce, no su sigla.

### 13.5 Estrategia de adopción realista

Honestidad primero: eMule oficial está casi inmóvil y aMule va lento.
El objetivo no es "todos adoptan"; es **dejar la puerta abierta con el
coste de cruzarla cerca de cero**, y conseguir un primer cruce que
demuestre portabilidad:

- **Primer objetivo natural: un patch de aMule.** El gate de T1 ya
  exige validar el passthrough de tags contra aMule (§6.4), así que
  aMule estará en el banco de pruebas de todos modos — el patch que lo
  hace *hablar* el protocolo (no solo tolerarlo) sale casi gratis de
  esa misma infraestructura, y prueba la portabilidad wx/POSIX de
  `libreach` de paso.
- **Qué gana el que adopta:** sus usuarios CGNAT conectan entre sí y
  con la base eSE desde el primer día, con cero regresión frente a
  quien no adopta (doctrina §10) y sin infraestructura nueva que
  operar. Es el argumento de venta completo; no hay letra pequeña.
- **Métrica de éxito medible:** pares cross-implementación conectados
  por capa de cascada — la telemetría del §12 ya distingue la
  implementación remota por sus cap bits, así que sabremos si la
  adopción existe en vez de suponerlo.

La prueba de que el coste es bajo cabe en una lista. El camino de
integración para un mod activo: (1) embeber `libreach` — o implementar
desde KEP-1 si no es C++ —, (2) cablear la media docena de callbacks
contra su propia red (Apéndice E), (3) una llamada de encode al
publicar fuentes, (4) delegar la conexión saliente en la cascada con su
camino clásico como fallback final, (5) pasar la suite del nivel
elegido. N1 son días; N2, semanas — y casi todas se van en integrar
libutp, que es territorio conocido: BitTorrent lleva quince años
embebiéndolo en clientes ajenos.

### 13.6 Riesgos específicos de publicar

- **Dialectos pese a todo:** mitigado por vectores de test + suite de
  conformidad (la spec sin suite es una invitación al dialecto).
- **Squatting de números:** mitigado por el registro; y los rangos ya
  auditados quedan documentados desde el día uno.
- **Carga de mantenimiento sobre un proyecto de ocio:** se acota por
  alcance — la lib es pequeña y de superficie estable, la spec v1 se
  congela, y el etiquetado es honesto: "referencia, sin SLA". No se
  promete soporte; se promete un registro y unos tests que no mienten.
- **¿Publicar el anti-abuso facilita el abuso?** No: Kerckhoffs. Los
  nonces, límites y reglas solo-suscriptores no dependen del secreto
  del mecanismo, y ya eran visibles en el binario para quien quisiera
  mirar.
- **Ecosistema estancado en N1:** posible — N1 da beneficio asimétrico
  (ellos conectan mejor hacia nosotros) sin reciprocidad de punch.
  Riesgo aceptado por diseño: N1 ya mejora la red para todos, y el
  incentivo hacia N2 crece solo con la masa N2 existente. La
  alternativa todo-o-nada garantiza el resultado peor: cero adopción.

---

## 14. Hoja de ruta, gates y criterio de oportunidad

### 14.1 Dependencias duras (de otros documentos)

Esta tesis **no debe arrancar** hasta que LOWID_NAT_TRAVERSAL_PLAN.md
esté validado: Fase 0 (2-vías end-to-end entre dos PCs reales) como
gate absoluto, Fases 1–2 (rendezvous 3-vías + keepalive) como núcleo, y
la validación dual-stack pendiente (`GetPeerAddressV4` bajo
`IPv6PreferredMode`) para la pata v6. Regla del proyecto: estabilizar
antes que añadir — la tesis es la *capa conceptual* sobre mecánica
probada, nunca sobre esqueletos.

### 14.2 Tramos de la tesis propiamente dicha (post-plan)

| Tramo | Contenido | Gate de salida |
|---|---|---|
| T1 | `TAG_ESE_REACH` (0x68): emitir + parsear; doble publicación; cap bit `ESE_CAP_REACH_V2` (bit 17, 0x20000) | vanilla y fork-viejo ignoran limpio (test de inocuidad §10); fork-nuevo ve el vector; passthrough verificado contra ≥1 indexador no-eMule (aMule, §6.4) |
| T2 | `CReachPipeline`: cascada §7 como selector único en `TryToConnect`, con memoria de ruta por NodeID | matriz §10 completa en banco de pruebas 2-PC; cero regresión clásica |
| T3 | Rendezvous k>1 (§8.1) sobre el pool de keepalive; publicación `rdv[]` | caída de un rdv no corta contactabilidad (test con 3 PCs) |
| T4 | UI de estado de ruta (§7.5); retirada del semáforo LowID para nodos eSE | — |
| T5 | Relay de datos generalizado (§8.2), tras E-β | par con UDP bloqueado transfiere vía relay, E2E cifrado |
| T6 (opc.) | Identidad firmada (vector firmado por clave del NodeID, §11.1) | suplantación de vector imposible en test |
| T7 | Extracción de `libreach` + publicación de KEP-1, registro y suite de conformidad (§13) | una implementación externa (patch aMule o mod) pasa la suite y conecta cross-client por punch |

Esfuerzo total estimado: calibre **v9** — comparable a un sprint mayor
del roadmap, no a un parche. T1+T2 son el corazón; T3–T7 son
incrementales y cada uno deja el sistema en estado consistente. T7
tiene además una implicación de orden: cuanto antes se sepa que se
publicará (decisión, no código), antes conviene escribir la cascada y
el TLV como módulo limpio sin dependencias MFC — extraer `libreach` a
posteriori de código entrelazado costaría el doble.

### 14.3 Criterio de oportunidad (cuándo merece la pena)

Simétrico al criterio registrado para la Kad v6: esto paga cuando hay
**masa de pares eSE↔eSE reales** que sufren el bloqueo LowID↔LowID o el
churn de identidad-por-IP. Señales concretas de "ya": los contadores de
la Fase 0–1 muestran punches frecuentes (la mecánica se usa), y/o Live
escala a meshes donde la identidad TunnelEndpoint convive incómodamente
con un plano clásico keyed por IP. Señal de "todavía no": base de
usuarios donde casi todo par ya conecta por las fases del plan. El
coste de esperar es cero — ninguna decisión de la tesis se vuelve más
cara por posponerse, porque los tags y cap bits quedan reservados aquí.

### 14.4 Reservas de espacio de nombres (efectivas desde este documento)

```
TAG_ESE_REACH        = 0x68    // TLV vector de alcanzabilidad. Slot de TAG auditado
                               // libre (Opcodes.h:485: "namespace 0x68-0xCF libres").
                               // Nota anti-confusión: 0x68 coincide numéricamente con
                               // el OPCODE KADEMLIA3_HOLEPUNCH_REQ (Opcodes.h:727);
                               // tags y opcodes son espacios de nombres distintos.
ESE_CAP_REACH_V2     = 0x00020000  // bit 17 — entiende TAG_ESE_REACH y cascada v2
                                   // Fuente de verdad: docs/protocol/PROTOCOL_REGISTRY.md §2.2
                                   // (bit 15 = ESE_CAP_HOLEPUNCH_RDV, bit 16 reservado;
                                   //  CAPABILITIES.csv:17 fija REACH_V2 en bit 17/0x20000)
// 0x66/0x67 (v6): ya reservados
```

---

## 15. Conclusión

El LowID nunca fue un bug; fue una abstracción razonable en 2002 que el
mundo dejó de cumplir. Veinte años de NAT, CGNAT y movilidad lo han
convertido en una deuda conceptual que castiga a una fracción creciente
de usuarios por la topología de su ISP, bloquea estructuralmente los
pares doblemente NATeados y contamina identidad, protocolo e interfaz
con un juicio binario que ya no informa nada.

La industria resolvió este problema hace década y media — Tor, ICE,
libp2p — y siempre con la misma jugada: **identidad como clave, alcanzabilidad
como negociación**. Esta tesis muestra que la jugada es ejecutable en
Kad sin romper un solo cliente clásico (doble publicación, tags
ignorables, cap bits), que el fork eSE ya la ejecutó una vez en
miniatura (la identidad por `TunnelEndpoint` de Live), y que su
fontanería — uTP, punch, keepalive, túneles — ya existe o está
planificada. Lo que falta no es un mecanismo: es dejar de modelar el
concepto. Publicar vectores en vez de tipos, negociar caminos en vez de
leer bits, y mostrar rutas en vez de estigmas.

Cuando llegue el momento (§14.3), el cambio cabe en siete tramos
incrementales con gates medibles — el último de los cuales saca la
solución del fork y la deja en la puerta del ecosistema entero, como
spec abierta y librería embebible al estilo libutp (§13), para que
abolir el LowID no sea un rasgo de eSE sino un bien común de la red.
Hasta entonces, este documento reserva los nombres, fija la doctrina y
deja constancia de la decisión de diseño: **en eSE, ser difícil de
alcanzar es un problema de rutas; quién eres, no se negocia con el
router.**

---

## Apéndice A — Wire format propuesto: `TAG_ESE_REACH` (0x68)

TLV dentro de un tag BSOB Kad estándar (ignorable por upstream):

```
offset  tam   campo
0       1     versión (=1)
1       2     capflags (LE):
              bit0 V4_TCP_IN     test entrante positivo
              bit1 V4_UDP_IN     verificado (UDPFirewallTester / sucesor)
              bit2 V6_IN         probe inbound v6 positivo (dir. en TAG 0x66)
              bit3 PUNCH_2W      soporta OP_ESE_HOLEPUNCH_REQ/ACK
              bit4 PUNCH_3W      soporta KADEMLIA3_HOLEPUNCH_* como objetivo
              bit5 KEEPALIVE     pinhole mantenido (contactable vía rdv)
              bit6 RELAY_OFFER   acepta circuitos de datos capados
              bit7-15            reservado (=0)
3       1     nRdv (0..3)
4       22×n  rdv[n]: KadID(16) + IPv4(4) + puertoUDP(2)
              (orden de bytes idéntico al de TAG_SOURCEIP/TAG_SOURCEPORT
              existentes — anclar al convenio del código, no redefinirlo)
```

Tamaño máximo: 4 + 66 = 70 bytes. Reglas: receptor ignora versiones
mayores; emisor solo declara bits verificados (§6.5); los rdv son
contactos *verified* con sesión keepalive activa en el momento de
publicar (preferir supernodos de uptime largo: un rdv[] churned es un
vector muerto hasta la siguiente republicación); las entradas rdv cuyo
nodo anuncia `RELAY_OFFER` actúan además como anclas de relay (§8.2).
Limitación asumida v1: los rdv se direccionan solo por v4 — correcto
hoy (un rdv es por definición un nodo abierto, y los abiertos v4
abundan), extensible por TLV versionado si un futuro v6-mayoritario lo
exige. La firma del vector (T6) se añadiría como TLV opcional al
final, manteniendo el prefijo parseable por versiones intermedias.

## Apéndice B — Pseudocódigo de la cascada (resumen normativo)

```text
conectar(B):
  si ruta_recordada(B.nodeID) viva → usarla; si falla, invalidar y seguir
  R_B = vector de B (TAG_ESE_REACH) o proyección de su registro clásico
  para capa en [DIRECTO_V6, DIRECTO_V4, CALLBACK, PUNCH_2W, PUNCH_3W, RELAY]:
      si capa.aplicable(mi_vector, R_B) y caps mutuos anunciados:
          resultado = capa.intentar(B, presupuesto[capa])
          si resultado = conectado:
              recordar_ruta(B.nodeID, capa); return socket
  return camino_clásico_0.70b(B)        # nunca peor que upstream
```

Invariantes: (1) ninguna capa eSE se intenta sin cap bit mutuo; (2)
todo endpoint de punch debe responder nonce antes de recibir más de N
paquetes; (3) el fallo de todas las capas degrada a clásico, jamás a
error nuevo.

## Apéndice C — Glosario

- **Vector de alcanzabilidad (`R`):** conjunto verificado de formas en
  que un nodo puede ser contactado/alcanzado ahora mismo (§3.2).
- **Rendezvous (rdv):** nodo abierto con sesión viva hacia un nodo
  NATeado, que reenvía señalización y coordina punches. Generalización
  k>1 del buddy.
- **Cascada / `CReachPipeline`:** selector único de camino de conexión,
  estilo ICE (§7).
- **DHT server/client:** rol de enrutado en Kad; única distinción de
  alcanzabilidad que sobrevive a la tesis (§9).
- **Doble publicación:** emitir registro clásico intacto + tags v2
  ignorables (§6.1).
- **Punch 2-vías/3-vías:** perforación NAT directa / coordinada por
  rendezvous, con transporte uTP resultante.

## Apéndice D — Mapa documental

| Documento | Relación con esta tesis |
|---|---|
| LOWID_NAT_TRAVERSAL_PLAN.md | **Prerequisito.** Construye los caminos (fases 0–4) que la cascada §7 consume. La tesis no duplica su contenido. |
| IPV6_PLAN.md / IPV6_ANALYSIS.md / IPV6_SPRINT_PLAN.md | Pata v6 del vector (`V6_IN`, tag 0x66); decisión "no Kad v6 paralela" respetada íntegramente (§9). |
| PAPER_eSE_Live_ES.md | Precedente de identidad sin IP (`TunnelEndpoint`) y del plano de túneles que el relay §8.2 reutiliza. |
| V8.1_SPRINT_PLAN.md / V8.1.1_SPRINT_E_BREAKDOWN.md | E-β (viewer-relays) comparte infraestructura con §8.2; la tesis es posterior en el roadmap (v9). |
| Monografía Kad Search v2 | Rediseño hermano del subsistema de búsqueda; el registro de fuente v2 (§6) deberá armonizarse con su modelo de resultados. |
| KEP-1 + `libreach` + suite de conformidad (futuros, §13/T7) | Artefactos publicables para el ecosistema; repo público propio cuando T7 arranque. La spec normativa será KEP-1, no esta tesis (la tesis es el *porqué*; la spec, el *qué exacto*). |

## Apéndice E — Boceto de la superficie de `libreach` (C ABI, patrón `utp.h`)

Ilustrativo, no normativo — la API exacta se congela en T7. Su función
aquí es que un implementador potencial pueda oler el tamaño real de la
integración (§13.5) sin leer nada más:

```c
/* ciclo de vida — sin sockets, sin hilos, sin Kad dentro */
reach_ctx *reach_init(const reach_callbacks *cb, void *user);
void       reach_tick(reach_ctx *, uint64_t now_ms);  /* ~1 Hz; cf. gancho Kademlia.cpp:227 */
void       reach_destroy(reach_ctx *);

/* tabla de callbacks que inyecta el anfitrión */
typedef struct {
    void (*send_udp)(void *user, const reach_addr *to,
                     const uint8_t *buf, size_t len);
    void (*connect_tcp)(void *user, const reach_addr *to);
                     /* camino directo/clásico: el anfitrión conecta */
    void (*kad_signal)(void *user, const reach_peer_id *via_rdv,
                       const uint8_t *buf, size_t len);
                     /* señalización vía la Kad del anfitrión (FWD a rendezvous) */
    void (*path_result)(void *user, const reach_peer_id *peer,
                        reach_path path, int ok);
                     /* path ∈ DIRECT_V6|DIRECT_V4|CALLBACK|PUNCH_2W|PUNCH_3W|RELAY */
    void (*get_random)(void *user, uint8_t *buf, size_t len);
                     /* CSPRNG del anfitrión (nonces) */
} reach_callbacks;

/* plano de paquetes: todo datagrama entrante se ofrece a la lib */
int  reach_feed_udp(reach_ctx *, const reach_addr *from,
                    const uint8_t *buf, size_t len);
     /* devuelve !=0 si lo consumió; 0 = "no era mío, procesadlo vosotros" */

/* modelo de datos (TLV del Apéndice A) */
int  reach_vector_encode(const reach_vector *, uint8_t out[REACH_TLV_MAX]);
int  reach_vector_decode(const uint8_t *buf, size_t len, reach_vector *out);

/* política */
void reach_connect(reach_ctx *, const reach_peer_id *peer,
                   const reach_vector *hint /* del search result, o NULL */);
void reach_set_limits(reach_ctx *, const reach_limits *);
     /* sesiones máx., rate por /64, presupuesto de relay */
```

Tres decisiones encarnadas en esta superficie:

1. `reach_feed_udp` con retorno consumido/no-consumido permite
   compartir el puerto Kad existente sin demultiplexor nuevo — el
   mismo patrón con el que `FeedRawUdp` alimenta hoy a `CUtpSocket`
   desde `ClientUDPSocket.cpp:93`.
2. `kad_signal` mantiene a la lib ciega a Kad: el anfitrión decide
   cómo viaja la señalización por su propia red. La lib no opina sobre
   routing, solo sobre *qué* decir y *cuándo*.
3. Cero hilos y cero E/S propios hacen el comportamiento reproducible:
   la suite de conformidad ejecuta la lib con reloj y CSPRNG falsos y
   obtiene trazas deterministas — sin esto, los vectores golden de
   KEP-1 no podrían cubrir la máquina de estados, solo el formato.
