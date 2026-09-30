# Plan: resolución de LowID sin abrir puertos (NAT traversal eSE)

**Fecha:** 2026-06-11
**Estado:** propuesta de sprint, no implementado
**Objetivo:** conectividad real eSE↔eSE detrás de NAT sin requerir port-forward/UPnP, como
complemento (no sustituto) de los callbacks clásicos. Cubre transferencias entre nodos del
fork y, sobre todo, el plano de datos de Live.

---

## 0. Encuadre y reglas

- **No cambia la etiqueta LowID** frente a servidores eD2K ni clientes vanilla. Lo que
  resuelve es la *alcanzabilidad real* entre nodos eSE. Frente a vanilla seguimos con el
  callback de siempre.
- **Backward-compat obligatoria** (ver [[feedback_backward_compat]]): todos los caminos
  nuevos van detrás de `TAG_ESE_CAPS` / `CAP_FORK_*`. Un peer que no corre el fork ignora
  los tags y cae al comportamiento 0.70b. Cero opcodes que rompan a upstream.
- **Estabilizar antes que añadir** (ver [[feedback_stabilize_before_features]]): la Fase 0
  (validar lo ya escrito) **bloquea** el resto. No construimos sobre código nunca probado.
- **100% gratis, sin terceros para entrega** (ver [[feedback_gratis_no_barato]],
  [[feedback_cloudflare_tos]]): rendezvous y relays son peers de la propia red, nunca un
  VPS/servicio externo.

### Estado del andamiaje (auditoría 2026-06-11)

| Mecanismo | Estado real | Archivo clave |
|---|---|---|
| uTP (libutp) integrado | **Activo** | `eMuleAI/UtpSocket.cpp`, `ClientUDPSocket.cpp:93` |
| Hole-punch 2-vías (REQ/ACK) | **Cableado, sin validar 2-PC** | `KademliaUDPListener.cpp:2181-2340`, `BaseClient.cpp:1556` |
| Hole-punch 3-vías (rendezvous) | Esqueleto, handlers stub | `HolePuncher.cpp`, `Opcodes.h:727` (`KADEMLIA3_HOLEPUNCH_*`) |
| KadKeepalive (mantener pinhole) | Esqueleto | `KadKeepalive.cpp` |
| FirewallProberV6 (cascada) | Esqueleto, `Try*()` = false | `FirewallProberV6.cpp:197-201` |
| Relay por túnel onion | Arquitectura completa (control), datos = E-β | `LiveTunnel.cpp`, `ESE_CAP_TUNNEL_DATAPLANE` |
| Listener dual-stack v6 | Activo opt-in, fix `GetPeerAddressV4` sin validar | `ListenSocket.cpp:2441` |

Eng, punto de enganche de ticks: `Kademlia.cpp:227` ya llama
`CLiveTunnel::Get().Tick()` y `CKadV2TunnelPool::Get().Tick()` en el loop de ~1 s — ahí
entran `CHolePuncher::Tick()` y `CKadKeepalive::Tick()`.

---

## Fase 0 — Validación del 2-vías existente (GATE, ~1 sesión)

No es código nuevo: es probar end-to-end lo que ya está escrito y nunca se ejecutó entre
dos máquinas. Si esto no funciona, nada de lo demás importa.

**Tareas**
1. Dos PCs, ambos LowID (NAT doméstico), Kad conectado, `UtpHolePunchEnabled = on`,
   `SupportsUTP()` true en ambos.
2. Forzar conexión A→B (descarga de un fichero que solo tiene B). Confirmar en log:
   `SendEseHolePunchReq` en A → `HOLEPUNCH_REQ` recibido en B → `HOLEPUNCH_ACK` de vuelta →
   `SeedNatTraversalExpectation` en ambos → uTP accept (reset de
   `m_uNatRendezvousAttempts` en `UtpSocket.cpp:388`).
3. Verificar contadores `/api/status`: `m_dwHolePunchSuccess` / `m_dwHolePunchAttempts`.
4. Probar la rama de NAT simétrico: confirmar que tras 4 intentos se diagnostica y
   se incrementa `m_dwHolePunchSymNATFail` sin spamear REQs.

**Criterio de salida:** al menos un par de routers domésticos completa el pinhole y
arranca una transferencia uTP sin puertos abiertos. Documentar qué tipos de NAT pasan.

**Riesgos conocidos a vigilar:** orden host/network del IP (`ntohl` en `BaseClient.cpp:1596`),
matching del accept uTP a la expectativa sembrada, y la interacción con el cifrado Kad-UDP.

---

## Fase 1 — Rendezvous de 3-vías (la pieza que cierra LowID↔LowID)

El 2-vías solo abre el pinhole si B puede **recibir** el REQ por UDP. Si A y B están ambos
NATeados sin keepalive, el REQ de A no llega: hace falta un tercero R que ya mantenga
conexión viva con B y le reenvíe el FWD. Esto es el clásico STUN/ICE-style rendezvous, y el
andamiaje (`CHolePuncher` + opcodes `KADEMLIA3_HOLEPUNCH_REQ/FWD/ACK`) ya existe a medias.

**Decisión de diseño — quién es R:** reutilizar el **buddy system de upstream**. Un nodo
firewalled ya mantiene conexión viva con su buddy, y la IP:puerto del buddy ya viaja en los
resultados de búsqueda Kad (`TAG_BUDDYHASH`/`TAG_SERVERIP`/`TAG_SERVERPORT`, ver
`Search.cpp`). Así no inventamos infraestructura nueva de supernodos: A manda REQ al buddy
de B, el buddy reenvía FWD a B por la conexión existente, ambos disparan UDP simultáneo.

**Tareas**
1. **Wire opcodes Kad3** en `KademliaUDPListener`: hoy `KADEMLIA3_HOLEPUNCH_REQ/FWD/ACK`
   caen en `Process_KADEMLIA3_GENERIC` (stub, `KademliaUDPListener.cpp:500-507`).
   Implementar los tres handlers reales que delegan en `CHolePuncher::OnRequest/OnForward/OnAck`.
2. **Implementar el envío** que hoy es TODO en `HolePuncher.cpp:62,84,105`: añadir
   `SendKad3HolepunchReq/Fwd` en el listener (paralelos a `SendEseHolePunchReq`, con el mismo
   esquema de nonce CSPRNG + cifrado por `CKadUDPKey` cuando el contacto está en la routing table).
3. **Selección de R**: en `BaseClient::TryToConnect`, cuando el 2-vías directo no es posible
   (B no está en nuestra routing table / sin ruta UDP directa) pero B tiene buddy válido
   (`HasValidBuddyID()` ya se comprueba en `BaseClient.cpp:1630`), invocar
   `CHolePuncher::StartPunch(B, buddyDeB, buddyPort)`.
4. **Cablear `CHolePuncher::Tick()`** en `Kademlia.cpp:227` junto a los otros ticks.
5. **Semilla NAT bilateral**: en `OnForward` (lado B) y al recibir el FWD-ACK (lado A),
   llamar `SeedNatTraversalExpectation` igual que ya hace el 2-vías, para que el uTP accept
   reconozca el SYN entrante.
6. **Cap bit**: reservar `ESE_CAP_HOLEPUNCH_RDV` (bit 15 / 0x8000 — primer libre tras los bits
   12-14 ya ocupados por TUNNEL_DATAPLANE/LIVE_CHUNK_FRAG/TUNNEL_BULK; ver PROTOCOL_REGISTRY.md)
   y solo intentar 3-vías contra peers que lo anuncian.
7. **Anti-abuso**: el cap `MAX_SESSIONS=32` y el rate-limit por /64 ya están; añadir que R
   solo reenvía FWD a un B que es su buddy actual (no relay abierto a cualquiera).

**Cobertura esperada:** full-cone, restricted y port-restricted NAT (mayoría de routers
domésticos). Simétrico↔simétrico sigue cayendo a Fase 3.

**Criterio de salida:** A y B ambos LowID, ninguno en la routing table del otro, completan
pinhole vía el buddy de B y arrancan uTP. Backward-compat: contra un peer sin el cap, no se
emite ningún Kad3 (cae a buddy/server callback clásico).

**Esfuerzo:** medio. La máquina de estados y la criptografía de nonce ya existen; el trabajo
es wiring de handlers + selección de R + 1 cap bit.

---

## Fase 2 — KadKeepalive (mantener el pinhole abierto)

Complementa al punching: sin tráfico, el conntrack del firewall caduca (~30-60 s) y el nodo
deja de ser alcanzable. Pings periódicos a un pool de supernodos mantienen la entrada
abierta, de modo que un nodo firewalled sigue recibiendo Kad-UDP sin necesidad de buddy.
Barato (<1 KB/s), funciona incluso tras CGNAT (el egress ya funciona).

**Tareas**
1. **Selección de pool** (hoy TODO, S5.3): poblar `m_supernodes` desde la routing table Kad
   eligiendo 5-10 contactos verified con buen RTT. Rotar al que acumula
   `consecutiveMisses`.
2. **Reutilizar PING existente**: no inventar opcode — usar `KADEMLIA2_PING`/`PONG` que ya
   procesa el listener. El "keepalive" es solo cadencia (~25 s) y contabilidad.
3. **Cablear `CKadKeepalive::Tick()`** en `Kademlia.cpp:227`.
4. **Activación condicionada**: `Start()` solo cuando somos LowID/firewalled y Kad está
   conectado. `Stop()` si pasamos a HighID. El `FirewallProberV6` la arranca cuando la
   cascada se asienta en `LayerKeepalive` (ya previsto en el header).
5. **Telemetría**: exponer `GetStats()` (pingsSent/pongsReceived/supernodesActive) en
   `/api/live/debug` para ver en vivo si el pinhole se mantiene.

**Criterio de salida:** un nodo firewalled con keepalive on recibe un `HOLEPUNCH_REQ`
entrante (Fase 0/1) tras >60 s de inactividad, demostrando que el conntrack siguió abierto.

**Esfuerzo:** bajo-medio. Sin opcodes nuevos; es selección de pool + cadencia + tick.

**Nota de coste de red:** pool de 8 × ping/25 s ≈ tráfico despreciable; vigilar no duplicar
con el refresco normal de la routing table (no pinguear contactos que Kad ya está sondeando).

---

## Fase 3 — Relay por túnel onion (fallback universal, tipo TURN sin servidores)

Para el ~5-10% que el punching no cubre (simétrico↔simétrico, UDP totalmente bloqueado).
Los túneles onion del fork ya atraviesan NAT por construcción (cadenas de conexiones TCP
salientes), así que extender el plano de control a datos da un TURN propio sin terceros, con
peers HighID voluntarios como relays. Misma dirección que E-β (viewer-relays) del roadmap
([[project_v8_roadmap]]), así que el trabajo se amortiza.

**Tareas**
1. **Reutilizar `OP_LIVE_TUNNEL_CELL`** (0xD5) y la cripto onion existente
   (`LiveCircuit::OnionEncrypt/PeelOne/DecryptAll`). No hay opcode nuevo de transporte.
2. **Selección de relay**: un nodo firewalled abre circuito hacia un peer HighID que anuncia
   `ESE_CAP_TUNNEL_DATAPLANE` (bit 12, ya definido) y lo usa como punto de encuentro. El par
   remoto también abre circuito al mismo relay (rendezvous por `streamKey`/hash de fichero).
3. **Aprovechar `LiveBuddyRelay`** (hoy stub) como capa de negociación: estados
   `LookingForBuddy → Negotiating → Active` ya esbozados; implementar `ConnectViaBuddy` y
   `AcceptRelayFromBroadcaster`.
4. **Contabilidad de ancho de banda** en el relay (es un voluntario; cap configurable) y
   `Tick()` de limpieza/fallback en `StateBuddyLost`.
5. **Orden ICE**: este camino es el último de la cascada. Solo se intenta tras agotar
   directo → 2-vías → 3-vías. Encaja en `FirewallProberV6::LayerBuddyRelay`.

**Criterio de salida:** dos nodos que fallan el punching (forzar bloqueo UDP) intercambian
datos vía un tercer nodo HighID, con la carga útil cifrada extremo-a-extremo (el relay no ve
contenido).

**Esfuerzo:** alto. Es el más caro y el de menor cobertura marginal — por eso va el último.
Depende de que el plano de datos de túnel (E-α/E-β) esté maduro.

---

## Fase 4 — IPv6 directo (la vía estructural)

Cuando ambos extremos tienen v6, no hay NAT que atravesar: solo firewall stateful, que cae
con el keepalive de la Fase 2. Es la solución limpia a largo plazo y la cascada de
`FirewallProberV6` ya la contempla como capa superior. No construir Kad v6 paralela
([[project_ipv6_kad_shelved]]); esto es solo transporte v6 + alcanzabilidad.

**Tareas**
1. **Validar 2-PC el listener dual-stack** y el fix `GetPeerAddressV4`
   ([[project_ipv6_dualstack_root_cause]]) bajo `IPv6PreferredMode` — es el gate de esta fase.
2. **Implementar `TryHighID()` de verdad** (`FirewallProberV6.cpp:163`): hoy detecta v6
   público por WinHTTP (egress) pero siempre devuelve false. Añadir prueba de **inbound**:
   un peer eSE con `CAP_FORK_IPV6_DUALSTACK` nos conecta de vuelta a `[v6]:puerto`
   (análogo a `OP_PUBLICIP_ANSWER` pero v6). Si entra, somos HighID v6 → fin de la cascada.
3. **Anunciar la dirección v6** en el registro Kad v4 (tag `\x66` ya reservado,
   [[project_ipv6_kad_shelved]]) para que peers v6-capaces nos contacten directo.
4. **Preferir v6 en `TryToConnect`**: si el peer anunció v6 y tenemos v6, intentar conexión
   directa v6 antes de cualquier hole-punch v4.
5. **Keepalive v6**: reutilizar Fase 2 contra supernodos v6 para sostener el conntrack del
   firewall stateful v6.

**Criterio de salida:** dos nodos dual-stack se conectan directos por v6 sin punching,
con caída automática a v4+punch si la ruta v6 falla.

**Esfuerzo:** medio, pero alto valor estructural. Bloqueado por la validación dual-stack
pendiente.

---

## Orden recomendado y dependencias

```
Fase 0 (validar 2-vías) ──► Fase 1 (3-vías/rendezvous) ──► Fase 2 (keepalive)
        │                                                        │
        └──────────────► Fase 4 (IPv6) ◄────────────────────────┘
                                                                 │
                                              Fase 3 (relay túnel, último recurso)
```

- **Fase 0 bloquea todo.** Es el reloj funcionando antes de añadir.
- **Fase 1** es la de mayor impacto/esfuerzo: cierra LowID↔LowID para la mayoría de NAT.
- **Fase 2** multiplica el valor de 0/1 (sin keepalive, los pinholes caducan).
- **Fase 4** puede correr en paralelo a 1/2 (equipo/tiempo distinto) y es la salida limpia.
- **Fase 3** va al final: máximo coste, mínima cobertura marginal, pero es la red de
  seguridad universal (ICE-style: punch primero, relay como último recurso).

## Cap bits a reservar (Opcodes.h)

```
// CORREGIDO 2026-06-13: bits 13/14 chocaban con ESE_CAP_LIVE_CHUNK_FRAG (0x2000) y
// ESE_CAP_TUNNEL_BULK (0x4000), ya en código. Movidos a 15/16. Ver
// docs/protocol/PROTOCOL_REGISTRY.md §2.2.
#define ESE_CAP_HOLEPUNCH_RDV   0x00008000  // bit 15 — rendezvous 3-vías (Fase 1)
#define ESE_CAP_KAD_KEEPALIVE   0x00010000  // bit 16 — mantiene pinhole (Fase 2)
// ESE_CAP_TUNNEL_DATAPLANE 0x1000 (bit 12) ya cubre Fase 3
// CAP_FORK_IPV6_DUALSTACK 0x04 ya cubre Fase 4
```

## Qué se descarta (y por qué)

- **PCP / IGDv2-AddPinhole**: siguen siendo "abrir puertos"; ya cubierto por UPnP/NAT-PMP.
- **TCP hole punching**: poco fiable teniendo uTP sobre UDP.
- **Port-prediction para NAT simétrico**: frágil; mejor caer a relay (Fase 3).
- **DERP/Tailscale para datos**: tercero externo, choca con la regla de no depender de
  nadie para entrega ([[feedback_gratis_no_barato]]).
