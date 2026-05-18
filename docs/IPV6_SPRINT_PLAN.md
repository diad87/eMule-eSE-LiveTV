# Plan de Ejecución IPv6 — Sprints, Verificación, Anti-Regresión

**Documento operativo complementario a [IPV6_PLAN.md](IPV6_PLAN.md).**
Versión 1.0 — 2026-05-17
Estado: propuesta de ejecución

> **Lectura previa obligatoria**: [`IPV6_PLAN.md`](IPV6_PLAN.md). Este documento asume que las decisiones arquitectónicas (ADRs, fases, opcodes, cascada anti-firewall) están aceptadas.

---

## §0 — El invariante primordio: NO ROMPER NADA

Todo el plan se construye sobre una sola regla, no negociable:

> **Cualquier PR que merge a la rama de integración debe pasar la Smoke Matrix completa (§3) con `IPv6Enabled=false`, comportándose byte-a-byte como la baseline tagged en Sprint 0.**

Corolarios:

1. **Toda funcionalidad IPv6 está detrás de un flag**, default `false`, hasta el Sprint 9 (beta).
2. **Ningún opcode legacy se modifica** — solo se añaden opcodes paralelos. Los handlers viejos quedan intactos.
3. **Ningún formato de archivo legacy se sobrescribe sin backup `.bak`**. Los parsers viejos siguen presentes y funcionales.
4. **Cada sprint produce un build ejecutable y desplegable**. No hay sprints "intermedios" que rompan la compilación o el arranque.
5. **Refactor PRs y feature PRs van separados**. Un PR no mezcla "muevo este código + añado IPv6". Primero refactor, luego feature.
6. **Pcap diff obligatorio**: si la baseline genera unos paquetes determinados en un escenario, el nuevo build debe generar los mismos bytes (modulo nuevos tags aditivos al final de los packets) en el mismo escenario.
7. **Rollback estudiado por adelantado**: cada sprint documenta cómo revertir su trabajo si se descubre un blocker en sprints posteriores.

Cuando dos requisitos colisionen — uno de la feature y otro del invariante — **gana el invariante**. Si una feature IPv6 no se puede implementar sin romper la baseline, no se implementa.

---

## §1 — Estrategia de testing

### 1.1 Niveles de prueba

| Nivel | Qué prueba | Cuándo se ejecuta | Owner |
|---|---|---|---|
| **L0 Build** | Compila en Debug + Release × x86 + x64 | Cada commit (CI) | Automático |
| **L1 Unit** | Funciones aisladas (`CAddress`, parsers, hashers) | Cada commit (CI) | Dev del PR |
| **L2 Integration** | Componentes que se llaman entre sí (Kad bootstrap, source exchange) | Cada PR a integration | CI + dev |
| **L3 Smoke matrix** | Recorrido funcional canónico (§3) con dos eMule reales | Cada PR a integration (manual + scripted) | QA + dev |
| **L4 Wire pcap diff** | Bytes en el cable son idénticos a baseline en escenarios fijados | Cada sprint, gate de merge | Automático |
| **L5 File roundtrip** | Archivos del baseline son legibles y reescribibles idénticos por bytes | Cada sprint que toque persistencia | Automático |
| **L6 Long-running** | 24h con Kad activo, sin leaks, sin asserts | Fin de cada sprint | Manual |
| **L7 Field** | Beta testers reales | Sprints 10-11 | Comunidad |

### 1.2 Herramientas a tener listas

- **Pcap capture/replay**: tcpdump/Wireshark en máquina virtual con la baseline, captura de los 12 escenarios canónicos. Para replay, un proceso que abra socket y inyecte paquetes a velocidad controlada, comparando outputs.
- **File fixtures**: directorio `tests/fixtures/baseline/` con `nodes.dat`, `server.met`, `known.met`, `preferences.ini`, `ipfilter.dat`, `credits.met` copiados de una instalación operativa con datos significativos (~100 contactos Kad, ~50 servidores, ~50 archivos compartidos).
- **Two-PC harness**: dos PCs en LAN (o dos VMs) configurados como `PC1` (broadcaster/seeder) y `PC2` (viewer/leecher). Snapshots de VM para reset rápido.
- **Memory leak detector**: Visual Leak Detector o el `_CRTDBG_MAP_ALLOC` ya presente en eMule, ejecutado en builds Debug.
- **Pcap diff script**: Python con `scapy`, ignora timestamps y orden de tags semánticamente equivalentes, marca diferencias byte-a-byte de payload.
- **Static analysis**: PVS-Studio o cppcheck con ruleset actual del repo (si existe), corrido pre-merge.

### 1.3 Definition of Done genérica

Una story se considera **Done** cuando:

1. Compila Debug + Release × x86 + x64 sin warnings nuevos.
2. Tests L1 nuevos pasan, tests L1 viejos siguen pasando.
3. Tests L2 relevantes pasan.
4. Smoke matrix L3 pasa con `IPv6Enabled=false`.
5. Smoke matrix L3 IPv6-extra (§3.2) pasa con `IPv6Enabled=true` si aplica al sprint.
6. Pcap diff L4 sin diferencias inesperadas.
7. File roundtrip L5 sin diferencias.
8. PR revisado por al menos 1 dev más (o aprobado por el dueño del módulo).
9. Documentación actualizada (CHANGELOG.md, comentarios en código si aplica).
10. La feature está detrás del flag correspondiente, default OFF.

---

## §2 — Infraestructura previa (Sprint 0 = "pre-sprint")

Antes del Sprint 1 hay que tener:

- [ ] Repositorio con CI activo (Win build + tests automatizados).
- [ ] Tag `baseline-v0.70b-pre-ipv6` en el commit del último release estable del fork (hoy: `07d09c1`).
- [ ] Build firmado de la baseline disponible para QA (esto es el "control" contra el que se compara todo).
- [ ] Dos VMs Windows 10/11 con la baseline instalada y configurada (PC1 seeder, PC2 leecher).
- [ ] Pcaps de los 12 escenarios canónicos capturados desde la baseline, guardados en `tests/fixtures/pcaps/`.
- [ ] Fixtures de archivos de configuración (§1.2) capturados de la baseline.
- [ ] Branch `feature/ipv6-integration` creada desde `baseline-v0.70b-pre-ipv6`.
- [ ] Issue tracker con los épicos por fase y stories por sprint (este documento sirve como input).
- [ ] Documento `tests/REGRESSION.md` con la smoke matrix (§3) en formato checklist marcable.

Si falta alguno → no se arranca Sprint 1.

---

## §3 — Smoke Matrix canónica

**Cada uno de estos escenarios debe funcionar antes Y después de cada sprint con `IPv6Enabled=false`.**

Si un sprint introduce IPv6, también debe pasar el subconjunto §3.2 con `IPv6Enabled=true`.

### 3.1 Baseline IPv4 (siempre)

| # | Escenario | Cómo verificar | Esperado |
|---|---|---|---|
| B1 | **Launch** | Doble click `emule.exe` | UI abre, no crash, log sin errores |
| B2 | **Conexión servidor** | Connect to `DonkeyServer No2` o equivalente IPv4 | Estado "Connected", IP servidor visible en status bar |
| B3 | **HighID/lowID** | Mirar status bar tras conexión | HighID si IPv4 pública permite, lowID si no — sin error |
| B4 | **Search** | Buscar `linux iso` con todas las opciones default | ≥1 resultado en lista |
| B5 | **Download start** | Click derecho → Download en un resultado | Aparece en lista de descargas, fuentes empiezan a aparecer |
| B6 | **Download complete** | Esperar fin de un archivo ≤10MB | Estado "Complete", hash verificado |
| B7 | **Hash check** | Hash del file completado vs hash conocido del repositorio | Idénticos |
| B8 | **Share** | Compartir un archivo en `Incoming` | Aparece en `Shared Files` con count `>0` |
| B9 | **Kad bootstrap** | Activar Kad (Network → Kad → Bootstrap from known clients) | Estado "Connected" en pestaña Kad en ≤2 min |
| B10 | **Kad contacts** | Esperar 5 min | `Active contacts > 50` |
| B11 | **Kad search** | Buscar el mismo término que B4 vía Kad | ≥1 resultado |
| B12 | **Upload** | Otro peer descarga de nosotros (PC2 → PC1) | Aparece en `Up Stats`, bytes subidos > 0 |
| B13 | **Long-running** | Sesión de 24h con Kad activo | Memory growth < 5%, ningún assert en log, exit limpio |
| B14 | **Restart con config** | Cerrar y reabrir | Todas las descargas siguen, servers/Kad reconectan |
| B15 | **Archivo legacy** | Copiar `nodes.dat` fixture sobre el actual y arrancar | Carga sin error, contactos visibles |
| B16 | **LiveTV broadcast** | PC1 inicia broadcast, PC2 se suscribe vía LiveStreamDlg | PC2 ve el stream HLS reproducido en VLC |

### 3.2 Extra IPv6 (cuando `IPv6Enabled=true`, a partir del Sprint 3)

| # | Escenario | Cómo verificar | Esperado |
|---|---|---|---|
| V1 | **Listener v6** | `netstat -an` tras arranque | TCP `:::4662` y UDP `:::4672` listening |
| V2 | **IP pública v6** | Status bar tras 30s | Muestra IPv6 propia detectada |
| V3 | **Probe firewall** | Status bar tras probe (≤30s) | Muestra una de las capas (HighID/PCP/Keepalive/Hole-punch/Buddy/Unreachable) |
| V4 | **Kad-v6 contacts** | Pestaña Kad tras 10 min con IPv6 enabled | Contactos v6 visibles, ≥10 |
| V5 | **Cross-family interop** | PC1 IPv4-only + PC2 dual-stack hablan entre sí | Conexión TCP funciona vía IPv4 (V6ONLY=0 lo permite) |
| V6 | **IPv6-only end-to-end** | PC1 dual-stack + PC2 con IPv4 deshabilitada en SO | Encuentran fuentes vía Kad-v6 y transfieren chunk |
| V7 | **LiveTV v6 mesh** | PC1 broadcaster v6 + PC2 viewer v6 | Stream llega, sin pasar por IPv4 (verificar con tcpdump) |

### 3.3 Compatibility (siempre que se toque wire o disco)

| # | Escenario | Cómo verificar | Esperado |
|---|---|---|---|
| C1 | **Wire ↔ baseline** | PC1 nuevo + PC2 baseline. Intercambio completo download. | Sin diferencias funcionales |
| C2 | **Wire ↔ upstream 0.70b** | PC1 nuevo + PC2 upstream eMule oficial 0.70b. | Conexión OK, search OK |
| C3 | **Disco ↔ baseline** | Copiar `nodes.dat`/`server.met`/`known.met` de baseline al nuevo. | Arranca, datos preservados |
| C4 | **Disco ↔ upstream** | Igual con archivos de upstream eMule 0.70b. | Arranca, datos preservados |
| C5 | **Downgrade** | Tras correr el nuevo, copiar `.bak` sobre los archivos y arrancar la baseline. | Baseline arranca normal |
| C6 | **Pcap diff** | Capturar 5 min de Kad activity con baseline e idéntico setup con nuevo + `IPv6Enabled=false`. | Diff vacío (modulo timestamps) |

---

## §4 — Sprint 0: Baseline y setup (semanas 1-2, en paralelo con preparación)

### Objetivo
Establecer la línea base contra la que se medirá todo lo demás. Sin código nuevo de IPv6 — solo plumbing.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S0.1 | Tagear `baseline-v0.70b-pre-ipv6` y firmar binarios | git, build server | XS |
| S0.2 | Setup CI con build x86+x64 Debug+Release | `.github/workflows/*.yml` o similar | M |
| S0.3 | Crear directorio `tests/fixtures/` con `pcaps/` y `configs/` | nuevos | S |
| S0.4 | Capturar pcaps de B1..B16 desde baseline | manual con Wireshark | M |
| S0.5 | Script `tools/pcap_diff.py` que ignora timestamps y compara payloads | Python | M |
| S0.6 | Script `tools/file_roundtrip.py` que carga y reescribe `nodes.dat` etc. | Python o C++ | S |
| S0.7 | Crear `tests/REGRESSION.md` con §3 en formato checklist | doc | XS |
| S0.8 | Branch `feature/ipv6-integration` con primer commit "empty IPv6 scaffolding" | git | XS |
| S0.9 | Two-VM harness operativo (PC1, PC2) con snapshots | infra | M |
| S0.10 | Documentar en `tests/README.md` cómo correr cada nivel | doc | S |

### DoD del sprint
- Tag visible, binario baseline en builds/.
- CI verde en branch baseline.
- Pcaps de B1-B16 capturados (>= 12 archivos en `tests/fixtures/pcaps/`).
- `pcap_diff.py` ejecutado contra él mismo da 0 diferencias.
- Smoke matrix §3.1 ejecutada manualmente en la baseline, 16/16 pasan.

### Demo
"Aquí está la baseline reproducible: tag, binario firmado, pcaps, fixtures, CI verde. Cualquiera puede reproducir B1-B16 con esta receta."

### Rollback
N/A — es el origen.

---

## §5 — Sprint 1: CAddress core (semanas 3-4) — Fase 1 inicio

### Objetivo
Completar la clase `CAddress` ([`Address.h`](srchybrid/eMuleAI/Address.h)) con los métodos que faltan (`WriteToBuffer`, `ReadFromBuffer`, `HashKey`, `GetSubnet`). Adoptarla **solo en zonas cerradas** (logging, status bar, AddSourceDlg) — nada que cruce wire ni disco.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S1.1 | Añadir `WriteToBuffer`/`ReadFromBuffer` a `CAddress` con tests | `Address.h/.cpp` + nuevo `Address_test.cpp` | M |
| S1.2 | Añadir `HashKey`, `GetSubnet`, `InSameSubnet`, `ToSyntheticUInt32` | `Address.h/.cpp` | S |
| S1.3 | Overloads `ipstr(const CAddress&)` en `OtherFunctions` | [`OtherFunctions.h/.cpp`](srchybrid/OtherFunctions.h) | XS |
| S1.4 | Reemplazar `inet_ntoa` en sitios de logging por `ipstr(CAddress)` | varios, listar | M |
| S1.5 | `AddSourceDlg` acepta sintaxis `[ipv6]:port` (parse, validar, rechazar conexión por ahora) | [`AddSourceDlg.cpp:135`](srchybrid/AddSourceDlg.cpp:135) | S |
| S1.6 | Flag `IPv6Enabled` (default false) en preferences, leído pero sin uso aún | [`Preferences.h/.cpp`](srchybrid/Preferences.h) | XS |
| S1.7 | Tests unitarios L1: roundtrip wire, conversión SA, mapped IPv4, hash distribution | `Address_test.cpp` | M |

### Archivos tocados (resumen)
- **NUEVO**: `tests/Address_test.cpp`, `tests/Address_test.h`
- **MODIFICADO** (no breaking): `eMuleAI/Address.h`, `eMuleAI/Address.cpp`, `OtherFunctions.h`, `OtherFunctions.cpp`, `AddSourceDlg.cpp`, `Preferences.h`, `Preferences.cpp`
- **NO TOCAR**: nada en wire, nada en disco, ningún listener.

### Verificación funcional (lo nuevo)
- [ ] Test unitario: `CAddress(uint32(0x01020304), true).ToStringC() == "1.2.3.4"`.
- [ ] Test unitario: roundtrip wire de IPv4 produce 6 bytes (1+1+4), de IPv6 produce 18 bytes (1+1+16).
- [ ] Test unitario: `HashKey()` distribuye ≥ 95% uniforme en 10000 inputs aleatorios.
- [ ] Test unitario: `GetSubnet(64)` de `2001:db8::1` == `2001:db8::`.
- [ ] AddSourceDlg con input `[::1]:4662` no rechaza el formato (lo guarda en `m_pendingV6` o similar, sin intentar conectar).

### Regresión obligatoria (lo que no romper)
- [ ] Smoke matrix §3.1 completa, 16/16.
- [ ] AddSourceDlg con input IPv4 `1.2.3.4:4662` funciona idéntico a baseline (genera connection).
- [ ] No hay nuevos warnings de compilación.
- [ ] Memory check L1 sin leaks en suite de tests.

### Demo
"`CAddress` totalmente funcional con tests. AddSourceDlg acepta IPv6 sintácticamente. Nada en wire ha cambiado."

### Rollback
Revertir el merge. `CAddress` queda como estaba; el código nuevo en `Address_test.cpp` y los overloads de `ipstr` son aditivos y revertibles atómicamente.

---

## §6 — Sprint 2: CAddress propagación + listener dual-stack init (semanas 5-6) — Fase 1 fin + Fase 2 inicio

### Objetivo
Extender adopción de `CAddress` a más capas internas (sin cruzar wire), y empezar la infraestructura del listener dual-stack — pero el listener IPv6 NO se enciende todavía (esperamos al Sprint 3).

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S2.1 | `CAsyncSocketEx::Create` documenta firma con `AF_INET6`, añade overload con `bDualStack` | [`AsyncSocketEx.h/.cpp`](srchybrid/AsyncSocketEx.h) | M |
| S2.2 | Wrapping de `inet_addr`/`inet_ntoa` restantes con guard de feature flag | múltiples archivos | M |
| S2.3 | Buffer `Server::ipfull[16] → [48]` con tests de overflow | [`Server.h:170`](srchybrid/Server.h:170) | XS |
| S2.4 | Preferences: añadir `IPv6BindAddress`, `IPv6Mode`, defaults | [`Preferences.h`](srchybrid/Preferences.h) | S |
| S2.5 | UI prefs: nuevo grupo "IPv6" en `PPgConnection` (toggle deshabilitado por ahora) | [`PPgConnection.cpp`](srchybrid/PPgConnection.cpp), recursos | M |
| S2.6 | `CListenSocket::StartListening()` admite `AF_INET6` con flag (encendido NO por defecto) | [`ListenSocket.cpp:2149`](srchybrid/ListenSocket.cpp:2149) | M |
| S2.7 | Tests L1: roundtrip CAddress con todos los formatos textuales (zonas, scopes, mapped) | `Address_test.cpp` | S |
| S2.8 | Tests L2: bind a `::` y rebind a `0.0.0.0` desde un test (no en eMule real) | nuevo `Socket_test.cpp` | M |

### Archivos tocados
- **MODIFICADO**: lista de S2.1-S2.6 + el set del Sprint 1.
- Crítico: ningún listener IPv6 está activo al final del sprint. El código existe pero el flag está OFF.

### Verificación funcional
- [ ] UI muestra el nuevo grupo "IPv6" en preferencias (con toggle deshabilitado y nota "experimental, próximo release").
- [ ] Test L2 `Socket_test::BindIPv6()` arranca un socket en `[::]:0`, lee la dirección efectiva, cierra — sin crash.
- [ ] Build con `IPv6Enabled=true` arranca y funciona como IPv4 normal (el toggle no hace efecto aún en runtime — solo prepara la pila).

### Regresión
- [ ] Smoke matrix §3.1 completa.
- [ ] `netstat -an` muestra **solo** `0.0.0.0:4662` (no `:::4662`). Hasta Sprint 3 el listener v6 no se enciende.
- [ ] Pcap diff L4 vs baseline: vacío.
- [ ] File roundtrip L5: `nodes.dat`/`server.met`/`known.met` byte-idénticos tras load+save.

### Demo
"La preferencia UI 'IPv6' existe y se persiste. Internamente todo está listo para encender el listener v6, pero el flag aún no hace efecto runtime — para preservar la baseline al 100%."

### Rollback
Revertir merge. Las opciones nuevas en preferences.ini quedan ignoradas por la baseline.

---

## §7 — Sprint 3: Listener dual-stack + Public IP v6 + Probe firewall (semanas 7-8) — Fase 2 fin + Fase 3

### Objetivo
**Primer hito visible**: con `IPv6Enabled=true`, el cliente escucha en `::` y detecta su IPv6 pública. La probe automática (§8.5 de IPV6_PLAN.md) reporta una capa de alcanzabilidad. **Sin opcodes wire `_V6` todavía** — la detección usa los opcodes legacy más una back-channel UDP con peers del fork ya actualizados (de momento usaremos un peer de prueba controlado por el equipo).

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S3.1 | `CListenSocket::StartListening()` con `AF_INET6` + `IPV6_V6ONLY=0` cuando flag ON | [`ListenSocket.cpp:2149`](srchybrid/ListenSocket.cpp:2149) | M |
| S3.2 | `CClientUDPSocket::Rebind()` análogo + soporte segundo socket v6-only para Kad | [`ClientUDPSocket.cpp`](srchybrid/ClientUDPSocket.cpp) | M |
| S3.3 | Reservar opcode `OP_PUBLICIP_ANSWER_V6 = 0xE0` en [`Opcodes.h`](srchybrid/Opcodes.h) y `Opcodes.h:289` doc | doc | XS |
| S3.4 | Implementar `OP_PUBLICIP_REQ` enviando *también* `OP_PUBLICIP_ANSWER_V6` cuando peer remoto tiene CAP_FORK_IPV6_WIRE (capability flag a definir aún, default 0) | [`BaseClient.cpp:2593`](srchybrid/BaseClient.cpp:2593), [`ListenSocket.cpp:1378`](srchybrid/ListenSocket.cpp:1378) | M |
| S3.5 | **Nueva clase `CFirewallProberV6`** (§8.5 cascade) con estado HighID/PCP/Keepalive/HolePunch/Buddy/Unreachable | nuevo `FirewallProberV6.h/.cpp` | L |
| S3.6 | Status bar muestra resultado de probe (`IPv6: HighID`, `IPv6: probing...`, `IPv6: lowID`) | [`EmuleDlg.cpp`](srchybrid/EmuleDlg.cpp) | S |
| S3.7 | UI prefs: toggle IPv6 ya hace efecto en runtime (con restart suave de listeners) | [`PPgConnection.cpp`](srchybrid/PPgConnection.cpp) | M |
| S3.8 | Tests L2: prober en modo "todo falla, somos lowID" debe terminar en Unreachable con eventos claros | `FirewallProberV6_test.cpp` | M |
| S3.9 | Tests L2: prober simulado con un peer mock que sí hace connect-back → HighID | `FirewallProberV6_test.cpp` | M |
| S3.10 | Documentar en `tests/MANUAL_TESTS_IPV6.md` cómo verificar V1-V3 manualmente | doc | S |

### Verificación funcional
- [ ] V1: `netstat -an` muestra `:::4662` y `:::4672` cuando `IPv6Enabled=true`.
- [ ] V2: status bar muestra IPv6 propia tras conexión a un peer test conocido (que envía OP_PUBLICIP_ANSWER_V6).
- [ ] V3: probe termina en ≤30s con un veredicto. Si el host es directamente alcanzable, "HighID".
- [ ] Test L3: dos eMules nuevos, ambos `IPv6Enabled=true`, en la misma LAN — uno detecta al otro como IPv6.

### Regresión (CRÍTICA — primer sprint que toca listening)
- [ ] **B1-B16 con `IPv6Enabled=false`**: 16/16 idénticos a baseline. Importante: `netstat` muestra solo `0.0.0.0:4662`.
- [ ] B1-B16 con `IPv6Enabled=true`: 16/16 funcionando. Importante: el listener dual-stack acepta conexiones IPv4 vía IPv4-mapped sin que el código de capas superiores note diferencia (gracias a `CAddress::IsMappedIPv4()`).
- [ ] **Pcap diff L4** con flag OFF: vacío vs baseline.
- [ ] Compatibility C1: PC1 nuevo (flag ON o OFF) + PC2 baseline → todo funciona.
- [ ] Compatibility C2: PC1 nuevo + PC2 upstream eMule 0.70b → todo funciona.

### Demo
"Status bar de eMule muestra ahora dos líneas: 'IPv4: 1.2.3.4 (HighID)' y 'IPv6: 2001:db8::1 (HighID directo)'. Funciona con cualquier peer del fork actualizado. La baseline IPv4-only no se entera de nada."

### Rollback
Revertir merge → el flag desaparece de prefs (queda como key huérfana, inocuo). El listener vuelve a ser IPv4 puro.

### Riesgo específico
`IPV6_V6ONLY=0` puede comportarse raro en algunos firewalls/AVs. Si fallamos en una máquina concreta, fallback automático a "dos sockets separados" (IPv4 en uno, IPv6-only en otro). Trabajo de contingencia: 1-2 días.

---

## §8 — Sprint 4: Kad-v6 core (semanas 9-10) — Fase 4 parte 1

### Objetivo
Kademlia con contactos IPv6, `nodes.dat` v4, y los opcodes `KADEMLIA3_HELLO_*` y `KADEMLIA3_REQ` funcionando. **Sin keepalive ni hole-punching todavía** (eso es Sprint 5).

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S4.1 | `CContact` extendido con `CAddress m_address` + adaptador legacy `m_uIp` derivado | [`Contact.h/.cpp`](srchybrid/kademlia/routing/Contact.h) | M |
| S4.2 | `nodes.dat` v4: reader nuevo + writer con flag "modo legacy" para WriteLegacyOnly | [`RoutingZone.cpp:182-228, 362-378`](srchybrid/kademlia/routing/RoutingZone.cpp:182) | L |
| S4.3 | Opcodes `KADEMLIA3_HELLO_REQ` (0x12), `_RES` (0x1A), `KADEMLIA3_REQ` (0x22) + handlers | [`Opcodes.h`](srchybrid/Opcodes.h), [`KademliaUDPListener.cpp`](srchybrid/kademlia/net/KademliaUDPListener.cpp) | L |
| S4.4 | `KADEMLIA3_BOOTSTRAP_REQ/RES` (0x02/0x09) + bootstrap dual (intenta v4 y v6) | [`Kademlia.cpp`](srchybrid/kademlia/kademlia/Kademlia.cpp) | M |
| S4.5 | Bootstrap lista estática `nodes_v6_bootstrap.dat` con 5-10 nodos del fork team | nuevo en `installer/config/` | S |
| S4.6 | Tests L1: roundtrip CContact wire | `Contact_test.cpp` | S |
| S4.7 | Tests L2: nodes.dat v2 → v4 migration con fixture | `RoutingZone_test.cpp` | M |
| S4.8 | Tests L3: dos eMules en LAN, ambos Kad-v6, se descubren y populan routing | manual + script | M |
| S4.9 | Métrica nueva en GUI: pestaña Kad muestra contactos v4 y v6 separados | [`Kademlia.cpp`](srchybrid/kademlia/kademlia/Kademlia.cpp), GUI | S |

### Verificación funcional
- [ ] V4: dos eMules en LAN con Kad-v6 → contactos v6 visibles en 10 min.
- [ ] Test L2: archivo `nodes.dat v2` se lee correctamente y se reescribe como v4 con los mismos contactos + nada nuevo (sin contactos v6, pero formato nuevo).
- [ ] Test L2: archivo `nodes.dat v4` se lee correctamente con mezcla v4/v6.
- [ ] Test L2: WriteLegacyOnly=true → `nodes.dat` reescrito en v2, contactos v6 filtrados.

### Regresión
- [ ] B9-B11 (Kad bootstrap, contacts, search) con `IPv6Enabled=false`: idénticos a baseline.
- [ ] C3 (disco ↔ baseline): copiar `nodes.dat` v2 de la baseline, arrancar nuevo, comprobar bootstrap normal.
- [ ] C5 (downgrade): tras correr nuevo con `nodes.dat v4`, hacer backup, restaurar v2, arrancar baseline → Kad arranca normal.
- [ ] **Pcap diff L4** del tráfico Kad con flag OFF: vacío.
- [ ] Long-running L6: 24h con Kad-v6, sin leak > 5%, sin assert.

### Demo
"Dos PCs en la misma LAN, ambos sin IPv4 entre ellos (deshabilitada manualmente en la VM), descubren a través de Kad-v6, intercambian HELLO, populan routing tables, hacen búsquedas Kad — todo IPv6 puro."

### Rollback
Es más complejo porque tocamos `RoutingZone.cpp`. Plan: feature branch separada para la migración v2→v4, mergeable solo cuando los tests L2 pasen al 100%. Si después se descubre un blocker, revertir el merge regenera `nodes.dat` en v2 desde la baseline (los usuarios pierden el cache pero no datos críticos).

---

## §9 — Sprint 5: Kad keepalive + hole-punching (semanas 11-12) — Fase 4 parte 2

### Objetivo
Implementar las capas C (keepalive) y D (hole-punching) de la cascada §8.5. Conectar con la probe del Sprint 3 para que la decisión de capa sea dinámica.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S5.1 | Opcodes `KADEMLIA3_PING_REQ` (0x61), `_RES` (0x62) | [`Opcodes.h`](srchybrid/Opcodes.h), Kad listener | S |
| S5.2 | **Nueva clase `CKadKeepalive`** con rotación de 5-10 supernodos, tick 25s | nuevo `KadKeepalive.h/.cpp` | M |
| S5.3 | Selección dinámica de supernodos por latencia + estabilidad | `KadKeepalive.cpp` | M |
| S5.4 | Opcodes `KADEMLIA3_HOLEPUNCH_REQ` (0x63), `_FWD` (0x64), `_ACK` (0x65) | [`Opcodes.h`](srchybrid/Opcodes.h) | XS |
| S5.5 | **Nueva clase `CHolePuncher`** con state machine A↔R↔B | nuevo `HolePuncher.h/.cpp` | L |
| S5.6 | Integración: `CFirewallProberV6` enciende keepalive si HighID directo falla; enciende hole-punch si keepalive falla | [`FirewallProberV6.cpp`](srchybrid/FirewallProberV6.cpp) | M |
| S5.7 | Tests L2: keepalive mantiene conntrack abierto en un mock-firewall (simulado con conntrack-like tracker) | `KadKeepalive_test.cpp` | M |
| S5.8 | Tests L2: hole-punch entre dos peers ambos firewalled simulados | `HolePuncher_test.cpp` | M |
| S5.9 | Tests L3: dos eMules reales en redes separadas con firewalls stateful default | manual | L |
| S5.10 | Métricas en UI: status bar añade nota cuando keepalive/hole-punch están activos | [`EmuleDlg.cpp`](srchybrid/EmuleDlg.cpp) | S |

### Verificación funcional
- [ ] PC1 con firewall stateful (drop unsolicited inbound) y PC2 normal → tras activar keepalive, PC2 puede iniciar conexión a PC1.
- [ ] PC1 y PC2 ambos firewalled → con un tercero R como rendezvous, hole-punching establece UDP bidireccional.
- [ ] Probe automática del Sprint 3 detecta esta situación y reporta capa correctamente.

### Regresión
- [ ] B9-B11 sin cambios (Kad legacy IPv4 sigue funcionando idéntico).
- [ ] Pcap diff L4 con flag OFF: vacío.
- [ ] CPU/network overhead del keepalive: < 1% CPU, < 1 KB/s upstream — medir en build Release.
- [ ] Memory de las nuevas state machines: < 100KB por cliente activo.

### Demo
"PC1 detrás de firewall doméstico estricto. PC2 quiere conectar a PC1. Sin nuestro código: imposible (no responde). Con nuestro código: keepalive mantiene PC1 alcanzable. Si keepalive falla, hole-punch coordinado por Kad establece la conexión. Funciona en ~99% de las configuraciones residenciales."

### Rollback
Las clases nuevas son aditivas. Revertir merge desactiva keepalive y hole-punch; la probe del Sprint 3 termina siempre en "lowID" pero el resto sigue funcionando.

---

## §10 — Sprint 6: eD2K wire P2P + PCP cliente (semanas 13-14) — Fase 5

### Objetivo
Capability negotiation con `CT_FORK_CAPABILITIES` en `OP_EMULEINFO`. Source exchange v5 con `CAddress`. PCP cliente para abrir pinholes automáticamente.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S6.1 | Definir tag `CT_FORK_CAPABILITIES = 0xF0` en [`Opcodes.h`](srchybrid/Opcodes.h) | doc | XS |
| S6.2 | `OP_HELLO`/`OP_HELLOANSWER` emiten tag aditivo cuando flag ON | [`BaseClient.cpp:737, 952`](srchybrid/BaseClient.cpp:737) | M |
| S6.3 | `OP_HELLOANSWER` parser preserva tags desconocidos y guarda `m_dwForkCaps` cuando reconoce el CT | [`BaseClient.cpp:746-820`](srchybrid/BaseClient.cpp:746) | M |
| S6.4 | `OP_ANSWERSOURCES2 v5` writer: si el peer es CAP_FORK_IPV6_WIRE, emite versión 5 con CAddress; si no, versión 1-3 legacy | [`KnownFile.cpp:1100-1160`](srchybrid/KnownFile.cpp:1100) | L |
| S6.5 | `OP_ANSWERSOURCES2` reader detecta versión y despacha al parser correcto | [`PartFile.cpp:2449-2528`](srchybrid/PartFile.cpp:2449) | M |
| S6.6 | PCP cliente: extender [`UPnPImplNATPMP.cpp`](srchybrid/UPnPImplNATPMP.cpp) a RFC 6887 `MAP` v2 con bloque IPv6 | M |
| S6.7 | Integración: probe del Sprint 3 invoca PCP tras detección de IPv6 firewalled | [`FirewallProberV6.cpp`](srchybrid/FirewallProberV6.cpp) | S |
| S6.8 | Tests L1: serialización de `OP_ANSWERSOURCES2` v5 roundtrip | `Packet_test.cpp` | M |
| S6.9 | Tests L2: cliente nuevo + cliente baseline intercambian sources (baseline ignora tags v6, recibe solo IPv4) | manual + script | M |
| S6.10 | Tests L2: dos clientes nuevos intercambian sources IPv6 vía v5 | manual + script | M |
| S6.11 | Tests L2: PCP mock-router responde a MAP, cliente abre pinhole, probe lo confirma | `PCP_test.cpp` | M |

### Verificación funcional
- [ ] Wireshark muestra el tag `CT_FORK_CAPABILITIES` en `OP_HELLO` del cliente nuevo.
- [ ] Source exchange entre dos peers v6 transporta direcciones IPv6 nativas en v5.
- [ ] PCP cliente envía `MAP` correcto a `[gateway]:5351` cuando se le pide abrir pinhole.
- [ ] Si router responde con éxito, probe del Sprint 3 reporta "HighID (PCP)" en lugar de "HighID directo".

### Regresión (CRÍTICA — primera vez que tocamos wire P2P)
- [ ] C1: PC1 nuevo + PC2 baseline → intercambio completo de archivo sin errores. Pcap del lado baseline no muestra tags desconocidos sin handling.
- [ ] C2: PC1 nuevo + PC2 upstream eMule 0.70b → idéntico. **Crítico**: si rompemos compat con upstream, vamos al Sprint 0.5 a entender por qué.
- [ ] B4-B7 (search, download, complete, hash): perfecto en ambos flags.
- [ ] Pcap diff L4 con flag OFF: vacío.
- [ ] Pcap diff L4 con flag ON contra baseline: solo diferencia esperada = nuevo tag opcional al final de `OP_HELLO`.

### Demo
"Wireshark capture lado-a-lado: cliente nuevo y cliente baseline hablando. El nuevo emite un tag extra que el baseline ignora con elegancia (parser drop). Source exchange entre dos clientes nuevos transporta `[::1]:4662` y `192.168.1.5:4662` en el mismo paquete v5. PCP abre el puerto automáticamente en el router del lab."

### Rollback
Revertir merge. Los tags `CT_FORK_CAPABILITIES` ya emitidos por clientes que se hayan actualizado quedan inertes — los baseline los ignoran.

---

## §11 — Sprint 7: eD2K finishing + LiveTV IPv6 core (semanas 15-16) — Fase 5 final + Fase 6 inicio

### Objetivo
Cerrar todo lo de wire P2P (publicip v6, capabilities polishing). Empezar la adaptación de LiveTV: opcode v2 para peer list y migración de `LiveStreamEntry` a `CAddress`.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S7.1 | `OP_PUBLICIP_ANSWER_V6` totalmente integrado en cascada de probe (no solo mocks) | [`ListenSocket.cpp:1378`](srchybrid/ListenSocket.cpp:1378), [`BaseClient.cpp:2593`](srchybrid/BaseClient.cpp:2593), `FirewallProberV6.cpp` | M |
| S7.2 | Capability bits: encender `CAP_FORK_IPV6_WIRE`, `CAP_FORK_IPV6_KAD`, `CAP_FORK_IPV6_DUALSTACK` cuando corresponda | [`BaseClient.cpp`](srchybrid/BaseClient.cpp) | S |
| S7.3 | `OP_LIVE_PEER_LIST_V2 = 0xCB` definido | [`Opcodes.h:289`](srchybrid/Opcodes.h:289) | XS |
| S7.4 | `BuildLivePeerListPacket` v2 con `CAddress` | [`LivePackets.cpp:71-79`](srchybrid/LivePackets.cpp:71) | M |
| S7.5 | `LiveStreamEntry::broadcasterIP` → `CAddress` (con adaptador legacy) | [`LiveKadBridge.h:14-26`](srchybrid/LiveKadBridge.h:14) | M |
| S7.6 | `TryConnectToStreamSource` overload con `CAddress` | [`LiveStreamManager.cpp:200-244`](srchybrid/LiveStreamManager.cpp:200) | M |
| S7.7 | Subnet diversity generalizada con `CAddress::InSameSubnet(64)` y `(48)` | [`LiveStreamManager.cpp:775-797`](srchybrid/LiveStreamManager.cpp:775) | M |
| S7.8 | Kad tags `TAG_ESE_LIVE_*` extendidos para llevar `CAddress` cuando broadcaster es v6 | [`Search.cpp:1195-1601`](srchybrid/kademlia/kademlia/Search.cpp:1195) | M |
| S7.9 | Tests L1: build/parse `OP_LIVE_PEER_LIST_V2` con mezcla v4/v6 | `LivePackets_test.cpp` | M |
| S7.10 | Tests L3: PC1 broadcasting IPv6, PC2 viewer IPv6 — primer chunk recibido | manual | L |

### Verificación funcional
- [ ] V7: LiveTV PC1-v6 → PC2-v6 funcional, primer chunk reproducible en VLC.
- [ ] Subnet diversity rechaza peers con misma /64 si ya hay K en la lista.
- [ ] Cliente nuevo broadcaster sigue siendo descubrible por cliente baseline (que solo ve la dirección IPv4 del broadcaster, no la v6) — necesita que el broadcaster sea dual-stack.

### Regresión
- [ ] B16 (LiveTV broadcast original) sigue funcionando entre baseline y baseline, baseline y nuevo, nuevo y nuevo (en IPv4).
- [ ] C1 con LiveTV: PC1 nuevo broadcaster v4+v6 + PC2 baseline viewer → PC2 recibe el stream por v4 sin problema.
- [ ] El `OP_LIVE_PEER_LIST` legacy (0xCA) sigue emitiéndose a peers sin capability v6.

### Demo
"LiveTV totalmente IPv6: dos PCs con direcciones v6 globales reales (test bench con prefix delegation simulado), uno emite, el otro recibe. Tcpdump confirma: cero paquetes IPv4 en la ruta entre PC1 y PC2. Reproducción fluida."

### Rollback
Más delicado por el toque a `LiveStreamEntry`. Si revertimos, el cache de streams existente puede tener IPs en formato nuevo. Mitigación: el `LiveKadBridge` lee tolerantemente ambas formas siempre que existe.

---

## §12 — Sprint 8: LiveTV buddy relay + persistencia (semanas 17-18) — Fase 6 fin + Fase 7

### Objetivo
Implementar buddy relay v6 (capa E de la cascada) para broadcasters firewalled. Migrar formatos de archivo restantes: `server.met`, `known.met`, `ipfilter.dat`.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S8.1 | Opcodes `OP_LIVE_RELAY_REQ` (0xCC), `OP_LIVE_RELAY_FWD` (0xCD) | [`Opcodes.h`](srchybrid/Opcodes.h) | XS |
| S8.2 | **Nueva clase `CLiveBuddyRelay`** con state machine broadcaster↔buddy↔viewer | nuevo `LiveBuddyRelay.h/.cpp` | L |
| S8.3 | Integración con `CLiveStreamManager`: detectar firewall en broadcaster → buscar buddy v6 → relay | [`LiveStreamManager.cpp`](srchybrid/LiveStreamManager.cpp) | M |
| S8.4 | `server.met` v2: extender struct con `ST_IPV6` tag (0x90) | [`Server.h:23`](srchybrid/Server.h:23), [`Server.cpp`](srchybrid/Server.cpp) | M |
| S8.5 | `known.met v0x10`: añadir `TAG_SOURCEIP_V6` (0x66), `TAG_SERVERIP_V6` (0x67) | [`KnownFile.cpp`](srchybrid/KnownFile.cpp) | M |
| S8.6 | `ipfilter.dat` parser texto: aceptar líneas IPv6 con CIDR | [`IPFilter.cpp:172-179`](srchybrid/IPFilter.cpp:172) | M |
| S8.7 | `ipfilter` binario PG6: nuevo magic `0xFEFEFEFE 'P6B'` reader + writer | [`IPFilter.cpp:99-150`](srchybrid/IPFilter.cpp:99) | L |
| S8.8 | Upgrade automático al primer arranque: crear `.bak` y reescribir en formato nuevo | [`ServerList.cpp`](srchybrid/ServerList.cpp), [`KnownFile.cpp`](srchybrid/KnownFile.cpp), [`IPFilter.cpp`](srchybrid/IPFilter.cpp) | M |
| S8.9 | Tests L1: roundtrip de los 4 archivos con fixtures de baseline y nuevos | tests | M |
| S8.10 | Tests L2: lectura de archivo upstream eMule 0.70b sin modificaciones funciona | manual + script | M |
| S8.11 | Tests L5: archivos escritos en nuevo formato son legibles por baseline (legacy fields preservados) | manual | M |

### Verificación funcional
- [ ] Broadcaster firewalled v6 + buddy highID v6 → viewer puede ver el stream pasando por buddy.
- [ ] `server.met v2` se lee, los servidores nuevos con `ST_IPV6` aparecen en la lista.
- [ ] `known.met v0x10` se lee tras la migración, fuentes v6 cacheadas se restauran.
- [ ] `ipfilter` con rangos IPv6 bloquea conexiones a esos rangos.

### Regresión
- [ ] **C3 (todos los formatos)**: archivos de baseline cargados por nuevo build → contenido íntegro. Lista de servidores, fuentes cacheadas, IP filter — todo idéntico tras load.
- [ ] **C4 (upstream eMule)**: idem con archivos de eMule oficial.
- [ ] **C5 (downgrade)**: tras correr nuevo, restaurar `.bak` y arrancar baseline → arranca normal con datos preservados.
- [ ] **L5 detallado**: cada archivo en formato nuevo tiene tamaño razonable (no regresión 2× del tamaño).

### Demo
"Servidor `[2001:db8::1]:4661` agregado al cliente, persiste en server.met v2, baseline arranca con el mismo fichero (lee solo los servidores v4, ignora limpio los v6). IP filter bloquea `2001:db8:bad::/48`. Buddy relay: broadcaster en VM móvil simulada con firewall todo cerrado salvo TCP saliente → stream llega al viewer vía buddy."

### Rollback
Crítico por los archivos. Cualquier rollback debe restaurar el `.bak`. Documentar procedimiento en `tests/ROLLBACK.md`.

---

## §13 — Sprint 9: UPnP IGDv2 + UI completa (semanas 19-20) — Fase 8

### Objetivo
Capa B de la cascada (IGDv2 AddPinhole) como fallback de PCP. Pulir UI completa: status bar, prefs, AddSourceDlg, ClientDetailDialog. **Empieza el beta**: flag por defecto pasa a `IPv6Mode=Auto`.

### Stories

| ID | Story | Files | Effort |
|---|---|---|---|
| S9.1 | `CUPnPImpl::OpenPortV6()` interfaz abstracta | [`UPnPImpl.h`](srchybrid/UPnPImpl.h) | S |
| S9.2 | `CUPnPImplWinServ::OpenPortV6()` con COM IGDv2 `AddPinhole` | [`UPnPImplWinServ.cpp`](srchybrid/UPnPImplWinServ.cpp) | L |
| S9.3 | `CUPnPImplMiniLib::OpenPortV6()` con miniupnpc actions | [`UPnPImplMiniLib.cpp`](srchybrid/UPnPImplMiniLib.cpp) | M |
| S9.4 | Cascada de fallback: probe orquesta PCP → IGDv2 → keepalive → hole-punch | [`FirewallProberV6.cpp`](srchybrid/FirewallProberV6.cpp) | M |
| S9.5 | `ServerListCtrl`: columna IP ancho automático para v6 | [`ServerListCtrl.cpp:124-126`](srchybrid/ServerListCtrl.cpp:124) | S |
| S9.6 | `AddSourceDlg`: parsing y validación completa `[ipv6]:port` | [`AddSourceDlg.cpp:135`](srchybrid/AddSourceDlg.cpp:135) | S |
| S9.7 | `ClientDetailDialog`: muestra ambas direcciones del par + capa de alcanzabilidad | [`ClientDetailDialog.cpp`](srchybrid/ClientDetailDialog.cpp) | M |
| S9.8 | `PPgConnection`: bloque IPv6 con bind, mode, override manual de capa, status visual | [`PPgConnection.cpp`](srchybrid/PPgConnection.cpp), recursos | L |
| S9.9 | Status bar: `IPv4: ... / IPv6: ...` con tooltip detallado de capa activa | [`EmuleDlg.cpp`](srchybrid/EmuleDlg.cpp) | M |
| S9.10 | i18n: actualizar strings para los idiomas presentes en repo | recursos | M |
| S9.11 | **Default change**: `IPv6Mode` pasa de `IPv4Only` a `Auto` | [`Preferences.cpp`](srchybrid/Preferences.cpp) | XS |
| S9.12 | Documentar en `INSTALL.md` y `CHANGELOG.md` el cambio default | docs | XS |

### Verificación funcional
- [ ] Router lab con UPnP IGDv2 (sin PCP) → AddPinhole funciona, probe reporta "HighID (UPnP-IGDv2)".
- [ ] Cascada completa: lab con router que no soporta PCP ni IGDv2 → cae a keepalive automáticamente.
- [ ] ClientDetailDialog muestra "IPv4: HighID / IPv6: HighID (PCP)" para peer dual-stack.

### Regresión (CRÍTICA — el default cambia)
- [ ] Smoke matrix §3.1 con flag `Auto` en host IPv4-only: 16/16. Comportamiento idéntico a baseline porque el sistema operativo no tiene IPv6 público, la probe termina rápido en "no v6", todo sigue por v4.
- [ ] Smoke matrix §3.2 (extras IPv6) con flag `Auto` en host dual-stack: 7/7.
- [ ] Compatibility C1/C2 sigue OK.
- [ ] Test de upgrade: usuario con prefs viejas (`IPv6Enabled` ausente) → default `Auto` aplica, sin cambio funcional si el SO no tiene v6.

### Demo
"Cliente recién instalado en máquina con IPv6: en 30s aparece status bar con ambas direcciones, capa correcta detectada. Mismo binario en máquina IPv4-only: comportamiento idéntico a baseline. Cambiamos manualmente la capa anti-firewall a 'modo agresivo (keepalive siempre)' desde prefs y vemos efecto en `netstat`/tcpdump."

### Rollback
Si descubrimos al final del sprint que `Auto` default rompe algo, cambio trivial: vuelta a `IPv4Only`. Pero esto cancela el inicio del beta — coste de coordinación.

---

## §14 — Sprint 10: Hardening, beta release (semanas 21-22)

### Objetivo
Build beta con tag `v0.71-beta1-ipv6`. Distribución a grupo cerrado de testers. Bugfixing intensivo.

### Stories

| ID | Story | Effort |
|---|---|---|
| S10.1 | Pasada de PVS-Studio / cppcheck en todo lo nuevo | M |
| S10.2 | Memory leak hunt con VLD en sesión 48h | M |
| S10.3 | Fixing de bugs descubiertos por testers internos | L |
| S10.4 | Telemetría opt-in: contadores de % de uso de cada capa anti-firewall (anónimo, agregado) | M |
| S10.5 | Documentación de usuario: "Modo IPv6 — preguntas frecuentes" | doc | M |
| S10.6 | `INSTALL.md` actualizado con req. de red IPv6 | doc | S |
| S10.7 | Tag `v0.71-beta1-ipv6`, build firmado, release notes | release | S |
| S10.8 | Onboarding de 20-50 beta testers | comunidad | M |
| S10.9 | Setup canal de feedback (issue tracker dedicado, Discord, lo que use el fork) | infra | S |

### Verificación funcional
- [ ] 48h de sesión continuada sin crash, sin leak > 5%, sin assert.
- [ ] Build distribuible (.exe + .pdb + installer).
- [ ] Release notes claras: qué hay nuevo, qué cambia, cómo dar feedback.

### Regresión
- [ ] Suite completa L0-L6 verde en build beta1.
- [ ] Test final manual: instalación limpia sobre baseline anterior → datos preservados, comportamiento normal.

### Demo
"Beta1 disponible. Aquí está el ejecutable firmado, las release notes, el formulario para reportar issues. Empieza el field testing."

---

## §15 — Sprint 11: Field testing, métricas, GA (semanas 23-24)

### Objetivo
30 días de field testing con métricas. Decisión Go/No-Go para GA (release general).

### Stories

| ID | Story | Effort |
|---|---|---|
| S11.1 | Recopilación semanal de métricas (4 weekly check-ins) | M ×4 |
| S11.2 | Triaje y fixing de issues del field | L |
| S11.3 | Análisis: % cobertura real de cada capa anti-firewall vs estimación §8.5 | doc | S |
| S11.4 | Análisis: latencia/throughput v4 vs v6 en datos reales | doc | S |
| S11.5 | Decisión Go/No-Go para GA | reunión | XS |
| S11.6 | Si Go: tag `v0.71-ipv6`, build GA, anuncio | release | M |
| S11.7 | Si No-Go: identificar issues bloqueantes, plan de sprint 12 | doc | S |
| S11.8 | Post-release: monitorear primeras 2 semanas, hotfix rápido si necesario | M |

### Criterios Go/No-Go
- [ ] Zero crash reports atribuibles a IPv6 en 7 días previos.
- [ ] ≥ 80% de los testers IPv6-capable consiguen estado HighID en alguna capa.
- [ ] LiveTV v6 mesh funcional para ≥ 3 broadcasters diferentes.
- [ ] Ningún issue P0 / P1 sin fix.
- [ ] Cobertura empírica de capas dentro de ±10% de la estimación (§8.5: 99% alcanzable).

### Demo
"Métricas reales: X% de testers acabaron en HighID directo, Y% en PCP, Z% en keepalive, W% en hole-punch. Comparado con baseline IPv4-CGNAT (~50%), la cifra es Z%. Decisión: Go. Release v0.71."

---

## §16 — Criterios de release (gates definitivos)

Para mergear de `feature/ipv6-integration` a `main`:

1. ✅ Todos los sprints 0-11 cerrados con DoD.
2. ✅ Smoke matrix §3 verde en CI y manual, en ambos flags.
3. ✅ Field testing 30 días con métricas dentro de criterios.
4. ✅ Documentación de usuario completa (`INSTALL.md`, `IPV6_USER_GUIDE.md`, FAQ).
5. ✅ Plan de rollback documentado (`tests/ROLLBACK.md`).
6. ✅ CHANGELOG con todos los cambios, incluyendo nuevos opcodes y formatos.
7. ✅ Aprobación de al menos 2 mantenedores del fork.
8. ✅ Backup de los `.bak` de los testers preservado durante 90 días post-release (por si downgrade masivo).

---

## §17 — Anti-patrones explícitos (lo que NO hacer)

| # | Anti-patrón | Por qué es malo | Qué hacer en su lugar |
|---|---|---|---|
| A1 | Modificar el formato de un opcode legacy (cambiar el ancho de un campo, reordenar) | Rompe baseline y upstream | Crear opcode paralelo `_V6`, dejar el legacy intacto |
| A2 | Borrar handlers viejos | Rompe compat retroactiva | Mantener todos los handlers; los opcodes obsoletos quedan no-op pero parseables |
| A3 | Mezclar refactor + feature en un PR | Diff imposible de revisar | PRs separados: refactor primero, luego feature |
| A4 | Activar flag IPv6 por defecto antes del Sprint 9 | Sorpresas en testing temprano | Default OFF hasta beta |
| A5 | Cambiar formato de archivo sin `.bak` | Pérdida irreversible si downgrade | Backup automático al primer upgrade |
| A6 | Asumir IPv6 disponible y no comprobar | Crash en hosts IPv4-only | Probe + fallback siempre |
| A7 | Tests solo en máquina dev | Funciona en mi PC™ | CI con matrix Windows + 32/64bit + Debug/Release |
| A8 | "Pequeño fix" sin smoke matrix | Regresiones silenciosas | Smoke matrix es gate de merge, sin excepciones |
| A9 | Comentar opcodes nuevos en código sin reservarlos en `Opcodes.h` | Colisión futura con otros forks | Apéndice B de `IPV6_PLAN.md` es la fuente de verdad, mantenerla |
| A10 | Optimizar antes de tests verde | Bugs ocultos | Correctness first, perf después |

---

## §18 — Apéndice: scripts y herramientas

### 18.1 `tools/pcap_diff.py` (pseudocódigo)

```python
# Uso: pcap_diff.py baseline.pcap new.pcap
# Output: 0 = idénticos, 1 = diferencias, 2 = error.

def normalize(pkt):
    pkt.timestamp = 0
    pkt.tcp.seq = 0  # ignorar números de secuencia
    if pkt.is_emule_packet:
        pkt.payload.tags = sorted(pkt.payload.tags, key=lambda t: t.id)
    return pkt

def diff(p1, p2):
    n1 = [normalize(p) for p in p1]
    n2 = [normalize(p) for p in p2]
    extra = set(n2) - set(n1)
    missing = set(n1) - set(n2)
    return extra, missing
```

Tags conocidos como "aditivos esperados" (p.ej. `CT_FORK_CAPABILITIES`) van en una whitelist.

### 18.2 `tools/file_roundtrip.sh` (pseudocódigo)

```bash
#!/bin/sh
# Para cada fixture, cargar y reescribir con el build. Comparar SHA-256.
for f in tests/fixtures/configs/*.dat tests/fixtures/configs/*.met; do
    cp "$f" /tmp/in.dat
    build/emule.exe --tool=roundtrip --file=/tmp/in.dat --out=/tmp/out.dat
    sha1=$(sha256sum /tmp/in.dat | cut -d' ' -f1)
    sha2=$(sha256sum /tmp/out.dat | cut -d' ' -f1)
    if [ "$sha1" != "$sha2" ]; then
        echo "REGRESSION: $f"
        exit 1
    fi
done
```

(El switch `--tool=roundtrip` es un nuevo entry point que hay que añadir en Sprint 0.)

### 18.3 Cheatsheet de comandos manuales

```
# Verificar listener:
netstat -an | findstr ":4662"

# Verificar IPv6 público:
curl -6 https://ifconfig.co/ip

# Forzar IPv6-only (Windows):
netsh interface ipv4 set interface "Ethernet" disabled

# Restaurar IPv4:
netsh interface ipv4 set interface "Ethernet" enabled

# Captura limitada al puerto eMule:
tcpdump -i any -nn -w capture.pcap "port 4662 or port 4672"

# Ver tags de un .met con Wireshark: filter "edonkey"
```

### 18.4 Lista de fixtures mínima

```
tests/fixtures/
├── configs/
│   ├── nodes_v2.dat       (de baseline con ~100 contactos)
│   ├── nodes_v4.dat       (generado por Sprint 4 con mezcla v4+v6)
│   ├── server_v1.met
│   ├── server_v2.met
│   ├── known_0E.met
│   ├── known_10.met
│   ├── ipfilter_pg2.dat
│   ├── ipfilter_p6b.dat
│   ├── preferences_legacy.ini
│   └── preferences_ipv6.ini
└── pcaps/
    ├── B01_launch.pcap
    ├── B02_server_connect.pcap
    ├── ...
    └── B16_livetv.pcap
```

---

## Cierre

11 sprints, 24 semanas (más Sprint 0 de setup = 26 semanas calendario). El cronograma del [plan principal](IPV6_PLAN.md) decía 21 semanas; esta versión suma 2-3 más por el hardening explícito y el field testing.

Cada sprint deja un build funcional y revertible. Ningún sprint tiene "deuda secreta" pendiente — si paramos en cualquier punto, lo entregado funciona en producción con la baseline intacta.

El invariante "no romper nada" se enforca con:

1. **Smoke matrix** como gate de merge de cada PR.
2. **Pcap diff** automático con whitelist de tags aditivos.
3. **File roundtrip** sobre fixtures de baseline.
4. **Flag default OFF** hasta el Sprint 9.
5. **Opcodes paralelos**, no modificación.
6. **`.bak` automático** en cualquier reescritura de archivo.
7. **Two-PC harness** para validar interop nuevo↔baseline↔upstream.

Si en cualquier sprint la smoke matrix se rompe, el sprint **no se cierra**. El equipo regresa al último commit que pasaba, identifica el cambio rompedor, y lo aísla.

---

*Fin del documento.*
