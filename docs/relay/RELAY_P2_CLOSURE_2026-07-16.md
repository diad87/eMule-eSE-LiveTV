# Relay/KRP — cierre P2 y Gate G2-SB

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Fase | P2 — Edge single-host y carrier WSS |
| Estado | `source/build-complete`; transporte loopback verificado |
| Gate local | G2-SB PASS |
| Gate físico CGNAT | PENDIENTE; no `lab-certified` externo |
| Modo público | No existe; default OFF |
| Siguiente fase | P3 — Cliente KRP, adaptadores y UI |

## 1. Resultado

P2 deja un ejecutable `relayedge.exe` C++17/MFC-free y un edge single-host acotado. Sólo puede
abrir red cuando recibe una configuración `lab-loopback` válida, con `explicit_lab_enable=true`,
bind `127.0.0.1`/`::1` y certificado/clave. No hay wildcard, destino público ni modo público.

El carrier real usa mbedTLS, verifica la cadena y el hostname del servidor, exige TLS 1.2 o
superior y expone el TLS exporter que liga la autenticación KRP al canal. Sobre él se implementa
WSS/H1 RFC 6455 binario con ruta `/krp/v1`, subprotocolo exacto `krp.v1`, masking obligatorio del
cliente, límites de handshake/frame y rechazo de extensiones/fragmentación/texto.

Esto no es todavía un cliente eMule ni concede High ID. P3 integra el cliente KRP y P4 añade el
flujo eD2K server/peer, `OP_IDCHANGE` y la validación High ID extremo a extremo.

## 2. Entregables por ticket

| Ticket | Evidencia implementada |
|---|---|
| REL-200 | `EdgeRuntime`, `EdgeDaemon`, configuración bounded, health, startup, drain, shutdown y CLI fail-closed. |
| REL-201 | `IRelayCarrier`, `LabTlsListener` y `TlsTcpCarrier` real con TLS exporter y timeouts de I/O. |
| REL-202 | Parser H1 bounded, upgrade RFC 6455, `WssFrameParser` y `WssH1Carrier` binario `krp.v1`. |
| REL-203 | `AuthenticateEdgeSession`, session table generacional, identidad única, pre/post-auth timeouts y cuotas de flows/leases. |
| REL-204 | Allocator TCP single-host con generation fencing, probe nonce, `ACTIVE`, drain y reuse delay. |
| REL-205 | Policy por `KrpService`, veto de redes especiales/metadata/infraestructura, hook IPFilter y revalidación antes de conectar. |
| REL-206 | Contadores saturating, audit ring de 1024 eventos sin payload, kill switch, GOAWAY/drain y cierre coordinado. |
| REL-207 | Forbidden targets, byte-wise slow reader, fuzz bounded, fallo TLS/auth, reconnect/cut storm, reuse y teardown bajo Release/ASan. |

## 3. Superficie construida

```text
relayedge/
  main.cpp                         CLI default OFF y lifecycle check
  lab-loopback.conf.example        única configuración de red admitida
  include/edge/
    relay_carrier.h                interfaz carrier
    tls_tcp_carrier.h              TLS/TCP real
    wss_h1.h / wss_carrier.h       H1/RFC6455 + carrier WSS
    edge_runtime.h                 config, health, metrics y audit
    edge_session_table.h           sesiones, cuotas y timeouts
    edge_auth.h                    promoción tras auth ligada al carrier
    edge_allocator.h               lease de puerto/probe/reuse
    edge_policy.h                  policy y revalidación
    edge_daemon.h                  coordinación single-host
  src/                             implementaciones anteriores
  tests/test_p2.cpp                gate local integrado
  make.bat                         Release + ASan reproducible
```

El ejecutable ofrece:

```text
relayedge.exe --self-test
relayedge.exe --check-config lab-loopback.conf.example
relayedge.exe --lab-startup-check lab-loopback.conf.example
relayedge.exe --lab-serve-ping-once lab-loopback.conf.example
```

Una ejecución normal continúa fallando cerrada y no abre sockets. El último comando atiende una
única sesión TLS/WSS con `KRP_PING/PONG` y termina drenado; no es un servicio público.

## 4. Invariantes verificadas

- Configuración máxima 16 KiB, línea máxima 1024 bytes, claves desconocidas/duplicadas rechazadas.
- Sólo bind loopback explícito; no existe configuración para modo público.
- TLS con verificación obligatoria en cliente, hostname validado, mínimo TLS 1.2 y exporter común.
- Handshake WSS máximo 8192 bytes/64 headers/1024 bytes por línea; `krp.v1` es obligatorio.
- Cliente WSS siempre enmascara con CSPRNG; frames de texto, RSV, fragmentación y extensiones se rechazan.
- Payload WSS máximo 64 KiB y buffering máximo de dos frames completos (menos de 129 KiB).
- Auth fallida destruye el slot pre-auth y no puede obtener lease.
- Handles de sesión y generations de puerto invalidan referencias obsoletas.
- Endpoint no es anunciable en `Allocated`, `Bound` o `Probing`; sólo tras nonce correcto y `ACTIVE`.
- Reuse delay impide reasignar inmediatamente un puerto liberado.
- Loopback, RFC1918, CGNAT, link-local, documentación, multicast/reservado y puertos de infraestructura se deniegan.
- El policy check se repite inmediatamente antes de conectar.
- Drain cierra admisión, marca sesiones y al deadline elimina sesiones/leases; kill switch es inmediato.
- Audit guarda campos estructurados bounded; no guarda payload, hostname ni material criptográfico.

## 5. Evidencia reproducible

Comando:

```bat
cd relayedge
make.bat
```

Salida final observada:

```text
relayedge P2: PASS (KRP 1.0, default OFF, public mode disabled)
relayedge config: VALID (lab-loopback 127.0.0.1:0, sessions=256)
relayedge health: HEALTHY (loopback port efímero)
relayedge shutdown: DRAINED (no listener orphan)
relayedge P2: PASS (30144 checks, real TLS/WSS loopback)
relayedge P2: PASS (30144 checks, real TLS/WSS loopback) [AddressSanitizer]
RELAYEDGE P2 GATE BUILD PASS
```

Cobertura relevante por ejecución:

- 10.000 inputs deterministas para el parser H1 y 20.000 para frames WSS;
- slow reader byte a byte;
- ocho ciclos TLS de corte/reconexión con exporter coincidente;
- rechazo de hostname de certificado incorrecto;
- upgrade WSS real y `KRP_PING/PONG` canónicos sobre el carrier;
- auth KRP correcta/incorrecta, cuotas, timeout, fencing, probe/reuse y policy adversarial;
- daemon startup, GOAWAY/drain y comprobación de cero sesiones/leases/listener huérfanos.

Totales Release + ASan: **60.288 checks** y **60.000 inputs fuzz deterministas**. El build ASan
instrumenta `relayedge`, el test y `relaycore_asan.lib`; el archivo mbedTLS ya existente es una
biblioteca Release precompilada y no queda instrumentado por este comando.

El registro continúa verde:

```text
protocol registry: 157 entries, 140 fork symbols in code
OK: registry is internally consistent and matches code.
```

## 6. Auditoría de Gate G2

| Condición G2 | Resultado al cierre P2 |
|---|---|
| Cliente CGNAT mantiene WSS/TLS y recupera tras corte acotado | **PARCIAL:** TLS/WSS real y ocho recuperaciones loopback; falta cliente P3 y red CGNAT física. |
| TLS/auth fallidos no consumen leases | **PASS local:** fallo de hostname y firma KRP dejan carrier/slot cerrados y allocator en cero. |
| Cero conexiones a loopback, redes especiales o infraestructura | **PASS de policy:** deny + revalidación; no existe todavía dialer de producto. La excepción loopback sólo vale para `PortTest` explícito. |
| Ningún endpoint se anuncia antes de `ACTIVE + probe` | **PASS local:** estados y nonce adversarial cubiertos. |
| Kill switch/GOAWAY drenan sin socket exterior huérfano | **PASS single-host local:** listener, sesiones y leases quedan en cero; falta matriz con flows exteriores P4. |
| WSS puede ser carrier único del MVP | **PASS source/build:** carrier WSS funcional sobre TLS verificado. |

**Decisión:** P2 queda cerrado como `source/build-complete` y habilita comenzar P3. No se concede
el claim `lab-certified` del G2 físico porque no existe aún el cliente P3 ni se ha ejecutado una
prueba CGNAT externa. No se concede ningún claim de High ID; éste pertenece a P4 y a G-HID.

## 7. Trabajo deliberadamente posterior

- P3: cliente KRP dentro de eMule, reconexión/backoff, thread handoff, preferencias y UI.
- P4: eD2K server/peer TCP, endpoint exterior real, `OP_IDCHANGE`, callback y High ID E2E.
- Instrumentar/reconstruir mbedTLS con ASan si se exige cobertura de memoria de la dependencia.
- Gate físico con dos hosts/red CGNAT y captura de tiempos de recuperación.
- Servicio público, wildcard bind, HA, H2/H3, UDP y claims de disponibilidad siguen bloqueados.
