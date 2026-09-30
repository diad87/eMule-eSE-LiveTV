# Relay/KRP — cierre P3 y Gate G3

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Fase | P3 — Cliente KRP, adaptadores y UI/API |
| Estado | `source/build-complete` |
| Gate local | G3 PASS |
| Gate físico CGNAT | PENDIENTE; no `lab-certified` externo |
| High ID real | NO; pertenece a P4/G-HID |
| Siguiente fase | P4 — TCP clásico, callback y `OP_IDCHANGE` real |

## 1. Resultado

P3 integra en eMule un cliente de relay separado del relay Live/Buddy ya existente. El nuevo
`CRelayClient` usa el coordinador MFC-free `librelayclient`, un carrier TLS/WSS real y una cola
acotada de eventos hacia el hilo principal. El proyecto x64 Release completo enlaza esta ruta en
`emule.exe`, pero la preferencia continúa **OFF por defecto**.

El worker recibe únicamente una copia bounded de la configuración, una cola de eventos de valor y
un notificador de ventana basado en `PostMessage`. No recibe punteros a `CemuleApp`, diálogos,
listas, sockets eMule ni otros objetos MFC. Sólo el hilo que construyó `RelayClientManager` puede
mutar estados o promover evidencia eD2K.

El carrier cliente permite conexión saliente normal, exige cadena CA y hostname válidos, negocia
TLS 1.2 o superior y hace un upgrade RFC 6455 estricto a `/krp/v1` + `krp.v1`. Un `select()`
acotado detecta cierre remoto sin ejecutar operaciones mbedTLS simultáneas desde dos hilos.

## 2. Entregables por ticket

| Ticket | Evidencia implementada |
|---|---|
| REL-300 | `RelayClientManager` y shell `CRelayClient`; estado de sesión en un único owner thread y sin duplicar codecs KRP. |
| REL-301 | `RelayWssTransport`, TLS verificado, handshake WSS cliente estricto, cola de 256 eventos y notifier `UM_KRP_CLIENT_EVENT`. |
| REL-302 | Reconnect exponencial capped, jitter determinista ±25 % máximo, grace, fallback clásico, fencing de generation y reason codes. |
| REL-303 | Estados independientes de carrier, sesión, lease, ED2K, endpoint, Kad y ruta; el worker no puede declarar High ID. |
| REL-304 | Sección `[KRPRelay]`, default OFF, endpoint/CA/hostname, política de servidor y kill switch local. |
| REL-305 | `/api/krp/status` localhost/token, cache thread-safe, display state y métricas sin endpoint, identidad, certificado ni payload. |
| REL-306 | Tests Release/ASan de UAF/lifetime, doble/stale callback, overflow, hilo incorrecto, cierre remoto y 10.000 ciclos de teardown. |

## 3. Arquitectura y regla de hilos

```text
RelayWssTransport worker
  copied config + TLS/WSS
             |
             v
RelayEventQueue (256 value events, generation fenced)
             |
             v  PostMessage(UM_KRP_CLIENT_EVENT)
CemuleDlg / main thread
             |
             v
CRelayClient -> RelayClientManager -> cached status/API
```

- La cola no contiene punteros ni payload KRP y rechaza nuevos eventos después de `Close()`.
- Un callback de una generación anterior incrementa `stale_events` y no cambia estado.
- `Disable`, kill y shutdown paran, hacen join, incrementan generation y eliminan estado saludable.
- La caída desde un lease activo conserva sólo un estado explícito `Grace/Degraded`; nunca conserva
  una afirmación saludable. Al vencer grace se vuelve a `LowId/Unknown/None`.
- El temporizador de backoff sólo publica el mismo mensaje de ventana; el retry se ejecuta en main.

## 4. Estados visibles e imposibilidad de sintetizar High ID

La superficie UI/API devuelve una de estas etiquetas:

- `Low ID`;
- `Low ID (relay pending)`;
- `relay endpoint degraded`;
- `High ID by relay`.

P3 sólo instala el hook de promoción futura. `ApplyEd2kRelayEvidence` exige simultáneamente:

1. sesión y lease activos;
2. endpoint ya marcado reachable;
3. confirmación de `IDCHANGE` validada en el hilo principal;
4. evidencia de reachability;
5. cumplimiento de la política `SelectedServerOnly`, salvo opt-in explícito a cualquier servidor.

No existe aún un caller de producto que aporte esas evidencias, por lo que el ejecutable P3 no puede
mostrar ni obtener High ID real. Eso evita confundir “TLS/WSS conectado” con “callback eD2K
funcionando”.

## 5. Preferencias y API

Ejemplo reproducible: `srchybrid/config/krp-relay.ini.example`.

```ini
[KRPRelay]
KrpRelayEnabled=0
KrpRelayKillSwitch=0
EndpointHost=relay.example.invalid
EndpointPort=443
ExpectedServerName=relay.example.invalid
CaBundlePath=C:\path\to\relay-ca.pem
AllowAnyConnectedServer=0
```

Si se activa sin host, hostname esperado o CA explícitos, la validación falla cerrada. El endpoint
WSS queda fijado a `/krp/v1`; no se persiste ninguna clave de identidad.

Cuando el WebServer local está habilitado:

```text
GET /api/krp/status
```

La respuesta incluye estados, generation, próximo retry y contadores de starts/reconnect/events,
stale transitions, disconnects y drops. La misma protección localhost/token de las APIs Live
impide lectura remota no autenticada.

## 6. Evidencia reproducible

Cliente P3:

```bat
cd librelayclient
make.bat
```

La suite compila Release y AddressSanitizer y cubre:

- 100.000 acciones concurrentes sobre la cola bounded;
- 10.000 ciclos de creación/start/disable/destrucción por ejecución;
- transición TLS → WSS real con certificado y hostname verificados;
- corte remoto real que programa reconnect y fallback clásico;
- grace, jitter/backoff, ausencia de reconnect storm, overflow y callbacks stale/dobles;
- rechazo de mutación desde un hilo distinto al owner;
- promoción ED2K bloqueada sin todas las evidencias y sin política de servidor válida.

Salida final observada:

```text
librelayclient P3 tests passed: 70697 checks, 100000 concurrent queue actions, 10000 lifetime cycles
librelayclient P3 TLS/WSS transport passed: 35 checks, worker-to-main queue only
librelayclient P3 tests passed: 70697 checks, 100000 concurrent queue actions, 10000 lifetime cycles [ASan]
librelayclient P3 TLS/WSS transport passed: 35 checks, worker-to-main queue only [ASan]
LIBRELAYCLIENT P3 GATE BUILD PASS
```

Regresión P2:

```bat
cd relayedge
make.bat
```

Resultado observado: **30.144 checks Release + 30.144 ASan**, TLS/WSS loopback real, drain sin
listener huérfano y `RELAYEDGE P2 GATE BUILD PASS`.

Integración eMule:

```bat
msbuild srchybrid\emule.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64
```

Resultado: `srchybrid/x64/Release/emule.exe` enlazado correctamente con `RelayClient.cpp`,
`librelayclient` y el carrier TLS/WSS. El registro continúa verde con **157 entradas / 140
símbolos**.

ASan instrumenta el cliente, tests y fuentes del carrier. `mbedTLS.lib` es la biblioteca Release
precompilada existente y no queda instrumentada; reconstruir esa dependencia sigue siendo trabajo
opcional de hardening.

## 7. Auditoría de Gate G3

| Condición G3 | Resultado |
|---|---|
| Sin acceso a objetos eMule fuera de main thread | **PASS:** worker limitado a config copiada, carrier, cola y HWND notifier; mutaciones sólo en owner thread. |
| Desconexión limpia adaptadores y estados públicos | **PASS:** corte real → fallback/backoff; disable/kill/shutdown hacen stop+join+generation fence; grace nunca afirma salud. |
| UI distingue High ID por relay, endpoint degradado y Low ID | **PASS source/build:** etiquetas separadas en cache/API; High ID permanece inalcanzable sin evidencias P4. |
| Default OFF y fallback clásico intacto | **PASS:** INI default 0, config incompleta fail-closed y route vuelve a Classic/FallbackClassic. |

**Decisión:** P3 queda cerrado como `source/build-complete` y Gate G3 local PASS. No se concede
`lab-certified` físico ni claim de High ID.

## 8. Frontera deliberadamente posterior

- El edge de laboratorio P2 atiende `KRP_PING/PONG`; aún no existe un intercambio wire completo
  AUTH/LEASE entre ambos ejecutables. Las transiciones de sesión/lease están implementadas y
  verificadas con un transport driver determinista, sin fingir que el lab ya las produce.
- P4 debe conectar el driver KRP real a `NodeIdentity`, solicitar lease, recibir callback TCP,
  procesar `OP_IDCHANGE` auténtico y aportar las evidencias al hook de main thread.
- El Gate G2 físico sigue necesitando dos hosts/CGNAT, corte/recovery medido y captura de que no hay
  mezcla entre tenants.
- No hay servicio edge público, wildcard bind, HA, UDP, H2/H3 ni claim de disponibilidad.
