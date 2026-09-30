# Relay/KRP — cierre P1 y Gate G1

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Fase | P1 — Core KRP/EPR MFC-free |
| Estado | `source/build-complete` |
| Gate G1 | PASS local |
| Wire/carrier | Desactivado |
| Public mode | Desactivado |
| Siguiente fase | P2 — Edge single-host y carrier WSS |

## 1. Tickets cerrados

| Ticket | Resultado |
|---|---|
| REL-100 | Cursor acotado, varints canónicos y límites previos a allocation. |
| REL-101 | Transcript auth determinista ligado a versión, nonces, RelayID, carrier exporter y settings; hooks de firma/verificación sin clave privada en el core. |
| REL-102 | `ControlFrame` KRP, payload máximo 64 KiB, vectores golden/adversariales y mapping al registro. |
| REL-103 | `Session` con ocho estados, SessionEpoch, RouteGeneration, fencing, 0/1-RTT y replay consume atómico. |
| REL-104 | `Flow`, secuencia estricta, half-close, pressure deadline, hard limits, presupuesto compartido y FlowID spend-once por epoch. |
| REL-105 | `EprLease` separado de SourceLease: TCP/UDP opcional, generation, bind, probe, ACTIVE, grace, renew, drain, revoke y expiry. |
| REL-106 | Matriz de autoridad por servicio sin `OPEN(host,port)` y adaptador real de `K6TargetTicket` con policy/consume de Kad6. |
| REL-107 | Unit, golden/adversarial, fuzz determinista, test cruzado G1, Release `/W4 /WX` y MSVC ASan. |

## 2. Superficie implementada

```text
librelaycore/include/relay
  relay_bytes.h              cursor/varints
  krp_control.h              envelope y registro KRP
  krp_auth.h                 transcript + hooks NodeIdentity
  krp_session.h              sesión/epoch/fencing/replay
  krp_authority.h            grants específicos por servicio
  kad6_authority_adapter.h   K6TargetTicket -> grant KRP
  krp_flow.h                 flow/buffer/sequence/FlowID registry
  epr_lease.h                endpoint public relay lease
```

El core sigue sin sockets, threads, MFC, UI, DNS o claves privadas. La única dependencia opcional
es el adaptador MFC-free de `libkad6`; reutiliza `VerifyK6TargetTicket`, su filtro de destinos, HMAC,
TTL y consumo atómico. No se ha creado un segundo formato de ticket.

El build produce `relaycore.lib` y `relaycore_asan.lib`; todos los tests enlazan contra el archivo
estático correspondiente, no contra copias ad hoc de sus fuentes.

## 3. Invariantes verificadas

### Identidad y autenticación

- `NodeID` es siempre la pubkey Ed25519 completa de 32 bytes.
- Una identidad efímera/no persistente no puede firmar auth KRP.
- La firma cubre versión, perfil de carrier, timestamp, nonces, RelayID, exporter y settings hash.
- Cambiar exporter, settings o firma produce `AuthFailed`.
- La clave privada queda detrás de `INodeIdentitySigner`; nunca forma parte de un record KRP.

### Epoch, replay y fencing

- `RESUME_COMMIT`, `FlowOpen`, renovación de lease y mutación de ruta fallan en 0-RTT.
- Epoch/generation obsoletos se rechazan antes de consumir autoridad o token.
- El replay store se consume mediante una operación atómica; si no está disponible, falla cerrado.
- Migrar propietario reemplaza conjuntamente owner, generation y fencing token.
- `CLOSED` invalida el fencing token.

### Flow y autoridad

- No existe campo de destino arbitrario en `KrpAuthorityRequest` ni `KrpFlowConfig`.
- Cada servicio admite únicamente su clase de autoridad.
- La evidencia está acotada a 4 KiB y los grants a TTL, bytes, flows y prioridad cerrados.
- `FlowID` no se reutiliza dentro de una `SessionEpoch`, incluso después de cerrar el flow.
- Registro máximo: 1.024 FlowID; límite activo inicial: 256.
- Buffer por flow ≤8 MiB; presupuesto por sesión ≤128 MiB; el test usa límites mucho menores.
- Hard limit, stall deadline o grant agotado resetean y devuelven la memoria reservada.

### EPR

- `EprLease` usa namespace/lifecycle propio y conserva NodeID, SessionID, SessionEpoch y route generation.
- TCP y UDP son opcionales y sus puertos pueden diferir.
- Direcciones privadas, especiales y de documentación no se aceptan como endpoint público.
- `ALLOCATED`/`BOUND`/`PROBING` no reciben tráfico nuevo; solo `ACTIVE` tras nonce E2E válido.
- Renew/resume requieren 1-RTT, generation actual y ventana temporal válida.
- `GRACE`, `DRAINING`, `REVOKED`, `EXPIRED`, `RELEASED` y `FAILED` nunca aparecen como healthy.

## 4. Evidencia ejecutada

Release y ASan ejecutaron exactamente la misma suite:

```text
test_relay_core: 6 passed, 0 failed
test_krp_control: 8335 passed, 0 failed
test_krp_session: 300047 passed, 0 failed
test_krp_auth: 30013 passed, 0 failed
test_krp_flow: 309661 passed, 0 failed
test_kad6_authority_adapter: 5 passed, 0 failed
test_epr_lease: 300027 passed, 0 failed
test_krp_p1_gate: 14 passed, 0 failed
```

Total por configuración: **948.108 checks**, cero fallos.

Fuzz/property determinista por configuración:

```text
100000 inputs ControlFrame
100000 acciones Session
10000 transcripts Auth firmados/verificados/mutados
100000 acciones Flow/budget/sequence
100000 acciones EprLease/lifecycle
```

Total: **410.000 inputs/acciones** por configuración. MSVC AddressSanitizer finalizó sin errores.

Registro:

```text
protocol registry: 157 entries, 140 fork symbols in code
OK: registry is internally consistent and matches code.
```

Se reservaron `KRP_RESUME_PROBE` (0x07), `KRP_RESUME_COMMIT` (0x08) y
`KRP_RESUME_RESULT` (0x09). Permanecen `reserved-proposed`: el core conoce su semántica, pero ningún
carrier puede emitirlos todavía.

Frontera de red:

```text
relayedge scaffold: PASS (KRP 1.0, wire disabled, public mode disabled)
```

## 5. Auditoría de Gate G1

| Criterio G1 | Resultado | Evidencia |
|---|---|---|
| Cero MFC/socket en `librelaycore` | PASS | Auditoría de includes + build independiente. |
| Size/overflow/flags/states/epochs antes de reservar | PASS | Codecs, state fuzz, hard limits y outputs transaccionales. |
| Replay no renueva lease ni abre flow | PASS | Tests unitarios y `test_krp_p1_gate`. |
| NodeID de 32 bytes | PASS | `static_assert` y binding auth/session/EPR. |
| Ningún flow admite destino arbitrario | PASS | API solo acepta autoridad service-specific; adapter Kad6 revalida policy. |
| Fuzz/ASan/Release verdes y memoria acotada | PASS | 948.108 checks y 410.000 acciones por configuración. |

**Decisión:** Gate G1 aprobado para comenzar P2. Esto autoriza desarrollo del daemon/carrier en modo
local y default OFF; no autoriza despliegue público, claim High ID, listener exterior ni tráfico real.

## 6. Frontera con P2

P2 debe aportar las side effects que P1 deliberadamente no contiene:

- lifecycle/config/health del daemon `relayedge`;
- `IRelayCarrier` TLS/TCP de laboratorio y WSS/H1;
- adaptación real de verificación Ed25519 y replay store;
- session table, quotas, timeouts, listeners y allocator single-host;
- policy de infraestructura, métricas, kill switch y drain.

P0b/G-HID físico sigue pendiente y bloquea cualquier afirmación de High ID o compatibilidad pública.
No bloquea comenzar P2 de forma local, aislada y fail-closed.
