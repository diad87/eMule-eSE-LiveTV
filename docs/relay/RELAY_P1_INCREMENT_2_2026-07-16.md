# Relay/KRP — P1, incremento 2

> Documento incremental histórico. P1 quedó cerrado posteriormente en
> [RELAY_P1_CLOSURE_2026-07-16.md](RELAY_P1_CLOSURE_2026-07-16.md).

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Ticket principal | REL-103 |
| Estado | `source/build-complete` |
| Wire KRP | Desactivado |
| Public mode | Desactivado |
| Gate G1 | Abierto; REL-101 y REL-104–106 pendientes |

## Alcance entregado

`KrpSession` implementa los ocho estados normativos de la v0.5:

```text
NEW -> AUTHENTICATING -> ACTIVE -> MIGRATING
                            |          |
                            +----------+
                            |
                            v
                    PASSIVE_PENDING -> PASSIVE
                            |
                            v
                        DRAINING -> CLOSED
```

La API mantiene un binding explícito con:

- `SessionID` de 16 bytes y `NodeID` canónico de 32 bytes;
- `SessionEpoch` no nulo y monotónico entre encarnaciones;
- `RouteGeneration` no nula y creciente al transferir propietario;
- `OwnerEdgeID` y `FencingToken` de 16 bytes;
- invalidación del fencing token al alcanzar `CLOSED`.

Las actualizaciones son transaccionales: una generación esperada obsoleta, un propietario vacío o
un fencing token inválido no modifican parcialmente el binding. Un objeto `CLOSED` es final; una
reconexión crea una nueva encarnación con otra `SessionID` y una `SessionEpoch` superior.

## 0-RTT y replay

`AuthorizeOperation` separa observación de mutación:

| Operación | 0-RTT | 1-RTT confirmado |
|---|---:|---:|
| `EarlyHello`, `ResumeProbe`, `StatusQuery` | Solo estados permitidos; no mutan | Permitido según estado |
| `FlowOpen` | REJECT | Solo `ACTIVE` + epoch/generation actuales |
| Mutación de lease | REJECT | Solo `ACTIVE` + epoch/generation actuales |
| Mutación de ruta | REJECT | Solo `ACTIVE` + epoch/generation actuales |
| `CommitResume` | REJECT | Binding exacto + token consumido atómicamente |

La protección contra replay se inyecta mediante `IReplayProtector::Consume()`. El contrato exige una
operación atómica de un solo uso; no admite un `check` seguido de `insert`. Si la autoridad de replay
no está disponible, la reanudación falla cerrada. Un epoch o generation obsoleto se rechaza antes de
consumir el token.

En este incremento los mensajes wire `RESUME_*` aún no formaban parte del subconjunto reservado.
Se añadieron después, al cerrar REL-101/P1, mediante una ampliación explícita del registro; ningún
transporte los emite todavía.

## Evidencia reproducible

```powershell
& .\librelaycore\make.bat
$env:RELAY_ASAN='1'; & .\librelaycore\make.bat; Remove-Item Env:RELAY_ASAN
python .\tools\check_protocol_registry.py
& .\relayedge\make.bat
```

Release `/O2 /W4 /WX` y MSVC AddressSanitizer produjeron el mismo resultado:

```text
test_relay_core: 6 passed, 0 failed
deterministic fuzz: 100000 inputs, 1042 valid frames
test_krp_control: 7334 passed, 0 failed
deterministic state fuzz: 100000 actions
test_krp_session: 300047 passed, 0 failed
```

Total por configuración: **307.387 checks**, 200.000 entradas/acciones de fuzz determinista y cero
fallos. `sizeof(KrpSession) < 512` se comprueba en compilación, muy por debajo del objetivo de estado
idle de 32 KiB.

Registro y frontera de red:

```text
protocol registry: 154 entries, 137 fork symbols in code
OK: registry is internally consistent and matches code.
relayedge scaffold: PASS (KRP 1.0, wire disabled, public mode disabled)
```

## Estado de P1

| Ticket | Estado |
|---|---|
| REL-100 | DONE |
| REL-102 | DONE para envelope común y mapping |
| REL-103 | DONE para state machine local, epochs, fencing y replay admission |
| REL-107 | PARTIAL: codecs y Session cubiertos en Release/ASan/fuzz |
| REL-101 | SIGUIENTE: transcript unido al carrier y hook de `NodeIdentity` |
| REL-104 | PENDIENTE: `Flow`, sequence, half-close, pressure y memory budget |
| REL-105 | PENDIENTE: `EprLease` |
| REL-106 | PENDIENTE: autoridad/tickets por servicio |

G1 todavía no está superado: exige completar autenticación, Flow, EprLease y autoridad específica,
además de probar que un replay no abre realmente un flow ni renueva un lease en esas máquinas.
