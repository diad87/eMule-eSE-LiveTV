# Relay/KRP — cierre P0 de fuente/build

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Estado | `source/build-complete` |
| Public mode | Desactivado |
| Wire KRP | Reservado; no activo |
| Gate físico | P0b pendiente |

## 1. Tickets

| Ticket | Estado | Evidencia |
|---|---|---|
| REL-000 | DONE | `RELAY_P0_BASELINE_2026-07-16.md`; tests, fuzz, linter y GUI Release. |
| REL-001 | DONE con blocker editorial explícito | Addendum creado; seis assets de la v0.5 siguen ausentes. |
| REL-002 | DONE | ADR-R01…R10 aceptadas provisionalmente. |
| REL-003 | DONE | 23 mensajes en `KRP_MESSAGES.csv`, todos `reserved-proposed`; linter 154/114 PASS. |
| REL-004 | DONE | `librelaycore` y `relayedge` compilan `/W4 /WX`; tests/self-test PASS. |
| REL-005 | DONE | Threat model P0 con 16 amenazas y release blockers. |

## 2. Scaffolds

```text
librelaycore
  include/relay/relay_core.h
  src/relay_core.cpp
  tests/test_relay_core.cpp

relayedge
  main.cpp
```

Resultados:

```text
test_relay_core: 6 passed, 0 failed
relayedge scaffold: PASS (KRP 1.0, wire disabled, public mode disabled)
```

Una ejecución normal de `relayedge` termina con código 2 y no crea listener. Solo `--self-test` y `--version` terminan con éxito.

## 3. Registro

```text
protocol registry: 154 entries, 114 fork symbols in code
OK: registry is internally consistent and matches code.
```

No se añadieron `#define`, capability bits ni opcodes al cliente. Los mensajes reservados no se emiten ni se anuncian.

## 4. Gate P0

| Criterio | Resultado |
|---|---|
| Baseline local reproducible | PASS |
| GUI Release x64 | PASS |
| Registro sin colisiones/drift | PASS |
| ADR/tamaños/ownership coherentes | PASS |
| Core/edge fail-closed | PASS |
| Laboratorio físico cliente-edge-server-peer | PENDIENTE P0b |

La parte documental y de fuente/build de P0 está cerrada. P1 puede avanzar porque es aislado y MFC-free. Ninguna capacidad de red se activa hasta completar P0b/G-HID y los gates de P2/P4 correspondientes.
