# Relay/KRP — documentación de ejecución

Este directorio contiene la documentación operativa del relay público derivado de la especificación v0.5. La especificación describe el producto objetivo; estos documentos fijan la frontera con el código actual y los gates que autorizan cada incremento.

| Documento | Propósito |
|---|---|
| [Plan de desarrollo](../RELAY_KRP_V05_DEVELOPMENT_PLAN.md) | Fases P0–P9, tickets, calendario y gates. |
| [Baseline P0](RELAY_P0_BASELINE_2026-07-16.md) | Evidencia reproducible previa a cambios KRP. |
| [Cierre P0](RELAY_P0_CLOSURE_2026-07-16.md) | Resultado de ADR, registro y scaffolds; frontera con P0b físico. |
| [P1 · Incremento 1](RELAY_P1_INCREMENT_1_2026-07-16.md) | Cursor/varints, `ControlFrame`, tests, fuzz, ASan y trabajo pendiente de G1. |
| [P1 · Incremento 2](RELAY_P1_INCREMENT_2_2026-07-16.md) | State machine `Session`, epochs, fencing, replay y admisión 0/1-RTT. |
| [Cierre P1 / Gate G1](RELAY_P1_CLOSURE_2026-07-16.md) | Auth, Flow, EprLease, autoridad, fuzz/ASan y auditoría final de G1. |
| [Cierre P2 / Gate G2-SB](RELAY_P2_CLOSURE_2026-07-16.md) | Edge single-host, TLS/WSS real, sesiones, allocator, policy, abuse tests y frontera física de G2. |
| [Cierre P3 / Gate G3](RELAY_P3_CLOSURE_2026-07-16.md) | Cliente eMule, carrier saliente TLS/WSS, handoff a main, estados, preferences/API, teardown y frontera P4. |
| [Cierre P4 / Gate G4-LAB](RELAY_P4_CLOSURE_2026-07-16.md) | Auth/lease real, puente TCP eD2K, callback/peer, `OP_IDCHANGE`, E2E y frontera pública. |
| [Cómo probar P4](RELAY_P4_TRY_IT.md) | Despliegue del edge público y prueba de High ID manteniendo cerrado el router doméstico. |
| [ADR de contratos](RELAY_KRP_ADR_001_CORE_CONTRACTS.md) | Identidad, wire, lease, carrier, edge, High ID y SLO. |
| [Addendum v0.5](RELAY_KRP_V05_INTEGRATION_ADDENDUM.md) | Traducción de la especificación objetivo al repositorio real. |
| [Threat model](RELAY_THREAT_MODEL.md) | Activos, fronteras de confianza, amenazas y release blockers. |

Estados de claim permitidos:

- `source/build-complete`: fuente enlazada y build/tests locales reproducibles;
- `lab-certified`: gate físico controlado con evidencia;
- `beta-certified`: matriz externa y soak limitado completados;
- `public-certified`: auditoría, operación y gates públicos completados.

Ningún documento de este directorio activa una capacidad por sí mismo.
