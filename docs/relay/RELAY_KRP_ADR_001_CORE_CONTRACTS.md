# ADR-R01…R10 — contratos iniciales Relay/KRP

| Campo | Valor |
|---|---|
| Estado | Aceptado provisionalmente para P0/P1 |
| Fecha | 2026-07-16 |
| Sustituye | Supuestos incompatibles de la especificación v0.5 |
| Revisión | Un cambio incompatible requiere una ADR nueva |

## Contexto

La especificación v0.5 define el producto objetivo, pero el repositorio ya contiene identidad Ed25519, K6Frame, tickets, leases de fuente, sockets virtuales, quotas y dataplanes Kad6/Live. KRP debe integrar estas piezas, no crear una segunda plataforma paralela. El árbol no contiene un edge público, KRP, H3/H2 o lease de endpoint genérico.

## ADR-R01 — Identidad canónica

**Decisión:** la clave pública de `NodeIdentity` es el NodeID canónico de 32 bytes para KRP y Kad6.

- `NodeID = Ed25519 public key`, 32 bytes; no se trunca para autoridad.
- `SessionID` es aleatorio de 16 bytes y no es identidad persistente.
- UserHash permanece identidad clásica eD2K.
- Un binding firmado relaciona NodeID y UserHash solo para el servicio que lo necesita.
- El edge recibe clave pública y firmas, nunca la clave privada.

**Corrección v0.5:** `krp_node_id: bytes16` deja de ser válido. Records KRP/Kad6 usan 32 bytes.

## ADR-R02 — Frontera del core

**Decisión:** se crea `librelaycore/`, C++17, MFC-free, sin sockets ni threads propios.

- Contiene tipos, codecs y state machines.
- Cripto, reloj, RNG y persistencia se inyectan desde el host.
- Puede reutilizar primitivas pequeñas y auditadas de `libkad6`.
- No incluye `CUpDownClient`, `CServerSocket`, UI ni headers MFC.
- `srchybrid` y `relayedge` son adaptadores del mismo core.

## ADR-R03 — Frontera de wire

**Decisión:** KRP solo gobierna sesión, autenticación, settings, flows, lease público, presión y lifecycle.

- Payload Kad6 conserva K6Frame.
- Live conserva mensajes, chunking, bulk y FEC existentes.
- eD2K conserva parsers/opcodes clásicos en ambos extremos.
- KRP no duplica búsqueda, publicación, tickets, onion o media.
- Los códigos KRP se reservan primero en `KRP_MESSAGES.csv`.

## ADR-R04 — Lease público

**Decisión:** `EprLease` es distinto de `K6SourceLease`.

Campos mínimos:

```text
lease_id, generation, session_id, node_pub,
class, public_address, tcp_port?, udp_port?,
issued_at, expires_at, grace_expires_at,
state, reason, limits
```

- Se asignan atómicamente solo los recursos solicitados.
- TCP y UDP son opcionales y no se exige mismo puerto.
- Clases iniciales: `LAB_ONLY`, `PEER_SHARED`, `SERVER_DEDICATED`; `KAD_UDP` se añade en P6.
- Estado inicial: `REQUESTED -> ALLOCATED -> BOUND -> PROBING -> ACTIVE`.
- Fallos: `FAILED`, `REVOKED`; cierre: `DRAINING -> EXPIRED/RELEASED`.
- El cliente no anuncia el endpoint antes de ACTIVE y probe válido.

## ADR-R05 — Orden de carriers

**Decisión:** la semántica KRP es independiente del carrier y el orden de implementación es:

1. framing de laboratorio sobre TLS/TCP;
2. WSS/H1 con TLS real para MVP;
3. H3/QUIC tras beta TCP;
4. H2 Extended CONNECT solo si cubre un caso medido no resuelto.

WSS usa subprotocolo `krp.v1`. H3 no usa tokens `:protocol` no especificados/registrados en producción.

## ADR-R06 — Proceso edge

**Decisión:** `relayedge` es un proceso separado del GUI eMule.

- Single-host en P2; HA en P5/P9.
- Session, Endpoint Gateway y Egress Gateway tienen fronteras explícitas aunque inicialmente compartan proceso.
- Cada gateway tiene allowlist, cuota y circuit breaker propios.
- El scaffold P0 no abre sockets y arranca fail-closed.

## ADR-R07 — High ID y reachability

**Decisión:** se mantienen dos estados independientes.

```text
ED2K_ID_STATE = valor autoritativo derivado de OP_IDCHANGE
ENDPOINT_REACHABILITY_STATE = probe/peer E2E por el endpoint arrendado
```

Solo la combinación permite `HIGH_RELAY_CONFIRMED`. Si la sesión/endpoint degrada, la UI muestra `HIGH_RELAY_DEGRADED`; nunca infiere High ID desde listener, lease o test local.

## ADR-R08 — Política de servidor

**Decisión:** el servidor elegido por el usuario se respeta por defecto.

- `STRICT_SELECTED_SERVER`: no cambia automáticamente.
- `PREFER_SELECTED_SERVER`: fallback opt-in y acotado.
- No se prueba un número ilimitado de servidores/estrategias.
- Los perfiles Lugdunum son observaciones versionadas, no certificaciones.
- Circuit breakers y backoff protegen infraestructura comunitaria.

## ADR-R09 — Gobierno de extensión HTTP

**Decisión:** el wire KRP no depende de `:protocol=kad6-relay` o `kad6-relay-flow`.

Antes de H3/H2 se elegirá una opción interoperable:

- extensión formal con token registrado y semántica publicada;
- WebSocket sobre H3/H2 cuando el perfil aplicable lo permita;
- otro carrier estandarizado/adaptador evaluado en P8.

WSS/H1 sigue siendo fallback y referencia funcional.

## ADR-R10 — SLO y elegibilidad

**Decisión:** no existe claim 99,9 % hasta P9.

- La elegibilidad se determina antes de conocer el resultado.
- Las exclusiones son códigos cerrados, versionados y auditables.
- Un rechazo del servidor no se excluye retroactivamente por haber fallado.
- Se publican por separado first-server, fallback y reachability.
- Se exige volumen suficiente, intervalo de confianza, error budget y soak prolongado.

## Consecuencias

### Positivas

- Reutilización explícita de componentes ya auditados.
- MVP menor y carrier reemplazable.
- High ID no se confunde con un listener local.
- UDP/H3/HA no bloquean la validación crítica.

### Costes

- KRP y K6Frame coexistirán con una frontera clara.
- El edge necesita adaptadores clásicos y policy específica.
- La especificación v0.5 requiere un addendum para reflejar IDs, leases y orden de fases.

## Gate de aceptación

- Todos los IDs persistentes tienen tamaño único/documentado.
- `EprLease` y `SourceLease` no comparten namespace/lifecycle.
- El registro KRP está reservado pero no activo.
- El scaffold core/edge compila sin abrir red.
- Cualquier implementación futura cita esta ADR o una sustituta.
