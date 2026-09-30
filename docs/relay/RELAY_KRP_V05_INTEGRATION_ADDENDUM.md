# Addendum de integración — especificación Relay/KRP v0.5

| Campo | Valor |
|---|---|
| Estado | Normativo para la integración con este repositorio |
| Fecha | 2026-07-16 |
| Base | `Especificacion_Tecnica_Relay_eMule_Kad6_v0.5.md` |
| Prioridad | Este addendum prevalece cuando la v0.5 contradice el baseline real |

## 1. Propósito

La v0.5 es la especificación objetivo. Este addendum impide que nombres de arquitectura futura se interpreten como componentes ya implementados y aplica las ADR P0 al árbol eMule/Kad6 actual.

## 2. Correcciones obligatorias

| Tema v0.5 | Tratamiento de integración |
|---|---|
| `krp_node_id: bytes16` | Se sustituye por NodeID Ed25519 de 32 bytes. SessionID permanece 16 bytes. |
| Nueva identidad KRP | Se reutiliza `NodeIdentity`; no se genera una autoridad persistente paralela. |
| `LeaseNetworkBundle` TCP+UDP indivisible | `EprLease` reserva atómicamente los recursos solicitados; TCP/UDP opcionales. |
| H3/H2/WSS en Fase 1 | WSS es MVP; H3/H2 se difieren a P8. |
| `:protocol=kad6-relay*` | No se usa en producción sin perfil/registro/interoperabilidad resueltos. |
| KRP transporta Kad6/media | Kad6 viaja como K6Frame en un flow; Live conserva su framing/FEC. |
| 99,9 % como objetivo inmediato | Claim bloqueado hasta P9 y medición con elegibilidad previa al resultado. |
| High ID | Requiere OP_IDCHANGE real y reachability E2E independiente. |

## 3. Matriz de reutilización

| Capacidad v0.5 | Reutilización | Trabajo nuevo |
|---|---|---|
| Identidad | `NodeIdentity`, `Kad6CryptoHost` | Transcript/binding KRP. |
| Framing bounded | `kad6_bytes`, patrones K6Frame/vectors/fuzz | ControlFrame KRP mínimo. |
| Autorización de destino | TargetTicket, policy/hardening Kad6 | Scopes ED2K_SERVER/PEER/EPR. |
| Socket virtual | `CKad6OriginSocket`, `CKad6ExitSocket` | `CRelayServerSocket` y adaptadores KRP. |
| Fuente/entrada de archivos | SourceLease, front-door, cohort | Coexistencia con EPR genérico. |
| Identidad exterior | VEP/SecureIdent | Tests multi-versión/server. |
| Cuotas/kill switch | K6 quota/hardening/release | Jerarquía de edge por tenant/servicio. |
| Live | BuddyRelay, LiveTunnel, bulk/FEC | Solo adapter/caps/reachability. |
| UDP clásico | Enum/codecs parciales | Runtime, mappings y anti-amplificación. |
| Edge público | Ninguno | Daemon, allocator, gateways, TLS/WSS y operación. |

## 4. Assets de la v0.5

La copia recibida referencia siete imágenes y seis rutas únicas bajo `Especificacion_Tecnica_Relay_eMule_Kad6_v0.5_assets/`; el directorio no estaba incluido. Hasta recuperar/generar esos assets, la versión Markdown no se considera autocontenida para publicación.

Assets esperados:

- `arquitectura_general.png`;
- `seleccion_ruta.png`;
- `pila_protocolos.png`;
- `highid_relay.png`;
- `streaming_directo.png`;
- `cluster_relay.png`.

La ausencia de imágenes no bloquea P0 técnico, pero sí bloquea una entrega documental final de la v0.5.

## 5. Claims permitidos durante el desarrollo

| Estado | Texto permitido |
|---|---|
| P0/P1 | “Core/scaffold en desarrollo; sin servicio público”. |
| P0b PASS | “High ID demostrado en matriz de laboratorio indicada”. |
| R1 | “MVP TCP experimental, default OFF”. |
| R2 | “Beta controlada con reachability/fencing según matriz”. |
| R4 | Claim público solo según SLI/auditoría efectivamente superados. |

No se permite “High ID garantizado”, “Kad abierto” o “relay público listo” antes de su gate.
