# Relay/KRP — threat model P0

| Campo | Valor |
|---|---|
| Versión | 0.1 |
| Fecha | 2026-07-16 |
| Alcance | Cliente KRP, edge, gateways, servidor/peer/Kad y plano de control |
| Estado | Inicial; se actualiza por fase |

## 1. Activos

- Clave privada `NodeIdentity` del cliente.
- UserHash, claves SecureIdent, créditos y estado clásico.
- SessionID, epochs, fencing tokens, tickets y leases.
- IP/puertos públicos y mappings de gateway.
- Policy de destino, listas de servidores y perfiles conductuales.
- Integridad de flows, archivos y media.
- Disponibilidad de edge/gateway y reputación de IPv4.
- Privacidad de búsquedas, nombres de archivo, hashes y payload.

## 2. Fronteras de confianza

```text
Cliente/MFC | carrier hostil | Relay Edge | red interna | Endpoint/Egress Gateway
     |                                                        |
     +---------------- Internet hostil ------------------------+
                    servidores / peers / Kad
```

- El carrier puede perder, retrasar, duplicar o reordenar según su perfil.
- Edge y gateway son servicios del operador, pero pueden fallar o quedar obsoletos.
- Servidores, peers, Kad records y direcciones aportadas son no confiables.
- El cliente puede ser malicioso y solicitar targets/clases/recursos abusivos.
- El control plane puede estar temporalmente no disponible; no autoriza fail-open.

## 3. Invariantes

1. La clave privada del cliente nunca sale del cliente.
2. Ningún target se abre sin autoridad service-specific.
3. Un lease pertenece a una sesión/generation y no se transfiere por replay.
4. Solo un owner/generation recibe tráfico nuevo.
5. Un endpoint no se anuncia antes de ACTIVE + probe.
6. High ID procede de OP_IDCHANGE; reachability procede de evidencia E2E independiente.
7. El gateway no sintetiza handshake/callback en nombre de un cliente ausente.
8. UDP no se encapsula antes de validar mapping/origen/budget.
9. Logs y métricas no contienen payload ni búsquedas por defecto.
10. Ausencia de claves, policy, capacity o directory produce fail-closed.

## 4. Amenazas y controles

| ID | Amenaza | Control mínimo | Gate |
|---|---|---|---|
| T-R01 | Open proxy / SSRF | Scopes, tickets, deny de redes especiales, DNS/IP recheck. | G2/G4 |
| T-R02 | Escaneo distribuido | Cuotas por identidad/IP/destino, allowlists y audit events. | G2 |
| T-R03 | Robo/replay de lease | Binding session/node/generation, token corto y fencing. | G1/G5 |
| T-R04 | Split-brain de owner | CAS, RouteGeneration, fencing e invalidación gateway. | G5 |
| T-R05 | Mezcla de tenants | Demux compuesto, tests dos clientes/IP y chaos. | G-HID/G5 |
| T-R06 | Falso High ID | OP_IDCHANGE real; UI no infiere; probe E2E. | G-HID |
| T-R07 | Callback spoofed | Listener activo, challenge/handshake cliente y LeaseEpoch. | G-HID/G4 |
| T-R08 | UDP reflection/amplification | Admisión antes del túnel, cookies y budget bytes/pps. | G6 |
| T-R09 | Agotamiento puertos/IP | Allocator bounded, reuse delay, grace reclamable y alarms. | G2/G5 |
| T-R10 | Memory/slow reader | Límites pre-allocation, backpressure y deadlines. | G1/G2 |
| T-R11 | Replay 0-RTT | P0/P1 no muta en 0-RTT; resume posterior solo 1-RTT. | G1/P8 |
| T-R12 | Downgrade de carrier | TLS obligatorio, transcript liga perfil y fallback observable. | G2/G8 |
| T-R13 | Edge malicioso/comprometido | Sin clave privada, payload E2E donde aplique, logs mínimos. | P9 |
| T-R14 | Relay record falso | Trust roots, firma, TTL, revocación y diversity. | G7/P9 |
| T-R15 | Abuso de servidores comunitarios | Servidor elegido, fallback opt-in, circuit breaker y canaries acotados. | G-HID/P9 |
| T-R16 | Fuga de metadata | Redacción de logs, cardinalidad bounded y PCAP autorizado. | Todos |

## 5. Release blockers

- Target crudo aceptado por cualquier flow.
- Epoch/fencing permite dos propietarios activos.
- Callback o bytes llegan al tenant equivocado.
- UI declara High ID/reachability sin evidencia autoritativa.
- UDP produce amplificación no acotada.
- Token replay extiende lease o recupera un recurso reasignado.
- Kill switch deja endpoint anunciado/socket huérfano.
- Logs contienen payload, búsquedas o secretos.
- Capacidad pública se anuncia sin recursos/self-test/gate.

## 6. Plan de verificación

- P1: vectors/fuzz/state-machine/replay/overflow.
- P2: forbidden targets, Slowloris, reconnect storm, auth flood.
- P4: callbacks/peers reales, tenant isolation y SecureIdent.
- P5: split-brain, stale owner, takeover y grace.
- P6: spoof/reflection/amplification/pps soak.
- P9: auditoría externa, SBOM, KMS, incident drills y 30 días.
