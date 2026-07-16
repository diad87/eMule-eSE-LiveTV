# librelaycore

Core C++17, MFC-free, del relay público/KRP.

Estado: P1 cerrado, Gate G1 `source/build-complete`:

- scaffold y códecs compilables con `/W4 /WX`;
- tamaños de identidad/sesión fijados;
- cursor acotado y varints unsigned LEB128 canónicos;
- envelope `ControlFrame` KRP con payload máximo de 64 KiB;
- valores `KRP_*` contrastados automáticamente con el registro;
- golden vectors, casos adversariales y fuzz determinista bajo Release/ASan;
- state machine `Session` con ocho estados, `SessionEpoch` y `RouteGeneration`;
- fencing de migración y reanudación mutable solo después de 1-RTT;
- consumo de token de reanudación atómico mediante interfaz inyectable;
- transcript de autenticación ligado a carrier exporter y `NodeIdentity` persistente;
- `Flow` con secuencia, half-close, pressure deadline y presupuestos de memoria;
- registro acotado que impide reutilizar `FlowID` dentro de `SessionEpoch`;
- `EprLease` TCP/UDP opcional con generation, bind, probe, grace, drain y revoke;
- autoridad estricta por servicio, sin destino host/port crudo;
- adaptador real para consumir `K6TargetTicket` mediante `libkad6`;
- wire y apertura de red desactivados de forma explícita;
- ningún mensaje `KRP_*` está activo en un transporte;
- sin sockets, threads, MFC, UI ni claves privadas.

Build local:

```bat
cd librelaycore
make.bat
```

El build genera `build/relaycore.lib` y enlaza toda la suite contra ese archivo;
`RELAY_ASAN=1` genera la variante instrumentada `relaycore_asan.lib`.

La evolución del core está gobernada por:

- `docs/relay/RELAY_KRP_ADR_001_CORE_CONTRACTS.md`;
- `docs/protocol/KRP_MESSAGES.csv`;
- `docs/RELAY_KRP_V05_DEVELOPMENT_PLAN.md`.

La evidencia final está en `docs/relay/RELAY_P1_CLOSURE_2026-07-16.md`.
