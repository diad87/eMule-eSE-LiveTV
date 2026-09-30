# Relay/KRP — cierre P4 y Gate G4-LAB

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Fase | P4 — TCP eD2K clásico y High ID por relay |
| Estado | `source/build-complete` + `lab-certified` local |
| Gate G4-LAB | PASS |
| High ID público real | Pendiente de prueba con un edge de IPv4 pública |
| Activación | Experimental y OFF por defecto |

## Resultado

P4 conecta el eMule sin modificar con un servidor eD2K a través de un proxy loopback y KRP sobre
TLS/WSS. El edge concede un puerto TCP público y reenvía por la misma sesión los callbacks y las
conexiones de peers hacia el listener local de eMule. El login anuncia el puerto concedido; el
`OP_IDCHANGE` sigue siendo procesado por el parser original y sólo se muestra `High ID by relay`
cuando además se ha observado tráfico entrante real.

Se han implementado:

- HELLO, reto, firma Ed25519, prueba de token ligada al TLS exporter y sesión autenticada;
- solicitud/concesión de lease y listener TCP real en el edge;
- binding de destino eD2K, validación de dirección/puerto y conexión saliente desde el edge;
- `FLOW_OPEN`, `FLOW_DATA`, cierre/reset, secuencias estrictas y fragmentos de hasta 32 KiB;
- flujo persistente de servidor y flujos independientes para callback y peers;
- publicación del puerto de lease en el login de eMule;
- evidencia main-thread de callback + `OP_IDCHANGE`, sin permitir que el worker sintetice High ID;
- token de 256 bits generado con CSPRNG, rechazo de overwrite y comparación constante;
- activación pública explícita y configuración incompleta fail-closed.

## Evidencia reproducible

```bat
cd librelaycore
make.bat

cd ..\librelayclient
make.bat

cd ..\relayedge
make.bat
```

Resultados observados:

```text
KRP TCP wire: 30335 checks; 10000 bounded data round trips
P4 E2E PASS: 52 checks; real TLS/WSS auth, lease, server flow,
callback, peer, IDCHANGE bytes and 256 KiB bidirectional payload
librelayclient P3 tests: 70697 checks, 100000 queue actions, 10000 lifetime cycles
relayedge regression: 30144 checks Release + 30144 checks ASan
```

El proyecto `srchybrid/emule.vcxproj` se compiló en x64 Release con MSBuild y produjo
`srchybrid/x64/Release/emule.exe`. No hubo errores de compilación; permanecen avisos preexistentes
del proyecto eMule.

## Auditoría del gate local

| Condición | Resultado |
|---|---|
| Login eD2K cruza el relay y anuncia el lease | PASS |
| Callback del servidor entra por el puerto concedido y recibe respuesta | PASS |
| Segundo peer usa un flujo independiente | PASS |
| Datos arbitrarios bidireccionales, fragmentados por KRP | PASS, 256 KiB por sentido |
| `OP_IDCHANGE` vuelve por el flujo real de servidor | PASS |
| High ID requiere `IDCHANGE` + endpoint reachable | PASS |
| Default OFF, token/CA/hostname obligatorios y sin fallback directo silencioso | PASS |
| Release, ASan de regresión y eMule x64 Release | PASS |

## Frontera del cierre

El gate físico público no puede certificarse dentro de un único PC: requiere ejecutar
`relayedge.exe` en una máquina con IPv4 pública, abrir allí el puerto TLS y el rango de leases y
conectar a un servidor eD2K público. Ejecutar el edge detrás del mismo router cerrado no aporta
reachability pública.

Este cierre no afirma HA, UDP/Kad, IPv6, H2/H3, servicio multi-tenant, transferencia pública de
archivos completa ni soak. El edge experimental procesa una sesión KRP activa cada vez. Es una
base funcional para probar High ID TCP real, no un servicio de producción.

La prueba pública y sus resultados deben añadirse como evidencia G-HID antes de usar el claim
`public-certified`.
