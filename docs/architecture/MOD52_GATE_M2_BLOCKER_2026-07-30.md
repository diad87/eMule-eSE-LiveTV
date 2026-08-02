# MOD-5.2 — bloqueo del Gate M2

Fecha: 2026-07-30  
Commit auditado: `2a583ec8`  
Estado: `BLOCKED`

## Decisión

`MOD-5.2` no puede obtener `PASS` con el alcance y la reserva vigentes.
El producto no ha mostrado aquí un defecto funcional nuevo: el bloqueo es el
incumplimiento de los límites arquitectónicos vinculantes del Gate M2.

La auditoría de implementación Terra/high y una auditoría independiente
Sol/high coinciden con confianza alta. No se modificó código de producción ni
se relajó ningún umbral.

## Contrato aplicable

`docs/V9.2_MODULARIZATION_AND_ARCHITECTURE_PLAN.md` exige al cerrar el Gate M2:

- cumplir el objetivo o el límite duro de LOC;
- mantener cero SCC/ciclos nuevos;
- no superar 150 líneas por función coordinadora, salvo dispatch tabular
  explícitamente catalogado;
- no superar 20 campos mutables por clase coordinadora;
- conservar límites de tamaño y dependencias en los módulos extraídos.

Los límites se aplican a LOC físicas completas. El plan vigente no autoriza
excluir activos embebidos, tablas ni otras regiones de los coordinadores.

## Resultado reproducible

### Límites físicos de los coordinadores

| Archivo | Actual | Límite duro | Exceso | Resultado |
|---|---:|---:|---:|---|
| `srchybrid/LiveTunnel.cpp` | 10.361 | 4.000 | 6.361 | FAIL |
| `srchybrid/LiveTunnel.h` | 1.248 | 900 | 348 | FAIL |
| `srchybrid/WebServer.cpp` | 7.937 | 3.500 | 4.437 | FAIL |
| `srchybrid/LiveStreamManager.cpp` | 5.026 | 3.000 | 2.026 | FAIL |
| `srchybrid/LiveStreamManager.h` | 677 | 700 | 0 | PASS |

`WebServer.h` tiene 390 líneas, pero el contrato no le asigna un límite duro
independiente.

### Campos mutables

Se aplicó el mismo inventario léxico de MOD-0.1.

| Clase coordinadora | Actual | Máximo | Exceso | Resultado |
|---|---:|---:|---:|---|
| `CLiveTunnel` | 87 | 20 | 67 | FAIL |
| `CWebServer` | 9 | 20 | 0 | PASS |
| `CLiveStreamManager` | 47 | 20 | 27 | FAIL |

### Funciones mayores de 150 líneas

| Coordinador | Cantidad |
|---|---:|
| `LiveTunnel` | 11 |
| `WebServer` | 8 |
| `LiveStreamManager` | 7 |
| **Total** | **26** |

No existe un ADR o catálogo vigente de excepciones de dispatch tabular. Incluso
si se concedieran como excepción `_ProcessURL` y `_ProcessLiveAPI`, continuarían
existiendo múltiples funciones largas que no son dispatch tabular.

## Controles que sí pasan

- módulos extraídos: máximo 1.079 LOC, por debajo del recomendado de 1.200 y
  del duro de 1.500;
- dependencias por módulo: máximo 2, por debajo del máximo de 8;
- grafo MOD-5.1: 30 módulos, 3 aristas/includes y 0 SCC nuevos;
- negativos MOD-5.1: 15/15;
- Node: `server.js` 250 LOC, ruta máxima 426 LOC y gate MOD-4.4 5/5.

## Impacto sobre la planificación

Los slices MOD-1, MOD-2 y MOD-3 cerraron correctamente su Gate M1 y sus pruebas
funcionales, pero no redujeron los tres coordinadores hasta el Gate M2 final.
Por tanto, sus resultados técnicos se conservan; lo que debe corregirse es la
trazabilidad que pudiera presentar `MOD-M1`, `MOD-M2` o `MOD-M3` como prueba de
cumplimiento del Gate M2.

`MOD-5.2` estaba presupuestado en 0,75 JP y la reserva modular total es 2 JP.
Los excesos observados requieren un programa adicional de extracciones y
reducción, o una degradación explícita del contrato. No es correcto consumir
silenciosamente la reserva ni elevar los límites.

## Criterio de desbloqueo

Hace falta una decisión del propietario del plan entre:

1. mantener el contrato y autorizar/reestimar un programa adicional de
   extracción hasta cumplir todos los límites;
2. degradar explícitamente Gate M2, documentando nuevos límites y excepciones;
3. diferir Gate M2 y detener la cadena dependiente en MOD-5.2.

Hasta esa decisión, `MOD-5.3`, `MOD-5.4` y MOD-6 no se ejecutan.
