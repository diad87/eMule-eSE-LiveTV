# MOD-0.1 — Inventario de coordinadores congelado

Este paquete es un punto de partida de arquitectura, no una extracción. Fija
los tres coordinadores monolíticos al commit
`b875d3dd61a2d675b2138d61161f0a8fec9d9888`:

| Coordinador | Implementación | Cabecera | Propósito inventariado |
| --- | --- | --- | --- |
| `CLiveTunnel` | `srchybrid/LiveTunnel.cpp` | `srchybrid/LiveTunnel.h` | circuitos, solicitudes pendientes, callbacks Kad6 e ingreso de túneles |
| `CWebServer` | `srchybrid/WebServer.cpp` | `srchybrid/WebServer.h` | despacho web y puente síncrono explícito hacia GUI/live |
| `CLiveStreamManager` | `srchybrid/LiveStreamManager.cpp` | `srchybrid/LiveStreamManager.h` | estado de streaming, peers/chunks y peticiones live de GUI/web |

El artefacto normativo es [mod01_architecture_inventory_v1.json](mod01_architecture_inventory_v1.json). Contiene, por fichero, SHA-256 del blob Git, LOC físicas y lógicas aproximadas, definiciones cualificadas de `.cpp`, definiciones inline de la cabecera, miembros directos `m_*`, records de estado con su propietario real y relación de contención, includes, locks, puntos de entrada de hilo/tarea/callback, seams de pruebas, responsabilidades, riesgos y condiciones de parada.

| Coordinador | LOC `.cpp` (física/lógica) | LOC `.h` (física/lógica) | Def. `.cpp` + inline `.h` | miembros directos | records / campos internos | locks miembro+local / operaciones / adquisiciones | marcadores/candidatos de entrada | refs. de test |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `CLiveTunnel` | 11.610 / 10.094 | 1.350 / 271 | 208 + 6 | 106 | 34 / 254 | 6+0 / 263 / 235 | 37 | 4 |
| `CWebServer` | 8.202 / 5.526 | 408 / 366 | 66 + 4 | 8 | 2 / 74 | 0+0 / 0 / 0 | 57 | 4 |
| `CLiveStreamManager` | 5.067 / 3.269 | 886 / 272 | 79 + 29 | 65 | 8 / 25 | 1+1 / 41 / 36 | 16 | 1 |

Los conteos son los del blob de baseline y se comprueban mediante prueba. Los
records anidados conservan su propio `owner`; por ejemplo, `GlobalParams` y
`WebTemplates` están relacionados con `m_Params` y `m_Templates`, pero sus 74
campos no se atribuyen a `CWebServer`. Las relaciones también registran
contención entre records y aliases de tipos. Cada rol declara su
`role_basis`: heurística por nombre o asignación explícita como callback. Una
referencia de test y un candidato de entrada basado en el nombre son evidencia
léxica, no una afirmación de cobertura ni de hilo llamador.

La excepción con contrato externo probado es `chunkCb`: el JSON enlaza su
definición y cuatro registros con el contrato de `CRTMPIngest`, que lo invoca
en su watcher thread antes de entrar en `CLiveStreamManager::FeedSegment`.
También se registran explícitamente los cuatro comparadores síncronos usados
por `qsort_s` en `CWebServer`.

## Reproducibilidad

Desde la raíz del repositorio:

```powershell
python tools/architecture/generate_mod01_architecture_inventory.py --verify
```

El verificador no usa rutas de usuario. Lee blobs del commit fijado y además
comprueba que los seis fuentes presentes equivalen a esos blobs tras normalizar
fin de línea. Cualquier cambio en los monolitos falla hasta que se tome
explícitamente una nueva decisión de baseline y se regenere el inventario:

```powershell
python tools/architecture/generate_mod01_architecture_inventory.py --write
```

`--write` sólo reconstruye desde el commit fijado; no convierte cambios del
árbol de trabajo en una nueva baseline por accidente.

## Lectura segura de concurrencia

Las definiciones incluyen locks miembro y locales; las operaciones incluyen
constructores RAII, `Lock` y `Unlock`, incluso mediante `self->` y guards
nombrados. Las adquisiciones y los bordes de secuencia se limitan a cada rango
de función extraído. Un borde sólo afirma que una adquisición aparece antes
que otra en el texto: no afirma que la primera siga retenida. No son un orden
de locks impuesto, ni una prueba de ausencia de deadlock. Antes de mover
un comportamiento deberán definirse el owner, hilo llamador, snapshot/vida de
los datos y el contrato de cancelación. Si no pueden definirse, se alcanza una
condición de parada del inventario y MOD-0.1 no autoriza ninguna extracción.

## Privacidad

El JSON no copia cuerpo de peticiones, direcciones, puertos, credenciales,
sesiones ni contenido de tráfico. Sólo registra identificadores de código,
rutas relativas, métricas, hashes y metadatos estructurales.

## Límites declarados

El extractor no es un compilador C++ ni evalúa el preprocesador MFC. Las
funciones/rangos y los puntos de entrada se derivan mediante análisis léxico;
macros, lambdas, condicionales, expansiones indirectas y llaves en literales
requieren revisión humana. El propio JSON conserva estos límites para que no
se confunda el inventario con una prueba semántica perfecta.
