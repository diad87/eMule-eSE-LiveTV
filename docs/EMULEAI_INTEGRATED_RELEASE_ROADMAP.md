# eSE — Encaje del programa eMule AI en las releases 9.x

**Sustituido como roadmap operativo el 30 de septiembre de 2026.** El
[`plan único v9.3`](V9.3_PLUS_RELEASE_TRAIN.md) reúne el alcance anterior
9.3–9.8, adelanta QUIC tras el selector mínimo y aplica validación proporcional.
El estado vivo está en [`V9.3_EXECUTION_STATE.md`](V9.3_EXECUTION_STATE.md).

| Etiqueta histórica | Destino vigente |
|---|---|
| 9.3 Core / avanzado | bloques A / B |
| 9.4 DirectOnlyV1 | B, reutilizando A |
| V95-CORE, 21 casos | E, motor y persistencia |
| V96-PRODUCT, 40 casos | F, producto y plataformas |
| V97-NETWORK, 16 casos | C, QUIC temprano, privacidad peer e interop |
| V98-SERVER-INTEROP | D, referencia propia e interop activa |
| B0-BASE + V92-ALIGNED, 15 casos | base/regresión; A/C conservan arrastres |

Se preservan abajo las 92 asignaciones, estados y referencias congelados para
trazabilidad, junto con sus 19 deltas. Las antiguas fechas, secuencias,
prohibiciones de empezar QUIC, autorizaciones pendientes y gates de proceso
describen **el tren histórico**, no el plan vigente. Ningún PASS se obtiene al
renumerar. La cobertura completa y el criterio de salida actuales están en
§§17–20 del plan único. 9.0–9.2 conservan su alcance propio.

## Documento histórico conservado — no operativo

Estado: plan transversal activo; enmienda de coherencia del 15 de agosto de
2026; no modifica por sí solo el alcance normativo de una release  
Fecha base del inventario histórico: 26 de julio de 2026  
Inventario de referencia: `EMULEAI_PARITY_AND_SUPERIORITY_PROGRAM.md`  
Delta vigente: `EMULEAI_V1.6_DELTA_BASELINE.md`  
Laboratorio externo: `SERVER_CONFORMANCE_LAB.md`  
Propuesta posterior: `V9.8_ECOSYSTEM_INTEROP_ENVELOPE.md`  
Tesis de contraste:
`TESIS_CONSOLIDADA_LOWID_A_LOWID_DIRECTO_V9.1_2026.docx`  
Jerarquía: `V9_RELEASE_SPECIFICATION.md` conserva autoridad superior para
9.0–9.4; un ADR solo la sustituye cuando está aceptado; el plan aprobado de
cada release queda subordinado a ambos; `V9.x_EXECUTION_STATE.md` es el único
ledger de selección y estado, pero no amplía alcance. Planes propuestos,
runbooks y este roadmap respetan esos gates y no adquieren autoridad por su
nombre.

## 1. Decisión

El programa de comparación no se ejecutará como una cuarta rama paralela ni se
inyectarán sus 92 casos dentro de 9.2, 9.3 y 9.4.

La secuencia será:

1. **Ahora:** seguir el ledger 9.2 dentro de la autorización provisional,
   cerrar la promoción de 9.1, congelar benchmarks y construir únicamente el
   catálogo/laboratorio de conformidad sin emisión ni UI nueva.
2. **9.2:** cerrar únicamente los casos de eMule AI que ya coinciden con
   alcance directo, mappings, cambio de red, IPv6 y diagnóstico; además,
   congelar el snapshot local de candidatos verificables que consume 9.3 y
   promover o volver a fijar el baseline público actual de eMule AI.
3. **9.3:** convertir el selector único en la autoridad DCO, consumir ese
   snapshot y medir Direct Core/Punch2 antes de promover Punch3/predicción.
4. **9.4:** ejecutar el perfil `DirectOnlyV1` solo después de reconciliar su
   autoridad; KRP, TURN y cualquier relay de payload quedan fuera.
5. **9.5:** primera release dedicada al programa: motor, compartidos,
   persistencia e I/O.
6. **9.6:** producto, búsqueda, UI y plataformas.
7. **9.7:** QUIC peer-to-peer, confianza, filtros, tuning e interoperabilidad
   externa básica con recepción primero.
8. **9.8 propuesta:** callback entre servidores, rendezvous autenticado,
   TLS cliente-servidor y QUIC de servidor opcional. Sigue `NOT AUTHORIZED`.

Así se preserva la ruta crítica ya aprobada y cada cambio llega cuando sus
dependencias arquitectónicas existen.

## 2. Corte documental — 15 de agosto de 2026

### 2.1 Resumen ejecutivo

| Elemento | Estado real | Avance demostrado | Pendiente para cerrar |
|---|---|---|---|
| Inventario eMule AI | `MODELO DUAL` | 49 funciones + 43 mejoras congeladas en 1.5.2; delta 1.6 de 19 cambios registrado | promover/revalidar el baseline vigente en el freeze de 9.2 |
| Asignación temporal | `HECHO` | 92 casos históricos asignados exactamente una vez; el delta no se duplica | reestimar 9.5–9.8 en el freeze de 9.2 |
| `AI-I03` admisión segura de compartidos | `PARIDAD LOCAL` | política única en scan/watcher, prueba standalone y build x64 verdes | A/B binario contra AI 1.5.2 y corpus común |
| Base `B0-BASE` | `PREPARADA` | 6 casos en `PARIDAD`; 1 caso `NO-ADOPTAR` | locks A/B/regresión y aceptación en una base limpia |
| eSE 9.1.0-beta.2 | `CANDIDATO EN ÁRBOL` | versión alineada, preflight con `-AllowDirty`, pruebas focalizadas y build x64 verdes | commit limpio, suite completa, paquete/self-test, físico, remoto y soak |
| 9.1 aprobada | `NO` | existen mejoras locales posteriores al informe del 24 de julio | actualizar evidencia y cerrar los gates físicos obligatorios |
| 9.2 | `DESARROLLO PROVISIONAL AUTORIZADO` | ledger integrado de 152,75 JP; la selección concreta pertenece a `V9.2_EXECUTION_STATE.md` | promoción bloqueada hasta aprobar 9.1; completar gates restantes |
| 9.3 | `BLOCKED_G92_93_DEV` | plan de 146/188 JP y ADR propuesto | `G92-93-DEV` solo habilita WP93-0 documental; código funcional exige `G-N0=PASS` con ADR aceptado |
| 9.4 | `BLOCKED_BY_SPEC_RECONCILIATION` | plan v2.0 `DirectOnlyV1`, 130 JP | reconciliar especificación, tesis y perfil antes de implementar |
| Laboratorio externo | `DISEÑADO` | catálogo externo, snapshots y gates receptor-primero | golden packets/PCAPs/fuzz; cero producción en 9.2–9.4 |
| 9.8 | `PROPOSED / NOT AUTHORIZED` | envolvente 95–135 JP con gates separados | 9.7 Stable, informe del laboratorio, reestimación y autorización expresa |
| Casos `ESE-SUPERA` | `0` | — | comparación A/B y regresión por caso |

`PARIDAD LOCAL`, `CANDIDATO EN ÁRBOL` y desarrollo provisional no equivalen a
release aceptada. Los ledgers de cada release son la fuente viva para tarjeta,
commit y gate; este roadmap no duplica ni intenta sustituir ese estado.

### 2.2 Evidencia histórica del corte de julio

- `srchybrid\tests\make.bat`: PASS; incluye 21.659 checks LiveFEC, 183
  LiveBulk, 14 hole-punch y las políticas nativas nuevas.
- `npm test`: PASS, 38/38 pruebas.
- matriz eMule AI: PASS, 49 + 43 casos y 92 asignaciones únicas.
- linter de orden de locks de `LiveTunnel`: PASS.
- gate de procesos Node síncronos: PASS.
- `release_preflight.ps1` para `v0.70b-eSE9.1.0-beta.2` con
  `-AllowDirty`: PASS.
- compilación `Release|x64`: PASS en
  `artifacts\roadmap-status-build\emule.exe`.

La salida normal `srchybrid\x64\Release\emule.exe` no pudo reemplazarse porque
esa copia estaba ejecutándose. No es un fallo de compilación: el enlace en la
salida alternativa terminó correctamente.

Esta lista conserva la procedencia del corte histórico; no afirma que esos
binarios sean el estado vivo del 15 de agosto. La evidencia actual de ejecución
se consulta en los ledgers y manifiestos de cada release.

### 2.3 Distribución actual de los 92 casos

| Tren | Casos | Estado actual |
|---|---:|---|
| `B0-BASE` | 7 | 6 `PARIDAD`, 1 `NO-ADOPTAR` |
| `V92-ALIGNED` | 8 | 6 `PARCIAL`, 1 `PARIDAD`, 1 `ESE-BETA` |
| `V95-CORE` | 21 | 11 `BRECHA`, 10 `PARCIAL` |
| `V96-PRODUCT` | 40 | 28 `BRECHA`, 12 `PARCIAL` |
| `V97-NETWORK` | 16 | 8 `BRECHA`, 8 `PARCIAL` |
| **Total** | **92** | **47 `BRECHA`, 36 `PARCIAL`, 7 `PARIDAD`, 1 `ESE-BETA`, 1 `NO-ADOPTAR`** |

Los 19 `AI16-Dxx` no forman otro tren ni aumentan este total. Refinan los
criterios de casos existentes y solo podrán crear un caso nuevo mediante el
gate explícito del delta 1.6.

## 3. Situación temporal real

| Ventana | Entrada | Trabajo ya planeado | Duración orientativa a tiempo completo | Regla para el programa eMule AI |
|---|---|---:|---:|---|
| Base 9.1 | ahora | cerrar gates obligatorios pendientes | no estimada aquí | hardening y evidencia; ninguna feature amplia |
| 9.2 | desarrollo provisional por `G91-92-DEV`; promoción tras 9.1 aprobada | 152,75 JP en el ledger vivo | 23–28 semanas era la base de 105 JP; requiere reestimación | AI solo por solape; ocho checkpoints sin JP netos |
| 9.3 release | WP93-0 documental tras `G92-93-DEV`; código funcional tras `G-N0=PASS`; promoción tras 9.2 Stable + gates | 146 JP | 32–40 semanas | Direct Core + Advanced A; DCO, Punch2/3 y predicción |
| 9.3 tesis completa | gates de track | 188 JP | 38–48 semanas | añade Birthday NetLab y DVL post-path; no bloqueantes |
| 9.4 | 9.3 Stable + reconciliación `G-ENTRY` | 130 JP | 32–38 semanas | `DirectOnlyV1`; cero KRP/TURN/relay; QUIC fuera |
| 9.5 | 9.4 Stable | 55–75 JP iniciales | 14–18 semanas | motor y datos |
| 9.6 | 9.5 Stable | 65–90 JP iniciales | 16–22 semanas | producto y plataformas |
| 9.7 | 9.6 Stable | 60–85 JP iniciales | 15–22 semanas | transporte peer, confianza e interop básica |
| 9.8 propuesta | 9.7 Stable + `G98-SPEC` | 95–135 JP iniciales | 24–34 semanas | plano cliente-servidor e interop avanzada; no autorizada |

El plan base de 9.2 continúa documentando 105 JP. El ledger vivo registra
152,75 JP tras autorizar 47,75 JP del programa adicional M2A. Los ocho casos
`V92-ALIGNED` continúan absorbidos por tarjetas anfitrionas y no explican ese
incremento. El calendario de 23–28 semanas no debe reutilizarse como promesa
sin reestimar el alcance ampliado.

La antigua cifra de 93 JP para 9.3 queda sustituida provisionalmente por dos
envolventes: **146 JP** para la línea release y **188 JP** para toda la tesis.
La ampliación no queda autorizada hasta reconciliar
`V9_RELEASE_SPECIFICATION.md` mediante actualización o ADR. Birthday y DVL no
bloquean Direct Core/Advanced A ni pueden consumir su reserva.

Las cifras 9.5–9.8 son presupuestos de orden de magnitud. Se recalculan durante
el freeze de contratos de cada release. No son autorización para consumir la
reserva de 9.2–9.4, cuyas reglas excluyen alcance nuevo.

No se publica un total 9.2–9.4 mientras 9.2 requiera reestimación y 9.4 siga
bloqueada por autoridad contradictoria. Sumando solo las envolventes no
autorizadas, 9.5–9.8 ocuparían 69–96 semanas a tiempo completo. En dedicación de
hobby, las fechas deben derivarse de horas disponibles y no de esos rangos.

## 4. Reglas para no romper 9.2–9.4

1. Los planes y ledgers de cada release siguen siendo la autoridad de selección.
2. Un caso `AI-*` solo entra en 9.2–9.4 si una tarjeta normativa ya necesita
   modificar el mismo contrato o code path para cumplir su DoD.
3. La comparación añade tests, métricas y evidencia; no añade una segunda
   implementación del mismo transporte o estado.
4. No se consume reserva de estabilización para una feature `AI-*`.
5. Si el incremento añade wire, dependencia, preferencia, migración o superficie
   pública no prevista, se aplaza a 9.5–9.8.
6. Si aumenta más de un 10 % el diff previsto de la tarjeta anfitriona o añade
   más de 0,5 JP, se separa y aplaza.
7. Todo cierre histórico conserva A/B contra 1.5.2. Tras el freeze de 9.2, un
   nuevo `ESE-SUPERA` exige además A/B contra el baseline vigente promovido;
   terminar una tarjeta 9.x no basta por sí solo.
8. Cada release mantiene una sola tarjeta activa. El trabajo comparativo no crea
   un segundo WIP.

## 5. Checkpoints dentro de las releases existentes

### 5.1 Entrada formal y desarrollo provisional de 9.2

- `G91-92-DEV=PASS` autoriza desarrollo provisional según el ledger. No
  equivale a entrada formal ni autoriza Alpha/Beta/RC/Stable.
- Cerrar los gates obligatorios de 9.1: la promoción de 9.2 continúa `BLOCKED`
  hasta que exista un commit 9.1 aprobado.
- Ejecutar y archivar el baseline eSE/eMule AI sobre el mismo corpus.
- Decidir por revisión si `AI-I03` y los locks de regresión B0 entran en la base
  9.1 aprobada. Si no entran sin retrasar el freeze, quedan preparados para 9.5.
- Seguir una sola tarjeta del estado maestro; el laboratorio comparativo no
  crea WIP productivo paralelo.
- No comenzar watcher recursivo, caché de compartidos, UI, QUIC, migración ni
  emisión del dialecto externo.

### 5.2 Durante 9.2

Los puntos de observación se añaden a las tarjetas equivalentes de topología,
mappers, cambio de red, API/UI y laboratorio. En Beta se ejecuta el A/B de los
ocho casos asignados a 9.2; en RC se fija su veredicto y evidencia.

Un caso que no alcance su criterio continúa `PARCIAL` o `BRECHA`; no retrasa
9.2 si sus requisitos `V92-*` sí están satisfechos.

### 5.3 Durante 9.3

9.3 no recibe una feature independiente del inventario AI. El “selector único”
del plan se nombra y limita como `DirectConnectionOrchestrator` (DCO): una sola
autoridad para orden, intentos, generación, cancelación, nominación y terminal.
Consume el snapshot 9.2 sin conocer UPnP/PCP/NAT-PMP.

`G92-93-DEV=PASS` solo permite WP93-0 documental, reauditoría, matrices y tests
puros. No autoriza editar código funcional. Ese trabajo exige `G-N0=PASS`, que
incluye el handoff, freeze de frontera, ADR aceptado y baseline válido. La
promoción de 9.3 exige además 9.2 Stable y sus gates de release. Si 9.2 cambia
schema, ownership, endpoint, verificación o generación, el gate se invalida y
9.3 debe parar, rebasar y repetir la matriz de handoff.

La promoción interna de 9.3 sigue este orden:

1. Direct Core: IPv6/direct/mapped, callback aplicable y Punch2 exacto;
2. Advanced A: witnesses, Punch3 y predicción ≤17, siempre detrás de gates;
3. Birthday punching y DVL quedan en tracks no bloqueantes, apagados y con
   promoción independiente; no forman parte de la línea release.

Sus checkpoints
producen evidencia reutilizable para:

- `AI-F14`: tasa de conexión y tiempo Direct→Mapped→Callback→Punch2→Punch3;
- `AI-I19`: tráfico por fuente útil y reasks;
- `AI-I20`: distribución, backoff y ráfagas;
- `AI-I43`: throughput, RTT, memoria y estabilidad por perfil.

La evidencia se captura en Alpha virtual, Beta física y RC. Los cuatro casos
se cierran más adelante porque sus criterios completos exceden el alcance 9.3.

Birthday punching permanece como experimento NetLab no bloqueante, solo para
EIM↔EDM clasificado, con consentimiento, cuotas y evidencia estadística. DVL
permanece como continuidad post-path: no puede usarse para afirmar que creó la
ruta inicial. Ninguno puede promocionarse fuera de su gate aunque el release
Core/Advanced A ya esté aprobado.

### 5.4 Durante 9.4

El plan v2.0 de 9.4 propone sustituir el antiguo plan KRP por `DirectOnlyV1`:
DCO como única autoridad, candidatos directos verificables, Punch2/Punch3 y un
terminal `DIRECT_UNREACHABLE` honesto. KRP, TURN, buddy relay de payload y
`REACH_RELAY` quedan fuera del producto.

El tren permanece `BLOCKED_BY_SPEC_RECONCILIATION`. Antes de implementar hay
que resolver la contradicción con la especificación de releases y cualquier
solape de autoridad. Mientras tanto solo se permiten diseño, auditoría y
evidencia que no cambien producción.

Si se autoriza, su campaña ampliará la evidencia de `AI-F14` sobre
alcanzabilidad directa y fallos físicamente imposibles. QUIC peer-to-peer sigue
fuera de 9.4; `AI-F14` no se cierra hasta el tramo de transporte de 9.7.

## 6. Asignación única de los 92 casos

La ventana indicada es aquella en la que debe intentarse el cierre completo,
no necesariamente el primer momento en que se obtenga evidencia.

<!-- SUPERIORITY-CLOSURE-MAP:BEGIN -->
| Ventana de cierre | Casos |
|---|---|
| `B0-BASE` | `AI-F24`, `AI-F32`, `AI-F44`, `AI-I03`, `AI-I31`, `AI-I36`, `AI-I39` |
| `V92-ALIGNED` | `AI-F04`, `AI-F08`, `AI-F15`, `AI-F23`, `AI-F49`, `AI-I11`, `AI-I16`, `AI-I28` |
| `V95-CORE` | `AI-F06`, `AI-F18`, `AI-F19`, `AI-F20`, `AI-F21`, `AI-F33`, `AI-F40`, `AI-F45`, `AI-I01`, `AI-I05`, `AI-I06`, `AI-I09`, `AI-I12`, `AI-I21`, `AI-I22`, `AI-I25`, `AI-I29`, `AI-I30`, `AI-I35`, `AI-I37`, `AI-I42` |
| `V96-PRODUCT` | `AI-F02`, `AI-F05`, `AI-F07`, `AI-F09`, `AI-F12`, `AI-F13`, `AI-F22`, `AI-F25`, `AI-F27`, `AI-F28`, `AI-F29`, `AI-F30`, `AI-F34`, `AI-F35`, `AI-F36`, `AI-F37`, `AI-F38`, `AI-F41`, `AI-F42`, `AI-F43`, `AI-F46`, `AI-F47`, `AI-F48`, `AI-I02`, `AI-I04`, `AI-I07`, `AI-I08`, `AI-I10`, `AI-I13`, `AI-I17`, `AI-I18`, `AI-I24`, `AI-I26`, `AI-I27`, `AI-I32`, `AI-I33`, `AI-I34`, `AI-I38`, `AI-I40`, `AI-I41` |
| `V97-NETWORK` | `AI-F01`, `AI-F03`, `AI-F10`, `AI-F11`, `AI-F14`, `AI-F16`, `AI-F17`, `AI-F26`, `AI-F31`, `AI-F39`, `AI-I14`, `AI-I15`, `AI-I19`, `AI-I20`, `AI-I23`, `AI-I43` |
<!-- SUPERIORITY-CLOSURE-MAP:END -->

Ningún caso se asigna a cierre completo en 9.3 o 9.4. Esto es deliberado:
ambas releases ya tienen rutas críticas grandes y aportan componentes y
evidencia para `V97-NETWORK`, especialmente `AI-F14`, sin absorber alcance
ajeno.

Tampoco se reasigna ninguno de los 92 casos a 9.8. QUIC peer-to-peer y el cierre
de `AI-F14` permanecen en `V97-NETWORK`; 9.8 cubre únicamente el plano
cliente-servidor y la interoperabilidad avanzada.

## 7. Contenido de las releases dedicadas

### 7.1 9.5 — Motor, compartidos y persistencia

Orden:

1. contratos comunes de cancelación, task graph, presupuestos de memoria y
   escritura atómica;
2. watcher/subdirectorios y reload mediante snapshot/commit;
3. caché versionada de compartidos y publicación por diferencias;
4. long paths, `part.met`, known files, config y crash consistency;
5. source cache, estado remoto y auto-query con límites;
6. motor del Download Validator 1.6: reglas versionadas, coincidencias
   explicables, historial/corpus y modo warn sin borrado automático;
7. benchmarks 10k/100k/500k, HDD/SSD y soak de memoria.

Gate de salida:

- los 21 casos `V95-CORE` tienen estado y evidencia;
- ninguna operación de disco bloquea la GUI fuera del presupuesto;
- upgrade/rollback y recuperación tras corte pasan;
- el tramo motor de `AI16-D01` queda absorbido por `AI-F21` y el tramo de
  clasificación de `AI16-D18` por el mismo propietario, con corpus y A/B; el
  veredicto completo de ambos deltas espera sus propietarios de 9.6/9.7;
- las mejoras de compartidos superan el corpus y los tiempos de eMule AI.

### 7.2 9.6 — Producto, búsqueda y plataformas

Se construye sobre el motor virtual y el task graph de 9.5:

1. listas virtuales, multisort, filtros e índices de búsqueda; en Kad, escoger
   otra palabra libre es solo fallback y no convierte varios términos en una
   consulta compartida bajo el mismo target;
2. operaciones bulk cancelables, “move all A4AF”, multiselección y semántica
   cancelar/olvidar;
3. dark/high-contrast, DPI, teclado, tooltips, reset de preferencias,
   notificaciones y estado de layout, incluida la página de opciones del
   Download Validator;
4. webservice tipado y operaciones múltiples;
5. idiomas, geolocalización local y preferencias;
6. portable/AppData, migración reversible, Docker/Wine y SBOM.

Gate de salida:

- los 40 casos `V96-PRODUCT` tienen estado y evidencia;
- p95 de interacción <50 ms en los datasets fijados;
- accesibilidad, privacidad y migración/rollback pasan;
- los propietarios `AI-I32/AI-F28/AI-F13` completan en UI y resultados de
  búsqueda `AI16-D01`; `AI16-D02`–`AI16-D09` y `AI16-D11`–`AI16-D15` tienen
  evidencia dentro de sus propietarios existentes, sin alterar el total de 40
  casos;
- Windows nativo y el perfil Wine/Docker publicado son reproducibles.

### 7.3 9.7 — Transporte, confianza y tuning

Solo empieza con el DCO y el perfil `DirectOnlyV1` estables:

1. threat model y contrato capability-gated de QUIC peer-to-peer;
2. integración QUIC como candidato del DCO, con fallback uTP/TCP y terminal
   directo tipado; nunca KRP o relay de payload;
3. perfiles de subida y conexión basados en BDP con límites y fairness
   ponderada por score/capacidad; no se adopta una alternancia IPv4/IPv6 50/50
   rígida que ignore la diferencia de mérito entre peers;
4. protección, spam, IP filter, PeerGuardian y consenso de nombres, con los
   falsos positivos 1.6 de abuso, MLDonkey, hash conflict y phishing;
5. privacidad de historial, crédito, notas y friend links;
6. recepción segura de `0xAA/0xAD/0xAE`, flags de servidor IPv6 `0x4000`,
   sentinel `0xFFFFFFFF`, callback IPv6 `0x26`, `OP_CHANGE_CLIENT_IP 0xAC`,
   sentinel de reask `0x9A`, bloque IPv6 final de `OP_SERVERLIST`, tag buddy
   `0xA0` y hints Kad `ip6`/`bi6`;
7. ExtSX v1 exacto (`0x83/0x84`, bits `0x01/0x04/0x20`), con bit
   `MODMISC_EXTXS_SKIPTAGS` obligatorio antes de emitir tags `0xBC/0xBE`, y
   obfuscation UDP IPv6 con vector byte-exact;
8. matriz física LowID/CGNAT/IPv6, eMuleQt/eNode/eMule clásico, abuso,
   compatibilidad y A/B final.

Gate de salida:

- los 16 casos `V97-NETWORK` tienen estado y evidencia;
- QUIC no introduce una segunda autoridad de ruta;
- 0-RTT no muta estado sensible;
- filtros y protección tienen corpus de falsos positivos;
- la interoperabilidad externa pasa golden packets, fuzz y control vanilla;
- 9.7 no emite `CT_MOD_IP_V6 0xAE` ni `SRVCAP_IPV6` en login de servidor y no
  inicia dial IPv6 de servidor; pasar el gate del sentinel es necesario para
  recibir, pero no suficiente para esos emisores, reservados a 9.8;
- `REG-DEBT-001` está resuelto antes de cualquier emisión externa; hasta
  entonces `0xF0` sigue siendo un alias privado y no implica soporte
  eMuleQt/eNode;
- `AI16-D10`, el tramo `AI-F14` de `AI16-D16`, `AI16-D17`, los tramos
  `AI-F11/F16` de `AI16-D18` y `AI16-D19` cierran en V97; los tramos
  `AI-F15→V92` y `AI-F21→V95` conservan sus propias ventanas, sin duplicados;
- `AI-F14` demuestra la cascada completa o conserva un estado honesto distinto
  de `ESE-SUPERA`.

9.7 no incluye login o dial IPv6 activo de servidor, callback entre servidores,
`PR_NAT`, TLS cliente-servidor ni QUIC de servidor. Su objetivo externo es
recepción segura de servidor e interoperabilidad peer básica receptor-primero,
con contratos suficientes para decidir 9.8 con datos.

### 7.4 9.8 propuesta — Interoperabilidad de servidores y rendezvous seguro

`V98-SERVER-INTEROP` permanece `PROPOSED / NOT AUTHORIZED`. Su envolvente
separada define siete candidatos:

1. promoción del registro externo y laboratorio de conformidad;
2. interoperabilidad activa de servidor por capacidades;
3. callback LowID entre servidores con voucher y return-routability;
4. `RendezvousV2` ligado a sesión/identidad, consentimiento, nonce, TTL,
   anti-replay, cuotas y antiamplificación;
5. TLS 1.3 opcional sobre TCP con PKIX/pin/TOFU y sin downgrade silencioso;
6. QUIC opcional para el enlace cliente-servidor con fallback
   `QUIC → TLS/TCP → TCP clásico` y sin doble login;
7. filtros, privacidad, kill switches, rollback y matriz física.

Su gate de entrada requiere 9.7 Stable, informe del laboratorio, namespace y
reserva verificables, threat model, reestimación y autorización expresa. No
puede reintroducir KRP en `DirectOnlyV1`, transportar payload por servidores ni
convertirse en una segunda autoridad del DCO.

## 8. Protocolo por caso

Cada caso pasa por estas tarjetas lógicas:

1. `C-BASELINE`: contrato, corpus y números de eMule AI.
2. `C-RED`: prueba que reproduce la carencia o diferencia.
3. `C-MIN`: implementación mínima capability-gated.
4. `C-AB`: comparación en mismo hardware, perfil y red.
5. `C-REG`: regresión, compatibilidad, seguridad y rollback.
6. `C-VERDICT`: actualizar matriz a `BRECHA`, `PARCIAL`, `PARIDAD`,
   `ESE-BETA`, `ESE-SUPERA` o `NO-ADOPTAR`.

No se abre `C-MIN` sin `C-BASELINE` y `C-RED`. No se usa `ESE-SUPERA` sin
`C-AB` y `C-REG`.

Cuando existe wire externo se añade antes de `C-MIN` un `C-INTEROP`:
snapshot/commit, entrada del catálogo, golden packet, parser hostil, downgrade y
control vanilla. `C-INTEROP` puede cerrar como evidencia sin autorizar emisor.

## 9. Próxima decisión ejecutable

La prioridad inmediata no es comenzar 9.5. Es:

1. seguir exclusivamente la tarjeta que marque `V9.2_EXECUTION_STATE.md`
   dentro de `G91-92-DEV`; el roadmap no selecciona otra en paralelo;
2. cerrar los gates de promoción de 9.1 con evidencia del mismo commit;
3. no iniciar trabajo funcional 9.3 hasta `G-N0=PASS`; `G92-93-DEV` solo
   habilita WP93-0 documental y el ADR continúa sin autoridad hasta aceptarse;
4. resolver antes de 9.4 la contradicción normativa que mantiene
   `DirectOnlyV1` en `BLOCKED_BY_SPEC_RECONCILIATION`;
5. completar el harness A/B, delta 1.6 y laboratorio de conformidad solo como
   herramientas, catálogo, fixtures, PCAPs y datasets, sin tocar producción,
   wire ni UI;
6. añadir golden packets y fuzz del sentinel/ExtSX/callback, manteniendo todos
   los emisores externos cerrados;
7. ejecutar los ocho `V92-ALIGNED` en sus tarjetas anfitrionas y conservar el
   mapa de 92 asignaciones únicas;
8. en el freeze Stable de 9.2, promover o volver a fijar el baseline vigente y
   reestimar 9.5–9.8.

El siguiente momento de replanificación del programa será el freeze Stable de
9.2. Allí se actualizan los ocho casos `V92-ALIGNED` y las estimaciones
9.5–9.8 con evidencia real. 9.8 tiene además un segundo gate de decisión en
9.7 Stable; antes de ambos sigue siendo una propuesta, no una release
autorizada.
