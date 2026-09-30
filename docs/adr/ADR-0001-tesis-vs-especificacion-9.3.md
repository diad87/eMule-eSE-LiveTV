# ADR-0001 — Reconciliación tesis ↔ especificación para eSE 9.3

| Campo | Valor |
|---|---|
| Tarjeta | `93-0.2` (WP93-0, entrada) |
| Estado | **PROPUESTO** — no aprobado; no levanta N0 por sí solo |
| Fecha de redacción | 2026-08-03 |
| Sustituiría al ser aceptado | `V9_RELEASE_SPECIFICATION.md` §10 (parcialmente; ver §4–§7) |
| No toca | `V9_RELEASE_SPECIFICATION.md` §1–§9 y §11 |
| Fuentes | `TESIS_CONSOLIDADA_LOWID_A_LOWID_DIRECTO_V9.1_2026.docx`; `V9.3_DEVELOPMENT_AND_TEST_PLAN.md` |
| Redactor | Claude (Fable 5), contexto de coordinación |

Las palabras `SUSTITUIDO` y `EXTENDIDO` de este documento describen únicamente
el resultado propuesto. No tienen efecto normativo mientras el estado siga
`PROPUESTO`.
| Ejecutor normativo exigido | `gpt-5.6-sol` xhigh (`SOL-X`) |
| Revisor normativo exigido | `gpt-5.6-sol` max (`SOL-MAX`), contexto independiente |

> **Lectura obligatoria antes de usarlo.** Este documento está redactado por un
> modelo distinto al que la política de orquestación asigna a `93-0.2`. Es un
> borrador completo y decidible, no una aprobación. Ver §13.

---

## 1. Contexto

`V9_RELEASE_SPECIFICATION.md` es la autoridad superior declarada de la rama 9.x.
Su §10 describe 9.3 como **un release monolítico**: una cascada única de ocho
pasos, Punch3 y predicción dentro del mismo gate que la ruta directa, y un
criterio de campo de «3 éxitos de 4 intentos».

La tesis consolidada y el plan derivado (`V9.3_DEVELOPMENT_AND_TEST_PLAN.md`)
describen otra cosa: **cuatro tracks con gates independientes** (Direct Core,
Advanced A, Birthday, DVL), una autoridad central nueva (`DCO`), un perfil
`DirectOnlyV1` con ausencia *estructural* de relay, identidad y generación
tipadas, y un modelo estadístico con denominador e intervalo de confianza.

Ambos textos no pueden gobernar a la vez. El §1.1 del plan 9.3 bloquea toda
edición de código (`N0`) hasta que se ejecute uno de dos actos: actualizar la
§10 o aprobar un ADR que declare qué requisitos de la tesis sustituyen o
extienden `V93-F01`–`V93-F16`. Este ADR ejerce la segunda opción.

Hecho adicional relevante: la especificación fue **borrada del árbol de trabajo
sin commitear**, y `docs/INDEX.md` fue editado para retirar su fila. Es decir,
la supersesión ya se estaba ejerciendo de facto, sin acto normativo y sin dejar
rastro de qué requisitos sobrevivían. El fichero se ha restaurado; este ADR
convierte ese borrado implícito en una decisión explícita y auditable.

## 2. Decisión

1. La **tesis consolidada es la fuente de diseño** de 9.3; el plan de desarrollo
   9.3 es su proyección ejecutable.
2. La **§10 de la especificación deja de aplicarse directamente** y pasa a
   gobernarse por este ADR, requisito a requisito.
3. Las secciones **1–9 y 11 de la especificación conservan autoridad íntegra**.
   En particular siguen vigentes sin cambio: las reglas normativas §2
   (DEBE/NO DEBE/PASS/FAIL/BLOCKED, y que `BLOCKED` nunca equivale a `PASS`),
   los principios §3, el laboratorio §4 —incluida la prohibición de que un
   overlay transporte datos usados como prueba—, evidencias y severidad §5 y
   los gates comunes §6 (`G-CLEAN`, `G-BUILD`, `G-SELFTEST`, `G-UPGRADE`,
   `G-COMPAT`, `G-SOAK`, `G-ROLLBACK`).
4. 9.3 se entrega como **cuatro tracks con gates propios**, no como un release
   monolítico. La línea comprometida es Direct Core + Advanced A. Birthday y DVL
   conservan gates, presupuestos y criterios de promoción independientes y
   **no pueden bloquear ni contaminar** la línea comprometida.

## 3. Orden de precedencia resultante

Para cualquier asunto de 9.3, ante discrepancia manda el primero que se
pronuncie:

1. este ADR;
2. `V9.3_DEVELOPMENT_AND_TEST_PLAN.md`;
3. `V9_RELEASE_SPECIFICATION.md` §1–§9 y §11;
4. `V9_RELEASE_SPECIFICATION.md` §10, **solo** en lo que este ADR no menciona.

Lo que este ADR no menciona sigue vigente. El silencio no deroga.

## 4. Reconciliación de `V93-F01`–`V93-F16`

Leyenda: **VIGENTE** = se mantiene tal cual · **EXTENDIDO** = se mantiene y la
tesis le añade obligaciones · **SUSTITUIDO** = la formulación de la §10 deja de
aplicarse y la reemplaza la de este ADR.

| ID | Requisito §10.3 | Veredicto | Qué manda a partir de ahora | Tarjetas |
|---|---|---|---|---|
| `V93-F01` | Vector de reachability versionado, acotado y extensible | EXTENDIDO | Se desdobla en dos contratos que **no compiten**: `ReachabilityDescriptor` (schema canónico interno) y `ReachVector` v2/v3 (su proyección wire para Kad y Source Exchange). Añade firma, identidad, generación, `valid_until` y TLV acotados. El formato compacto DEBE caber en el límite Kad; si no, publica resumen y recupera detalle por fetch autenticado | `93-2.1`, `93-2.3`, `93-2.8`, `93-2.10` |
| `V93-F02` | Capacidades desconocidas preservadas o ignoradas de forma segura | EXTENDIDO | Se añade downgrade seguro y expiración. Si v2 ya fue distribuido con semántica parcial, se emite v3 y los lectores v2 lo ignoran **sin reinterpretarlo** | `93-2.8`, `93-2.1` |
| `V93-F03` | Selector único reutilizado por descargas y LiveTV | SUSTITUIDO | No hay «selector»: hay un `DirectConnectionOrchestrator` que es **autoridad única** y gobierna **cuatro** consumidores, no dos — Download, Upload, Source Exchange y LiveTV — sobre el mismo session handle vía `IClientByteTransport` | WP93-1, `93-6.1`–`93-6.9` |
| `V93-F04` | Punch2 con cookie de return-routability | EXTENDIDO | Se añade obligación de socket: **Punch2 exacto desde el mismo socket UDP/uTP**. Es checkpoint Sol obligatorio (§9.6 del routing) | `93-4.x` |
| `V93-F05` | Punch3 solo mediante peer rendezvous autenticado | EXTENDIDO + REUBICADO | Pasa a track Advanced A con gate propio. Se formaliza como `RdvReservationV1` (voucher acotado), máximo **tres** reservas R rotatorias, **solo señalización**, y se verifica con `rdv_file_payload_bytes == 0` y `rdv_livetv_payload_bytes == 0` más PCAP A/R/B y caída de R tras la conexión | `93-2.5`, `93-10.x` |
| `V93-F06` | Predicción solo después de fallos previos | EXTENDIDO + REUBICADO | Track Advanced A. Debe ser **secuencial tipada y ligada a evidencia**, no heurística libre | `93-10.x`, WP93-11 |
| `V93-F07` | Ventana máxima por defecto de 17 datagramas por intento | ACLARADO + EXTENDIDO — ver §4.1 | El límite normativo es **17 destinos por intento** (`max_candidates: u8 <= 17`). Se añade el invariante de la tesis: el techo es **por intento, no por llamada interna**, y descargas y LiveTV **no reciben presupuestos separados contra el mismo peer** | `93-10.x`, WP93-11 |
| `V93-F08` | Cooldown, token bucket y backoff por peer | EXTENDIDO | La tesis especifica la forma: token bucket **global** para datagramas experimentales, **más** buckets por peer y por IP/prefijo para impedir Sybil barato tras un CGNAT; refill con reloj **monotónico** y protección frente a overflow; tras agotar predicción, backoff de minutos salvo nueva generación | `93-3.x`, WP93-11 |
| `V93-F09` | No escanear puertos ni direcciones ajenas | VIGENTE + REFORZADO | Se añade evidencia anti-scan explícita como entregable | WP93-11 |
| `V93-F10` | No confundir KadID, user hash e identidad de nodo | VIGENTE + REFORZADO | Deja de ser una prohibición redactada y pasa a ser **tipos distintos con conversiones explícitas y asserts**. Ver §4.2 | `93-2.6` |
| `V93-F11` | Cancelar intentos restantes al obtener una ruta | EXTENDIDO | Se modela: `attempt_id` + `topology_generation` en todo evento, single-winner, exactly-once, y **todo evento de generación antigua es un no-op**, incluidos callbacks tardíos | `93-4.4`–`93-4.8` |
| `V93-F12` | Evitar dobles conexiones y doble contabilidad | EXTENDIDO | Se instrumenta con `single_winner_conflicts` y queda cubierto por el trigger `ESC-DOUBLE` | `93-4.x`, `93-6.x` |
| `V93-F13` | Estados UI: Directo v6, Directo v4, Mapeado, Callback, Punch2, Punch3, No alcanzable | SUSTITUIDO | La enumeración fija de siete estados desaparece. Hay **un solo terminal sin ruta**, `DIRECT_UNREACHABLE`, cualificado por `reason_stage` (`CORE` \| `ADVANCED_A`). Core y Advanced **no son enums terminales distintos**. La UI deriva de outcome + reason chain | `93-1.4`, `93-8.3` |
| `V93-F14` | Métricas por ruta, motivo de descarte y latencia | EXTENDIDO | Se nombran contadores obligatorios: `punch2_attempts`, `punch3_attempts`, `prediction_width`, `single_winner_conflicts`, `rdv_file_payload_bytes`, `rdv_livetv_payload_bytes` | `93-8.x` |
| `V93-F15` | Consentimiento explícito para Punch3/predicción durante beta | VIGENTE + EXTENDIDO | Se extiende a Birthday, que además exige exactamente un extremo EIM y otro EDM, capacidad bilateral y NetLab | `93-8.x`, WP93-12 |
| `V93-F16` | Kill switch elimina capacidades y cancela intentos pendientes | VIGENTE | Sin cambio; sigue exigiendo cancelación en menos de 5 s (`V93-K01`) | `93-8.x` |

### 4.1 Resolución de la discrepancia de `V93-F07`

La §10.3 dice «17 **datagramas** por intento»; el plan dice 17 **destinos**. No
son sinónimos: 17 destinos con reintento superan 17 datagramas.

**Consultada la tesis, la discrepancia es aparente y queda resuelta.** La tesis
fija el límite en destinos (`max_candidates: u8 <= 17`,
`authorize_bounded_window(max_endpoints=17)`, «no supera 17 destinos por
intento») y explica por qué las dos cifras coinciden: un spread de ±8 alrededor
del puerto previsto produce exactamente 17 puertos, que es lo que el árbol
actual pulveriza a un datagrama por puerto. La §10.3 describía el efecto en el
código; la tesis describe la causa.

**Decisión:** el invariante normativo es **≤ 17 destinos por intento**, con un
datagrama por destino en el caso base. La mejora respecto de la §10.3 es
semántica y es el punto de la tesis: deja de ser una preferencia configurable y
pasa a ser un permiso **producido por evidencia tipada** (`NatMappingEvidence`
con clasificación, confianza y `stride`), ligado a IP pública, socket,
generación y tiempo. Sin esa evidencia no hay predicción, aunque el techo lo
permita.

**Invariante adicional que la §10.3 no recogía y este ADR eleva a requisito:**
el techo de 17 es *por intento, no por llamada interna*, y **descargas y LiveTV
no reciben presupuestos separados contra el mismo peer**. Dos consumidores
contra el mismo destino comparten el mismo techo. Sin esta cláusula, el
presupuesto se duplica silenciosamente en cuanto ambos consumidores compiten,
que es precisamente el escenario que `V93-F18` (DCO como autoridad única) hace
posible.

### 4.2 Nota sobre `V93-F10` (identidad)

Este requisito se marca como **reforzado y de riesgo activo**, no como
formalidad. Existe en `main` una regresión conocida y no corregida en la que se
confunden Kad node ID y user hash eD2K, rompiendo un hole-punch previamente
validado. `93-2.6` (tipos y conversiones explícitas con asserts) DEBE
considerarse remediación de un defecto real observado, y ninguna tarjeta que
toque identidad puede cerrarse apoyándose solo en revisión visual.

## 5. Requisitos que la tesis **añade** a la §10.3

Se incorporan al mismo espacio de identificadores para que la especificación
siga siendo el índice canónico de requisitos.

| ID | Requisito nuevo | Origen |
|---|---|---|
| `V93-F17` | **DirectOnlyV1**: relay estructuralmente ausente. No se registra adapter, factory, callback ni transición de relay; no se devuelve `REACH_RELAY`; Kad/R pueden transportar control autenticado pero **nunca** archivo ni LiveTV; se verifica que el socket ganador termina en A y en B | plan §3 |
| `V93-F18` | **DCO autoridad única** para los cuatro consumidores sobre un mismo session handle; ningún consumidor abre transporte por su cuenta | plan §5, §6.3 |
| `V93-F19` | **Generación topológica**: `topology_generation` en todo evento; un incremento por cambio real; cero mutación desde generación stale | plan §6.3 |
| `V93-F20` | **Definición de éxito**: una ruta no gana por ACK, SYN ni `UTP_STATE_CONNECT`. `NOMINATED` es provisional; el commit ocurre en `CONNECTED` tras validar Hello/SecureIdent, identidad, generación y return-routability. Para métrica de producto, éxito exige además **el primer bloque eD2K válido** | plan §2 |
| `V93-F21` | **Witness**: de dos a cuatro witnesses con diversidad de dirección o prefijo, consultados **desde el mismo socket UDP** que se usará para punching; máximo cuatro solicitudes por ciclo y cooldown por witness; `ObservedEndpointReceiptV1` firmado con nonce, bucket, expiración y generación; una observación witness bajo EDM **clasifica**, no inventa un candidato hacia A. Si los resultados son inconexos, se prohíbe la predicción y solo quedan candidatos exactos o reserva Punch3 | tesis §6.1–6.2; plan §6.1–6.2 |
| `V93-F22` | **Frontera 9.2**: se consume `DirectCandidateSnapshotV1` sin reinterpretar ownership, endpoint, verificación ni generación | plan §4, §6.1 |
| `V93-F23` | **Límites de publicación**: máximo ocho candidatos y tres reservas R; dedup por familia/transporte/IP/puerto/generación; ninguna IP privada ni `100.64.0.0/10` publicada como endpoint de Internet | plan §6.1 |
| `V93-F24` | **Honestidad estadística**: todo claim porcentual publica cohorte, denominador e intervalo de confianza; el 70 % externo es benchmark condicional, nunca criterio universal | plan §11 |
| `V93-F25` | **Aislamiento de tracks**: Birthday y DVL tienen gates propios y no bloquean Core/A; DVL nunca usa TUN/TAP, arranca solo sobre transporte ya autenticado y **no altera la tasa de reachability** | plan §2.3, §12 |

## 6. Supersesión de la cascada §10.2

La cascada de ocho pasos se sustituye por una cascada **por tracks**:

```text
Direct Core (línea comprometida)
  1. IPv6 global/pinhole verificado
  2. IPv4 directa verificada
  3. IPv4 mapeada por UPnP/NAT-PMP/PCP con inbound proof
  4. Callback clásico aplicable
  5. Punch2 exacto desde el mismo socket UDP/uTP
  6. DIRECT_UNREACHABLE con reason_stage=CORE

Advanced A (gate propio; no hereda el PASS de Core)
  7. Punch3 mediante reserva R autenticada, solo señalización
  8. Predicción secuencial tipada, ligada a evidencia, ≤17 destinos
  9. DIRECT_UNREACHABLE con reason_stage=ADVANCED_A
```

Diferencias que este ADR declara vinculantes frente a la §10.2:

- el paso 3 exige **inbound proof**; un MAP sin proof queda en `CANDIDATE` y no
  promociona;
- el paso 5 exige **el mismo socket**, no un socket equivalente;
- el terminal deja de ser el rótulo «No alcanzable sin relay» y pasa a ser
  `DIRECT_UNREACHABLE` con `reason_stage`;
- la frontera Core/Advanced es un **gate**, no un simple orden de intento: los
  pasos 7–8 no se ejecutan mientras `G-CORE` no esté verde.

Se conserva sin cambio, y se subraya, la regla de la §10.2: **9.3 NO incluye
relay como ruta de éxito**.

## 7. Supersesión de §10.5, §10.6 y §10.7

**§10.5 (pruebas obligatorias).** Los casos `V93-A01`…`V93-O01` siguen siendo
escenarios válidos y NO se derogan, pero dejan de constituir por sí solos el
conjunto de aceptación: quedan subsumidos en la WBS y en los paquetes
`QA93-01`–`QA93-10`, con la matriz requisito→código→test→evidencia de `93-0.3`
como índice de trazabilidad. El harness `tools/holepunch_gate_test.ps1` sigue
siendo válido como harness base de las tarjetas físicas.

**§10.6 (criterio de éxito de campo).** SUSTITUIDO. La regla de «al menos 3
éxitos de 4 intentos» queda **degradada a smoke**: cuatro rondas por sentido
comprueban cableado y elegibilidad, no rendimiento. La aceptación de campo es
`G-FIELD`: ≥30 intentos por sentido y celda, con denominador e intervalo de
confianza, más 4 GiB, LiveTV 2 h y soak 24 h.

Se conservan íntegras las cinco exigencias cualitativas de la §10.6 (clasificar
correctamente cada dirección; que todo paquete esperado aparezca en contadores y
captura; terminación acotada y honesta en topología incompatible; no superar
ningún límite de paquetes; y que **ninguna ruta se declare directa si fue
overlay o relay**).

**§10.7 (gate de salida 9.3).** SUSTITUIDO por la escalera de gates del plan:
`G-N0` → `G-WIRE` → `G-CORE` → `G-ADV-A` → `G-FIELD` → `G-RC` → `G-STABLE`, con
`G-BDAY` y `G-DVL` fuera de la línea comprometida. Advanced A **no hereda** el
PASS de Core.

Se conservan como obligaciones de release las cuatro cláusulas de honestidad de
la §10.7: misma cascada para descarga y LiveTV; LowID sustituido en la UI eSE
por estado de ruta; las notas dicen «LowID deja de decidir entre peers eSE» y
**no** «HighID universal»; y los casos sin ruta terminan de forma explícita.

## 8. Resolución de la contradicción normativa sobre `WP93-0`

Existe una contradicción real entre documentos vigentes:

- `V9.3_MODEL_ORCHESTRATION.md` §13 dice que la ausencia de freeze 9.2 bloquea
  «cualquier tarjeta distinta de WP93-0», y que WP93-0 **puede localizarlo** y
  debe bloquear si demuestra que no existe;
- `V9.3_EXECUTION_RUNBOOK.md` (§«`93-0.1` solo se vuelve seleccionable cuando
  `G92-93-DEV=PASS`»), el ledger de `V9.3_EXECUTION_STATE.md` y
  `V9.2_EXECUTION_RUNBOOK.md` §30A («Solo `PASS` permite crear el worktree 9.3 y
  ejecutar `WP93-0`») dicen lo contrario.

La contradicción es material: `V9.3_MODEL_ORCHESTRATION.md` §13 lista
«contradicción normativa» como condición de parada, de modo que la regla se
dispara sobre sí misma y deja el programa sin arranque definido.

**Decisión:** se resuelve **a favor de la orquestación**, con alcance acotado.

1. `93-0.2` (este ADR) y `93-0.3` (crosswalk) son ejecutables **sin**
   `G92-93-DEV`, porque son actos documentales de autoridad que no consumen la
   frontera 9.2 ni congelan contrato de código.
2. `93-0.1` es ejecutable **sin** `G92-93-DEV` con un único propósito:
   determinar si el freeze existe. Si demuestra que no existe, DEBE terminar en
   `BLOCKED`, nunca en `PASS`.
3. `93-0.4` (baseline) puede **ensayarse** sobre el árbol actual para reducir
   riesgo, pero su PASS exige el commit de handoff. Un ensayo NO es evidencia de
   gate y se registra como ensayo.
4. Toda tarjeta a partir de WP93-1 sigue **bloqueada** hasta `G92-93-DEV=PASS`.
   Esta cláusula no se relaja por conveniencia.

Justificación: `G92-93-DEV` protege contra que la frontera 9.2 se mueva bajo el
código de 9.3. Un ADR y un crosswalk no tienen frontera que se mueva. Aplicar el
gate a documentos convierte una protección técnica en ceremonia y deja el
programa sin ninguna tarjeta arrancable, que es el estado actual.

Consecuencia documental: `V9.3_EXECUTION_RUNBOOK.md` y el ledger de
`V9.3_EXECUTION_STATE.md` DEBEN alinearse con esta cláusula al aprobarse el ADR.

## 9. Consecuencias

**Positivas.** Se desbloquea trabajo real sin `G92-93-DEV`. Birthday y DVL dejan
de poder hundir la línea comprometida. La honestidad estadística (`V93-F24`)
pasa a ser requisito y no criterio de estilo. La ausencia de relay pasa de
promesa redactada a propiedad estructural verificable (`V93-F17`).

**Negativas y aceptadas.** El espacio de requisitos crece de 16 a 25, y la
superficie de revisión crece con él. La escalera de gates es más lenta que un
gate único: Advanced A no hereda Core. Y este ADR **no** desbloquea código: la
línea de código sigue esperando a 9.2.

**Riesgo asumido.** Si 9.2 cambia schema, ownership, endpoint o generación
después de WP93-0, se dispara el riesgo 13 del plan y hay que rebasar y repetir
`H93-01`–`H93-16`. Este ADR no reduce ese riesgo; solo evita que bloquee trabajo
documental que no lo corre.

## 10. Alternativas descartadas

1. **Actualizar la §10 en vez de emitir un ADR** (opción 1 del plan §1.1).
   Descartada: reescribir la §10 para que describa cuatro tracks la convertiría
   de facto en el plan 9.3 duplicado, con dos textos que envejecen por separado.
   El ADR deja la especificación estable y concentra la deriva en un solo sitio.
2. **Dejar la especificación borrada** y que el plan 9.3 sea la única autoridad.
   Descartada: perdería `V93-F01`–`V93-F16` como identificadores trazables, y
   las secciones 1–9 y 11 (gates comunes, laboratorio, severidades, 9.4) no
   tienen sustituto en ningún otro documento.
3. **Mantener el release monolítico**. Descartada: obligaría a que Birthday y
   DVL —los dos tracks más caros e inciertos— bloqueen la salida de la ruta
   directa, que es la entrega con valor real para el usuario.

## 11. Lo que este ADR **no** decide

- No decide v2 frente a v3 del wire: eso es `93-2.1`, con auditoría propia.
- No abre `G-N0`: N0 exige además `G92-93-DEV=PASS` y baseline reproducible.
- No aprueba ninguna promoción de track.
- No modifica la frontera 9.2 ni reinterpreta `DirectCandidateSnapshotV1`.
- No autoriza edición de código bajo ninguna lectura.

## 12. Invalidación

Este ADR vuelve a `INVALIDATED` si cambia la definición de `VERIFIED`,
ownership, endpoint o generación en la frontera 9.2; si la tesis se revisa en
los puntos aquí citados; o si aparece un `S0`/`S1` que contradiga uno de los
requisitos reconciliados.

## 13. Qué falta para pasar a `ACEPTADO`

Este ADR está **PROPUESTO**. Para aceptarlo:

- [ ] ejecutar/refrendar en contexto `SOL-X` (`gpt-5.6-sol`, xhigh), según el
      routing de `93-0.2`;
- [ ] revisión independiente en contexto `SOL-MAX` (`gpt-5.6-sol`, max) **sin**
      el razonamiento del redactor, conforme al checkpoint Sol nº 1;
- [x] ~~confirmar §4.1 (destinos frente a datagramas) contra el texto literal de
      la tesis~~ — hecho: la tesis fija 17 **destinos** y explica la coincidencia
      numérica con los 17 datagramas del árbol (spread ±8 = 17 puertos). El
      resto de la reconciliación se apoya en el plan, que es la proyección
      ejecutable de la tesis; un revisor `SOL-MAX` DEBE verificar por muestreo
      que el plan no se desvía de la tesis en `V93-F17`–`V93-F25`;
- [ ] confirmar §8 con el propietario, por ser una relajación de gate;
- [ ] alinear `V9.3_EXECUTION_RUNBOOK.md` y `V9.3_EXECUTION_STATE.md` con §8;
- [ ] registrar en el histórico de routing modelo solicitado, real, esfuerzo,
      fallback y veredicto.

Mientras siga `PROPUESTO`, `93-0.2` permanece **abierta** y N0 sigue cerrado.
