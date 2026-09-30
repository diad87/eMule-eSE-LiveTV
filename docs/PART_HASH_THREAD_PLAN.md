# Plan: verificación de partes fuera del hilo UI (track H)

**Objetivo:** eliminar los congelamientos de la interfaz ("se queda pillado y tarda en
responder") cuando hay varias descargas rápidas simultáneas. La causa dominante es que
la verificación hash de cada parte completada (9,28 MB: lectura de disco + MD4 + AICH)
se ejecuta en el hilo principal, que también mueve la UI **y toda la red** (CAsyncSocket).

**Fecha:** 2026-06-11 · **Estado:** H0 instrumentado + H1 implementado, ambos compilan
en Release x64 (2026-06-11). Pendiente: medición H0 (manual) y validación H3.
**Exes:** `srchybrid\x64\Release\emule_H0_baseline.exe` = pre-H1 instrumentado (para el
baseline); `emule.exe` = H1 (también instrumentado; en su log `hash` debe salir ~0).
**Track independiente de v8.1.x y del track M** — no toca wire formats, ni formatos de
fichero, ni el plano Live. Es estabilización pura (prioridad según filosofía del
proyecto: primero que lo existente funcione como un reloj). Prefijo de sprints **H**.

**Compatibilidad:** ninguna estructura serializada cambia (ni red ni `.part.met`).
Compatible con 0.70b upstream y con versiones previas del fork por construcción.

---

## 0. Síntoma y diagnóstico (auditado 2026-06-11)

Reporte de usuario de 0.70b community (no del fork, pero compartimos base): con varias
descargas a la vez, mejor no tocar nada porque la app deja de responder a ratos.

Cadena causal confirmada en código:

1. `CPartFile::Process()` corre en el timer del hilo principal y dispara
   `FlushBuffer()` por tamaño de buffer o por tiempo — PartFile.cpp:2191-2192.
   También se fuerza flush inline desde `WriteToBuffer` si el buffer se desborda
   (descargas rápidas) — PartFile.cpp:4032-4037.
2. `FlushBuffer()` encola las escrituras al hilo de I/O solapada (eso ya está bien),
   pero después, **en el mismo hilo principal**, para cada parte que ha cambiado y ha
   quedado completa llama a `HashSinglePart()` — PartFile.cpp:4156-4167.
3. `HashSinglePart()` (PartFile.cpp:3123-3200) lee la parte entera del disco
   (`m_hpartfile.Seek` + `CreateHash`, líneas 3153-3154) y calcula MD4 + AICH.
   Eso es ~9,3 MB de lectura + dos hashes por parte, bloqueando el message pump.
4. Con N descargas rápidas, las partes se completan en ráfagas → el hilo principal
   encadena varios de estos bloqueos → UI congelada **y** red parada (los sockets
   también viven en el message pump, por eso "tarda en responder" todo).

Bloqueos secundarios del mismo hilo (menores, se tratan en H2 o se descartan):

| Qué | Dónde | Coste | Frecuencia |
|---|---|---|---|
| Verificación de recuperación AICH (lee la parte + hashea, 2 veces) | PartFile.cpp:5297-5374 (`AICHRecoveryDataAvailable`, incl. `HashSinglePart` en 5365) | alto | raro (solo corrupción) |
| Recheck ICH de parte corrupta | PartFile.cpp:4197-4199 | alto | raro |
| `SavePartFile()` periódico (~29 s por fichero) | PartFile.cpp:4233-4236 | bajo (met pequeño) | frecuente |
| `SetLength()` para asignación | PartFile.cpp:4101 | bajo (NTFS no rellena al extender) | por crecimiento |

## 1. Lo que ya está resuelto en la base 0.70b (no tocar)

| Pieza | Dónde | Estado |
|---|---|---|
| Escrituras a disco en hilo propio (IOCP, I/O solapada) | PartFileWriteThread.cpp | ✅ |
| Compleción de fichero (copia Temp→Incoming) en hilo | PartFile.cpp:2703 (`CompleteThreadProc`) | ✅ |
| Hashing inicial / rehash completo en hilo | `CAddFileThread` (PartFile.cpp:2689) | ✅ |
| Asignación de espacio vía write thread (`uAllocate`) | PartFile.cpp:4064-4127 | ✅ |
| Patrón de marshaling hilo→main probado | `TM_*` + `PostMessage` (EmuleDlg.h:361-365, EmuleDlg.cpp:220-225) | ✅ |

El diseño nuevo **clona estos patrones existentes**, no inventa infraestructura.

## 2. Diseño: `CPartHashThread`

### 2.1 Componentes nuevos

- `srchybrid/PartHashThread.h/.cpp` — hilo trabajador persistente, prioridad
  `THREAD_PRIORITY_BELOW_NORMAL`, cola FIFO protegida por `CCriticalSection` +
  evento de despertar. Plantilla de estructura/ciclo de vida: `CPartFileWriteThread`.
- Mensaje nuevo `TM_PARTHASHED` en el enum de EmuleDlg.h:361 + handler
  `CemuleDlg::OnPartHashed` registrado en el message map (EmuleDlg.cpp:220).
- `CPartFile::ProcessPartHashResult(...)` — refactor: la lógica de consecuencias del
  verdict que hoy vive inline en FlushBuffer (PartFile.cpp:4156-4230) extraída a un
  método llamable tanto desde el camino síncrono (que pervive para casos raros) como
  desde el handler del mensaje.

### 2.2 Flujo

**Encolado (hilo principal, dentro de FlushBuffer):**
para cada parte con `m_aChangedPart` y sin gaps (`IsCompleteBD`), en vez de llamar a
`HashSinglePart` inline:
1. Snapshot del trabajo: `{ CPartFile* (token opaco), nº de parte, generación,
   offset, longitud, ruta del .part, params del árbol AICH (dataSize/baseSize/
   isLeftBranch, copiados como hace hoy 3140-3148) }`. **No se copia ningún hash
   esperado**: la comparación se hace al volver, en el hilo principal, contra el
   estado actual (robusto frente a hashsets que llegan tarde).
2. Marcar la parte como "hash pendiente" e incrementar `m_nHashingParts`. La parte
   **permanece en `m_aChangedPart` hasta verdict OK** (lo limpia el handler, no el
   encolado); el set de pendientes evita re-encolarla en flushes siguientes. Esto es
   lo que permite que el camino síncrono de shutdown vea los leftovers (§2.6.3).
   ✅ Verificado en H1 (2026-06-11): los demás consumidores son inocuos —
   `AssertValid` (debug), `SetSize(0)` en `PerformFileComplete` (corre con el map
   vacío gracias a los gates), `SetSize(N)` al fijar tamaño, y el productor
   `DeleteWrittenItem`, que además marca las partes **tras aterrizar la escritura
   física** (no al bufferizar): nunca se encola un hash con writes en vuelo.
3. Encolar y despertar al worker.

**Worker (ningún acceso a estado de CPartFile):**
1. Abre **su propio handle de solo lectura** sobre el .part
   (`CFile::shareDenyNone | osSequentialScan`). Viable porque `m_hpartfile` ya se
   abre con `shareDenyNone` (PartFile.cpp:400, 1060) y el write thread ya demuestra
   que múltiples handles conviven (PartFileWriteThread.cpp:205).
2. `CreateHash(&file, length, md4result, pAICHTree)` — la misma rutina que ya usa
   `CAddFileThread` desde un hilo, una sola pasada para MD4 + AICH.
3. `PostMessage(TM_PARTHASHED, ...)` con `{ CPartFile*, parte, generación,
   md4[16], hash AICH, flags de qué se calculó }`. Si la lectura falla, postea
   verdict de error (el main thread decide; no toca nada desde el worker).

**Verdict (hilo principal, `OnPartHashed`):**
1. Validar `theApp.downloadqueue->IsPartFile(p) && !theApp.IsClosing()` — el mismo
   guardarraíl que `OnImportPart` (EmuleDlg.cpp:1941-1952). Fichero cancelado/borrado
   → verdict descartado sin tocar memoria liberada.
2. Validar generación y que la parte sigue sin gaps; si está obsoleto, descartar
   (y re-encolar si la parte volvió a quedar completa).
3. Comparar los hashes calculados contra `m_FileIdentifier` **actual** (la lógica de
   decisión de 3156-3199 se mueve aquí).
4. `ProcessPartHashResult(...)`: éxito → `VerifiedData` del blackbox, limpiar
   `corrupted_list`, `AddToSharedFiles()`; fallo → `AddGap`, `corrupted_list`,
   `RequestAICHRecovery`, estadísticas de corrupción — exactamente el bloque
   4164-4230 de hoy.
5. Decrementar `m_nHashingParts`; comprobar compleción (ver 2.4).

### 2.3 Invariante de threading (la clave de que esto sea seguro)

**Todo el estado de `CPartFile` se sigue tocando solo desde el hilo principal.**
El encolado ocurre en FlushBuffer (main), el verdict en OnPartHashed (main). El worker
solo lee disco con su propio handle y postea un POD. Consecuencias:

- `m_nHashingParts`, el set de partes pendientes y las generaciones **no necesitan
  locks ni atomics**.
- No hay carrera con el write thread: escribe regiones distintas por otro handle
  (mismo modelo que hoy, donde el hash lee mientras otras partes se escriben).
- Cumple la regla de la casa post-auditoría threading: nada de tocar estado de
  main-thread desde workers.

### 2.4 Gating de la compleción del fichero

Hoy: `if (m_gaplist.IsEmpty()) { if (m_iWrites <= 0 && m_BufferedData_list.IsEmpty()
&& GetStatus() != PS_COMPLETING) CompleteFile(false); else reintentar en breve; }`
(PartFile.cpp:4240-4244). Ya existe el precedente de esperar a trabajo asíncrono
(`m_iWrites`); se añade `&& m_nHashingParts == 0` a la condición y al ASSERT de
precondición de `CompleteFile` (PartFile.cpp:2675).

**Auditar todos los call-sites de `CompleteFile(false)`** y aplicar el mismo gate:
PartFile.cpp:1110, 3384, 4242, 5383. (El de `CompleteFile(true)` en 1567 es el camino
post-rehash de `CAddFileThread`, no aplica.) Además, el handler del verdict dispara la
comprobación de compleción cuando `m_nHashingParts` llega a 0 — el último verdict OK es
quien completa el fichero, igual que hoy lo hace el último hash inline.

### 2.5 Invalidación por generación

Contador de generación por parte pendiente (estructura pequeña en CPartFile, p. ej.
lista de `{parte, gen}`). Cualquier `AddGap` que toque una parte con hash pendiente
incrementa su generación → el verdict viejo se descarta al llegar. Como AddGap solo
ocurre en el hilo principal, no hay carreras. Caso práctico que cubre: dos fuentes,
una corrupta — el verdict de fallo re-abre gaps mientras otro verdict viajaba.

### 2.6 Ciclo de vida, cancelación y shutdown

- Creación/destrucción espejo del write thread: `new` en Emule.cpp:651 (al lado de
  `m_pPartFileWriteThread`), `EndThread()` en EmuleDlg.cpp:2164, `delete` en :2236.
  Orden: terminar el hash thread **antes** de destruir `downloadqueue` (:2224) — con
  el esquema de abajo ese orden es además lo que hace trivial el fallback síncrono.
- `PartHashThread::CancelFile(CPartFile*)`: purga la cola (no el trabajo en vuelo;
  su verdict morirá en la validación `IsPartFile`). Llamar desde la cancelación/
  borrado del fichero y desde `CompleteFile` (junto al
  `CPartFileWriteThread::RemFile` de :2676). En cancelación/borrado **no se espera
  nada**: el fichero muere y verificar sería trabajo tirado.
- **Shutdown limpio — semántica copiada de aMule 3.0.0** (`PartFileHashThread.cpp` +
  `~CPartFile`; decidido 2026-06-11): un cierre limpio **nunca** persiste en el
  `.part.met` una parte completa sin verificar. Mecanismo, adaptado a nuestro
  invariante §2.3:
  1. `EndThread()` deja terminar el trabajo en vuelo (≤1 parte, ~decenas de ms),
     postea su verdict (que ya nadie procesará — inofensivo, ver paso 3) y hace
     join. La cola pendiente se descarta.
  2. Con el hilo parado, `FlushBuffer` cae automáticamente al camino síncrono
     (`HashSinglePart` inline, el branch que H1.7 conserva).
  3. Cada `~CPartFile` (vía la destrucción de `downloadqueue`, :2224) ejecuta hoy
     `FlushBuffer(false, true)` (:295) antes de su `SavePartFile` final; como las
     partes permanecen en `m_aChangedPart` hasta verdict OK (§2.2), ese mismo flush
     síncrono re-verifica solo los leftovers sin código nuevo en el destructor.
  Nota de adaptación: aMule espera en `~CPartFile` un contador atómico
  (`m_pendingHashes`) porque su worker comparte el handle del fichero; nuestro
  worker no toca `CPartFile` ni su handle (snapshot + handle propio), así que basta
  parar el hilo antes de los destructores — misma semántica, cero atomics, y el
  invariante §2.3 queda intacto. Coste idéntico al de aMule: cierre lento solo si
  se cierra en plena ráfaga de partes recién completadas — cita de su código:
  *"Slow shutdown is acceptable for the rare cancel-mid-download case; the common
  paths keep m_aChangedPart drained throughout the session, so the loop usually
  has nothing to do."*

## 3. Fases

### H0 — Reproducir y medir (½ día) — EN CURSO 2026-06-11

Pasos en orden:

1. ✅ **Instrumentación temporal** (hecho 2026-06-11): 6 ediciones en `FlushBuffer`
   (PartFile.cpp), todas etiquetadas `// eSE H0` — greppables para retirarlas en H1.
   Cronometra: total del flush, hash acumulado (los dos call-sites de
   `HashSinglePart`), `SetLength` (alloc) y `SavePartFile` (met). Si el total ≥50 ms
   y Verbose está activo, emite al debug log:
   `eSE H0: FlushBuffer <total> ms (hash <ms> / <n> parts, alloc <ms>, met <ms>) - <fichero>`
2. ✅ **Compilar Release x64** (hecho 2026-06-11): `srchybrid\x64\Release\emule.exe`,
   0 errores (solo warnings preexistentes).
3. ⬜ **Medición** (manual, PC real — usar `emule_H0_baseline.exe`, porque
   `emule.exe` ya lleva H1):
   - Opciones → Extendido → activar **Verbose** (idealmente también el volcado del
     debug log a fichero para no perder líneas).
   - 3-5 descargas simultáneas con muchas fuentes, corriendo a velocidad alta
     ≥10-15 min (cuanto más rápido, más ráfagas de partes completadas).
   - Durante las ráfagas: interactuar con la lista de transferencias (scroll,
     expandir fuentes, pausar/reanudar) y anotar cuándo se nota el "pillado".
   - Recoger todas las líneas `eSE H0:` del log.
4. ⬜ **Registrar baseline** (en esta sección): nº de eventos ≥100 ms por 10 min,
   máximo observado, y qué fracción del total es `hash`. Con los valores de
   `alloc`/`met` se decide el alcance de H2 (si <20 ms sostenidos → descartar).

**Salida:** confirmación numérica de que los stalls ≥100 ms son el hash (baseline
para comparar en H3). Sin ceremonia: dos cifras y un log bastan.

#### Baseline (pendiente de medición — REQUIERE MÁQUINA REAL)

La tabla siguiente sólo se rellena con runtime real: hay que correr
`emule_H0_baseline.exe` (camino síncrono, hash en el hilo UI) con Verbose activo,
generar carga ≥10 min y recoger las líneas `eSE H0:`. **No es automatizable** desde
una sesión sin descargas reales (no hay partes que completar → `FlushBuffer` nunca
hashea → el log no emite). Protocolo exacto: §H0 paso 3 de arriba.

| Métrica | Valor |
|---|---|
| Eventos ≥100 ms / 10 min | — (medir en PC) |
| Stall máximo (ms) | — (medir en PC) |
| % atribuible a hash | — (medir en PC) |
| alloc / met típicos (ms) | — (medir en PC) |

Estimación teórica (NO sustituye la medición; sólo encuadra la magnitud): una parte
de 9,28 MB = lectura secuencial de disco (~5-15 ms SSD / ~30-90 ms HDD si no está en
caché) + MD4 + AICH(SHA1) en una pasada (~20-40 ms). Coste por parte ≈ **30-130 ms**;
con N partes completándose en la misma ráfaga de `FlushBuffer` se acumulan y superan
los 100 ms con holgura en HDD. En H1 ese coste sale del hilo UI: en el log de
`emule.exe` la columna `hash` debe quedar ~0 ms y `<n> parts` ~0 (camino async),
salvo el branch ICH y el shutdown, que siguen síncronos por diseño.

### H1 — Núcleo: camino caliente asíncrono (2-3 días) — IMPLEMENTADO 2026-06-11

Los 7 pasos de abajo están implementados y **compilan en Release x64 sin errores**
(2026-06-11; dos fixes sobre el primer intento: include de `OtherFunctions.h` para
`MDX_DIGEST_SIZE` y `friend class CPartHashThread` en `CKnownFile` porque el
`CreateHash` estático es protected). Pendiente: H3.
Notas de implementación respecto al diseño:
- El refactor (paso 2) extrajo el branch normal a `ProcessCompletePartVerdict`; el
  branch ICH quedó inline en FlushBuffer (síncrono en H1 igualmente, diff menor).
- `FlushBuffer` ganó el parámetro `bSyncHash` (default `false`); el destructor llama
  `FlushBuffer(false, true, true)` para forzar el camino síncrono también en
  cancelaciones mid-session (paridad de coste con el comportamiento actual), no solo
  cuando el hilo ya está parado.
- Verdict stale ⇒ se saca del map de pendientes y `m_aChangedPart` queda set; el
  flush periódico (corre por timer aunque no haya datos nuevos) lo re-encola.
- Caso sin hashset (MD4 ni AICH): se cortocircuita en el encolado, sin I/O, con la
  misma semántica que `HashSinglePart` (asumir OK + flags de "hashset needed").

1. `PartHashThread.h/.cpp` + alta en `emule.vcxproj` (junto a PartFileWriteThread).
2. Refactor `ProcessPartHashResult` (extraer 4156-4230 sin cambiar comportamiento;
   commit propio, verificable por diff casi-mecánico).
3. `TM_PARTHASHED` + `OnPartHashed` con validaciones (IsPartFile, IsClosing,
   generación, IsCompleteBD).
4. FlushBuffer: encolado en vez de hash inline **solo para el branch normal**
   (4164-4196). El branch ICH de parte corrupta (4197-4229) queda síncrono en H1
   (raro por definición: solo partes ya marcadas corruptas).
5. Contador + gating de compleción (2.4) + generaciones (2.5).
6. `CancelFile` + integración de ciclo de vida (2.6).
7. El camino síncrono (`HashSinglePart` tal cual) **se conserva** para: branch ICH,
   `AICHRecoveryDataAvailable`, y shutdown (re-verificación de leftovers vía el
   `FlushBuffer` de los destructores con el hilo ya parado, §2.6.3) — nada de
   borrarlo.

**Salida:** Release x64 compila; descarga multi-fichero completa con hashes finales
correctos; cancelar/pausar/borrar con hashes en vuelo no crashea.

### H2 — Caminos secundarios (1 día, opcional según medición H0)

- Mover el branch ICH (4197) y la verificación de `AICHRecoveryDataAvailable`
  (5297-5374) al worker con un flag en el snapshot. Solo si H0/uso real muestra que
  duelen; son raros y la maquinaria de H1 ya lo deja casi hecho.
- Medir `SavePartFile` y `SetLength` en el log de H0; si no superan ~20 ms, se
  descartan formalmente (apuesta: se descartan).

### H3 — Validación (1-2 días)

Matriz funcional (todo en Release x64 — Debug x64 está roto):

| Prueba | Qué valida |
|---|---|
| 2 PCs, 3+ descargas simultáneas rápidas, completar todas | camino caliente, compleción, fichero final íntegro |
| Corromper bytes de un .part en disco (pausa → hex edit → reanudar) | detección de corrupción, AddGap, ICH, recuperación AICH, blackbox |
| Cancelar/borrar fichero justo cuando completan partes (stress repetido) | CancelFile + validación IsPartFile, sin UAF |
| Pausar/reanudar con hashes en vuelo | generaciones, re-encolado |
| Cerrar la app con cola de hash llena | shutdown ordenado: join del trabajo en vuelo, leftovers re-verificados síncronos por los destructores, `.met` final sin partes completas-sin-verificar (§2.6) |
| Fichero de 1 sola parte y fichero con última parte corta | ramas MD4 contra hash de fichero (3167) y longitud parcial |
| Fichero en NTFS comprimido/sparse | ramas `IsNormalFile()` |
| Import parts (TM_IMPORTPART) | convivencia con el otro productor de buffers |
| Hashset MD4/AICH llegando después de completar una parte | comparación en verdict-time (2.2 paso 3) |
| A/B contra baseline H0 con la misma carga | el stall ≥100 ms desaparece del hilo UI |

**Salida:** baseline H0 vs H1 documentado en este fichero + commit final.

#### Resultados de validación (2026-06-13)

**Alcance honesto:** la matriz H3 es mayoritariamente **runtime real** (descargas de la
red eMule, 2 PCs, edición hex de `.part` en disco, cierre en plena ráfaga). Eso **no se
puede automatizar** desde una sesión de código. Lo que sí se hizo aquí:

1. **Build Release x64 — PASA.** Recompilación forzada de `PartHashThread.cpp`,
   `PartFile.cpp` y `EmuleDlg.cpp` + relink: **0 errores, 0 warnings nuevos** (los 18
   warnings son preexistentes: `eMuleAI/Address.h`, `atlenc.h`, `EmuleDlg.cpp:155/1860`,
   `PartFile.cpp:2929/4702` — todos fuera de las zonas H1). Debug x64 no se tocó (roto).
   Exes presentes: `emule_H0_baseline.exe` (pre-H1, 2026-06-11) y `emule.exe` (H1).
2. **Auditoría estática adversarial** (validación *por inspección*) de cada prueba.
   Verdicts abajo. No encontró bugs de corrección; el invariante de threading §2.3 se
   respeta (el worker nunca toca estado de `CPartFile` ni su handle; snapshot + handle
   propio; verdict procesado en el hilo principal).

| # | Prueba | Verdict estático | Falta runtime |
|---|---|---|---|
| 1 | Multi-descarga rápida, completar todas | Encolado/verdict/compleción correctos; la compleción gatea con `m_mapPendingHashParts.IsEmpty()` en **todos** los call-sites de `CompleteFile(false)` (3434, 4300, 4565, 5606) + ASSERT en `CompleteFile` (2700). El último verdict completa el fichero (4564). | **SÍ** — integridad del fichero final sólo se prueba descargando |
| 2 | Corromper bytes de un `.part`, reanudar | `ProcessCompletePartVerdict` en fallo: `AddGap`+`corrupted_list`+`RequestAICHRecovery`+stats, idéntico al bloque inline original (4454-4469). Branch ICH y `AICHRecoveryDataAvailable` siguen **síncronos** (H1 a propósito). | **SÍ** — corrupción inducida real |
| 3 | Cancelar/borrar al completar partes (stress) | `~CPartFile`/`DeleteFile` → `CancelFile` purga cola (no in-flight); el verdict en vuelo muere en `OnPartHashed` por `IsPartFile(p) && !IsClosing()` (EmuleDlg 1965). Sin UAF: el worker no desreferencia `pFile`. | **SÍ** — la carrera real sólo aparece en runtime |
| 4 | Pausar/reanudar con hashes en vuelo | Generaciones: `AddGap` sobre parte pendiente hace `++m_uPartHashGen` (1599-1604); verdict stale (`uGen != verdict.uGen`) se descarta y `m_aChangedPart` queda set → el flush periódico re-encola (liveness vía `Process`→`FlushBuffer` por `GetFileBufferTimeLimit`). | **SÍ** — secuencia temporal real |
| 5 | Cerrar con cola de hash llena | `EndThread()` en EmuleDlg **antes** del dtor de `downloadqueue` (2214 vs 2274); el dtor cae al camino síncrono (`FlushBuffer(false,true,true)`, 305) y re-verifica leftovers antes del `SavePartFile` final (309). `.met` sin partes completas-sin-verificar en cierre limpio. | **SÍ** — sólo verificable cerrando en ráfaga |
| 6 | 1 sola parte / última parte corta | Paridad exacta con `HashSinglePart`: rama `GetPartCount()>1 \|\| m_nFileSize==PARTSIZE` (MD4) y `GetPartCount()>1` (AICH) replicadas en `ProcessPartHashVerdict` (4519/4536); longitud `min(PARTSIZE, m_nFileSize-uStart)` coincide con `min(GetLength()-uOff,PARTSIZE)` cuando el fichero está dimensionado. | parcial — runtime confirmaría |
| 7 | NTFS comprimido/sparse | El worker abre su handle con `shareDenyNone` (igual que `m_hpartfile`); `IsNormalFile()` sólo afecta a alloc, no al hash. Sin cambio de comportamiento. | **SÍ** |
| 8 | Import parts (`TM_IMPORTPART`) | Convive: `OnImportPart` escribe al buffer; el productor de hashes (`DeleteWrittenItem` marca tras aterrizar la escritura) es el mismo. Sin solape de handles en escritura/lectura distinta. | **SÍ** |
| 9 | Hashset MD4/AICH tardío | **Clave del diseño:** no se copia hash esperado en el snapshot; la comparación corre en verdict-time contra `m_FileIdentifier` actual (4517-4542). Sin hashset → misma semántica que `HashSinglePart` (asumir OK + flags needed), en encolado (4414) y en verdict (4545). | parcial |
| 10 | A/B vs baseline H0 | Instrumentación viva en ambos exes; ver §H0. En H1 la columna `hash` del log debe ser ~0. | **SÍ** — medición |

**Conclusión de la auditoría:** la implementación es correcta por inspección y compila;
la lógica de decisión async es un espejo fiel del camino síncrono. **Pendiente
ineludible:** ejecutar la matriz en máquina real (runbook abajo). Hasta entonces el
estado honesto es *"H1 verificado estáticamente + compila; sin validar en runtime"*.

#### Runbook de runtime (para ejecutar en PC, no automatizable)

Preparación: Opciones→Extendido→**Verbose** ON + volcado de debug log a fichero.

Análisis de los logs: `tools\parthash_h0_ab.ps1` parsea las líneas `eSE H0:` y saca las
métricas de la tabla Baseline (eventos ≥100 ms / 10 min, stall máx., % atribuible a
hash, alloc/met típicos) y, en modo A/B, compara baseline vs H1 verificando que en H1
el `hash` del hilo UI ~= 0:
`./tools/parthash_h0_ab.ps1 -BaselineLog <h0.log> [-H1Log <h1.log>] [-DurationMinutes N]`

- **Baseline H0:** arrancar `emule_H0_baseline.exe`. 3-5 descargas con muchas fuentes a
  velocidad alta, ≥10-15 min. Interactuar con la lista (scroll/expandir/pausar) durante
  las ráfagas. Pasar el log al script → rellenar la tabla Baseline de §H0.
- **A/B H1:** repetir con `emule.exe`; pasar ambos logs al script con `-H1Log`. Confirmar
  que `hash` sale ~0 ms y la UI no se congela en las ráfagas; comparar nº de eventos
  ≥100 ms (baseline → H1).
- **Pruebas 1-9:** descargar varios ficheros; para corrupción (2) pausar→editar hex un
  `.part`→reanudar y confirmar detección+recuperación; para cancelación (3) borrar
  ficheros justo al completar partes (repetir); para shutdown (5) cerrar la app con
  descargas rápidas activas y verificar que al reabrir el `.met` no marca partes
  completas-sin-verificar ni rehashea de más; probar fichero de 1 parte y de última
  parte corta (6).

## 4. Riesgos y decisiones

- **R1 — Ventana "parte completa sin verificar" se alarga** (de ~0 a 1-3 s): los
  peers ven disponibilidad por gaplist, así que en esa ventana podría servirse un
  bloque aún no verificado. **Ya pasa hoy** (los gaps se rellenan en
  `WriteToBuffer`/`FillGap` PartFile.cpp:4024, el hash llega en el flush posterior);
  solo se ensancha. Mitigación: worker dedicado mantiene la ventana corta; un fallo
  de verdict re-abre gaps exactamente como hoy. Verificado en H1 (2026-06-11):
  `WritePartStatus` anuncia por `IsCompleteBD` (PartFile.cpp:2112) — gaplist y buffers, nunca el verdict de hash. Aceptado.
- **R2 — Crash con verdict pendiente** → el `.part.met` (guardado cada ~29 s,
  :4233) podría persistir la parte como completa sin verificar. El **cierre limpio
  ya no tiene esta ventana** (§2.6, esquema aMule); queda solo el crash duro —
  ventana equivalente a la que ya existe hoy entre fill-gap y flush. Mitigación
  barata incluida en H1 para ese caso: si hay verdicts pendientes de un fichero,
  posponer su `SavePartFile` al handler del verdict (los verdicts resuelven en
  segundos; no se pospone indefinidamente).
- **R3 — `PartFile.utf8.cpp` no se compila** (emule.vcxproj:414 solo incluye
  `PartFile.cpp`) y **ya estaba divergido** (p. ej. 5277 vs 5303). Decisión: tocar
  solo `PartFile.cpp`; el espejo es un artefacto pre-Claude (era Antigravity) — su
  limpieza es tarea aparte, fuera de este track.
- **R4 — Disco lento/HDD:** un solo worker serializa los hashes (bueno: no
  thrashea), pero la cola puede crecer en ráfagas. Irrelevante para la UI (es el
  punto del plan); solo retrasa compleción unos segundos en el peor caso.
- **R5 — Complejidad vs. hobby:** es la cirugía más delicada del fork hasta la
  fecha en código heredado. Por eso: fases pequeñas, refactor mecánico separado
  (H1.2), camino síncrono conservado, y validación con corrupción real inducida.

## 5. Qué NO se toca (a propósito)

- La red en el hilo principal (CAsyncSocket): rehacerla sería otra liga de riesgo.
  Con el hash fuera, el pump queda libre y el síntoma reportado desaparece.
- Repintado de la lista de descargas / `UpdateDisplayedInfo` (ya throttled).
- Formatos de `.part.met`, protocolo, comportamiento observable por otros clientes.
- `CPartFileWriteThread`, `CAddFileThread`, compleción threaded: funcionan, se imitan.

## 6. Estimación

~1 semana a ritmo hobby: H0 ½d · H1 2-3d · H2 0-1d · H3 1-2d. Cada fase es un commit
(o serie corta) compilable y probable por separado. Sin dependencias con v8.1.x ni
track M; puede intercalarse.
