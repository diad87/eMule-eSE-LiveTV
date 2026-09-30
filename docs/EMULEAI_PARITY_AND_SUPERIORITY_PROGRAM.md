# eSE — Programa de paridad y superioridad frente a eMule AI

Fecha del baseline histórico: 25 de julio de 2026  
Fecha de registro del baseline público actual: 15 de agosto de 2026

Referencias:

- baseline histórico congelado: eMule AI `eMuleAI_v1.5.2`, commit
  `de8e27e2029044d533f7090f173c95856fe4635a`;
- baseline público actual candidato: eMule AI `eMuleAI_v1.6`, commit
  `a2f05dc8db772a11ca874adf0a16baaf30560519`;
- eSE `9.1.0-beta.1` más el commit documental `9539a8356db6260b8d043dd2952643e12d79af87`.

El encaje temporal y la asignación a releases se definen en
`EMULEAI_INTEGRATED_RELEASE_ROADMAP.md`. Este inventario define qué hay que
superar; el roadmap decide cuándo puede intentarse sin romper 9.2–9.4.
Los 19 cambios observados en 1.6 y su deduplicación contra esta matriz se
definen en `EMULEAI_V1.6_DELTA_BASELINE.md`.

Este programa no declara superioridad por número de opciones o líneas de
código. La evidencia histórica contra 1.5.2 nunca se reescribe. Cada nuevo caso
solo cambia a `ESE-SUPERA` cuando existe una comparación reproducible contra
1.5.2 y contra el baseline vigente promovido en el freeze de 9.2, pasan las
regresiones de eMule 0.70b y el resultado no depende de activar funciones
experimentales sin consentimiento.

## 1. Estados y regla de cierre

| Estado | Significado |
|---|---|
| `BRECHA` | eMule AI ofrece una capacidad útil que eSE no tiene |
| `PARCIAL` | existe una parte, pero AI conserva una ventaja práctica |
| `PARIDAD` | capacidad equivalente; aún no se afirma superioridad |
| `ESE-BETA` | eSE tiene mayor alcance, pero falta evidencia física o de promoción |
| `ESE-SUPERA` | eSE supera el baseline con evidencia reproducible |
| `NO-ADOPTAR` | el comportamiento contradice identidad, seguridad o compatibilidad; se sustituye por una solución mejor |

Para cerrar cualquier `AI-*`:

1. contrato e invariantes escritos;
2. implementación capability-gated cuando afecte al wire;
3. prueba unitaria o determinista;
4. prueba de integración;
5. comparación A/B contra AI 1.5.2 y, para nuevos veredictos tras el freeze de
   9.2, contra el baseline vigente promovido, con el mismo equipo, perfil,
   archivos y red;
6. memoria, CPU, latencia y throughput publicados;
7. upgrade, rollback y control negativo 0.70b;
8. revisión de seguridad y licencia.

## 2. Matriz completa de funciones

| ID | Función de eMule AI | Estado eSE | Objetivo para superar |
|---|---|---|---|
| `AI-F01` | QUIC NAT-T | `BRECHA` | QUIC v1 capability-gated, TLS 1.3, 0-RTT desactivado para operaciones mutables, uTP/TCP fallback y benchmark LowID/CGNAT |
| `AI-F02` | Docker Linux/macOS | `BRECHA` | imagen reproducible y sin privilegios, perfiles persistentes, healthcheck y SBOM; evaluar Wine frente a cliente nativo |
| `AI-F03` | ajustes avanzados de subida | `BRECHA` | control adaptativo por RTT/backlog/disco, fairness demostrada y límites seguros automáticos |
| `AI-F04` | bind de red e IP Guard | `PARCIAL` | bind dual-stack por interfaz, pérdida de interfaz fail-closed, allowlist local/pública y recuperación sin fuga |
| `AI-F05` | overlays de arranque/salida/bulk | `BRECHA` | progreso cancelable, accesible y basado en tareas reales, sin bloquear GUI ni cierre |
| `AI-F06` | caché de compartidos | `BRECHA` | caché versionada con checksum, escritura atómica, invalidación por identidad fuerte y benchmark de 10k/100k/500k archivos |
| `AI-F07` | límites de búsqueda y Last Request | `BRECHA` | presupuestos adaptativos por rareza/coste, métricas y columna sin hot-path de GUI |
| `AI-F08` | firewall nativo y puertos aleatorios | `PARCIAL` | reglas con ownership por instancia, limpieza segura, rango criptográfico y rollback verificable |
| `AI-F09` | modos de notificación | `BRECHA` | toast/tray/in-app accesibles, rate-limited y sin exponer nombres sensibles por defecto |
| `AI-F10` | nombre mayoritario | `BRECHA` | consenso resistente a Sybil, confianza por fuente y preview/undo antes de renombrar |
| `AI-F11` | panel de protección | `BRECHA` | motor explicable, evidencia por sanción, caducidad, allowlist y simulador de falsos positivos |
| `AI-F12` | modo oscuro | `BRECHA` | tema completo high-contrast, DPI, teclado y contraste WCAG medido |
| `AI-F13` | listas rápidas | `BRECHA` | modelo virtual común, actualizaciones incrementales y p95 medido con 500k filas |
| `AI-F14` | NAT traversal y source exchange extendido | `PARCIAL` | DCO único Direct→Callback/Punch2→Punch3→QUIC/uTP→terminal tipado, sin relay de payload ni doble autoridad y con matriz física |
| `AI-F15` | IPv6 end-to-end | `ESE-BETA` | cerrar los 25 casos pendientes de 9.1 y demostrar IPv6-only físico, fallback y compatibilidad |
| `AI-F16` | spam/blacklist | `PARCIAL` | clasificación explicable local, import/export firmado y evaluación con corpus etiquetado |
| `AI-F17` | historial de clientes | `BRECHA` | historial mínimo, cifrable, con retención y borrado; sin crear identificador de seguimiento |
| `AI-F18` | reload de compartidos en thread | `BRECHA` | snapshot/commit cancelable, sin punteros MFC cruzando threads y benchmark de latencia GUI |
| `AI-F19` | watcher de compartidos | `BRECHA` | threadpool I/O sin límite de 64 handles, subárbol opcional, overflow recovery, renames correlacionados y política de entrada única |
| `AI-F20` | compartir subdirectorios | `BRECHA` | reglas include/exclude, detección de ciclos/junctions y preview del alcance antes de activar |
| `AI-F21` | validador de descargas | `BRECHA` | reglas versionadas y explicables sobre similitud/hash/metadata, corpus histórico y compartido, modo warn por defecto y cero borrado automático |
| `AI-F22` | 116 idiomas embebidos | `BRECHA` | cobertura igual o mayor con QA automática de placeholders, clipping y fallback |
| `AI-F23` | connection checker | `PARCIAL` | diagnóstico eD2K/Kad2/Kad6/TCP/UDP/NAT/QUIC con causas y evidencia exportable saneada |
| `AI-F24` | emulación de clientes/comunidades | `NO-ADOPTAR` | perfiles de interoperabilidad honestos; nunca falsificar identidad para obtener prioridad |
| `AI-F25` | botones de estado/reload/backup/preview | `PARCIAL` | command palette configurable, backup transaccional y undo |
| `AI-F26` | carga automática PeerGuardian | `BRECHA` | importador streaming de `.p2p`/CIDR con límites, procedencia, firma opcional y preview |
| `AI-F27` | límite de búsqueda Kad | `BRECHA` | presupuesto por coste/rareza y stop anticipado observable |
| `AI-F28` | filtros Search/Transfer | `PARCIAL` | consultas combinables persistentes, accesibles y ejecutadas sobre índice |
| `AI-F29` | columnas Friend/hash/ID/client | `PARCIAL` | selector de columnas completo sin exponer hashes por defecto |
| `AI-F30` | columna IP:puerto | `PARCIAL` | endpoint dual-stack, copia segura y modo privacidad |
| `AI-F31` | ver créditos propios remotos | `PARCIAL` | diagnóstico de crédito con procedencia, timestamp y estado no verificable explícito |
| `AI-F32` | cancelar desde menús | `PARIDAD` | conservar y añadir undo/backup de enlace |
| `AI-F33` | estado de shared-files remoto | `BRECHA` | máquina de estado explícita con timeout, cancelación y rate limit |
| `AI-F34` | nota por cliente | `BRECHA` | notas locales cifrables, exportables y nunca transmitidas |
| `AI-F35` | copiar listas con Ctrl+C/X | `PARCIAL` | TSV/CSV/JSON seleccionable, redacción de datos sensibles y accesibilidad |
| `AI-F36` | limpiar resultados | `PARCIAL` | preview, reglas explicables y undo |
| `AI-F37` | desactivar find-as-you-type | `BRECHA` | búsqueda incremental indexada con throttle; toggle accesible |
| `AI-F38` | cancelar sin marcar histórico | `BRECHA` | semántica separada cancelar/olvidar con undo |
| `AI-F39` | friend links | `PARCIAL` | parser estricto, confirmación, deduplicación y fuzzing |
| `AI-F40` | source cache | `BRECHA` | cache con TTL, procedencia, endpoint generation y límites anti-stale/anti-Sybil |
| `AI-F41` | geolocalización IP | `BRECHA` | base opcional y reproducible, sin llamadas remotas, IPv4/IPv6 y modo privacidad |
| `AI-F42` | versión de cliente en tooltip | `PARCIAL` | tooltip accesible con capacidad negociada y advertencia de dato autodeclarado |
| `AI-F43` | webservices mejorados | `PARCIAL` | API UTF-8 tipada, selección múltiple, CSRF/auth y compatibilidad legacy |
| `AI-F44` | SpeedMeter | `PARIDAD` | métricas coherentes entre GUI/API/tray con prueba de invariantes |
| `AI-F45` | auto-query shared files | `BRECHA` | opt-in, presupuesto de privacidad, rate limit y no-query a peers sensibles |
| `AI-F46` | guardar estado de aplicación | `BRECHA` | perfiles de layout versionados, diff, import/export y reset seguro |
| `AI-F47` | portable por defecto | `PARCIAL` | selector explícito portable/AppData, permisos comprobados y migración reversible |
| `AI-F48` | asistente de migración | `BRECHA` | dry-run, copia, validación por schema, backup y rollback completo |
| `AI-F49` | no filtrar IP privadas | `PARCIAL` | excepción por interfaz/subred, nunca global, con advertencia y tests LAN/VPN |

## 3. Matriz completa de mejoras internas

| ID | Mejora de eMule AI | Estado eSE | Objetivo para superar |
|---|---|---|---|
| `AI-I01` | preparación background/carga paralela | `BRECHA` | task graph cancelable, límites de concurrencia y cero acceso MFC desde workers |
| `AI-I02` | listas grandes responsivas | `BRECHA` | p95 de input <50 ms con 500k filas |
| `AI-I03` | procesamiento seguro de compartidos | `PARIDAD` | política central con razones, mismos resultados en scan/watcher y corpus negativo |
| `AI-I04` | DB-IP City Lite | `BRECHA` | actualización atómica firmada, lookup IPv4/IPv6 y benchmark contra `AI-F41` |
| `AI-I05` | guardado long-path-safe | `PARCIAL` | helper único, temp+fsync+replace y pruebas >260/>32k límites documentados |
| `AI-I06` | soporte long path general | `BRECHA` | hash/move/preview/backup con rutas extendidas y regresión UNC |
| `AI-I07` | motor de listas virtuales | `BRECHA` | virtualización común, scroll p95 <50 ms y memoria acotada como `AI-F13` |
| `AI-I08` | carga rápida de resultados | `BRECHA` | lazy materialization, índices y benchmark 1M resultados sintéticos |
| `AI-I09` | escritura de part files | `PARCIAL` | colas acotadas, backpressure, crash consistency y benchmark HDD/SSD |
| `AI-I10` | operaciones bulk rápidas | `BRECHA` | transacciones por lotes cancelables y GUI responsiva |
| `AI-I11` | reconexión tras cambio de IP | `PARCIAL` | endpoint generation único y pruebas LAN→hotspot→LAN |
| `AI-I12` | guardado seguro de config | `PARCIAL` | escritor transaccional común con recuperación de corte en cada etapa |
| `AI-I13` | restauración de parámetros Search | `PARCIAL` | round-trip lossless y versionado |
| `AI-I14` | UX bootstrap Kad | `PARCIAL` | validación, historial privado y bootstrap dual Kad2/Kad6 |
| `AI-I15` | IP filter mejorado | `BRECHA` | whitelist/blacklist CIDR unificadas, parser streaming y fuzz |
| `AI-I16` | información de red viva | `PARIDAD` | coherencia GUI/API y generación de endpoint |
| `AI-I17` | owner-draw oscuro | `BRECHA` | cobertura visual completa, contraste WCAG y cero artefactos como `AI-F12` |
| `AI-I18` | UI y multisort | `BRECHA` | sort estable multi-columna y accesibilidad |
| `AI-I19` | passive sources/UDP reask | `PARCIAL` | simulador determinista, menor tráfico por fuente útil |
| `AI-I20` | spreading de requests/timers | `PARCIAL` | scheduler único con jitter CSPRNG y límites |
| `AI-I21` | limpieza de memoria | `PARCIAL` | budgets por colección, telemetría local y soak 72 h |
| `AI-I22` | publicación de ficheros rápida | `PARCIAL` | diff publish, packet budget y benchmark |
| `AI-I23` | merge de resultados | `PARCIAL` | merge determinista resistente a spam/Sybil |
| `AI-I24` | detección Windows 11 | `PARCIAL` | detección por capacidades, no por versión |
| `AI-I25` | carga rápida de part files | `PARCIAL` | pipeline incremental y benchmark 10k part files |
| `AI-I26` | integración WINE | `BRECHA` | suite WINE estable, detección por capacidades y paridad funcional con `AI-F02` |
| `AI-I27` | webservice multiselección | `BRECHA` | operaciones batch autenticadas, límites y rollback parcial como `AI-F43` |
| `AI-I28` | evitar save en reconnect | `PARCIAL` | dirty flags tipados y prueba de reducción de I/O |
| `AI-I29` | evitar I/O de default apps | `PARCIAL` | cache invalidada por cambio y métrica de I/O |
| `AI-I30` | path en known files | `BRECHA` | schema versionado, múltiples paths por hash y rollback |
| `AI-I31` | tolerancia DST known.met | `PARIDAD` | conservar `AdjustNTFSDaylightFileTime` y añadir casos de zona/clock skew |
| `AI-I32` | preferencias avanzadas | `BRECHA` | búsqueda, reset por sección, export y validación |
| `AI-I33` | Preview Next | `BRECHA` | cola de preview segura y configurable |
| `AI-I34` | mover/redimensionar filtro | `BRECHA` | layout responsive y teclado |
| `AI-I35` | file-type tag solo necesario | `PARCIAL` | compatibilidad wire y reducción medida |
| `AI-I36` | nombres de threads Release | `PARIDAD` | cobertura de todos los workers y dump verificable |
| `AI-I37` | higiene de trace | `PARCIAL` | logging estructurado con niveles y redacción |
| `AI-I38` | repetir lista de servidores | `BRECHA` | acción idempotente con validación |
| `AI-I39` | SafeHash | `PARIDAD` | mantener y ampliar crash/fuzz corpus |
| `AI-I40` | persistir tipo de Search | `PARCIAL` | round-trip de todos los campos |
| `AI-I41` | evitar doble-click toolbar | `BRECHA` | debouncing de comandos y prueba UI |
| `AI-I42` | set category solo al cambiar | `PARCIAL` | actualización diff-based |
| `AI-I43` | tuning moderno de conexión | `BRECHA` | autotuning basado en BDP, límites RAM y perfiles medidos |

## 4. Orden de ejecución

El orden no sigue la numeración de AI. Sigue riesgo y dependencias:

1. **S0 — benchmark y trazabilidad:** perfiles A/B, datasets, métricas y formato
   de evidencia.
2. **S1 — compartidos seguros:** `AI-I03`, después watcher/subdirectorios y
   caché (`F19`, `F20`, `F06`, `F18`).
3. **S2 — modelo y UI a gran escala:** `F13`, `I01`, `I02`, `I07`, `I08`,
   `I10`.
4. **S3 — transferencia clásica:** `F03`, `I09`, `I19`, `I20`, `I21`, `I22`,
   `I25`, `I43`.
5. **S4 — reachability práctica:** `F04`, `F08`, `F14`, `I11`, y por último
   QUIC `F01`.
6. **S5 — seguridad y calidad de resultados:** `F10`, `F11`, `F16`, `F21`,
   `F26`, `F40`, `I15`, `I23`.
7. **S6 — producto y plataformas:** resto de GUI, migración, idiomas, Docker
   y Wine.

QUIC no se integra antes de tener benchmark, selector de ruta único, budgets de
memoria y una suite de compatibilidad. Copiarlo primero produciría otra ruta
paralela difícil de auditar.

## 5. Primer caso: `AI-I03`

El primer incremento debe:

- usar una única política en el escaneo inicial y en `DirectoryWatcher`;
- rechazar atributos no compartibles, tamaño cero/excesivo y nombres
  temporales conocidos;
- comparar ASCII sin depender del locale;
- exponer el motivo exacto de rechazo;
- no rechazar nombres parecidos pero válidos;
- compilar como política C++ pura y tener tests standalone.

Se considerará `PARIDAD` al pasar la prueba focalizada y el build x64. Solo
será `ESE-SUPERA` después de comparar un corpus de entrada común contra AI
1.5.2 y, tras la promoción del delta, contra el baseline vigente; deberá
demostrar menor tasa de falsos positivos o mayor cobertura sin regresión.

Estado del primer incremento:

- política C++ pura centralizada en `SharedFileIntakePolicy.h`;
- integrada tanto en el escaneo inicial como en `DirectoryWatcher`;
- suite standalone: PASS;
- build `Release|x64`: PASS;
- comparación binaria A/B frente a AI 1.5.2: pendiente; por eso el estado se
  mantiene en `PARIDAD`.
