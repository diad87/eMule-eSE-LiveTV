# eMule eSE 9.x: especificación de releases y plan de validación

Estado: borrador normativo para desarrollo y publicación

Ámbito: eSE 9.0, 9.1, 9.2, 9.3 y 9.4

Base inicial inspeccionada: `35264bb` (candidato binario beta.2: `ab1ad6b`)

Revisión actual: fuente `9.1.0-rc.3` previa a congelación; el commit y los
hashes definitivos se fijan al construir la candidata limpia.

Fecha de revisión: 2026-07-27

## 1. Propósito

Este documento define qué debe contener cada versión de la rama 9.x, qué queda
fuera, qué pruebas debe superar y cómo se desarrolla, valida, promociona y
revierte cada entrega.

Las pruebas obligatorias se han diseñado para poder ejecutarse con los equipos
y redes disponibles actualmente. No se exige comprar hardware, contratar un
VPS, disponer de un NAS ni encontrar una comunidad externa de betatesters.

Una emulación controlada sirve para demostrar lógica, compatibilidad, límites y
tratamiento de errores. No sustituye una prueba de Internet real cuando la
afirmación pública se refiera expresamente a una red real. Si una propiedad no
puede observarse en el laboratorio, se limita la afirmación pública en lugar de
convertir una simulación en una prueba de campo.

## 2. Reglas normativas

Los términos de este documento tienen el siguiente significado:

- **DEBE**: requisito bloqueante. Si no se cumple, la versión no se publica.
- **NO DEBE**: comportamiento prohibido y bloqueante.
- **DEBERÍA**: requisito esperado; solo puede omitirse con una excepción
  documentada.
- **PUEDE**: comportamiento opcional que no condiciona por sí solo la salida.
- **PASS**: resultado reproducible que satisface todos los criterios del caso.
- **FAIL**: resultado contrario al esperado.
- **BLOCKED**: el caso no pudo ejecutarse o no produjo evidencia suficiente.
  `BLOCKED` nunca equivale a `PASS`.

Ninguna versión estable se publica con un caso obligatorio en estado `FAIL` o
`BLOCKED`.

## 3. Principios comunes a toda la rama 9.x

### 3.1 Compatibilidad

1. Las extensiones eSE DEBEN ser aditivas y negociadas mediante capacidades.
2. Un eMule 0.70b sin soporte eSE NO DEBE recibir opcodes ni payloads eSE
   antes de negociar capacidades. PUEDE recibir tags aditivos en `HELLO` si
   usa el mecanismo extensible heredado, el peer antiguo los ignora y una
   captura demuestra que no alteran campos, opcodes ni formatos clásicos.
3. IPv4 heredado NO DEBE cambiar de tamaño ni significado.
4. Un peer desconocido o antiguo DEBE degradar al comportamiento clásico.
5. Kad2 DEBE conservar sus formatos, `nodes.dat`, routing y semántica pública.
6. Kad6 NO DEBE insertar contactos ni direcciones sintéticas en Kad2.
7. Una dirección IPv6 NO DEBE convertirse en un supuesto IPv4 para satisfacer
   una API heredada.
8. El cliente Kad6 nativo PUEDE ejecutarse sobre IPv4 o IPv6, pero solo DEBE
   intercambiar su wire propio con nodos eSE que participen en ese plano.
9. Durante las betas anteriores al RC de 9.1, un cambio incompatible del wire
   Kad6 DEBE incrementar su versión. Un cliente que no reconozca esa versión
   DEBE rechazarla sin degradar Kad2 ni enviar el formato a peers antiguos.
10. El wire Kad6 se considera estable únicamente después de congelarse para el
    RC de 9.1; distribuir una beta no convierte por sí solo su wire experimental
    en una promesa de compatibilidad permanente.

### 3.2 Seguridad, consentimiento y privacidad

1. Toda medición NetLab y toda función que preste recursos, actúe como relay,
   gateway o salida pública DEBE comenzar desactivada en un perfil nuevo.
2. La participación en NetLab y la contribución de recursos DEBEN requerir una
   decisión afirmativa y persistente.
3. La aceptación de NetLab básico NO DEBE activar Punch3, predicción de puertos,
   relay, KRP, donación de ancho de banda ni salida pública Kad6.
4. Cada contribución de recursos DEBE tener consentimiento independiente.
5. Debe existir una acción **Desactivar todo** que cierre las funciones de
   laboratorio sin reiniciar el equipo.
6. No se realizarán escaneos de hosts aleatorios.
7. No se subirá telemetría automáticamente.
8. Los informes exportados NO DEBEN contener claves privadas, tokens, payloads,
   nombres de archivos privados ni direcciones completas salvo decisión
   explícita del operador.
9. El panel web y la API permanecerán ligados a loopback por defecto.
10. El puerto web NO DEBE publicarse mediante UPnP.

El cliente Kad6 nativo es una selección de red, no una contribución NetLab:
puede estar seleccionado junto a Kad2 en una beta pública siempre que se
etiquete como experimental, sea desactivable de forma independiente y no
active por ello salida pública, relay, gateway ni donación de recursos.

### 3.3 Integridad

1. Ninguna función de red puede comprometer `.part`, `.part.met`, `known.met`,
   créditos, claves o preferencias.
2. La verificación de hashes y chunks DEBE ocurrir antes de promover datos a
   estado válido.
3. Un cierre abrupto durante una transferencia DEBE permitir reanudarla sin
   perder bloques ya confirmados.
4. Una dirección no representable en una estructura heredada DEBE rechazarse
   de forma explícita, no truncarse.

### 3.4 Operación

1. Cada paquete DEBE incluir versión, commit, manifiesto y SHA-256.
2. `emule.exe` y `ese-server.exe` DEBEN proceder del mismo build.
3. Solo se publicarán builds `Release x64` durante la rama 9.x.
4. Cada versión DEBE documentar copia de seguridad, actualización y rollback.
5. Los cambios de protocolo se congelan al entrar en RC. Un cambio posterior
   obliga a crear otro RC.

## 4. Laboratorio disponible

Los nombres siguientes son roles de laboratorio. Las direcciones concretas,
tokens y credenciales no deben incorporarse a informes públicos.

| ID | Equipo disponible | Uso |
|---|---|---|
| `H1` | Equipo Windows x64 principal | Compilación, nodo principal, origen LiveTV, captura, router doméstico y posible KRP edge |
| `H2` | Segundo equipo Windows | Peer físico en otra ubicación, rendezvous o cliente detrás de otra red |
| `H3` | Portátil Windows | Peer móvil, peer de compatibilidad y cliente conectado al hotspot |
| `N1` | Teléfono Android | Solo hotspot/USB tether y observación de la red móvil; las pruebas 9.1 no requieren instalar software en el teléfono |
| `V1` | VM Hyper-V en `H1` | eMule 0.70b, eSE 8.1 o versión anterior |
| `V2` | Segunda VM o segundo perfil aislado | Peer eSE adicional, gateway simulado o prueba de fallo |
| `H4` | Cuarto equipo Windows, cuando esté disponible | Capacidad adicional; nunca es requisito único de salida |

Estado observado al redactar este plan:

- `H1`, `H2` y `N1` estaban visibles en la red de control.
- `H3` estaba apagado o desconectado, pero forma parte del material disponible.
- `H1` tiene Hyper-V, Tailscale, Cloudflare WARP y un router doméstico.
- El estado local de eSE en `H1` confirmaba Kad conectado y mapping UPnP.
- La API eSE de `H2` no era accesible en ese momento; antes de una sesión de
  campo debe arrancarse el candidato y comprobarse localmente.

### 4.1 Uso permitido de Tailscale

Tailscale se usa para:

- administrar los equipos;
- sincronizar la hora de una prueba;
- copiar binarios y recoger informes;
- recuperar un equipo después de un fallo.

Tailscale NO cuenta como ruta de datos válida para demostrar:

- apertura de puertos del router;
- funcionamiento bajo CGNAT;
- hole punching público;
- entrada IPv6 pública;
- KRP sobre Internet.

En esos casos eSE debe recibir explícitamente la dirección no-Tailscale del
peer y la captura debe confirmar que el tráfico no utiliza el adaptador
Tailscale.

### 4.2 Perfiles de red

| ID | Topología | Equipos | Qué demuestra |
|---|---|---|---|
| `T0` | Dos perfiles/instancias aisladas | `H1` | Estado, wire, persistencia y controles negativos |
| `T1` | Dos equipos en la LAN doméstica | `H1` + `H3` | IPv4/IPv6 local, rendimiento y compatibilidad |
| `T2` | Dos redes físicas | `H1` + `H2` | Internet real, NAT distinto y comportamiento remoto |
| `T3` | Hogar frente a red móvil | `H1` + `H3` mediante `N1` | CGNAT móvil, cambio de red y IPv6 delegado si existe |
| `T4` | Tres redes/roles | `H1` + `H2` + `H3/N1` | Rendezvous, relay, caída de un tercero y malla LiveTV |
| `T5` | IPv6 aislado sin IPv4 | `H1` + `H2/H3` o `V1/V2` | Correctitud IPv6-only sin depender de un ISP ni de software Android |
| `T6` | IPv6 entre redes mediante overlay | Dos Windows físicos | Transporte IPv6 remoto; no prueba entrada IPv6 pública |
| `T7` | Router doméstico | `H1` | UPnP real, renovación, cambio de puerto y limpieza |
| `T8` | NAT/gateway simulado | `H1` + Hyper-V | PCP, NAT-PMP, doble NAT, expiración y fallos reproducibles |
| `T9` | Edge KRP propio | `H1` edge + `H2/H3` clientes | Relay autenticado sin servicio cloud |

### 4.3 Preparación obligatoria de cada nodo

Antes de una prueba entre equipos:

1. Instalar exactamente el mismo ZIP candidato cuando el caso no sea de
   compatibilidad.
2. Comparar SHA-256 del ZIP y de `emule.exe`.
3. Usar perfiles independientes y previamente copiados.
4. Configurar alias `eSE-A`, `eSE-B` y `eSE-R`; no usar nombres personales en
   el informe.
5. Sincronizar reloj con una diferencia máxima de un segundo.
6. Guardar `BUILD_INFO.txt`, configuración sanitizada y `/api/status`.
7. Registrar adaptadores, familia IP, tipo de red y puertos antes de empezar.
8. Confirmar que el panel remoto no está publicado.
9. Cerrar otros procesos eMule que utilicen los mismos puertos.
10. Mantener Tailscale solo como canal de control, salvo en los casos `T6`
    que declaran expresamente el overlay como plano de datos y la excepción
    estrictamente acotada de `V91-C01` descrita en su matriz.

La excepción `T6` es deliberada y acotada: `V91-I06` valida transporte IPv6
remoto sobre overlay. Su informe debe etiquetar la ruta como overlay y no puede
usarse para afirmar IPv6 pública, entrada directa, apertura de puertos, ausencia
de CGNAT ni hole punching.

## 5. Evidencias y severidad

### 5.1 Evidencia mínima por ejecución

Cada ejecución obligatoria produce:

- versión y commit;
- hashes del paquete;
- equipos y topología;
- preferencias experimentales efectivas;
- hora inicial y final;
- estado previo y posterior de `/api/status`;
- contadores relevantes;
- fragmento de log con timestamps;
- hash del archivo transferido, si aplica;
- resultado `PASS`, `FAIL` o `BLOCKED`;
- explicación de cualquier desviación.

Los archivos privados se conservan fuera del repositorio. Solo se añade al
repositorio un resumen sanitizado.

### 5.2 Severidades

| Nivel | Ejemplos | Efecto |
|---|---|---|
| `S0` | corrupción, exposición de clave/token, proxy abierto, tráfico sin consentimiento | Bloquea cualquier build y exige nueva auditoría |
| `S1` | crash, cuelgue, falsa promoción HighID, fuga de endpoint, bypass de kill switch | Bloquea beta, RC y estable |
| `S2` | pérdida de ruta, reconexión rota, degradación grave, incompatibilidad | Bloquea RC y estable |
| `S3` | diagnóstico incorrecto, UI confusa, fallo recuperable | Puede entrar en beta; debe resolverse antes de estable |
| `S4` | cosmética o documentación menor | Puede diferirse con issue |

### 5.3 Escalera de promoción

1. **Dev**: compila una configuración y pasan pruebas focalizadas.
2. **Alpha**: pasan todos los tests automáticos y `T0`.
3. **Beta**: pasan `T1` y al menos una topología física remota.
4. **RC**: feature freeze, todos los gates obligatorios y soak completo.
5. **Stable**: dos ejecuciones completas del mismo commit, en días distintos,
   con reinicio de los nodos entre ambas y sin `S0`–`S2`.

## 6. Gates comunes de publicación

Estos gates se repiten en 9.0–9.4.

### `G-CLEAN`: fuente y versión

- Árbol Git y submódulos sin cambios ni archivos no inventariados.
- `Version.h`, `package.json`, tag y release notes coinciden.
- Registro de protocolos sin colisiones.
- No existen claves privadas ni tokens reales en el paquete.

### `G-BUILD`: build con inputs fijados y manifiesto verificado

```powershell
.\tools\run_alpha_tests.ps1 -Suite All
.\tools\verify_eSE.ps1
```

Además:

- recompilación completa `Release x64`, no solo incremental;
- lenguaje y recursos de las 43 traducciones;
- `npm audit --audit-level=high`;
- ASan de relay y componentes que lo soporten;
- inputs externos fijados y verificados antes de empaquetar;
- manifiesto por archivo y SHA-256 externo del ZIP comprobados contra el
  paquete congelado.

Hasta implantar y verificar timestamps, orden de entradas y metadatos
normalizados, este gate no afirma que dos ejecuciones produzcan un ZIP
idéntico byte a byte.

### `G-SELFTEST`: paquete extraído

1. Extraer el ZIP en una carpeta nueva.
2. Ejecutar:

```powershell
.\emule.exe --portable --selftest
```

3. Verificar salida cero.
4. Repetir con el control negativo previsto por el self-test.
5. Confirmar que ninguna ruta depende del árbol de fuentes.

### `G-UPGRADE`: actualización y rollback

- Perfil nuevo.
- Copia de un perfil de la versión estable anterior.
- Copia de un perfil de la beta anterior.
- Inicio, cierre limpio, reinicio y rollback.
- Ningún `.met` se abre simultáneamente con dos procesos.
- La versión anterior puede arrancar sobre la copia de rollback o se documenta
  explícitamente qué archivo nuevo debe retirarse.

### `G-COMPAT`: peers anteriores

Matriz mínima:

| A | B | Operación |
|---|---|---|
| versión candidata | eMule 0.70b | hello, fuente, descarga y subida |
| versión candidata | eSE 8.1 | descarga, LiveTV y modo directo |
| versión candidata | 9.x anterior | negociación, fallback y cierre |

No se exige que un peer antiguo entienda una función nueva; se exige que no se
rompa ni reciba wire incompatible.

### `G-SOAK`: estabilidad

- 12 horas conectado a Kad/eD2K.
- Una descarga y subida mantenidas.
- Un periodo LiveTV de al menos dos horas a 12 Mbps cuando la versión toca
  transporte o reachability.
- Muestreo de handles, threads y memoria cada cinco minutos.
- No puede existir crecimiento monótono sin límite, proceso huérfano ni
  degradación progresiva de la tasa.

### `G-ROLLBACK`: recuperación

- Kill switch durante una operación.
- Cierre normal.
- Terminación abrupta del proceso.
- Reinicio de Windows entre dos ejecuciones del candidato.
- Restauración de la versión anterior usando una copia del perfil.

## 7. eSE 9.0: laboratorio público seguro

### 7.1 Objetivo

9.0 proporciona una base pública de observación y consentimiento. Permite
obtener evidencia real sin convertir funciones experimentales en promesas de
soporte.

Decisión de release: 9.0 incluye el **cliente Kad6 nativo experimental
seleccionado por defecto junto a Kad2**. Un perfil nuevo usa máscara `3`
(`Kad2|Kad6`) y un perfil antiguo con `NetworkKademlia=1` migra a esa misma
máscara. Esta decisión permite formar una población beta suficiente para
validar el plano sin confundirlo con una función ya soportada.

La selección anterior activa únicamente el plano UDP Kad6 nativo: routing
firmado, bootstrap, mantenimiento y registros de fuentes sobre endpoints
elegibles IPv4 o IPv6. No activa una salida pública Kad6, KRP, relay,
contribución de ancho de banda ni el gateway/carrier anónimo. Estas superficies
mantienen preferencias, capacidades y gates de consentimiento independientes.

### 7.2 Requisitos funcionales

| ID | Requisito |
|---|---|
| `V90-F01` | Conservar íntegro el conjunto funcional estable de eSE 8.1 |
| `V90-F02` | Solicitar consentimiento NetLab en el primer arranque de un perfil |
| `V90-F03` | Distinguir `undecided`, `declined`, `accepted+disabled` y `accepted+enabled` |
| `V90-F04` | No activar NetLab al actualizar un perfil que nunca lo aceptó |
| `V90-F05` | Medir solo interacciones con peers que anuncien consentimiento compatible |
| `V90-F06` | Mantener informes sanitizados localmente |
| `V90-F07` | Proporcionar un kill switch inmediato |
| `V90-F08` | Mantener relay, KRP, predicción, Punch3 y salida Kad6 apagados |
| `V90-F09` | Exponer estado y contadores suficientes para diagnosticar las pruebas |
| `V90-F10` | Mantener dashboard, API y HLS recibido limitados a loopback; acceso LAN/remoto aplazado |
| `V90-F11` | Producir un paquete con inputs fijados, manifiesto verificado, SHA-256 externo y rollback comprobado |
| `V90-F12` | Mantener integridad de descargas, hashing, part files y LiveTV |
| `V90-F13` | Seleccionar Kad2+Kad6 en perfiles nuevos y al migrar un `NetworkKademlia=1`, con controles independientes |
| `V90-F14` | Persistir Kad6 en `nodes_v6.dat`, separado de `nodes.dat`, y recargar todos los contactos en probation |
| `V90-F15` | Rechazar versiones Kad6 desconocidas sin afectar a Kad2; el wire continúa explícitamente experimental hasta el RC de 9.1 |

### 7.3 Fuera de alcance

- Garantizar conectividad bajo cualquier CGNAT.
- Declarar IPv6-only completamente soportado.
- Donar ancho de banda o aceptar relay por defecto.
- Operar infraestructura pública KRP o Kad6.
- Subir telemetría automáticamente.
- Eliminar el LowID clásico.

### 7.4 Pruebas obligatorias

| ID | Topología | Procedimiento | Criterio PASS |
|---|---|---|---|
| `V90-A01` | build | Ejecutar `G-CLEAN`, `G-BUILD` y `G-SELFTEST` | Todos verdes |
| `V90-C01` | `T0` | Perfil nuevo, responder **No** | NetLab inactivo; cero actividad experimental tras 30 min |
| `V90-C02` | `T0` | Perfil nuevo, responder **Sí** y desactivar después | El estado persiste y el kill switch detiene actividad en menos de 5 s |
| `V90-C03` | `T1` | A acepta y B rechaza | No se ejecuta una medición bilateral |
| `V90-C04` | `T1` | A y B aceptan | Solo aumentan contadores NetLab permitidos |
| `V90-C05` | `T1` | Activar NetLab con funciones avanzadas en cero | Punch3, predicción, relay y KRP continúan en cero |
| `V90-S01` | `T0` | Intentar acceder a dashboard/API/HLS desde una interfaz no loopback | Conexión rechazada; el paquete rc.3 no publica esas superficies |
| `V90-S02` | `T7` | Arrancar con web local y UPnP general activo | El puerto web no aparece mapeado |
| `V90-I01` | `T1` | Transferir archivo de 4 GiB, cerrar abruptamente y reanudar | Hash final idéntico; no se pierde estado confirmado |
| `V90-L01` | `T4` | Emisor y dos viewers LiveTV a 12 Mbps durante 2 h | Sin crash; reproducción continua y chunks válidos |
| `V90-L02` | `T4` | Retirar un viewer y después el emisor | Limpieza de suscripción, FFmpeg y HLS sin afectar al otro viewer |
| `V90-K01` | `T1/T2` | Mantener Kad 12 h con keepalive consentido | Pings/pongs acotados, sin bucle ni crecimiento de contactos inválidos |
| `V90-K02` | `T0/T1` | Arrancar perfil nuevo y perfil migrado con Kad conectado | Máscara `3`; Kad2 y Kad6 observables; salida pública, gateway y contribución continúan apagados |
| `V90-K03` | `T0/T1` | Guardar contactos Kad6, reiniciar y observar su promoción | `nodes_v6.dat` se conserva; ningún contacto se considera verificado hasta completar un nuevo challenge |
| `V90-U01` | perfiles | Ejecutar `G-UPGRADE` desde 8.1 y beta anterior | Configuración conservada y rollback documentado |
| `V90-B01` | `V1` | Ejecutar `G-COMPAT` con 0.70b | Sin wire nuevo hacia el peer antiguo |
| `V90-B02` | `H3/V1` | Ejecutar `G-COMPAT` con 8.1 | Descarga y Live directo correctos |
| `V90-R01` | paquete | Instalar, retirar y restaurar paquete anterior | Perfil recuperable y binarios no mezclados |

### 7.5 Gate de salida 9.0

9.0 se considera completa cuando:

- pasan todos los gates comunes;
- no existe `S0`–`S2`;
- los controles de consentimiento y kill switch pasan dos veces;
- LiveTV de tres nodos pasa en el laboratorio actual;
- el cliente Kad6 experimental cumple `V90-K02/K03`;
- las funciones de servicio, salida y contribución de 9.1–9.4 siguen apagadas
  en el paquete; la selección por defecto del cliente Kad6 nativo es la
  excepción explícita descrita en 7.1;
- la documentación no afirma IPv6 completo, HighID universal ni anonimato
  fuerte.

## 8. eSE 9.1: IPv6 de producción entre peers eSE

### 8.1 Objetivo

9.1 promociona a función soportada el trabajo dual-stack y el cliente Kad6
experimental ya distribuido en 9.0. IPv6 deja de ser únicamente una superficie
beta y pasa a ser una ruta real para conexión, fuentes, callbacks, LiveTV y
descubrimiento eSE.

La promoción se completa en el RC, no en la primera beta. Las betas 9.1 pueden
exponer funciones adelantadas del runtime para obtener evidencia real si se
cumplen simultáneamente estas condiciones:

- el usuario acepta por separado el laboratorio base, el laboratorio avanzado
  y cualquier contribución de recursos;
- los tres niveles parten apagados y la ausencia de decisión equivale a
  rechazo;
- un kill switch general detiene las superficies experimentales;
- la UI, API, logs y notas distinguen una **Beta Exit** de la salida pública
  estable;
- la evidencia obtenida con una Beta Exit no satisface por sí sola el gate de
  salida estable del RC.

Esto permite mejorar y probar Kad6 sin ocultarlo ni reducir sus requisitos de
seguridad, interoperabilidad o estabilidad.

El consentimiento NetLab no forma parte de la selección de la ruta IPv6
ordinaria. Un `HELLO` actual que aporte una dirección IPv6 pública y anuncie
simultáneamente `IPV6_WIRE` y `IPV6_DUALSTACK` habilita esa ruta soportada sin
activar el laboratorio. Activar o revocar NetLab tampoco puede modificar la
preferencia de transporte IPv6 `Off`/`Auto`/`Preferred`. Los vectores de alcance
Kad previos a `HELLO`, Punch3 y las demás superficies experimentales conservan
sus gates bilaterales de consentimiento.

### 8.2 Requisitos funcionales

| ID | Requisito |
|---|---|
| `V91-F01` | `CAddress` debe conservar familia, longitud y bytes nativos |
| `V91-F02` | Listener dual `AF_INET6` con fallback a IPv4 |
| `V91-F03` | Conexión saliente IPv6 con fallback IPv4 acotado |
| `V91-F04` | DNS `AF_UNSPEC` y soporte simultáneo A/AAAA |
| `V91-F05` | Fuentes y callbacks IPv6 solo tras negociación de capacidad |
| `V91-F06` | SOCKS5 `ATYP=4` y HTTP CONNECT con `[IPv6]:puerto` |
| `V91-F07` | SOCKS4 debe rechazar IPv6 explícitamente |
| `V91-F08` | Bans, dead sources y deduplicación por `(familia,dirección,puerto)` |
| `V91-F09` | Live peer-list v2, direct-join `[IPv6]:puerto` y conexión LiveTV IPv6 |
| `V91-F10` | Promocionar y volver a validar el aislamiento, selección y observabilidad de Kad2 y Kad6 |
| `V91-F11` | Promocionar el cliente Kad6 básico ya presente: routing firmado, fuentes y persistencia separada con revalidación tras reinicio |
| `V91-F12` | Nunca usar un IPv4 sintético como identidad, crédito o seguridad |
| `V91-F13` | Definir tratamiento de créditos IPv6-only: identidad eSE o estado neutral, nunca atribución incorrecta |
| `V91-F14` | Cambio de dirección temporal sin duplicar ni banear al mismo nodo por error |
| `V91-F15` | UI y API deben mostrar familia y ruta realmente empleadas |
| `V91-F16` | Seleccionar `IPv6Mode=Off` en eSE debe restaurar un baseline IPv4 puro sin exigir que Windows deshabilite su pila IPv6 |
| `V91-F17` | Separar consentimiento base, avanzado y contribución; cada nivel debe partir apagado, persistir y poder revocarse |
| `V91-F18` | Una `Kad6BetaExitOptIn` consentida debe permanecer separada de `Kad6PublicExitOptIn` y no eludir el gate firmado de salida estable |
| `V91-F19` | Escaneo inicial y `DirectoryWatcher` deben usar una única política de admisión de compartidos, con motivos de rechazo y comparación ASCII independiente del locale |
| `V91-F20` | La ruta IPv6 ordinaria negociada por `HELLO` y la preferencia `Off`/`Auto`/`Preferred` deben ser independientes del consentimiento NetLab; el alcance Kad pre-`HELLO` experimental mantiene consentimiento bilateral |

### 8.3 Política de identidad y créditos

La serie `9.1.0-beta` adopta **neutralidad IPv6-only**: un endpoint IPv6-only puede
transferir, pero no recibe ni utiliza créditos IPv4 heredados y su tiempo de
espera se mantiene local al cliente. No se atribuye actividad mediante una
dirección IPv4 sintética.

Antes de RC esta política debe superar la matriz completa o ser reemplazada,
con migración y pruebas, por:

- **Identidad eSE**: créditos eSE-eSE ligados a la clave pública persistente
  del nodo, con registros separados de los créditos IPv4 clásicos.

Está prohibido reutilizar un hash de IPv6 truncado o un `uint32` sintético.

### 8.4 Fuera de alcance

- Punch3 y predicción de puertos como comportamiento estable.
- KRP.
- Salida pública Kad6 estable. Una **Kad6 Beta Exit** puede probarse en una
  beta únicamente con consentimiento de contribución y gates runtime; nunca se
  anuncia ni contabiliza como salida estable.
- Garantizar entrada IPv6 en todos los ISP.
- NAT64/464XLAT como ruta oficialmente soportada, aunque no debe provocar
  crash ni corrupción.
- Cliente eSE para Android; su portabilidad pertenece a una versión posterior.

### 8.5 Herramientas de laboratorio que deben existir

- `ipv6_echo` para Windows x64 (`H1`/`H2` o `V1`/`V2`): TCP/UDP echo con log
  de la dirección observada. No debe depender de Android ni de Termux.
- Script de configuración `T5` que active una red ULA y retire IPv4 en los
  nodos de prueba sin alterar permanentemente la red del usuario.
- Proxy SOCKS5/HTTP CONNECT local reproducible.
- Captura con `pktmon` o herramienta equivalente que registre la familia real.
- Comparador de endpoints anunciados, conectados y mostrados en UI/API.

### 8.6 Pruebas obligatorias

| ID | Topología | Procedimiento | Criterio PASS |
|---|---|---|---|
| `V91-A01` | build | Ejecutar wire tests IPv6 y gates comunes | 6/6, 5/5, 2/2, 6/6 y suite completa verde |
| `V91-A02` | build | Ejecutar la política de admisión y el corpus A/B fijado a eMule AI 1.5.2 `de8e27e` | Cero falsos positivos; menos falsos negativos que el baseline; Core, Integration y `Release|x64` verdes |
| `V91-I01` | `T5` | Dos peers IPv6-only, sin ruta IPv4 | Hello, fuente y transferencia de 4 GiB por IPv6 |
| `V91-I02` | `T5` | LiveTV IPv6-only a 12 Mbps durante 2 h | Playlist y chunks válidos; cero fallback IPv4 |
| `V91-I03` | `T1/T2` | Un mismo peer eSE HighID conserva IPv4 real e IPv6 pública aprendida por `HELLO`; con ambas rutas disponibles, repetir el dial en `Auto` y `Preferred` | `Auto` usa IPv4 para el peer dual HighID ordinario; `Preferred` usa IPv6; ambas rutas quedan atribuidas al PID/socket real y a una interfaz física |
| `V91-I04` | `T1/T2` | Sobre ese mismo peer dual, aplicar `DROP` silencioso al TCP IPv6 manteniendo IPv4 operativo | Se observa un SYN IPv6 sin respuesta durante al menos 2,75 s y un único fallback IPv4 entre 2,75 s y menos de 8 s; la conexión termina antes de 10 s, completa un único `HELLO`/`HELLOANSWER`, no duplica la entrada lógica de conexión y mantiene UI/API responsivas |
| `V91-I05` | `T1` | Comprobar primero que IPv6 sigue operativo entre las NIC físicas; después fijar `IPv6Mode=Off` solo en ambos peers eSE y repetir por IPv4 literal on-link la transferencia canónica de 4 GiB de `V91-I01`, sin deshabilitar el binding IPv6 de Windows | Origen y destino coinciden en tamaño, SHA-256 y ED2K calculados localmente; el wire usa framing clásico y opcodes de fichero grande sobre sockets IPv4 atribuidos al PID y a las NIC físicas; ningún socket o flujo peer del PID candidato usa IPv6, overlay o interfaz virtual; solo se permite el control TCP loopback de la API fijada; API y procesos permanecen responsivos; la limpieza detiene la captura propia y elimina solo reglas de firewall nonce-owned |
| `V91-I06` | `T6` | Dos Windows físicos usando direcciones IPv6 del overlay | Transferencia remota funcional; informe marcado como overlay |
| `V91-I07` | `T3` | Portátil mediante hotspot; comprobar IPv6 global delegado | PASS solo con dirección y ruta IPv6 globales nativas y una conexión eSE directa atribuida al PID y a la NIC física; si el hotspot no delega IPv6 global, registrar la limitación y mantener `BLOCKED` |
| `V91-I08` | `T5` | Endpoint echo Windows independiente por IPv6 | Cliente abre TCP/UDP y conserva los 128 bits observados |
| `V91-D01` | `T1/T2` | Hostname controlado con A y AAAA válidos, una sola inyección y dos hosts físicos; el Source aplica `DROP` silencioso exacto al TCP IPv6 mientras mantiene operativo el forward IPv4 | El resolver devuelve y el cliente retiene simultáneamente ambos candidatos; la captura atribuida al PID/adaptador/tupla prueba el intento AAAA sin respuesta y la transferencia termina por el candidato A |
| `V91-P01` | `T0/T1` | SOCKS5 IPv6 | `ATYP=4`, destino y puerto correctos |
| `V91-P02` | `T0/T1` | HTTP CONNECT IPv6 | Autoridad `[IPv6]:puerto` correcta |
| `V91-P03` | `T0` | Intentar IPv6 mediante SOCKS4 | Rechazo explícito, sin truncado |
| `V91-K01` | `T5` | Kad6-only: bootstrap, routing, publish y source find | Contacto autenticado y fuente recuperada |
| `V91-K02` | `T1` | En un único proceso Kad2+Kad6, aplicar en caliente y sin reinicio las máscaras `Both -> Kad6-only -> Kad2-only`; sondear ambos planos en cada fase | El plano habilitado completa su intercambio, el apagado no responde y las máscaras configurada/activa coinciden en todas las muestras |
| `V91-K03` | perfiles | Guardar un perfil Kad6-only con la candidata y abrir una copia con el paquete eSE 8.1.0 fijado por hashes, con autoconexión activa | Kad2 no se inicia ni se reactiva; evidencia mínima: `NetworkKademlia=0` antes y después, proceso 8.1 vivo y API con `kad_connected=false` continuamente durante al menos 30 s |
| `V91-K04` | `T1/T5` | Reiniciar ambos nodos con `nodes_v6.dat` poblado | Contactos cargados en probation; re-verificación acotada y sin confianza heredada |
| `V91-C01` | `V1/H2` | Peer nuevo frente a 0.70b en un Windows independiente | Transferencia íntegra; solo opcodes y payloads clásicos. Se permiten tags `HELLO` aditivos ignorados por 0.70b |
| `V91-C02` | `T0` | Rechazar sucesivamente base, avanzado y contribución | Ninguna superficie del nivel rechazado se inicia; KRP y Beta Exit permanecen cerrados |
| `V91-C03` | `T0/T1` | Aceptar los tres niveles y revocar el general durante actividad | El estado persiste y relay, KRP y Beta Exit se detienen en menos de 5 s; el gate estable de Kad6, independiente de NetLab, no cambia |
| `V91-C04` | `T0` | Aceptar contribución con configuración KRP incompleta | KRP falla cerrado; no abre listener ni conexión |
| `V91-S01` | `T5` | Introducir dos IPv6 que colisionarían en un hash de 32 bits | Se mantienen como endpoints diferentes |
| `V91-S02` | `T5` | Reutilizar temporal IPv6 de otro epoch | Registro viejo rechazado; nodo legítimo no recibe crédito ajeno |
| `V91-S03` | `T1/T5` | Enviar `BOOTSTRAP_REQ`, `REQ` y `FIND_SOURCE_REQ` desde un endpoint no verificado | Solo se emite challenge acotado; ninguna respuesta amplificada sale antes de una prueba transaction-bound |
| `V91-R01` | `T3` | Cambiar portátil de LAN a hotspot durante sesión | Reconexión limpia, endpoint anterior caduca |
| `V91-O01` | `T1` | Soak dual-stack continuo de 43.200 s entre dos Windows físicos | Procesos y API responsivos en todas las muestras; LiveTV IPv6 y transferencia IPv4 íntegras sobre NIC físicas; crecimiento por proceso ≤256 MiB y ≤1.024 handles; ratio incremental de chunks duplicados ≤25 %, deriva acumulada ≤5 puntos y cero corrupción |

Para `V91-C01`, `V1` sigue siendo válida, pero un segundo Windows físico
independiente (`H2`) constituye un aislamiento más fuerte y también satisface
el caso. Solo para esta prueba de interoperabilidad se permite que un proxy
L4 byte-transparente y el peer vanilla se comuniquen por un overlay controlado:
el objeto de la prueba son los bytes del protocolo clásico, no la
alcanzabilidad. La ejecución debe capturar íntegramente ambos sentidos, fijar
por hash tanto la candidata como el binario 0.70b, acreditar que los Windows
son distintos y etiquetar el transporte como overlay. Esta excepción no
demuestra IPv4/IPv6 pública, entrada directa, apertura de puertos, ausencia de
CGNAT ni hole punching, y no habilita Tailscale como plano de datos para ningún
otro caso distinto de `T6`.

La matriz normativa vigente contiene **27 casos**. El recuento histórico de
beta.2 era de 26 porque todavía no incluía `V91-A02`; desde beta.3, cualquier
ledger de RC que omita `V91-A02` es incompleto.

En `T5`, una ULA RFC 4193 solo es dirección Kad6 válida cuando está
configurada explícitamente como `IPv6BindAddr`. El runtime no puede inferirla
de otra interfaz ni publicarla mediante el prober de IPv6 pública. Su admisión
UDP queda limitada al discriminador `OP_KAD6HEADER` y a opcodes Kad6 nativos:
Kad2, uTP y UDP arbitrario mantienen el rechazo de direcciones no públicas.
La excepción tampoco convierte la ULA en salida pública ni permite usarla
para identidad, ASN o diversidad de una Beta Exit.

La misma ULA puede materializarse como fuente directa TCP desde un enlace
`ed2k://` únicamente durante `T5`, con consentimiento NetLab de contribución
activo y una ULA fijada explícitamente en `IPv6BindAddr`. Esta excepción no
admite loopback, link-local, IPv4 mapeada ni otras direcciones no públicas,
no habilita resolución o descubrimiento público y desaparece al desactivar
NetLab. La captura debe atribuir el socket al PID candidato y a la NIC física.

Para `V91-K02`, las tres fases se ejecutan en el mismo PID y cada una mantiene
su máscara durante al menos 15 s con muestreo de API cada segundo. El cambio
se aplica por la misma ruta de Preferencias que usa el usuario, no editando el
INI ni reiniciando. Cada fase inyecta un `BOOTSTRAP_REQ` Kad2 y un
`BOOTSTRAP_REQ` Kad6: con el plano activo debe completarse la respuesta
correspondiente (incluido el challenge firmado de Kad6), y con el plano
apagado no puede salir challenge ni respuesta. Para evitar que la protección
de reutilización de identidad se mezcle con el aislamiento, cada fase usa una
identidad y dirección IPv6 propias. En un laboratorio sin prefijo global se
permite `2001:2::/48`, reservado por RFC 5180 para benchmarking, solo con rutas
locales `/128`; esa fixture no demuestra alcanzabilidad pública. La captura
física debe contener todos los eventos declarados, cero tramas inesperadas,
cero descartes del kernel y limpieza completa.

Para `V91-S01`, los dos endpoints deben ser direcciones IPv6 completas
distintas, pertenecer a prefijos `/64` distintos y compartir deliberadamente
los mismos 32 bits bajos. Cada endpoint usa identidad Kad y puerto UDP propios,
completa de forma independiente el challenge firmado transaction-bound y
permanece simultáneamente en la tabla verificada: la telemetría debe alcanzar
dos contactos, no una sustitución. La captura física debe acreditar ambas
direcciones de 128 bits, las dos verificaciones, la ausencia de overlay y la
limpieza completa del fixture. Una proyección abreviada que colisione no puede
participar en la identidad, clave, crédito, deduplicación ni reemplazo del
contacto.

Para `V91-S02`, una identidad A se verifica con un record firmado de vigencia
corta en un endpoint IPv6 exacto. Tras observar su caducidad y retirada de la
tabla verificada, una identidad B distinta y con epoch superior reutiliza la
misma dirección IPv6 completa y el mismo puerto UDP. B debe recibir y completar
un challenge transaction-bound nuevo antes de obtener respuesta semántica: ni
la dirección ni el puerto transmiten el crédito de A. Reinyectar después el
record exacto y ya caducado de A no puede producir challenge, respuesta
semántica ni promoción. La telemetría debe acreditar la secuencia de contactos
verificados `0 -> 1 -> 0 -> 1`, y la captura física debe fijar las identidades,
epochs, endpoint, ausencia de overlay y limpieza completa.

Para `V91-S03`, cada uno de los tres opcodes se prueba desde una identidad y
puerto no verificados contra un proceso candidato recién iniciado. Cada
petición debe producir exactamente un `HELLO_REQ` firmado, válido y de tamaño
menor o igual que la petición; no puede producir `BOOTSTRAP_RES`,
`FIND_NODE_RES`, `FIND_SOURCE_RES` ni ninguna respuesta adicional. La captura
debe acreditar las tuplas IPv6 físicas, el PID candidato, el hash del binario,
la ausencia de overlay y la limpieza completa del fixture.

`V91-I05` es una prueba física de regresión IPv4 entre exactamente dos peers.
Kad2 y Kad6 deben permanecer apagados en ambos, el enlace se inyecta una sola
vez mediante la IPv4 literal on-link del Source, sin conexión a servidor eD2K
ni otra fuente. El Downloader debe registrar las 5-tuplas exactas de sus sockets
y solo puede mantener tuplas de peer del PID candidato que terminen en la IPv4
y puerto controlados del Source; este solo puede mantener las tuplas inversas
del mismo flujo. Así, ningún tercero puede aportar bytes a la transferencia
canónica.

Como `T1` usa direcciones RFC1918, ambos perfiles aislados fijan
`FilterBadIPs=0` antes de arrancar y lo revalidan durante la ejecución. Esta
excepción pertenece solo al fixture: no cambia el valor predeterminado del
producto y no amplía el alcance efectivo, porque las reglas nonce-owned
permiten exclusivamente la tupla privada exacta entre Source y Downloader.

Antes de inyectar el enlace, el Downloader debe instalar exactamente diez
reglas `Block` nonce-owned y program-scoped, con `Profile=Any` y todas las
interfaces. Deben cerrar TCP/UDP IPv4 e IPv6 salvo la tupla peer IPv4 exacta
con el Source y la respuesta TCP loopback de la API cuyo puerto local es
`8011`; UDP, incluido loopback, queda completamente cerrado. `MpsSvc`, los
perfiles Domain/Private/Public y las diez reglas con todos sus filtros deben
revalidarse en cada muestra del watchdog. El número de verificaciones exactas
de filtros debe coincidir con el número de muestras.

La captura de `V91-I05` solo es adjudicable si el componente de PktMon se
resuelve de forma unívoca por el GUID de la NIC física, se captura y convierte
filtrando por sus identificadores válidos. `Id` y, si existe, `SecondaryId` no
cero se convierten por separado; exactamente una conversión debe contener la
5-tupla que el inventario de sockets atribuyó previamente al PID candidato.
Cero o más de una coincidencia producen `BLOCKED`. PCAPNG no atribuye PID por
sí mismo: la adjudicación combina la tupla observada por PID, el aislamiento
program-scoped, la NIC física y la evidencia cruzada del Source. Nombre
visible, alias localizado o mera presencia de tráfico entre ambas IPv4 no
bastan. Los inventarios `pre`, `armed` y `post` deben conservar el mismo mapeo,
y todos los contadores ETW de pérdida deben ser cero.

PktMon captura con `snaplen=256`; por ello un paquete IPv4 peer truncado es
esperable e informativo y no invalida por sí solo la ejecución. Un PCAPNG
estructuralmente inválido, una pérdida ETW o una conversión no adjudicable son
`BLOCKED`. En una captura válida, la ausencia o contradicción de framing,
opcodes de fichero grande o fixture en la tupla exacta es `FAIL`. Paquetes
IPv6, tuplas rechazadas o tráfico de terceros vistos solo en la NIC física, sin
atribución suficiente al proceso, se tratan como contaminación y producen
`BLOCKED`; un socket peer IPv6 o de tercero atribuido al PID candidato es
`FAIL`.

Para el fixture de exactamente `2^32` bytes, la petición debe contener
`OP_REQUESTPARTS_I64 (C5:A3)`. La respuesta puede usar
`OP_COMPRESSEDPART (C5:40)`, `OP_COMPRESSEDPART_I64 (C5:A1)` u
`OP_SENDINGPART_I64 (C5:A2)`: el emisor elige la variante según el extremo del
bloque concreto, no solo según el tamaño total del fichero. El adjudicador
exige al menos un `A3` y al menos una respuesta `40`, `A1` o `A2`, todos
ligados al ED2K exacto del fixture; cualquier firma inválida sigue siendo
`FAIL`.

En una NIC Wi-Fi, `pktmon etl2pcap` puede declarar `LinkType=Ethernet (1)` y
conservar tramas de datos IEEE 802.11. El analizador admite ese caso únicamente
si la cabecera 802.11 es de datos y va seguida por una cabecera LLC/SNAP exacta
`AA AA 03 00 00 00` con EtherType IPv4 o IPv6. No se infiere la familia desde
otros bytes ni se aceptan cabeceras LLC/SNAP parciales; una captura que no
produzca la 5-tupla exacta después de esta decapsulación queda `BLOCKED`.

El Downloader conserva los artefactos completos. El Coordinator recibe y
valida un paquete compacto con manifiesto, hashes y tamaños de esos artefactos,
análisis de captura, mapeo de componente, estado y pérdidas de PktMon, y prueba
de sockets. El paquete se valida por tamaño y SHA-256, se abre sin confiar en sus
rutas y sus campos se contrastan con el resultado declarado por el peer remoto.
Sin esa evidencia central el caso no puede ser `PASS`; repetir íntegramente el
análisis de paquetes exige recuperar también los artefactos raw retenidos.

Se permite readjudicar una ejecución sin repetir el producto únicamente cuando
el resultado original fue `LAB_BLOCKED` dentro del adjudicador post-captura y
se conservan completos el nonce, candidata, fixture, ETL, PCAPNG, inventarios,
contadores, muestras, prueba de sockets y expediente de limpieza. La
readjudicación debe usar un adjudicador corregido cuyos self-tests pasen,
reconstruir el paquete compacto central, superar de nuevo la validación H1 y
publicar un informe enlazado por hashes al `FAILURE` original, al cleanup y al
commit exacto del harness. No puede readjudicarse una ejecución con limpieza
incompleta, evidencia ausente, fallo anterior a la captura, contaminación ni
una contradicción del producto. El informe declara expresamente que reutiliza
evidencia bruta y que no volvió a ejecutar el producto.

Las reglas de contención que cubren el espacio IPv6 completo se materializan
en Windows como los dos intervalos exactos `::/1` y `8000::/1`. Su unión
equivale a `::/0`, pero el expediente conserva y valida los dos filtros
realmente instalados, incluidos sus hashes y cardinalidad, sin sustituirlos por
una representación teórica.

Ambos extremos deben calcular localmente tamaño, SHA-256 y ED2K sobre los bytes
del fichero. No se acepta como prueba que el Downloader se limite a devolver el
ED2K recibido en el enlace o en el comando de control.

Antes de la primera mutación de firewall, PktMon o procesos, cada nodo escribe
el estado `ACTIVE/session` con nonce y flags `pending`, lo actualiza después de
cada mutación y permite que la limpieza resuelva también estados parciales. El
protocolo de error fija `FAILURE.status` a `LAB_BLOCKED` o
`PRODUCT_INVARIANT`: el primero se proyecta a `BLOCKED` y el segundo a `FAIL`.
Cada `FAILURE` contiene además `schema`, `case_id`, `nonce`, `phase`,
`category`, `message_sha256` y el estado de `cleanup`.

`COMPLETE.evidence_bundle` contiene `schema`, `encoding=base64`, `bytes`,
`sha256`, `manifest_sha256` y `content_base64`. El ZIP compacto no supera
524.288 bytes, contiene exactamente 11 entradas y expande como máximo
4.194.304 bytes; el frame de control completo no supera 1.048.576 bytes.

En cada checkpoint donde el API esté disponible, `kad_connected`,
`kad6_running` y `kad6_connected` son campos obligatorios de tipo booleano y
deben valer `false`. Un campo ausente, de tipo incorrecto o `true` constituye
una contradicción del producto. Durante toda la transferencia también deben
permanecer `IPv6Mode=0`, `KadNetworkMask=0`, `NetworkKademlia=0` y
`NetworkED2K=0`; `FilterBadIPs=0` debe seguir fijado para no descartar el único
peer RFC1918 autorizado por el fixture.

Una carencia o avería del laboratorio en `V91-I05` —NIC/componente no
resoluble, pérdida ETW, conversión de captura, disco, transporte de control o
limpieza incompleta— produce `BLOCKED`. Con fixture y captura válidos, una
violación del producto —modo o API contradictorios, tráfico IPv6 de peer,
hash/ED2K distinto, opcodes inválidos o proceso no responsivo— produce `FAIL`.
Una contaminación externa o preexistente por terceros invalida el fixture y
produce `BLOCKED`; si, partiendo de un baseline limpio, la candidata inicia o
utiliza un tercero pese a Kad y servidor eD2K desactivados, produce `FAIL`.
Un `PRODUCT_INVARIANT` demostrado con evidencia suficiente permanece `FAIL`
aunque falle después el control o la limpieza; el incidente de laboratorio se
registra adicionalmente. Si el fallo de laboratorio impide demostrar la
supuesta invariante, el resultado es `BLOCKED`. La captura solo es requisito
para adjudicar invariantes del wire, no para un fallo previo de arranque, modo o
API ya probado por evidencia válida.

El preflight IPv6 de `V91-I05` admite una dirección link-local, ULA o global
sobre la NIC física porque solo prueba que la pila de Windows sigue operativa.
Una prueba link-local satisface este control, pero no demuestra IPv6 pública.

`V91-I07` no convierte la política del operador móvil en un resultado del
producto. El preflight debe distinguir una dirección global nativa de ULA,
link-local, overlay, VPN o traducción. Sin dirección y ruta IPv6 globales
delegadas por el hotspot, el caso queda `BLOCKED`; con ambas acreditadas, un
fallo de conexión directa de la candidata es `FAIL`.

`V91-O01` utiliza `T1`, no `T5`. LiveTV sobre IPv6 debe permanecer activo
durante 43.200 segundos completos después del warm-up. Al menos una
transferencia IPv4 canónica debe iniciarse y completarse dentro de esa ventana,
sin necesidad de ocuparla completa, y conservar su SHA-256 final. Se muestrean
proceso y API al menos cada 60 segundos y LiveTV al menos cada 30 segundos, sin
huecos mayores que dos intervalos. No se permiten reinicios, cambios de red,
otra instancia eMule ni otra captura durante la ventana medida. Preparación y
limpieza quedan fuera de los 43.200 segundos.

En la primera y última muestra de `V91-O01`, y cada vez que cambie una tupla, se
conservan PID, 5-tupla, ruta efectiva e `InterfaceGuid`; IPv4 e IPv6 deben
quedar atribuidas a NIC físicas. No se requiere una captura de paquetes.

Para `V91-O01`, `duplicate_ratio` es
`(duplicates_final - duplicates_initial) /
(received_final - received_initial)` y `ratio_drift` es
`cumulative_ratio_final - cumulative_ratio_initial`. Los contadores deben ser
monótonos y `received_final` debe ser mayor que `received_initial`; de lo
contrario no existe una medición válida. Una indisponibilidad de proceso o API
observada por un monitor todavía operativo es `FAIL`; una caída del monitor, un
hueco de evidencia superior al permitido o una duración no demostrable son
`BLOCKED`. Un `FAIL` de producto ya acreditado no se rebaja por un fallo
posterior de recogida o limpieza: se registran ambos incidentes.

`start_v91_o01_partial_soak.ps1` y
`finalize_v91_o01_partial_soak.ps1` son únicamente una regresión local y siempre
mantienen el caso formal en `BLOCKED`. El `PASS` exige un Coordinator `T1` que
ejecute monitores locales en `H1` y `H3`, reúna ambos paquetes de evidencia y
compruebe duración efectiva, cadencia y huecos.

`V91-I04` valida la conmutación de familia de un único peer dual-stack; no es
una prueba DNS ni permite sustituir el `DROP` por un puerto cerrado, `RST` o
`REJECT`, porque esos casos entregan un error inmediato y no detectan un
blackhole. `V91-D01` cubre por separado la conservación de todas las respuestas
de un hostname. Para ambos casos, la captura debe demostrar la ruta efectiva y
no basta con la familia anunciada por la aplicación.

La adjudicación de `V91-I04` separa el fixture de la conducta del producto. Con
topología, disparador ordinario, `DROP`, captura sin pérdidas y atribución PID
válidos, la ausencia del SYN IPv6, del fallback IPv4, del `HELLOANSWER` o el
incumplimiento temporal son `FAIL`, no `BLOCKED`. El API local debe aportar el
user hash realmente cargado y los contadores de conexiones en curso, altas
totales, máximo simultáneo y altas duplicadas; el baseline y el cierre deben
demostrar exactamente una alta para el dial lógico completo, ninguna alta
adicional durante el fallback y cero altas duplicadas.

Para `V91-I03`, `V91-I04` y `V91-D01`, tanto `T1` como `T2` son válidas solo
si hay dos hosts Windows físicos distintos, IPv4 real y una ruta IPv6 pública
nativa directa. La captura debe atribuir cada socket al PID candidato y al
adaptador físico. WARP, Tailscale, VPN, túnel, proxy, relay o una ruta que
vuelva al mismo host no satisfacen ninguna de las dos topologías.

`V91-D01` usa los roles Coordinator/Source, un servidor eD2K mínimo controlado,
Kad apagado, cero terceros y una única inyección del enlace. Antes de inyectar
se obtiene `sequence` de `GET /api/debug/source-resolutions`; después se pide
`?after=<sequence>`. Debe existir exactamente un evento nuevo con esquema
`ese.debug.source-resolutions/v1`, hashes canónicos coincidentes, recuentos
A=1/AAAA=1 tanto resueltos como materializados,
`simultaneously_retained=true`, dos candidatos con origen `hostname_link` y
resultado `added` o `merged_existing`. El API es solo local y no devuelve
hostname ni direcciones sin hash. Con fixture válido, la ausencia o
contradicción de esa evidencia es `FAIL`; solo una carencia externa de
topología/captura puede ser `BLOCKED`.

El Source instala antes del disparo una regla reversible y nonce-scoped de
`DROP` entrante para la IPv6 y puerto exactos del candidato, sin afectar al
listener/forward IPv4. La captura solo es adjudicable si cada SYN pertenece al
PID candidato, al adaptador físico previsto y a la 5-tupla dentro de su ventana
temporal. La regla, el listener, la captura y cualquier proceso iniciado se
registran en el inventario y se revierten también en los caminos de excepción.

El hostname controlado de `V91-D01` se expresa en forma ASCII/IDNA A-label
canónica (minúsculas y sin punto final). Así, el hash calculado por el harness
y el emitido por el cliente representan exactamente los mismos bytes.

### 8.7 Gate de salida 9.1

- Toda la matriz IPv4-only, IPv6-only y dual-stack pasa.
- Existe una política explícita y probada para identidad/créditos IPv6-only.
- Un peer antiguo no recibe formatos nuevos.
- Kad6 básico funciona sin salida pública ni contaminación de Kad2.
- Los tres niveles de consentimiento y su revocación pasan dos veces; una Beta
  Exit nunca satisface ni modifica el gate de salida estable.
- El reinicio no conserva confianza Kad6 y la protección anti-amplificación
  pasa para todas las respuestas mayores que su petición.
- Se ha realizado al menos una prueba entre Windows físicos por IPv6.
- Si no fue posible una entrada IPv6 pública real, las notas dicen
  **transporte IPv6 validado en laboratorio y overlay**, no “funciona con todos
  los ISP”.

#### Cierre de candidata `9.1.0-beta.2`

El commit de candidata
`d773427b9dafb3eba8260d0185a8943b00895798` cierra los dos fallos reproducibles
de beta.1:

- `V91-C03`: PASS en dos rondas, con revocación en 2.462,1 ms y 2.258,8 ms,
  persistencia tras reinicio y Kad6 estable sin cambios.
- `V91-P03`: PASS con HTTP 400, `success/joined/dialed=false`,
  `ipv6_not_supported_by_socks4` y ninguna conexión al proxy.

La matriz histórica de 26 casos queda provisionalmente en **8 PASS, 0 FAIL y
18 BLOCKED**. Los bloqueados necesitan topologías físicas que no estaban
disponibles; por tanto:

- decisión para publicar una **beta de laboratorio**: `GO_WITH_LIMITATIONS`;
- gate normativo completo de 9.1/RC: `NO_GO` hasta ejecutar los 18 casos
  bloqueados.

Esta distinción permite obtener masa de prueba con consentimiento explícito
sin presentar como certificadas las topologías que todavía no se han podido
ejecutar.

#### Incremento de candidata `9.1.0-beta.3`

Beta.3 incorpora `V91-F19` sin modificar wire, preferencias ni topologías de
red:

- `SharedFileIntakePolicy` centraliza atributos, tamaño y nombres inseguros;
- el escaneo inicial y `DirectoryWatcher` llaman a la misma política;
- los rechazos distinguen directorio, atributos, vacío, exceso de tamaño y
  nombre inseguro;
- `thumbs.db` conserva la validación de contenido histórica mediante
  `IsThumbsDb`, evitando rechazar por nombre un archivo válido;
- el corpus A/B de 31 casos está fijado al commit
  `de8e27e2029044d533f7090f173c95856fe4635a` de eMule AI 1.5.2.

El resultado previo a congelación es:

- eMule AI 1.5.2: 0 falsos positivos y 7 falsos negativos;
- eSE beta.3: 0 falsos positivos y 0 falsos negativos;
- prueba focalizada, Core, Integration y build limpio `Release|x64`: PASS.

La evidencia reproducible se documenta en
`AI_I03_V9.1_EVIDENCE.md`.

## 9. eSE 9.2: alcanzabilidad directa y mappings automáticos

### 9.1 Objetivo

9.2 obtiene y mantiene la mejor ruta directa sin pedir al usuario que entienda
UPnP, PCP, NAT-PMP, leases o cambios de endpoint.

### 9.2 Requisitos funcionales

| ID | Requisito |
|---|---|
| `V92-F01` | Priorizar IPv6 directa cuando esté verificada |
| `V92-F02` | Soportar mapping UPnP IGD, PCP y NAT-PMP |
| `V92-F03` | Mantener TCP y UDP con leases y generaciones coherentes |
| `V92-F04` | Renovar antes de expiración y reaccionar a epoch/reinicio del gateway |
| `V92-F05` | Registrar y eliminar únicamente mappings creados por eSE |
| `V92-F06` | No borrar una regla propiedad de otra aplicación o instancia |
| `V92-F07` | Detectar IP privada, shared CGNAT y endpoint no enrutable |
| `V92-F08` | No anunciar un puerto externo hasta disponer de mapping coherente |
| `V92-F09` | No mostrar HighID hasta observar evidencia válida de servidor e inbound |
| `V92-F10` | Reconectar al servidor si cambia el endpoint anunciado |
| `V92-F11` | Recuperarse de cambio de red, router o lease |
| `V92-F12` | Exponer mapper, endpoint, generación, lease y motivo de fallo |
| `V92-F13` | Dos instancias deben resolver colisiones sin compartir ownership |
| `V92-F14` | Con mappings desactivados, comportamiento clásico |

### 9.3 Fuera de alcance

- Punch3.
- Predicción de puertos.
- Relay/KRP.
- Declarar HighID cuando el router acepte una petición pero la entrada no haya
  sido comprobada.

### 9.4 Herramienta obligatoria: gateway NAT simulado

Debe añadirse un harness ejecutable en `H1`/Hyper-V que pueda simular:

- UPnP, PCP y NAT-PMP correctos;
- respuesta lenta o perdida;
- puerto concedido distinto del solicitado;
- lease de duración corta;
- epoch reiniciado;
- dirección RFC1918 o rango CGNAT como “externa”;
- colisión de puerto;
- renovación rechazada;
- mapping desaparecido;
- doble capa NAT;
- dos clientes con ownership distinto.

El simulador permite resultados deterministas sin depender de que el router
doméstico implemente PCP o NAT-PMP.

### 9.5 Pruebas obligatorias

| ID | Topología | Procedimiento | Criterio PASS |
|---|---|---|---|
| `V92-A01` | build | `libnatmap`, ownership linter y gates comunes | Todo verde |
| `V92-U01` | `T7` | Crear mapping UPnP real en router doméstico | TCP/UDP visibles y verificados |
| `V92-U02` | `T7` | Cerrar eSE limpiamente | Se eliminan solo reglas propias |
| `V92-U03` | `T7` | Reiniciar eSE con mapping previo | Reconciliación sin duplicado ni borrado ajeno |
| `V92-U04` | `T7` | Dos perfiles con puertos iguales | Uno obtiene alternativa o falla explícitamente |
| `V92-P01` | `T8` | PCP con puerto concedido igual | Lease activado y verificado |
| `V92-P02` | `T8` | PCP concede otro puerto | Se anuncia el concedido, nunca el local |
| `V92-P03` | `T8` | Reinicio de epoch | Nueva generación y nueva verificación |
| `V92-N01` | `T8` | NAT-PMP normal y renovación | Tres renovaciones sin cambiar identidad |
| `V92-N02` | `T8` | NAT-PMP caduca/rechaza | Se deja de anunciar el mapping |
| `V92-C01` | `T3/T8` | Endpoint “externo” en rango CGNAT | No se promociona; diagnóstico CGNAT |
| `V92-C02` | `T8` | Doble NAT con primera dirección privada | Se solicita capa superior o se informa `NoRoute` |
| `V92-E01` | `T7/T8` | Servidor da HighID pero no llega inbound | UI no da ruta directa verificada |
| `V92-E02` | `T7` | IDCHANGE válido más conexión inbound | Se promociona una sola vez |
| `V92-R01` | `T7` | Cambiar puerto externo durante sesión | Re-login y anuncio nuevo; el antiguo caduca |
| `V92-R02` | `T3` | Cambiar de LAN a hotspot y volver | Estado anterior se invalida y se reconstruye |
| `V92-XF01` | `T8` | Respuestas malformed, replay o generación vieja | Rechazo sin alterar snapshot vigente |
| `V92-O01` | `T8` | Leases cortos durante 8 h | Sin mapping huérfano, fuga ni generación descontrolada |
| `V92-B01` | `T0` | Desactivar mappings | Mismos puertos locales y comportamiento clásico |

### 9.6 Gate de salida 9.2

- UPnP real pasa en `H1`.
- PCP y NAT-PMP pasan contra el gateway simulado.
- La red móvil produce un fallo honesto o una ruta válida, nunca falso HighID.
- Cambio de red, renovación, colisión y cleanup pasan.
- Ningún test necesita Punch3 o KRP para ser declarado PASS.

## 10. eSE 9.3: fin del LowID como estado binario entre peers eSE

### 10.1 Objetivo

9.3 sustituye la decisión única HighID/LowID por un conjunto de rutas
negociadas entre peers eSE. La ausencia de entrada IPv4 directa deja de
descartar por sí sola una conexión.

No significa conectividad universal: sin relay, dos NAT simétricos pueden seguir
sin ruta. El objetivo es que **LowID deje de decidir** y que el cliente intente
de forma segura todas las rutas directas disponibles.

### 10.2 Cascada normativa

El orden estable es:

1. IPv6 directa verificada.
2. IPv4 directa verificada.
3. Mapping UPnP/PCP/NAT-PMP verificado.
4. Callback clásico aplicable.
5. Punch2 autenticado.
6. Punch3 mediante rendezvous eSE autenticado.
7. Predicción acotada cuando exista evidencia compatible.
8. `No alcanzable sin relay`.

9.3 NO incluye relay como ruta de éxito.

### 10.3 Requisitos funcionales

| ID | Requisito |
|---|---|
| `V93-F01` | Vector de reachability versionado, acotado y extensible |
| `V93-F02` | Capacidades desconocidas preservadas o ignoradas de forma segura |
| `V93-F03` | Selector único reutilizado por descargas y LiveTV |
| `V93-F04` | Punch2 con cookie de return-routability |
| `V93-F05` | Punch3 solo mediante peer rendezvous autenticado |
| `V93-F06` | Predicción solo después de fallos previos |
| `V93-F07` | Ventana máxima por defecto de 17 datagramas por intento |
| `V93-F08` | Cooldown, token bucket y backoff por peer |
| `V93-F09` | No escanear puertos ni direcciones ajenas |
| `V93-F10` | No confundir KadID, user hash e identidad de nodo |
| `V93-F11` | Cancelar intentos restantes al obtener una ruta |
| `V93-F12` | Evitar dobles conexiones y doble contabilidad |
| `V93-F13` | Estados UI: Directo v6, Directo v4, Mapeado, Callback, Punch2, Punch3, No alcanzable |
| `V93-F14` | Métricas por ruta, motivo de descarte y latencia |
| `V93-F15` | Consentimiento explícito para Punch3/predicción durante beta |
| `V93-F16` | Kill switch elimina capacidades y cancela intentos pendientes |

### 10.4 Fuera de alcance

- Relay KRP.
- Garantizar conexión en todos los CGNAT.
- Convertir un éxito Punch3 en HighID clásico global.
- Usar un rendezvous como proxy de datos.

### 10.5 Pruebas obligatorias

El harness base es:

```powershell
.\tools\holepunch_gate_test.ps1
```

Cada ejecución física debe guardar los dos JSON y producir el resultado
fusionado.

| ID | Topología | Procedimiento | Criterio PASS |
|---|---|---|---|
| `V93-A01` | build | `libreach`, cookie, wire y gates comunes | Todo verde |
| `V93-D01` | `T1` | Dos peers directamente alcanzables | Se elige directo; cero punches |
| `V93-D02` | `T2` | A directo, B no entrante | Ruta aplicable en ambas direcciones y motivo correcto |
| `V93-P01` | `T3` | `H1` y `H3` en hotspot, 4 rondas por sentido | Contadores de emisor/receptor concuerdan |
| `V93-P02` | `T3` | Repetir con kill switch apagado | `holepunch_disabled`; cero movimiento |
| `V93-P03` | `T3` | Punch2 válido y ACK perdido | Diagnóstico diferencia REQ recibido de REQ perdido |
| `V93-R01` | `T4` | `H2` como rendezvous entre `H1` y `H3` | Punch3 solo tras fallar rutas anteriores |
| `V93-R02` | `T4` | Rendezvous sin capacidad o consentimiento | Rechazo; no se envía petición de tercero |
| `V93-R03` | `T4` | Apagar rendezvous durante el intento | Timeout acotado y estado `No alcanzable sin relay` |
| `V93-S01` | `T0/T4` | Cookie inválida, vieja y de otra dirección | Rechazo sin respuesta amplificadora |
| `V93-S02` | `T0/T4` | Suplantar identidad/capacidad | No se inicia Punch3 |
| `V93-S03` | `T3` | Solicitar intentos por encima del rate limit | Máximo y backoff respetados |
| `V93-S04` | `T3` | Predicción con spread máximo | Nunca más de 17 destinos por intento |
| `V93-S05` | `T3` | Cambiar puerto observado durante predicción | Generación vieja cancelada |
| `V93-X01` | `T2/T3` | Transferencia de 4 GiB tras Punch2/Punch3 | Hash correcto, una sola sesión contabilizada |
| `V93-X02` | `T4` | LiveTV 12 Mbps tras ruta negociada, 2 h | Ruta estable, sin duplicar suscripciones |
| `V93-C01` | `V1` | Peer 0.70b/8.1 | Selector usa solo rutas comprendidas por el peer |
| `V93-K01` | `T4` | Desactivar todo durante Punch3 | Cancelación en menos de 5 s y capabilities retiradas |
| `V93-O01` | `T4` | 100 ciclos conectar/desconectar | Sin handles, sockets o estados huérfanos |

### 10.6 Criterio de éxito de campo

No se fija un porcentaje universal de punching porque depende de la topología.
Se exige:

- que cada dirección sea clasificada correctamente;
- que todo paquete esperado aparezca en contadores y captura;
- que una topología compatible consiga al menos 3 éxitos de 4 intentos;
- que una topología incompatible termine de forma acotada y honesta;
- que no se supere ningún límite de paquetes;
- que ninguna ruta se declare directa si fue overlay o relay.

### 10.7 Gate de salida 9.3

- La misma cascada gobierna descarga y LiveTV.
- Las pruebas físicas `H1`–`H2`, `H1`–`H3` y de tres nodos pasan.
- LowID se sustituye en UI eSE por estado de ruta.
- Las notas dicen “LowID deja de decidir entre peers eSE”, no “HighID
  universal”.
- Los casos sin ruta terminan como `No alcanzable sin relay`.

## 11. eSE 9.4: ruta KRP para CGNAT difícil

### 11.1 Objetivo

9.4 añade una última ruta opcional para los casos donde no exista conexión
directa. Un KRP edge presta un endpoint TCP público y reenvía bytes eD2K
autenticados sin convertirse en servidor de contenidos ni proxy arbitrario.

### 11.2 Requisitos funcionales

| ID | Requisito |
|---|---|
| `V94-F01` | KRP solo se intenta después de agotar rutas 9.3 |
| `V94-F02` | TLS con CA y hostname válidos |
| `V94-F03` | Reto firmado por identidad persistente y prueba ligada al token |
| `V94-F04` | Token rotatorio y revocable; ninguna clave privada de edge en el cliente |
| `V94-F05` | Lease público acotado por identidad, generación y expiración |
| `V94-F06` | Listener público restringido al lease; no forward arbitrario host/port |
| `V94-F07` | Transporte bidireccional de servidor, callback y peer |
| `V94-F08` | Secuenciación, half-close, backpressure y límites de memoria |
| `V94-F09` | Cuotas de sesiones y ancho de banda por nodo |
| `V94-F10` | HighID solo tras `IDCHANGE` válido y entrada real por el lease |
| `V94-F11` | UI distingue `Relayed/KRP` de `Directo` |
| `V94-F12` | Kill switch cierra sesión, listener, lease y anuncio |
| `V94-F13` | Reconexión y resumption no reutilizan token consumido |
| `V94-F14` | Edge drena y apaga sin dejar listeners |
| `V94-F15` | Operación con edge propio; ningún servicio central obligatorio |
| `V94-F16` | Logs sin payloads, tokens ni claves |
| `V94-F17` | Configuración fail-closed ante certificado, token, dirección o puerto inválido |
| `V94-F18` | Capacidad multi-sesión probada antes de cualquier uso comunitario |

### 11.3 Fuera de alcance

- Proxy genérico.
- Almacenamiento o indexación de archivos.
- Anonimato frente al edge.
- Relay activado por defecto.
- Garantía de capacidad comunitaria.
- Servidor cloud obligatorio.

### 11.4 Banco KRP sin terceros

`T9` se construye así:

- `H1`: `relayedge` con certificado de CA de laboratorio y rango de puertos
  mapeado en el router doméstico.
- `H2`: cliente KRP desde su red.
- `H3`: segundo cliente mediante hotspot de `N1`.
- `V1/V2`: sesiones adicionales para carga y controles negativos.
- Tailscale: solo administración y copia de logs.

Si el router de `H1` no permite el rango requerido, se invierten roles con
`H2`. No se contrata un VPS.

Antes de montar `T9` se debe comprobar desde la red móvil que al menos `H1` o
`H2` puede aceptar TCP entrante en el puerto de control y en un puerto del
rango. Si ninguno de los dos resulta públicamente alcanzable, las pruebas
funcionales KRP pueden ejecutarse en LAN/overlay, pero las pruebas de Internet
real quedan `BLOCKED` y 9.4 no puede promocionarse a estable. Un simulador no
puede sustituir la existencia física del endpoint público que KRP promete.

### 11.5 Pruebas obligatorias

| ID | Topología | Procedimiento | Criterio PASS |
|---|---|---|---|
| `V94-A01` | build | relaycore Release+ASan, edge y client E2E | Todas las suites verdes |
| `V94-T01` | `T9` | TLS, auth, lease y conexión servidor | Flujo completo y estado `Relayed` |
| `V94-T02` | `T9` | Callback entrante por puerto de lease | Llega al listener local correcto |
| `V94-T03` | `T9` | Conexión peer y transferencia de 4 GiB | Hash idéntico y flujo bidireccional |
| `V94-T04` | `T9` | LiveTV por peer alcanzado mediante KRP, si usa ese socket | Chunks válidos; ruta declarada KRP |
| `V94-H01` | `T9` | Server no emite `IDCHANGE` válido | No se promociona HighID |
| `V94-H02` | `T9` | `IDCHANGE` válido pero sin inbound | No se considera completamente verificado |
| `V94-S01` | `T9` | CA incorrecta | Cero lease y cero listener |
| `V94-S02` | `T9` | Hostname incorrecto | Cero lease |
| `V94-S03` | `T9` | Token incorrecto/expirado | Cero lease y respuesta acotada |
| `V94-S04` | `T9` | Replay de reto/firma | Rechazo |
| `V94-S05` | `T9` | Reutilizar resumption token | Solo el primer consumo es válido |
| `V94-S06` | `T9` | Intentar forward a host/puerto no autorizado | Rechazo; no se abre socket |
| `V94-Q01` | `T9` | Superar sesiones por identidad | Nuevas sesiones rechazadas sin afectar a existentes |
| `V94-Q02` | `T9` | Superar ancho de banda | Límite efectivo dentro de ±10 % tras 30 s |
| `V94-Q03` | `T9` | Peer lento/backpressure | Memoria acotada y resto de sesiones vivas |
| `V94-XF01` | `T9` | Cortar red del cliente durante flujo | Edge libera sesión al expirar |
| `V94-XF02` | `T9` | Reiniciar edge | Clientes vuelven a estado no alcanzable y pueden reconectar |
| `V94-XF03` | `T9` | Activar kill switch en cliente | Cierre y retirada de ruta en menos de 5 s |
| `V94-XF04` | `T9` | Apagado drenado del edge | Cero listener y cero lease huérfano |
| `V94-M01` | `T9` | Dos físicos más dos VMs concurrentes | Aislamiento de flujos y cuotas |
| `V94-O01` | `T9` | 12 h, dos transferencias y reconexiones periódicas | Sin fuga; crecimiento estable menor de 64 MiB tras warm-up |
| `V94-R01` | perfiles | Desactivar KRP y volver a 9.3 | Rutas directas siguen funcionando |

### 11.6 Gate de salida 9.4

- KRP funciona con los tres equipos actuales sin infraestructura contratada.
- Todos los controles TLS, token, replay, cuota y kill switch pasan.
- Nunca se concede HighID por el mero hecho de abrir un túnel.
- El edge no permite destinos arbitrarios.
- Se prueban varias sesiones; una prueba single-session no permite release
  estable.
- La documentación deja claro que el edge conoce IP, tiempo y volumen, y que
  KRP no proporciona anonimato.

## 12. Plan de desarrollo

El desarrollo se organiza por dependencias, no por fechas. Una fase no comienza
su promoción mientras la anterior conserve un gate rojo.

### 12.1 WP0: infraestructura común de pruebas

Estado a 24 de julio de 2026: el núcleo común (entregables 1–6) está
implementado en `tools/lab/`, documentado y cubierto por
`test_lab_tools.ps1`, que forma parte del gate `Core`. Los entregables 7–10
siguen pendientes y se incorporarán con la versión que necesite cada fixture;
por tanto, WP0 completo todavía no se considera cerrado.

Entregables:

1. `tools/lab/inventory.ps1`: recoge versión, adaptadores y rutas sanitizadas.
2. `tools/lab/prepare_node.ps1`: crea perfiles A/B/R con puertos no solapados.
3. `tools/lab/capture_status.ps1`: snapshots antes/después de API y procesos.
4. `tools/lab/assert_data_route.ps1`: confirma que eSE no usa Tailscale cuando
   el caso prohíbe overlay.
5. `tools/lab/collect_report.ps1`: genera JSON sanitizado común.
6. `tools/lab/soak_monitor.ps1`: memoria, handles, threads, sockets y contadores.
7. Gateway NAT simulado de 9.2.
8. Agente IPv6 echo reproducible para Windows x64.
9. Generador de CA y configuración KRP de laboratorio.
10. Índice de casos y resultados por commit.

WP0 debe completarse antes de declarar RC de 9.0. Las herramientas específicas
pueden añadirse antes de la versión que las necesita.

### 12.2 WP90: cerrar 9.0

1. Corregir todos los gates actuales, incluido el inventario de puertos.
2. Congelar defaults seguros.
3. Separar con claridad NetLab básico de advanced/contribution.
4. Completar tests de consentimiento y kill switch.
5. Ejecutar compatibilidad y LiveTV de tres nodos.
6. Ejecutar soak y rollback.
7. Publicar beta, RC y stable sin activar funciones 9.1–9.4 como soportadas.

### 12.3 WP91: promover IPv6

1. Cerrar auditoría de todos los `uint32` de dirección.
2. Resolver identidad/créditos IPv6-only.
3. Completar callback, server source, Live y proxy matrices.
4. Promocionar el cliente Kad6 experimental y validar `nodes_v6.dat`,
   probation, re-verificación, anti-amplificación y churn de reinicio.
5. Crear topologías `T5/T6` y agente echo Windows.
6. Ejecutar cambio de dirección, fallback y soak.
7. Incrementar la versión del wire si una beta requiere un cambio incompatible
   y congelarlo antes del RC.

### 12.4 WP92: promover mapping directo

1. Terminar el gateway NAT simulado.
2. Conectar `DirectReachabilityManager` a todos los mappers.
3. Auditar ownership, leases, generation y cleanup.
4. Exigir evidencia antes de HighID.
5. Probar router real, red móvil, doble NAT y cambios de red.
6. Ejecutar soak de leases cortos.

### 12.5 WP93: promover el selector

1. Unificar el selector de descarga y LiveTV.
2. Conectar vector de reachability y persistencia.
3. Completar Punch2, Punch3 y predicción con límites.
4. Ampliar `holepunch_gate_test.ps1` para registrar ruta y generación.
5. Ejecutar matrices A↔B y A↔R↔B con los tres Windows.
6. Probar abuso, spoofing, rate limit y kill switch.
7. Cambiar UI de HighID/LowID a estados de ruta para peers eSE.

### 12.6 WP94: promover KRP

1. Congelar KRP v1 y su authority model.
2. Completar multi-sesión y cuotas.
3. Preparar CA/token/edge de laboratorio.
4. Integrar KRP como último escalón del selector.
5. Ejecutar E2E físico con `H1/H2/H3`.
6. Ejecutar matriz TLS/auth/replay y carga multi-sesión.
7. Ejecutar soak, failover y rollback.
8. Documentar operación de un edge propio sin anunciar servicio público.

## 13. Flujo de trabajo por cambio

Cada cambio funcional sigue este orden:

1. Crear o actualizar el caso de prueba que representa el requisito.
2. Comprobar que el test falla por el motivo esperado.
3. Implementar detrás de capability y preferencia cuando corresponda.
4. Ejecutar pruebas focalizadas.
5. Ejecutar Core.
6. Ejecutar Integration.
7. Recompilar completamente.
8. Ejecutar `T0`.
9. Ejecutar la topología física correspondiente.
10. Actualizar documentación, registro de wire y notas.

No se actualiza un golden test para ocultar un cambio. Se documenta por qué el
resultado nuevo es el contrato correcto.

## 14. Calendario de testeo por candidato

### Cada commit

- pruebas focalizadas;
- registro de protocolo;
- idiomas;
- linter de puertos;
- sintaxis Node.

### Candidato diario

- Core;
- Integration;
- build Release x64;
- self-test;
- paridad de paquete.

### Beta

- `T0`, `T1` y una topología remota;
- actualización/rollback;
- control de defaults;
- cuatro horas de operación mínima.

### RC

- toda la matriz de la versión;
- 12 horas de soak;
- tres nodos cuando la versión lo requiera;
- paquete extraído en carpeta nueva;
- dos reinicios de Windows;
- cero cambios de protocolo después de la prueba.

### Stable

- repetir el RC completo en otro día sobre el mismo commit;
- comparar resultados;
- confirmar cero `S0`–`S2`;
- firmar resumen de aceptación;
- generar tag y checksums desde árbol limpio.

## 15. Orden recomendado de sesiones físicas

Para reducir coordinación:

### Sesión A: `H1` solo

- build, unitarios, integración, paquete y self-test;
- perfiles `T0`;
- gateway NAT simulado;
- proxies IPv6;
- controles de seguridad;
- pruebas de crash y rollback.

### Sesión B: `H1` + `H3`

- LAN IPv4/IPv6;
- compatibilidad;
- rendimiento;
- router UPnP;
- cambio LAN/hotspot;
- Punch2.

### Sesión C: `H1` + `H2`

- red remota;
- transferencia y LiveTV;
- callback;
- IPv6 overlay;
- mapping observado desde otra red.

### Sesión D: `H1` + `H2` + `H3/N1`

- Punch3/rendezvous;
- retirada del nodo R;
- malla LiveTV;
- KRP edge y dos clientes;
- multi-sesión y failover.

## 16. Reglas para afirmar resultados públicamente

| Evidencia | Afirmación permitida |
|---|---|
| Solo unitarios/wire | “Implementado y probado de forma determinista” |
| VM o LAN aislada | “Validado en laboratorio” |
| Tailscale IPv6 | “Validado sobre transporte IPv6 overlay” |
| Dos redes físicas sin overlay | “Validado entre redes reales” |
| Hotspot móvil clasificado como CGNAT | “Validado en esta red CGNAT móvil” |
| KRP propio con tres nodos | “Validado con edge autoalojado” |

Nunca se transforman estos resultados en:

- “funciona con todos los CGNAT”;
- “HighID universal”;
- “IPv6 garantizado en cualquier ISP”;
- “anonimato”;
- “relay público disponible”.

## 17. Estado de referencia de esta especificación

Esta revisión acompaña a la fuente candidata `9.1.0-rc.3`:

- `rc.1` fue rechazada al demostrar `V91-I04` que el blackhole IPv6 carecía de
  fallback acotado.
- `rc.2` incorpora la corrección, la conservación simultánea A/AAAA y los
  harnesses exactos I03/I04/D01; su ledger queda conservado como evidencia
  histórica.
- `rc.3` añade únicamente la corrección de scheduling para fuentes HighID
  explícitas cuando eD2K y Kad están desconectados, más el endurecimiento del
  laboratorio necesario para repetir `V91-I05`.
- NetLab y las superficies 9.2–9.4 siguen fail-closed y no forman parte del
  transporte IPv6 ordinario declarado para 9.1.
- `libreach`, `libnatmap`, Punch3, predicción, selector y KRP conservan sus gates
  experimentales y no adquieren estado público por estar presentes en el árbol.
- El estado formal vigente lo determina exclusivamente el
  `V91-RC-LEDGER.json` del commit/binario exactos, no este resumen narrativo.

Por tanto, la presencia de código 9.2–9.4 en el binario no cambia el orden de
promoción: cada capa debe ganarse su versión mediante sus propios tests.
