# M2A-W12 — ampliación de seguridad y cierre literal W7-SEC-02
Fecha de decisión: 2026-08-02
Estado inicial: `PRE-A / implementation`
Rama aislada: `codex/v9.2-w12-webserver-facade`
Dependencia de entrada: W11 activo y verde
Dependencia de salida: LS1 no puede comenzar hasta que W12 alcance A, H y R
### Base definitiva de integración
La versión `v0.70b-eSE9.1.0`, tag inmutable en
`d08f8b071019b9e5f54f84b2e6e155b6efb9f688`, queda cerrada y no se modifica
para desarrollar v9.2. W1--W11 se integran sobre ese commit en una rama v9.2
separada. El commit de integración resultante
`545cdf45f9f2efaf56899bee6459bc133cf96071`, y no la rama de v9.1 ni el
antiguo HEAD provisional de W11, es el `w12_base_commit` definitivo.
W12 sólo puede crear A después de que esa integración haya pasado sus gates.
El orden obligatorio es `v9.1 final -> integración W1--W11 -> W12 PRE-A -> A
-> H -> R`. Cualquier hash, métrica o evidencia calculado antes de fijar el
commit de integración es provisional y debe recalcularse sobre el árbol final.
## 1. Motivo y alcance
El presupuesto original de W12 (0,75 JP) cubría una fachada mínima, el borrado
de duplicados y la repetición de los gates de WebServer. No cubría el cierre
literal del hallazgo W7-SEC-02: el identificador numérico de sesión aparecía en
URLs Live/HLS y podía actuar como bearer.
Esta ampliación añade, sin aceptar deuda residual:
1. sesión remota mediante cookie aleatoria de 256 bits;
2. almacenamiento por SHA-256 de los bearers de sesión y multimedia;
3. capability HLS de sólo lectura, separada de sesión y CSRF;
4. binding a sesión propietaria, rol HLS, stream y generación Live real;
5. revocación por logout, timeout, parada/reinicio y cambio de generación;
6. rutas HLS canónicas y fail-closed antes de cualquier acceso a fichero;
7. conservación byte-exacta de playlist, segmento, retry y Range;
8. redacción de logs y `Referrer-Policy: no-referrer` probado en navegador;
9. pruebas negativas con contadores que exigen cero IO y cero
   `NotePlayerFetch`;
10. evidencia A/H/R y trazabilidad explícita de W7-SEC-02;
11. adapter `/api/reach/status` de sólo lectura, sin nueva lógica ni wire;
12. caché `std::string` publicada desde el hilo principal y consumida sin
    acceder al snapshot mutable desde el worker web;
13. frontera admin y deny-list remota con salida privada y no cacheable;
14. publicación Kad6 con puertos TCP/UDP anunciados correctos por familia.
Quedan fuera de W12: cambios de códec, QUIC, nuevo empaquetador HLS, cambios de
protocolo LiveTunnel y la extracción LS1-LS6.
## 2. Reestimación aprobada
### Enmienda v2: lease, buffer inmutable y presupuesto del adaptador
La revisión P1 y el adapter Reach ampliaron `WebServer.cpp` en 292 líneas
netas frente al HEAD de entrada integrado, de 1.756 a 2.048 LOC. El par
`WebServer.cpp/.h` queda en
421 adiciones, 137 borrados y +284 netas. Se aprueba de forma explícita este
crecimiento porque contiene exclusivamente cableado sin estado para el lease
HLS, la captura acotada y el envío posterior. Su techo W12 se reduce de 3.500
a 2.100 LOC y no puede ganar ningún campo mutable. Este objetivo incorpora
las 185 líneas IPv6/I08 de v9.1/W10 preservadas por la integración y mantiene
intacto el límite duro de 3.500 LOC.
El mínimo de borrado del coordinador queda fijado en 120 líneas, por debajo
de las 137 reales. La revisión independiente obligó a restaurar las
declaraciones ODR históricas y las cuatro pruebas W8-W11 byte a byte; no se
contabiliza esa restauración como una reducción ficticia. Tras integrar sobre
la base definitiva y reformatear las dos superficies del collector para que
la gobernanza LOC mida código auditable, el corte PRE-A real es
11.870 adiciones, 5.511 borrados y +6.359 netas. El presupuesto queda fijado
en 12.000 adiciones máximas, 5.500 borrados mínimos y +6.500 netas máximas:
márgenes respectivos de 130, 11 y 141 líneas, sin autorizar crecimiento del
coordinador. El borrado real de `WebServer_original.cpp` sostiene la reducción
sin atribuirle eliminaciones ficticias a las restauraciones históricas.
La lógica de lease vive en `LiveHlsReadLease.h/.cpp`, cuyo cuerpo queda en
178/180 LOC físicas. `LiveStreamManager.h` queda dos líneas por debajo de su
baseline y `LiveStreamManager.cpp` no crece; no se versiona una excepción de
crecimiento del coordinador. La materialización del ratchet v2 ejecutable y del
stack R fail-closed incrementa la estimación en 1,00 JP; no altera los límites
de producción ni autoriza crecimiento del coordinador.
El `--selftest` de producción usa un broadcast `testpattern`, toma un snapshot
Broadcast real, lee `stream.m3u8` bajo `ExecuteHlsReadIfCurrent`, conserva una
copia byte-exacta tras `StopBroadcastFull` y exige que el snapshot anterior
quede `Stale` sin invocar el callback. Esta prueba complementa, sin sustituir,
las carreras deterministas del harness nativo.
La gobernanza PRE-A queda cerrada por `mod52_migration_matrix_v2.json`,
`mod52_migration_contract_v2.json`,
`mod03_ownership_layering_contract_v3.json` y
`mod04_architecture_gate_catalog_v3.json`: fijan CARD_PATHS, owners, presupuestos
por superficie y los once IDs W12-COV. El plan M2A v1 permanece como evidencia
histórica hash-pinned; un path, owner, dependencia o presupuesto nuevo exige
otra revisión antes de editar producción.
Unidad: 1 JP = 7 horas netas.
| Área | JP | Horas | % de W12 |
|---|---:|---:|---:|
| Contrato, caracterización y amenazas | 0,25 | 1,75 | 5,26 % |
| Cookie de sesión y digest del bearer | 0,55 | 3,85 | 11,58 % |
| Política de capability HLS | 0,65 | 4,55 | 13,68 % |
| Snapshot Live de rol/stream/generación/root | 0,45 | 3,15 | 9,47 % |
| Integración de rutas, playlists, segmentos y Range | 0,55 | 3,85 | 11,58 % |
| Pruebas nativas, integración y concurrencia | 0,55 | 3,85 | 11,58 % |
| Ratchet v2, schemas cerrados y gobernanza | 0,50 | 3,50 | 10,53 % |
| Revisión independiente Sol y correcciones | 0,25 | 1,75 | 5,26 % |
| Build limpio, A y repetición H | 0,25 | 1,75 | 5,26 % |
| Artefacto R, navegador real y documentación | 0,75 | 5,25 | 15,79 % |
| **Total W12 ampliado** | **4,75** | **33,25** | **100 %** |
El incremento respecto de W12 original es +4,00 JP. Con el total global previo
de 152,75 JP, v9.2 pasa a 156,75 JP (1.097,25 h). El programa M2A pasa de
47,75 a 51,75 JP (362,25 h), con rango orientativo 46–60 JP. La integración
posterior de la base v9.1.0 se mide aparte porque afecta al árbol v9.2 completo,
no al presupuesto cerrado de producción W12.
La reestimación no autoriza relajar límites silenciosamente. Los presupuestos
por superficie se congelarán con los LOC reales antes de A; `WebServer.cpp`
debe seguir en <=2.100 LOC, no se añade estado mutable al coordinador y ningún
módulo nuevo puede superar 1.500 LOC ni ocho dependencias.
## 3. Contrato de seguridad obligatorio
### 3.1 Sesión web
- El login genera un token CSPRNG de 32 bytes, codificado como 64 hex
  minúsculas.
- La respuesta emite `eSEWebSession` con `HttpOnly`, `SameSite=Strict`,
  `Path=/` y `Secure` cuando el transporte es HTTPS.
- El servidor conserva únicamente SHA-256 del bearer.
- Una petición remota no se autentica mediante `ses` ni `/s/{id}`.
- Si se conserva `/s/{id}` como locator, requiere cookie válida y coincidencia
  exacta de sesión incluso en loopback; sin cookie no alcanza el handler.
- Logout elimina la sesión, revoca todas sus capabilities y caduca la cookie.
- Una cookie duplicada, mal formada o de longitud incorrecta falla cerrada.
### 3.2 Capability multimedia
Formato único:

`/h/{cap64}/{generation}/{stream32}/{resource}`

- `cap64`: 64 hex minúsculas exactos; el registro conserva sólo SHA-256.
- `generation`: entero decimal uint64 canónico, mayor que cero, sin signo ni
  ceros iniciales.
- `stream32`: 32 hex minúsculas exactos.
- `resource`: sólo hojas HLS realmente emitidas por el productor activo:
  `stream.m3u8`, `stream_[0-4].m3u8`, `seg_[0-9]{5,10}.ts` y
  `seg_[0-4]_[0-9]{5,10}.ts`. La rama multi-audio está desactivada; habilitarla
  exige ampliar de forma explícita esta gramática y sus pruebas. No se admite
  query, `%xx`, `..`, barra inversa, dos puntos, subdirectorios ni slash
  adicional.
- Scope inmutable: `HlsRead`. Nunca produce `WebRole`, nunca autoriza API ni
  mutaciones.
- Binding: `owner_session_id + Viewer|Broadcast + stream_key + live_generation`.
- TTL absoluto: 12 horas desde emisión; no se desliza con cada GET.
- El uso HLS válido actualiza el timeout normal de la sesión para permitir
  reproducción activa. Un token inventado no toca ninguna sesión.
- Retry, lectura repetida y Range son idempotentes durante la vigencia; la
  capability no es single-use.

### 3.3 Orden fail-closed

Cada GET HLS sigue este orden:

1. parse canónico de la ruta;
2. digest e `Inspect` de capability, scope, revocación y TTL;
3. comprobación de owner vivo sin renovar un token inválido;
4. snapshots iniciales de rol, stream y generación, todavía sin autorizar;
5. adquisición de `LiveStreamManager::m_lock` y revalidación exacta de
   `{stream, rol, generación}`, conservando la prioridad Broadcast-first;
6. `Commit` y touch de owner bajo el mismo lease; si falla, cero IO, reserva y
   `NotePlayerFetch`;
7. resolución de la hoja bajo el root fijo, reserva acotada y copia completa
   del rango solicitado a memoria inmutable, todavía bajo el lease;
8. `NotePlayerFetch` sólo para Viewer, generación exacta y plan 200/206 con
   cuerpo preparado;
9. liberación del lease y envío del búfer fuera del lock.

Si cualquier paso falla, la respuesta es uniforme, no revela existencia del
fichero, no cae a StaticAsset, no llama `NotePlayerFetch` y no contiene secretos.
Una petición ya autorizada puede terminar; logout/revoke impide toda petición
nueva.

El orden de locks permitido es únicamente
`LiveStreamManager::m_lock -> WebAuthPolicy::m_mutex -> reserva atómica`. El
callback ejecutado bajo el lease no puede realizar red, UI, esperas ni volver a
entrar en el manager. El cuerpo se limita a 20 MiB por respuesta y 64 MiB
agregados. La reserva agregada vive hasta consumir el último byte de la cola o
hasta fallo, desconexión o destrucción; la saturación responde 503 con
`Retry-After: 1`, `no-store` y `no-referrer`.

### 3.4 Cabeceras y logs

- HTML, playlists y segmentos de capability usan
  `Referrer-Policy: no-referrer`.
- Credenciales y contenido autenticado no usan cache pública; W12 exige
  `Cache-Control: no-store` o una política privada equivalente documentada.
- No se registra cookie, capability, URL completa, query ni `Referer`.
- Los rechazos sólo registran un código de razón y, si se necesita, IP ya
  admitida por la política existente; nunca el target.

## 4. Secuencia ejecutable y criterios de salida

### Fase 1 — PRE-A

1. Caracterizar rutas, login, timeout, HLS root y HLS por stream.
2. Congelar este contrato y la matriz de amenazas.
3. Implementar política pura con reloj y tokens deterministas para tests.
4. Implementar snapshot coherente Viewer/Broadcast bajo el lock del manager.
5. Integrar cookie, `/h/`, emisión en player y servicio de fichero.
6. Añadir tests unitarios y de integración descritos en la sección 5.
7. Ejecutar revisión Sol de sólo lectura.
8. Corregir todos los P0/P1 y repetir desde el punto 6.

Salida PRE-A: `W12-COV-01` a `W12-COV-05` y `W12-COV-08` a
`W12-COV-11` verdes, código compilable, suites
focales verdes, revisión Sol `APPROVE`, presupuesto versionado y ninguna
aceptación residual. `W12-COV-06` pertenece a A/H y `W12-COV-07` a R; los
siete son obligatorios para completar W12, no para entrar en A.

### Fase 2 — A

1. Build Release x64 limpio, incluyendo dependencias desde cero.
2. Ejecutar selftests de producción y suites Python/Node aplicables.
3. Ejecutar ratchet MOD-5.2 con todos los ficheros W12 en `CARD_PATHS`.
4. Calcular SHA normalizados y actualizar overlays.
5. Crear commit A inmutable con evidencia y hashes.

Salida A: commit verde identificado; cualquier cambio de producción posterior
invalida A y devuelve el flujo a PRE-A.

### Fase 3 — H

1. Activar W12 en ledger desde checkout limpio de A.
2. Verificar que los hashes de producción coinciden con A.
3. Repetir build, selftests, tests nativos, Python, ratchet y escaneos.
4. Confirmar que H sólo activa evidencia y no cambia semántica.

Salida H: ledger activo y repetición completa verde.

### Fase 4 — R

1. Construir/usar el artefacto final exactamente ligado al commit de activación
   `A` y comprobar su manifest antes de exponer el servidor loopback.
2. Crear un scratch aleatorio fuera de la salida R; exigir ACL privada para el
   usuario y SYSTEM, sin puntos de reanálisis, y revalidar esa propiedad antes
   de cada lectura o escritura transitoria. El nodo, binario, configuración y
   verificador permanecen exclusivamente en ese scratch privado. Un segundo
   directorio de intercambio, hermano y efímero, sólo admite al usuario,
   SYSTEM, `CodexSandboxOffline` y exactamente los dos SID restringidos de la
   sesión presentes en la raíz autorizada; nunca admite `CodexSandboxUsers` ni
   contiene el candidato o el verificador. Cualquier ACL distinta es STOP.
3. Ejecutar el login y los checks runtime contra el binario final. Generar en
   scratch el `browser-handoff/v3`: contiene contraseña, stream, canary,
   nonces y rutas raw/done, por lo que es estrictamente transitorio y nunca
   puede entrar en la salida R.
4. Escribir junto al handoff el `browser-ready/v3`, que sólo contiene hashes
   ligados a `A`, al run y al handoff. Emitir una única línea parseable
   `W12_BROWSER_READY=<ruta-absoluta>`; su ruta permanece en el intercambio
   ACL-aislado para que el consumidor no sondee `%TEMP%` y pueda derivar el
   handoff por dirname. Una segunda línea, una ruta fuera de ese intercambio o
   un ready no hash-only es STOP.
5. En la sesión Node REPL documentada, importar directamente el módulo
   collector cuya huella está fijada por `A` y llamar al collector con el
   binding de navegador real. No se admite un adaptador ni una copia local del
   collector. El collector reclama (`claim`) el ready una sola vez; un claim
   duplicado, ajeno o de hash distinto es STOP.
6. Abrir una pestaña real con URL limpia y hacer que sus requests observados
   pasen por el proxy loopback autorizado. La URL de la pestaña no incluye
   contraseña, cookie, CSRF ni capability.
7. Ejecutar, sin iniciar broadcast adicional, una de las dos secuencias que
   realmente produce R: `login (ignorado) -> player -> master -> segmento
   Range -> forged -> log -> logout -> revoked` para `StartTestPattern`, o
   `login (ignorado) -> player -> master -> variant -> segmento Range ->
   forged -> log -> logout -> revoked` para los perfiles multivariante.
   Ambas exigen GET, `no-store`, `no-referrer`, 206 en Range, 403 forged y
   revocación 403 después del logout.
8. Capturar en scratch una traza con forma de eventos CDP, pero derivada de la
   observación del proxy loopback, no de una afirmación de CDP nativo. La traza
   raw puede contener material transitorio sólo dentro del scratch; el done v3
   liga hashes de raw, ready, handoff, collector, navegador y metadatos del
   navegador al binding de `A`.
9. Esperar como máximo 180 segundos el claim, raw y done. Timeout, fichero
   incompleto, hash/shape/binding no exacto, `Referer`, URL secreta o fuga de
   canary es STOP y produce un runtime R `FAIL` saneado.
10. Materializar desde Git el verificador exacto de `A`, comprobar su SHA-256
    contra la activación y usarlo para validar el handoff/ready/done y
    normalizar la captura. La normalización retiene sólo semántica de
    protocolo, hashes y cabeceras seguras; rechaza `Referer` y elimina los
    nombres `cookie` y `x-csrf-token` antes de persistir.
11. Escanear la traza normalizada, DOM, cabeceras y logs buscando contraseña,
    stream, capability, canary y URL loopback en ASCII, UTF-8, UTF-16LE y
    codificaciones relevantes. Cualquier coincidencia es STOP.
12. Borrar incluso en fallo handoff, ready, claim, raw, done y el verificador
    materializado; confirmar el borrado antes de abandonar el scratch.
13. Persistir exactamente cinco artefactos R: `activation.json`,
    `runtime.json`, `browser-challenge.json`, `browser-cdp-trace.json` y
    `verdict.json`. Ningún secreto, raw, claim, ready, handoff, done o
    verificador puede sobrevivir fuera del scratch.
14. Cerrar trazabilidad W7-SEC-02 y publicar sólo métricas y evidencia
    saneadas. Un texto fuente, una captura manual, un CDP declarado nativo o
    una evidencia fuera de este protocolo no sustituye R.

Salida R: evidencia reproducible contra el binario final. Una comprobación de
texto fuente no sustituye esta fase.

## 5. Matriz mínima de pruebas

### Emisión y sesión

- owner activo emite; owner caducado/inexistente no emite;
- dos emisiones producen tokens distintos y distintos de cookie/CSRF;
- cookie correcta, incorrecta, truncada, duplicada y de otra sesión;
- `/s/{id}` sin cookie, con cookie correcta y con cookie cruzada;
- logout, purge, timeout, StopServer y restart revocan.

### Binding y rutas

- Viewer positivo y Broadcast positivo con sus roots reales;
- mismo hash tras leave/rejoin o stop/start rechaza capability vieja;
- rol, hash, generación o token cruzado falla;
- mayúsculas, gen 0/00/overflow, token corto, query, doble encode, traversal,
  `.js`, `.css`, `.png`, URI absoluta y `//host` fallan;
- cualquier `/h/` no canónica queda en 404/403 y nunca en StaticAsset;
- capability no autoriza status, join, leave, alive, broadcast ni dashboard.

### Streaming

- master/variant mantienen URIs relativas bajo el prefijo capability;
- playlist y segmento completos devuelven bytes exactos;
- Range válido devuelve 206 y `Content-Range` exacto;
- Range inválido, múltiple o duplicado devuelve 416;
- ocho o más GET concurrentes y retries funcionan sin consumir la capability;
- negativos mantienen contadores IO=0 y `NotePlayerFetch=0`.
- rollover entre snapshot y lease rechaza sin touch, IO, reserva ni Note;
- una transición iniciada durante la copia espera al lease y los bytes
  entregados siguen perteneciendo a la generación autorizada;
- tres cuerpos simultáneos de 20 MiB reservan 60 MiB; otra reserva de 5 MiB
  obtiene 503, y completion/fallo/desconexión devuelven el contador a cero;
- durante un envío parcial la reserva sigue viva hasta consumir el último byte;
- estrés concurrente logout + leave/rejoin + lectura termina sin deadlock bajo
  un watchdog acotado.

### Fugas

- ningún HTML/playlist contiene sesión, CSRF o contraseña;
- ninguna respuesta/log contiene el canary;
- navegador real envía la petición de prueba sin cabecera `Referer`;
- la capability no aparece en logs de rechazo ni en evidencia automática.

## 6. Política de modelos y criterios STOP

- Implementación, compilación y corrección mecánica: GPT-5.6 Terra.
- Contrato, amenazas y revisión independiente PRE-A/A/H/R: GPT-5.6 Sol.
- Sol no edita el corte que revisa; Terra no autoaprueba sus cambios.

STOP y única causa de intervención del usuario:

1. una operación requerida exige credenciales, hardware o decisión funcional
   que no puede deducirse del repositorio;
2. el sistema operativo bloquea repetidamente una herramienta legítima y no
   existe alternativa ya autorizada;
3. aparece una incompatibilidad de producto que obliga a elegir entre romper
   clientes existentes o debilitar el contrato;
4. tras tres intentos independientes persiste el mismo fallo externo no
   corregible desde el código.

Un fallo de compilación, test o revisión no es un bloqueo: se corrige y se
repite. W12 sólo alcanza 100 % después de A + H + R verdes.
