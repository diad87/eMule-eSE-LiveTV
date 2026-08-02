# V91-I07 - IPv6 movil nativa y conexion eSE directa

## Estado

El harness esta preparado y validado offline. I07 sigue `BLOCKED` hasta una
ejecucion fisica T3 valida; los selftests locales no sustituyen esa ejecucion.
No se debe lanzar mientras `V91-O01` u otro job use cualquiera de los agentes.
La ejecucion formal exige dos cuentas de laboratorio desechables, una por
nodo, y el SHA-256 del SID bajo el que se ejecuta cada agente. Una cuenta de
uso personal o un SID no predeclarado bloquean la prueba antes de arrancar
eMule.

## Objetivo

El portatil H3 debe usar el hotspot movil cualificado por `V91-R01`, recibir
IPv6 global nativa y abrir una sesion LiveTV eSE directa con otro peer fisico
controlado que tambien disponga de IPv6 global nativa. La ruta y el socket se
atribuyen al PID candidato y al `InterfaceGuid` fisico exactos.

Una direccion global o una ruta aisladas solo permiten continuar el preflight;
no son un PASS de I07. ULA, link-local, Tailscale, WARP, VPN, NAT64, Teredo,
6to4 y direcciones de documentacion o benchmark no cuentan.
El clasificador tambien rechaza el bloque IPv6 especial `2001::/23` y la
delegacion directa AS112 `2620:4f:8000::/48`; ambos tienen casos negativos
offline y no pueden calificarse como `global-native`.

## Orden de una sesion desatendida

1. Terminar O01 y comprobar que no queda ningun job en los agentes.
2. Ejecutar R01 y obtener su aggregate `PASS`. R01 siempre devuelve H3 a la
   Wi-Fi Home antes de terminar.
3. Lanzar I07 desde Home con la orden unica de este documento. I07 resuelve
   localmente los perfiles guardados por SHA-256, arma primero el watchdog de
   Home y cambia H3 al hotspot por si mismo.
4. I07 restaura y verifica Home al terminar, tanto en la ruta normal como en la
   de error. No requiere clics ni una segunda orden.

R01 aporta el contrato doble sin publicar nombres de red:

- `requested_home_wlan_profile_sha256` y
  `requested_hotspot_wlan_profile_sha256` identifican perfiles WLAN guardados;
- `topology.home_connection_profile_sha256` y
  `topology.hotspot_connection_profile_sha256` identifican los perfiles NLA
  observados; y
- `remote.topology.initial/mobile` enlaza ambos hashes con el mismo
  `InterfaceGuid` fisico.

I07 lee el aggregate R01 una sola vez como snapshot de bytes, valida ese
snapshot y conserva el original unicamente en memoria del controlador. No
copia el JSON bruto al bundle. En su lugar conserva
`private/r01-prerequisite.json`, un resumen tipado y saneado con el SHA-256 y
tamano exactos del aggregate fuente, las identidades local/remota de candidata,
el binding del ZIP, los cuatro fingerprints, el GUID canonico y el cleanup.
El constructor y el validador de procedencia vuelven a parsear los bytes,
exigen el contrato R01 `PASS`/T3 completo y comparan campo a campo la proyeccion
canonica. Antes de publicar `PASS`, `FAIL` o un `BLOCKED` que declare R01
valido, el terminal vuelve a ligar fuente, resumen retenido, referencia de
artefacto e identidad local/remota exacta de la candidata I07.

## Protecciones antes de cambiar Wi-Fi

El controlador no cambia H3 al hotspot salvo que se cumpla todo lo siguiente:

- ambos agentes estan `IDLE` y responden al protocolo small-frame 2;
- ambos anuncian la capacidad `cooperative_cancel`;
- cada ping contiene `utc_now`, su RTT es como maximo 2 s y el limite superior
  del desfase Source/Viewer calculado con los intervalos t0/remote/t1 es como
  maximo 1 s;
- el baseline remoto tipado ve cero procesos eMule preexistentes; y
- todos los puertos TCP/UDP reservados para I07 estan libres en ambos nodos.

La evidencia se escribe en `private/manifest.json` antes de cualquier mutacion
Wi-Fi.
Un contrato antiguo, reloj no acotado, proceso previo o puerto ocupado produce
`BLOCKED` y H3 permanece en Home.

## Transaccion de sistema y cuenta

Antes de crear el nodo candidato o tocar reglas de firewall, cada nodo:

1. verifica la atestacion de cuenta desechable y compara el SID efectivo con
   el SHA-256 predeclarado para su rol;
2. toma dos snapshots estables del subarbol HKCU
   `Software\Microsoft\Windows\CurrentVersion\Run`, siguiendo de forma exacta
   el valor `eMuleAutoStart`, y de
   `Software\Classes\ed2k`;
3. exige ausencia inicial exacta de ambos artefactos eMule; y
4. toma dos snapshots estables del estado global `ActiveStore` del firewall.

El snapshot global incluye reglas y los siete filtros asociados: puerto,
aplicacion, direccion, interfaz, tipo de interfaz, servicio y seguridad. La
evidencia solo conserva recuentos y hashes canonicos, no nombres, programas,
SIDs ni valores del registro.

Al terminar se repite la captura y se exige el mismo SID, la misma ausencia
HKCU y el mismo hash global del firewall. El harness no intenta una restauracion
destructiva del registro: si eMule crea alguno de esos artefactos, si cambia
otra parte de los subarboles observados o si un collector no puede demostrar el
estado, el cleanup queda incompleto y el resultado formal es `BLOCKED`. Al ser
cuentas desechables, esa politica no arriesga borrar estado del usuario.

## Watchdog local de Home

Antes de ejecutar `netsh wlan connect` hacia el hotspot, H3 crea una lease
nonce-owned de 300 a 1800 segundos y arranca un PowerShell oculto local. El
watchdog resuelve Home por el hash del perfil WLAN guardado y conserva tambien
el hash NLA esperado y el `InterfaceGuid`; nunca persiste SSID ni nombres en
claro.

Si desaparecen el controlador o Tailscale, al vencer la lease el watchdog
restaura Home de forma autonoma. Esa recuperacion protege el equipo, pero deja
I07 `BLOCKED`: un PASS normal exige `trigger=controller_restore`, los dos hashes
y el GUID coincidentes, proceso watchdog terminado y evidencia tipada
`disarmed`. El directorio de lease queda inactivo como registro de auditoria.

## Prerrequisitos de candidata y topologia

- Paquete limpio y preposicionado en ambos nodos.
- Contrato completo de todos los ficheros y directorios del paquete. Los siete
  ficheros de produccion (`BUILD_INFO.txt`, `emule.exe`, `eMule.tmpl`,
  `ese-server.exe`, `ffmpeg.exe`, `ffprobe.exe` y `SHA256SUMS.txt`) siguen
  siendo obligatorios, pero ya no delimitan el manifiesto: cualquier asset
  anidado tambien queda ligado por ruta NFC, tamano y SHA-256. Directorios
  vacios no contratados, reparse points, colisiones por mayusculas/minusculas,
  rutas no NFC y traversal se rechazan. El paquete no puede traer
  `config/preferences.ini`, porque ese fichero pertenece al perfil efimero que
  construye el harness.
- ZIP exacto del mismo conjunto completo. Se admite raiz directa o un unico
  directorio envolvente seguro; se rechazan entradas extra/faltantes,
  directorios no ligados, raices multiples, separadores mixtos, symlinks,
  reparse entries y cualquier diferencia de bytes. Cada nodo calcula tamano y
  SHA-256 de su propio ZIP preposicionado y lo lee mediante un `FileStream`
  compartido solo para lectura durante hash y parseo.
- Mismo commit limpio y mismo EXE en Source y Viewer.
- Peer Source consentido, controlado y alcanzable por IPv6 publica nativa.
- Ambas tareas de agente ejecutandose bajo las cuentas desechables declaradas;
  al inicio deben estar ausentes el valor HKCU
  `Run/eMuleAutoStart` y todo el subarbol HKCU `Classes/ed2k`.

El small-frame solo inyecta scripts y peticiones pequenas; no transfiere el ZIP
de cientos de MiB durante la ventana movil.

Para calcular cada hash SID, ejecute este bloque **bajo la misma cuenta que
ejecuta la tarea del agente**. Repitalo en Source y Viewer; no intercambie los
dos resultados:

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sha = [Security.Cryptography.SHA256]::Create()
try {
  ([BitConverter]::ToString(
    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid))
  )).Replace('-', '').ToLowerInvariant()
} finally { $sha.Dispose() }
```

El SID en claro no se pasa al controlador ni se publica. El hash si es un dato
privado de laboratorio y solo debe aparecer en las peticiones privadas.

## Una sola orden

Desde el repositorio, despues de R01:

```powershell
& .\tools\lab\invoke_v91_i07_campaign.ps1 `
  -CandidatePackagePath 'C:\lab\v91\package' `
  -CandidateZipPath 'C:\lab\v91\candidate.zip' `
  -ExpectedCommit '<40-hex>' `
  -SourceCandidateZipPath 'C:\lab\v91\candidate.zip' `
  -ViewerCandidatePackagePath 'C:\ProgramData\eSE-Lab-Agent\candidates\<id>\package' `
  -ViewerCandidateZipPath 'C:\ProgramData\eSE-Lab-Agent\candidates\<id>\candidate.zip' `
  -R01AggregatePath 'C:\lab-runs\v91-r01\<run-id>\aggregate-result.json' `
  -SourceAgentIPv4 '<IPv4-agente-source>' `
  -ViewerAgentIPv4 '<IPv4-agente-viewer>' `
  -SourceDisposableLabAccountAcknowledged `
  -ViewerDisposableLabAccountAcknowledged `
  -ExpectedSourceLabUserSidSha256 '<64-hex-source>' `
  -ExpectedViewerLabUserSidSha256 '<64-hex-viewer>'
```

`SourceCandidatePackagePath` es opcional cuando controlador y agente Source
usan el mismo paquete. Direcciones, puertos y rutas DPAPI se pueden cambiar con
los parametros del script. La orden hace baseline, cambio seguro, discovery,
canal TCP IPv6 bidireccional previo a la candidata, `direct_join`, recoleccion,
cleanup y restauracion Home.
Los dos switches son una atestacion explicita: no deben usarse si cualquiera
de las cuentas no es realmente desechable o si el hash no corresponde a la
identidad efectiva de su tarea de agente.

## Adjudicacion

`PASS` exige, ademas de todas las protecciones anteriores:

- direccion fuente y ruta `global-native` exactas en NIC fisica no virtual;
- canal de control IPv6 bidireccional antes de arrancar la candidata;
- manifiesto completo revalidado en el nodo inmediatamente antes de cada
  `Start-Process`, sin ficheros extra y con el EXE exacto; la configuracion
  fuerza `AutoStart=0`, `AutoTakeED2KLinks=0`,
  `WatchClipboard4ED2kFilelinks=0` y `OpenPortsOnStartUp=0`;
- identidad del proceso capturada por handle, PID, hora de inicio, hash de ruta,
  hash del EXE y hash del SID; los descendientes admitidos son exclusivamente
  FFmpeg del mismo usuario, ruta y binario, nacidos despues de la candidata;
- `direct_join` aceptado y peer exacto visible en
  `/api/live/privacy/peers`;
- socket establecido propiedad del PID candidato, con direccion local, peer,
  puertos y `InterfaceGuid` exactos en los dos nodos;
- LiveTV activo y playlist/segmento nuevos durante la ejecucion;
- API loopback responsiva al principio y al final, con eD2K, Kad, Kad2, Kad6 y
  NetLab desactivados y sus mascaras a cero durante toda la prueba;
- evidencia retenida antes de borrar el staging: `BUILD_INFO.txt` validado con
  su schema de produccion exacto, `build-info-evidence.json`, configuracion
  efectiva por allowlist (incluido `Nick=eSE-A`/`Nick=eSE-B`, sin password ni
  bind), snapshots API pre/post saneados, topologia/puertos y
  `log-evidence.json` estructurado con al menos un evento real con timestamp;
- Web/API bloqueada hacia interfaces fisicas para IPv4 e IPv6 mediante regla
  nonce-owned de programa/puerto. Cada regla creada se liga a su identidad y
  tupla completa antes de poder borrarse; y
- broadcast, FFmpeg hijo, procesos, canal, HLS, staging y reglas completamente
  limpiados, registro HKCU y firewall global sin cambios, seguido de Home
  restaurado y watchdog desarmado.

Un resultado de nodo solo puede adjudicar `FAIL` si su schema, caso, rol,
nonce, commit, hashes de candidata/BUILD_INFO/ZIP y prueba nativa previa son
exactos, y `failure.category=PRODUCT_INVARIANT` con un codigo fijo. Nunca se
persiste el texto bruto de una excepcion. Cualquier resultado viejo,
mal formado o limpieza incompleta es `BLOCKED`. Un fallo de producto valido se
conserva aunque falte el otro nodo o falle despues la recuperacion del lab.
La adjudicacion liga ademas el hash SID Source/Viewer y el manifiesto de
prearranque al contexto de la peticion; intercambiar nodos, cuentas, ZIPs o
resultados no puede fabricar un `PASS` ni un `FAIL` de producto valido.

Los resultados descargados se validan primero en una zona temporal fuera del
bundle y permanecen en memoria. Un `PASS` no conserva los resultados de nodo:
tras restaurar Home y confirmar estados terminales escribe unicamente
`source-pass-proof.json` y `viewer-pass-proof.json`, proyecciones tipadas,
saneadas y ligadas por SHA-256/tamano a los bytes fuente, al contexto esperado
y entre si. Un `FAIL` conserva unicamente `source-failure-proof.json` y/o
`viewer-failure-proof.json`, pruebas causales tipadas y con la misma procedencia
fuente. Un `BLOCKED` no conserva resultados de nodo ni pruebas de producto.

El staging temporal tiene nombre y ubicacion ownership-checked, rechaza
directorios y reparse points y se borra con reintentos. Ningun resultado
publico se emite si el controlador no puede demostrar esa eliminacion; tras
reintentar tambien en la ruta de error termina con codigo 3 y
`STAGING_CLEANUP_NOT_PROVEN`. La ruta de error purga ademas cualquier escritura
parcial o no autorizada de evidencia de producto.

## Frontera publica y privada

Cada ejecucion crea `lab-runs/v91-i07/<run-id>/`. Su raiz contiene unicamente
`aggregate-result.json` y el directorio `private/`; `lab-runs/` permanece fuera
de Git. El agregado usa el schema `ese.v91.i07-public-aggregate/v1` y solo
publica:

- caso, topologia T3, estado y un `outcome_code` cerrado;
- los alias `eSE-A` (Source) y `eSE-B` (Viewer);
- identidad publica de la candidata;
- doce comprobaciones booleanas; y
- referencias relativas `private/...` con tamano y SHA-256.

IP, endpoint del agente, ruta absoluta, GUID, nonce, SSID, nombre de perfil,
hash WLAN/NLA, token, clave LiveTV, password y URL nunca salen al agregado
publico. Los artefactos que el controlador admite en `private/` son contratos
tipados y saneados; no copia respuestas o diagnosticos brutos. Tampoco se
publica el SHA-256 simple de un SSID conocido. El serializer rechaza rutas no
allowlisted, reparse points, conjuntos vacios, duplicados, desordenados o
incompletos; un `PASS` requiere los doce booleanos verdaderos y los 18
artefactos privados exactos.

Los 18 artefactos de un `PASS` son: `manifest.json`,
`r01-prerequisite.json`, las cuatro parejas request/result de baseline y
preflight, las dos parejas de transicion request/result (hotspot y Home), las
dos peticiones de nodo y las dos pruebas PASS saneadas. No se admiten
`source-result.json`, `viewer-result.json` ni resultados recuperados de nodo.

Los resultados brutos originales pueden seguir existiendo bajo
`jobs/<job-id>/` en cada agente controlado. No forman parte del bundle, no se
publican ni se descargan para retencion. Su borrado es manual; mientras no se
defina una politica operativa de expiracion, su retencion local es indefinida y
debe tratarse como evidencia privada de laboratorio.

Limitaciones P1 conocidas: el agente aun no aplica TTL automatico a esos
`jobs/`, por lo que la limpieza sigue siendo manual. Si falla la propia capa de
serializacion/publicacion durante la recuperacion del `trap`, el controlador
sale con codigo 2 y puede
dejar evidencia privada tipada sin `aggregate-result.json`; no fabrica un
`FAIL`, pero esa perdida de telemetria terminal requiere inspeccion operativa.
Un `hard kill` o corte de energia despues de crear
`%TEMP%\ese-i07-stage-<guid>.json` y antes de ejecutar el `finally` puede dejar
un resultado de nodo bruto local huerfano por tiempo indefinido. Ese fichero no
se publica ni puede fabricar un `PASS` o `FAIL`; la mitigacion P1 futura es un
scavenger seguro limitado por namespace, edad y ownership, o semantica
`delete-on-close`.

## Verificacion exclusivamente offline

Estas ordenes no cambian Wi-Fi, no abren listeners y no arrancan eMule:

```powershell
powershell -NoProfile -File .\tools\lab\inspect_v91_i07_remote.ps1 -SelfTest
powershell -NoProfile -File .\tools\lab\run_v91_i07_node.ps1 -SelfTest
powershell -NoProfile -File .\tools\lab\invoke_v91_i07_campaign.ps1 -SelfTest
powershell -NoProfile -File .\tools\lab\test_v91_i07_offline.ps1
```

Frozen offline checkpoint for this revision: the dedicated suite completed
twice with `status=PASS`, `formal_case_status=BLOCKED` and
`physical_execution_performed=false`. Both canonical outputs have SHA-256
`d17c72e09215f0d883c354fbfc6c8aed5f081d50c290eccb0f2e5399361c3533`.
El schema offline es `ese.v91.i07-offline-selftest/v3`: liga ocho ficheros de
fixture (incluido un asset anidado), cuatro contratos de ruta negativos, 14
ZIPs negativos, siete mutaciones del paquete/nodo, nueve guards INI, ocho
familias de collector de firewall y los guards de cuenta, registro,
prearranque, proceso, cleanup y privacidad.
Los 19 casos de direcciones incluyen los negativos special-purpose, de
traduccion, transicion, documentacion y benchmark descritos arriba. Este
checkpoint es un preflight, no una ejecucion fisica T3.

Artefactos futuros: `lab-runs/v91-i07/<run-id>/aggregate-result.json` y, bajo
`private/`, manifiesto/readiness, resumen tipado R01, baseline pre-mutation,
peticiones, transiciones hotspot/Home y discovery. `PASS` retiene dos pruebas
tipadas y saneadas; `FAIL`, una o dos pruebas causales saneadas; `BLOCKED`,
ningun artefacto de producto.
