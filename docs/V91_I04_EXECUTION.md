# V91-I04 - fallback IPv6 a IPv4

## Estado y alcance

V91-I04 dispone de una batería offline determinista para revisar el parser, los
contratos puros, las fixtures PCAPNG y el wiring estático del harness. Un
`offline PASS` significa **GO de preflight**, pero no abre sockets, no inicia
eMule, no instala reglas de firewall y no demuestra el fallback entre dos
equipos. El caso continúa formalmente `BLOCKED` hasta completar la campaña
física.

El objetivo físico es probar que, después de una ruta IPv6 silenciosamente
descartada en el peer controlado, la candidata:

- emite exactamente un intento de transporte IPv6 atribuible a su PID;
- no recibe TCP, RST, aplicación ni ICMPv6 correlacionado durante la ventana
  fija de `2750 ms`;
- emite exactamente un fallback IPv4 entre `2750 ms` inclusive y
  `min(FallbackLimitSeconds * 1000, 8000 ms)` exclusivo; y
- completa el handshake IPv4 antes de `FallbackLimitSeconds`, sin segundo
  fallback ni owner ajeno o ambiguo.

## Prerrequisitos físicos exactos

No iniciar la campaña salvo que se cumpla todo lo siguiente:

1. Hay dos hosts Windows físicos distintos, dedicados a I04, con PowerShell
   elevado. No comparten ventana, puertos, roots ni captura con O01, I03, I05 u
   otro job. La lectura de `MachineGuid` y del SID actual funciona en ambos.
2. Cada host usa una cuenta de laboratorio desechable. El operador conoce los
   SHA-256 de los dos `MachineGuid` y de los dos SID, y los liga explícitamente
   mediante los cuatro parámetros `Expected*Sha256` y
   `-DisposableLabAccountAcknowledged`.
3. En cada cuenta, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   existe pero no contiene `eMuleAutoStart`, y el subárbol
   `HKCU\Software\Classes\ed2k` no existe. El harness toma snapshots canónicos
   dobles antes de cualquier mutación y después del cleanup. Un estado inicial
   distinto, una lectura inestable o un cambio concurrente deja el caso
   `BLOCKED`; no se autoriza restauración destructiva del registro.
4. Ambos hosts tienen el mismo paquete limpio y congelado y el mismo ZIP
   candidato situado fuera del paquete. Coinciden commit, SHA-256 de
   `emule.exe`, SHA-256 y tamaño del ZIP, set exacto de entradas, tamaños,
   digests y manifiesto del paquete. No hay traversal, colisión por mayúsculas,
   reparse point ni fichero adicional. También coinciden, byte a byte, el
   harness principal, `common.ps1` y `prepare_node.ps1`; sus tres SHA-256 son
   parámetros obligatorios. El harness abre los tres ficheros con locks de
   lectura inmutables antes de importar `common.ps1` y conserva esos locks
   hasta el `finally` exterior.
5. `OutputRoot`, `CoordinationRoot`, paquete, ZIP y repositorio son roots
   canónicos disjuntos, sin relación padre/hijo ni reparse points. Son privados
   y no versionados; cada output está ausente o vacío y el nonce no se reutiliza.
   Ambos hosts ven los mismos bytes del directorio compartido.
6. El peer ofrece IPv4 pública HighID real, IPv4 local asignada e IPv6 global
   pública nativa. El coordinador también tiene IPv4 e IPv6 nativas. Las rutas
   pertenecen a NIC físicas `Up`, sin proxy, VPN, overlay, túnel, relay ni
   traducción.
7. No cuentan Tailscale, WireGuard, WARP, ZeroTier, OpenVPN, TAP, Hyper-V,
   vEthernet, Teredo, 6to4, ISATAP, IP-HTTPS, ULA, link-local, IPv4-mapped IPv6,
   rangos de documentación o benchmark.
8. Los seis puertos TCP/UDP/Web del peer y cliente son únicos y están libres
   en TCP —cualquier estado— y UDP. No existen procesos eMule preexistentes.
9. `pktmon.exe`, `logman.exe`, el colector ETW y el sampler PID/socket de 25 ms
   están disponibles. La pérdida ETW se consulta después de un flush confirmado
   y antes del stop terminal. La captura debe terminar con `EventsLost=0`,
   `LogBuffersLost=0`, `RealTimeBuffersLost=0` y ETL por debajo del límite
   circular; de otro modo el caso es `BLOCKED`. Iniciar cada campaña en un
   proceso PowerShell nuevo: los helpers gestionados de COPYDATA, UI, ETW,
   sampler y launcher restringido deben exponer exactamente su `ContractId`;
   una clase ya cargada con otro contrato bloquea la ejecución antes de poder
   reutilizarla.
10. Epoch y QPC son monótonos y coherentes con el boundary formal. El sampler
   cubre desde antes de la captura hasta después de la observación, con gap
   máximo inferior a la tolerancia de correlación.
11. El peer puede instalar transaccionalmente una regla **inbound IPv6 Block**
    limitada al nonce, programa, dirección y puerto controlados. No crear una
    regla local REJECT/RST: una respuesta activa invalida la prueba de silencio.
12. Cada nodo se prepara desde el paquete ligado y con preferencias exactas.
    No se heredan `preferences.dat`, `cryptkey.dat`, `clients.met`, servidores,
    logs o shares de otra sesión; Kad, proxy, UPnP, NetLab, uTP punch, relay y
    rutas experimentales permanecen desactivados. En particular,
    `AutoStart`, `AutoTakeED2KLinks`, `WatchClipboard4ED2kFilelinks` y
    `OpenPortsOnStartUp` valen exactamente `0` antes de cada arranque.
13. El operador reserva hasta 2700 segundos para el escenario y no interrumpe
    ninguna consola, job, captura o share hasta el cleanup terminal. Cada root
    iniciado queda ligado a nonce, rol, PID, tiempos de creación Process/CIM,
    hashes de ruta y ejecutable, SID y handle retenido. Un descendiente, PID
    reutilizado o fallo del collector bloquea el caso; el harness nunca mata un
   proceso cuya identidad completa no pueda volver a probar. Cada candidata se
   crea suspendida y se asigna antes de reanudarla a un Job Object propio con
   `ActiveProcessLimit=1` y cierre destructivo del job; no se admite ningún
   descendiente.

## Cálculo privado de bindings de host y cuenta

Ejecutar por separado en cada host. Conservar solo los digests en el entorno
privado de laboratorio:

```powershell
$machineGuidRaw = [string](Get-ItemProperty `
  -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
  -Name MachineGuid -ErrorAction Stop).MachineGuid
$machineGuid = ([Guid]::Parse($machineGuidRaw)).ToString('D').ToLowerInvariant()
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sha = [Security.Cryptography.SHA256]::Create()
try {
  $machineIdSha256 = ([BitConverter]::ToString(
    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid))
  )).Replace('-', '').ToLowerInvariant()
  $sha.Initialize()
  $userSidSha256 = ([BitConverter]::ToString(
    $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid))
  )).Replace('-', '').ToLowerInvariant()
} finally {
  $sha.Dispose()
  Remove-Variable machineGuidRaw, machineGuid, sid `
    -ErrorAction SilentlyContinue
}
```

Registrar por canales privados:

- `$coordinatorMachineIdSha256` y `$coordinatorUserSidSha256`; y
- `$peerMachineIdSha256` y `$peerUserSidSha256`.

No intercambiar el SID o `MachineGuid` en claro ni reutilizar el digest de un
host para el otro.

## Ejecución offline

Desde la raíz del repositorio, en Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\lab\test_v91_i04_offline.ps1
```

La suite lee una sola instantánea de bytes del harness, la parsea como AST y
extrae funciones concretas en scopes aislados. Las fixtures se limitan a un
root temporal y se eliminan al terminar. No ejecuta ni dot-sourcea
`test_v91_i04_fallback.ps1`, no inicia eMule y no altera firewall, adaptadores,
rutas ni red externa. Un único probe acotado puede lanzar
`PING.EXE -t 127.0.0.1` dentro del Job Object restringido para probar
`CREATE_SUSPENDED`, asignación antes de resume, accounting y cierre; el lease se
libera y el proceso se destruye dentro del propio test.

La batería cubre bindings ZIP/directorio y sus mutaciones, roots disjuntos
—incluido repositorio igual, padre o hijo de output/coordinación—, ausencia
fail-closed de procesos eMule preexistentes, snapshots HKCU/firewall, existencia
obligatoria de `HKCU\...\Run` antes y después, rutas y reparse points,
clasificación IPv4/IPv6 y
overlays, preferencias de cardinalidad y valor exactos, tipos API, reloj
epoch/QPC, correlación PID+5-tupla, PCAPNG/interface/NIC y handshake, logs y ETW
fail-closed, límites `2750..<8000`, failure tipado, precedencia
`PASS/FAIL/BLOCKED`, allowlist pública, ownership, descendientes y cleanup
terminal. También muta el contrato del bundle para rechazar hashes de harness,
`common.ps1` o `prepare_node.ps1` distintos, locks falsos/coercibles y campos
ausentes, y verifica su igualdad en `run.json`, `peer-ready.json`,
`peer-result.json`, el resumen y los lanzamientos manual/remoting. Los
`ContractId` de COPYDATA, UI, ETW, sampler y launcher restringido se prueban con
mismatches herméticos. También se exige el censo exacto de filtros PktMon, los
snapshots inmutables de PCAPNG/socket con bytes, SHA-256 y read lock, el binding
tipado de source/boundary, los snapshots de firewall del escenario en ambos
roles y el accounting `total=1`, `active=1→0` del Job Object. El parser
PCAPNG rechaza además secciones múltiples, bloques Packet/
Simple Packet obsoletos, opciones IDB desbordadas, interfaces desconocidas,
linktypes no soportados, `captured_length != original_length`, frames que no se
pueden parsear y entre 1 y 11 bytes de cola. Los contratos API rechazan tipos
coercibles —por ejemplo, strings usados como booleanos o enteros—, propiedades
ausentes y objetos nulos.

Ejecutar dos veces sobre los mismos bytes congelados. Ambas salidas deben tener
exit code cero, cero `FAIL`, idéntico `test_count`, `harness_sha256` y
`result_sha256`. La salida declara siempre:

```text
schema=ese.v91.i04-offline-selftest/v1
case_id=V91-I04
physical_execution_performed=false
formal_case_status=BLOCKED
```

Checkpoint offline congelado del 1 de agosto de 2026 tras diferir toda
publicación formal del Coordinator hasta después del cleanup exterior:

- harness SHA-256
  `d89da7c4f7fa33628c5e25b68d603015edf89d83067eb9475399eeceb4f65f36`;
- suite offline SHA-256
  `9118989747975a70707a597aae42db67816edcc8522b2a92a29740a4e0590bc2`;
- run 1: `410/410 PASS`, exit code cero, cero `FAIL` y `597.141 s`;
- run 2: `410/410 PASS`, exit code cero, cero `FAIL` y `569.158 s`;
- ambos runs tienen el mismo `test_count=410` y el mismo
  `result_sha256=4358bdce164e9aacdd1a9f99631faff12115b5eb0ab4e0d1e9cf4a9658d4a25e`;
  y
- los hashes de la suite y del harness permanecieron estables antes y después
  de cada run, con AST limpio en ambos scripts.

Este checkpoint es evidencia de preflight offline, no de ejecución física:
`physical_execution_performed=false` y `formal_case_status=BLOCKED` en ambas
salidas reproducibles. El rol Peer ya no puede publicar `COMPLETE` antes de
liberar y probar terminalmente sus leases Job Object; el coordinador valida el
receipt terminal y los jobs remotos, y el mutex propio de PktMon se conserva
desde antes del censo hasta después del cleanup.

El Coordinator conserva su resultado en memoria durante el rol. Su finalizador
solo se ejecuta después del `finally` exterior y de todos sus guards; entonces
escribe summary, public-summary y, como último artefacto, un receipt ligado a
los hashes de ambos resúmenes. Un fallo al liberar cualquiera de los tres
grupos de locks impide alcanzar ese finalizador y, por tanto, impide publicar
PASS.

## Contratos A-D del preflight

### A. Filtros PktMon exactos

El preflight exige inventario global vacío y arma exactamente tres filtros con
nonce: TCP IPv4 con IP y puerto exactos, TCP IPv6 con IP y puerto exactos, e
ICMPv6 completo sin IP ni puerto. Antes de iniciar la captura debe existir
exactamente una instancia de cada filtro, tanto si PktMon presenta filas
numeradas como si presenta campos con nombre. Cualquier filtro ausente,
duplicado, adicional o con dirección, protocolo o puerto extra bloquea la
adjudicación.
El inventario armado y el inventario inmediatamente posterior al boundary de
captura se ligan por SHA-256; cualquier drift entre ambos contradice la prueba
y fuerza `BLOCKED`.

### B. Snapshots inmutables PCAPNG/socket y failures

Cada fuente se captura una sola vez como bytes inmutables bajo un read lock
retenido, con longitud y SHA-256 registrados; los parsers consumen exclusivamente
ese snapshot en memoria. Los failures tipados exigen tipos no coercibles, PID
candidato, boundary exacto y la correspondencia `FailureType→SourceKind`:
`socket_contract` usa `socket_sampler`; los demás failure types admitidos usan
`packet_verdict`. El hash de la evidencia embebida también debe coincidir. Una
ausencia o discrepancia produce `BLOCKED`.

### C. Firewall de escenario y contradicción

Los snapshots globales del firewall usan el schema estable v2. El coordinador
aporta estados pre-boundary y post-observación; el peer aporta estados armado y
pre-removal. Los hashes cruzados enlazan los artefactos. Un drift demostrado
produce `proof_contradicted/BLOCKED`; una fuente ausente o ilegible produce
`incomplete/BLOCKED`. La restauración del baseline postcleanup se verifica por
separado.

### D. Proceso restringido y censo terminal

El candidato se crea suspendido, se asigna antes de reanudarlo a un Job Object
nuevo con `ACTIVE_PROCESS=1` y `KILL_ON_JOB_CLOSE`, y después se consulta su
accounting exacto. Durante la ventana se exige total=1, activo=1 y ausencia
estructural de descendientes; en terminal, activo=0. La identidad, ownership y
binding del failure deben coincidir. Ambos roles publican además un censo
terminal de procesos, TCP, UDP y puertos, y la liberación del lease es
fail-closed.

## Ejecución física manual

Crear una vez un nonce y usarlo en ambos hosts:

```powershell
$runNonce = [Guid]::NewGuid().ToString('N')
```

Calcular los tres hashes del bundle desde los mismos bytes que permanecerán
bajo lock durante la ejecución:

```powershell
$harnessSha256 = (Get-FileHash -Algorithm SHA256 `
  -LiteralPath .\tools\lab\test_v91_i04_fallback.ps1).Hash.ToLowerInvariant()
$commonSha256 = (Get-FileHash -Algorithm SHA256 `
  -LiteralPath .\tools\lab\common.ps1).Hash.ToLowerInvariant()
$prepareNodeSha256 = (Get-FileHash -Algorithm SHA256 `
  -LiteralPath .\tools\lab\prepare_node.ps1).Hash.ToLowerInvariant()
```

Repetir el cálculo en el peer y exigir los mismos tres valores. No copiar solo
el script principal: un `common.ps1` o `prepare_node.ps1` distinto invalida el
bundle.

Iniciar primero Coordinator. Sustituir rutas, direcciones y hashes por los
valores privados certificados:

```powershell
& .\tools\lab\test_v91_i04_fallback.ps1 `
  -Role Coordinator `
  -PackagePath 'C:\lab\i04\package' `
  -PackageZipPath 'C:\lab\i04\candidate.zip' `
  -ExpectedPackageZipSha256 '<64-hex>' `
  -ExpectedHarnessSha256 $harnessSha256 `
  -ExpectedCommonSha256 $commonSha256 `
  -ExpectedPrepareNodeSha256 $prepareNodeSha256 `
  -OutputRoot 'C:\lab-private\i04-coordinator-output' `
  -Commit '<40-hex>' `
  -ExpectedEmuleSha256 '<64-hex>' `
  -PeerIPv4 '<peer-public-ipv4>' `
  -PeerLocalIPv4 '<peer-assigned-local-ipv4>' `
  -PeerIPv6 '<peer-public-native-ipv6>' `
  -CoordinatorIPv4 '<coordinator-native-ipv4>' `
  -CoordinatorIPv6 '<coordinator-public-native-ipv6>' `
  -CoordinationRoot '\\lab-share\private\i04' `
  -ControlledPeerAcknowledged `
  -ExpectedCoordinatorMachineIdSha256 $coordinatorMachineIdSha256 `
  -ExpectedPeerMachineIdSha256 $peerMachineIdSha256 `
  -ExpectedCoordinatorUserSidSha256 $coordinatorUserSidSha256 `
  -ExpectedPeerUserSidSha256 $peerUserSidSha256 `
  -DisposableLabAccountAcknowledged `
  -PeerTcpPort 9462 -PeerUdpPort 9472 -PeerWebPort 9511 `
  -ClientTcpPort 9562 -ClientUdpPort 9572 -ClientWebPort 9611 `
  -FileSizeBytes 1073741824 `
  -PeerReadyTimeoutSeconds 300 `
  -ScenarioTimeoutSeconds 2700 `
  -FallbackLimitSeconds 10 `
  -PeerControlMode Manual `
  -RunNonce $runNonce
```

Coordinator escribe y muestra `evidence\MANUAL-PEER-COMMAND.txt`. Revisar sus
bindings y ejecutar esa orden en el peer; no recuperar una orden de otra
sesión. Su forma esperada es:

```powershell
& .\tools\lab\test_v91_i04_fallback.ps1 `
  -Role Peer `
  -PackagePath 'C:\lab\i04\package' `
  -PackageZipPath 'C:\lab\i04\candidate.zip' `
  -ExpectedPackageZipSha256 '<64-hex>' `
  -ExpectedHarnessSha256 $harnessSha256 `
  -ExpectedCommonSha256 $commonSha256 `
  -ExpectedPrepareNodeSha256 $prepareNodeSha256 `
  -OutputRoot 'C:\lab-private\i04-peer-output' `
  -Commit '<40-hex>' `
  -ExpectedEmuleSha256 '<64-hex>' `
  -PeerIPv4 '<peer-public-ipv4>' `
  -PeerLocalIPv4 '<peer-assigned-local-ipv4>' `
  -PeerIPv6 '<peer-public-native-ipv6>' `
  -CoordinatorIPv4 '<coordinator-native-ipv4>' `
  -CoordinatorIPv6 '<coordinator-public-native-ipv6>' `
  -CoordinationRoot '\\lab-share\private\i04' `
  -ControlledPeerAcknowledged `
  -ExpectedCoordinatorMachineIdSha256 $coordinatorMachineIdSha256 `
  -ExpectedPeerMachineIdSha256 $peerMachineIdSha256 `
  -ExpectedCoordinatorUserSidSha256 $coordinatorUserSidSha256 `
  -ExpectedPeerUserSidSha256 $peerUserSidSha256 `
  -DisposableLabAccountAcknowledged `
  -PeerTcpPort 9462 -PeerUdpPort 9472 -PeerWebPort 9511 `
  -ClientTcpPort 9562 -ClientUdpPort 9572 -ClientWebPort 9611 `
  -FileSizeBytes 1073741824 `
  -FallbackLimitSeconds 10 `
  -ScenarioTimeoutSeconds 2700 `
  -RunNonce $runNonce
```

En modo `PowerShellRemoting`, además se requieren nombre/credencial del peer y
rutas remotas exactas para script, paquete, ZIP, output y coordinación. No usar
remoting si el transporte no conserva los mismos bytes y roots privados. El
mapa remoto y `MANUAL-PEER-COMMAND.txt` deben propagar obligatoriamente los tres
hashes; `run.json`, `peer-ready.json`, `peer-result.json` y el resumen privado
deben contener el mismo bundle derivado y `immutable_read_locks_held=true`.

## Adjudicación

Un `PASS` físico exige simultáneamente:

- paquete, ZIP, manifiesto, commit y binario exactos en ambos roles;
- bundle idéntico del harness principal, `common.ps1` y `prepare_node.ps1`,
  con sus tres hashes obligatorios, locks de lectura retenidos y la misma
  identidad en run, ready, result y summary;
- dos máquinas físicas y dos cuentas desechables ligadas a sus cuatro hashes;
- baseline IPv4 e IPv6 real al mismo peer HighID antes del DROP;
- boundary formal publicado y correlacionado por epoch/QPC;
- captura ETW consultada post-flush sin pérdidas ni wrap, sampler PID/socket con
  cobertura válida y parser PCAPNG completo, sin cola, truncados, linktypes o
  bloques/frames no adjudicables o parseados como `null`;
- inventario PktMon con exactamente los tres filtros del escenario: TCP IPv4 y
  TCP IPv6 ligados a sus IP/puerto, e ICMPv6 sin IP ni puerto, con el mismo
  SHA-256 de inventario armado y pre-stop;
- snapshots PCAPNG/socket de lectura única, con bytes, tamaño, SHA-256 y lock
  retenido ligados al mismo PID y boundary que el failure tipado;
- todos los frames objetivo pertenecen al `interface_id` ligado a la NIC física
  esperada; una interfaz ajena, virtual o ambigua bloquea el caso;
- snapshots HKCU y firewall global completos, estables e idénticos pre/post;
  además, firewall de escenario idéntico entre pre-boundary/post-observación
  del coordinador y armado/pre-removal del peer;
- clave `HKCU\...\Run` existente tanto en baseline como en postcheck, sin
  `eMuleAutoStart`, y recuento inicial de procesos eMule exactamente cero;
- snapshots de log v2 legibles, completos y adjudicables;
- exactamente un SYN IPv6 y un SYN IPv4 post-boundary, ambos ligados a la
  candidata por PID y 5-tupla, sin owner ajeno o ambiguo;
- silencio IPv6 completo durante `2750 ms`;
- primer SYN IPv4 en `2750 <= delta < min(limit, 8000)`, SYN/ACK y ACK final,
  con conexión completa antes del límite;
- exactamente un fallback acotado, HELLO, HELLOANSWER y transición A4AF;
- progreso esperado de los ficheros A/B y ausencia de retry tardío; y
- Job Object restringido ligado a la candidata, con límite activo uno,
  asignación antes de resume, accounting total uno/activo uno durante la
  ventana y activo cero en terminal; y
- cleanup terminal completo de los roots propios, registro intacto, firewall
  global intacto, ausencia censada de
  descendientes, jobs, captura, reglas firewall, sockets TCP/UDP, puertos,
  roots transitorios y bindings del candidato.

`FAIL` requiere evidencia tipada `ese.v91.i04-product-failure/v1`,
post-boundary, adjudicable y ligada al contrato de fuente aplicable, a la
identidad de la candidata y al trigger exactos. Cuando la fuente es red, también
debe estar ligada al PID, endpoint o 5-tupla correspondientes. Un string legacy,
tipo JSON coercible, evidencia de fuente inválida, owner no probado o timestamp
anterior al boundary es `BLOCKED`. Una vez probada, conserva
precedencia frente a un incidente de laboratorio posterior. Si ese incidente
contradice el origen, identidad o captura necesarios para probarla, el resultado
es `BLOCKED`, no `FAIL`.

Evidencia ausente, vieja, mal formada, log ilegible, reloj incoherente, flush o
consulta ETW fallidos, pérdida ETW, wrap, frame truncado/no soportado, interfaz
ajena, owner foráneo/ambiguo, respuesta IPv6, fixture no certificada, binding
roto o cleanup incompleto produce `BLOCKED`. Ninguna incertidumbre puede
convertirse en falso `PASS` o `FAIL`.

## P0 antes de autorizar la ventana física

Cualquiera de estos puntos es NO-GO:

- parser o test offline fallido, o dos runs no deterministas;
- paquete/ZIP/bundle/identidades/SID/puertos/roots no ligados exactamente;
- hash ausente o distinto para el harness, `common.ps1` o `prepare_node.ps1`,
  lock del bundle no probado o bundle desigual entre artefactos/roles;
- cuenta no desechable, hosts no físicos o identidades de máquina iguales;
- roots solapados, `eMuleAutoStart`/`ed2k` presentes al inicio, snapshot HKCU
  inestable, clave `Run` ausente pre/post, proceso eMule preexistente o
  firewall global no ligado;
- `ContractId` ausente o distinto en los helpers gestionados de COPYDATA, UI,
  ETW, sampler o launcher restringido;
- filtro PktMon ausente, duplicado o adicional, o contrato IP/protocolo/puerto
  no exacto;
- snapshot PCAPNG/socket releído, sin bytes/SHA-256/read lock o no ligado al
  PID, source kind y boundary exactos;
- drift del firewall de escenario en coordinador o peer que no fuerce
  `proof_contradicted/BLOCKED`;
- candidata fuera del Job Object restringido, asignada después de resume,
  accounting distinto de total uno/activo `1→0` o descendiente posible;
- overlay, proxy, túnel, NAT64, relay o dirección no nativa;
- preferencias no verificadas por lectura exacta;
- captura/sampler/reloj/log que pueda colapsar error a evidencia vacía;
- PCAPNG que pierda `interface_id`, acepte cola/truncado/linktype desconocido o
  trate un frame no adjudicable como silencio;
- pérdida ETW leída antes del flush o no confirmada después del flush;
- adjudicación que acepte más de un fallback, owner ajeno o tiempo fuera de
  `2750..<8000`;
- error privado o dirección/tuple/path/secreto en una proyección pública; o
- ownership, rollback de firewall o cleanup no resueltos.

## Retención y privacidad

`OutputRoot`, el nonce bajo `CoordinationRoot`, ETL, PCAPNG, logs, snapshots de
sockets, reglas, paths, IP, 5-tuplas, SID y detalles de error son evidencia
privada. Deben quedar fuera de Git, OneDrive público y shares con terceros.

Solo se puede exportar una proyección que haya pasado un validador público de
allowlist cerrada. No puede contener IP, endpoint, 5-tupla, hostname, GUID,
MachineGuid, SID en claro, username, path absoluto/UNC, `user_hash`, password,
token, cookie, autorización, excepción, mensaje libre, logs ni PCAP raw. Los
errores públicos se representan con códigos cerrados y digests. La proyección
admitida usa `ese.v91.i04-public-summary/v1`, se escribe como
`evidence\public-summary.json` y queda ligada al SHA-256 del resumen privado.

## Limitaciones P1

- El modo manual requiere dos consolas y coordinación humana; el remoting exige
  configuración previa y rutas remotas equivalentes.
- Un hard kill, reinicio o pérdida del share invalida la sesión. Aislar la
  evidencia y repetir con nonce, outputs y perfiles nuevos.
- El harness no borra la clave `Run` ni el subárbol `ed2k`. Solo admite que
  ambos permanezcan exactamente como en el snapshot inicial; cualquier cambio
  propio, concurrente o fallo de lectura bloquea la adjudicación.
- El DROP debe instalarse y retirarse en el peer exacto. Una regla previa,
  concurrente o cuyo ownership no pueda probarse bloquea el caso.
- Un `offline PASS` no valida NIC, firewall, ETW, scheduler, sockets, handshake,
  transferencia ni cleanup reales y nunca sustituye el soak físico.
