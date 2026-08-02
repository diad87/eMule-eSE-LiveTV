# V91-D01 - DNS dual A+AAAA con fallback al candidato A

## Estado y alcance

V91-D01 dispone de una bateria offline determinista para revisar los bytes y el
parser del harness, sus contratos puros de contadores y evidencia inmutable, y
el wiring AST del rollback global de PktMon. Un `offline PASS` significa **GO de
preflight**: permite preparar la ventana fisica, pero no ejecuta eMule, no abre
sockets, no consulta DNS y no inicia PktMon o ETW.

El caso conserva siempre `formal_case_status=BLOCKED` hasta completar una
campana fisica valida en dos hosts Windows. La bateria offline declara
explicitamente:

```text
schema=ese.v91.d01-offline-selftest/v1
case_id=V91-D01
physical_execution_performed=false
formal_case_status=BLOCKED
```

El objetivo fisico es demostrar que un unico enlace con hostname controlado y
respuestas A+AAAA simultaneas conserva ambos candidatos, intenta el AAAA sobre
IPv6 nativa silenciosamente descartada y completa el mismo fichero por A/IPv4,
con atribucion exacta a PID, adaptador, 5-tupla, evento de telemetria y captura
sin perdida.

## Ejecucion offline

Desde la raiz del repositorio, en Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\lab\test_v91_d01_offline.ps1
```

La suite realiza exactamente una lectura `ReadAllBytes` del harness, calcula el
SHA-256 sobre ese array y parsea exclusivamente el texto obtenido de esa
instantanea. Las funciones puras se extraen desde el AST mediante una allowlist
cerrada y se ejecutan en scopes aislados con helpers locales de hash. Las
funciones de procesos, PktMon, ETW, driver, firewall y roles fisicos solo se
inspeccionan como AST; nunca se extraen ni se ejecutan.

Las unicas escrituras de la suite son fixtures JSON dentro de un directorio
temporal unico, eliminado y verificado al terminar. La suite no dot-sourcea ni
invoca `test_v91_d01_dual_dns.ps1`, no ejecuta C# y no inicia procesos hijos,
eMule, PktMon, ETW, red, firewall o registro.

La matriz offline cubre especificamente los tres cierres finales:

1. Binding objeto -> JSON `ConvertTo-Json -Depth 48` -> UTF-8 sin BOM ->
   longitud/SHA-256/archivo congelado. Incluye positivos y mutaciones de objeto,
   bytes, longitud, digest, lock y metadata.
2. Para cada contador `Type='Descartes'`, `Counter.Name` debe ser exactamente
   igual a `Component.Name`, tanto en el parser como en el revalidador. Un
   contador `Flujos` conserva su identidad independiente. Hay fixtures validas,
   mismatch y mismatch solo por mayusculas/minusculas.
3. El cleanup pendiente se registra antes de la primera mutacion, conserva el
   mismo estado y ledger de fallos, retorna antes de cruzar operaciones si el
   ledger no esta quiescent, se reintenta en el `finally` exterior solo despues
   de probar quiescence, se vuelve a censar y bloquea el unico commit mientras
   siga pendiente. Mutaciones AST separadas eliminan cada guard y deben ser
   rechazadas. Tambien se exige una sola invocacion `reset` y una sola
   eliminacion global de filtros.

Ejecutar dos veces sobre los mismos bytes congelados. Ambas pasadas deben tener
exit code cero, parser limpio, `fail_count=0` y los mismos `test_count`,
`harness_sha256` y `result_sha256`. Antes y despues de cada pasada deben
permanecer estables los SHA-256 de la suite y del harness.

## Checkpoint offline

No publicar un freeze fisico con un solo run. El checkpoint se completa solo
despues de dos pasadas identicas y una auditoria estatica independiente.

Checkpoint reproducible congelado el 2026-08-01:

- harness SHA-256:
  `887be972c31f0a6973d702cd402e1c01fb6725d8b27f0ee6ee9e0fa47a5de0fc`;
- suite offline SHA-256:
  `9136b0fdb870470bab02bb46b46aea45e132af5174cfcdf93e176030d31dcbec`;
- run 1: exit code `0`, `35/35 PASS`, `fail_count=0`, `76.687 s`,
  `physical_execution_performed=false`, `formal_case_status=BLOCKED`;
- run 2: exit code `0`, `35/35 PASS`, `fail_count=0`, `75.575 s`,
  `physical_execution_performed=false`, `formal_case_status=BLOCKED`; y
- resultado canonico SHA-256:
  `79b2cba8ef4c63765e72199aaa254342f2bf2247ff7c43d6b2b9ba2f90e3160f`.

Aunque el checkpoint sea reproducible, sigue siendo evidencia de preflight y
no una ejecucion fisica: `physical_execution_performed=false` y
`formal_case_status=BLOCKED`.

## Prerrequisitos fisicos exactos

No iniciar la campana salvo que se cumpla todo lo siguiente:

1. Hay dos hosts Windows fisicos distintos, dedicados a D01, con PowerShell
   elevado y cuentas de laboratorio desechables. No comparten ventana, puertos,
   roots, firewall, ETW o PktMon con O01, I03, I04, I05 u otro job.
2. Ambos hosts tienen el mismo paquete limpio y congelado y el mismo ZIP
   candidato situado fuera del paquete. Coinciden commit, SHA-256 de
   `emule.exe`, SHA-256 del ZIP, manifiesto y contenido extraido.
3. `OutputRoot`, `CoordinationRoot`, paquete, ZIP y repositorio son roots
   canonicos disjuntos, sin relacion padre/hijo ni reparse points. Los outputs
   estan ausentes o vacios y el nonce no se reutiliza.
4. Los SHA-256 de `MachineGuid` y del SID actual de Coordinator y Source son
   conocidos por canal privado, distintos entre hosts y se pasan mediante los
   cuatro parametros `Expected*Sha256`.
5. El hostname es un A-label ASCII controlado. Su respuesta estable contiene
   exactamente un A igual a `SourcePublicIPv4` y un AAAA igual a `SourceIPv6`.
   No se cambia zona, TTL, resolver o cache durante la observacion.
6. Source dispone de IPv4 publica HighID realmente enrutable, IPv4 local
   asignada e IPv6 global publica nativa. Coordinator tambien dispone de IPv4
   publica/local e IPv6 global nativa. La topologia observada debe ser T1 o T2
   sobre NIC fisicas `Up`, sin VPN, overlay, proxy, tunnel, relay o traduccion.
7. Source puede instalar transaccionalmente el `DROP` inbound TCP IPv6 exacto
   para programa, direccion y puerto controlados sin RST/REJECT, mientras el
   forward IPv4 sigue operativo.
8. Los seis puertos TCP/UDP/Web son unicos y estan libres en cualquier estado
   TCP y en UDP. No hay procesos eMule preexistentes.
9. El operador acepta expresamente el fixture controlado, las cuentas
   desechables y el control global exclusivo de PktMon. No existe ningun otro
   `pktmon.exe`, filtro, sesion ETW/provider, llamada a `pktmonapi.dll` o IOCTL
   que pueda mutar driver, filtros o contadores.
10. La tupla binaria auditada de `pktmon.exe`, `pktmonapi.dll`, `pktmon.sys` y
    MUI coincide exactamente con la allowlist del harness. El driver esta
    inactivo en su configuracion baseline, la sesion `PktMon` no existe, el
    inventario global de filtros esta vacio y todos los contadores globales
    estan a cero antes de START.
11. El ETL circular tiene capacidad suficiente; todas las consultas ETW
    terminan con cero eventos/buffers perdidos y sin wrap. El ledger de procesos
    confiables conserva handles, PID, tiempo de inicio, ruta y hash exactos.
12. Kad, servidores de terceros, proxy, UPnP, relay, NetLab y autostart estan
    desactivados. Solo existe el servidor controlado local y una unica inyeccion
    de enlace con hostname.
13. El endpoint local `/api/debug/source-resolutions` esta disponible y expone
    el schema esperado. API y UI permanecen responsivas durante toda la ventana.
14. El operador reserva la ventana completa y no interrumpe consolas, procesos,
    captura, DNS o share hasta que ambos roles publiquen cleanup terminal.

## Bindings privados de host y cuenta

Ejecutar por separado en cada host y conservar solo los digests:

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

No publicar SID o `MachineGuid` en claro. Registrar por canal privado los dos
digests de Coordinator y los dos de Source.

## Ejecucion fisica manual

Congelar primero los valores comunes en ambos hosts:

```powershell
$harness = '.\tools\lab\test_v91_d01_dual_dns.ps1'
$runNonce = [Guid]::NewGuid().ToString('N')
$package = 'D:\ese-v91-candidate'
$zip = 'D:\ese-v91-candidate.zip'
$coordination = '\\labshare\ese-v91-d01'
$commit = '<40-hex>'
$emuleSha256 = '<64-hex>'
$zipSha256 = '<64-hex>'
$hostname = 'dualstack-fixture.example.net'
$sourcePublicV4 = '<public-v4>'
$sourceLocalV4 = '<local-v4>'
$sourceV6 = '<native-global-v6>'
$coordinatorPublicV4 = '<public-v4>'
$coordinatorLocalV4 = '<local-v4>'
$coordinatorV6 = '<native-global-v6>'
$coordinatorMachine = '<64-hex>'
$sourceMachine = '<64-hex>'
$coordinatorSid = '<64-hex>'
$sourceSid = '<64-hex>'
```

Iniciar primero Coordinator:

```powershell
& $harness -Role Coordinator `
  -PackagePath $package -PackageZipPath $zip `
  -OutputRoot 'D:\ese-v91-d01-coordinator' `
  -CoordinationRoot $coordination -RunNonce $runNonce `
  -Commit $commit -ExpectedEmuleSha256 $emuleSha256 `
  -ExpectedPackageZipSha256 $zipSha256 -Hostname $hostname `
  -SourcePublicIPv4 $sourcePublicV4 -SourceLocalIPv4 $sourceLocalV4 `
  -SourceIPv6 $sourceV6 `
  -CoordinatorPublicIPv4 $coordinatorPublicV4 `
  -CoordinatorLocalIPv4 $coordinatorLocalV4 `
  -CoordinatorIPv6 $coordinatorV6 `
  -ExpectedCoordinatorMachineIdSha256 $coordinatorMachine `
  -ExpectedSourceMachineIdSha256 $sourceMachine `
  -ExpectedCoordinatorUserSidSha256 $coordinatorSid `
  -ExpectedSourceUserSidSha256 $sourceSid `
  -ControlledFixtureAcknowledged `
  -DisposableLabAccountAcknowledged `
  -ExclusivePktmonDriverControlAcknowledged
```

Cuando Coordinator este esperando el barrier, iniciar Source con los mismos
valores y nonce:

```powershell
& $harness -Role Source `
  -PackagePath $package -PackageZipPath $zip `
  -OutputRoot 'D:\ese-v91-d01-source' `
  -CoordinationRoot $coordination -RunNonce $runNonce `
  -Commit $commit -ExpectedEmuleSha256 $emuleSha256 `
  -ExpectedPackageZipSha256 $zipSha256 -Hostname $hostname `
  -SourcePublicIPv4 $sourcePublicV4 -SourceLocalIPv4 $sourceLocalV4 `
  -SourceIPv6 $sourceV6 `
  -CoordinatorPublicIPv4 $coordinatorPublicV4 `
  -CoordinatorLocalIPv4 $coordinatorLocalV4 `
  -CoordinatorIPv6 $coordinatorV6 `
  -ExpectedCoordinatorMachineIdSha256 $coordinatorMachine `
  -ExpectedSourceMachineIdSha256 $sourceMachine `
  -ExpectedCoordinatorUserSidSha256 $coordinatorSid `
  -ExpectedSourceUserSidSha256 $sourceSid `
  -ControlledFixtureAcknowledged `
  -DisposableLabAccountAcknowledged
```

No reutilizar output ni nonce. No cerrar ninguna consola hasta que el cleanup y
los recibos terminales esten publicados.

## Adjudicacion

Un `PASS` fisico exige simultaneamente:

- fixture T1/T2, identidades, roots, paquete/ZIP, DNS A+AAAA y aislamiento
  exactos;
- una unica inyeccion de hostname y un unico fichero;
- evento local de telemetria que conserva simultaneamente los candidatos A y
  AAAA con hashes canonicos exactos;
- intento AAAA/IPv6 atribuible al PID y adaptador, sin respuesta correlacionada;
- forward y transferencia completa por A/IPv4 con hash final exacto;
- captura PktMon/ETW sin perdida, contadores y evidencia congelada ligados al
  objeto publicado;
- reset global unico despues de congelar evidencia final, recenso post-reset y
  precommit iguales al baseline cero;
- driver, sesion ETW, filtros, contadores, procesos, firewall, registro y hosts
  restaurados y probados terminalmente; y
- API/UI responsivas y candidata/ZIP inmutables hasta el commit.

`FAIL` se reserva para una falla de producto tipada, source-bound y observada
despues del boundary con fixture y observabilidad completas. Cualquier fixture
incompleto, collector ambiguo, perdida, drift, cleanup incompleto o falta de
evidencia produce `BLOCKED`, nunca un falso `PASS` o `FAIL`.

Los exit codes fisicos son `0=PASS`, `1=FAIL` y `2=BLOCKED`.

## P0 antes de autorizar la ventana fisica

No ejecutar si ocurre cualquiera de estas condiciones:

- parser o suite offline fallidos, o dos runs offline no deterministas;
- SHA-256 de suite/harness distinto del checkpoint auditado;
- hostname, A o AAAA fuera del conjunto controlado exacto;
- host virtual, overlay/VPN/proxy/tunnel o topologia fuera de T1/T2;
- paquete/ZIP/identidad/cuenta/root/nonce no ligados exactamente;
- eMule, PktMon, ETW, filtro, driver o contador global preexistente;
- tupla binaria PktMon fuera de la allowlist auditada;
- imposibilidad de garantizar control exclusivo global de PktMon;
- puertos ocupados, DROP IPv6 no silencioso o forward IPv4 no probado; o
- imposibilidad de completar y verificar rollback terminal.

## Retencion y privacidad

Conservar los outputs privados de ambos roles, el directorio nonce de
coordinacion, ETL/PCAPNG, inventarios, snapshots de contadores, hashes de
precommit y recibos terminales hasta terminar la auditoria. No publicar paths
locales, IP privadas, SID, `MachineGuid`, credenciales, payloads, logs brutos o
detalles de cuenta. La proyeccion publica debe respetar su allowlist y quedar
ligada por SHA-256 al resumen privado.

## Limitaciones P1

- Un `offline PASS` no prueba DNS real, NIC, rutas, firewall, sockets, PID,
  PktMon, ETW, telemetria, transferencia o cleanup fisicos.
- La suite offline solo acredita los bytes congelados indicados por
  `harness_sha256`; cualquier cambio exige repetir dos runs y la auditoria.
- El contrato privado de PktMon es valido unicamente para la tupla binaria y ABI
  exactas codificadas en el harness.
- El control global exclusivo es una precondicion operacional; una aplicacion o
  usuario externo que muta PktMon invalida la campana y fuerza `BLOCKED`.
- D01 permanece formalmente `BLOCKED` hasta disponer de dos hosts fisicos con
  IPv4 publica, IPv6 publica nativa y DNS A+AAAA estable controlado.
