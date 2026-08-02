# V91-I03 - selección de ruta Auto/Preferred

## Estado y alcance

El harness físico está acompañado por una batería offline determinista. Un
`PASS` de `test_v91_i03_offline.ps1` autoriza a preparar la campaña física,
pero no ejecuta eMule, no consulta ni modifica la red y no demuestra una ruta
real. Por tanto:

- `offline PASS` significa **GO de preflight**;
- `offline FAIL` significa **P0 / NO-GO**; y
- V91-I03 continúa formalmente `BLOCKED` hasta completar la ejecución física
  en dos hosts y obtener su adjudicación terminal.

El objetivo físico es demostrar, sobre la misma candidata y el mismo peer
HighID dual-stack controlado, exactamente una conexión estable por política:

- `IPv6Mode=1` (`auto`): una conexión IPv4; y
- `IPv6Mode=2` (`preferred`): una conexión IPv6.

## Prerrequisitos físicos exactos

No se debe iniciar la campaña salvo que se cumpla todo lo siguiente:

1. Hay dos hosts Windows físicos distintos, controlados y dedicados a I03.
   Las dos consolas PowerShell están elevadas. Ningún O01, I05 u otro job usa
   los hosts, sus puertos o el directorio de coordinación. La lectura de
   `MachineGuid` y `Win32_ComputerSystem` funciona en ambos; no aparece ninguna
   firma de hipervisor o máquina virtual.
2. Cada host usa una **cuenta de laboratorio desechable**, nunca una cuenta
   personal. El operador conoce el SHA-256 del SID del usuario actual de cada
   host y acepta expresamente el binding mediante
   `-DisposableLabAccountAcknowledged` y
   `-ExpectedLabUserSidSha256`.
3. En `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` la clave `Run`
   existe, pero el valor `eMuleAutoStart` no existe. El subárbol
   `HKCU\Software\Classes\ed2k` tampoco existe. Un estado distinto es
   `BLOCKED`; el harness no debe limpiar datos preexistentes.
4. Ambos hosts tienen el mismo paquete limpio y congelado, y un ZIP candidato
   situado fuera del paquete. Coinciden exactamente commit, SHA-256 de
   `emule.exe`, SHA-256 y tamaño del ZIP, manifiesto extraído, número de
   ficheros y bytes. No se modifica el paquete durante la sesión.
5. `OutputRoot` y `CoordinationRoot` están fuera del paquete y del repositorio,
   son privados y no versionados. Cada `OutputRoot` está ausente o vacío; el
   directorio nonce de coordinación está ausente. Los dos hosts ven el mismo
   `CoordinationRoot` compartido y los mismos bytes de control.
6. El peer dispone de IPv4 pública HighID realmente enrutable, IPv4 local
   asignada e IPv6 global pública nativa. IPv4 e IPv6 pertenecen a la misma NIC
   física, no virtual y en estado `Up`. El coordinador también usa rutas
   físicas nativas para ambas familias.
7. No cuentan WARP, Tailscale, WireGuard, VPN, TAP, túnel, proxy, relay, NAT64,
   Teredo, 6to4, ISATAP, IP-HTTPS, ULA, link-local, IPv4-mapped IPv6 ni rangos
   de documentación o benchmark.
8. La topología es una de estas dos:

   - **T1**: identidades de máquina distintas, prefijo físico IPv4 compartido,
     prefijo físico IPv6 compartido y next hop IPv6 `on-link`.
   - **T2**: identidades de máquina distintas y ruta IPv6 global nativa
     enrutada mediante next hop link-local o global nativo.

9. Los nueve puertos elegidos son únicos y están libres tanto en TCP como en
   UDP, sin importar el estado TCP: TCP/UDP/Web del peer, del cliente Auto y
   del cliente Preferred. El puerto dinámico del servidor controlado queda
   fuera de ese conjunto, se vuelve a censar antes de certificar cada caso y
   no hay procesos eMule preexistentes.
10. Los relojes pueden certificarse a `<= 1000 ms` con el intercambio de cuatro
    timestamps `t0/t1/t2/t3`. Un timestamp mal formado, eco distinto, orden
    invertido, delay negativo o incertidumbre superior al límite bloquea I03.
11. Cada perfil de nodo es nuevo. El harness debe escribir y volver a leer las
    35 preferencias de arranque exactas antes del primer lanzamiento; sección
    errónea, clave duplicada o variante de mayúsculas/minúsculas es `BLOCKED`.
12. Cada nodo se prepara desde una instantánea congelada de
    `config\preferences.ini`. Un oráculo separado debe reproducir exactamente
    `RunId`, `NodeRole` y `PortOffset`, y certificar SHA-256 y tamaño de las
    preferencias resultantes antes del primer arranque. El resto del paquete
    inicial debe coincidir byte a byte; al terminar, todos los EXE, DLL y
    `BUILD_INFO` esperados deben seguir intactos y no puede aparecer ningún EXE
    o DLL no manifestado.

## Cálculo privado del binding de cuenta

Ejecutar este fragmento por separado en cada host. No copiar ni conservar el
SID en claro; solo se usa su digest local:

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $labSidSha256 = ([BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sid))
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
    Remove-Variable sid -ErrorAction SilentlyContinue
}
```

`$labSidSha256` puede ser distinto en Coordinator y Peer. No se debe reutilizar
el digest de un host en el otro.

## Ejecución offline

La batería offline valida los bytes y el parser del harness, funciones puras,
fixtures positivas y negativas, schemas cerrados, adjudicación, privacidad,
provenance y el wiring estático de preflight/ownership/cleanup. Es evidencia
válida para detectar una regresión y decidir el GO de preparación.

No valida NIC, rutas, reloj, sockets, PID, UI/API, transferencia o cleanup
reales. Esos hechos dependen de los dos hosts y solo los acredita la campaña
física; por eso un `PASS` offline no cambia el estado formal `BLOCKED`.

Desde la raíz del repositorio, en Windows PowerShell 5.1:

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\lab\test_v91_i03_offline.ps1
```

Ejecutar la orden dos veces sobre los mismos bytes. Ambas pasadas deben tener
parser limpio, cero `FAIL`, el mismo `test_count`, el mismo
`harness_sha256` y el mismo `result_sha256`. La salida declara siempre
`physical_execution_performed=false` y `formal_case_status=BLOCKED`. La suite
parsea una única instantánea de bytes y falla si el harness cambia durante la
pasada; no editar ninguno de los dos scripts mientras se ejecuta.

Checkpoint offline congelado el 2026-08-01 sobre los mismos bytes:

- run 1: `PASS`, `419/419`, `221.180 s`;
- run 2: `PASS`, `419/419`, `222.548 s`;
- suite SHA-256:
  `3decb7200c53a2799fa54b3a40b66a17c86ec248fbe64ace54a89887e5415d0a`;
- harness SHA-256:
  `03a63bde6c06b9838e30d27e4a0d421479227a61a4d11e63dc2a89bb06cd6fce`;
- resultado canónico SHA-256:
  `0586ff12543b82f9173ec96dd97d41847ba16d31db5c1988b191f7b57ec2b60f`.

Las dos salidas declaran `physical_execution_performed=false` y
`formal_case_status=BLOCKED`; este checkpoint no es un soak físico.

## Ejecución física

Elegir un nonce una sola vez y usarlo en ambos hosts:

```powershell
$runNonce = [Guid]::NewGuid().ToString('N')
```

Primero iniciar Coordinator. Sustituir rutas, direcciones y hashes por los
valores privados certificados del laboratorio:

```powershell
& .\tools\lab\test_v91_i03_route_selection.ps1 `
  -Role Coordinator `
  -PackagePath 'C:\lab\i03\package' `
  -CandidateZipPath 'C:\lab\i03\candidate.zip' `
  -ExpectedCandidateZipSha256 '<64-hex>' `
  -OutputRoot 'C:\lab-private\i03-coordinator-output' `
  -Commit '<40-hex>' `
  -ExpectedEmuleSha256 '<64-hex>' `
  -PeerIPv4 '<peer-public-ipv4>' `
  -PeerLocalIPv4 '<peer-assigned-local-ipv4>' `
  -PeerIPv6 '<peer-public-native-ipv6>' `
  -CoordinationRoot '\\lab-share\private\i03' `
  -ControlledPeerAcknowledged `
  -DisposableLabAccountAcknowledged `
  -ExpectedLabUserSidSha256 $labSidSha256 `
  -PeerTcpPort 9462 -PeerUdpPort 9472 -PeerWebPort 9511 `
  -AutoTcpPort 9562 -AutoUdpPort 9572 -AutoWebPort 9611 `
  -PreferredTcpPort 9662 -PreferredUdpPort 9672 `
  -PreferredWebPort 9711 `
  -FileSizeBytes 1073741824 `
  -PeerReadyTimeoutSeconds 300 `
  -CaseTimeoutSeconds 2400 `
  -StableObservationSeconds 5 `
  -RunNonce $runNonce
```

Después iniciar Peer con el mismo nonce, commit, hashes, endpoints, puertos y
directorio compartido. El paquete/ZIP y `$labSidSha256` son los valores locales
del Peer:

```powershell
& .\tools\lab\test_v91_i03_route_selection.ps1 `
  -Role Peer `
  -PackagePath 'C:\lab\i03\package' `
  -CandidateZipPath 'C:\lab\i03\candidate.zip' `
  -ExpectedCandidateZipSha256 '<64-hex>' `
  -OutputRoot 'C:\lab-private\i03-peer-output' `
  -Commit '<40-hex>' `
  -ExpectedEmuleSha256 '<64-hex>' `
  -PeerIPv4 '<peer-public-ipv4>' `
  -PeerLocalIPv4 '<peer-assigned-local-ipv4>' `
  -PeerIPv6 '<peer-public-native-ipv6>' `
  -CoordinationRoot '\\lab-share\private\i03' `
  -ControlledPeerAcknowledged `
  -DisposableLabAccountAcknowledged `
  -ExpectedLabUserSidSha256 $labSidSha256 `
  -PeerTcpPort 9462 -PeerUdpPort 9472 -PeerWebPort 9511 `
  -AutoTcpPort 9562 -AutoUdpPort 9572 -AutoWebPort 9611 `
  -PreferredTcpPort 9662 -PreferredUdpPort 9672 `
  -PreferredWebPort 9711 `
  -FileSizeBytes 1073741824 `
  -PeerReadyTimeoutSeconds 300 `
  -CaseTimeoutSeconds 2400 `
  -StableObservationSeconds 5 `
  -RunNonce $runNonce
```

Coordinator también escribe una copia privada de la orden Peer exacta. No se
debe ejecutar un comando recuperado de una sesión anterior.

## Adjudicación

Un `PASS` físico exige simultáneamente:

- binding exacto del paquete, ZIP, manifiesto, commit y binario en ambos hosts;
- cuenta desechable y SID-hash exactos en ambos roles;
- topología T1 o T2 nativa, dos máquinas distintas y reloj certificado;
- baseline dual-stack correlacionado en ambos extremos;
- prewarm IPv4 probado mediante HELLO ligado al servidor controlado: ausencia
  del log esperado es `PRODUCT_INVARIANT/IPV4_PREWARM_INVARIANT`, mientras que
  un fallo al enumerar o leer logs es un incidente de colector y deja el caso
  `BLOCKED`;
- Auto con exactamente una IPv4 estable y Preferred con exactamente una IPv6
  estable, sin selección ambigua, ruta anterior, familia errónea ni ventana
  estable corta;
- socket actual atribuido al PID, tiempo de inicio, path-hash y EXE-hash de la
  candidata, más atribución inversa exacta al proceso Peer;
- censo TCP/UDP completo del proceso candidato, ligado al PID exacto y sin
  listeners, estados ni destinos de terceros fuera de la allowlist del caso;
- UI/API sanas y aislamiento efectivo de Kad, NetLab, proxy, DNS y servidores
  externos; y
- cleanup terminal probado: procesos/descendientes fuera, listeners y tuples
  fuera, nueve puertos TCP/UDP libres, paquete/ZIP intactos, registro restaurado
  exactamente y digests de adaptadores, rutas, DNS, hosts y firewall iguales.

`FAIL` solo puede proceder de un registro `PRODUCT_INVARIANT` tipado, ligado al
caso/nonce/rol/política/candidata y a una prueba fuente cuyo binding sea de
confianza, después de certificar la fixture. Un fallo de producto válido en
Coordinator o Peer conserva precedencia `FAIL` aunque después ocurra un
incidente de lab o cleanup.

Evidencia ausente, vieja, ambigua, mal formada, no ligada, collector fallido,
topología/reloj no certificados o cleanup incompleto producen `BLOCKED`, nunca
un falso `PASS` o `FAIL`.

## P0 antes de autorizar la ventana física

Cualquiera de estos puntos es NO-GO:

- parser o test offline fallido, o dos runs offline no deterministas;
- proyección pública que no pasa su validador de privacidad allowlist;
- paquete/ZIP/SID/cuenta/puertos/topología/reloj no certificados;
- OutputRoot o CoordinationRoot reutilizado, público, dentro del paquete o del
  repositorio;
- colector que colapsa error a lista vacía o evidencia de socket ambigua;
- cualquier proceso eMule previo o contaminación externa; o
- planner de registro, ownership de procesos o prueba de cleanup no resueltos.

## Retención y privacidad

Todo `OutputRoot` y el directorio nonce bajo `CoordinationRoot` son evidencia
operativa **privada**. Deben permanecer fuera de Git, sincronización pública y
directorios compartidos con terceros. Conservarlos con acceso restringido
hasta cerrar la campaña; después aplicar la política local de laboratorio.

Dentro de cada `OutputRoot`, `private\summary.json`, `private\cleanup.json`, el
manifiesto privado y el resto de capturas son privados. La única zona
exportable es `evidence\`, y solo después de completar el validador: debe
contener exactamente `summary.json` y `evidence-manifest.json`. Cualquier otro
fichero público, campo adicional o tipo inesperado invalida la exportación.

Solo se puede compartir una proyección que haya pasado el validador público
allowlist. Puede contener schemas, estado, códigos cerrados, contadores,
booleanos, tamaños y digests criptográficos necesarios. No puede contener:

- `user_hash` bruto ni su valor estable de perfil;
- IP, endpoint, tuple, MAC, GUID o nombre de interfaz;
- SID en claro, nombre de usuario/equipo o ruta absoluta/UNC;
- password, token, cookie, cabecera de autorización, clave privada o secreto;
- texto de excepción, logs brutos o contenido del fichero transferido.

El SID se liga únicamente mediante SHA-256. Los mensajes de fallo se conservan
como digest; los paths, endpoints y snapshots detallados permanecen en la zona
privada. No copiar `summary.json` u otro artefacto operativo como si fuera una
salida pública sin validarlo primero.

## Limitaciones P1

- La campaña requiere dos consolas y un share privado; no hay orquestación
  remota automática de ambos roles.
- No existe TTL/scavenger automático para OutputRoot, coordinación o evidencia
  privada. La caducidad y eliminación son operativas.
- Un hard kill, reinicio o corte de energía puede dejar procesos, perfiles,
  coordinación o una transacción activa huérfanos. No se debe reanudar ni
  adjudicar esa sesión: aislar evidencia, verificar el host manualmente y
  repetir con cuenta desechable, roots y nonce nuevos.
- La restauración de registro solo puede borrar el valor `eMuleAutoStart`
  creado por la ejecución cuando tipo y data coinciden con el hash allowlisted.
  Nunca borra la clave `Run` ni restaura destructivamente `ed2k`; una escritura
  concurrente convierte el resultado en `BLOCKED`.
