# IPv6 dual-stack: checklist de beta 2

Este documento es la lista de salida de la implementación IPv6. La regla de
compatibilidad es estricta: IPv4 sigue siendo el formato heredado por defecto,
los peers antiguos siguen funcionando y ningún endpoint IPv6 se convierte en
una identidad IPv4 sintética en un paquete antiguo.

## Contrato de compatibilidad

- `CAddress` conserva IPv4 y añade IPv6 con familia, longitud y bytes explícitos.
- Los opcodes heredados no cambian de tamaño ni de significado.
- Los formatos aditivos (`OP_CALLBACK_V6`, `OP_LIVE_PEER_LIST_V2` y tags IPv6)
  solo se envían cuando el receptor anuncia capacidad; un peer antiguo recibe
  exactamente el flujo IPv4 anterior.
- La escucha intenta primero un socket dual `AF_INET6` (`V6ONLY=0`) y cae a
  `AF_INET` si el sistema no lo permite. Desactivar IPv6 conserva IPv4 puro.
- Las búsquedas de hostname usan `AF_UNSPEC` y prueban AAAA y A; un AAAA
  válido conserva su dirección nativa y no se guarda como `uint32` real.
- Búsqueda de cliente, bans, fuentes muertas, deduplicación y rutas de conexión
  distinguen `(CAddress, puerto)`. El `uint32` sintético solo sirve como puente
  interno para estructuras heredadas y no cruza wire, seguridad ni Kad3.
- SOCKS5 usa `ATYP=4`; HTTP CONNECT encierra IPv6 entre corchetes; SOCKS4
  rechaza IPv6 explícitamente en vez de truncarlo o recodificarlo.

## Estado de las 13 fases

1. Línea base IPv4 y detección dual: completada.
2. `CAddress` y conversiones seguras: completada.
3. Wire heredado y formatos IPv6 aditivos: completada.
4. Endpoint dual de `CUpDownClient` y fallback: completada.
5. ClientList, bans, fuentes muertas y deduplicación: completada.
6. TCP entrante, saliente y callback IPv6: completada.
7. UDP/Kad/firewall/uTP sin identidades sintéticas: completada para los
   formatos heredados; los servicios Kad6 siguen usando sus propios records.
8. Proxy SOCKS/HTTP y DNS `AF_UNSPEC`: completada.
9. Fuentes, UI, enlaces ED2K y resolución AAAA: completada.
10. Extensiones de protocolo y persistencia retrocompatible: completada.
11. Auditoría de usos peligrosos de `uint32`: completada en las rutas de red,
    seguridad, crédito, fuentes y Live revisadas.
12. Preferencias, fallback y observabilidad: completada.
13. Documentación y criterios de beta: este documento y la matriz siguiente.

## Matriz manual obligatoria

| Caso | Resultado esperado |
|---|---|
| IPv4 solamente | Escucha, conexión, Kad, Live y proxy igual que antes. |
| IPv6 solamente | `CAddress` nativa, TCP directo y fuentes AAAA funcionan; no aparece una IPv4 falsa en wire, bans ni diagnósticos. |
| Dual-stack | Se conserva IPv4 como fallback y se prefiere IPv6 cuando la ruta y el peer son utilizables. |
| Hostname A + AAAA | Se prueban ambas familias; si AAAA falla, A sigue funcionando. |
| `[2001:db8::10]:4662` | Se acepta en enlaces y diálogo de fuentes; el puerto no se pierde. |
| SOCKS5 IPv6 | La petición contiene `ATYP=4` y 16 bytes de dirección. |
| Proxy HTTP IPv6 | `CONNECT [2001:db8::10]:4662` conserva los corchetes. |
| Peer antiguo | Solo recibe opcodes/tags IPv4 heredados y sigue conectando. |
| Peer nuevo IPv6 | Recibe V2/callback IPv6 y se deduplica por dirección+puerto. |
| Live con peer IPv6 | La lista V2 conserva la dirección nativa; el diagnóstico `/api/live/privacy/peers` no muestra el ID IPv4 sintético. |

## Decisión de privacidad Live

El cuerpo histórico del túnel Live (`TUN_OP_LIVE_PEER_LIST` y el subscribe
heredado) es IPv4-only. En modo estricto no se degrada silenciosamente: una
fuente IPv6 se omite y se registra como bloqueo fail-closed. En modos no
estrictos se usa conexión IPv6 directa y se registra el fallback. Esto evita
filtrar la IP del visor por accidente; para una futura beta que exija túnel
IPv6 estricto habrá que añadir un opcode de subscribe/lista V2 y su autorización
Kad6 correspondiente, con una matriz de interoperabilidad propia.

## Pruebas reproducibles

Desde la raíz del repositorio:

```powershell
& .\tools\run_alpha_tests.ps1 -Suite Core
& .\tools\run_alpha_tests.ps1 -Suite Integration
& 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe' .\srchybrid\emule.sln /m:1 /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /t:Build /v:minimal
```

La salida automatizada debe ser cero errores y las pruebas de wire IPv6 deben
informar `6/6`, `5/5` y `2/2` en sus respectivos bloques. La etiqueta beta 2
solo debe publicarse después de ejecutar además la matriz manual con dos nodos
IPv4, dos IPv6 y un peer antiguo.
