# v0.70b-eSE9.0.0-beta.1

Fecha de corte prevista: 2026-07-17.

Esta es una **beta pública para validación**, no la versión estable. Este documento
define el alcance prometido; la beta no se considera publicada hasta que el tag,
`BUILD_INFO.txt`, el ZIP y su checksum apunten al mismo SHA limpio y estén cerrados
los gates bloqueantes de `V9_RELEASE_MASTER_CHECKLIST.md`.

## Qué incluye la beta

- Compatibilidad eD2K/Kad y LiveTV de v8.1, con correcciones del cierre de sesión,
  identidad eD2K y ciclo punch2 `ACK -> uTP`.
- Keepalive Kad R.2, reachability D5/D6, detección IPv6 in-band y fallback v4,
  condicionados a sus pruebas físicas documentadas.
- Túnel autenticado, Bulk/FEC, límites antiabuso y kill switches, condicionados a
  los gates de red del candidato.
- Dashboard y API local con autenticación, observabilidad y administración remota
  cerrada por defecto.
- Cohorte opcional `ESE_NETLAB_V1`: el primer inicio solicita aceptación explícita
  antes de anunciar participación. Si se acepta, usa únicamente descargas y
  emisiones reales para pruebas limitadas con otros participantes de la beta.
- Paquete reproducible con FFmpeg/ffprobe fijados por SHA-256, registro de protocolo,
  manifiesto por fichero y checksum externo del ZIP.

Si una ruta BASE no supera su gate antes del tag, se demota explícitamente a LAB/OFF;
no se publica parcialmente ni se debilita el criterio de aceptación.

## Funciones experimentales que permanecen OFF

- Punch3 y predicción de puerto anti-CGNAT.
- KRP relay y su plano de datos experimental.
- Kad6 Rev3, gateway y public exit.
- Rutas/cohortes experimentales que no tengan acta física PASS.

La presencia de código experimental en el binario no equivale a soporte público. Con
las puertas apagadas no debe anunciar capability, responder al protocolo experimental
ni abrir una salida pública.

## Defaults seguros del perfil nuevo

El paquete crea estas preferencias en `0`:

```ini
[WebServer]
WebUseUPnP=0

[eSE]
EseNetLabConsent=0
EseNetLabEnabled=0
EseV9Experimental=0
EseKad3Rendezvous=0
EseAutoKeepalive=0
EseRelayAccept=0
EseRelayEgress=0
EseReachSelector=0
EseHolePunchPortPredict=0
EseEd2kPunch3=0
Kad6PublicExitOptIn=0

[KRPRelay]
KrpRelayEnabled=0
KrpRelayKillSwitch=0
ExperimentalTcpDataPlane=0
```

El servidor web no se publica mediante UPnP y no acepta administración remota sin
autenticación. No reutilice un perfil de laboratorio para evaluar estos defaults.

## Cohorte NetLab y activación controlada

Instalar la beta no equivale a participar. En el primer inicio se muestra un aviso
con elección Sí/No; hasta aceptar, el cliente no anuncia `ESE_NETLAB_V1` ni realiza
intentos automáticos de la cohorte. La participación base puede apagarse de inmediato
desde el dashboard o desde la máquina local:

```text
http://127.0.0.1:4711/api/ese/v9?on=0
```

Tras haber aceptado el aviso, puede reactivarse la capa base con:

```text
http://127.0.0.1:4711/api/ese/v9?on=1
```

La capa base cubre IPv6 Auto, mappings existentes, keepalive y punch2 sobre intentos
naturales; no hace escaneos aleatorios. Punch3, predicción y selector siguen
escalonados y OFF. Relay, donación de ancho de banda, KRP y Kad6 public exit requieren
autorizaciones independientes y no se encienden ni se apagan con este endpoint.

El dashboard muestra el estado, ofrece desactivación inmediata y permite copiar un
informe local saneado. El informe no incluye IP completa ni se sube mediante
telemetría central implícita.

## Límites y claims que esta beta no hace

- No se declara que LowID haya desaparecido en cualquier NAT o CGNAT.
- No se declara soporte IPv6 completo en todos los sockets y topologías.
- No se promete High ID universal ni relay público general.
- Kad6 public exit y KRP permanecen cerrados.
- No se ofrece anonimato fuerte ni resistencia demostrada frente a adversarios.
- Los resultados de una topología no se extrapolan a NAT simétrica, doble NAT,
  IPv6-only u otros ISP sin evidencia separada.

## Compatibilidad y datos

Antes de publicar se prueba beta frente a eSE 8.1.0 y eMule vanilla 0.70b, además de
upgrade y rollback con copia del perfil. Haga copia de `config`, ficheros `.met`,
preferencias y claves antes de probar. No comparta un perfil simultáneamente entre
beta y una versión anterior.

## Rollback

1. Desactive la puerta maestra con `/api/ese/v9?on=0`.
2. Desactive por separado KRP, relay, Kad6 y cualquier ruta LAB activada.
3. Cierre eMule y conserve `ese-live.log`, `preferences.ini` y los logs del gate.
4. Restaure la copia del perfil y vuelva a eSE 8.1.0 si aparece corrupción o una
   regresión bloqueante.
5. No reutilice como perfil limpio uno que haya activado experimentos.

## Cómo reportar un fallo

Incluya siempre:

- tag y SHA de `BUILD_INFO.txt` y SHA-256 del ZIP;
- Windows, CPU/GPU y versión del driver cuando intervenga LiveTV;
- número de PCs, ISP, topología, IPv4/IPv6 y tipo de NAT;
- preferencias v9 activadas y estado de cada kill switch;
- pasos, hora exacta, resultado esperado/real y si el fallo se reproduce;
- `ese-live.log`, logs de eMule y captura `/api/status`, eliminando claves, tokens,
  hashes privados y direcciones que no desee publicar.

La evidencia consolidada de aceptación se registra en
`V9_RELEASE_MASTER_CHECKLIST.md`; un PASS verbal no promociona el candidato.
