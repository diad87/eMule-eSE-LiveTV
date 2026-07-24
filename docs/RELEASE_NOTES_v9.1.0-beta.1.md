# eMule eSE 9.1.0-beta.1

Status: **beta pública de laboratorio para Windows x64**.

Esta es la primera beta de la serie 9.1. Promociona el transporte IPv6 y el
cliente Kad6 a una superficie utilizable entre peers eSE, pero no es todavía
el RC ni afirma compatibilidad con todos los ISP, routers, proxies o escenarios
IPv6-only.

## Cambios principales

### IPv6 y Kad6

- Kad2 y Kad6 siguen seleccionados por defecto en perfiles nuevos
  (`KadNetworkMask=3`), con estado y persistencia separados.
- Listener dual-stack con fallback IPv4 y respeto del `BindAddr` IPv4
  configurado: IPv6 no amplía silenciosamente la escucha a otras interfaces.
- Fuentes, conexiones directas y listas de peers LiveTV conservan los 128 bits
  de la dirección.
- El direct-join LiveTV acepta un endpoint nativo `[IPv6]:puerto`, permitiendo
  aislar y medir el plano de vídeo sin un bootstrap ni fallback IPv4.
- `OP_LIVE_PEER_LIST_V2` implementa el campo `Score` definido por el wire y
  mantiene lectura compatible con el borrador emitido por beta.2.
- `OP_CALLBACK_V6` exige negociación, longitud exacta y un endpoint previamente
  conocido; un buddy no puede provocar una conexión a un destino arbitrario.
- SOCKS5 y HTTP CONNECT admiten destinos IPv6; SOCKS4/4A los rechazan
  explícitamente.
- Las respuestas SOCKS5 de longitud variable usan bytes sin signo y un BIND
  no compatible se rechaza sin reinterpretar memoria como IPv4.
- Una dirección IPv4 de bind explícita conserva el comportamiento IPv4 puro.

### Equidad, identidad y antiabuso

- Un peer IPv6 nuevo ya no recibe antigüedad artificial en la cola de subida.
- Los peers IPv6-only usan espera local neutral y no reciben multiplicador de
  créditos IPv4.
- Bans, historial de hashes y peticiones incorrectas usan la dirección nativa,
  nunca el `uint32` sintético.
- El límite anti-Sybil de la cola se aplica por `/64` en IPv6.
- Se restauró la política de eMule 0.70b para archivos de la cola de descarga:
  solo un archivo completo de una parte puede responder como fuente.

### Laboratorio con consentimiento explícito

El primer arranque ofrece tres decisiones independientes:

1. **Base**: mediciones limitadas de IPv6, LowID, Punch2 y CGNAT con otros
   participantes de la beta.
2. **Avanzado**: Punch3, predicción acotada de puertos, selector de ruta,
   funciones avanzadas de Kad6, túneles autenticados, Bulk y FEC. El cliente
   Kad6 nativo conserva su selección de red independiente.
3. **Contribución**: relay Live y Kad6 Beta Exit; KRP solo si el paquete dispone
   además de endpoint, CA y token válidos.

Rechazar o no contestar deja cada nivel apagado. El apagado general persiste y
detiene todos los niveles. Kad6 Beta Exit no sustituye el gate firmado de una
salida pública estable.

El paquete se entrega con estos valores cerrados:

```ini
[eSE]
EseNetLabConsent=0
EseNetLabAdvancedConsent=0
EseNetLabContributionConsent=0
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
Kad6BetaExitOptIn=0

[KRPRelay]
KrpRelayEnabled=0
KrpRelayKillSwitch=1
ExperimentalTcpDataPlane=0
```

No se sube telemetría automáticamente. El informe NetLab permanece local y
está saneado.

### Relay y reconexión

- La cola de envío Live se limita por peer: un receptor lento pierde chunks
  recuperables en vez de hacer crecer la RAM sin límite.
- El throttle de ratio libera el paquete rechazado y evita una fuga por cada
  petición descartada.
- El asignador del edge reclama una lease cuyo tiempo de reutilización ya
  venció aunque una reconexión llegue antes del siguiente `Tick`.
- Se conserva el retardo de reutilización y la defensa anti-replay.
- KRP puede aplicar un apagado o una configuración local aceptada sin requerir
  reiniciar eMule; una configuración incompleta falla cerrada.

## Evidencia disponible antes de esta beta

- Suite standalone eMule: PASS, incluidas 21.659 comprobaciones FEC.
- Relay edge: PASS, 30.145 comprobaciones con TLS/WSS real en loopback.
- Build Windows x64 y enlace completo: PASS.
- Archivo de 12.000.000.000 bytes: corte abrupto, recodificación, reanudación
  desde el 88 % y SHA-256 final idéntico.
- Soak local: Kad conectado sin muestras de desconexión durante más de 14 h;
  LiveTV creció de 47 a 28.648 chunks durante más de 12,7 h, con cero chunks
  perdidos observados.
- LiveTV sobre plano de datos IPv6 estricto: PASS durante 2 h a 12 Mbps entre
  dos instancias Windows aisladas en el mismo host, con 468 muestras válidas,
  playlist y segmentos MPEG-TS correctos, búfer sin huecos y cero fallback
  IPv4. La comprobación final confirmó una conexión TCP IPv6 global directa.
  Esta evidencia valida el plano de datos, pero no sustituye el caso normativo
  `T5` entre dos equipos físicos.
- Consentimiento rechazado/aceptado, seguridad web local y kill switch:
  validados.
- Camino directo beta.2 -> eSE 8.1: validado.

La prueba física de tres nodos, el cambio LAN -> tethering y las matrices
IPv6-only que requieren el portátil se publicarán como evidencia adicional.
No se contabilizan como PASS mientras el equipo no esté disponible. Un overlay
como Tailscale se etiqueta como overlay y no como prueba de ruta IPv6 pública.

## Límites conocidos

- No garantiza High ID ni atravesar cualquier CGNAT.
- No ofrece salida Kad6 estable ni infraestructura KRP pública por defecto.
- La identidad eSE ligada a clave pública para créditos IPv6 queda para una
  beta posterior; esta beta usa la política neutral, sin atribuir créditos
  IPv4 a un endpoint IPv6-only.
- La resolución A/AAAA conserva ambas familias, pero la migración completa del
  `getaddrinfo(AF_UNSPEC)` a un worker no bloqueante sigue pendiente.
- No hay cliente Android y no es necesario instalar nada en Android.

## Actualización y rollback

1. Copiar el directorio `config` completo y todos los `.met`.
2. Probar primero con una copia del perfil.
3. No abrir el mismo perfil con dos procesos.
4. Mantener `emule.exe` y `ese-server.exe` del mismo paquete.
5. Para volver atrás: desactivar NetLab, cerrar eMule y restaurar la copia del
   perfil anterior.
