# Plan APK Viewer — "eSE en el sofá" (track M, Mobile)

**Objetivo:** ver los mismos streams y broadcasts de eSE desde móvil, tablet, Android TV,
Fire Stick, iPhone/iPad y otros PCs. El PC con eSE es el cerebro (P2P, Kad,
reconstrucción HLS); el dispositivo es un visor sin carga de trabajo.

**Nombre del producto:** pendiente (candidatos: MuleTV, eSE Play). No usar marcas
ajenas ni en código ni en docs.

**Fecha:** 2026-06-11 · **Estado:** M1 core implementado 2026-06-11, pendiente
validación con dispositivos reales; resto propuesto
**Track independiente de v8.1.x** — no toca wire formats ni el core P2P, así que no
colisiona con Sprint E-α/E-β (V8.1.1_SPRINT_E_BREAKDOWN.md) y puede avanzar en paralelo
o después. Prefijo de sprints **M** para no confundir con los sprints A-E de v8.1.

---

## 0. Punto de partida (auditado 2026-06-11)

Lo que ya existe y se reutiliza tal cual:

| Pieza | Dónde | Estado |
|---|---|---|
| HLS por HTTP per-stream | `/api/live/{hash}/stream.m3u8` + segs — WebServer.cpp:6319 | ✅ funciona (VLC validado) |
| Catálogo de canales JSON | `/api/live/channels` — WebServer.cpp:6020 | ✅ |
| Directorio Kad de streams | `/api/live/kad/streams` — WebServer.cpp:6080 | ✅ |
| Join/leave/heartbeat marshalados | `/api/live/join`, `/leave`, `/player-alive` — WebServer.cpp:4609+ | ✅ (auditoría threading 6857f32) |
| Broadcast start/stop por API | `/api/live/broadcast/*` — WebServer.cpp:4696 | ✅ |
| Auth challenge-response SHA256 + sesiones | WebServer.cpp:372-490 | ✅ |
| HTTPS opcional (mbedtls) | WebSocket.h:29 | ✅ compilado, no por defecto |
| Cripto para identidad (ECDSA, AES-GCM, PBKDF2) | mbedtls/tf-psa-crypto en el árbol | ✅ disponible |

**El bloqueo:** todos los `/api/live/*` y `/hls/*` son **loopback-only** por diseño
(WebServer.cpp:4524-4553, gate de seguridad porque van sin sesión). Un móvil en la LAN
recibe `403 {"error":"forbidden"}`. Por eso M1 va primero y es lado PC.

**Fuera de alcance de este plan** (decidido, no olvidado):
- VOD/películas (necesita `/api/files` + HTTP Range 206 — plan aparte cuando Live funcione como un reloj).
- Mini-cliente Kad en el APK (localizador Kad de la conversación 2026-06-11) — futuro lejano.
- Play Store / Amazon Appstore — distribución por sideload + ZIP portable, como siempre.
- P2P en el móvil. El móvil jamás habla eD2K/Kad en este plan.

**Restricciones heredadas:** cero coste (sin VPS/dominios; fuera de casa = Tailscale),
compatibilidad hacia atrás intacta (solo cambia webserver + app nueva), endpoints nuevos
siguen el patrón de marshaling (SendMessage UM_LIVE_WEB_*) o snapshots bajo lock.

---

## M1 — PC: acceso remoto con autenticación (la puerta) — tamaño S/M

> **Estado 2026-06-11: core implementado** (WebSocket.cpp dispatch + WebServer.cpp
> `_ProcessLiveAPI`). Hecho: gate `loopback || token`, prefijo `/s/{ses}/` con strip
> y renovación de sesión vía `_IsLoggedIn()`, guard guest-vs-admin (broadcast/holepunch/
> privacy solo admin por `/s/`), routing de `/live*` al handler embebido (antes era
> código muerto: el dispatch nunca lo enrutaba), páginas /live y /live/{hash}
> prefijo-conscientes (variable JS `B`), y guard `window.Hls` para que Safari use HLS
> nativo aunque el CDN de hls.js no cargue. M1.4 ya estaba cubierto por `badlogins`
> en el login (4 fallos → ban 15 min); los tokens inválidos NO alimentan badlogins
> a propósito (un player pausado con sesión caducada se auto-banearía).
> Pendiente: validación con VLC Android / Safari iPhone por LAN y Tailscale.

Hoy el gate es binario: loopback sí, resto no. Pasa a: loopback sí, remoto **solo con
token válido**. El default sigue siendo seguro: sin contraseña de webserver configurada,
el remoto sigue bloqueado exactamente igual que hoy.

- **M1.1** Sustituir el gate loopback-only (WebServer.cpp:4541-4553) por
  `loopback || sesión válida`. Mantener la línea `LIVE_LOG("SEC", ...)` para rechazos.
  Si `thePrefs.GetWSPass()` está vacío → remoto bloqueado siempre (default actual).
- **M1.2** **Token por prefijo de ruta, no por query string.** Los players HLS resuelven
  los segmentos como URLs relativas a la playlist y **pierden los query params**, así que
  `?ses=` no sirve para los `.ts`. Solución: prefijo `/s/{token}/...` — la app pide
  `/s/{tok}/api/live/{hash}/stream.m3u8`, las refs relativas de la playlist heredan el
  prefijo y cada `.ts` llega autenticado solo. Implementación: al inicio de `_ProcessURL`,
  si la URL empieza por `/s/`, extraer token, validar contra las sesiones existentes,
  strip del prefijo y seguir el flujo normal. Una sola pieza nueva, cero cambios en los
  handlers existentes.
- **M1.3** Vida de sesión: el timeout actual (300 s, WebServer.h:10) se renueva con cada
  petición — los segmentos HLS cada pocos segundos la mantienen viva solos. Verificarlo;
  si las sesiones solo se renuevan con páginas, añadir renovación en el camino `/s/`.
- **M1.4** Anti fuerza bruta en el login remoto: contador de fallos por IP + lockout
  temporal (mismo espíritu que el rate-limit de `/api/holepunch/test`).
- **M1.5** Transporte v1: en LAN y tailnet, HTTP es aceptable (Tailscale ya cifra
  extremo a extremo con WireGuard). HTTPS propio llega en M5 con la identidad. Documentar
  esta decisión en el doc para no exponerlo jamás a internet abierto.

**Criterio de aceptación (cierra el sprint):**
1. VLC para Android en la LAN reproduce `http://<PC>:4711/s/{tok}/api/live/{hash}/stream.m3u8`.
2. Lo mismo por Tailscale desde fuera de casa (datos móviles).
3. Sin token → 403 idéntico al actual; dashboard localhost sigue funcionando sin cambios.
4. Con contraseña vacía, comportamiento idéntico al de hoy.

> Bonus gratis: tras M1, **cualquier navegador del tailnet** puede abrir la página player
> `/live/{hash}` con el prefijo de token → "ver desde otro PC" queda resuelto sin APK.

### Validación 2026-06-13 (curl en caliente, sin tocar C++)

Probado contra el binario en ejecución `emule_v8.1.0.exe` (WS en `0.0.0.0:4711`,
`Enabled=1`, `Password`+`PasswordLow` configuradas, `UseLowRightsUser=0`) con una
emisión real activa (`hash=0328fadc…`, "Hola mundo"). IP loopback `127.0.0.1`, IP LAN
`192.168.68.64`, IP Tailscale `100.69.24.30` (mismo equipo, simulando "remoto").

| Caso | Petición | Esperado | Resultado |
|---|---|---|---|
| A | loopback `/api/live/{hash}/stream.m3u8` | 200 m3u8 | ✅ 200 `application/vnd.apple.mpegurl` 525 B |
| I | loopback `seg_*.ts` real | 200 vídeo | ✅ 200 `video/mp2t` 1,3 MB |
| E | loopback `/dashboard` | 200 | ✅ 200 (dashboard intacto) |
| F | loopback `/` (UI clásica) | 200 | ✅ 200 (login intacto) |
| B | LAN, sin token, `/api/live/…` | 403 | ✅ 403 `localhost-only` |
| C | Tailscale, sin token, `/api/live/…` | 403 | ✅ 403 `localhost-only` |
| G | LAN, sin token, `/dashboard` | 403 | ✅ 403 |
| D | LAN, token inválido `/s/999999/…` | 403 | ✅ 403 `invalid or expired token` |
| — | loopback `/s/0/`, `/s/abc/`, `/s/999999/` | 403 | ✅ 403 (cero / no-numérico / inexistente) |

Revisión de código (WebServer.cpp:4520-4624 + WebSocket.cpp:94-108): el parseo
`/s/{ses}/` (offset 3, `atol` hasta el `/`, `Find('/',3)` para el strip), la
validación+renovación vía `_IsLoggedIn()` (resetea `startTime`, así un player vivo
mantiene su propia sesión) y el guard guest-vs-admin (`bTokenAuth && !bTokenAdmin` →
broadcast/holepunch/privacy a 403) son correctos. Los tokens inválidos NO alimentan
`badlogins` (a propósito).

**Pendiente de cerrar M1:**
- ⏳ **Pata positiva remota automatizable** (IP no-loopback + token *válido* → 200 m3u8):
  no ejecutada porque requiere un token de sesión y la contraseña del WS no está
  disponible. La rama de token-válido del código es idéntica al camino loopback ya
  verificado (A/I); falta la confirmación empírica de un extremo a otro.
- 🔌 **Pendiente de hardware (no automatizable):**
  - Criterio 1 — VLC para Android en la LAN reproduce `…/s/{tok}/api/live/{hash}/stream.m3u8`.
  - Criterio 2 — lo mismo por Tailscale desde datos móviles.
  - Safari iPhone/iPad reproduciendo HLS nativo vía `…/s/{tok}/live/{hash}`.
- ℹ️ **No ejercitable en runtime con esta config:** la rama de denegación guest
  (`bTokenAuth && !bTokenAdmin`) no se puede disparar con `UseLowRightsUser=0`
  (no existen sesiones guest); queda cubierta por revisión de código.

---

## M2 — APK MVP: móvil y tablet — tamaño M/L

Proyecto nuevo en `android/` dentro de este repo (mono-repo, simplicidad hobby).

- **M2.1** Esqueleto: Kotlin + Jetpack Compose + Media3/ExoPlayer (HLS de serie).
  minSdk 24 (cubre Fire OS 6+). Gradle, Android Studio. Sin dependencias de Google
  Play Services.
- **M2.2** Pantalla "Conectar": host:puerto + contraseña. Lista de PCs guardados
  (DataStore). Texto de ayuda: IP LAN o IP Tailscale 100.x.
- **M2.3** Login: mismo challenge-response SHA256 del webserver (portar el esquema de
  WebServer.cpp:466-490) → token de sesión → todo lo demás vía `/s/{tok}/`.
- **M2.4** Pantalla "Canales": merge de `/api/live/channels` (activos) +
  `/api/live/kad/streams` (descubiertos), con título, categoría, viewers, bitrate.
  Pull-to-refresh. Estado vacío decente ("no hay nadie emitiendo").
- **M2.5** Ver stream: tap → `/s/{tok}/api/live/join?key=...` (ya marshalado) → abrir
  `stream.m3u8` en Media3 → heartbeat `/player-alive` cada 10 s mientras reproduce →
  `/leave` en onStop/back. Vertical: lista+player; horizontal: fullscreen.
- **M2.6** Fin de stream y errores: tombstone/stream caído → mensaje claro y volver a
  la lista, no spinner infinito. Errores de red en lenguaje humano.

**Criterio de aceptación:** prueba 2-dispositivos — PC emite (testpattern del
`/api/live/broadcast/start`), el móvil en LAN lo ve con latencia < 10 s; repetir por
Tailscale con wifi apagado. Matar la app → el watchdog ghost-viewer limpia el viewer
en el PC (verificar en `/api/live/debug`).

---

## M3 — Robustez de reproducción — tamaño S/M

- **M3.1** Reconexión automática con backoff (cambio wifi↔datos, PC ocupado, segmento
  404 transitorio durante el join). ExoPlayer da los hooks; la política es nuestra.
- **M3.2** Tuning de buffer para HLS de ~2-6 s de segmento: empezar conservador
  (estable > rápido), exponer latencia medida en un overlay de debug oculto.
- **M3.3** Ciclo de vida: al ir a background → leave limpio (es directo, no on-demand;
  decisión consciente de no mantener audio en background en v1). PiP = futuro.
- **M3.4** Indicadores: viewers, bitrate y calidad del canal (ya vienen en el JSON).

**Criterio de aceptación:** 30 min de visionado continuo sin intervención; cambiar de
wifi a datos a mitad y que se recupere solo en < 15 s.

---

## M4 — TV: Android TV y Fire Stick — tamaño M

Mismo APK, segundo form factor.

- **M4.1** Intent leanback + banner TV; navegación D-pad completa (Compose for TV):
  parrilla de canales → OK entra, BACK sale (= leave), sin trampas de foco.
- **M4.2** Fire Stick: guía de sideload por ADB en `docs/` (Developer options →
  ADB debugging → `adb install`). Probar en Fire OS real, no solo emulador.
- **M4.3** Códecs: el broadcast FFmpeg produce H.264/AAC → decodificación hardware
  universal en TV. Verificar y dejar constancia; si algún día el broadcast emite otra
  cosa, este es el punto a revisar.

**Criterio de aceptación:** Fire Stick en el salón reproduce el canal manejado solo
con el mando; al salir, el viewer desaparece del PC.

---

## Estrategia iOS / iPadOS — PWA, sin App Store (decidido 2026-06-11)

No habrá app nativa iOS: instalar sin App Store exige o sideload con cuenta gratuita
(caduca cada 7 días, refirma desde PC), o cuenta de desarrollador (99 $/año — rompe
la regla de 100% gratis), o marketplaces alternativos UE (también exigen cuenta de
pago + notarización). El camino gratis es la **PWA**:

- Safari reproduce **HLS de forma nativa** (es el formato de Apple) — la página
  player embebida `/live/{hash}` ya funciona en iPhone/iPad a través de
  `/s/{tok}/live/{hash}` tras M1, sin hls.js y sin CDN.
- Pulido PWA (pequeño, puede ir con M5/M6): `manifest.json` + iconos servidos por el
  webserver para "Añadir a pantalla de inicio", y una mini-página de login que haga
  el challenge-response y redirija a `/s/{ses}/live`.
- Límites asumidos: sin app de TV para Apple TV (AirPlay desde Safari cubre el caso),
  y la PWA no puede hacer NSD/mDNS — en iOS el descubrimiento es manual o por QR (M5).

## M5 — Emparejamiento "DNI digital" (identidad autocertificada) — tamaño M

Diseño conversación 2026-06-11 (modelo Syncthing). La clave privada **nunca** sale del PC.

- **M5.1** PC: generar keypair ECDSA P-256 + certificado TLS autofirmado (mbedtls).
  Guardar clave cifrada en disco: PBKDF2(contraseña) → AES-256-GCM. Fichero =
  `ese_identity.bin` junto a preferences. **ID = huella SHA-256 del cert en base32.**
- **M5.2** PC: activar HTTPS del webserver con ese cert para acceso remoto.
- **M5.3** Dashboard: mostrar el ID como código QR (ID + puerto + hints de host).
- **M5.4** App: escanear QR (o teclear código corto en TV) → guardar huella → en cada
  conexión TLS, **pin**: huella del cert presentado == ID, o rechazo. MITM imposible
  sin CA, sin dominios, sin coste.
- **M5.5** Revocación = borrar/regenerar el fichero de identidad; los dispositivos
  re-emparejan. Sin listas de revocación, sin ceremonia.

**Criterio de aceptación:** conexión por HTTPS con cert autofirmado pineado desde móvil
y Fire Stick; un cert distinto (PC reinstalado) → la app avisa y pide re-emparejar.

---

## M6 — Descubrimiento — tamaño S

- **M6.1** PC: anunciar `_ese._tcp.local` por mDNS con la huella en el TXT record
  (API nativa de Windows DNS-SD o announcer mínimo propio).
- **M6.2** App: NSD discovery → "PCs encontrados en casa", un tap y emparejado
  (combinado con M5: la huella del TXT pre-rellena el pin).
- **M6.3** Fuera de casa: guía Tailscale en `docs/` (PC + Android + Fire TV tienen
  app oficial). El localizador Kad (publish firmado vía patrón CLiveKadBridge +
  mini-Kad en el APK) queda documentado como evolución futura, explícitamente
  fuera de este plan.

**Criterio de aceptación:** factory reset de la app → en casa, encuentra el PC y
empareja en < 30 s sin teclear ninguna IP.

---

## M7 (opcional) — Mando a distancia de broadcast — tamaño S

La API ya existe y está marshalada; es solo UI.

- **M7.1** Pantalla "Emitir": `/api/live/preflight` (semáforo: Kad, HighID, FFmpeg,
  firewall) → `/api/live/broadcast/start?source=...&title=...` → enlace + estado →
  `/broadcast/stop`.
- Convierte el móvil en mando del cerebro: empiezas a emitir desde el sofá.

---

## Orden, dependencias y tamaño

```
M1 (PC, puerta) ──► M2 (APK MVP) ──► M3 (robustez) ──► M4 (TV)
                                          │
                                          ▼
                              M5 (identidad) ──► M6 (descubrimiento)
                                          │
                                          ▼
                                    M7 (opcional)
```

- M1 es prerequisito duro de todo. M2-M4 dan el visor de salón completo usable
  con contraseña + Tailscale. M5-M6 son calidad de vida y seguridad de largo plazo.
- Tamaños: S = días sueltos, M = 1-2 semanas hobby, L = varias semanas. El único L
  real es M2 (primer contacto con Android si no hay experiencia previa).
- Validación estilo casa: cada sprint cierra con su prueba 2-dispositivos real
  (PC emite, dispositivo ve), igual que el 2-PC de los sprints Kad.

## Riesgos conocidos

1. **Sesiones de 300 s vs. maratones de visionado** — cubierto en M1.3; si muerde,
   token de player de larga vida separado del de admin.
2. **Latencia HLS** — la cadena actual es HLS clásico (~5-15 s). Suficiente para v1;
   LL-HLS sería otro proyecto. No prometer "tiempo real".
3. **Workers del webserver (64 máx, timeout 30 s)** — segmentos HLS son ficheros
   pequeños y rápidos; 2-3 dispositivos en casa no se acercan al límite. Vigilar en
   M3 con el overlay de latencia.
4. **Fire OS viejos** — minSdk 24 cubre Fire OS 6+; sticks de 1ª gen quedan fuera
   y no nos importa.
5. **Exposición accidental a internet** — la app y la doc empujan siempre a
   LAN/tailnet; M1 mantiene el default cerrado y M5 añade TLS pineado. Nunca UPnP
   para el puerto web.
