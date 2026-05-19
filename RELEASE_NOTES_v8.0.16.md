# v0.70b-eSE 8.0.16 — Smart Playback rediseño (state machine S1..S7)

Hotfix de la línea v8.0. Reemplaza la cadena de parches del monitor de reproducción (`monitorForFile`) por una máquina de estados real impulsada por verdad-de-disco (`.met` gap-list, `ffprobe`, ventana rolling de tasa de descarga). Cierra los regresos crónicos reportados entre v8.0.12 y v8.0.15: "Buffer listo" sobre fichero vacío, arranque sin velocidad sostenida, eMule "buggeándose" al cambiar prioridades, falta de pausa al quedarse sin buffer.

> Solo cambia el lado Node.js (`ese-server.exe` + bundle JS de cliente). `emule.exe` v8.0.15 sigue vigente.

## Por qué esta versión

Tres bugs reproducibles en v8.0.15:

1. **Arranque con velocidad insuficiente.** El gate de v8.0.15 calculaba la tasa requerida como `totalBytes / 90min × 1.3` (asumía duración 90 min) y dependía del cliente para muestrear la tasa. En pelis largas (2h30) o ratios viejos infraestimaba la tasa real y arrancaba con margen falso.
2. **Sin reacción a stalls.** Una vez `playPartFile()` arrancaba el `<video>`, no había vigilancia activa. Si la descarga caía, el reproductor seguía y se cortaba sin avisar.
3. **Cambio de fuente manual.** Si una fuente fallaba el usuario tenía que hacerlo todo a mano. No había transición clara desde "esto no va a aguantar" hacia "probar la siguiente".

## Qué cambia

### Backend (`emule_routes.js`)

- **`_parseMetGaps()` extendido.** Antes devolvía solo `{fileSize, downloaded}`. Ahora también `{headContiguousBytes, firstGapStart, firstGapEnd, gapCount}`. La diferencia importa: `downloaded` es la suma de bytes recibidos (incluyendo chunks dispersos por el fichero) — `headContiguousBytes` es lo que el reproductor puede consumir SIN seek. eMule con preview-priority sesga al inicio pero no siempre arranca limpio desde el byte 0.
- **`GET /api/emule/probe?file=NNNN.part`** (nuevo). Llama a `ffprobe` sobre el .part parcial. Devuelve `duration`, `bitrate`, `container`, `videoCodec`, `audioCodec`, `width`, `height`, `audioChannels`, `audioSampleRate`. Cacheado 60 s por hash. Si el head contiguo es <5 MB devuelve `{ready:false, reason:"head_too_small"}` para que el cliente siga esperando.
- **`GET /api/emule/rate?file=NNNN.part&windowSec=60`** (nuevo). Ventana rolling de muestras `(t, downloadedBytes)` que se alimenta DESDE el mismo bucle de `/api/emule/downloads` que el cliente ya polla. Una sola fuente de verdad: el cliente recibe `bytesPerSec` calculado por el servidor. Antes el cliente mantenía su propio buffer en `window._smartPlayRateSamples` que se reseteaba en cada recarga y se duplicaba si había dos pestañas abiertas.

### Cliente (`playback_state.js`, nuevo)

Sustituye a `monitorForFile` (eliminado en ambos `smart_play.js` y `player.js`, dejando un wrapper delgado) con una máquina de estados explícita:

| Estado | Qué hace | Salida |
|---|---|---|
| **S1 INIT** | Polea `/api/emule/downloads`. Espera matching por hash (NUNCA por nombre cuando hay hash — fix del bug "a todo gas 6"). | → PROBE cuando hay descarga activa con head > 0. → FAIL `no_data` tras 120 s. |
| **S2 PROBE** | Llama a `/api/emule/probe`. Lee bitrate real. | → SUSTAIN cuando hay bitrate fiable. → SUSTAIN con bitrate estimado tras 45 s si ffprobe nunca responde. |
| **S3 SUSTAIN** | Polea `/api/emule/rate`. Compara contra `bitrate × 1.3` con piso 256 KB/s. Espera `headContiguousBytes ≥ 15 MB`. | → HEAD_BUFFER cuando rate y head OK, o si el fichero ya está completo. → FAIL `low_rate` / `no_head` tras 90 s. |
| **S4 HEAD_BUFFER** | Pausa de 1 s para que la UI muestre "Buffer listo". | → PLAYING. |
| **S5 PLAYING** | Llama a `onPlay(partFile, fileName, probe)`. Cada 5 s mide `bytesPlayed = currentTime × bitrate`, compara contra `headContiguousBytes`. | → STALL si `lead < 10 s` AND `rate < bitrate × 0.8`. → COMPLETE en `video.ended`. |
| **S6 STALL** | Pausa el `<video>`. Cuenta intentos (max 2). | → PLAYING cuando `lead ≥ 20 s` AND `rate ≥ bitrate`. → FAIL `repeated_stalls` al 3.º. → FAIL `stall_timeout` tras 60 s. |
| **S7 COMPLETE** | Llama a `onComplete`. Para timers. | terminal. |
| **FAIL** | Llama a `onFail(reason, remaining, retry)`. UI por defecto pinta botones "Probar otra fuente (N) / Dejar descargando / Volver". `retry()` invoca `trySmartSource(sourceIndex + 1)`. | terminal. |

Detalles clave:
- La UI reutiliza los mismos `#smart-play-status` / `-title` / `-progress` / `-actions` — no hay rediseño visual, solo textos honestos por estado.
- Hash-only matching: con hash MD4 explícito NUNCA cae al fuzzy de nombre. El fuzzy queda solo para llamadas legacy sin hash.
- Single source of truth: tasa, head-contiguous y bitrate vienen TODOS del backend.

### Compatibilidad

- Si `playback_state.js` no carga por cualquier motivo, `monitorForFile` cae a la implementación v8.0.15 renombrada a `_monitorForFile_legacy`. Degradación silenciosa.
- Formato `.met` / `.part` no cambia. Los binarios v8.0.x previos siguen interoperando.
- Endpoints existentes no se rompen. `/api/emule/downloads` añade campos pero los antiguos siguen presentes.

## Cómo verificar

1. Arranca `emule.exe` (v8.0.15) en C:\emule.
2. Verifica badge inferior-derecha: debe leer `[ESE 8.0.16] …`.
3. Click "Probar" en una peli ed2k con velocidad ≤ 50 KB/s. Debe:
   - mostrar "Comprobando velocidad…" con `↓ X KB/s · necesitas ≥ Y KB/s · bitrate Z kbps`
   - tras ~90 s sin alcanzar la tasa: ofrecer "Probar otra fuente"
   - NO arrancar el video.
4. En una peli con velocidad >= bitrate × 1.3, debe arrancar y mostrar buffer en estado "Reproduciendo".
5. Si la descarga cae a mitad: ver "Buffering…" con "intento 1/2", `<video>` pausado.
6. Si recupera: vuelve a "Reproduciendo" automáticamente.

## Diagnóstico

- Errores nuevos: ninguno (no nuevos códigos `Exx`).
- Log: cada transición de estado se loguea como `[PlaybackState] FROM → TO (after Ns)` en la consola del navegador.
- Para inspeccionar estado en vivo: `window._smartPlayMonitor.getContext()`.
