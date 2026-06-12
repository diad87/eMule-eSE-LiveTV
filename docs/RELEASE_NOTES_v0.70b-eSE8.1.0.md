# v0.70b-eSE 8.1.0 — Plano de control anónimo para LiveTV

> **v8.1.0** — validado en vivo el 2026-06-12 con 3 PCs (Tailscale). Plano de control tunelizado con anonimato real, estable a 12000 kbps. Backward-compatible con vanilla 0.70b y v8.0.0.

## En una frase

v8.1 añade un **plano de control anónimo** al P2P LiveTV: la **búsqueda Kad por palabra clave** y la **suscripción a un canal** pueden viajar por un **circuito onion** dentro de la propia red eD2K/Kad, ocultando *quién busca qué* y *quién se suscribe a quién* al emisor y a la red — sin VPS, sin dominios, sin terceros.

## Qué es nuevo

- **Transporte onion tunelizado** (Sprint A): celdas multi-cell sobre `OP_EMULEPROT`, dispatcher en el exit, API asíncrona, sweeper de buffers abandonados.
- **Búsqueda Kad por el túnel** (Sprint B): el exit ejecuta una `CSearch` real en nombre del viewer; los resultados vuelven por el circuito, nunca exponen la IP del que busca.
- **Suscripción y control de LiveTV por el túnel** (Sprint C): el exit hace de **proxy multicast** (C7) — se suscribe UNA vez al emisor en nombre de N viewers tunelizados; el emisor ve al exit, nunca al viewer.
- **Selector de modo de privacidad** (Sprint D): `Directo` / `Tunelizado` / `Adaptive`, persistente, con política de *fallback* (`strict` / `balanced` / `best-effort`) y panel web.
- **Estabilidad a bitrate alto:** fragmentación de chunks por encima del límite de 2 MB de eMule (`OP_LIVE_CHUNK_FRAG`, gated por capacidad) + segmentos HLS de 2 s → emisión fluida validada a **12000 kbps (4K)** en malla de varios viewers.

## ⚠️ Alcance honesto de la privacidad (léelo)

v8.1 anonimiza el **plano de control**, NO el **plano de datos**:

| Qué | v8.1 |
|-----|------|
| Quién BUSCA un canal | 🟢 oculto (búsqueda tunelizada) |
| Quién se SUSCRIBE a un canal | 🟢 oculto (el emisor ve al exit, no al viewer) |
| La IP del viewer al recibir los CHUNKS | 🔴 **visible** (el plano de datos sigue directo) |

El modo `Tunelizado` **NO satisface la garantía G1** (anonimato de la IP del viewer en los datos) — eso lo cierra **v8.1.1 (Sprint E)**, con los chunks por el túnel a bitrate nativo. Hasta entonces, `Tunelizado` = *control privado, datos directos*. Se documenta así en la UI.

## Compatibilidad hacia atrás (F2 — auditado, PASA)

Todo el wire/formato de v8.1 degrada con gracia frente a **eMule vanilla 0.70b** y al **fork previo v8.0.0**:

- Las celdas de túnel (`OP_LIVE_TUNNEL_CELL`) y los chunks fragmentados (`OP_LIVE_CHUNK_FRAG`) **solo se envían a peers que anunciaron la capacidad** (`TAG_ESE_CAPS` 0x6C, bits `PRIVACY_TUNNELING`/`LIVE_CHUNK_FRAG`). Un peer antiguo nunca los recibe.
- Un opcode `OP_EMULEPROT` desconocido se descarta en silencio (sin `OnError`, sin desconexión).
- Los registros Kad usan tags estándar (`TAG_SOURCEIP`/`TAG_SOURCEPORT`) + tags eSE con nombre-string que los holders desconocidos **ignoran y conservan**. Por debajo del umbral de fragmentación el wire es **byte-idéntico** al de hoy.

## Rendimiento (F5 — coste del anonimato)

> Honestidad sobre el coste: el túnel es más lento que la búsqueda directa. Medido en vivo (3 PCs, Tailscale):

| Métrica | Directo | Tunelizado (1 hop) |
|---------|---------|--------------------|
| Latencia búsqueda Kad (inicio → 1er lote de resultados) | ~3-5 s (rango típico Kad) † | **~8 s (medido)** ‡ |

† No medible de forma limpia en el banco de 3 PCs (la única stream queda cacheada en el directorio local + cooldown de búsqueda); el valor es el rango habitual de una búsqueda Kad por keyword.
‡ Medido en vivo: `Search BEGIN [tunneled]` → `Tunneled search fed 15 result(s)` = 8 s. Incluye que el exit ejecuta una `CSearch` real, espera su ventana de acumulación, y devuelve los resultados por el circuito. El sobrecoste (~3-4 s sobre el directo) es el precio del anonimato del control.

## Problemas conocidos

- **Datos directos:** la IP del viewer se expone al servir chunks (ver alcance). → v8.1.1.
- **Duplicados de malla:** con varios viewers, un segmento puede pedirse a 2 fuentes y llegar 2× (se descarta, desperdicia ancho de banda). Optimización pendiente (dedup PUSH/PULL).
- **Steering de exit:** para que el circuito NO salga por el propio emisor, el emisor debe **arrancar** en modo `Directo` (la capacidad se fija al arranque). Si arrancó en otro modo, reinícialo en Directo.

## Despliegue

- `emule.exe` + `ese-server.exe` deben ser **del mismo build** en todos los nodos.
- Solo `Release x64`.
