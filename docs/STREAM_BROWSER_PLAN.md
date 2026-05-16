# Stream Browser + Thumbnails — Plan

## ✅ Estado FINAL (commits `c587126`, `1dced79`, `82fda02`, `5e164b2`)

| Sprint | Estado | Commit | Resultado |
|---|---|---|---|
| **BROWSE-S03** rebuild pipeline ese-server.exe | ✅ DONE | `1dced79` | npm run build produce ese-server.exe; runtime_dir.js para state writable (%APPDATA%\eSE en pkg mode); api_keys/tunnel/favorites/thumb_extractor adaptados |
| **BROWSE-S01** cross-peer thumbnails | ✅ DONE | `5e164b2` | /api/live/channels enriquece cada entry con broadcasterIP, httpPort, thumbnailUrl. Locals: /live/thumb/{hash}.jpg. Remotes: http://{remote_ip}:8080/live/thumb/{hash}.jpg. Grid usa src directamente; on-error oculta |
| **BROWSE-S05** search debounce | ✅ DONE | `5e164b2` | Input search debounce 250 ms; refresh global mantenido en 10 s (era ya razonable) |
| **BROWSE-S04** trending | ⏭️ SKIP | — | El sort dropdown ya tiene "Más vistos" que usa viewers actuales. Trending histórico real requiere persistencia DHT (V3+) |
| **BROWSE-S02** MFC native tab | ⏭️ SKIP | — | Botón "Browse Live Directory →" ya existe y abre /live (mismo UX). Pestaña CListCtrl nativa sería duplicación. Si en el futuro hace falta UI offline, alternativa rápida = WebView2 embebido |

## ✅ Verificado E2E

- ese-server.exe arranca limpio en pkg mode (sin ENOENT)
- /live page sirve 200 OK con grid completo
- Per-hash thumb `{hash}.jpg` se genera cada 20 s en %APPDATA%\eSE\eSE-live\thumbs\
- /api/live/channels Node retorna enriquecido con thumbnailUrl, broadcasterIP, httpPort
- Local broadcasts → relative URL → Node sirve desde runtime thumbs dir
- Remote broadcasts (Kad-discovered) → absolute URL al broadcaster's :8080
- Cuando 8080 está cerrado/no responde, browser cae a placeholder vía onerror

---

## Estado intermedio (histórico)

**Estado tras commit `c587126`:**
- `/live` página web con grid + filters + favoritos + cinema player ✅
- Thumbnail extractor cada 20 s con guardado per-hash ✅ (requiere ese-server rebuild para que apliquen los cambios JS)
- Botón "Browse Live Directory →" en MFC ✅

## Lo que sigue faltando

| # | Gap | Severidad | Esfuerzo | Por qué |
|---|-----|-----------|----------|---------|
| **B-1** | Cross-peer thumbnails — el grid muestra streams descubiertos via Kad de OTROS broadcasters, pero solo nosotros generamos `{hash}.jpg` localmente. Para esos otros streams, la miniatura es la del último broadcast local (vía fallback `emule_broadcast.jpg`). | 🟠 ALTO | M | Sin esto, el "buscador" no muestra previews de streams ajenos — solo del propio |
| **B-2** | MFC Discover tab — pestaña nativa con `CListCtrl` que muestre streams descubiertos directamente en la app, sin abrir navegador | 🟡 MEDIO | M-L | Usuarios desktop que no quieren browser; consistencia UX con MFC |
| **B-3** | ese-server.exe rebuild pipeline — el .exe actual es de Abril, no refleja cambios en JS. Necesita rebuild reproducible para CI | 🟡 MEDIO | S | Sin rebuild, cualquier mejora en JS queda "muerta" hasta empaquetar |
| **B-4** | Trending / popularity ranking en /live grid — actualmente ordena por viewers snapshot, sin histórico | 🟢 BAJO | M | Mejora UX pero no bloqueante |
| **B-5** | Search bar dentro del grid llama refresh agresivo — saturable | 🟢 BAJO | S | UX detail |

---

## Plan: sprints BROWSE-S01 a BROWSE-S05

### BROWSE-S01 — Cross-peer thumbnail fetch via HTTP (B-1)

**Objetivo**: el grid muestra una miniatura real para CADA stream descubierto, no solo el propio.

**Diseño**:
1. **Lado broadcaster** (C++ WebServer.cpp): nuevo endpoint `GET /api/live/thumb/<HASH>.jpg` accesible localhost-only (igual que `/api/live/*` actuales). Sirve el JPG desde `$TEMP/eMule_RTMP/thumb_LATEST.jpg` (generado por FFmpeg como subproducto del HLS — ver paso 2).
2. **Lado broadcaster** (C++ RTMPIngest.cpp): añadir output secundario al cmdline FFmpeg `-vf "thumbnail=fps=1/20" -f image2 thumb_%05d.jpg`. Total +1% CPU.
3. **Lado viewer** (Node `/live/thumb/{hash}.jpg`): cuando se pide un hash que no es nuestro, hace HTTP GET al broadcaster (vía IP:HTTP_PORT — nuevo: el broadcaster expone su HTTP port en `livehash:` Kad metadata). Cache local 60 s en `eSE-live/thumbs/{hash}_remote.jpg`.

**Tiempo**: 2-3 días.
**Bloqueante**: ninguno. Funciona sin B-3 (rebuild ese-server) si se accede a Node directamente.

**Riesgo**: expone HTTP del broadcaster a la WAN. Mitigación: exponer SOLO `/api/live/thumb/<HASH>.jpg` (no el resto de la API) en una pestaña de "Public Thumbnail Service" en MFC + bind a 0.0.0.0 solo si esa opción está marcada.

---

### BROWSE-S02 — MFC Discover tab nativa (B-2)

**Objetivo**: pestaña "Discover" en el LiveStreamDlg con un `CListReportCtrl` mostrando todos los streams descubiertos, con miniatura inline (CImageList), columns: title, category, language, bitrate, viewers, age. Doble click → JoinStream.

**Diseño**:
1. **Resource (.rc)**: nuevo IDD_LIVESTREAM_DISCOVER con CListCtrl + filters + refresh button + status bar.
2. **MFC class** `CLiveStreamDiscoverDlg`: refresca cada 5 s vía `/api/live/kad/streams`. Renderiza CImageList con thumbs descargadas de `/live/thumb/{hash}.jpg`.
3. **Integración**: añadir pestaña a `CLiveStreamDlg` (que ya es un tabbed dialog) o crear un nuevo botón "Discover" que abra modal.

**Tiempo**: 3-5 días.
**Bloqueante**: B-1 ideal pero no obligatorio (sin él, todas las cards usan fallback `emule_broadcast.jpg`).

**Riesgo**: tooling MFC es legacy + frágil. Alternativa más rápida: empotrar un WebView2 en la pestaña que cargue `http://localhost:8080/live` directamente. Resultado idéntico al UI Node, sin reimplementar UI nativa.

---

### BROWSE-S03 — ese-server.exe rebuild reproducible (B-3)

**Objetivo**: cualquier cambio en `srchybrid/eSE/**/*.js` regenera `srchybrid/x64/Release/ese-server.exe` automáticamente vía script o pre-build step de msbuild.

**Diseño**:
1. `srchybrid/eSE/package.json`: añadir scripts `"build": "pkg server.js -o ../x64/Release/ese-server.exe -t node18-win-x64"` y `"dev": "node server.js"`.
2. `srchybrid/eSE/pkg.config.json`: lista de assets (eSE-live/, public/, etc.) que pkg debe empaquetar.
3. Pre-build step en `emule.vcxproj` que invoca `npm run build` si algún .js es más nuevo que .exe.
4. Documentación en `docs/BUILD.md` (nuevo) explicando los 2 modos: dev (node directo) y prod (pkg).

**Tiempo**: 1 día.
**Bloqueante**: requiere Node 18+ instalado en máquina de build.

---

### BROWSE-S04 — Trending ranking (B-4)

**Objetivo**: el grid ordena streams por "trending" no solo por snapshot viewers.

**Diseño**:
1. **Node `eSE-live/channel_rating.js`**: extender el rating actual con histórico de viewers (sliding window 5 min, requiere persistir en disco un JSON por canal).
2. **Score combinado**: `0.4 * viewers + 0.3 * uptime + 0.2 * bitrate + 0.1 * recency` (ajustable).
3. **UI**: añadir tab "Trending" en `/live` al lado de "All channels".

**Tiempo**: 2 días.
**Bloqueante**: ninguno.

---

### BROWSE-S05 — Refresh throttle + search debounce (B-5)

**Objetivo**: el search input del grid no dispara fetch en cada tecla.

**Diseño**: debounce 300 ms en `live_tv_page.js`. Refresh global cada 10 s, no 2 s.

**Tiempo**: medio día.

---

## Roadmap recomendado

| Orden | Sprint | Por qué primero |
|---|---|---|
| 1 | **BROWSE-S03** rebuild pipeline | sin esto, NINGÚN cambio JS surte efecto en producción |
| 2 | **BROWSE-S01** cross-peer thumbs | "buscador con miniaturas" no funciona de verdad sin esto |
| 3 | **BROWSE-S02** MFC Discover | UX desktop completa |
| 4 | **BROWSE-S05** search debounce | polish |
| 5 | **BROWSE-S04** trending | nice-to-have |

---

## Lo que YA está hecho (no requiere sprint)

- ✅ Página `/live` con grid responsive
- ✅ Filtros search / category / language / sort
- ✅ Favoritos persistidos (localStorage)
- ✅ Cinema player con hls.js (HLS + audio multi-pista)
- ✅ Rating local de cada stream
- ✅ Endpoint `/api/live/kad/streams` (C++) con discovery vía Kad
- ✅ Endpoint `/api/live/diagnose` (DISC-S10) para support
- ✅ Botón MFC "Browse Live Directory →" → abre `/live`
- ✅ Thumbnail extractor cada 20 s + guardado per-hash (necesita rebuild ese-server.exe — ver B-3)
- ✅ Fallback automático a Node directo si ese-server.exe ausente (`ToggleEseServer`)
