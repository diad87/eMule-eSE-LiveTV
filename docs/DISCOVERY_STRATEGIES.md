# Discovery Strategies — Brainstorm + Recommended Path

## Problema real

Tras DISC-S01..S15 el descubrimiento P2P funciona bien técnicamente pero
sigue teniendo 4 puntos débiles inherentes a **DHT-only**:

| Punto débil | Síntoma |
|---|---|
| **Cold bootstrap lento** | Primer arranque sin `nodes.dat` tarda 2-5 min hasta tener Kad usable |
| **Propagación impredecible** | 30 s – 5 min para que un publish llegue al viewer remoto |
| **No hay "browse"** | DHT funciona por keyword exacto — necesitas saber qué buscar |
| **Aislamiento social** | No hay forma de saber "qué están viendo mis amigos" |

Cualquier estrategia que ataque al menos uno de esos 4 puntos suma.

---

## 1. Catálogo de estrategias (26 ideas)

Agrupadas por mecanismo. La columna **Impact/Effort** es estimación gruesa.

### A. Centralizadas (necesitan infraestructura)

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| A1 | **HTTPS tracker** federable (≥3 nodos) | 🔥🔥🔥 | S | Node.js o Cloudflare Worker. Broadcasters POST cada 60 s; viewers GET la lista. Sub-segundo. Acepta múltiples trackers por defecto |
| A2 | **`eSE.live` directory site** público | 🔥🔥 | M | Web pública con grid de streams agregados. Marketing + discovery |
| A3 | **eD2K server bridge** | 🔥🔥 | L | Servidores eD2K clásicos (server.met) propagan metadata live. Compat con clientes viejos |
| A4 | **WebRTC signaling server** | 🔥🔥 | M-L | WebSocket relay para descubrimiento sub-segundo. Más complejo que A1 pero más ágil |

### B. P2P puras (sin infraestructura)

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| B1 | **PEX (Peer Exchange)** de streams | 🔥🔥🔥 | M | Cada peer mantiene cache de streams vistos; al conectar, intercambia caches con los 5 peers más cercanos. Decentralizado pero rápido |
| B2 | **HyParView + Plumtree** | 🔥🔥🔥 | L | Gossip estructurado, sub-segundo. Ya está en `MASTER_PLAN.md §11.3.7` |
| B3 | **mDNS / Bonjour LAN** | 🔥🔥 | S | Zero-config en la misma red local. LAN parties, oficinas, conferencias. Sin pasar por Kad |
| B4 | **IPv6 multicast** | 🔥 | M | Anuncios en `ff05::live` para nodos IPv6. Limitado por adopción IPv6 |
| B5 | **DHT-bridging** (Mainline BT DHT + IPFS) | 🔥🔥 | L | Múltiples DHTs en paralelo aumentan resiliencia |

### C. Sociales / curadas

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| C1 | **Stream catalogs M3U-like** | 🔥🔥🔥 | S | URL `streams.json` que un broadcaster publica; viewers se "suscriben". Como RSS para streams. Empowerea comunidad |
| C2 | **Friend lists** con presence | 🔥🔥🔥 | M | Si tu amigo empieza a emitir, notificación en <5 s. Killer feature de engagement |
| C3 | **Stream aliases** memorables (`torrente.ese`) | 🔥🔥 | S | DNS-style. Mucho más shareables que hashes hex |
| C4 | **QR codes / deep links** | 🔥 | S | Móvil → desktop. Marketing en redes |
| C5 | **"Watch together" sessions** | 🔥🔥 | M | Privacidad opt-in: tus amigos ven que estás viendo X |
| C6 | **RSS / Atom feeds** por broadcaster | 🔥 | S | Notificación al estilo podcasts |
| C7 | **Federación con YouTube Live / Twitch** | 🔥 | M | Bridge a APIs públicas, indexar; redirige al sitio externo |

### D. Optimizaciones del DHT actual

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| D1 | **Pre-aggregated category bundles** | 🔥🔥 | S-M | Cada 30 min algun "super-peer" agrupa top N por categoría en una entrada Kad. Una sola búsqueda = 100 streams |
| D2 | **Bootstrap-on-launch shortcut** | 🔥🔥 | S | Al arrancar emule, si `last_viewed_streams.json` existe, ping a esos IPs primero — bypassea Kad cold-start |
| D3 | **Trending tag por publishCount** | 🔥 | M | Cada peer cuenta cuántas veces ha visto cada hash publicado; reporta top a Kad como "trending:topN" |
| D4 | **Republish desde viewers** (no solo broadcaster) | 🔥🔥 | S | Ya tenemos `PublishAsRelay` (DISC-S17). Aumentar agresividad: 3 segundos al inicio |
| D5 | **NameSystem distribuido** (DNSlink-style) | 🔥 | L | Hash registrado bajo alias resoluble |

### E. Onboarding / UX

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| E1 | **First-launch suggested streams** | 🔥🔥 | S | Lista pre-cargada de 10-20 streams "always-on" (testpatterns oficiales, demos) que aparezcan vacía la pestaña |
| E2 | **Hashtags / categorías clickeables** | 🔥 | S | Click en "Deportes" en card → search filtrado al momento |
| E3 | **Buscador con auto-suggestions** | 🔥 | S | Inline dropdown con coincidencias del directorio local |
| E4 | **Notificaciones push** | 🔥🔥 | M | Cuando broadcaster favorito vuelve. Browser notifications API |
| E5 | **Recomendaciones LLM local** | 🔥 | L | Pequeño modelo local sugiere streams basado en historial |

### F. Bootstrap & resilencia

| # | Idea | Impact | Effort | Notas |
|---|---|---|---|---|
| F1 | **Bootstrap nodos lista comunitaria** | 🔥🔥 | S | Lista mantenida en GitHub con IPs de "always-on" nodes para Kad seed |
| F2 | **Tor / I2P fallback** | 🔥 | L | Discovery via redes anonymizing cuando DHT está bloqueado |
| F3 | **NAT punching via STUN público** | 🔥🔥 | M | Resolver LowID-to-LowID problema, gana ~30% de hosts |

---

## 2. Matriz: impacto vs esfuerzo

```
       │
  ALTO │  A1   B1                C1                D1   D4
       │  C2          B2
       │  A4
       │  A2          A3                          D2     E1
  MEDIO│  B3                     C5                E4
       │                                          C3        
       │                B5      F1   F3
  BAJO │                B4              C4   C6   C7   D3   D5   F2
       │                                                     E2  E3  E5
       └─────────────────────────────────────────────────────────
           S     M     L
                ESFUERZO →
```

---

## 3. Estrategia recomendada (fase por fase)

### 🎯 Fase 1 — Quick wins (1 semana)

Cuatro cambios mínimos que dan **80% del valor**:

1. **A1 — HTTPS tracker federable** (2 días)
   - Node.js `tracker.js` que corra en Cloudflare Worker o VPS
   - Broadcasters POST `{streamKey, ip, port, title, ttl}` cada 60 s
   - Viewers GET `/list?category=...&lang=...&q=...` con CDN cache 5 s
   - Lista de trackers default en código (3-5 endpoints federados)
   - **eMule sigue funcionando sin tracker** — es FALLBACK, no requisito
   - Impact: discovery <1 s vs minutos

2. **B3 — mDNS LAN** (1 día)
   - Anuncia stream con `_emule-live._tcp.local`
   - En la misma red WiFi, descubre instantáneamente
   - Casos de uso: home network, oficina, eventos

3. **C1 — Stream catalogs M3U-style** (1 día)
   - Endpoint nuevo `/api/live/catalog/import?url=https://example.com/streams.json`
   - JSON schema simple: `[{streamKey, title, category, language, broadcasterHint}]`
   - Suscripciones persistidas; refresh cada 5 min
   - Empowera community curators

4. **E1 — First-launch suggested streams** (½ día)
   - Lista hardcoded (10-15 streams "siempre activos" — testpatterns públicos, demos)
   - Vacío grid se llena de algo al arrancar
   - Click → join inmediato

**Total estimado**: 4-5 días dev + 1 día testing
**Result**: usuario nuevo abre eMule por primera vez, click en "Live Directory", **ya ve streams en <2 segundos** (cargados de tracker + catálogos). No espera a Kad.

---

### 🎯 Fase 2 — Decentralization + social (2 semanas)

5. **B1 — PEX peer exchange** (4 días)
   - Cada `OP_LIVE_HEARTBEAT` actual añade ahora un campo `recentStreams[5]` (los 5 más vistos por ese peer en últimas 10 min)
   - Cuando recibo HEARTBEAT, mergeo en mi directorio local
   - **Sin trackers**, propaga viralmente

6. **C2 — Friend lists con presence** (5 días)
   - Pubkey por usuario (ya existe userhash)
   - "Add Friend" intercambia hashes
   - Notificación cuando friend empieza a emitir (via PEX o tracker)
   - Cards de friends destacadas arriba del grid

7. **C3 — Stream aliases** (3 días)
   - DNS-style: `mibroadcast.ese`
   - Resolución: el broadcaster registra su alias en un tracker (A1) + propaga en Kad como `livename:mibroadcast` → HASH
   - Links humanos en vez de hashes

8. **D2 — Bootstrap shortcut** (1 día)
   - `~/.eMule/last_streams.json` guarda los 20 IPs de los últimos broadcasts vistos
   - Al arrancar, ping a esos IPs antes de Kad bootstrap
   - 30% de los joins exitosos sin tocar Kad

**Total estimado**: ~13 días dev
**Result**: ecosystem social emerge, "qué están viendo mis amigos" funciona, aliases hacen los links compartibles en Twitter/Discord.

---

### 🎯 Fase 3 — Long-term scaling (1-2 meses)

9. **B2 — HyParView + Plumtree** (3-4 sem)
   - Gossip estructurado, sub-segundo cross-continent
   - Ya en `MASTER_PLAN.md §11.3.7`

10. **A4 — WebRTC signaling** (2 sem)
    - Sub-segundo discovery via WS relay
    - También habilita viewers browser-only (sin eMule instalado)

11. **D1 — Category bundles** (1 sem)
    - Aggregator runs as super-peer
    - Reduce Kad searches a 1 por categoría

12. **C7 — Federación YouTube/Twitch** (2 sem)
    - Indexar streams externos
    - Click → abre en plataforma original, pero descubren la app

**Total estimado**: ~10 semanas
**Result**: capacidad para 50k-500k viewers, discovery sub-segundo, ecosystem comparable a Twitch en términos de descubrimiento.

---

## 4. Mi recomendación de ataque

Si tuviera que elegir UNA cosa para empezar mañana: **A1 + E1** (1 semana).

**Por qué**:
- Solo con el tracker + suggested streams, un usuario nuevo tiene experiencia "tipo YouTube" desde el primer arranque.
- Es completamente OPCIONAL — eMule sigue funcionando 100% P2P si el tracker está caído.
- El tracker NO ve el contenido (solo metadata pública); no hay implicaciones de privacidad mayores que las que ya existen al publicar a Kad.
- Cloudflare Worker free tier soporta 100k requests/día gratis → tracker puede atender ~5000 broadcasters concurrentes sin costo.
- Si el tracker triunfa, otros pueden levantar trackers federados — sin permiso, sin dependencia.

**Lo que NO recomiendo**: HyParView/WebRTC/Tor ahora. Son grandes inversiones sin validación previa de qué problema realmente bloquea adopción. Mejor lanzar lo simple, ver qué falla, iterar.

---

## 5. Decisión

| Opción | Acción |
|---|---|
| **A** | Implementar Fase 1 completa (1 semana) → mayor mejora de UX |
| **B** | Solo tracker A1 (2 días) → quick win, validar antes de expandir |
| **C** | Saltar a Fase 3 directamente (HyParView, WebRTC) → trabajo serio |
| **D** | Seguir solo con DHT + lo ya hecho → no añadir nuevos vectores |

Mi voto: **B**. Tracker simple, observar uso real, iterar.
