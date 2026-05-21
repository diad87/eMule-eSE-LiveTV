# v0.70b-eSE 8.0.0 — Privacy V1

First release with **onion routing 2-hop privacy layer verified empirically between two physical machines**. Compatible 100% con la red eD2K + Kad existente (TLV-additive, backward compat con eMule 0.70b vanilla).

> ⚠️ La pila de privacidad onion es **V1 — funcional pero no auditada externamente todavía**. La criptografía está implementada con primitivos estándar (CryptoPP) y verificada empíricamente, pero hasta que pase auditoría externa + ProVerif, no es válida para casos de uso donde la vida dependa de ello.

## 🧅 Privacy V1 — onion routing (NUEVO)

- **Cripto onion**: X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD
- **2-hop circuits** con self-loopback para setups de testing con 2 PCs
- **Auto-discovery** vía `TAG_ESE_CAPS` (0x6C) en `OP_HELLO` — backward compat con v7.x
- **Cover traffic** real con distribución Poisson (`CELL_PADDING` inyectado)
- **Identity binding** hash en `CELL_CREATE`/`EXTEND` (anti-redirection MITM)
- **Tunneled Kad search** — el destino nunca sabe quién pregunta
- **Suscripciones cifradas con DPAPI** + REST CRUD API
- **3 modos elegibles**: Directo / Tunelizado / Adaptativo

## 🔍 Verifiabilidad — REST API para auditar el stack en vivo

- `GET /api/live/privacy` — estado runtime + capabilities bitmap
- `GET /api/live/privacy/peers` — peers visibles + sus capabilities
- `GET /api/live/privacy/circuits` — circuits activos + estado por hop
- `GET /api/live/privacy/test_circuit?hops=2` — construye circuito onion
- `GET /api/live/privacy/tunnel_ping?text=X` — demo data plane (echo)
- `GET /api/live/privacy/tunnel_search?keyword=Y` — Kad search anónima
- `GET /api/live/privacy/subscriptions` — CRUD canales suscritos

## 🖥 UI mejoras

- Nuevo bloque **"Privacidad (eSE V1)"** en Información propia
  — auto-refresca cada 2s con estado real
- Nuevo pane **`P:Adaptive`** en barra de estado — modo + circuits activos/pendientes
- Todos los contadores leen de los singletons vivos, no de config cacheada

## 🌐 IPv6

- Detección automática de IP pública v6 vía `api6.ipify.org` (HTTPS, 5s timeout)
- Modos: Off / **Auto (default)** / Preferido (experimental)
- Etiquetas honestas en GUI: el checkbox dice exactamente lo que hace

## 🔐 Stream integrity (v7.6/v7.7)

- Ed25519 long-term keypair por broadcaster
- `streamKey` self-certificante = `sha1(pubkey)[:16]`
- Chunks firmados (`OP_LIVE_CHUNK_V2` con Ed25519 signature)
- `OP_LIVE_END` firmado (tombstone con signature sobre `streamKey || reason`)
- Pubkey pinning en receivers — un atacante no puede inyectar chunks falsos

## 📡 Verificación empírica end-to-end

**LiveTV PC1→PC2 entre dos NATs distintas (validado hace días):**
- PC1 HighID, testpattern 3000 kbps vía FFmpeg → RTMP ingest → publicado en Kad
- PC2 LowID, pegó enlace `|live|`, reproducido primero en VLC (fase 1), después en el reproductor cinema integrado del propio eSE (fase 2)
- Sin VPS, sin Cloudflare, sin terceros

**Privacy V1 entre dos máquinas reales (hoy):**
- Auto-discovery TAG_ESE_CAPS: PC1 vio a PC2 con `eseCaps: 0x00000F35`, recíproco confirmado
- Handshake onion 1-hop: `circuitsActive: 1` confirmado vía REST en 800 ms
- Handshake onion 2-hop: `hop_count: 2` confirmado en 47 ms con cripto X25519 + HKDF separation por dirección
- Data plane: `tunnel_ping?text=hola` devolvió `received: "echo:hola"` a través del onion 2-hop. **Bytes reales atravesaron la cebolla ida y vuelta.**

## ⚠ Limitaciones conocidas (honestidad ante todo)

- **Identity binding es "lite", no full ntor.** Defensa contra redirección por hop1, no contra MITM activo con clave long-term. Full ntor con per-node Ed25519 identity en roadmap.

- **2-hop verificado en loopback (2 PCs)**. Con solo 2 nodos del fork, hop1 = hop2 = mismo nodo físico → anonimato real = 0, protocolo válido. Anonimato real requiere 3+ nodos del fork en la red.

- **Data plane parcial.** Solo `tunnel_ping` y `tunnel_search` van por la cebolla. Kad search nativo, LiveTV subscribe y chunks reales todavía van por path eD2K directo. v8.1 lo cablea.

- **Listener IPv6 dual-stack (modo Preferido) rompe HighID** en eD2K. Reproducido en 2 redes distintas — bug fundamental. **Default Auto NO se ve afectado.** Para experimentar dual-stack: editar `preferences.ini` → `IPv6Mode=2`.

- **WebServer clásico de eMule (puerto 4711)** tiene un bug raro de bind en algunos equipos. Workaround: el panel Node sirve los segmentos HLS directamente.

- **Búsqueda Kad clásica** sigue siendo la del eMule original. El rediseño Kad Search v2 está parcialmente implementado (M3 vivo, M1/M5/M6 con bits seteados pero handlers parciales).

- **USER_GUIDE.md** dentro del ZIP tiene una nota desactualizada que menciona `eSE.vbs` — ese launcher YA NO EXISTE. El método correcto está en el README.md y abajo en este release.

## 🚀 Migración desde v7.x

Drop-in replacement. No hay cambios de formato. `nodes.dat`, `known.met`, `preferences.ini`, `server.met` siguen funcionando tal cual. El único fichero nuevo es `subscriptions.dat` en `%APPDATA%\eMule\ese\` (DPAPI cifrado, vacío al primer arranque).

## 📋 Roadmap próximo

- **v8.1**: cablear Kad search + LiveTV subscribe a través del tunnel en modo Tunelizado
- **v8.2**: MFC dialog nativo para gestión de suscripciones + import/export invite tokens base32
- **v8.x**: full ntor con identidad Ed25519 long-term por nodo
- **v9.0**: ProVerif validation + auditoría externa cerrada + 3-hop opt-in

## 🚀 Cómo arrancar (corregido)

1. **Descarga el ZIP** del asset abajo
2. **Descomprime** en cualquier carpeta (p.ej. `C:\eSE\`)
3. **Doble click en `emule.exe`**
4. Espera a que conecte a **eD2K + Kad** (verás IDs verdes / amarillas en la barra de estado)
5. **Click en el botón `eSE` de la barra de herramientas** de eMule
6. Tu navegador por defecto se abre automáticamente en `http://localhost:8080/live`

**No hay instalador. No toca registro.** Toda la config va a `%APPDATA%\eMule\` y `%APPDATA%\eSE\`.

> Si el firewall de Windows pide permiso para `emule.exe`, `ese-server.exe`, o `ffmpeg.exe` — acéptalo. Son los tres procesos que necesita el bundle.

## 🧪 Cómo verificar la pila de privacidad

```powershell
# Estado general (puerto del eMule classic web admin, NO el panel Node 8080)
curl http://127.0.0.1:4711/api/live/privacy | ConvertFrom-Json | Select -Expand runtime

# Construir circuito 2-hop (necesita otro nodo fork conectado vía eD2K)
curl 'http://127.0.0.1:4711/api/live/privacy/test_circuit?hops=2'

# Esperar y verificar hop_count=2
Start-Sleep -Seconds 2
curl http://127.0.0.1:4711/api/live/privacy/circuits | ConvertFrom-Json | ConvertTo-Json -Depth 4

# Demo data plane atravesando la cebolla
curl 'http://127.0.0.1:4711/api/live/privacy/tunnel_ping?text=hola'
# Esperado: {ok:true, sent:"hola", received:"echo:hola"}
```

## 🤝 Busco testers

Bugs por **GitHub Issues** o por el hilo del foro. **No contesto MPs.**

---

GPLv2. Windows 10/11 x64. Hecho con asistencia de Gemini 3.1 Pro + Claude Code.
