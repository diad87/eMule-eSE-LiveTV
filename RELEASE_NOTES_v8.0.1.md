# v0.70b-eSE 8.0.1 — Privacy V1 hotfix: cero dependencias externas

Hotfix de v8.0.0. Cierra un blocker transversal: el panel Node.js (`ese-server.exe`) llamaba en runtime a varios servicios de terceros que contradicen los invariantes del proyecto. Todos fuera. La pila eD2K/Kad y la pila Privacy V1 no cambian.

> El binario `emule.exe` no se ha tocado. Es el mismo de v8.0.0. Solo cambia `ese-server.exe` y el bundle JS de cliente. Si solo te interesa la pila P2P, no hace falta actualizar.

## ⚠ Por qué este hotfix

Auditoría revisada el 2026-05-19 detectó las siguientes llamadas a terceros en `ese-server.exe` v8.0.0:

| Servicio | Uso anterior | Riesgo |
|---|---|---|
| `ntfy.sh` | publishUrl + heartbeat 5min para acceso remoto | TOS / privacy leak; expone uso por nodo |
| `api.telegram.org` | bot notifications opcional | API key del usuario filtrada si configuró bot |
| `img.icons8.com` | iconos PWA (manifest) | tracking pasivo en cada install |
| `cdn.jsdelivr.net/hls.js` | reproductor cinema (runtime) | dep crítica externa; bloqueo de jsdelivr = no hay player |
| `fonts.googleapis.com` (Inter) | tipografía UI | tracking pasivo en cada GET |
| `api.ipify.org` / `icanhazip.com` / `ifconfig.me` | fallback de IP pública | filtra que usas eSE |
| `api.qrserver.com` | QR de emparejamiento móvil | filtra la URL local + código pairing |
| `cloudflare_tunnel.js` (stub) | borrado en v7.4.0, quedaba dead code | ninguno funcional, limpieza |

Estas llamadas violaban tres reglas grabadas del proyecto:
- `feedback_cloudflare_tos.md` — never rely on CF for content delivery
- `feedback_gratis_no_barato.md` — cero coste, sin VPS, sin dominios
- `project_ese_privacy_architecture.md` — ese-server no debe filtrar uso

## 🧹 Qué cambia en v8.0.1

### Eliminado
- **`tunnel.js`** reescrito: ya no llama a ntfy.sh ni Telegram ni a servicios HTTP de IP. La detección de IP pública ahora la hace el router via UPnP (`GetExternalIPAddress` SOAP), sin dependencia externa.
- **`eSE_Remote.html`** borrado: era una página redirect que polleaba ntfy.sh.
- **`/go`, `/remote`, `/qr`** retiradas: dependían de ntfy/qrserver. Reemplazadas por una página estática que lista IPs LAN + recomienda Tailscale/Tor onion para acceso cruzado.
- **`/connect` QR** generado por qrserver.com: eliminado. El emparejamiento móvil ahora es manual: muestra código de un solo uso + URL completa para escribir en el teléfono.
- **`hls.js` desde jsdelivr** → bundleado dentro de `ese-server.exe` y servido en `/vendor/hls.min.js`.
- **`Inter` desde Google Fonts** → `system-ui` fallback.
- **icons8.com PWA icons** → SVG local (`/emule_mascot.svg`).
- **api.ipify.org STUN fallback** en `/api/live/preflight` → solo Kad. Si Kad aún no detectó tu IP, la UI dice "Esperando a Kad" en vez de filtrar por terceros.
- **`cloudflare_tunnel.js` stub** borrado (Cloudflare ya estaba fuera desde v7.4.0).
- **Telegram bot** quitado de `tunnel.js`. Si tenías `telegram.json` configurado, deja de mandar mensajes silenciosamente (no se elimina el fichero — quítalo a mano si quieres).

### Añadido
- **`/api/system/network`** nuevo endpoint: lista IPs LAN, IPs Tailscale (heurística por rango 100.64.0.0/10), v6, y estado UPnP. Útil para diagnosticar conectividad sin filtrarla.
- **Tailscale detection** integrada en `/api/connect-seed` y en el flujo de `/app`: si tienes Tailscale activo, se ofrecen sus IPs como ruta alternativa.

### Mantenido (y honestidad sobre por qué)
- **`nodes-dat.com`** sigue siendo el fallback de bootstrap de Kad SI tras 60s Kad no arranca. Es una lista de peers Kad pública, no telemetría. eMule classic hace lo mismo desde hace 20 años. La ZIP sigue trayendo un `nodes.dat` bundleado como fuente primaria; el fetch externo solo dispara en último recurso. Sigue siendo un dominio externo; aceptado pragmáticamente para que la red P2P arranque para usuarios nuevos.
- **TMDB / OMDb / YouTube embed / Google OAuth** siguen disponibles porque son features opt-in del usuario (poster art, trailers, AI assistant). El usuario decide si configura su API key; eSE no llama por defecto.

## 🛠 Verificación

Estática (re-grep tras el hotfix):
```bash
grep -rE 'cloudflare|trycloudflare|ntfy\.sh|api\.telegram|img\.icons8|cdn\.jsdelivr|fonts\.googleapis|api\.ipify|icanhazip|ifconfig\.me|api\.qrserver' srchybrid/eSE/ --exclude-dir=node_modules --exclude-dir=_deprecated
```
Solo devuelve comentarios documentando la eliminación. Ninguna llamada activa.

Dinámica (recomendada antes de instalar):
```powershell
# Wireshark filter — captura todo tráfico que sale de ese-server.exe durante 5 min idle:
# Filter: ip.dst != 127.0.0.0/8 and ip.dst != 192.168.0.0/16 and ip.dst != 10.0.0.0/8 and ip.dst != 100.64.0.0/10
# Esperado: 0 paquetes (excepto Kad UDP en 4672, eD2K en 4662)
```

## 📦 Compatibilidad

- **eD2K + Kad**: sin cambios. 100% compatible con eMule 0.70b vanilla, v7.x y v8.0.x. El protocolo no se ha tocado.
- **Privacy V1 (onion routing)**: sin cambios funcionales. Los circuits, cripto, cover traffic — todo idéntico a v8.0.0.
- **Settings**: `%APPDATA%\eSE\config.json` se mantiene. Si tenías `telegram.json`, deja de usarse silenciosamente.
- **Suscripciones**: `%APPDATA%\eMule\ese\subscriptions.dat` sin cambios.
- **Acceso remoto fuera de LAN**: roto si dependías de ntfy.sh + UPnP. Alternativas: instala **Tailscale** (gratis, P2P, sin dominio) o monta un Tor onion service apuntando a `http://127.0.0.1:8080`.

## 🚀 Cómo arrancar (igual que v8.0.0)

1. Descarga el ZIP del asset abajo
2. Descomprime en cualquier carpeta
3. Doble click en `emule.exe`
4. Espera a que conecte (eD2K + Kad verdes/amarillas)
5. Click en el botón `eSE` de la toolbar
6. Navegador en `http://localhost:8080/live`

## 📋 Próximo (v8.1)

- Bloque A — Full ntor identity binding (Ed25519 long-term keys por nodo)
- Bloque B — LiveTV chunks via tunnel (subscribe + chunk + publish todo cifrado)
- Bloque C — Channel discovery privado (LiveChannel publish + verify cableado)

Roadmap completo en plan interno; ETA 2-3 semanas tras v8.0.1 estable.

## 🤝 Tests bienvenidos

Si verificas con Wireshark que tu instalación NO contacta con ninguno de los servicios eliminados durante 5+ minutos idle, dilo en el foro / issue. Es el único smoke test real para "100% sin terceros".

---

GPLv2. Windows 10/11 x64. Hecho con asistencia de Gemini 3.1 Pro + Claude Code.
