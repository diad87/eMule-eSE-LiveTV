# Distribution analysis — 2026-05-16

Estado real del checkout en este momento. **Ningún cambio hecho todavía**;
esto es el snapshot de lo que tenemos, lo que falta y los riesgos antes
de tocar nada.

---

## 1. Lo que SÍ tenemos (verificado en disco)

| Pieza | Ruta | Tamaño | mtime | Estado |
|---|---|---|---|---|
| `emule.exe` Release x64 | `srchybrid/x64/Release/emule.exe` | 11.6 MB | hoy 22:44 | ✅ Fresco |
| `ese-server.exe` (pkg) | `srchybrid/eSE/ese-server.exe` | 55 MB | hoy 23:00 | ⚠️ **Obsoleto** — añadí cambios al JS a las 23:28 (update toast en `live_tv_page.js`) que no están dentro |
| `cloudflared.exe` | `srchybrid/eSE/cloudflared.exe` | ~25 MB | — | ✅ Presente |
| `ffmpeg.exe` (Gyan full) | `%LOCALAPPDATA%\…\Gyan.FFmpeg…\ffmpeg-8.1-full_build\bin\ffmpeg.exe` | 101 MB | — | ✅ Localizable; **pesa la mitad del paquete** |
| `node.exe` | `C:\nvm4w\nodejs\node.exe` | — | — | ✅ En PATH |
| Snapshot previo | `Desktop/eSE-Package/` | 339 MB | 15-may | ⚠️ Lleva basura (`emule.exe.bak`, `emule.exe.bak2`, `ese-server.exe.OLD`) |
| ZIP previo | `Desktop/eSE-Package-x64.zip` | — | — | Existe, anterior a todos los cambios de hoy |
| Script de packaging | `build_package.ps1` | — | — | ✅ Funcional, ya parchado para idiomas + docs + tools/ |
| Installer "minimalista" | `installer.iss` | 2.4 KB | — | ✅ Inno Setup script, ~30 LOC |
| Installer "completo" | `installer/setup_ese.iss` | 4.9 KB | — | ✅ Modern wizard, soporta ES+EN, firewall, taskkill, uninstall limpio |
| Launcher | `installer/eSE.vbs`, `srchybrid/eSE-dist/eSE.vbs`, `srchybrid/eSE/eSE.vbs` | — | — | ⚠️ **3 copias** — habría que consolidar |

## 2. Lo que NOS FALTA

### Bloqueante para shippear
| # | Falta | Impacto | Tiempo de arreglar |
|---|---|---|---|
| F1 | `ese-server.exe` no contiene los últimos cambios (update toast D6) | El botón "Actualizar ahora" no aparece | 2 min: `cd srchybrid/eSE && npm run build` |
| F2 | **Las 43 DLLs de idiomas no están construidas** (`srchybrid/x64/lang/` no existe) | Toda interfaz MFC en inglés aunque Windows esté en español | 10 min: MSBuild de cada `lang/*.vcxproj` (el `[1b]` del `build_package.ps1` ya lo hace) |
| F3 | `eMule.tmpl` no encontrado ni en `srchybrid/` ni en `%APPDATA%` | El WebServer eMule rehúsa arrancar al primer install | Hay que localizarlo; suele estar en el repo upstream o en un instalación previa |
| F4 | `server.met` y `nodes.dat` ausentes | eD2K vacío + Kad bootstrap lento al primer arranque | `build_package.ps1` ya los descarga si faltan (gruk.org + nodes-dat.com) |

### Importante pero no bloqueante
| # | Falta | Impacto | Notas |
|---|---|---|---|
| F5 | **Inno Setup compiler (ISCC.exe) no instalado** | No podemos producir `.exe` installer, solo ZIP portable | `winget install JRSoftware.InnoSetup` (~6 MB) |
| F6 | Firma digital / certificado .pfx | SmartScreen muestra "publisher desconocido" → click extra para usuario | Cert OV-code-signing ≈ 250 €/año, o Microsoft Trusted Signing para OSS |
| F7 | Tag/version unificada | `installer/setup_ese.iss` dice `0.70b-eSE6.2`, no hay tag git actual | Decisión de versionado — propongo `v0.70b-eSE7.0` (cambios mayores: discovery + sec + auto-update + crash + langs) |
| F8 | 11 cambios de C++/JS sin commitear + 7 archivos nuevos | El build de hoy (23:00) no refleja git HEAD | Commit antes de buildear final |

### Polish
| # | Falta | Impacto |
|---|---|---|
| F9 | 3 copias diferentes del launcher `eSE.vbs` | Confusión sobre cuál es la "buena" |
| F10 | El script no produce SHA256 checksum del ZIP final | Usuarios no pueden verificar integridad de la descarga |
| F11 | No hay release notes para el tag | Página de GitHub Releases queda vacía |
| F12 | `.github/workflows/build.yml` (D8 de ayer) genera artefacto en CI pero **no** sube release | Cada release sigue siendo manual |

---

## 3. Riesgos que vi al revisar

| Riesgo | Causa | Mitigación |
|---|---|---|
| R1 — ZIP final infla con `*.bak` / `*.OLD` del snapshot anterior | `build_package.ps1` hace `Remove-Item $dst -Recurse` al principio, así que **el dst se limpia**, pero el `eSE-Package` antiguo en Desktop **no es el `$dst`** — son dos rutas distintas | Verificar que `$dst` realmente queda limpio. Hoy parece OK. |
| R2 — ffmpeg full build = 101 MB de los 150 MB del ZIP | `build_package.ps1 [5a]` copia el que encuentre, sin elegir variante | Cambiar a "essentials build" (~40 MB) — auto-detecta NVENC/QSV igual |
| R3 — `[1b] lang` requiere MSBuild en PATH | Si el usuario corre `build_package.ps1` desde un PowerShell normal sin VS DevPrompt, MSBuild puede no estar | El script ya busca via `vswhere`, fallback documentado |
| R4 — `[5b0] server.met` se baja de `gruk.org` por HTTP, sin TLS | MITM podría inyectar lista de servidores maliciosos | Cambiar a `https://gruk.org/server.met.gz` (si soporta) o agregar checksum conocido |
| R5 — Dos `.iss` distintos sin documentar cuál usar | `installer.iss` (raíz, simple) vs `installer/setup_ese.iss` (modern wizard) | Recomiendo conservar **solo** `installer/setup_ese.iss` y borrar el otro |
| R6 — `LiveStreamManager` y otros componentes nuevos sin smoke test final | Los cambios de seguridad de hoy (XSS fix) cambiaron el HTML servido en `/live` — si el JS rompe, la página queda blanca | Validar con `npm run build` + lanzar `emule.exe`, abrir `/live` en navegador |
| R7 — Idiomas: aún si construimos las 43 DLLs, los `.rc` heredados de eMule 0.70b están desactualizados (no tienen strings para los cambios nuevos como el wizard) | Strings nuevas caen en `IDS_MB_LANGUAGEINFO` -> en inglés | No bloquea — el dashboard Node sí está en español. Los menús MFC heredados ya estaban traducidos en su época, los strings nuestros son ASCII en inglés (LIVE_LOG etc.) y van al log, no al usuario |

---

## 4. Lo que necesitamos producir

Suponiendo objetivo "release portable + installer, instalable por usuario final en Win10/11 sin nada previo":

### Pipeline de build (orden estricto)
1. **Git commit** de los 11 cambios + 7 archivos nuevos (todo lo de hoy: D1-D10 + langs + modernización)
2. **MSBuild** `srchybrid/emule.sln` → `emule.exe`
3. **npm install + npm run build** en `srchybrid/eSE/` → `ese-server.exe` con cambios de hoy
4. **MSBuild** de los 43 `srchybrid/lang/*.vcxproj` → `srchybrid/x64/lang/*.dll`
5. **`build_package.ps1`** orquesta:
   - Copia `emule.exe`, `ese-server.exe`, langs, ffmpeg, node, cloudflared, configs, docs, tools
   - Genera ZIP
6. **(Opcional)** `ISCC installer/setup_ese.iss` → `.exe` installer
7. **(Opcional)** `signtool sign` sobre `emule.exe` + `ese-server.exe` + installer.exe
8. **SHA256** del ZIP/installer
9. **Subir a GitHub Releases** con tag + release notes

### Productos finales
- `eSE-LiveTV-x64-YYYY-MM-DD-portable.zip` — ZIP portable, ~85-150 MB
- `eSE-LiveTV-x64-YYYY-MM-DD-setup.exe` — installer Inno Setup, ~80-145 MB
- `SHA256SUMS.txt` — checksums

---

## 5. Lo que NO voy a hacer (out of scope hoy)

- Firma digital (sin certificado disponible)
- Build de ffmpeg essentials (requiere descarga manual del build de Gyan)
- Subida automática a GitHub Releases (necesita `gh` autenticado + token)
- Refactor de los 3 `eSE.vbs` a uno solo
- Verificar todas las strings traducidas en los `.rc` heredados (mucho trabajo, marginal)

---

## 6. Decisiones que necesito de ti

Después del análisis quedan estas decisiones de scope antes de tirar
del gatillo. Te las pongo arriba.
