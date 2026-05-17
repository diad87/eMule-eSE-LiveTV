# 🍿 Guía rápida — Tu Netflix P2P en 5 minutos

> Esta guía es para usuarios que **no quieren complicarse**. No hay que compilar nada, no hay que instalar nada. Solo descargar, descomprimir y pulsar un botón.

---

## 1️⃣ Descarga el paquete desde GitHub

Abre tu navegador y entra aquí:

👉 **https://github.com/diad87/eMule-eSE-LiveTV/releases**

Verás una lista de versiones. La de arriba del todo es la más reciente. Busca el fichero que termina en **`.zip`** (pesa unos 84 MB) y haz clic para descargarlo.

![Página de releases en GitHub con el ZIP destacado](docs/screenshots/01-github-releases.png)

> 💡 *Captura sugerida: la página de Releases de GitHub con una flecha apuntando al fichero `eSE-LiveTV-x64-XXXX-XX-XX.zip`.*

---

## 2️⃣ Descomprime el ZIP

Una vez descargado, haz **clic derecho** sobre el ZIP → **Extraer todo…**

Elige una carpeta donde te sea fácil acceder (por ejemplo `C:\eSE` o el Escritorio). Cuando termine, abre la carpeta extraída — verás algo así:

![Contenido de la carpeta extraída](docs/screenshots/02-carpeta-extraida.png)

> 💡 *Captura sugerida: el Explorador de Windows mostrando los ficheros dentro de la carpeta. El protagonista es `emule.exe` (con icono del burrito).*

Los ficheros clave son:
- **`emule.exe`** ← este es el que vas a abrir
- **`ese-server.exe`** ← el motor del panel web (no toques, pero tiene que estar al lado de `emule.exe`)
- carpeta `eSE\` — los recursos del panel web
- carpeta `node\` — Node.js portable (no toques nada)

> ⚠️ **No muevas ningún fichero ni carpeta.** `emule.exe` y `ese-server.exe` **tienen que estar siempre en la misma carpeta**; si no, el botón eSE dará error.

---

## 3️⃣ Arranca eMule

Haz **doble clic** en `emule.exe`.

La primera vez Windows puede pedirte permiso para abrir el cortafuegos — **acepta** (es para que eMule pueda conectarse a la red P2P).

> 🛡️ Si ves un aviso de Windows SmartScreen ("Se impidió el inicio de una aplicación no reconocida"), haz clic en **Más información → Ejecutar de todas formas**.

Se abrirá la ventana clásica de eMule:

![Ventana principal de eMule recién abierta](docs/screenshots/03-emule-abierto.png)

> 💡 *Captura sugerida: ventana principal de eMule en la pantalla de inicio, con la barra de herramientas arriba y la barra de estado abajo.*

---

## 4️⃣ Conéctate a ed2k y Kad

En la barra de herramientas de arriba, pulsa el botón **Conectar**:

![Botón Conectar en la barra de herramientas de eMule](docs/screenshots/04-boton-conectar.png)

> 💡 *Captura sugerida: la barra de herramientas de eMule con el botón "Conectar" rodeado en rojo.*

Espera unos segundos. En la parte de abajo a la derecha (la barra de estado) tienen que aparecer **dos bolitas verdes** 🟢🟢:

- **ed2k:** verde = conectado al servidor de la red eDonkey
- **Kad:** verde = conectado a la red Kademlia (la descentralizada)

![Indicadores ed2k y Kad en verde](docs/screenshots/05-conectado-verde.png)

> 💡 *Captura sugerida: esquina inferior derecha de eMule mostrando los dos indicadores en verde.*

Si alguna queda en amarillo o rojo, espera 1-2 minutos más — a veces tarda en encontrar nodos. Si pasados 5 minutos siguen sin ponerse en verde, revisa tu cortafuegos o el router.

---

## 5️⃣ Pulsa el botón **eSE** — y a disfrutar

Ya con eMule conectado, busca en la barra de herramientas el botón con el logo **eSE**:

![Botón eSE en la barra de herramientas](docs/screenshots/06-boton-ese.png)

> 💡 *Captura sugerida: la barra de herramientas de eMule con el botón eSE resaltado.*

Púlsalo. eMule arranca el servidor web internamente y se abre tu navegador en el **panel eSE** — tu Netflix P2P:

![Panel principal de eSE en el navegador](docs/screenshots/07-panel-ese.png)

> 💡 *Captura sugerida: la interfaz web en `http://localhost:8080` con la sección Live TV, posters de películas, etc.*

Desde ahí puedes:
- 📺 **Ver canales en directo** que otros usuarios estén emitiendo
- 🎬 **Buscar películas** con carátulas (vía TMDB) y reproducirlas mientras se descargan
- 📡 **Emitir tu propio canal** vía RTMP (por ejemplo desde OBS)

> 💡 Para parar el panel sin cerrar eMule, vuelve a pulsar el botón eSE: hace toggle (arranca/para el servidor).

---

## ❓ Problemas frecuentes

**Al pulsar el botón eSE sale "No se encontró ese-server.exe junto a emule.exe"**
→ Has movido `emule.exe` o `ese-server.exe` a carpetas distintas. Tienen que estar **siempre en la misma carpeta**. Si extrajiste mal el ZIP, vuelve a extraer y deja la estructura intacta.

**Windows SmartScreen bloquea `emule.exe`**
→ Clic derecho sobre el ZIP original **antes** de extraer → Propiedades → marca "Desbloquear" → Aplicar. Vuelve a extraer.

**El navegador abre `localhost:8080` pero la página no carga**
→ Espera 10 segundos más y refresca con F5. La primera vez tarda en arrancar el servidor.

**eMule no se pone en verde (ed2k/Kad)**
→ Comprueba que tu router no está bloqueando los puertos **4662 TCP** y **4672 UDP**. Si tu ISP usa CGNAT, abre el panel eSE y entra en **Settings → NAT** para ver el diagnóstico.

**Falta FFmpeg para emitir en directo**
→ Solo lo necesitas si vas a **emitir** un canal (no para ver). Descarga `ffmpeg.exe` de https://ffmpeg.org y déjalo al lado de `emule.exe`.

---

## 📂 Para cerrarlo todo

- **Cerrar el panel web (sin cerrar eMule):** pulsa otra vez el botón **eSE** en la barra de herramientas.
- **Cerrar eMule del todo:** clic derecho en el burrito de la bandeja del sistema → **Salir**. Eso cierra eMule, el servidor web y libera los puertos.

---

¿Listo? Pues ya tienes tu Netflix descentralizado funcionando 🎉
