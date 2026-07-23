# Guía rápida de eMule eSE 9.0.0-beta.1

Esta beta pública funciona como una aplicación portable para Windows 10/11
x64. No hace falta compilar ni instalar nada.

## 1. Descargar

Descarga el paquete oficial:

[eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip](https://github.com/diad87/eMule-eSE-LiveTV/releases/download/v0.70b-eSE9.0.0-beta.1/eSE-LiveTV-v0.70b-eSE9.0.0-beta.1-x64.zip)

La [página de la versión](https://github.com/diad87/eMule-eSE-LiveTV/releases/tag/v0.70b-eSE9.0.0-beta.1)
incluye también el fichero SHA-256 para comprobar la descarga.

## 2. Extraer

Haz clic derecho en el ZIP, elige **Extraer todo** y usa una carpeta con
permisos de escritura, por ejemplo `C:\eSE\`.

No ejecutes el programa desde dentro del ZIP ni separes sus archivos. El
paquete ya contiene `emule.exe`, `ese-server.exe`, FFmpeg, el panel web, los
idiomas y la configuración inicial.

## 3. Iniciar y conectar

1. Abre `emule.exe`.
2. Autoriza el acceso en el cortafuegos de Windows si lo solicita.
3. Pulsa **Conectar** y espera a que eD2K y Kad se conecten.
4. Pulsa el botón **eSE** de la barra de herramientas.
5. Se abrirá el panel en
   [http://localhost:8080/live](http://localhost:8080/live).

La primera ejecución muestra una decisión sobre **NetLab**. Actívalo solo si
quieres participar en mediciones de conectividad. Rechazarlo no impide usar
eMule ni Live TV.

## 4. Ver o emitir

Desde el panel eSE puedes:

- descubrir y ver emisiones P2P disponibles;
- abrir una URL HLS local para reproducir una emisión;
- crear una emisión desde OBS/RTMP, pantalla, archivo o patrón de prueba;
- elegir codificación por GPU cuando esté disponible, con alternativa
  automática por CPU.

## Solución rápida de problemas

### El botón eSE no abre el panel

Espera unos segundos y abre manualmente
[http://localhost:8080/live](http://localhost:8080/live). Si no responde,
comprueba que `ese-server.exe` continúa junto a `emule.exe` y que el
cortafuegos no lo ha bloqueado.

### eD2K o Kad no conectan

Espera unos minutos y revisa el cortafuegos y el router. Los valores habituales
son TCP `4662`, UDP `4672` y el panel local TCP `8080`, pero los puertos P2P
pueden cambiarse en Preferencias.

### Windows muestra SmartScreen

Verifica que el ZIP procede de la versión oficial y comprueba su SHA-256. Si
confías en el archivo, usa **Más información > Ejecutar de todas formas**.

### Quiero cerrar eSE

Vuelve a pulsar el botón **eSE** para detener el panel. Salir de eMule detiene
también los procesos auxiliares.

Para configuración avanzada, emisión con OBS y diagnóstico consulta la
[guía de usuario](docs/USER_GUIDE.md).
