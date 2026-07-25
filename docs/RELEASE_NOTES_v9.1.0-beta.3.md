# eMule eSE 9.1.0-beta.3

Estado: **candidata beta pública de laboratorio para Windows x64**.

Beta.3 conserva íntegro el alcance IPv6/Kad6 y las correcciones de beta.2.
Añade una política única y comprobable para impedir que archivos temporales,
incompletos o inseguros entren en la biblioteca compartida.

## Cambios desde beta.2

### LiveTV con emisión y reproducción simultáneas

- Emitir un canal local mientras se reproduce otro canal remoto mantiene
  identidades, claves, buffers, bitrates y temporizadores independientes.
- Los anuncios, latidos, publicación Kad, malla, túneles y relays utilizan la
  identidad correspondiente a cada rol.
- Los segmentos del canal local no pueden entrar en el HLS del canal remoto,
  ni los chunks remotos pueden redistribuirse a los espectadores de la emisión
  local.
- Las peticiones de actividad y cierre del reproductor quedan vinculadas a la
  clave que se está visualizando.
- El directorio deduplica las claves de stream sin distinguir mayúsculas y
  minúsculas.
- Las miniaturas remotas nunca reutilizan la captura del canal local como
  fallback.
- El self-test reproduce el escenario de doble rol y comprueba que la clave
  publicada y ambos buffers permanecen aislados.

### Admisión segura de archivos compartidos

- El escaneo inicial y `DirectoryWatcher` utilizan exactamente la misma
  política.
- Se rechazan directorios, atributos de sistema/temporales, archivos vacíos,
  tamaños superiores al límite eD2K y nombres temporales conocidos.
- La comparación de nombres no depende del locale.
- Cada rechazo tiene un motivo tipado y comprobable.
- Los nombres parecidos pero válidos no se rechazan por coincidencias
  parciales.
- `thumbs.db` conserva la comprobación histórica de contenido y no se rechaza
  únicamente por su nombre.

### Evidencia frente a eMule AI

La prueba A/B está fijada a eMule AI 1.5.2, commit
`de8e27e2029044d533f7090f173c95856fe4635a`.

Sobre un corpus común de 31 casos:

- eMule AI: 0 falsos positivos y 7 falsos negativos;
- eSE beta.3: 0 falsos positivos y 0 falsos negativos.

También pasan la prueba focalizada, la suite Core, la suite Integration y una
recompilación limpia `Release|x64`.

## Alcance heredado

- Kad2 y Kad6 seleccionables y persistentes por separado.
- Listener dual-stack con fallback IPv4.
- Direcciones IPv6 nativas en fuentes, peers y LiveTV.
- LiveTV directo sobre IPv6 y soporte IPv6 en SOCKS5/HTTP CONNECT.
- Revocación persistente de NetLab y rechazo explícito de IPv6 en SOCKS4/4A.
- Laboratorio de red cerrado por defecto y sin telemetría central.

## Límites conocidos

- Esta beta no garantiza High ID ni atravesar cualquier CGNAT.
- Los 18 casos físicos bloqueados del gate de v9.1 siguen requiriendo las
  topologías correspondientes.
- No se ofrece infraestructura KRP pública por defecto.
- No hay cliente Android en esta versión.

## Actualización y rollback

1. Guardar el directorio `config` y todos los `.met`.
2. Extraer beta.3 en un directorio nuevo.
3. Mantener `emule.exe` y `ese-server.exe` del mismo paquete.
4. Para volver atrás, cerrar eMule y restaurar beta.2 junto con la copia del
   perfil. AI-I03 no introduce ninguna migración de datos.
