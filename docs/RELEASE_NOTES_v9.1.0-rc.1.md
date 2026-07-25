# eMule eSE 9.1.0-rc.1

Estado: **candidata de publicación para Windows x64**.

Esta candidata congela el alcance funcional de v9.1. A partir de este punto
solo se admitirán correcciones de defectos bloqueantes para la publicación;
el desarrollo de funciones nuevas continuará en v9.2.

## Cambios desde beta.3

### LiveTV directo sobre IPv6 de overlay

- Un enlace directo de LiveTV admite IPv6 pública y direcciones ULA
  RFC 4193 encaminables mediante un overlay controlado por el usuario.
- La aceptación de conexiones entrantes conserva los 128 bits de la dirección
  y reconoce el origen directo ULA sin convertirlo en una dirección pública.
- El transporte directo ULA no amplía Kad, PeX, servidores ni el
  descubrimiento general de peers: esas rutas continúan aceptando únicamente
  endpoints públicos.
- Las direcciones link-local, multicast, loopback, no especificadas y las
  demás reservas IPv6 siguen rechazadas.
- El diagnóstico registra la decisión de ruta IPv6 directa y el motivo de una
  desconexión para que las pruebas físicas sean auditables.

### Laboratorio reproducible

- La revocación persiste primero el kill-switch maestro antes de responder,
  sin esperar a guardar estadísticas ni preferencias ajenas; al reiniciar,
  todos los niveles derivados se normalizan desde ese marcador y quedan
  cerrados.
- El arranque aislado de LiveTV guarda versión, commit, hashes, puertos y clave
  del stream en una sesión de evidencia nueva.
- Los informes de self-test, proxy y consentimiento toman la versión del
  paquete probado y rechazan un commit o un paquete sucio distintos.
- El modo de desarrollo sucio del laboratorio debe solicitarse de forma
  explícita; la validación de una candidata permanece estricta por defecto.

## Alcance congelado de v9.1

- Kad2 y Kad6 seleccionables y persistentes por separado.
- Listener dual-stack y rutas IPv4 e IPv6 nativas.
- LiveTV entre peers eSE por IPv6 pública o por un overlay ULA explícito.
- Soporte IPv6 en SOCKS5 y HTTP CONNECT, con rechazo en SOCKS4/4A.
- Revocación persistente de NetLab y funciones experimentales cerradas por
  defecto.
- Admisión segura y coherente de archivos compartidos.

## Criterio de promoción

El binario solo se publicará como RC aprobada cuando el mismo commit y los
mismos hashes superen el pipeline limpio, la prueba física entre los dos
Windows disponibles, dos horas de LiveTV IPv6 y el soak dual-stack previsto.
Una ejecución local de dos procesos sirve como prueba de desarrollo, pero no
sustituye la topología física.

## Límites conocidos

- No garantiza High ID ni atravesar cualquier CGNAT.
- No se ofrece infraestructura KRP pública por defecto.
- No hay cliente Android ni administración remota en v9.1.

## Actualización y rollback

1. Guardar el directorio `config` y todos los `.met`.
2. Extraer rc.1 en un directorio nuevo.
3. Mantener `emule.exe` y `ese-server.exe` del mismo paquete.
4. Para volver atrás, cerrar eMule y restaurar beta.3 junto con la copia del
   perfil. Esta candidata no introduce una migración de datos.
