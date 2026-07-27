# eMule eSE 9.1.0-rc.1

Estado: **RECHAZADA / NO_GO**. Se conserva para trazabilidad y evidencia; no
debe publicarse ni promoverse.

Durante la reconciliación de `V91-I04` se demostró que esta candidata solo
caía a IPv4 tras un error IPv6 explícito. Un blackhole silencioso podía esperar
el timeout global de 45 segundos y, por tanto, incumplía el límite de menos de
10 segundos. El sucesor que corrige y vuelve a calificar ese camino es
`9.1.0-rc.2`.

Esta candidata congeló el alcance funcional de v9.1, pero quedó rechazada. El
texto restante describe el delta histórico que se intentó calificar; no es una
instrucción para publicar o instalar `rc.1`.

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

## Criterio de promoción histórico (no satisfecho)

Este era el criterio previsto: el mismo commit y los mismos hashes debían
superar el pipeline limpio, la prueba física entre los dos Windows disponibles,
dos horas de LiveTV IPv6 y el soak dual-stack. `rc.1` no lo satisfizo porque
`V91-I04` falló. Una ejecución local de dos procesos sirve como prueba de
desarrollo, pero no sustituye la topología física.

## Límites conocidos

- No garantiza High ID ni atravesar cualquier CGNAT.
- No se ofrece infraestructura KRP pública por defecto.
- No hay cliente Android ni administración remota en v9.1.

## Procedimiento histórico de actualización (no ejecutar con rc.1)

El procedimiento que se había preparado consistía en guardar `config` y todos
los `.met`, extraer la candidata en un directorio nuevo y mantener
`emule.exe`/`ese-server.exe` del mismo paquete. No debe aplicarse a `rc.1`;
use la candidata sucesora que complete su propia calificación.
