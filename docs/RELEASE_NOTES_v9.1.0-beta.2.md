# eMule eSE 9.1.0-beta.2

Status: **beta pública de estabilización para Windows x64**.

Esta segunda beta de 9.1 mejora la concurrencia, la honestidad del protocolo,
el aislamiento del dashboard y la fiabilidad de build y pruebas. No añade
funciones de 9.2, 9.3 o 9.4 y todavía no constituye el RC de 9.1.

## Cambios principales

### Concurrencia

- El temporizador compartido de shaping y fair queue tiene un lock hoja propio.
- Se elimina el borde de locks `m_pendingLock → m_lock` que podía formar un
  ciclo con `Tick()`.
- La jerarquía efectiva queda documentada y cubierta por regresión.

### Capacidades de protocolo

- Sealed Records y Gossip dejan de anunciarse mientras sus handlers de red
  completos permanezcan reservados.
- La fragmentación Live continúa anunciándose porque su recorrido de datos sí
  está operativo.
- Los opcodes reservados fallan cerrados y no se presentan como soportados.

### Dashboard

- El servidor escucha en `127.0.0.1` por defecto.
- `ESE_BIND_HOST` permite exposición explícita sólo cuando existe un token de
  acceso válido.
- Los probes multimedia se ejecutan sin shell, con timeout, límite de salida y
  concurrencia acotada.
- Listados, metadata y comprobaciones de archivos usan I/O asíncrono y caché
  invalidada por tamaño y `mtime`.

### Live TV

- Emitir un canal local y ver simultáneamente otro canal ya no mezcla sus
  identidades, búferes, segmentos HLS, anuncios ni latidos.
- El canal publicado y sus enlaces conservan siempre la clave de la emisión
  local, aunque el mismo nodo se una a una emisión remota.
- Las peticiones de cierre y actividad del reproductor quedan ligadas a la
  clave vista, evitando que una pestaña anterior cierre o mantenga viva otra
  sesión.
- El directorio normaliza y deduplica las claves de canal.
- Las miniaturas remotas usan la URL del emisor remoto y nunca reutilizan como
  fallback la captura de la emisión local.
- Se añaden regresiones automatizadas para el escenario de doble rol y para la
  separación de miniaturas y ciclo de vida.

### Build y validación

- Las pruebas Node dinámicas cubren bind y ejecución de procesos acotada.
- La política de capacidades se prueba con un target C++ independiente.
- Build, tests, audit y self-test son gates automáticos de pull request.
- CodeQL incorpora análisis del build C++ en Windows.
- Release x64 enlaza sin `/FORCE:MULTIPLE`, usa C++17, `/W4` y CFG.
- El código nuevo aislado y los tests nativos usan `/WX`; el árbol MFC
  histórico queda bajo ratchet hasta eliminar su baseline de warnings.
- La versión se comprueba en binario, dashboard, package, instalador, guía y
  notas antes de publicar.

### Dependencias y empaquetado

- Se actualiza la dependencia transitiva `tar` para eliminar el hallazgo
  moderado conocido.
- El package Node declara la licencia GPL-2.0-or-later del proyecto.
- El instalador ya no crea una excepción amplia de firewall para Node.

## Límites de esta beta

- Gossip y las operaciones peer-to-peer de canales siguen desactivadas.
- Kad6 continúa sujeto a consentimiento y a sus gates experimentales.
- No se afirma salida pública Kad6 estable.
- Los casos físicos pendientes de la matriz `V91-*` siguen bloqueando RC.
- UPnP/PCP/NAT-PMP, Punch3, predicción y KRP no se promocionan aquí.

## Criterio de publicación

El candidato sólo puede publicarse si:

- Core, Integration, pruebas Node y tests nativos están verdes;
- Release x64 y el paquete se construyen desde un checkout limpio;
- el self-test del paquete extraído termina con código cero;
- la regresión IPv4/dual-stack y la compatibilidad con un peer anterior pasan;
- existe una prueba remota física del mismo commit;
- el soak de 12 horas no presenta crash, deadlock ni crecimiento sostenido;
- no quedan defectos S0, S1 o S2 abiertos.
