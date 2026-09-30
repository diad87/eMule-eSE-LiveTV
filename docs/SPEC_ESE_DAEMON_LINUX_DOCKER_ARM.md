# Especificación de producto y arquitectura — eSE Daemon para Linux, Docker, Raspberry Pi y NAS

**Estado:** borrador normativo para Spec-Driven Development  
**Versión:** 0.2.1  
**Fecha:** 2026-07-14  
**Ámbito:** eMule eSE LiveTV  
**Audiencia:** desarrollo, revisión de arquitectura, QA, empaquetado y operadores del daemon  
**Idioma normativo:** español; los identificadores y nombres de API se mantienen en inglés para facilitar la implementación.

---

## 0. Cómo leer y utilizar esta especificación

Este documento define el producto objetivo **eSE Daemon**: un nodo eMule/eSE sin interfaz gráfica, capaz de permanecer encendido durante días o semanas en una Raspberry Pi, NAS, mini-PC, servidor doméstico, contenedor Docker o equipo antiguo, administrado desde otro dispositivo mediante navegador o API.

La especificación diferencia tres estados:

- **[ACTUAL]**: existe en el repositorio o hay una implementación parcial que debe conservarse o adaptarse.
- **[OBJETIVO]**: requisito que el daemon debe cumplir antes de considerarse terminado.
- **[DECISIÓN]**: decisión propuesta que debe respetarse salvo cambio explícito de esta especificación.
- **[PENDIENTE]**: punto que requiere una decisión posterior, una prueba en hardware o una medición.

Las palabras **DEBE**, **NO DEBE**, **DEBERÍA**, **PUEDE** y **NO PUEDE** son normativas:

- **DEBE / NO DEBE**: requisito obligatorio.
- **DEBERÍA / NO DEBERÍA**: requisito recomendado; solo se puede omitir documentando el motivo.
- **PUEDE**: opción permitida, no obligatoria.

Cada requisito tiene un identificador estable. Los commits, tests, issues y PR deben referenciar esos identificadores, por ejemplo `DMD-LIFE-004` o `API-AUTH-003`.

### 0.1 Regla de trazabilidad SDD

Ninguna funcionalidad P0/P1 se considera implementada si no tiene:

1. requisitos cubiertos;
2. escenarios Given/When/Then o una prueba equivalente;
3. una implementación identificable;
4. una prueba automatizada o una prueba manual reproducible;
5. documentación de configuración y operación;
6. evidencia de compatibilidad con el cliente Windows cuando el cambio toque el protocolo o los formatos persistentes.

### 0.2 Historial de revisiones

| Versión | Fecha | Cambios principales |
|---|---|---|
| 0.1.0 | 2026-07-14 | Borrador inicial Linux/Docker/ARM/HDD/Live. |
| 0.2.0 | 2026-07-14 | Revisión arquitectónica: overlay VPS reubicado, `CAsyncSocketEx` marcado no portable, single-writer, schema/migraciones, filesystems, backup/restore, OpenAPI, semántica HTTP, bind Docker, supply chain, privacidad y nuevos gates. |
| 0.2.1 | 2026-07-14 | Revisión de consistencia: identidad persistente frente al `--headless` de pruebas, decisión port propio/aMule, defaults versionados de perfiles, límites sin ceros ambiguos, ejemplo Compose inmutable y casos límite adicionales de storage/systemd. |

### 0.3 Metadatos, precedencia y control de cambios

Un requisito formal es una fila o enunciado asociado a un ID estable. El texto explicativo, los diagramas y los ejemplos ayudan a interpretarlo, pero no crean por sí solos una excepción. El uso de una palabra normativa sin ID se considera un defecto de la especificación y debe corregirse antes de implementar ese punto.

Cada spec hija debe registrar, como mínimo:

| Campo | Valores o contenido esperado |
|---|---|
| ID | identificador estable y único |
| estado | `proposed`, `accepted`, `implemented`, `verified`, `deprecated` o `superseded` |
| prioridad | P0, P1 o P2 |
| origen | requisito padre, riesgo, issue o ADR |
| propietario | componente/equipo responsable, no necesariamente una persona |
| verificación | unit, integration, compatibility, security, performance o manual reproducible |
| dependencias | IDs que deben estar aceptados o implementados antes |
| evidencia | test, benchmark, log, pcap, informe o artefacto de release |

Reglas de cambio:

- `SDD-META-001`: un ID publicado no debe cambiar de significado silenciosamente; un cambio incompatible crea un ID nuevo y marca el anterior `superseded`.
- `SDD-META-002`: una spec hija puede concretar este documento, pero no contradecirlo sin un cambio aprobado del requisito padre y un ADR cuando afecte arquitectura, protocolo, seguridad o datos persistentes.
- `SDD-META-003`: si un ejemplo contradice un requisito con ID, manda el requisito y el ejemplo se considera un bug documental.
- `SDD-META-004`: cada release debe generar una matriz `requisito → implementación → tests → evidencia` y fallar el gate si un P0 aceptado queda sin cobertura.
- `SDD-META-005`: una decisión pendiente no puede convertirse en comportamiento irreversible por defecto; debe mantenerse detrás de configuración, capability o experimento hasta resolverse.
- `SDD-META-006`: los requisitos de integridad de datos, seguridad y compatibilidad de cable tienen precedencia sobre optimizaciones de consumo o conveniencia operativa.

### 0.4 Glosario operativo

| Término | Definición en este documento |
|---|---|
| daemon | proceso sin GUI, supervisado externamente y ejecutado en foreground desde la perspectiva de systemd/Docker |
| core portable | código compilable sin MFC, Windows SDK, ventanas auxiliares ni message pump |
| configuración | valores elegidos por el operador; versionados y validables antes de arrancar |
| estado | identidad, preferencias, progreso y metadatos que cambian durante la ejecución |
| datos | archivos descargados, compartidos o generados que pueden residir en un volumen grande separado |
| ready | el proceso puede aceptar las operaciones prometidas por su perfil; no implica necesariamente HighID ni Kad conectado |
| live | el proceso y su event loop responden; no implica que storage, red P2P o FFmpeg estén listos |
| perfil | conjunto versionado de defaults de consumo/capacidades (`lite`, `standard`, `live`) |
| overlay | política adicional de despliegue que restringe o reemplaza defaults sin convertirse en un cuarto perfil |
| instancia lógica | instalación que conserva identidad y estado aunque cambie de host, contenedor o versión |
| volumen de estado | almacenamiento single-writer que contiene identidad, schemas y metadatos críticos |
| volumen de datos | almacenamiento de descargas/shared; puede ser grande, externo y recuperarse de forma independiente |

---

## 1. Resumen ejecutivo

### 1.1 Visión

El proyecto debe producir un nodo eMule/eSE que pueda instalarse en un equipo sin monitor y dejarse funcionando de forma permanente:

```text
                         PC / móvil / tablet / Smart TV
                                  │
                         navegador, VLC, Kodi o API
                                  │
                     ┌────────────┴────────────┐
                     │ red local o acceso seguro│
                     └────────────┬────────────┘
                                  │
                  ┌───────────────▼────────────────┐
                  │      eSE Daemon                 │
                  │  eD2K + Kad + Live + API/HLS    │
                  └───────┬───────────┬────────────┘
                          │           │
                    HDD/SSD externo   FFmpeg opcional
                    descargas/shared  ingest/transcoding
```

El daemon debe ser útil aunque no se instale el dashboard Node.js. El dashboard es una interfaz de administración opcional; el motor y la API son el producto base.

### 1.2 Resultado esperado

Un operador debe poder:

- instalar el daemon en Docker, Linux nativo o una Raspberry Pi;
- indicarle un HDD externo para descargas, temporales y archivos compartidos;
- iniciar el servicio y dejarlo arrancado automáticamente;
- acceder desde otro equipo a una interfaz web;
- buscar, descargar, compartir, pausar, reanudar y borrar trabajos;
- ver estado de Kad/eD2K, conectividad, espacio de disco, memoria y errores;
- iniciar o detener una emisión LiveTV cuando el hardware lo permita;
- reproducir un canal mediante HLS desde navegador, VLC o Kodi;
- actualizar o reiniciar el servicio sin perder identidad, preferencias, descargas ni estado recuperable;
- detectar problemas de disco, puertos, NAT, memoria o FFmpeg sin tener que entrar al equipo por SSH.

### 1.3 Recomendación de nombres

Los nombres propuestos son:

- `ese-daemon`: binario nativo sin GUI.
- `ese-core`: biblioteca o conjunto de componentes comunes.
- `ese-web`: dashboard Node.js opcional.
- `eMule eSE`: nombre del producto completo.
- `eMule eSE Windows`: cliente con GUI MFC.

`ARCH-NAME-001`: los nombres pueden cambiar, pero la separación conceptual DEBE mantenerse.

---

## 2. Contexto del repositorio actual

La arquitectura actual ya separa varias piezas útiles para este objetivo:

- motor eMule/eSE en `srchybrid/`;
- API HTTP C++ en el puerto 4711;
- dashboard Node.js en el puerto 8080;
- sistema LiveTV en `LiveStreamManager`, `LiveKadBridge`, `LivePackets`, `LiveMeshManager`, `LiveChunkBuffer` y `RTMPIngest`;
- backend POSIX de identidad de nodo en `NodeIdentityStorage.cpp`;
- pruebas POSIX independientes en `tests/test_node_identity_storage.cpp`;
- hoja de ruta de desacoplamiento y portabilidad en [`docs/MODERNIZATION_ROADMAP.md`](./MODERNIZATION_ROADMAP.md);
- mapa de procesos y puertos en [`ARCHITECTURE.md`](../ARCHITECTURE.md).

### 2.1 Limitación actual que esta especificación debe resolver

El flag `--headless` existente no equivale todavía a un daemon Linux portable. El código actual continúa creando `CemuleDlg` y ejecutando el ciclo modal de la aplicación. El objetivo es que el modo daemon:

- no cree ninguna ventana;
- no dependa de un message pump de Windows;
- no dependa de `WM_TIMER`, `SetTimer` ni callbacks de GUI;
- no requiera MFC para compilar en Linux;
- tenga un bucle de vida propio;
- pueda recibir `SIGTERM` y salir limpiamente;
- exponga un estado de salud y de preparación verificable.

`CAsyncSocketEx` tampoco debe considerarse una base portable por su nombre: actualmente hereda de `CObject`, usa estado AFX, `WSAAsyncSelect`, mensajes `WM_*` y una ventana Win32 auxiliar. Puede servir como referencia de comportamiento del target Windows, pero el daemon Linux necesita un reactor/event loop portable o un adaptador de sockets distinto.

Existe además una diferencia de identidad que no se puede trasladar al producto final: el `--headless` actual llama a `CPreferences::RegenerateUserHash()` durante el arranque para que viewers de estrés ejecutados en el mismo host no sean detectados como el propio broadcaster. Ese comportamiento es útil para pruebas aisladas, pero un daemon real debe conservar UserHash e identidad entre reinicios. Solo un comando explícito de clonación/test podrá regenerarlos.

### 2.2 Compatibilidad que no se debe perder

La compatibilidad obligatoria se concreta en `COMP-WIRE-001` a `COMP-WIRE-008` e incluye:

- eD2K clásico;
- Kad clásico;
- extensiones Live eSE negociadas mediante capacidades;
- formatos de identidad compatibles;
- formatos de preferencias y estado que se hayan declarado portables;
- links Live anónimos y directos según el protocolo vigente.

En particular, `COMP-WIRE-002` y `COMP-WIRE-004` impiden que las extensiones Live rompan el tráfico clásico con peers eMule/aMule que no las conozcan.

### 2.3 Decisión arquitectónica: port propio frente a fork de aMule

**[DECISIÓN]** La fuente de verdad será este repositorio eMule-eSE y se extraerá un core portable con un target `ese-daemon`. No se hará un fork de aMule como implementación principal en esta fase.

Razones:

- las extensiones eSE/Live, sus tests y su comportamiento actual ya viven en este árbol;
- portar los cambios a aMule antes de estabilizar sus contratos obligaría a mantener dos implementaciones y dos superficies de regresión;
- la separación GUI/core, el reactor de red y los formatos persistentes siguen siendo trabajo necesario aunque se cambie de base;
- conservar un único origen facilita comparar Windows y Linux byte a byte;
- aMule sigue siendo valioso como peer de interoperabilidad y como referencia POSIX, sin convertirlo en la fuente de verdad.

| ID | Decisión/requisito |
|---|---|
| `ARCH-ADR-001` | El primer daemon Linux se implementará como target de este repositorio, compartiendo core y protocolo con eMule-eSE Windows. |
| `ARCH-ADR-002` | No se copiarán módulos completos de aMule sin revisar licencia, procedencia, divergencias de protocolo y coste de mantenimiento. |
| `ARCH-ADR-003` | aMule formará parte de la matriz de interoperabilidad clásica, pero no se le prometerá soporte de extensiones Live eSE. |
| `ARCH-ADR-004` | Antes de F1 debe existir un spike que compile un slice portable mínimo —identidad, scheduler, reactor y una ruta de red— para validar la estrategia de extracción. |
| `ARCH-ADR-005` | La decisión solo se reabrirá con un ADR comparativo que mida cobertura de protocolo eSE, volumen de código a portar, dependencias, licencias, tests y mantenimiento a tres años. |
| `ARCH-ADR-006` | Si se evalúa un backend basado en aMule, deberá demostrar compatibilidad mediante los mismos fixtures, pcaps y tests de dos nodos antes de sustituir cualquier componente. |

---

## 3. Objetivos y no objetivos

### 3.1 Objetivos P0

| ID | Objetivo |
|---|---|
| `OBJ-001` | Ejecutar eSE sin GUI en Linux x86_64 y ARM64. |
| `OBJ-002` | Ejecutar el mismo producto mediante Docker sin privilegios especiales. |
| `OBJ-003` | Funcionar de forma continua 24/7 con reinicio automático. |
| `OBJ-004` | Usar un HDD externo para descargas, temporales y archivos compartidos. |
| `OBJ-005` | Administrar el nodo desde otro equipo mediante API y navegador. |
| `OBJ-006` | Mantener compatibilidad de red con la rama Windows eSE. |
| `OBJ-007` | Proporcionar logs, métricas, salud y diagnóstico remoto. |
| `OBJ-008` | Permitir una instalación mínima sin Node.js ni FFmpeg. |
| `OBJ-009` | Añadir LiveTV de forma opcional y controlada por recursos. |
| `OBJ-010` | Convertir cada bloque funcional en una unidad de trabajo verificable mediante SDD. |

### 3.2 Objetivos P1

| ID | Objetivo |
|---|---|
| `OBJ-101` | Imágenes Docker multi-arquitectura para `linux/amd64` y `linux/arm64`. |
| `OBJ-102` | Soporte experimental para `linux/arm/v7` cuando las dependencias lo permitan. |
| `OBJ-103` | Unidad `systemd` con hardening razonable. |
| `OBJ-104` | Configuración de bind solo localhost, LAN autenticada o reverse proxy. |
| `OBJ-105` | Gestión segura de actualización y rollback. |
| `OBJ-106` | Modo de bajo consumo con límites de conexiones, ancho de banda y frecuencia de tareas. |
| `OBJ-107` | Diagnóstico de pérdida o desconexión del HDD sin crash del proceso. |
| `OBJ-108` | Exportación Prometheus y endpoint de healthcheck para Docker/orquestadores. |

### 3.3 No objetivos de la primera versión

| ID | No objetivo |
|---|---|
| `NOBJ-001` | No se pretende sustituir inicialmente el cliente gráfico Windows. |
| `NOBJ-002` | No se pretende reescribir inmediatamente todo el dashboard Node.js. |
| `NOBJ-003` | No se pretende soportar todos los formatos de vídeo de entrada mediante un encoder propio. |
| `NOBJ-004` | No se pretende que el daemon monte discos automáticamente. El montaje lo administra el sistema operativo, Docker Compose o el operador. |
| `NOBJ-005` | No se permite exposición pública de la API sin autenticación, aunque el usuario la solicite mediante una variable de entorno. |
| `NOBJ-006` | No se promete ARMv7 en la primera release estable. |
| `NOBJ-007` | No se adopta aMule como base del daemon en esta fase. Podrá evaluarse como port posterior. |
| `NOBJ-008` | No se introduce una base de datos pesada si los formatos actuales de eMule son suficientes. |

---

## 4. Perfiles de ejecución y despliegue

`PROF-CAP-001`: los perfiles `lite`, `standard` y `live` son políticas de ejecución: fijan defaults y límites, pero no sustituyen a los flags de compilación. Un binario construido sin FFmpeg/Live/Node DEBE rechazar un perfil que requiera una capacidad ausente. El overlay `vps-safe` se aplica además de uno de los perfiles de ejecución.

### 4.1 Perfil `lite`

Uso: Raspberry Pi antigua, equipo con 512 MB–1 GB de RAM, dispositivo siempre encendido.

Incluye:

- eD2K;
- Kad;
- descargas y compartición;
- API C++;
- métricas y healthcheck;
- HLS de reproducción cuando ya existan segmentos disponibles;
- buffer Live en RAM;
- sin dashboard Node obligatorio;
- sin RTMP/FFmpeg obligatorio;
- sin transcoding automático.

Restricciones objetivo:

- RSS en reposo del daemon: **<150 MB** sin Node ni FFmpeg;
- CPU en reposo: **<10 % de un core lógico** en un nodo estable, excluyendo picos de hash y red;
- escritura temporal mínima fuera de las descargas;
- límite conservador de conexiones simultáneas configurable.

### 4.2 Perfil `standard`

Uso: mini-PC, NAS, Raspberry Pi 4/5, servidor doméstico.

Incluye:

- todo `lite`;
- dashboard Node opcional;
- WebSocket o polling de estado si se conserva la implementación actual;
- UPnP/NAT-PMP/PCP cuando la plataforma lo soporte;
- mDNS de descubrimiento LAN opcional;
- más conexiones y buffer configurables;
- LiveTV con FFmpeg externo si el hardware lo permite.

Objetivos de recursos:

- RSS del daemon sin FFmpeg: **<250 MB**;
- RSS conjunto daemon + dashboard: **<400 MB** como objetivo;
- `PROF-STD-001`: el perfil DEBE poder funcionar en un equipo con 1 GB de RAM, aunque el número de conexiones y la calidad Live se reduzcan.

### 4.3 Perfil `live`

Uso: emisión, relay o recepción LiveTV.

Incluye:

- todo `standard`;
- RTMP ingest opcional;
- FFmpeg como proceso externo;
- HLS y segmentos;
- métricas de bitrate, latencia, buffer, pérdidas y peers;
- políticas de backpressure y degradación.

Reglas:

- `PROF-LIVE-001`: FFmpeg DEBE ser un proceso hijo separado y monitorizado;
- `PROF-LIVE-002`: el daemon NO DEBE asumir que FFmpeg existe;
- `PROF-LIVE-003`: si no hay FFmpeg, la funcionalidad de descargas eD2K/Kad DEBE seguir funcionando;
- `PROF-LIVE-004`: el sistema DEBE rechazar una emisión si no hay memoria, espacio temporal o capacidad de CPU suficiente;
- `PROF-LIVE-005`: la calidad y el bitrate DEBEN poder limitarse por configuración.

### 4.4 Overlay de despliegue `vps-safe`

Uso: nodo siempre accesible desde Internet, punto de administración remota, relay, bootstrap de conectividad o instancia Docker en un proveedor cloud.

Un VPS es un destino válido para el daemon, pero no sustituye automáticamente a un NAS/Raspberry con HDD. El VPS normalmente ofrece disco virtual, block storage o volumen adicional, no un disco USB local controlado por el operador.

`PROF-VPS-001`: el overlay `vps-safe` DEBE aplicar valores conservadores sobre `lite`, `standard` o `live`:

- exposición de dashboard y API limitada a loopback o red privada; en Docker el proceso puede escuchar en `0.0.0.0` dentro del namespace si el puerto del host se publica solo en `127.0.0.1` o una IP privada autorizada;
- acceso administrativo mediante reverse proxy autenticado, VPN o túnel seguro;
- UPnP/NAT-PMP/PCP desactivado;
- mDNS/multicast desactivado;
- límite explícito de upload y download;
- límite explícito de conexiones y viewers;
- no actuar como proxy abierto;
- no publicar servicios de relay o túnel para terceros sin opt-in y revisión del proveedor;
- almacenamiento de identidad y configuración en volumen persistente separado;
- backups fuera del VPS;
- logs y métricas para detectar tráfico anómalo, abuse reports o consumo inesperado.

El overlay `vps-safe` es especialmente adecuado para:

- mantener una identidad eSE accesible 24/7;
- disponer de una IP pública para pruebas de reachability;
- ejecutar un viewer o relay de bajo/medio bitrate;
- administrar remotamente nodos domésticos;
- realizar pruebas de interoperabilidad Windows↔Linux;
- servir una API privada mediante VPN o reverse proxy.

No debe considerarse automáticamente adecuado para:

- almacenar una biblioteca grande sin comprobar coste de disco y backups;
- emitir vídeo de alto bitrate sin comprobar tráfico incluido;
- compartir contenido cuya autorización no esté clara;
- usar funciones de anonimización o relay que contradigan la política del proveedor;
- depender de multicast o UPnP.

Requisitos específicos:

| ID | Requisito |
|---|---|
| `VPS-001` | El daemon debe poder arrancar en un VPS Linux sin acceso a dispositivos USB, multicast ni UPnP. |
| `VPS-002` | Debe poder usar una IP pública estática o una IP documentada por el proveedor. |
| `VPS-003` | Debe permitir configurar límites de tráfico inferiores al límite contractual del proveedor. |
| `VPS-004` | Debe exponer una prueba de puertos TCP/UDP independiente del dashboard. |
| `VPS-005` | Debe funcionar con solo disco virtual persistente y sin asumir un punto de montaje físico. |
| `VPS-006` | Debe detectar si el disco raíz o volumen adicional se está llenando. |
| `VPS-007` | Debe permitir desactivar mDNS, UPnP, RTMP y transcoding por separado. |
| `VPS-008` | Debe poder ejecutar el perfil `lite` sin Node.js ni FFmpeg. |
| `VPS-009` | Debe documentar que el proveedor puede recibir quejas de abuso o copyright asociadas a la IP del VPS. |
| `VPS-010` | El instalador no debe afirmar que el tráfico P2P está permitido sin verificar la AUP concreta del proveedor, producto y región. |
| `VPS-011` | La configuración no debe convertir el daemon en un proxy abierto, un relay público accidental o un servicio de administración sin autenticación. |
| `VPS-012` | Debe existir un overlay `vps-safe` con límites bajos y sin discovery multicast. |

### 4.5 Defaults versionados de perfiles

Los siguientes valores son defaults iniciales de seguridad y consumo, no límites físicos ni promesas de rendimiento. Una spec de benchmark puede ajustarlos antes de la beta, pero el cambio requiere incrementar `profile_defaults_version` para que una actualización no altere silenciosamente el comportamiento de una instalación existente.

| Clave | `lite` | `standard` | `live` | overlay `vps-safe` |
|---|---:|---:|---:|---:|
| `max_connections` | 128 | 384 | 512 | `min(base, 256)` |
| `max_active_downloads` | 8 | 20 | 20 | `min(base, 10)` |
| `hash_workers` | 1 | `min(2, cores)` | `min(2, cores)` | 1 |
| `api_max_inflight` | 16 | 64 | 64 | `min(base, 32)` |
| `max_live_viewers` | 2 | 8 | 16 | `min(base, 4)` |
| `max_download_kib` | 5120 | 20480 | 20480 | `min(base, 5120)` |
| `max_upload_kib` | 1024 | 5120 | 10240 | `min(base, 1024)` |
| mDNS/multicast discovery | off | opt-in | opt-in | off |
| UPnP/NAT-PMP/PCP | off | opt-in | opt-in | off |
| auto-transcoding | off | off | opt-in | off |
| relay para terceros | off | off | opt-in autenticado | off |

| ID | Requisito |
|---|---|
| `PROF-DEF-001` | El schema debe declarar `profile_defaults_version` además de `config_schema_version`. |
| `PROF-DEF-002` | La API de configuración efectiva debe mostrar perfil, overlays, versión de defaults, valor final y origen de cada override sin mostrar secretos. |
| `PROF-DEF-003` | Un valor explícito del operador puede reemplazar un default, salvo un hard safety cap documentado; el cambio debe aparecer en diagnóstico. |
| `PROF-DEF-004` | `0` no significará a la vez desactivado e ilimitado. Los valores especiales deben representarse como enums explícitos (`disabled`, `unlimited`, `auto`) o sentinels inequívocos validados por schema. |
| `PROF-DEF-005` | `vps-safe` debe arrancar con límites finitos; pedir `unlimited` requiere configuración explícita y una advertencia sobre cuota/AUP. |
| `PROF-DEF-006` | Un perfil no debe activar una capacidad ausente; el error debe enumerar el componente o build flag que falta. |

### 4.6 Elección de topología

La topología recomendada para uso doméstico es híbrida:

```text
                  VPS pequeño
          IP pública / API privada / relay
                         │
                 VPN o protocolo eSE
                         │
              Raspberry / NAS doméstico
                 HDD externo y biblioteca
```

Ventajas:

- el HDD grande permanece en casa;
- el VPS aporta disponibilidad y reachability;
- el nodo doméstico no necesita estar directamente expuesto si se usa un canal privado;
- se puede limitar el tráfico del VPS sin perder la biblioteca local.

La topología de nodo único en VPS también es válida para descargas pequeñas, pruebas y relay, siempre que el coste de almacenamiento, transferencia y política del proveedor estén aceptados.

---

## 5. Casos de uso

### UC-001 — Nodo permanente con HDD externo

**Actor:** operador doméstico.  
**Precondiciones:** Linux instalado, HDD montado en `/mnt/ese-data`.  
**Flujo:**

1. Instala el paquete o imagen Docker.
2. Configura `config`, `downloads`, `incoming`, `shared` y `temp`.
3. Inicia el servicio.
4. El daemon carga o genera su identidad.
5. Se conecta a Kad/eD2K.
6. El operador administra el nodo desde `http://IP_DEL_NODO:8080` o la API configurada.
7. El nodo continúa funcionando aunque el navegador del operador se cierre.

**Resultado:** las descargas, compartición y conectividad continúan sin sesión gráfica ni SSH.

### UC-002 — Administración desde otro dispositivo

**Actor:** operador desde PC/móvil.  
**Flujo:**

1. Abre el dashboard.
2. Inicia sesión o proporciona token.
3. Consulta salud, red, disco y trabajos.
4. Añade una descarga o cambia una preferencia.
5. Consulta el progreso.
6. Reinicia de forma controlada si hace falta.

**Resultado:** ninguna operación de administración requiere acceso local al equipo.

### UC-003 — Docker en un host Linux

**Actor:** operador Docker.  
**Flujo:**

1. Crea volúmenes para configuración y datos.
2. Publica los puertos necesarios.
3. Inicia el contenedor.
4. El healthcheck pasa de `starting` a `healthy` cuando el proceso acepta API y ha inicializado el motor.
5. El contenedor se reinicia automáticamente si el proceso termina.

**Resultado:** el nodo funciona sin instalar MFC, wxWidgets, X11 ni un escritorio.

### UC-004 — Equipo de bajo consumo

**Actor:** operador con Raspberry Pi o mini-PC.  
**Flujo:**

1. Selecciona el perfil `lite` o `standard`.
2. Desactiva dashboard, RTMP y transcoding si no son necesarios.
3. Configura límites de CPU, conexiones, ancho de banda y espacio.
4. Deja el equipo encendido permanentemente.

**Resultado:** el consumo se mantiene predecible y los servicios no esenciales no se ejecutan.

### UC-005 — HDD desconectado

**Actor:** operador o fallo físico.  
**Flujo:**

1. El sistema pierde el montaje de datos.
2. El daemon detecta errores de IO.
3. Marca el almacenamiento como `degraded`.
4. Detiene nuevas escrituras peligrosas.
5. Conserva la identidad y el estado mínimo en el volumen de configuración.
6. Expone instrucciones de reparación por API/log.
7. Reintenta la disponibilidad con backoff.

**Resultado:** el proceso no entra en un bucle de crash/restart ni corrompe el estado persistente.

### UC-006 — Emisión LiveTV desde un equipo capaz

**Actor:** operador con cámara, OBS o fichero.  
**Flujo:**

1. Comprueba el preflight.
2. Inicia broadcast desde el dashboard o API.
3. FFmpeg genera HLS.
4. El daemon publica metadata en Kad y distribuye chunks.
5. Otros peers descubren y reproducen el stream.
6. El operador detiene la emisión.
7. FFmpeg se cierra y los segmentos temporales se limpian según política.

**Resultado:** LiveTV funciona sin convertirlo en requisito del nodo de descargas.

---

## 6. Arquitectura lógica

### 6.1 Capas

```text
┌────────────────────────────────────────────────────────────┐
│ Interfaces                                                  │
│ Dashboard Node / API REST / HLS / Prometheus / CLI opcional │
├────────────────────────────────────────────────────────────┤
│ Control plane                                                │
│ auth, config, commands, snapshots, health, lifecycle        │
├────────────────────────────────────────────────────────────┤
│ eSE engine                                                   │
│ eD2K, Kad, Live protocol, mesh, queue, sharing, scheduler   │
├────────────────────────────────────────────────────────────┤
│ Media                                                        │
│ RTMP ingest, FFmpeg supervisor, HLS segment watcher         │
├────────────────────────────────────────────────────────────┤
│ Storage                                                      │
│ preferences, identity, nodes, downloads, shared, cache     │
├────────────────────────────────────────────────────────────┤
│ Platform                                                     │
│ sockets, threads, timers, filesystem, process, signals      │
├────────────────────────────────────────────────────────────┤
│ OS                                                           │
│ Linux, Windows, Docker, ARM64, x86_64                       │
└────────────────────────────────────────────────────────────┘
```

### 6.2 Targets

`ARCH-TARGET-001`: el build debe producir como mínimo:

| Target | GUI | Plataforma | Uso |
|---|---:|---|---|
| `emule` | Sí | Windows | Cliente actual, compatibilidad de escritorio |
| `ese-daemon` | No | Linux x86_64/ARM64 | Servicio nativo |
| `ese-daemon` | No | Windows opcional | Servicio/headless de validación |
| `ese-web` | No | Node.js multiplataforma | Dashboard opcional |
| `ese-core-tests` | No | Linux/Windows | Tests unitarios y de integración |

### 6.3 Regla de dependencias

Los módulos del core portable:

| ID | Requisito |
|---|---|
| `ARCH-PORT-001` | NO DEBEN incluir cabeceras MFC. |
| `ARCH-PORT-002` | NO DEBEN depender de `CWnd`, `CDialog`, `CObject`, `CFile`, `CString`, `CAsyncSocket` ni del `CAsyncSocketEx` actual. |
| `ARCH-PORT-003` | NO DEBEN acceder directamente a `theApp.emuledlg`. |
| `ARCH-PORT-004` | NO DEBEN llamar `MessageBox`, `SetTimer`, `PostMessage`, `Sleep` como mecanismo de scheduling principal ni APIs Win32 equivalentes. |
| `ARCH-PORT-005` | DEBEN usar interfaces de plataforma o tipos C++ estándar. |
| `ARCH-PORT-006` | DEBEN poder compilarse con un toolchain Linux sin MFC ni Windows SDK. |
| `ARCH-PORT-007` | El CI DEBE buscar mecánicamente includes, símbolos y macros prohibidos en los directorios portables. Una allowlist temporal requiere propietario, motivo y fecha/condición de retirada. |

La GUI Windows podrá conservar adaptadores MFC mientras el core migra de forma incremental.

### 6.4 Interfaces mínimas

#### `IEngineSink`

`ARCH-SINK-001`: el motor DEBE publicar eventos mediante una interfaz equivalente a:

```cpp
class IEngineSink {
public:
    virtual ~IEngineSink() = default;
    virtual void OnLog(const LogEvent& event) = 0;
    virtual void OnConnectionStateChanged(const ConnectionState& state) = 0;
    virtual void OnDownloadChanged(const DownloadSnapshot& snapshot) = 0;
    virtual void OnUploadChanged(const UploadSnapshot& snapshot) = 0;
    virtual void OnFileAdded(const FileSnapshot& file) = 0;
    virtual void OnFileCompleted(const FileSnapshot& file) = 0;
    virtual void OnLiveChanged(const LiveSnapshot& snapshot) = 0;
    virtual void OnNotification(const Notification& notification) = 0;
};
```

`ARCH-SINK-002`: los nombres exactos pueden cambiar, pero la interfaz DEBE cubrir las dependencias motor→GUI existentes y permitir dos implementaciones:

- `CGuiSink`: reenvía a MFC.
- `CHeadlessSink`: escribe logs, actualiza snapshots y publica eventos por API.

#### `IPlatform`

`ARCH-PLAT-001`: `IPlatform` debe encapsular como mínimo:

- reloj monotónico y wall clock;
- timers y scheduler;
- filesystem y paths;
- creación/terminación de procesos;
- señales y shutdown;
- sockets BSD/Windows;
- permisos y usuario efectivo;
- almacenamiento seguro de identidad;
- detección de CPU, memoria y espacio disponible;
- aleatoriedad criptográfica;
- locks de instancia/estado;
- resolución DNS cancelable;
- reactor de red y wakeup entre threads;
- operaciones atómicas y durables de fichero.

#### `INetworkReactor`

`ARCH-NET-001`: el daemon necesita una frontera explícita entre el protocolo y el mecanismo de IO. La interfaz debe poder implementarse con `epoll` en Linux y con un backend Windows equivalente sin exponer `HWND`, `WPARAM`, `LPARAM`, `WSAAsyncSelect` ni mensajes de ventana al core.

Debe cubrir al menos:

- registro y baja de sockets;
- interés de lectura/escritura;
- connect/accept no bloqueante;
- timers monotónicos;
- cancelación y wakeup;
- propagación normalizada de errores;
- límites de eventos por iteración para evitar starvation.

#### `IStateStore`

`ARCH-STATE-001`: `IStateStore` debe centralizar el acceso a estado crítico y definir:

- lectura compatible con versiones anteriores;
- escritura temporal + flush + rename;
- backup previo a migración;
- lock single-writer;
- detección de truncado/corrupción;
- política de recuperación por tipo de fichero;
- snapshot consistente para backup.

#### `IEngineCommandQueue`

`ARCH-CMD-001`: las peticiones HTTP NO DEBEN modificar directamente estructuras del motor desde hilos arbitrarios. Deben:

1. validar autenticación y parámetros;
2. crear un comando tipado;
3. encolarlo;
4. ejecutarlo en el hilo o contexto del motor;
5. devolver un resultado con ID/correlation ID;
6. exponer el nuevo snapshot mediante lectura consistente.

---

## 7. Ciclo de vida del daemon

### 7.1 Estados del proceso

```text
STOPPED
  │ start
  ▼
STARTING
  │ configuración válida + storage mínimo
  ▼
INITIALIZING
  │ motor, sockets, API y scheduler listos
  ▼
READY
  │ Kad/eD2K pueden seguir conectando de forma asíncrona
  ├──────────────► DEGRADED
  │                         │ recuperación
  │                         └────────────► READY
  │ signal / API / error fatal
  ▼
STOPPING
  │ flush, unpublish, stop children, close sockets
  ▼
STOPPED
```

### 7.2 Requisitos de arranque

| ID | Requisito |
|---|---|
| `DMD-LIFE-001` | El proceso DEBE arrancar sin X11, Wayland, display, sesión gráfica o terminal interactiva. |
| `DMD-LIFE-002` | El proceso DEBE aceptar `SIGTERM` y comenzar shutdown ordenado. |
| `DMD-LIFE-003` | `SIGINT` DEBERÍA producir el mismo shutdown ordenado para uso local y Docker. |
| `DMD-LIFE-004` | `SIGKILL` no puede garantizar flush; los formatos persistentes deben resistir una terminación abrupta razonable. |
| `DMD-LIFE-005` | El proceso DEBE rechazar configuración inválida antes de abrir puertos de producción. |
| `DMD-LIFE-006` | El proceso DEBE crear o cargar una identidad estable antes de anunciarse a peers. |
| `DMD-LIFE-007` | El proceso DEBE crear la API de health aunque Kad aún no esté conectado. |
| `DMD-LIFE-008` | El estado `ready` NO DEBE significar necesariamente HighID o Kad conectado; esos estados se reportan por separado. |
| `DMD-LIFE-009` | El proceso DEBE tener timeout de arranque configurable para detectar bloqueos. |
| `DMD-LIFE-010` | El daemon NO DEBE abrir el navegador ni lanzar una UI local. |
| `DMD-LIFE-011` | El daemon DEBE poder ejecutarse en primer plano para Docker y en modo servicio para systemd. |
| `DMD-LIFE-012` | El daemon DEBE escribir a stdout/stderr en contenedor y poder escribir a journald/syslog o fichero en instalación nativa. |
| `DMD-LIFE-013` | El proceso NO DEBE hacer double-fork ni auto-daemonizarse; systemd, Docker u otro supervisor gestionan el background. |
| `DMD-LIFE-014` | El proceso DEBE adquirir un lock exclusivo sobre el directorio de estado antes de cargar identidad o abrir puertos. |
| `DMD-LIFE-015` | Una segunda instancia que apunte al mismo estado DEBE fallar con un error accionable, no compartir ficheros ni identidad concurrentemente. |
| `DMD-LIFE-016` | Deadlines, TTL, retries y timeouts DEBEN usar reloj monotónico; el wall clock se reserva para timestamps y fechas persistentes. |
| `DMD-LIFE-017` | Un salto de hora, cambio de zona horaria o sincronización NTP NO DEBE expirar masivamente peers ni bloquear timers. |
| `DMD-LIFE-018` | El signal handler solo realizará operaciones async-signal-safe y despertará el event loop; no persistirá estado ni ejecutará lógica de negocio directamente. |
| `DMD-LIFE-019` | El supervisor no recibirá señal de readiness hasta adquirir locks, validar/migrar estado y abrir correctamente los listeners requeridos por el perfil. |

### 7.3 Shutdown ordenado

El orden obligatorio es:

1. marcar `stopping` y rechazar comandos nuevos salvo `status`;
2. detener nuevas descargas/emisiones según política;
3. enviar unpublish/bye de Live cuando sea posible;
4. dejar de aceptar conexiones nuevas;
5. detener FFmpeg y esperar/recolectar el proceso hijo;
6. drenar comandos pendientes con timeout;
7. persistir preferencias, identidad, nodes y estado permitido;
8. cerrar sockets y timers;
9. cerrar logs y salir con código explícito.

Requisitos:

- `DMD-LIFE-020`: shutdown normal DEBE completar en menos de 15 segundos en un nodo sano.
- `DMD-LIFE-021`: si un child process no termina, el supervisor DEBE aplicar `SIGTERM`, esperar y después `SIGKILL` únicamente al proceso que controla.
- `DMD-LIFE-022`: no se debe matar por nombre a todos los procesos FFmpeg del host en Linux; cada child debe identificarse por PID, process group o cgroup.
- `DMD-LIFE-023`: el exit code debe distinguir configuración inválida, fallo de dependencia, shutdown normal y crash.
- `DMD-LIFE-024`: el lock de instancia debe liberarse al salir y un lock abandonado debe poder recuperarse de forma segura comprobando el lock del kernel, no confiando solo en un PID file.
- `DMD-LIFE-025`: el shutdown debe publicar la última revisión persistida para distinguir un cierre limpio de una recuperación tras crash.
- `DMD-LIFE-026`: una petición administrativa de restart debe hacer shutdown limpio y salir con el código reservado para que reinicie el supervisor; no hará `fork+exec` ni reemplazará su binario.

### 7.4 Códigos de salida propuestos

| Código | Significado |
|---:|---|
| 0 | Shutdown normal o `--version`/`--check-config` correcto |
| 2 | Argumentos o configuración inválidos |
| 3 | No se pudo abrir el almacenamiento mínimo |
| 4 | No se pudo iniciar la API o puerto obligatorio |
| 5 | Dependencia obligatoria ausente |
| 10 | Restart solicitado o fallo recuperable que pide reinicio al supervisor |
| 70 | Error inesperado no recuperado |

---

## 8. Configuración y layout de almacenamiento

### 8.1 Principios

- `CFG-BASE-001`: la configuración DEBE ser explícita y legible.
- `CFG-BASE-002`: las rutas DEBEN poder configurarse por fichero, variables de entorno y CLI, con la precedencia normativa de `CFG-SCHEMA-002`.
- `CFG-BASE-003`: las rutas NO DEBEN depender de `%APPDATA%` o `%TEMP%` en Linux.
- `CFG-BASE-004`: el daemon DEBE soportar XDG por defecto.
- `CFG-BASE-005`: un HDD externo NO DEBE contener necesariamente la identidad si el operador desea conservarla en almacenamiento interno.

### 8.2 Rutas Linux nativas

Valores por defecto propuestos:

```text
Configuración: ${XDG_CONFIG_HOME:-$HOME/.config}/ese
Datos persistentes: ${XDG_DATA_HOME:-$HOME/.local/share}/ese
Cache: ${XDG_CACHE_HOME:-$HOME/.cache}/ese
Logs: ${XDG_STATE_HOME:-$HOME/.local/state}/ese/logs
```

Cuando se ejecuta como usuario de sistema:

```text
/etc/ese/ese.conf                 configuración administrada
/var/lib/ese/                     identidad, nodes y estado persistente
/var/log/ese/                     solo si no se usa journald
/run/ese/                          pid, socket local y estado efímero
```

La ruta exacta puede cambiar, pero debe existir una especificación única por plataforma.

### 8.3 Layout de datos recomendado

```text
/mnt/ese-data/
├── incoming/          archivos completados
├── shared/            archivos compartidos explícitamente
├── downloads/         trabajos y partes en progreso
├── temp/              temporales de eD2K/Live/FFmpeg
├── hls/               segmentos Live temporales, si se usa disco
├── cache/             thumbnails y cache regenerable
└── exports/           listas, links y exportaciones opcionales
```

El volumen de configuración debe permanecer separado:

```text
/var/lib/ese/
├── identity/
├── config/
├── nodes.dat
├── preferences.ini
├── server.met
└── state/
```

### 8.4 Requisitos de configuración

| ID | Requisito |
|---|---|
| `CFG-PATH-001` | El daemon DEBE aceptar `--config <file>`. |
| `CFG-PATH-002` | El daemon DEBE aceptar `--data-dir <dir>` como raíz de datos. |
| `CFG-PATH-003` | El daemon DEBE aceptar rutas independientes para `incoming`, `shared`, `downloads`, `temp` y `cache`. |
| `CFG-PATH-004` | Las rutas relativas DEBEN resolverse respecto al fichero de configuración o rechazarse; no se debe depender del cwd accidental. |
| `CFG-PATH-005` | `--check-config` DEBE validar rutas, permisos, puertos y límites sin iniciar el motor de red. |
| `CFG-PATH-006` | El daemon DEBE informar de la ruta efectiva de cada directorio mediante `/api/v1/system/config`. |
| `CFG-PATH-007` | El daemon NO DEBE sobrescribir un fichero de configuración existente durante un arranque normal. |
| `CFG-PATH-008` | Los cambios de configuración DEBEN aplicarse atómicamente mediante fichero temporal + rename cuando sean persistentes. |
| `CFG-PATH-009` | Las credenciales y tokens DEBEN estar en un fichero con permisos equivalentes a `0600`. |
| `CFG-PATH-010` | Los cambios de rutas que impliquen mover datos DEBEN ser explícitos; cambiar la ruta no debe mover automáticamente terabytes. |

### 8.5 Configuración de ejemplo

```ini
[daemon]
profile=lite
foreground=true
shutdown_timeout_seconds=15
instance_name=ese-home
config_schema_version=1
profile_defaults_version=1

[network]
tcp_port=4662
udp_port=4672
api_enabled=true
api_bind=127.0.0.1
api_port=4711
dashboard_enabled=false
dashboard_bind=127.0.0.1
dashboard_port=8080
lan_discovery=false
upnp_enabled=false

[storage]
config_dir=/var/lib/ese
data_dir=/mnt/ese-data
incoming_dir=/mnt/ese-data/incoming
shared_dir=/mnt/ese-data/shared
downloads_dir=/mnt/ese-data/downloads
temp_dir=/mnt/ese-data/temp
cache_dir=/mnt/ese-data/cache
min_free_space_mb=2048

[limits]
max_connections=128
max_download_kib=5120
max_upload_kib=1024
max_active_downloads=8
max_live_viewers=2
max_live_bitrate_kbps=2500

[live]
enabled=true
rtmp_enabled=false
rtmp_port=1935
ffmpeg_path=
hls_segment_seconds=4
hls_buffer_segments=16
keep_hls_on_disk=false

[security]
require_auth=true
allow_lan=false
token_file=/var/lib/ese/config/api.token
trusted_proxy=false

[observability]
log_level=info
log_format=text
metrics_enabled=true
metrics_bind=127.0.0.1
metrics_port=9091
```

### 8.6 Schema, precedencia y recarga

| ID | Requisito |
|---|---|
| `CFG-SCHEMA-001` | Todo fichero de configuración persistido DEBE declarar `config_schema_version`. |
| `CFG-SCHEMA-002` | La precedencia normativa será `defaults < fichero < entorno < CLI`; una fuente posterior solo reemplaza claves explícitas. |
| `CFG-SCHEMA-003` | Una variable de entorno vacía NO DEBE borrar silenciosamente un valor salvo que la clave documente esa semántica. |
| `CFG-SCHEMA-004` | Las claves desconocidas DEBEN producir error por defecto para detectar typos; un modo de compatibilidad puede convertirlas en warnings. |
| `CFG-SCHEMA-005` | Cada clave DEBE clasificarse como `dynamic`, `restart_required` o `immutable_after_init`. |
| `CFG-SCHEMA-006` | Una recarga DEBE validarse completa antes de aplicar cambios; no puede dejar una configuración aplicada a medias. |
| `CFG-SCHEMA-007` | La API y `--print-effective-config` DEBEN indicar origen de cada valor (`default`, `file`, `env`, `cli`) y ocultar secretos. |
| `CFG-SCHEMA-008` | Una versión de schema futura no soportada DEBE rechazarse sin reescribir el fichero. |
| `CFG-SCHEMA-009` | Las migraciones DEBEN ser explícitas, versionadas, idempotentes y ejecutables en modo dry-run. |
| `CFG-SCHEMA-010` | Ningún secreto debe tener un default universal incluido en la imagen o repositorio. |
| `CFG-SCHEMA-011` | Cada límite debe declarar tipo, unidad, rango, overflow y semántica de valores especiales; no se reutilizará `0` con significados incompatibles. |
| `CFG-SCHEMA-012` | La combinación de varios overlays debe ser determinista, mostrar el orden efectivo y rechazar conflictos no resolubles. |
| `CFG-SCHEMA-013` | La versión de defaults de perfil se persiste por instancia; una actualización no aplicará nuevos defaults sobre valores ya materializados sin preview/aceptación. |
| `CFG-SCHEMA-014` | El parser debe detectar ciclos/profundidad excesiva si se admiten includes y no debe permitir que un include escape de las rutas autorizadas. |

---

## 9. HDD externo y almacenamiento de bajo riesgo

### 9.1 Modelo operativo

El sistema operativo o el runtime Docker monta el HDD. El daemon solo valida y utiliza las rutas entregadas.

Ejemplo nativo:

```bash
sudo mkdir -p /mnt/ese-data
sudo mount /dev/disk/by-uuid/XXXX /mnt/ese-data
sudo chown -R ese:ese /mnt/ese-data
```

Ejemplo Docker:

```yaml
volumes:
  - /srv/ese/config:/var/lib/ese
  - /mnt/ese-data:/mnt/ese-data
```

### 9.2 Requisitos de disco

| ID | Requisito |
|---|---|
| `STO-DISK-001` | El daemon DEBE comprobar que cada ruta esperada existe o indicar exactamente qué falta. |
| `STO-DISK-002` | El daemon DEBE comprobar lectura, creación de fichero, rename y borrado en cada directorio configurable. |
| `STO-DISK-003` | La prueba de escritura DEBE usar un fichero temporal y limpiarlo. |
| `STO-DISK-004` | El daemon DEBE comprobar espacio libre antes de iniciar descargas grandes y antes de crear una emisión que use disco. |
| `STO-DISK-005` | Debe existir umbral de espacio mínimo configurable. |
| `STO-DISK-006` | Al bajar del umbral, no se deben iniciar nuevas operaciones que puedan llenar el disco. |
| `STO-DISK-007` | El daemon DEBE distinguir almacenamiento `ok`, `warning`, `full`, `missing`, `readonly`, `io_error` y `unknown`. |
| `STO-DISK-008` | La pérdida del HDD no debe provocar un crash. |
| `STO-DISK-009` | La pérdida del HDD debe detener o pausar operaciones dependientes del mismo. |
| `STO-DISK-010` | La identidad, token y configuración deben poder estar fuera del HDD de datos. |
| `STO-DISK-011` | Los ficheros parcialmente descargados deben poder reanudarse tras reinicio o desconexión breve. |
| `STO-DISK-012` | Las escrituras críticas deben ser atómicas y no deben dejar un fichero válido truncado tras un crash normal. |
| `STO-DISK-013` | La API debe mostrar el punto de montaje efectivo, filesystem si se puede detectar, bytes libres y última comprobación. |
| `STO-DISK-014` | La reparación del disco no debe exigir borrar automáticamente partes o descargas. |
| `STO-DISK-015` | El daemon NO DEBE seguir escribiendo a un directorio vacío si el operador esperaba un HDD montado; debe detectar el cambio de dispositivo o exigir `allow_fallback_to_local=false`. |
| `STO-DISK-016` | El operador DEBE poder fijar una identidad esperada del volumen (`UUID`, device ID o marcador firmado/simple) para impedir fallback silencioso al root filesystem. |
| `STO-DISK-017` | El daemon DEBE impedir dos writers sobre el mismo estado aunque lleguen desde dos contenedores o servicios. |
| `STO-DISK-018` | La finalización `temp → incoming` DEBE distinguir rename atómico en el mismo filesystem de copia cross-filesystem. |
| `STO-DISK-019` | Una copia cross-filesystem DEBE usar nombre temporal, progreso recuperable, verificación de tamaño/hash y rename final. |
| `STO-DISK-020` | El daemon DEBE soportar offsets y tamaños de archivo de 64 bits en todas las plataformas P0. |
| `STO-DISK-021` | Debe detectar cambios externos, truncados o reemplazos de archivos compartidos antes de servir datos obsoletos. |
| `STO-DISK-022` | El escaneo/hash de bibliotecas grandes DEBE ser incremental, cancelable, persistir progreso y respetar límites de CPU/IO. |
| `STO-DISK-023` | La corrupción de un metadato no debe provocar que el daemon borre automáticamente el archivo de datos asociado. |
| `STO-DISK-024` | Los ficheros críticos requieren flush durable del contenido y del directorio cuando la plataforma/filesystem lo permita. |
| `STO-DISK-025` | El preflight debe considerar bytes, inodos y cuota efectiva cuando el sistema los exponga; “espacio libre” no se reduce a `statvfs().f_bfree`. |
| `STO-DISK-026` | Los nombres deben tratar UTF-8 inválido, normalización Unicode, case sensitivity y colisiones Windows↔Linux sin sobrescribir otro archivo. |
| `STO-DISK-027` | Las rutas de escritura deben resolverse y validarse contra raíces autorizadas; symlinks, bind mounts o reemplazos concurrentes no pueden escapar del volumen permitido. |
| `STO-DISK-028` | Fallos de preallocation, sparse write, quota o `ENOSPC` deben pausar la operación afectada y conservar progreso válido, no truncar datos existentes. |

### 9.3 Política de desmontaje

Antes de desmontar:

1. pausar nuevas escrituras;
2. esperar o cancelar operaciones activas con timeout;
3. persistir metadatos mínimos en configuración;
4. marcar storage como `offline`;
5. desmontar desde el host.

El daemon no debe ejecutar `umount` por defecto.

### 9.4 HDD frente a SSD/RAM

La configuración debe permitir:

- datos persistentes en HDD;
- `temp_dir` en SSD o tmpfs;
- `cache_dir` en almacenamiento regenerable;
- buffer Live en RAM por defecto;
- HLS en disco solo cuando se solicite persistencia o compatibilidad con un player concreto.

### 9.5 Matriz de filesystems

`STO-FS-006`: la primera release estable DEBE declarar una matriz real, sin asumir que todos los filesystems tienen las mismas garantías:

| Filesystem | Prioridad | Política inicial |
|---|---|---|
| ext4 | P0 | referencia Linux y Docker bind mount |
| XFS/Btrfs | P1 | soportado tras tests de atomic rename, fsync y sparse files |
| NTFS/exFAT en Linux | P1/best effort | warning por permisos, ownership y semántica de rename |
| FAT32 | no recomendado | rechazar descargas incompatibles con su límite de tamaño |
| NFS/SMB/CIFS | experimental | no asumir locks, fsync, inotify ni latencia local |
| tmpfs | temporal | solo cache/HLS/temp con límites; nunca única copia de estado crítico |

Requisitos:

- `STO-FS-001`: el preflight debe mostrar tipo de filesystem y capacidades detectadas.
- `STO-FS-002`: el daemon debe advertir antes de aceptar un archivo mayor que el límite del filesystem.
- `STO-FS-003`: sparse files y preallocation deben ser configurables y tener fallback seguro.
- `STO-FS-004`: NFS/SMB no entran en P0 hasta superar tests de locking, disconnect/reconnect y coherencia.
- `STO-FS-005`: el uso de inotify debe tener fallback por rescan periódico y manejar overflow de la cola.

### 9.6 Backups consistentes y restauración

Debe existir un contrato operativo independiente del mecanismo de backup del host:

1. solicitar `quiesce` o snapshot de metadatos;
2. detener mutaciones persistentes brevemente o capturar una generación consistente;
3. copiar configuración, identidad y metadatos;
4. registrar versión de schema, versión del daemon y checksum del manifiesto;
5. reanudar operaciones;
6. permitir `restore --check` antes de sustituir estado.

| ID | Requisito |
|---|---|
| `STO-BACKUP-001` | El backup DEBE incluir identidad, configuración, preferencias y progreso; los datos grandes pueden referenciarse por volumen separado. |
| `STO-BACKUP-002` | El backup NO DEBE copiar una mezcla incoherente de generaciones de metadatos. |
| `STO-BACKUP-003` | La restauración DEBE validar manifest, checksums, schema y ausencia de otro writer. |
| `STO-BACKUP-004` | Un restore no debe tocar el estado activo sin backup previo o confirmación explícita. |
| `STO-BACKUP-005` | Debe existir una prueba automatizada backup→destrucción de estado→restore→reanudación. |

---

## 10. Red, puertos y conectividad

### 10.1 Puertos base

| Puerto | Protocolo | Estado | Uso |
|---:|---|---|---|
| 4662 | TCP | obligatorio configurable | eD2K y Live sobre TCP |
| 4672 | UDP | obligatorio configurable | Kad, pruebas UDP y transporte auxiliar |
| 4711 | TCP | backend actual/compat | API C++ actual; puerto público final pendiente de decisión |
| 8080 | TCP | gateway opcional | dashboard Node.js y posible fachada pública |
| 1935 | TCP | opcional | RTMP ingest |
| 5354 | UDP multicast | opcional | descubrimiento LAN eSE |
| 9091 | TCP | opcional | listener Prometheus separado; por defecto puede compartir el listener API |

### 10.2 Requisitos de conectividad

| ID | Requisito |
|---|---|
| `NET-PORT-001` | Los puertos eD2K/Kad DEBEN ser configurables individualmente. |
| `NET-PORT-002` | El daemon DEBE detectar y reportar colisiones de puerto antes de declarar el servicio ready. |
| `NET-PORT-003` | Los puertos de administración DEBEN poder ligarse a loopback, LAN específica o todas las interfaces mediante configuración explícita. |
| `NET-PORT-004` | El bind por defecto de API y dashboard DEBE ser loopback. |
| `NET-PORT-005` | La habilitación de LAN DEBE requerir autenticación y dejar un evento de auditoría. |
| `NET-PORT-006` | La API DEBE distinguir `bind_address` de `advertised_address`. |
| `NET-PORT-007` | El daemon DEBE soportar IPv4 en la primera release y no debe impedir añadir IPv6. |
| `NET-PORT-008` | La escucha dual-stack debe ser una decisión explícita; no se debe asumir que `::` implica el mismo comportamiento en todos los kernels. |
| `NET-PORT-009` | El daemon DEBE funcionar detrás de NAT sin asumir que su IP privada es pública. |
| `NET-PORT-010` | UPnP/NAT-PMP/PCP DEBE ser opcional y desactivado en el perfil más conservador. |
| `NET-PORT-011` | Un fallo de UPnP no debe impedir el arranque del nodo. |
| `NET-PORT-012` | El tráfico de administración no debe mezclarse con el tráfico eD2K en reglas de firewall generadas automáticamente. |
| `NET-PORT-013` | El daemon NO DEBE modificar firewall, `sysctl` o rutas del host sin una acción explícita del operador. |
| `NET-PORT-014` | La resolución DNS DEBE ser asíncrona/cancelable o ejecutarse fuera del hilo del motor con timeout. |
| `NET-PORT-015` | Debe existir una vista de reachability separada para TCP eD2K, UDP Kad, API, RTMP e IPv4/IPv6. |
| `NET-PORT-016` | El healthcheck interno no debe depender de una prueba externa de puertos ni de un servicio de terceros. |
| `NET-PORT-017` | En VPS con IP pública no debe ejecutarse UPnP; los puertos se gestionan mediante firewall/security group del proveedor. |

### 10.3 Docker y red

Se deben soportar dos modos:

#### Bridge, recomendado para API y puertos explícitos

Ventajas:

- aislamiento razonable;
- publicación explícita de puertos;
- compatible con la mayoría de hosts.

Limitaciones:

- multicast 5354 puede no funcionar sin configuración adicional;
- UPnP y detección de interfaces pueden observar la red del contenedor, no la del host;
- el operador debe mapear TCP/UDP correctamente.

#### Host network, opcional

Uso:

- mDNS/multicast LAN;
- UPnP o casos donde se necesite ver interfaces del host;
- instalación doméstica controlada.

`NET-DOC-001`: el modo host DEBE documentar que reduce el aislamiento de red y no será obligatorio para el funcionamiento base.

En modo bridge hay dos scopes de bind distintos y deben documentarse sin ambigüedad:

- **dentro del contenedor:** el daemon suele tener que escuchar en `0.0.0.0` o en la interfaz de la red Docker;
- **en el host:** Docker puede publicar ese puerto solo en `127.0.0.1`, una IP LAN concreta o todas las interfaces.

`NET-DOC-002`: escuchar en `127.0.0.1` dentro del contenedor impide normalmente que el port publishing del host alcance el servicio. La configuración y los ejemplos Compose DEBEN distinguir el bind del proceso y el bind publicado por el host.

---

## 11. API de administración

### 11.1 Principios

- La API pública estable será `/api/v1/...`.
- Las rutas actuales `/api/live/...` y `/api/status` se conservarán como compatibilidad durante la migración.
- La API debe ser consumible sin dashboard.
- Todas las respuestas deben indicar `Content-Type: application/json` cuando corresponda.
- Las operaciones que mutan estado deben ser idempotentes cuando sea posible.
- Los errores deben ser legibles por humanos y máquinas.

Requisitos de contrato:

| ID | Requisito |
|---|---|
| `API-CONTRACT-001` | La API `/api/v1` DEBE publicarse como OpenAPI 3.1 o versión posterior compatible, almacenada en el repositorio. |
| `API-CONTRACT-002` | Ningún endpoint nuevo que cambie estado puede usar GET. Debe usar POST, PATCH o DELETE según la semántica. |
| `API-CONTRACT-003` | Los GET mutantes actuales son compatibilidad temporal, solo loopback por defecto, y deben llevar plan de deprecación. |
| `API-CONTRACT-004` | Todos los timestamps públicos usarán UTC y RFC 3339; las duraciones usarán enteros con unidad en el nombre. |
| `API-CONTRACT-005` | Todos los listados potencialmente grandes usarán paginación por cursor estable, con límite máximo del servidor. |
| `API-CONTRACT-006` | POST reintentables como añadir descarga o iniciar operación aceptarán `Idempotency-Key`. |
| `API-CONTRACT-007` | Las respuestas de snapshot incluirán `revision` o ETag para detectar cambios y evitar lost updates. |
| `API-CONTRACT-008` | PATCH de configuración requerirá revisión esperada (`If-Match` o equivalente). |
| `API-CONTRACT-009` | La API debe declarar límites de body, timeout, charset UTF-8 y content types aceptados. |
| `API-CONTRACT-010` | Contadores/tamaños que puedan superar el entero seguro de JavaScript se serializarán como string decimal o con una representación documentada sin pérdida. |
| `API-CONTRACT-011` | Los códigos de error son parte del contrato estable; cambiar el texto humano no debe romper clientes. |
| `API-CONTRACT-012` | Toda respuesta debe incluir o propagar un `request_id` no controlable libremente por el cliente. |

### 11.2 Formato de error

```json
{
  "ok": false,
  "error": {
    "code": "STORAGE_NOT_READY",
    "message": "El directorio de descargas no está disponible",
    "details": {
      "path": "/mnt/ese-data/downloads"
    },
    "retryable": true
  },
  "request_id": "01J..."
}
```

### 11.3 Salud y disponibilidad

| Endpoint | Método | Estado | Finalidad |
|---|---|---|---|
| `/api/v1/health/live` | GET | [OBJETIVO] | El proceso está vivo. No depende de Kad ni del HDD. |
| `/api/v1/health/ready` | GET | [OBJETIVO] | API, configuración mínima y motor inicializados. |
| `/api/v1/status` | GET | [OBJETIVO] | Estado agregado del nodo. |
| `/api/status` | GET | [ACTUAL]/compat | Mantener información existente. |
| `/api/live/preflight` | GET | [ACTUAL] | Preflight Live. |
| `/api/live/diagnose` | GET | [ACTUAL] | Diagnóstico de discovery, Kad, NAT y peers. |

`health/live` debe devolver HTTP 200 mientras el proceso atienda peticiones. `health/ready` debe devolver:

- 200 cuando está listo;
- 503 cuando está arrancando, degradado de forma que no pueda aceptar operaciones o la configuración mínima sea inválida.

| ID | Requisito |
|---|---|
| `API-HEALTH-001` | Liveness debe comprobar progreso reciente del event loop/motor, no solo que un thread HTTP pueda responder. |
| `API-HEALTH-002` | Readiness debe devolver componentes y reason codes estables (`config`, `state_lock`, `storage`, `engine`, `api`, `media`) sin filtrar secretos. |
| `API-HEALTH-003` | Kad desconectado, LowID o un test externo de puertos fallido se reportan en status/reachability y no convierten por sí solos al proceso en no-live. |
| `API-HEALTH-004` | Las dependencias externas no se usarán como liveness; readiness solo dependerá de ellas si el perfil declara que impiden aceptar trabajo local. |
| `API-HEALTH-005` | Los cambios ready↔degraded deben tener histéresis/debounce cuando proceda para evitar flapping del orquestador. |

### 11.4 Configuración y sistema

| Endpoint | Método | Requisito |
|---|---|---|
| `/api/v1/system/info` | GET | versión, commit, arquitectura, kernel, perfil y uptime |
| `/api/v1/system/resources` | GET | CPU, RAM, espacio, límites y consumo del daemon |
| `/api/v1/system/config` | GET | configuración efectiva sin secretos |
| `/api/v1/system/config/validate` | POST | validar un candidato sin aplicarlo |
| `/api/v1/system/reload` | POST | recargar opciones permitidas sin reinicio |
| `/api/v1/system/shutdown` | POST | shutdown autenticado y auditado |
| `/api/v1/system/restart` | POST | solicitar restart al supervisor; no debe intentar reiniciar dentro del mismo proceso |
| `/api/v1/storage` | GET | estado de todos los volúmenes y rutas |
| `/api/v1/logs` | GET | tail paginado y filtrado, sin secretos |

`API-SYS-001`: los endpoints de shutdown/restart DEBEN estar desactivados o protegidos con permisos de administrador.

### 11.5 Descargas y archivos

La primera implementación puede adaptar las estructuras eMule existentes. El contrato objetivo es:

| Endpoint | Método | Finalidad |
|---|---|---|
| `/api/v1/downloads` | GET | listar descargas con filtros y paginación |
| `/api/v1/downloads` | POST | añadir link ed2k/magnet permitido |
| `/api/v1/downloads/{id}` | GET | detalle y progreso |
| `/api/v1/downloads/{id}/pause` | POST | pausar |
| `/api/v1/downloads/{id}/resume` | POST | reanudar |
| `/api/v1/downloads/{id}/cancel` | POST | cancelar con política explícita de borrar/no borrar partes |
| `/api/v1/downloads/{id}/priority` | PATCH | cambiar prioridad |
| `/api/v1/files` | GET | archivos completados y compartidos |
| `/api/v1/files/{id}/share` | POST | compartir |
| `/api/v1/files/{id}/unshare` | POST | dejar de compartir |
| `/api/v1/files/{id}` | DELETE | borrar con confirmación explícita |
| `/api/v1/links/validate` | POST | validar un link sin iniciar operación |

Requisitos:

- `API-DL-001`: no se debe aceptar una ruta arbitraria del filesystem como destino desde un endpoint no privilegiado.
- `API-DL-002`: el destino debe ser una categoría o volumen configurado.
- `API-DL-003`: las operaciones deben tener IDs estables durante el reinicio cuando el formato actual lo permita.
- `API-DL-004`: la paginación debe ser obligatoria para listados grandes.
- `API-DL-005`: la API debe diferenciar `paused`, `queued`, `downloading`, `completed`, `error`, `missing_storage` y `cancelled`.
- `API-DL-006`: borrar un archivo físico requiere una confirmación reforzada y no puede ser efecto secundario de `unshare`.
- `API-DL-007`: cuando se habilite, la papelera/quarantine debe estar en el mismo volumen o usar un workflow cross-filesystem recuperable.
- `API-DL-008`: añadir dos veces el mismo link con la misma `Idempotency-Key` no debe crear dos trabajos.

### 11.6 Búsqueda, red y uploads

El control remoto completo necesita cubrir también búsquedas y actividad de subida:

| Endpoint | Método | Finalidad |
|---|---|---|
| `/api/v1/searches` | POST | iniciar búsqueda eD2K/Kad asíncrona |
| `/api/v1/searches/{id}` | GET | estado de búsqueda |
| `/api/v1/searches/{id}/results` | GET | resultados paginados |
| `/api/v1/searches/{id}` | DELETE | cancelar y liberar resultados |
| `/api/v1/searches/{id}/download` | POST | añadir un resultado validado |
| `/api/v1/uploads` | GET | slots/uploads activos paginados |
| `/api/v1/network` | GET | estado eD2K/Kad, reachability y puertos |
| `/api/v1/network/connect` | POST | solicitar conexión |
| `/api/v1/network/disconnect` | POST | desconexión controlada |
| `/api/v1/categories` | GET/POST | listar/crear categorías dentro de roots permitidos |
| `/api/v1/categories/{id}` | PATCH/DELETE | modificar/eliminar sin borrar datos implícitamente |

Requisitos:

- `API-SEARCH-001`: las búsquedas tendrán TTL, límite global, rate limit y cancelación.
- `API-SEARCH-002`: un resultado remoto no podrá inyectar HTML, paths locales ni URLs administrativas.
- `API-SEARCH-003`: los resultados se identificarán mediante IDs opacos y no se confiará en campos reenviados por el navegador.
- `API-UP-001`: la API de uploads no expondrá IPs completas a roles sin permiso de diagnóstico.
- `API-CAT-001`: una categoría solo podrá resolver destinos bajo roots configurados.

### 11.7 Endpoints Live

Se conservan o versionan las funciones actuales:

| Endpoint actual | Contrato objetivo |
|---|---|
| `/api/live/channels` | catálogo de canales locales/descubiertos |
| `/api/live/kad/streams` | streams encontrados por Kad |
| `/api/live/join` | iniciar viewer por stream key |
| `/api/live/direct_join` | join mediante link directo |
| `/api/live/leave` | detener viewer |
| `/api/live/broadcast/start` | iniciar broadcast, sujeto a preflight y permisos |
| `/api/live/broadcast/stop` | detener broadcast |
| `/api/live/debug` | snapshot técnico |
| `/api/live/metrics` | métricas Prometheus |
| `/api/live/log` | log de diagnóstico filtrado |
| `/api/live/diagnose` | diagnóstico completo |
| `/api/live/{hash}/stream.m3u8` | playlist HLS |
| `/api/live/{hash}/seg_*.ts` | segmentos HLS permitidos |

### 11.8 Listas IPTV

Se debe añadir o consolidar:

```text
GET /api/v1/live/playlist.m3u
GET /api/live/playlist.m3u       compatibilidad
```

Requisitos:

- solo incluir canales activos o explícitamente favoritos;
- no incluir IP pública en links anónimos cuando el modo de privacidad lo prohíba;
- generar URLs relativas o URLs del endpoint configurado;
- respetar bind LAN y autenticación;
- no exponer un canal privado solo por conocer el hash.

### 11.9 API asíncrona

Operaciones que puedan tardar más de 500 ms deberían devolver:

```json
{
  "ok": true,
  "accepted": true,
  "operation_id": "op-123",
  "status_url": "/api/v1/operations/op-123"
}
```

El endpoint `/api/v1/operations/{id}` debe permitir conocer `queued`, `running`, `succeeded`, `failed` o `cancelled`.

Las operaciones completadas deben tener TTL y límite máximo. Expirar una operación no debe borrar el recurso creado ni perder el resultado final persistente.

---

## 12. Autenticación, autorización y exposición remota

### 12.1 Modelo de exposición

Niveles permitidos:

1. **Localhost sin red LAN:** API en `127.0.0.1`, útil detrás de SSH tunnel o dashboard local.
2. **LAN autenticada:** API en IP LAN o `0.0.0.0`, token obligatorio.
3. **Reverse proxy autenticado:** API interna en loopback, TLS y autenticación delegada al proxy.
4. **Internet directa:** no soportada como configuración simple; requiere diseño adicional, TLS, rate limits, auditoría y revisión de amenazas.

### 12.2 Requisitos

| ID | Requisito |
|---|---|
| `API-AUTH-001` | Toda mutación remota DEBE requerir autenticación. |
| `API-AUTH-002` | El bind LAN DEBE rechazar peticiones no autenticadas, incluido HLS si el canal no es público. |
| `API-AUTH-003` | El token DEBE almacenarse fuera de la imagen Docker y con permisos restringidos. |
| `API-AUTH-004` | La comparación de tokens debe ser resistente a timing attacks en la medida razonable para el runtime. |
| `API-AUTH-005` | Las respuestas no deben revelar el token, secretos, claves privadas ni rutas sensibles innecesarias. |
| `API-AUTH-006` | Los endpoints de diagnóstico deben filtrar IPs o identificadores sensibles según el nivel de acceso. |
| `API-AUTH-007` | Las acciones administrativas deben quedar registradas con timestamp, actor lógico, endpoint y resultado. |
| `API-AUTH-008` | Debe existir rotación de token sin perder la identidad eD2K/Kad. |
| `API-AUTH-009` | La aplicación debe poder funcionar detrás de un reverse proxy sin confiar ciegamente en `X-Forwarded-For`. |
| `API-AUTH-010` | CORS debe estar desactivado o restringido por defecto. |
| `API-AUTH-011` | Debe haber rate limit para login/token inválido, broadcast start/stop y endpoints de control. |
| `API-AUTH-012` | Las páginas web no deben ejecutar acciones destructivas solo por cargar una URL GET. |
| `API-AUTH-013` | En primer arranque se generará un secreto aleatorio de al menos 256 bits; no habrá contraseña universal. |
| `API-AUTH-014` | El secreto bootstrap se escribirá en un fichero `0600` o secret store y no se imprimirá completo en logs persistentes. |
| `API-AUTH-015` | `health/live` puede ser anónimo, pero su respuesta remota será mínima y no incluirá versión detallada, paths, peers ni red interna. |
| `API-AUTH-016` | TLS directo no es obligatorio en el MVP, pero el despliegue remoto debe terminar TLS en un reverse proxy/VPN documentado. |
| `API-AUTH-017` | Si el dashboard usa cookies, las mutaciones requieren protección CSRF; si usa Bearer token, no debe copiarlo a URLs o logs. |
| `API-AUTH-018` | Los tokens HLS para players que no soporten headers serán capability tokens de alcance mínimo, expiración corta y revocables. |
| `API-AUTH-019` | Los capability tokens no deben aparecer en métricas, referers, logs normales ni playlists persistidas. |
| `API-AUTH-020` | La confianza en reverse proxy debe limitarse a una lista de IPs/redes configuradas y no solo a un booleano. |
| `API-AUTH-021` | El operador debe poder preprovisionar autenticación mediante un fichero/secret mount; el valor no se pasará en argumentos ni variables recomendadas de Compose. |
| `API-AUTH-022` | Debe existir un comando local para crear/rotar un token y escribirlo directamente en un fichero `0600`, sin incluirlo en logs. |
| `API-AUTH-023` | No habrá un endpoint de pairing LAN anónimo por defecto. Cualquier pairing futuro requerirá TTL corto, rate limit y aprobación local autenticada. |
| `API-AUTH-024` | Si un token generado se muestra una sola vez, será solo por una acción explícita en TTY/local control; nunca durante el arranque normal ni por health. |
| `API-AUTH-025` | El backend debe almacenar un verifier/hash del token cuando no necesite recuperar el bearer original; los tokens aleatorios tendrán ID separado para auditoría/revocación. |
| `API-AUTH-026` | Rotación y reset deben definir qué tokens, sesiones de dashboard y capabilities HLS se revocan y permitir un solapamiento corto para no bloquear al operador. |

### 12.3 Privilegios

Debe existir como mínimo:

- `viewer`: leer estado, canales y HLS permitido;
- `operator`: gestionar descargas, shares y Live;
- `admin`: configuración, token, shutdown, restart y actualización.

En la primera iteración se puede implementar un único token administrador, pero el contrato no debe impedir roles posteriores.

La autorización se evalúa en el backend del daemon. El dashboard no puede ser la única barrera de seguridad porque la API puede consumirse sin él.

### 12.4 Bootstrap en un equipo sin interfaz

Flujo recomendado:

1. montar un token creado por el operador, o ejecutar localmente `ese-daemon auth init --output <file>`;
2. arrancar el daemon ligado a loopback;
3. copiar el token al gestor de secretos del dispositivo administrador por un canal local/SSH/VPN;
4. habilitar el bind LAN o reverse proxy solo después de comprobar autenticación;
5. rotar el token y revocar el bootstrap si se usó para enrolar otro cliente.

`API-AUTH-027`: si la CLI controla un daemon en ejecución mediante Unix socket, el socket debe tener permisos restrictivos, verificar credenciales del peer (`SO_PEERCRED` o equivalente) y no aceptar conexiones desde el listener HTTP público.

- `API-AUTH-028`: la autorización se aplica en el daemon por endpoint/acción; confiar en que el dashboard oculte un botón no es un control de seguridad.
- `API-AUTH-029`: players, televisores y URLs HLS no recibirán un token administrador cuando una capability de solo lectura y alcance limitado sea suficiente.

---

## 13. Dashboard web

### 13.1 Requisitos

- `WEB-001`: el dashboard debe funcionar desde otro dispositivo de la LAN.
- `WEB-002`: el dashboard no debe ser requisito para que el daemon descargue o comparta.
- `WEB-003`: debe detectar si el backend está `starting`, `ready` o `degraded`.
- `WEB-004`: debe mostrar un aviso claro cuando el HDD no está disponible.
- `WEB-005`: debe mostrar CPU, memoria, disco, conectividad, Kad, HighID/LowID y puertos.
- `WEB-006`: debe permitir configurar y validar el path de datos sin mover ficheros automáticamente.
- `WEB-007`: debe manejar reconexiones y reinicios del daemon.
- `WEB-008`: debe poder ejecutarse como proceso separado o ser omitido en `lite`.
- `WEB-009`: no debe asumir que `localhost` del navegador es el host del daemon cuando se accede remotamente.
- `WEB-010`: las URLs HLS deben construirse a partir del origen del daemon o del `advertised_address` configurado.
- `WEB-011`: `ese-web` debe poder ejecutarse en otro host/contenedor y administrar un daemon remoto sin acceso directo a su filesystem.
- `WEB-012`: el daemon `lite` debe seguir siendo totalmente administrable por API/CLI; una variante de assets web estáticos servidos sin runtime Node es P1.
- `WEB-013`: dashboard y daemon deben negociar versión/capabilities de API y mostrar incompatibilidad explícita, no fallar con controles parcialmente operativos.
- `WEB-014`: el modo de bajo ancho de banda debe evitar polling agresivo y permitir reducir frecuencia de gráficas/eventos.
- `WEB-015`: el dashboard no debe cachear tokens ni respuestas sensibles en service workers o caches compartidas sin una política explícita de borrado/logout.

### 13.2 Diseño de despliegue

Se soportarán dos variantes:

```text
Variante A: daemon + API C++
                 ▲
                 │ navegador / cliente externo

Variante B: daemon + ese-web en el mismo host/red privada
                 ▲
                 │ navegador

Variante C: daemon lite ── API/HLS autenticada ── ese-web en otro host
                                                    ▲
                                                    │ navegador
```

En Docker, `ese-web` puede estar en el mismo contenedor para simplificar una instalación doméstica, en un segundo contenedor o en otro equipo. En la variante remota, HLS y descargas se sirven desde el daemon/gateway autorizado; el dashboard no intenta leer el HDD por una ruta local coincidente.

### 13.3 Contrato de proxy

Si Node actúa como gateway:

- solo debe hablar con el backend por loopback o red Docker privada;
- debe propagar status codes y errores correctamente;
- debe aplicar timeout de backend;
- no debe ocultar un `503` del daemon como `200` con HTML vacío;
- debe poder detectar backend down y mostrarlo;
- no debe duplicar la lógica de negocio del motor.
- debe eliminar headers hop-by-hop y validar `Host`, `Origin` y tamaño de respuesta;
- no debe reenviar a destinos elegidos por el usuario ni convertirse en un proxy HTTP genérico;
- debe mantener los tokens fuera del HTML, URLs, localStorage no protegido y logs de acceso cuando sea posible.

---

## 14. LiveTV y FFmpeg en hardware limitado

### 14.1 Separación de funciones

El daemon base debe funcionar sin LiveTV. Live añade:

- ingest RTMP o fuente externa;
- supervisor de FFmpeg;
- generación de HLS;
- watcher de segmentos;
- buffer de chunks en RAM;
- publicación/descubrimiento Kad;
- distribución por peers;
- API de reproducción.

### 14.2 Requisitos

| ID | Requisito |
|---|---|
| `LIVE-RES-001` | Live debe poder desactivarse globalmente. |
| `LIVE-RES-002` | RTMP debe poder desactivarse independientemente de la reproducción. |
| `LIVE-RES-003` | FFmpeg debe localizarse por ruta configurada, PATH o paquete del sistema, en ese orden documentado. |
| `LIVE-RES-004` | El comando de FFmpeg debe construirse con argumentos estructurados, nunca concatenando input de usuario en un shell. |
| `LIVE-RES-005` | Título, nombre de canal y paths deben escaparse de forma segura. |
| `LIVE-RES-006` | Cada emisión debe tener directorio aislado y nombre seguro. |
| `LIVE-RES-007` | El supervisor debe conocer PID, estado, exit code y causa de terminación. |
| `LIVE-RES-008` | No se debe terminar FFmpeg de otros usuarios o contenedores por nombre global. |
| `LIVE-RES-009` | FFmpeg debe tener límites de tiempo, memoria o cgroup cuando el entorno lo permita. |
| `LIVE-RES-010` | Si FFmpeg muere, el estado Live debe pasar a `error` y el daemon debe seguir operativo. |
| `LIVE-RES-011` | La emisión debe rechazar bitrate/calidad que superen límites configurados. |
| `LIVE-RES-012` | El buffer Live debe permanecer acotado y no crecer indefinidamente. |
| `LIVE-RES-013` | El daemon debe limpiar segmentos huérfanos por TTL y al apagar limpiamente. |
| `LIVE-RES-014` | El watcher debe tolerar segmentos incompletos, renombres y latencia de filesystem. |
| `LIVE-RES-015` | Una Pi incapaz de transcodificar debe poder actuar como relay/viewer sin encoder local. |

### 14.3 Modos de fuente

El contrato puede conservar las fuentes actuales y añadir:

- `testpattern` para smoke tests;
- `rtmp-listen` para OBS;
- `file` para fichero local;
- `external-hls` para HLS ya generado;
- `pipe` o `stdin` solo si se define un contrato seguro y no bloqueante.

### 14.4 Capacidad mínima recomendada

El software debe calcular un preflight aproximado con:

- cores disponibles;
- carga de CPU;
- RAM libre;
- espacio temporal;
- presencia de FFmpeg;
- encoder hardware detectado si procede;
- bitrate solicitado;
- número de viewers/peers;
- ancho de banda configurado.

El resultado debe ser `ok`, `warning` o `fail`, con razones accionables.

---

## 15. Scheduler, concurrencia y robustez 24/7

### 15.1 Principios

- El motor debe tener un scheduler monotónico propio.
- El API no debe bloquear el hilo de red esperando Kad, disco o FFmpeg.
- Los locks no deben mantenerse durante IO de socket o disco lento.
- Los snapshots deben ser consistentes y baratos de leer.
- Cada thread debe tener ownership y shutdown definidos.

### 15.2 Threads o actores mínimos

| Componente | Responsabilidad |
|---|---|
| Main engine loop | comandos, estado y tareas periódicas |
| eD2K TCP | aceptación y tráfico TCP |
| Kad UDP | DHT, bootstrap y búsquedas |
| Live transport | peers, chunks, mesh y retransmisiones |
| Storage workers | operaciones de disco acotadas |
| API server | HTTP y autenticación |
| FFmpeg supervisor | child process y watcher |
| Metrics/log | agregación y exportación |

El número exacto puede reducirse en `lite`, pero la separación de responsabilidades debe mantenerse.

### 15.3 Requisitos de estabilidad

| ID | Requisito |
|---|---|
| `ROB-001` | Ningún endpoint de lectura debe bloquearse indefinidamente por una operación del motor. |
| `ROB-002` | Toda operación de red debe tener timeout o cancelación. |
| `ROB-003` | Toda operación de disco debe manejar ENOENT, EACCES, ENOSPC, EROFS, EIO y EINTR. |
| `ROB-004` | Las excepciones de worker deben convertirse en estado/log; no deben terminar el proceso sin política explícita. |
| `ROB-005` | El proceso debe tener watchdog externo en systemd/Docker, no solo un thread que se observe a sí mismo. |
| `ROB-006` | Los backoffs deben tener jitter para evitar tormentas después de reinicio. |
| `ROB-007` | Las colas internas deben tener límites y métricas de saturación. |
| `ROB-008` | El crecimiento de memoria debe medirse en una prueba de 24 h como mínimo y preferiblemente 7 días antes de release estable. |
| `ROB-009` | Las operaciones repetidas de start/stop/reconnect deben ser idempotentes. |
| `ROB-010` | La pérdida temporal de Kad, API externa, DNS o HDD no debe producir busy-loop. |

---

## 16. Observabilidad y diagnóstico

### 16.1 Logs

Cada línea debería incluir:

- timestamp;
- nivel;
- componente;
- instance ID;
- thread/contexto cuando ayude;
- correlation ID para peticiones API;
- código estable del evento;
- mensaje humano;
- campos estructurados opcionales.

Los logs deben tener política de retención y redacción. Por defecto no registrarán nombres completos de archivos, hashes completos, IPs completas, tokens, rutas privadas o query strings de HLS autenticado en nivel `info`. El nivel de diagnóstico ampliado será temporal, explícito y advertirá del riesgo de datos sensibles.

Formato texto ejemplo:

```text
2026-07-14T18:21:04Z INFO [STORAGE] instance=ese-home code=STORAGE_READY path=/mnt/ese-data free_mb=81234
```

Formato JSON opcional:

```json
{"ts":"2026-07-14T18:21:04Z","level":"info","component":"storage","code":"STORAGE_READY","free_mb":81234}
```

### 16.2 Métricas obligatorias

El endpoint Prometheus debe incluir como mínimo:

- uptime;
- estado del proceso;
- conexiones TCP/UDP;
- peers activos;
- Kad conectado, contactos, búsquedas y latencia;
- descargas activas, completadas y errores;
- bytes descargados/subidos;
- memoria RSS;
- CPU si está disponible;
- espacio libre por volumen;
- errores de IO;
- operaciones API y latencia;
- estado de FFmpeg;
- bitrate y chunks Live;
- p50/p95/p99 de llegada de chunks cuando Live esté habilitado;
- reconnects, timeouts y backpressure.

`OBS-MET-001`: las métricas DEBEN evitar cardinalidad no acotada: no se permiten labels por peer, IP, filename, hash, stream key, request ID u operation ID. Ese detalle pertenece a snapshots/logs protegidos, no a Prometheus.

### 16.3 Privacidad y telemetría

| ID | Requisito |
|---|---|
| `OBS-PRIV-001` | No habrá telemetría, analytics ni crash upload externos activados por defecto. |
| `OBS-PRIV-002` | Toda exportación remota debe ser opt-in, documentar destino y mostrar qué campos salen del nodo. |
| `OBS-PRIV-003` | Los crash dumps pueden contener datos sensibles y deben almacenarse localmente con permisos restringidos y retención configurable. |
| `OBS-PRIV-004` | Logs y auditoría tendrán límites por tamaño/tiempo y rotación segura. |
| `OBS-PRIV-005` | El usuario debe poder borrar logs/cache sin borrar identidad ni progreso de descargas. |

### 16.4 Diagnóstico remoto

`/api/v1/diagnostics` debe producir un resumen accionable:

```json
{
  "overall": "warning",
  "checks": [
    {"id":"config","status":"ok"},
    {"id":"storage","status":"warning","reason":"free space below threshold"},
    {"id":"kad","status":"ok","contacts":128},
    {"id":"tcp_port","status":"fail","port":4662,"reason":"not reachable"},
    {"id":"ffmpeg","status":"skipped","reason":"live disabled"}
  ]
}
```

Nunca debe incluir claves privadas ni tokens.

---

## 17. Docker

### 17.1 Requisitos de imagen

| ID | Requisito |
|---|---|
| `DOC-IMG-001` | La imagen debe poder ejecutarse en `linux/amd64` y `linux/arm64`. |
| `DOC-IMG-002` | La imagen debe tener tag versionado inmutable y tag de canal (`stable`, `beta`, `nightly`) separado. |
| `DOC-IMG-003` | La imagen debe ejecutar el daemon en foreground. |
| `DOC-IMG-004` | La imagen debe usar un usuario no root por defecto. |
| `DOC-IMG-005` | La imagen no debe necesitar `--privileged`. |
| `DOC-IMG-006` | La imagen no debe requerir acceso al socket Docker. |
| `DOC-IMG-007` | La configuración y los datos deben vivir en volúmenes externos. |
| `DOC-IMG-008` | El root filesystem debería poder montarse read-only. |
| `DOC-IMG-009` | `/tmp` y `/run` deben poder ser tmpfs. |
| `DOC-IMG-010` | La imagen debe incluir healthcheck o documentación equivalente. |
| `DOC-IMG-011` | El contenedor debe respetar `SIGTERM` y `stop-grace-period`. |
| `DOC-IMG-012` | La imagen debe declarar arquitectura, versión, commit y fecha de build. |
| `DOC-IMG-013` | El contenedor debe funcionar sin Node.js en el perfil lite. |
| `DOC-IMG-014` | FFmpeg debe ser una variante, paquete opcional o dependencia explícita, no una sorpresa oculta. |
| `DOC-IMG-015` | La imagen debe documentar UID/GID y permisos necesarios de los volúmenes. |
| `DOC-IMG-016` | La imagen DEBE funcionar con todas las Linux capabilities eliminadas en el perfil base. |
| `DOC-IMG-017` | Las bases de imagen se fijarán por versión/digest y se revisarán por vulnerabilidades conocidas. |
| `DOC-IMG-018` | Cada release publicará SBOM, checksums y procedencia del commit; la firma de imagen es P1. |
| `DOC-IMG-019` | Los ejemplos de producción usarán versión inmutable o digest, no dependerán solo de `latest`. |
| `DOC-IMG-020` | El healthcheck local debe funcionar sin exponer un token administrativo en `docker inspect` o `ps`. |
| `DOC-IMG-021` | UID/GID efectivos deben poder adaptarse a bind mounts sin ejecutar permanentemente como root. |
| `DOC-IMG-022` | La imagen no ejecutará migraciones destructivas automáticamente sin backup y compatibilidad comprobada. |
| `DOC-IMG-023` | Entrypoint/init deben propagar señales y exit codes; ningún wrapper shell puede convertir un error fatal en un proceso colgado o exit 0. |
| `DOC-IMG-024` | La documentación debe advertir que `restart: unless-stopped` puede reintentar errores permanentes y explicar cómo diagnosticar/detener un crash loop. |
| `DOC-IMG-025` | El arranque no hará `chown -R` ni escaneo completo de un HDD grande; validará las rutas necesarias y ofrecerá una preparación de permisos explícita. |

### 17.2 Variables de entorno

Prefijo propuesto `ESE_`:

```text
ESE_PROFILE=lite|standard|live
ESE_OVERLAYS=vps-safe
ESE_CONFIG_FILE=/etc/ese/ese.conf
ESE_CONFIG_DIR=/var/lib/ese
ESE_DATA_DIR=/mnt/ese-data
ESE_API_BIND=0.0.0.0
ESE_API_PORT=4711
ESE_DASHBOARD_ENABLED=false
ESE_DASHBOARD_BIND=0.0.0.0
ESE_DASHBOARD_PORT=8080
ESE_TCP_PORT=4662
ESE_UDP_PORT=4672
ESE_RTMP_ENABLED=false
ESE_AUTH_TOKEN_FILE=/var/lib/ese/config/api.token
ESE_LOG_FORMAT=json
ESE_LOG_LEVEL=info
```

La precedencia debe estar documentada. Propuesta:

```text
defaults < config file < environment < CLI explícita
```

Los secretos no deben pasarse en argumentos visibles en `ps`.

### 17.3 Docker Compose de referencia

El siguiente fichero es una especificación de despliegue de la variante single-container con dashboard. La versión `1.0.0` es ilustrativa y debe sustituirse por una release inmutable o digest publicado; no se usará `stable`/`latest` en producción:

```yaml
services:
  ese-daemon:
    image: ghcr.io/ese-project/ese-daemon:1.0.0
    container_name: ese-daemon
    restart: unless-stopped
    init: true
    stop_signal: SIGTERM
    stop_grace_period: 20s
    read_only: true
    tmpfs:
      - /tmp:size=256m
      - /run:size=16m
    environment:
      ESE_PROFILE: standard
      ESE_CONFIG_FILE: /etc/ese/ese.conf
      ESE_API_BIND: 0.0.0.0
      ESE_DASHBOARD_ENABLED: "true"
      ESE_DASHBOARD_BIND: 0.0.0.0
      ESE_LOG_FORMAT: json
      ESE_LOG_LEVEL: info
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 256
    ports:
      - "4662:4662/tcp"
      - "4672:4672/udp"
      - "127.0.0.1:4711:4711/tcp"
      - "127.0.0.1:8080:8080/tcp"
    volumes:
      - ./config:/etc/ese:ro
      - ./state:/var/lib/ese
      - /mnt/ese-data:/mnt/ese-data
    healthcheck:
      test: ["CMD", "ese-daemon", "--healthcheck", "live"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
```

Si la API se publica solo mediante un reverse proxy, el bind directo de 4711 debe quedar en loopback o en una red Docker privada.

Los binds `0.0.0.0` del ejemplo pertenecen al namespace del contenedor. Los binds `127.0.0.1:PUERTO_HOST:PUERTO_CONTENEDOR` limitan la exposición en el host. Para acceso LAN se debe cambiar explícitamente el bind del host y mantener autenticación.

### 17.4 Actualización de contenedores

La estrategia será de imagen inmutable:

1. obtener nueva imagen por tag versionado/digest;
2. detener limpiamente la versión actual;
3. crear backup/snapshot del volumen de estado;
4. ejecutar `--check-state-migration` con la nueva versión;
5. arrancar el nuevo contenedor;
6. verificar health, identidad, descargas y schema;
7. conservar la imagen anterior y backup para rollback.

Conforme a `UPG-007`, el daemon dentro del contenedor no reemplaza su propio binario ni ejecuta un auto-updater Windows. Rollback solo es seguro si el formato persistente es backward-compatible o se restaura el snapshot previo.

### 17.5 Docker con multicast

La funcionalidad mDNS-style/UDP multicast 5354 es opcional. Debe documentarse:

- bridge normal: puede no recibir multicast;
- `network_mode: host`: suele ser la opción doméstica más sencilla, con menor aislamiento;
- redes macvlan/ipvlan: requieren configuración específica del host;
- el daemon no debe considerar la ausencia de multicast como error fatal.

### 17.6 VPS: viabilidad técnica y política de proveedor

El daemon es técnicamente viable en un VPS porque su base funcional es Linux, sockets TCP/UDP, almacenamiento de ficheros y procesos opcionales. Docker tampoco debe ser un impedimento especial: el mismo contenedor puede ejecutarse en un VPS si el proveedor permite los puertos y el tráfico necesarios.

La limitación principal no es técnica sino contractual y operativa. Un proveedor puede:

- bloquear o restringir algunos puertos TCP/UDP;
- restringir multicast;
- aplicar fair-use o throttling cuando el tráfico sea excepcionalmente alto;
- enviar una notificación de abuso ante una queja de copyright, spam, escaneo o tráfico anómalo;
- suspender o bloquear la IP o el servidor mientras se investiga;
- prohibir explícitamente P2P, proxies, Tor, VPN pública o servicios de relay en un producto concreto.

Por tanto, antes de desplegar se debe comprobar la AUP vigente del producto exacto, no una opinión general sobre la marca. Como referencias de la clase de restricciones que hay que revisar:

- [DigitalOcean Droplet Policies](https://docs.digitalocean.com/products/droplets/details/policies/) y su [Acceptable Use Policy](https://www.digitalocean.com/legal/acceptable-use-policy): el usuario es responsable del uso del Droplet, se prohíben infracciones de propiedad intelectual y se mencionan restricciones de tráfico como torrents en ciertos escenarios y multicast.
- [OVHcloud Service-Specific Terms](https://us.ovhcloud.com/legal/service-specific-terms/): advierten que algunos protocolos o usos, incluido el intercambio P2P, pueden estar restringidos, y prohíben determinados servicios de proxy, VPN, Tor o P2P según las condiciones aplicables.
- [Hetzner guideline for locked products](https://docs.hetzner.com/robot/dedicated-server/troubleshooting/guideline-in-case-of-server-locking/): contempla bloqueos por abuso, material que infrinja copyright y ataques de red.
- [Contabo fair-use bandwidth policy](https://help.contabo.com/en/support/solutions/articles/103000271195-are-there-any-bandwith-limits-at-contabo-): indica que un uso excepcionalmente alto o disruptivo puede provocar throttling.

Estas referencias no constituyen una lista de proveedores recomendados ni asesoramiento legal. La comprobación debe repetirse al contratar, porque las condiciones, regiones y productos cambian.

#### Checklist antes de contratar un VPS

El operador debe obtener una respuesta afirmativa o una confirmación escrita para cada punto:

- [ ] ¿La AUP permite un cliente P2P privado para contenido legalmente autorizado?
- [ ] ¿Se permiten conexiones entrantes TCP y UDP en los puertos elegidos?
- [ ] ¿Hay límites de tráfico mensual, fair-use o throttling?
- [ ] ¿El proveedor bloquea o filtra tráfico eD2K/Kad o UDP no web?
- [ ] ¿El producto permite almacenamiento persistente adicional?
- [ ] ¿El precio del disco y del tráfico es compatible con el uso previsto?
- [ ] ¿Qué ocurre ante una queja de copyright o abuso?
- [ ] ¿Se bloquea solo la IP, el VPS, la cuenta o toda la organización?
- [ ] ¿Existe una ventana para responder a una notificación?
- [ ] ¿Se necesita IPv4 pública y tiene coste adicional?
- [ ] ¿El proveedor permite Docker sin `--privileged`?
- [ ] ¿El proveedor restringe multicast, aunque no se use en el perfil `vps-safe`?
- [ ] ¿Hay snapshots/backups o se deben mantener fuera?

#### Política de operación segura en VPS

La instalación VPS debe:

1. comenzar con `vps-safe`;
2. abrir solo API privada, SSH protegido y puertos eD2K/Kad necesarios;
3. comprobar el límite de tráfico contratado;
4. desactivar RTMP y transcoding inicialmente;
5. usar contenido cuya distribución esté autorizada;
6. monitorizar bytes de salida, conexiones, errores y avisos del proveedor;
7. mantener un canal de contacto actualizado para responder a abuse reports;
8. disponer de backup fuera del VPS;
9. tener una forma rápida de detener el daemon o limitar upload;
10. no intentar eludir bloqueos o límites del proveedor.

#### VPS frente a Raspberry/NAS

| Criterio | VPS | Raspberry/NAS doméstico |
|---|---|---|
| Disponibilidad pública | alta | depende de NAT/CGNAT |
| HDD externo | no físico; volumen cloud | sí |
| Coste de almacenamiento | mensual y escalable | compra inicial, electricidad |
| Política P2P | depende del proveedor y abuse | depende del ISP, normalmente más control local |
| IP pública | normalmente sí | normalmente no o dinámica |
| Live encode | limitado por CPU/coste | depende del hardware |
| Privacidad de archivos | depende del proveedor | control físico local |
| Backups | responsabilidad del operador | responsabilidad del operador |
| Mejor uso | relay, reachability, pruebas, nodo pequeño | biblioteca, descargas permanentes, HLS doméstico |

---

## 18. Linux nativo y systemd

### 18.1 Unidad de referencia

```ini
[Unit]
Description=eMule eSE headless daemon
After=network-online.target local-fs.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=ese
Group=ese
ExecStart=/usr/bin/ese-daemon --config /etc/ese/ese.conf --foreground
Restart=on-failure
RestartSec=10s
RestartPreventExitStatus=2 3 4 5
TimeoutStopSec=20s
StateDirectory=ese
RuntimeDirectory=ese
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ese /mnt/ese-data /run/ese
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077

[Install]
WantedBy=multi-user.target
```

La unidad final debe revisarse en cada distribución. No se debe activar `ProtectSystem`, `PrivateTmp`, `ProtectHome`, `ReadWritePaths`, filtros de syscalls o `MemoryDenyWriteExecute` sin comprobar que no rompan las rutas configuradas, FFmpeg ni las bibliotecas del build. `ExecReload` solo se añadirá cuando `SIGHUP` tenga semántica transaccional implementada y probada.

### 18.2 Requisitos systemd

- `SYS-001`: el paquete debe incluir usuario/grupo opcional o documentar su creación.
- `SYS-002`: la unidad debe reiniciar solo ante errores, no tras `systemctl stop` normal.
- `SYS-003`: el servicio debe ser observable mediante `systemctl status` y journald.
- `SYS-004`: el daemon no debe requerir login de usuario.
- `SYS-005`: el fichero de token no debe ser legible por otros usuarios.
- `SYS-006`: la unidad debe permitir un override local sin editar el fichero distribuido.
- `SYS-007`: si se usa un HDD externo, la unidad puede declarar dependencia sobre un mountpoint, pero el daemon debe seguir manejando la pérdida posterior.
- `SYS-008`: la unidad distribuida no debe requerir capabilities para los puertos por defecto, todos superiores a 1024.
- `SYS-009`: las rutas custom se añadirán mediante override de systemd; el paquete no debe asumir que `/mnt/ese-data` existe.
- `SYS-010`: el hardening se verificará con una prueba funcional; una puntuación alta de `systemd-analyze security` no justifica romper media, red o storage.
- `SYS-011`: la unidad debe limitar crash loops y usar `RestartPreventExitStatus` para distinguir errores permanentes de configuración/storage/dependencia de fallos recuperables.
- `SYS-012`: un watchdog con `sd_notify` puede añadirse cuando mida progreso real del event loop; no debe enviar keepalives desde un thread independiente que oculte un motor bloqueado.

---

## 19. Build system y portabilidad

### 19.1 Build objetivo

El proyecto debe evolucionar de una solución centrada en `.sln/.vcxproj` a una estructura que permita:

```bash
cmake -S . -B build/linux-release \
  -DESE_BUILD_DAEMON=ON \
  -DESE_BUILD_GUI=OFF \
  -DESE_BUILD_WEB=OFF \
  -DESE_BUILD_LIVE=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build/linux-release --parallel
ctest --test-dir build/linux-release --output-on-failure
```

### 19.2 Targets de toolchain

P0:

- Ubuntu/Debian x86_64;
- Ubuntu/Debian ARM64;
- compilación local con GCC y Clang cuando sea posible;
- sanitizers en x86_64.
- proceso y archivos de 64 bits; no se soporta un daemon P0 de 32 bits.

P1:

- cross-compile ARM64 desde x86_64;
- Debian/Raspberry Pi OS;
- Alpine/musl como evaluación separada;
- ARMv7 experimental.

El target portable usará como mínimo C++17 mientras no se apruebe otra versión. El CI debe compilar contra la distribución base más antigua soportada para no producir accidentalmente binarios que requieran una glibc más nueva. La matriz concreta de distribución, glibc, GCC y Clang debe fijarse antes de la primera beta.

### 19.3 Abstracciones que hay que aislar

| Área actual | Sustituto objetivo |
|---|---|
| `CString` | `std::string`/`std::wstring` solo en adaptador de plataforma cuando sea necesario |
| `CFile` | capa de filesystem + `std::fstream`/POSIX fd |
| `CObject` | clases C++ normales |
| `CCriticalSection` | `std::mutex`/`std::recursive_mutex` donde esté justificado |
| `CAsyncSocket` y `CAsyncSocketEx` actual | `INetworkReactor` + sockets BSD/Windows sin ventanas auxiliares |
| `WSA*` | wrapper de errores y sockets |
| `GetTickCount` | reloj monotónico |
| `Sleep` | scheduler/condition variable |
| `CreateProcess` | `IProcessSupervisor` |
| `SetTimer/WM_TIMER` | scheduler del engine |
| `%APPDATA%` | `PathProvider` XDG/Windows |
| `SHGetFolderPath` | `PathProvider` |
| `CreateDirectory` | filesystem portable |
| DPAPI | `INodeIdentityStorage` con backend POSIX |

### 19.4 Regla de migración

No se debe convertir todo el repositorio en un único cambio. La migración debe seguir este orden:

1. interfaces puras y tests;
2. adaptador Windows que preserve comportamiento;
3. uso del adaptador desde un componente;
4. build del componente en Linux;
5. integración del componente en `ese-daemon`;
6. eliminación de la dependencia MFC cuando ningún target la necesite.

Gates automáticos:

- compilar headers públicos del core en translation units mínimas;
- fallar si un directorio portable incluye MFC/Windows SDK fuera de adaptadores allowlist;
- tratar warnings nuevos como error en el código portable;
- ejecutar ASan/UBSan en Linux y el análisis equivalente disponible en Windows;
- verificar que tamaños serializados usan tipos de anchura fija;
- no usar glob recursivo de fuentes en CMake si puede ocultar altas/bajas accidentales.

### 19.5 Dependencias, supply chain y licencias

| ID | Requisito |
|---|---|
| `SUPPLY-001` | Cada binario e imagen debe identificar versión, commit y configuración de build. |
| `SUPPLY-002` | La release debe publicar SBOM de dependencias C/C++, Node y binarios auxiliares. |
| `SUPPLY-003` | Dependencias vendorizadas y de sistema deben tener versión, origen, checksum y licencia documentados. |
| `SUPPLY-004` | Las vulnerabilidades críticas conocidas deben bloquear una release salvo excepción documentada con mitigación. |
| `SUPPLY-005` | Los artefactos deben tener checksums; firma de releases/imágenes es P1. |
| `SUPPLY-006` | La distribución Docker/Linux debe cumplir GPL-2.0 y ofrecer el corresponding source exacto de la build distribuida. |
| `SUPPLY-007` | La imagen debe incluir o enlazar de forma clara `license.txt`, `THIRD_PARTY_LICENSES.md` y avisos requeridos. |
| `SUPPLY-008` | La variante con FFmpeg debe documentar configuración, codecs y obligaciones de licencia diferentes de la variante lite. |
| `SUPPLY-009` | El build no debe descargar ejecutables sin checksum durante una release reproducible. |
| `SUPPLY-010` | Las credenciales de CI, registry o firma nunca se incorporarán a capas de imagen ni artefactos. |

---

## 20. Compatibilidad de protocolo y formatos

### 20.1 Requisitos de cable

| ID | Requisito |
|---|---|
| `COMP-WIRE-001` | El daemon debe interoperar con un cliente Windows eSE de la misma generación. |
| `COMP-WIRE-002` | El tráfico eD2K/Kad clásico debe seguir funcionando con clientes vanilla compatibles. |
| `COMP-WIRE-003` | Las extensiones Live deben anunciarse mediante capability/capability gate. |
| `COMP-WIRE-004` | Un peer que no entiende Live no debe recibir una secuencia que rompa el protocolo clásico. |
| `COMP-WIRE-005` | Cualquier nuevo opcode o tag requiere vector de bytes, parser, writer, test y pcap de compatibilidad. |
| `COMP-WIRE-006` | La endianess y los tamaños de enteros deben estar documentados por campo. |
| `COMP-WIRE-007` | Los parsers deben rechazar longitudes truncadas, excesivas o inconsistentes sin desbordamiento. |
| `COMP-WIRE-008` | Deben existir fixtures compartidos entre C++ Windows, C++ Linux y Python cuando sea útil. |

### 20.2 Identidad

Las identidades no son intercambiables y no deben regenerarse como una única operación implícita:

| Identificador/secreto | Uso | Persistencia esperada | Regeneración |
|---|---|---|---|
| instance ID | manifiesto, API y operación | vida de la instancia lógica | clonación explícita |
| eD2K UserHash | compatibilidad de cable/peers | estable entre reinicios y upgrades | comando explícito con confirmación |
| node key / Node ID eSE | identidad criptográfica del nodo | estable y respaldada, clave `0600` | recuperación/clonación explícita |
| API token | autenticación administrativa | persistente pero rotatable | independiente de UserHash/Node ID |
| stream key | una emisión Live | efímera o según política de la emisión | nueva emisión/rotación de stream |

- La identidad del nodo debe persistir entre reinicios.
- En POSIX, el fichero de identidad debe ser `0600`.
- La clave privada nunca se expone por API.
- La migración de configuración no debe generar una identidad nueva por cambiar de contenedor si el volumen de estado se conserva.
- `ESE_NODE_ID` debe ser estable y visible solo en la medida necesaria para diagnóstico.
- Las instancias deliberadamente múltiples en un mismo host deben usar directorios y puertos separados y no compartir identidad.

Requisitos:

- `COMP-ID-001`: el daemon debe ofrecer un comando explícito para clonar configuración regenerando identidad y secretos.
- `COMP-ID-002`: copiar un volumen para backup no debe regenerar identidad al restaurarlo en la misma instancia lógica.
- `COMP-ID-003`: ejecutar simultáneamente dos clones con la misma identidad debe generar una advertencia de alta severidad cuando pueda detectarse.
- `COMP-ID-004`: regenerar UserHash, node key o API token son operaciones distintas y no deben acoplarse accidentalmente.
- `COMP-ID-005`: las claves deben generarse con CSPRNG y validarse por tamaño/versión al cargar.
- `COMP-ID-006`: el daemon Linux no heredará la regeneración automática de UserHash que hoy ejecuta `m_bHeadless`; solo se permite en un modo de test efímero o comando explícito.
- `COMP-ID-007`: arrancar con `--ephemeral-identity` debe estar prohibido en el servicio/imagen de producción salvo opt-in inequívoco y debe mostrar una advertencia de alta severidad.
- `COMP-ID-008`: backup y restore deben conservar instance ID, UserHash y node key de la misma generación; restaurar solo una parte debe rechazarse o entrar en modo reparación.
- `COMP-ID-009`: los logs pueden mostrar fingerprints públicos abreviados para diagnóstico, pero nunca claves privadas, tokens ni material suficiente para suplantar el nodo.

### 20.3 Formatos persistentes

Cada formato debe declarar:

- propietario lógico;
- versión;
- compatibilidad de lectura;
- compatibilidad de escritura;
- estrategia de backup;
- comportamiento ante truncado/corrupción;
- si es regenerable o crítico.

Clasificación propuesta:

| Tipo | Ejemplo | Pérdida aceptable |
|---|---|---|
| Crítico | identidad, preferences, progreso | no |
| Recuperable | nodes.dat, cache de discovery | sí, con degradación |
| Regenerable | thumbnails, HLS temporal, logs | sí |
| Externo | descargas y shared | no sin confirmación |

### 20.4 Migraciones, upgrade y rollback

| ID | Requisito |
|---|---|
| `UPG-001` | Toda migración persistente debe declarar versión origen, destino, reversibilidad y espacio temporal requerido. |
| `UPG-002` | Antes de una migración se crea backup/snapshot consistente o se rechaza la operación. |
| `UPG-003` | `--check-state-migration` debe inspeccionar sin modificar y devolver diagnóstico accionable. |
| `UPG-004` | Una migración interrumpida debe poder reanudarse o hacer rollback sin mezclar generaciones. |
| `UPG-005` | El daemon no debe abrir estado de una versión futura en modo escritura. |
| `UPG-006` | Downgrade de binario solo se considera soportado restaurando el snapshot previo, salvo compatibilidad explícita. |
| `UPG-007` | Las imágenes Docker son inmutables; el proceso no auto-actualiza su binario. |
| `UPG-008` | En Linux nativo, las actualizaciones deben integrarse con el package manager o instalación atómica documentada. |
| `UPG-009` | El rollback debe verificar que identidad, descargas y puertos efectivos coinciden con el estado esperado. |
| `UPG-010` | Debe existir una matriz automatizada N-1→N y N→fallo→restore N-1 antes de release estable. |

### 20.5 Manifiesto de estado

El directorio persistente debe incluir un manifiesto legible sin arrancar toda la red, con:

- `state_schema_version`;
- versión/commit que escribió por última vez;
- instance ID y node ID público abreviado;
- timestamp de última escritura y último shutdown limpio;
- lista de componentes/formats presentes;
- checksums solo de metadatos donde sea práctico;
- migration journal si hay una operación incompleta.

El manifiesto no contendrá claves privadas, tokens ni nombres completos de archivos compartidos.

---

## 21. Seguridad operativa

### 21.1 Threat model mínimo

El daemon debe asumir:

- otros dispositivos en la LAN no son automáticamente confiables;
- el HDD puede contener nombres, hashes y datos sensibles;
- un link Live puede contener metadata controlada por un peer;
- el contenedor puede ejecutarse con un UID que no coincida con el host;
- un atacante puede enviar HTTP malformado;
- los peers remotos pueden enviar longitudes, tags, bitmaps o bitrates falsos;
- el proceso puede reiniciarse o perder red en cualquier momento.

### 21.2 Requisitos

- `SEC-D-001`: validar todos los paths contra las raíces configuradas.
- `SEC-D-002`: rechazar `..`, separadores inesperados y symlinks peligrosos en recursos HLS.
- `SEC-D-003`: aplicar límites de tamaño a bodies, query strings, tags y fragmentos.
- `SEC-D-004`: no loggear tokens, contraseñas, claves privadas ni links completos si contienen información sensible.
- `SEC-D-005`: limitar peticiones de control por IP/token.
- `SEC-D-006`: no usar shell para procesar input de usuario.
- `SEC-D-007`: usar listas allowlist para recursos HLS.
- `SEC-D-008`: revisar todos los endpoints existentes para asegurar que la autenticación se aplica antes de despachar la operación.
- `SEC-D-009`: las funciones de test/sabotage deben compilarse desactivadas o quedar inaccesibles en producción.
- `SEC-D-010`: el contenedor debe correr sin root.
- `SEC-D-011`: el fichero de identidad POSIX debe crearse con modo `0600` y comprobarse después.
- `SEC-D-012`: las acciones administrativas deben auditarse.
- `SEC-D-013`: los valores de peers usados para ranking, viewer count y bitrate deben tener límites sanity-check.
- `SEC-D-014`: todo parser de red, metadatos, playlists y media se trata como superficie expuesta a input no confiable y debe tener fuzzing/fixtures negativas.
- `SEC-D-015`: endpoints que acepten URLs no podrán realizar SSRF contra loopback, link-local, metadata cloud o redes privadas fuera de allowlist.
- `SEC-D-016`: redirects y resolución DNS deberán revalidar el destino efectivo antes de conectar.
- `SEC-D-017`: el daemon impondrá límites de memoria, concurrencia y tiempo antes de reservar buffers declarados por un peer.
- `SEC-D-018`: FFmpeg y parsers auxiliares no heredarán secrets innecesarios, file descriptors administrativos ni acceso de escritura a configuración.
- `SEC-D-019`: los ficheros completados no serán ejecutados, previsualizados ni descomprimidos automáticamente por el daemon.
- `SEC-D-020`: los backups y crash dumps se consideran sensibles y tendrán los mismos controles de acceso que el estado.
- `SEC-D-021`: la rotación/eliminación de secretos debe invalidar sesiones y capability URLs derivadas.
- `SEC-D-022`: todas las dependencias HTTP deben limitar request line, headers, número de headers, body y conexiones keep-alive.

---

## 22. Recursos y límites configurables

### 22.1 Límites principales

El daemon debe permitir configurar:

- `max_connections`;
- `max_upload_slots`;
- `max_downloads_active`;
- `max_upload_kib` y `max_download_kib`;
- `max_searches_per_minute`;
- `max_live_viewers`;
- `max_broadcast_bitrate_kbps`;
- `max_buffer_segments`;
- `max_hls_disk_mb`;
- `max_log_size_mb`;
- `max_api_body_bytes`;
- `max_worker_threads`;
- `min_free_space_mb`;
- `memory_soft_limit_mb` y `memory_hard_limit_mb` si la plataforma lo permite.

También debe observar límites efectivos del entorno (`cgroup`, `RLIMIT_NOFILE`, cuota de disco y CPU asignada) en vez de asumir los recursos totales del host.

### 22.2 Degradación controlada

Cuando el recurso esté bajo:

1. no iniciar operaciones nuevas de baja prioridad;
2. reducir frecuencia de discovery y diagnósticos;
3. reducir conexiones o viewers nuevos;
4. reducir calidad Live si el operador lo permite;
5. preservar descargas y estado crítico;
6. informar por API, métricas y log;
7. no entrar en crash-loop.

### 22.3 Presupuesto de recursos de aceptación

Estos valores son objetivos iniciales que deben medirse en hardware real y revisarse si no son realistas:

| Perfil | RAM reposo daemon | CPU reposo | Disco temporal | Hardware de referencia |
|---|---:|---:|---:|---|
| lite | <150 MB | <10 % de 1 core | <100 MB salvo descargas | Pi 3 / mini-PC antiguo |
| standard | <250 MB | <15 % de 1 core | <512 MB | Pi 4/5 / NAS |
| live relay | <350 MB + buffer | dependiente de bitrate | configurable | Pi 4/5 o mini-PC |
| live encode | no fijar sin benchmark | hardware-dependent | configurable | mini-PC/encoder HW |

Los valores de CPU deben reportarse como metodología de medida, no como promesa independiente del kernel y del número de peers.

Requisitos adicionales:

- `RES-001`: hashing y reindexado deben tener límites de CPU/IO y pausarse bajo presión de reproducción Live.
- `RES-002`: el daemon debe calcular un máximo seguro de conexiones a partir de `RLIMIT_NOFILE` y reservar descriptores para logs, API y estado.
- `RES-003`: alcanzar un límite de file descriptors debe producir degradación y métrica, no un loop de accept fallido.
- `RES-004`: la memoria reportada en contenedor debe usar el límite cgroup efectivo cuando exista.
- `RES-005`: las métricas de consumo deben separar daemon, dashboard y FFmpeg cuando sea posible.
- `RES-006`: thermal throttling de Raspberry puede reportarse como warning si el sistema expone el dato, pero no es requisito para arrancar.
- `RES-007`: el escaneo inicial de shared no debe impedir health/live; readiness debe indicar `indexing` y progreso.

---

## 23. CLI del daemon

La CLI mínima debe incluir:

```text
ese-daemon --help
ese-daemon --version
ese-daemon --foreground
ese-daemon --config FILE
ese-daemon --check-config
ese-daemon --print-effective-config
ese-daemon --healthcheck live|ready
ese-daemon --selftest
ese-daemon --profile lite|standard|live
ese-daemon --overlay vps-safe
ese-daemon --api-port N
ese-daemon --tcp-port N
ese-daemon --udp-port N
ese-daemon --data-dir DIR
ese-daemon --log-level LEVEL
ese-daemon --check-state-migration
ese-daemon --backup DIR
ese-daemon --restore DIR --check
ese-daemon --clone-config DIR --regenerate-identity
ese-daemon auth init --output FILE
ese-daemon auth rotate --output FILE
ese-daemon auth revoke TOKEN_ID
```

Requisitos:

- `CLI-001`: `--help`, `--version`, `--check-config` no deben iniciar red de producción.
- `CLI-002`: los argumentos CLI deben aparecer en la configuración efectiva sin mostrar secretos.
- `CLI-003`: los errores de CLI deben devolver código 2.
- `CLI-004`: `--selftest` debe ser determinista y no contactar peers públicos por defecto.
- `CLI-005`: `--healthcheck live` debe medir liveness sin depender de Kad/HDD/Internet; `--healthcheck ready` aplica las condiciones de readiness del perfil.
- `CLI-006`: la CLI debe poder ejecutarse sin TTY.
- `CLI-007`: comandos destructivos o de restore exigirán confirmación explícita o flag no interactivo inequívoco; nunca asumirán “sí” por falta de TTY.
- `CLI-008`: `--backup` y `--restore` deben respetar locks y no operar concurrentemente con otro writer no coordinado.
- `CLI-009`: `--clone-config` debe indicar exactamente qué identidades y secretos regenera.
- `CLI-010`: los secretos no deben aceptarse como argumentos CLI salvo modo explícitamente documentado como inseguro para desarrollo.
- `CLI-011`: los comandos `auth` deben escribir el secreto directamente al destino `0600`; stdout mostrará solo token ID/fingerprint salvo `--show-once` local y explícito.
- `CLI-012`: `auth rotate/revoke` contra un daemon activo debe usar el control local autenticado o la API con credenciales; no editará el fichero por debajo del proceso.

---

## 24. Testing y gates de calidad

### 24.1 Niveles

| Nivel | Nombre | Alcance | Gate |
|---|---|---|---|
| T0 | Compile | CMake/MSBuild, targets y warnings | obligatorio por PR |
| T1 | Unit | parsers, paths, config, storage, timers, auth | obligatorio por PR |
| T2 | Component | API + engine mock, FFmpeg supervisor mock | obligatorio por módulo |
| T3 | Container | Docker, volúmenes, usuario, healthcheck | obligatorio por imagen |
| T4 | Two-node | Windows↔Linux y Linux↔Linux | obligatorio para wire |
| T5 | Hardware | Raspberry/NAS/mini-PC | obligatorio antes de release |
| T6 | Soak | 24 h mínimo, 7 días recomendado | release estable |
| T7 | Security | fuzz/parsers, auth, paths, process spawn | P0/P1 y release |
| T8 | Upgrade/restore | N-1→N, migración interrumpida, rollback y backup | release candidata |
| T9 | Performance | RAM, CPU, IO, API, hashing y bitrate por perfil | antes de fijar presupuestos |

### 24.2 Tests unitarios obligatorios

#### Configuración

- defaults;
- precedencia file/env/CLI;
- paths relativos;
- rutas inexistentes;
- permisos insuficientes;
- puertos inválidos;
- secret accidental en print-config;
- reload permitido/no permitido;
- versión y materialización de defaults de perfil;
- conflicto/orden de overlays;
- valores `disabled`, `auto`, `unlimited` y cero rechazado donde sea ambiguo.

#### Almacenamiento

- create/read/write/rename;
- `0600` de identidad;
- fichero truncado;
- fichero sobredimensionado;
- ENOSPC simulado;
- EROFS simulado;
- HDD missing;
- symlink/path traversal;
- reinicio con estado válido;
- lock single-writer y segundo proceso rechazado;
- rename atómico y finalización cross-filesystem;
- FAT32/NTFS/exFAT/NFS según la matriz declarada;
- backup/restore y migración interrumpida;
- biblioteca grande con hash cancelable/reanudable;
- UserHash, node key e instance ID estables tras reinicio/recreación;
- regeneración únicamente en clone/test explícito;
- colisiones Unicode/case-sensitive entre Linux y destinos Windows;
- agotamiento de inodos/cuota y fallo de preallocation sin pérdida de datos.

#### API

- error envelope;
- auth válida/inválida;
- rate limit;
- CORS;
- body demasiado grande;
- paginación;
- command queue;
- timeout;
- health durante startup/degraded/stopping;
- bootstrap por secret file sin token en logs/args;
- rotación, revocación y solapamiento de token;
- control local rechazado para UID no autorizado.

#### Protocolo

- vectores byte a byte;
- longitudes truncadas;
- tags desconocidos;
- capability gating;
- compatibilidad Live off/on;
- fragmentación y reassembly;
- bitmap y secuencias.

#### Proceso/FFmpeg

- args estructurados;
- paths con espacios y caracteres especiales;
- proceso que termina pronto;
- proceso que ignora SIGTERM;
- timeout y kill del process group;
- no afectar a otros PIDs.
- child sin secrets/fds heredados;
- fallo de spawn por permisos o binario incompatible.

### 24.3 Tests de integración Docker

Cada release de imagen debe verificar:

1. arranque con directorios vacíos;
2. generación de identidad;
3. persistencia de identidad tras recrear contenedor;
4. usuario no root;
5. volumen read-only de configuración cuando corresponda;
6. HDD de datos montado;
7. HDD ausente;
8. healthcheck startup→healthy;
9. SIGTERM y salida limpia;
10. reinicio por fallo;
11. API bind loopback/LAN;
12. puertos TCP y UDP;
13. imagen amd64;
14. imagen arm64;
15. dashboard opcional;
16. FFmpeg ausente en lite;
17. live desactivado;
18. logs stdout JSON;
19. dos contenedores apuntando al mismo volumen: solo uno adquiere el lock;
20. bind interno `0.0.0.0` + publicación host loopback funciona;
21. migración dry-run y rollback con snapshot;
22. imagen rootless con `cap_drop: ALL`;
23. liveness sigue correcta durante caída de Kad/HDD mientras readiness/status explican la degradación;
24. configuración inválida produce exit code permanente y diagnóstico visible durante crash loop;
25. arranque sobre un volumen con millones de archivos no ejecuta `chown -R` ni recorrido implícito completo;
26. auth bootstrap/rotación funciona con secret mount sin filtrar el bearer en inspect/logs;
27. wrapper/init propaga SIGTERM y el exit code exacto del daemon.

### 24.4 Tests de dos nodos

Matriz mínima:

| Nodo A | Nodo B | Comprobar |
|---|---|---|
| Windows eSE | Linux daemon | eD2K/Kad, identidad, Live |
| Linux daemon | Linux daemon | eD2K/Kad, discovery, Live |
| Windows vanilla | Linux daemon | compatibilidad eD2K/Kad clásico |
| aMule | Linux daemon | compatibilidad clásica, sin prometer Live |
| Docker amd64 | Raspberry ARM64 | mismo protocolo y API |
| Pi relay | PC broadcaster | relay/viewer sin encoder local |

### 24.5 Soak test

Duración:

- 24 h obligatorio antes de beta;
- 72 h recomendado para release candidata;
- 7 días recomendado antes de estable.

Medir:

- RSS inicial/final y máximo;
- file descriptors;
- threads;
- conexiones;
- bytes de red;
- errores API;
- reconnects;
- Kad contacts;
- espacio libre;
- corrupción de estado;
- zombies de FFmpeg;
- reinicios inesperados;
- latencia del API;
- pérdida de chunks Live.

Objetivos:

- crecimiento de RSS <5 % en 24 h sin cambio de carga;
- cero crash;
- cero zombie de child process;
- cero corrupción de identidad o preferencias;
- shutdown limpio;
- recuperación tras pérdida temporal de red;
- recuperación tras restaurar el HDD.

---

## 25. Criterios de aceptación del MVP

El MVP `ese-daemon 1.0-alpha` se considera aceptado si cumple todos los P0 siguientes:

### Instalación y ejecución

- [ ] `ese-daemon --help` funciona sin GUI.
- [ ] `ese-daemon --version` informa versión/commit/arquitectura.
- [ ] `ese-daemon --check-config` detecta configuración inválida sin iniciar producción.
- [ ] Arranca en Linux sin X11/Wayland.
- [ ] Arranca como usuario no root.
- [ ] Acepta SIGTERM y sale en menos de 15 segundos.

### Persistencia

- [ ] Genera identidad POSIX con permisos 0600.
- [ ] Conserva UserHash, node key e instance ID después de reinicio/recreación.
- [ ] Conserva preferencias y nodes en el volumen configurado.
- [ ] No guarda datos críticos únicamente en el filesystem efímero del contenedor.
- [ ] Rechaza una segunda instancia que apunte al mismo estado.
- [ ] Expone `config_schema_version`, `state_schema_version` y `profile_defaults_version`.
- [ ] Backup→restore conserva identidad y reanuda una descarga de prueba.

### Red

- [ ] Escucha TCP 4662 y UDP 4672 configurables.
- [ ] API loopback funciona en 4711.
- [ ] Health live/ready funciona.
- [ ] Una caída de Kad/Internet no falla liveness y aparece con reason code en status.
- [ ] Kad/eD2K se inicializan sin interfaz gráfica.
- [ ] Un cliente Windows eSE puede conectarse al daemon.

### HDD

- [ ] El HDD externo puede montarse como `/mnt/ese-data`.
- [ ] Las descargas se escriben en el directorio correcto.
- [ ] Los archivos completados se conservan tras reinicio.
- [ ] El daemon reporta falta de disco.
- [ ] La desconexión del HDD no provoca crash ni escritura silenciosa en una ruta equivocada.

### Administración

- [ ] Un navegador remoto puede consultar estado cuando LAN está activada.
- [ ] El acceso LAN requiere token.
- [ ] El token se puede preprovisionar o inicializar localmente sin aparecer en argumentos/logs.
- [ ] Se pueden consultar recursos y storage.
- [ ] Se puede pausar/reanudar una descarga.
- [ ] Se puede consultar log y diagnóstico.
- [ ] Existe OpenAPI versionada para `/api/v1`.
- [ ] Ningún endpoint nuevo mutante usa GET.
- [ ] Los listados grandes están paginados y los tamaños de 64 bits no pierden precisión.

### Docker

- [ ] La imagen arranca en amd64.
- [ ] La imagen arranca en arm64.
- [ ] Healthcheck funciona.
- [ ] El contenedor no necesita `--privileged`.
- [ ] Un volumen preserva identidad y estado.
- [ ] Funciona con usuario no root, `cap_drop: ALL` y `no-new-privileges`.
- [ ] El bind interno del contenedor y la publicación host loopback están probados.

### Live mínimo

- [ ] Live puede desactivarse.
- [ ] Sin FFmpeg, el daemon base sigue funcionando.
- [ ] Con FFmpeg disponible, el preflight informa capacidad.
- [ ] Un viewer puede unirse a una stream eSE compatible.
- [ ] La emisión no puede dejar FFmpeg huérfano.

---

## 26. Roadmap por fases

### F0 — Baseline y cierre del WIP

Objetivo: no iniciar la portabilidad sobre un árbol ambiguo.

Entregables:

- baseline Windows Release;
- baseline de protocolo y pcaps;
- inventario de cambios sin commit;
- lista de módulos portables/no portables;
- smoke test Live de referencia;
- decisión de formatos persistentes que el daemon debe leer;
- spike `ARCH-ADR-004` con identidad, scheduler, reactor y una ruta de red compilados fuera de MFC;
- informe comparativo suficiente para confirmar o reabrir `ARCH-ADR-001`, sin iniciar dos ports en paralelo.

Gate: build Windows, tests existentes y estado de trabajo revisado.

### F1 — Plataforma y contratos

Entregables:

- `IPlatform`;
- `IEngineSink`;
- `IEngineCommandQueue`;
- `INetworkReactor`;
- `IStateStore`;
- `PathProvider`;
- `Clock/Scheduler`;
- `IProcessSupervisor`;
- tests Linux sin MFC;
- backend de identidad POSIX consolidado;
- gate CI que impide dependencias MFC/Win32 en el core portable.

Gate: compilan los módulos puros en Linux y Windows.

### F2 — Headless Windows real

Entregables:

- `--headless` sin `CemuleDlg`;
- no GUI objects;
- scheduler propio;
- API y motor funcionando;
- `CGuiSink` mantiene la GUI normal;
- `--headless` conserva UserHash/Node ID; la identidad efímera queda restringida al modo de test explícito.

Gate: cliente Windows con GUI y modo daemon pasan la misma prueba eD2K/Kad.

### F3 — Daemon Linux x86_64

Entregables:

- CMake;
- `ese-daemon` sin MFC;
- API health/status;
- persistencia XDG;
- lock single-writer;
- config/state schema versionados;
- configuración externa;
- systemd;
- tests unitarios e integración local.

Gate: arranque Linux sin interfaz y comunicación con Windows eSE.

### F4 — Docker amd64/arm64

Entregables:

- Dockerfile multi-stage;
- imagen no-root;
- Compose;
- healthcheck;
- volúmenes;
- logs stdout;
- CI multiarch.
- SBOM y checksums de imagen;
- prueba de bind bridge y rootless sin capabilities.

Gate: ciclo completo de crear, reiniciar y recrear contenedor conservando identidad/estado.

### F5 — HDD y administración remota

Entregables:

- storage monitor;
- estados de disco;
- API de descargas/files/storage;
- auth LAN;
- dashboard remoto;
- path safety;
- pruebas de pérdida/restauración HDD.
- backup/restore consistente;
- finalización cross-filesystem;
- matriz ext4 y filesystems secundarios.

Gate: nodo administrable sin SSH en una LAN.

### F6 — LiveTV daemon

Entregables:

- Live core en daemon;
- viewer/relay;
- HLS;
- FFmpeg supervisor POSIX;
- RTMP opcional;
- preflight de recursos;
- malla Windows↔Linux.

Gate: broadcast en PC, recepción/relay en Linux y reproducción HLS.

### F7 — Low-resource hardening

Entregables:

- perfil lite medido;
- límites de RAM/CPU/conexiones;
- backpressure;
- 24/72 h soak;
- Pi/NAS reproducible;
- documentación de tuning.

Gate: ejecución estable en hardware de referencia.

### F8 — Release estable

Entregables:

- paquetes Linux;
- imágenes multiarch versionadas;
- upgrade/rollback;
- SBOM/licencias;
- corresponding source GPL de cada build distribuida;
- manual de operación;
- matriz de compatibilidad;
- checklist de release.

Gate: todos los requisitos P0, seguridad y soak verdes.

---

## 27. Descomposición para Spec-Driven Development

Cada bloque debe abrirse como una especificación pequeña, con sus propios tests.

### SPEC-DMD-001 — Lifecycle sin GUI

Debe cubrir `DMD-LIFE-001` a `DMD-LIFE-026`.

Escenario principal:

```gherkin
Given un sistema Linux sin DISPLAY ni sesión gráfica
And una configuración válida
When ejecuto ese-daemon --foreground
Then el proceso arranca sin crear ventanas
And expone /api/v1/health/live
And acepta SIGTERM
And termina limpiamente dentro del timeout configurado
```

### SPEC-PLAT-001 — Platform abstraction

Debe cubrir filesystem, clock, scheduler, process, signals, sockets y path provider.

### SPEC-ARCH-001 — Portability extraction and aMule decision gate

Debe cubrir `ARCH-ADR-*`, el spike portable de F0, el mapa de dependencias prohibidas y los criterios medibles para mantener o reabrir la decisión.

### SPEC-PROFILE-001 — Profiles, overlays and effective limits

Debe cubrir `PROF-*`, versionado de defaults, combinación de overlays, recursos ausentes y semántica inequívoca de límites.

### SPEC-STORE-001 — Persistent identity and storage

Debe cubrir `CFG-PATH-*`, `STO-DISK-*`, `COMP-ID-*` y compatibilidad/migración de identidad.

### SPEC-NET-001 — Portable eD2K/Kad sockets

Debe cubrir bind, connect, timeout, IPv4, IPv6 preparado y errores POSIX.

### SPEC-API-001 — Versioned control API

Debe cubrir error envelope, health, status, auth, commands y snapshots.

### SPEC-API-002 — Download/file administration

Debe cubrir descargas, files, shares, paginación, permisos y paths.

### SPEC-AUTH-001 — LAN authentication

Debe cubrir token, permisos, rate limits, auditoría, rotación y CORS.

### SPEC-DOC-001 — Docker image

Debe cubrir imagen, usuario, volúmenes, healthcheck, señales y multiarch.

### SPEC-HDD-001 — External storage resilience

Debe cubrir mount, missing, readonly, ENOSPC, unplug/replug y fallback.

### SPEC-LIVE-001 — Live core on daemon

Debe cubrir viewer, relay, chunk buffer, HLS y compatibilidad de wire.

### SPEC-MEDIA-001 — POSIX FFmpeg supervisor

Debe cubrir spawn seguro, process groups, timeout, cleanup y resource limits.

### SPEC-OBS-001 — Metrics and diagnostics

Debe cubrir logs, health, Prometheus, redaction y correlation IDs.

### SPEC-BACKUP-001 — Backup, restore and single-writer

Debe cubrir `STO-BACKUP-*`, locks, manifiesto de estado, quiesce y recuperación.

### SPEC-UPGRADE-001 — Schema migration and rollback

Debe cubrir `CFG-SCHEMA-*`, `UPG-*`, N-1→N, migración interrumpida y restore.

### SPEC-SUPPLY-001 — Reproducible release and licensing

Debe cubrir `SUPPLY-*`, SBOM, checksums, GPL corresponding source y variante FFmpeg.

### SPEC-PERF-001 — Low-resource budgets

Debe cubrir `RES-*`, metodología de benchmark, cgroups, hashing y gates por perfil.

### SPEC-TEST-001 — Cross-platform and soak matrix

Debe convertir la matriz de este documento en jobs reproducibles de CI/hardware.

---

## 28. Definition of Done por feature

Una feature del daemon solo está terminada cuando:

- [ ] tiene requisitos con IDs;
- [ ] se conoce si es P0/P1/P2;
- [ ] se identificaron dependencias y riesgos;
- [ ] existe diseño de interfaz o contrato;
- [ ] existe test de fallo, no solo happy path;
- [ ] no introduce dependencias MFC en core portable;
- [ ] no cambia el wire format sin capability gate y fixtures;
- [ ] no cambia formatos persistentes sin migración/rollback;
- [ ] actualiza configuración de ejemplo;
- [ ] actualiza API o documentación si corresponde;
- [ ] actualiza OpenAPI y sus tests de contrato si toca `/api/v1`;
- [ ] pasa build Linux y Windows afectado;
- [ ] pasa sanitizers o equivalente para código nuevo relevante;
- [ ] tiene evidencia de Docker o hardware si toca despliegue;
- [ ] los logs y métricas permiten diagnosticar un fallo;
- [ ] el PR referencia los IDs de requisitos;
- [ ] el cambio no deja procesos hijos o timers huérfanos;
- [ ] el cambio queda cubierto por el release checklist.
- [ ] una dependencia nueva tiene versión, licencia, origen y entrada de SBOM.

---

## 29. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Acoplamiento MFC profundo | alto | `IEngineSink`, migración incremental y build target puro |
| Divergencia Windows/Linux | alto | tests de wire y escenarios cross-platform |
| Diferencias de sockets POSIX/Windows | alto | wrapper de plataforma y tests de timeout/bind |
| Falsa portabilidad de `CAsyncSocketEx` | alto | tratarlo como backend Windows y crear `INetworkReactor` portable |
| Abrir un fork de aMule antes de estabilizar contratos | alto | `ARCH-ADR-*`, un solo source of truth y aMule como oracle de interoperabilidad |
| HDD desconectado | alto | storage state machine, no fallback silencioso |
| FFmpeg pesado en Pi | medio/alto | perfiles, preflight, relay sin encoder |
| Node consume demasiada RAM | medio | dashboard opcional y daemon API-only |
| Multicast Docker complejo | medio | discovery opcional y modo host documentado |
| API expuesta sin auth | alto | loopback default, token obligatorio en LAN, tests de auth |
| corrupción por crash | alto | writes atómicas, backups y soak tests |
| cambios de protocolo | alto | capability gates, pcap diff, compatibilidad vanilla |
| identidad duplicada en clones Docker | alto | documentación de volúmenes y warning de clone |
| dos writers sobre el mismo volumen | crítico | lock de kernel, manifest y test con dos contenedores |
| migración irreversible | alto | dry-run, snapshot previo, journal y restore probado |
| filesystem con semántica distinta | alto | matriz explícita y ext4 como referencia P0 |
| supply chain/licencias incompletas | alto | SBOM, checksums, corresponding source y gate de release |
| bloqueo del operador en un equipo sin UI | alto | bootstrap local/secret mount, rotación probada y recuperación documentada |
| cambio silencioso de defaults al actualizar | medio/alto | `profile_defaults_version`, preview y origen de cada valor |
| arranque que recorre/chown un HDD enorme | medio/alto | validación puntual, indexing incremental y preparación explícita de permisos |
| crash loop por error permanente | medio | exit codes, `RestartPreventExitStatus`, rate limit y runbook Docker |
| Build ARM lento/inestable | medio | cross-compile desde amd64 + smoke en hardware |
| LowID/CGNAT | alto para utilidad remota | conservar Track R y diagnóstico de reachability |
| exceso de alcance | alto | fases separadas y perfil lite antes de Live completo |

---

## 30. Decisiones pendientes

Estas decisiones deben resolverse antes de congelar el contrato de la primera implementación:

| ID | Decisión pendiente | Límite |
|---|---|---|
| `DEC-001` | ¿La API pública estable será 4711 o se expondrá 8080 como gateway único? | SPEC-API-001/F3 |
| `DEC-002` | ¿`ese-web` se distribuye en imagen principal, imagen separada y/o paquete estático? | SPEC-DOC-001/F4 |
| `DEC-003` | ¿ARMv7 entra en beta o se limita oficialmente a ARM64? | antes de publicar matriz multiarch |
| `DEC-004` | ¿Se mantienen los formatos de preferencias actuales o se define `ese.conf` nuevo con migrador? | SPEC-STORE-001/F3 |
| `DEC-005` | ¿Qué operaciones de descarga son P0 en la primera API? | SPEC-API-002 |
| `DEC-006` | ¿Se implementan roles desde el principio o un único token administrador? | SPEC-AUTH-001 |
| `DEC-007` | ¿HLS se sirve siempre desde el daemon C++ o puede delegarse al dashboard? | SPEC-LIVE-001/F6 |
| `DEC-008` | ¿Qué variante/licencia de FFmpeg se empaqueta y cuál se instala desde la distribución? | SPEC-MEDIA-001/F6 |
| `DEC-009` | ¿Se usa SQLite para el índice administrativo o las estructuras eMule actuales? | SPEC-STORE-001/F3 |
| `DEC-010` | ¿Cuál es la matriz oficial de Raspberry Pi, RAM y kernel? | SPEC-PERF-001/F7 |
| `DEC-011` | ¿UPnP entra en P0, P1 o queda como componente opcional? | SPEC-NET-001/F5 |
| `DEC-012` | ¿Qué compatibilidad N-1 concreta se garantiza al actualizar una instancia Docker? | SPEC-UPGRADE-001/F4 |
| `DEC-013` | ¿Qué política se aplica a links Live anónimos cuando API/HLS se publican en LAN? | SPEC-AUTH-001/F6 |
| `DEC-014` | ¿Qué métricas son API pública estable y cuáles internas? | SPEC-OBS-001/F3 |
| `DEC-015` | ¿Cuál es la distribución, glibc, GCC y Clang mínimos para binarios nativos? | antes de beta Linux |
| `DEC-016` | ¿Qué filesystems pasan de experimental a soportado además de ext4? | SPEC-HDD-001/F5 |
| `DEC-017` | ¿Qué mecanismo implementa snapshots consistentes sin pausar demasiado el motor? | SPEC-BACKUP-001/F5 |
| `DEC-018` | ¿Las métricas usan el listener API o uno separado por defecto? | SPEC-OBS-001/F3 |
| `DEC-019` | ¿Cuál es el periodo de soporte N-1 para config/state schemas y API? | SPEC-UPGRADE-001/F8 |
| `DEC-020` | ¿Una UI estática mínima sin Node entra en P1 o la administración lite queda API/CLI + `ese-web` remoto? | SPEC-PROFILE-001/F4 |
| `DEC-021` | ¿El control local usa Unix socket propio, HTTP loopback o ambos? | SPEC-AUTH-001/F3 |
| `DEC-022` | ¿Los defaults numéricos propuestos de perfiles superan benchmarks Pi/mini-PC o deben revisarse? | SPEC-PERF-001 antes de beta |

---

## 31. Checklist de revisión arquitectónica

Antes de aprobar una implementación relacionada con el daemon, el revisor debe poder responder “sí” a estas preguntas:

- [ ] ¿Puede compilarse sin MFC si pertenece al core portable?
- [ ] ¿Tiene un ownership de threads y shutdown claro?
- [ ] ¿Puede bloquear por disco, red o child process?
- [ ] ¿Qué pasa si el HDD desaparece?
- [ ] ¿Qué pasa si Kad no conecta?
- [ ] ¿Qué pasa si la API recibe 100 peticiones simultáneas?
- [ ] ¿Qué pasa si FFmpeg termina instantáneamente?
- [ ] ¿Qué pasa si el contenedor se recrea?
- [ ] ¿Qué pasa si se clona el volumen de identidad?
- [ ] ¿Qué pasa si dos instancias montan el mismo volumen?
- [ ] ¿Qué pasa si el proceso recibe SIGTERM durante una escritura?
- [ ] ¿Está protegido el endpoint desde LAN?
- [ ] ¿Se ha medido el uso de memoria?
- [ ] ¿Se conserva la compatibilidad Windows↔Linux?
- [ ] ¿Se ha añadido test a la matriz correcta?
- [ ] ¿Se han actualizado logs, métricas y documentación?
- [ ] ¿Se puede hacer backup/restore y rollback de este cambio?
- [ ] ¿Se respetan OpenAPI, semántica HTTP e idempotencia?
- [ ] ¿La dependencia/licencia/SBOM de cualquier componente nuevo está resuelta?

---

## 32. Conclusión normativa

El producto objetivo no es “eMule con una ventana escondida”. Es un **nodo eMule/eSE portable y operable**, con:

- motor independiente de GUI;
- almacenamiento configurable y resistente a HDD externo;
- API estable y autenticada;
- dashboard opcional;
- Docker multi-arquitectura;
- despliegue VPS mediante overlay `vps-safe`;
- soporte Linux/ARM64;
- perfiles de consumo;
- LiveTV desacoplado del núcleo de descargas;
- observabilidad y operación 24/7;
- compatibilidad de protocolo con Windows eSE y clientes clásicos.

La estrategia recomendada es mantener eMule-eSE como fuente de verdad, extraer primero el core portable y añadir `ese-daemon` como target paralelo. El port a aMule puede estudiarse posteriormente como backend alternativo, pero no debe bloquear ni sustituir esta ruta.
