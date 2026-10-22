# Rediseño y auditoría UX UI de eSE

11 de octubre de 2026

## Actualización: estructura y E2E de la web

La segunda revisión fusiona Archivos, Guardados y Descargas en Biblioteca; unifica la búsqueda en `/search`; mantiene Explorar como descubrimiento; consolida las rutas de conexión y añade una página 404 recuperable. Inicio muestra un resumen, Ajustes es un diálogo accesible desde todas las páginas y las herramientas técnicas Live quedan plegadas.

Se han recorrido las páginas en un navegador real con un host aislado que usa los renderizadores de producción y FFmpeg real para vídeos sintéticos. Catálogo, acciones de descarga y conexión Live utilizan respuestas simuladas identificadas. Los resultados, capturas, límites y decisiones están en [el informe E2E](../artifacts/ese-e2e-2026-10-11/e2e-report.md) y [el mapa de páginas](../artifacts/ese-e2e-2026-10-11/architecture-review.md). La suite vigente se registra en `artifacts/ese-e2e-2026-10-11/test-results.tap`.

El usuario abrió después el ejecutable de la vista previa en el puerto 8091. Se recuperó su conexión con eMule y se verificaron Inicio, Ajustes, la ficha del catálogo y reproducción, pausa y cierre de un archivo local real. La incidencia y el parche posterior de autenticación constan en [el informe de conexión](../artifacts/ese-connection-2026-10-11/connection-report.md). La instalación principal de `C:\tmp\emule-rc2` no se sustituyó. No se certifican emisiones Kad, vinculación entre dispositivos ni seek sobre archivos incompletos `.part`. Las cifras y hallazgos de las secciones siguientes son registros de fases anteriores; no describen el estado final de esta revisión.

## Registro de la primera ronda de correcciones

La interfaz diferencia catálogo, biblioteca local y títulos guardados. Después de la auditoría se han implementado correcciones en el reproductor, las fichas, los favoritos, las descargas y Live TV. Los hallazgos originales se conservan más abajo como registro; su estado posterior se detalla en esta sección.

La auditoría combina inspección visual del rediseño, revisión heurística y reproducciones aisladas de JavaScript; no es un estudio con usuarios ni una certificación de accesibilidad. Las correcciones posteriores se validaron con pruebas automatizadas y consultas reales de metadatos. La validación visual del ejecutable corregido sigue pendiente: la revisión automática rechazó tanto sustituir el servidor activo como arrancar una instancia separada, sin proporcionar un motivo adicional. No se sustituyó la instalación abierta en `C:\tmp\emule-rc2`.

## Seguimiento de las correcciones

| Hallazgo | Corrección y evidencia posterior |
| --- | --- |
| Reintentos y respuestas de otro vídeo | Sesiones independientes, abortado de consultas, cancelación de temporizadores y listeners del vídeo y MSE. Pruebas con A→B, cambio de calidad y lecturas pendientes. También se invalida la fuente anterior al elegir otra dentro del mismo modal. |
| Fichas y selección inferior no disponibles | Búsqueda y detalle consultan TMDB con plazo máximo y errores recuperables; IDs canónicos para películas y series, y resolución de favoritos IMDb existentes. Consultas reales de búsqueda, ficha y temporada confirmadas. |
| Volver deja un modal vacío o no detiene el vídeo | Cierre cuando no existe una ficha previa, parada independiente del almacenamiento y salida funcional desde errores. Navegar no envía ya una limpieza global que pueda afectar a otro reproductor. |
| Reanudar borra la posición | La posición se pasa directamente a la sesión y no se guarda un cero antes de confirmar reproducción. Prueba de la posición guardada en 125 segundos. |
| Favoritos corruptos o sin espacio | Validación de lista y elementos; conservación del almacenamiento si está dañado; errores visibles de lectura/escritura; el botón sólo cambia tras una escritura correcta. |
| Controles de reproducción inaccesibles | Nombres de botones y selectores, estados de volumen/reproducción, slider con flechas, Inicio/Fin y avance de un minuto. Probado con DOM simulado; lector de pantalla real pendiente. |
| Duración y episodios inventados | Duración desconocida si no hay información; sin valor fijo de dos horas. Temporadas y capítulos cargados del catálogo, con recuperación de errores y protección frente a cambios rápidos. |
| Descargas sin datos de progreso y control | Parser del formato nativo `.part.met` e0/e2: hash, tamaño total y bytes recibidos calculados con los intervalos faltantes. Un archivo preasignado no implica descarga completa. Formatos desconocidos dejan progreso/control indisponibles. Error de carpeta devuelve HTTP 503 en vez de lista vacía. |
| Filtros Live ignorados por Kad | Normalización, deduplicación, filtrado y orden sobre el conjunto final de canales. Pruebas sobre consulta, idioma, categoría, calidad y valoración. |
| Monitor Live antiguo | Última actualización, indicadores desactualizados/no disponibles, recuperación y rechazo de respuestas anteriores. Sin emisiones reales durante estas pruebas. |
| Catálogo demasiado alto en móvil | A 760/400 px se compactan encabezados y búsqueda; los géneros ocupan varias filas sin desplazamiento interno ni opciones ocultas. Áreas táctiles de 44 px. Comprobación visual del paquete pendiente. |

La batería final suma **107 pruebas superadas**, registradas en `artifacts/ese-ux-ui-2026-10-11/fixes-test-results.tap`. Se actualizó una expectativa antigua de la prueba C++ para aceptar el modo de autoprueba adicional que ya existía; no se modificó el núcleo C++.

El ejecutable está sincronizado en `eSE-Package` y `srchybrid/x64/Release`. El script `tools/sync_ese_package.ps1 -WebOnly` sincroniza y verifica la web sin copiar `emule.exe`. El ZIP de actualización y un lanzador local en el puerto 8091 permiten probar la nueva web con el eMule existente. La prueba usa configuración, PID y temporales propios, con descubrimiento y tareas de fondo desactivados.

## Referencias aplicadas

| Referencia | Aplicación en eSE |
| --- | --- |
| [Mobbin](https://mobbin.com/) y [Refero](https://refero.design/apps) | Patrones de catálogo, navegación por tarjetas, búsqueda explícita y estados diferenciados. Se utilizaron como bibliotecas de referencia, sin copiar una interfaz concreta ni asumir acceso a sus colecciones de pago. |
| [Refactoring UI](https://refactoringui.com/) | Jerarquía entre título, sinopsis, metadatos y acciones; espaciado consistente; una acción principal por grupo; tratamiento uniforme de tarjetas sin imagen. |
| [Nielsen Norman Group](https://www.nngroup.com/articles/ten-usability-heuristics/) | Visibilidad del estado, lenguaje comprensible, control del usuario, consistencia y recuperación de errores. Base para las prioridades de esta auditoría. |

## Cambios implementados

- **Inicio:** el destacado adapta su altura al contenido y deja de recortar los metadatos. «Ver ficha» tiene mayor jerarquía que «Buscar fuentes». Conserva navegación manual y adaptación móvil.
- **Biblioteca:** buscador local por título o nombre de archivo, tolerante a acentos, contador de resultados y estado vacío con acción para limpiar. Los títulos ocupan hasta dos líneas; los episodios conservan temporada y capítulo; las tarjetas sin cartel identifican el archivo local.
- **Identificación:** las películas se asocian mediante coincidencia de título y año, cuando existe, rechazando resultados ambiguos. Los episodios ya no se consultan como películas. Una identificación incierta conserva el nombre local; queda pendiente un catálogo específico de series y una corrección manual de metadatos.
- **Catálogo:** encabezados y tarjetas comunes, indicación de disponibilidad, filtros por contenido y género, controles visibles de carrusel con límites y alternativas si falla un cartel. «Animación» sustituye una etiqueta que sugería erróneamente contenido infantil.
- **Búsqueda:** botón explícito, filtros reales Todos/Películas/Series y resumen que explica el alcance de la primera página. Consulta y filtros se conservan en la URL.
- **Fichas:** estado de carga legible, error con reintento y salida, descarte de respuestas antiguas y conservación de la acción local cuando falla la información. Cerrar vuelve a la búsqueda o categoría de origen mediante destinos locales validados.
- **Mi Lista:** diferencia guardado y descarga, explica que los favoritos pertenecen a este navegador y permite deshacer una eliminación.
- **Seguir viendo:** tarjeta dentro de la página; no tapa el catálogo ni elimina el historial por una consulta fallida. La espera de metadatos queda ligada al modal abierto. El motor todavía tiene la limitación de posición descrita abajo.
- **Live TV:** canales como enlaces nativos, filtros etiquetados, foco conservado durante refrescos, respuesta más reciente como válida y estados de error con reintento.

## Auditoría inicial — registro anterior a las correcciones

P1: puede alterar o bloquear la tarea principal y debe atenderse primero. P2: perjuicio funcional o de accesibilidad relevante. P3: mejora de claridad o eficiencia. Los casos marcados «aislado» utilizan objetos y almacenamiento simulados; no reproducen una emisión ni modifican datos reales.

| Prioridad | Hallazgo y evidencia | Cambio recomendado |
| --- | --- | --- |
| **P1** | **Un reintento de A puede interferir con el vídeo B.** `cinema_player.js:496` conserva un temporizador que escribe en el `video` global. A falla, se cierra, se abre B y el temporizador de A cambia su fuente. Confirmado en ejecución aislada. Afecta al control del usuario. | Cancelar temporizadores al cerrar/cambiar y comprobar la identidad del vídeo y de la sesión antes de cada reintento. |
| **P1 en el entorno comprobado** | **La búsqueda muestra títulos cuya ficha no carga.** En navegador: buscar Dune, abrir Dune Parte dos → error recuperable. La selección inferior del inicio también falla. Catálogo TMDB operativo y servicio de ficha consultado a través del servidor instalado; la causa de este servicio no se ha aislado. | Comprobar configuración y respuesta del servicio de metadatos en el paquete definitivo; ofrecer ficha básica con datos del catálogo cuando falle el proveedor secundario. El diseño de recuperación ya está implementado. |
| **P2** | **«Volver» puede dejar una pantalla vacía o abortarse.** `cinema_player.js:311` muestra una zona de ficha vacía en reproducciones rápidas; un `ese_resume` corrupto interrumpe el cierre antes de pausar. El botón del error en `:521` sólo oculta el reproductor. Confirmado en ejecución aislada. | Cerrar el modal cuando no hay ficha previa y aislar cualquier fallo de almacenamiento de la navegación. |
| **P2** | **Continuar puede perder la posición al fallar la carga.** `cinema_player.js:63` guarda posición cero antes de recibir metadatos. Confirmado en ejecución aislada con una sesión guardada en 125 segundos. | Mantener la posición pendiente hasta confirmar reproducción o un avance real. |
| **P2** | **Los helpers de favoritos aún aceptan datos dañados.** `init.js:219` puede devolver un objeto y `isInMyList` ejecuta `.some`; un error de escritura tampoco se comunica. Confirmado con datos simulados. La página Mi Lista sí maneja su propio error de lectura. | Validar estructura y elementos en el helper compartido; conservar la ficha y explicar cuando no se puede guardar. |
| **P2** | **El reproductor no está completamente disponible mediante teclado o lector.** `cinema_player.js:24`, `:32` y `:102`: progreso basado en clic, botón de volumen sin nombre y controles sin etiquetas asociadas. Evidencia de código, sin prueba con lector real. | Añadir nombres y estados, slider de progreso operable por teclado y etiquetas para calidad, audio y subtítulos. |
| **P2** | **Hay datos presentados como ciertos sin verificarlos.** `cinema_player.js:150` supone 7200 segundos; `search_ui.js:286` supone 15 temporadas cuando faltan y ofrece 30 capítulos por temporada. Evidencia de código. | Mostrar duración desconocida; cargar episodios reales o distinguir expresamente una selección manual no verificada. |
| **P2** | **Las descargas no permiten conocer avance ni gestionar todos los archivos.** En navegador aparecen progreso no disponible y acciones deshabilitadas. `routes/emule_routes.js:190` devuelve tamaño parcial sin total ni identificador de control. | Obtener los datos canónicos de eMule y distinguir error de consulta de lista vacía. La UI ya evita inventar porcentajes. |
| **P2** | **Los filtros Live pueden ser ignorados por resultados Kad.** `eSE-live/channel_api.js:943` aplica filtros a resultados locales antes de incorporar resultados Kad. Evidencia de código; no validado con emisiones reales. | Aplicar el mismo filtro al conjunto final de canales. |
| **P3** | **El diagnóstico Live puede mostrar información antigua.** `eSE-live/live_tv_page.js:307` conserva información del monitor tras errores. Evidencia de código; afecta al panel técnico. | Mostrar última actualización y marcar datos desactualizados al perder conexión. |
| **P3** | **En móvil estrecho los controles de catálogo ocupan mucho espacio.** Observado a 320 y 390 px: encabezado, acceso a biblioteca, nota y filtros desplazan la primera fila; a 320 px hay desplazamiento horizontal dentro del grupo de filtros. La página no desborda horizontalmente. | Compactar el encabezado móvil y estudiar un desplegable de géneros, comprobándolo con usuarios antes de ocultar opciones habituales. |

## Validación inicial — registro histórico

La suite completa devuelve **68 pruebas: 67 correctas y 1 fallo**. Las 15 pruebas añadidas en esta fase pasan. El fallo de `test/live_tv_regression.test.js:686` exige una expresión concreta del retorno de `--selftest` en `srchybrid/Emule.cpp`; ya estaba presente en la revisión anterior y no se ha modificado ese archivo. Tras el último ajuste de tarjetas se repitieron las 12 pruebas relacionadas, todas correctas.

Pruebas funcionales: búsqueda local, coincidencia de metadatos, exclusión de episodios en búsquedas de películas, destinos de retorno seguros, cierre y foco de diálogos, respuestas tardías, errores de almacenamiento al cerrar, historial ante fallos de biblioteca, canales con teclado y refrescos que preservan foco.

Comprobación visual: inicio en escritorio de 1280 px y móvil de 390 px; búsqueda, Explorar, Mi Lista y Live entre 320 y 390 px. En las pantallas medidas, el ancho de documento coincide con el disponible y no hay desbordamiento horizontal de página. Los carruseles conservan su desplazamiento interno. Se verificó el regreso mediante Escape de una ficha fallida a `/search?q=Dune`, con la consulta restaurada.

La vista previa es de lectura: biblioteca real mediante el servidor instalado, catálogo mediante la configuración fuente y operaciones de reproducción, descarga, emisión y vinculación bloqueadas. Por ello, **queda pendiente la prueba integral de reproducción sobre el paquete compilado**, además de lector de pantalla, zoom y pruebas con usuarios. El estado de seguridad remota de la auditoría anterior no se reevalúa aquí.

## Evidencia y orden de trabajo iniciales — registro histórico

Capturas y resultado de pruebas: `artifacts/ese-ux-ui-2026-10-11/`. El script `audit-repro.js` de esa carpeta reproduce cinco hallazgos con objetos en memoria, sin red ni cambios en los datos del usuario. Ejecutado desde la raíz con `node artifacts/ese-ux-ui-2026-10-11/audit-repro.js`; `CONFIRMED` significa problema pendiente reproducido, no prueba de aceptación superada.

![Inicio en escritorio](C:/Users/iunan/OneDrive/Desktop/eMule0.70b-Sources/artifacts/ese-ux-ui-2026-10-11/inicio-escritorio.jpg)

Primero resolver los reintentos de reproducción y el servicio de fichas; después continuidad, cierre y accesibilidad del reproductor. A continuación, unificar favoritos y datos reales de series/descargas. La siguiente validación debe recorrer buscar → abrir ficha → reproducir → salir → continuar, también con fallo de red y sólo teclado.

Para repetir la vista previa desde `srchybrid/eSE`: `node tools/bundle_client.js` y `node tools/preview_web.js`. Abre `http://127.0.0.1:8091`; el servidor instalado en 8080 aporta las consultas locales permitidas. Ejecuta `npm test` para la suite.
