# Roadmap de releases eMule eSE 9.3 a 9.8

La **v9.3 sale primero con QUIC seguro y compatible**. La **v9.4 se centra en
encontrar y ver directos fiables**. El resto del trabajo conserva sus contratos
y destino, pero deja de bloquear esas dos entregas. D21 sustituye la exigencia
de D14 de publicar todo A–F en v9.3. No hay cambios en 9.0–9.2.

Este roadmap manda sobre **qué versión entrega cada cosa y qué bloquea su
publicación**. El [plan técnico](V9.3_PLUS_RELEASE_TRAIN.md) y la
[especificación](V9.3_IMPLEMENTATION_SPECIFICATION.md) conservan el diseño,
los IDs y los oráculos. El [registro de ejecución](V9.3_EXECUTION_STATE.md)
dice qué se ha probado. Esta partición no implementa, cierra ni publica nada.

| Versión | Qué ofrece | Bloques asignados |
| --- | --- | --- |
| **9.3** | Transferencias eSE por QUIC fiables, con recuperación y compatibilidad clásica. | V93-00, A1, A2 para rutas activas, C1/C2 para QUIC entre peers, seguridad de C3, mínimos de datos y producto de E/F, y R1 acotado. |
| **9.4** | LiveTV privado fiable: buscar un directo desde eSE y verlo sin cambiar de pestaña. | Plan LiveTV de §11, LT94-01…07 y las tres mejoras generales detrás del hito de LiveTV. |
| **9.5** | Motor y escritorio más sólidos para bibliotecas y colas grandes. | Resto de E1/E2 y F1/F2. Mejoras de protección local y de búsqueda de C3 que no sean necesarias para rutas ya expuestas. |
| **9.6** | Encontrar fuentes y conectar directamente por Kad6 sin servidor fijo. | B1; resto de A2 y C3 vinculado a Kad6, alcance directo e interoperabilidad peer; casos compartidos B1/C2. |
| **9.7** | Interoperar con servidores sin depender de sus operadores para desarrollar ni validar. | D1/D2 y la parte de C3 de los protocolos de servidor. |
| **9.8** | Laboratorio opcional de rutas difíciles y continuidad. | Birthday y DVL de B2, si el diferencial justifica publicarlos; desactivados por defecto. |

## v9.3 — Publicación corta de QUIC

1. **Reconciliar primero la base.** Comparar con la rc.2 publicada en copia
   aislada; conservar sus funcionalidades, autenticación web y perfiles.
   Fijar el SHA integrado, compilar x64/Win32 y probar arranque/cierre, web
   y el par pequeño/F2. Aislar la lentitud de C2 con la cadencia del producto.
   Usar [§4.1–4.2 del plan](V9.3_PLUS_RELEASE_TRAIN.md#41-reconciliación-temprana-con-la-rc2-publicada).
2. **Cerrar el recorrido principal.** Dos equipos eSE propios transfieren
   F1 (1 GiB) por QUIC en cada sentido con hash correcto. Cubrir bloqueo UDP
   al inicio y atasco con control vivo tras conectar (`NC-Q05/06`): recuperar
   si hay ruta autorizada, cancelar el perdedor, no duplicar sesión, slot o
   crédito; si no hay ruta, terminar con motivo. Comprobar que un cambio de
   red no vuelve a usar eventos de una generación anterior. No prometer
   continuidad por rutas o perfiles no probados. Mantener los negativos de
   pausa, integridad y autenticación de las rutas que se habiliten.
3. **Conservar lo clásico y los datos.** Control con eMule clásico sin
   modificar y versión anterior de eSE: Kad2/TCP, búsqueda, transferencia
   y callback en los perfiles aplicables; no emitir extensiones sin
   negociación ni anunciar accesibilidad ficticia. Endurecer los parsers
   expuestos (incluidos los límites MD4/AICH), resolver conflictos de
   namespace antes de emitir, preservar las garantías de privacidad actuales
   y corregir P0 aplicables. Probar guardado y recuperación de `.part.met`,
   configuración y perfiles que se toquen, incluyendo fallo de reemplazo y
   rollback. KRP/R.3 quedan fuera del build y sus valores no se reutilizan
   (`NC-B08`); se conserva la prohibición de relé de datos.
4. **Empaquetar y probar el candidato real.** Paquetes x64/Win32
   reproducibles, dependencias QUIC con procedencia apta para release,
   arranque, actualización y cierre. Hacer una campaña conjunta y repetir
   las regresiones afectadas por correcciones. Conservar `H93-16` y los
   casos físicos aplicables agrupados con esa sesión. Si persiste la
   lentitud intermitente o hay fugas, ejecutar la prueba focalizada capaz de
   detectarlas antes de cerrar; no imponer 24 h universales ni repetir todos
   los ensayos históricos por cada candidato.

No bloquean la RC de v9.3: LiveTV nuevo, Kad6-only con colaboradores
avanzados, Birthday, DVL, D1/D2, la paridad completa E/F ni matrices contra
mods/operadores externos. Una ruta aplazada no se enciende ni se anuncia
como validada. No se quitan protecciones ni rutas ya soportadas de la base
publicada. Los dos procesos del mismo equipo sirven para iterar, no para
acreditar el recorrido entre equipos o NAT. La lista de salida se aplica en
[§17 del plan](V9.3_PLUS_RELEASE_TRAIN.md#17-salida-de-v93-y-validación-proporcional).

## v9.4 — LiveTV privado, buscar y ver

- **Primero estabilidad:** el directo aparece pronto, muestra imagen,
  reproduce con continuidad, se recupera ante un corte con ruta viable y
  desaparece al terminar o caducar. Comparar en condiciones iguales arranque,
  tiempo congelado, recuperación y retirada; probar entre dos equipos y en
  móvil sin debilitar el modo privado.
- **Después el recorrido principal (`LT94-07`):** buscar «Real Madrid» en
  el buscador general de eSE, encontrar una emisión disponible y pulsar
  «Ver en directo». Reutilizar el directorio y el reproductor, respetar
  autorización y no iniciar reproducción al buscar. Incluye un negativo
  sin coincidencias o con el directo ya terminado.
- **Completar el [plan LiveTV de §11](V9.3_PLUS_RELEASE_TRAIN.md#11-lo-que-queda-fuera-de-la-93):**
  túnel autenticado y privacidad, canales, Swarm DVR, visor móvil y
  LT94-01…06 (arranque/zapeo, reanudación, canal de prueba, ensayo,
  invitaciones y grabación local). No espera a Punch3, Birthday ni D1/D2.
  Mover descargas incompletas entre discos, seguir colecciones y modo
  doméstico sin ventana quedan en 9.4 **detrás de LiveTV**, sin bloquear su
  entrega; el traslado reutiliza los contratos de persistencia que necesite.

## v9.5 — Motor, biblioteca y escritorio

- **Motor primero (E1/E2 restantes):** validar endgame con varias fuentes,
  hash en segundo plano y memoria AICH, tareas cancelables, watcher,
  recarga, publicación incremental, cachés, persistencia ampliada y
  Download Validator en modo aviso. Reusar las correcciones mínimas de 9.3.
- **Producto después (F1/F2 restantes):** listas virtuales, búsqueda,
  operaciones masivas, redacción, accesibilidad, idiomas y perfiles
  portable/AppData y Wine/Docker según contrato. E precede al bulk de F;
  lo independiente puede avanzar antes. Completar protección, filtros y
  consenso de nombres de C3 que no dependen de nuevas rutas.
- **Cierre:** corpus `EP-*` aplicable, endgame sin doble contabilidad, carga
  10k/100k/500k donde esté especificada, cancelación y rollback, prueba básica de UI
  y accesibilidad. Mantener por separado la evidencia nativa y la de Wine.

## v9.6 — Kad6 directo y compatibilidad entre peers

- Completar A2/B1 y C3 peer: índice directo, encuentro sin servidor fijo,
  colaboradores voluntarios sustituibles, Punch3, predicción acotada,
  witnesses, coexistencia Kad2 y receptores antes de emitir. Afinar los
  perfiles de movilidad/interop que no se habilitaron en 9.3.
- **Cierre:** `NC-KD01…08` (también los compartidos con C2), contratos
  `NC-B01…04/09` y `NC-BC*` aplicables. Dos equipos en redes propias,
  traspaso de colaborador, hash correcto y cero payload de archivo en
  intermediarios. Si no hay ruta, terminal honesto, nunca un relé oculto.

## v9.7 — Servidor propio de referencia e interoperabilidad

- **D1 (`V98-F01…F04/F07`):** especificar y probar en nuestro servidor
  local login/fuentes/callback IPv6, callback entre servidores, vouchers y
  RendezvousV2. Incluye TLS y autenticación mínimos; no enviar extensiones
  antes de validar sus receptores de C3.
- **D2 (`V98-F05/F06`):** completar TLS/QUIC cliente-servidor, progreso por
  operación, fallback y recuperación sin doble login ni doble publicación.
- **Cierre:** `DS-*` aplicables con ambos extremos propios, casos de replay,
  cambio de endpoint y fallo de confianza, y servidor clásico como control.
  Los snapshots Rust/Go son evidencia externa adicional, no dependencias.

## v9.8 — Laboratorio opcional de conectividad avanzada

- **Birthday:** solo en el perfil NAT autorizado, opt-in en ambos extremos,
  con cuota de sondeos y cero tráfico si falta capacidad/consentimiento.
- **DVL:** continuidad sobre una ruta ya existente. Medir qué mejora frente
  a QUIC normal antes de exponerlo; no se presenta como apertura de NAT.
- **Cierre:** `NC-B05/06/07` y guardas aplicables con presupuestos, negativa,
  cancelación y sin relé. Desactivado por defecto. Si no demuestra beneficio
  suficiente o no pasa sus mínimos, se queda en laboratorio: v9.8 no tiene
  fecha comprometida ni bloquea ninguna entrega anterior.

## Trazabilidad y orden de ejecución

V93-00/A1 y toda evidencia anterior se conservan con su alcance. A2/C3/E/F
se reparten por contrato, no por renombrado de tarjeta. Los 92 contratos,
19 deltas y siete requisitos de servidor siguen en la especificación; ningún
aplazado equivale a PASS. Cada parte conserva su ID, destino y prueba; cuando
dos entregas comparten un caso, repetir solo la superficie que cambie.

Cada release tiene su propio cierre de paquete, compatibilidad, regresiones
y limitaciones conocidas. No esperar al final del tren para integrar ni
usar evidencia de otra revisión sin comprobar equivalencia. Siguiente
acción: **reconciliación con rc.2 y sesión QUIC de v9.3**; nada de v9.4 o
posterior entra en ese camino crítico salvo una corrección que sea necesaria
para que la funcionalidad ya distribuida siga siendo segura.
