# ADR MOD-0.3 — Ownership, layering y concurrencia

- Estado: **Aceptado / PASS**
- Versión: `v1`
- Contrato ejecutable:
  [mod03_ownership_layering_contract_v1.json](mod03_ownership_layering_contract_v1.json)
- Baselines: inventario MOD-0.1 y characterization MOD-0.2 PASS

## Decisión

Los owners existentes siguen siendo exactamente `CLiveTunnel`, `CWebServer` y
`CLiveStreamManager`. MOD-0.3 no crea owners, no mueve campos ni funciones y no
inicia una extracción. Cada campo mutable conserva el owner registrado en
MOD-0.1; cada record conserva tanto su `owner` como su relación
`contained_by_owner`/`contained_by_fields`. Una transferencia posterior debe
ser atómica: durante un slice nunca pueden coexistir dos owners para el mismo
estado.

Los 29 `planned_modules` normativos son exactamente los diez módulos de túnel,
los diez de web y los nueve de streaming enumerados por el plan 9.2. El JSON
fija su nombre, layer y responsabilidad. `owner_before` sigue siendo el
coordinador; `owner_after` es el módulo sólo después de la transferencia
atómica de su slice. MOD-0.3 no asigna todavía campos a esos módulos.

Se adopta una dirección de dependencias acíclica:

```text
composition -> facade -> application -> domain_state -> foundation
      |          |           |
      v          v           v
   adapters -> ports ------> foundation
      |
      +--------------------> foundation
```

La lista exacta de aristas permitidas y prohibidas está en el contrato. La
política es `deny_unlisted`. El coordinador es fachada, composition root y
owner de lifetime mientras se extraen colaboradores. Un colaborador recibe
ports estrechos por constructor/factory; no consulta `theApp`, no usa service
locator y nunca incluye el header del coordinador. Las dependencias concretas
de UI, socket, Kad, filesystem o proceso viven en adapters `.cpp`.

Estas reglas son objetivo vinculante para slices posteriores; no afirman que
el monolito actual ya tenga esas fronteras. Si una ruta actual no puede
adaptarse sin cambiar comportamiento, se activa STOP.

El gate MOD-0.3 verifica el segundo ejemplar normativo completo del contrato y
sus proyecciones contra MOD-0.1/MOD-0.2. No escanea módulos futuros, no asigna
campos o records a colaboradores y no demuestra por sí solo que cada ruta de
runtime ya respete el orden de locks, el marshaling o los includes objetivo.
Esas pruebas de código pertenecen a MOD-0.4 y a cada slice de extracción.

## Threads y marshaling

`CLiveTunnel` aplica mutaciones coordinadas desde el drain principal. Ingress,
Kad, sockets, timers y workers validan/copían y publican comandos con valores
inmutables u ownership explícito; `m_mtQueue`/`m_mtLock` es el seam de
marshaling inventariado. El worker de advertise necesita fence de lifetime.

`CWebServer` parsea, autoriza y proyecta en el request thread. Toda mutación GUI
cruza un message port explícito hacia el main thread. Los comparadores operan
sólo sobre snapshots del caller.

`CLiveStreamManager` mantiene el owner único de sesiones, peers y chunks. Los
`On*` validan/copían en el dispatch thread; las salidas se invocan tras soltar
el lock. El edge inventariado
`CRTMPIngest watcher -> chunkCb -> FeedSegment` conserva bytes propios y exige
fence de shutdown/generación. Ese edge es la única
`external_async_callback_edge` de MOD-0.1 y queda ligado por count/hash en el
contrato. UI y web sólo reciben snapshots inmutables.

Ningún objeto interno, referencia prestada ni puntero a record cruza una
frontera async.

## Locks y callbacks

El orden objetivo es:

```text
registry -> pending -> queue -> timer_or_leaf
```

Una función puede omitir dominios, pero nunca invertirlos. Para
`CLiveTunnel`: `m_lock` es registry; `m_pendingLock`, pending; `m_mtLock`,
queue; `m_k6ReleaseLock`, `m_peersCacheLock` y `m_proxyIngestLock` son leaves.
Para `CLiveStreamManager`, `m_lock` es registry y
`s_liveRequestRateLock` es leaf. MOD-0.1 no establecía orden y sus secuencias
eran sólo evidencia léxica; por ello una ruta baseline contraria no se
“corrige” aquí: detiene el slice y exige una prueba de concurrencia dedicada.

Todos los callbacks externos siguen `snapshot -> unlock -> invoke`. Esto
incluye sockets, Kad, GUI messages, tunnel/manager crossings, `SetEvent`,
watcher RTMP y transport sends. Si un callback necesita el lock interno
adquirido, la extracción se detiene.

## Includes, composición y ownership

- Un módulo extraído nunca incluye `LiveTunnel.h`, `WebServer.h` o
  `LiveStreamManager.h` de su coordinador.
- Un dominio no incluye UI, socket, Kad ni otro coordinador; consume un port.
- Los headers públicos exponen valores/ports, no tipos concretos de adapter.
- Sólo la fachada/composition root crea e inyecta colaboradores y controla su
  shutdown.
- Los hashes/proyecciones del JSON atan fields, records, locks, entrypoints e
  includes a MOD-0.1; cualquier drift requiere un ADR nuevo.

## Compatibilidad y condiciones de parada

Este ADR no cambia wire, opcodes, formatos persistidos, preferencias,
serialización, afinidad observable ni comportamiento. MOD-0.2 permanece como
baseline ejecutable.

STOP inmediato si cambia wire/persistencia, aparece owner duplicado, un
callback queda bajo lock, un módulo incluye al coordinador, surge ciclo/SCC,
falta characterization, se mezclan fixes funcionales, el slice supera 1.500
líneas netas o hace falta invertir el orden de locks sin prueba dedicada. Las
seis condiciones específicas del inventario también son vinculantes.

**Ninguna extracción MOD-1/MOD-2/MOD-3 empieza antes de MOD-0.3 PASS y de que
este contrato y sus fixtures negativos estén verdes.** MOD-0.4 es el siguiente
gate; este ADR no lo sustituye.
