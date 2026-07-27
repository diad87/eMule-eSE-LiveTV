# Kad6: diseño, fronteras y política de promoción

Estado: especificación viva del runtime presente en eSE 9.1.0-rc.2.

Este documento describe el Kad6 que realmente existe en el árbol. No convierte
una beta en una promesa de soporte y no autoriza infraestructura pública.

## 1. Decisión de producto

Kad6 no se reduce a copiar Kad2 sobre IPv6. Es un plano eSE separado y
family-neutral que aporta:

- identidad de nodo Ed25519 persistente;
- records firmados que ligan identidad, epoch y endpoints IPv4/IPv6;
- routing y fuentes nativos sin insertar direcciones sintéticas en Kad2;
- una base autenticada para futuros servicios K6.

eSE 9.0 distribuye el **cliente UDP Kad6 nativo como función experimental
seleccionada por defecto** junto a Kad2. eSE 9.1 no lo introduce por primera
vez: lo promociona a soportado después de completar las topologías y gates
IPv6-only, dual-stack, seguridad, compatibilidad y churn.

## 2. Selección y migración

`KadNetworkMask` representa cuatro estados:

| Máscara | Kad2 | Kad6 |
| ---: | :---: | :---: |
| `0` | no | no |
| `1` | sí | no |
| `2` | no | sí |
| `3` | sí | sí |

La máscara por defecto es `3`. Un perfil sin `KadNetworkMask` migra
`NetworkKademlia=1` a `3` y `NetworkKademlia=0` a `0`. Una selección explícita
válida siempre prevalece. El booleano heredado refleja únicamente el bit Kad2,
de forma que una versión antigua no reactive Kad2 al abrir una copia de un
perfil Kad6-only.

Kad6 es desactivable en caliente y su estado de ejecución/conexión se muestra
independientemente de Kad2.

## 3. Condiciones reales de activación

La selección de Kad6 abre su receive path y su mantenimiento, pero un nodo solo
puede construir y anunciar un header Kad6 utilizable cuando dispone de:

1. Kad6 seleccionado y UDP activo;
2. socket UDP de cliente disponible;
3. identidad Ed25519 persistente;
4. al menos un endpoint público elegible, IPv4 o IPv6.

Por tanto, Kad6 no requiere poseer IPv6 global para formar un record: su wire es
family-neutral y admite un endpoint IPv4 público. Sin contactos bootstrap,
persistidos o importados, el scheduler puede estar activo sin tener destinos a
los que enviar rondas.

## 4. Frontera entre Kad6 nativo y servicios K6

Se deben distinguir tres superficies:

1. **Cliente Kad6 UDP nativo**: `OP_KAD6HEADER`, routing, bootstrap, hello,
   find-node y records de fuentes. Es la selección de red experimental
   disponible en 9.0.
2. **Gateway/carrier K6 en `CLiveTunnel`**: búsqueda, publicación, tickets,
   streams, cuotas y rutas privadas dentro de `TUN_OP_KAD6_GATEWAY`. Requiere
   sus propias capacidades y políticas; seleccionar Kad6 no lo activa.
3. **Salida pública o contribución**: aceptar trabajo de terceros, prestar
   ancho de banda o actuar como exit. Permanece apagado por defecto y exige
   consentimiento y gates independientes. `Kad6PublicExitOptIn=0` no apaga el
   cliente nativo; apaga la salida pública estable. Durante las betas,
   `Kad6BetaExitOptIn` puede habilitar únicamente la superficie de prueba si
   existe consentimiento de contribución y el runtime está sano. No activa,
   sustituye ni aporta evidencia suficiente para la salida pública estable.

La documentación y la UI no deben llamar “Kad6 apagado” a un estado en el que
solo está apagada la salida. Deben nombrar la superficie concreta.

## 5. Routing, probation y persistencia

Kad6 mantiene su tabla en `CKad6RoutingTable`, separada del routing Kad2.

- Un contacto aprendido indirectamente entra en probation.
- La promoción requiere una respuesta ligada a una transacción desde el
  endpoint exacto.
- Los records firmados incluyen epoch y caducidad.
- La tabla limita contactos, candidatos, diversidad y fallos.
- Los contactos se persisten en `nodes_v6.dat`; no existe contaminación de
  `nodes.dat`.
- Al reiniciar, las entradas persistidas se cargan de nuevo en probation:
  el bit histórico de verificación nunca restaura confianza.
- `kad6_router_epoch.dat` conserva la monotonía del record local.
- `kad6_asn.dat`, `kad6_path_evidence.dat` y el bootstrap privado firmado son
  estados auxiliares distintos de la tabla.

La ausencia de confianza persistida es deliberada. El gate `V91-K04` mide que
la re-verificación sea viable con una población pequeña.

## 6. Seguridad de respuesta

`BOOTSTRAP_REQ`, `REQ` y `FIND_SOURCE_REQ` pueden provocar respuestas mayores
que la petición. El runtime no debe emitir esas respuestas basándose en
historial previo: exige un challenge fresco de return-routability ligado a la
transacción.

Además:

- las respuestas deben coincidir con `txid`, endpoint y nodo esperado;
- los contactos recibidos entran en probation con un límite inferior al
  tamaño total de la respuesta;
- firmas, epochs, freshness, tamaños y recuentos se validan antes de promover;
- source-store requiere un remitente ya verificado;
- cualquier versión de routing desconocida se rechaza.

`V91-S03` convierte la protección anti-amplificación en un gate de red
reproducible, no solo en una propiedad inspeccionada del código.

## 7. Evolución del wire beta

El wire Kad6 de las betas es experimental:

- un cambio incompatible incrementa `kK6RouteWireVersion`;
- el receptor acepta solo la versión runtime vigente;
- una beta antigua queda fuera de Kad6 de forma fail-closed;
- Kad2 continúa disponible y byte-compatible;
- una beta no obliga a mantener eternamente su versión Kad6.

Al entrar en RC de 9.1, el wire se congela. Después de ese punto, un cambio
incompatible requiere una nueva versión de protocolo y una política explícita
de coexistencia; no puede reutilizar silenciosamente la versión estable.

## 8. Bootstrap y condición de “isla”

Kad6 es eSE-a-eSE. Un cliente vanilla puede ignorar tags aditivos, pero no
interpreta el plano Kad6 ni descubre por él una fuente IPv6-only.

La población se forma mediante:

- contactos conservados en `nodes_v6.dat`, revalidados al arrancar;
- bootstrap Kad6 firmado o explícito;
- endpoints IPv6 aprendidos como pistas desde Kad2, siempre en probation;
- respuestas Kad6 autenticadas que aportan contactos acotados.

Hasta que exista adopción fuera del fork, cualquier claim de discovery
IPv6-only debe decir **entre peers eSE**. Kad2 sigue siendo la red pública
compatible con eMule clásico.

## 9. Gates por versión

### eSE 9.0

- máscara `3` por defecto y migración documentada;
- cliente Kad6 etiquetado como experimental;
- aislamiento Kad2/Kad6 y persistencia separada;
- versiones desconocidas rechazadas;
- salida pública, gateway y contribución apagados por defecto;
- sin claim de IPv6-only completo.

### eSE 9.1

- topologías IPv4-only, dual-stack e IPv6-only;
- bootstrap, routing, source publish/find y transferencia real;
- aislamiento al apagar cada plano en caliente;
- política neutral de créditos IPv6-only en beta.1, sin identidad IPv4
  sintética; revalidación de la decisión antes del RC;
- anti-amplificación `V91-S03`;
- churn y re-verificación tras reinicio `V91-K04`;
- consentimiento base, avanzado y contribución independientes, todos cerrados
  por defecto y revocables mediante kill switch;
- Beta Exit separada de la salida pública estable, condicionada al
  consentimiento de contribución y a los gates runtime;
- wire congelado antes del RC.

## 10. Fuentes normativas y de implementación

- [`V9_RELEASE_SPECIFICATION.md`](V9_RELEASE_SPECIFICATION.md)
- [`KAD_NETWORK_SELECTION.md`](KAD_NETWORK_SELECTION.md)
- [`IPV6_DUALSTACK_BETA2_RELEASE.md`](IPV6_DUALSTACK_BETA2_RELEASE.md)
- [`protocol/PROTOCOL_REGISTRY.md`](protocol/PROTOCOL_REGISTRY.md)
- [`protocol/OPCODES.csv`](protocol/OPCODES.csv)
- [`libkad6/README.md` in the source repository](https://github.com/diad87/eMule-eSE-LiveTV/blob/main/libkad6/README.md)
- `srchybrid/kademlia/net/KademliaUDPListener.cpp`
- `srchybrid/kademlia/routing/Kad6RoutingTable.cpp`
