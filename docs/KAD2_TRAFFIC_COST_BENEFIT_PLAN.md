# Plan de validación coste/beneficio del tráfico Kad2

## 1. Objetivo y afirmaciones que se podrán defender

El objetivo no es demostrar que las modificaciones «generan poco tráfico» en
abstracto, sino responder con evidencia reproducible a cuatro preguntas:

1. ¿Qué tráfico adicional genera cada modificación, en reposo y por operación?
2. ¿Qué parte de ese tráfico es útil, redundante, fallida o evitable?
3. ¿Qué mejora funcional compra ese tráfico: menos latencia, más búsquedas
   correctas, más conexiones reales a través de NAT o menos reconexiones?
4. ¿En qué tipos de red merece la pena activar cada función?

El resultado defendible deberá tener esta forma:

> En el escenario S, la función F añade **X bytes y Y datagramas por
> nodo/hora** (IC 95 %), o **Z bytes por operación exitosa**, y cambia el
> resultado útil de **A a B**. Cumple/no cumple el umbral previamente
> registrado.

No se aceptarán como resultado final cifras derivadas únicamente del tamaño de
las estructuras del código, del contador global de eMule ni de una sola
ejecución.

## 2. Alcance exacto

### Plano que se medirá

Para aislar Kad2 se usará `KadNetworkMask=1`. Kad6 se ensayará aparte con
`KadNetworkMask=2` y el modo dual con `KadNetworkMask=3`; sus bytes no se
atribuirán a Kad2.

Las extensiones que viajan por el socket clásico pero usan opcodes de la banda
`KADEMLIA3_*` se presentarán como **extensiones eSE sobre transporte Kad**, no
como tráfico Kad2 vanilla. Esta separación evita ocultar el coste de keepalive
y punch3 dentro de una cifra agregada.

### Funciones que se evaluarán por separado

| ID | Función | Tráfico esperado |
| --- | --- | --- |
| F0 | Kad2 vanilla/eSE con todas las extensiones apagadas | Control |
| F1 | FastKad: timeout adaptativo de búsqueda | Puede adelantar consultas y respuestas tardías |
| F2 | Punch2 directo y cookie de return-routability (`0x63`–`0x65`) | Tráfico por intento, no continuo |
| F3 | Predicción de puerto/spray | 1 + hasta 2 × `spread` solicitudes por intento |
| F4 | Punch3/rendezvous (`0x68`–`0x6C`) | Tráfico por escalado a un tercero |
| F5 | Keepalive (`0x66`–`0x67`) | Tráfico continuo cada 25 s, hasta 10 destinos |
| F6 | Negociación de capacidades eSE | Bytes añadidos al handshake, fuera del UDP Kad |

También se ensayará una combinación final, pero **solo después** de medir cada
función individualmente. De lo contrario no sería posible atribuir el coste o
el beneficio.

## 3. Situación actual y brechas de observabilidad

El código ya ofrece:

- bytes y paquetes Kad globales de subida y bajada;
- contadores de intentos, confirmaciones, fallos y paquetes extra de spray;
- contadores de punch3;
- pings, pongs y número de destinos keepalive;
- un informe NetLab local y saneado.

No es suficiente para este estudio:

- el contador Kad agrega Kad2, Kad6 y extensiones eSE;
- `AddUpDataOverheadKad(packet->size)` contabiliza el tamaño que conoce el
  objeto `Packet`, no el coste IP/UDP real en la interfaz;
- los bytes de sesión del informe NetLab incluyen tráfico no Kad;
- no hay bytes por opcode, motivo, intento u operación;
- `tools/pcap_diff.py` compara huellas semánticas como conjuntos y no conserva
  multiplicidad, por lo que no sirve para cuantificar volumen.

Antes del experimento se añadirá telemetría local, sin IP, KadID, hash de
archivo ni payload:

```text
timestamp_bucket, run_id, build_id, plane, feature, direction, opcode,
packets, app_bytes, operation_id, outcome
```

Los contadores mínimos serán:

- por dirección y opcode: datagramas y bytes de cuerpo;
- por función: intentos, reintentos, respuestas, expiraciones y rechazos;
- búsquedas: inicio/fin, tipo, contactos consultados, respuestas válidas,
  respuestas tardías y resultado;
- punch: intento, camino elegido, puerto candidato, ACK de señalización,
  conexión uTP establecida y primer byte útil;
- keepalive: ping, pong correlacionado, destino retirado, conservación/pérdida
  del mapeo y reconexión evitada;
- bytes en cable obtenidos de PCAP como fuente de verdad.

La API de lectura deberá entregar acumulados monotónicos. Cada ejecución
guardará una instantánea inicial y otra final; así no hace falta exponer un
reset remoto.

## 4. Tres controles necesarios

1. **Control upstream:** tag `upstream-eMule-v0.70b-audit`.
2. **Control eSE apagado:** mismo commit que el tratamiento, todas las
   extensiones apagadas, `KadNetworkMask=1`.
3. **Tratamiento unitario:** mismo binario y perfil que el control eSE, con una
   sola función activa. FastKad necesitará un selector experimental
   `fixed_3s/adaptive`, porque ahora no es una preferencia conmutable.

El control upstream mide el coste total frente a eMule original. El control
eSE apagado atribuye el efecto de la función sin confundirlo con cambios no
relacionados entre versiones.

Cada perfil partirá de copias idénticas de `nodes.dat`, preferencias, lista de
archivos y estado de publicación. No se reutilizará un perfil mutable entre
tratamientos.

## 5. Presupuesto teórico previo, no resultado experimental

Estas cifras sirven para detectar errores de instrumentación. No deben
publicarse como medición final.

| Función | Límite deducible del código | Orden de magnitud esperado |
| --- | --- | --- |
| Punch2 cookie, peer no verificado | cuerpos 26 + 20 + 38 + 22 B | 106 B de cuerpos; 4 datagramas antes de framing, cifrado e IP/UDP |
| Spray `spread=4` | 1 base + 8 extra | 9 solicitudes por intento |
| Spray máximo `spread=8` | 1 base + 16 extra | 17 solicitudes por intento |
| Keepalive propio al máximo | 10 pings + 10 pongs/25 s | 69 120 datagramas/día; el PCAP determinará bytes reales |

Como comprobación inferior, un datagrama IPv4 añade al menos 28 B de cabeceras
IP+UDP y uno IPv6 al menos 48 B, antes de considerar framing Kad, cifrado,
Ethernet, túneles o retransmisiones de enlace. La captura se informará en dos
capas:

- `udp_payload_bytes`, portable y comparable;
- `ip_wire_bytes`, incluyendo IP+UDP, que representa el coste para el acceso a
  Internet.

No se sumará Ethernet para comparar accesos distintos; podrá aparecer como
anexo diagnóstico.

## 6. Matriz de escenarios

### A. Reposo

Duración: 24 h por celda, cinco repeticiones independientes.

| Escenario | Estado |
| --- | --- |
| A0 | Kad2 desconectado: mide ruido y valida el filtro |
| A1 | Kad2 conectado, sin búsquedas, descargas ni publicaciones nuevas |
| A2 | A1 + keepalive, 1/5/10 destinos |
| A3 | A1 con 1 % de pérdida y reinicios de NAT |

Métrica principal: bytes y datagramas por nodo/hora. A1 contra F0 debe
detectar cualquier tráfico periódico accidental. A2 cuantifica explícitamente
el coste continuo.

### B. Búsqueda Kad2/FastKad

Se preparará una lista congelada de:

- 300 búsquedas existentes y populares;
- 300 búsquedas existentes de baja disponibilidad;
- 200 búsquedas negativas;
- 200 búsquedas de fuentes para hashes controlados.

Total: 1 000 operaciones por condición, repartidas en diez bloques y con orden
aleatorio. No se enviarán en ráfaga: se aplicará una cadencia de usuario
realista y un límite acordado para no abusar de la red pública.

Condiciones de red controladas:

| RTT | Jitter | Pérdida | Reordenación |
| ---: | ---: | ---: | ---: |
| 20 ms | 5 ms | 0 % | 0 % |
| 80 ms | 20 ms | 0,1 % | 0 % |
| 180 ms | 50 ms | 1 % | 0,1 % |
| 350 ms | 100 ms | 3 % | 0,5 % |

Se comparará timeout fijo de 3 s contra FastKad adaptativo. Se registrarán
respuestas que llegan después de que el adaptativo haya consultado a otro
contacto: esos datagramas son el indicador directo de tráfico adelantado
posiblemente innecesario.

### C. Punch2, cookie y spray

Topologías:

- IP pública o mapeo manual;
- NAT port-preserving;
- NAT con puerto dependiente del destino;
- doble NAT;
- CGNAT/simétrico emulado;
- firewall UDP bloqueado;
- pérdida de 0 %, 1 % y 3 %.

Se ejecutarán 200 intentos por combinación y tratamiento, con enfriamiento
suficiente para no reutilizar accidentalmente el mismo estado conntrack.
Tratamientos: punch2 clásico, cookie, cookie + spray 2, 4 y 8.

Un éxito **no** será solo recibir ACK. Se exigirán, por separado:

1. señalización correlacionada;
2. socket uTP conectado;
3. transferencia bidireccional de 64 KiB;
4. primer byte útil dentro del plazo.

Los paquetes enviados a puertos candidatos que no ganan se clasificarán como
redundancia necesaria del algoritmo; se publicará su coste aunque el intento
termine con éxito.

### D. Punch3/rendezvous

Tres hosts reales A/R/B, no tres procesos que compartan el mismo NAT. Se
cruzarán las clases NAT de A y B y se repetirá con R abierto, degradado,
apagado y sin consentimiento/capacidad.

Mínimo: 200 intentos por celda. Se medirá tráfico en los tres roles, no solo en
A, porque el coste que se desplaza al rendezvous sigue siendo coste de red.

### E. Keepalive

Duración: 24 h por celda, cinco repeticiones.

- intervalo actual de 25 s;
- 1, 5 y 10 destinos;
- timeouts NAT de 20, 30, 60, 120 y 300 s;
- con y sin tráfico útil durante 1 h, 6 h y 24 h;
- peer que responde siempre, pierde 1 % y deja de responder.

El beneficio será la conservación demostrada del mapeo y una conexión útil
posterior, no el número de pongs. También se calculará cuánto keepalive se
envió a mapeos que no habrían expirado o que nunca se usaron.

### F. Campo real

Tras superar el laboratorio: 15–30 nodos voluntarios, al menos cuatro clases
de acceso, durante 14 días. Diseño cruzado y aleatorizado:

- mitad A/B y mitad B/A;
- 48 h de calentamiento;
- bloques de 72 h por tratamiento;
- mismo binario y cambio solo de flags;
- día y hora incluidos como efectos de bloque.

No se centralizarán direcciones ni identificadores. Cada participante
entregará el JSON agregado y un PCAP recortado a la ventana de prueba o un
resumen `tshark` verificable.

## 7. Métricas y normalización

### Coste

- bytes IP/UDP y datagramas de subida, bajada y total;
- bytes/nodo/hora en reposo;
- bytes/búsqueda y bytes/búsqueda correcta;
- bytes/intento de punch y bytes/conexión uTP útil;
- bytes/día de keepalive;
- p50, p95 y p99, además de media e IC 95 %.

### Utilidad

- tasa de búsqueda correcta y latencia p50/p95/p99;
- contactos consultados por búsqueda;
- tasa de señalización, conexión uTP y transferencia útil;
- tiempo hasta socket y hasta primer byte;
- mapeos conservados, reconexiones y repunch evitados;
- CPU y memoria como guardas secundarias.

### Tráfico innecesario

Se etiquetará, sin esconderlo en el total:

- consulta adelantada antes de una respuesta válida tardía;
- duplicado o reintento sin cambio de resultado;
- solicitud de spray a puerto no ganador;
- challenge/ACK sin posterior conexión útil;
- ping sin pong o a destino retirado;
- keepalive de un mapeo que no se usa en la ventana declarada;
- paquete emitido con función apagada o sin capacidad negociada.

La métrica de decisión será:

```text
coste_incremental = tratamiento - control_eSE_apagado
coste_por_exito_incremental =
    max(0, bytes_tratamiento - bytes_control) /
    max(1, exitos_tratamiento - exitos_control)
```

La segunda fórmula se usará solo si el tratamiento obtiene más éxitos. Si no
los obtiene, se declarará «sin beneficio incremental», no infinito ni cero.

## 8. Umbrales pre-registrados

Los siguientes valores son una propuesta inicial y deben congelarse antes de
mirar los resultados:

| Función | Puerta de tráfico | Puerta de utilidad |
| --- | --- | --- |
| Todas apagadas | 0 opcodes eSE; delta Kad2 en reposo compatible con ±1 % | Sin regresión funcional >1 punto porcentual |
| FastKad | ≤ +2 % bytes por búsqueda | ≥15 % menos p95 de latencia o igual latencia con menos bytes; éxito no inferior en más de 1 pp |
| Cookie punch2 | p95 ≤1 KiB incremental por intento | Misma conexión útil; anti-reflection validado |
| Spray | p95 ≤2 KiB por intento con `spread=4` | ≥10 pp de mejora de conexión útil en NAT objetivo; no activación fuera de ese objetivo |
| Punch3 | p95 ≤4 KiB por intento sumando A/R/B | ≥10 pp de conexiones útiles sobre punch2 o ≥20 % menos tiempo |
| Keepalive | ≤10 MiB/nodo/día con 10 destinos | ≥30 % menos pérdidas de mapeo/reconexiones en NAT con timeout corto |

Además:

- ningún modo puede superar 1 datagrama/s sostenido por nodo en reposo sin una
  justificación específica;
- ningún tratamiento puede aumentar p99 de tráfico más de 2× aunque la media
  cumpla;
- una mejora solo en ACK sin mejora en conexión/transferencia no justifica la
  función;
- si una función solo ayuda a una clase NAT, deberá activarse de forma
  selectiva y permanecer apagada por defecto fuera de ella.

## 9. Análisis estadístico

- hipótesis, métricas primarias y exclusiones pre-registradas;
- pares A/B comparados dentro del mismo nodo y bloque temporal;
- intervalos de confianza del 95 % mediante bootstrap pareado por ejecución,
  no por paquete;
- tasas comparadas en puntos porcentuales con intervalo binomial;
- p95/p99 calculados por ejecución y agregados entre ejecuciones;
- resultados por escenario y globales; no se ocultará un escenario malo
  dentro de la media total;
- corrección Holm para las comparaciones primarias múltiples;
- se publicarán datos crudos agregados, scripts, commit, configuración y
  hashes SHA-256 de PCAP/JSON.

## 10. Automatización y artefactos

Cada ejecución producirá:

```text
artifacts/kad2/<run_id>/
  manifest.json
  before.json
  after.json
  counters.csv
  events.jsonl
  capture.pcapng
  tshark-summary.csv
  host-metrics.csv
  logs-sanitized.txt
  SHA256SUMS
```

`manifest.json` contendrá commit, binario, flags, máscara Kad, perfil, rol,
topología, NAT, emulación de red, hora UTC, duración y motivo de finalización.

Un nuevo analizador, distinto de `pcap_diff.py`, deberá:

1. filtrar el puerto UDP real y ambas direcciones;
2. clasificar plano/opcode cuando sea visible;
3. conservar el número de paquetes y longitudes;
4. reconciliar PCAP contra contadores internos;
5. fallar si la diferencia supera 1 %;
6. generar tablas por ejecución y el resumen pareado A/B.

Los contadores internos sirven para atribución; el PCAP manda para volumen.

## 11. Orden de ejecución

1. Congelar alcance, controles, umbrales y diccionario de métricas.
2. Implementar contadores por plano/opcode/función y exportación local.
3. Implementar el analizador cuantitativo de PCAP y pruebas unitarias con
   capturas sintéticas conocidas.
4. Ejecutar prueba de contabilidad: enviar N paquetes conocidos y reconciliar
   contador/PCAP.
5. Ejecutar reposo y FastKad.
6. Ejecutar punch2/cookie/spray.
7. Ejecutar punch3 y keepalive.
8. Solo si pasan sus puertas, ejecutar la combinación final.
9. Ejecutar cohorte real cruzada.
10. Generar informe reproducible, incluyendo resultados negativos.

## 12. Criterio final de «merece la pena»

Cada función recibirá una de cuatro decisiones:

- **Activar por defecto:** mejora amplia, coste bajo y colas p95/p99 seguras.
- **Activar selectivamente:** beneficio probado solo para una clase de red
  detectable.
- **Mantener opt-in/laboratorio:** señal prometedora pero muestra o evidencia
  de campo insuficiente.
- **Retirar/rediseñar:** no mejora el resultado útil, incumple coste o genera
  tráfico cuando está apagada/sin capacidad.

La conclusión no será una única cifra de tráfico Kad. Será una tabla por
función que enfrente **bytes adicionales** con **resultados útiles
adicionales**, acompañada de intervalos de confianza y de los artefactos que
permiten repetirla.
