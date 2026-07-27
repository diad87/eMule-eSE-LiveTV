# Plan de ejecución eSE 9.1.0-rc.1

## Cierre de rc.1

Decisión: **NO_GO**.

- Commit exacto final:
  `f4f813d2976ddf4da877771f3f6a6a6d68de7dfd`.
- `emule.exe` SHA-256:
  `CD5E05FA930903E2F59C23C2D536824AE31387BC7C86AD32C2949E561FBCD5CF`.
- Bloqueante: `V91-I04`. La revisión de los blobs exactos demostró que el
  fallback dependía de un error de socket IPv6 y no tenía temporizador de
  familia para un `DROP` silencioso; el único límite aplicable era el timeout
  global de conexión de 45 segundos.
- Sucesora: `9.1.0-rc.2`.

El soak de rc.1 se completó y archivó bajo su identidad original. No se
relabela como evidencia exacta de rc.2.

### Resultado histórico de O01

La ejecución local exacta de `f4f813d` terminó el 26 de julio de 2026:

- 43.200 segundos solicitados y 12 h 6 min observados;
- `source`, `viewer` y LiveTV: `PASS`;
- 27.632 chunks recibidos durante la ventana, 6.035 duplicados y ratio
  incremental `0,218406`, por debajo del límite `0,25`;
- deriva acumulada del ratio de duplicados `0,044456`, por debajo de `0,05`;
- cero fallback IPv4, cero chunks ausentes al cierre y cero fallos;
- crecimiento acotado: source `+1.904.640` bytes y `+27` handles; viewer
  `+5.849.088` bytes y `+9` handles.

El veredicto automatizado es `PASS` parcial. El estado formal permanece
`BLOCKED` porque esta ejecución usa dos perfiles en un único Windows `H1` y
`V91-O01` exige `T1/T5`.

## Candidata de partida

La campaña parte del paquete limpio `9.1.0-beta.3`:

- commit: `8d40100df76e735b53f2ae599e104f813c3a6b38`;
- `emule.exe`:
  `D84E13F21BC959A1122D2E51AE9C7AB966B33271774798AC82501C39FA269D9D`;
- `ese-server.exe`:
  `9992219822D9E1ED03DD860F0528F1312056F37673F4081D4ED04DEA3E9CBA75`;
- ZIP:
  `9A661B8F2E1A01EB4A79E056EA7B72D022AD38F0308492DD9EE845EA9C20B9DF`.

Cada harness obtiene commit, versión y hashes de `BUILD_INFO.txt`. Un paquete
dirty, un hash distinto o evidencia atribuida a otro commit detiene el caso.

## Regla de promoción histórica (no satisfecha)

`rc.1` solo se habría promovido y publicado si:

1. los 27 casos de la sección 8.6 de la especificación están reconciliados;
2. no queda ningún `FAIL`, ningún `BLOCKED` presentado como `PASS` y ningún
   defecto abierto S0, S1 o S2;
3. LiveTV IPv6 completa dos horas y el soak completa doce horas;
4. existe evidencia de al menos dos Windows físicos;
5. el mismo commit se reconstruye limpio, pasa Core, Integration,
   `Release|x64`, self-test y paridad del ZIP;
6. wire, formatos persistentes y preferencias quedan congelados. Cualquier
   corrección posterior que los cambie obliga a crear otro RC.

Una ejecución local con dos perfiles puede descubrir regresiones y cerrar la
parte automatizable, pero conserva estado `BLOCKED` cuando el caso exige
`T1`, `T3`, `T5`, `T6` o `V1`.

## Orden de ejecución

### Fase A — automatización y compatibilidad local

| Casos | Ejecución |
|---|---|
| `A01`, `A02` | pipeline completo, corpus A/B, build y self-test exactos |
| `P01`–`P03` | capturas SOCKS5, HTTP CONNECT y rechazo SOCKS4 |
| `C02`–`C04` | matriz de consentimiento en dos rondas |
| `K03` | downgrade sobre copia con el paquete exacto de eSE 8.1 |
| `C01` parcial | transferencia y captura de wire frente a 0.70b |
| `I01`, `I05` parciales | transferencia de 4 GiB por cada familia |
| `K01`–`K04`, `S01`–`S03` parciales | 29 ejecutables Kad6 individuales |

### Fase B — LiveTV y estabilidad

- `I02`: 12 Mbps, dos horas, playlist y chunks válidos, socket IPv6 observado
  en cada muestra y cero fallback IPv4.
- `O01`: doce horas, crecimiento acotado de memoria y handles, sin corrupción,
  desconexiones crecientes, chunks ausentes ni aceleración de duplicados.
- La misma sesión local puede alimentar ambos monitores, pero no convierte la
  topología local en `T5`.

### Fase C — dos Windows físicos, equipo principal y María

Se despliega el mismo ZIP y se comprueba su SHA-256 antes de arrancar:

- `I01`: 4 GiB con IPv4 retirado del camino de datos;
- `I02`: LiveTV IPv6-only a 12 Mbps durante dos horas;
- `I03` y `I04`: preferencia dual-stack y fallback AAAA→A;
- `I05`: repetición IPv4-only;
- `I06`: transporte IPv6 del overlay, etiquetado explícitamente como overlay;
- `I08`: echo TCP/UDP conservando los 128 bits;
- `K01`, `K02`, `K04`: ciclo Kad6, aislamiento y reinicio;
- `S01`–`S03`: identidad, epoch y anti-amplificación;
- regresión LiveTV de doble rol: emitir un canal y ver otro sin mezclar claves,
  buffers, playlists ni tarjetas.

### Fase D — portátil cuando vuelva a estar disponible

- `I07`: registrar si el hotspot delega IPv6 global. La ausencia de delegación
  se registra como limitación del acceso, no como fallo del producto.
- `R01`: cambio LAN→hotspot durante sesión, reconexión y caducidad del endpoint
  anterior.

## Campaña beta.3 iniciada el 25 de julio de 2026

Directorio de evidencia:
`C:\tmp\v91-rc-prep-8d40100`.

Esta campaña queda como evidencia histórica de desarrollo. Sus soaks no se
atribuyen a rc.1 porque el transporte directo ULA cambió después y la candidata
debe reconstruirse desde otro commit. Ningún resultado de ese directorio se
presenta como validación de rc.1.

Ya ejecutados sobre el paquete exacto:

- pipeline completo y self-test: PASS;
- `P01`–`P03`: PASS;
- `C02`–`C04`: PASS en dos rondas;
- `K03`: PASS;
- 29/29 ejecutables Kad6: PASS;
- `C01` local: transferencia de 223.394.208 bytes e integridad/wire PASS,
  pendiente de la topología formal `V1`;
- `I01` local: 4 GiB íntegros por IPv6 y cero conexión IPv4, pendiente de
  `T5`.

Ejecuciones locales históricas no válidas para promover rc.1:

- `I02` local, dos horas;
- `O01` local, doce horas.

El control `I05` local no abrió un socket de peer ni avanzó datos durante más
de diez minutos. Se conserva como `PARTIAL_INCONCLUSIVE`; se repite en `T1`
con María, donde la dirección remota no puede ser descartada como propia.

Pendiente de ejecución física exacta:

- la fase C con María;
- la fase D con el portátil.

## Cierre histórico

Los resultados se consolidan con `tools/lab/write_v91_campaign_ledger.ps1`.
El ledger final de `rc.1` tiene 27 filas y decidió `NO_GO`. El proceso previsto
era construir primero un artefacto identificable, obtener 27 `PASS`,
reconstruir el mismo commit desde limpio y repetir la fase A antes de etiquetar.
Ese tramo no se ejecuta para `rc.1`; la corrección y la nueva calificación
pertenecen a `rc.2`.
