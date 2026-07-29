# MOD-0.2 — Caracterización de seams

La matriz [mod02_characterization_matrix_v1.json](mod02_characterization_matrix_v1.json)
cubre exactamente los nueve pares `(owner, existing_test_seam.file)` del
inventario MOD-0.1: cuatro de `CLiveTunnel`, cuatro de `CWebServer` y uno de
`CLiveStreamManager`. El verificador compara ambos multisets, rechaza
duplicados y exige que cada fila nombre un golden existente.

Los goldens de
[mod02_characterization_goldens_v1.json](mod02_characterization_goldens_v1.json)
tokenizan cuerpos C++ de producción ignorando formato y comentarios, pero
conservando cada literal exacto. Por tanto detectan cambios en rutas, mensajes,
cabeceras o contratos de serialización. El negativo altera `"/api/live/"`
dentro de `_ProcessLiveAPI`; debe invalidar el golden.

```powershell
python tools/architecture/verify_mod02_characterization.py --verify
python tools/architecture/verify_mod02_characterization.py --negative-fixture
```

## Golden ejecutable con identidad fuerte

La ejecución requiere obligatoriamente
[mod02_build_manifest_v1.json](mod02_build_manifest_v1.json). Su esquema v1
contiene sólo el commit, la identidad de fuentes críticas y el SHA-256 del
binario. La identidad es SHA-256 UTF-8 del `join('\n')`, en orden fijo, de:

`relativePath=sha256(raw bytes)` para los nueve ficheros críticos de
`EmuleDlg`, `LiveTunnel`, `LiveCellQueue`, `WebServer` y
`LiveStreamManager`. El header
`srchybrid/Mod02BuildIdentity.h` queda fuera del material hash para evitar
auto-referencia, pero debe estar limpio y aporta el mismo valor al marcador
`SOURCE <identity>` del propio binario antes de los seis marcadores
`BEGIN/PASS` de coordinadores.

El runner [run_mod02_stream_selftest.ps1](../../tools/architecture/run_mod02_stream_selftest.ps1)
comprueba commit, árbol limpio de las nueve fuentes más el header, identidad,
SHA del ejecutable y secuencia exacta de siete marcadores. Guarda los hashes
del manifiesto, fuente, binario y marcador en `summary.json`. Si vence el
límite, inicia `taskkill.exe /T /F` oculto, espera como máximo 10 segundos al
terminador y cinco al proceso objetivo; no usa esperas ilimitadas y exige
confirmación de terminación.

## Estado

MOD-0.2 está **PASS**. El binario Release x64 se compiló desde el commit de
fuente `c3a66642d836a9628a0594338c2ae22e53844f7a`; su SHA-256 es
`3b40f45a57edb28cc1359fb47d0df3bdcc7bcbeabc509dfd8e3f436afd2515a7`.
La ejecución final terminó con código `0` en nueve segundos, sin timeout, con
`source_tree_clean=true`, terminación confirmada y los siete marcadores
exactos. La huella del marcador es
`f8bdc5c3829867e08ddc32c69b21d63aa82f045352c583a361a33fa93f223ed0`
y la del resumen sanitizado es
`06b086f13eecf0c512922b34b732108e5f44a0df488dd304603626463dd009b9`.

El hook de `CWebServer` comprueba parser, escaping y gzip completo: magic,
CRC, ISIZE y descompresión exacta de `mod02`. El hook de túnel ejerce framing,
parseo, reensamblado y rechazo fail-closed. El selftest existente del manager
cubre broadcast, segmento firmado y rechazos de duplicado/manipulación.

El runner Node `srchybrid/eSE/test/live_tv_regression.test.js` exige la política
IPv6 actual: `bSameLanDirectRoute` deriva de `bDirectRoute`, requiere
`ObserveSameLanRouteToPeer` y `CanUseSameLanEndpoint`, y acompaña la condición
final de IPv6 pública. No altera producción.
