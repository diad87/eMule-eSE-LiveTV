# eSE 9.1.0-beta.2 — informe de gates

Fecha UTC: `2026-07-25`.

## Candidata exacta

- Commit: `d773427b9dafb3eba8260d0185a8943b00895798`
- Estado de build: limpio (`dirty: false`)
- `emule.exe` SHA-256:
  `59CE052338A458B8F2D0128D02150BE139CFE4F4DBB0981E26912441299B3AC1`
- `ese-server.exe` SHA-256:
  `C33687B0D4A0FF9AF0F6BB9A7C948CD69265C60F077B1F7FE098B5720A4696D7`
- ZIP SHA-256:
  `DFB372F94B4EC928F1BA7771B677342C0218C5F8AD601B641D8059F1E82D5694`

El ZIP contiene 142 archivos, coincide archivo por archivo con el directorio
de paquete y su checksum externo coincide con el ZIP.

## Build y regresión

- Preflight de release: PASS.
- Core: PASS.
- Kad6: PASS, incluidos 1.400.000 inputs de fuzz normal y 1.400.000 con ASan,
  cero fallos.
- Build Windows x64: PASS.
- Integration: PASS.
- Paquete: PASS, 141 hashes internos verificados.
- Smoke del paquete: PASS.
- `G-SELFTEST`: PASS, exit code 0, 10,528 s.

## Gates corregidos

### Consentimiento y revocación

`V91-C02`, `V91-C03` y `V91-C04` pasaron sobre el paquete exacto.

- C02: 6/6 ejecuciones PASS.
- C03: 2/2 ejecuciones PASS.
- C04: 2/2 ejecuciones PASS.
- Revocación C03: 2.462,1 ms y 2.258,8 ms.
- Ambos reinicios conservaron `EseNetLabEnabled=false`.
- Kad6 estable permaneció activo: el kill switch de NetLab solo cerró sus
  niveles y Kad6 Beta Exit.

### Proxy IPv6

`V91-P01`, `V91-P02` y `V91-P03` pasaron sobre el paquete exacto.

- SOCKS5 emitió un destino IPv6 nativo.
- HTTP CONNECT emitió la autoridad IPv6 correcta.
- SOCKS4 no abrió conexión y `direct_join` respondió HTTP 400,
  `success=false`, `joined=false`, `dialed=false` y
  `error=ipv6_not_supported_by_socks4`.

## Integridad de la evidencia

Los resúmenes locales quedaron bajo
`C:\tmp\v91-beta2-gates-d773427` con estos SHA-256:

- `G-SELFTEST-SUMMARY.json`:
  `D6291F66B4945879400027C28D77216B1F921FA612B5D78F16A28C51B23778F7`
- `V91-CONSENT-SUMMARY.json`:
  `9877A03CD9153AE69D7FF4C39257BBF0BEBC500EDA3426F48BB13D904F954E52`
- `V91-PROXY-SUMMARY.json`:
  `11B00B43FA4ED7CCFA1F1F78E1452C2604F40B25BA94F7BC0550A72B27700BD6`

## Decisión

La actualización de la matriz histórica es **8 PASS, 0 FAIL y 18 BLOCKED**.
Los bloqueados exigen topologías físicas no disponibles en esta ejecución.

- Beta pública de laboratorio: **GO_WITH_LIMITATIONS**.
- Gate completo 9.1/RC: **NO_GO** hasta ejecutar los casos bloqueados.

No se presenta un caso bloqueado como PASS. La beta se publica para ampliar la
cohorte consentida y obtener precisamente la evidencia de red real que falta.
