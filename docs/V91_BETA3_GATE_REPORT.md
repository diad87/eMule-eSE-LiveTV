# eMule eSE 9.1.0-beta.3 — informe de gates

Fecha UTC: `2026-07-25`.

## Candidata exacta

- Commit de runtime:
  `d3e418d9bafebb7b53b8a1d38985e300c042fa46`
- Estado del build: limpio (`dirty: false`).
- `emule.exe` SHA-256:
  `78880100B7E5DAE6B68CE93CE57400675F781F59103D29BCFAF11BE1C15B1DEE`
- `ese-server.exe` SHA-256:
  `E85C21EB3D9F070DAAAFFCB33AA50718D3019A2F461B0F1CF0601F9CB0C6A272`
- ZIP SHA-256:
  `55E0E3E7E6979E2E37D03CB39B7E0824030EAF378E158236E3A31F264015021F`

El ZIP contiene 142 archivos, coincide con los 142 archivos del directorio de
paquete y su checksum externo coincide con el artefacto.

## Build y regresión

- Preflight de release: PASS.
- Core: PASS.
- Kad6: PASS, incluidos 1.400.000 inputs de fuzz normal y 1.400.000 con ASan,
  cero fallos.
- Build limpio Windows `Release|x64`: PASS.
- Integration: PASS.
- Relay release y ASan: PASS.
- `ese-server.exe`: PASS.
- 43 DLL de idioma: PASS.
- Paquete: PASS, 141 hashes internos verificados.
- Smoke de `ese-server.exe` y FFmpeg: PASS.
- `G-SELFTEST`: PASS, exit code 0, 8,501 s.

El primer intento de empaquetado detectó que `npm ci` dejaba
`package-lock.json` stat-dirty por normalización LF/CRLF aunque el blob fuera
idéntico. El commit candidato incluye una corrección del pipeline: refresca el
índice para el bundle y el lockfile y sigue fallando si existe cualquier
deriva real. El pipeline completo se repitió desde ese commit y pasó.

## AI-I03 / V91-A02

El escaneo normal y `DirectoryWatcher` usan
`SharedFileIntakePolicy`.

El corpus A/B está fijado a eMule AI 1.5.2, commit
`de8e27e2029044d533f7090f173c95856fe4635a`.

| Clasificador | Falsos positivos | Falsos negativos |
|---|---:|---:|
| eMule AI 1.5.2 | 0 | 7 |
| eSE 9.1.0-beta.3 | 0 | 0 |

La prueba focalizada y el A/B pasan dentro del gate Integration.

## Evidencia de self-test

Directorio local:

`C:\tmp\v91-beta3-selftest-d3e418d`

El resumen canónico confirma:

- candidate commit: `d3e418d9bafebb7b53b8a1d38985e300c042fa46`;
- candidate binary:
  `78880100B7E5DAE6B68CE93CE57400675F781F59103D29BCFAF11BE1C15B1DEE`;
- exit code: `0`;
- verdict: `PASS`.

## Decisión

- Candidata beta.3: **GO**.
- Beta pública de laboratorio: **GO_WITH_LIMITATIONS**.
- Gate completo v9.1/RC: **NO_GO** hasta cerrar y reconciliar los casos de
  topología física heredados de beta.2.

AI-I03 no modifica wire, preferencias, formatos persistentes ni topologías de
red. Por tanto, no invalida por diseño la evidencia de red anterior, pero el
ledger de RC debe justificar explícitamente cada evidencia reutilizada y
ejecutar sobre el commit congelado todos los casos sensibles al binario.
