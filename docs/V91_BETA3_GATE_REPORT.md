# eMule eSE 9.1.0-beta.3 — informe de gates

Fecha UTC: `2026-07-25`.

## Candidata exacta

- Commit de runtime:
  `8d40100df76e735b53f2ae599e104f813c3a6b38`
- Estado del build: limpio (`dirty: false`).
- `emule.exe` SHA-256:
  `D84E13F21BC959A1122D2E51AE9C7AB966B33271774798AC82501C39FA269D9D`
- `ese-server.exe` SHA-256:
  `9992219822D9E1ED03DD860F0528F1312056F37673F4081D4ED04DEA3E9CBA75`
- ZIP SHA-256:
  `9A661B8F2E1A01EB4A79E056EA7B72D022AD38F0308492DD9EE845EA9C20B9DF`

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
- `G-SELFTEST`: PASS, exit code 0, 8,503 s.

## LiveTV con doble rol

La corrección de la sesión
`019f991c-aedf-75c2-9dcf-38c1e5411aec` se trasladó sobre la rama limpia de
beta.3 sin incorporar el resto del directorio de trabajo original.

Quedan separados:

- identidad, clave, metadata, bitrate y buffer de la emisión local;
- identidad, clave, metadata, bitrate y buffer del canal remoto;
- peers, malla, anuncios, bitmaps, pings, publicación Kad, relay y túnel;
- HLS, actividad del reproductor, cierre de sesión y miniaturas.

La regresión Node específica pasa junto con las otras 32 pruebas LiveTV. El
self-test nativo reproduce el escenario de doble rol sobre el mismo manager:
mantiene activa la emisión, instala una identidad remota distinta, alimenta un
nuevo segmento local y exige que la clave publicada y ambos buffers sigan
aislados.

La batería completa se ejecutó dos veces durante la integración. La segunda
ejecución partió del commit limpio exacto indicado arriba.

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

`C:\tmp\v91-beta3-selftest-8d40100`

El resumen canónico confirma:

- candidate commit: `8d40100df76e735b53f2ae599e104f813c3a6b38`;
- candidate binary:
  `D84E13F21BC959A1122D2E51AE9C7AB966B33271774798AC82501C39FA269D9D`;
- exit code: `0`;
- verdict: `PASS`.

## Decisión

- Candidata beta.3: **GO**.
- Beta pública de laboratorio: **GO_WITH_LIMITATIONS**.
- Gate completo v9.1/RC: **NO_GO** hasta cerrar y reconciliar los casos de
  topología física heredados de beta.2.

AI-I03 no modifica wire, preferencias, formatos persistentes ni topologías de
red. La corrección LiveTV sí cambia el reparto interno de estado y el
enrutamiento por rol, aunque mantiene el wire existente. La prueba física
anterior de dos equipos es evidencia del comportamiento trasladado, no del
binario `8d40100`; antes de RC debe repetirse sobre el commit congelado todo
caso físico sensible a LiveTV.
