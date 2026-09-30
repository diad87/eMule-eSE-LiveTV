# Relay/KRP P0 — baseline reproducible

| Campo | Valor |
|---|---|
| Fecha | 2026-07-16 |
| Commit base | `5575a911070f4f03c368a632eb5562c75300c5ca` |
| Rama | `main` |
| Worktree | Sucio; contiene trabajo Kad6/Live del usuario que esta línea preserva |
| Configuración GUI | `Release|x64` |
| Estado P0 | PASS local; gates físicos y públicos no ejecutados |

## 1. Comandos ejecutados

```powershell
cd libkad6
test_all.bat

cd ..
python tools/check_protocol_registry.py
./tools/build_all.ps1 -Skip ese,langs,package
```

## 2. Resultado libkad6

`test_all.bat` recompiló y ejecutó:

- 25 suites standalone mediante `make.bat`;
- 3 suites de integración Crypto++/host mediante `make_crypto_vectors.bat`;
- 7 ficheros / 17 vectores JSON con schema y hex válidos;
- 13 targets de fuzz, 100.000 iteraciones por target en Release;
- los mismos 13 targets, 100.000 iteraciones por target con MSVC AddressSanitizer.

Resultado:

| Gate | Resultado |
|---|---|
| Suites recompiladas | 28/28 PASS |
| Fuzz Release | 1.300.000 iteraciones, 0 fallos; pico RSS 4.188 KiB |
| Fuzz ASan | 1.300.000 iteraciones, 0 fallos; pico RSS 181.568 KiB |
| Registry | 131 entradas, 114 símbolos fork en código; PASS antes de reservas KRP |
| Gate agregado | `libkad6 complete gate: PASS` |

### Nota sobre el artefacto ASan de gateway

El ejecutable `build/test_kad6_gateway_asan.exe` existente era anterior a la fuente actual y, sin el runtime de Visual Studio en `PATH`, terminaba con `0xC0000135`. Tras recompilarlo desde la fuente vigente con `/fsanitize=address` y ejecutar con el runtime correcto, el resultado fue `44 passed, 0 failed`. No se usa el binario antiguo como evidencia.

## 3. Build eMule

| Campo | Resultado |
|---|---|
| Pipeline | `tools/build_all.ps1`, solo etapa `emule` |
| MSBuild | Visual Studio 2022 Build Tools |
| Resultado | PASS en 67,6 s |
| Binario | `srchybrid/x64/Release/emule.exe` |
| Tamaño | 10.890.752 bytes |
| SHA-256 | `F85C254770B735AED8FEC5F18BD5A0CAF231ABB2D19E05DC4D7EB2FEDEFF5F83` |
| Log | `tools/build_logs/emule-20260716-094751.log` |

No se reconstruyeron eSE-server, DLL de idiomas ni paquete ZIP porque no forman parte del cambio P0 de core.

## 4. Baseline funcional relevante

| Pieza | Estado observado |
|---|---|
| Live Buddy Relay | Fuente/build; default OFF; gate físico pendiente. |
| Kad6 gateway TCP eD2K | Fuente/build; suites locales PASS; gates de red pendientes. |
| Kad6 UDP gateway | Enum/codecs presentes; runtime no soportado. |
| NodeIdentity | Ed25519 persistente enlazada en GUI y adaptadores Kad6. |
| KRP / EprLease / relayedge | No existen antes de P0. |
| H3/H2/WSS de producción | No existen antes de P0. |

## 5. Límites de esta evidencia

- No prueba High ID mediante relay.
- No prueba callback de servidor o conexión de peer a un edge público.
- No prueba aislamiento multi-tenant en red real.
- No certifica 30 días, HA, abuso, rendimiento ni SLO.
- No convierte claims source/build en claims públicos.

Esta baseline es la referencia de no-regresión para P0/P1.
