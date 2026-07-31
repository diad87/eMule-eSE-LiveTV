# Estado de la matriz eSE 9.1 — instantánea declarada

Fecha de la instantánea: **2026-07-31**.
Fuente normativa: `docs/V9_RELEASE_SPECIFICATION.md`, sección 8.6 (27 casos).

## Naturaleza de este documento

Este es un **estado declarado por el operador** de la campaña local. El ledger
hash-bound (`ese.v91.rc-ledger/v2`, con `results_sha256` y los SHA-256 de la
candidata exacta) todavía no se ha subido al remoto; hasta que se publique,
este documento no sustituye la evidencia formal ni modifica ninguna decisión
de gate. El último ledger publicado en el remoto es
`docs/V91_RC2_CASE_RESULTS.json` en la rama `fix/v91-ai-i03`
(9.1.0-rc.2, 2026-07-28: 11 PASS / 16 BLOCKED, `NO_GO`).

## Recuento declarado

| Total | PASS | FAIL | BLOCKED |
|---|---|---|---|
| 27 | **21** | 0 | 6 |

## Estado por caso

| ID | Estado | Nota |
|---|---|---|
| `V91-A01` | PASS | |
| `V91-A02` | PASS | |
| `V91-I01` | PASS | |
| `V91-I02` | PASS | |
| `V91-I03` | BLOCKED | Harness solo ejecutable con topología física pública |
| `V91-I04` | BLOCKED | Harness solo ejecutable con topología física pública |
| `V91-I05` | PASS | Campaña física desatendida (eSE Lab Agent) |
| `V91-I06` | PASS | Overlay `T6` |
| `V91-I07` | BLOCKED | Requiere hotspot/tethering (`T3`) |
| `V91-I08` | PASS | |
| `V91-D01` | BLOCKED | Harness solo ejecutable con topología física pública |
| `V91-P01` | PASS | |
| `V91-P02` | PASS | |
| `V91-P03` | PASS | |
| `V91-K01` | PASS | |
| `V91-K02` | PASS | |
| `V91-K03` | PASS | |
| `V91-K04` | PASS | |
| `V91-C01` | PASS | |
| `V91-C02` | PASS | |
| `V91-C03` | PASS | |
| `V91-C04` | PASS | |
| `V91-S01` | PASS | |
| `V91-S02` | PASS | |
| `V91-S03` | PASS | |
| `V91-R01` | BLOCKED | Requiere hotspot/tethering (`T3`) |
| `V91-O01` | EN CURSO | Soak sano al 64,1 % en el momento de la instantánea; formalmente BLOCKED hasta completar |

## Trabajo offline completado sobre los casos bloqueados

Todo lo ejecutable sin la topología pública ya se ha ejecutado:

- `I03`, `I04` y `D01`: parser PowerShell — PASS.
- Configuración efectiva — PASS 6/6.
- Regresiones C++ de selección, fallback y DNS — PASS.
- Contrato JavaScript A+AAAA de `D01` — PASS.

Estos resultados validan los harnesses y las políticas, pero no producen un
PASS formal de los casos: `I03`, `I04` y `D01` solo pueden adjudicarse con la
topología física pública.

## Próximo trabajo offline

Crear baterías deterministas completas para dejar los tres harnesses
preparados al estilo `R01`/`I07` (listos para ejecutar cuando exista la
topología):

1. **`I03`** (primero: el más barato y base de `I04`): selección Auto=IPv4 y
   Preferred=IPv6, evidencias, cleanup y adjudicación.
2. **`I04`**: fallback único, límites 2,75/8/10 s, firewall y rollback.
3. **`D01`**: DNS A+AAAA, PCAPNG, correlación PID/tupla y privacidad.

## Pendiente para que este estado sea formal

1. Publicar en el remoto el ledger hash-bound actualizado
   (`V91_RC*_CASE_RESULTS.json`) y su documento de ejecución.
2. Completar el soak `O01` y archivar sus tres monitores bajo la identidad de
   la candidata exacta.
3. Reevaluar el gate 8.7 con la matriz publicada; los 6 casos restantes
   dependen únicamente de topología (`T1/T2` pública, `T3` hotspot), no de
   defectos: no hay ningún FAIL declarado.
