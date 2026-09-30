# Relay/KRP — P1, incremento 1

| Campo | Resultado |
|---|---|
| Fecha | 2026-07-16 |
| Estado | `source/build-complete` para REL-100 y el envelope de REL-102 |
| Wire KRP | Desactivado |
| Public mode | Desactivado |
| Gate G1 | Abierto; todavía no superado |

## Alcance entregado

- `RelayByteReader` y `RelayByteWriter` MFC-free, sin sockets y con acceso siempre acotado.
- Varints unsigned LEB128 de 64 bits con representación canónica.
- Rechazo de input truncado, overlong y mayor de 64 bits sin modificar el valor de salida.
- Envelope de control `type | flags | payload_length | payload`, todos los campos de cabecera como varint.
- Límite duro de payload de control de 64 KiB comprobado antes de reservar memoria.
- Lista cerrada de los 23 tipos reservados en `KRP_MESSAGES.csv`.
- Rechazo fail-closed de tipos y flags desconocidos en este incremento.
- Decodificación incremental: consume exactamente un frame y deja los bytes siguientes al parser de stream.
- Salidas transaccionales: un fallo no reemplaza el buffer del encoder y reinicia frame/`consumed` en el decoder.

El rechazo de todo tipo desconocido es deliberadamente más estricto que una futura negociación de
extensiones. REL-103 deberá distinguir extensiones críticas e ignorables solo después de autenticar y
negociar capacidades; hasta entonces no se acepta ninguna.

## Evidencia reproducible

Comandos:

```powershell
& .\librelaycore\make.bat
$env:RELAY_ASAN='1'; & .\librelaycore\make.bat; Remove-Item Env:RELAY_ASAN
python .\tools\check_protocol_registry.py
& .\relayedge\make.bat
```

Resultados Release (`/O2 /W4 /WX`):

```text
test_relay_core: 6 passed, 0 failed
deterministic fuzz: 100000 inputs, 1042 valid frames
test_krp_control: 7334 passed, 0 failed
```

Los mismos 7.340 checks y las 100.000 entradas se ejecutaron con MSVC AddressSanitizer
(`/Od /Zi /fsanitize=address`) sin error.

Registro:

```text
protocol registry: 154 entries, 137 fork symbols in code
OK: registry is internally consistent and matches code.
```

El linter incluye ahora `librelaycore/include/relay/krp_control.h`: un cambio de valor o un nuevo
`KRP_*` sin fila registrada deja el gate en rojo.

## Estado de tickets P1

| Ticket | Estado del incremento |
|---|---|
| REL-100 | DONE. Cursor acotado, varints canónicos y checks previos a allocation. |
| REL-102 | DONE para el envelope común y mapping; los payloads tipados llegarán con sus state machines. |
| REL-107 | PARTIAL. Golden/adversarial, fuzz determinista y ASan del código entregado. |
| REL-101 | PENDIENTE. Transcript y hook de firma `NodeIdentity`. |
| REL-103 | PENDIENTE. State machine `Session`, epochs y replay. |
| REL-104 | PENDIENTE. State machine `Flow`, pressure y presupuesto. |
| REL-105 | PENDIENTE. `EprLease`, generation, probe, drain y revoke. |
| REL-106 | PENDIENTE. Autoridad/tickets por servicio. |

## Frontera de seguridad

Este incremento no enlaza `librelaycore` con eMule, no abre listener, no crea conexiones y no activa
opcodes. `relayedge` continúa siendo un scaffold fail-closed: solo `--self-test` y `--version` pueden
terminar con éxito. La activación de un carrier sigue bloqueada por P0b/G-HID y por los gates de P2.

El siguiente incremento de P1 debe implementar primero REL-103 (sesión/epoch/replay) y después
REL-101 (transcript autenticado), reutilizando `NodeIdentity` mediante una interfaz de firma sin
trasladar claves privadas al edge.
