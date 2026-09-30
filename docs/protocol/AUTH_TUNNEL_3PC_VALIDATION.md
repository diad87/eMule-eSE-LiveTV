# Receta de validación 3-PC — handshake de túnel autenticado (CREATE/CREATED v2)

> **Estado:** 🧪 receta lista — actualizada 2026-07-15. Valida en runtime el handshake v2
> experimental que describe [`../AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md`](../AUTHENTICATED_TUNNEL_HANDSHAKE_PLAN.md).
> **Qué certifica:** (A) el camino feliz autenticado de 1 y 2 saltos; (B) que el **rogue relay**
> (hop1 manipulando el tramo hacia hop2) dispara el cortocircuito **verify-before-derive**, no un
> timeout de red. Auditoría estática (compila + simetría transcript/HKDF): **PASA**. Falta runtime.

---

## 0. Prerrequisitos

- **3 PCs / 3 IPs distintas** — `V` (originador), `hop1` (relay), `hop2` (exit). El loopback 2-PC se
  queda **v1 a propósito** (test-only, cero anonimato), así que el 2-salto autenticado **exige nodos
  distintos**. El 1-salto autenticado se puede validar con 2 PCs (`V` + `hop1`).
- Build **Release x64 fuera de OneDrive** (los locks de sync rompen el build paralelo; usar serie).
- Los 3 nodos deben **verse como peers del fork** (intercambian HELLO con `TAG_ESE_NODE_PUB 0x6D`).
  Sin overlay público, usar la muleta de test (Tailscale 100.x / LAN) para que se conecten.

### 0.1 Verificación de activación

1. Confirmar en cada nodo que `NodeIdentityInit()` tuvo éxito y que `TAG_ESE_CAPS` contiene
   `ESE_CAP_TUNNEL_AUTH=0x00040000`. No hace falta editar código: K6-1A ya lo activa de forma
   condicional. Si falla la identidad, el nodo no anuncia AUTH y conserva v1.
2. **Strict (test opcional, no requerido para el sabotaje):** sin pref/UI aún → en el build de test,
   `eSELive::SetTunnelAuthStrict(true)` junto a `NodeIdentityInit()`. Los checks de **pin y firma
   abortan SIEMPRE** (no van gated por strict), así que el rogue-relay test funciona en **Mixto**.
3. Hacerlo en un **build de test aislado**, NO sobre el binario del plano de control Sprint Z validado.

---

## 1. Topología

```
   Originador (V)            Relay (hop1)             Exit (hop2)
        │                        │                        │
        ├──── CELL_CREATE v2 ───►│  (V↔hop1)               │
        │◄─── CELL_CREATED v2 ───┤  firma Ed25519 de hop1  │
        │                        │                        │
        ├──── CELL_EXTEND v2 ───►│  (opaco; nonce2 dentro) │
        │                        ├──── CELL_CREATE v2 ────►│  firma Ed25519 de hop2
        │                        │◄─── CELL_CREATED v2 ────┤  (ver|er_pub2|node_pub2|caps|sig2)
        │◄─── CELL_EXTENDED ─────┤  (133B envueltos→149B)  │
        │   verify-before-derive contra el pin de hop2     │
```
Cada celda viaja en un envoltorio **fijo de 512B** (relleno por `CellPack`), así que el demux de
`ListenSocket` (que exige `size==512`) es ciego al tamaño útil. La verificación de hop2 usa el
`node_pub` que **V cosechó del HELLO directo con hop2**, no de hop1.

---

## 2. curl (loopback, puerto 4711 del webserver C++ en cada nodo)

> El gate del webserver es loopback-only; ejecuta los curl **en la propia máquina** del nodo.

```sh
# Modo de privacidad (debe ser Tunneled o Adaptive para construir circuitos):
curl -s "http://127.0.0.1:4711/api/live/privacy?mode=Tunneled"

# Construir un circuito de prueba de 2 saltos (en V):
curl -s "http://127.0.0.1:4711/api/live/privacy/test_circuit?hops=2"
#   -> {"ok":true,"circuit_id":"0x........"}   ó   {"ok":false,"reason":"..."}

# Listar circuitos + su columna Auth (en V), repetir tras ~1-2 s:
curl -s "http://127.0.0.1:4711/api/live/privacy/circuits"
#   -> {"total":N,"circuits":[{"circ_id":"0x..","state":"Active","hop_count":2,
#       "forwarding":false,"next_circ_id":"0x..","auth_ok":true}, ...]}
```

El panel web (ese-server, puerto 8080) muestra los mismos circuitos con la columna **`Auth`**:
`v2` (ambos saltos verificados) · `v2…` (extendiendo, hop1 verificado) · `v1` (degradado) · `—` (relay/pending).
*(La columna requiere reconstruir `ese-server.exe` con `npm run build`; el dato `auth_ok` ya está en el JSON del 4711.)*

---

## 3. Test A — Camino feliz (Mixto)

1. En los 3 nodos: modo `Tunneled`/`Adaptive`, cap AUTH encendida, conectados como peers del fork.
2. En `V`: `test_circuit?hops=2` (o el botón del panel) eligiendo hop1+hop2 distintos.
3. **PASS** en el log de `V`:
   ```
   LiveTunnel: v2 AUTH SUCCESS both hops circ=0x........ (handshake complete and verified)
   ```
   y en `circuits`: el circuito en `"state":"Active"` con **`"auth_ok":true`** (panel: `Auth = v2`).
   **No** debe aparecer ninguna línea `AUTH-ABORT` ni `REAP` para ese `circ_id`.

---

## 4. Test B — The Rogue Relay (el corazón de la Fase 2)

Sabotaje controlado: hop1 manipula el efímero de hop2 → la firma de hop2 deja de cuadrar en `V`.

1. **Build "rogue hop1":** en `srchybrid/LiveTunnel.cpp`, dentro de `HandleExtend_Relay` (rama de
   reenvío de producción), **justo antes** de construir `fwdPayload`, corrompe el efímero:
   ```cpp
   evPub2[0] ^= 0xFF;   // SABOTAJE DE TEST — hop1 altera el ev_pub2 de hop2 (quitar tras la prueba)
   ```
   hop2 firmará el `ev_pub2` corrupto; `V` reconstruye el transcript con su `m_ephemeral_pub2` real.
2. Repite Test A con este hop1 saboteado.
3. **PASS** en el log de `V` — **inmediato** al llegar la EXTENDED:
   ```
   LiveTunnel: v2 AUTH-ABORT hop2 circ=0x........ reason=SIG_FAIL (exit Ed25519 verify-before-derive tripped — hop1 tampered ev_pub2 or forged CREATED)
   ```
   El circuito pasa a `Destroyed`, **sin** plano de datos, **sin** `REAP ... EXTEND_TIMEOUT`.
4. **Variante PIN_MISMATCH** (prueba el pin de identidad): un hop1 que responda con su **propio**
   CREATED v2 (firmado como hop1) en vez de reenviar a hop2 → `reason=PIN_MISMATCH`.

---

## 5. Matriz de diagnóstico (cómo distinguir rechazo-cripto de timeout)

Las trazas son **mutuamente excluyentes** en texto, origen y timing. En el log de `V`:

| Observación | Línea | Origen / timing | Veredicto |
|---|---|---|---|
| Éxito 2-salto | `v2 AUTH SUCCESS both hops circ=…` | síncrono, al verificar hop2 | ✅ handshake completo |
| Éxito 1-salto | `v2 AUTH SUCCESS 1-hop circ=…` | síncrono | ✅ (config 1-salto) |
| **Rechazo cripto** | `v2 AUTH-ABORT hop2 circ=… reason=SIG_FAIL` | **síncrono**, al llegar la EXTENDED (sin `age`) | ✅ muro funciona |
| Suplantación de identidad | `v2 AUTH-ABORT hop2 circ=… reason=PIN_MISMATCH` | síncrono | ✅ pin funciona |
| Downgrade en strict | `v2 AUTH-ABORT … reason=STRICT_V1` / `CAPS_FLOOR` | síncrono | ✅ suelo funciona |
| **Timeout de red** | `circ=… REAP reason=EXTEND_TIMEOUT (… age=~12800 ms)` | **diferido**, desde `Tick()` | ⚠️ celda perdida → reintenta |

**Clave:** `SIG_FAIL` **solo se emite tras recibir + pelar + fallar la verificación** de la celda
(el código no llega a `VerifySignature` si la celda no llegó). Por tanto su presencia **prueba**
matemáticamente que la EXTENDED llegó y fue rechazada por cripto, **no** por la red. Un timeout
produce `REAP … EXTEND_TIMEOUT` y **ninguna** `AUTH-ABORT`. Greps:

```sh
grep "AUTH SUCCESS"  emule-debug.log    # camino feliz
grep "AUTH-ABORT"    emule-debug.log    # rechazos (reason=SIG_FAIL/PIN_MISMATCH/CAPS_FLOOR/STRICT_V1)
grep "REAP reason"   emule-debug.log    # bajas por timeout (NO son rechazo cripto)
```

---

## 6. Notas

- El handshake v2 está **dormante** hasta el paso 0.1; con la cap apagada, `BuildPool` emite v1 →
  cero cambio de comportamiento (protege el plano Sprint Z validado).
- El **loopback 2-PC se queda v1** (test-only); por eso el 2-salto autenticado se valida con 3 nodos.
- La columna `Auth` del panel necesita `ese-server.exe` reconstruido (`npm run build`); el `auth_ok`
  del endpoint 4711 ya está disponible sin rebuild.
- Quitar el `evPub2[0] ^= 0xFF` del build de hop1 tras la prueba.
