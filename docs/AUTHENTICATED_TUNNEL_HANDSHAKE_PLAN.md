# Plan: handshake de túnel autenticado (CREATE/CREATED v2)

> **Estado:** 🟢 spec de wire congelada (§3/§4/§5) — 2026-06-14. **IMPLEMENTADO Y ACTIVADO COMO EXPERIMENTAL** en el working tree: handshake autenticado v2 de **1 salto** (`BuildPool` → `HandleCreate_Relay` → `HandleCreated_Originator`) **y de 2 saltos** (`BuildExtend` → `HandleExtend_Relay` → `ForwardCreatedAsExtended_Relay` → `HandleExtended_Originator`). Desde K6-1A, `EmuleDlg` anuncia `ESE_CAP_TUNNEL_AUTH` únicamente cuando la identidad persistente está disponible; peers anteriores conservan v1. **Pendiente: validación en runtime** (1 salto = 2-PC; 2 saltos = 3-PC con nodos distintos — el loopback 2-PC se queda v1 a propósito). Auditoría de simetría estática transcript/HKDF (1+2 saltos): **PASA** (2026-06-14).
> **Ámbito:** plano de control del túnel onion eSE Live (`CLiveTunnel`). Convierte el ECDH
> **no autenticado** actual en un intercambio de claves **autenticado y resistente a degradación**.
> **Prerrequisito de:** cierre del agujero MITM/downgrade descrito abajo. **No toca** el plano de
> datos directo (chunks en claro) — eso es alcance de E-α (ver `V8.1.1_SPRINT_E_BREAKDOWN.md`).
>
> **Regla del repo:** este documento es la **especificación formal**. Al picar el parsing en
> `HandleCreate_Relay` / `HandleCreated_Originator`, los offsets de byte de §3 y el orden del
> transcript de §4 mandan. Cualquier desviación es un bug, no una decisión de implementación.

---

## 0. Por qué (resumen del modelo de amenaza)

El handshake actual (`LiveTunnel.cpp`) es **ntor a medias**: X25519 efímero + HKDF + ChaCha20-Poly1305
reales, pero **el `CELL_CREATED` del hop NO va firmado**. Consecuencias:

1. **Sustitución de clave (MITM activo).** Un hop intermedio (hop1 = el "rendezvous") puede
   sustituir el efímero de hop2 durante el `EXTEND` y leer/alterar la capa interna.
2. **Degradación criptográfica.** No hay binding del conjunto de capacidades negociado: un
   atacante puede forzar un modo más débil.
3. **Binding de identidad solo "lite".** `target_user_hash` comprueba *intención*, no *posesión*
   de clave privada (el `user_hash` MD4 es autoaseverado). `BuildPool` lo admite en su comentario
   (`LiveTunnel.cpp:181-183`).

**Qué cierra este plan:**

| Amenaza | Estado hoy | Con v2 |
|---|---|---|
| MITM activo sustituye clave en V↔hop2 (vía hop1) | ❌ abierto | ✅ cerrado (firma de hop2 verificada contra clave que V tiene **independiente de hop1**) |
| Downgrade de suite por manipulación de caps | ❌ abierto | ✅ cerrado (caps firmadas + atadas al HKDF) |
| Suplantación de identidad de hop (prueba de posesión) | ⚠️ solo hash | ✅ firma Ed25519 = prueba de posesión |
| Cross-circuit / cross-session replay | ⚠️ implícito | ✅ explícito (`create_nonce` 128-bit) |
| MITM pasivo de red entre V y hop1 (primer contacto) | ❌ | ⚠️ residual (TOFU/strict; sin PKI no se puede más — ver §8) |

**Invariante de anonimato (G1):** la firma es **unidireccional R→V**. V **nunca** firma ni revela
identidad persistente. Ver §4 para por qué el `UserHash` de V **no** entra en el transcript.

---

## 1. Clave de identidad de nodo (el ancla que hoy no existe)

Los hops son peers eMule arbitrarios: solo tienen `user_hash` MD4 (autoaseverado) y clave RSA de
SecureIdent (TOFU, pesada, tardía, acoplada a créditos). **No hay Ed25519 de nodo persistente.**
`CircuitHop::pub_long[32]` (`LiveCircuit.h:37`) ya está reservado para ella pero nunca se rellena.

### 1.1 Nueva clave (distinta de la per-stream del broadcaster)

- **Ed25519**, generada **una vez** en el primer arranque, **persistida entre sesiones**.
- Identifica al **nodo como relay** (la del broadcaster en `LiveCrypto.*` es per-emisión; ésta es
  per-nodo). Reutiliza `eSELive::GenerateBroadcasterKeypair / SignMessage / VerifySignature`.

```cpp
// NUEVO — NodeIdentity.h
namespace eSELive {
  const uint8_t* NodeIdentityPub();                              // 32 B, estable entre sesiones
  bool           NodeIdentitySign(const uint8_t* msg, size_t n,  // firma con la privada de nodo
                                  uint8_t sig[64]);
  void           NodeIdentityInit();                             // carga o genera+persiste al arranque
}
```

### 1.2 Persistencia multiplataforma (corrección Fase 5)

El core **no** debe atar la cripto de persistencia a la API de Windows: la Fase 5 (daemon Linux /
RPi / NAS / Docker) no tiene DPAPI. Interfaz de abstracción:

```cpp
// NUEVO — INodeIdentityStorage.h
class INodeIdentityStorage {
public:
    virtual ~INodeIdentityStorage() = default;
    virtual bool SaveKey(const uint8_t* privateKey, size_t len) = 0;   // persiste cifrada/protegida
    virtual bool LoadKey(uint8_t* out, size_t len)              = 0;   // false si no existe aún
};

// Fábrica seleccionada en build/runtime (NO #ifdef esparcido por el core):
std::unique_ptr<INodeIdentityStorage> CreateNodeIdentityStorage();
```

| Implementación | Mecanismo |
|---|---|
| `WinDpapiStorage` (`_WIN32`) | `CryptProtectData`/`CryptUnprotectData` → `<configdir>\node_identity.dat` |
| `PosixFileStorage` (Linux/macOS) | archivo plano con permisos `chmod 600` (modelo clave SSH) en `$XDG_CONFIG_HOME` / `~/.config` |

`NodeIdentityInit()` → `CreateNodeIdentityStorage()->LoadKey()`; si no existe, genera, `SaveKey()`,
y mantiene la pública en memoria. La privada **nunca** sale del proceso salvo a través del storage.

---

## 2. Asignaciones del registro de protocolo (verificadas contra los CSV)

> ⚠️ **Colisión evitada:** `0x00008000` (bit 15) **NO** está libre — ya es `ESE_CAP_HOLEPUNCH_RDV`
> (reservado, corregido desde el bit 13). Bits 15/16/17 = holepunch/keepalive/reach-v2 (design).

### 2.1 Capability bit — `CAPABILITIES.csv` (namespace CAP-ESE)

```
ESE_CAP_TUNNEL_AUTH,0x00040000,CAP-ESE,v8.x,experimental,none,"bit 18 -- authenticated tunnel handshake (CREATE/CREATED v2, Ed25519 signed). Advertised only with persistent identity.",additive,srchybrid/Opcodes.h,560
```
- **Bit 18 = `0x00040000`.** Primer bit libre tras el bloque reservado de diseño (15/16/17).
- Alternativa si se prefiere mantener caps de túnel en la zona baja: bits 6/7 (`0x40`/`0x80`) están
  libres (hueco entre M6 y PRIVACY_TUNNELING). **Decisión: bit 18**, para no fragmentar el bloque M.
- Activado en `g_uEseCapsRuntime` tras `NodeIdentityInit()`; no se anuncia si falla la identidad.

### 2.2 Tag HELLO — `TAGS.csv` (namespace TAG-ED2K)

```
TAG_ESE_NODE_PUB,0x6D,TAG-ED2K,v8.x,experimental,ESE_CAP_TUNNEL_AUTH,"32-byte Ed25519 node identity pubkey (blob); advertised next to TAG_ESE_CAPS",additive-ignorable,srchybrid/BaseClient.cpp,741
```
- **`0x6D` verificado libre** (0x66–0x6C ocupados; 0x6D el siguiente).
- Blob de 32 B vía `CTag`, adyacente a `TAG_ESE_CAPS (0x6C)`.

### 2.3 Cell commands

**Sin opcodes nuevos.** `CELL_CREATE (0x01)` / `CELL_CREATED (0x02)` / `CELL_EXTEND (0x03)` /
`CELL_EXTENDED (0x04)` se mantienen; v2 se detecta por **longitud de payload + marca de versión**
(§3). Esto preserva compat con v8.0/v8.1 a nivel de opcode.

### 2.4 Constantes de dominio (no son números de wire, pero se congelan aquí)

| Constante | Valor |
|---|---|
| Marca de versión CREATE v2 | ASCII `"EAU2"` (4 B) + `ver = 0x02` (1 B) |
| Label transcript | `"ese-tun-created-v2"` (18 B, sin NUL) |
| Label HKDF V→R | `"ese-tunnel-V-to-R-v2"` |
| Label HKDF R→V | `"ese-tunnel-R-to-V-v2"` |
| `create_nonce` | 16 B (128 bit) de `SecureRandomBytes` |

---

## 3. Formatos de wire (byte-exactos)

> Todos los enteros multi-byte **little-endian**, consistente con la convención de celda existente
> (`LiveCellQueue.h`). Los payloads de celda son **layouts crudos** (`memcpy` en `CellPack`), **no**
> `CSafeMemFile`. Offsets relativos al inicio del payload de celda (tras la cabecera de 7 B).

### 3.1 `CELL_CREATE` v2 (V→R) — 69 B

| Offset | Tam | Campo | Notas |
|---|---|---|---|
| 0 | 32 | `ev_pub` | X25519 efímero de V | (igual que v1)
| 32 | 16 | `target_user_hash` | hash del hop esperado | (igual que v1)
| 48 | 4 | `magic` = `"EAU2"` | inicio del sufijo v2 |
| 52 | 1 | `ver` = `0x02` | |
| 53 | 16 | `create_nonce` | 128-bit, único por CREATE |

**Compat:** un peer v1 parsea `[0..31]`+`[32..47]` e **ignora el sufijo** (confirmado por el
comentario de `BuildPool`: *"Old fork binaries... parse the first 32B as ev_pub and ignore the rest"*).
`HandleCreate_Relay` ya acepta 32 B y 48 B (`LiveTunnel.cpp:461,470`).

### 3.2 `CELL_CREATED` v2 (R→V) — 133 B

| Offset | Tam | Campo | Notas |
|---|---|---|---|
| 0 | 1 | `ver` = `0x02` | distingue de v1 (32 B sin `ver`) |
| 1 | 32 | `er_pub` | X25519 efímero de R |
| 33 | 32 | `node_pub` | Ed25519 de identidad de R |
| 65 | 4 | `signed_caps` | `g_uEseCapsRuntime` real de R |
| 69 | 64 | `sig` | `Ed25519(node_priv, TRANSCRIPT)` (§4) |

**Detección:** `payloadLen >= 133 && payload[0] == 0x02` ⇒ v2; si no, v1 (`er_pub` crudo de 32 B).

### 3.3 `CELL_EXTEND` v2 (V→hop1, plaintext tras pelar) — 71 B

Extiende el `extendPlain` de 54 B actual (`LiveTunnel.cpp:797`):

| Offset | Tam | Campo |
|---|---|---|
| 0 | 4 | `hop2_ip` (LE) |
| 4 | 2 | `hop2_port` (LE) |
| 6 | 32 | `ev_pub2` (X25519 efímero V↔hop2) |
| 38 | 16 | `hop2_user_hash` |
| 54 | 1 | `ver` = `0x02` |
| 55 | 16 | `create_nonce2` (nuevo, para el tramo hop2) |

hop1 reenvía a hop2 un `CELL_CREATE` v2 (§3.1) construido a partir de estos campos.

### 3.4 `CELL_EXTENDED` v2 (hop2→hop1→V)

`CREATED v2` de hop2 (133 B) **envuelto una capa** con `k_send` de hop1 → `133 + 16 (tag) = 149 B`
de ciphertext. Cabe en `CELL_PAYLOAD_MAX (505)`. V lo pela con hop1 (`OnionPeelOne`) y verifica
`sig` contra el **`node_pub` de hop2 que V ya posee** (§7.3).

---

## 4. El transcript firmado (congelado)

Serialización: **concatenación de campos de ancho fijo** (no hace falta length-prefix; todos los
campos son fijos), con el label de dominio como prefijo de longitud fija. Idéntica en firmante y
verificador.

```
TRANSCRIPT (150 B) =
    "ese-tun-created-v2"   18 B   // separación de dominio
  ‖ ev_pub                 32 B   // efímero de V  -> ata key-substitution + identidad EFÍMERA de A
  ‖ er_pub                 32 B   // efímero de R
  ‖ signed_caps             4 B   // LE — ata el DOWNGRADE
  ‖ create_nonce           16 B   // 128-bit -> ancla anti-replay (cross-circuit, cross-session, sesión)
  ‖ target_user_hash       16 B   // hash del hop (B), ata la identidad RECLAMADA del destino
  ‖ node_pub               32 B   // clave de verificación, atada explícitamente
```

> **`circ_id` NO va en el transcript** (corrección de implementación 2026-06-14): es **per-tramo** — en
> el EXTEND, hop1 elige un `outId` nuevo para el tramo hop1↔hop2, así que firmante (hop2, con `outId`) y
> verificador (V, con su `circ->Id()`) discreparían → la firma **siempre** fallaría en 2 saltos. El ancla
> de sesión es `create_nonce`, que **sí** es consistente por tramo (V lo acuña y se reenvía intacto).
>
> Helper único `BuildCreatedTranscript(ev_pub, er_pub, signed_caps, create_nonce, target_hash,
> node_pub, out)` — usado **idéntico** por relay (firmar) y originador (verificar) y por ambos tramos
> (CREATE y EXTEND). Una sola función ⇒ imposible desalinear offsets entre extremos.

### 4.1 Por qué NO va el `UserHash` del originador A (decisión, no omisión)

- El transcript lo **firma el relay**; para incluir el hash de A, el relay tendría que **conocerlo**.
  Para hop2 (exit) eso **viola G1** (el exit nunca debe saber quién es V).
- El transcript debe ser **uniforme** entre hop1 y hop2 (misma función) ⇒ excluir el hash de A es la
  única opción coherente; lo contrario reintroduce justo las desalineaciones de offset que tememos.
- **El binding de A correcto ya está presente y es el deseable:** `ev_pub` (efímero, por circuito) +
  `create_nonce` (128-bit, único). Ambos son **no-vinculables** — un identificador persistente sería
  un **correlador** que el exit usaría para ligar circuitos del mismo V en el tiempo.

### 4.2 Anti-replay (responde formalmente a la pregunta de cross-circuit replay)

- **Ancla = `create_nonce`.** `circ_id` colisiona/se reutiliza tras reinicio rápido **y es per-tramo**,
  por eso **NO entra en el transcript**; el `create_nonce` (128-bit, consistente por tramo) es la única
  base anti-replay.
- Un `CREATED` replayado de otra sesión lleva *otro* `create_nonce` firmado; V verifica con *su*
  nonce → mismatch → descarte. Dos circuitos no pueden compartir transcript (difieren en `ev_pub` y
  `create_nonce`), así que el replay cross-circuit es imposible aun con colisión de `circ_id`.
- **Replay de CREATE hacia el relay:** inocuo (el relay genera `er_priv` fresco ⇒ claves distintas;
  responde a quien envió, no a V). Acotado además por el admission gate (`LiveTunnel.cpp:540+`).
- **Hardening opcional (no en transcript):** caché de `create_nonce` vistos en el relay (TTL ~60 s)
  para tirar CREATEs duplicados; handle de dedup `circ_tag = SHA256(ev_pub ‖ create_nonce)[:8]`.

---

## 5. Derivación de claves v2 (binding de transcript en HKDF)

Sustituye el HKDF de `HandleCreated_Originator:398-404` y `HandleCreate_Relay:503-507` cuando v2:

```
salt = create_nonce            (16 B)
ikm  = X25519_shared           (32 B)
info(V→R) = "ese-tunnel-V-to-R-v2" ‖ ev_pub ‖ er_pub ‖ signed_caps ‖ node_pub   // sin circ_id (per-tramo)
info(R→V) = "ese-tunnel-R-to-V-v2" ‖ ev_pub ‖ er_pub ‖ signed_caps ‖ node_pub
k_send / k_recv = HKDF(ikm, salt, info)[0..31]
```

**Doble candado:**
- **Firma Ed25519** = autenticación (R prueba posesión de `node_priv`; un MITM activo no la forja ⇒
  no puede sustituir clave). *Necesaria*: el HKDF-binding solo no detiene un proxy-MITM que corre dos
  handshakes.
- **Transcript en HKDF** = commitment: si *cualquier* campo difiere entre extremos (p.ej. el MITM
  tocó `signed_caps`), derivan claves distintas y la **primera celda AEAD destruye el circuito**.
  Mata downgrade y cross-session replay aunque la verificación de firma tuviera un hueco.

---

## 6. Versionado de circuito (cap por-hop)

Añadir a `CLiveCircuit` (`LiveCircuit.h`, junto a `m_multicell_ok` / `m_bulk_ok`):

```cpp
bool m_auth_ok = false;   // true si TODOS los hops completaron el handshake v2 autenticado
```
Sembrar en `BuildPool` desde `hop1->GetEseCapabilities() & ESE_CAP_TUNNEL_AUTH`; AND con hop2 en
`BuildExtend` (igual patrón que `m_bulk_ok`). Expuesto en el panel / `/api/live/privacy/*`.

---

## 7. Máquina de estados y hooks (file:line)

Principio: **verificar ANTES de derivar/comprometer estado.** Si la firma falla → directo a
`Destroyed`, nunca pasa por `Active` ⇒ el circuito jamás entra en la rotación de envío con claves
sin autenticar.

### 7.1 Emisión (BuildPool `:175-196`, BuildExtend `:793-813`)
Enviar forma v2 si el hop anuncia `ESE_CAP_TUNNEL_AUTH`. Guardar en el circuito: `m_ephemeral_pub`,
`m_create_nonce`, `m_expectedNodePub`/`m_expectedHash` (pin del hop, leídos del `CUpDownClient`).

Campos nuevos en `CLiveCircuit`:
```cpp
uint8_t m_ephemeral_pub[32]  = {0};   // V necesita SU ev_pub para el transcript (hoy solo guarda priv)
uint8_t m_create_nonce[16]   = {0};
uint8_t m_expectedNodePub[32]= {0};   bool m_expectedNodePubSet = false;
uint8_t m_expectedHash[16]   = {0};
```

### 7.2 Firmar — `HandleCreate_Relay` (`:457-538`)
Tras los checks baratos (longitud, `target_user_hash` `:489`) y la verja anti-flood (`:540+`),
**y solo entonces** el X25519+firma:
```cpp
bool v2 = (payloadLen >= 69 && memcmp(payload+48,"EAU2",4)==0 && payload[52]==0x02);
const uint8_t* create_nonce = v2 ? payload+53 : nullptr;
// 491-499 sin cambios (X25519GenerateKeypair + SharedSecret)
// HKDF: v2 -> §5 (transcript-bound); v1 -> labels actuales
if (v2) {
    uint8_t tr[146]; BuildCreatedTranscript(circId, viewerPub, erPub, g_uEseCapsRuntime,
                                            create_nonce, thePrefs.GetUserHash(),
                                            eSELive::NodeIdentityPub(), tr);
    uint8_t sig[64]; eSELive::NodeIdentitySign(tr, sizeof tr, sig);   // ~60 µs, acotado por la verja
    // empaqueta CREATED v2 (§3.2) -> CellPack(CELL_CREATED)
} else {
    // rama v1 actual intacta (532-536) -> red mixta viva
}
```

### 7.3 Verificar — `HandleCreated_Originator` (`:384-451`) y `HandleExtended_Originator` (`:1069-1123`)
```cpp
bool v2 = (payloadLen >= 133 && payload[0] == 0x02);
if (theApp.IsTunnelAuthStrict() && !v2) { circ->SetState(Destroyed); return false; }
if (v2) {
    const uint8_t* er_pub=payload+1,*node_pub=payload+33,*sig=payload+69;
    uint32_t signed_caps = PeekUInt32LE(payload+65);
    // (1) pin: node_pub == clave del hop esperado (de SU HELLO, indep. de hop1)
    if (!circ->m_expectedNodePubSet || memcmp(node_pub,circ->m_expectedNodePub,32)!=0) {
        if (theApp.IsTunnelAuthStrict()) { circ->SetState(Destroyed); return false; }
        // default/mixto: TOFU (fija ahora, alarma si cambia)
    }
    // (2) suelo de caps
    if (theApp.IsTunnelAuthStrict() && !(signed_caps & ESE_CAP_TUNNEL_AUTH)) {
        circ->SetState(Destroyed); return false; }
    // (3) VERIFICAR antes de cualquier HKDF/AddHop — short-circuit total
    uint8_t tr[146]; BuildCreatedTranscript(circ->Id(), circ->m_ephemeral_pub, er_pub,
        signed_caps, circ->m_create_nonce, circ->m_expectedHash, node_pub, tr);
    if (!eSELive::VerifySignature(node_pub, tr, sizeof tr, sig)) {
        circ->SetState(Destroyed); return false;   // 0 estado comprometido, 0 ECDH gastado
    }
    memcpy(hop.pub_long, node_pub, 32);   // rellena el campo reservado desde F4
}
// solo si pasó: HKDF v2 (§5) + AddHop + SetState(Active)
```
`HandleExtended_Originator` es idéntico pero `node_pub` se contrasta contra el **pin de hop2** →
**este es el hook que neutraliza a hop1 como rendezvous malicioso** (V tiene la clave de hop2 por su
propio HELLO con hop2, no por hop1).

### 7.4 Latencia (por qué el streaming no se entera)
- La verificación está en la **construcción del circuito**, no en el camino de datos. Pool de 3-5
  circuitos, rotación 5 min (`TUNNEL_ROTATION_BASE_MS`). 1 `VerifySignature` ≈ **50-60 µs**, **una
  vez por hop y construcción** (~6-10 por pool cada 5 min). El cifrado por celda sigue siendo **solo
  AEAD**. Cero cripto asimétrica en el camino caliente.
- *Make-before-break* (`BuildSuccessorCircuit`) construye el reemplazo mientras el viejo entrega
  datos ⇒ la rotación también esconde el verify. A 12000 kbps el flujo no percibe nada.
- La verificación **gobierna `Pending → Active`**; fallo ⇒ `Destroyed` (nunca entra en rotación).

---

## 8. Compatibilidad hacia atrás y suelo de degradación

Tri-modo (espejo de `IsCryptLayerRequired` / `...Strict` de eMule). Nuevo `theApp.IsTunnelAuthStrict()`
en `Preferences`:

| Modo | v2 | v1 (legacy/downgrade) | Uso |
|---|---|---|---|
| **Off** | — | — | sin túneles |
| **Default (mixto)** | se intenta siempre | se acepta (TOFU) | red real con nodos viejos |
| **Strict-Auth** | obligatorio | **rechazo → Destroyed** | despliegue eSE puro / paranoia |

- **CREATE v2 es wire-compatible** (sufijo ignorado por legacy) ⇒ V lo envía a todos; la **forma de
  la respuesta** (v1 32 B sin firma vs v2 133 B firmada) le dice qué obtuvo.
- **Ataque legacy-spoof (el que preguntaste):** un MITM quita `ESE_CAP_TUNNEL_AUTH` del HELLO y/o
  trunca el sufijo del CREATE ⇒ R responde v1 sin firma. V (que esperaba firma) lo **detecta**; solo
  **Strict-Auth lo bloquea**. Honestidad: en red mixta **no se puede ser default-on Y a prueba de
  downgrade sin un ancla de confianza** (mismo límite que la ofuscación clásica). Mitigaciones sin
  coste (coherentes con "100% gratis, sin dominios"):
  1. **TOFU por identidad** (caché DPAPI/POSIX): visto un `node_pub` hablando v2, recordar; reaparición
     sin AUTH ⇒ alarma/rechazo. Cierra todo menos el primerísimo contacto.
  2. **Anclar la señal de capacidad en identidad comprometida:** la *presencia* de `TAG_ESE_NODE_PUB`
     implica AUTH; meter `node_pub` en el **registro Kad firmado** del stream para que la selección de
     hop2 se comprometa con su clave (el MITM no puede a la vez mantener la creencia de "es hop2" y
     quitar AUTH).
  3. **Strict-Auth** para garantía dura.

---

## 9. Despliegue por fases

- **Fase 1 — identidad de nodo (prerrequisito, no toca handshake).** `INodeIdentityStorage` + impls
  Win/POSIX + `NodeIdentity.*` + cap bit `0x00040000` + `TAG_ESE_NODE_PUB 0x6D` (enviar/parsear en
  `BaseClient.cpp`, almacenar en `CUpDownClient::m_eseNodePub`). Validable solo: dos nodos se ven el
  `node_pub` en el panel. **Tiro limpio una vez congelado este doc.**
- **Fase 2 — firmar/verificar CREATE/CREATED v2** (1-hop): §7.2 + §7.3 (rama CREATED) + §3.1/3.2 +
  §4 + §5. Validar 2-PC: circuito 1-hop autenticado, `m_auth_ok=true`.
- **Fase 3 — EXTEND/EXTENDED v2** (2-hop): §3.3/3.4 + `HandleExtended_Originator`. Validar 3-PC: el
  cierre del rendezvous malicioso (hop1 no puede MITM V↔hop2).
- **Fase 4 — suelo + TOFU + Strict-Auth** (§8) + entradas Kad firmadas (§8.2).

Tras cada fase: actualizar los CSV del registro + pasar `tools/check_protocol_registry.py`.

---

## 10. Pendientes / verificación

- [ ] Registrar las filas de §2 en `CAPABILITIES.csv` / `TAGS.csv` y pasar el linter.
- [ ] Extender el modelo **ProVerif** (`docs/audit/proverif/`) con la firma + transcript-binding;
      probar la propiedad de autenticación del exit y la no-degradación.
- [ ] Decidir formato exacto del blob `TAG_ESE_NODE_PUB` vía `CTag` (string/blob de 32 B).
- [ ] `circ_tag` de dedup y caché de `create_nonce` en relay: ¿necesarios a escala? (medir).
- [ ] Confirmar coste real de `VerifySignature` en el x64 objetivo (presupuesto 50-60 µs).

---

## Archivos a tocar (resumen)

| Archivo | Cambio |
|---|---|
| `NodeIdentity.h/.cpp`, `INodeIdentityStorage.h`, `*Storage.cpp` *(nuevos)* | clave de nodo + persistencia multiplataforma |
| `Opcodes.h` | `ESE_CAP_TUNNEL_AUTH 0x00040000`; `TAG_ESE_NODE_PUB 0x6D` |
| `EmuleDlg.cpp:1002` | encender cap en `g_uEseCapsRuntime` |
| `BaseClient.cpp` `:626`, `:1168` | parsear/enviar `TAG_ESE_NODE_PUB` |
| `UpdownClient.h` | `m_eseNodePub[32]` + accessor + `SupportsEseTunnelAuth()` |
| `LiveCircuit.h` | `m_auth_ok`, `m_ephemeral_pub`, `m_create_nonce`, `m_expectedNodePub`, `m_expectedHash` |
| `LiveTunnel.cpp` | v2 en BuildPool/BuildExtend; firmar en HandleCreate_Relay; verificar en HandleCreated_/HandleExtended_Originator; HKDF v2; `BuildCreatedTranscript` |
| `Preferences.*` | `IsTunnelAuthStrict()` (tri-modo) |
| `docs/protocol/*.csv` + linter | registrar cap/tag |
