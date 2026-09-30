# `ReachHostAdapter` — integration plan (libreach ⇄ eMule host)

**Status:** design, NOT applied to the live MFC tree. This is the executable spec
("rail") for wiring the standalone, verified `libreach` (KEP-1 L1+L2+L3, 190
checks green, `/W4`) into eMule's `CUpDownClient`/Kad world. See
[`libreach/README.md`](../libreach/README.md) and `THESIS_KAD_SIN_LOWID.md` §7/§13.

**Scope of THIS document:** the adapter translation unit (`ReachHostAdapter.{h,cpp}`),
its C-ABI binding, the lifecycle/identity model, the HELLO ingest transaction, the
byte-order conversion rules, the gating switch, and the build wiring. Out of scope:
L4 punch/relay payload encoding (the adapter only *dispatches* a chosen layer to
the host; the punch bytes are L4) and any change to the cascade itself.

**Why a doc first:** the adapter touches live MFC classes (`CUpDownClient`,
`CClientList`, `theApp`) under a heavy global build with concurrent WIP. A link
error or an FFI type mismatch would stall the whole tree. This spec is the
surgical-injection manual so the edit is mechanical and reviewable.

---

## 0. Design invariants (inherited from `reach.h`, non-negotiable)

1. **No host pointer is ever stored by libreach.** The only host pointer it keeps
   is the context cookie (`this`, the adapter), whose lifetime outlives the context.
2. **Identity is a stable 16-byte hash, never a `CUpDownClient*`.** The adapter maps
   `reach_peer_id ↔ user-hash` and resolves the live client **at call time**.
3. **Single-thread discipline.** Every libreach entry point and every callback runs
   on the main message-pump thread (same as Kad). **No mutex anywhere in the adapter.**
4. **Additive + inert by default.** All scaffolding is behind a compile gate; a build
   without the gate is byte-identical to today.

---

## 1. The C-ABI binding (vtable ⇄ static methods)

`reach_context_create(const reach_host_callbacks* cb, const reach_config* cfg, void* host)`
is called once at startup with `host = this` (the adapter). Every callback's first
arg is that cookie; the adapter recovers itself with a `static_cast`.

| `reach_host_callbacks` field | Adapter static method | Action |
|---|---|---|
| `abi_version` | — | set to `REACH_ABI_VERSION` |
| `send_udp(host,peer,dst,data,len)` | `HostSendUdp` | send a raw datagram on the Kad UDP socket to `dst` (L4 punch bytes ride here) |
| `open_transport(host,peer,layer,dst)` | `HostOpenTransport` | resolve `peer`→live client; start the real transport toward `dst` for `layer`; return 0 if started |
| `signal_via_rdv(host,peer,via,payload,len)` | `HostSignalViaRdv` | forward opaque signaling to rdv `via` through our Kad (L4 3-way) |
| `csprng(host,out,n)` | `HostCsprng` | fill from a function-`static CryptoPP::AutoSeededRandomPool` — **no lock** (adapter is main-thread-confined, §7); mirrors the established pattern (`EncryptedDatagramSocket.cpp:146`, and `EseHolePunchRandomBlock` at `KademliaUDPListener.cpp:104`) |
| `clock_ms(host)` | `HostClockMs` | `::GetTickCount64()` (monotonic; 64-bit avoids the 49.7-day wrap) |
| `on_result(host,peer,result,via)` | `HostOnResult` | a connect resolved; wire the `CUpDownClient` to its chosen transport, or fall to the classic path on `REACH_RESULT_CLASSIC` |
| `log(host,level,msg)` | `HostLog` | route to `DebugLog`/`AddDebugLogLine` |

`reach_config`: `my_cap_flags` = our advertised `KAD_CAP_*` (derived from
firewall/UDP/v6 prober state); `connect_deadline_ms` / `layer_budget_ms[]` left 0
to take libreach defaults (§7.1: hundreds of ms for direct, seconds for punch).

```cpp
// ReachHostAdapter.h  (gated; see §6)
class CReachHostAdapter {
public:
    bool Init();                 // build vtable+cfg, reach_context_create(.., this)
    void Shutdown();             // reach_context_destroy
    void Tick();                 // from the main pump (~1 Hz): reach_tick(m_ctx)

    void OnPeerObserved(const CUpDownClient* c, const uint8* reachVec, size_t vlen);
    void OnClientGone(const CUpDownClient* c);              // ← CClientList::RemoveClient
    void OnUdp(const reach_endpoint* from, uint8 op, const uint8* p, size_t n);
    void OnTransportResult(const CUpDownClient* c, bool ok);

private:
    static int      HostSendUdp(void*, reach_peer_id, const reach_endpoint*, const uint8*, size_t);
    static int      HostOpenTransport(void*, reach_peer_id, reach_layer, const reach_endpoint*);
    static int      HostSignalViaRdv(void*, reach_peer_id, const reach_endpoint*, const uint8*, size_t);
    static int      HostCsprng(void*, uint8*, size_t);
    static uint64_t HostClockMs(void*);
    static void     HostOnResult(void*, reach_peer_id, reach_result, reach_layer);
    static void     HostLog(void*, int, const char*);

    CUpDownClient*  ResolveLive(reach_peer_id) const;       // id→hash→FindClientByUserHash (late-bind)

    reach_context* m_ctx = nullptr;
    using Hash = std::array<uint8, 16>;
    std::map<reach_peer_id, Hash> m_idToHash;               // stable identity, NEVER a pointer
    std::map<Hash, reach_peer_id> m_hashToId;
};
```

`ResolveLive` is the anti-UAF keystone:

```cpp
CUpDownClient* CReachHostAdapter::ResolveLive(reach_peer_id id) const {
    auto it = m_idToHash.find(id);
    if (it == m_idToHash.end()) return nullptr;
    return theApp.clientlist->FindClientByUserHash(it->second.data()); // null ⇒ gone ⇒ caller drops
}
```

---

## 2. Lifecycle & identity (reactive hook, late-bind resolve)

- **Birth / observation:** when a HELLO (or any contact) reveals a peer's reach
  vector, `OnPeerObserved` runs the ingest transaction (§3).
- **Death:** **one line** in the existing teardown chokepoint
  [`CClientList::RemoveClient`](../srchybrid/ClientList.cpp) (called from
  `~CUpDownClient`, [BaseClient.cpp:349](../srchybrid/BaseClient.cpp), and every
  other teardown path), beside the existing `uploadqueue`/`downloadqueue` removals:

  ```cpp
  if (theApp.reachAdapter) theApp.reachAdapter->OnClientGone(toremove);
  ```
  ```cpp
  void CReachHostAdapter::OnClientGone(const CUpDownClient* c) {
      Hash h; memcpy(h.data(), c->GetUserHash(), 16);
      auto it = m_hashToId.find(h);
      if (it == m_hashToId.end()) return;
      reach_peer_close(m_ctx, it->second);   // safe inside or outside a callback (deferred-free)
      m_idToHash.erase(it->second);
      m_hashToId.erase(it);
  }
  ```

- **Why not an opportunistic orphan sweep:** to find an orphan you'd inspect stored
  `CUpDownClient*`s — but dereferencing a freed pointer is UAF, and pointer-identity
  comparison is ABA-vulnerable (freed slot reused at the same address). It cannot be
  a correct GC. Late-bind `ResolveLive` makes the *datapath* safe regardless; the
  reactive hook makes cleanup *prompt*. A periodic sweep, if ever added, is pure
  memory hygiene over the hash map (no pointer deref), never a safety mechanism.

**Identity choice:** the 16-byte **eD2K user-hash** (`CUpDownClient::GetUserHash()`)
is the canonical key — it survives IP changes and is what `FindClientByUserHash`
indexes. It is also passed verbatim as libreach's opaque `nodeid` (both 16 bytes;
libreach never interprets it).

---

## 3. The HELLO ingest transaction (ordering — caps before the cascade)

The cascade must never run on absent/stale capability data. Guaranteed by binding
caps **at** `connect()` and doing the whole ingest synchronously on one thread:

```cpp
void CReachHostAdapter::OnPeerObserved(const CUpDownClient* c,
                                       const uint8* reachVec, size_t vlen) {
    Hash h; memcpy(h.data(), c->GetUserHash(), 16);

    // 1. CONNECT — binds CAPS (+ rdv anchors) from tag 0x68. Idempotent per hash.
    reach_peer_id id = REACH_PEER_NONE;
    if (reach_connect(m_ctx, h.data(), reachVec, vlen, &id) != REACH_OK) return;
    m_idToHash[id] = h; m_hashToId[h] = id;        // register identity mapping

    // 2. CANDIDATES — binds the peer's PRIMARY endpoints (not in the vector).
    reach_endpoint v4 = FromClassicV4(c);          // §4
    reach_endpoint v6 = FromTag0x66(c);            // §4; family 0 if absent
    reach_set_candidates(m_ctx, id,
                         v4.family ? &v4 : nullptr,
                         v6.family ? &v6 : nullptr);
    // 3. return to pump. The cascade runs on a later Tick(), seeing caps AND endpoints.
}
```

**Invariants this enforces**
- `reach_connect` registers the peer as `Connecting` but does **not** actuate; the
  cascade is deferred to `tick()`. So step 2 always completes before any cascade pass.
- Caps are present the instant the peer exists (vector decoded in `connect`, or
  classic projection if `reachVec == nullptr`). "Absent/stale caps at cascade time"
  is therefore impossible.
- Out-of-order is still *safe*: caps drive selection, endpoints gate actuation
  (skip-if-absent) → degrade, never wrong.

**Staleness bound / refresh:** `reach_connect` for an already-active NodeID returns
the same handle **without** re-decoding the vector. Caps are thus frozen for the
~5 s connect window. A later, fresh connect rebinds fresh caps. To force a mid-flight
refresh (rare), `reach_peer_close` then re-observe. Document this at the call site so
nobody expects live cap mutation.

---

## 4. Endpoint conversion — THE byte-order rule

`reach_endpoint { uint8 family; uint8 reserved; uint16 port; uint8 addr[16]; }`:
- `addr` = **raw address octets in wire/network order** (`addr[0]` = first dotted
  octet, e.g. `192` in `192.168.1.1`).
- `port` = **host-order integer** (libreach never byte-swaps; the host's socket
  layer applies `htons` when it actually sends).

eMule sources differ in convention — convert explicitly:

| Source | IP order (verified) | Port order | → `reach_endpoint` |
|---|---|---|---|
| `CUpDownClient::GetIP()` (`m_dwUserIP`, [UpdownClient.h:115](../srchybrid/UpdownClient.h)) | **network** (eMule convention; sibling `EncryptedStreamSocket::GetIP`/`ED2KLink::GetDialIP` are documented network-order) ⚠ confirm with a known peer in the first integration test | `GetUserPort()` = **host** | `memcpy(addr, &ip, 4)`; `port = GetUserPort()` |
| Kad contact (`uIP`, `uUDPPort` — "host order, Kad convention", cf. `KademliaUDPListener.cpp`) | **host** | **host** | `addr[i] = (uint8)(uIP >> (24-8*i))` (MSB-first); `port = uUDPPort` |
| `RdvEntry` from the decoded vector (libreach already gives raw octets + host-order port) | raw octets | host (LE on wire → decoded to host) | copy octets straight; `port = rdv.udpPort` |
| Tag `0x66` v6 (`CAddress`, `eMuleAI/Address.h`; raw 16 octets) | network/raw | per tag | `memcpy(addr,16)`; `family=6` |

**Reverse (in `HostOpenTransport`, `reach_endpoint` → socket dispatch):**
`sin_addr.s_addr = *(uint32*)addr` (octets are already network order);
`sin_port = htons(ep->port)`. If handing off to a classic eMule connect routine
that itself expects network-order IP / host-order port, match that routine's
signature — note the target function's convention at the call site.

> **Rule of thumb:** network-order *storage* → `memcpy` the 4 bytes. Host-order
> *integer* → shift out MSB-first (or `htonl` then `memcpy`). `reach_endpoint.port`
> is **always** the plain host-order integer; `htons` happens only at the socket.

The first integration test MUST assert a round-trip on a known peer
(`GetIP()` → `reach_endpoint` → `SOCKADDR_IN` → dotted string == expected), to pin
the one ⚠ cell above before anything depends on it.

---

## 5. Layer → host action (what `open_transport` does per rung)

The adapter is the cascade's **actuator hands**; the selection already happened in
`NextApplicableLayer`. `HostOpenTransport(peer, layer, dst)`:

1. `c = ResolveLive(peer);` if null → `return 1;` (client gone; libreach advances).
2. switch on `layer`:
   - `DIRECT_V6` / `DIRECT_V4` → start the classic uTP/TCP connect to `dst` on `c`.
   - `CALLBACK` → emit the appropriate callback request so `c` connects back to us.
   - `PUNCH_2W` → kick the 2-way hole-punch toward `dst` (the REQ/cookie bytes are
     **L4**; for now this hands off to the existing `SendEseHolePunchReq` path / a
     stub that reports failure so the cascade advances).
   - `PUNCH_3W` / `RELAY` → `dst` is the **rdv anchor**; coordinate via that node
     (L4 payload; stub-fail until L4 lands).
3. return 0 once the attempt is genuinely started; the host later calls
   `OnTransportResult(c, ok)` → `reach_on_transport_result`.

Until L4, only the DIRECT rungs are fully wired; punch/relay `open_transport` may
return non-zero (not started) so the cascade falls through them to CLASSIC — exactly
the safe degenerate behavior, and a clean staging boundary.

---

## 6. Gating — inert by default

A single switch keeps the whole adapter dormant until ratified:

```cpp
// emule.h or a small ese_config.h
//#define ENABLE_ESE_LIBREACH_V9   // OFF by default — flip to arm the adapter
```

- `theApp.reachAdapter` is a `CReachHostAdapter*`, **null** unless the gate is on
  (so the `RemoveClient` line and the `Tick()` driver are null-guarded and free).
- The `ReachHostAdapter.cpp` body compiles to an empty TU when the gate is off
  (`#ifdef ENABLE_ESE_LIBREACH_V9 … #endif`), so linking libreach is opt-in too.
- With the gate off the build is byte-identical to today ([[feedback_backward_compat]]).

The libreach sources (`reach_codec.cpp`, `reach_context.cpp`, `reach_cascade.cpp`)
are added to `emule.vcxproj` but, gated off, contribute no behavior — they are pure,
MFC-free, and already `/W4`-clean standalone.

---

## 7. Threading

Everything — `OnPeerObserved`, `OnClientGone`, `Tick`, `OnUdp`, `OnTransportResult`,
and every `Host*` callback — runs on the **main pump thread**. The adapter maps are
main-thread-confined; **no locks**. The only cross-thread reader is the WebServer
diagnostics, which consumes the lock-free `reach_stats` snapshot
(`reach_get_stats`) copied out right after `Tick()` — it never touches the route
table or the id↔hash maps. (Mirrors [[project_ese_live_api_threadsafety]].)

---

## 8. Build wiring (when armed)

1. `emule.vcxproj`: add `ClCompile` for `ReachHostAdapter.cpp` +
   `libreach\src\reach_codec.cpp`, `reach_context.cpp`, `reach_cascade.cpp`;
   add `libreach\include` to the include path; `ClInclude` for `ReachHostAdapter.h`.
2. `theApp` (`CemuleApp`): add `CReachHostAdapter* reachAdapter = nullptr;`
   `Init()` it after Kad starts (gated); call `reachAdapter->Tick()` from
   `CKademlia::Process()` ([Kademlia.cpp:214](../srchybrid/kademlia/kademlia/Kademlia.cpp)),
   the Kad ~1 Hz main-thread pump, right after its existing periodic work (same
   thread as every callback, §7); `Shutdown()` on exit before Kad teardown.
3. One line in `CClientList::RemoveClient` (§2).
4. HELLO call site (`KademliaUDPListener` HELLO_RES / `CUpDownClient` ProcessHello)
   → `OnPeerObserved` once the vector tag (0x68) is parsed.

All four are additive and null-guarded; none alter existing control flow when the
gate is off.

---

## 9. Validation (adapter is MFC-side — cannot be unit-tested standalone)

Unlike libreach (190 checks, verifiable in isolation), the adapter only exists
inside the MFC build. Plan:
1. **Compile** Release x64 with the gate ON (the only thing that proves the FFI
   types/byte-order line up).
2. **Byte-order round-trip assert** (§4) on a known peer — first runtime check.
3. **2-PC direct**: HighID peer → DIRECT_V4 selected, `open_transport` fires with
   the right dotted IP/port, transport connects, route remembered.
4. **Lifecycle**: destroy the `CUpDownClient` mid-connect → `OnClientGone` fires,
   `reach_peer_close` called, no crash; a late callback resolves to null and drops.
5. **Gate-off regression**: build with the gate OFF → byte-identical behavior, Kad
   and transfers unaffected.

---

## 10. Open items / hand-offs

- **L4** owns the actual punch/relay payload (nonce, cookie reuse of
  `HolePunchCookieCore.h`, rendezvous rate-cap). Until then punch/relay rungs
  `open_transport`-fail and the cascade degrades to CLASSIC.
- **`my_cap_flags` source**: wire from the firewall/UDP/v6 prober state
  (`CUDPFirewallTester`, `FirewallProberV6`) — define the exact bit mapping when arming.
- **Confirm `GetIP()` order** (§4 ⚠) before trusting the direct rungs.
- **Peer-v6 capture is a SHARED prerequisite (with IPv6 persistence).** `FromTag0x66`
  (§3) and the `DIRECT_V6` rung are inert until a peer's v6 address is actually stored
  in the host model — and today nothing stores it: neither `CUpDownClient` nor the Kad
  `CContact` ([Contact.h:104-120](../srchybrid/kademlia/routing/Contact.h)) carries a v6
  field, and `TAG_SOURCEIP_V6` RX is log-only (TX zero). So the armed adapter ships with
  `DIRECT_V4`/CLASSIC live and `DIRECT_V6` degenerate-to-CLASSIC until that capture lands.
  This is the **same** "capture peer v6 into the host" work that IPv6 `nodes.dat`
  persistence needs (a v6 field on the contact/client + reading the HELLO tag) — it is a
  single prerequisite shared by the LowID and IPv6 legs. Do it once, both legs advance.
- Register no new wire numbers here: the adapter emits only existing opcodes; the
  reach vector tag (`TAG_ESE_REACH` 0x68, TAG-ED2K namespace) and `ESE_CAP_REACH_V2`
  (**bit 17 / 0x20000** — NOT bit 15, which is `ESE_CAP_HOLEPUNCH_RDV`) are already in
  [[project_protocol_registry]] ([CAPABILITIES.csv:17](protocol/CAPABILITIES.csv)).
