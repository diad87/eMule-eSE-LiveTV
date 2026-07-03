# libreach

Reference library for **KEP-1** — the reachability vector + connection
cascade that abolishes the LowID/HighID binary in Kademlia-derived networks.
This is the publishable component described in
[`docs/THESIS_KAD_SIN_LOWID.md`](../docs/THESIS_KAD_SIN_LOWID.md) §13: a clean,
embeddable library at the `libutp` level, so any client (eMule mods, aMule,
jed2k via FFI) can adopt the same identity≠reachability model without a
flag-day.

> **Status:** under construction.
> **L1** — the `TAG_REACH` TLV codec (Appendix A) — is implemented and pinned by
> golden vectors (`test_reach_codec`, 88 checks).
> **L2** — the C ABI facade (`reach.h`) and the single-threaded IoC engine
> (generation-counted peer handles, deferred-free, lock-free stats snapshot) — is
> implemented and exercised through the C ABI by a mock host
> (`test_reach_facade`, 43 checks).
> **L3** — the full connection cascade (Appendix B / §7.1):
> the pure transition function `NextApplicableLayer(myCaps, peerVector, after)`
> (`reach_cascade.{h,cpp}`, golden vectors, `test_reach_cascade`, 33 checks) PLUS
> the engine actuator — `reach_set_candidates` (the host supplies the peer's own
> primary v4/v6 endpoint, which the vector does not carry), per-rung dispatch via
> `open_transport` (rdv-mediated rungs source their dst from the vector anchors),
> and NodeID-keyed route memory (the *nominated pair*) with **timer-free
> eviction**: validate-on-use (a stale route fails its optimistic retry and is
> dropped — the network-jump case), a TTL checked on access, and a per-layer
> budget. Driven through the C ABI by a mock host (`test_reach_actuator`, 26
> checks). Backward-compatible: a host that never calls `reach_set_candidates`
> simply loses the direct rungs and still degrades to `CLASSIC`.
> Punch + prober (L4) and the conformance suite (L5) follow.

## Design contract (thesis §13.2)

`libreach` follows the `libutp` pattern *to the end*:

- **No sockets, no threads, no Kad.** The host injects every side effect —
  UDP send, TCP open, signaling via the host's own Kad, CSPRNG, clock — and
  drives a `tick()` at ~1 Hz. The library only owns the hard, dialect-prone
  parts: the TLV codec, the cascade state machine, punch encoding, the
  capability prober, and anti-abuse accounting.
- **Single-threaded discipline.** Host clients have hostile thread models;
  a library that spawns threads is a library nobody integrates twice.
- **C ABI surface** (`extern "C"`, like `utp.h`) for FFI/JNI consumers.
- **Out of scope, explicitly:** Kad routing, uTP transport (that is `libutp`),
  Kad packet crypto, and all UI policy. Fixed border against scope creep.
- **Brand-neutral names.** The normative tag is `TAG_REACH`, the bits are
  `KAD_CAP_*`, the symbols `reach_*` — never `ESE_*`. eSE keeps internal
  aliases and is the *reference implementation*, not the owner.
- **License: MIT.** This is new code (the cascade, the TLV and the puncher are
  ours, not derived from eMule), so it embeds without friction in the GPL
  clients of the ecosystem. The glue inside each client stays under that
  client's license.

## Conformance levels (thesis §13.3)

| Level | Implements | Buys |
|---|---|---|
| **N0 — Transparent** | Nothing active; just stores & forwards unknown tags | The modern network works *through* it (eMule 0.70b already does this) |
| **N1 — Reader** | Parses `TAG_REACH`; connects direct-v6, uses rdv for callbacks | Its users connect better *toward* modern nodes |
| **N2 — Full** | Publishes its own vector; 2-/3-way punch with uTP; keepalive | Abolishes the LowID *for its community* |
| **N3 — Infrastructure citizen** | Open nodes offer rendezvous and (opt-in) capped relay | Sustains the shared plane |

Anti-abuse rules are **unconditional MUSTs** at every level: punch without a
nonce, or rendezvous without the subscribers-only rule, is *non-conformant* —
it would turn users into amplifiers.

## Layout

```
libreach/
  include/reach/
    reach_types.h     normative on-wire types (Appendix A)
    reach_codec.h     TAG_REACH serialize / parse API
    reach.h           public C ABI (extern "C", FFI surface)
  src/
    reach_codec.cpp   codec implementation
    reach_engine.h    internal C++ engine (not a public header)
    reach_context.cpp C ABI shim + engine implementation
  tests/
    test_reach_codec.cpp    golden vectors + adversarial cases
    test_reach_facade.cpp   C ABI lifecycle / IoC / anti-dangling
```

## Build & test (standalone, no MFC)

From `libreach/`, with the MSVC x64 toolchain on `PATH` (`vcvars64.bat`):

```bat
cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_codec.exe ^
   tests\test_reach_codec.cpp src\reach_codec.cpp
build\test_reach_codec.exe

cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_facade.exe ^
   tests\test_reach_facade.cpp src\reach_context.cpp src\reach_codec.cpp
build\test_reach_facade.exe

cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_cascade.exe ^
   tests\test_reach_cascade.cpp src\reach_cascade.cpp
build\test_reach_cascade.exe

cl /EHsc /O2 /W4 /std:c++17 /Iinclude /Febuild\test_reach_actuator.exe ^
   tests\test_reach_actuator.cpp src\reach_context.cpp src\reach_codec.cpp src\reach_cascade.cpp
build\test_reach_actuator.exe
```

…or with GCC/Clang anywhere:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Iinclude -o test_reach_codec \
    tests/test_reach_codec.cpp src/reach_codec.cpp && ./test_reach_codec
```

Exit code 0 means every golden vector matched. The vectors are the normative
pin: any drift in `libreach` *or* in a third-party implementation is a
conformance failure (cf. [`tests/test_address_wire.py`](../tests/test_address_wire.py)
for the address wire format).

## TAG_REACH wire format (KEP-1 Appendix A)

All multi-byte scalars are little-endian.

```
offset  size   field
0       1      version (=1)
1       2      capflags (KadCap bitfield, LE)
3       1      nRdv (0..3)
4       22×n   rdv[n] = NodeID(16) ++ IPv4(4 raw octets) ++ udpPort(2 LE)
4+22n   ...    optional trailing TLV(s) — preserved opaquely (e.g. signature)
```

Maximum known v1 size: `4 + 3×22 = 70` bytes. Producer is strict (rejects
reserved capflag bits and `nRdv > 3`); consumer is lenient (tolerates higher
version bytes and preserves unknown trailing bytes — Postel's law).
