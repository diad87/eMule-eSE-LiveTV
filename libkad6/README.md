# libkad6

Standalone, MFC-free reference codecs for the **Kad6** anonymous/compat overlay
(spec [`docs/SPEC_KAD6_ANONYMOUS_COMPAT.md`](../docs/SPEC_KAD6_ANONYMOUS_COMPAT.md),
execution plan [`docs/KAD6_IMPLEMENTATION_PLAN.md`](../docs/KAD6_IMPLEMENTATION_PLAN.md)).
Same design contract as [`libreach`](../libreach/README.md): a small, embeddable
library that owns only the dialect-prone, hard-to-get-right parts — the wire
codecs, canonical serialization, structural limits and validation — while the
host injects every side effect.

> **Status (2026-07-15): K6-0…K6-8 source/build-complete within their declared boundaries; physical, 30-day and external-review gates remain separate.** All current tests build
> `/W4`-clean under VS2022 (`cl /W4 /std:c++17`) and pass
> (**21,462 checks, 0 failed** across twenty-six assertion-counted executables, plus the K6-5 gate executable). The dedicated thirteen-target
> fuzzer passes 1,300,000 deterministic iterations in both Release and MSVC ASan;
> seven external JSON files pin 17 wire/crypto vectors, including real Crypto++
> conformance to RFC 4231/5869/8032/8439. The sources
> are linked into `srchybrid`; the K6-2 native-IPv6 routing runtime emits its
> capability only while a public IPv6 address and dual-stack UDP bind are live.
> The K6-1A onion gateway now carries cap-gated canonical Live discovery while
> preserving the deployed legacy wire; its multi-PC G0 evidence is still pending.
> The registry linter is green (129 entries, 112 fork symbols). K6-3 now includes
> signed source leases/publication, Kad2 shadow publication and native Kad6 STORE;
> its inbound serving gate remains dependent on K6-5.

## Design contract

- **No MFC, no sockets, no threads, no embedded crypto.** Brand-neutral names
  (`kad6_*`), namespace `kad6::`, **MIT** license (new code — embeds without
  friction in the GPL clients of the ecosystem).
- **IoC for crypto.** libkad6 embeds no HMAC/Ed25519/CSPRNG. The host injects
  them via `Kad6CryptoHooks`. Unit tests wire deterministic mocks for failure
  paths, while the K6-0 conformance suite wires the vendored Crypto++ through a
  test-only host adapter and checks normative RFC vectors. This keeps the library standalone-testable and keeps "no homemade
  crypto" honest (spec I6 / K6-ABUSE-018).
- **Producer strict, consumer prudent (Postel).** Every `Decode` rejects
  malformed input *before* allocating, and cheap gates (version, counts, TTL,
  size caps) run *before* the expensive signature verify (spec K6-NATIVE-003).
- **Bounded parsing in one place.** All codecs read through `ByteReader`
  (`kad6_bytes.h`), which never advances past its buffer — the class of
  out-of-bounds read the fuzz loops guard against cannot occur by construction.

## Layout

```
libkad6/
  include/kad6/
    kad6_types.h        Byte, Kad6Status, sizes, constant-time compare
    kad6_bytes.h        ByteReader / ByteWriter (bounded little-endian cursor)
    kad6_crypto.h       Kad6CryptoHooks — injected hmac/sha256/ed25519/csprng
    kad6_address.h      Kad6Address wire object (byte-identical to CAddress)
    kad6_endpoint.h     K6EndpointV1 (address + ports/flags/validity)
    kad6_frame.h        K6FrameV1 (common gateway message header)
    kad6_tags.h         K6TagListV1 (canonical, bounded tag list)
    kad6_ticket.h       K6TargetTicketV1 (anti-open-proxy MAC ticket)
    kad6_records.h      Ed25519 records: NodeBind / Rotate / Router / Source
    kad6_shaped_bulk.h  class-5 anti-watermark 17000-byte shaped carrier
    kad6_search.h       bounded search request/result/response bodies
    kad6_live_search.h  strict LiveStreamEntry-independent canonical tag adapter
    kad6_economy.h      exit-supply admission/economics math
    kad6_quota.h        RFC 9474 anonymous admission token wire/policy
    kad6_exit_notice.h  canonical JCS/Ed25519 public exit notice
    kad6_hardening.h    fixed-cardinality telemetry and beta policy
    kad6_routing.h      signed native-v6 BOOTSTRAP/HELLO/FIND_NODE RPCs + snapshot
    kad6_asn.h          offline IPv6-prefix to ASN/operator longest-prefix DB
    kad6_bootstrap.h    signed private-bootstrap bundle + anti-rollback codec
    kad6_lease.h        signed source BIND/BOUND/UNBIND + lease state machine
    kad6_publish.h      signed publish/ack/unpublish + QPS budget/coalescer
    kad6_store.h        authenticated native Kad6 source STORE request/response
  src/                  *.cpp
  tests/                test_*.cpp  (assert-based CHECK harness, exit 0 = pass)
  tests/fuzz/           thirteen deterministic parser targets + RSS-aware runner
  tests/support/        test-only Crypto++ implementation of Kad6CryptoHooks
  vectors/              external golden/adversarial JSON wire + crypto vectors
  tools/                strict vector schema/hex checker
  make.bat              standalone build+run helper (wraps vcvars64 + cl)
  make_fuzz.bat         Release or MSVC-ASan 100k-per-target fuzz gate
  make_crypto_vectors.bat  normative RFC vectors against vendored Crypto++
  test_all.bat          complete standalone + fuzz + linter gate
```

## Build & test (standalone, no MFC)

`make.bat` wraps `vcvars64.bat` so `cl` need not be on `PATH`:

```bat
make.bat test_kad6_smoke       tests\test_kad6_smoke.cpp
make.bat test_kad6_address     tests\test_kad6_address.cpp     src\kad6_address.cpp
make.bat test_kad6_asn         tests\test_kad6_asn.cpp src\kad6_asn.cpp src\kad6_address.cpp
make.bat test_kad6_bootstrap   tests\test_kad6_bootstrap.cpp src\kad6_bootstrap.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_frame       tests\test_kad6_frame.cpp       src\kad6_frame.cpp
make.bat test_kad6_gateway     tests\test_kad6_gateway.cpp src\kad6_gateway.cpp src\kad6_hints.cpp src\kad6_vep.cpp src\kad6_ed2k_policy.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_tags        tests\test_kad6_tags.cpp        src\kad6_tags.cpp src\kad6_address.cpp
make.bat test_kad6_ticket      tests\test_kad6_ticket.cpp      src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_records     tests\test_kad6_records.cpp     src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_shaped_bulk tests\test_kad6_shaped_bulk.cpp src\kad6_shaped_bulk.cpp
make.bat test_kad6_search      tests\test_kad6_search.cpp src\kad6_search.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_live_search tests\test_kad6_live_search.cpp src\kad6_live_search.cpp src\kad6_search.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_economy     tests\test_kad6_economy.cpp src\kad6_economy.cpp
make.bat test_kad6_quota       tests\test_kad6_quota.cpp src\kad6_quota.cpp
make.bat test_kad6_exit_notice tests\test_kad6_exit_notice.cpp src\kad6_exit_notice.cpp src\kad6_tags.cpp src\kad6_address.cpp
make.bat test_kad6_lease       tests\test_kad6_lease.cpp src\kad6_lease.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_publish     tests\test_kad6_publish.cpp src\kad6_publish.cpp src\kad6_tags.cpp src\kad6_address.cpp
make.bat test_kad6_store       tests\test_kad6_store.cpp src\kad6_store.cpp src\kad6_routing.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_routing     tests\test_kad6_routing.cpp src\kad6_routing.cpp src\kad6_records.cpp src\kad6_endpoint.cpp src\kad6_address.cpp
make.bat test_kad6_vectors     tests\test_kad6_vectors.cpp src\kad6_address.cpp src\kad6_endpoint.cpp src\kad6_frame.cpp src\kad6_tags.cpp src\kad6_ticket.cpp src\kad6_records.cpp src\kad6_shaped_bulk.cpp
make_crypto_vectors.bat
make_fuzz.bat
set KAD6_ASAN=1 && make_fuzz.bat
```

Run `test_all.bat` for the complete reproducible gate, including the protocol
registry linter. Exit code 0 means every check passed. Or with GCC/Clang: `g++ -std=c++17 -O2
-Wall -Wextra -Iinclude ...`.

## Codec status (phase K6-0)

| Codec | Spec | Tests | Notes |
|---|---|---:|---|
| `kad6_address` | §7.1 | 51 | byte-identical to `CAddress`; IPv4-mapped normalization; subnet ops |
| `kad6_asn` | ADR-08 / §17.3 | 4.195 | canonical local snapshot; bounded binary trie; longest-prefix ASN/operator lookup |
| `kad6_bootstrap` | §17.4 | 10.299 | signed bundle, pinned distribution key, bounded pre-scan, time/sequence and inner signatures |
| `kad6_frame` | §10.2 | 1054 | 1 MiB body cap; reserved-flag Postel handling |
| `kad6_gateway` / hints / VEP / eD2K policy | §14-16 | 44 | ticket request, DIAL/stream, aggregate quota, SX1/SX2 provenance, VEP and fail-closed opcode inventory |
| `kad6_tags` | §11.3.1 | 55 | strict UTF-8, canonical sort/uniqueness, structural CADDRESS validation, 128/64KiB/16KiB limits |
| `kad6_endpoint` | §7.2 | (with ticket) | address + transport flags |
| `kad6_ticket` | §14.2 | 68 | MAC; exact wire; host target policy; atomic use consumption; quota/expiry binding |
| `kad6_records` | §6.2/6.3/17.2/17.5 | 158 | atomic state advance; dual-sig rotation; strict router identity/window/endpoint validation |
| `kad6_shaped_bulk` | §9.6.1 | 145 | opaque onion prefix; exact-17000 carrier; relay rebuild after host AEAD peel |
| `kad6_shaper` / `kad6_path` | §9/§19 | 213 | STRICT3 path diversity and class-5 scheduler invariants |
| `kad6_search` | §11.3 | 124 | strict enums/masks/non-zero IDs; bounded search bodies and nested ticket/tag codecs |
| `kad6_live_search` | K6-1A mapping | 26 | exact Live tag names/types, required-field uniqueness, strict UTF-8/CAddress parsing, additive unknown tags |
| `kad6_economy` | §20.7 | 90 | measured windows, fail-closed resource ratios, admission, DRR and exit-supply thresholds |
| `kad6_quota` | §20.2 | 49 + 15 real | bounded blind-token wire, issuer limiter, spent-set and RFC 9474 Crypto++ vector |
| `kad6_exit_notice` | §20.9 | 16 + 16 server | JCS/Ed25519 notice and isolated read-only dual-stack HTTP listener |
| `kad6_hardening` | K6-7 | 57 | fixed-cardinality telemetry, sealed windows, health and local kill-switch policy |
| `kad6_lease` | §13 / §25.3 | 188 | compat proof, signed BOUND, downgrade resistance, exact wire, circuit-bound state and cohort invariants |
| `kad6_frontdoor` | K6-5 / G10/G11 | gate | fixed 512-slot pre-auth, IPv4/IPv6 quotas, Slowloris deadline/rate and fair single-backend cohort pins |
| `kad6_publish` | §12 / §20.8 | 86 | signed PUBLISH, ACK states, unpublish, multidimensional budget and endpoint/hash coalescing |
| `kad6_store` | K6-3 native STORE | 11 | authenticated route header, signed source record and exact 1.200-byte-bounded RPC |
| `kad6_routing` | K6-2 wire v2 | 4.411 | signed router-record coherence; exact six RPCs; legacy-v1 downgrade; `nodes_v6.dat` v2 |
| external wire vectors | K6-TEST-001 | 33 | six codec files; golden + adversarial; loaded by C++ tests |
| real Crypto++ vectors | I6 / K6-TEST-001 | 44 | SHA-256, HMAC-SHA256, HKDF-SHA256, Ed25519 and ChaCha20-Poly1305 RFC vectors |

In addition to the unit-test fuzz loops, `tests/fuzz/` drives all thirteen critical
decoder families for 100,000 iterations each with a fixed seed, bounded corpus
mutation and output invariants. Release enforces a 64 MiB RSS/private-growth
guard; the separate MSVC-ASan run detects OOB/UAF while reporting its quarantine
memory independently. See the closure evidence in
[`docs/KAD6_K6_0_CLOSURE_2026-07-15.md`](../docs/KAD6_K6_0_CLOSURE_2026-07-15.md).

## Known boundaries / to-do

- **The Crypto++ adapter under `tests/support/` is conformance infrastructure,**
  not a provider dependency of libkad6. Production hosts still own key storage,
  policy, CSPRNG lifetime and hook wiring.
- **`K6SourceRecord.pub_key[32]`** is explicit and its pseudonym is canonically
  derived from it. This is normative in spec 0.3.0-draft.
- **Shaped carrier AEAD remains host-owned.** K6-0 validates the selected
  ChaCha20-Poly1305/HKDF primitives and exact opaque framing; end-to-end onion
  seal/open/replay integration belongs to the later circuit runtime phase.
- **K6-2 is source/build complete, not network-certified.** Production routing
  requires the external three-host IPv6 gate, and a release must ship/update its
  trusted ASN and private-bootstrap artifacts. Wire v2 requires a signed
  `K6RouterRecord`; the old unsigned experimental v1 is decode-only and rejected
  by the runtime.
- **K6-8 is source/build complete, not public-exit certified.** External review
  of RFC 9474 integration, physical G10–G15, anti-churn and a 30-day supply window
  remain mandatory; stable public mode stays off until those gates pass.
- **K6-3 activation is wired for the compatibility source profile.** Shared-file rotation
  creates a signed source bind and circuit-pinned Kad2 shadow publication; the exit marks
  the lease `SERVING` only after publication is queued/acknowledged. Native Kad6 STORE remains
  available through the publication API. `G3/G15` still require external peers and captures.
- **K6-4 activation is wired into the download path, but G4 is not externally certified.**
  TCP DIAL, protocol-aware stream proxy, PEX hints and IPv4 SecureIdent VEP are integrated;
  a controlled vanilla peer, known file and pcap are still required for the physical gate.
- **K6-5 is source/build complete for the shared cohort endpoint.** The listener uses bounded
  pre-auth before allocating a client, demuxes by exact file hash, selects exactly one origin,
  sends `K6M_ACCEPT` and runs A's unchanged upload parser over the stream. Deterministic G10/G11
  pass; the 5,000-real-socket and two-origin multi-PC variants remain external evidence.
- No C ABI facade yet (libreach-style `extern "C"`); add when a non-C++ consumer
  needs it.
