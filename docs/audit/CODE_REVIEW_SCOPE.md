# eSE Live V1 — Security review scope (F6 deliverable)

This document defines what an external security reviewer needs to look
at before V1 release. Decision 9.3 (thesis main Cap 9) marks the review
as **bloqueante**.

## Critical modules (MUST review)

All paths relative to `srchybrid/`.

### 1. Cryptographic core

- `LiveCrypto.cpp/h` — Ed25519 keypair, sign/verify, streamKey derivation.
- `LiveOnionCrypto.cpp/h` — X25519, ChaCha20-Poly1305 AEAD, HKDF-SHA-256,
  secure RNG, SecureWipe.
  * Check: AEAD nonce uniqueness invariant. Look at every
    `BuildNonce(counter++)` call site and confirm the counter cannot wrap
    in a session or reuse across keys.
  * Check: SecureRandomBytes never reads from a uninitialised RNG.
  * Check: SecureWipe is called for every secret on every exit path
    (including exceptions).

### 2. Tunnel construction

- `LiveTunnel.cpp/h`, `LiveCircuit.cpp/h`, `LiveCellQueue.cpp/h`.
  * Check: `OnionEncrypt` / `OnionPeelOne` invariants — what happens with
    malformed input, oversized payload, payload that decrypts but is then
    interpreted as a structured cell.
  * Check: nonce_send / nonce_recv counters under reordering / replay.
  * Check: 32-bit random circuit IDs — collision handling on duplicate.
  * Check: CellPack random padding — RNG failure mode.

### 3. Channel identity

- `LiveChannel.cpp/h` — ChannelRecord parse/sign/verify/seal/open.
  * Check: ChannelRecordParse exhaustive bounds (every PopU* validates
    remaining buffer).
  * Check: rendezvous count cap (uint8 max 255) cannot exhaust memory.
  * Check: ChannelRecordSeal nonce randomness.

### 4. Sealed records (private channels)

- `LiveChannel::DeriveKadRecordKey` — HKDF over channel secret.
  * Check: info string is fixed and unambiguous ("ese-kad-record-key-v1").
  * Check: secret is never logged.

### 5. Subscription storage

- `LiveSubscriptionStore.cpp/h` — DPAPI roundtrip.
  * Check: file is atomic-replaced (no half-written window).
  * Check: SecureWipe of plaintext after parse.
  * Check: ParseUnencrypted has bounds checks on every field.

### 6. Wire format parsers (untrusted input)

- `LiveBootstrap::PeerInviteParse`
- `LiveChannel::ChannelRecordParse`
- `LiveCellQueue::CellUnpack`
- `LiveGossip::ChannelGossipParse`
- `Kademlia::CKadV2Sharding::ParseAnnounce`
- `LiveKadBridge::OnKadSearchResult` (already in production, recheck)
  * Check: each parser handles malformed/truncated/oversized input
    without UB, no length-extension, no integer overflow.

### 7. Plan H namespace isolation (already in production)

- `EseLiveGetKeywordHash` in Search.h / Kademlia.cpp.
- Dual-publish / dual-search in LiveKadBridge.cpp.
- TAG_FILENAME / TAG_FILETYPE omission in Search.cpp.
  * Check: the prefix `"\x00eSE\x00"` is constant and not under attacker
    control.
  * Check: pref `m_bEseLivePublishLegacy` cannot be flipped remotely.

## Acceptance criteria

Reviewer fills `REVIEW_LOG.md` (sibling file) for each module:

```
| Module | Reviewer | Date | Result | Critical findings |
|---|---|---|---|---|
| LiveCrypto.cpp/h | ... | YYYY-MM-DD | PASS / FAIL | ... |
| ...
```

V1 is released **only when every row above is PASS** with a signed reviewer
identity. If any FAIL, issues go to a private security tracker; the
release is gated until each one has a fix commit + retest row in the
log.

## Compensating controls if review reveals issues

The reviewer is encouraged to consider:

- **Fuzzing**: each parser in §6 should be exercised with AFL++ or
  libFuzzer for ≥24 h pre-release. Current state: not done.
- **Static analysis**: `clang-tidy` and `cppcheck` runs over the new
  modules. Current state: not done.
- **Memory safety**: all 'new' modules use std::vector + raw `uint8_t[]`
  with explicit bounds. Compile with /sdl /GS /guard:cf. Current state:
  /GS on by default; /guard:cf not verified.

## Bounty template (if public bounty path is chosen)

Decision 9.4 (Cap 9 + plan §9): bounty público is the no-cost option.

Recommended scope text for a public bounty (e.g. HackerOne, Bugcrowd):

> **Project**: eSE Live V1 release candidate.
> **In scope**:
>   - All `srchybrid/Live*.cpp/h`
>   - All `srchybrid/kademlia/kademlia/KadV2*.cpp/h`
>   - Network parsers for OP_LIVE_*, KADEMLIA2_*, CELL_*
>   - DPAPI subscription store
> **Out of scope**:
>   - Existing eMule 0.70b code (upstream)
>   - Node.js ese-server (separate project)
>   - UI dialog code (no security boundary)
> **Severities**:
>   - Critical: any path that leaks viewer IP without 2-hop tunnel; any
>     bypass of channel signature verification; any AEAD nonce reuse.
>   - High: any DoS that crashes the eMule process; any unsigned
>     channel record acceptance; any sensitive-keyword bypass.
>   - Medium: subscription-store decryption by non-owner account;
>     gossip-cache poisoning.
> **Rewards**: this is a free/community project (feedback_gratis_no_barato).
>   Acknowledgement in release notes + AUTHORS file is the offered comp.

## Out of scope for F6

- ProVerif formal verification — that's F4a, separately bloqueante.
- Performance review — that's F7 (benchmarks before release).
- Legal review of the threat model — that's the thesis itself, already
  done and immutable from a release perspective.
