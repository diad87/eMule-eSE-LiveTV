# IPv6 in eMule eSE — Analysis and Roadmap

> **TL;DR.** Yes, IPv6 would be a real achievement — `MASTER_PLAN.md`
> already flags it as *"CRÍTICO: free HighID a ~50% de Europa,
> biggest free win"*. But "adding IPv6" is not a one-line change:
> the eD2K wire protocol, the Kad DHT, our own five new live opcodes,
> the mDNS multicast group, the `ed2k://` link format and the IPFilter
> tables all bake `uint32` (IPv4-only) addresses into the contract.
> A pragmatic 3-phase plan gets us 80% of the value (live-traffic
> reachability + Kad hint records) in ~5–6 weeks. The full retrofit
> of eD2K + Kad is months of work and carries real compatibility risk
> with the upstream user base.

---

## 1. Why this matters for us specifically

Three forces are pushing IPv6 from "nice to have" to "increasingly
load-bearing" for a P2P live-streaming app:

| Force | Concrete effect |
|---|---|
| **CGNAT proliferation** | Mobile carriers and many residential ISPs (especially in LATAM, Africa, parts of Europe) place users behind Carrier-Grade NAT. Inbound TCP simply doesn't work even with UPnP. IPv6 bypasses this entirely — the device has a globally-routable address. |
| **Mobile = IPv6-mostly** | LTE/5G networks in DE/FR/IN/ES are 60–70% IPv6 capable; many are IPv6-only with NAT64 for legacy IPv4. A viewer on a phone on a hotspot is increasingly an IPv6-native peer. |
| **"Free HighID"** | An IPv6 peer is reachable on inbound TCP without UPnP, without hole-punching, without any of the LowID dance. Every IPv6 peer becomes a potential relay. This is the property `MASTER_PLAN.md §11.3.8` calls *"biggest free win"*. |

For live streaming specifically, **every IPv6-reachable peer is a
candidate relay that doesn't need hole-punching**, which is exactly
the constraint our tree topology (Section 3.4 of the paper) hits
hardest: the broadcaster cap of 10 direct viewers exists because
hole-punching to a 100th viewer is expensive and unreliable.

---

## 2. Current state — what we have, what we don't

Surveyed 2026-05-17.

### 2.1 Upstream eMule 0.70b (what we inherited)

| Layer | IPv6 status today |
|---|---|
| **Low-level socket abstraction** (`AsyncSocketEx`, `AsyncProxySocketLayer`) | **Partial**. Mentions `AF_INET6` in a few code paths but unverified end-to-end. Probably needs auditing before relying on. |
| **eD2K wire protocol** (`BaseClient`, `ListenSocket`, `DownloadClient`, etc.) | **IPv4-only**. Every place we send a peer endpoint over the wire uses `uint32 IP` + `uint16 port`. |
| **Kad DHT** (`Contact`, `Entry`, `Prefs`, `PacketTracking`, `LookupHistory`) | **IPv4-only**. `Contact.h:111` declares `uint32 m_uIp` (host order) + `uint32 m_uNetIp` (network order). All k-bucket bookkeeping is 32-bit. |
| **eD2K Server protocol** (`ServerConnect`, `ServerSocket`) | **IPv4-only**, with `ServerConnect.cpp` having a few `IPv6` references that look like dead code. |
| **server.met / nodes.dat / clients.met file formats** | **IPv4-only**. The on-disk record format is `uint32 IP + uint16 port + ...`. |
| **IPFilter** | **IPv4 only**. Range tables are `uint32 begin / end`. |
| **NAT traversal** (hole-punch, UPnP) | **IPv4-only by design**. Concepts of LowID / HighID, hole-punch signaling, UPnP port mapping all assume NAT. |
| **Anti-leech / anti-Sybil heuristics** | **IPv4-only**. "Same /24" rate limits, banning by IP, all uint32. |
| **WebServer / WebSocket** (`:4711`) | **IPv4-only socket bind**. The loopback gate compares against `htonl(INADDR_LOOPBACK)`; would need `IN6ADDR_LOOPBACK_INIT` equivalent for `::1`. |

The existing IPv6 references in `AsyncSocketEx` etc. **don't propagate
upward** — the layers above still call `Connect(uint32 IP, uint16 port)`
and the socket layer interprets the uint32 as IPv4. So they are
dormant code paths.

### 2.2 What our fork added

Everything we added is IPv4-only:

| Layer (ours) | Where |
|---|---|
| **5 new live opcodes** (HEARTBEAT, CHUNK_REQ/RESP, PING, PONG) | `LivePackets.h` — PEX entries are `uint32 broadcasterIP` |
| **Kad publish/search** (`live:HEXKEY`, `livehash:HEXKEY`, `livehelp:HEXKEY`) | Inherits Kad's uint32 IPs |
| **mDNS LAN multicast** | `224.0.0.251:5354` — IPv4 multicast group only. The IPv6 equivalent (`ff02::fb`) is not used. |
| **Bootstrap cache** (`last_streams.json`) | IPv4 IP/port pairs only |
| **`ed2k://|live|HEX|IP:PORT|TITLE|/` link format** | Format requires literal IPv4 — no bracketing convention defined |
| **`/api/live/direct_join?ip=...&port=...`** | `inet_addr()` (IPv4 only) — `inet_pton()` would be needed for v6 |
| **Loopback gate** in `WebServer.cpp` | Compares against `htonl(INADDR_LOOPBACK)` — IPv4 only |

### 2.3 V2-S23 (the planned-but-not-implemented sprint)

`docs/SPRINTS_V2.md:1180` already names the sprint. Its scope was
deliberately small ("3 days"): *create one IPv6 socket on startup,
log whether the OS supports it*. That gives us a runtime signal but
doesn't actually let any data flow over IPv6.

The MASTER_PLAN calls out IPv6 as the highest-ROI NAT-bypass change
(`§11.3.8`) but never enumerates the implementation work.

---

## 3. Surface area of changes — full inventory

If we wanted *complete* IPv6 support, this is what would need to
move (call this the "scope of change" map):

### 3.1 Wire protocol

- **eD2K opcodes with embedded IP fields** — every place we serialize
  a peer endpoint needs an address-family tag. The TLV pattern from
  BitTorrent's BEP-10 is the right precedent.
- **Kad packet types** — `KADEMLIA2_HELLO_REQ/RES`, `KADEMLIA2_REQ/RES`,
  `KADEMLIA2_BOOTSTRAP_REQ/RES`, source publish, store, search — all
  carry `Contact` records with `uint32 m_uIp`. New v6-aware variants
  are needed, gated by version negotiation.
- **Our 5 new live opcodes** — `OP_LIVE_HEARTBEAT`'s PEX block uses
  `uint32 broadcasterIP`; would extend to a `uint8 family + uint8[]
  addr` form with the address-family byte before each entry.

### 3.2 In-memory data structures

- `Kademlia::CContact` (`Contact.h:111`) — add `in6_addr m_uIp6`
  alongside `m_uIp`. Probably also `enum AddrFamily m_family`.
- `CKnownClient`, `CUpDownClient` — same pattern. These are the
  hot in-memory structures touched on every packet.
- `Kademlia::Indexes::CFileEntry`, `CKeywordEntry` — store published
  endpoints; need to carry v6.
- `CSearchManager` / `CSearch` — query result accumulation; need to
  carry v6 hits.

### 3.3 On-disk file formats

Three formats with eMule-defined record layouts:

- **`server.met`** — eD2K server list, `uint32 IP`. Extend with a
  version byte? Or add a sidecar `server_v6.met`?
- **`nodes.dat`** — Kad bootstrap contacts. Same question.
- **`clients.met`** — known peers + credit info. Same.

Backward compatibility is the headache: older clients read these
files and crash on unexpected formats. The standard play is to bump
the file version and have old clients ignore the new file (falling
back to a v1 file we still maintain). This means writing **two** sets
of records — an annoyance.

### 3.4 String representations and URLs

- `ipstr()` everywhere produces `"1.2.3.4"` — needs a v6-aware sibling
  that produces `"2001:db8::1"`.
- `inet_addr()` parsing needs replacement with `inet_pton(AF_INET, ...)`
  + `inet_pton(AF_INET6, ...)`.
- `ed2k://|live|HEX|IP:PORT|TITLE|/` link format — needs a bracketed
  v6 form like `ed2k://|live|HEX|[2001:db8::1]:4662|TITLE|/`. Parsers
  need to handle both. Documenting the bracketed form as a
  fork-specific extension is fine, but old clients won't parse it.

### 3.5 NAT traversal and reachability classification

- **LowID/HighID is a v4 concept.** For v6, the equivalent is just
  "reachable" vs "not reachable" (no NAT typology to speak of). The
  classification code paths need a "v6-reachable" boolean alongside
  the existing HighID bit.
- **Hole-punching code skips for v6.** The whole UDP hole-punch
  signaling machinery (`UDPSocket.cpp`, `CClientList::AskForHolepunch`)
  should be a no-op when the destination is v6.
- **UPnP code stays v4.** Routers expose v4 NAT mapping; v6 doesn't
  need it.

### 3.6 IPFilter

- `CIPFilter` — range tables are `uint32 begin / end`. Standard
  approach is a parallel v6 table with `in6_addr` ranges. The popular
  `ipfilter.dat` format used by eMule has community variants that
  carry v6 entries (e.g. PeerBlock's `.p2b` v3 format), so prior art
  exists.

### 3.7 Anti-Sybil and rate limiting

- "Same /24" rate limits — need to also be "same /64" for v6 (the
  per-customer prefix in most ISP allocations).
- IP-based deduplication of search results — needs to be aware that
  the same peer might appear via v4 and v6.

### 3.8 Statistics, metrics, logging

- Per-peer counters keyed by IP — need a unified key (e.g.
  `(family, addr, port)` tuple).
- `/api/live/metrics` Prometheus exposition — labels currently use
  `ip="1.2.3.4"`; would need to handle bracketed v6 in label values.
- Logs that print IP — need format-string helpers.

---

## 4. Three pragmatic approaches

I see three coherent ways to ship IPv6, in increasing order of scope
and ambition.

### Approach A — "Dual-stack opportunistic" (small)

**Scope:** Open IPv6 listening sockets alongside IPv4. Accept inbound
v6 connections. For outbound, prefer v6 when the remote endpoint has
a known v6 address (from any source: DNS AAAA, future Kad hint,
explicit user input). **Do not change the wire protocol or any file
format.** The Kad directory stays IPv4 — v6 is purely a side channel
for connections initiated with a v6 address already in hand.

**What this gets you:**
- Mobile and CGNAT users behind v4 NAT can still reach v6-reachable
  broadcasters using explicit `ed2k://|live|...|[v6]:port|/` links.
- Manual paste-link works across v6.
- mDNS LAN discovery can be extended to listen on `ff02::fb` for the
  v6-native LAN case.

**What this does NOT get you:**
- **Kad search returns IPv4 endpoints only.** A v6-only peer is
  invisible to Kad searches.
- No v6 entries in PEX gossip. So the viral propagation of v6
  endpoints requires an out-of-band channel.

**Effort:** ~1–2 weeks. The biggest unknown is whether the existing
`AsyncSocketEx` IPv6 paths actually work end-to-end. If yes, this is
a refactor. If no, it's an audit.

### Approach B — "Sidecar IPv6 Kad" (medium)

**Scope:** Run a second Kad instance ("Kad6") on the IPv6 transport,
with its own bootstrap nodes and its own routing table. Each peer
optionally participates in both Kad and Kad6. Publish operations
publish to both. Search operations query both and merge results.

**What this gets you:**
- Full directory of v6 peers.
- IPv4 Kad stays byte-identical to upstream — zero compat risk.
- v6-only peers can find each other and reach each other.
- Mixed-stack peers see the union.

**Drawbacks:**
- **Fragments the discovery network** — early v6 adopters see fewer
  peers in Kad6 than in v4 Kad, creating a chicken-and-egg problem.
- Doubles the maintenance cost (two Kad instances, two routing
  tables, two `nodes.dat` files).
- Doesn't help mixed-traffic flows where the broadcaster is v4 and
  the viewer is v6 (they need to find each other in *the same*
  directory).

**Effort:** ~3–4 weeks for the Kad6 instance plus integration glue.

### Approach C — "Full retrofit" (large, the real achievement)

**Scope:** Make every layer address-family aware. `CContact` carries
both v4 and v6 endpoints. Kad opcodes are extended (versioned). File
formats get version bytes. NAT-traversal code branches on family.
IPFilter gets a v6 table. PEX, mDNS, link formats — everything.

**What this gets you:**
- A single, unified directory where every peer carries its full
  reachability story (v4 LowID/HighID + v6 endpoint if any).
- Future-proof: when residential ISPs go v6-only, the system
  doesn't degrade.
- The "free HighID via v6" property that `MASTER_PLAN` highlights.

**Drawbacks:**
- **Months of work** — easily 8–12 weeks for the core protocol
  changes plus another 4 for IPFilter / metrics / link format /
  documentation.
- **Real compat risk with upstream eMule.** Every protocol extension
  needs careful TLV gating; bugs here are visible to the entire eD2K
  community.
- Hard to test thoroughly without a v6-native test network.

**Effort:** 3–4 months, full time.

---

## 5. Recommended phased plan

Three phases. Phase 1 alone gives the live-streaming use case most
of what it needs. Phase 2 unlocks Kad-directory v6. Phase 3 is the
optional "full achievement".

### Phase 1 — Live-traffic dual stack (1–2 weeks)

**Goal:** Our 5 new live opcodes + the WebServer + the dashboard
become IPv6-aware. The upstream eMule wire protocol is **not
touched**.

**Concrete changes:**
1. Add an `enum AddrFamily { AF4, AF6 }` and a `union { uint32 v4;
   in6_addr v6; } addr` struct for endpoint representation in our
   new live code (`LivePackets.h`, `LiveStreamManager.h`).
2. Extend `OP_LIVE_HEARTBEAT` PEX entries with a leading family byte:
   - `[byte family][20-byte payload]` (1 + 4 + 2 = 7 for v4, 1 + 16 + 2 = 19 for v6).
   - Receivers ignoring the v6 entries (because they're v4-only)
     drop them. Forward compat preserved.
3. `OP_LIVE_CHUNK_REQUEST/RESPONSE`, `OP_LIVE_PING/PONG` get
   address-family awareness in their dispatch but the on-wire format
   for v4-only connections is unchanged.
4. WebServer also binds `[::]:4711` alongside `0.0.0.0:4711`. The
   loopback gate accepts both `127.0.0.1` and `::1`.
5. `ed2k://|live|...|[2001:db8::1]:4662|...|/` bracketed link format
   parsed by `/api/live/direct_join`. Documented as fork-specific.
6. mDNS extended to also send/listen on `ff02::fb:5354` (the standard
   v6 mDNS multicast group; same port as v4 to keep config simple).
7. Bootstrap cache (`last_streams.json`) gains a `family` field
   per entry.

**Verification:**
- Two v6-only peers on the same LAN find each other via mDNS6 in
  <1 s.
- v6 paste link `[2001:db8::1]:4662` joins successfully from a v4
  CGNAT peer that can reach the broadcaster via v6.
- Mixed-stack peers prefer v6 when available (avoids hole-punch
  cost).

**Risk:** Low. We don't touch the upstream wire protocol; the only
thing we're modifying is our own opcode layer.

### Phase 2 — Kad-directory v6 hints (3–4 weeks)

**Goal:** A Kad search for a stream returns both v4 and (when
present) v6 endpoints for the broadcaster.

**Concrete changes:**
1. Publish operation for `live:HEXKEY` gains a Kad tag carrying the
   v6 endpoint, e.g. `TAG_ESE_LIVE_V6` = `[in6_addr][uint16 port]`.
   Standard Kad tag carries v4 as today.
2. Kad search results have a 2nd-pass enrichment: if the result
   record carries `TAG_ESE_LIVE_V6`, expose it to the
   `LiveStreamManager` alongside the v4 endpoint.
3. PEX gossip (already extended in Phase 1) propagates these v6
   endpoints virally — a viewer that finds the v4 endpoint via Kad
   learns the v6 endpoint via the heartbeat PEX from the
   broadcaster's other viewers.
4. `nodes.dat` and `clients.met` stay v4-only (we don't need to
   change them for live traffic; full retrofit is Phase 3).

**Verification:**
- Broadcaster on dual-stack publishes both endpoints.
- v6-only viewer's Kad search returns the v6 endpoint and the
  viewer joins via v6 without hole-punching.
- v4-only viewer's Kad search returns the v4 endpoint and the
  viewer behaves as today.

**Risk:** Medium. The Kad tag extension is wire-additive
(TLV-friendly) and the standard Kad code ignores unknown tags. We
should test with upstream eMule peers in the swarm to confirm no
crashes from oversized record payloads.

### Phase 3 — Full retrofit (optional, 3–4 months)

The classic eD2K + Kad goes dual-stack: `Contact` becomes
v4+v6, `nodes.dat` gets a version bump with v6 records, IPFilter
gains a v6 table, anti-Sybil rules learn about /64 prefixes.

**This is the "great achievement"** the user asked about. It is a
real engineering project of multiple person-months, but it would
make this fork the first eMule-derivative with full IPv6 support
and would be a significant contribution back to the upstream
community if they wanted to take the patches.

I'd only do Phase 3 if:
- Phase 1 + 2 have shipped and are in production for ≥3 months
- We have a small group of v6-native testers willing to provide
  measurements
- We have appetite for ~3 months of careful protocol-extension work

---

## 6. Risks and unknowns

| # | Risk | Mitigation |
|---|---|---|
| R1 | Existing `AsyncSocketEx` v6 paths are buggy / never tested | Audit + small unit test before relying on them in Phase 1 |
| R2 | Upstream eMule peers reject extended packets they don't understand | All extensions are TLV-additive + capability-flag gated; tested in mixed swarm before release |
| R3 | `ed2k://|live|...|[v6]:port|/` link format is fork-specific — won't work in upstream clients | Document as fork extension; emit both v4-only and v6 link variants when applicable |
| R4 | Test infrastructure: many dev machines are v4-only behind home NAT | Wireguard tunnel to a v6-capable VPS provides a v6 endpoint for testing |
| R5 | v6 reachability changes per network change (laptop home → café → mobile) | Re-probe v6 reachability on network change events; treat v6 endpoint as ephemeral cache, like v4 public IP |
| R6 | Anti-Sybil heuristics tuned for /24 are wrong for /64 (which is per-customer in v6) | Add separate per-/64 rate limit constant; default to looser than per-/24 because the prefix is exclusive per customer |
| R7 | Hole-punching code paths assume NAT, may misbehave on v6 | Add explicit `is_ipv6(target) → skip_holepunch` short-circuit early in the signaling code |

---

## 7. Is this a "gran logro"?

**Honest answer:** depends on which phase.

- **Phase 1 (live-traffic dual stack)**: ~2 weeks of work for a
  noticeable UX win for CGNAT and mobile users in our specific
  live-streaming use case. *Solid but not "great achievement"
  material.*
- **Phase 2 (Kad-directory v6 hints)**: another 3–4 weeks. **This
  is the achievement** for our specific app — it makes the
  "free HighID via v6" property of `MASTER_PLAN.md §11.3.8` actually
  reachable for live streams. Phase 1 alone gives reachability;
  Phase 2 gives *discovery* on v6.
- **Phase 3 (full retrofit)**: months of work. **This is the
  community-level achievement** — making eMule itself IPv6 native.
  If shipped and stable, this would plausibly be the most
  significant fork contribution since the 0.50 Kad integration in
  2007. The cost is correspondingly large.

My recommendation: **commit to Phase 1 + Phase 2 (~5–6 weeks
total)**. Park Phase 3 as a "would be nice if we have a quarter
free" item. The Phase 1+2 combination addresses our specific live-
streaming pain (CGNAT viewers can't see streams; mobile viewers
can't be relays) without taking on the full upstream-compatibility
burden of touching the classic eD2K file-sharing wire protocol.

---

## 8. One concrete first-step proposal

If you want to start tomorrow:

1. **Write a 30-line probe** in `LiveStreamManager::Init` that
   creates an `AF_INET6` UDP socket, attempts to bind `[::]:0`,
   measures whether it succeeds, and logs `[NET] IPv6 socket: OK`
   or `[NET] IPv6 socket: not available — reason: <getlasterror>`.
   Ship it. Collect this telemetry across our test users for a
   week. We learn the v6 capability of our actual user base.
2. In parallel, **audit `AsyncSocketEx` IPv6 paths** to determine
   if Phase 1 can re-use that abstraction or needs to bypass it.
   ~2 days.
3. **If the audit is green and v6 telemetry is encouraging**, kick
   off Phase 1 proper.

That gives a 1-week "let's see if this is worth pursuing" gate before
committing to the 6-week investment.

---

_Last updated: 2026-05-17._
