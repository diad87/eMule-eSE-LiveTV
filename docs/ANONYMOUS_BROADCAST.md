# Anonymous Broadcast — Relay-Protected Streaming

> **Goal.** Allow a broadcaster to emit a live stream **without
> publishing their own IP in the Kad directory**. Their IP is known
> only to 2-3 recruited relay peers; the rest of the network (viewers,
> Kad observers, crawlers) sees only the relays.
>
> **Explicit non-goal.** This is not Tor. Single-hop. A determined
> relay can deanonymize the broadcaster. ISPs, nation-states, and
> traffic analysis are out of scope — for those threat levels, the
> answer is VPN or Tor in front of the broadcaster.
>
> **What this buys you.** Casual privacy. The broadcast link
> (`ed2k://|live|HEX||TITLE|/`) reveals nothing, the Kad directory
> reveals nothing, screenshots reveal nothing. Only the 3 relays
> the broadcaster chose know the origin.

---

## 1. Problem and motivation

### 1.1 What today's broadcasts leak

When a broadcaster goes live today (without the anonymous mode):

| Channel | What's revealed about the broadcaster |
|---|---|
| `link_direct` shared on web | IP + port, printed in URL |
| `link_anonymous` shared on web | Nothing in URL, **but** any viewer pasting the link triggers a Kad lookup that returns the IP |
| Kad search `live:<HEXKEY>` | IP + port, regardless of which link variant was shared |
| PEX gossip via `OP_LIVE_HEARTBEAT` | IP + port propagates virally to every peer in O(log N) heartbeats |
| mDNS LAN multicast | IP + port broadcast every 30s on the LAN |
| `livehash:<HEXKEY>` self-published by viewers | Indirect (only viewer IPs, but those viewers connected directly to broadcaster) |

In other words: **the streamKey alone is sufficient to find the
broadcaster's current IP**. The anonymous link variant only protects
against passive URL-string leaks (Twitter screenshots, search engine
indexing), not against active lookups.

### 1.2 What broadcasters actually want

Two distinct use cases the user articulated:

1. **Plausible deniability for casual content.** *"I don't want my
   home IP printed on a web page where I share a stream — somebody
   might broadcast something controversial and the IP becomes
   forever-associated with my identity."*
2. **Dynamic-IP friendliness.** *"My ISP changes my IP every few
   days. Any link with an IP embedded becomes invalid."*

(Item 2 is already solved by the existing `link_anonymous` variant
— the link carries only the streamKey, and the Kad lookup at click
time returns the current IP. We do not need to do anything more for
this case.)

This document addresses item 1: **what would it take to make the
broadcaster's IP genuinely not appear in Kad / not propagate via PEX /
not be discoverable by anyone holding only the streamKey?**

---

## 2. Threat model

### 2.1 Adversaries we defend against

| Adversary | Defended? | How |
|---|---|---|
| Passive scraper of public web pages collecting IPs from URLs | ✓ Yes | Link string carries no IP (already true with `link_anonymous`) |
| Search engine indexing public posts | ✓ Yes | Same |
| Any peer on the Kad network with the streamKey doing a lookup | ✓ Yes | Broadcaster never self-publishes; only relays appear in Kad |
| PEX-gossip observer in the mesh | ✓ Yes | PEX entries name only relays as broadcast endpoints |
| LAN observer on a network the broadcaster is not on | ✓ Yes | mDNS announcements emitted only by relays (relays opt into broadcasting on their own LANs) |
| Viewer connecting to the stream | ✓ Yes | Viewer dials a relay; never sees the broadcaster's IP |

### 2.2 Adversaries we explicitly do NOT defend against

| Adversary | Why not |
|---|---|
| A recruited relay turning malicious / colluding | Single-hop architecture. The relay receives chunks from the broadcaster — it must know the broadcaster's IP. Mitigated (not eliminated) by relay rotation and friends-first recruitment. For stronger guarantees: use Tor in front of the broadcaster, or wait for multi-hop V4 work. |
| The broadcaster's ISP | Sees outbound TCP/UDP from the broadcaster regardless of overlay. Out of scope — use a VPN. |
| Nation-state adversary with passive network observation across multiple links | Out of scope — use Tor. |
| Traffic-timing correlation attacks | Out of scope — chunk arrival timing at the relays gives away the broadcaster source. Mitigated only by full mix-network constructions, which we do not build. |

---

## 3. Architecture

### 3.1 The topology

```
                       ┌─────────────────┐
                       │   BROADCASTER   │
                       │  (real IP X)    │
                       └────────┬────────┘
                                │
              push chunks       │       push chunks
              ┌─────────────────┼─────────────────┐
              │                 │                 │
         ┌────▼────┐       ┌────▼────┐       ┌────▼────┐
         │ RELAY 1 │       │ RELAY 2 │       │ RELAY 3 │
         │ (IP A)  │       │ (IP B)  │       │ (IP C)  │
         └────┬────┘       └────┬────┘       └────┬────┘
              │                 │                 │
       publish "live:HEXKEY"    │                 │
            to Kad              │                 │
              │                 │                 │
              │  Viewers dial whichever relay     │
              │  Kad search returns (round-robin) │
              │  ─────────────────────────────    │
              ▼                 ▼                 ▼
        ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐
        │  V1  │  │  V2  │  │  V3  │  │  V4  │  │  V5  │
        └──────┘  └──────┘  └──────┘  └──────┘  └──────┘
                          (viewers see relays' IPs only)
```

Default 3 relays. Configurable. Each relay publishes itself in Kad
as if it were the broadcaster (with a tag noting `role=relay`, see
§4.1). The broadcaster is invisible to the Kad directory.

### 3.2 Single-hop tradeoff explicitly acknowledged

The relays know the broadcaster's IP because the chunks have to
come from somewhere. This is the cost of avoiding multi-hop onion
routing (which would add 2-3 seconds of latency per hop and require
months of additional work).

Mitigations:

- **Friends-first recruitment** (§5.1) — the user picks trusted
  friends as preferred relays when available
- **Relay rotation** (§5.4) — relays are rotated every 30 minutes;
  any single relay sees the broadcaster's IP for at most that window
- **Capability advertising** — broadcasters can blacklist specific
  peers from relay recruitment (e.g. known anti-piracy crawlers)

If those mitigations are insufficient for your threat model, the
correct answer is to run the broadcaster behind a VPN or Tor. The
relay-protected mode is a 90%-good improvement over no protection;
it is not a 100% guarantee.

---

## 4. Wire protocol

### 4.1 Capability bit

A new capability flag `CAP_LIVE_RELAY` is advertised in the eD2K
hello handshake's extension flags. Peers without this bit are not
considered for recruitment.

**Backward compat:** unmodified upstream eMule clients do not
advertise this bit, so they are simply never recruited as relays.
They continue to function as file-sharing peers without disruption.

### 4.2 New opcodes

Four new opcodes, all TLV-prefixed for future extensibility:

| Opcode | Code | Payload (TLV) | Direction |
|---|---|---|---|
| `OP_LIVE_RELAY_REQUEST` | `0xE9` | `streamKey(16B) + bitrateHint(4B) + durationHint(4B, 0=unknown) + capabilityFlags(1B)` | Broadcaster → candidate relay |
| `OP_LIVE_RELAY_ACCEPT` | `0xEA` | `streamKey(16B) + maxViewers(1B) + role(1B, always =relay) + relayCapabilityFlags(1B)` | Relay → broadcaster |
| `OP_LIVE_RELAY_DECLINE` | `0xEB` | `streamKey(16B) + reasonCode(1B)` | Relay → broadcaster |
| `OP_LIVE_RELAY_HEARTBEAT` | `0xEC` | `streamKey(16B) + activeViewerCount(2B) + relayHealthByte(1B)` | Broadcaster ↔ relay (every 30s) |

`reasonCode` values: `1=at_capacity`, `2=not_capable`,
`3=blacklisted_broadcaster`, `4=other`.

`relayHealthByte` bits: `0x01=healthy`, `0x02=chunk_buffer_low`,
`0x04=upload_saturated`, `0x08=about_to_drop`.

### 4.3 Kad publish format (relay side)

Each relay publishes itself in Kad under `live:HEXKEY` (same
keyword as the standard broadcast) but with an additional Kad tag
`TAG_ESE_LIVE_ROLE = 1` (relay) instead of `0` (origin). The tag is
already documented for DISC-S15 (Sybil defense — distinguishing
relays from broadcasters); we re-use that infrastructure.

The Kad record looks like (TLV-additive, ignored by upstream):

```
streamKey: <16 bytes>
publisherIP: <relay's IP, not broadcaster's>
publisherPort: <relay's TCP port>
TAG_ESE_LIVE_ROLE: 1            (relay)
TAG_ESE_LIVE_BITRATE: <kbps>
TAG_ESE_LIVE_TITLE: <UTF-8>
TAG_ESE_LIVE_RELAY_GROUP: <16-byte random group id>   (NEW for anonymous)
TAG_ESE_LIVE_RELAY_CAPACITY: <max viewers this relay accepts>
```

`TAG_ESE_LIVE_RELAY_GROUP` lets viewers identify that multiple Kad
entries with the same streamKey are different relays for the same
broadcast (not duplicate publications or Sybil spam). The group ID
is generated once by the broadcaster and shared with all 3 relays
at recruitment time.

### 4.4 Viewer experience: unchanged

Viewers continue to do a Kad search for `live:HEXKEY`. They receive
multiple entries (one per relay), pick one (preferring lowest RTT
or highest capacity), and dial it. They never know it's a relay
versus the origin — the chunk delivery is byte-identical.

The C++ viewer code does NOT need a new capability bit; it just
dials whatever Kad gives back. **This means the anonymous broadcast
mode is compatible with viewers running prior fork versions** — they
treat the relay as if it were the broadcaster.

---

## 5. Recruitment protocol

### 5.1 Friends-first, anycast fallback

Selected via user feedback (2026-05-17). Algorithm:

```
TARGET_RELAY_COUNT = 3  // configurable
recruited = []

# Phase 1: friends list (trusted)
for friend in thePrefs.GetFriendsList() ordered by uptime descending:
    if friend has CAP_LIVE_RELAY:
        accept = send_OP_LIVE_RELAY_REQUEST(friend, streamKey, bitrate, ...)
        if accept and accept.maxViewers > 0:
            recruited.append(friend)
        if len(recruited) >= TARGET_RELAY_COUNT:
            break

# Phase 2: anycast via Kad keyword "livehelp:HEXKEY" (existing
# anycast infrastructure from V2-S22)
if len(recruited) < TARGET_RELAY_COUNT:
    candidates = kad_search("livehelp:" + streamKey, max_results=20)
    for c in candidates ordered by tier descending, then RTT ascending:
        if not c.has(CAP_LIVE_RELAY):
            continue
        if c in blacklist:
            continue
        accept = send_OP_LIVE_RELAY_REQUEST(c, streamKey, bitrate, ...)
        if accept and accept.maxViewers > 0:
            recruited.append(c)
        if len(recruited) >= TARGET_RELAY_COUNT:
            break
```

Logging: every recruitment attempt + outcome goes to `LIVE_LOG("AB", ...)`
so the user can see in the dashboard which relays were considered
and why each accepted/declined.

### 5.2 Capacity negotiation

Each relay candidate advertises its `maxViewers` in the
`OP_LIVE_RELAY_ACCEPT` response. The broadcaster's recruitment
target is:

```
expected_total_viewers = max(estimated_audience, 10)
total_capacity_needed = ceil(expected_total_viewers × 1.5)  // 50% headroom

while sum(recruited_relay_capacities) < total_capacity_needed
      and len(recruited) < TARGET_RELAY_COUNT × 2:    // cap at 6 even if uncertainty grows
    recruit_more()
```

So if a relay says "I can serve 5 viewers" and another says
"I can serve 30", and the broadcaster estimates 30 viewers, the
broadcaster picks the 30-viewer relay first and stops.

### 5.3 Fail-loud when no relays

Per user feedback: never silently fall back to direct mode.

```
if len(recruited) == 0:
    show_dialog("No relays available", error_modal)
    options:
        - "Try again" (re-run recruitment)
        - "Emit in direct mode (your IP will be visible)" (explicit opt-out)
        - "Cancel broadcast"
```

This means a broadcaster with no friends online AND no SUPER_SEEDER
peers available will see an explicit error — they must consciously
choose to lose anonymity. Acceptable cost of the privacy guarantee.

### 5.4 Relay rotation (background)

Every 30 minutes, the broadcaster:

1. Recruits 1 fresh relay
2. Transfers viewer flow to the fresh relay (it publishes to Kad;
   the old relay sets `relayHealthByte=about_to_drop` so viewers
   migrate during the 60s Kad TTL window)
3. Tombstones the old relay (it publishes a tombstone, viewers
   already on it finish their chunks then disconnect)

This bounds the window in which any single relay knows the
broadcaster's IP to 30-90 minutes. A long-running broadcast that
lasts 12 hours will go through ~24 relay rotations.

Configurable (off by default for simplicity in v1; on by default in
v2 once we've gathered usage telemetry).

---

## 6. Failure modes & UX

### 6.1 Relay drops mid-broadcast

Detection: `OP_LIVE_RELAY_HEARTBEAT` missing for 60s, OR explicit
`OP_LIVE_RELAY_DECLINE` mid-stream (e.g. relay's network died).

Action: broadcaster recruits a replacement using §5.1, transparent
to viewers. If we drop below 1 active relay, the broadcaster's
stream is effectively offline until at least one is found — the
broadcaster sees a yellow warning toast.

### 6.2 All relays gone

If recruitment fails repeatedly and zero relays are active for
>60s, the broadcast is paused with a modal:

> "All your relays disconnected. Reconnecting attempts have failed
> for 60s. Options:
> - Wait (we keep trying every 30s)
> - Switch to direct mode (your IP will become visible)
> - Stop broadcast"

### 6.3 Relay turns malicious

A relay could log the broadcaster's IP and dox them later. There is
no cryptographic prevention. Mitigations:

- Friends-first recruitment: trusted relays are picked first
- Rotation: bounds the window of exposure per relay
- Blacklist: users can blacklist specific peer IDs from being
  candidates (UI not in v1; manual via preferences.ini)
- Reporting: a future v2 feature might let users report a relay
  that doxxed them, building a community blacklist; out of scope
  for v1

---

## 7. Sprint plan

| ID | Title | Effort | Files touched |
|---|---|---|---|
| **AB-S01** | Wire protocol: new opcodes + capability bit | 2-3 d | `LivePackets.{h,cpp}`, `LiveProtocol.{h,cpp}`, `ListenSocket.cpp` |
| **AB-S02** | Broadcaster recruitment logic (friends-first + anycast) | 3-4 d | `LiveStreamManager.{h,cpp}` |
| **AB-S03** | Relay accept/decline + capacity advertising | 2-3 d | `LiveStreamManager.{h,cpp}` |
| **AB-S04** | Relay publishes to Kad under `live:HEXKEY` with `role=1` tag | 2-3 d | `LiveKadBridge.{h,cpp}` |
| **AB-S05** | Broadcaster → relay chunk push (reuse existing chunk transfer) | 1-2 d | `LiveStreamManager.{h,cpp}` |
| **AB-S06** | Relay health monitoring + replacement on churn | 2-3 d | `LiveStreamManager.{h,cpp}` |
| **AB-S07** | UI: "Anonymous broadcast" checkbox in broadcast wizard | 1 d | `live_tv_page.js`, `channel_api.js` |
| **AB-S08** | UI: "No relays available" dialog (fail-loud) | 1 d | `live_tv_page.js` |
| **AB-S09** | Telemetry: relay count, recruitment latency, rotation events | 1 d | `WebServer.cpp` (`/api/live/metrics` extension), `LiveStreamManager.{h,cpp}` |
| **AB-S10** | Mixed-swarm testing (3 relays + 1 broadcaster + 3 viewers + 1 upstream eMule) for 1h soak | 2-3 d | `tools/stress-test/` |
| **AB-S11** | (Optional v2) Relay rotation every 30 min, opt-in flag | 2 d | `LiveStreamManager.{h,cpp}` |
| **AB-S12** | (Optional v2) Relay blacklist UI + persistence | 1-2 d | `live_tv_page.js`, `Preferences.{h,cpp}` |

**Total v1 (S01-S10):** ~3 weeks (15-22 days of focused work, ~30%
overhead for testing per the backward-compat memory).

**Total v2 (+ S11-S12):** ~4 weeks.

---

## 8. Backward compatibility analysis

Per [feedback memory `feedback_backward_compat.md`](#) — every
extension must work with upstream eMule 0.70b and prior fork versions.

| Surface | Compat status |
|---|---|
| New opcodes 0xE9-0xEC | Gated by `CAP_LIVE_RELAY` capability bit. Upstream eMule never advertises the bit, never receives the opcodes. ✓ |
| New Kad tag `TAG_ESE_LIVE_RELAY_GROUP` | TLV-additive. Upstream Kad ignores unknown tags. ✓ |
| Viewers running prior fork versions | Dial relay IPs from Kad as if they were broadcaster IPs. Chunk transfer is byte-identical. ✓ |
| Viewers running upstream eMule | They are file-sharing peers, not live viewers. Not affected. ✓ |
| `ed2k://|live|HEX||TITLE|/` link format | Unchanged. The relay publishes under the same `live:HEXKEY` keyword. ✓ |
| Existing `link_anonymous` flow | Unchanged. The flow naturally finds relays via Kad without knowing they're relays. ✓ |

**Risk:** if a viewer running a v6.x fork connects to a relay (v7.x)
serving an anonymous broadcast, and the v6.x viewer doesn't know
about role=relay tag, it might try to mark the relay as the
"broadcaster" in its UI. This is cosmetic — the chunk transfer still
works. Fix: v6.x viewers display "broadcaster" instead of "relay";
v7.x+ viewers display the correct label. No correctness impact.

---

## 9. Testing requirements

Per the backward-compat memory, before any merge:

1. **Unit tests** for the new opcodes' serialization (round-trip a packet through `LivePackets::Pack` and `Unpack`, verify byte-for-byte).
2. **Mixed-swarm CI test** for ≥1 hour:
   - 1 broadcaster in anonymous mode (3 relays)
   - 3 viewers (mix of v7.x and v6.x)
   - 1 upstream eMule 0.70b peer (file-sharing only)
   - Verify: zero crashes, zero rejected packets, viewer playback uninterrupted, upstream peer's file-sharing functionality intact.
3. **Failure injection**: kill one relay mid-broadcast, verify recruitment + viewer continuity.
4. **Kad pollution test**: have a Sybil node publish 100 fake `live:HEXKEY` entries with role=0 (claiming to be the broadcaster). Verify viewers prefer entries with `role=1` + matching `TAG_ESE_LIVE_RELAY_GROUP` over the fakes.
5. **Long soak** (24h) with realistic churn to validate relay rotation if enabled.

---

## 10. Decision record

| Decision | Choice | Rationale |
|---|---|---|
| Default relay count | 3 | Sweet spot for redundancy without overloading broadcaster uplink |
| Recruitment source | Friends-first, anycast fallback | Best balance of trust and availability |
| Behavior when no relays | Fail with explicit dialog | Preserve privacy guarantee; no silent regression |
| Single-hop vs multi-hop | Single-hop | Multi-hop is months of work; out of scope. User explicitly said "no busco nivel tor" |
| Viewer-side changes | None | Maintain compatibility with prior fork versions |
| Relay rotation | Off in v1, on in v2 | Ship the simpler thing first, learn from telemetry |

---

_Last updated: 2026-05-17._
