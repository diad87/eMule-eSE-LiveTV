# eMule eSE LiveTV v0.70b-eSE7.1.2 — 2026-05-17

Second point release of the day, on top of
[v0.70b-eSE7.1.1](RELEASE_NOTES_v0.70b-eSE7.1.1.md). Fixes the silent failure
that made every LiveTV broadcast invisible/unreachable across the network.

---

## The fix

When a broadcaster published a stream to the Kad DHT, the entry stored on
holder nodes had **no broadcaster IP**. Viewers searching for streams got
back results with `IP=0` and the defensive filter at
[LiveKadBridge.cpp:523](srchybrid/LiveKadBridge.cpp) rejected every one of
them as an invalid endpoint. Net effect: the channel directory at `/live`
showed at most the broadcaster's local self-publish, no cross-PC discovery
ever worked, and `kadResultsAccepted` stayed at 0 forever.

**Root cause:** the live-stream publish in
[Search.cpp::PrepareLivePacketForTags](srchybrid/kademlia/kademlia/Search.cpp)
sent `TAG_SOURCEPORT` but not `TAG_SOURCEIP`. The receiving holder code at
[KademliaUDPListener.cpp:1341](srchybrid/kademlia/net/KademliaUDPListener.cpp)
was supposed to derive `TAG_SOURCEIP` from the UDP packet source, but this
falls apart in three real-world cases:

1. The holder is running upstream eMule (not this fork) — has no such code at all.
2. The publisher and holder are the same machine (self-publish via loopback) — `uIP` comes through as 0.
3. NAT/UDP weirdness — `uIP` can be 0 on certain paths.

The first false-success during testing came from a byte-order bug in the
initial attempt (publish included the IP, but in the wrong byte order — viewers
discovered `161.22.11.88` instead of `88.11.22.161` and connected to a random
machine). Both fixes are now in.

**Changes**

- [`srchybrid/kademlia/kademlia/Search.cpp`](srchybrid/kademlia/kademlia/Search.cpp)
  — explicit `TAG_SOURCEIP = theApp.GetPublicIP()` in the publish, in host
  byte order to match the existing convention used by `ipstr()` and the
  receiver path.
- [`srchybrid/kademlia/net/KademliaUDPListener.cpp`](srchybrid/kademlia/net/KademliaUDPListener.cpp)
  — defensive guard: holders no longer override the publisher's `TAG_SOURCEIP`
  with 0 when the UDP source IP is unavailable.

---

## Upgrading from v7.1.1

Hot-swap is supported but this time you need the new **`emule.exe`** (not
just `ese-server.exe`). The fix is entirely in the C++ Kad code; the Node
side is unchanged.

Two options, same as v7.1.1:

1. **Re-download the ZIP** and extract over your v7.1.1 install.
2. **Hot-swap `emule.exe`**: download `emule.exe` from this release's
   assets and replace yours. Close eMule first; reopen after.

---

## What this does NOT fix

- Existing zombie publishes from v7.1.1 and earlier are still in Kad with
  TTLs of up to ~10 minutes. You'll see them as `Discovered stream "X" from
  161.22.11.88:38362` for a while (wrong byte order, won't actually
  connect). They'll age out.
- The pre-existing streaming-time crash inherited from upstream eMule 0.70b
  ([known issue from v7.1.1](RELEASE_NOTES_v0.70b-eSE7.1.1.md#known-issues))
  is still open.

---

## Verifying the fix works

After upgrading, broadcast a testpattern:

```
http://localhost:8080/api/live/broadcast/start?source=testpattern&title=Test&bitrate=1500
```

Then check the eMule log (bottom panel). You should see Kad search results
arriving like:

```
eSE Kad: Discovered stream "Test" from 88.11.22.161:38362 (0 viewers, 1500kbps)
```

with **your actual public IP** in correct byte order, not `IP=0` or some
reversed garbage.

`http://localhost:8080/api/live/monitor` should also show
`kadResultsAccepted` climbing instead of staying at 0 (assuming there's
something out there other than your own broadcast).

---

GPL-2.0-only.
