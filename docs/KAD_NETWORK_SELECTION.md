# Kad2 and Kad6 network selection

eMule eSE exposes Kad2 and Kad6 as two independent checkboxes under
**Preferences > Connection > Network**. A fresh profile enables both.

## Selection model

| Stored mask | Kad2 | Kad6 | Runtime behavior |
| ---: | :---: | :---: | --- |
| `0` | off | off | Kad is stopped |
| `1` | on | off | Classic Kad2 only |
| `2` | off | on | Native Kad6 only |
| `3` | on | on | Both protocol planes run in parallel (default) |

The selected value is stored as `KadNetworkMask` in the `[Connection]`
section of `preferences.ini`. Disabling UDP temporarily makes the effective
mask `0`, but does not erase the two checkbox selections.

Profiles which predate `KadNetworkMask` migrate as follows:

- `NetworkKademlia=1` becomes mask `3`, enabling Kad6 as requested for the
  new default.
- `NetworkKademlia=0` becomes mask `0`.
- A valid explicit mask always wins over the legacy boolean.
- An invalid mask fails through the same migration rule and is logged.

For downgrade safety, the legacy `NetworkKademlia` key mirrors the Kad2 bit,
not the aggregate mask. Therefore a Kad6-only profile does not silently
re-enable Kad2 when opened by an older build that cannot understand Kad6.

## Protocol isolation

Kad2 and Kad6 share the application's UDP listener and top-level lifetime,
but not their traffic gates or connection state:

- Kad2 owns the classic routing zone, `KADEMLIA2_*` packets, classic searches,
  publishing, firewall tests, buddies, callbacks and `nodes.dat` bootstrap.
- Kad6 owns the native signed routing table, `KADEMLIA3_*` packets and native
  source-record lookup/publication over eligible IPv4 or IPv6 endpoints.
- Turning one plane off closes its receive and send paths before its pending
  work is drained. It never falls back to the other plane unless that plane
  is also selected.
- Changing either checkbox while Kad is running applies immediately. Shared
  objects remain alive when one plane continues, avoiding a full reconnect.

Classic keyword search, comments, friend lookup and the current LiveTV
directory bridge still require Kad2. Kad6-only remains useful for native
Kad6 routing and source records, and the UI/API report the two states
separately so this limitation is not hidden.

## Status and API

The main status text, Kad window and network information dialog show Kad2 and
Kad6 independently. `/api/status` and `/api/network/connect` retain their
aggregate Kad fields and add:

- `kad_configured_mask`
- `kad_running_mask`
- `kad2_running` / `kad2_connected`
- `kad6_running` / `kad6_connected`
- `kad6_verified_contacts`

`kad6_connected` is true only after an authenticated native response from a
currently verified contact; merely starting the plane is reported as
running/connecting.

## Verification

Automated coverage includes:

- all four masks, migration, UDP suspension, hot-add/remove deltas and
  downgrade compatibility in `test_kad_network_policy.cpp`;
- static integration guards for UI controls, defaults, persistence, packet
  isolation and API fields in the dashboard regression suite;
- the complete standalone policy suite and Release x64 application build.

Run the focused checks from the repository root:

```powershell
srchybrid\tests\make.bat
Set-Location srchybrid\eSE
npm test
```
