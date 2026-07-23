# libreach

`libreach` is a standalone C++17 library for encoding peer reachability and
selecting a bounded connection path without depending on MFC, Kad or sockets.

The host supplies endpoints and side effects; the library owns the portable
codec and state machine.

## Design contract

- No sockets or background threads.
- Single-threaded host calls.
- C ABI for non-C++ consumers.
- Generation-counted peer handles.
- Deferred destruction and lock-free statistics snapshots.
- Capability-based selection instead of a single LowID/HighID flag.
- Explicit fallback to the host's classic connection behavior.

The host injects time, randomness, packet transmission, transport opening and
rendezvous signaling.

## Layout

| Path | Purpose |
|---|---|
| `include/reach/reach.h` | Public C ABI |
| `include/reach/reach_types.h` | Public wire and capability types |
| `include/reach/reach_codec.h` | Reachability-vector codec |
| `include/reach/reach_cascade.h` | Pure path-selection function |
| `src/reach_context.cpp` | Context and peer lifecycle |
| `src/reach_codec.cpp` | Strict encoder and compatible decoder |
| `src/reach_cascade.cpp` | Connection cascade |
| `tests/` | Golden vectors and host-actuator tests |

## Build and test

From a Visual Studio developer prompt:

```bat
cd libreach
make.bat
```

The script builds the library and runs its codec, facade, cascade and actuator
tests. Exit code 0 means the suite passed.

## Reachability vector

All multi-byte scalars are little-endian.

```text
offset  size   field
0       1      version
1       2      capability flags
3       1      rendezvous count (0..3)
4       22*n   NodeID(16) + IPv4(4) + UDP port(2)
...     ...    optional preserved TLVs
```

The producer rejects invalid reserved flags and oversized rendezvous lists.
The decoder preserves unknown trailing data so a newer vector can be relayed
without reinterpreting it.

## Host integration

The host:

1. creates a context with callback functions;
2. adds a peer and its decoded reachability vector;
3. supplies current direct/rendezvous candidates;
4. asks the cascade for the next applicable layer;
5. performs the transport action through `open_transport`;
6. reports success or failure;
7. removes the peer before destroying the context.

Runtime policy, UI and network ownership remain outside the library.
