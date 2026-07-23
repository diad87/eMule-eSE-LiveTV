# libkad6

`libkad6` contains standalone C++17 codecs and validation primitives for the
experimental Kad6 overlay. It is MFC-free and does not open sockets or start
threads.

The eMule host owns routing policy, persistence, identities, randomness and
network I/O. The library owns canonical framing, bounded decoding and
cryptographic message validation.

## Safety boundary

- Kad6 runtime advertisement is capability and preference gated.
- Kad6 public exit is off by default in eSE 9.0.0-beta.1.
- Internal message IDs are valid only inside a Kad6 frame.
- Decoders enforce size, count and allocation limits before processing input.
- Signed records use canonical serialization.
- Replay, quota and expiry fields are validated by the corresponding codec.
- Experimental support in the binary is not a public-service claim.

## Layout

| Path | Purpose |
|---|---|
| `include/kad6/kad6_frame.h` | Outer Kad6 frame |
| `include/kad6/kad6_search.h` | Search messages |
| `include/kad6/kad6_publish.h` | Source publication and leases |
| `include/kad6/kad6_gateway.h` | Gateway messages |
| `include/kad6/kad6_quota.h` | Anonymous quota messages |
| `include/kad6/kad6_routing.h` | Routing records |
| `include/kad6/kad6_crypto.h` | Canonical crypto helpers |
| `src/` | Implementations |
| `tests/` | Codec, vector, adversarial and integration tests |
| `vectors/` | External wire/crypto vectors |

## Build and test

From a Visual Studio developer prompt:

```bat
cd libkad6
test_all.bat
```

The script builds the standalone tests, runs the vector suites and exercises
the parser fuzz targets. A non-zero exit code indicates failure.

## Host integration

The host is responsible for:

- enabling the feature only after explicit policy checks;
- choosing and authenticating a tunnel circuit;
- storing persistent keys securely;
- supplying a CSPRNG and clock;
- enforcing network and bandwidth policy;
- shutting down listeners and advertisements when a kill switch is used.

The eSE wire registry for Kad6 inner messages is
[`docs/protocol/KAD6_MESSAGES.csv`](../docs/protocol/KAD6_MESSAGES.csv).
