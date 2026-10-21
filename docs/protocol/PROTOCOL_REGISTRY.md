# eSE protocol registry

The eSE-owned CSV files in this directory are the governed registry for wire
identifiers owned by the fork. They prevent accidental reuse of a value within
the same protocol namespace and document how an extension behaves with older
clients. Their authority is subject to the blocking governance debt recorded
below; the checker must not be described as complete while that debt remains.

`EXTERNAL_INTEROP_CATALOG.csv` is deliberately different: it records contracts
observed in pinned third-party implementations. It is evidence for compatibility
work, never an allocation, endorsement or claim of ownership.

## Registry files

| File | Contents |
|---|---|
| [`OPCODES.csv`](OPCODES.csv) | eD2K, Kad and protocol-selector opcodes |
| [`TAGS.csv`](TAGS.csv) | eD2K/Kad tag identifiers |
| [`CAPABILITIES.csv`](CAPABILITIES.csv) | eSE and fork capability bits |
| [`TUNNEL_SERVICES.csv`](TUNNEL_SERVICES.csv) | Services inside tunnel cells |
| [`KAD6_MESSAGES.csv`](KAD6_MESSAGES.csv) | Kad6 inner message identifiers |
| [`KRP_MESSAGES.csv`](KRP_MESSAGES.csv) | Relay-control message identifiers |
| [`ESE_WIRE.csv`](ESE_WIRE.csv) | Owned magic, ALPN, signature domains and peer-profile constants |
| [`EXTERNAL_INTEROP_CATALOG.csv`](EXTERNAL_INTEROP_CATALOG.csv) | Observed third-party contracts, commits, compatibility verdicts and send gates; non-authoritative |

Legacy rows default to `value_kind=number`; `TAGS.csv` also permits explicit
`string` identifiers. String values use C/Python-compatible escapes for magic
bytes (for example `\x00ESECTL1`), never the implicit C string terminator.
The checker inspects EseWireProtocol.h and compares decoded values. Collision
keys include namespace and value kind; string tags do not allocate classic
numeric slots. `design` means no receiver/emitter is enabled by this declaration.
The new file and selected-code checks do not resolve REG-DEBT-001 or prove
that the named transports, discovery, or advertisements are operational.

Each row records a symbolic name, value, namespace, introduction
version, lifecycle status, capability gate, format, compatibility behavior and
the implementation location.

The external catalog has its own schema because direction, frozen upstream
commit, classification, local relation and security/send policy matter more
than code ownership. External symbols must not be copied into the eSE-owned
CSVs until eSE implements and legitimately owns that surface.

## Ownership boundary

- `OPCODES.csv`, `TAGS.csv`, `CAPABILITIES.csv`, `TUNNEL_SERVICES.csv`,
  `KAD6_MESSAGES.csv` and `KRP_MESSAGES.csv` form the governed eSE-owned set,
  subject to the explicit blocking exception `REG-DEBT-001` below.
- `EXTERNAL_INTEROP_CATALOG.csv` is an observational compatibility ledger.
- Narrative documents and forum posts allocate nothing.
- The same numeric value may be an exact alias, a different dialect, a real
  collision or unresolved. The external catalog must classify it before any
  emitter is proposed.
- A receiver may be implemented behind a closed gate after golden/fuzz tests;
  an emitter additionally requires capability negotiation, downgrade behavior
  and a verified ownership/reservation decision.

### Known governance debt

`REG-DEBT-001`: `CT_FORK_CAPABILITIES (0xF0)` exists in code but is not yet
represented in `TAGS.csv`; the checker selects it and reports a named blocking
debt instead of pretending the registry is complete. In classic eMule headers
the numeric slot is `CT_EMULE_RESERVED1`. The debt has
two distinct wire contexts: server login advertises `CAP_FORK_IPV6_WIRE 0x01`
to the private JEmuleServer dialect, while peer HELLO always emits the tag with
the defined bits `IPV6_WIRE 0x01`, `IPV6_KAD 0x02`, `IPV6_DUALSTACK 0x04` and
`ED25519 0x08` as applicable.

This exception is recorded rather than hidden. `REG-DEBT-001` blocks every
external emitter gate, not only presentation: `0xF0` cannot be treated as an
ecosystem capability or reused for eMuleQt/eNode interoperability. A
dedicated protocol change must decide whether to retain it as an explicitly
private alias, migrate it or deprecate its emission, then update code, registry,
fixtures and compatibility evidence together. Resolution requires separate
peer-HELLO and server-login fixtures; proving one context never authorizes or
defines the other.

## Namespaces

Numeric values are unique only inside their dispatch namespace. Reusing the
same byte in two independent namespaces is valid.

Examples:

- `EMULEPROT-CC` — sub-opcodes below `OP_EMULEPROT`;
- `KADEMLIA-UDP` — Kad UDP request/response opcodes;
- `UDP-PROTOCOL` — top-level packet protocol selectors;
- `TAG-ED2K` — tag-name bytes;
- `CAP-ESE` and `CAP-FORK` — independent capability bitmaps;
- `TUNNEL-CELL` — service IDs inside an authenticated tunnel cell;
- `KAD6-INNER` — messages inside the Kad6 frame;
- `KRP-CONTROL` — relay control frames.

Reviewers must compare both namespace and value before reporting a collision.

## Status values

| Status | Meaning |
|---|---|
| `stable` | Shipped compatibility surface |
| `experimental` | Implemented but capability/preference gated |
| `deprecated` | Accepted for compatibility but not used for new traffic |
| `reserved` | Allocated compatibility value |

A reservation is not evidence that a runtime service is enabled or supported.

## Compatibility rules

1. Fork extensions are additive.
2. A sender must not emit a gated message until the peer advertised the
   corresponding capability.
3. Unknown eSE tags must remain safely ignorable by older clients.
4. Legacy IPv4 fields stay present when an additive IPv6 field is used.
5. Tag counts must match the number of serialized tags exactly.
6. A previously shipped opcode or layout cannot be reassigned.
7. Experimental listeners and output paths must remain closed when their
   preferences are off.
8. Internal tunnel/Kad6/KRP identifiers are never interpreted outside their
   enclosing frame.

## Automated check

Run:

```powershell
python tools\check_protocol_registry.py
python tests\test_external_interop_catalog.py
```

The check fails when:

- two rows own the same `(namespace, value)`;
- a fork-owned symbol exists in code but is absent from the registry;
- a code value disagrees with the registered value;
- a non-reserved registry row has no implementation symbol.

The external-catalog check separately fails when its schema, ID sequence,
commit pins, sources, classifications, receiver-first policies or v9.8 safety
invariants drift. It also prevents an observed external symbol from being
silently presented as eSE-owned.

The check runs as part of `tools/run_alpha_tests.ps1 -Suite Core`.

## Updating the registry

When changing a wire identifier:

1. choose the correct namespace;
2. add or update the CSV row in the same change as the code;
3. provide the capability gate and downgrade behavior;
4. run the registry check;
5. test against an older eSE peer and vanilla eMule when the outer protocol is
   shared.

Do not allocate identifiers from narrative documentation. The eSE-owned CSVs
and matching code definitions are the governed local set, subject to
`REG-DEBT-001`. The external catalog is authoritative only about what snapshot
was audited and what compatibility verdict eSE recorded.
