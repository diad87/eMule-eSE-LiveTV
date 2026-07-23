# eSE protocol registry

The CSV files in this directory are the source of truth for wire identifiers
owned by the eSE fork. They prevent accidental reuse of a value within the
same protocol namespace and document how an extension behaves with older
clients.

## Registry files

| File | Contents |
|---|---|
| [`OPCODES.csv`](OPCODES.csv) | eD2K, Kad and protocol-selector opcodes |
| [`TAGS.csv`](TAGS.csv) | eD2K/Kad tag identifiers |
| [`CAPABILITIES.csv`](CAPABILITIES.csv) | eSE and fork capability bits |
| [`TUNNEL_SERVICES.csv`](TUNNEL_SERVICES.csv) | Services inside tunnel cells |
| [`KAD6_MESSAGES.csv`](KAD6_MESSAGES.csv) | Kad6 inner message identifiers |
| [`KRP_MESSAGES.csv`](KRP_MESSAGES.csv) | Relay-control message identifiers |

Each row records a symbolic name, numeric value, namespace, introduction
version, lifecycle status, capability gate, format, compatibility behavior and
the implementation location.

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
```

The check fails when:

- two rows own the same `(namespace, value)`;
- a fork-owned symbol exists in code but is absent from the registry;
- a code value disagrees with the registered value;
- a non-reserved registry row has no implementation symbol.

The check runs as part of `tools/run_alpha_tests.ps1 -Suite Core`.

## Updating the registry

When changing a wire identifier:

1. choose the correct namespace;
2. add or update the CSV row in the same change as the code;
3. provide the capability gate and downgrade behavior;
4. run the registry check;
5. test against an older eSE peer and vanilla eMule when the outer protocol is
   shared.

Do not allocate identifiers from narrative documentation. The CSV files and
the matching code definitions are authoritative.
