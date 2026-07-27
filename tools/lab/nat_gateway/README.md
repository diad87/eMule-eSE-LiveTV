# T8 simulated NAT gateway

Design status: `92-1.1` / `B01` only. There is intentionally no executable,
socket code or production behavior in this directory yet.

The normative architecture is
[`docs/V9.2_T8_ARCHITECTURE.md`](../../../docs/V9.2_T8_ARCHITECTURE.md).
Scenarios must validate against
[`scenario.schema.json`](scenario.schema.json) before any network adapter is
started.

## Chosen shape

- Location: `tools/lab/nat_gateway/`.
- Runtime: Node.js 22, strict JavaScript, standard library first.
- One foreground process with UPnP, PCP and NAT-PMP modules.
- One shared gateway state; protocol and network adapters do not own state.
- Pure reducer and injectable real/virtual monotonic clock.
- JSON/CLI control and append-only JSON Lines events.
- Logical adapters and all ports supplied by the scenario.
- Same process contract on the Windows host or inside the T8 VM.

The fixture is independent of MFC and does not import `libnatmap` codecs as
its oracle. Interoperability vectors will be copied from the existing codec
tests in the protocol cards, with an independent response implementation.

## Planned component layout

The names below reserve responsibilities, not implementation:

```text
nat_gateway/
  README.md
  scenario.schema.json
  bin/                    CLI / process entry
  control/                argv and JSONL command adapters
  domain/                 immutable state, reducer, allocation, ownership
  protocols/              pure UPnP, PCP and NAT-PMP codecs
  adapters/               UDP, HTTP and event/report sinks
  test/                   pure tests, vectors and adapter integration tests
```

Domain tests must run with fake adapters and a virtual clock, without
privileges or network access.

## Scenario contract

The root object contains:

- `schema_version`, stable `scenario_id` and deterministic `seed`;
- `clock`: real monotonic or explicitly advanced virtual time;
- gateway identity, epoch, generation, WAN and LAN addresses;
- bind addresses, logical interfaces and configurable protocol ports;
- enabled protocols and port-allocation policy;
- initial mappings, request counters and queued semantic responses;
- named fault rules;
- a mandatory sanitized-report privacy policy.

All objects are closed with `additionalProperties: false`. Unknown fields are
errors. Address formats require a Draft 2020-12 validator with IPv4/IPv6 format
assertions enabled. JSON Schema handles shape and scalar ranges; the future
loader must additionally reject duplicate IDs, invalid allocation ordering,
incoherent lease arithmetic, mapping collisions, incomplete atomic pairs and
listener/protocol mismatches.

Scenario files are private test inputs. Use only documentation or isolated lab
address space; never commit addresses, interface GUIDs or hostnames taken from
a real environment. The schema has no credential field.

## Command surface

Every entry point dispatches the same domain command:

```text
start
stop
reset
load-scenario
advance-time
list-mappings
delete-mapping
restart-epoch
export-report
get-status
```

The canonical live control transport is one JSON command per line on stdin
and one response per line on stdout. This avoids an administrative network
port and credentials. A lab runner owns the foreground child and its pipes
whether the child runs on the host or in a VM.

Example command envelope (illustrative only):

```json
{"schema":"ese.v92.t8.command/v1","request_id":"req-0001","command":"advance-time","arguments":{"delta_ms":1000}}
```

`advance-time` is valid only for the virtual clock. `load-scenario` is valid
only while stopped. `start` must validate the complete scenario and all bind
collisions before requesting the first socket effect.

## State rules

- Epoch belongs to the simulated gateway; generation is a separate, nonzero,
  process-local monotonic identity.
- Restarting epoch clears mappings and pending responses and advances
  generation once.
- Reset recreates the same baseline for the same command trace while never
  recycling generation inside the process.
- Finite leases use monotonic creation/expiry times. Lifetime zero represents
  a permanent stored mapping; protocol delete remains an operation.
- PCP ownership requires the matching 96-bit nonce; UPnP requires reconciled
  journal/description data; NAT-PMP is limited to the exact lease scope.
- Mapping collisions are keyed by external address, port and transport.

TCP and UDP protocol requests remain separate. `atomic_group_id` correlates a
test pair but does not invent gateway transaction semantics. A scenario can
accept TCP and reject/drop UDP so the product's rollback and snapshot
atomicity can be tested.

## Fault model

Each rule has a stable ID, request selector, deterministic trigger and one
strict action. The schema can describe delay/jitter, drop, duplicate, reorder,
wrong source, truncate, replay, rejection, lease cap, disappeared mapping,
gateway restart, WAN change, granted-port change and client conflict.

Rules are evaluated in declaration order against the already-incremented
request counter. Every match and action becomes a sanitized JSONL event.
There are no raw packet bodies in scenario queues or reports.

## JSONL and privacy

Events use schema `ese.v92.t8.event/v1`, a strictly increasing sequence,
monotonic time, scenario/run IDs, epoch, generation, protocol/transport,
mapping/fault IDs, outcome and stable reason code.

The canonical report always:

- classifies or digests addresses instead of exporting full addresses;
- hashes nonces, instance IDs, interface identities and owner tokens;
- omits packet payloads and authorization data;
- uses logical adapter names instead of physical NIC identifiers.

No credential or real environment address is embedded in these design files.

## Validation planned for the next cards

1. Parse the JSON document.
2. Validate it against Draft 2020-12 with format assertions.
3. Apply cross-field invariants without opening sockets.
4. Freeze the effective scenario and its hash.
5. Only then allow `start` to ask adapters to bind.

Invalid input must identify the field and return a stable reason code.

## STOP

Stop and return to architecture review if:

- a pure test needs administrator rights, a socket, a real NIC or a sleep;
- state and sockets become mixed;
- an adapter bypasses the reducer;
- reset is missing or nondeterministic;
- generation is reused or confused with epoch;
- partial TCP/UDP is reported as an atomic success;
- ownership is guessed from a successful MAP;
- validation occurs after any bind;
- logs expose full IPs, nonce/token, payloads or credentials.
