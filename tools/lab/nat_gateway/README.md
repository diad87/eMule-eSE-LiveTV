# T8 simulated NAT gateway

Implementation status: `92-1.2` / `B05` adds the pure structured event log and
canonical public report projection.
There is intentionally no socket code or production behavior in this directory.

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

## Offline scenario loader (B02)

`scenario_loader.js` exposes `loadScenarioFromObject`,
`loadScenarioFromText` and `loadScenarioFromFile`. Each performs, in this
order, bounded input handling, Draft 2020-12 schema validation with strict
IPv4/IPv6 checks, cross-field validation and a defensive immutable copy. No
socket, timer, log or adapter is touched by the loader.

Failures are `ScenarioValidationError` values with stable `reason_code` and
`field_path`. The loader rejects unknown fields, disabled protocol references,
invalid ranges or leases, duplicated IDs, external mapping collisions and
incomplete/incoherent TCP+UDP atomic groups. It accepts a shared PCP/NAT-PMP
UDP port because their future adapter deliberately demultiplexes the two wire
protocols; other enabled UDP listener collisions remain invalid.

The only dependency is locked `ajv@8.20.0` (MIT), instantiated via
`ajv/dist/2020`; address format assertions use Node's `net.isIP`. File loading
uses only the explicitly supplied path, enforces a 1 MiB byte limit and rejects
malformed UTF-8. It does not search paths, read environment configuration or
emit scenario data.

## Injectable clock (B04)

`clock.js` is the sole time port available to the lab domain. It exports
`VirtualMonotonicClock` and `RealMonotonicClock`, each with `now_ms()` and
`advance_ms(delta_ms)`. Values are non-negative safe integers measured in
milliseconds; neither class uses UTC. The virtual clock is deterministic and
is the only clock that accepts `advance_ms`. The real clock accepts an
injected monotonic source (the default wraps the Node standard `performance`
clock) and fails closed if that source is invalid or regresses.

`ClockError` exposes stable `reason_code` and `field_path`. No reset method is
provided: reset is a gateway-state operation, not a reversal of monotonic
time. Unit tests inject every clock source and use no timer, sleep or socket.
The mapping-model integration test passes `clock.now_ms()` explicitly into
renewal and expiry operations, proving a lease remains live before its
deadline, expires exactly at it, renewal moves the deadline, and expiry cannot
be revived.

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

## Structured log and report (B05)

`structured_log.js` is a pure boundary: it takes explicit event/state inputs,
uses no clock, sockets, timers or I/O, and exports `createStructuredLog`,
`projectPublicMappings` and `createCanonicalReport`.  Events are restricted to
`ese.v92.t8.event/v1`; `append` assigns a strictly increasing sequence and
rejects regressing explicit monotonic time.  `canonicalJson` sorts object keys
for stable JSONL independent of caller property insertion order.

All boundary objects use explicit whitelists. Unknown event, mapping and
top-level report fields fail closed; unknown fields inside public report
sections are deliberately omitted, and no unknown field is ever copied.
The v1 event, outcome and reason-code vocabularies are closed, versioned and
append-only: they are semantic labels, never caller-controlled free text.
`event` accepts the documented `map_created`/request/map lifecycle, response,
fault, restart/time, run and invariant labels only. Allocation strategies are
likewise restricted to `requested-or-next`, `range` and `forced`.

Every variable identifier that can reach the public channel is projected as a
stable domain-separated SHA-256 digest: scenario, run, mapping, fault, atomic
group, gateway, client and owner identifiers all have distinct domains. Thus
JSONL, mapping projections and canonical reports retain correlation without
emitting raw IDs; applied fault IDs are sorted digests. Mappings retain only
protocol data, lease/version fields and classified/digested addresses.
PCP nonce, owner scope/description, raw IPs, payloads, credentials and error
details cannot enter event or public-report output. Proxies are rejected before
any trap can run, and sparse arrays (including `new Array(n)`) are rejected
before element traversal. `createCanonicalReport` also whitelists its effective
configuration, normalized states, counters and fault summary before combining
them with the sanitized mapping projection. Finite leases are checked again for
exact monotonic expiry arithmetic before projection.

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
