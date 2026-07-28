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

## NAT-PMP C01 vectors

`natpmp_vectors.js` contains frozen, literal NAT-PMP goldens with exact native
file-and-line provenance. It performs no packet behavior and is checked by a
pure Node test; the table, including the deliberately absent UDP response, is
documented in [`docs/V9.2_T8_NATPMP_VECTORS.md`](../../../docs/V9.2_T8_NATPMP_VECTORS.md).

## NAT-PMP C02 request decoder

`natpmp_request_decoder.js` is a pure, independent request boundary. It accepts
only non-shared, non-detached `Buffer` or `Uint8Array` input, makes a defensive
byte copy, and returns a frozen normalized command. Shared views fail closed:
they cannot provide a snapshot protected from concurrent mutation. It accepts
exactly the two-byte external-address request or a twelve-byte UDP/TCP MAP
request, validates version `0`, request opcodes `0`/`1`/`2`, zero reserved bytes
and a nonzero internal port. Lifetime zero is normalized to `delete` and
requires a zero suggested external port. Malformed inputs raise
`NatPmpRequestError` with stable `reason_code` and `field_path`; no socket,
timer, clock, filesystem or productive codec is used.

## NAT-PMP C03 response encoder

`natpmp_response_encoder.js` is a pure response boundary. It accepts one exact
ordinary-object shape for an external-address response or a UDP/TCP MAP
response and returns a newly allocated `Buffer` in network byte order. The
closed result-code set is NAT-PMP `0..5`. Rejected external-address responses
carry `0.0.0.0`; rejected MAP responses echo their nonzero internal port and
carry zero external port and lifetime. The epoch remains explicitly
configurable. A successful external-address response requires a nonzero IPv4
address, matching the client's usable-address gate. Successful MAP responses require either a nonzero port and
lease, or both zero for a delete acknowledgement. All wire-integer fields,
including IPv4 octets, reject JavaScript `-0` so zero has one canonical input
representation before it is encoded.

Input is read exclusively through data descriptors, so proxies, getters,
class instances, arrays, unknown keys, sparse IPv4 values and invalid scalar
ranges fail closed without evaluating hostile values. The module uses no
socket, timer, clock, filesystem or productive codec. It checks the C01
external-address and TCP MAP goldens exactly; UDP's response opcode is derived
only by the protocol rule and is not added to the C01 table.

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
before element traversal. Unknown property names are rendered as `*` in public
and validation errors so a hostile key cannot become an error-message channel.
Mapping projection revalidates the complete protocol-specific owner proof and
exports only domain-separated digests for nonce, gateway identity or lease
scope. `createCanonicalReport` also whitelists its effective
configuration, normalized states, counters and fault summary before combining
them with the sanitized mapping projection. Finite leases are checked again for
exact monotonic expiry arithmetic before projection.

## C04 UDP loopback boundary

`natpmp_udp_server.js` is the deliberately thin UDP fixture boundary.  It only
binds `udp4` to an explicit IPv4 address (never a wildcard), accepts packets of
at most 12 bytes, validates an explicit IPv4 source allow-list, then calls the
injected application exactly once with the frozen decoded command and a frozen
source snapshot.  The application is the mapping/ownership-policy boundary;
the UDP adapter neither owns nor reproduces that policy.

The queue is FIFO and fixed at 32 waiting datagrams.  Excess traffic is dropped
before application work.  `close()` removes reception, discards waiting work,
aborts the callback signal and returns without waiting for a callback that
ignores cancellation; any late callback result is observed and cannot send once
closing begins.

The required `event_sink` receives only the adapter envelope
`{ protocol, outcome, reason_code }`: it never contains a raw address, port,
packet or mapping field.  An outer scenario adapter may canonicalize those
closed labels into the structured log after it has the required context; C04
does not invent transport for malformed or external-address traffic.

`event_sink` is a trusted, injected, synchronous `void` observer, not a
scenario-supplied plugin or an asynchronous extension point.  It must return
`undefined` and must not start detached asynchronous work.  A synchronous
throw is contained, and an ordinary accidentally returned native Promise is
observed defensively, but work deliberately hidden by the callback (for
example, a rejected Promise wrapped in a `Proxy`) is outside the adapter's
containment boundary: JavaScript cannot safely recover that Proxy's target.
The production runner must supply the repository-owned structured-log sink.

## C05 NAT-PMP deterministic faults

`natpmp_fault_injector.js` is the post-encoder, pre-send fault boundary.  Its
first closed action, `drop`, returns no packet, so the UDP adapter emits the
sanitized `response-dropped` event and performs no send.  The injector receives
only an owned response copy, the frozen decoded command and the lifecycle abort
signal.  It never mutates the encoder output or mapping state.

The `delay` action uses a cancellable scheduler and returns an owned packet copy
only after the fixed delay.  C05 accepts `jitter_ms: 0`; seeded jitter selection
belongs to the shared fault selector, so this protocol edge cannot introduce
runtime randomness.

`reject` maps a closed protocol label to NAT-PMP result `1..5` and zeros every
response field that cannot be asserted on failure while preserving the request
opcode and echoed internal port.

`change-port` replaces only the external port of a successful non-delete MAP
response; it is rejected for other packet/command combinations and when the
configured port would not change the wire result.

`cap-lease` deterministically reduces a successful MAP lifetime to a positive
configured cap strictly below the encoded lease.

`restart-gateway` replaces only the response epoch with the configured
post-restart value, including the normative reset value zero.  An unchanged
epoch is rejected as an ineffective fault.

`truncate` produces the malformed mode by returning the exact configured
prefix, from an empty datagram through 15 bytes.  It cannot grow or reuse the
owned response buffer.

## C06 diagnostic smoke client

`natpmp_diagnostic_client.js` is a loopback-only TCP MAP probe for the smoke
gate.  It sends one bounded request, accepts a response only from the exact
configured gateway endpoint, parses the NAT-PMP success fields independently
and returns a sanitized frozen `mapped` state.  Its timeout is capped at five
seconds and every exit closes the UDP handle.

## PCP D01 wire study

`pcp_vectors.js` freezes the native PCP MAP and ANNOUNCE test bytes with exact
source provenance. It covers the base TCP request, renewal address, native
IPv6, PREFER_FAILURE, PORT_SET, delete, MAP response and ANNOUNCE pair. The
field layout and productive client behavior are documented in
[`docs/V9.2_T8_PCP_VECTORS.md`](../../../docs/V9.2_T8_PCP_VECTORS.md). No
complete UDP golden is fabricated.

## PCP D02 MAP decoder

`pcp_map_request_decoder.js` is a pure, fail-closed MAP boundary. It snapshots
genuine byte views, validates the PCP version, request opcode, 96-bit nonce
(including RFC 6887's legal all-zero value), TCP/UDP protocol, internal port,
deletion semantics and aligned options,
ignores received reserved bits as required, then returns a deeply immutable
command. It decodes `PREFER_FAILURE` and `PORT_SET`, rejects unsupported
mandatory options and ignores well-formed unknown optional options as PCP
requires. Stable errors carry the PCP result code needed by the later UDP
server.

## PCP D03 MAP response encoder

`pcp_map_response_encoder.js` independently emits closed PCP MAP responses.
It supports TCP/UDP, every native result code, IPv4-mapped and native IPv6
addresses, successful deletion, `PREFER_FAILURE` and `PORT_SET`. Rejection
responses snapshot and echo the bounded original request wire, including
invalid nonce/protocol/port and unknown or malformed options; they also apply
the parsed/unparsed client-address-tail rule from RFC 6887. Successful
responses reject unspecified, loopback, link-local, multicast and broadcast
external addresses. The semantic nonce remains explicit so later fault
scenarios can intentionally emit a mismatched value without hidden mutation.

## PCP D04 ANNOUNCE codec

`pcp_announce_codec.js` provides the independent pure ANNOUNCE request and
response boundary. The decoder accepts only a bounded, aligned PCP request,
snapshots genuine byte views, requires version `2` and request opcode `0`, and
returns the canonical client address while ignoring the request lifetime and
reserved fields as RFC 6887 requires. Well-formed optional options are ignored,
including MAP's optional-to-process `PORT_SET`; unknown mandatory options
return `UNSUPP_OPTION`, while known mandatory MAP-only or structurally
malformed options return `MALFORMED_OPTION`.

The semantic encoder emits only a successful 24-byte ANNOUNCE response with
zero lifetime and an explicit epoch. Every error must use error-echo mode,
which preserves the bounded original request and applies the same
parsed/unparsed client-address-tail rule used by MAP errors while overwriting
only the common response fields. Closed input shapes, hostile-storage
rejection and defensive copies keep the codec free of sockets, timers, clocks,
state and productive-code dependencies.

## PCP D05 UDP boundary

`pcp_udp_server.js` is the bounded IPv4/IPv6 UDP edge for MAP and ANNOUNCE.
It binds only an explicit unicast address, snapshots at most 1100 bytes,
accepts only configured source addresses and compares the canonical datagram
source with the Client IP Address carried in the PCP common header before the
mapping application can run. A mismatch returns PCP `ADDRESS_MISMATCH` (`12`)
with zero lifetime and an injected epoch, without reading or mutating mapping
state.

The adapter returns safe wire-preserving errors for decodable MAP and ANNOUNCE
requests and `UNSUPP_OPCODE` for a bounded unknown request opcode. Version
rejection has precedence over opcode rejection. Short or misaligned requests
of at least 24 bytes receive `MALFORMED_REQUEST`; oversized datagrams are
snapshotted only through byte 1100 and receive a bounded malformed response.
Datagrams whose response bit is already set are dropped, preventing response
loops. Application responses remain protocol-bound: a MAP request can only
pass through the MAP encoder and ANNOUNCE through its own encoder.

The FIFO has one active item and at most 32 waiting datagrams. Closing removes
reception, discards waiting work, aborts an active application/send and is
idempotent. Events expose only the closed
`{ protocol, outcome, reason_code }` envelope. The epoch provider, application
and event sink are injected; this boundary owns no clock, lease, nonce,
mapping or ownership state. The injected epoch provider is authoritative for
both success and error wire responses; an application-supplied epoch is
validated by its codec but cannot override the gateway epoch.

The trusted application receives a fourth frozen request context containing
the routed opcode kind and an owned wire snapshot. D06 uses that private copy
to construct normative error-echo responses. It is never sent to the event
sink, structured log or public report.

## PCP D06 mapping lifecycle

`pcp_mapping_lifecycle.js` is the pure bridge from a decoded MAP command to
the shared immutable mapping model. Time, client identity, granted lifetime
and a possible new allocation are explicit closed inputs. Before processing,
expired mappings are removed at the supplied monotonic instant.

An existing PCP mapping is identified by internal address, transport and
internal port. A matching 96-bit nonce renews that exact mapping without
changing its external endpoint; a different nonce returns `NOT_AUTHORIZED`
with the rounded-up remaining lifetime and cannot mutate state. A correctly
owned deletion removes the mapping, while retransmitting deletion after it is
gone returns success as RFC 6887 requires. An expired mapping can be recreated
with a new nonce and allocation. Multiple live PCP mappings for the same
internal tuple are treated as an invariant failure rather than selected
arbitrarily.

An existing static mapping is returned unchanged with the recommended maximum
lifetime for MAP, but PCP cannot delete it. New allocations are canonicalized
and must be usable unicast external endpoints before any model mutation.

`PREFER_FAILURE` rejects a different existing or proposed endpoint with
`CANNOT_PROVIDE_EXTERNAL`; absence of an allocation returns bounded
`NO_RESOURCES`. TCP and UDP remain separate mapping spaces. The response
projector converts only branded lifecycle results into the strict D03 MAP
encoder shapes, snapshots bounded request wire for error echo and emits
zero-port/zero-address deletion success. Its raw mapping result is an internal
domain value and must never be exported directly to logs or reports.

## PCP D07 epoch restart and recovery

`gateway_epoch_restart.js` implements the pure, protocol-independent
`restart-epoch` reducer slice. PCP exercises it in D07; NAT-PMP and UPnP must
use the same transition rather than maintain protocol-local generations.
It installs the scenario's restart epoch, clears every active gateway mapping
and advances the process-local generation exactly once. Baseline mappings are
retained only for a later explicit `reset`; they never become active during an
epoch restart.

Pending responses belong to branded gateway state and are bounded to the
scenario queue maximum of 4096. The transition atomically empties that trusted
queue, emits one ordered `CANCEL_RESPONSE` effect per entry and records the
closed `gateway_restarted` event before the returned state can process a
recovery request. A late completion must still match the current epoch,
generation and queued response ID before it can produce `SEND_RESPONSE`.
Consequently, an old epoch/generation completion is rejected without an
effect, and a subsequent PCP MAP is a fresh allocation carrying the new epoch
and generation.

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
