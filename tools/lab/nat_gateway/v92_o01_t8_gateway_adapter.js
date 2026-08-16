'use strict';

// In-process semantic boundary for O01 tests.  It deliberately owns the one
// mapping state used by every protocol and delegates all mutations to the
// already-tested lifecycle/model operations.
const {
  createMappingState, createMapping, renewMapping, expireMappings, deleteMapping,
  resetMappingState, snapshotInternalMappings,
} = require('./mapping_model');
const { applyPcpMapCommand, toPcpMapResponse } = require('./pcp_mapping_lifecycle');
const { applyUpnpAddPortMapping } = require('./upnp_mapping_lifecycle');
const { applyUpnpDeletePortMapping } = require('./upnp_mapping_delete');
const { readUpnpPortMapping, projectUpnpReadbackSoapResult } = require('./upnp_mapping_readback');

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const TRANSPORTS = Object.freeze(['tcp', 'udp']);

function pcpCommand(transport, lifetimeSeconds, nonce = transport === 'tcp' ? '01'.repeat(12) : '02'.repeat(12)) {
  return { protocol: 'pcp', operation: lifetimeSeconds === 0 ? 'delete' : 'map', transport,
    client_address: '192.0.2.10', nonce, internal_port: transport === 'tcp' ? 4662 : 4672,
    suggested_external_port: 0, suggested_external_address: '0.0.0.0', lifetime_seconds: lifetimeSeconds,
    options: { prefer_failure: false, port_set: null } };
}
function upnpCommand(transport) {
  const port = transport === 'tcp' ? 4662 : 4672;
  return { protocol: 'upnp', operation: 'add_port_mapping',
    service_type: 'urn:schemas-upnp-org:service:WANIPConnection:1', remote_host: '',
    external_port: port, transport, internal_port: port, internal_client: '192.0.2.10',
    enabled: true, description: `eSE O01 ${transport.toUpperCase()}`, lease_seconds: 0 };
}
function owned(protocol, transport) { return `o01.${protocol}.${transport}`; }

function createGatewayAdapter(options = {}) {
  const externalAddress = options.externalAddress || '198.51.100.10';
  const externalOctets = externalAddress.split('.').map(Number);
  if (externalOctets.length !== 4 || externalOctets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) throw new Error('O01_ADAPTER_EXTERNAL_ADDRESS_INVALID');
  const foreign = { mapping_id: 'foreign.persistent.tcp', protocol: 'upnp', transport: 'tcp',
    client_id: 'foreign-client', internal_address: '192.0.2.200', internal_port: 62000,
    requested_external_port: 62000, external_address: externalAddress, external_port: 62000,
    lease: { lifetime_seconds: 0, created_monotonic_ms: 0, expires_monotonic_ms: null },
    owner: { kind: 'none' }, epoch: 1, generation: 1 };
  let state = createMappingState({ epoch: 1, generation: 1, mappings: [foreign], baseline_mappings: [foreign] });
  let lastFault = 'renew_success';
  const traffic = { pcp_requests: 0, natpmp_requests: 0, upnp_add_requests: 0,
    upnp_get_requests: 0, upnp_delete_requests: 0, accepted_outcomes: 0, rejected_outcomes: 0,
    pcp_accepted: 0, pcp_rejected: 0, natpmp_accepted: 0, natpmp_rejected: 0,
    upnp_accepted: 0, upnp_rejected: 0,
    max_owned_mapping_count: 0 };
  const transactionBrand = new WeakMap();
  const pendingPairs = new Map();
  const now = () => {
    const value = typeof options.now === 'function' ? options.now() : 0;
    if (!Number.isSafeInteger(value) || value < 0) throw new Error('O01_ADAPTER_CLOCK_INVALID');
    return value;
  };
  function trackOwnedPeak() {
    const count = snapshotInternalMappings(state).filter((entry) => entry.client_id === 'o01-client').length;
    traffic.max_owned_mapping_count = Math.max(traffic.max_owned_mapping_count, count);
  }
  function transactPair(operation) {
    let candidate = state;
    for (const transport of TRANSPORTS) {
      if (typeof options.transitionHook === 'function') options.transitionHook(transport);
      candidate = operation(candidate, transport);
    }
    state = candidate;
    return observe();
  }
  function mapPair(protocol, lifetimeSeconds = 30) {
    if (!['pcp', 'natpmp', 'upnp'].includes(protocol)) throw new Error('O01_ADAPTER_PROTOCOL_INVALID');
    return transactPair((current, transport) => {
      if (protocol === 'pcp') return applyPcpMapCommand(current, pcpCommand(transport, lifetimeSeconds), {
        now_monotonic_ms: now(), client_id: 'o01-client', instance_id_digest: DIGEST_A,
        granted_lifetime_seconds: lifetimeSeconds,
        new_mapping: { mapping_id: owned(protocol, transport), external_address: externalAddress, external_port: transport === 'tcp' ? 54662 : 54672 },
      }).state;
      if (protocol === 'upnp') {
        const result = applyUpnpAddPortMapping(current, upnpCommand(transport), {
          client_id: 'o01-client', gateway_external_address: externalAddress, gateway_identity_digest: DIGEST_A,
          instance_id_digest: DIGEST_B, now_monotonic_ms: now(), table_capacity: 16,
        });
        if (!result.ok) throw new Error(`O01_ADAPTER_UPNP_${result.error_code}`);
        return result.state;
      }
      const port = transport === 'tcp' ? 4662 : 4672;
      return createMapping(current, { mapping_id: owned(protocol, transport), protocol, transport,
        client_id: 'o01-client', internal_address: '192.0.2.10', internal_port: port,
        requested_external_port: 0, external_address: externalAddress, external_port: port + 51000,
        lease: { lifetime_seconds: lifetimeSeconds, created_monotonic_ms: now(), expires_monotonic_ms: now() + lifetimeSeconds * 1000 },
        owner: { kind: 'natpmp-lease-scope', instance_id_digest: DIGEST_A, scope_id: 'o01' },
        epoch: current.epoch, generation: current.generation, atomic_group_id: `o01.${protocol}.pair`,
      }).state;
    });
  }
  function renewPair(protocol, lifetimeSeconds = 30) {
    return transactPair((current, transport) => {
      const mapping = snapshotInternalMappings(current).find((entry) => entry.mapping_id === owned(protocol, transport));
      if (!mapping) throw new Error('O01_ADAPTER_MAPPING_MISSING');
      if (protocol === 'pcp') return applyPcpMapCommand(current, pcpCommand(transport, lifetimeSeconds), {
        now_monotonic_ms: now(), client_id: 'o01-client', instance_id_digest: DIGEST_A,
        granted_lifetime_seconds: lifetimeSeconds, new_mapping: null,
      }).state;
      if (protocol === 'upnp') return applyUpnpAddPortMapping(current, upnpCommand(transport), {
        client_id: 'o01-client', gateway_external_address: externalAddress, gateway_identity_digest: DIGEST_A,
        instance_id_digest: DIGEST_B, now_monotonic_ms: now(), table_capacity: 16,
      }).state;
      return renewMapping(current, { mapping_id: mapping.mapping_id, epoch: current.epoch,
        generation: current.generation, owner: mapping.owner, lifetime_seconds: lifetimeSeconds,
        now_monotonic_ms: now() }).state;
    });
  }
  function expire() { state = expireMappings(state, now()).state; return observe(); }
  function restartEpoch(seconds) {
    if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > 0xffffffff) throw new Error('O01_ADAPTER_EPOCH_INVALID');
    state = resetMappingState(state, { epoch: seconds, generation: state.generation + 1 }).state;
    return observe();
  }
  function rejectStale(expectedGeneration) {
    const before = state;
    try { renewMapping(state, { mapping_id: snapshotInternalMappings(state)[0]?.mapping_id || 'missing',
      epoch: state.epoch, generation: expectedGeneration, lifetime_seconds: 30,
      now_monotonic_ms: now() }); } catch (_) {}
    if (state !== before) throw new Error('O01_ADAPTER_STALE_MUTATED');
    lastFault = 'stale';
    return observe();
  }
  function rejectForeign() {
    const before = state;
    try { renewMapping(state, { mapping_id: 'foreign.persistent.tcp', epoch: state.epoch,
      generation: state.generation, lifetime_seconds: 30, now_monotonic_ms: now() }); } catch (_) {}
    if (state !== before) throw new Error('O01_ADAPTER_FOREIGN_MUTATED');
    return observe();
  }
  function observe() {
    const mappings = snapshotInternalMappings(state);
    return Object.freeze({ epoch: state.epoch, generation: state.generation,
      mappings, pair_atomic: mappings.filter((entry) => entry.client_id === 'o01-client').length % 2 === 0 });
  }
  function observeProtocol() {
    const mappings = snapshotInternalMappings(state);
    const ownedMappings = mappings.filter((entry) => entry.client_id === 'o01-client');
    const transports = new Set(ownedMappings.map((entry) => entry.transport));
    const resources = typeof options.resources === 'function' ? options.resources() : {};
    const uint = (name) => Number.isSafeInteger(resources[name]) && resources[name] >= 0 ? resources[name] : 0;
    const live = ownedMappings.length > 0;
    traffic.max_owned_mapping_count = Math.max(traffic.max_owned_mapping_count, ownedMappings.length);
    return Object.freeze({
      gateway: Object.freeze({ generation: state.generation, epoch: state.epoch,
        mapping_count: mappings.length, pair_atomic: ownedMappings.length % 2 === 0 && (ownedMappings.length === 0 || (transports.has('tcp') && transports.has('udp'))),
        foreign_fixture_present: mappings.some((entry) => entry.mapping_id === 'foreign.persistent.tcp'), last_fault: lastFault }),
      product: Object.freeze({ topology_generation: state.generation,
        tcp_state: live && transports.has('tcp') ? 'VERIFIED' : 'WITHDRAWN',
        udp_state: live && transports.has('udp') ? 'VERIFIED' : 'WITHDRAWN',
        publisher_active: live && transports.has('tcp') && transports.has('udp'), journal_entry_count: ownedMappings.length }),
      resources: Object.freeze({ gateway_rss_bytes: uint('gateway_rss_bytes'), gateway_heap_bytes:uint('gateway_heap_bytes'),gateway_external_bytes:uint('gateway_external_bytes'),gateway_array_buffers_bytes:uint('gateway_array_buffers_bytes'),product_working_set_bytes: uint('product_working_set_bytes'),
        gateway_handles: uint('gateway_handles'), product_handles: uint('product_handles'), gateway_sockets: uint('gateway_sockets'),
        product_sockets: uint('product_sockets'), event_loop_lag_ms: uint('event_loop_lag_ms') }),
      traffic: Object.freeze({ ...traffic, final_owned_mapping_count: ownedMappings.length,
        final_owned_pcp: ownedMappings.filter((entry) => entry.protocol === 'pcp').length,
        final_owned_natpmp: ownedMappings.filter((entry) => entry.protocol === 'natpmp').length,
        final_owned_upnp: ownedMappings.filter((entry) => entry.protocol === 'upnp').length }),
    });
  }
  function applyPcp(command, requestWire) {
    const existing = snapshotInternalMappings(state).find((entry) => entry.protocol === 'pcp' && entry.transport === command.transport);
    const result = applyPcpMapCommand(state, command, {
      now_monotonic_ms: now(), client_id: 'o01-client', instance_id_digest: DIGEST_A,
      granted_lifetime_seconds: command.lifetime_seconds,
      new_mapping: existing || command.operation === 'delete' ? null : { mapping_id: owned('pcp', command.transport),
        external_address: externalAddress, external_port: command.transport === 'tcp' ? 54662 : 54672 },
    });
    state = result.state; trackOwnedPeak();
    return toPcpMapResponse(command, result, requestWire);
  }
  function applyNatPmp(command, sourceAddress) {
    if (command.operation === 'external-address') { return { response_type: 'external-address', result_code: 0, epoch: state.epoch, external_ip: externalOctets }; }
    const mappingId = owned('natpmp', command.transport);
    const existing = snapshotInternalMappings(state).find((entry) => entry.mapping_id === mappingId);
    if (command.operation === 'delete') {
      if (existing) state = deleteMapping(state, { mapping_id: mappingId, epoch: state.epoch, generation: state.generation, owner: existing.owner }).state;
      trackOwnedPeak();
      return { response_type: 'map', transport: command.transport, result_code: 0, epoch: state.epoch,
        internal_port: command.internal_port, external_port: 0, lifetime_seconds: 0 };
    }
    if (existing) state = renewMapping(state, { mapping_id: mappingId, epoch: state.epoch, generation: state.generation,
      owner: existing.owner, lifetime_seconds: command.lifetime_seconds, now_monotonic_ms: now() }).state;
    else state = createMapping(state, { mapping_id: mappingId, protocol: 'natpmp', transport: command.transport,
      client_id: 'o01-client', internal_address: sourceAddress, internal_port: command.internal_port,
      requested_external_port: command.suggested_external_port, external_address: externalAddress,
      external_port: command.transport === 'tcp' ? 55662 : 55672,
      lease: { lifetime_seconds: command.lifetime_seconds, created_monotonic_ms: now(), expires_monotonic_ms: now() + command.lifetime_seconds * 1000 },
      owner: { kind: 'natpmp-lease-scope', instance_id_digest: DIGEST_A, scope_id: 'o01' },
      epoch: state.epoch, generation: state.generation, atomic_group_id: 'o01.natpmp.pair' }).state;
    trackOwnedPeak(); return { response_type: 'map', transport: command.transport, result_code: 0, epoch: state.epoch,
      internal_port: command.internal_port, external_port: command.transport === 'tcp' ? 55662 : 55672, lifetime_seconds: command.lifetime_seconds };
  }
  function applyUpnp(command) {
    if (command.operation === 'delete_port_mapping') traffic.upnp_delete_requests++; else traffic.upnp_add_requests++;
    const context = { client_id: 'o01-client', gateway_external_address: externalAddress,
      gateway_identity_digest: DIGEST_A, instance_id_digest: DIGEST_B, now_monotonic_ms: now(), table_capacity: 16 };
    const result = command.operation === 'delete_port_mapping' ? applyUpnpDeletePortMapping(state, command, {
      gateway_external_address: context.gateway_external_address, now_monotonic_ms: context.now_monotonic_ms }) : applyUpnpAddPortMapping(state, command, context);
    if (result.ok) { state = result.state; trackOwnedPeak(); traffic.accepted_outcomes++; traffic.upnp_accepted++; } else { traffic.rejected_outcomes++; traffic.upnp_rejected++; }
    return result;
  }
  function prepare(protocol, transport, operation) {
    if (!['pcp','natpmp','upnp'].includes(protocol) || !TRANSPORTS.includes(transport) || typeof operation !== 'function') throw new Error('O01_ADAPTER_TRANSACTION_INVALID');
    const committed = state; const pending = pendingPairs.get(protocol);
    if (pending && pending.transports.has(transport)) throw new Error('O01_ADAPTER_PAIR_DUPLICATE');
    state = pending ? pending.state : committed;
    let response;
    try { response = operation(); } catch (error) { state = committed; pendingPairs.delete(protocol); throw error; }
    const candidate = state; state = committed;
    const token = Object.freeze({ protocol, transport });
    transactionBrand.set(token, { protocol, committed, candidate, response,
      transports: new Set([...(pending ? pending.transports : []), transport]) });
    return Object.freeze({ token, response });
  }
  function commitPrepared(token) {
    const tx = transactionBrand.get(token); if (!tx || tx.committed !== state) throw new Error('O01_ADAPTER_TRANSACTION_STALE');
    transactionBrand.delete(token);
    if (tx.transports.size === 1) { pendingPairs.set(tx.protocol, { state: tx.candidate, transports: tx.transports }); return false; }
    state = tx.candidate; pendingPairs.delete(tx.protocol); trackOwnedPeak(); return true;
  }
  function abortPrepared(token) { const tx=transactionBrand.get(token);if(!tx)return false;transactionBrand.delete(token);pendingPairs.delete(tx.protocol);return true; }
  function preparePcp(command, wire) { return prepare('pcp', command.transport, () => applyPcp(command, wire)); }
  function prepareNatPmp(command, source) { return prepare('natpmp', command.transport, () => applyNatPmp(command, source)); }
  function readUpnp(command) {
    traffic.upnp_get_requests++;
    const result = projectUpnpReadbackSoapResult(readUpnpPortMapping(state, command, {
      readback: 'full', gateway_external_address: externalAddress, now_monotonic_ms: now(), description_limit: 64 }));
    if (result.ok) { traffic.accepted_outcomes++; traffic.upnp_accepted++; } else { traffic.rejected_outcomes++; traffic.upnp_rejected++; }
    return result;
  }
  function recordWireOutcome(protocol, accepted) {
    if (!['pcp','natpmp'].includes(protocol) || typeof accepted !== 'boolean') throw new Error('O01_ADAPTER_WIRE_OUTCOME_INVALID');
    traffic[protocol === 'pcp' ? 'pcp_requests' : 'natpmp_requests']++;
    const outcome = `${protocol}_${accepted ? 'accepted' : 'rejected'}`;
    traffic[outcome]++;
    if (accepted) traffic.accepted_outcomes++; else traffic.rejected_outcomes++;
  }
  function cleanupOwned() {
    trackOwnedPeak();
    let candidate = state;
    for (const mapping of snapshotInternalMappings(candidate).filter((entry) => entry.client_id === 'o01-client')) {
      candidate = deleteMapping(candidate, { mapping_id: mapping.mapping_id, epoch: candidate.epoch,
        generation: candidate.generation, owner: mapping.owner }).state;
    }
    state = candidate; lastFault = 'final_boundary'; return observeProtocol();
  }
  return Object.freeze({ mapPair, renewPair, expire, restartEpoch, rejectStale, rejectForeign,
    observe, observeProtocol, applyPcp, applyNatPmp, applyUpnp, readUpnp, cleanupOwned,
    preparePcp, prepareNatPmp, commitPrepared, abortPrepared, recordWireOutcome });
}

module.exports = Object.freeze({ createGatewayAdapter });
