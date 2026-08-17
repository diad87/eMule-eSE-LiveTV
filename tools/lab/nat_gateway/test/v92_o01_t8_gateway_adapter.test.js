'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createGatewayAdapter } = require('../v92_o01_t8_gateway_adapter');
const { validateObservation } = require('../v92_o01_bridge_protocol');
const { decodeNatPmpRequest } = require('../natpmp_request_decoder');
const { decodePcpMapRequest } = require('../pcp_map_request_decoder');
const { NATPMP_VECTORS } = require('../natpmp_vectors');
const { PCP_VECTORS } = require('../pcp_vectors');

function natPmpCommand(name) {
  return decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS[name].hex, 'hex'));
}

function pcpPacket(transport = 'tcp', lifetimeSeconds = 7200) {
  const wire = Buffer.from(PCP_VECTORS.map_tcp_request.hex, 'hex');
  wire.writeUInt32BE(lifetimeSeconds, 4);
  if (transport === 'udp') {
    wire[36] = 17;
    wire.writeUInt16BE(4672, 40);
  }
  return wire;
}

test('O01 adapter shares one state across PCP, NAT-PMP and UPnP readback', () => {
  let time = 1000; const adapter = createGatewayAdapter({ now: () => time });
  adapter.mapPair('pcp'); adapter.mapPair('natpmp'); adapter.mapPair('upnp');
  const snapshot = adapter.observe();
  assert.equal(snapshot.mappings.length, 7); assert.equal(snapshot.pair_atomic, true);
  assert.deepEqual(new Set(snapshot.mappings.map((entry) => entry.protocol)), new Set(['pcp','natpmp','upnp']));
  time += 10000; adapter.renewPair('pcp'); adapter.renewPair('natpmp');
  assert.equal(adapter.observe().generation, 1);
});

test('pair transaction does not publish half a conflicting cross-protocol pair', () => {
  let fail = false;
  const adapter = createGatewayAdapter({ now: () => 1000,
    transitionHook(transport) { if (fail && transport === 'udp') throw new Error('injected-second-member-failure'); } });
  adapter.mapPair('natpmp');
  const before = adapter.observe();
  fail = true;
  assert.throws(() => adapter.renewPair('natpmp'), /injected-second-member-failure/);
  assert.deepEqual(adapter.observe(), before);
});

test('stale generation rejection is byte-stable and epoch restart is the only increment', () => {
  const adapter = createGatewayAdapter({ now: () => 1000 }); adapter.mapPair('natpmp');
  const before = adapter.observe(); adapter.rejectStale(999); adapter.rejectForeign(); assert.deepEqual(adapter.observe(), before);
  const restarted = adapter.restartEpoch(22); assert.equal(restarted.generation, before.generation + 1);
  assert.equal(restarted.mappings.length, 1);
  assert.equal(restarted.mappings[0].mapping_id, 'foreign.persistent.tcp');
});

test('expiry removes both members while permanent UPnP mappings survive', () => {
  let time = 1000; const adapter = createGatewayAdapter({ now: () => time });
  adapter.mapPair('natpmp', 30); adapter.mapPair('upnp'); time += 30001;
  const snapshot = adapter.expire(); assert.equal(snapshot.mappings.length, 3);
  assert.ok(snapshot.mappings.every((entry) => entry.protocol === 'upnp'));
});

test('formal lifetime clamp and logical expiry are atomic and clock regression fails closed', () => {
  let time = 1000; const adapter = createGatewayAdapter({ now: () => time, maximumLifetimeSeconds: 120 });
  adapter.mapPair('pcp', 7200);
  assert.deepEqual(adapter.observe().mappings.filter((entry) => entry.client_id === 'o01-client')
    .map((entry) => entry.lease.lifetime_seconds), [120,120]);
  const expired = adapter.expireOwned(); assert.equal(expired.mappings.length, 1);
  assert.equal(expired.mappings[0].mapping_id, 'foreign.persistent.tcp');
  adapter.mapPair('natpmp', 7200);
  assert.deepEqual(adapter.observe().mappings.filter((entry) => entry.client_id === 'o01-client')
    .map((entry) => entry.lease.lifetime_seconds), [120,120]);
  const before = adapter.observe(); time = 999;
  assert.throws(() => adapter.renewPair('natpmp', 7200), /CLOCK_INVALID/);
  time = 1000;
  assert.deepEqual(adapter.observe(), before);
  let changing = 2000; const moving = createGatewayAdapter({ now: () => changing++, maximumLifetimeSeconds: 120 });
  assert.doesNotThrow(() => moving.mapPair('natpmp', 7200));
  for (const mapping of moving.observe().mappings.filter((entry) => entry.client_id === 'o01-client')) {
    assert.equal(mapping.lease.expires_monotonic_ms,
      mapping.lease.created_monotonic_ms + mapping.lease.lifetime_seconds * 1000);
  }
});

test('protocol observation expires owned leases at their physical deadline', () => {
  let time = 1000;
  const adapter = createGatewayAdapter({ now: () => time, maximumLifetimeSeconds: 120 });
  adapter.mapPair('natpmp', 7200);
  time = 120999;
  assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count, 2);
  time = 121000;
  const expired = adapter.observeProtocol();
  assert.equal(expired.traffic.final_owned_mapping_count, 0);
  assert.equal(expired.product.publisher_active, false);
  assert.equal(expired.product.journal_entry_count, 0);
  assert.equal(adapter.observe().mappings.filter((entry) => entry.mapping_id === 'foreign.persistent.tcp').length, 1);
});

test('wire epoch advances from physical time, resets independently and covers map, announce and delete responses', () => {
  let time = 1000;
  const adapter = createGatewayAdapter({ now: () => time, maximumLifetimeSeconds: 120 });
  const natMap = adapter.applyNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  const pcpMapWire = pcpPacket();
  const pcpMap = adapter.applyPcp(decodePcpMapRequest(pcpMapWire), pcpMapWire);
  assert.equal(natMap.epoch, 1);
  assert.equal(pcpMap.epoch, 1);

  time = 55000;
  assert.equal(adapter.observe().epoch, 55); // PCP ANNOUNCE and UPnP uptime projection.
  const natDelete = adapter.applyNatPmp(natPmpCommand('map_tcp_delete_request'), '192.0.2.10');
  const pcpDeleteWire = pcpPacket('tcp', 0);
  const pcpDelete = adapter.applyPcp(decodePcpMapRequest(pcpDeleteWire), pcpDeleteWire);
  assert.equal(natDelete.epoch, 55);
  assert.equal(pcpDelete.epoch, 55);

  const internalBefore = adapter.observeProtocol().gateway;
  const resetProjection = adapter.applyFaultBoundary('epoch_reset');
  const internalAfter = adapter.observeProtocol().gateway;
  assert.equal(resetProjection.epoch, 0);
  assert.equal(internalAfter.epoch, internalBefore.epoch + 1);
  assert.equal(internalAfter.generation, internalBefore.generation + 1);
  time = 56000;
  assert.equal(adapter.applyNatPmp(natPmpCommand('external_address_request'), '192.0.2.10').epoch, 1);
});

test('logical expiry does not fast-forward the wire epoch', () => {
  let time = 1000;
  const adapter = createGatewayAdapter({ now: () => time, maximumLifetimeSeconds: 120 });
  adapter.mapPair('natpmp', 7200);
  assert.equal(adapter.observe().epoch, 1);
  assert.equal(adapter.expireOwned().epoch, 1);
  assert.equal(adapter.applyNatPmp(natPmpCommand('external_address_request'), '192.0.2.10').epoch, 1);
  assert.equal(adapter.observeProtocol().gateway.epoch, 1);
});

test('expiry invalidates an old pending identity without blocking or clobbering recovery', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  adapter.mapPair('natpmp', 7200);
  const first = adapter.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(first.token), false);
  const stale = adapter.prepareNatPmp(natPmpCommand('map_udp_request'), '192.0.2.10');

  adapter.expireOwned();
  const recoveryFirst = adapter.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(recoveryFirst.token), false);
  assert.throws(() => adapter.commitPrepared(stale.token), /O01_ADAPTER_TRANSACTION_STALE/);
  assert.equal(adapter.abortPrepared(stale.token), true);
  const recoverySecond = adapter.prepareNatPmp(natPmpCommand('map_udp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(recoverySecond.token), true);
  assert.equal(adapter.observeProtocol().traffic.final_owned_natpmp, 2);
});

test('a stale abort cannot erase a newer pending pair', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const staleWire = pcpPacket();
  const stale = adapter.preparePcp(decodePcpMapRequest(staleWire), staleWire);
  const current = adapter.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(current.token), false);
  assert.equal(adapter.abortPrepared(stale.token), true);
  const second = adapter.prepareNatPmp(natPmpCommand('map_udp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(second.token), true);
  assert.deepEqual(adapter.observeProtocol().traffic.final_owned_mapping_count, 2);
});

test('a stale commit fails and cannot disturb the exact pending identity', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const staleWire = pcpPacket();
  const stale = adapter.preparePcp(decodePcpMapRequest(staleWire), staleWire);
  const current = adapter.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(current.token), false);
  assert.throws(() => adapter.commitPrepared(stale.token), /O01_ADAPTER_TRANSACTION_STALE/);
  assert.equal(adapter.abortPrepared(stale.token), true);
  const second = adapter.prepareNatPmp(natPmpCommand('map_udp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(second.token), true);
  assert.equal(adapter.observeProtocol().traffic.final_owned_natpmp, 2);
});

test('one global pending pair prevents PCP and NAT-PMP interleaving in both directions', () => {
  const natFirst = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const natTcp = natFirst.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(natFirst.commitPrepared(natTcp.token), false);
  const blockedPcpWire = pcpPacket();
  assert.throws(() => natFirst.preparePcp(decodePcpMapRequest(blockedPcpWire), blockedPcpWire), /O01_ADAPTER_TRANSACTION_PENDING/);
  const natUdp = natFirst.prepareNatPmp(natPmpCommand('map_udp_request'), '192.0.2.10');
  assert.equal(natFirst.commitPrepared(natUdp.token), true);

  const pcpFirst = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const pcpTcpWire = pcpPacket();
  const pcpTcp = pcpFirst.preparePcp(decodePcpMapRequest(pcpTcpWire), pcpTcpWire);
  assert.equal(pcpFirst.commitPrepared(pcpTcp.token), false);
  assert.throws(() => pcpFirst.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10'), /O01_ADAPTER_TRANSACTION_PENDING/);
  const pcpUdpWire = pcpPacket('udp');
  const pcpUdp = pcpFirst.preparePcp(decodePcpMapRequest(pcpUdpWire), pcpUdpWire);
  assert.equal(pcpFirst.commitPrepared(pcpUdp.token), true);
  assert.equal(pcpFirst.observeProtocol().traffic.final_owned_pcp, 2);
});

test('a rejected second member releases only its exact pending pair', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const tcpWire = pcpPacket();
  const udpWire = pcpPacket('udp');
  const tcp = adapter.preparePcp(decodePcpMapRequest(tcpWire), tcpWire);
  assert.equal(adapter.commitPrepared(tcp.token), false);
  const udp = adapter.preparePcp(decodePcpMapRequest(udpWire), udpWire);
  assert.equal(adapter.commitPrepared(udp.token), true);

  const renewal = adapter.preparePcp(decodePcpMapRequest(tcpWire), tcpWire);
  assert.equal(adapter.commitPrepared(renewal.token), false);
  const rejectedWire = Buffer.from(udpWire);
  rejectedWire[24] ^= 0xff;
  const rejected = adapter.preparePcp(decodePcpMapRequest(rejectedWire), rejectedWire);
  assert.notEqual(rejected.response.result_code, 0);
  assert.equal(adapter.commitPrepared(rejected.token), false);
  const recovery = adapter.prepareNatPmp(natPmpCommand('map_tcp_request'), '192.0.2.10');
  assert.equal(adapter.commitPrepared(recovery.token), false);
});

test('protocol projection is closed and contains no address, port, nonce or path', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, resources: () => ({ gateway_rss_bytes: 7, gateway_sockets: 2 }) });
  adapter.mapPair('pcp'); const projection = {...adapter.observeProtocol(),faults:{armed_fault_ordinal:0,armed_fault_name:'none',last_executed_fault_ordinal:0,last_executed_fault_name:'renew_success',last_executed_outcome:'none',last_fault_candidate_committed:false,pair_transactions_attempted:0,pair_transactions_committed:0,pair_transactions_aborted:0,last_recovery_transaction_ordinal:0,late_packets_delivered:0,late_packets_ignored:0}};
  delete projection.faults.late_packets_delivered; delete projection.faults.late_packets_ignored;
  Object.assign(projection.faults,{last_wire_protocol:'none',fault_transactions_attempted:0,recovery_transactions_attempted:0,late_packets_emitted:0,late_packets_suppressed:0,generation_before:0,generation_after:0,epoch_before:0,epoch_after:0,owned_before:0,owned_after:0,publisher_before:false,publisher_after:false,journal_before:0,journal_after:0});
  assert.equal(validateObservation(projection), projection);
  const json = JSON.stringify(projection);
  assert.doesNotMatch(json, /(?:address|port|nonce|path|192\.0\.2|198\.51\.100|\\Users\\|\/home\/)/i);
  assert.equal(projection.resources.gateway_rss_bytes, 7);
  assert.equal(projection.resources.gateway_sockets, 2);
});
