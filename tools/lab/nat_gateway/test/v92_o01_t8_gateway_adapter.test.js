'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createGatewayAdapter } = require('../v92_o01_t8_gateway_adapter');
const { validateObservation } = require('../v92_o01_bridge_protocol');

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

test('protocol projection is closed and contains no address, port, nonce or path', () => {
  const adapter = createGatewayAdapter({ now: () => 1000, resources: () => ({ gateway_rss_bytes: 7, gateway_sockets: 2 }) });
  adapter.mapPair('pcp'); const projection = {...adapter.observeProtocol(),faults:{armed_fault_ordinal:0,armed_fault_name:'none',last_executed_fault_ordinal:0,last_executed_fault_name:'renew_success',last_executed_outcome:'none',last_fault_candidate_committed:false,pair_transactions_attempted:0,pair_transactions_committed:0,pair_transactions_aborted:0,last_recovery_transaction_ordinal:0,late_packets_delivered:0,late_packets_ignored:0}};
  delete projection.faults.late_packets_delivered; delete projection.faults.late_packets_ignored;
  Object.assign(projection.faults,{last_wire_protocol:'none',fault_transactions_attempted:0,recovery_transactions_attempted:0,late_packets_emitted:0,generation_before:0,generation_after:0,epoch_before:0,epoch_after:0,owned_before:0,owned_after:0,publisher_before:false,publisher_after:false,journal_before:0,journal_after:0});
  assert.equal(validateObservation(projection), projection);
  const json = JSON.stringify(projection);
  assert.doesNotMatch(json, /(?:address|port|nonce|path|192\.0\.2|198\.51\.100|\\Users\\|\/home\/)/i);
  assert.equal(projection.resources.gateway_rss_bytes, 7);
  assert.equal(projection.resources.gateway_sockets, 2);
});
