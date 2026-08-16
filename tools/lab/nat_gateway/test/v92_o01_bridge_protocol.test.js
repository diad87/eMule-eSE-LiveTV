'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createSession, tokenHash, parseLine } = require('../v92_o01_bridge_protocol');
const TOKEN = 'a'.repeat(64);
const line = (sequence, command, arguments_) => JSON.stringify({ schema: 'ese.v92.o01-control/v1', sequence, command, arguments: arguments_ });
function adapter() { const calls = []; const observation = (fault = 'renew_success') => ({ gateway: { generation: 1, epoch: 1, mapping_count: 3, pair_atomic: true, foreign_fixture_present: true, last_fault: fault }, product: { topology_generation: 1, tcp_state: 'VERIFIED', udp_state: 'VERIFIED', publisher_active: true, journal_entry_count: 2 }, resources: { gateway_rss_bytes: 1,gateway_heap_bytes:1,gateway_external_bytes:1,gateway_array_buffers_bytes:1,product_working_set_bytes: 1, gateway_handles: 1, product_handles: 1, gateway_sockets: 1, product_sockets: 1, event_loop_lag_ms: 0 }, traffic:{pcp_requests:0,natpmp_requests:0,upnp_add_requests:0,upnp_get_requests:0,upnp_delete_requests:0,accepted_outcomes:0,rejected_outcomes:0,pcp_accepted:0,pcp_rejected:0,natpmp_accepted:0,natpmp_rejected:0,upnp_accepted:0,upnp_rejected:0,max_owned_mapping_count:2,final_owned_mapping_count:2,final_owned_pcp:2,final_owned_natpmp:0,final_owned_upnp:0},faults:{armed_fault_ordinal:0,armed_fault_name:'none',last_executed_fault_ordinal:0,last_executed_fault_name:'renew_success',last_executed_outcome:'none',last_fault_candidate_committed:false,last_wire_protocol:'none',pair_transactions_attempted:0,pair_transactions_committed:0,pair_transactions_aborted:0,fault_transactions_attempted:0,recovery_transactions_attempted:0,last_recovery_transaction_ordinal:0,late_packets_emitted:0,generation_before:0,generation_after:0,epoch_before:0,epoch_after:0,owned_before:0,owned_after:0,publisher_before:false,publisher_after:false,journal_before:0,journal_after:0} }); return { calls, value: { observe: async () => (calls.push('observe'), observation()), inject: async (fault) => (calls.push(fault), observation(fault)), beginSlot:async(fault)=> (calls.push(`slot:${fault}`),observation(fault)),shutdown: async () => (calls.push('shutdown'), observation()) } }; }
test('authenticated session enforces sequence and planned fault ordinal', async () => {
  const fixture = adapter(); const session = createSession(tokenHash(TOKEN), fixture.value);
  assert.equal((await session.dispatch(line(1, 'hello', { token: TOKEN }))).state, 'authenticated');
  await session.dispatch(line(2, 'observe', {})); await session.dispatch(line(3, 'inject', { fault: 'stale', planned_ordinal: 1 }));
  assert.deepEqual(fixture.calls, ['observe','stale']);
  await assert.rejects(session.dispatch(line(5, 'observe', {})), /O01_PROTOCOL_SEQUENCE/);
});
test('wrong token, replay, reauth and ordinal gaps fail closed', async () => {
  await assert.rejects(createSession(tokenHash(TOKEN), adapter().value).dispatch(line(1, 'hello', { token: 'b'.repeat(64) })), /O01_PROTOCOL_AUTH/);
  const session = createSession(tokenHash(TOKEN), adapter().value); await session.dispatch(line(1, 'hello', { token: TOKEN }));
  await assert.rejects(session.dispatch(line(1, 'observe', {})), /O01_PROTOCOL_SEQUENCE/);
  await assert.rejects(session.dispatch(line(2, 'hello', { token: TOKEN })), /O01_PROTOCOL_REAUTH/);
  await assert.rejects(session.dispatch(line(2, 'inject', { fault: 'expiry', planned_ordinal: 2 })), /O01_PROTOCOL_ORDINAL/);
});
test('parser rejects open, oversized and hostile commands', () => {
  assert.throws(() => parseLine('{}'), /O01_PROTOCOL_SHAPE/);
  assert.throws(() => parseLine(line(1, 'inject', { fault: 'unknown', planned_ordinal: 1 })), /O01_PROTOCOL_FAULT/);
  assert.throws(() => parseLine('x'.repeat(4097)), /O01_PROTOCOL_LINE/);
  assert.throws(() => parseLine(`${line(1, 'observe', {})}\n`), /O01_PROTOCOL_LINE/);
});
test('shutdown is terminal and adapter observations stay closed', async () => {
  const session = createSession(tokenHash(TOKEN), adapter().value); await session.dispatch(line(1, 'hello', { token: TOKEN }));
  const result = await session.dispatch(line(2, 'shutdown', {})); assert.equal(result.state, 'closed');
  await assert.rejects(session.dispatch(line(3, 'observe', {})), /O01_PROTOCOL_CLOSED/);
});
test('nested observations are a privacy-safe closed projection', async () => {
  const broken = adapter(); broken.value.observe = async () => ({ gateway: { secret: 'x' }, product: {}, resources: {} });
  const session = createSession(tokenHash(TOKEN), broken.value); await session.dispatch(line(1, 'hello', { token: TOKEN }));
  await assert.rejects(session.dispatch(line(2, 'observe', {})), /O01_PROTOCOL_SHAPE/);
});
