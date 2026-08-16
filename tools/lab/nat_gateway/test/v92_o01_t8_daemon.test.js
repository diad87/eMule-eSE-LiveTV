'use strict';
const assert = require('node:assert/strict'); const test = require('node:test');
const { PassThrough } = require('node:stream');
const { tokenHash } = require('../v92_o01_bridge_protocol'); const { runDaemon } = require('../v92_o01_t8_daemon');
const TOKEN = 'a'.repeat(64);
const observation = { gateway: { generation: 1, epoch: 1, mapping_count: 3, pair_atomic: true, foreign_fixture_present: true, last_fault: 'renew_success' }, product: { topology_generation: 1, tcp_state: 'VERIFIED', udp_state: 'VERIFIED', publisher_active: true, journal_entry_count: 2 }, resources: { gateway_rss_bytes: 1,gateway_heap_bytes:1,gateway_external_bytes:1,gateway_array_buffers_bytes:1,product_working_set_bytes: 1, gateway_handles: 1, product_handles: 1, gateway_sockets: 1, product_sockets: 1, event_loop_lag_ms: 0 }, traffic:{pcp_requests:0,natpmp_requests:0,upnp_add_requests:0,upnp_get_requests:0,upnp_delete_requests:0,accepted_outcomes:0,rejected_outcomes:0,pcp_accepted:0,pcp_rejected:0,natpmp_accepted:0,natpmp_rejected:0,upnp_accepted:0,upnp_rejected:0,max_owned_mapping_count:2,final_owned_mapping_count:2,final_owned_pcp:2,final_owned_natpmp:0,final_owned_upnp:0},faults:{armed_fault_ordinal:0,armed_fault_name:'none',last_executed_fault_ordinal:0,last_executed_fault_name:'renew_success',last_executed_outcome:'none',last_fault_candidate_committed:false,pair_transactions_attempted:0,pair_transactions_committed:0,pair_transactions_aborted:0,last_recovery_transaction_ordinal:0,late_packets_delivered:0,late_packets_ignored:0} };
delete observation.faults.late_packets_delivered; delete observation.faults.late_packets_ignored;
Object.assign(observation.faults,{last_wire_protocol:'none',fault_transactions_attempted:0,recovery_transactions_attempted:0,late_packets_emitted:0,generation_before:0,generation_after:0,epoch_before:0,epoch_after:0,owned_before:0,owned_after:0,publisher_before:false,publisher_after:false,journal_before:0,journal_after:0});
const message = (sequence, command, args) => JSON.stringify({ schema: 'ese.v92.o01-control/v1', sequence, command, arguments: args });
test('daemon processes authenticated JSONL in order and closes terminally', async () => {
  const input = new PassThrough(); const output = new PassThrough(); let text = ''; output.on('data', (chunk) => { text += chunk; });
  const adapter = { observe: async () => observation, inject: async () => observation, shutdown: async () => observation };
  const running = runDaemon(input, output, { O01_MODE: 'NON_RELEASE', O01_CONTROL_TOKEN_SHA256: tokenHash(TOKEN) }, adapter);
  input.end(`${message(1,'hello',{token:TOKEN})}\n${message(2,'observe',{})}\n${message(3,'shutdown',{})}\n`); await running;
  const rows = text.trim().split('\n').map(JSON.parse); assert.equal(rows.length, 3); assert.equal(rows[2].state, 'closed');
});
test('formal daemon rejects wrong Node before reading input', async () => {
  if (process.versions.node.split('.')[0] === '22') return;
  await assert.rejects(runDaemon(new PassThrough(), new PassThrough(), { O01_MODE: 'FORMAL_T8', O01_CONTROL_TOKEN_SHA256: tokenHash(TOKEN) }, {}), /O01_DAEMON_NODE22_REQUIRED/);
});
test('daemon source wiring uses the complete network adapter, never the semantic adapter directly',()=>{const fs=require('node:fs');const source=fs.readFileSync(require.resolve('../v92_o01_t8_daemon'),'utf8');assert.match(source,/createT8NetworkAdapter/);assert.doesNotMatch(source,/require\('\.\/v92_o01_t8_gateway_adapter'\)/);});
