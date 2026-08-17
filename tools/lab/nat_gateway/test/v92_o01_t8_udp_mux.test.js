'use strict';
const assert = require('node:assert/strict'); const test = require('node:test'); const dgram = require('node:dgram');
const { createGatewayAdapter } = require('../v92_o01_t8_gateway_adapter');
const { _projectObservationForTest } = require('../v92_o01_t8_network_adapter');
const { createO01UdpMux } = require('../v92_o01_t8_udp_mux');
const { NATPMP_VECTORS } = require('../natpmp_vectors'); const { PCP_VECTORS } = require('../pcp_vectors');
const {createO01FaultController}=require('../v92_o01_t8_fault_controller');
function request(socket, target, packet) { return new Promise((resolve, reject) => { socket.once('message', resolve); socket.send(packet, target.port, target.address, (e) => e && reject(e)); }); }
function sendOnly(socket, target, packet) { return new Promise((resolve, reject) => socket.send(packet, target.port, target.address, (error) => error ? reject(error) : resolve())); }
async function waitUntil(predicate) { for (let index = 0; index < 100; index += 1) { if (predicate()) return; await new Promise((resolve) => setTimeout(resolve, 2)); } throw new Error('O01_TEST_WAIT_TIMEOUT'); }
test('single loopback socket demuxes NAT-PMP v0 and PCP v2 into shared state', async (t) => {
  const adapter = createGatewayAdapter({ now: () => 1000, maximumLifetimeSeconds: 120 });
  const mux = createO01UdpMux({ mode: 'NON_RELEASE', bind_address: '127.0.0.1', port: 0, allowed_source_addresses: ['127.0.0.1'], adapter });
  const target = await mux.start(); const client = dgram.createSocket('udp4'); t.after(async () => { await mux.close(); client.close(); });
  const nat = await request(client, target, Buffer.from(NATPMP_VECTORS.map_tcp_request.hex, 'hex')); assert.equal(nat[0], 0); assert.equal(nat[1], 0x82); assert.equal(nat.readUInt32BE(12), 120);
  const natUdp = await request(client,target,Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex')); assert.equal(natUdp.readUInt32BE(12), 120);
  const pcpPacket = Buffer.from(PCP_VECTORS.map_tcp_request.hex, 'hex'); Buffer.from('00000000000000000000ffff7f000001','hex').copy(pcpPacket, 8);
  const pcp = await request(client, target, pcpPacket); assert.equal(pcp[0], 2); assert.equal(pcp[1], 0x81); assert.equal(pcp.readUInt32BE(4), 120);
  const pcpUdp=Buffer.from(pcpPacket);pcpUdp[36]=17;pcpUdp.writeUInt16BE(4672,40);const pcpUdpResponse=await request(client,target,pcpUdp);assert.equal(pcpUdpResponse.readUInt32BE(4),120);
  await request(client,target,Buffer.from(NATPMP_VECTORS.external_address_request.hex,'hex'));
  const announce=Buffer.from(PCP_VECTORS.announce_request.hex,'hex');Buffer.from('00000000000000000000ffff7f000001','hex').copy(announce,8);await request(client,target,announce);
  assert.deepEqual(new Set(adapter.observe().mappings.map((entry) => entry.protocol)), new Set(['upnp','natpmp','pcp']));
  assert.equal(adapter.observe().mappings.filter((entry)=>['natpmp','pcp'].includes(entry.protocol)).every((entry)=>entry.lease.lifetime_seconds===120),true);
  const traffic=adapter.observeProtocol().traffic;assert.deepEqual({pcp:traffic.pcp_requests,natpmp:traffic.natpmp_requests,accepted:traffic.accepted_outcomes,rejected:traffic.rejected_outcomes},{pcp:3,natpmp:3,accepted:6,rejected:0});
});
test('invalid version is dropped and formal mode rejects missing T8 provenance', async () => {
  const adapter = createGatewayAdapter({ now: () => 1000 });
  assert.throws(() => createO01UdpMux({ mode: 'FORMAL_T8', bind_address: '127.0.0.1', port: 5351, allowed_source_addresses: ['127.0.0.1'], adapter }), /PROVENANCE/);
  assert.throws(() => createO01UdpMux({ mode: 'NON_RELEASE', bind_address: '0.0.0.0', port: 0, allowed_source_addresses: ['127.0.0.1'], adapter }), /LOOPBACK/);
});
test('wire ownership rejection and NAT-PMP delete are delegated without foreign mutation', async (t) => {
  const adapter = createGatewayAdapter({ now: () => 1000 });
  const mux = createO01UdpMux({ mode: 'NON_RELEASE', bind_address: '127.0.0.1', port: 0, allowed_source_addresses: ['127.0.0.1'], adapter });
  const target = await mux.start(); const client = dgram.createSocket('udp4'); t.after(async () => { await mux.close(); client.close(); });
  const pcpPacket = Buffer.from(PCP_VECTORS.map_tcp_request.hex, 'hex'); Buffer.from('00000000000000000000ffff7f000001','hex').copy(pcpPacket, 8);
  await request(client, target, pcpPacket);const pcpUdp=Buffer.from(pcpPacket);pcpUdp[36]=17;pcpUdp.writeUInt16BE(4672,40);await request(client,target,pcpUdp); const before = adapter.observe();
  const wrong = Buffer.from(pcpPacket); wrong[24] ^= 0xff; const rejected = await request(client, target, wrong);
  assert.equal(rejected[3], 2); assert.deepEqual(adapter.observe(), before);const rejectedTraffic=adapter.observeProtocol().traffic;assert.equal(rejectedTraffic.pcp_requests,3);assert.equal(rejectedTraffic.pcp_accepted,2);assert.equal(rejectedTraffic.pcp_rejected,1);
  await request(client, target, Buffer.from(NATPMP_VECTORS.map_tcp_request.hex, 'hex'));await request(client,target,Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex'));
  await request(client, target, Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex, 'hex'));
  const udpDelete=Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex,'hex');udpDelete[1]=1;udpDelete.writeUInt16BE(4672,4);await request(client,target,udpDelete);
  assert.equal(adapter.observe().mappings.some((entry) => entry.mapping_id === 'o01.natpmp.tcp'), false);
  assert.equal(adapter.observe().mappings.some((entry) => entry.mapping_id === 'foreign.persistent.tcp'), true);
});
test('wire reject, malformed and partial second member abort candidate byte-stably',async(t)=>{const adapter=createGatewayAdapter({now:()=>1000});const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const tcp=Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'),udp=Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex');const initial=adapter.observe();await request(client,target,tcp);faults.arm('explicit_reject');const rejected=await request(client,target,udp);assert.equal(rejected.readUInt16BE(2),2);assert.deepEqual(adapter.observe(),initial);assert.equal(faults.state().last_executed_fault_ordinal,1);assert.equal(faults.state().pair_transactions_aborted,1);assert.equal(faults.state().last_fault_candidate_committed,false);assert.equal(_projectObservationForTest(adapter.observeProtocol(),faults.state()).gateway.last_fault,'explicit_reject');
 await request(client,target,tcp);await request(client,target,udp);assert.equal(faults.state().last_recovery_transaction_ordinal,1);assert.equal(faults.state().pair_transactions_committed,1);const baseline=adapter.observe();await request(client,target,tcp);faults.arm('malformed');const malformed=await request(client,target,udp);assert.equal(malformed.length,3);assert.deepEqual(adapter.observe(),baseline);
 await request(client,target,tcp);faults.arm('partial_pair');const dropped=new Promise(resolve=>setTimeout(resolve,30));client.send(udp,target.port,target.address);await dropped;assert.deepEqual(adapter.observe(),baseline);
});
for (const boundaryName of ['expiry','epoch_reset']) test(`${boundaryName} is wire-gated, aborts one pair and requires a real recovery pair`,async(t)=>{const adapter=createGatewayAdapter({now:()=>1000,maximumLifetimeSeconds:120});const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const tcp=Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'),udp=Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex');await request(client,target,tcp);await request(client,target,udp);const before=adapter.observeProtocol();faults.arm(boundaryName,{planned_ordinal:1});
 const external=await request(client,target,Buffer.from(NATPMP_VECTORS.external_address_request.hex,'hex'));assert.equal(external[1],128);assert.equal(faults.state().armed_fault_ordinal,1);
 await request(client,target,tcp);const boundary=adapter.observeProtocol();assert.equal(boundary.traffic.final_owned_mapping_count,0);assert.equal(faults.state().last_executed_fault_ordinal,0);
 await sendOnly(client,target,udp);await waitUntil(()=>faults.state().last_executed_fault_ordinal===1);const executed=faults.state();assert.equal(executed.last_executed_outcome,'aborted');assert.equal(executed.last_recovery_transaction_ordinal,0);assert.equal(executed.pair_transactions_aborted,1);assert.equal(executed.owned_before,2);assert.equal(executed.owned_after,0);
 await request(client,target,tcp);await request(client,target,udp);const recovered=faults.state(),after=adapter.observeProtocol();assert.equal(recovered.last_recovery_transaction_ordinal,1);assert.equal(recovered.recovery_transactions_attempted,1);assert.equal(recovered.pair_transactions_attempted,recovered.pair_transactions_committed+recovered.pair_transactions_aborted);assert.equal(after.gateway.epoch,before.gateway.epoch+(boundaryName==='epoch_reset'?1:0));assert.equal(after.gateway.generation,before.gateway.generation+(boundaryName==='epoch_reset'?1:0));assert.equal(after.traffic.final_owned_mapping_count,2);assert.equal(after.product.publisher_active,true);assert.equal(after.product.journal_entry_count,2);
});

for (const failureStage of ['prepare','commit']) test(`boundary ${failureStage} failure never creates an audit or lets the later UDP consume`,async(t)=>{
 const base=createGatewayAdapter({now:()=>1000,maximumLifetimeSeconds:120});base.mapPair('natpmp',120);let injected=true;
 const adapter=Object.freeze({...base,
  prepareNatPmp(command,source){if(failureStage==='prepare'&&injected&&command.transport==='tcp'){injected=false;throw new Error('injected-prepare');}return base.prepareNatPmp(command,source);},
  commitPrepared(token){if(failureStage==='commit'&&injected){injected=false;const partial=base.commitPrepared(token);if(partial!==false)throw new Error('injected-commit-not-partial');throw new Error('injected-commit');}return base.commitPrepared(token);},
 });
 const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const tcp=Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'),udp=Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex');faults.arm('expiry');await sendOnly(client,target,tcp);await waitUntil(()=>injected===false);const expectedOwned=failureStage==='prepare'?2:0;assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count,expectedOwned);
 await sendOnly(client,target,udp);await waitUntil(()=>adapter.observeProtocol().traffic.natpmp_requests===1);const state=faults.state();assert.equal(state.armed_fault_ordinal,1);assert.equal(state.last_executed_fault_ordinal,0);assert.equal(state.fault_transactions_attempted,0);assert.equal(state.pair_transactions_attempted,0);assert.equal(state.owned_before,0);assert.equal(state.owned_after,0);assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count,expectedOwned);
});

test('a boundary claimed by NAT-PMP cannot be consumed by a PCP UDP member',async(t)=>{
 const adapter=createGatewayAdapter({now:()=>1000,maximumLifetimeSeconds:120});adapter.mapPair('natpmp',120);const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const natTcp=Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'),natUdp=Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex');const pcpUdp=Buffer.from(PCP_VECTORS.map_tcp_request.hex,'hex');Buffer.from('00000000000000000000ffff7f000001','hex').copy(pcpUdp,8);pcpUdp[36]=17;pcpUdp.writeUInt16BE(4672,40);
 faults.arm('expiry');await request(client,target,natTcp);await sendOnly(client,target,pcpUdp);await new Promise(resolve=>setTimeout(resolve,30));assert.equal(faults.state().armed_fault_ordinal,1);assert.equal(faults.state().last_executed_fault_ordinal,0);
 await sendOnly(client,target,natUdp);await waitUntil(()=>faults.state().last_executed_fault_ordinal===1);assert.equal(faults.state().last_wire_protocol,'natpmp');assert.equal(faults.state().pair_transactions_aborted,1);
});

test('a natively rejected PCP member cannot apply or consume a boundary',async(t)=>{
 const adapter=createGatewayAdapter({now:()=>1000,maximumLifetimeSeconds:120});const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const tcp=Buffer.from(PCP_VECTORS.map_tcp_request.hex,'hex');Buffer.from('00000000000000000000ffff7f000001','hex').copy(tcp,8);const udp=Buffer.from(tcp);udp[36]=17;udp.writeUInt16BE(4672,40);await request(client,target,tcp);await request(client,target,udp);const baseline=adapter.observeProtocol();faults.arm('expiry');
 const rejectedTcp=Buffer.from(PCP_VECTORS.map_prefer_failure_request.hex,'hex');Buffer.from('00000000000000000000ffff7f000001','hex').copy(rejectedTcp,8);const tcpResponse=await request(client,target,rejectedTcp);assert.notEqual(tcpResponse[3],0);assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count,2);assert.equal(faults.state().armed_fault_ordinal,1);assert.equal(faults.state().last_executed_fault_ordinal,0);
 const rejectedUdp=Buffer.from(rejectedTcp);rejectedUdp[36]=17;rejectedUdp.writeUInt16BE(4672,40);const udpResponse=await request(client,target,rejectedUdp);assert.notEqual(udpResponse[3],0);assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count,2);assert.equal(faults.state().armed_fault_ordinal,1);assert.equal(faults.state().last_executed_fault_ordinal,0);assert.equal(faults.state().pair_transactions_attempted,0);
 assert.equal(adapter.observeProtocol().traffic.pcp_rejected-baseline.traffic.pcp_rejected,2);
});

test('final-boundary cleanup deletes mappings without creating a recovery transaction',async(t)=>{
 const adapter=createGatewayAdapter({now:()=>1000,maximumLifetimeSeconds:120});const faults=createO01FaultController({sleep:async()=>{}});const mux=createO01UdpMux({mode:'NON_RELEASE',bind_address:'127.0.0.1',port:0,allowed_source_addresses:['127.0.0.1'],adapter,fault_controller:faults});const target=await mux.start();const client=dgram.createSocket('udp4');t.after(async()=>{await mux.close();client.close();});
 const tcp=Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'),udp=Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex');await request(client,target,tcp);await request(client,target,udp);faults.arm('final_boundary');await request(client,target,tcp);await sendOnly(client,target,udp);await waitUntil(()=>faults.state().last_executed_fault_ordinal===1);assert.equal(faults.state().last_recovery_transaction_ordinal,0);await request(client,target,tcp);await request(client,target,udp);const recovered=faults.state();assert.equal(recovered.last_recovery_transaction_ordinal,1);assert.equal(recovered.recovery_transactions_attempted,1);
 const tcpDelete=Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex,'hex'),udpDelete=Buffer.from(tcpDelete);udpDelete[1]=1;udpDelete.writeUInt16BE(4672,4);await request(client,target,tcpDelete);await request(client,target,udpDelete);assert.deepEqual(faults.state(),recovered);assert.equal(adapter.observeProtocol().traffic.final_owned_mapping_count,0);
});
