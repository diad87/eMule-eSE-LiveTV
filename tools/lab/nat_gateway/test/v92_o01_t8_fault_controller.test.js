'use strict';
const assert=require('node:assert/strict');const test=require('node:test');
const {decodeNatPmpRequest}=require('../natpmp_request_decoder');const {NATPMP_VECTORS}=require('../natpmp_vectors');
const {createO01FaultController}=require('../v92_o01_t8_fault_controller');

const udpRequest=()=>decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.map_udp_request.hex,'hex'));
const tcpRequest=()=>decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.map_tcp_request.hex,'hex'));
const pcpUdpRequest=()=>({...udpRequest(),protocol:'pcp',nonce:'ab'.repeat(12)});
const pcpTcpRequest=()=>({...tcpRequest(),protocol:'pcp',nonce:'ab'.repeat(12)});
const response=(fill=0x31)=>{const value=Buffer.from(NATPMP_VECTORS.map_tcp_response.hex,'hex');value[1]=129;value.fill(fill,12);return value;};
const observation=(generation=1,epoch=1,owned=2)=>({gateway:{generation,epoch},traffic:{final_owned_mapping_count:owned},product:{publisher_active:owned===2,journal_entry_count:owned}});

test('dropped-late waits 8000 ms, suppresses correlated retries and emits one packet',async()=>{
 let release;let waited=0;const c=createO01FaultController({lateDelayMs:8000,sleep:async(ms)=>{waited=ms;await new Promise(resolve=>{release=resolve;});}});const signal=new AbortController().signal;
 const tcpPrime=await c.apply(response(0x41),tcpRequest(),signal,'client-a');c.recordTransaction(tcpPrime,false,observation(),observation(),'natpmp',true);
 const udpPrime=await c.apply(response(0x42),udpRequest(),signal,'client-a');c.recordTransaction(udpPrime,true,observation(),observation(),'natpmp',true);
 c.arm('dropped_late');const pending=c.apply(response(0x43),udpRequest(),signal,'client-a');await new Promise(resolve=>setImmediate(resolve));
 assert.equal(waited,8000);const retry=await c.apply(response(0x44),udpRequest(),signal,'client-a');assert.equal(retry.packets.length,0);assert.equal(retry.consumed,false);
 const tcpRetry=await c.apply(response(0x44),tcpRequest(),signal,'client-a');assert.equal(tcpRetry.packets.length,0);assert.equal(tcpRetry.consumed,false);
 const differentPort={...udpRequest(),suggested_external_port:udpRequest().suggested_external_port+1};const independent=await c.apply(response(0x45),differentPort,signal,'client-a');assert.equal(independent.packets.length,1);assert.equal(independent.consumed,false);
 const otherClient=await c.apply(response(0x46),udpRequest(),signal,'client-b');assert.equal(otherClient.packets.length,1);assert.equal(otherClient.consumed,false);assert.equal(c.state().late_packets_suppressed,2);
 release();const late=await pending;assert.equal(late.packets.length,1);assert.equal(late.late,true);assert.equal(c.state().late_packets_emitted,1);assert.equal(c.state().late_packets_suppressed,2);
});

test('dropped-late pair correlation is promoted only by the exact closing UDP commit',async()=>{
 const signal=new AbortController().signal;
 const exercise=async(recordUdp,udpCommitted,udpMutation={})=>{let release;const c=createO01FaultController({sleep:()=>new Promise(resolve=>{release=resolve;})});
  const tcp=await c.apply(response(0x47),tcpRequest(),signal,'client-a');c.recordTransaction(tcp,false,observation(),observation(),'natpmp',true);
  const udp=await c.apply(response(0x48),{...udpRequest(),...udpMutation},signal,'client-a');if(recordUdp)c.recordTransaction(udp,udpCommitted,observation(),observation(),'natpmp',true);
  c.arm('dropped_late');const pending=c.apply(response(0x49),{...udpRequest(),...udpMutation},signal,'client-a');await new Promise(resolve=>setImmediate(resolve));
  const tcpRetry=await c.apply(response(0x4a),tcpRequest(),signal,'client-a');release();await pending;return tcpRetry.packets.length;};
 assert.equal(await exercise(true,true),0);
 assert.equal(await exercise(true,false),1);
 assert.equal(await exercise(false,false),1);
});

test('dropped-late PCP correlation requires the same committed nonce and exact member keys',async()=>{
 let release;const c=createO01FaultController({sleep:()=>new Promise(resolve=>{release=resolve;})});const signal=new AbortController().signal;
 const tcp=await c.apply(response(0x4b),pcpTcpRequest(),signal,'client-a');c.recordTransaction(tcp,false,observation(),observation(),'pcp',true);
 const udp=await c.apply(response(0x4c),pcpUdpRequest(),signal,'client-a');c.recordTransaction(udp,true,observation(),observation(),'pcp',true);
 c.arm('dropped_late');const pending=c.apply(response(0x4d),pcpUdpRequest(),signal,'client-a');await new Promise(resolve=>setImmediate(resolve));
 assert.equal((await c.apply(response(0x4e),pcpTcpRequest(),signal,'client-a')).packets.length,0);
 assert.equal((await c.apply(response(0x4f),{...pcpTcpRequest(),nonce:'cd'.repeat(12)},signal,'client-a')).packets.length,1);
 assert.equal((await c.apply(response(0x50),{...pcpTcpRequest(),suggested_external_port:pcpTcpRequest().suggested_external_port+1},signal,'client-a')).packets.length,1);
 assert.equal((await c.apply(response(0x51),pcpTcpRequest(),signal,'client-b')).packets.length,1);
 release();await pending;
 const mismatch=createO01FaultController({sleep:async()=>{}});
 const mismatchedTcp=await mismatch.apply(response(0x52),pcpTcpRequest(),signal,'client-a');mismatch.recordTransaction(mismatchedTcp,false,observation(),observation(),'pcp',true);
 const mismatchedUdp=await mismatch.apply(response(0x53),{...pcpUdpRequest(),nonce:'cd'.repeat(12)},signal,'client-a');mismatch.recordTransaction(mismatchedUdp,true,observation(),observation(),'pcp',true);
 mismatch.arm('dropped_late');await mismatch.apply(response(0x54),{...pcpUdpRequest(),nonce:'cd'.repeat(12)},signal,'client-a');
 assert.equal((await mismatch.apply(response(0x55),pcpTcpRequest(),signal,'client-a')).packets.length,1);
});

test('external, delete and TCP map never consume; UDP map consumes exactly once',async()=>{
 const c=createO01FaultController({sleep:async()=>{}});const signal=new AbortController().signal;c.arm('explicit_reject');
 const external=decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.external_address_request.hex,'hex'));
 const deletion=decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex,'hex'));
 assert.equal((await c.apply(response(),external,signal)).consumed,false);assert.equal((await c.apply(response(),deletion,signal)).consumed,false);
 assert.equal((await c.apply(response(),tcpRequest(),signal)).consumed,false);assert.equal(c.state().armed_fault_ordinal,1);
 const consumed=await c.apply(response(),udpRequest(),signal);assert.equal(consumed.consumed,true);assert.equal(consumed.packets[0].readUInt16BE(2),2);assert.equal(c.state().armed_fault_ordinal,0);
});

test('replay cache is typed by the exact UDP member, never overwritten by TCP',async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal;
 const tcpHistorical=await c.apply(response(0x51),tcpRequest(),signal);c.recordTransaction(tcpHistorical,false,observation(),observation(),'natpmp',true);
 const udpHistorical=response(0x52),udpDecision=await c.apply(udpHistorical,udpRequest(),signal);c.recordTransaction(udpDecision,true,observation(),observation(),'natpmp',true);
 c.arm('replay_duplicate');const tcpCurrent=await c.apply(response(0x53),tcpRequest(),signal);c.recordTransaction(tcpCurrent,false,observation(),observation(),'natpmp',true);
 const replay=await c.apply(response(0x54),udpRequest(),signal);
 assert.equal(replay.packets.length,2);assert.deepEqual(replay.packets[0],udpHistorical);assert.deepEqual(replay.packets[1],udpHistorical);
});

test('replay cache promotes only a pair-committed capture',async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal,exact=udpRequest();c.arm('replay_duplicate');
 const unrecorded=await c.apply(response(0x55),exact,signal,'client-a');assert.equal(unrecorded.consumed,false);
 const afterUnrecorded=await c.apply(response(0x56),exact,signal,'client-a');assert.equal(afterUnrecorded.consumed,false);assert.equal(afterUnrecorded.packets.length,1);
 c.recordTransaction(afterUnrecorded,false,observation(),observation(),'natpmp',true);
 const rejected=await c.apply(response(0x57),exact,signal,'client-a');assert.equal(rejected.consumed,false);assert.equal(rejected.packets.length,1);
 c.recordTransaction(rejected,true,observation(),observation(),'natpmp',true);
 const replay=await c.apply(response(0x58),exact,signal,'client-a');assert.equal(replay.consumed,true);assert.equal(replay.packets.length,2);
 assert.deepEqual(replay.packets[0],response(0x57));assert.deepEqual(replay.packets[1],response(0x57));
});

test('replay cache miss primes normally and the next exact correlated UDP replays that prime',async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal,exact=udpRequest();
 const historical=response(0x61),historicalDecision=await c.apply(historical,exact,signal,'client-a');c.recordTransaction(historicalDecision,true,observation(),observation(),'natpmp',true);c.arm('replay_duplicate');
 const different={...exact,suggested_external_port:exact.suggested_external_port+1};
 const primePacket=response(0x62),miss=await c.apply(primePacket,different,signal,'client-a');
 assert.deepEqual({packets:miss.packets.length,commit:miss.commit,consumed:miss.consumed,fault:miss.fault},
   {packets:1,commit:true,consumed:false,fault:'renew_success'});assert.deepEqual(miss.packets[0],primePacket);
 c.recordTransaction(miss,true,observation(),observation(),'natpmp',true);
 const afterMiss=c.state();assert.deepEqual({armed:afterMiss.armed_fault_ordinal,armedName:afterMiss.armed_fault_name,
   executed:afterMiss.last_executed_fault_ordinal,executedName:afterMiss.last_executed_fault_name,
   outcome:afterMiss.last_executed_outcome,attempted:afterMiss.pair_transactions_attempted,
   aborted:afterMiss.pair_transactions_aborted,faultAttempted:afterMiss.fault_transactions_attempted},
   {armed:1,armedName:'replay_duplicate',executed:0,executedName:'renew_success',outcome:'none',attempted:0,aborted:0,faultAttempted:0});
 const replay=await c.apply(response(0x63),different,signal,'client-a');
 assert.equal(replay.consumed,true);assert.equal(replay.commit,false);assert.equal(replay.packets.length,2);
 assert.deepEqual(replay.packets[0],primePacket);assert.deepEqual(replay.packets[1],primePacket);
 c.recordTransaction(replay,false,observation(),observation(),'natpmp',true);
 assert.equal(c.state().armed_fault_ordinal,0);assert.equal(c.state().last_executed_fault_ordinal,1);
 assert.equal(c.state().last_executed_fault_name,'replay_duplicate');assert.equal(c.state().fault_transactions_attempted,1);
 assert.equal(c.state().pair_transactions_aborted,1);
});

for(const name of ['expiry','epoch_reset'])test(`${name} is claimed on TCP, audited, aborted on UDP and then recovered`,async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal,identity='client-a';c.arm(name);
 assert.equal(c.claimBoundary(udpRequest(),identity),null);const token=c.claimBoundary(tcpRequest(),identity);assert.equal(token.name,name);assert.equal(token.protocol,'natpmp');assert.equal(token.client_identity,identity);
 const before=observation();const afterBoundary=name==='expiry'?observation(1,1,0):observation(2,2,0);assert.throws(()=>c.recordBoundary(token,before,afterBoundary,true),/BOUNDARY_INVALID/);c.recordBoundary(token,before,afterBoundary,false);
 const first=await c.apply(response(),tcpRequest(),signal,identity);assert.equal(first.consumed,false);
 const failed=await c.apply(response(),udpRequest(),signal,identity);assert.equal(failed.consumed,true);assert.equal(failed.commit,false);assert.equal(failed.packets.length,0);
 c.recordTransaction(failed,false,afterBoundary,afterBoundary,'natpmp',true);assert.equal(c.state().owned_before,2);assert.equal(c.state().owned_after,0);
 await c.apply(response(),tcpRequest(),signal,identity);const recovered=await c.apply(response(),udpRequest(),signal,identity);
 c.recordTransaction(recovered,true,afterBoundary,observation(afterBoundary.gateway.generation,afterBoundary.gateway.epoch,2),'natpmp',true);
 assert.equal(c.state().last_recovery_transaction_ordinal,1);assert.equal(c.state().last_fault_candidate_committed,false);assert.equal(c.state().last_executed_outcome,'aborted');
});

test('boundary audit is fail-closed and only its protocol and client identity can consume it',async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal;c.arm('expiry');
 const token=c.claimBoundary(tcpRequest(),'client-a');const before=observation(),after=observation(1,1,0);
 const unaudited=await c.apply(response(),udpRequest(),signal,'client-a');assert.equal(unaudited.consumed,false);assert.equal(unaudited.packets.length,0);assert.equal(c.state().armed_fault_ordinal,1);
 c.recordBoundary(token,before,after,false);
 const otherProtocol=await c.apply(response(),pcpUdpRequest(),signal,'client-a');assert.equal(otherProtocol.consumed,false);assert.equal(otherProtocol.packets.length,1);
 const otherClient=await c.apply(response(),udpRequest(),signal,'client-b');assert.equal(otherClient.consumed,false);assert.equal(otherClient.packets.length,1);assert.equal(c.state().last_executed_fault_ordinal,0);
 const matched=await c.apply(response(),udpRequest(),signal,'client-a');assert.equal(matched.consumed,true);assert.equal(matched.packets.length,0);assert.equal(c.state().last_executed_fault_ordinal,1);
});

test('final boundary aborts one pair, then permits one accredited recovery and cleanup',async()=>{
 const c=createO01FaultController();const signal=new AbortController().signal;c.arm('final_boundary');
 await c.apply(response(),tcpRequest(),signal);const terminal=await c.apply(response(),udpRequest(),signal);assert.equal(terminal.consumed,true);
 c.recordTransaction(terminal,false,observation(),observation(),'natpmp',true);
 const recoveryTcp=await c.apply(response(),tcpRequest(),signal);assert.equal(recoveryTcp.packets.length,1);const recoveryUdp=await c.apply(response(),udpRequest(),signal);assert.equal(recoveryUdp.packets.length,1);c.recordTransaction(recoveryUdp,true,observation(),observation(),'natpmp',true);assert.equal(c.state().last_recovery_transaction_ordinal,1);
 const deletion=decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex,'hex'));const cleanup=await c.apply(response(),deletion,signal);assert.equal(cleanup.packets.length,1);assert.equal(cleanup.commit,true);
 const beforeCleanup=c.state();c.recordTransaction(cleanup,true,observation(),observation(1,1,0),'natpmp',false);assert.deepEqual(c.state(),beforeCleanup);
 assert.equal(c.state().last_recovery_transaction_ordinal,1);
});
