'use strict';
const test = require('node:test'); const assert = require('node:assert/strict');
const scenario = require('../v92_o01_scenario.json');
const { validateScenario, createCrossValidator, makeCheckpoint, _runControllerTest } = require('../v92_o01_formal_controller');
const HOSTILE = new Set(['dropped_late','explicit_reject','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
function product(sequence = 2, elapsed = 60000, generation = 1) { return { schema: 'ese.v92.o01-product-sample/v1', sequence,
  elapsed_ms: elapsed, available: true, tcp_state: 'CANDIDATE', udp_state: 'CANDIDATE', same_generation: true,
  generation, tcp_reason_code: 0, udp_reason_code: 0, working_set_bytes: 1000, handle_count: 10 }; }
function gateway(audit = {}) { return { gateway: { generation: 1, epoch: audit.epoch || 1, mapping_count: audit.terminal ? 1 : 3,
  pair_atomic: true, foreign_fixture_present: true, last_fault: audit.fault || 'renew_success' },
  product: { topology_generation: 1, tcp_state: 'CANDIDATE', udp_state: 'CANDIDATE',
    publisher_active: !audit.terminal, journal_entry_count: audit.terminal ? 0 : 2 },
  resources: { gateway_rss_bytes: 1, gateway_heap_bytes: 1, gateway_external_bytes: 1, gateway_array_buffers_bytes: 1, product_working_set_bytes: 1, gateway_handles: 1,
    product_handles: 1, gateway_sockets: audit.terminal ? 0 : 2, product_sockets: 1, event_loop_lag_ms: 1 },
  traffic: { pcp_requests: 1, natpmp_requests: 1, upnp_add_requests: 1, upnp_get_requests: 0,
    upnp_delete_requests: 0, accepted_outcomes: 3, rejected_outcomes: 0, pcp_accepted: 1, pcp_rejected: 0,
    natpmp_accepted: 1, natpmp_rejected: 0, upnp_accepted: 1, upnp_rejected: 0,
    max_owned_mapping_count: 2, final_owned_mapping_count: audit.terminal ? 0 : 2,
    final_owned_pcp: 0, final_owned_natpmp: audit.terminal ? 0 : 2, final_owned_upnp: 0 },
  faults: { armed_fault_ordinal: audit.armed || 0, armed_fault_name: audit.armed ? audit.fault : 'none',
    last_executed_fault_ordinal: audit.executed || 0, last_executed_fault_name: audit.fault || 'renew_success',
    last_executed_outcome: audit.outcome || 'none', last_fault_candidate_committed: Boolean(audit.candidateCommitted),
    pair_transactions_attempted: audit.attempted || 0, pair_transactions_committed: audit.committed || 0,
    last_wire_protocol:audit.executed?'natpmp':'none',pair_transactions_aborted: audit.aborted || 0,fault_transactions_attempted:audit.faultAttempted||0,recovery_transactions_attempted:audit.recoveryAttempted||0,last_recovery_transaction_ordinal: audit.recovery || 0,late_packets_emitted:audit.late||0,generation_before:1,generation_after:1,epoch_before:audit.epoch||1,epoch_after:audit.epoch||1,owned_before:2,owned_after:2,publisher_before:true,publisher_after:true,journal_before:2,journal_after:2 } }; }
function mockChild() { const state = { slot: 0, fault: null, attempted: 0, committed: 0, aborted: 0,faultAttempted:0,recoveryAttempted:0,recovery: 0, late: 0, epoch: 1, completed: false, begins: 0 };
  const view = (terminal = false) => gateway({ fault: state.fault || 'renew_success', armed: state.completed ? 0 : state.slot,
    executed: state.completed ? state.slot : Math.max(0, state.slot - 1), outcome: state.completed ? (HOSTILE.has(state.fault) ? (state.fault === 'dropped_late' ? 'late_emitted' : 'aborted') : 'committed') : 'none',
    candidateCommitted: state.completed && !HOSTILE.has(state.fault), attempted: state.attempted, committed: state.committed,faultAttempted:state.faultAttempted,recoveryAttempted:state.recoveryAttempted,
    aborted: state.aborted, recovery: state.recovery, late: state.late, epoch: state.epoch, terminal });
  return { state, child: { async start() {}, async beginSlot(fault, ordinal) { state.slot = ordinal; state.fault = fault; state.completed = false; state.begins += 1; if (fault === 'epoch_reset') state.epoch += 1; const value=view();if(fault==='epoch_reset'){value.faults.armed_fault_ordinal=0;value.faults.armed_fault_name='none';value.faults.last_executed_fault_ordinal=ordinal;value.faults.last_executed_fault_name=fault;}return value; },
    async observe() { if (!state.completed) { state.completed = true; state.attempted += 1;state.faultAttempted+=1;
      if (HOSTILE.has(state.fault)) { state.aborted += 1; if (state.fault === 'dropped_late') state.late += 1;
        if (state.fault !== 'final_boundary') { state.attempted+=1;state.recoveryAttempted+=1;state.committed += 1; state.recovery = state.slot; } }
      else { state.committed += 1; state.recovery = state.slot; } } return view(); },
    async shutdown() { return view(true); } } };
}

test('formal plan has 2880 ticks, 960 slots and exact ten-outcome vocabulary', () => {
  const plan = validateScenario(scenario); assert.equal(plan.tick_count, 2880); assert.equal(plan.schedule.length, 960);
  assert.equal(plan.schedule.at(-1), 'final_boundary'); assert.equal(Object.values(plan.planned).reduce((a,b)=>a+b,0),960);
  assert.throws(() => validateScenario({ ...scenario, fault_slot_ms: 10000 }), /SCENARIO/);
  assert.throws(() => validateScenario({ ...scenario, cycle: scenario.cycle.map((x,i)=>i===0?'unknown':x) }), /SCENARIO/);
});

test('slot machine rejects noop, wrong order, hostile commit and product mismatch', () => {
  const noop = createCrossValidator(scenario); noop.beginSlot('renew_success', gateway({ fault:'renew_success', armed:1 }));
  for(let i=0;i<3;i++)noop.acceptTick(gateway({ fault:'renew_success', armed:1 }));
  assert.throws(()=>noop.completeSlot(),/FAULT_NOT_CONSUMED/);
  assert.throws(()=>createCrossValidator(scenario).beginSlot('expiry',gateway({fault:'expiry',armed:1})),/FAULT_ORDER/);
  const hostileScenario={...scenario,cycle:['explicit_reject',...scenario.cycle.slice(1)]};const hostile=createCrossValidator(hostileScenario);
  hostile.beginSlot('explicit_reject',gateway({fault:'explicit_reject',armed:1}));
  for(let i=0;i<3;i++)hostile.acceptTick(gateway({fault:'explicit_reject',executed:1,outcome:'committed',candidateCommitted:true,attempted:1,committed:1,faultAttempted:1,recovery:1}));
  assert.throws(()=>hostile.completeSlot(),/REJECT_MUTATED/);
});

test('checkpoint binds slot prefix, product, gateway and predecessor', () => {
  const slots=Array.from({length:10},(_,index)=>({ordinal:index+1}));
  const previous='a'.repeat(64);const value=makeCheckpoint({ordinal:1,elapsedMs:300000,faultOrdinal:10,
    executed:{renew_success:10},slots,product:product(6,300000),gateway:gateway(),previousSha256:previous});
  assert.match(value.record_sha256,/^[a-f0-9]{64}$/);assert.throws(()=>makeCheckpoint({ordinal:1,elapsedMs:300000,faultOrdinal:30,executed:{},slots,product:product(),gateway:gateway(),previousSha256:previous}),/CHECKPOINT/);
});

test('accelerated controller drives 2880 observations, 960 consumed slots and 95 persisted checkpoints', async () => {
  const lines=[JSON.stringify({schema:'ese.v92.o01-product-started/v1',sequence:1,elapsed_ms:0,identity_accredited:true,preexisting_processes_unchanged:true})];
  for(let i=1;i<=480;i++)lines.push(JSON.stringify(product(i+1,i*60000)));
  lines.push(JSON.stringify({schema:'ese.v92.o01-product-terminal/v1',sequence:482,elapsed_ms:28800000,graceful_exit:true,mappings_absent:true,ini_restored_byte_exact:true,preexisting_processes_unchanged:true}));
  let now=0;const checkpoints=[];const fixture=mockChild();
  const result=await _runControllerTest({config:scenario,child:fixture.child,sourceCommit:'1'.repeat(40),sourceTree:'2'.repeat(40),scenarioSha256:'3'.repeat(64),boundFiles:scenario.bound_files.map(path=>({path,sha256:'4'.repeat(64)})),readProduct:async()=>lines.shift(),emitCheckpoint:async(value)=>{checkpoints.push(value);return value.record_sha256;},clock:{now:()=>now},sleep:async(ms)=>{now+=ms;}});
  assert.equal(result.verdict,'PASS');assert.equal(result.tick_count,2880);assert.equal(result.fault_slot_count,960);assert.equal(fixture.state.begins,960);assert.equal(checkpoints.length,95);assert.equal(lines.length,0);assert.equal(result.chain_tip_sha256,result.terminal_record.record_sha256);
});
