'use strict';
const test = require('node:test'); const assert = require('node:assert/strict'); const fs = require('node:fs'); const crypto=require('node:crypto');
const os=require('node:os');const path=require('node:path');const {execFileSync}=require('node:child_process');
const scenario = require('../v92_o01_scenario.json');
const { _runControllerTest } = require('../v92_o01_formal_controller');
const { _validateFormalEvidenceTest:validateFormalEvidence,validateFormalEvidence:validateBoundEvidence } = require('../v92_o01_validate_formal');

function product(sequence, elapsed) { return { schema: 'ese.v92.o01-product-sample/v1', sequence,
  elapsed_ms: elapsed, available: true, tcp_state: 'CANDIDATE', udp_state: 'CANDIDATE', same_generation: true,
  generation: 1, tcp_reason_code: 0, udp_reason_code: 0, working_set_bytes: 1000, handle_count: 10 }; }
const HOSTILE=new Set(['dropped_late','explicit_reject','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
function canonical(value){if(Array.isArray(value))return`[${value.map(canonical).join(',')}]`;if(value&&typeof value==='object')return`{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;return JSON.stringify(value);}
function checkpointHash(value){const body={...value};delete body.record_sha256;return crypto.createHash('sha256').update('ese.v92.o01-checkpoint/v2\0').update(canonical(body)).digest('hex');}
function gateway(a={}) { const value={ gateway: { generation: 1, epoch: a.epoch||1,
  mapping_count: a.terminal ? 1 : 3, pair_atomic: true, foreign_fixture_present: true, last_fault: a.fault||'renew_success' },
  product: { topology_generation: 1, tcp_state: 'CANDIDATE', udp_state: 'CANDIDATE',
    publisher_active: !a.terminal, journal_entry_count: a.terminal ? 0 : 2 }, resources: { gateway_rss_bytes: 1, gateway_heap_bytes: 1, gateway_external_bytes: 1, gateway_array_buffers_bytes: 1,
    product_working_set_bytes: 1, gateway_handles: 1, product_handles: 1, gateway_sockets: 2,
    product_sockets: 1, event_loop_lag_ms: 1 }, traffic: { pcp_requests: 1, natpmp_requests: 1,
    upnp_add_requests: 1, upnp_get_requests: 0, upnp_delete_requests: 0, accepted_outcomes: 3,
    rejected_outcomes: 0, pcp_accepted: 1, pcp_rejected: 0, natpmp_accepted: 1, natpmp_rejected: 0,
    upnp_accepted: 1, upnp_rejected: 0, max_owned_mapping_count: 2,
    final_owned_mapping_count: a.terminal ? 0 : 2, final_owned_pcp: 0, final_owned_natpmp: a.terminal ? 0 : 2,
    final_owned_upnp: 0 },faults:{armed_fault_ordinal:a.armed||0,armed_fault_name:a.armed?a.fault:'none',last_executed_fault_ordinal:a.executed||0,last_executed_fault_name:a.fault||'renew_success',last_executed_outcome:a.outcome||'none',last_fault_candidate_committed:Boolean(a.candidateCommitted),last_wire_protocol:a.executed?'natpmp':'none',pair_transactions_attempted:a.attempted||0,pair_transactions_committed:a.committed||0,pair_transactions_aborted:a.aborted||0,fault_transactions_attempted:a.faultAttempted||0,recovery_transactions_attempted:a.recoveryAttempted||0,last_recovery_transaction_ordinal:a.recovery||0,late_packets_emitted:a.late||0,generation_before:1,generation_after:1,epoch_before:a.epoch||1,epoch_after:a.epoch||1,owned_before:2,owned_after:2,publisher_before:true,publisher_after:true,journal_before:2,journal_after:2} };return value; }
function mockChild(){const s={slot:0,fault:null,attempted:0,committed:0,aborted:0,faultAttempted:0,recoveryAttempted:0,recovery:0,late:0,epoch:1,completed:false};const view=(terminal=false)=>gateway({fault:s.fault||'renew_success',armed:s.completed?0:s.slot,executed:s.completed?s.slot:Math.max(0,s.slot-1),outcome:s.completed?(HOSTILE.has(s.fault)?(s.fault==='dropped_late'?'late_emitted':'aborted'):'committed'):'none',candidateCommitted:s.completed&&!HOSTILE.has(s.fault),attempted:s.attempted,committed:s.committed,aborted:s.aborted,faultAttempted:s.faultAttempted,recoveryAttempted:s.recoveryAttempted,recovery:s.recovery,late:s.late,epoch:s.epoch,terminal});return{async start(){},async beginSlot(fault,ordinal){s.slot=ordinal;s.fault=fault;s.completed=false;if(fault==='epoch_reset')s.epoch++;const value=view();if(fault==='epoch_reset'){value.faults.armed_fault_ordinal=0;value.faults.armed_fault_name='none';value.faults.last_executed_fault_ordinal=ordinal;value.faults.last_executed_fault_name=fault;}return value;},async observe(){if(!s.completed){s.completed=true;s.attempted++;s.faultAttempted++;if(HOSTILE.has(s.fault)){s.aborted++;if(s.fault==='dropped_late')s.late++;if(s.fault!=='final_boundary'){s.attempted++;s.recoveryAttempted++;s.committed++;s.recovery=s.slot;}}else{s.committed++;s.recovery=s.slot;}}return view();},async shutdown(){return view(true);}}}
async function fixture(binding={sourceCommit:'1'.repeat(40),sourceTree:'2'.repeat(40),scenarioSha256:'3'.repeat(64),boundFiles:scenario.bound_files.map(path=>({path,sha256:'4'.repeat(64)}))}) {
  const lines = [JSON.stringify({ schema: 'ese.v92.o01-product-started/v1', sequence: 1, elapsed_ms: 0,
    identity_accredited: true, preexisting_processes_unchanged: true })];
  for (let index = 1; index <= 480; index += 1) lines.push(JSON.stringify(product(index + 1, index * 60000)));
  lines.push(JSON.stringify({ schema: 'ese.v92.o01-product-terminal/v1', sequence: 482, elapsed_ms: 28800000,
    graceful_exit: true, mappings_absent: true, ini_restored_byte_exact: true, preexisting_processes_unchanged: true }));
  let now = 0; const checkpoints = [];
  const result = await _runControllerTest({ config: scenario, ...binding,
    child: mockChild(),
    readProduct: async () => lines.shift(), emitCheckpoint: async (value) => {checkpoints.push(value);return value.record_sha256;},
    clock: { now: () => now }, sleep: async (milliseconds) => { now += milliseconds; } });
  return { checkpoints, result };
}

test('independent formal validator accepts the exact 95-record chain', async () => {
  const evidence = await fixture();
  assert.deepEqual(validateFormalEvidence({ config: scenario, ...evidence }), { verdict: 'PASS', checkpoints: 95, fault_slots:960,ticks:2880, samples: 480 });
  const controllerSource = fs.readFileSync(require.resolve('../v92_o01_formal_controller'), 'utf8');
  assert.doesNotMatch(controllerSource, /v92_o01_validate_formal/);
});

test('independent validator rejects missing, reordered, edited and false cleanup evidence', async () => {
  const base = await fixture();
  assert.throws(() => validateFormalEvidence({ config: scenario, checkpoints: base.checkpoints.slice(1), result: base.result }), /O01_FORMAL_RESULT/);
  const reordered = structuredClone(base); [reordered.checkpoints[0], reordered.checkpoints[1]] = [reordered.checkpoints[1], reordered.checkpoints[0]];
  assert.throws(() => validateFormalEvidence({ config: scenario, ...reordered }), /O01_FORMAL_(?:PRODUCT|CHECKPOINT)/);
  const edited = structuredClone(base); edited.checkpoints[4].product.generation += 1;
  assert.throws(() => validateFormalEvidence({ config: scenario, ...edited }), /O01_FORMAL_CHECKPOINT/);
  const dirty = structuredClone(base); dirty.result.terminal_record.product.ini_restored_byte_exact = false;
  assert.throws(() => validateFormalEvidence({ config: scenario, ...dirty }), /O01_FORMAL_TERMINAL/);
  const semantic=structuredClone(base);semantic.checkpoints[0].slots[0].candidate_committed=false;
  assert.throws(()=>validateFormalEvidence({config:scenario,...semantic}),/O01_FORMAL_SLOT_OUTCOME/);
  const leak=structuredClone(base);leak.checkpoints[0].gateway.resources.gateway_rss_bytes=scenario.limits.rss_absolute_bytes+1;
  assert.throws(()=>validateFormalEvidence({config:scenario,...leak}),/O01_FORMAL_RESOURCE/);
  const paths=structuredClone(base);paths.result.bound_files[0].path='tools/lab/other.js';
  assert.throws(()=>validateFormalEvidence({config:scenario,...paths}),/O01_FORMAL_RESULT/);
  const sourceRoot=path.resolve(__dirname,'..','..','..','..');const repo=fs.mkdtempSync(path.join(os.tmpdir(),'o01-dirty-repo-'));
  for(const relative of scenario.bound_files){const target=path.join(repo,...relative.split('/'));fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(sourceRoot,...relative.split('/')),target);}
  execFileSync('git',['init','-q'],{cwd:repo});execFileSync('git',['config','user.email','o01@test.invalid'],{cwd:repo});execFileSync('git',['config','user.name','O01 Test'],{cwd:repo});execFileSync('git',['add','.'],{cwd:repo});execFileSync('git',['commit','-qm','fixture'],{cwd:repo});
  const git=(...args)=>execFileSync('git',args,{cwd:repo,encoding:'utf8'}).trim();const scenarioBytes=fs.readFileSync(path.join(repo,'tools/lab/nat_gateway/v92_o01_scenario.json'));
  const bound=await fixture({sourceCommit:git('rev-parse','HEAD'),sourceTree:git('rev-parse','HEAD^{tree}'),scenarioSha256:crypto.createHash('sha256').update(scenarioBytes).digest('hex'),boundFiles:scenario.bound_files.map(relative=>({path:relative,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(repo,...relative.split('/')))).digest('hex')}))});
  fs.writeFileSync(path.join(repo,'dirty.marker'),'dirty');
  try{assert.throws(()=>validateBoundEvidence({config:scenario,...bound,repoRoot:repo}),/O01_FORMAL_SOURCE_DIRTY/);}finally{fs.rmSync(repo,{recursive:true,force:true});}
});

test('independent validator rejects a forged valid-hex checkpoint and a recomputed broken predecessor',async()=>{
  const forged=structuredClone(await fixture());forged.checkpoints[4].product.generation+=1;
  forged.checkpoints[4].record_sha256=checkpointHash(forged.checkpoints[4]);
  assert.match(forged.checkpoints[4].record_sha256,/^[a-f0-9]{64}$/);
  assert.throws(()=>validateFormalEvidence({config:scenario,...forged}),/O01_FORMAL_CHECKPOINT/);
  const broken=structuredClone(await fixture());broken.checkpoints[7].previous_sha256='a'.repeat(64);
  broken.checkpoints[7].record_sha256=checkpointHash(broken.checkpoints[7]);
  assert.throws(()=>validateFormalEvidence({config:scenario,...broken}),/O01_FORMAL_CHECKPOINT/);
});
