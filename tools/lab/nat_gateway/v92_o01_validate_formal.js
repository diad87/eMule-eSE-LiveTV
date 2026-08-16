'use strict';
const crypto = require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {execFileSync}=require('node:child_process');

function fail(code) { throw new Error(code); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function hash(domain, value) { return crypto.createHash('sha256').update(`${domain}\0`).update(canonical(value)).digest('hex'); }
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail('O01_FORMAL_SHAPE');
}
function uint(value,max=Number.MAX_SAFE_INTEGER){if(!Number.isSafeInteger(value)||value<0||value>max)fail('O01_FORMAL_INTEGER');}
function counts(events) { const out = {}; for (const event of events) out[event] = (out[event] || 0) + 1; return Object.fromEntries(Object.entries(out).sort()); }
function schedule(config) {
  if (!config || config.schema !== 'ese.v92.o01-scenario/v1' || config.formal_duration_ms !== 28800000 ||
      config.tick_ms !== 10000 || config.fault_slot_ms !== 30000 || config.sample_ms !== 60000 || config.checkpoint_ms !== 300000 ||
      !Array.isArray(config.cycle) || config.cycle.length !== 18 || config.final_fault !== 'final_boundary' ||
      [...new Set([...config.cycle,config.final_fault])].sort().join(',') !== ['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary'].sort().join(',')) fail('O01_FORMAL_SCENARIO');
  const out = Array.from({ length: 960 }, (_, index) => config.cycle[index % config.cycle.length]); out[959] = config.final_fault; return out;
}
function product(value, ordinal) {
  exact(value, ['schema','sequence','elapsed_ms','available','tcp_state','udp_state','same_generation','generation','tcp_reason_code','udp_reason_code','working_set_bytes','handle_count']);
  for(const key of ['sequence','elapsed_ms','generation','tcp_reason_code','udp_reason_code','working_set_bytes','handle_count'])uint(value[key],['tcp_reason_code','udp_reason_code'].includes(key)?65535:Number.MAX_SAFE_INTEGER);
  if (value.schema !== 'ese.v92.o01-product-sample/v1' || value.sequence !== ordinal * 5 + 1 ||
      value.elapsed_ms < ordinal * 300000 || value.elapsed_ms > ordinal * 300000 + 10000 ||
      value.available !== true || value.same_generation !== true || value.tcp_state !== value.udp_state || !['CANDIDATE','REACHABLE','BLOCKED','UNKNOWN','OTHER'].includes(value.tcp_state)) fail('O01_FORMAL_PRODUCT');
}
const GATEWAY_KEYS=['generation','epoch','mapping_count','pair_atomic','foreign_fixture_present','last_fault'];
const PRODUCT_KEYS=['topology_generation','tcp_state','udp_state','publisher_active','journal_entry_count'];
const RESOURCE_KEYS=['gateway_rss_bytes','gateway_heap_bytes','gateway_external_bytes','gateway_array_buffers_bytes','product_working_set_bytes','gateway_handles','product_handles','gateway_sockets','product_sockets','event_loop_lag_ms'];
const TRAFFIC_KEYS=['pcp_requests','natpmp_requests','upnp_add_requests','upnp_get_requests','upnp_delete_requests','accepted_outcomes','rejected_outcomes','pcp_accepted','pcp_rejected','natpmp_accepted','natpmp_rejected','upnp_accepted','upnp_rejected','max_owned_mapping_count','final_owned_mapping_count','final_owned_pcp','final_owned_natpmp','final_owned_upnp'];
const FAULT_KEYS=['armed_fault_ordinal','armed_fault_name','last_executed_fault_ordinal','last_executed_fault_name','last_executed_outcome','last_fault_candidate_committed','last_wire_protocol','pair_transactions_attempted','pair_transactions_committed','pair_transactions_aborted','fault_transactions_attempted','recovery_transactions_attempted','last_recovery_transaction_ordinal','late_packets_emitted','generation_before','generation_after','epoch_before','epoch_after','owned_before','owned_after','publisher_before','publisher_after','journal_before','journal_after'];
const SLOT_KEYS=['schema','ordinal','fault','generation_before','generation_after','epoch_before','epoch_after','owned_before','owned_after','attempted_delta','committed_delta','aborted_delta','late_emitted_delta','candidate_committed','recovery_ordinal','outcome','wire_protocol','fault_generation_before','fault_generation_after','fault_epoch_before','fault_epoch_after','fault_owned_before','fault_owned_after','fault_publisher_before','fault_publisher_after','fault_journal_before','fault_journal_after','pair_atomic','foreign_fixture_present','publisher_active','journal_entry_count'];
function privacy(value){if(value&&typeof value==='object'){for(const [key,item] of Object.entries(value)){if(/address|port|pid|nonce|credential|token|secret|path/i.test(key))fail('O01_FORMAL_PRIVACY');privacy(item);}}else if(typeof value==='string'&&/(?:[A-Z]:\\|\/home\/|(?:\d{1,3}\.){3}\d{1,3})/i.test(value))fail('O01_FORMAL_PRIVACY');}
function gateway(value) {
  exact(value, ['gateway','product','resources','traffic','faults']);
  exact(value.gateway,GATEWAY_KEYS);exact(value.product,PRODUCT_KEYS);exact(value.resources,RESOURCE_KEYS);exact(value.traffic,TRAFFIC_KEYS);exact(value.faults,FAULT_KEYS);privacy(value);
  for(const key of ['generation','epoch','mapping_count'])uint(value.gateway[key]);for(const key of ['topology_generation','journal_entry_count'])uint(value.product[key]);for(const item of Object.values(value.resources))uint(item);for(const item of Object.values(value.traffic))uint(item);for(const key of ['armed_fault_ordinal','last_executed_fault_ordinal','pair_transactions_attempted','pair_transactions_committed','pair_transactions_aborted','fault_transactions_attempted','recovery_transactions_attempted','last_recovery_transaction_ordinal','late_packets_emitted','generation_before','generation_after','epoch_before','epoch_after','owned_before','owned_after','journal_before','journal_after'])uint(value.faults[key]);
  if (value.gateway.pair_atomic !== true || value.gateway.foreign_fixture_present !== true ||
      value.gateway.mapping_count < 1 || value.gateway.mapping_count > 3 ||
      typeof value.product.publisher_active!=='boolean'||typeof value.faults.last_fault_candidate_committed!=='boolean'||typeof value.faults.publisher_before!=='boolean'||typeof value.faults.publisher_after!=='boolean'||!['none','pcp','natpmp'].includes(value.faults.last_wire_protocol)||
      !['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary'].includes(value.gateway.last_fault)||
      !['none','renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary'].includes(value.faults.armed_fault_name)||
      !['none','event','committed','aborted','late_emitted'].includes(value.faults.last_executed_outcome)||
      value.traffic.final_owned_mapping_count > value.traffic.max_owned_mapping_count||
      value.traffic.final_owned_mapping_count!==value.traffic.final_owned_pcp+value.traffic.final_owned_natpmp+value.traffic.final_owned_upnp||
      value.traffic.pcp_requests+value.traffic.natpmp_requests+value.traffic.upnp_add_requests+value.traffic.upnp_get_requests+value.traffic.upnp_delete_requests!==value.traffic.accepted_outcomes+value.traffic.rejected_outcomes) fail('O01_FORMAL_GATEWAY');
}
function limits(config,p,g){if(g.resources.gateway_rss_bytes>config.limits.rss_absolute_bytes||g.resources.gateway_heap_bytes>config.limits.heap_absolute_bytes||g.resources.gateway_external_bytes>config.limits.external_absolute_bytes||g.resources.gateway_array_buffers_bytes>config.limits.array_buffers_absolute_bytes||g.resources.gateway_handles>config.limits.handles||g.resources.gateway_sockets>config.limits.sockets||g.resources.event_loop_lag_ms>2000||g.gateway.mapping_count>config.limits.mapping_table||g.product.journal_entry_count>config.limits.journal_entries||p.working_set_bytes>config.limits.rss_absolute_bytes||p.handle_count>config.limits.handles)fail('O01_FORMAL_RESOURCE');}
function slot(value,ordinal,fault){exact(value,SLOT_KEYS);for(const key of ['ordinal','generation_before','generation_after','epoch_before','epoch_after','owned_before','owned_after','attempted_delta','committed_delta','aborted_delta','late_emitted_delta','recovery_ordinal','fault_generation_before','fault_generation_after','fault_epoch_before','fault_epoch_after','fault_owned_before','fault_owned_after','fault_journal_before','fault_journal_after','journal_entry_count'])uint(value[key]);if(value.schema!=='ese.v92.o01-slot/v1'||value.ordinal!==ordinal||value.fault!==fault||value.attempted_delta<1||value.pair_atomic!==true||value.foreign_fixture_present!==true||typeof value.candidate_committed!=='boolean'||typeof value.publisher_active!=='boolean'||typeof value.fault_publisher_before!=='boolean'||typeof value.fault_publisher_after!=='boolean'||!['pcp','natpmp'].includes(value.wire_protocol)||value.owned_after===1)fail('O01_FORMAL_SLOT');const hostile=['dropped_late','explicit_reject','stale','replay_duplicate','malformed','partial_pair','final_boundary'].includes(fault);if(hostile){if(value.candidate_committed||value.aborted_delta<1||!['aborted','late_emitted'].includes(value.outcome)||(fault!=='final_boundary'&&value.recovery_ordinal!==ordinal)||value.fault_generation_before!==value.fault_generation_after||value.fault_epoch_before!==value.fault_epoch_after||value.fault_owned_before!==value.fault_owned_after||value.fault_publisher_before!==value.fault_publisher_after||value.fault_journal_before!==value.fault_journal_after)fail('O01_FORMAL_SLOT_OUTCOME');}else if(!value.candidate_committed||value.committed_delta<1||value.recovery_ordinal!==ordinal||value.outcome!=='committed')fail('O01_FORMAL_SLOT_OUTCOME');if(fault==='dropped_late'&&(value.late_emitted_delta<1||value.outcome!=='late_emitted'))fail('O01_FORMAL_SLOT_LATE');if(fault==='epoch_reset'&&value.epoch_after!==value.epoch_before+1)fail('O01_FORMAL_SLOT_EPOCH');}
function validateEvidenceCore({ config, checkpoints, result }) {
  const events = schedule(config); const planned = counts(events);
  exact(result, ['schema','verdict','source_commit','source_tree','scenario_sha256','bound_files','elapsed_ms',
    'tick_count','fault_slot_count','product_sample_count','checkpoint_count','planned','executed','chain_tip_sha256','terminal_record']);
  if (result.schema !== 'ese.v92.o01-controller-result/v1' || result.verdict !== 'PASS' ||
      !/^[a-f0-9]{40}$/.test(result.source_commit) || !/^[a-f0-9]{40}$/.test(result.source_tree) ||
      !/^[a-f0-9]{64}$/.test(result.scenario_sha256) || !Array.isArray(result.bound_files) || result.bound_files.length < 1 ||
      result.bound_files.map((entry)=>entry.path).join('\n')!==config.bound_files.join('\n')||new Set(result.bound_files.map((entry)=>String(entry.path).toLowerCase())).size!==result.bound_files.length||result.bound_files.some((entry)=>!entry||Object.keys(entry).sort().join(',')!=='path,sha256'||!/^[a-f0-9]{64}$/.test(entry.sha256)||!config.bound_files.includes(entry.path))||
      result.elapsed_ms < 28800000 || result.tick_count !== 2880 || result.fault_slot_count !== 960 || result.product_sample_count !== 480 ||
      result.checkpoint_count !== 95 || canonical(result.planned) !== canonical(planned) ||
      canonical(result.executed) !== canonical(planned) || !Array.isArray(checkpoints) || checkpoints.length !== 95) fail('O01_FORMAL_RESULT');
  let previous = hash('ese.v92.o01-formal-chain-seed/v1', { source_commit: result.source_commit,
    source_tree: result.source_tree, scenario_sha256: result.scenario_sha256,
    bound_files: result.bound_files, duration_ms: 28800000 });
  const resourceHistory=[];
  for (let index = 0; index < checkpoints.length; index += 1) {
    const value = checkpoints[index]; const ordinal = index + 1; const elapsed = ordinal * 300000;
    exact(value, ['schema','ordinal','elapsed_ms','fault_ordinal','executed','slots','product','gateway','product_sha256','gateway_sha256','previous_sha256','record_sha256']);
    product(value.product, ordinal); gateway(value.gateway);limits(config,value.product,value.gateway);resourceHistory.push(value);
    if(index>=2&&ordinal*300000>config.warmup_ms){const prior=resourceHistory[index-2];if(value.gateway.resources.gateway_rss_bytes-prior.gateway.resources.gateway_rss_bytes>config.limits.rss_window_growth_bytes||value.gateway.resources.gateway_heap_bytes-prior.gateway.resources.gateway_heap_bytes>config.limits.heap_window_growth_bytes||value.product.working_set_bytes-prior.product.working_set_bytes>config.limits.rss_window_growth_bytes)fail('O01_FORMAL_RESOURCE_SLOPE');}
    const expectedExecuted = counts(events.slice(0, ordinal * 10));if(!Array.isArray(value.slots)||value.slots.length!==10)fail('O01_FORMAL_SLOTS');for(let offset=0;offset<10;offset++){const slotOrdinal=index*10+offset+1;slot(value.slots[offset],slotOrdinal,events[slotOrdinal-1]);}
    if (value.schema !== 'ese.v92.o01-checkpoint/v2' || value.ordinal !== ordinal ||
        value.elapsed_ms !== elapsed || value.fault_ordinal !== ordinal * 10 ||
        canonical(value.executed) !== canonical(expectedExecuted) || value.previous_sha256 !== previous ||
        value.product_sha256 !== hash('ese.v92.o01-product-sample/v1', value.product) ||
        value.gateway_sha256 !== hash('ese.v92.o01-gateway-observation/v1', value.gateway)) fail('O01_FORMAL_CHECKPOINT');
    const body = { ...value }; delete body.record_sha256;
    if (value.record_sha256 !== hash('ese.v92.o01-checkpoint/v2', body)) fail('O01_FORMAL_CHAIN');
    previous = value.record_sha256;
  }
  const terminal=result.terminal_record;
  exact(terminal,['schema','elapsed_ms','slots','product','gateway','product_sha256','gateway_sha256','previous_sha256','record_sha256']);
  if(!Array.isArray(terminal.slots)||terminal.slots.length!==10)fail('O01_FORMAL_SLOTS');for(let offset=0;offset<10;offset++){const ordinal=951+offset;slot(terminal.slots[offset],ordinal,events[ordinal-1]);}
  gateway(terminal.gateway);limits(config,checkpoints[94].product,terminal.gateway);const slopeBase=checkpoints[92];if(terminal.gateway.resources.gateway_rss_bytes-slopeBase.gateway.resources.gateway_rss_bytes>config.limits.rss_window_growth_bytes||terminal.gateway.resources.gateway_heap_bytes-slopeBase.gateway.resources.gateway_heap_bytes>config.limits.heap_window_growth_bytes)fail('O01_FORMAL_RESOURCE_SLOPE');exact(terminal.product,['schema','sequence','elapsed_ms','graceful_exit','mappings_absent','ini_restored_byte_exact','preexisting_processes_unchanged']);const terminalBody={...terminal};delete terminalBody.record_sha256;
  if (terminal.schema!=='ese.v92.o01-terminal/v1'||terminal.previous_sha256!==previous||
      terminal.product_sha256!==hash('ese.v92.o01-product-terminal/v1',terminal.product)||
      terminal.gateway_sha256!==hash('ese.v92.o01-gateway-terminal/v1',terminal.gateway)||
      terminal.record_sha256!==hash('ese.v92.o01-terminal/v1',terminalBody)||result.chain_tip_sha256!==terminal.record_sha256||
      terminal.product.schema !== 'ese.v92.o01-product-terminal/v1' || terminal.product.sequence !== 482 || terminal.product.elapsed_ms < 28800000 ||
      terminal.product.graceful_exit !== true || terminal.product.mappings_absent !== true || terminal.product.ini_restored_byte_exact !== true || terminal.product.preexisting_processes_unchanged !== true ||
      terminal.gateway.gateway.mapping_count !== 1 || terminal.gateway.gateway.foreign_fixture_present !== true ||
      terminal.gateway.traffic.final_owned_mapping_count !== 0 || terminal.gateway.product.publisher_active !== false || terminal.gateway.product.journal_entry_count !== 0) fail('O01_FORMAL_TERMINAL');
  return Object.freeze({ verdict: 'PASS', checkpoints: 95, fault_slots: 960, ticks:2880, samples: 480 });
}
function validateRepository(repoRoot,config,result){const root=path.resolve(repoRoot||'');const git=(args)=>execFileSync('git',['-C',root,...args],{encoding:'utf8',windowsHide:true}).trim();if(git(['status','--porcelain=v1','--untracked-files=all'])!=='')fail('O01_FORMAL_SOURCE_DIRTY');if(git(['rev-parse','HEAD'])!==result.source_commit||git(['rev-parse','HEAD^{tree}'])!==result.source_tree)fail('O01_FORMAL_SOURCE_BINDING');const scenarioBytes=fs.readFileSync(path.join(root,'tools/lab/nat_gateway/v92_o01_scenario.json'));const diskConfig=JSON.parse(scenarioBytes.toString('utf8'));if(canonical(diskConfig)!==canonical(config))fail('O01_FORMAL_SCENARIO_SEMANTICS');const scenarioSha=crypto.createHash('sha256').update(scenarioBytes).digest('hex');if(scenarioSha!==result.scenario_sha256||config.bound_files.length!==20)fail('O01_FORMAL_SCENARIO_BINDING');for(let index=0;index<config.bound_files.length;index++){const relative=config.bound_files[index];const digest=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,...relative.split('/')))).digest('hex');if(result.bound_files[index].path!==relative||result.bound_files[index].sha256!==digest)fail('O01_FORMAL_FILE_BINDING');}}
function validateFormalEvidence(options){const verdict=validateEvidenceCore(options);validateRepository(options.repoRoot,options.config,options.result);return verdict;}
function runCli(){if(process.argv.length!==2||Number(process.versions.node.split('.')[0])!==22)fail('O01_FORMAL_VALIDATOR_AUTHORITY');const repo=process.env.O01_FORMAL_REPO_ROOT,evidence=process.env.O01_FORMAL_EVIDENCE_ROOT;if(typeof repo!=='string'||typeof evidence!=='string')fail('O01_FORMAL_VALIDATOR_CONFIG');const names=fs.readdirSync(evidence).sort();const expected=[...Array.from({length:95},(_,index)=>`checkpoint-${String(index+1).padStart(2,'0')}.json`),'controller-result.json'].sort();if(names.join('\n')!==expected.join('\n'))fail('O01_FORMAL_EVIDENCE_SET');const parse=(file)=>JSON.parse(fs.readFileSync(path.join(evidence,file),'utf8'));const config=JSON.parse(fs.readFileSync(path.join(repo,'tools/lab/nat_gateway/v92_o01_scenario.json'),'utf8'));const result=parse('controller-result.json');const checkpoints=Array.from({length:95},(_,index)=>parse(`checkpoint-${String(index+1).padStart(2,'0')}.json`));const verdict=validateFormalEvidence({repoRoot:repo,config,result,checkpoints});process.stdout.write(`${JSON.stringify({schema:'ese.v92.o01-formal-validation/v1',verdict:verdict.verdict,checkpoints:verdict.checkpoints,fault_slots:verdict.fault_slots,ticks:verdict.ticks,samples:verdict.samples})}\n`);}
if(require.main===module){try{runCli();}catch(error){process.stderr.write(`V92_O01_FORMAL_VALIDATION_FAIL ${error.message}\n`);process.exitCode=1;}}
module.exports = Object.freeze({ validateFormalEvidence,_validateFormalEvidenceTest:validateEvidenceCore });
