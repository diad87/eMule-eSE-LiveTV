'use strict';

const crypto = require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {execFileSync}=require('node:child_process');
const { countSchedule, canonical } = require('./v92_o01_soak');
const { validateObservation } = require('./v92_o01_bridge_protocol');
const { parseLine, createProductStreamState } = require('./v92_o01_product_stream');

const REJECT_STABLE = new Set(['explicit_reject', 'stale', 'replay_duplicate', 'malformed', 'partial_pair']);
const BOUNDARY_FAULTS = new Set(['expiry', 'epoch_reset']);
const FAULT_TICK_LIMIT = 12;
const RECOVERY_TICK_LIMIT = 20;
const MAX_TRANSIENT_PRODUCT_SAMPLES = 2;
const ALL_FAULTS = Object.freeze(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
const TRANSIENT_FAULTS = new Set(ALL_FAULTS.filter(value => value !== 'renew_success'));
// Retain the closed legacy projection for already-persisted pre-A40 failures: O01_CONTROLLER_PRODUCT.
const CHECKPOINT_KEYS = Object.freeze([
  'schema', 'ordinal', 'elapsed_ms', 'fault_ordinal', 'executed', 'slots',
  'product', 'gateway', 'product_sha256', 'gateway_sha256', 'previous_sha256', 'record_sha256',
]);

function fail(code) { throw new Error(code); }
function hash(domain, value) {
  return crypto.createHash('sha256').update(`${domain}\0`).update(canonical(value)).digest('hex');
}
function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) fail('O01_CONTROLLER_SHAPE');
}
function bounded(promise,milliseconds,code){let timer;return Promise.race([Promise.resolve(promise),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error(code)),milliseconds);})]).finally(()=>clearTimeout(timer));}
function repositoryBinding(repoRoot,config){const root=path.resolve(repoRoot||'');const git=(args)=>execFileSync('git',['-C',root,...args],{encoding:'utf8',windowsHide:true}).trim();if(git(['status','--porcelain=v1','--untracked-files=all'])!=='')fail('O01_CONTROLLER_SOURCE_DIRTY');const sourceCommit=git(['rev-parse','HEAD']);const sourceTree=git(['rev-parse','HEAD^{tree}']);const scenarioPath=path.join(root,'tools/lab/nat_gateway/v92_o01_scenario.json');const scenarioSha256=crypto.createHash('sha256').update(fs.readFileSync(scenarioPath)).digest('hex');const boundFiles=config.bound_files.map((relative)=>({path:relative,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,...relative.split('/')))).digest('hex')}));return{sourceCommit,sourceTree,scenarioSha256,boundFiles};}
function validateScenario(config) {
  if (!config || config.schema !== 'ese.v92.o01-scenario/v1' || config.formal_duration_ms !== 28800000 || config.tick_ms !== 10000 ||
      config.fault_slot_ms !== 300000 || config.lease_ms !== 120000 || config.late_delay_ms !== 8000 ||
      config.sample_ms !== 60000 || config.checkpoint_ms !== 300000 || config.node_major !== 22 || config.limits.product_handles !== 512 ||
      !Array.isArray(config.cycle) || config.cycle.length !== 18 || config.final_fault !== 'final_boundary' ||
      [...new Set([...config.cycle, config.final_fault])].sort().join(',') !== [...ALL_FAULTS].sort().join(',')) {
    fail('O01_CONTROLLER_SCENARIO');
  }
  const tickCount = config.formal_duration_ms / config.tick_ms;
  const slotCount = config.formal_duration_ms / config.fault_slot_ms;
  const slotTicks = config.fault_slot_ms / config.tick_ms;
  const schedule = Array.from({ length: slotCount }, (_, index) => config.cycle[index % config.cycle.length]);
  schedule[slotCount - 1] = config.final_fault;
  if (tickCount !== 2880 || slotTicks !== 30 || schedule.length !== 96 || schedule.at(-1) !== 'final_boundary') fail('O01_CONTROLLER_SCHEDULE');
  return Object.freeze({ tick_count: tickCount, slot_ticks: slotTicks,
    schedule: Object.freeze(schedule), planned: Object.freeze(countSchedule(schedule)) });
}
function assertLimits(config, product, gateway) {
  if(gateway.resources.gateway_rss_bytes>config.limits.rss_absolute_bytes)fail('O01_CONTROLLER_RESOURCE_GATEWAY_RSS');
  if(gateway.resources.gateway_heap_bytes>config.limits.heap_absolute_bytes)fail('O01_CONTROLLER_RESOURCE_GATEWAY_HEAP');
  if(gateway.resources.gateway_external_bytes>config.limits.external_absolute_bytes)fail('O01_CONTROLLER_RESOURCE_GATEWAY_EXTERNAL');
  if(gateway.resources.gateway_array_buffers_bytes>config.limits.array_buffers_absolute_bytes)fail('O01_CONTROLLER_RESOURCE_GATEWAY_ARRAY_BUFFERS');
  if(gateway.resources.gateway_handles>config.limits.handles)fail('O01_CONTROLLER_RESOURCE_GATEWAY_HANDLES');
  if(gateway.resources.gateway_sockets>config.limits.sockets)fail('O01_CONTROLLER_RESOURCE_GATEWAY_SOCKETS');
  if(gateway.resources.event_loop_lag_ms>2000)fail('O01_CONTROLLER_RESOURCE_EVENT_LOOP_LAG');
  if(gateway.gateway.mapping_count>config.limits.mapping_table)fail('O01_CONTROLLER_RESOURCE_MAPPING_TABLE');
  if(gateway.product.journal_entry_count>config.limits.journal_entries)fail('O01_CONTROLLER_RESOURCE_JOURNAL');
  if(product&&product.working_set_bytes>config.limits.rss_absolute_bytes)fail('O01_CONTROLLER_RESOURCE_PRODUCT_RSS');
  if(product&&product.handle_count>config.limits.product_handles)fail('O01_CONTROLLER_RESOURCE_PRODUCT_HANDLES');
}
function createCrossValidator(config) {
  const plan = validateScenario(config);
  let slotOrdinal = 0; let ticks = 0; let baseline = null; let latestGateway = null;
  let latestProduct = null; let productSamples = 0; let latestProductGeneration = null; let activeFault = null; let slotStartTick = 0;
  let faultTickOffset = 0; let recoveryTickOffset = 0; let transientProductSamples = 0;
  let latestProductCoherent = true; const gatewayHistory=[]; const productHistory=[];
  const executed = {};
  return Object.freeze({ beginSlot(fault, gatewayValue) {
    const gateway = validateObservation(gatewayValue);
    const expected = plan.schedule[slotOrdinal];
    if (activeFault || fault !== expected || gateway.faults.armed_fault_ordinal!==slotOrdinal+1 ||
        gateway.faults.armed_fault_name!==fault||gateway.faults.last_executed_fault_ordinal!==slotOrdinal) fail('O01_CONTROLLER_FAULT_ORDER');
    baseline = latestGateway ? structuredClone(latestGateway) : structuredClone(gateway);
    activeFault = fault; latestGateway = structuredClone(gateway); slotStartTick = ticks;
    faultTickOffset = 0; recoveryTickOffset = 0; transientProductSamples = 0;
    latestProductCoherent = true; return gateway;
  }, acceptTick(gatewayValue) {
    if (!activeFault) fail('O01_CONTROLLER_SLOT_NOT_STARTED');
    const gateway = validateObservation(gatewayValue); ticks += 1;
    const pairTransition=TRANSIENT_FAULTS.has(activeFault)&&faultTickOffset>0&&recoveryTickOffset===0&&
      gateway.gateway.pair_atomic===false&&gateway.gateway.mapping_count===2&&
      gateway.traffic.final_owned_mapping_count===1;
    if ((!gateway.gateway.pair_atomic&&!pairTransition) || !gateway.gateway.foreign_fixture_present ||
        gateway.gateway.mapping_count < 1 || gateway.gateway.mapping_count > 3 ||
        (gateway.gateway.mapping_count === 2&&!pairTransition) ||
        gateway.traffic.final_owned_mapping_count > gateway.traffic.max_owned_mapping_count) {
      fail('O01_CONTROLLER_GATEWAY');
    }
    const ordinal=slotOrdinal+1;const offset=ticks-slotStartTick;
    if(gateway.faults.last_executed_fault_ordinal===ordinal&&faultTickOffset===0)faultTickOffset=offset;
    if(gateway.faults.last_recovery_transaction_ordinal===ordinal&&recoveryTickOffset===0)recoveryTickOffset=offset;
    if(faultTickOffset>FAULT_TICK_LIMIT||(offset>=FAULT_TICK_LIMIT&&faultTickOffset===0))fail('O01_CONTROLLER_FAULT_NOT_CONSUMED');
    assertLimits(config, null, gateway);gatewayHistory.push(gateway);if(ticks>config.warmup_ms/config.tick_ms&&gatewayHistory.length>60){const prior=gatewayHistory[gatewayHistory.length-61];if(gateway.resources.gateway_rss_bytes-prior.resources.gateway_rss_bytes>config.limits.rss_window_growth_bytes||gateway.resources.gateway_heap_bytes-prior.resources.gateway_heap_bytes>config.limits.heap_window_growth_bytes)fail('O01_CONTROLLER_RESOURCE_SLOPE');} latestGateway = structuredClone(gateway); return gateway;
  }, completeSlot() {
    if (!activeFault || ticks !== (slotOrdinal + 1) * plan.slot_ticks) fail('O01_CONTROLLER_SLOT_TICKS');
    const fault = activeFault; const current = latestGateway; const ordinal = slotOrdinal + 1;
    if (current.faults.armed_fault_ordinal !== 0 || current.faults.armed_fault_name !== 'none' ||
        current.faults.last_executed_fault_ordinal !== ordinal || current.faults.last_executed_fault_name !== fault ||
        current.faults.pair_transactions_attempted <= baseline.faults.pair_transactions_attempted) fail('O01_CONTROLLER_FAULT_NOT_CONSUMED');
    if(faultTickOffset<1||faultTickOffset>FAULT_TICK_LIMIT||
       recoveryTickOffset<faultTickOffset||recoveryTickOffset>RECOVERY_TICK_LIMIT||!latestProductCoherent)fail('O01_CONTROLLER_RECOVERY_MISSING');
    if (!['pcp','natpmp'].includes(current.faults.last_wire_protocol)) fail('O01_CONTROLLER_MAPPER_PROTOCOL');
    if (current.faults.pair_transactions_attempted !== current.faults.pair_transactions_committed + current.faults.pair_transactions_aborted ||
        current.faults.pair_transactions_attempted !== current.faults.fault_transactions_attempted + current.faults.recovery_transactions_attempted) fail('O01_CONTROLLER_TRANSACTION_ACCOUNTING');
    const attemptedDelta=current.faults.pair_transactions_attempted-baseline.faults.pair_transactions_attempted;
    const committedDelta=current.faults.pair_transactions_committed-baseline.faults.pair_transactions_committed;
    const abortedDelta=current.faults.pair_transactions_aborted-baseline.faults.pair_transactions_aborted;
    if(attemptedDelta!==committedDelta+abortedDelta||committedDelta<1||
       current.traffic.final_owned_mapping_count!==2||current.product.publisher_active!==true||current.product.journal_entry_count!==2)fail('O01_CONTROLLER_TRANSACTION_ACCOUNTING');
    if (REJECT_STABLE.has(fault) || fault === 'dropped_late' || fault === 'final_boundary') {
      if (current.faults.last_fault_candidate_committed || current.faults.pair_transactions_aborted <= baseline.faults.pair_transactions_aborted) fail('O01_CONTROLLER_REJECT_MUTATED');
      if (current.faults.generation_before!==current.faults.generation_after||current.faults.epoch_before!==current.faults.epoch_after||current.faults.owned_before!==current.faults.owned_after||current.faults.publisher_before!==current.faults.publisher_after||current.faults.journal_before!==current.faults.journal_after) fail('O01_CONTROLLER_HOSTILE_STATE_MUTATED');
      if (current.faults.last_recovery_transaction_ordinal !== ordinal) fail('O01_CONTROLLER_RECOVERY_MISSING');
    } else if(BOUNDARY_FAULTS.has(fault)){
      if(current.faults.last_fault_candidate_committed||current.faults.pair_transactions_aborted<=baseline.faults.pair_transactions_aborted||
         current.faults.last_recovery_transaction_ordinal!==ordinal||current.faults.owned_before!==2||current.faults.owned_after!==0||
         current.faults.publisher_before!==true||current.faults.publisher_after!==false||current.faults.journal_before!==2||current.faults.journal_after!==0||
         current.traffic.final_owned_mapping_count!==2)fail('O01_CONTROLLER_BOUNDARY_RECOVERY');
      if(current.faults.generation_before!==baseline.gateway.generation||current.faults.epoch_before!==baseline.gateway.epoch)fail('O01_CONTROLLER_BOUNDARY_RECOVERY');
      if(fault==='expiry'&&(current.faults.generation_after!==baseline.gateway.generation||current.faults.epoch_after!==baseline.gateway.epoch||current.gateway.generation!==baseline.gateway.generation||current.gateway.epoch!==baseline.gateway.epoch))fail('O01_CONTROLLER_EXPIRY');
      if(fault==='epoch_reset'&&(current.faults.generation_after!==baseline.gateway.generation+1||current.faults.epoch_after!==baseline.gateway.epoch+1||current.gateway.generation!==baseline.gateway.generation+1||current.gateway.epoch!==baseline.gateway.epoch+1))fail('O01_CONTROLLER_EPOCH');
    } else if (current.faults.pair_transactions_committed <= baseline.faults.pair_transactions_committed ||
               current.faults.last_recovery_transaction_ordinal !== ordinal) fail('O01_CONTROLLER_RECOVERY_MISSING');
    if(!BOUNDARY_FAULTS.has(fault)&&(current.faults.generation_before!==baseline.gateway.generation||
       current.faults.epoch_before!==baseline.gateway.epoch||current.faults.owned_before!==baseline.traffic.final_owned_mapping_count||
       current.faults.publisher_before!==baseline.product.publisher_active||current.faults.journal_before!==baseline.product.journal_entry_count||
       current.faults.generation_after!==current.gateway.generation||current.faults.epoch_after!==current.gateway.epoch||
       current.faults.owned_after!==current.traffic.final_owned_mapping_count||current.faults.publisher_after!==current.product.publisher_active||
       current.faults.journal_after!==current.product.journal_entry_count))fail('O01_CONTROLLER_FAULT_AUDIT');
    if (fault === 'dropped_late' && (current.faults.late_packets_emitted-baseline.faults.late_packets_emitted!==1||
        current.faults.late_packets_suppressed<=baseline.faults.late_packets_suppressed)) fail('O01_CONTROLLER_LATE_NOT_EMITTED');
    if(fault!=='epoch_reset'&&(current.gateway.generation!==baseline.gateway.generation||current.gateway.epoch!==baseline.gateway.epoch))fail('O01_CONTROLLER_GENERATION_DRIFT');
    if (fault === 'epoch_reset' && current.gateway.epoch !== baseline.gateway.epoch + 1) fail('O01_CONTROLLER_EPOCH');
    const summary=Object.freeze({schema:'ese.v92.o01-slot/v1',ordinal,fault,fault_tick_offset:faultTickOffset,recovery_tick_offset:recoveryTickOffset,transient_product_samples:transientProductSamples,generation_before:baseline.gateway.generation,generation_after:current.gateway.generation,epoch_before:baseline.gateway.epoch,epoch_after:current.gateway.epoch,owned_before:baseline.traffic.final_owned_mapping_count,owned_after:current.traffic.final_owned_mapping_count,attempted_delta:attemptedDelta,committed_delta:committedDelta,aborted_delta:abortedDelta,late_emitted_delta:current.faults.late_packets_emitted-baseline.faults.late_packets_emitted,late_suppressed_delta:current.faults.late_packets_suppressed-baseline.faults.late_packets_suppressed,candidate_committed:current.faults.last_fault_candidate_committed,recovery_ordinal:current.faults.last_recovery_transaction_ordinal,outcome:current.faults.last_executed_outcome,wire_protocol:current.faults.last_wire_protocol,fault_generation_before:current.faults.generation_before,fault_generation_after:current.faults.generation_after,fault_epoch_before:current.faults.epoch_before,fault_epoch_after:current.faults.epoch_after,fault_owned_before:current.faults.owned_before,fault_owned_after:current.faults.owned_after,fault_publisher_before:current.faults.publisher_before,fault_publisher_after:current.faults.publisher_after,fault_journal_before:current.faults.journal_before,fault_journal_after:current.faults.journal_after,pair_atomic:current.gateway.pair_atomic,foreign_fixture_present:current.gateway.foreign_fixture_present,publisher_active:current.product.publisher_active,journal_entry_count:current.product.journal_entry_count});
    slotOrdinal = ordinal; executed[fault] = (executed[fault] || 0) + 1; activeFault = null;
    return summary;
  }, acceptProduct(productValue) {
    if (!latestGateway || ticks === 0 || ticks % 6 !== 0 || productSamples + 1 !== ticks / 6) fail('O01_CONTROLLER_PRODUCT_PHASE');
    const product = typeof productValue === 'string' ? parseLine(productValue) : productValue;
    if (product.schema !== 'ese.v92.o01-product-sample/v1') fail('O01_CONTROLLER_PRODUCT_SHAPE');
    if (product.available !== true) fail('O01_CONTROLLER_PRODUCT_UNAVAILABLE');
    if (product.same_generation !== true) fail('O01_CONTROLLER_PRODUCT_GENERATION');
    if (product.tcp_state !== product.udp_state) fail('O01_CONTROLLER_PRODUCT_PAIR_DIVERGED');
    if (product.sequence !== productSamples + 2) fail('O01_CONTROLLER_PRODUCT_SEQUENCE');
    if(!Number.isSafeInteger(product.generation)||product.generation<latestGateway.product.topology_generation||
       (latestProductGeneration!==null&&product.generation<latestProductGeneration))fail('O01_CONTROLLER_PRODUCT_TOPOLOGY');
    latestProductGeneration=product.generation;
    const needsPublisher=['CANDIDATE','REACHABLE'].includes(product.tcp_state);
    const coherent=!needsPublisher||(latestGateway.product.publisher_active&&latestGateway.product.journal_entry_count===2);
    if(!coherent){const faultTransition=TRANSIENT_FAULTS.has(activeFault)&&faultTickOffset>0&&recoveryTickOffset===0&&
      !latestGateway.product.publisher_active&&latestGateway.product.journal_entry_count===0&&
      latestGateway.traffic.final_owned_mapping_count===0&&transientProductSamples<MAX_TRANSIENT_PRODUCT_SAMPLES;
      if(!faultTransition)fail('O01_CONTROLLER_PRODUCT_PUBLISHER');transientProductSamples+=1;}
    latestProductCoherent=coherent;
    assertLimits(config, product, latestGateway);productHistory.push(product);if(productSamples+1>config.warmup_ms/config.sample_ms&&productHistory.length>10){const prior=productHistory[productHistory.length-11];if(product.working_set_bytes-prior.working_set_bytes>config.limits.rss_window_growth_bytes)fail('O01_CONTROLLER_RESOURCE_SLOPE');}
    productSamples += 1; latestProduct = Object.freeze({ ...product });
    return Object.freeze({ product: latestProduct, gateway: latestGateway });
  }, snapshot() {
    return Object.freeze({ slot_ordinal: slotOrdinal, tick_count: ticks, product_samples: productSamples,
      executed: Object.freeze(Object.fromEntries(Object.entries(executed).sort())), planned: plan.planned,
      latest_product: latestProduct, latest_gateway: latestGateway });
  } });
}
function makeCheckpoint({ ordinal, elapsedMs, faultOrdinal, executed, slots, product, gateway, previousSha256 }) {
  if (!Number.isSafeInteger(ordinal) || ordinal < 1 || ordinal > 95 ||
      elapsedMs !== ordinal * 300000 || !Number.isSafeInteger(faultOrdinal) || faultOrdinal !== ordinal ||
      !Array.isArray(slots)||slots.length!==1||slots[0].ordinal!==faultOrdinal||
      typeof previousSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(previousSha256)) fail('O01_CONTROLLER_CHECKPOINT');
  const body = { schema: 'ese.v92.o01-checkpoint/v2', ordinal, elapsed_ms: elapsedMs,
    fault_ordinal: faultOrdinal, executed: Object.fromEntries(Object.entries(executed).sort()), slots,
    product, gateway,
    product_sha256: hash('ese.v92.o01-product-sample/v1', product),
    gateway_sha256: hash('ese.v92.o01-gateway-observation/v1', gateway), previous_sha256: previousSha256 };
  const record = { ...body, record_sha256: hash('ese.v92.o01-checkpoint/v2', body) };
  exactKeys(record, CHECKPOINT_KEYS);
  return Object.freeze(record);
}
function makeTerminalRecord({ product, gateway, slots, previousSha256 }) {
  if(!Array.isArray(slots)||slots.length!==1||slots[0].ordinal!==96)fail('O01_CONTROLLER_TERMINAL_SLOTS');
  const body = { schema: 'ese.v92.o01-terminal/v1', elapsed_ms: product.elapsed_ms,
    slots,product, gateway, product_sha256: hash('ese.v92.o01-product-terminal/v1', product),
    gateway_sha256: hash('ese.v92.o01-gateway-terminal/v1', gateway), previous_sha256: previousSha256 };
  return Object.freeze({ ...body, record_sha256: hash('ese.v92.o01-terminal/v1', body) });
}

async function runControllerCore(options) {
  const { config, child, readProduct, emitCheckpoint, clock, sleep,
    sourceCommit, sourceTree, scenarioSha256, boundFiles } = options;
  const plan = validateScenario(config);
  if (!child || typeof child.start !== 'function' || typeof child.beginSlot !== 'function' || typeof child.observe !== 'function' ||
      typeof child.shutdown !== 'function' || typeof readProduct !== 'function' ||
      typeof emitCheckpoint !== 'function' || !clock || typeof clock.now !== 'function' || typeof sleep !== 'function') {
    fail('O01_CONTROLLER_CONFIG');
  }
  if (typeof sourceCommit !== 'string' || !/^[a-f0-9]{40}$/.test(sourceCommit) ||
      typeof sourceTree !== 'string' || !/^[a-f0-9]{40}$/.test(sourceTree) ||
      typeof scenarioSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(scenarioSha256) ||
      !Array.isArray(boundFiles) || boundFiles.length < 1 || boundFiles.some((entry) => !entry ||
        typeof entry.path !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(entry.path) ||
        typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256)) ||
      boundFiles.map((entry)=>entry.path).join('\n') !== config.bound_files.join('\n') ||
      new Set(boundFiles.map((entry)=>entry.path.toLowerCase())).size !== boundFiles.length) fail('O01_CONTROLLER_BINDING');
  const productState = createProductStreamState({ durationMs: config.formal_duration_ms,
    maxGapMs: config.limits.checkpoint_max_gap_ms > 70000 ? 70000 : config.limits.checkpoint_max_gap_ms });
  const cross = createCrossValidator(config); let childStarted = false; let childClosed = false;
  let previous = hash('ese.v92.o01-formal-chain-seed/v1', { source_commit: sourceCommit,
    source_tree: sourceTree, scenario_sha256: scenarioSha256, bound_files: boundFiles,
    duration_ms: config.formal_duration_ms });
  try {
    await child.start(); childStarted = true;
    const started = productState.accept(await bounded(readProduct(),240000,'O01_CONTROLLER_PRODUCT_START_TIMEOUT'));
    if (started.schema !== 'ese.v92.o01-product-started/v1') fail('O01_CONTROLLER_PRODUCT_NOT_STARTED');
    const mapperPreflight=validateObservation(await child.observe());
    if(mapperPreflight.traffic.final_owned_upnp!==0||
       !((mapperPreflight.traffic.final_owned_pcp===2&&mapperPreflight.traffic.final_owned_natpmp===0)||
         (mapperPreflight.traffic.final_owned_natpmp===2&&mapperPreflight.traffic.final_owned_pcp===0)))
      fail('O01_CONTROLLER_MAPPER_PROTOCOL');
    const epoch = clock.now(); let lastTickObserved = 0; let lastProduct = null; let lastGateway = null;let pendingSlots=[];let persistedCheckpoints=0;
    for (let index = 0; index < plan.tick_count; index += 1) {
      if (index % plan.slot_ticks === 0) {
        const slot = index / plan.slot_ticks + 1; const fault = plan.schedule[slot - 1];
        cross.beginSlot(fault, await child.beginSlot(fault, slot));
      }
      const target = (index + 1) * config.tick_ms;
      const remaining = target - (clock.now() - epoch);
      if (remaining > 0) await sleep(remaining);
      const elapsed = clock.now() - epoch;
      if (!Number.isSafeInteger(elapsed) || elapsed < target || elapsed - target > 2000 ||
          elapsed <= lastTickObserved || elapsed - lastTickObserved > 12000) fail('O01_CONTROLLER_CLOCK_GAP');
      lastTickObserved = elapsed;
      lastGateway = await child.observe(); cross.acceptTick(lastGateway);
      if ((index + 1) % 6 === 0) {
        const line = await bounded(readProduct(),15000,'O01_CONTROLLER_PRODUCT_SAMPLE_TIMEOUT'); productState.accept(line);
        lastProduct = parseLine(line); cross.acceptProduct(lastProduct);
      }
      if ((index + 1) % plan.slot_ticks === 0) pendingSlots.push(cross.completeSlot());
      if ((index + 1) % 30 === 0 && index + 1 < plan.tick_count) {
        const ordinal = (index + 1) / 30;
        const checkpoint = makeCheckpoint({ ordinal, elapsedMs: ordinal * config.checkpoint_ms,
          faultOrdinal: (index + 1) / plan.slot_ticks, executed: cross.snapshot().executed,slots:pendingSlots, product: lastProduct,
          gateway: lastGateway, previousSha256: previous });
        const receipt = await emitCheckpoint(checkpoint);
        if (receipt !== checkpoint.record_sha256) fail('O01_CONTROLLER_CHECKPOINT_NOT_PERSISTED');
        previous = checkpoint.record_sha256;persistedCheckpoints++;pendingSlots=[];
      }
    }
    const terminal = productState.accept(await bounded(readProduct(),60000,'O01_CONTROLLER_PRODUCT_TERMINAL_TIMEOUT'));
    if (terminal.schema !== 'ese.v92.o01-product-terminal/v1') fail('O01_CONTROLLER_PRODUCT_TERMINAL');
    const finalGateway = validateObservation(await child.shutdown()); childClosed = true;
    const snapshot = cross.snapshot();
    if (snapshot.slot_ordinal !== 96 || snapshot.tick_count !== 2880 || snapshot.product_samples !== 480 ||
        canonical(snapshot.executed) !== canonical(plan.planned) ||
        finalGateway.gateway.mapping_count !== 1 || finalGateway.gateway.foreign_fixture_present !== true ||
        finalGateway.traffic.final_owned_mapping_count !== 0 || finalGateway.product.publisher_active !== false ||
        finalGateway.product.journal_entry_count !== 0) fail('O01_CONTROLLER_FINAL');
    assertLimits(config, lastProduct, finalGateway);
    if(persistedCheckpoints!==95)fail('O01_CONTROLLER_CHECKPOINT_COUNT');
    const terminalRecord = makeTerminalRecord({ product: terminal, gateway: finalGateway,slots:pendingSlots, previousSha256: previous });
    previous = terminalRecord.record_sha256;
    return Object.freeze({ schema: 'ese.v92.o01-controller-result/v1', verdict: 'PASS',
      source_commit: sourceCommit, source_tree: sourceTree, scenario_sha256: scenarioSha256,
      bound_files: boundFiles,
      elapsed_ms: terminal.elapsed_ms, tick_count: snapshot.tick_count, fault_slot_count: snapshot.slot_ordinal,
      product_sample_count: snapshot.product_samples, checkpoint_count: persistedCheckpoints,
      planned: plan.planned, executed: snapshot.executed, chain_tip_sha256: previous,
      terminal_record: terminalRecord });
  } finally {
    if (childStarted && !childClosed) await child.shutdown().catch(() => {});
  }
}

async function runFormalController(options) {
  if (Number(process.versions.node.split('.')[0]) !== 22 || options.clock || options.sleep || options.sourceCommit || options.sourceTree || options.scenarioSha256 || options.boundFiles) fail('O01_CONTROLLER_FORMAL_AUTHORITY');
  const clock = { now: () => Math.floor(performance.now()) };
  const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
  return runControllerCore({ ...options,...repositoryBinding(options.repoRoot,options.config), clock, sleep });
}

module.exports = Object.freeze({ validateScenario, createCrossValidator, makeCheckpoint, makeTerminalRecord, runFormalController,
  _runControllerTest: runControllerCore });
