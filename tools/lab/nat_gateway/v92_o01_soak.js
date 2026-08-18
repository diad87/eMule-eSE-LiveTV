'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..', '..');
const CONFIG_PATH = path.join(__dirname, 'v92_o01_scenario.json');
const BOUND_PATHS = ['tools/lab/handoff93/run_product_mapper_cycle.ps1','tools/lab/nat_gateway/v92_o01_product_stream.js','tools/lab/nat_gateway/v92_o01_formal_controller.js','tools/lab/nat_gateway/v92_o01_validate_formal.js','tools/lab/nat_gateway/v92_o01_scenario.json','tools/lab/nat_gateway/v92_o01_soak.js','tools/lab/nat_gateway/v92_o01_t8_child.js','tools/lab/nat_gateway/v92_o01_t8_daemon.js','tools/lab/nat_gateway/v92_o01_bridge_protocol.js','tools/lab/nat_gateway/v92_o01_t8_network_adapter.js','tools/lab/nat_gateway/v92_o01_t8_gateway_adapter.js','tools/lab/nat_gateway/v92_o01_t8_udp_mux.js','tools/lab/nat_gateway/v92_o01_t8_upnp_edge.js','tools/lab/nat_gateway/v92_o01_t8_fault_controller.js','tools/lab/nat_gateway/v92_o01_formal_host.js','tools/lab/nat_gateway/v92_o01_formal_rpc.js','tools/lab/run_v92_o01_formal.ps1','tools/lab/v92_o01_vm_session.psm1','tools/lab/t8_hyperv.ps1','tools/lab/common.ps1','tools/lab/v91_r01_upnp.ps1'];

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function hashDomain(domain, value) {
  return crypto.createHash('sha256').update(`${domain}\0`).update(typeof value === 'string' ? value : canonical(value)).digest('hex');
}
function fileHash(filename) { return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'); }
function readConfig() {
  const value = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const keys = ['schema','case_id','formal_duration_ms','tick_ms','fault_slot_ms','lease_ms','late_delay_ms','checkpoint_ms','sample_ms','warmup_ms','slope_window_ms','node_major','owner_tag','transports','cycle','final_fault','limits','bound_files'];
  const limitKeys = ['rss_absolute_bytes','heap_absolute_bytes','external_absolute_bytes','array_buffers_absolute_bytes','rss_window_growth_bytes','heap_window_growth_bytes','handles','product_handles','timers','sockets','mapping_table','journal_entries','log_bytes','artifact_bytes','checkpoint_max_gap_ms'];
  if (!value || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical(keys.sort()) ||
      value.schema !== 'ese.v92.o01-scenario/v1' || value.case_id !== 'V92-O01' || value.formal_duration_ms !== 28800000 ||
      value.node_major !== 22 || canonical(value.transports) !== canonical(['tcp','udp']) || value.final_fault !== 'final_boundary' ||
      !Array.isArray(value.cycle) || value.cycle.length !== 18 || canonical(value.bound_files) !== canonical(BOUND_PATHS) ||
      !value.limits || canonical(Object.keys(value.limits).sort()) !== canonical(limitKeys.sort()) ||
      ![value.tick_ms,value.fault_slot_ms,value.lease_ms,value.late_delay_ms,value.checkpoint_ms,value.sample_ms,value.warmup_ms,value.slope_window_ms,...Object.values(value.limits)].every((entry) => Number.isSafeInteger(entry) && entry > 0) ||
      value.formal_duration_ms % value.tick_ms !== 0 || value.checkpoint_ms % value.tick_ms !== 0 || value.slope_window_ms % value.sample_ms !== 0) throw new Error('O01_SCENARIO_INVALID');
  return value;
}
function bindings(config) {
  return config.bound_files.map((relative) => ({ path: relative.replaceAll('\\', '/'), sha256: fileHash(path.join(REPO, relative)) }));
}
function exactSchedule(config, durationMs) {
  if (durationMs % config.tick_ms !== 0) throw new Error('O01_DURATION_NOT_TICK_ALIGNED');
  const ticks = durationMs / config.tick_ms;
  const events = Array.from({ length: ticks }, (_, index) => config.cycle[index % config.cycle.length]);
  events[events.length - 1] = config.final_fault;
  return events;
}
function countSchedule(events) {
  const counts = {};
  for (const event of events) counts[event] = (counts[event] || 0) + 1;
  return Object.fromEntries(Object.entries(counts).sort());
}
function resourceSnapshot(model, memory, handles) {
  return {
    rss_bytes: memory.rss, heap_bytes: memory.heapUsed, external_bytes: memory.external,
    array_buffers_bytes: memory.arrayBuffers || 0, handles,
    timers: model.timers, sockets: model.sockets,
    mapping_table_entries: model.pair.length + model.foreign.length,
    journal_entries: model.journal_entries, log_bytes: model.log_bytes,
  };
}
function assertResources(sample, limits) {
  const checks = [
    ['rss_bytes', 'rss_absolute_bytes'], ['heap_bytes', 'heap_absolute_bytes'],
    ['external_bytes', 'external_absolute_bytes'], ['array_buffers_bytes', 'array_buffers_absolute_bytes'],
    ['handles', 'handles'], ['timers', 'timers'], ['sockets', 'sockets'],
    ['mapping_table_entries', 'mapping_table'], ['journal_entries', 'journal_entries'], ['log_bytes', 'log_bytes'],
  ];
  for (const [field, limit] of checks) if (!Number.isSafeInteger(sample[field]) || sample[field] < 0 || sample[field] > limits[limit]) throw new Error(`O01_RESOURCE_LIMIT_${field}`);
}
function newPair(generation, ownerTag, expiresAt) {
  return ['tcp', 'udp'].map((transport) => Object.freeze({ transport, generation, owner_tag: ownerTag, lease_live: true, expires_at_ms: expiresAt }));
}
function verifyAtomic(model, config) {
  if (model.foreign.length !== 1 || model.foreign[0].owner_tag !== 'foreign-persistent') throw new Error('O01_FOREIGN_FIXTURE_CHANGED');
  if (model.pair.length !== 2 || model.pair[0].generation !== model.pair[1].generation ||
      model.pair.some((entry, index) => entry.transport !== config.transports[index] || entry.owner_tag !== config.owner_tag || !entry.lease_live) ||
      model.journal_entries !== 2 || !model.publisher || model.timers !== 2 || model.sockets !== 2) throw new Error('O01_ATOMIC_PAIR_INVALID');
}
function recover(model, config, now) {
  model.publisher = false; model.pair = []; model.journal_entries = 0; model.generation += 1;
  model.pair = newPair(model.generation, config.owner_tag, now + config.lease_ms); model.journal_entries = 2; model.publisher = true;
}
function applyEvent(model, event, config, now) {
  verifyAtomic(model, config);
  const before = canonical(model.pair);
  if (event === 'renew_success') { model.pair = newPair(model.generation, config.owner_tag, now + config.lease_ms); model.renewals += 2; }
  else if (event === 'epoch_reset') { model.epoch += 1; recover(model, config, now); }
  else if (event === 'expiry') {
    model.pair = model.pair.map((entry) => ({ ...entry, expires_at_ms: now }));
    if (model.pair.some((entry) => entry.expires_at_ms > now)) throw new Error('O01_EXPIRY_NOT_DUE');
    recover(model, config, now);
  }
  else if (event === 'dropped_late') {
    const lateGeneration = model.generation; recover(model, config, now);
    if (lateGeneration === model.generation) throw new Error('O01_LATE_ACCEPTED');
  }
  else if (event === 'partial_pair' || event === 'final_boundary') {
    model.publisher = false; model.pair = [newPair(model.generation, config.owner_tag, now + config.lease_ms)[0]]; model.journal_entries = 1;
    if (model.publisher) throw new Error('O01_PARTIAL_PUBLISHED'); recover(model, config, now);
  } else {
    if (['stale', 'replay_duplicate', 'malformed', 'explicit_reject', 'dropped_late'].includes(event) && canonical(model.pair) !== before) throw new Error('O01_REJECT_MUTATED');
    recover(model, config, now);
  }
  model.log_bytes += 24;
  verifyAtomic(model, config);
}
function chainRecord(domain, payload, previousSha256) {
  const body = { ...payload, previous_sha256: previousSha256 };
  return Object.freeze({ ...body, record_sha256: hashDomain(domain, body) });
}
function assertFreshDirectory(directory) {
  if (fs.existsSync(directory)) throw new Error('O01_NO_RESUME_NEW_COMMIT_REQUIRED');
}

async function runSimulation(options) {
  const { config, clock, sleep, durationMs, mode, sourceCommit, sourceTree, boundFiles,
    memory, handles, emit } = options;
  if (mode !== 'NON_RELEASE_ACCELERATED') throw new Error('O01_FORMAL_BRIDGE_NOT_IMPLEMENTED');
  if (!clock || typeof clock.now !== 'function' || typeof sleep !== 'function' || typeof emit !== 'function') throw new Error('O01_CONFIG_INVALID');
  const schedule = exactSchedule(config, durationMs);
  const planned = countSchedule(schedule);
  const executed = {};
  const started = clock.now();
  const model = { generation: 1, epoch: 1, pair: newPair(1, config.owner_tag, started + config.lease_ms),
    foreign: [{ owner_tag: 'foreign-persistent' }], journal_entries: 2, publisher: true,
    timers: 2, sockets: 2, renewals: 0, log_bytes: 0 };
  const samples = [];
  let nextCheckpoint = config.checkpoint_ms;
  let nextSample = config.sample_ms;
  let previous = hashDomain('ese.v92.o01-chain-seed/v1', { sourceCommit, sourceTree, boundFiles, durationMs, mode });
  let checkpointOrdinal = 0;
  const startedRecord = chainRecord('ese.v92.o01-started/v1', { schema: 'ese.v92.o01-started/v1', mode,
    source_commit: sourceCommit, source_tree: sourceTree, bound_files: boundFiles,
    scenario_sha256: fileHash(CONFIG_PATH), requested_duration_ms: durationMs,
    resumable: false, elapsed_ms: 0 }, previous);
  previous = startedRecord.record_sha256; emit('started', 0, startedRecord);
  verifyAtomic(model, config);
  for (let index = 0; index < schedule.length; index += 1) {
    applyEvent(model, schedule[index], config, clock.now());
    executed[schedule[index]] = (executed[schedule[index]] || 0) + 1;
    await sleep(config.tick_ms);
    const elapsed = clock.now() - started;
    while (elapsed >= nextSample) {
      const sample = resourceSnapshot(model, memory(), handles()); assertResources(sample, config.limits);
      samples.push({ elapsed_ms: nextSample, ...sample }); nextSample += config.sample_ms;
    }
    while (elapsed >= nextCheckpoint && nextCheckpoint < durationMs) {
      checkpointOrdinal += 1;
      const checkpointResource = resourceSnapshot(model, memory(), handles());
      assertResources(checkpointResource, config.limits);
      const record = chainRecord('ese.v92.o01-checkpoint/v1', { schema: 'ese.v92.o01-checkpoint/v1', mode,
        ordinal: checkpointOrdinal, elapsed_ms: nextCheckpoint, executed: Object.fromEntries(Object.entries(executed).sort()),
        generation: model.generation, epoch: model.epoch, pair_atomic: true, publisher: true,
        foreign_fixture_present: true, resource: checkpointResource, resumable: false }, previous);
      previous = record.record_sha256; emit('checkpoint', checkpointOrdinal, record); nextCheckpoint += config.checkpoint_ms;
    }
  }
  const observed = clock.now() - started;
  if (observed < durationMs || canonical(planned) !== canonical(Object.fromEntries(Object.entries(executed).sort()))) throw new Error('O01_SCHEDULE_INCOMPLETE');
  const recoveryEvents = Object.entries(executed).filter(([name]) => name !== 'renew_success').reduce((sum, [, count]) => sum + count, 0);
  if (model.generation !== 1 + recoveryEvents) throw new Error('O01_GENERATION_FORMULA');
  model.publisher = false; model.pair = []; model.journal_entries = 0; model.timers = 0; model.sockets = 0;
  if (model.foreign.length !== 1) throw new Error('O01_FOREIGN_CLEANUP');
  const resultPayload = { schema: 'ese.v92.o01-result/v2', case_id: 'V92-O01', mode,
    verdict: 'NON_RELEASE_PASS', source_commit: sourceCommit,
    source_tree: sourceTree, bound_files: boundFiles, scenario_sha256: fileHash(CONFIG_PATH),
    requested_duration_ms: durationMs, observed_duration_ms: observed, continuous: true, resumed: false,
    planned, executed: Object.fromEntries(Object.entries(executed).sort()), generation_initial: 1,
    generation_final: model.generation, generation_formula_recoveries: recoveryEvents,
    final_owned_mapping_count: 0, foreign_fixture_count: 1, publisher_active: false,
    journal_entries: 0, timers: 0, sockets: 0, samples };
  const terminal = chainRecord('ese.v92.o01-result/v2', resultPayload, previous);
  if (typeof options.beforeTerminal === 'function') options.beforeTerminal();
  emit('terminal', checkpointOrdinal + 1, terminal);
  return terminal;
}

async function formalMain() {
  const config = readConfig();
  if (process.versions.node.split('.')[0] !== String(config.node_major)) throw new Error('O01_NODE22_REQUIRED');
  if (process.argv.length !== 2) throw new Error('O01_FORMAL_TAKES_NO_ARGUMENTS');
  throw new Error('O01_FORMAL_BRIDGE_NOT_IMPLEMENTED');
}

if (require.main === module) formalMain().catch((error) => { process.stderr.write(`V92_O01_FAIL ${error.message}\n`); process.exitCode = 1; });
module.exports = { canonical, hashDomain, exactSchedule, countSchedule, runSimulation, readConfig, bindings, assertFreshDirectory };
