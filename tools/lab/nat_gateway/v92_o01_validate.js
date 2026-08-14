'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const REPO = path.resolve(__dirname, '..', '..', '..');
const CONFIG_PATH = path.join(__dirname, 'v92_o01_scenario.json');
const BOUND_PATHS = ['tools/lab/nat_gateway/v92_o01_soak.js','tools/lab/nat_gateway/v92_o01_validate.js','tools/lab/nat_gateway/v92_o01_scenario.json','tools/lab/nat_gateway/test/v92_o01_soak.test.js'];
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function hashDomain(domain, value) { return crypto.createHash('sha256').update(`${domain}\0`).update(typeof value === 'string' ? value : canonical(value)).digest('hex'); }
function fileHash(filename) { return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'); }
function readConfig() {
  const value = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const keys = ['schema','case_id','formal_duration_ms','tick_ms','lease_ms','checkpoint_ms','sample_ms','warmup_ms','slope_window_ms','node_major','owner_tag','transports','cycle','final_fault','limits','bound_files'];
  const limitKeys = ['rss_absolute_bytes','heap_absolute_bytes','external_absolute_bytes','array_buffers_absolute_bytes','rss_window_growth_bytes','heap_window_growth_bytes','handles','timers','sockets','mapping_table','journal_entries','log_bytes','artifact_bytes','checkpoint_max_gap_ms'];
  if (!value || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical(keys.sort()) ||
      value.schema !== 'ese.v92.o01-scenario/v1' || value.case_id !== 'V92-O01' || value.formal_duration_ms !== 28800000 ||
      value.node_major !== 22 || canonical(value.transports) !== canonical(['tcp','udp']) || value.final_fault !== 'final_boundary' ||
      !Array.isArray(value.cycle) || value.cycle.length !== 18 || canonical(value.bound_files) !== canonical(BOUND_PATHS) ||
      !value.limits || canonical(Object.keys(value.limits).sort()) !== canonical(limitKeys.sort()) ||
      ![value.tick_ms,value.lease_ms,value.checkpoint_ms,value.sample_ms,value.warmup_ms,value.slope_window_ms,...Object.values(value.limits)].every((entry) => Number.isSafeInteger(entry) && entry > 0) ||
      value.formal_duration_ms % value.tick_ms !== 0 || value.checkpoint_ms % value.tick_ms !== 0 || value.slope_window_ms % value.sample_ms !== 0) throw new Error('O01_SCENARIO_INVALID');
  return value;
}
function bindings(config) { return config.bound_files.map((relative) => ({ path: relative.replaceAll('\\', '/'), sha256: fileHash(path.join(REPO, relative)) })); }
function exactSchedule(config, durationMs) {
  if (durationMs % config.tick_ms !== 0) throw new Error('O01_DURATION_NOT_TICK_ALIGNED');
  const events = Array.from({ length: durationMs / config.tick_ms }, (_, index) => config.cycle[index % config.cycle.length]);
  events[events.length - 1] = config.final_fault; return events;
}
function countSchedule(events) { const counts = {}; for (const event of events) counts[event] = (counts[event] || 0) + 1; return Object.fromEntries(Object.entries(counts).sort()); }
function readJson(filename) { return JSON.parse(fs.readFileSync(filename, 'utf8')); }
function verifyRecord(domain, record, previous) {
  if (record.previous_sha256 !== previous || !/^[a-f0-9]{64}$/.test(record.record_sha256)) throw new Error('O01_CHAIN_LINK');
  const body = { ...record }; delete body.record_sha256;
  if (hashDomain(domain, body) !== record.record_sha256) throw new Error('O01_RECORD_HASH');
  return record.record_sha256;
}
function assertClosedKeys(value, keys, label) {
  if (!value || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) throw new Error(`O01_${label}_SHAPE`);
}
function validateDirectory(directory, expected) {
  const config = expected.config;
  const names = fs.readdirSync(directory).sort();
  const checkpointNames = names.filter((name) => /^checkpoint-\d{3}\.json$/.test(name));
  const expectedCheckpoints = Math.ceil(config.formal_duration_ms / config.checkpoint_ms) - 1;
  if (names.length !== expectedCheckpoints + 2 || checkpointNames.length !== expectedCheckpoints || names[0] !== 'checkpoint-001.json' ||
      checkpointNames.at(-1) !== `checkpoint-${String(expectedCheckpoints).padStart(3, '0')}.json` ||
      !names.includes('started.json') || !names.includes('terminal.json')) throw new Error('O01_ARTIFACT_SET');
  const totalBytes = names.reduce((sum, name) => sum + fs.statSync(path.join(directory, name)).size, 0);
  if (totalBytes > config.limits.artifact_bytes) throw new Error('O01_ARTIFACT_SIZE');
  const started = readJson(path.join(directory, 'started.json'));
  assertClosedKeys(started, ['schema','mode','source_commit','source_tree','bound_files','scenario_sha256','requested_duration_ms','resumable','elapsed_ms','previous_sha256','record_sha256'], 'STARTED');
  const seed = hashDomain('ese.v92.o01-chain-seed/v1', { sourceCommit: expected.sourceCommit,
    sourceTree: expected.sourceTree, boundFiles: expected.boundFiles, durationMs: config.formal_duration_ms, mode: 'NON_RELEASE_ACCELERATED' });
  let previous = verifyRecord('ese.v92.o01-started/v1', started, seed);
  if (started.schema !== 'ese.v92.o01-started/v1' || started.mode !== 'NON_RELEASE_ACCELERATED' || started.resumable !== false ||
      started.source_commit !== expected.sourceCommit || started.source_tree !== expected.sourceTree ||
      canonical(started.bound_files) !== canonical(expected.boundFiles) || started.scenario_sha256 !== expected.scenarioSha256) throw new Error('O01_STARTED_BINDING');
  let lastElapsed = 0;
  for (let index = 0; index < checkpointNames.length; index += 1) {
    const record = readJson(path.join(directory, checkpointNames[index]));
    assertClosedKeys(record, ['schema','mode','ordinal','elapsed_ms','executed','generation','epoch','pair_atomic','publisher','foreign_fixture_present','resource','resumable','previous_sha256','record_sha256'], 'CHECKPOINT');
    assertClosedKeys(record.resource, ['rss_bytes','heap_bytes','external_bytes','array_buffers_bytes','handles','timers','sockets','mapping_table_entries','journal_entries','log_bytes'], 'CHECKPOINT_RESOURCE');
    previous = verifyRecord('ese.v92.o01-checkpoint/v1', record, previous);
    const ordinal = index + 1;
    const prefix = exactSchedule(config, config.formal_duration_ms).slice(0, record.elapsed_ms / config.tick_ms);
    const expectedExecuted = countSchedule(prefix);
    const expectedRecoveries = Object.entries(expectedExecuted).filter(([name]) => name !== 'renew_success').reduce((sum, [, count]) => sum + count, 0);
    if (record.ordinal !== ordinal || record.elapsed_ms !== ordinal * config.checkpoint_ms ||
        record.elapsed_ms - lastElapsed > config.limits.checkpoint_max_gap_ms || record.resumable !== false ||
        record.pair_atomic !== true || record.publisher !== true || record.foreign_fixture_present !== true ||
        canonical(record.executed) !== canonical(expectedExecuted) || record.generation !== 1 + expectedRecoveries ||
        record.epoch !== 1 + (expectedExecuted.epoch_reset || 0)) throw new Error('O01_CHECKPOINT_CONTRACT');
    lastElapsed = record.elapsed_ms;
  }
  const terminal = readJson(path.join(directory, 'terminal.json'));
  assertClosedKeys(terminal, ['schema','case_id','mode','verdict','source_commit','source_tree','bound_files','scenario_sha256','requested_duration_ms','observed_duration_ms','continuous','resumed','planned','executed','generation_initial','generation_final','generation_formula_recoveries','final_owned_mapping_count','foreign_fixture_count','publisher_active','journal_entries','timers','sockets','samples','previous_sha256','record_sha256'], 'TERMINAL');
  verifyRecord('ese.v92.o01-result/v2', terminal, previous);
  const schedule = exactSchedule(config, config.formal_duration_ms); const planned = countSchedule(schedule);
  const recoveries = Object.entries(planned).filter(([name]) => name !== 'renew_success').reduce((sum, [, count]) => sum + count, 0);
  if (terminal.schema !== 'ese.v92.o01-result/v2' || terminal.case_id !== 'V92-O01' || terminal.mode !== 'NON_RELEASE_ACCELERATED' || terminal.verdict !== 'NON_RELEASE_PASS' ||
      terminal.source_commit !== expected.sourceCommit || terminal.source_tree !== expected.sourceTree || canonical(terminal.bound_files) !== canonical(expected.boundFiles) ||
      terminal.scenario_sha256 !== expected.scenarioSha256 || terminal.requested_duration_ms !== config.formal_duration_ms || terminal.observed_duration_ms < config.formal_duration_ms ||
      terminal.continuous !== true || terminal.resumed !== false || canonical(terminal.planned) !== canonical(planned) || canonical(terminal.executed) !== canonical(planned) ||
      terminal.generation_initial !== 1 || terminal.generation_formula_recoveries !== recoveries || terminal.generation_final !== 1 + recoveries ||
      terminal.final_owned_mapping_count !== 0 || terminal.foreign_fixture_count !== 1 || terminal.publisher_active !== false || terminal.journal_entries !== 0 || terminal.timers !== 0 || terminal.sockets !== 0) throw new Error('O01_TERMINAL_CONTRACT');
  if (!Array.isArray(terminal.samples) || terminal.samples.length !== config.formal_duration_ms / config.sample_ms) throw new Error('O01_SAMPLE_COUNT');
  let prior = 0;
  for (let sampleIndex = 0; sampleIndex < terminal.samples.length; sampleIndex += 1) {
    const sample = terminal.samples[sampleIndex];
    assertClosedKeys(sample, ['elapsed_ms','rss_bytes','heap_bytes','external_bytes','array_buffers_bytes','handles','timers','sockets','mapping_table_entries','journal_entries','log_bytes'], 'SAMPLE');
    if (sample.elapsed_ms !== prior + config.sample_ms) throw new Error('O01_SAMPLE_CADENCE'); prior = sample.elapsed_ms;
    const limits = config.limits;
    if (sample.rss_bytes > limits.rss_absolute_bytes || sample.heap_bytes > limits.heap_absolute_bytes || sample.external_bytes > limits.external_absolute_bytes ||
        sample.array_buffers_bytes > limits.array_buffers_absolute_bytes || sample.handles > limits.handles || sample.timers > limits.timers || sample.sockets > limits.sockets ||
        sample.mapping_table_entries > limits.mapping_table || sample.journal_entries > limits.journal_entries || sample.log_bytes > limits.log_bytes) throw new Error('O01_SAMPLE_LIMIT');
    if (sample.elapsed_ms >= config.warmup_ms + config.slope_window_ms) {
      const windowSamples = config.slope_window_ms / config.sample_ms;
      const base = terminal.samples[sampleIndex - windowSamples];
      if (!base || sample.rss_bytes - base.rss_bytes > limits.rss_window_growth_bytes || sample.heap_bytes - base.heap_bytes > limits.heap_window_growth_bytes) throw new Error('O01_SAMPLE_SLOPE');
    }
  }
  const forbidden = /(?:ownership_nonce|internal_address|external_address|gateway_address|description|command_line|user_profile|\\Users\\|\/home\/)/i;
  for (const name of names) if (forbidden.test(fs.readFileSync(path.join(directory, name), 'utf8'))) throw new Error('O01_PRIVACY');
  return { verdict: 'NON_RELEASE_VALID', artifacts: names.length, terminal_sha256: terminal.record_sha256 };
}

function main() {
  if (process.argv.length !== 2) throw new Error('O01_VALIDATOR_TAKES_NO_ARGUMENTS');
  throw new Error('O01_FORMAL_BRIDGE_NOT_IMPLEMENTED');
}
if (require.main === module) { try { main(); } catch (error) { process.stderr.write(`V92_O01_VALIDATE_FAIL ${error.message}\n`); process.exitCode = 1; } }
module.exports = { validateDirectory, verifyRecord };
