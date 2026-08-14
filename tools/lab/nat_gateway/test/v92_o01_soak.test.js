'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { VirtualMonotonicClock } = require('../clock');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { canonical, hashDomain, exactSchedule, countSchedule, runSimulation, readConfig, assertFreshDirectory } = require('../v92_o01_soak');
const { validateDirectory, verifyRecord } = require('../v92_o01_validate');

function accelerated(overrides = {}) {
  const config = readConfig(); const virtual = new VirtualMonotonicClock(1000); const records = [];
  const options = { config, clock: { now: () => virtual.now_ms() }, sleep: async (ms) => virtual.advance_ms(ms),
    durationMs: config.formal_duration_ms, mode: 'NON_RELEASE_ACCELERATED', sourceCommit: '1'.repeat(40), sourceTree: '2'.repeat(40),
    boundFiles: config.bound_files.map((entry) => ({ path: entry, sha256: '3'.repeat(64) })),
    memory: () => ({ rss: 50_000_000, heapUsed: 20_000_000, external: 1_000_000, arrayBuffers: 500_000 }),
    handles: () => 3, emit: (kind, ordinal, record) => records.push({ kind, ordinal, record }), ...overrides };
  return { config, options, records };
}

async function nonReleaseFixture() {
  const base = accelerated(); await runSimulation(base.options);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v92-o01-validator-'));
  const sourceCommit = base.options.sourceCommit; const sourceTree = base.options.sourceTree;
  let previous = hashDomain('ese.v92.o01-chain-seed/v1', { sourceCommit, sourceTree,
    boundFiles: base.options.boundFiles, durationMs: base.config.formal_duration_ms, mode: 'NON_RELEASE_ACCELERATED' });
  for (const entry of base.records) {
    const record = structuredClone(entry.record);
    record.previous_sha256 = previous; delete record.record_sha256;
    const domain = entry.kind === 'started' ? 'ese.v92.o01-started/v1' : entry.kind === 'terminal' ? 'ese.v92.o01-result/v2' : 'ese.v92.o01-checkpoint/v1';
    record.record_sha256 = hashDomain(domain, record); previous = record.record_sha256;
    const name = entry.kind === 'checkpoint' ? `checkpoint-${String(entry.ordinal).padStart(3, '0')}.json` : `${entry.kind}.json`;
    fs.writeFileSync(path.join(directory, name), `${JSON.stringify(record, null, 2)}\n`);
  }
  const scenarioSha256 = crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '..', 'v92_o01_scenario.json'))).digest('hex');
  return { directory, expected: { config: base.config, sourceCommit, sourceTree, boundFiles: base.options.boundFiles, scenarioSha256 } };
}

test('V92-O01 accelerated campaign executes exact schedule but can never emit release PASS', async () => {
  const { config, options, records } = accelerated(); const result = await runSimulation(options);
  const planned = countSchedule(exactSchedule(config, config.formal_duration_ms));
  assert.equal(result.mode, 'NON_RELEASE_ACCELERATED'); assert.equal(result.verdict, 'NON_RELEASE_PASS');
  assert.deepEqual(result.executed, planned); assert.equal(result.observed_duration_ms, 28_800_000);
  const recoveries = Object.entries(planned).filter(([name]) => name !== 'renew_success').reduce((sum, [, value]) => sum + value, 0);
  assert.equal(result.generation_final, 1 + recoveries); assert.equal(result.final_owned_mapping_count, 0);
  assert.equal(result.foreign_fixture_count, 1); assert.equal(result.samples.length, 480);
  assert.equal(records[0].kind, 'started'); assert.equal(records.at(-1).kind, 'terminal');
  assert.equal(records.filter((entry) => entry.kind === 'checkpoint').length, 95);
  for (let index = 1; index < records.length; index += 1) assert.equal(records[index].record.previous_sha256, records[index - 1].record.record_sha256);
});

test('schedule includes every normative fault and an exact final boundary fault', () => {
  const config = readConfig(); const schedule = exactSchedule(config, config.formal_duration_ms);
  for (const name of ['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']) assert.ok(schedule.includes(name));
  assert.equal(schedule.at(-1), 'final_boundary'); assert.equal(schedule.length, 2880);
});

test('exported accelerated seam cannot claim formal authority', async () => {
  const { options } = accelerated({ mode: 'FORMAL_RELEASE' });
  await assert.rejects(runSimulation(options), /O01_FORMAL_BRIDGE_NOT_IMPLEMENTED/);
});

test('final binding failure occurs before terminal evidence is emitted', async () => {
  const { options, records } = accelerated({ beforeTerminal() { throw new Error('O01_FINAL_BINDING_CHANGED'); } });
  await assert.rejects(runSimulation(options), /O01_FINAL_BINDING_CHANGED/);
  assert.equal(records.some((entry) => entry.kind === 'terminal'), false);
});

test('memory and malformed configuration fail closed before a verdict', async () => {
  const { options } = accelerated({ memory: () => ({ rss: 600_000_000, heapUsed: 1, external: 1, arrayBuffers: 1 }) });
  await assert.rejects(runSimulation(options), /O01_RESOURCE_LIMIT_rss_bytes/);
  const bad = accelerated(); bad.options.config = { ...bad.config, tick_ms: 7000 };
  await assert.rejects(runSimulation(bad.options), /O01_DURATION_NOT_TICK_ALIGNED/);
});

test('hash chain rejects corruption, replay and predecessor substitution', async () => {
  const { options, records } = accelerated(); await runSimulation(options);
  const checkpoint = records.find((entry) => entry.kind === 'checkpoint').record;
  assert.throws(() => verifyRecord('ese.v92.o01-checkpoint/v1', { ...checkpoint, elapsed_ms: checkpoint.elapsed_ms + 1 }, checkpoint.previous_sha256), /O01_RECORD_HASH/);
  assert.throws(() => verifyRecord('ese.v92.o01-checkpoint/v1', checkpoint, '0'.repeat(64)), /O01_CHAIN_LINK/);
  const later = records.filter((entry) => entry.kind === 'checkpoint')[1].record;
  assert.throws(() => verifyRecord('ese.v92.o01-checkpoint/v1', checkpoint, later.previous_sha256), /O01_CHAIN_LINK/);
});

test('independent validator accepts only a complete non-release fixture', async (t) => {
  const fixture = await nonReleaseFixture(); t.after(() => fs.rmSync(fixture.directory, { recursive: true, force: true }));
  const result = validateDirectory(fixture.directory, fixture.expected);
  assert.equal(result.verdict, 'NON_RELEASE_VALID'); assert.equal(result.artifacts, 97);
});

test('validator rejects missing artifacts and semantically forged terminal counts', async (t) => {
  const missing = await nonReleaseFixture(); t.after(() => fs.rmSync(missing.directory, { recursive: true, force: true }));
  fs.rmSync(path.join(missing.directory, 'checkpoint-050.json'));
  assert.throws(() => validateDirectory(missing.directory, missing.expected), /O01_ARTIFACT_SET/);
  const forged = await nonReleaseFixture(); t.after(() => fs.rmSync(forged.directory, { recursive: true, force: true }));
  const terminalPath = path.join(forged.directory, 'terminal.json'); const terminal = JSON.parse(fs.readFileSync(terminalPath));
  terminal.executed.renew_success -= 1; delete terminal.record_sha256;
  terminal.record_sha256 = hashDomain('ese.v92.o01-result/v2', terminal); fs.writeFileSync(terminalPath, JSON.stringify(terminal));
  assert.throws(() => validateDirectory(forged.directory, forged.expected), /O01_TERMINAL_CONTRACT/);
});

test('validator rejects privacy leakage even when attacker recomputes terminal hash', async (t) => {
  const fixture = await nonReleaseFixture(); t.after(() => fs.rmSync(fixture.directory, { recursive: true, force: true }));
  const terminalPath = path.join(fixture.directory, 'terminal.json'); const terminal = JSON.parse(fs.readFileSync(terminalPath));
  terminal.diagnostic = 'internal_address'; delete terminal.record_sha256;
  terminal.record_sha256 = hashDomain('ese.v92.o01-result/v2', terminal); fs.writeFileSync(terminalPath, JSON.stringify(terminal));
  assert.throws(() => validateDirectory(fixture.directory, fixture.expected), /O01_(TERMINAL_SHAPE|PRIVACY)/);
});

test('formal CLI on a non-Node22 runtime fails before artifacts or arguments matter', () => {
  if (process.versions.node.split('.')[0] === '22') return;
  const result = spawnSync(process.execPath, [require.resolve('../v92_o01_soak')], { encoding: 'utf8' });
  assert.equal(result.status, 1); assert.match(result.stderr, /^V92_O01_FAIL O01_NODE22_REQUIRED\n$/);
});

test('formal runner and validator cannot emit release evidence before the product bridge exists', () => {
  if (process.versions.node.split('.')[0] !== '22') return;
  const runner = spawnSync(process.execPath, [require.resolve('../v92_o01_soak')], { encoding: 'utf8' });
  assert.equal(runner.status, 1);
  assert.match(runner.stderr, /^V92_O01_FAIL O01_FORMAL_BRIDGE_NOT_IMPLEMENTED\n$/);
  const validator = spawnSync(process.execPath, [require.resolve('../v92_o01_validate')], { encoding: 'utf8' });
  assert.equal(validator.status, 1);
  assert.match(validator.stderr, /^V92_O01_VALIDATE_FAIL O01_FORMAL_BRIDGE_NOT_IMPLEMENTED\n$/);
});

test('crash marker or prior directory makes resume impossible', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'v92-o01-no-resume-'));
  assert.throws(() => assertFreshDirectory(root), /O01_NO_RESUME_NEW_COMMIT_REQUIRED/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scenario is a closed, deterministic contract', () => {
  const config = readConfig();
  assert.deepEqual(Object.keys(config).sort(), ['bound_files','case_id','checkpoint_ms','cycle','final_fault','formal_duration_ms','lease_ms','limits','node_major','owner_tag','sample_ms','schema','slope_window_ms','tick_ms','transports','warmup_ms'].sort());
  assert.equal(new Set(config.bound_files.map((entry) => entry.toLowerCase())).size, 4);
  assert.equal(canonical(config.transports), canonical(['tcp','udp']));
});
