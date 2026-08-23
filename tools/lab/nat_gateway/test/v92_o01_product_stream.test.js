'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseLine, createProductStreamState } = require('../v92_o01_product_stream');

function sample(overrides = {}) {
  return JSON.stringify({ schema: 'ese.v92.o01-product-sample/v1', sequence: 2,
    elapsed_ms: 60000, available: true, tcp_state: 'CANDIDATE', udp_state: 'CANDIDATE',
    same_generation: true, generation: 7, tcp_reason_code: 0, udp_reason_code: 0,
    working_set_bytes: 1000000, handle_count: 20, ...overrides });
}
function terminal(overrides = {}) {
  return JSON.stringify({ schema: 'ese.v92.o01-product-terminal/v1', sequence: 482,
    elapsed_ms: 28800000, graceful_exit: true, mappings_absent: true,
    ini_restored_byte_exact: true, preexisting_processes_unchanged: true, ...overrides });
}
const started = () => JSON.stringify({ schema: 'ese.v92.o01-product-started/v1', sequence: 1,
  elapsed_ms: 0, identity_accredited: true, preexisting_processes_unchanged: true });
function fillEightHours(state) {
  state.accept(started());
  for (let index = 1; index <= 480; index += 1) {
    state.accept(sample({ sequence: index + 1, elapsed_ms: index * 60000 }));
  }
}

test('product stream accepts only closed privacy-safe samples', () => {
  assert.equal(parseLine(sample()).generation, 7);
  assert.equal(parseLine(started()).elapsed_ms, 0);
  assert.equal(parseLine(sample({ available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE',
    same_generation: false, generation: 0, tcp_reason_code: 65535, udp_reason_code: 65535 })).available, false);
  for (const state of ['DISABLED', 'DISCOVERING', 'CANDIDATE', 'VERIFIED',
    'WITHDRAWN', 'BLOCKED', 'OTHER']) {
    assert.equal(parseLine(sample({ tcp_state: state, udp_state: state })).tcp_state, state);
  }
  for (const hostile of [
    sample({ path: 'C:\\secret' }), sample({ available: 'true' }),
    sample({ tcp_state: 'REACHABLE' }), sample({ tcp_state: 'UNKNOWN' }),
    sample({ tcp_state: 'OPEN' }), sample({ tcp_reason_code: 65536 }), sample({ available: false }),
    sample({ tcp_reason_code: 22 }), sample({ udp_reason_code: 22 }),
    sample({ available: true, tcp_state: 'UNAVAILABLE' }),
    sample({ available: true, udp_state: 'UNAVAILABLE' }),
    sample({ available: true, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE' }),
    sample({ available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE', generation: 0 }),
    sample({ available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE', same_generation: false }),
    sample({ available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE',
      same_generation: false, generation: 0, tcp_reason_code: 65535 }),
    sample({ available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE',
      same_generation: false, generation: 0, udp_reason_code: 65535 }),
    sample({ available: false, tcp_state: 'UNAVAILABLE', same_generation: false, generation: 0 }),
    `${sample()}\n`, '{',
  ]) assert.throws(() => parseLine(hostile), /O01_PRODUCT_/);
  assert.doesNotMatch(sample(), /(?:path|address|port|nonce|pid|credential)/i);
});

test('product stream rejects gaps, replay and early or dirty terminal', () => {
  const state = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  state.accept(started());
  state.accept(sample());
  assert.throws(() => state.accept(sample()), /O01_PRODUCT_ORDER/);
  const gap = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  gap.accept(started());
  gap.accept(sample());
  assert.throws(() => gap.accept(sample({ sequence: 3, elapsed_ms: 131000 })), /O01_PRODUCT_GAP/);
  for (const mutation of [
    { elapsed_ms: 28799999 }, { graceful_exit: false }, { mappings_absent: false },
    { ini_restored_byte_exact: false }, { preexisting_processes_unchanged: false },
  ]) {
    const candidate = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
    fillEightHours(candidate);
    assert.throws(() => candidate.accept(terminal(mutation)), /O01_PRODUCT_(?:ORDER|TERMINAL)/);
  }
});

test('product stream closes exactly once after eight hours', () => {
  const state = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  fillEightHours(state);
  state.accept(terminal());
  const snapshot = state.snapshot();
  assert.equal(snapshot.samples, 480); assert.equal(snapshot.available, 480);
  assert.equal(snapshot.terminal.schema, 'ese.v92.o01-product-terminal/v1');
  assert.throws(() => state.accept(terminal({ sequence: 483, elapsed_ms: 28800001 })), /O01_PRODUCT_AFTER_TERMINAL/);
});

test('product stream requires all 480 exact available sample ordinals', () => {
  const short = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  short.accept(started());
  for (let index = 1; index <= 479; index += 1) short.accept(sample({ sequence: index + 1, elapsed_ms: index * 60000 }));
  assert.throws(() => short.accept(terminal({ sequence: 481 })), /O01_PRODUCT_TERMINAL/);

  const unavailable = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  unavailable.accept(started());
  for (let index = 1; index <= 480; index += 1) unavailable.accept(sample({ sequence: index + 1, elapsed_ms: index * 60000,
    ...(index === 240 ? { available: false, tcp_state: 'UNAVAILABLE', udp_state: 'UNAVAILABLE', same_generation: false,
      generation: 0, tcp_reason_code: 65535, udp_reason_code: 65535 } : {}) }));
  assert.throws(() => unavailable.accept(terminal()), /O01_PRODUCT_TERMINAL/);

  const shifted = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  shifted.accept(started());
  assert.throws(() => shifted.accept(sample({ elapsed_ms: 59000 })), /O01_PRODUCT_CADENCE/);

  const sparse = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  sparse.accept(started());
  sparse.accept(sample({ elapsed_ms: 70000 }));
  assert.throws(() => sparse.accept(sample({ sequence: 3, elapsed_ms: 140000 })), /O01_PRODUCT_CADENCE/);

  const extra = createProductStreamState({ durationMs: 28800000, maxGapMs: 70000 });
  fillEightHours(extra);
  assert.throws(() => extra.accept(sample({ sequence: 482, elapsed_ms: 28860000 })), /O01_PRODUCT_CADENCE/);
});
