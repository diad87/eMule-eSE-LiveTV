'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createNatPmpFaultInjector, NatPmpFaultError } = require('../natpmp_fault_injector');
const { decodeNatPmpRequest } = require('../natpmp_request_decoder');
const { NATPMP_VECTORS } = require('../natpmp_vectors');

const command = decodeNatPmpRequest(Buffer.from(NATPMP_VECTORS.map_tcp_request.hex, 'hex'));

test('C05 drop: deterministically suppresses the response without mutating input', async () => {
  const packet = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  const before = Buffer.from(packet);
  const inject = createNatPmpFaultInjector({ type: 'drop' });
  assert.equal(await inject(packet, command, new AbortController().signal), null);
  assert.deepEqual(packet, before);
});

test('C05 drop: rejects hostile action, packet, command and signal shapes', async () => {
  for (const action of [{}, { type: 'unknown' }, { type: 'drop', extra: true }, new Proxy({ type: 'drop' }, {})]) {
    assert.throws(() => createNatPmpFaultInjector(action), NatPmpFaultError);
  }
  const inject = createNatPmpFaultInjector({ type: 'drop' });
  await assert.rejects(inject(Buffer.alloc(11), command, new AbortController().signal), NatPmpFaultError);
  await assert.rejects(inject(new Proxy(Buffer.alloc(16), {}), command, new AbortController().signal), NatPmpFaultError);
  await assert.rejects(inject(Buffer.alloc(16), { ...command }, new AbortController().signal), NatPmpFaultError);
  await assert.rejects(inject(Buffer.alloc(16), command, {}), NatPmpFaultError);
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(inject(Buffer.alloc(16), command, aborted.signal), (error) => error.reason_code === 'NATPMP_FAULT_ABORTED');
});

test('C05 delay: waits through the injected cancellable scheduler and returns an owned copy', async () => {
  const calls = []; const packet = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  const inject = createNatPmpFaultInjector(
    { type: 'delay', delay_ms: 75, jitter_ms: 0 },
    { sleep: async (milliseconds, signal) => calls.push([milliseconds, signal.aborted]) },
  );
  const result = await inject(packet, command, new AbortController().signal);
  assert.deepEqual(calls, [[75, false]]);
  assert.deepEqual(result, packet); assert.notEqual(result, packet);
  packet.fill(0); assert.equal(result.toString('hex'), NATPMP_VECTORS.map_tcp_response.hex);
});

test('C05 delay: rejects nondeterministic jitter and maps scheduler cancellation', async () => {
  assert.throws(() => createNatPmpFaultInjector({ type: 'delay', delay_ms: 1, jitter_ms: 1 }), NatPmpFaultError);
  const controller = new AbortController();
  const inject = createNatPmpFaultInjector(
    { type: 'delay', delay_ms: 1, jitter_ms: 0 },
    { sleep: async () => { controller.abort(); throw new Error('cancelled'); } },
  );
  await assert.rejects(
    inject(Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex'), command, controller.signal),
    (error) => error.reason_code === 'NATPMP_FAULT_ABORTED',
  );
});

test('C05 reject: emits each closed NAT-PMP rejection with deterministic zero fields', async () => {
  const names = ['unsupported-version', 'not-authorized', 'network-failure', 'out-of-resources', 'unsupported-opcode'];
  for (let index = 0; index < names.length; index += 1) {
    const inject = createNatPmpFaultInjector({ type: 'reject', result_code: names[index] });
    const result = await inject(Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex'), command, new AbortController().signal);
    assert.equal(result.readUInt16BE(2), index + 1);
    assert.equal(result.subarray(10).equals(Buffer.alloc(6)), true);
  }
  assert.throws(() => createNatPmpFaultInjector({ type: 'reject', result_code: 'bogus' }), NatPmpFaultError);
});

test('C05 wrong port: changes only a successful MAP external port', async () => {
  const original = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  const inject = createNatPmpFaultInjector({ type: 'change-port', external_port: 65000 });
  const result = await inject(original, command, new AbortController().signal);
  assert.equal(result.readUInt16BE(10), 65000);
  assert.deepEqual(result.subarray(0, 10), original.subarray(0, 10));
  assert.deepEqual(result.subarray(12), original.subarray(12));
  assert.throws(() => createNatPmpFaultInjector({ type: 'change-port', external_port: 0 }), NatPmpFaultError);
});

test('C05 short lease: caps only the lease of a successful non-delete MAP', async () => {
  const packet = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  const inject = createNatPmpFaultInjector({ type: 'cap-lease', lifetime_seconds: 30 });
  const result = await inject(packet, command, new AbortController().signal);
  assert.equal(result.readUInt32BE(12), 30);
  assert.deepEqual(result.subarray(0, 12), packet.subarray(0, 12));
  assert.throws(() => createNatPmpFaultInjector({ type: 'cap-lease', lifetime_seconds: 0 }), NatPmpFaultError);
});

test('C05 epoch reset: replaces only the response epoch, including zero', async () => {
  const packet = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  const inject = createNatPmpFaultInjector({ type: 'restart-gateway', restart_epoch_seconds: 0 });
  const result = await inject(packet, command, new AbortController().signal);
  assert.equal(result.readUInt32BE(4), 0);
  assert.deepEqual(result.subarray(0, 4), packet.subarray(0, 4));
  assert.deepEqual(result.subarray(8), packet.subarray(8));
  assert.throws(() => createNatPmpFaultInjector({ type: 'restart-gateway', restart_epoch_seconds: -1 }), NatPmpFaultError);
});

test('C05 malformed: truncates to the exact configured wire length, including zero', async () => {
  const packet = Buffer.from(NATPMP_VECTORS.map_tcp_response.hex, 'hex');
  for (const length of [0, 1, 7, 15]) {
    const inject = createNatPmpFaultInjector({ type: 'truncate', length_bytes: length });
    const result = await inject(packet, command, new AbortController().signal);
    assert.equal(result.length, length);
    assert.deepEqual(result, packet.subarray(0, length));
  }
  assert.throws(() => createNatPmpFaultInjector({ type: 'truncate', length_bytes: 16 }), NatPmpFaultError);
});
