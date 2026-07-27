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
