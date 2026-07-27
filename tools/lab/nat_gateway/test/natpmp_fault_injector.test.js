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
