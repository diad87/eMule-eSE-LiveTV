'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { NATPMP_VECTORS } = require('../natpmp_vectors');
const { NatPmpRequestError, decodeNatPmpRequest } = require('../natpmp_request_decoder');

function bytes(hex) { return Buffer.from(hex, 'hex'); }

function expectError(packet, code, path) {
  assert.throws(() => decodeNatPmpRequest(packet), (error) => {
    assert.ok(error instanceof NatPmpRequestError);
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, path);
    assert.equal(error.message, `${code} at ${path}`);
    return true;
  });
}

test('C02: decodes C01 external-address, TCP map and UDP map requests', () => {
  const external = decodeNatPmpRequest(bytes(NATPMP_VECTORS.external_address_request.hex));
  assert.deepEqual(external, { protocol: 'natpmp', operation: 'external-address' });
  assert.ok(Object.isFrozen(external));

  const tcp = decodeNatPmpRequest(bytes(NATPMP_VECTORS.map_tcp_request.hex));
  assert.deepEqual(tcp, { protocol: 'natpmp', operation: 'map', transport: 'tcp', internal_port: 4662, suggested_external_port: 443, lifetime_seconds: 7200 });
  assert.ok(Object.isFrozen(tcp));

  const udp = decodeNatPmpRequest(bytes(NATPMP_VECTORS.map_udp_request.hex));
  assert.deepEqual(udp, { protocol: 'natpmp', operation: 'map', transport: 'udp', internal_port: 4662, suggested_external_port: 443, lifetime_seconds: 7200 });
  assert.ok(Object.isFrozen(udp));
});

test('C02: exact request sizes reject truncation and trailing bytes', () => {
  for (const packet of [Buffer.alloc(0), Buffer.from([0]), Buffer.from([0, 0, 0])]) {
    expectError(packet, 'NATPMP_SIZE_INVALID', '$');
  }
  for (const opcode of [1, 2]) {
    const truncated = Buffer.from([0, opcode, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
    const trailing = Buffer.from([0, opcode, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0]);
    expectError(truncated, 'NATPMP_SIZE_INVALID', '$');
    expectError(trailing, 'NATPMP_SIZE_INVALID', '$');
  }
  expectError(Buffer.from([0, 0, 0]), 'NATPMP_SIZE_INVALID', '$');
});

test('C02: rejects bad version and all response or unknown opcodes', () => {
  expectError(Buffer.from([1, 0]), 'NATPMP_VERSION_INVALID', '$[0]');
  for (const opcode of [3, 127, 128, 129, 130, 255]) {
    expectError(Buffer.from([0, opcode]), 'NATPMP_OPCODE_INVALID', '$[1]');
  }
});

test('C02: map requests require zero reserved bytes and a nonzero internal port', () => {
  expectError(bytes('00020001123601bb00001c20'), 'NATPMP_RESERVED_INVALID', '$[2..3]');
  expectError(bytes('00020000123601bb00001c20').fill(0, 4, 6), 'NATPMP_INTERNAL_PORT_INVALID', '$[4..5]');
});

test('C02: lifetime zero is an explicit delete with external port zero', () => {
  const deletion = decodeNatPmpRequest(bytes(NATPMP_VECTORS.map_tcp_delete_request.hex));
  assert.deepEqual(deletion, { protocol: 'natpmp', operation: 'delete', transport: 'tcp', internal_port: 4662, suggested_external_port: 0, lifetime_seconds: 0 });
  expectError(bytes('000200001236000100000000'), 'NATPMP_DELETE_EXTERNAL_PORT_INVALID', '$[6..7]');
});

test('C02: reads unsigned network-byte-order limits correctly', () => {
  const command = decodeNatPmpRequest(bytes('000100000001ffffffffffff'));
  assert.deepEqual(command, { protocol: 'natpmp', operation: 'map', transport: 'udp', internal_port: 1, suggested_external_port: 65535, lifetime_seconds: 4294967295 });
});

test('C02: accepts Uint8Array, copies caller bytes, and never mutates input', () => {
  const input = new Uint8Array(bytes(NATPMP_VECTORS.map_tcp_request.hex));
  const before = Uint8Array.from(input);
  const command = decodeNatPmpRequest(input);
  input.fill(0);
  assert.deepEqual(before, Uint8Array.from(bytes(NATPMP_VECTORS.map_tcp_request.hex)));
  assert.equal(command.internal_port, 4662);
  assert.throws(() => { command.operation = 'changed'; }, TypeError);
});

test('C02: ignores all hostile own metadata and coercion getters on genuine byte views', () => {
  for (const input of [new Uint8Array(bytes('0000')), Buffer.from([0, 0])]) {
    let reads = 0;
    const hostile = { get() { reads += 1; throw new Error('secret'); } };
    for (const key of ['length', 'buffer', 'byteLength', 'byteOffset', Symbol.iterator, 'valueOf', 'toString']) {
      Object.defineProperty(input, key, hostile);
    }
    assert.deepEqual(decodeNatPmpRequest(input), { protocol: 'natpmp', operation: 'external-address' });
    assert.equal(reads, 0);
  }
});

test('C02: copies from backing stores without consulting constructor or species', () => {
  let ownConstructorReads = 0;
  const ownBacking = new ArrayBuffer(2);
  new Uint8Array(ownBacking).set([0, 0]);
  Object.defineProperty(ownBacking, 'constructor', { get() { ownConstructorReads += 1; throw new Error('secret'); } });
  const ownCommand = decodeNatPmpRequest(new Uint8Array(ownBacking));
  assert.deepEqual(ownCommand, { protocol: 'natpmp', operation: 'external-address' });
  assert.equal(ownConstructorReads, 0);

  let speciesReads = 0;
  class HostileArrayBuffer extends ArrayBuffer {}
  Object.defineProperty(HostileArrayBuffer, Symbol.species, { get() { speciesReads += 1; throw new Error('secret'); } });
  const subclassBacking = new HostileArrayBuffer(2);
  const subclassView = new Uint8Array(subclassBacking);
  subclassView.set([0, 0]);
  const subclassCommand = decodeNatPmpRequest(subclassView);
  subclassView.fill(255);
  assert.deepEqual(subclassCommand, { protocol: 'natpmp', operation: 'external-address' });
  assert.equal(speciesReads, 0);
});

test('C02: rejects hostile or non-byte input without exposing its contents', () => {
  expectError(null, 'NATPMP_INPUT_INVALID', '$');
  expectError('0000', 'NATPMP_INPUT_INVALID', '$');
  expectError(new Uint16Array([0, 0]), 'NATPMP_INPUT_INVALID', '$');
  expectError(Object.create(Uint8Array.prototype), 'NATPMP_INPUT_INVALID', '$');
  expectError(Object.create(Buffer.prototype), 'NATPMP_INPUT_INVALID', '$');
  const proxy = new Proxy(Buffer.from([0, 0]), { get() { throw new Error('secret'); } });
  expectError(proxy, 'NATPMP_INPUT_INVALID', '$');
});

test('C02: detached byte views fail as a stable input error', () => {
  const buffer = new ArrayBuffer(2);
  const detached = new Uint8Array(buffer);
  structuredClone(buffer, { transfer: [buffer] });
  expectError(detached, 'NATPMP_INPUT_INVALID', '$');
});

test('C02: shared byte views fail closed because they cannot be snapshotted safely', () => {
  const shared = new Uint8Array(new SharedArrayBuffer(2));
  expectError(shared, 'NATPMP_INPUT_INVALID', '$');
});
