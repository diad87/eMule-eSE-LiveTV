'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { NATPMP_VECTORS } = require('../natpmp_vectors');

function bytes(hex) {
  return Buffer.from(hex, 'hex');
}

function u16be(packet, offset) {
  return packet.readUInt16BE(offset);
}

function u32be(packet, offset) {
  return packet.readUInt32BE(offset);
}

test('C01: NAT-PMP goldens have exact length, hex, and immutable traceability', () => {
  const expected = Object.freeze({
    external_address_request: '0000',
    external_address_response: '008000000000002a580b1604',
    map_tcp_request: '00020000123601bb00001c20',
    map_udp_request: '00010000123601bb00001c20',
    map_tcp_response: '00820000000000631236cbb000000e10',
    map_tcp_delete_request: '000200001236000000000000',
  });

  assert.ok(Object.isFrozen(NATPMP_VECTORS));
  for (const [name, hex] of Object.entries(expected)) {
    const vector = NATPMP_VECTORS[name];
    assert.ok(Object.isFrozen(vector), name);
    assert.ok(Object.isFrozen(vector.provenance), name);
    assert.equal(vector.hex, hex, name);
    assert.equal(vector.length, bytes(hex).length, name);
    assert.match(vector.derivation, /^(EXISTING_TEST_VECTOR|PRODUCTIVE_CODEC|DERIVED_FROM_PRODUCTIVE_CONSTANT)$/);
    assert.ok(vector.provenance.length > 0, name);
    for (const source of vector.provenance) assert.match(source, /^libnatmap\/.+\.((h)|(cpp)):\d+-\d+$/);
  }
});

test('C01: NAT-PMP header and integer fields are network byte order', () => {
  const externalRequest = bytes(NATPMP_VECTORS.external_address_request.hex);
  assert.deepEqual([...externalRequest], [0x00, 0x00]);

  const externalResponse = bytes(NATPMP_VECTORS.external_address_response.hex);
  assert.equal(externalResponse[0], 0x00);
  assert.equal(externalResponse[1], 0x80);
  assert.equal(u16be(externalResponse, 2), 0);
  assert.equal(u32be(externalResponse, 4), 42);
  assert.deepEqual([...externalResponse.subarray(8, 12)], [88, 11, 22, 4]);

  const tcp = bytes(NATPMP_VECTORS.map_tcp_request.hex);
  assert.deepEqual([...tcp.subarray(0, 4)], [0, 2, 0, 0]);
  assert.equal(u16be(tcp, 4), 4662);
  assert.equal(u16be(tcp, 6), 443);
  assert.equal(u32be(tcp, 8), 7200);

  const udp = bytes(NATPMP_VECTORS.map_udp_request.hex);
  assert.deepEqual([...udp.subarray(0, 4)], [0, 1, 0, 0]);
  assert.equal(udp.toString('hex').slice(4), tcp.toString('hex').slice(4));
  assert.equal(NATPMP_VECTORS.map_udp_request.derivation, 'DERIVED_FROM_PRODUCTIVE_CONSTANT');

  const response = bytes(NATPMP_VECTORS.map_tcp_response.hex);
  assert.deepEqual([...response.subarray(0, 2)], [0, 130]);
  assert.equal(u16be(response, 2), 0);
  assert.equal(u32be(response, 4), 99);
  assert.equal(u16be(response, 8), 4662);
  assert.equal(u16be(response, 10), 52144);
  assert.equal(u32be(response, 12), 3600);

  const deletion = bytes(NATPMP_VECTORS.map_tcp_delete_request.hex);
  assert.deepEqual([...deletion.subarray(0, 4)], [0, 2, 0, 0]);
  assert.equal(u16be(deletion, 4), 4662);
  assert.equal(u16be(deletion, 6), 0);
  assert.equal(u32be(deletion, 8), 0);
});

test('C01: only the UDP opcode is a normative derivation; no UDP response golden exists', () => {
  assert.deepEqual(NATPMP_VECTORS.map_udp_request.provenance, [
    'libnatmap/tests/test_mapping_codecs.cpp:25-31',
    'libnatmap/include/natmap/natpmp_codec.h:8-11',
    'libnatmap/src/natpmp_codec.cpp:69-74',
  ]);
  assert.equal(Object.hasOwn(NATPMP_VECTORS, 'map_udp_response'), false);
});
