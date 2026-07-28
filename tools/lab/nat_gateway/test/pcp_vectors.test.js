'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { PCP_VECTORS } = require('../pcp_vectors');

function bytes(name) { return Buffer.from(PCP_VECTORS[name].hex, 'hex'); }

test('D01: PCP goldens have exact literal bytes and immutable traceability', () => {
  const expected = Object.freeze({
    map_tcp_request: '0201000000001c2000000000000000000000ffffc0a801140102030405060708090a0b0c06000000123601bb00000000000000000000000000000000',
    map_tcp_renewal_request: '0201000000001c2000000000000000000000ffffc0a801140102030405060708090a0b0c06000000123601bb00000000000000000000ffff580b1604',
    map_native_v6_request: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db8000100020000000000000040',
    map_prefer_failure_request: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db800010002000000000000004002000000',
    map_port_set_request: '0201000000001c2020010db80001000200000000000000200102030405060708090a0b0c06000000123601bb20010db8000100020000000000000040820000050020123601000000',
    map_tcp_delete_request: '020100000000000020010db80001000200000000000000200102030405060708090a0b0c060000001236000000000000000000000000000000000000',
    map_tcp_response: '0281000000000e10000004d20000000000000000000000000102030405060708090a0b0c060000001236cbb000000000000000000000ffff580b1604820000050020123601000000',
    announce_request: '020000000000000000000000000000000000ffffc0a80114',
    announce_response: '028000020000000000002694000000000000000000000000',
  });
  assert.ok(Object.isFrozen(PCP_VECTORS));
  for (const [name, hex] of Object.entries(expected)) {
    const vector = PCP_VECTORS[name];
    assert.ok(Object.isFrozen(vector), name);
    assert.ok(Object.isFrozen(vector.provenance), name);
    assert.equal(vector.hex, hex, name);
    assert.equal(vector.length, Buffer.from(hex, 'hex').length, name);
    assert.equal(vector.derivation, 'EXISTING_TEST_VECTOR', name);
    assert.ok(vector.provenance.length > 0, name);
    for (const source of vector.provenance) {
      assert.match(source, /^(libnatmap\/(src|tests)\/.+\.cpp):\d+-\d+$/);
      const [, from, to] = source.match(/:(\d+)-(\d+)$/);
      assert.ok(Number(from) <= Number(to), source);
    }
  }
});

test('D01: MAP header, lifetime, address, nonce, protocol and ports use exact offsets', () => {
  const packet = bytes('map_tcp_request');
  assert.equal(packet[0], 2);
  assert.equal(packet[1], 1);
  assert.deepEqual([...packet.subarray(2, 4)], [0, 0]);
  assert.equal(packet.readUInt32BE(4), 7200);
  assert.equal(packet.subarray(8, 24).toString('hex'), '00000000000000000000ffffc0a80114');
  assert.equal(packet.subarray(24, 36).toString('hex'), '0102030405060708090a0b0c');
  assert.equal(packet[36], 6);
  assert.deepEqual([...packet.subarray(37, 40)], [0, 0, 0]);
  assert.equal(packet.readUInt16BE(40), 4662);
  assert.equal(packet.readUInt16BE(42), 443);
  assert.equal(packet.subarray(44, 60).equals(Buffer.alloc(16)), true);
});

test('D01: renewal, delete, IPv6 and options differ only at their documented fields', () => {
  const base = bytes('map_tcp_request');
  const renewal = bytes('map_tcp_renewal_request');
  assert.deepEqual(renewal.subarray(0, 44), base.subarray(0, 44));
  assert.equal(renewal.subarray(44).toString('hex'), '00000000000000000000ffff580b1604');

  const deletion = bytes('map_tcp_delete_request');
  assert.equal(deletion.readUInt32BE(4), 0);
  assert.equal(deletion.subarray(8, 24).toString('hex'), '20010db8000100020000000000000020');
  assert.equal(deletion.readUInt16BE(42), 0);
  assert.equal(deletion.subarray(44).equals(Buffer.alloc(16)), true);
  assert.deepEqual(deletion.subarray(24, 42), base.subarray(24, 42));

  const native = bytes('map_native_v6_request');
  assert.equal(native.subarray(8, 24).toString('hex'), '20010db8000100020000000000000020');
  assert.equal(native.subarray(44, 60).toString('hex'), '20010db8000100020000000000000040');
  assert.equal(bytes('map_prefer_failure_request').subarray(60).toString('hex'), '02000000');
  assert.equal(bytes('map_port_set_request').subarray(60).toString('hex'), '820000050020123601000000');
});

test('D01: response and ANNOUNCE vectors expose result, lifetime and epoch unambiguously', () => {
  const response = bytes('map_tcp_response');
  assert.deepEqual([...response.subarray(0, 4)], [2, 0x81, 0, 0]);
  assert.equal(response.readUInt32BE(4), 3600);
  assert.equal(response.readUInt32BE(8), 1234);
  assert.equal(response.subarray(12, 24).equals(Buffer.alloc(12)), true);
  assert.equal(response.subarray(24, 36).toString('hex'), '0102030405060708090a0b0c');
  assert.equal(response[36], 6);
  assert.equal(response.readUInt16BE(40), 4662);
  assert.equal(response.readUInt16BE(42), 52144);
  assert.equal(response.subarray(44, 60).toString('hex'), '00000000000000000000ffff580b1604');

  const announce = bytes('announce_request');
  assert.deepEqual([...announce.subarray(0, 8)], [2, 0, 0, 0, 0, 0, 0, 0]);
  const announceResponse = bytes('announce_response');
  assert.deepEqual([...announceResponse.subarray(0, 4)], [2, 0x80, 0, 2]);
  assert.equal(announceResponse.readUInt32BE(8), 9876);
});

test('D01: no complete UDP MAP golden is invented', () => {
  assert.equal(Object.hasOwn(PCP_VECTORS, 'map_udp_request'), false);
  assert.equal(Object.hasOwn(PCP_VECTORS, 'map_udp_response'), false);
});
