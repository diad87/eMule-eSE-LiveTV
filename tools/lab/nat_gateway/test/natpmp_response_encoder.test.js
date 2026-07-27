'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { NATPMP_VECTORS } = require('../natpmp_vectors');
const { NatPmpResponseError, encodeNatPmpResponse } = require('../natpmp_response_encoder');

function hex(packet) { return packet.toString('hex'); }
function external(overrides = {}) { return { response_type: 'external-address', result_code: 0, epoch: 42, external_ip: [88, 11, 22, 4], ...overrides }; }
function map(overrides = {}) { return { response_type: 'map', transport: 'tcp', result_code: 0, epoch: 99, internal_port: 4662, external_port: 52144, lifetime_seconds: 3600, ...overrides }; }
function expectError(input, code, path) {
  assert.throws(() => encodeNatPmpResponse(input), (error) => {
    assert.ok(error instanceof NatPmpResponseError); assert.equal(error.reason_code, code); assert.equal(error.field_path, path); assert.equal(error.message, `${code} at ${path}`); return true;
  });
}

test('C03: encodes the frozen C01 external-address and TCP MAP response goldens', () => {
  assert.equal(hex(encodeNatPmpResponse(external())), NATPMP_VECTORS.external_address_response.hex);
  assert.equal(hex(encodeNatPmpResponse(map())), NATPMP_VECTORS.map_tcp_response.hex);
});
test('C03: derives the UDP MAP opcode without inventing a C01 UDP golden', () => {
  assert.equal(hex(encodeNatPmpResponse(map({ transport: 'udp' }))), '00810000000000631236cbb000000e10');
  assert.equal(Object.hasOwn(NATPMP_VECTORS, 'map_udp_response'), false);
});
test('C03: encodes alternate ports, reduced leases, epochs and uint limits big-endian', () => {
  assert.equal(hex(encodeNatPmpResponse(map({ epoch: 0xffffffff, external_port: 1, lifetime_seconds: 2 }))), '00820000ffffffff1236000100000002');
  assert.equal(hex(encodeNatPmpResponse(map({ internal_port: 65535, external_port: 65535, lifetime_seconds: 0xffffffff }))), '0082000000000063ffffffffffffffff');
  assert.equal(hex(encodeNatPmpResponse(external({ epoch: 0, external_ip: [255, 0, 127, 1] }))), '0080000000000000ff007f01');
});
test('C03: encodes all normative rejections with deterministic fields', () => {
  for (const resultCode of [1, 2, 3, 4, 5]) {
    assert.equal(hex(encodeNatPmpResponse(external({ result_code: resultCode, epoch: 7, external_ip: [0, 0, 0, 0] }))), `0080${resultCode.toString(16).padStart(4, '0')}0000000700000000`);
    assert.equal(hex(encodeNatPmpResponse(map({ result_code: resultCode, epoch: 7, external_port: 0, lifetime_seconds: 0 }))), `0082${resultCode.toString(16).padStart(4, '0')}000000071236000000000000`);
  }
});
test('C03: encodes successful deletion as zero external port and lifetime', () => {
  assert.equal(hex(encodeNatPmpResponse(map({ external_port: 0, lifetime_seconds: 0 }))), '00820000000000631236000000000000');
});
test('C03: rejects closed shape, unsupported results, invalid ranges and incompatible fields', () => {
  expectError(null, 'NATPMP_RESPONSE_INPUT_INVALID', '$'); expectError([], 'NATPMP_RESPONSE_INPUT_INVALID', '$');
  expectError(external({ extra: true }), 'NATPMP_RESPONSE_UNKNOWN_FIELD', '$.*'); expectError(external({ response_type: 'nope' }), 'NATPMP_RESPONSE_TYPE_INVALID', '$.response_type');
  expectError(map({ transport: 'icmp' }), 'NATPMP_RESPONSE_TRANSPORT_INVALID', '$.transport'); expectError(external({ result_code: 6 }), 'NATPMP_RESPONSE_RESULT_INVALID', '$.result_code');
  expectError(map({ epoch: -1 }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.epoch'); expectError(map({ internal_port: 1.5 }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.internal_port');
  expectError(map({ epoch: -0 }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.epoch'); expectError(external({ external_ip: [-0, 0, 0, 0] }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip[0]');
  expectError(external({ external_ip: [256, 0, 0, 0] }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip[0]'); expectError(external({ external_ip: [1, 2, 3] }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip');
  expectError(external({ external_ip: [0, 0, 0, 0] }), 'NATPMP_RESPONSE_EXTERNAL_IP_INVALID', '$.external_ip');
  expectError(external({ result_code: 2 }), 'NATPMP_RESPONSE_REJECT_FIELDS_INVALID', '$.external_ip'); expectError(map({ result_code: 2 }), 'NATPMP_RESPONSE_REJECT_FIELDS_INVALID', '$');
  expectError(map({ internal_port: 0 }), 'NATPMP_RESPONSE_INTERNAL_PORT_INVALID', '$.internal_port'); expectError(map({ external_port: 0 }), 'NATPMP_RESPONSE_MAP_FIELDS_INVALID', '$'); expectError(map({ lifetime_seconds: 0 }), 'NATPMP_RESPONSE_MAP_FIELDS_INVALID', '$');
});
test('C03: requires every top-level field and identifies unknown fields without count heuristics', () => {
  const missingType = external(); delete missingType.response_type; expectError(missingType, 'NATPMP_RESPONSE_FIELD_MISSING', '$.response_type');
  const missingExternal = external(); delete missingExternal.epoch; expectError(missingExternal, 'NATPMP_RESPONSE_FIELD_MISSING', '$.epoch');
  const missingMap = map(); delete missingMap.transport; expectError(missingMap, 'NATPMP_RESPONSE_FIELD_MISSING', '$.transport');
  const compensated = external(); delete compensated.epoch; compensated.extra = true; expectError(compensated, 'NATPMP_RESPONSE_UNKNOWN_FIELD', '$.*');
  const secret = external(); secret.leaked_secret_value = true;
  assert.throws(() => encodeNatPmpResponse(secret), (error) => { assert.equal(error.reason_code, 'NATPMP_RESPONSE_UNKNOWN_FIELD'); assert.equal(error.field_path, '$.*'); assert.equal(error.message.includes('leaked_secret_value'), false); return true; });
  const symbolInput = external(); symbolInput[Symbol('secret')] = true; expectError(symbolInput, 'NATPMP_RESPONSE_UNKNOWN_FIELD', '$.*');
});
test('C03: requires enumerable own data properties at every response boundary', () => {
  const hiddenType = external(); Object.defineProperty(hiddenType, 'response_type', { enumerable: false, value: 'external-address' }); expectError(hiddenType, 'NATPMP_RESPONSE_INPUT_INVALID', '$.response_type');
  let typeReads = 0; const accessorType = external(); Object.defineProperty(accessorType, 'response_type', { enumerable: true, get() { typeReads += 1; throw new Error('secret'); } }); expectError(accessorType, 'NATPMP_RESPONSE_INPUT_INVALID', '$.response_type'); assert.equal(typeReads, 0);
  const hidden = external(); Object.defineProperty(hidden, 'epoch', { enumerable: false, value: 42 }); expectError(hidden, 'NATPMP_RESPONSE_INPUT_INVALID', '$.epoch');
  const hiddenIp = external(); Object.defineProperty(hiddenIp.external_ip, '1', { enumerable: false, value: 11 }); expectError(hiddenIp, 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip[1]');
  const unknownIp = external(); unknownIp.external_ip.extra = true; expectError(unknownIp, 'NATPMP_RESPONSE_UNKNOWN_FIELD', '$.external_ip.*');
  const symbolIp = external(); symbolIp.external_ip[Symbol('secret')] = true; expectError(symbolIp, 'NATPMP_RESPONSE_UNKNOWN_FIELD', '$.external_ip.*');
  const missingOctet = external(); delete missingOctet.external_ip[2]; expectError(missingOctet, 'NATPMP_RESPONSE_FIELD_MISSING', '$.external_ip[2]');
});
test('C03: snapshots input, leaves it unchanged and returns a fresh Buffer', () => {
  const input = map(); const before = structuredClone(input); const first = encodeNatPmpResponse(input); input.external_port = 1; input.lifetime_seconds = 1; const second = encodeNatPmpResponse(before); first.fill(0);
  assert.deepEqual(before, map()); assert.equal(hex(second), NATPMP_VECTORS.map_tcp_response.hex); assert.notStrictEqual(first, second);
});
test('C03: rejects proxies, getters, class instances and sparse arrays without invoking getters', () => {
  expectError(new Proxy(map(), { get() { throw new Error('secret'); } }), 'NATPMP_RESPONSE_INPUT_INVALID', '$');
  let reads = 0; const getterInput = map(); Object.defineProperty(getterInput, 'epoch', { enumerable: true, get() { reads += 1; throw new Error('secret'); } }); expectError(getterInput, 'NATPMP_RESPONSE_INPUT_INVALID', '$.epoch'); assert.equal(reads, 0);
  class Response {} expectError(Object.assign(new Response(), map()), 'NATPMP_RESPONSE_INPUT_INVALID', '$');
  const sparse = external({ external_ip: new Array(4) }); expectError(sparse, 'NATPMP_RESPONSE_FIELD_MISSING', '$.external_ip[0]');
  const normalProxy = external({ external_ip: new Proxy([1, 2, 3, 4], { get() { throw new Error('secret'); } }) });
  expectError(normalProxy, 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip');
  const revocable = Proxy.revocable([1, 2, 3, 4], {}); revocable.revoke();
  expectError(external({ external_ip: revocable.proxy }), 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip');
  let octetReads = 0; const hostileIp = external({ external_ip: [1, 2, 3, 4] });
  Object.defineProperty(hostileIp.external_ip, '0', { enumerable: true, get() { octetReads += 1; throw new Error('secret'); } });
  expectError(hostileIp, 'NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip[0]'); assert.equal(octetReads, 0);
});
