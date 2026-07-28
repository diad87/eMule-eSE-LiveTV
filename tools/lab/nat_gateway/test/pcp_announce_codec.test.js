'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { PCP_VECTORS } = require('../pcp_vectors');
const {
  PcpAnnounceError,
  decodePcpAnnounceRequest,
  encodePcpAnnounceResponse,
} = require('../pcp_announce_codec');

function vector(name) { return Buffer.from(PCP_VECTORS[name].hex, 'hex'); }

function expectDecodeError(packet, code, path, resultCode, parsed) {
  assert.throws(() => decodePcpAnnounceRequest(packet), (error) => {
    assert.ok(error instanceof PcpAnnounceError);
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, path);
    assert.equal(error.pcp_result_code, resultCode);
    assert.equal(error.request_parsed, parsed);
    return true;
  });
}

function semantic(overrides = {}) {
  return {
    mode: 'semantic',
    response_type: 'announce',
    result_code: 0,
    epoch: 9876,
    ...overrides,
  };
}

function errorEcho(overrides = {}) {
  return {
    mode: 'error-echo',
    response_type: 'announce',
    result_code: 6,
    epoch: 9876,
    request_wire: vector('announce_request'),
    request_parsed: false,
    ...overrides,
  };
}

function expectEncodeError(input, code, path) {
  assert.throws(() => encodePcpAnnounceResponse(input), (error) => {
    assert.ok(error instanceof PcpAnnounceError);
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, path);
    return true;
  });
}

test('D04: decodes frozen ANNOUNCE request and encodes frozen response', () => {
  const command = decodePcpAnnounceRequest(vector('announce_request'));
  assert.deepEqual(command, {
    protocol: 'pcp',
    operation: 'announce',
    client_address: '192.168.1.20',
  });
  assert.ok(Object.isFrozen(command));
  assert.equal(encodePcpAnnounceResponse(errorEcho({
    result_code: 2,
    request_parsed: true,
  })).toString('hex'),
    PCP_VECTORS.announce_response.hex);
});

test('D04: request lifetime and reserved fields are ignored on reception', () => {
  const packet = vector('announce_request');
  packet[2] = 0xff;
  packet[3] = 0xff;
  packet.writeUInt32BE(0xffffffff, 4);
  assert.equal(decodePcpAnnounceRequest(packet).client_address,
    '192.168.1.20');
});

test('D04: decodes native IPv6 client address canonically', () => {
  const packet = vector('announce_request');
  Buffer.from('20010db8000100020000000000000020', 'hex').copy(packet, 8);
  assert.equal(decodePcpAnnounceRequest(packet).client_address,
    '2001:db8:1:2::20');
});

test('D04: ignores every well-formed optional option, including MAP PORT_SET', () => {
  for (const option of [
    '8300000301020300',
    '820000050020123601000000',
  ]) {
    const packet = Buffer.concat([
      vector('announce_request'),
      Buffer.from(option, 'hex'),
    ]);
    assert.equal(decodePcpAnnounceRequest(packet).operation, 'announce');
  }
});

test('D04: unsupported mandatory and malformed options get exact results', () => {
  const mandatory = Buffer.concat([
    vector('announce_request'),
    Buffer.from('04000000', 'hex'),
  ]);
  expectDecodeError(mandatory, 'PCP_ANNOUNCE_OPTION_UNSUPPORTED',
    '$[24]', 5, true);

  const malformed = Buffer.concat([
    vector('announce_request'),
    Buffer.from('8300000801020300', 'hex'),
  ]);
  expectDecodeError(malformed, 'PCP_ANNOUNCE_OPTION_MALFORMED',
    '$[24..]', 6, false);

  const padding = Buffer.concat([
    vector('announce_request'),
    Buffer.from('8300000301020301', 'hex'),
  ]);
  expectDecodeError(padding, 'PCP_ANNOUNCE_OPTION_MALFORMED',
    '$[24..]', 6, false);

  for (const option of [
    '02000000',
  ]) {
    const wrongOpcodeOption = Buffer.concat([
      vector('announce_request'),
      Buffer.from(option, 'hex'),
    ]);
    expectDecodeError(wrongOpcodeOption, 'PCP_ANNOUNCE_OPTION_MALFORMED',
      '$[24]', 6, true);
  }
});

test('D04: rejects size, version and non-request opcode deterministically', () => {
  for (const length of [0, 1, 23]) {
    expectDecodeError(Buffer.alloc(length), 'PCP_ANNOUNCE_SIZE_INVALID',
      '$', 3, false);
  }
  expectDecodeError(Buffer.alloc(1104), 'PCP_ANNOUNCE_SIZE_INVALID',
    '$', 3, false);
  expectDecodeError(Buffer.concat([
    vector('announce_request'), Buffer.from([0]),
  ]), 'PCP_ANNOUNCE_ALIGNMENT_INVALID', '$', 3, false);

  const version = vector('announce_request');
  version[0] = 1;
  expectDecodeError(version, 'PCP_ANNOUNCE_VERSION_INVALID',
    '$[0]', 1, false);
  for (const opcode of [1, 0x80, 0xff]) {
    const packet = vector('announce_request');
    packet[1] = opcode;
    expectDecodeError(packet, 'PCP_ANNOUNCE_OPCODE_INVALID',
      '$[1]', 4, false);
  }
});

test('D04: semantic success and error echo cover every native result and uint epoch', () => {
  const success = encodePcpAnnounceResponse(semantic({
    epoch: 0xffffffff,
  }));
  assert.deepEqual([...success.subarray(0, 4)], [2, 0x80, 0, 0]);
  assert.equal(success.readUInt32BE(4), 0);
  assert.equal(success.readUInt32BE(8), 0xffffffff);
  assert.equal(success.subarray(12).equals(Buffer.alloc(12)), true);

  for (let resultCode = 1; resultCode <= 13; resultCode += 1) {
    const packet = encodePcpAnnounceResponse(errorEcho({
      result_code: resultCode,
      epoch: 0xffffffff,
      request_parsed: true,
    }));
    assert.equal(packet.length, 24);
    assert.deepEqual([...packet.subarray(0, 4)], [2, 0x80, 0, resultCode]);
    assert.equal(packet.readUInt32BE(4), 0);
    assert.equal(packet.readUInt32BE(8), 0xffffffff);
    assert.equal(packet.subarray(12).equals(Buffer.alloc(12)), true);
  }
  expectEncodeError(semantic({ result_code: 1 }),
    'PCP_ANNOUNCE_RESULT_INVALID', '$.result_code');
});

test('D04: error echo preserves options and applies parsed tail rule', () => {
  const request = Buffer.concat([
    vector('announce_request'),
    Buffer.from('0300000401020304', 'hex'),
  ]);
  Buffer.from('0102030405060708090a0b0c', 'hex').copy(request, 12);
  let packet = encodePcpAnnounceResponse(errorEcho({
    request_wire: request,
    request_parsed: false,
  }));
  assert.equal(packet.subarray(12, 24).toString('hex'),
    '0102030405060708090a0b0c');
  assert.equal(packet.subarray(24).toString('hex'), '0300000401020304');
  packet = encodePcpAnnounceResponse(errorEcho({
    request_wire: request,
    request_parsed: true,
  }));
  assert.equal(packet.subarray(12, 24).equals(Buffer.alloc(12)), true);
});

test('D04: error echo accepts only bounded ANNOUNCE request wire', () => {
  expectEncodeError(errorEcho({ result_code: 0 }),
    'PCP_ANNOUNCE_RESULT_INVALID', '$.result_code');
  expectEncodeError(errorEcho({ request_parsed: 1 }),
    'PCP_ANNOUNCE_FIELD_INVALID', '$.request_parsed');
  expectEncodeError(errorEcho({ request_wire: Buffer.alloc(23) }),
    'PCP_ANNOUNCE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  expectEncodeError(errorEcho({ request_wire: new Uint8Array(16 * 1024 * 1024) }),
    'PCP_ANNOUNCE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  const response = vector('announce_request');
  response[1] = 0x80;
  expectEncodeError(errorEcho({ request_wire: response }),
    'PCP_ANNOUNCE_REQUEST_OPCODE_INVALID', '$.request_wire[1]');
});

test('D04: codec rejects hostile byte storage without executing traps', () => {
  let reads = 0;
  const proxy = new Proxy(vector('announce_request'), {
    get() { reads += 1; throw new Error('secret'); },
  });
  expectDecodeError(proxy, 'PCP_ANNOUNCE_INPUT_INVALID', '$', 3, false);
  assert.equal(reads, 0);
  expectDecodeError(new Uint8Array(new SharedArrayBuffer(24)),
    'PCP_ANNOUNCE_INPUT_INVALID', '$', 3, false);
  expectEncodeError(errorEcho({ request_wire: proxy }),
    'PCP_ANNOUNCE_REQUEST_WIRE_INVALID', '$.request_wire');
});

test('D04: response shape is closed, data-only and snapshotted', () => {
  expectEncodeError(null, 'PCP_ANNOUNCE_INPUT_INVALID', '$');
  expectEncodeError({ mode: 'other' }, 'PCP_ANNOUNCE_MODE_INVALID', '$.mode');
  const missing = semantic();
  delete missing.epoch;
  expectEncodeError(missing, 'PCP_ANNOUNCE_FIELD_MISSING', '$.epoch');
  expectEncodeError(semantic({ secret: true }),
    'PCP_ANNOUNCE_UNKNOWN_FIELD', '$.*');
  let reads = 0;
  const getter = semantic();
  Object.defineProperty(getter, 'epoch', {
    enumerable: true,
    get() { reads += 1; throw new Error('secret'); },
  });
  expectEncodeError(getter, 'PCP_ANNOUNCE_INPUT_INVALID', '$.epoch');
  assert.equal(reads, 0);

  const input = semantic({ result_code: 0 });
  const first = encodePcpAnnounceResponse(input);
  input.epoch = 0;
  const second = encodePcpAnnounceResponse(semantic({ result_code: 0 }));
  first.fill(0);
  assert.equal(second.readUInt32BE(8), 9876);
});
