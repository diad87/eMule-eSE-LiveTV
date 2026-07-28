'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { PCP_VECTORS } = require('../pcp_vectors');
const { PcpResponseError, encodePcpMapResponse } =
  require('../pcp_map_response_encoder');

function semantic(overrides = {}) {
  return {
    mode: 'semantic',
    response_type: 'map',
    result_code: 0,
    epoch: 1234,
    lifetime_seconds: 3600,
    nonce: '0102030405060708090a0b0c',
    protocol_number: 6,
    internal_port: 4662,
    external_port: 52144,
    external_address: '88.11.22.4',
    options: {
      prefer_failure: false,
      port_set: {
        size: 32,
        first_internal_port: 4662,
        preserve_parity: true,
      },
    },
    ...overrides,
  };
}

function noOptions() {
  return { prefer_failure: false, port_set: null };
}

function request(name = 'map_tcp_request') {
  return Buffer.from(PCP_VECTORS[name].hex, 'hex');
}

function errorEcho(overrides = {}) {
  return {
    mode: 'error-echo',
    response_type: 'map',
    result_code: 3,
    epoch: 1234,
    lifetime_seconds: 30,
    request_wire: request(),
    request_parsed: true,
    ...overrides,
  };
}

function expectError(input, code, path) {
  assert.throws(() => encodePcpMapResponse(input), (error) => {
    assert.ok(error instanceof PcpResponseError);
    assert.equal(error.name, 'PcpResponseError');
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, path);
    assert.equal(error.message, `${code} at ${path}`);
    return true;
  });
}

test('D03: semantic path encodes the frozen D01 MAP response byte for byte', () => {
  assert.equal(encodePcpMapResponse(semantic()).toString('hex'),
    PCP_VECTORS.map_tcp_response.hex);
});

test('D03: encodes same/alternate ports and unsigned integers big-endian', () => {
  const same = encodePcpMapResponse(semantic({
    external_port: 4662,
    options: noOptions(),
  }));
  assert.equal(same.length, 60);
  assert.equal(same.readUInt16BE(40), 4662);
  assert.equal(same.readUInt16BE(42), 4662);

  const limits = encodePcpMapResponse(semantic({
    epoch: 0xffffffff,
    lifetime_seconds: 0xffffffff,
    internal_port: 65535,
    external_port: 1,
    options: noOptions(),
  }));
  assert.equal(limits.readUInt32BE(4), 0xffffffff);
  assert.equal(limits.readUInt32BE(8), 0xffffffff);
  assert.equal(limits.readUInt16BE(40), 65535);
});

test('D03: encodes IPv4-mapped, embedded and native IPv6 addresses', () => {
  const ipv4 = encodePcpMapResponse(semantic({ options: noOptions() }));
  assert.equal(ipv4.subarray(44, 60).toString('hex'),
    '00000000000000000000ffff580b1604');

  const embedded = encodePcpMapResponse(semantic({
    external_address: '::ffff:88.11.22.4',
    options: noOptions(),
  }));
  assert.equal(embedded.subarray(44, 60).toString('hex'),
    '00000000000000000000ffff580b1604');

  const native = encodePcpMapResponse(semantic({
    external_address: '2001:db8:1:2::40',
    options: noOptions(),
  }));
  assert.equal(native.subarray(44, 60).toString('hex'),
    '20010db8000100020000000000000040');
});

test('D03: encodes UDP, successful deletion and both known options', () => {
  const udp = encodePcpMapResponse(semantic({
    protocol_number: 17,
    options: noOptions(),
  }));
  assert.equal(udp[36], 17);

  const deletion = encodePcpMapResponse(semantic({
    lifetime_seconds: 0,
    external_port: 0,
    external_address: '::',
    options: noOptions(),
  }));
  assert.equal(deletion.readUInt32BE(4), 0);
  assert.equal(deletion.subarray(42, 60).equals(Buffer.alloc(18)), true);

  const prefer = encodePcpMapResponse(semantic({
    options: { prefer_failure: true, port_set: null },
  }));
  assert.equal(prefer.subarray(60).toString('hex'), '02000000');
});

test('D03: intentional wrong nonce changes only the semantic nonce field', () => {
  const correct = encodePcpMapResponse(semantic({ options: noOptions() }));
  const wrong = encodePcpMapResponse(semantic({
    nonce: 'ff02030405060708090a0b0c',
    options: noOptions(),
  }));
  assert.deepEqual(wrong.subarray(0, 24), correct.subarray(0, 24));
  assert.deepEqual(wrong.subarray(36), correct.subarray(36));
  assert.notDeepEqual(wrong.subarray(24, 36), correct.subarray(24, 36));
});

test('D03: error path emits every native result and echoes MAP wire fields', () => {
  const original = request();
  for (let resultCode = 1; resultCode <= 13; resultCode += 1) {
    const packet = encodePcpMapResponse(errorEcho({ result_code: resultCode }));
    assert.equal(packet.length, original.length);
    assert.deepEqual([...packet.subarray(0, 4)], [2, 0x81, 0, resultCode]);
    assert.equal(packet.readUInt32BE(4), 30);
    assert.equal(packet.readUInt32BE(8), 1234);
    assert.equal(packet.subarray(12, 24).equals(Buffer.alloc(12)), true);
    assert.deepEqual(packet.subarray(24), original.subarray(24));
  }
});

test('D03: error echo preserves invalid nonce, protocol, port and raw options', () => {
  const malformed = Buffer.concat([
    request(),
    Buffer.from('0300000401020304', 'hex'),
  ]);
  malformed.fill(0, 24, 36);
  malformed[36] = 255;
  malformed.fill(0, 40, 42);
  const packet = encodePcpMapResponse(errorEcho({
    result_code: 6,
    request_wire: malformed,
  }));
  assert.equal(packet.subarray(24, 36).equals(Buffer.alloc(12)), true);
  assert.equal(packet[36], 255);
  assert.equal(packet.readUInt16BE(40), 0);
  assert.equal(packet.subarray(60).toString('hex'), '0300000401020304');
});

test('D03: unparsed error copies client tail; parsed error clears it', () => {
  const original = request();
  Buffer.from('0102030405060708090a0b0c', 'hex').copy(original, 12);
  const unparsed = encodePcpMapResponse(errorEcho({
    request_wire: original,
    request_parsed: false,
  }));
  assert.equal(unparsed.subarray(12, 24).toString('hex'),
    '0102030405060708090a0b0c');
  const parsed = encodePcpMapResponse(errorEcho({
    request_wire: original,
    request_parsed: true,
  }));
  assert.equal(parsed.subarray(12, 24).equals(Buffer.alloc(12)), true);
});

test('D03: semantic success rejects invalid scalar and wire fields', () => {
  expectError(semantic({ result_code: 2 }), 'PCP_RESPONSE_RESULT_INVALID',
    '$.result_code');
  expectError(semantic({ epoch: -1 }), 'PCP_RESPONSE_FIELD_INVALID', '$.epoch');
  expectError(semantic({ lifetime_seconds: 0x100000000 }),
    'PCP_RESPONSE_FIELD_INVALID', '$.lifetime_seconds');
  expectError(semantic({ protocol_number: 7 }),
    'PCP_RESPONSE_PROTOCOL_INVALID', '$.protocol_number');
  expectError(semantic({ internal_port: 0 }),
    'PCP_RESPONSE_INTERNAL_PORT_INVALID', '$.internal_port');
  expectError(semantic({ external_port: -0 }),
    'PCP_RESPONSE_FIELD_INVALID', '$.external_port');
  expectError(semantic({ nonce: '0'.repeat(24) }),
    'PCP_RESPONSE_NONCE_INVALID', '$.nonce');
  expectError(semantic({ nonce: 'ab' }), 'PCP_RESPONSE_NONCE_INVALID', '$.nonce');
  for (const address of ['', '999.1.1.1', '2001:::1', 'fe80::1%3', 7]) {
    expectError(semantic({ external_address: address }),
      'PCP_RESPONSE_ADDRESS_INVALID', '$.external_address');
  }
});

test('D03: successful non-delete rejects unusable external endpoints', () => {
  expectError(semantic({ external_port: 0 }),
    'PCP_RESPONSE_MAP_FIELDS_INVALID', '$');
  for (const address of [
    '::', '0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1',
    '255.255.255.255', '::1', 'fe80::1', 'ff02::1',
  ]) {
    expectError(semantic({ external_address: address }),
      'PCP_RESPONSE_MAP_FIELDS_INVALID', '$');
  }
});

test('D03: semantic options are closed and coherent', () => {
  expectError(semantic({ options: {
    prefer_failure: true,
    port_set: { size: 32, first_internal_port: 4662, preserve_parity: true },
  } }), 'PCP_RESPONSE_OPTIONS_INVALID', '$.options');
  expectError(semantic({ options: {
    prefer_failure: false,
    port_set: { size: 1, first_internal_port: 4662, preserve_parity: true },
  } }), 'PCP_RESPONSE_OPTION_FIELD_INVALID', '$.options.port_set.size');
  expectError(semantic({ options: {
    prefer_failure: false,
    port_set: { size: 32, first_internal_port: 0, preserve_parity: true },
  } }), 'PCP_RESPONSE_OPTION_FIELD_INVALID',
  '$.options.port_set.first_internal_port');
  expectError(semantic({ options: {
    prefer_failure: false,
    port_set: { size: 32, first_internal_port: 4662, preserve_parity: 1 },
  } }), 'PCP_RESPONSE_OPTION_FIELD_INVALID',
  '$.options.port_set.preserve_parity');
  expectError(semantic({ options: {
    prefer_failure: 1,
    port_set: null,
  } }), 'PCP_RESPONSE_OPTION_FIELD_INVALID', '$.options.prefer_failure');
  expectError(semantic({
    lifetime_seconds: 0,
    external_port: 0,
    external_address: '::',
    options: { prefer_failure: true, port_set: null },
  }), 'PCP_RESPONSE_OPTIONS_INVALID', '$.options.prefer_failure');
});

test('D03: error-echo rejects unsafe or incoherent request wire early', () => {
  expectError(errorEcho({ result_code: 0 }), 'PCP_RESPONSE_RESULT_INVALID',
    '$.result_code');
  expectError(errorEcho({ result_code: 14 }), 'PCP_RESPONSE_RESULT_INVALID',
    '$.result_code');
  expectError(errorEcho({ request_parsed: 1 }),
    'PCP_RESPONSE_FIELD_INVALID', '$.request_parsed');
  expectError(errorEcho({ request_wire: Buffer.alloc(59) }),
    'PCP_RESPONSE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  expectError(errorEcho({ request_wire: Buffer.alloc(1104) }),
    'PCP_RESPONSE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  expectError(errorEcho({ request_wire: new Uint8Array(16 * 1024 * 1024) }),
    'PCP_RESPONSE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  for (const opcode of [0, 0x81]) {
    const wrongOpcode = request();
    wrongOpcode[1] = opcode;
    expectError(errorEcho({ request_wire: wrongOpcode }),
      'PCP_RESPONSE_REQUEST_OPCODE_INVALID', '$.request_wire[1]');
  }
  expectError(errorEcho({ request_wire: new SharedArrayBuffer(60) }),
    'PCP_RESPONSE_REQUEST_WIRE_INVALID', '$.request_wire');
});

test('D03: closed modes reject missing, unknown, proxy and accessor input', () => {
  expectError(null, 'PCP_RESPONSE_INPUT_INVALID', '$');
  expectError([], 'PCP_RESPONSE_INPUT_INVALID', '$');
  expectError({ mode: 'other' }, 'PCP_RESPONSE_MODE_INVALID', '$.mode');
  const missing = semantic();
  delete missing.epoch;
  expectError(missing, 'PCP_RESPONSE_FIELD_MISSING', '$.epoch');
  expectError(semantic({ secret: true }), 'PCP_RESPONSE_UNKNOWN_FIELD', '$.*');
  const symbol = semantic();
  symbol[Symbol('secret')] = true;
  expectError(symbol, 'PCP_RESPONSE_UNKNOWN_FIELD', '$.*');
  let reads = 0;
  const getter = semantic();
  Object.defineProperty(getter, 'epoch', {
    enumerable: true,
    get() { reads += 1; throw new Error('secret'); },
  });
  expectError(getter, 'PCP_RESPONSE_INPUT_INVALID', '$.epoch');
  assert.equal(reads, 0);
  expectError(new Proxy(semantic(), {
    get() { throw new Error('secret'); },
  }), 'PCP_RESPONSE_INPUT_INVALID', '$');
});

test('D03: snapshots caller data and returns fresh response buffers', () => {
  const input = semantic();
  const before = structuredClone(input);
  const first = encodePcpMapResponse(input);
  input.epoch = 0;
  input.options.port_set.size = 2;
  const second = encodePcpMapResponse(before);
  first.fill(0);
  assert.equal(second.toString('hex'), PCP_VECTORS.map_tcp_response.hex);
  assert.notStrictEqual(first, second);

  const wire = request();
  const echoed = encodePcpMapResponse(errorEcho({ request_wire: wire }));
  wire.fill(0);
  assert.equal(echoed[0], 2);
  assert.equal(echoed[24], 1);
});
