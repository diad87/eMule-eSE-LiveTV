'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { types } = require('node:util');

const { PCP_VECTORS } = require('../pcp_vectors');
const { PcpRequestError, decodePcpMapRequest } = require('../pcp_map_request_decoder');

function vector(name) { return Buffer.from(PCP_VECTORS[name].hex, 'hex'); }

function expectError(packet, code, path, resultCode) {
  assert.throws(() => decodePcpMapRequest(packet), (error) => {
    assert.ok(error instanceof PcpRequestError);
    assert.equal(error.name, 'PcpRequestError');
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, path);
    assert.equal(error.pcp_result_code, resultCode);
    assert.equal(error.message, `${code} at ${path}`);
    return true;
  });
}

test('D02: decodes the frozen TCP MAP request into an immutable command', () => {
  const command = decodePcpMapRequest(vector('map_tcp_request'));
  assert.deepEqual(command, {
    protocol: 'pcp',
    operation: 'map',
    transport: 'tcp',
    client_address: '192.168.1.20',
    nonce: '0102030405060708090a0b0c',
    internal_port: 4662,
    suggested_external_port: 443,
    suggested_external_address: '::',
    lifetime_seconds: 7200,
    options: {
      prefer_failure: false,
      port_set: null,
    },
  });
  assert.ok(Object.isFrozen(command));
  assert.ok(Object.isFrozen(command.options));
});

test('D02: decodes UDP, native IPv6, renewal, delete and unsigned lifetime', () => {
  const udp = vector('map_tcp_request');
  udp[36] = 17;
  assert.equal(decodePcpMapRequest(udp).transport, 'udp');

  const native = decodePcpMapRequest(vector('map_native_v6_request'));
  assert.equal(native.client_address, '2001:db8:1:2::20');
  assert.equal(native.suggested_external_address, '2001:db8:1:2::40');

  const uncompressed = vector('map_native_v6_request');
  Buffer.from('20010db8000100020003000400050006', 'hex').copy(uncompressed, 8);
  assert.equal(decodePcpMapRequest(uncompressed).client_address,
    '2001:db8:1:2:3:4:5:6');

  const renewal = decodePcpMapRequest(vector('map_tcp_renewal_request'));
  assert.equal(renewal.suggested_external_address, '88.11.22.4');

  const deletion = decodePcpMapRequest(vector('map_tcp_delete_request'));
  assert.equal(deletion.operation, 'delete');
  assert.equal(deletion.lifetime_seconds, 0);
  assert.equal(deletion.suggested_external_port, 0);
  assert.equal(deletion.suggested_external_address, '::');

  const maximum = vector('map_tcp_request');
  maximum.writeUInt32BE(0xffffffff, 4);
  assert.equal(decodePcpMapRequest(maximum).lifetime_seconds, 4294967295);
});

test('D02: rejects truncated, oversized and misaligned MAP requests', () => {
  for (const length of [0, 1, 2, 23, 59]) {
    expectError(Buffer.alloc(length), 'PCP_SIZE_INVALID', '$', 3);
  }
  expectError(Buffer.alloc(1104), 'PCP_SIZE_INVALID', '$', 3);
  expectError(new Uint8Array(16 * 1024 * 1024),
    'PCP_SIZE_INVALID', '$', 3);
  expectError(Buffer.concat([vector('map_tcp_request'), Buffer.from([0])]),
    'PCP_ALIGNMENT_INVALID', '$', 3);
});

test('D02: rejects incorrect version and request opcode', () => {
  const badVersion = vector('map_tcp_request');
  badVersion[0] = 1;
  expectError(badVersion, 'PCP_VERSION_INVALID', '$[0]', 1);

  for (const opcode of [0, 2, 0x80, 0x81, 0xff]) {
    const packet = vector('map_tcp_request');
    packet[1] = opcode;
    expectError(packet, 'PCP_OPCODE_INVALID', '$[1]', 4);
  }
});

test('D02: ignores common, MAP and option reserved bits on reception', () => {
  const packet = vector('map_prefer_failure_request');
  for (const offset of [2, 3, 37, 38, 39, 61]) packet[offset] = 0xff;
  const command = decodePcpMapRequest(packet);
  assert.equal(command.internal_port, 4662);
  assert.equal(command.options.prefer_failure, true);

  const portSet = vector('map_port_set_request');
  portSet[68] = 0xfe;
  assert.equal(decodePcpMapRequest(portSet).options.port_set.preserve_parity, false);
  portSet[68] = 0xff;
  assert.equal(decodePcpMapRequest(portSet).options.port_set.preserve_parity, true);
});

test('D02: accepts a zero nonce and rejects unsupported transport or zero internal port', () => {
  const zeroNonce = vector('map_tcp_request');
  zeroNonce.fill(0, 24, 36);
  assert.equal(decodePcpMapRequest(zeroNonce).nonce, '0'.repeat(24));

  for (const value of [0, 1, 16, 18, 255]) {
    const packet = vector('map_tcp_request');
    packet[36] = value;
    expectError(packet, 'PCP_TRANSPORT_PROTOCOL_INVALID', '$[36]', 9);
  }

  const zeroPort = vector('map_tcp_request');
  zeroPort.fill(0, 40, 42);
  expectError(zeroPort, 'PCP_INTERNAL_PORT_INVALID', '$[40..41]', 3);
});

test('D02: delete ignores but preserves nonzero suggestions for the response echo', () => {
  const port = vector('map_tcp_delete_request');
  port.writeUInt16BE(1, 42);
  let command = decodePcpMapRequest(port);
  assert.equal(command.operation, 'delete');
  assert.equal(command.suggested_external_port, 1);

  const address = vector('map_tcp_delete_request');
  address[59] = 1;
  command = decodePcpMapRequest(address);
  assert.equal(command.operation, 'delete');
  assert.equal(command.suggested_external_address, '::1');
});

test('D02: decodes PREFER_FAILURE and PORT_SET options exactly', () => {
  const prefer = decodePcpMapRequest(vector('map_prefer_failure_request'));
  assert.deepEqual(prefer.options, { prefer_failure: true, port_set: null });

  const portSet = decodePcpMapRequest(vector('map_port_set_request'));
  assert.deepEqual(portSet.options, {
    prefer_failure: false,
    port_set: {
      size: 32,
      first_internal_port: 4662,
      preserve_parity: true,
    },
  });
  assert.ok(Object.isFrozen(portSet.options.port_set));
});

test('D02: rejects malformed, duplicate or incoherent known options', () => {
  const cases = [];
  cases.push(Buffer.concat([vector('map_native_v6_request'), Buffer.from('02000004', 'hex')]));
  cases.push(Buffer.concat([vector('map_native_v6_request'), Buffer.from('0200000400000000', 'hex')]));
  cases.push(Buffer.concat([vector('map_prefer_failure_request'), Buffer.from('02000000', 'hex')]));

  const duplicatePortSet = Buffer.concat([
    vector('map_port_set_request'),
    Buffer.from('820000050020123601000000', 'hex'),
  ]);
  cases.push(duplicatePortSet);

  const zeroSize = vector('map_port_set_request');
  zeroSize.fill(0, 64, 66);
  cases.push(zeroSize);

  const wrongFirstPort = vector('map_port_set_request');
  wrongFirstPort.writeUInt16BE(4663, 66);
  cases.push(wrongFirstPort);

  const nonzeroPadding = vector('map_port_set_request');
  nonzeroPadding[71] = 1;
  cases.push(nonzeroPadding);

  const preferOnDelete = Buffer.concat([
    vector('map_tcp_delete_request'),
    Buffer.from('02000000', 'hex'),
  ]);
  cases.push(preferOnDelete);

  const preferWithoutPort = vector('map_prefer_failure_request');
  preferWithoutPort.fill(0, 42, 44);
  cases.push(preferWithoutPort);

  const preferAndPortSet = Buffer.concat([
    vector('map_prefer_failure_request'),
    Buffer.from('820000050020123601000000', 'hex'),
  ]);
  cases.push(preferAndPortSet);

  for (const packet of cases) {
    expectError(packet, 'PCP_OPTION_MALFORMED', '$[60..]', 6);
  }
});

test('D02: unsupported mandatory option fails while unknown optional option is ignored', () => {
  const mandatory = Buffer.concat([
    vector('map_native_v6_request'),
    Buffer.from('03000000', 'hex'),
  ]);
  expectError(mandatory, 'PCP_OPTION_UNSUPPORTED', '$[60]', 5);

  const optional = Buffer.concat([
    vector('map_native_v6_request'),
    Buffer.from('83000000', 'hex'),
  ]);
  assert.deepEqual(decodePcpMapRequest(optional).options, {
    prefer_failure: false,
    port_set: null,
  });
});

test('D02: snapshots genuine byte views without consulting hostile properties', () => {
  const input = new Uint8Array(vector('map_tcp_request'));
  const before = Uint8Array.from(input);
  let reads = 0;
  const hostile = { get() { reads += 1; throw new Error('secret'); } };
  for (const key of ['length', 'buffer', 'byteLength', 'byteOffset',
    Symbol.iterator, 'valueOf', 'toString']) {
    Object.defineProperty(input, key, hostile);
  }
  const command = decodePcpMapRequest(input);
  Uint8Array.prototype.fill.call(input, 0);
  assert.deepEqual(before, new Uint8Array(vector('map_tcp_request')));
  assert.equal(command.internal_port, 4662);
  assert.equal(reads, 0);
});

test('D02: rejects proxies, forged views, shared and detached byte storage safely', () => {
  for (const input of [null, 'packet', new Uint16Array([1]),
    Object.create(Uint8Array.prototype), Object.create(Buffer.prototype)]) {
    expectError(input, 'PCP_INPUT_INVALID', '$', 3);
  }

  let trapReads = 0;
  const proxy = new Proxy(vector('map_tcp_request'), {
    get() { trapReads += 1; throw new Error('secret'); },
  });
  expectError(proxy, 'PCP_INPUT_INVALID', '$', 3);
  assert.equal(trapReads, 0);
  assert.ok(types.isProxy(proxy));

  expectError(new Uint8Array(new SharedArrayBuffer(60)),
    'PCP_INPUT_INVALID', '$', 3);

  const backing = new ArrayBuffer(60);
  const detached = new Uint8Array(backing);
  structuredClone(backing, { transfer: [backing] });
  expectError(detached, 'PCP_INPUT_INVALID', '$', 3);
});
