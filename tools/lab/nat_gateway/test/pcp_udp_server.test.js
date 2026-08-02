'use strict';

const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const {
  createPcpUdpServer,
  PcpUdpServerError,
  MAX_QUEUE,
} = require('../pcp_udp_server');
const { PCP_VECTORS } = require('../pcp_vectors');

function vector(name) { return Buffer.from(PCP_VECTORS[name].hex, 'hex'); }
function withIpv4(name, address = [127, 0, 0, 1]) {
  const packet = vector(name);
  Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    ...address]).copy(packet, 8);
  return packet;
}
function response(command) {
  if (command.operation === 'announce') {
    return {
      mode: 'semantic',
      response_type: 'announce',
      result_code: 0,
      epoch: 42,
    };
  }
  return {
    mode: 'semantic',
    response_type: 'map',
    result_code: 0,
    epoch: 42,
    lifetime_seconds: command.operation === 'delete' ? 0 : 3600,
    nonce: command.nonce,
    protocol_number: command.transport === 'tcp' ? 6 : 17,
    internal_port: command.internal_port,
    external_port: command.operation === 'delete' ? 0 : 52144,
    external_address: command.operation === 'delete' ? '0.0.0.0' : '88.11.22.4',
    options: { prefer_failure: false, port_set: null },
  };
}
function config(overrides = {}) {
  return {
    bind_address: '127.0.0.1',
    port: 0,
    allow_ephemeral_port_for_test: true,
    allowed_source_addresses: ['127.0.0.1'],
    application: async (command) => response(command),
    epoch_provider: () => 42,
    event_sink: () => {},
    ...overrides,
  };
}
function bind(socket) {
  return new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
}
function close(socket) {
  return new Promise((resolve) => socket.close(resolve));
}
function receive(socket) {
  return new Promise((resolve) => socket.once('message', resolve));
}
function send(socket, packet, target) {
  return new Promise((resolve, reject) => socket.send(
    packet, target.port, target.address,
    (error) => error ? reject(error) : resolve()));
}
function fakeSocket(address = '127.0.0.1', port = 9001) {
  const socket = new EventEmitter();
  socket.sent = [];
  socket.bind = () => socket.emit('listening');
  socket.address = () => ({ address, port });
  socket.send = (packet, targetPort, targetAddress, done) => {
    socket.sent.push({
      packet: Buffer.from(packet),
      port: targetPort,
      address: targetAddress,
    });
    done();
  };
  socket.close = (done) => { if (done) done(); };
  return socket;
}
function settle() {
  return new Promise((resolve) => setImmediate(resolve));
}

test('D05: real udp4 server routes MAP and ANNOUNCE and replies to exact source', async (t) => {
  const commands = [];
  const sources = [];
  const requests = [];
  const server = createPcpUdpServer(config({
    application: async (command, source, signal, request) => {
      commands.push(command);
      sources.push(source);
      requests.push(request);
      return response(command);
    },
  }));
  const target = await server.start();
  const client = dgram.createSocket('udp4');
  t.after(async () => { await server.close(); await close(client); });
  await bind(client);

  let reply = receive(client);
  await send(client, withIpv4('map_tcp_request'), target);
  let packet = await reply;
  assert.equal(packet[1], 0x81);
  assert.equal(packet[3], 0);
  assert.equal(packet.readUInt32BE(8), 42);
  assert.equal(packet.readUInt16BE(42), 52144);

  reply = receive(client);
  await send(client, withIpv4('announce_request'), target);
  packet = await reply;
  assert.equal(packet.toString('hex'),
    '02800000000000000000002a000000000000000000000000');
  assert.deepEqual(commands.map((command) => command.operation),
    ['map', 'announce']);
  assert.ok(sources.every(Object.isFrozen));
  assert.ok(sources.every((source) =>
    source.address === '127.0.0.1' &&
    source.port === client.address().port));
  assert.deepEqual(requests.map((request) => request.kind),
    ['map', 'announce']);
  assert.ok(requests.every(Object.isFrozen));
  assert.ok(requests.every((request) => Buffer.isBuffer(request.wire)));
});

test('D05: client-address mismatch returns result 12 without model access', async () => {
  const socket = fakeSocket();
  const events = [];
  let calls = 0;
  const server = createPcpUdpServer(config({
    application: async () => { calls += 1; return {}; },
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  socket.emit('message', vector('map_tcp_request'),
    { address: '127.0.0.1', port: 1234 });
  await settle();
  assert.equal(calls, 0);
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].packet[3], 12);
  assert.equal(socket.sent[0].packet.readUInt32BE(4), 0);
  assert.equal(socket.sent[0].packet.subarray(12, 24)
    .equals(Buffer.alloc(12)), true);
  assert.ok(events.some((event) => event.reason_code === 'address-mismatch'));
  await server.close();
});

test('D05: decodable MAP and ANNOUNCE errors preserve wire response semantics', async () => {
  const socket = fakeSocket();
  const server = createPcpUdpServer(config(),
    { socket_factory: () => socket });
  await server.start();

  const map = withIpv4('map_tcp_request');
  map.fill(0, 40, 42);
  socket.emit('message', map, { address: '127.0.0.1', port: 9 });
  const announce = Buffer.concat([
    withIpv4('announce_request'),
    Buffer.from('04000000', 'hex'),
  ]);
  socket.emit('message', announce, { address: '127.0.0.1', port: 9 });
  await settle();
  await settle();

  assert.deepEqual(socket.sent.map((entry) =>
    [entry.packet[1], entry.packet[3]]), [[0x81, 3], [0x80, 5]]);
  assert.ok(socket.sent.every((entry) => entry.packet.readUInt32BE(8) === 42));
  await server.close();
});

test('D05: common errors honor version precedence and bounded malformed replies', async () => {
  const socket = fakeSocket();
  const events = [];
  let calls = 0;
  const server = createPcpUdpServer(config({
    application: async () => { calls += 1; return {}; },
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  const unknown = withIpv4('announce_request');
  unknown[1] = 7;
  socket.emit('message', unknown, { address: '127.0.0.1', port: 1 });
  const oldUnknown = Buffer.from(unknown);
  oldUnknown[0] = 1;
  socket.emit('message', oldUnknown,
    { address: '127.0.0.1', port: 1 });
  const oldAnnounce = withIpv4('announce_request');
  oldAnnounce[0] = 1;
  socket.emit('message', oldAnnounce,
    { address: '127.0.0.1', port: 1 });
  const oldMap = withIpv4('map_tcp_request');
  oldMap[0] = 1;
  socket.emit('message', oldMap,
    { address: '127.0.0.1', port: 1 });
  const shortMap = withIpv4('announce_request');
  shortMap[1] = 1;
  socket.emit('message', shortMap,
    { address: '127.0.0.1', port: 1 });
  const misalignedMap = Buffer.concat([
    withIpv4('map_tcp_request'),
    Buffer.from([0]),
  ]);
  socket.emit('message', misalignedMap,
    { address: '127.0.0.1', port: 1 });
  const misalignedAnnounce = Buffer.concat([
    withIpv4('announce_request'),
    Buffer.from([0]),
  ]);
  socket.emit('message', misalignedAnnounce,
    { address: '127.0.0.1', port: 1 });
  const misalignedUnknown = Buffer.from(misalignedAnnounce);
  misalignedUnknown[1] = 7;
  socket.emit('message', misalignedUnknown,
    { address: '127.0.0.1', port: 1 });
  const oversize = Buffer.concat([
    withIpv4('announce_request'),
    Buffer.alloc(1101 - 24),
  ]);
  socket.emit('message', oversize,
    { address: '127.0.0.1', port: 1 });
  const oversizeMap = Buffer.from(oversize);
  oversizeMap[1] = 1;
  socket.emit('message', oversizeMap,
    { address: '127.0.0.1', port: 1 });
  const oversizeUnknown = Buffer.from(oversize);
  oversizeUnknown[1] = 7;
  socket.emit('message', oversizeUnknown,
    { address: '127.0.0.1', port: 1 });
  const oversizeResponse = Buffer.from(oversize);
  oversizeResponse[1] = 0x80;
  socket.emit('message', oversizeResponse,
    { address: '127.0.0.1', port: 1 });
  const responseLoop = withIpv4('announce_request');
  responseLoop[1] = 0x80;
  socket.emit('message', responseLoop,
    { address: '127.0.0.1', port: 1 });
  socket.emit('message', withIpv4('announce_request'),
    { address: '127.0.0.2', port: 1 });
  await settle();
  await settle();
  assert.equal(calls, 0);
  assert.deepEqual(socket.sent.map((entry) => [
    entry.packet.length, entry.packet[1], entry.packet[3],
  ]), [
    [24, 0x87, 4],
    [24, 0x87, 1],
    [24, 0x80, 1],
    [60, 0x81, 1],
    [24, 0x81, 3],
    [64, 0x81, 3],
    [28, 0x80, 3],
    [28, 0x87, 3],
    [1100, 0x80, 3],
    [1100, 0x81, 3],
    [1100, 0x87, 3],
  ]);
  for (const entry of socket.sent.filter(({ packet }) =>
    packet.length === 64 || packet.length === 28)) {
    const originalLength = entry.packet.length === 64 ? 61 : 25;
    assert.equal(entry.packet.subarray(originalLength)
      .equals(Buffer.alloc(entry.packet.length - originalLength)), true);
  }
  assert.deepEqual(new Set(events.filter((event) => event.outcome === 'rejected')
    .map((event) => event.reason_code)),
  new Set(['invalid-request', 'invalid-source', 'oversize-datagram']));
  await server.close();
});

test('D05: structurally malformed MAP option preserves client-address tail', async () => {
  const socket = fakeSocket();
  const server = createPcpUdpServer(config(),
    { socket_factory: () => socket });
  await server.start();
  const request = Buffer.concat([
    withIpv4('map_tcp_request'),
    Buffer.from('02000004', 'hex'),
  ]);
  socket.emit('message', request,
    { address: '127.0.0.1', port: 2 });
  await settle();
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].packet[3], 6);
  assert.equal(socket.sent[0].packet.subarray(12, 24)
    .equals(request.subarray(12, 24)), true);
  await server.close();
});

test('D05: IPv6 addresses are canonicalized before source comparison', async () => {
  const socket = fakeSocket('::1');
  let calls = 0;
  const server = createPcpUdpServer(config({
    bind_address: '0:0:0:0:0:0:0:1',
    allowed_source_addresses: ['0:0:0:0:0:0:0:1'],
    application: async (command) => {
      calls += 1;
      return response(command);
    },
  }), { socket_factory: () => socket });
  await server.start();
  const packet = vector('announce_request');
  packet.fill(0, 8, 24);
  packet[23] = 1;
  socket.emit('message', packet,
    { address: '0:0:0:0:0:0:0:1', port: 77 });
  await settle();
  assert.equal(calls, 1);
  assert.equal(socket.sent.length, 1);
  assert.equal(socket.sent[0].packet[3], 0);
  await server.close();
});

test('D05: FIFO queue is bounded and close aborts active model work', async () => {
  const socket = fakeSocket();
  const events = [];
  let signal;
  const server = createPcpUdpServer(config({
    application(command, source, value) {
      signal = value;
      return new Promise(() => {});
    },
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  for (let index = 0; index < MAX_QUEUE + 2; index += 1) {
    socket.emit('message', withIpv4('announce_request'),
      { address: '127.0.0.1', port: index + 1 });
  }
  await Promise.resolve();
  const first = server.close();
  const second = server.close();
  await Promise.all([first, second]);
  assert.equal(signal.aborted, true);
  assert.equal(socket.sent.length, 0);
  assert.equal(server.state(), 'closed');
  assert.ok(events.some((event) => event.reason_code === 'queue-full'));
});

test('D05: model, epoch, send and runtime socket failures stay contained', async () => {
  const cases = [
    {
      application: async () => { throw new Error('model'); },
      expected: 'model-failure',
    },
    {
      application: async (command) => response(command),
      epoch_provider: () => { throw new Error('clock'); },
      request: vector('map_tcp_request'),
      expected: 'epoch-failure',
    },
  ];
  for (const item of cases) {
    const socket = fakeSocket();
    const events = [];
    const server = createPcpUdpServer(config({
      application: item.application,
      epoch_provider: item.epoch_provider || (() => 42),
      event_sink: (event) => events.push(event),
    }), { socket_factory: () => socket });
    await server.start();
    socket.emit('message', item.request || withIpv4('announce_request'),
      { address: '127.0.0.1', port: 1 });
    await settle();
    assert.ok(events.some((event) => event.reason_code === item.expected));
    await server.close();
  }

  const sendSocket = fakeSocket();
  sendSocket.send = (packet, port, address, done) =>
    done(new Error('send'));
  const sendEvents = [];
  const sendServer = createPcpUdpServer(config({
    event_sink: (event) => sendEvents.push(event),
  }), { socket_factory: () => sendSocket });
  await sendServer.start();
  sendSocket.emit('message', withIpv4('announce_request'),
    { address: '127.0.0.1', port: 1 });
  await settle();
  assert.ok(sendEvents.some((event) => event.reason_code === 'send-failed'));
  sendSocket.emit('error', new Error('socket'));
  assert.equal(sendServer.state(), 'failed');
  await sendServer.close();
});

test('D05: configuration and dependencies are closed before socket effects', () => {
  const invalid = [
    null,
    {},
    config({ bind_address: 'bad' }),
    config({ bind_address: '0.0.0.0' }),
    config({ bind_address: '::' }),
    config({ bind_address: '224.0.0.1' }),
    config({ bind_address: '239.255.255.250' }),
    config({ bind_address: '255.255.255.255' }),
    config({ bind_address: 'ff02::1' }),
    config({ port: 0, allow_ephemeral_port_for_test: false }),
    config({ port: -0 }),
    config({ port: -1 }),
    config({ port: 1.5 }),
    config({ port: 65536 }),
    config({ allowed_source_addresses: [] }),
    config({ allowed_source_addresses: new Array(1) }),
    config({ allowed_source_addresses: new Proxy(['127.0.0.1'], {}) }),
    config({ allowed_source_addresses: ['bad'] }),
    config({ application: null }),
    config({ epoch_provider: null }),
    config({ event_sink: null }),
    config({ extra: true }),
    new Proxy(config(), {}),
  ];
  for (const value of invalid) {
    assert.throws(() => createPcpUdpServer(value), PcpUdpServerError);
  }
  assert.throws(() => createPcpUdpServer(config(), { extra: true }),
    PcpUdpServerError);
  assert.throws(() => createPcpUdpServer(config(), { socket_factory: null }),
    PcpUdpServerError);
  assert.doesNotThrow(() => createPcpUdpServer(config({
    port: 1,
    allow_ephemeral_port_for_test: false,
  })));
  assert.doesNotThrow(() => createPcpUdpServer(config({
    port: 65535,
    allow_ephemeral_port_for_test: false,
  })));
  assert.throws(() => createPcpUdpServer(config({
    bind_address: '::ffff:127.0.0.1',
    allowed_source_addresses: ['::ffff:127.0.0.1'],
  })), PcpUdpServerError);
  assert.doesNotThrow(() => createPcpUdpServer(config({
    bind_address: '::1',
    allowed_source_addresses: ['::ffff:127.0.0.1'],
  })));

  const symbol = config();
  symbol[Symbol('secret')] = true;
  assert.throws(() => createPcpUdpServer(symbol), PcpUdpServerError);
  const accessor = config();
  Object.defineProperty(accessor, 'port', {
    enumerable: true,
    get() { throw new Error('must not run'); },
  });
  assert.throws(() => createPcpUdpServer(accessor), PcpUdpServerError);
  const sourceAccessor = ['127.0.0.1'];
  Object.defineProperty(sourceAccessor, '0', {
    enumerable: true,
    get() { throw new Error('must not run'); },
  });
  assert.throws(() => createPcpUdpServer(config({
    allowed_source_addresses: sourceAccessor,
  })), PcpUdpServerError);
  const sourceSymbol = ['127.0.0.1'];
  sourceSymbol[Symbol('secret')] = true;
  assert.throws(() => createPcpUdpServer(config({
    allowed_source_addresses: sourceSymbol,
  })), PcpUdpServerError);
  const sourcePrototype = ['127.0.0.1'];
  Object.setPrototypeOf(sourcePrototype, null);
  assert.throws(() => createPcpUdpServer(config({
    allowed_source_addresses: sourcePrototype,
  })), PcpUdpServerError);
});

test('D05: hostile packet and source metadata are rejected without coercion', async () => {
  const socket = fakeSocket();
  let reads = 0;
  const server = createPcpUdpServer(config(),
    { socket_factory: () => socket });
  await server.start();
  const packet = new Proxy(withIpv4('announce_request'), {
    get() { reads += 1; throw new Error('secret'); },
  });
  socket.emit('message', packet, { address: '127.0.0.1', port: 1 });
  socket.emit('message', withIpv4('announce_request'), {
    address: { toString() { reads += 1; return '127.0.0.1'; } },
    port: 1,
  });
  socket.emit('message', {}, { address: '127.0.0.1', port: 1 });
  socket.emit('message', new Uint8Array(new SharedArrayBuffer(24)),
    { address: '127.0.0.1', port: 1 });
  const detached = new Uint8Array(24);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  socket.emit('message', detached, { address: '127.0.0.1', port: 1 });
  for (const source of [
    null,
    { address: '127.0.0.1', port: -0 },
    { address: '127.0.0.1', port: 1.5 },
    { address: '127.0.0.1', port: 65536 },
  ]) {
    socket.emit('message', withIpv4('announce_request'), source);
  }
  const maximum = new Uint8Array(Buffer.alloc(1100));
  maximum[1] = 0x80;
  socket.emit('message', maximum,
    { address: '127.0.0.1', port: 1 });
  await settle();
  assert.equal(reads, 0);
  assert.equal(socket.sent.length, 0);
  await server.close();
});

test('D05: epoch and model response boundaries fail closed', async () => {
  for (const invalidEpoch of [
    () => { throw new Error('clock'); },
    () => -0,
    () => -1,
    () => 1.5,
    () => 0x100000000,
    () => '42',
  ]) {
    const socket = fakeSocket();
    const events = [];
    const server = createPcpUdpServer(config({
      epoch_provider: invalidEpoch,
      event_sink: (event) => events.push(event),
    }), { socket_factory: () => socket });
    await server.start();
    socket.emit('message', vector('announce_request'),
      { address: '127.0.0.1', port: 1 });
    await settle();
    assert.equal(socket.sent.length, 0);
    assert.ok(events.some((event) => event.reason_code === 'epoch-failure'));
    await server.close();
  }

  const socket = fakeSocket();
  const events = [];
  const server = createPcpUdpServer(config({
    application: async () => ({}),
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  socket.emit('message', withIpv4('announce_request'),
    { address: '127.0.0.1', port: 1 });
  await settle();
  assert.equal(socket.sent.length, 0);
  assert.ok(events.some((event) => event.reason_code === 'model-failure'));
  await server.close();

  const successSocket = fakeSocket();
  const successServer = createPcpUdpServer(config({
    application: async (command) => ({
      ...response(command),
      epoch: 999,
    }),
    epoch_provider: () => 42,
  }), { socket_factory: () => successSocket });
  await successServer.start();
  successSocket.emit('message', withIpv4('announce_request'),
    { address: '127.0.0.1', port: 1 });
  await settle();
  assert.equal(successSocket.sent[0].packet.readUInt32BE(8), 42);
  await successServer.close();
});

test('D05: socket construction, bind and public address failures are stable', async () => {
  await assert.rejects(
    createPcpUdpServer(config(), { socket_factory: () => ({}) }).start(),
    (error) => error.reason_code === 'PCP_UDP_SOCKET_INVALID');
  await assert.rejects(
    createPcpUdpServer(config(), {
      socket_factory() { throw new Error('factory'); },
    }).start(),
    (error) => error.reason_code === 'PCP_UDP_START_FAILED');

  const bindFailure = fakeSocket();
  bindFailure.bind = () => bindFailure.emit('error', new Error('bind'));
  await assert.rejects(
    createPcpUdpServer(config(), {
      socket_factory: () => bindFailure,
    }).start(),
    (error) => error.reason_code === 'PCP_UDP_START_FAILED');

  const wrongBind = fakeSocket('127.0.0.2');
  await assert.rejects(
    createPcpUdpServer(config(), {
      socket_factory: () => wrongBind,
    }).start(),
    PcpUdpServerError);

  const socket = fakeSocket();
  let currentAddress = { address: '127.0.0.1', port: 9001 };
  socket.address = () => currentAddress;
  const server = createPcpUdpServer(config(),
    { socket_factory: () => socket });
  await server.start();
  for (const invalid of [
    null,
    {},
    { address: 'bad', port: 1 },
    { address: '127.0.0.1', port: 0 },
    { address: '127.0.0.2', port: 9001 },
  ]) {
    currentAddress = invalid;
    assert.throws(() => server.address(),
      (error) => error.reason_code === 'PCP_UDP_BIND_INVALID');
  }
  currentAddress = { address: '127.0.0.1', port: 9001 };
  assert.deepEqual(server.limits(), {
    max_datagram_bytes: 1100,
    max_queue: MAX_QUEUE,
  });
  await server.close();
});

test('D05: event observer failures cannot alter protocol progress', async () => {
  for (const eventSink of [
    () => { throw new Error('observer'); },
    () => Promise.reject(new Error('observer')),
  ]) {
    const socket = fakeSocket();
    const server = createPcpUdpServer(config({ event_sink: eventSink }),
      { socket_factory: () => socket });
    await server.start();
    socket.emit('message', withIpv4('announce_request'),
      { address: '127.0.0.1', port: 1 });
    await settle();
    assert.equal(socket.sent.length, 1);
    await server.close();
  }
});

test('D05: synchronous model failure and close during epoch prevent sends', async () => {
  let socket = fakeSocket();
  let events = [];
  let server = createPcpUdpServer(config({
    application() { throw new Error('sync model'); },
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  socket.emit('message', withIpv4('announce_request'),
    { address: '127.0.0.1', port: 1 });
  await settle();
  assert.ok(events.some((event) => event.reason_code === 'model-failure'));
  await server.close();

  socket = fakeSocket();
  events = [];
  let closing;
  server = createPcpUdpServer(config({
    application: async () => { throw new Error('must not run'); },
    epoch_provider() {
      closing = server.close();
      return 42;
    },
    event_sink: (event) => events.push(event),
  }), { socket_factory: () => socket });
  await server.start();
  socket.emit('message', vector('announce_request'),
    { address: '127.0.0.1', port: 1 });
  await closing;
  assert.equal(socket.sent.length, 0);
  assert.ok(events.some((event) => event.reason_code === 'closed'));
});

test('D05: lifecycle rejects double start and closes a stalled bind', async () => {
  const socket = fakeSocket();
  const server = createPcpUdpServer(config(),
    { socket_factory: () => socket });
  await server.start();
  await assert.rejects(server.start(), PcpUdpServerError);
  assert.equal(server.address().address, '127.0.0.1');
  await server.close();
  assert.equal(server.address(), null);

  const stalled = fakeSocket();
  stalled.bind = () => {};
  const stalledServer = createPcpUdpServer(config(),
    { socket_factory: () => stalled });
  const starting = stalledServer.start();
  await stalledServer.close();
  await assert.rejects(starting, PcpUdpServerError);
  assert.equal(stalledServer.state(), 'closed');
});
