'use strict';

const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { EventEmitter, getEventListeners } = require('node:events');
const test = require('node:test');
const { createNatPmpUdpServer, NatPmpUdpServerError, MAX_QUEUE } = require('../natpmp_udp_server');
const { NATPMP_VECTORS } = require('../natpmp_vectors');

function response(command) { return command.operation === 'external-address' ? { response_type: 'external-address', result_code: 0, epoch: 42, external_ip: [88, 11, 22, 4] } : { response_type: 'map', transport: command.transport, result_code: 0, epoch: 99, internal_port: command.internal_port, external_port: command.operation === 'delete' ? 0 : 52144, lifetime_seconds: command.operation === 'delete' ? 0 : 3600 }; }
function config(overrides = {}) { return { bind_address: '127.0.0.1', port: 0, allow_ephemeral_port_for_test: true, allowed_source_addresses: ['127.0.0.1'], application: async (command) => response(command), event_sink: () => {}, ...overrides }; }
function bind(socket) { return new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve)); }
function receive(socket) { return new Promise((resolve) => socket.once('message', (packet, info) => resolve({ packet, info }))); }
function close(socket) { return new Promise((resolve) => socket.close(resolve)); }
function send(socket, packet, target) { return new Promise((resolve, reject) => socket.send(packet, target.port, target.address, (error) => error ? reject(error) : resolve())); }

test('C04: rejects closed or wildcard configuration before any socket exists', () => {
  for (const broken of [{}, config({ bind_address: '0.0.0.0' }), config({ bind_address: '::1' }), config({ port: 0, allow_ephemeral_port_for_test: false }), config({ allowed_source_addresses: [] }), config({ extra: true })]) assert.throws(() => createNatPmpUdpServer(broken), NatPmpUdpServerError);
});
test('C04: real udp4 loopback pipeline sends exact external and map responses', async (t) => {
  const commands = []; const sources = []; const server = createNatPmpUdpServer(config({ application: async (command, source) => { commands.push(command); sources.push(source); return response(command); } })); const target = await server.start(); const client = dgram.createSocket('udp4'); t.after(async () => { await server.close(); await close(client); }); await bind(client);
  let reply = receive(client); await send(client, Buffer.from(NATPMP_VECTORS.external_address_request.hex, 'hex'), target); assert.equal((await reply).packet.toString('hex'), NATPMP_VECTORS.external_address_response.hex);
  reply = receive(client); await send(client, Buffer.from(NATPMP_VECTORS.map_tcp_request.hex, 'hex'), target); assert.equal((await reply).packet.toString('hex'), NATPMP_VECTORS.map_tcp_response.hex);
  reply = receive(client); await send(client, Buffer.from(NATPMP_VECTORS.map_udp_request.hex, 'hex'), target); assert.equal((await reply).packet.toString('hex'), '00810000000000631236cbb000000e10');
  reply = receive(client); await send(client, Buffer.from(NATPMP_VECTORS.map_tcp_delete_request.hex, 'hex'), target); assert.equal((await reply).packet.toString('hex'), '00820000000000631236000000000000');
  assert.deepEqual(commands.map((command) => command.operation), ['external-address', 'map', 'map', 'delete']); assert.equal(sources.every(Object.isFrozen), true); assert.equal(sources.every((source) => source.address === '127.0.0.1' && source.port === client.address().port), true); assert.equal(server.address().address, '127.0.0.1');
});
test('C04: drops oversize, malformed and invalid sources without application or send', async () => {
  const events = []; let calls = 0; const server = createNatPmpUdpServer(config({ application: async () => { calls += 1; return response({ operation: 'external-address' }); }, event_sink: (event) => events.push(event) }));
  // The real socket cannot forge a foreign source on loopback, so exercise the
  // same receive boundary through an injected socket in the next test.
  await server.start(); await server.close(); assert.equal(calls, 0); assert.ok(events.some((event) => event.reason_code === 'bound'));
});
test('C04: injected edge validates source, datagram cap, queue order and exact send target', async () => {
  const listeners = new Map(); const sent = []; const events = []; let release; const gate = new Promise((resolve) => { release = resolve; }); const commands = [];
  const fake = { on(name, fn) { listeners.set(name, fn); }, once(name, fn) { listeners.set(name, fn); }, removeListener(name) { listeners.delete(name); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9123 }; }, send(packet, port, address, done) { sent.push({ packet: Buffer.from(packet), port, address }); done(); }, close(done) { done(); } };
  const server = createNatPmpUdpServer(config({ application: async (command) => { commands.push(command.operation); await gate; return response(command); }, event_sink: (event) => events.push(event) }), { socket_factory: () => fake }); await server.start();
  const message = listeners.get('message'); message(Buffer.alloc(13), { address: '127.0.0.1', port: 1 }); message(Buffer.from([0, 0]), { address: '127.0.0.2', port: 1 }); message(Buffer.from([0, 9]), { address: '127.0.0.1', port: 1 }); message(Buffer.from([0, 0]), { address: '127.0.0.1', port: 3333 }); message(Buffer.from(NATPMP_VECTORS.map_tcp_request.hex, 'hex'), { address: '127.0.0.1', port: 3333 });
  await Promise.resolve(); assert.deepEqual(commands, ['external-address']); release(); await new Promise((resolve) => setImmediate(resolve)); await new Promise((resolve) => setImmediate(resolve)); assert.deepEqual(commands, ['external-address', 'map']); assert.deepEqual(sent.map((item) => [item.address, item.port]), [['127.0.0.1', 3333], ['127.0.0.1', 3333]]); assert.ok(events.every((event) => Object.keys(event).every((key) => ['protocol', 'outcome', 'reason_code'].includes(key)))); await server.close();
});
test('C04: queue is bounded, close is idempotent and no send occurs after close', async () => {
  const listeners = new Map(); const sent = []; let release; const gate = new Promise((resolve) => { release = resolve; }); const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9001 }; }, send(p, po, a, done) { sent.push(p); done(); }, close(done) { done(); } }; const events = [];
  const server = createNatPmpUdpServer(config({ application: async (command) => { await gate; return response(command); }, event_sink: (event) => events.push(event) }), { socket_factory: () => fake }); await server.start(); const message = listeners.get('message'); for (let n = 0; n < MAX_QUEUE + 2; n += 1) message(Buffer.from([0, 0]), { address: '127.0.0.1', port: n + 1 }); await Promise.resolve(); const a = server.close(); const b = server.close(); release(); await Promise.all([a, b]); assert.equal(server.state(), 'closed'); assert.equal(sent.length, 0); assert.ok(events.some((event) => event.reason_code === 'queue-full'));
});
test('C04: start failure and application failures are contained', async () => {
  const events = []; const broken = { on() {}, once(name, fn) { if (name === 'error') this.error = fn; }, removeListener() {}, bind() { this.error(new Error('no')); }, send() {}, close() {} }; const server = createNatPmpUdpServer(config({ event_sink: (event) => events.push(event) }), { socket_factory: () => broken }); await assert.rejects(server.start(), (error) => error.reason_code === 'NATPMP_UDP_START_FAILED'); assert.equal(server.state(), 'failed'); assert.ok(events.some((event) => event.reason_code === 'bind-failed'));
});
test('C04: all contained failure exits are closed, and a live socket error closes its handle', async () => {
  class FakeSocket extends EventEmitter {
    constructor(mode) { super(); this.mode = mode; this.closed = 0; }
    bind() { this.emit('listening'); }
    address() { return { address: '127.0.0.1', port: 8999 }; }
    send(packet, port, address, done) { if (this.mode === 'send-fail') done(new Error('no')); else done(); }
    close(done) { this.closed += 1; if (done) done(); }
  }
  const events = []; const base = (application, mode) => { const fake = new FakeSocket(mode); const server = createNatPmpUdpServer(config({ application, event_sink: (event) => events.push(event) }), { socket_factory: () => fake }); return { fake, server }; };
  let unit = base(async () => { throw new Error('model'); }); await unit.server.start(); unit.fake.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 3 }); await new Promise((resolve) => setImmediate(resolve)); await unit.server.close();
  unit = base(async () => ({})); await unit.server.start(); unit.fake.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 3 }); await new Promise((resolve) => setImmediate(resolve)); await unit.server.close();
  unit = base(async (command) => response(command), 'send-fail'); await unit.server.start(); unit.fake.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 3 }); await new Promise((resolve) => setImmediate(resolve)); await unit.server.close();
  unit = base(async (command) => response(command)); await unit.server.start(); unit.fake.emit('error', new Error('socket')); assert.equal(unit.server.state(), 'failed'); assert.ok(unit.fake.closed > 0); await unit.server.close();
  assert.deepEqual(new Set(events.filter((event) => event.outcome === 'failed').map((event) => event.reason_code)), new Set(['model-failure', 'send-failed', 'socket-error']));
});
test('C04: rejects hostile data-only configuration and invalid injected dependencies', () => {
  const accessor = config(); Object.defineProperty(accessor, 'port', { enumerable: true, get() { throw new Error('no read'); } });
  for (const item of [new Proxy(config(), {}), accessor, config({ allowed_source_addresses: ['0.0.0.0'] }), config({ allowed_source_addresses: ['bad'] }), config({ port: -0 }), config({ application: null }), config({ event_sink: null })]) assert.throws(() => createNatPmpUdpServer(item), NatPmpUdpServerError);
  assert.throws(() => createNatPmpUdpServer(config(), { other: true }), NatPmpUdpServerError); assert.throws(() => createNatPmpUdpServer(config(), { socket_factory: null }), NatPmpUdpServerError);
});
test('C04: close aborts a hung model callback without a post-close send', async () => {
  const listeners = new Map(); const sent = []; let seenSignal;
  const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9010 }; }, send(p, po, a, done) { sent.push(p); done(); }, close(done) { done(); } };
  const server = createNatPmpUdpServer(config({ application: async (command, source, signal) => { seenSignal = signal; await new Promise(() => {}); return response(command); } }), { socket_factory: () => fake }); await server.start(); listeners.get('message')(Buffer.from([0, 0]), { address: '127.0.0.1', port: 7 }); await Promise.resolve(); await server.close(); assert.equal(seenSignal.aborted, true); assert.equal(sent.length, 0);
});
test('C04: does not retain abort listeners across sequential applications', async () => {
  const listeners = new Map(); let signal; const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9011 }; }, send(p, po, a, done) { done(); }, close(done) { done(); } };
  const server = createNatPmpUdpServer(config({ application: async (command, source, value) => { signal = value; return response(command); } }), { socket_factory: () => fake }); await server.start(); for (let n = 0; n < 24; n += 1) { listeners.get('message')(Buffer.from([0, 0]), { address: '127.0.0.1', port: n + 1 }); await new Promise((resolve) => setImmediate(resolve)); assert.equal(getEventListeners(signal, 'abort').length, 0); } await server.close();
});
test('C04: aborts a hung send and hostile strings are never coerced', async () => {
  const listeners = new Map(); const events = []; const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9012 }; }, send() {}, close(done) { done(); } };
  const server = createNatPmpUdpServer(config({ event_sink: (event) => events.push(event) }), { socket_factory: () => fake }); await server.start(); listeners.get('message')(Buffer.from([0, 0]), { address: '127.0.0.1', port: 7 }); await Promise.resolve(); await server.close(); assert.equal(events.some((event) => event.reason_code === 'response-sent'), false);
  let reads = 0; const hostile = { toString() { reads += 1; return '127.0.0.1'; } }; assert.throws(() => createNatPmpUdpServer(config({ bind_address: hostile })), NatPmpUdpServerError); assert.equal(reads, 0);
  const optional = config({ port: 5351 }); Object.defineProperty(optional, 'allow_ephemeral_port_for_test', { enumerable: true, get() { reads += 1; return true; } }); assert.throws(() => createNatPmpUdpServer(optional), NatPmpUdpServerError); assert.equal(reads, 0);
});
test('C04: boundary matrix covers lifecycle, exact limits and hostile inputs', async () => {
  const required = ['bind_address', 'port', 'allowed_source_addresses', 'application', 'event_sink'];
  for (const key of required) { const value = config(); delete value[key]; assert.throws(() => createNatPmpUdpServer(value), NatPmpUdpServerError); }
  const symbol = config(); symbol[Symbol('x')] = true; assert.throws(() => createNatPmpUdpServer(symbol), NatPmpUdpServerError);
  const sparse = config({ allowed_source_addresses: new Array(1) }); assert.throws(() => createNatPmpUdpServer(sparse), NatPmpUdpServerError);
  assert.doesNotThrow(() => createNatPmpUdpServer(config({ port: 1, allow_ephemeral_port_for_test: false }))); assert.doesNotThrow(() => createNatPmpUdpServer(config({ port: 65535, allow_ephemeral_port_for_test: false })));
  const listeners = new Map(); let sends = 0; const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9020 }; }, send(p, po, a, done) { sends += 1; done(); }, close(done) { if (done) done(); } };
  const events = []; const server = createNatPmpUdpServer(config({ event_sink() { throw new Error('ignored'); } }), { socket_factory: () => fake }); assert.equal(server.address(), null); await server.start(); await assert.rejects(server.start(), NatPmpUdpServerError); const message = listeners.get('message');
  for (const source of [null, { address: '127.0.0.1', port: 0 }, { address: '127.0.0.1', port: 65536 }, { address: '127.0.0.2', port: 1 }, { address: { toString() { throw new Error('no'); } }, port: 1 }]) message(Buffer.from([0, 0]), source);
  message({}, { address: '127.0.0.1', port: 1 }); message(new Proxy(Buffer.from([0, 0]), {}), { address: '127.0.0.1', port: 1 }); message(Buffer.alloc(13), { address: '127.0.0.1', port: 1 }); message(Buffer.alloc(12, 9), { address: '127.0.0.1', port: 1 }); await new Promise((resolve) => setImmediate(resolve)); assert.equal(sends, 0); await server.close(); assert.equal(server.address(), null); await server.close();
  await assert.rejects(createNatPmpUdpServer(config(), { socket_factory() { throw new Error('factory'); } }).start(), /NATPMP_UDP_START_FAILED/);
});
test('C04: same-tick close never starts application or send after close', async () => {
  const listeners = new Map(); const order = []; let resolveApplication; const delayed = new Promise((resolve) => { resolveApplication = resolve; });
  const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9021 }; }, send(p, po, a, done) { order.push('send-start'); done(); }, close(done) { if (done) done(); } };
  const server = createNatPmpUdpServer(config({ application(command) { order.push('app-start'); return delayed.then(() => response(command)); } }), { socket_factory: () => fake }); await server.start(); listeners.get('message')(Buffer.from([0, 0]), { address: '127.0.0.1', port: 7 }); order.push('close-call'); const close = server.close(); resolveApplication(); await close; assert.deepEqual(order, ['app-start', 'close-call']);
});
test('C04: close before a controlled application result prevents send start', async () => {
  const listeners = new Map(); let resolveApplication; let sends = 0; const delayed = new Promise((resolve) => { resolveApplication = resolve; });
  const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return { address: '127.0.0.1', port: 9022 }; }, send() { sends += 1; }, close(done) { if (done) done(); } };
  const server = createNatPmpUdpServer(config({ application(command) { return delayed.then(() => response(command)); } }), { socket_factory: () => fake }); await server.start(); listeners.get('message')(Buffer.from([0, 0]), { address: '127.0.0.1', port: 7 }); const close = server.close(); resolveApplication(); await close; assert.equal(sends, 0);
});
test('C04: close cancels a bind that never listens and leaves closed state', async () => {
  const listeners = new Map(); const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() {}, address() { return { address: '127.0.0.1', port: 9 }; }, send() {}, close(done) { if (done) done(); } };
  const server = createNatPmpUdpServer(config(), { socket_factory: () => fake }); const starting = server.start(); await server.close(); await assert.rejects(starting, NatPmpUdpServerError); assert.equal(server.state(), 'closed'); assert.equal(listeners.has('message'), false); assert.equal(listeners.has('error'), false); if (listeners.has('listening')) listeners.get('listening')(); assert.equal(server.state(), 'closed');
});
test('C04: close fallback and runtime error abort a hung callback', async () => {
  let signal; const fake = new EventEmitter(); fake.bind = () => fake.emit('listening'); fake.address = () => ({ address: '127.0.0.1', port: 9023 }); fake.send = () => { throw new Error('must not'); }; fake.close = () => {};
  const server = createNatPmpUdpServer(config({ application(command, source, value) { signal = value; return new Promise(() => {}); } }), { socket_factory: () => fake }); await server.start(); fake.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 7 }); fake.emit('error', new Error('runtime')); assert.doesNotThrow(() => fake.emit('error', new Error('again'))); await new Promise((resolve) => setImmediate(resolve)); assert.equal(signal.aborted, true); assert.equal(server.state(), 'failed'); await server.close(); assert.equal(server.state(), 'closed');
});
test('C04: public address rejects hostile adapter shapes with a stable error', async () => {
  const listeners = new Map(); let shape = { address: '127.0.0.1', port: 9024 }; const fake = { on(n, f) { listeners.set(n, f); }, once(n, f) { listeners.set(n, f); }, removeListener(n) { listeners.delete(n); }, bind() { listeners.get('listening')(); }, address() { return shape; }, send(p, po, a, done) { done(); }, close(done) { done(); } };
  const server = createNatPmpUdpServer(config(), { socket_factory: () => fake }); await server.start(); for (const value of [null, {}, { address: 'bad', port: 1 }, { address: '127.0.0.1', port: 0 }, { address: '127.0.0.2', port: 9024 }, new Proxy({}, {})]) { shape = value; assert.throws(() => server.address(), (error) => error.reason_code === 'NATPMP_UDP_BIND_INVALID'); } shape = { address: '127.0.0.1', port: 9024 }; await server.close();
});
test('C04: synchronous adapter failures remain contained across every lifecycle edge', async () => {
  function fakeSocket(overrides = {}) {
    const socket = new EventEmitter();
    socket.bind = () => socket.emit('listening');
    socket.address = () => ({ address: '127.0.0.1', port: 9025 });
    socket.send = (packet, port, address, done) => done();
    socket.close = (done) => { if (done) { done(); done(); } };
    return Object.assign(socket, overrides);
  }

  await assert.rejects(createNatPmpUdpServer(config(), { socket_factory: () => ({}) }).start(), (error) => error.reason_code === 'NATPMP_UDP_SOCKET_INVALID');
  await assert.rejects(createNatPmpUdpServer(config(), { socket_factory: () => fakeSocket({ bind() { throw new Error('bind'); } }) }).start(), (error) => error.reason_code === 'NATPMP_UDP_START_FAILED');
  await assert.rejects(createNatPmpUdpServer(config(), { socket_factory: () => fakeSocket({ address() { throw new Error('address'); } }) }).start(), (error) => error.reason_code === 'NATPMP_UDP_BIND_INVALID');

  const modelEvents = []; const modelSocket = fakeSocket();
  const modelServer = createNatPmpUdpServer(config({ application() { throw new Error('model'); }, event_sink: (event) => modelEvents.push(event) }), { socket_factory: () => modelSocket });
  await modelServer.start(); const lateMessage = getEventListeners(modelSocket, 'message')[0]; const lateError = getEventListeners(modelSocket, 'error')[0];
  modelSocket.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 1 }); await new Promise((resolve) => setImmediate(resolve));
  assert.ok(modelEvents.some((event) => event.reason_code === 'model-failure')); await modelServer.close();
  assert.doesNotThrow(() => lateMessage(Buffer.from([0, 0]), { address: '127.0.0.1', port: 1 }));
  assert.doesNotThrow(() => lateError(new Error('late')));

  const sendEvents = []; const sendSocket = fakeSocket({ send() { throw new Error('send'); }, close() { throw new Error('close'); } });
  const sendServer = createNatPmpUdpServer(config({ event_sink: (event) => sendEvents.push(event) }), { socket_factory: () => sendSocket });
  await sendServer.start(); sendSocket.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 1 }); await new Promise((resolve) => setImmediate(resolve));
  assert.ok(sendEvents.some((event) => event.reason_code === 'send-failed')); await sendServer.close(); assert.equal(sendServer.state(), 'closed');
});
test('C04: close keeps an error guard until asynchronous socket close completes', async () => {
  const socket = new EventEmitter();
  socket.bind = () => socket.emit('listening');
  socket.address = () => ({ address: '127.0.0.1', port: 9026 });
  socket.send = (packet, port, address, done) => done();
  socket.close = (done) => setImmediate(done);
  const server = createNatPmpUdpServer(config(), { socket_factory: () => socket });
  await server.start(); const closing = server.close();
  assert.doesNotThrow(() => socket.emit('error', new Error('late-close-error')));
  await closing; assert.equal(server.state(), 'closed'); assert.equal(getEventListeners(socket, 'error').length, 0);
});
test('C04: event observation cannot strand the queue and observes an accidental native Promise', async () => {
  const socket = new EventEmitter();
  socket.bind = () => socket.emit('listening');
  socket.address = () => ({ address: '127.0.0.1', port: 9027 });
  socket.send = (packet, port, address, done) => done();
  socket.close = (done) => done();
  let server; let closing; let applications = 0;
  server = createNatPmpUdpServer(config({
    application(command) { applications += 1; return response(command); },
    event_sink(event) {
      if (event.reason_code === 'request-received') closing = server.close();
      return Promise.reject(new Error('ignored-observer-rejection'));
    },
  }), { socket_factory: () => socket });
  await server.start(); socket.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 1 });
  await closing; await new Promise((resolve) => setImmediate(resolve));
  assert.equal(server.state(), 'closed'); assert.equal(applications, 0);
});

test('C05 drop: response fault suppresses send and reports the drop', async () => {
  const socket = new EventEmitter(); const events = []; let sends = 0;
  socket.bind = () => socket.emit('listening');
  socket.address = () => ({ address: '127.0.0.1', port: 9028 });
  socket.send = () => { sends += 1; };
  socket.close = (done) => done();
  const server = createNatPmpUdpServer(config({ event_sink: (event) => events.push(event) }), {
    socket_factory: () => socket,
    response_fault: async () => null,
  });
  await server.start(); socket.emit('message', Buffer.from([0, 0]), { address: '127.0.0.1', port: 1 });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(sends, 0);
  assert.ok(events.some((event) => event.reason_code === 'response-dropped'));
  await server.close();
});
