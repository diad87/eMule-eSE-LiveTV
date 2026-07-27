'use strict';

// C04 deliberately keeps UDP at the edge.  Commands and response descriptors
// cross this boundary as small values; the mapping model stays injected.
const dgram = require('node:dgram');
const { types } = require('node:util');
const { decodeNatPmpRequest } = require('./natpmp_request_decoder');
const { encodeNatPmpResponse } = require('./natpmp_response_encoder');

const MAX_DATAGRAM_BYTES = 12;
const MAX_QUEUE = 32;
const IPV4 = /^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;
const objectPrototype = Object.prototype;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const promiseThen = Promise.prototype.then;

class NatPmpUdpServerError extends Error {
  constructor(reasonCode) { super(reasonCode); this.name = 'NatPmpUdpServerError'; this.reason_code = reasonCode; }
}
function fail(code) { throw new NatPmpUdpServerError(code); }
function dataObject(value) { return value !== null && typeof value === 'object' && !types.isProxy(value) && Object.getPrototypeOf(value) === objectPrototype; }
function ownData(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable ? descriptor.value : undefined;
}
function strictConfig(input) {
  if (!dataObject(input) || Object.getOwnPropertySymbols(input).length) fail('NATPMP_UDP_CONFIG_INVALID');
  const allowed = new Set(['bind_address', 'port', 'allowed_source_addresses', 'application', 'event_sink', 'allow_ephemeral_port_for_test']);
  const names = Object.getOwnPropertyNames(input);
  if (names.some((name) => !allowed.has(name))) fail('NATPMP_UDP_CONFIG_INVALID');
  for (const name of names) { const descriptor = Object.getOwnPropertyDescriptor(input, name); if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail('NATPMP_UDP_CONFIG_INVALID'); }
  const bindAddress = ownData(input, 'bind_address');
  const port = ownData(input, 'port');
  const sources = ownData(input, 'allowed_source_addresses');
  const application = ownData(input, 'application');
  const eventSink = ownData(input, 'event_sink');
  const ephemeral = ownData(input, 'allow_ephemeral_port_for_test');
  if (typeof bindAddress !== 'string' || !IPV4.test(bindAddress) || bindAddress === '0.0.0.0' || !Number.isInteger(port) || Object.is(port, -0) ||
    (port === 0 ? ephemeral !== true : port < 1 || port > 65535) || typeof application !== 'function' || typeof eventSink !== 'function') fail('NATPMP_UDP_CONFIG_INVALID');
  if (types.isProxy(sources) || !Array.isArray(sources) || Object.getPrototypeOf(sources) !== Array.prototype || Object.getOwnPropertySymbols(sources).length) fail('NATPMP_UDP_CONFIG_INVALID');
  const lengthDescriptor = Object.getOwnPropertyDescriptor(sources, 'length');
  const sourceLength = lengthDescriptor && Object.hasOwn(lengthDescriptor, 'value') && lengthDescriptor.enumerable === false ? lengthDescriptor.value : undefined;
  if (!Number.isSafeInteger(sourceLength) || sourceLength === 0 || Object.getOwnPropertyNames(sources).length !== sourceLength + 1) fail('NATPMP_UDP_CONFIG_INVALID');
  const values = [];
  for (let index = 0; index < sourceLength; index += 1) {
    const value = ownData(sources, String(index));
    if (typeof value !== 'string' || !IPV4.test(value) || value === '0.0.0.0') fail('NATPMP_UDP_CONFIG_INVALID');
    values.push(value);
  }
  return Object.freeze({ bindAddress, port, allowedSources: new Set(values), application, eventSink });
}
function sourceSnapshot(value, allowedSources) {
  if (!dataObject(value)) fail('NATPMP_UDP_SOURCE_INVALID');
  const address = ownData(value, 'address'); const port = ownData(value, 'port');
  if (typeof address !== 'string' || !IPV4.test(address) || !allowedSources.has(address) || !Number.isInteger(port) || port < 1 || port > 65535) fail('NATPMP_UDP_SOURCE_INVALID');
  return Object.freeze({ address, port });
}
function boundedPacket(packet) {
  // The dgram implementation supplies a Buffer.  Test adapters are hostile by
  // default, therefore no user-visible byte property is read here.
  if (types.isProxy(packet) || !types.isUint8Array(packet)) fail('NATPMP_UDP_PACKET_INVALID');
  let length;
  try { length = typedArrayByteLengthGetter.call(packet); } catch { fail('NATPMP_UDP_PACKET_INVALID'); }
  if (length > MAX_DATAGRAM_BYTES) fail('NATPMP_UDP_PACKET_OVERSIZE');
  return packet;
}
function socketAddressSnapshot(socket) {
  let value;
  try { value = socket.address(); } catch { fail('NATPMP_UDP_BIND_INVALID'); }
  if (!dataObject(value)) fail('NATPMP_UDP_BIND_INVALID');
  const address = ownData(value, 'address'); const port = ownData(value, 'port');
  if (typeof address !== 'string' || !IPV4.test(address) || !Number.isInteger(port) || port < 1 || port > 65535) fail('NATPMP_UDP_BIND_INVALID');
  return Object.freeze({ address, port });
}
function safeEvent(sink, outcome, reason) {
  // `event_sink` is an injected, trusted, synchronous void observer.  A normal
  // Promise return is observed defensively, but callback-created asynchronous
  // work (including a Promise hidden behind a Proxy) remains the callback's
  // responsibility: JavaScript provides no safe way to recover a Proxy target.
  try {
    const result = sink(Object.freeze({ protocol: 'natpmp', outcome, reason_code: reason }));
    if (types.isPromise(result)) {
      try { promiseThen.call(result, undefined, () => {}); } catch {}
    }
  } catch { /* observability never changes protocol behaviour */ }
}
function bindSocket(socket, port, address, signal) {
  return new Promise((resolve, reject) => {
    const onError = (error) => { cleanup(); reject(error); };
    const onListening = () => { cleanup(); resolve(); };
    const onAbort = () => { cleanup(); reject(new NatPmpUdpServerError('NATPMP_UDP_START_ABORTED')); };
    const cleanup = () => { socket.removeListener('error', onError); socket.removeListener('listening', onListening); signal.removeEventListener('abort', onAbort); };
    socket.once('error', onError); socket.once('listening', onListening);
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) { onAbort(); return; }
    try { socket.bind(port, address); } catch (error) { cleanup(); reject(error); }
  });
}
function sendSocket(socket, packet, source) {
  return new Promise((resolve, reject) => {
    try { socket.send(packet, source.port, source.address, (error) => error ? reject(error) : resolve()); } catch (error) { reject(error); }
  });
}
function closeSocketBounded(socket) {
  return new Promise((resolve) => {
    let complete = false;
    let fallback;
    const finish = () => { if (complete) return; complete = true; if (fallback) clearImmediate(fallback); resolve(); };
    fallback = setImmediate(finish);
    try { socket.close(finish); } catch { finish(); }
    // Fake/adversarial adapters may violate dgram's callback contract.  Do not
    // let that turn close() into an unbounded lifecycle wait.
  });
}
function raceWithAbort(start, signal) {
  // Start synchronously after the first abort check.  Deferring `start` to a
  // microtask would permit close() to win the gap and then run an application
  // or send effect after close had returned.
  if (signal.aborted) return Promise.resolve({ aborted: true });
  let task;
  try { task = Promise.resolve(start()); } catch { return Promise.resolve({ failed: true }); }
  task.catch(() => {});
  if (signal.aborted) return Promise.resolve({ aborted: true });
  return new Promise((resolve) => {
    let complete = false;
    const finish = (result) => { if (complete) return; complete = true; signal.removeEventListener('abort', onAbort); resolve(result); };
    const onAbort = () => finish({ aborted: true });
    signal.addEventListener('abort', onAbort, { once: true });
    task.then((value) => finish({ value }), () => finish({ failed: true }));
  });
}

function createNatPmpUdpServer(configInput, dependencies = {}) {
  const config = strictConfig(configInput);
  if (!dataObject(dependencies) || Object.getOwnPropertySymbols(dependencies).length || Object.getOwnPropertyNames(dependencies).some((name) => name !== 'socket_factory')) fail('NATPMP_UDP_DEPENDENCIES_INVALID');
  const hasFactory = Object.hasOwn(dependencies, 'socket_factory');
  const factory = hasFactory ? ownData(dependencies, 'socket_factory') : (() => dgram.createSocket('udp4'));
  if (hasFactory && typeof factory !== 'function') fail('NATPMP_UDP_DEPENDENCIES_INVALID');
  let state = 'new'; let socket; let queue = []; let active = false; let closePromise; let idleResolvers = []; const aborter = new AbortController();
  const idle = () => { if (!active && queue.length === 0) { const resolvers = idleResolvers; idleResolvers = []; resolvers.forEach((resolve) => resolve()); } };
  const waitIdle = () => (!active && queue.length === 0 ? Promise.resolve() : new Promise((resolve) => idleResolvers.push(resolve)));
  async function process(item) {
    const command = item.command;
    let descriptor;
    // The application owns mapping/ownership policy.  It receives a frozen
    // source snapshot for that purpose; the event sink never receives it.
    // The callback can ignore abort, so it is observed separately and raced
    // with the server abort.  The helper removes its abort listener on either
    // outcome and observes a late rejection.
    const result = await raceWithAbort(() => config.application(command, item.source, aborter.signal), aborter.signal);
    if (result.aborted) { safeEvent(config.eventSink, 'rejected', 'closed'); return; }
    if (result.failed) { safeEvent(config.eventSink, 'failed', 'model-failure'); return; }
    descriptor = result.value;
    if (state !== 'running') { safeEvent(config.eventSink, 'rejected', 'closed'); return; }
    let response;
    try { response = encodeNatPmpResponse(descriptor); } catch { safeEvent(config.eventSink, 'failed', 'model-failure'); return; }
    const sent = await raceWithAbort(() => sendSocket(socket, response, item.source), aborter.signal);
    if (sent.aborted) { safeEvent(config.eventSink, 'rejected', 'closed'); return; }
    if (sent.failed) { safeEvent(config.eventSink, 'failed', 'send-failed'); return; }
    safeEvent(config.eventSink, 'succeeded', 'response-sent');
  }
  async function drain() {
    if (active) return; active = true;
    while (state === 'running' && queue.length) await process(queue.shift());
    active = false; idle();
  }
  function receive(packet, rinfo) {
    if (state !== 'running') return;
    try { boundedPacket(packet); } catch (error) { safeEvent(config.eventSink, 'rejected', error.reason_code === 'NATPMP_UDP_PACKET_OVERSIZE' ? 'oversize-datagram' : 'invalid-request'); return; }
    let source;
    try { source = sourceSnapshot(rinfo, config.allowedSources); } catch { safeEvent(config.eventSink, 'rejected', 'invalid-source'); return; }
    let command;
    try { command = decodeNatPmpRequest(packet); } catch { safeEvent(config.eventSink, 'rejected', 'invalid-request'); return; }
    if (queue.length >= MAX_QUEUE) { safeEvent(config.eventSink, 'rejected', 'queue-full'); return; }
    queue.push(Object.freeze({ command, source }));
    safeEvent(config.eventSink, 'succeeded', 'request-received');
    if (state !== 'running') { idle(); return; }
    void drain();
  }
  function onSocketError() {
    if (state === 'running') {
      state = 'failed'; queue = []; safeEvent(config.eventSink, 'failed', 'socket-error');
      aborter.abort();
      // Close the erroring handle and stop message intake immediately. Keep
      // the error listener until explicit close so a second error cannot
      // become an unhandled EventEmitter error; close removes it.
      try { socket.removeListener('message', receive); socket.close(); } catch {}
      idle();
    }
  }
  return Object.freeze({
    async start() {
      if (state !== 'new') fail('NATPMP_UDP_STATE_INVALID');
      state = 'starting';
      try { socket = factory(); if (!socket || typeof socket.on !== 'function' || typeof socket.bind !== 'function' || typeof socket.send !== 'function' || typeof socket.close !== 'function') fail('NATPMP_UDP_SOCKET_INVALID'); socket.on('error', onSocketError); socket.on('message', receive); await bindSocket(socket, config.port, config.bindAddress, aborter.signal); const bound = socketAddressSnapshot(socket); if (bound.address !== config.bindAddress) fail('NATPMP_UDP_BIND_INVALID'); if (state !== 'starting') fail('NATPMP_UDP_STATE_INVALID'); state = 'running'; safeEvent(config.eventSink, 'succeeded', 'bound'); return bound; }
      catch (error) { const closing = state === 'closing' || state === 'closed'; if (!closing) { state = 'failed'; safeEvent(config.eventSink, 'failed', 'bind-failed'); try { if (socket) { socket.removeListener('message', receive); socket.removeListener('error', onSocketError); socket.close(); } } catch {} } if (error instanceof NatPmpUdpServerError) throw error; throw new NatPmpUdpServerError('NATPMP_UDP_START_FAILED'); }
    },
    address() { if (!socket || (state !== 'running' && state !== 'closing')) return null; const bound = socketAddressSnapshot(socket); if (bound.address !== config.bindAddress) fail('NATPMP_UDP_BIND_INVALID'); return bound; },
    async close() {
      if (closePromise) return closePromise;
      closePromise = (async () => { state = 'closing'; queue = []; aborter.abort(); if (socket) { try { socket.removeListener('message', receive); await closeSocketBounded(socket); socket.removeListener('error', onSocketError); } catch {} } await waitIdle(); state = 'closed'; safeEvent(config.eventSink, 'succeeded', 'closed'); })();
      return closePromise;
    },
    state() { return state; },
    limits() { return Object.freeze({ max_datagram_bytes: MAX_DATAGRAM_BYTES, max_queue: MAX_QUEUE }); },
  });
}

module.exports = Object.freeze({ NatPmpUdpServerError, createNatPmpUdpServer, MAX_DATAGRAM_BYTES, MAX_QUEUE });
