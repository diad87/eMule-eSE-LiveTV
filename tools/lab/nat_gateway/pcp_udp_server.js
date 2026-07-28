'use strict';

// D05 keeps packet metadata at the UDP edge. Mapping state, ownership and
// clocks stay behind injected ports.
const dgram = require('node:dgram');
const net = require('node:net');
const { types } = require('node:util');
const { decodePcpMapRequest } = require('./pcp_map_request_decoder');
const { encodePcpMapResponse } = require('./pcp_map_response_encoder');
const {
  decodePcpAnnounceRequest,
  encodePcpAnnounceResponse,
} = require('./pcp_announce_codec');

const MAX_DATAGRAM_BYTES = 1100;
const MAX_QUEUE = 32;
const objectPrototype = Object.prototype;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const bufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const arrayBufferLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const promiseThen = Promise.prototype.then;

class PcpUdpServerError extends Error {
  constructor(reasonCode) {
    super(reasonCode);
    this.name = 'PcpUdpServerError';
    this.reason_code = reasonCode;
  }
}

function fail(code) { throw new PcpUdpServerError(code); }
function dataObject(value) {
  return value !== null && typeof value === 'object' &&
    !types.isProxy(value) && Object.getPrototypeOf(value) === objectPrototype;
}
function ownData(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && descriptor.enumerable &&
    Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}
function canonicalAddress(value) {
  if (typeof value !== 'string') fail('PCP_UDP_ADDRESS_INVALID');
  const family = net.isIP(value);
  if (family === 0) fail('PCP_UDP_ADDRESS_INVALID');
  let address;
  try {
    address = new net.SocketAddress({
      address: value,
      port: 1,
      family: family === 4 ? 'ipv4' : 'ipv6',
    }).address;
  } catch {
    fail('PCP_UDP_ADDRESS_INVALID');
  }
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  return Object.freeze({
    address: mapped ? mapped[1] : address,
    family,
  });
}
function strictArray(input) {
  if (types.isProxy(input) || !Array.isArray(input) ||
    Object.getPrototypeOf(input) !== Array.prototype ||
    Object.getOwnPropertySymbols(input).length) {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  const length = Object.getOwnPropertyDescriptor(input, 'length');
  if (!length || !Object.hasOwn(length, 'value') ||
    !Number.isSafeInteger(length.value) || length.value < 1 ||
    Object.getOwnPropertyNames(input).length !== length.value + 1) {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  const values = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')) fail('PCP_UDP_CONFIG_INVALID');
    values.push(canonicalAddress(descriptor.value).address);
  }
  return values;
}
function strictConfig(input) {
  if (!dataObject(input) || Object.getOwnPropertySymbols(input).length) {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  const allowed = new Set([
    'bind_address', 'port', 'allowed_source_addresses', 'application',
    'epoch_provider', 'event_sink', 'allow_ephemeral_port_for_test',
  ]);
  const names = Object.getOwnPropertyNames(input);
  if (names.some((name) => !allowed.has(name))) fail('PCP_UDP_CONFIG_INVALID');
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')) fail('PCP_UDP_CONFIG_INVALID');
  }
  const bind = canonicalAddress(ownData(input, 'bind_address'));
  if (bind.address === '0.0.0.0' || bind.address === '::') {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  if (bind.family === 6 && net.isIP(bind.address) === 4) {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  if ((bind.family === 4 &&
      Number(bind.address.split('.')[0]) >= 224) ||
    (bind.family === 6 && bind.address.toLowerCase().startsWith('ff'))) {
    fail('PCP_UDP_CONFIG_INVALID');
  }
  const port = ownData(input, 'port');
  const ephemeral = ownData(input, 'allow_ephemeral_port_for_test');
  const application = ownData(input, 'application');
  const epochProvider = ownData(input, 'epoch_provider');
  const eventSink = ownData(input, 'event_sink');
  if (!Number.isInteger(port) || Object.is(port, -0) ||
    (port === 0 ? ephemeral !== true : port < 1 || port > 65535) ||
    typeof application !== 'function' || typeof epochProvider !== 'function' ||
    typeof eventSink !== 'function') fail('PCP_UDP_CONFIG_INVALID');
  const sources = strictArray(ownData(input, 'allowed_source_addresses'));
  return Object.freeze({
    bind, port, application, epochProvider, eventSink,
    allowedSources: new Set(sources),
  });
}
function packetSnapshot(packet) {
  if (types.isProxy(packet) || !types.isUint8Array(packet)) {
    fail('PCP_UDP_PACKET_INVALID');
  }
  try {
    const backing = bufferGetter.call(packet);
    const offset = byteOffsetGetter.call(packet);
    const length = byteLengthGetter.call(packet);
    const backingLength = arrayBufferLengthGetter.call(backing);
    if (!types.isArrayBuffer(backing) ||
      offset < 0 || length < 0 || offset > backingLength ||
      length > backingLength - offset) {
      fail('PCP_UDP_PACKET_INVALID');
    }
    const boundedLength = Math.min(length, MAX_DATAGRAM_BYTES);
    return Object.freeze({
      bytes: Buffer.from(new Uint8Array(backing, offset, boundedLength)),
      oversize: length > MAX_DATAGRAM_BYTES,
    });
  } catch (error) {
    if (error instanceof PcpUdpServerError) throw error;
    fail('PCP_UDP_PACKET_INVALID');
  }
}
function sourceSnapshot(input, config) {
  if (!dataObject(input)) fail('PCP_UDP_SOURCE_INVALID');
  const address = canonicalAddress(ownData(input, 'address')).address;
  const port = ownData(input, 'port');
  if (!config.allowedSources.has(address) || !Number.isInteger(port) ||
    Object.is(port, -0) || port < 1 || port > 65535) {
    fail('PCP_UDP_SOURCE_INVALID');
  }
  return Object.freeze({ address, port });
}
function epoch(config) {
  let value;
  try { value = config.epochProvider(); } catch { fail('PCP_UDP_EPOCH_INVALID'); }
  if (!Number.isInteger(value) || Object.is(value, -0) ||
    value < 0 || value > 0xffffffff) fail('PCP_UDP_EPOCH_INVALID');
  return value;
}
function safeEvent(sink, outcome, reason) {
  try {
    const result = sink(Object.freeze({
      protocol: 'pcp', outcome, reason_code: reason,
    }));
    if (types.isPromise(result)) {
      try { promiseThen.call(result, undefined, () => {}); } catch {}
    }
  } catch {}
}
function raceWithAbort(start, signal) {
  if (signal.aborted) return Promise.resolve({ aborted: true });
  let task;
  try { task = Promise.resolve(start()); } catch {
    return Promise.resolve({ failed: true });
  }
  task.catch(() => {});
  if (signal.aborted) return Promise.resolve({ aborted: true });
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      signal.removeEventListener('abort', onAbort);
      resolve(result);
    };
    const onAbort = () => finish({ aborted: true });
    signal.addEventListener('abort', onAbort, { once: true });
    task.then((value) => finish({ value }), () => finish({ failed: true }));
  });
}
function bindSocket(socket, port, address, signal) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.removeListener('error', onError);
      socket.removeListener('listening', onListening);
      signal.removeEventListener('abort', onAbort);
    };
    const onError = (error) => { cleanup(); reject(error); };
    const onListening = () => { cleanup(); resolve(); };
    const onAbort = () => {
      cleanup();
      reject(new PcpUdpServerError('PCP_UDP_START_ABORTED'));
    };
    socket.once('error', onError);
    socket.once('listening', onListening);
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) { onAbort(); return; }
    try { socket.bind(port, address); } catch (error) { cleanup(); reject(error); }
  });
}
function closeSocket(socket) {
  return new Promise((resolve) => {
    let done = false;
    let fallback;
    const finish = () => {
      if (done) return;
      done = true;
      if (fallback) clearImmediate(fallback);
      resolve();
    };
    fallback = setImmediate(finish);
    try { socket.close(finish); } catch { finish(); }
  });
}
function sendSocket(socket, packet, source) {
  return new Promise((resolve, reject) => {
    try {
      socket.send(packet, source.port, source.address,
        (error) => error ? reject(error) : resolve());
    } catch (error) { reject(error); }
  });
}
function parsedMapError(error) {
  return !new Set([
    'PCP_INPUT_INVALID', 'PCP_SIZE_INVALID', 'PCP_ALIGNMENT_INVALID',
    'PCP_VERSION_INVALID', 'PCP_OPCODE_INVALID', 'PCP_OPTION_MALFORMED',
  ]).has(error.reason_code);
}
function addressText(bytes) {
  let mapped = true;
  for (let offset = 8; offset < 18; offset += 1) {
    if (bytes[offset] !== 0) mapped = false;
  }
  if (mapped && bytes[18] === 0xff && bytes[19] === 0xff) {
    return `${bytes[20]}.${bytes[21]}.${bytes[22]}.${bytes[23]}`;
  }
  const groups = [];
  for (let offset = 8; offset < 24; offset += 2) {
    groups.push((bytes[offset] << 8) | bytes[offset + 1]);
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== 0) { start += 1; continue; }
    let end = start + 1;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const parts = groups.map((group) => group.toString(16));
  if (bestLength < 2) return parts.join(':');
  const left = parts.slice(0, bestStart).join(':');
  const right = parts.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}
function decode(bytes) {
  if (bytes.length < 2) fail('PCP_UDP_REQUEST_INVALID');
  if ((bytes[1] & 0x80) !== 0) fail('PCP_UDP_REQUEST_INVALID');
  if (bytes.length < 24) fail('PCP_UDP_REQUEST_INVALID');
  if ((bytes.length & 3) !== 0) {
    return Object.freeze({
      kind: bytes[1] === 1 ? 'map' :
        (bytes[1] === 0 ? 'announce' : 'generic'),
      error: Object.freeze({ result_code: 3, request_parsed: false }),
    });
  }
  if (bytes[0] !== 2) {
    return Object.freeze({
      kind: bytes[1] === 1 ? 'map' :
        (bytes[1] === 0 ? 'announce' : 'generic'),
      error: Object.freeze({ result_code: 1, request_parsed: false }),
    });
  }
  if (bytes[1] === 0) {
    try {
      return Object.freeze({
        kind: 'announce',
        command: decodePcpAnnounceRequest(bytes),
      });
    } catch (error) {
      if (!Number.isInteger(error.pcp_result_code)) throw error;
      return Object.freeze({
        kind: 'announce',
        error: Object.freeze({
          result_code: error.pcp_result_code,
          request_parsed: error.request_parsed === true,
        }),
      });
    }
  }
  if (bytes[1] === 1) {
    try {
      return Object.freeze({
        kind: 'map',
        command: decodePcpMapRequest(bytes),
      });
    } catch (error) {
      if (!Number.isInteger(error.pcp_result_code)) throw error;
      return Object.freeze({
        kind: 'map',
        error: Object.freeze({
          result_code: error.pcp_result_code,
          request_parsed: parsedMapError(error),
        }),
      });
    }
  }
  return Object.freeze({
    kind: 'generic',
    error: Object.freeze({ result_code: 4, request_parsed: false }),
  });
}
function genericErrorResponse(bytes, resultCode, requestParsed, valueEpoch) {
  const out = Buffer.alloc((bytes.length + 3) & ~3);
  bytes.copy(out);
  out[0] = 2;
  out[1] |= 0x80;
  out[2] = 0;
  out[3] = resultCode;
  out.fill(0, 4, 8);
  out[8] = valueEpoch >>> 24;
  out[9] = valueEpoch >>> 16;
  out[10] = valueEpoch >>> 8;
  out[11] = valueEpoch;
  if (requestParsed) out.fill(0, 12, 24);
  return out;
}
function errorResponse(kind, bytes, resultCode, requestParsed, valueEpoch) {
  if (kind === 'map' && bytes.length >= 60 &&
    (bytes.length & 3) === 0) {
    return encodePcpMapResponse({
      mode: 'error-echo',
      response_type: 'map',
      result_code: resultCode,
      epoch: valueEpoch,
      lifetime_seconds: 0,
      request_wire: bytes,
      request_parsed: requestParsed,
    });
  }
  if (kind === 'announce' && bytes.length >= 24 &&
    (bytes.length & 3) === 0) return encodePcpAnnounceResponse({
    mode: 'error-echo',
    response_type: 'announce',
    result_code: resultCode,
    epoch: valueEpoch,
    request_wire: bytes,
    request_parsed: requestParsed,
  });
  return genericErrorResponse(bytes, resultCode, requestParsed, valueEpoch);
}
function responseFor(kind, descriptor, valueEpoch) {
  const response = kind === 'map' ?
    encodePcpMapResponse(descriptor) :
    encodePcpAnnounceResponse(descriptor);
  response[8] = valueEpoch >>> 24;
  response[9] = valueEpoch >>> 16;
  response[10] = valueEpoch >>> 8;
  response[11] = valueEpoch;
  return response;
}

function createPcpUdpServer(configInput, dependencies = {}) {
  const config = strictConfig(configInput);
  if (!dataObject(dependencies) || Object.getOwnPropertySymbols(dependencies).length ||
    Object.getOwnPropertyNames(dependencies).some((name) => name !== 'socket_factory')) {
    fail('PCP_UDP_DEPENDENCIES_INVALID');
  }
  const hasFactory = Object.hasOwn(dependencies, 'socket_factory');
  const factory = hasFactory ? ownData(dependencies, 'socket_factory') :
    (() => dgram.createSocket(config.bind.family === 4 ? 'udp4' : 'udp6'));
  if (hasFactory && typeof factory !== 'function') {
    fail('PCP_UDP_DEPENDENCIES_INVALID');
  }
  let state = 'new';
  let socket;
  let queue = [];
  let active = false;
  let closePromise;
  let idleResolvers = [];
  const aborter = new AbortController();
  const idle = () => {
    if (!active && queue.length === 0) {
      const resolvers = idleResolvers;
      idleResolvers = [];
      for (const resolve of resolvers) resolve();
    }
  };
  const waitIdle = () => !active && queue.length === 0 ?
    Promise.resolve() : new Promise((resolve) => idleResolvers.push(resolve));
  async function process(item) {
    let response;
    if (item.error) {
      try {
        response = errorResponse(item.kind, item.bytes,
          item.error.result_code, item.error.request_parsed, epoch(config));
      } catch (error) {
        safeEvent(config.eventSink,
          error.reason_code === 'PCP_UDP_EPOCH_INVALID' ? 'failed' : 'rejected',
          error.reason_code === 'PCP_UDP_EPOCH_INVALID' ?
            'epoch-failure' : 'invalid-request');
        return;
      }
    } else {
      const result = await raceWithAbort(
        () => config.application(item.command, item.source, aborter.signal),
        aborter.signal,
      );
      if (result.aborted) {
        safeEvent(config.eventSink, 'rejected', 'closed');
        return;
      }
      if (result.failed) {
        safeEvent(config.eventSink, 'failed', 'model-failure');
        return;
      }
      try {
        response = responseFor(item.kind, result.value, epoch(config));
      } catch {
        safeEvent(config.eventSink, 'failed', 'model-failure');
        return;
      }
    }
    if (state !== 'running') {
      safeEvent(config.eventSink, 'rejected', 'closed');
      return;
    }
    const sent = await raceWithAbort(
      () => sendSocket(socket, response, item.source), aborter.signal);
    if (sent.aborted) safeEvent(config.eventSink, 'rejected', 'closed');
    else if (sent.failed) safeEvent(config.eventSink, 'failed', 'send-failed');
    else safeEvent(config.eventSink, 'succeeded', 'response-sent');
  }
  async function drain() {
    if (active) return;
    active = true;
    while (state === 'running' && queue.length) await process(queue.shift());
    active = false;
    idle();
  }
  function receive(packet, rinfo) {
    if (state !== 'running') return;
    let snapshot;
    try { snapshot = packetSnapshot(packet); } catch {
      safeEvent(config.eventSink, 'rejected', 'invalid-request');
      return;
    }
    const { bytes } = snapshot;
    let source;
    try { source = sourceSnapshot(rinfo, config); } catch {
      safeEvent(config.eventSink, 'rejected', 'invalid-source');
      return;
    }
    let decoded;
    if (snapshot.oversize) {
      if (bytes.length < 2 || (bytes[1] & 0x80) !== 0) {
        safeEvent(config.eventSink, 'rejected', 'invalid-request');
        return;
      }
      decoded = Object.freeze({
        kind: bytes[1] === 1 ? 'map' :
          (bytes[1] === 0 ? 'announce' : 'generic'),
        error: Object.freeze({ result_code: 3, request_parsed: false }),
      });
      safeEvent(config.eventSink, 'rejected', 'oversize-datagram');
    } else {
      try { decoded = decode(bytes); } catch {
        safeEvent(config.eventSink, 'rejected', 'invalid-request');
        return;
      }
    }
    if (bytes.length >= 24 &&
      addressText(bytes) !== source.address) {
      decoded = Object.freeze({
        kind: decoded.kind,
        error: Object.freeze({
          result_code: 12,
          request_parsed: true,
        }),
      });
      safeEvent(config.eventSink, 'rejected', 'address-mismatch');
    }
    if (queue.length >= MAX_QUEUE) {
      safeEvent(config.eventSink, 'rejected', 'queue-full');
      return;
    }
    queue.push(Object.freeze({ bytes, source, ...decoded }));
    safeEvent(config.eventSink, 'succeeded', 'request-received');
    if (state === 'running') void drain();
  }
  function onSocketError() {
    if (state !== 'running') return;
    state = 'failed';
    queue = [];
    aborter.abort();
    safeEvent(config.eventSink, 'failed', 'socket-error');
    try {
      socket.removeListener('message', receive);
      socket.close();
    } catch {}
    idle();
  }
  return Object.freeze({
    async start() {
      if (state !== 'new') fail('PCP_UDP_STATE_INVALID');
      state = 'starting';
      try {
        socket = factory();
        if (!socket || typeof socket.on !== 'function' ||
          typeof socket.once !== 'function' ||
          typeof socket.removeListener !== 'function' ||
          typeof socket.bind !== 'function' ||
          typeof socket.send !== 'function' ||
          typeof socket.close !== 'function' ||
          typeof socket.address !== 'function') fail('PCP_UDP_SOCKET_INVALID');
        socket.on('error', onSocketError);
        socket.on('message', receive);
        await bindSocket(socket, config.port, config.bind.address, aborter.signal);
        const bound = sourceSnapshot(socket.address(), {
          allowedSources: new Set([config.bind.address]),
        });
        if (bound.address !== config.bind.address) fail('PCP_UDP_BIND_INVALID');
        if (state !== 'starting') fail('PCP_UDP_STATE_INVALID');
        state = 'running';
        safeEvent(config.eventSink, 'succeeded', 'bound');
        return bound;
      } catch (error) {
        const closing = state === 'closing' || state === 'closed';
        if (!closing) {
          state = 'failed';
          safeEvent(config.eventSink, 'failed', 'bind-failed');
          try {
            if (socket) {
              socket.removeListener('message', receive);
              socket.removeListener('error', onSocketError);
              socket.close();
            }
          } catch {}
        }
        if (error instanceof PcpUdpServerError) throw error;
        throw new PcpUdpServerError('PCP_UDP_START_FAILED');
      }
    },
    address() {
      if (!socket || (state !== 'running' && state !== 'closing')) return null;
      let bound;
      try {
        bound = sourceSnapshot(socket.address(), {
          allowedSources: new Set([config.bind.address]),
        });
      } catch { fail('PCP_UDP_BIND_INVALID'); }
      return bound;
    },
    async close() {
      if (closePromise) return closePromise;
      closePromise = (async () => {
        state = 'closing';
        queue = [];
        aborter.abort();
        if (socket) {
          try {
            socket.removeListener('message', receive);
            await closeSocket(socket);
            socket.removeListener('error', onSocketError);
          } catch {}
        }
        await waitIdle();
        state = 'closed';
        safeEvent(config.eventSink, 'succeeded', 'closed');
      })();
      return closePromise;
    },
    state() { return state; },
    limits() {
      return Object.freeze({
        max_datagram_bytes: MAX_DATAGRAM_BYTES,
        max_queue: MAX_QUEUE,
      });
    },
  });
}

module.exports = Object.freeze({
  PcpUdpServerError,
  createPcpUdpServer,
  MAX_DATAGRAM_BYTES,
  MAX_QUEUE,
});
