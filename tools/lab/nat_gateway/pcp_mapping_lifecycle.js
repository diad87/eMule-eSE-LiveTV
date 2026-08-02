'use strict';

// D06 is a pure PCP-to-domain transition. Allocation decisions and time are
// explicit inputs; UDP framing and epoch generation remain outside.
const { types } = require('node:util');
const net = require('node:net');
const { decodePcpMapRequest } = require('./pcp_map_request_decoder');
const {
  createMapping,
  renewMapping,
  expireMappings,
  deleteMapping,
  snapshotInternalMappings,
} = require('./mapping_model');

const objectPrototype = Object.prototype;
const lifecycleBrand = new WeakSet();
const lifecycleMetadata = new WeakMap();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const byteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;

class PcpMappingLifecycleError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'PcpMappingLifecycleError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}
function fail(code, path) { throw new PcpMappingLifecycleError(code, path); }
function dataObject(value, keys, path) {
  if (value === null || typeof value !== 'object' || types.isProxy(value) ||
    Object.getPrototypeOf(value) !== objectPrototype ||
    Object.getOwnPropertySymbols(value).length) fail('PCP_LIFECYCLE_INPUT_INVALID', path);
  const names = Object.getOwnPropertyNames(value);
  for (const name of names) {
    if (!keys.includes(name)) fail('PCP_LIFECYCLE_UNKNOWN_FIELD', `${path}.*`);
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value')) fail('PCP_LIFECYCLE_INPUT_INVALID', `${path}.${name}`);
  }
  for (const key of keys) {
    if (!names.includes(key)) fail('PCP_LIFECYCLE_FIELD_MISSING', `${path}.${key}`);
  }
  return value;
}
function uint(value, maximum, path, nonzero = false) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < 0 ||
    value > maximum || (nonzero && value === 0)) {
    fail('PCP_LIFECYCLE_FIELD_INVALID', path);
  }
  return value;
}
function text(value, pattern, path) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail('PCP_LIFECYCLE_FIELD_INVALID', path);
  }
  return value;
}
function canonicalAddress(value, path) {
  if (typeof value !== 'string' || net.isIP(value) === 0) {
    fail('PCP_LIFECYCLE_FIELD_INVALID', path);
  }
  const family = net.isIP(value);
  try {
    const address = new net.SocketAddress({
      address: value,
      port: 1,
      family: family === 4 ? 'ipv4' : 'ipv6',
    }).address;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    return mapped ? mapped[1] : address;
  } catch {
    fail('PCP_LIFECYCLE_FIELD_INVALID', path);
  }
}
function usableExternalAddress(address) {
  if (net.isIPv4(address)) {
    const octets = address.split('.').map(Number);
    return octets[0] !== 0 && octets[0] !== 127 &&
      !(octets[0] === 169 && octets[1] === 254) &&
      octets[0] < 224 && address !== '255.255.255.255';
  }
  const lower = address.toLowerCase();
  if (lower === '::' || lower === '::1' || lower.startsWith('ff')) return false;
  const first = Number.parseInt(lower.split(':')[0] || '0', 16);
  return (first & 0xffc0) !== 0xfe80;
}
function snapshotContext(input) {
  const value = dataObject(input, [
    'now_monotonic_ms', 'client_id', 'instance_id_digest',
    'granted_lifetime_seconds', 'new_mapping',
  ], '$.context');
  const newMapping = value.new_mapping === null ? null :
    dataObject(value.new_mapping, [
      'mapping_id', 'external_address', 'external_port',
    ], '$.context.new_mapping');
  return Object.freeze({
    now: uint(value.now_monotonic_ms, Number.MAX_SAFE_INTEGER,
      '$.context.now_monotonic_ms'),
    clientId: text(value.client_id, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,
      '$.context.client_id'),
    instanceDigest: text(value.instance_id_digest, /^[a-f0-9]{64}$/,
      '$.context.instance_id_digest'),
    lifetime: uint(value.granted_lifetime_seconds, 0xffffffff,
      '$.context.granted_lifetime_seconds'),
    newMapping: newMapping === null ? null : (() => {
      const externalAddress = canonicalAddress(newMapping.external_address,
        '$.context.new_mapping.external_address');
      if (!usableExternalAddress(externalAddress)) {
        fail('PCP_LIFECYCLE_FIELD_INVALID',
          '$.context.new_mapping.external_address');
      }
      return Object.freeze({
        mappingId: text(newMapping.mapping_id,
        /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/,
        '$.context.new_mapping.mapping_id'),
        externalAddress,
        externalPort: uint(newMapping.external_port, 0xffff,
          '$.context.new_mapping.external_port', true),
      });
    })(),
  });
}
function commandShape(command) {
  const value = dataObject(command, [
    'protocol', 'operation', 'transport', 'client_address', 'nonce',
    'internal_port', 'suggested_external_port',
    'suggested_external_address', 'lifetime_seconds', 'options',
  ], '$.command');
  const options = dataObject(value.options,
    ['prefer_failure', 'port_set'], '$.command.options');
  let portSet = null;
  if (options.port_set !== null) {
    const candidate = dataObject(options.port_set, [
      'size', 'first_internal_port', 'preserve_parity',
    ], '$.command.options.port_set');
    if (!Number.isInteger(candidate.size) || candidate.size < 1 ||
      candidate.size > 65535 ||
      !Number.isInteger(candidate.first_internal_port) ||
      candidate.first_internal_port < 1 ||
      candidate.first_internal_port > 65535 ||
      typeof candidate.preserve_parity !== 'boolean') {
      fail('PCP_LIFECYCLE_COMMAND_INVALID', '$.command');
    }
    portSet = Object.freeze({
      size: candidate.size,
      first_internal_port: candidate.first_internal_port,
      preserve_parity: candidate.preserve_parity,
    });
  }
  const clientAddress = canonicalAddress(value.client_address,
    '$.command.client_address');
  const suggestedAddress = canonicalAddress(value.suggested_external_address,
    '$.command.suggested_external_address');
  if (value.protocol !== 'pcp' ||
    !['map', 'delete'].includes(value.operation) ||
    !['tcp', 'udp'].includes(value.transport) ||
    typeof value.nonce !== 'string' ||
    !/^[a-f0-9]{24}$/.test(value.nonce) ||
    !Number.isInteger(value.internal_port) ||
    !Number.isInteger(value.suggested_external_port) ||
    !Number.isInteger(value.lifetime_seconds) ||
    value.internal_port < 1 || value.internal_port > 65535 ||
    value.suggested_external_port < 0 ||
    value.suggested_external_port > 65535 ||
    value.lifetime_seconds < 0 || value.lifetime_seconds > 0xffffffff ||
    value.operation === 'delete' !== (value.lifetime_seconds === 0) ||
    typeof options.prefer_failure !== 'boolean' ||
    (options.prefer_failure &&
      (value.operation === 'delete' ||
       value.suggested_external_port === 0 ||
       portSet !== null))) {
    fail('PCP_LIFECYCLE_COMMAND_INVALID', '$.command');
  }
  return Object.freeze({
    protocol: value.protocol,
    operation: value.operation,
    transport: value.transport,
    client_address: clientAddress,
    nonce: value.nonce,
    internal_port: value.internal_port,
    suggested_external_port: value.suggested_external_port,
    suggested_external_address: suggestedAddress,
    lifetime_seconds: value.lifetime_seconds,
    options: Object.freeze({
      prefer_failure: options.prefer_failure,
      port_set: portSet,
    }),
  });
}
function sameTuple(mapping, command) {
  return mapping.protocol === 'pcp' &&
    mapping.transport === command.transport &&
    mapping.internal_address === command.client_address &&
    mapping.internal_port === command.internal_port;
}
function remainingLifetime(mapping, now) {
  if (mapping.lease.expires_monotonic_ms === null) return 0xffffffff;
  return Math.max(0,
    Math.ceil((mapping.lease.expires_monotonic_ms - now) / 1000));
}
function preferFailureMismatch(command, externalAddress, externalPort) {
  return command.options.prefer_failure &&
    (command.suggested_external_port !== externalPort ||
     (command.suggested_external_address !== '::' &&
      command.suggested_external_address !== '0.0.0.0' &&
      command.suggested_external_address !== externalAddress));
}
function commandKey(command) { return JSON.stringify(command); }
function result(command, state, action, resultCode, lifetime, mapping = null) {
  const value = Object.freeze({
    state,
    action,
    result_code: resultCode,
    lifetime_seconds: lifetime,
    mapping,
  });
  lifecycleBrand.add(value);
  lifecycleMetadata.set(value, commandKey(command));
  return value;
}
function ownerFor(nonce, instanceDigest) {
  return {
    kind: 'pcp-nonce',
    instance_id_digest: instanceDigest,
    nonce,
  };
}

function applyPcpMapCommand(state, commandInput, contextInput) {
  const command = commandShape(commandInput);
  const context = snapshotContext(contextInput);
  let currentState = expireMappings(state, context.now).state;
  const matches = snapshotInternalMappings(currentState)
    .filter((mapping) => sameTuple(mapping, command));
  if (matches.length > 1) {
    fail('PCP_LIFECYCLE_STATE_AMBIGUOUS', '$.state');
  }
  const [existing] = matches;
  if (existing && !usableExternalAddress(existing.external_address)) {
    fail('PCP_LIFECYCLE_STATE_INVALID', '$.state');
  }

  if (existing && (!existing.owner ||
    existing.owner.kind !== 'pcp-nonce')) {
    if (existing.lease.lifetime_seconds !== 0 ||
      existing.lease.expires_monotonic_ms !== null) {
      fail('PCP_LIFECYCLE_STATE_INVALID', '$.state');
    }
    if (command.operation === 'delete') {
      return result(command, currentState, 'rejected', 2,
        remainingLifetime(existing, context.now));
    }
    if (preferFailureMismatch(command,
      existing.external_address, existing.external_port)) {
      return result(command, currentState, 'rejected', 11,
        0xffffffff, existing);
    }
    return result(command, currentState, 'static', 0, 0xffffffff, existing);
  }
  if (existing && existing.owner.nonce !== command.nonce) {
    return result(command, currentState, 'rejected', 2,
      remainingLifetime(existing, context.now));
  }
  if (existing &&
    existing.owner.instance_id_digest !== context.instanceDigest) {
    return result(command, currentState, 'rejected', 2,
      remainingLifetime(existing, context.now));
  }
  if (command.operation === 'delete') {
    if (!existing) return result(command, currentState, 'delete-noop', 0, 0);
    const deleted = deleteMapping(currentState, {
      mapping_id: existing.mapping_id,
      epoch: currentState.epoch,
      generation: currentState.generation,
      owner: ownerFor(command.nonce, context.instanceDigest),
    });
    return result(command, deleted.state, 'deleted', 0, 0);
  }
  if (context.lifetime === 0) {
    fail('PCP_LIFECYCLE_FIELD_INVALID',
      '$.context.granted_lifetime_seconds');
  }
  if (existing) {
    if (preferFailureMismatch(command,
      existing.external_address, existing.external_port)) {
      return result(command, currentState, 'rejected', 11,
        remainingLifetime(existing, context.now), existing);
    }
    const renewed = renewMapping(currentState, {
      mapping_id: existing.mapping_id,
      epoch: currentState.epoch,
      generation: currentState.generation,
      owner: ownerFor(command.nonce, context.instanceDigest),
      lifetime_seconds: context.lifetime,
      now_monotonic_ms: context.now,
    });
    return result(command, renewed.state, 'renewed', 0,
      context.lifetime, renewed.mapping);
  }
  if (context.newMapping === null) {
    return result(command, currentState, 'rejected', 8, 30);
  }
  if (preferFailureMismatch(command,
    context.newMapping.externalAddress, context.newMapping.externalPort)) {
    return result(command, currentState, 'rejected', 11, 30);
  }
  const expires = context.now + (context.lifetime * 1000);
  if (!Number.isSafeInteger(expires)) {
    fail('PCP_LIFECYCLE_FIELD_INVALID',
      '$.context.granted_lifetime_seconds');
  }
  const created = createMapping(currentState, {
    mapping_id: context.newMapping.mappingId,
    protocol: 'pcp',
    transport: command.transport,
    client_id: context.clientId,
    internal_address: command.client_address,
    internal_port: command.internal_port,
    requested_external_port: command.suggested_external_port,
    external_address: context.newMapping.externalAddress,
    external_port: context.newMapping.externalPort,
    lease: {
      lifetime_seconds: context.lifetime,
      created_monotonic_ms: context.now,
      expires_monotonic_ms: expires,
    },
    owner: ownerFor(command.nonce, context.instanceDigest),
    epoch: currentState.epoch,
    generation: currentState.generation,
  });
  return result(command, created.state, 'created', 0,
    context.lifetime, created.mapping);
}

function toPcpMapResponse(commandInput, lifecycle, requestWire) {
  const command = commandShape(commandInput);
  if (!lifecycleBrand.has(lifecycle)) {
    fail('PCP_LIFECYCLE_RESULT_INVALID', '$.lifecycle');
  }
  if (lifecycleMetadata.get(lifecycle) !== commandKey(command)) {
    fail('PCP_LIFECYCLE_RESULT_INVALID', '$.lifecycle');
  }
  if (types.isProxy(requestWire) || !types.isUint8Array(requestWire)) {
    fail('PCP_LIFECYCLE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  let wire;
  try {
    const backing = bufferGetter.call(requestWire);
    const offset = byteOffsetGetter.call(requestWire);
    const length = byteLengthGetter.call(requestWire);
    const backingLength = arrayBufferLengthGetter.call(backing);
    if (!types.isArrayBuffer(backing) || length < 60 || length > 1100 ||
      (length & 3) !== 0 || offset < 0 || offset > backingLength ||
      length > backingLength - offset) {
      fail('PCP_LIFECYCLE_REQUEST_WIRE_INVALID', '$.request_wire');
    }
    wire = Buffer.from(new Uint8Array(backing, offset, length));
  } catch (error) {
    if (error instanceof PcpMappingLifecycleError) throw error;
    fail('PCP_LIFECYCLE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  let wireCommand;
  try { wireCommand = commandShape(decodePcpMapRequest(wire)); } catch {
    fail('PCP_LIFECYCLE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  if (commandKey(wireCommand) !== commandKey(command)) {
    fail('PCP_LIFECYCLE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  if (lifecycle.result_code !== 0) {
    return Object.freeze({
      mode: 'error-echo',
      response_type: 'map',
      result_code: lifecycle.result_code,
      epoch: 0,
      lifetime_seconds: lifecycle.lifetime_seconds,
      request_wire: wire,
      request_parsed: true,
    });
  }
  const mapping = lifecycle.mapping;
  const deletion = lifecycle.action === 'deleted' ||
    lifecycle.action === 'delete-noop';
  if (!deletion && mapping === null) {
    fail('PCP_LIFECYCLE_RESULT_INVALID', '$.lifecycle.mapping');
  }
  return Object.freeze({
    mode: 'semantic',
    response_type: 'map',
    result_code: 0,
    epoch: 0,
    lifetime_seconds: deletion ? 0 : lifecycle.lifetime_seconds,
    nonce: command.nonce,
    protocol_number: command.transport === 'tcp' ? 6 : 17,
    internal_port: command.internal_port,
    external_port: deletion ? 0 : mapping.external_port,
    external_address: deletion ? '0.0.0.0' : mapping.external_address,
    options: Object.freeze({
      prefer_failure: deletion ? false : command.options.prefer_failure,
      port_set: null,
    }),
  });
}

module.exports = Object.freeze({
  PcpMappingLifecycleError,
  applyPcpMapCommand,
  toPcpMapResponse,
});
