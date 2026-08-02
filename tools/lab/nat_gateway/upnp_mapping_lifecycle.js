'use strict';

const net = require('node:net');
const { types } = require('node:util');
const {
  MappingModelError,
  createMapping,
  deleteMapping,
  expireMappings,
  renewMapping,
  snapshotInternalMappings,
} = require('./mapping_model');

const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

class UpnpMappingLifecycleError extends Error {
  constructor(reasonCode = 'UPNP_MAPPING_LIFECYCLE_INVALID',
      fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpMappingLifecycleError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpMappingLifecycleError(reasonCode, fieldPath);
}

function readClosedData(input, required, fieldPath) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_MAPPING_INPUT_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_MAPPING_INPUT_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_MAPPING_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function isUsableIpv4(value) {
  if (net.isIP(value) !== 4 ||
      value === '0.0.0.0' ||
      value === '255.255.255.255' ||
      /^127\./.test(value)) {
    return false;
  }
  const firstOctet = Number(value.split('.')[0]);
  return firstOctet > 0 && firstOctet < 224;
}

function validateCommand(input) {
  const required = [
    'protocol', 'operation', 'service_type', 'remote_host', 'external_port',
    'transport', 'internal_port', 'internal_client', 'enabled', 'description',
    'lease_seconds',
  ];
  const command = readClosedData(input, required, '$.command');
  if (command.protocol !== 'upnp' ||
      command.operation !== 'add_port_mapping' ||
      command.service_type !==
        'urn:schemas-upnp-org:service:WANIPConnection:1' ||
      command.remote_host !== '' ||
      !Number.isInteger(command.external_port) ||
      command.external_port < 1 || command.external_port > 65535 ||
      !['tcp', 'udp'].includes(command.transport) ||
      !Number.isInteger(command.internal_port) ||
      command.internal_port < 1 || command.internal_port > 65535 ||
      !isUsableIpv4(command.internal_client) ||
      typeof command.enabled !== 'boolean' ||
      typeof command.description !== 'string' ||
      !/^[A-Za-z0-9 ._-]{1,64}$/.test(command.description) ||
      !Number.isInteger(command.lease_seconds) ||
      Object.is(command.lease_seconds, -0) ||
      command.lease_seconds < 0 || command.lease_seconds > 0xffffffff) {
    fail('UPNP_MAPPING_COMMAND_INVALID', '$.command');
  }
  return command;
}

function validateContext(input) {
  const required = [
    'client_id', 'gateway_external_address', 'gateway_identity_digest',
    'instance_id_digest', 'now_monotonic_ms', 'table_capacity',
  ];
  const context = readClosedData(input, required, '$.context');
  if (typeof context.client_id !== 'string' ||
      !ID_PATTERN.test(context.client_id) ||
      !isUsableIpv4(context.gateway_external_address) ||
      typeof context.gateway_identity_digest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(context.gateway_identity_digest) ||
      typeof context.instance_id_digest !== 'string' ||
      !/^[a-f0-9]{64}$/.test(context.instance_id_digest) ||
      !Number.isSafeInteger(context.now_monotonic_ms) ||
      Object.is(context.now_monotonic_ms, -0) ||
      context.now_monotonic_ms < 0 ||
      !Number.isInteger(context.table_capacity) ||
      context.table_capacity < 1 || context.table_capacity > 65535) {
    fail('UPNP_MAPPING_CONTEXT_INVALID', '$.context');
  }
  return context;
}

function fault(state, errorCode, errorDescription) {
  return Object.freeze({
    ok: false,
    state,
    error_code: errorCode,
    error_description: errorDescription,
  });
}

function readMappings(state) {
  try {
    return snapshotInternalMappings(state);
  } catch (error) {
    if (error instanceof MappingModelError) {
      fail('UPNP_MAPPING_STATE_INVALID', '$.state');
    }
    throw error;
  }
}

function expireState(state, nowMonotonicMs) {
  try {
    return expireMappings(state, nowMonotonicMs).state;
  } catch (error) {
    if (error instanceof MappingModelError) {
      fail('UPNP_MAPPING_STATE_INVALID', '$.state');
    }
    throw error;
  }
}

function createOwnedMapping(state, mappingId, command, context, owner,
    atomicGroupId) {
  return createMapping(state, {
    mapping_id: mappingId,
    protocol: 'upnp',
    transport: command.transport,
    client_id: context.client_id,
    internal_address: command.internal_client,
    internal_port: command.internal_port,
    requested_external_port: command.external_port,
    external_address: context.gateway_external_address,
    external_port: command.external_port,
    lease: {
      lifetime_seconds: 0,
      created_monotonic_ms: context.now_monotonic_ms,
      expires_monotonic_ms: null,
    },
    owner,
    epoch: state.epoch,
    generation: state.generation,
    ...(atomicGroupId === undefined ? {} :
      { atomic_group_id: atomicGroupId }),
  });
}

function applyUpnpAddPortMapping(state, commandInput, contextInput) {
  const command = validateCommand(commandInput);
  const context = validateContext(contextInput);
  const currentState = expireState(state, context.now_monotonic_ms);
  const mappings = readMappings(currentState);
  if (command.lease_seconds !== 0) {
    return fault(currentState, 725, 'OnlyPermanentLeasesSupported');
  }
  if (!command.enabled) {
    return fault(currentState, 501, 'Action Failed');
  }
  const existing = mappings.find((mapping) =>
    mapping.external_address === context.gateway_external_address &&
    mapping.external_port === command.external_port &&
    mapping.transport === command.transport);
  const owner = Object.freeze({
    kind: 'upnp-journal',
    instance_id_digest: context.instance_id_digest,
    gateway_identity_digest: context.gateway_identity_digest,
    description: command.description,
  });
  if (existing) {
    const replaceable =
      existing.protocol === 'upnp' &&
      existing.client_id === context.client_id &&
      existing.internal_address === command.internal_client &&
      existing.owner &&
      existing.owner.kind === owner.kind &&
      existing.owner.instance_id_digest === owner.instance_id_digest &&
      existing.owner.gateway_identity_digest ===
        owner.gateway_identity_digest;
    if (!replaceable) {
      return fault(currentState, 718, 'ConflictInMappingEntry');
    }
    if (context.now_monotonic_ms < existing.lease.created_monotonic_ms) {
      fail('UPNP_MAPPING_CONTEXT_INVALID', '$.context.now_monotonic_ms');
    }
    const identical =
      existing.internal_port === command.internal_port &&
      existing.requested_external_port === command.external_port &&
      existing.owner.description === owner.description;
    if (identical) {
      const renewed = renewMapping(currentState, {
        mapping_id: existing.mapping_id,
        epoch: currentState.epoch,
        generation: currentState.generation,
        lifetime_seconds: 0,
        now_monotonic_ms: context.now_monotonic_ms,
        owner,
      });
      return Object.freeze({
        ok: true,
        state: renewed.state,
        mapping: renewed.mapping,
        disposition: 'renewed',
      });
    }
    const removed = deleteMapping(currentState, {
      mapping_id: existing.mapping_id,
      epoch: currentState.epoch,
      generation: currentState.generation,
      owner: existing.owner,
    });
    const replaced = createOwnedMapping(
      removed.state, existing.mapping_id, command, context, owner,
      existing.atomic_group_id);
    return Object.freeze({
      ok: true,
      state: replaced.state,
      mapping: replaced.mapping,
      disposition: 'replaced',
    });
  }
  if (mappings.length >= context.table_capacity) {
    return fault(currentState, 728, 'NoPortMapsAvailable');
  }
  const mappingId = `upnp.${command.transport}.${command.external_port}`;
  if (mappings.some((mapping) => mapping.mapping_id === mappingId)) {
    return fault(currentState, 718, 'ConflictInMappingEntry');
  }
  const created = createOwnedMapping(
    currentState, mappingId, command, context, owner);
  return Object.freeze({
    ok: true,
    state: created.state,
    mapping: created.mapping,
    disposition: 'created',
  });
}

module.exports = Object.freeze({
  UpnpMappingLifecycleError,
  applyUpnpAddPortMapping,
});
