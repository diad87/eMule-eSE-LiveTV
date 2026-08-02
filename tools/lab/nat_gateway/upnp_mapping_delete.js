'use strict';

const net = require('node:net');
const { types } = require('node:util');
const {
  MappingModelError,
  deleteMapping,
  expireMappings,
  snapshotInternalMappings,
} = require('./mapping_model');

const SERVICE_TYPE =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const resultBrand = new WeakSet();

class UpnpMappingDeleteError extends Error {
  constructor(reasonCode = 'UPNP_DELETE_INVALID', fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpMappingDeleteError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpMappingDeleteError(reasonCode, fieldPath);
}

function readClosedData(input, required, fieldPath) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_DELETE_INPUT_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_DELETE_INPUT_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_DELETE_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function validateCommand(input) {
  const command = readClosedData(input, [
    'protocol', 'operation', 'service_type', 'remote_host', 'external_port',
    'transport',
  ], '$.command');
  if (command.protocol !== 'upnp' ||
      command.operation !== 'delete_port_mapping' ||
      command.service_type !== SERVICE_TYPE ||
      command.remote_host !== '' ||
      !Number.isInteger(command.external_port) ||
      command.external_port < 1 || command.external_port > 65535 ||
      !['tcp', 'udp'].includes(command.transport)) {
    fail('UPNP_DELETE_COMMAND_INVALID', '$.command');
  }
  return command;
}

function validateContext(input) {
  const context = readClosedData(input, [
    'gateway_external_address', 'now_monotonic_ms',
  ], '$.context');
  const first = typeof context.gateway_external_address === 'string' ?
    Number(context.gateway_external_address.split('.')[0]) : NaN;
  if (net.isIP(context.gateway_external_address) !== 4 ||
      context.gateway_external_address === '0.0.0.0' ||
      context.gateway_external_address === '255.255.255.255' ||
      /^127\./.test(context.gateway_external_address) ||
      first < 1 || first >= 224 ||
      !Number.isSafeInteger(context.now_monotonic_ms) ||
      Object.is(context.now_monotonic_ms, -0) ||
      context.now_monotonic_ms < 0) {
    fail('UPNP_DELETE_CONTEXT_INVALID', '$.context');
  }
  return context;
}

function branded(value) {
  const result = Object.freeze(value);
  resultBrand.add(result);
  return result;
}

function applyUpnpDeletePortMapping(state, commandInput, contextInput) {
  const command = validateCommand(commandInput);
  const context = validateContext(contextInput);
  let currentState;
  let mappings;
  try {
    currentState = expireMappings(state, context.now_monotonic_ms).state;
    mappings = snapshotInternalMappings(currentState);
  } catch (error) {
    if (error instanceof MappingModelError) {
      fail('UPNP_DELETE_STATE_INVALID', '$.state');
    }
    throw error;
  }
  const existing = mappings.find((mapping) =>
    mapping.external_address === context.gateway_external_address &&
    mapping.external_port === command.external_port &&
    mapping.transport === command.transport);
  if (!existing) {
    return branded({
      ok: false,
      state: currentState,
      error_code: 714,
      error_description: 'NoSuchEntryInArray',
    });
  }
  if (!existing.owner || existing.owner.kind === 'none') {
    return branded({
      ok: false,
      state: currentState,
      error_code: 606,
      error_description: 'Action not authorized',
    });
  }
  const deleted = deleteMapping(currentState, {
    mapping_id: existing.mapping_id,
    epoch: currentState.epoch,
    generation: currentState.generation,
    owner: existing.owner,
  });
  return branded({
    ok: true,
    state: deleted.state,
    deleted_mapping_id: deleted.deleted_mapping_id,
  });
}

function projectUpnpDeleteSoapResult(result) {
  if (!resultBrand.has(result)) {
    fail('UPNP_DELETE_RESULT_INVALID', '$.result');
  }
  return result.ok ?
    Object.freeze({ ok: true }) :
    Object.freeze({
      ok: false,
      error_code: result.error_code,
      error_description: result.error_description,
    });
}

module.exports = Object.freeze({
  UpnpMappingDeleteError,
  applyUpnpDeletePortMapping,
  projectUpnpDeleteSoapResult,
});
