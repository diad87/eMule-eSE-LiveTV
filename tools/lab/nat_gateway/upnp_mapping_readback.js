'use strict';

const net = require('node:net');
const { types } = require('node:util');
const {
  MappingModelError,
  expireMappings,
  snapshotInternalMappings,
} = require('./mapping_model');

const SERVICE_TYPE =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const resultBrand = new WeakSet();

class UpnpMappingReadbackError extends Error {
  constructor(reasonCode = 'UPNP_READBACK_INVALID', fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpMappingReadbackError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpMappingReadbackError(reasonCode, fieldPath);
}

function readClosedData(input, required, fieldPath) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_READBACK_INPUT_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_READBACK_INPUT_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_READBACK_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function validateCommand(input) {
  const base = ['protocol', 'operation', 'service_type'];
  if (input === null || typeof input !== 'object' || types.isProxy(input)) {
    fail('UPNP_READBACK_INPUT_INVALID', '$.command');
  }
  const operation = input && Object.getOwnPropertyDescriptor(
    input, 'operation');
  const specific = operation &&
    Object.hasOwn(operation, 'value') &&
    operation.value === 'get_specific_port_mapping_entry';
  const required = specific ?
    [...base, 'remote_host', 'external_port', 'transport'] :
    [...base, 'index'];
  const command = readClosedData(input, required, '$.command');
  if (command.protocol !== 'upnp' ||
      command.service_type !== SERVICE_TYPE ||
      (specific && (command.operation !==
        'get_specific_port_mapping_entry' ||
        command.remote_host !== '' ||
        !Number.isInteger(command.external_port) ||
        command.external_port < 1 || command.external_port > 65535 ||
        !['tcp', 'udp'].includes(command.transport))) ||
      (!specific && (command.operation !==
        'get_generic_port_mapping_entry' ||
        !Number.isInteger(command.index) ||
        command.index < 0 || command.index > 65535))) {
    fail('UPNP_READBACK_COMMAND_INVALID', '$.command');
  }
  return command;
}

function validateContext(input) {
  const context = readClosedData(input, [
    'readback', 'gateway_external_address', 'now_monotonic_ms',
    'description_limit',
  ], '$.context');
  if (!['full', 'unsupported'].includes(context.readback) ||
      net.isIP(context.gateway_external_address) !== 4 ||
      context.gateway_external_address === '0.0.0.0' ||
      context.gateway_external_address === '255.255.255.255' ||
      /^127\./.test(context.gateway_external_address) ||
      Number(context.gateway_external_address.split('.')[0]) < 1 ||
      Number(context.gateway_external_address.split('.')[0]) >= 224 ||
      !Number.isSafeInteger(context.now_monotonic_ms) ||
      Object.is(context.now_monotonic_ms, -0) ||
      context.now_monotonic_ms < 0 ||
      !Number.isInteger(context.description_limit) ||
      context.description_limit < 1 || context.description_limit > 64) {
    fail('UPNP_READBACK_CONTEXT_INVALID', '$.context');
  }
  return context;
}

function currentMappings(state, context) {
  try {
    const currentState =
      expireMappings(state, context.now_monotonic_ms).state;
    const mappings = snapshotInternalMappings(currentState)
      .filter((mapping) =>
        mapping.external_address === context.gateway_external_address &&
        net.isIP(mapping.internal_address) === 4)
      .sort((left, right) =>
        left.external_port - right.external_port ||
        (left.transport < right.transport ? -1 :
          left.transport > right.transport ? 1 : 0) ||
        (left.mapping_id < right.mapping_id ? -1 :
          left.mapping_id > right.mapping_id ? 1 : 0));
    return { currentState, mappings };
  } catch (error) {
    if (error instanceof MappingModelError) {
      fail('UPNP_READBACK_STATE_INVALID', '$.state');
    }
    throw error;
  }
}

function descriptionFor(mapping, limit) {
  const source = mapping.owner &&
    mapping.owner.kind === 'upnp-journal' ?
    mapping.owner.description : `${mapping.protocol.toUpperCase()} mapping`;
  return Array.from(source.toWellFormed()
    .replace(/[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/gu, '_'))
    .slice(0, limit).join('');
}

function entryFor(mapping, context) {
  const expires = mapping.lease.expires_monotonic_ms;
  const leaseSeconds = expires === null ? 0 :
    Math.ceil((expires - context.now_monotonic_ms) / 1000);
  return Object.freeze({
    remote_host: '',
    external_port: mapping.external_port,
    transport: mapping.transport,
    internal_port: mapping.internal_port,
    internal_client: mapping.internal_address,
    enabled: true,
    description: descriptionFor(mapping, context.description_limit),
    lease_seconds: leaseSeconds,
  });
}

function branded(value) {
  const result = Object.freeze(value);
  resultBrand.add(result);
  return result;
}

function readUpnpPortMapping(state, commandInput, contextInput) {
  const command = validateCommand(commandInput);
  const context = validateContext(contextInput);
  const { currentState, mappings } = currentMappings(state, context);
  if (context.readback === 'unsupported') {
    return branded({
      ok: false,
      operation: command.operation,
      state: currentState,
      error_code: 501,
      error_description: 'Action Failed',
    });
  }
  let mapping;
  let missingCode;
  let missingDescription;
  if (command.operation === 'get_specific_port_mapping_entry') {
    mapping = mappings.find((item) =>
      item.external_port === command.external_port &&
      item.transport === command.transport);
    missingCode = 714;
    missingDescription = 'NoSuchEntryInArray';
  } else {
    mapping = mappings[command.index];
    missingCode = 713;
    missingDescription = 'SpecifiedArrayIndexInvalid';
  }
  if (!mapping) {
    return branded({
      ok: false,
      operation: command.operation,
      state: currentState,
      error_code: missingCode,
      error_description: missingDescription,
    });
  }
  return branded({
    ok: true,
    operation: command.operation,
    state: currentState,
    entry: entryFor(mapping, context),
  });
}

function projectUpnpReadbackSoapResult(result) {
  if (!resultBrand.has(result)) {
    fail('UPNP_READBACK_RESULT_INVALID', '$.result');
  }
  if (!result.ok) {
    return Object.freeze({
      ok: false,
      error_code: result.error_code,
      error_description: result.error_description,
    });
  }
  if (result.operation === 'get_specific_port_mapping_entry') {
    return Object.freeze({
      ok: true,
      internal_port: result.entry.internal_port,
      internal_client: result.entry.internal_client,
      enabled: result.entry.enabled,
      description: result.entry.description,
      lease_seconds: result.entry.lease_seconds,
    });
  }
  return Object.freeze({
    ok: true,
    ...result.entry,
  });
}

module.exports = Object.freeze({
  UpnpMappingReadbackError,
  projectUpnpReadbackSoapResult,
  readUpnpPortMapping,
});
