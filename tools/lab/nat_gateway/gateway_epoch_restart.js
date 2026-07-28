'use strict';

// Pure shared-gateway reducer slice. It owns pending response identities,
// advances the gateway generation, clears mappings and declares effects.
const { types } = require('node:util');
const {
  restartMappingEpoch,
  snapshotInternalMappings,
} = require('./mapping_model');

const MAX_PENDING_RESPONSES = 4096;
const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const stateBrand = new WeakSet();

class GatewayEpochRestartError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'GatewayEpochRestartError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new GatewayEpochRestartError(reasonCode, fieldPath);
}

function dataObject(value, required, fieldPath) {
  if (value === null || typeof value !== 'object' || types.isProxy(value) ||
      Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    fail('GATEWAY_EPOCH_INPUT_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(value);
  for (const name of names) {
    if (!required.includes(name)) {
      fail('GATEWAY_EPOCH_UNKNOWN_FIELD', `${fieldPath}.*`);
    }
  }
  const copy = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) fail('GATEWAY_EPOCH_FIELD_MISSING', `${fieldPath}.${name}`);
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('GATEWAY_EPOCH_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    copy[name] = descriptor.value;
  }
  return copy;
}

function uint(value, maximum, fieldPath) {
  if (!Number.isInteger(value) || Object.is(value, -0) ||
      value < 0 || value > maximum) {
    fail('GATEWAY_EPOCH_FIELD_INVALID', fieldPath);
  }
  return value;
}

function responseId(value, fieldPath) {
  if (typeof value !== 'string' || value.length > 64 ||
      !ID_PATTERN.test(value)) {
    fail('GATEWAY_EPOCH_FIELD_INVALID', fieldPath);
  }
  return value;
}

function denseArray(value, fieldPath) {
  if (types.isProxy(value) || !Array.isArray(value) ||
      Object.getOwnPropertySymbols(value).length !== 0 ||
      value.length > MAX_PENDING_RESPONSES) {
    fail('GATEWAY_EPOCH_FIELD_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || names[names.length - 1] !== 'length') {
    fail('GATEWAY_EPOCH_FIELD_INVALID', fieldPath);
  }
  return value;
}

function pendingResponses(value, epoch, generation) {
  const list = denseArray(value, '$.pending_responses');
  const seen = new Set();
  const result = [];
  for (let index = 0; index < list.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(list, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('GATEWAY_EPOCH_FIELD_INVALID', `$.pending_responses[${index}]`);
    }
    const item = dataObject(descriptor.value,
      ['response_id', 'epoch', 'generation'],
      `$.pending_responses[${index}]`);
    const id = responseId(item.response_id,
      `$.pending_responses[${index}].response_id`);
    if (seen.has(id)) {
      fail('GATEWAY_EPOCH_RESPONSE_DUPLICATE',
        `$.pending_responses[${index}].response_id`);
    }
    seen.add(id);
    const itemEpoch = uint(item.epoch, 0xffffffff,
      `$.pending_responses[${index}].epoch`);
    const itemGeneration = uint(item.generation, Number.MAX_SAFE_INTEGER,
      `$.pending_responses[${index}].generation`);
    if (itemEpoch !== epoch || itemGeneration !== generation) {
      fail('GATEWAY_EPOCH_RESPONSE_STALE', `$.pending_responses[${index}]`);
    }
    result.push(Object.freeze({
      response_id: id,
      epoch: itemEpoch,
      generation: itemGeneration,
    }));
  }
  return Object.freeze(result);
}

function freezeState(mappingState, responses) {
  const result = Object.freeze({
    mapping_state: mappingState,
    pending_responses: responses,
  });
  stateBrand.add(result);
  return result;
}

function createGatewayEpochState(mappingState, pendingInput) {
  snapshotInternalMappings(mappingState);
  return freezeState(mappingState,
    pendingResponses(pendingInput, mappingState.epoch,
      mappingState.generation));
}

function requireState(state) {
  if (!stateBrand.has(state)) fail('GATEWAY_EPOCH_STATE_INVALID', '$.state');
  return state;
}

function restartGatewayEpoch(gatewayState, input) {
  const current = requireState(gatewayState);
  const request = dataObject(input, ['restart_seconds'], '$');
  const restartSeconds = uint(request.restart_seconds, 0xffffffff,
    '$.restart_seconds');
  const transition = restartMappingEpoch(current.mapping_state, {
    restart_seconds: restartSeconds,
  });
  const effects = current.pending_responses.map((response) => Object.freeze({
    type: 'CANCEL_RESPONSE',
    response_id: response.response_id,
  }));
  const next = freezeState(transition.state, Object.freeze([]));
  return Object.freeze({
    state: next,
    effects: Object.freeze(effects),
    event: Object.freeze({
      event: 'gateway_restarted',
      previous_epoch: current.mapping_state.epoch,
      epoch: transition.state.epoch,
      previous_generation: current.mapping_state.generation,
      generation: transition.state.generation,
      removed_mapping_count: transition.removed_mapping_count,
      invalidated_response_count: current.pending_responses.length,
    }),
  });
}

function completeGatewayResponse(gatewayState, input) {
  const current = requireState(gatewayState);
  const completion = dataObject(input,
    ['response_id', 'epoch', 'generation'], '$');
  const id = responseId(completion.response_id, '$.response_id');
  const epoch = uint(completion.epoch, 0xffffffff, '$.epoch');
  const generation = uint(completion.generation, Number.MAX_SAFE_INTEGER,
    '$.generation');
  if (generation !== current.mapping_state.generation) {
    return Object.freeze({
      accepted: false,
      reason_code: 'stale-generation',
      state: current,
      effects: Object.freeze([]),
    });
  }
  if (epoch !== current.mapping_state.epoch) {
    return Object.freeze({
      accepted: false,
      reason_code: 'stale-epoch',
      state: current,
      effects: Object.freeze([]),
    });
  }
  const index = current.pending_responses.findIndex(
    (response) => response.response_id === id);
  if (index === -1) {
    return Object.freeze({
      accepted: false,
      reason_code: 'not-found',
      state: current,
      effects: Object.freeze([]),
    });
  }
  const remaining = Object.freeze(current.pending_responses.filter(
    (_, responseIndex) => responseIndex !== index));
  return Object.freeze({
    accepted: true,
    reason_code: 'none',
    state: freezeState(current.mapping_state, remaining),
    effects: Object.freeze([Object.freeze({
      type: 'SEND_RESPONSE',
      response_id: id,
    })]),
  });
}

module.exports = Object.freeze({
  GatewayEpochRestartError,
  completeGatewayResponse,
  createGatewayEpochState,
  restartGatewayEpoch,
});
