'use strict';

const crypto = require('node:crypto');
const { types } = require('node:util');
const { loadScenarioFromFile, loadScenarioFromObject } = require('./scenario_loader');
const {
  createMappingState,
  resetMappingState,
  restartMappingEpoch,
  expireMappings,
  snapshotInternalMappings
} = require('./mapping_model');
const { compileFaultCatalog, resetFaultCatalog } = require('./fault_catalog');
const { projectPublicMappings } = require('./structured_log');

const MAX_ARG_LENGTH = 4096;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const controlBrand = new WeakSet();
const controlErrorBrand = new WeakSet();
const INTERNAL_ERROR_TOKEN = Symbol('t8-control-error');

class T8ControlError extends Error {
  constructor(reasonCode, fieldPath, exitCode = 2, token = null) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'T8ControlError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
    this.exit_code = exitCode;
    if (token === INTERNAL_ERROR_TOKEN) controlErrorBrand.add(this);
  }
}

function fail(reasonCode, fieldPath, exitCode = 2) {
  throw new T8ControlError(reasonCode, fieldPath, exitCode, INTERNAL_ERROR_TOKEN);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function dataObject(value, required, fieldPath) {
  if (types.isProxy(value) || value === null || typeof value !== 'object' ||
      Array.isArray(value) ||
      (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
      Object.getOwnPropertySymbols(value).length !== 0) {
    fail('CONTROL_INPUT_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== required.length || names.some((name) => !required.includes(name))) {
    fail('CONTROL_SHAPE_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      fail('CONTROL_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function uint(value, maximum, fieldPath) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < 0 || value > maximum) {
    fail('CONTROL_VALUE_INVALID', fieldPath);
  }
  return value;
}

function word(value, fieldPath) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ARG_LENGTH ||
      value.includes('\0') || /[\r\n]/.test(value)) {
    fail('CONTROL_VALUE_INVALID', fieldPath);
  }
  return value;
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function scenarioDigest(scenarioId) {
  return crypto.createHash('sha256').update(`t8.scenario-id/v1\0${scenarioId}`, 'utf8').digest('hex');
}

function stoppedState() {
  const state = freeze({
    status: 'stopped',
    scenario: null,
    scenario_id_digest: null,
    mapping_state: null,
    fault_catalog: null,
    now_monotonic_ms: 0,
    command_sequence: 0,
    pending_drop_faults: freeze([])
  });
  controlBrand.add(state);
  return state;
}

function activeState(source, overrides = {}) {
  const state = freeze({ ...source, ...overrides });
  controlBrand.add(state);
  return state;
}

function createT8Control() {
  return stoppedState();
}

function requireControl(value) {
  if (!value || typeof value !== 'object' || !controlBrand.has(value)) {
    fail('CONTROL_STATE_INVALID', '$.control', 1);
  }
  return value;
}

function requireLoaded(state) {
  if (state.status !== 'loaded') fail('CONTROL_NOT_LOADED', '$.command', 1);
}

function result(state, command, data = {}) {
  return freeze({
    state,
    exit_code: 0,
    output: {
      schema: 'ese.v92.t8.cli-result/v1',
      ok: true,
      reason_code: 'none',
      command,
      ...data
    }
  });
}

function loadCommand(state, args) {
  if (state.status !== 'stopped') fail('CONTROL_ALREADY_LOADED', '$.command', 1);
  const values = dataObject(args, ['scenario'], '$.arguments');
  const scenario = loadScenarioFromObject(values.scenario);
  const mappingState = createMappingState({
    epoch: scenario.gateway.epoch.initial_seconds,
    generation: scenario.gateway.initial_generation,
    mappings: scenario.initial_state.mappings,
    baseline_mappings: scenario.initial_state.mappings
  });
  const now = scenario.clock.mode === 'virtual' ? scenario.clock.start_monotonic_ms : 0;
  const next = activeState(state, {
    status: 'loaded',
    scenario,
    scenario_id_digest: scenarioDigest(scenario.scenario_id),
    mapping_state: mappingState,
    fault_catalog: compileFaultCatalog(scenario.faults),
    now_monotonic_ms: now,
    command_sequence: state.command_sequence + 1,
    pending_drop_faults: freeze([])
  });
  return result(next, 'load', {
    status: next.status,
    scenario_id_digest: next.scenario_id_digest,
    epoch: mappingState.epoch,
    generation: mappingState.generation
  });
}

function resetCommand(state, args) {
  requireLoaded(state);
  dataObject(args, [], '$.arguments');
  if (state.mapping_state.generation === Number.MAX_SAFE_INTEGER) {
    fail('CONTROL_GENERATION_EXHAUSTED', '$.generation', 1);
  }
  const transition = resetMappingState(state.mapping_state, {
    generation: state.mapping_state.generation + 1,
    epoch: state.scenario.gateway.epoch.initial_seconds
  });
  const now = state.scenario.clock.mode === 'virtual' ? state.scenario.clock.start_monotonic_ms : 0;
  const next = activeState(state, {
    mapping_state: transition.state,
    fault_catalog: resetFaultCatalog(state.fault_catalog),
    now_monotonic_ms: now,
    command_sequence: state.command_sequence + 1,
    pending_drop_faults: freeze([])
  });
  return result(next, 'reset', {
    status: next.status,
    epoch: next.mapping_state.epoch,
    generation: next.mapping_state.generation,
    mapping_count: next.mapping_state.mappings.length
  });
}

function statusCommand(state, args) {
  dataObject(args, [], '$.arguments');
  return result(state, 'status', state.status === 'stopped' ? {
    status: 'stopped',
    mapping_count: 0,
    pending_drop_count: 0
  } : {
    status: 'loaded',
    scenario_id_digest: state.scenario_id_digest,
    monotonic_ms: state.now_monotonic_ms,
    epoch: state.mapping_state.epoch,
    generation: state.mapping_state.generation,
    mapping_count: state.mapping_state.mappings.length,
    pending_drop_count: state.pending_drop_faults.length
  });
}

function listCommand(state, args) {
  requireLoaded(state);
  dataObject(args, [], '$.arguments');
  const mappings = projectPublicMappings(snapshotInternalMappings(state.mapping_state));
  return result(state, 'list', {
    epoch: state.mapping_state.epoch,
    generation: state.mapping_state.generation,
    mapping_count: mappings.length,
    mappings
  });
}

function restartEpochCommand(state, args) {
  requireLoaded(state);
  const values = dataObject(args, ['restart_seconds'], '$.arguments');
  const restartSeconds = uint(values.restart_seconds, 0xffffffff, '$.arguments.restart_seconds');
  const transition = restartMappingEpoch(state.mapping_state, { restart_seconds: restartSeconds });
  const next = activeState(state, {
    mapping_state: transition.state,
    command_sequence: state.command_sequence + 1
  });
  return result(next, 'restart-epoch', {
    epoch: next.mapping_state.epoch,
    generation: next.mapping_state.generation,
    removed_mapping_count: transition.removed_mapping_count
  });
}

function dropNextCommand(state, args) {
  requireLoaded(state);
  const values = dataObject(args, ['protocol'], '$.arguments');
  if (!PROTOCOLS.has(values.protocol)) fail('CONTROL_VALUE_INVALID', '$.arguments.protocol');
  const sequence = state.command_sequence + 1;
  const fault = freeze({
    fault_id: `cli-drop-${sequence}`,
    protocol: values.protocol,
    injection_point: 'post-encode-pre-send',
    configured_times: 1,
    remaining_times: 1,
    expected_result: 'response-dropped',
    auto_reset: true,
    action: freeze({ type: 'drop' })
  });
  const next = activeState(state, {
    command_sequence: sequence,
    pending_drop_faults: freeze([...state.pending_drop_faults, fault])
  });
  return result(next, 'drop-next', {
    fault_id: fault.fault_id,
    protocol: fault.protocol,
    pending_drop_count: next.pending_drop_faults.length
  });
}

function expireCommand(state, args) {
  requireLoaded(state);
  const values = dataObject(args, ['now_monotonic_ms'], '$.arguments');
  const now = uint(values.now_monotonic_ms, Number.MAX_SAFE_INTEGER, '$.arguments.now_monotonic_ms');
  if (now < state.now_monotonic_ms) fail('CONTROL_TIME_REGRESSION', '$.arguments.now_monotonic_ms', 1);
  const transition = expireMappings(state.mapping_state, now);
  const next = activeState(state, {
    mapping_state: transition.state,
    now_monotonic_ms: now,
    command_sequence: state.command_sequence + 1
  });
  return result(next, 'expire', {
    monotonic_ms: now,
    expired_mapping_count: transition.expired_mapping_ids.length,
    mapping_count: next.mapping_state.mappings.length
  });
}

function stopCommand(state, args) {
  dataObject(args, [], '$.arguments');
  const next = stoppedState();
  return result(next, 'stop', {
    status: 'stopped',
    removed_mapping_count: state.status === 'loaded' ? state.mapping_state.mappings.length : 0
  });
}

const COMMANDS = Object.freeze({
  load: loadCommand,
  reset: resetCommand,
  status: statusCommand,
  list: listCommand,
  'restart-epoch': restartEpochCommand,
  'drop-next': dropNextCommand,
  expire: expireCommand,
  stop: stopCommand
});

function dispatchT8Control(control, commandInput) {
  const state = requireControl(control);
  const envelope = dataObject(commandInput, ['command', 'arguments'], '$');
  if (typeof envelope.command !== 'string' || !hasOwn(COMMANDS, envelope.command)) {
    fail('CONTROL_COMMAND_UNKNOWN', '$.command');
  }
  return COMMANDS[envelope.command](state, envelope.arguments);
}

function argvData(argv) {
  if (types.isProxy(argv) || !Array.isArray(argv) || Object.getPrototypeOf(argv) !== Array.prototype ||
      Object.getOwnPropertySymbols(argv).length !== 0 || argv.length > 3) {
    fail('CLI_ARGV_INVALID', '$.argv');
  }
  const names = Object.getOwnPropertyNames(argv);
  if (names.length !== argv.length + 1 || names[names.length - 1] !== 'length') {
    fail('CLI_ARGV_INVALID', '$.argv');
  }
  const result = [];
  for (let index = 0; index < argv.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(argv, String(index));
    if (!descriptor || !descriptor.enumerable || !hasOwn(descriptor, 'value')) {
      fail('CLI_ARGV_INVALID', `$.argv[${index}]`);
    }
    result.push(word(descriptor.value, `$.argv[${index}]`));
  }
  return result;
}

function parseDecimal(value, maximum, fieldPath) {
  if (!/^(0|[1-9]\d*)$/.test(value)) fail('CLI_ARGUMENT_INVALID', fieldPath);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) fail('CLI_ARGUMENT_INVALID', fieldPath);
  return parsed;
}

function translateArgv(argv, loadScenarioFile) {
  if (argv.length === 0) fail('CLI_COMMAND_MISSING', '$.argv');
  const [command, argument] = argv;
  if (command === 'load') {
    if (argv.length !== 2) fail('CLI_ARGUMENT_COUNT', '$.argv');
    return { command, arguments: { scenario: loadScenarioFile(argument) } };
  }
  if (['reset', 'status', 'list', 'stop'].includes(command)) {
    if (argv.length !== 1) fail('CLI_ARGUMENT_COUNT', '$.argv');
    return { command, arguments: {} };
  }
  if (command === 'restart-epoch') {
    if (argv.length !== 2) fail('CLI_ARGUMENT_COUNT', '$.argv');
    return { command, arguments: { restart_seconds: parseDecimal(argument, 0xffffffff, '$.argv[1]') } };
  }
  if (command === 'drop-next') {
    if (argv.length !== 2 || !PROTOCOLS.has(argument)) fail('CLI_ARGUMENT_INVALID', '$.argv[1]');
    return { command, arguments: { protocol: argument } };
  }
  if (command === 'expire') {
    if (argv.length !== 2) fail('CLI_ARGUMENT_COUNT', '$.argv');
    return { command, arguments: { now_monotonic_ms: parseDecimal(argument, Number.MAX_SAFE_INTEGER, '$.argv[1]') } };
  }
  fail('CONTROL_COMMAND_UNKNOWN', '$.argv[0]');
}

function failureOutput(command, reasonCode) {
  return {
    schema: 'ese.v92.t8.cli-result/v1',
    ok: false,
    reason_code: reasonCode,
    command: typeof command === 'string' && command.length <= 64 ? command : 'unknown'
  };
}

function classifyCaughtError(error) {
  try {
    if (types.isProxy(error)) return { reason_code: 'CLI_COMMAND_FAILED', exit_code: 1 };
    if (error instanceof T8ControlError && controlErrorBrand.has(error)) {
      const reason = Object.getOwnPropertyDescriptor(error, 'reason_code');
      const exit = Object.getOwnPropertyDescriptor(error, 'exit_code');
      if (reason && hasOwn(reason, 'value') && typeof reason.value === 'string' &&
          exit && hasOwn(exit, 'value') && [1, 2].includes(exit.value)) {
        return { reason_code: reason.value, exit_code: exit.value };
      }
      return { reason_code: 'CLI_COMMAND_FAILED', exit_code: 1 };
    }
  } catch {
    return { reason_code: 'CLI_COMMAND_FAILED', exit_code: 1 };
  }
  return { reason_code: 'CLI_COMMAND_FAILED', exit_code: 1 };
}

function executeT8Cli(control, argvInput, dependencies = {}) {
  let command = 'unknown';
  try {
    const state = requireControl(control);
    if (types.isProxy(dependencies) || dependencies === null || typeof dependencies !== 'object' ||
        Array.isArray(dependencies) ||
        (Object.getPrototypeOf(dependencies) !== Object.prototype && Object.getPrototypeOf(dependencies) !== null) ||
        Object.getOwnPropertySymbols(dependencies).length !== 0) {
      fail('CLI_DEPENDENCY_INVALID', '$.dependencies', 1);
    }
    const names = Object.getOwnPropertyNames(dependencies);
    if (names.some((name) => name !== 'loadScenarioFile')) fail('CLI_DEPENDENCY_INVALID', '$.dependencies', 1);
    const descriptor = Object.getOwnPropertyDescriptor(dependencies, 'loadScenarioFile');
    if (descriptor && (!descriptor.enumerable || !hasOwn(descriptor, 'value'))) {
      fail('CLI_DEPENDENCY_INVALID', '$.dependencies.loadScenarioFile', 1);
    }
    const loader = descriptor === undefined ? loadScenarioFromFile : descriptor.value;
    if (typeof loader !== 'function') fail('CLI_DEPENDENCY_INVALID', '$.dependencies.loadScenarioFile', 1);
    const argv = argvData(argvInput);
    command = argv[0] || 'unknown';
    const envelope = translateArgv(argv, loader);
    const dispatched = dispatchT8Control(state, envelope);
    return freeze({
      state: dispatched.state,
      exit_code: dispatched.exit_code,
      stdout: `${JSON.stringify(dispatched.output)}\n`,
      stderr: ''
    });
  } catch (error) {
    const classified = classifyCaughtError(error);
    return freeze({
      state: controlBrand.has(control) ? control : createT8Control(),
      exit_code: classified.exit_code,
      stdout: `${JSON.stringify(failureOutput(command, classified.reason_code))}\n`,
      stderr: ''
    });
  }
}

module.exports = {
  T8ControlError,
  createT8Control,
  dispatchT8Control,
  executeT8Cli
};
