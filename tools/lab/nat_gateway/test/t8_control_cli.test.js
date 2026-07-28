'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  T8ControlError,
  createT8Control,
  dispatchT8Control,
  executeT8Cli
} = require('../t8_control_cli');

const INSTANCE = 'a'.repeat(64);

function scenario() {
  return {
    schema_version: 'ese.v92.t8.scenario/v1',
    scenario_id: 'cli-scenario',
    seed: 1,
    clock: { mode: 'virtual', start_monotonic_ms: 1000 },
    gateway: {
      gateway_id: 'gateway-1',
      epoch: { initial_seconds: 10, restart_seconds: 1 },
      initial_generation: 4,
      wan_address: '198.51.100.1',
      lan_addresses: ['192.0.2.1']
    },
    listeners: {
      upnp: { interface_id: 'lan-1', bind_address: '192.0.2.1', ssdp_port: 1900, http_port: 5000 },
      pcp: { interface_id: 'lan-1', bind_address: '192.0.2.1', port: 5351 },
      natpmp: { interface_id: 'lan-1', bind_address: '192.0.2.1', port: 5350 }
    },
    protocols: {
      upnp: { enabled: false, igd_version: 'v1', readback: 'full' },
      pcp: { enabled: true },
      natpmp: { enabled: false }
    },
    allocation: { strategy: 'range', range_start: 45000, range_end: 45010 },
    initial_state: {
      mappings: [{
        mapping_id: 'map-1',
        protocol: 'pcp',
        transport: 'tcp',
        client_id: 'client-1',
        internal_address: '192.0.2.10',
        internal_port: 4662,
        requested_external_port: 45000,
        external_address: '198.51.100.1',
        external_port: 45000,
        lease: { lifetime_seconds: 1, created_monotonic_ms: 1000, expires_monotonic_ms: 2000 },
        owner: { kind: 'pcp-nonce', instance_id_digest: INSTANCE, nonce: 'b'.repeat(24) },
        epoch: 10,
        generation: 4
      }],
      request_counters: { total: 0, upnp: 0, pcp: 0, natpmp: 0 },
      response_queue: []
    },
    faults: [],
    privacy: {
      report_mode: 'sanitized',
      address_mode: 'class-only',
      nonce_mode: 'sha256',
      payload_mode: 'omitted',
      allow_credentials: false
    }
  };
}

function run(state, argv) {
  return executeT8Cli(state, argv, { loadScenarioFile: () => scenario() });
}

function output(result) {
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.endsWith('\n'), true);
  assert.equal(result.stdout.split('\n').length, 2);
  return JSON.parse(result.stdout);
}

test('F03 all required CLI commands return exit code zero and one JSON line', () => {
  let state = createT8Control();
  let call = run(state, ['status']);
  assert.equal(call.exit_code, 0);
  assert.equal(output(call).status, 'stopped');
  state = call.state;

  call = run(state, ['load', 'scenario.json']);
  assert.equal(call.exit_code, 0);
  assert.equal(output(call).status, 'loaded');
  assert.equal(output(call).generation, 4);
  state = call.state;

  call = run(state, ['list']);
  const listed = output(call);
  assert.equal(listed.mapping_count, 1);
  const serialized = call.stdout;
  for (const secret of ['192.0.2.10', '198.51.100.1', INSTANCE, 'b'.repeat(24), '"mapping_id":"map-1"']) {
    assert.equal(serialized.includes(secret), false);
  }

  call = run(state, ['drop-next', 'pcp']);
  assert.equal(output(call).pending_drop_count, 1);
  assert.equal(output(call).fault_id, 'cli-drop-2');
  state = call.state;

  call = run(state, ['expire', '2000']);
  assert.equal(output(call).expired_mapping_count, 1);
  assert.equal(output(call).mapping_count, 0);
  state = call.state;

  call = run(state, ['reset']);
  assert.equal(output(call).mapping_count, 1);
  assert.equal(output(call).generation, 5);
  state = call.state;

  call = run(state, ['restart-epoch', '7']);
  assert.equal(output(call).removed_mapping_count, 1);
  assert.equal(output(call).epoch, 7);
  assert.equal(output(call).generation, 6);
  state = call.state;

  call = run(state, ['stop']);
  assert.equal(output(call).status, 'stopped');
  assert.equal(call.state.status, 'stopped');
});

test('F03 CLI exit codes distinguish usage failures from state/operation failures', () => {
  const stopped = createT8Control();
  for (const argv of [
    [],
    ['unknown'],
    ['status', 'extra'],
    ['restart-epoch', '-1'],
    ['expire', '01'],
    ['drop-next', 'icmp']
  ]) {
    const call = run(stopped, argv);
    assert.equal(call.exit_code, 2);
    assert.equal(output(call).ok, false);
  }
  const notLoaded = run(stopped, ['list']);
  assert.equal(notLoaded.exit_code, 1);
  assert.equal(output(notLoaded).reason_code, 'CONTROL_NOT_LOADED');

  const loaded = run(stopped, ['load', 'scenario.json']).state;
  const duplicateLoad = run(loaded, ['load', 'scenario.json']);
  assert.equal(duplicateLoad.exit_code, 1);
  const regression = run(loaded, ['expire', '999']);
  assert.equal(regression.exit_code, 1);
  assert.equal(output(regression).reason_code, 'CONTROL_TIME_REGRESSION');
});

test('F03 object dispatcher and CLI share the same immutable state transition', () => {
  const initial = createT8Control();
  const loaded = dispatchT8Control(initial, { command: 'load', arguments: { scenario: scenario() } });
  assert.equal(initial.status, 'stopped');
  assert.equal(loaded.state.status, 'loaded');
  assert.ok(Object.isFrozen(loaded.state));
  assert.ok(Object.isFrozen(loaded.output));
  const status = dispatchT8Control(loaded.state, { command: 'status', arguments: {} });
  assert.equal(status.state, loaded.state);
  assert.equal(status.output.mapping_count, 1);
  assert.throws(
    () => dispatchT8Control({}, { command: 'status', arguments: {} }),
    (error) => error instanceof T8ControlError && error.reason_code === 'CONTROL_STATE_INVALID'
  );
});

test('F03 rejects hostile argv, envelopes and dependencies without invoking traps or leaking errors', () => {
  const state = createT8Control();
  let traps = 0;
  const trap = () => { traps += 1; throw new Error('secret'); };
  const hostileArgv = new Proxy(['status'], { get: trap, ownKeys: trap });
  const argvResult = run(state, hostileArgv);
  assert.equal(argvResult.exit_code, 2);
  assert.equal(argvResult.stdout.includes('secret'), false);
  assert.equal(traps, 0);

  const sparse = new Array(1);
  assert.equal(run(state, sparse).exit_code, 2);
  const decorated = ['status']; decorated.extra = true;
  assert.equal(run(state, decorated).exit_code, 2);
  const accessor = ['status'];
  Object.defineProperty(accessor, '0', { enumerable: true, get: trap });
  assert.equal(run(state, accessor).exit_code, 2);
  assert.equal(traps, 0);

  const dependencyFailure = executeT8Cli(state, ['load', 'x'], {
    loadScenarioFile: () => { throw new Error('private path'); }
  });
  assert.equal(dependencyFailure.exit_code, 1);
  assert.equal(output(dependencyFailure).reason_code, 'CLI_COMMAND_FAILED');
  assert.equal(dependencyFailure.stdout.includes('private path'), false);

  const hostileThrown = new Proxy(new Error('private'), {
    getPrototypeOf: trap,
    getOwnPropertyDescriptor: trap,
    get: trap
  });
  const hostileFailure = executeT8Cli(state, ['load', 'x'], {
    loadScenarioFile: () => { throw hostileThrown; }
  });
  assert.equal(hostileFailure.exit_code, 1);
  assert.equal(output(hostileFailure).reason_code, 'CLI_COMMAND_FAILED');
  assert.equal(traps, 0);

  const forgedReason = executeT8Cli(state, ['load', 'x'], {
    loadScenarioFile: () => { throw { reason_code: 'PRIVATE_PATH_SECRET_123' }; }
  });
  assert.equal(output(forgedReason).reason_code, 'CLI_COMMAND_FAILED');
  assert.equal(forgedReason.stdout.includes('PRIVATE_PATH_SECRET_123'), false);

  for (const forgedError of [
    new T8ControlError('PRIVATE_SECRET_123', '$', 1),
    Object.assign(Object.create(T8ControlError.prototype), {
      reason_code: 'FORGED_SECRET',
      exit_code: 1
    })
  ]) {
    const forgedFailure = executeT8Cli(state, ['load', 'x'], {
      loadScenarioFile: () => { throw forgedError; }
    });
    assert.equal(output(forgedFailure).reason_code, 'CLI_COMMAND_FAILED');
    assert.equal(forgedFailure.stdout.includes('SECRET'), false);
  }

  const accessorDependency = {};
  Object.defineProperty(accessorDependency, 'loadScenarioFile', {
    enumerable: true,
    get: trap
  });
  assert.equal(executeT8Cli(state, ['status'], accessorDependency).exit_code, 1);
  assert.equal(traps, 0);

  const envelope = new Proxy({ command: 'status', arguments: {} }, {});
  assert.throws(() => dispatchT8Control(state, envelope), T8ControlError);
});

test('F03 closed boundaries cover command shapes, scalar limits and dependency storage', () => {
  const state = createT8Control();
  for (const envelope of [
    { command: 'status' },
    { command: 'status', arguments: {}, extra: true },
    { command: 1, arguments: {} },
    { command: 'unknown', arguments: {} },
    { command: 'restart-epoch', arguments: { restart_seconds: -0 } }
  ]) {
    assert.throws(() => dispatchT8Control(state, envelope), T8ControlError);
  }
  const accessorEnvelope = { command: 'status', arguments: {} };
  Object.defineProperty(accessorEnvelope, 'command', { enumerable: true, get: () => 'status' });
  assert.throws(() => dispatchT8Control(state, accessorEnvelope), T8ControlError);

  for (const argv of [
    [1],
    [''],
    ['x'.repeat(4097)],
    ['status\0'],
    ['status\n'],
    ['a', 'b', 'c', 'd']
  ]) {
    assert.equal(executeT8Cli(state, argv).exit_code, 2);
  }
  const symbolArgv = ['status']; symbolArgv[Symbol('x')] = true;
  assert.equal(executeT8Cli(state, symbolArgv).exit_code, 2);
  const subclassArgv = new (class Args extends Array {} )('status');
  assert.equal(executeT8Cli(state, subclassArgv).exit_code, 2);

  for (const dependencies of [
    null,
    [],
    { extra: true },
    { loadScenarioFile: 1 },
    new (class Dependencies {})()
  ]) {
    assert.equal(executeT8Cli(state, ['status'], dependencies).exit_code, 1);
  }
  const symbolDependencies = {};
  symbolDependencies[Symbol('x')] = true;
  assert.equal(executeT8Cli(state, ['status'], symbolDependencies).exit_code, 1);
});

test('F03 covers stopped stop, real-clock load and exhausted reset generation', () => {
  const stopped = executeT8Cli(createT8Control(), ['stop']);
  assert.equal(output(stopped).removed_mapping_count, 0);

  const realScenario = scenario();
  realScenario.clock = { mode: 'real' };
  const realLoaded = executeT8Cli(createT8Control(), ['load', 'x'], {
    loadScenarioFile: () => realScenario
  });
  assert.equal(output(executeT8Cli(realLoaded.state, ['status'])).monotonic_ms, 0);

  const exhaustedScenario = scenario();
  exhaustedScenario.gateway.initial_generation = Number.MAX_SAFE_INTEGER;
  exhaustedScenario.initial_state.mappings[0].generation = Number.MAX_SAFE_INTEGER;
  const exhausted = executeT8Cli(createT8Control(), ['load', 'x'], {
    loadScenarioFile: () => exhaustedScenario
  });
  const reset = executeT8Cli(exhausted.state, ['reset']);
  assert.equal(reset.exit_code, 1);
  assert.equal(output(reset).reason_code, 'CONTROL_GENERATION_EXHAUSTED');
});
