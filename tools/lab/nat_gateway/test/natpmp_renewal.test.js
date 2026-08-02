'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { VirtualMonotonicClock } = require('../clock');
const {
  createMappingState,
  createMapping,
  renewMapping,
  snapshotInternalMappings,
} = require('../mapping_model');
const { createNatPmpUdpServer } = require('../natpmp_udp_server');
const { runNatPmpDiagnostic } = require('../natpmp_diagnostic_client');

const OWNER = Object.freeze({
  kind: 'natpmp-lease-scope',
  instance_id_digest: 'a'.repeat(64),
  scope_id: 'j04-client-scope',
});

test('J04: T8 performs three NAT-PMP renewals with virtual time and stable identity', async (t) => {
  const initialClockMs = 1000;
  const initialGatewayEpoch = 17;
  const clock = new VirtualMonotonicClock(initialClockMs);
  let mappingState = createMappingState({
    epoch: 17,
    generation: 7,
    mappings: [],
  });
  const commands = [];
  const events = [];

  const server = createNatPmpUdpServer({
    bind_address: '127.0.0.1',
    port: 0,
    allow_ephemeral_port_for_test: true,
    allowed_source_addresses: ['127.0.0.1'],
    application(command, source) {
      commands.push(command);
      const current = snapshotInternalMappings(mappingState);
      if (current.length === 0) {
        mappingState = createMapping(mappingState, {
          mapping_id: 'j04-tcp',
          protocol: 'natpmp',
          transport: command.transport,
          client_id: 'j04-client',
          internal_address: source.address,
          internal_port: command.internal_port,
          requested_external_port: command.suggested_external_port,
          external_address: '198.51.100.44',
          external_port: 52144,
          lease: {
            lifetime_seconds: command.lifetime_seconds,
            created_monotonic_ms: clock.now_ms(),
            expires_monotonic_ms:
              clock.now_ms() + command.lifetime_seconds * 1000,
          },
          owner: OWNER,
          epoch: mappingState.epoch,
          generation: mappingState.generation,
        }).state;
      } else {
        mappingState = renewMapping(mappingState, {
          mapping_id: 'j04-tcp',
          epoch: mappingState.epoch,
          generation: mappingState.generation,
          owner: OWNER,
          lifetime_seconds: command.lifetime_seconds,
          now_monotonic_ms: clock.now_ms(),
        }).state;
      }
      return {
        response_type: 'map',
        transport: command.transport,
        result_code: 0,
        epoch: initialGatewayEpoch
          + Math.floor((clock.now_ms() - initialClockMs) / 1000),
        internal_port: command.internal_port,
        external_port: 52144,
        lifetime_seconds: command.lifetime_seconds,
      };
    },
    event_sink(event) { events.push(event); },
  });

  const target = await server.start();
  t.after(() => server.close());
  const request = (suggestedExternalPort) => runNatPmpDiagnostic({
    gateway_address: target.address,
    gateway_port: target.port,
    internal_port: 4662,
    suggested_external_port: suggestedExternalPort,
    lifetime_seconds: 100,
    timeout_ms: 1000,
  });

  const initial = await request(0);
  assert.deepEqual(initial, {
    status: 'mapped',
    transport: 'tcp',
    internal_port: 4662,
    external_port: 52144,
    lifetime_seconds: 100,
    epoch: 17,
  });
  const initialMapping = snapshotInternalMappings(mappingState)[0];

  for (let renewal = 1; renewal <= 3; renewal += 1) {
    clock.advance_ms(45000);
    const response = await request(52144);
    assert.deepEqual(response, {
      status: 'mapped',
      transport: 'tcp',
      internal_port: 4662,
      external_port: 52144,
      lifetime_seconds: 100,
      epoch: initialGatewayEpoch + renewal * 45,
    });
    const [mapping] = snapshotInternalMappings(mappingState);
    assert.equal(mapping.mapping_id, initialMapping.mapping_id);
    assert.equal(mapping.generation, initialMapping.generation);
    assert.equal(mapping.internal_port, initialMapping.internal_port);
    assert.equal(mapping.external_port, initialMapping.external_port);
    assert.deepEqual(mapping.owner, initialMapping.owner);
    assert.equal(mapping.lease.created_monotonic_ms, clock.now_ms());
    assert.equal(
      mapping.lease.expires_monotonic_ms,
      clock.now_ms() + 100000,
    );
  }

  assert.deepEqual(commands, [
    {
      protocol: 'natpmp',
      operation: 'map',
      transport: 'tcp',
      internal_port: 4662,
      suggested_external_port: 0,
      lifetime_seconds: 100,
    },
    ...Array.from({ length: 3 }, () => ({
      protocol: 'natpmp',
      operation: 'map',
      transport: 'tcp',
      internal_port: 4662,
      suggested_external_port: 52144,
      lifetime_seconds: 100,
    })),
  ]);
  assert.equal(snapshotInternalMappings(mappingState).length, 1);
  assert.equal(
    events.filter((event) => event.reason_code === 'response-sent').length,
    4,
  );
});
