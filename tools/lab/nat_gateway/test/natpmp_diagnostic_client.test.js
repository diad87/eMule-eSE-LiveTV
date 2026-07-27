'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { createNatPmpUdpServer } = require('../natpmp_udp_server');
const { runNatPmpDiagnostic, NatPmpDiagnosticError } = require('../natpmp_diagnostic_client');

test('C06: real diagnostic client observes request, parses response and reaches mapped state', async (t) => {
  const commands = [];
  const server = createNatPmpUdpServer({
    bind_address: '127.0.0.1',
    port: 0,
    allow_ephemeral_port_for_test: true,
    allowed_source_addresses: ['127.0.0.1'],
    application(command) {
      commands.push(command);
      return {
        response_type: 'map', transport: 'tcp', result_code: 0, epoch: 17,
        internal_port: command.internal_port, external_port: 52144, lifetime_seconds: 120,
      };
    },
    event_sink() {},
  });
  const target = await server.start(); t.after(() => server.close());
  const state = await runNatPmpDiagnostic({
    gateway_address: target.address,
    gateway_port: target.port,
    internal_port: 4662,
    suggested_external_port: 0,
    lifetime_seconds: 3600,
    timeout_ms: 1000,
  });
  assert.equal(commands.length, 1);
  assert.deepEqual(commands[0], {
    protocol: 'natpmp', operation: 'map', transport: 'tcp',
    internal_port: 4662, suggested_external_port: 0, lifetime_seconds: 3600,
  });
  assert.deepEqual(state, {
    status: 'mapped', transport: 'tcp', internal_port: 4662,
    external_port: 52144, lifetime_seconds: 120, epoch: 17,
  });
});

test('C06: diagnostic client rejects unsafe targets and times out boundedly', async () => {
  const base = {
    gateway_address: '127.0.0.1', gateway_port: 9, internal_port: 4662,
    suggested_external_port: 0, lifetime_seconds: 60, timeout_ms: 10,
  };
  await assert.rejects(runNatPmpDiagnostic({ ...base, gateway_address: '0.0.0.0' }), NatPmpDiagnosticError);
  await assert.rejects(runNatPmpDiagnostic(base), (error) => error.reason_code === 'NATPMP_DIAGNOSTIC_TIMEOUT');
});

test('C06: diagnostic configuration rejects every unsafe scalar boundary', async () => {
  const base = {
    gateway_address: '127.0.0.1', gateway_port: 5351, internal_port: 4662,
    suggested_external_port: 0, lifetime_seconds: 60, timeout_ms: 100,
  };
  const invalid = [
    null, {}, { ...base, extra: true }, new Proxy(base, {}),
    { ...base, gateway_address: 1 }, { ...base, gateway_address: '127.0.0.2' },
    { ...base, gateway_port: 1.5 }, { ...base, gateway_port: 0 }, { ...base, gateway_port: 65536 },
    { ...base, internal_port: 0 }, { ...base, internal_port: 65536 }, { ...base, internal_port: 1.5 },
    { ...base, suggested_external_port: -1 }, { ...base, suggested_external_port: 65536 },
    { ...base, lifetime_seconds: 1.5 }, { ...base, lifetime_seconds: 0 }, { ...base, lifetime_seconds: 0x100000000 },
    { ...base, timeout_ms: 1.5 }, { ...base, timeout_ms: 0 }, { ...base, timeout_ms: 5001 },
  ];
  for (const value of invalid) {
    await assert.rejects(runNatPmpDiagnostic(value), (error) => error.reason_code === 'NATPMP_DIAGNOSTIC_CONFIG_INVALID');
  }
  const symbol = { ...base }; symbol[Symbol('x')] = true;
  await assert.rejects(runNatPmpDiagnostic(symbol), NatPmpDiagnosticError);
});

test('C06: diagnostic rejects every malformed success-response field', async () => {
  const mutations = [
    (packet) => packet.subarray(0, 15),
    (packet) => { packet[0] = 1; return packet; },
    (packet) => { packet[1] = 129; return packet; },
    (packet) => { packet.writeUInt16BE(3, 2); return packet; },
    (packet) => { packet.writeUInt16BE(1, 8); return packet; },
    (packet) => { packet.writeUInt16BE(0, 10); return packet; },
    (packet) => { packet.writeUInt32BE(0, 12); return packet; },
  ];
  for (const mutate of mutations) {
    const server = createNatPmpUdpServer({
      bind_address: '127.0.0.1', port: 0, allow_ephemeral_port_for_test: true,
      allowed_source_addresses: ['127.0.0.1'],
      application(command) {
        return {
          response_type: 'map', transport: 'tcp', result_code: 0, epoch: 1,
          internal_port: command.internal_port, external_port: 2, lifetime_seconds: 3,
        };
      },
      event_sink() {},
    }, {
      response_fault(packet) { return mutate(Buffer.from(packet)); },
    });
    const target = await server.start();
    await assert.rejects(runNatPmpDiagnostic({
      gateway_address: target.address, gateway_port: target.port, internal_port: 4662,
      suggested_external_port: 0, lifetime_seconds: 60, timeout_ms: 1000,
    }), (error) => error.reason_code === 'NATPMP_DIAGNOSTIC_RESPONSE_INVALID');
    await server.close();
  }
});

test('C06: foreign-source datagram cannot consume the exact-gateway response listener', async () => {
  const gateway = dgram.createSocket('udp4'); const foreign = dgram.createSocket('udp4');
  const bind = (socket) => new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
  const close = (socket) => new Promise((resolve) => socket.close(resolve));
  await bind(gateway); await bind(foreign);
  gateway.once('message', (request, source) => {
    const response = Buffer.alloc(16); response[1] = 130; response.writeUInt32BE(1, 4);
    response.writeUInt16BE(request.readUInt16BE(4), 8); response.writeUInt16BE(9, 10); response.writeUInt32BE(10, 12);
    foreign.send(response, source.port, source.address, () => {
      setImmediate(() => gateway.send(response, source.port, source.address));
    });
  });
  const state = await runNatPmpDiagnostic({
    gateway_address: '127.0.0.1', gateway_port: gateway.address().port, internal_port: 4662,
    suggested_external_port: 0, lifetime_seconds: 60, timeout_ms: 1000,
  });
  assert.equal(state.status, 'mapped'); assert.equal(state.external_port, 9);
  await close(gateway); await close(foreign);
});
