'use strict';

const { types } = require('node:util');
const dgram = require('node:dgram');
const { createNatPmpUdpServer } = require('./natpmp_udp_server');

const objectPrototype = Object.prototype;
const proxyNames = Object.freeze([
  'ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY',
  'all_proxy', 'https_proxy', 'http_proxy',
]);

class T8RouteProbeError extends Error {
  constructor(reasonCode) {
    super(reasonCode);
    this.name = 'T8RouteProbeError';
    this.reason_code = reasonCode;
  }
}
function fail(code) { throw new T8RouteProbeError(code); }
function dataObject(value) {
  return value !== null && typeof value === 'object' &&
    !types.isProxy(value) && Object.getPrototypeOf(value) === objectPrototype;
}
function ownData(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') &&
    descriptor.enumerable ? descriptor.value : undefined;
}
function snapshot(input) {
  const keys = ['gateway_address', 'client_address', 'mode'];
  if (!dataObject(input) || Object.getOwnPropertySymbols(input).length ||
      Object.getOwnPropertyNames(input).length !== keys.length ||
      Object.getOwnPropertyNames(input).some((key) => !keys.includes(key))) {
    fail('T8_ROUTE_PROBE_CONFIG_INVALID');
  }
  const value = Object.fromEntries(keys.map((key) => [key, ownData(input, key)]));
  if (value.mode !== 'baseline' && value.mode !== 'dns-proxy-perturbed') {
    fail('T8_ROUTE_PROBE_CONFIG_INVALID');
  }
  return Object.freeze(value);
}
function proxyEnvironment() {
  return proxyNames.filter((name) =>
    Object.hasOwn(process.env, name) && process.env[name] !== '');
}

function runLocalDiagnostic(value, gatewayPort) {
  const socket = dgram.createSocket('udp4');
  const request = Buffer.alloc(12);
  request[1] = 2;
  request.writeUInt16BE(4662, 4);
  request.writeUInt32BE(3600, 8);
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (error, result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      try { socket.close(); } catch {}
      if (error) reject(error); else resolve(result);
    };
    const timer = setTimeout(() =>
      finish(new T8RouteProbeError('T8_ROUTE_PROBE_TIMEOUT')), 2000);
    socket.once('error', () =>
      finish(new T8RouteProbeError('T8_ROUTE_PROBE_SOCKET_FAILED')));
    socket.on('message', (packet, source) => {
      if (!dataObject(source) ||
          ownData(source, 'address') !== value.gateway_address ||
          ownData(source, 'port') !== gatewayPort) return;
      if (!Buffer.isBuffer(packet) || packet.length !== 16 ||
          packet[0] !== 0 || packet[1] !== 130 ||
          packet.readUInt16BE(2) !== 0 ||
          packet.readUInt16BE(8) !== 4662 ||
          packet.readUInt16BE(10) !== 52144 ||
          packet.readUInt32BE(12) !== 120) {
        finish(new T8RouteProbeError('T8_ROUTE_PROBE_RESPONSE_INVALID'));
        return;
      }
      finish(null, Object.freeze({
        status: 'mapped',
        internal_port: packet.readUInt16BE(8),
        external_port: packet.readUInt16BE(10),
        lifetime_seconds: packet.readUInt32BE(12),
        epoch: packet.readUInt32BE(4),
      }));
    });
    try {
      // Both binds must succeed locally before any datagram can be sent.
      // Therefore an external/home-router address cannot become a target.
      socket.bind(0, value.client_address, () => {
        socket.send(request, gatewayPort, value.gateway_address, (error) => {
          if (error) {
            finish(new T8RouteProbeError('T8_ROUTE_PROBE_SEND_FAILED'));
          }
        });
      });
    } catch {
      finish(new T8RouteProbeError('T8_ROUTE_PROBE_SOCKET_FAILED'));
    }
  });
}

async function runT8MapperRouteProbe(input) {
  const value = snapshot(input);
  const configuredProxies = proxyEnvironment();
  if ((value.mode === 'baseline' && configuredProxies.length !== 0) ||
      (value.mode === 'dns-proxy-perturbed' &&
       configuredProxies.length !== proxyNames.length)) {
    fail('T8_ROUTE_PROBE_ENVIRONMENT_INVALID');
  }
  let observedSource = null;
  let observedCommand = null;
  const events = [];
  const server = createNatPmpUdpServer({
    bind_address: value.gateway_address,
    port: 5351,
    allowed_source_addresses: [value.client_address],
    application(command, source) {
      observedCommand = command;
      observedSource = source.address;
      return {
        response_type: 'map',
        transport: 'tcp',
        result_code: 0,
        epoch: 17,
        internal_port: command.internal_port,
        external_port: 52144,
        lifetime_seconds: 120,
      };
    },
    event_sink(event) { events.push(event); },
  });
  try {
    const bound = await server.start();
    const mapping = await runLocalDiagnostic(value, bound.port);
    const passed = bound.address === value.gateway_address &&
      observedSource === value.client_address &&
      observedCommand !== null &&
      observedCommand.protocol === 'natpmp' &&
      observedCommand.operation === 'map' &&
      observedCommand.transport === 'tcp' &&
      mapping.status === 'mapped' &&
      mapping.internal_port === 4662 &&
      mapping.external_port === 52144 &&
      events.some((event) => event.reason_code === 'request-received') &&
      events.some((event) => event.reason_code === 'response-sent');
    if (!passed) fail('T8_ROUTE_PROBE_ASSERTION_FAILED');
    return Object.freeze({
      schema: 'ese.v92.t8-mapper-route-probe/v1',
      verdict: 'PASS',
      mode: value.mode,
      mapper: Object.freeze({
        protocol: 'natpmp',
        gateway_port: bound.port,
        gateway_target_exact: bound.address === value.gateway_address,
        server_source_exact: observedSource === value.client_address,
        mapping_status: mapping.status,
        internal_port: mapping.internal_port,
        external_port: mapping.external_port,
        lifetime_seconds: mapping.lifetime_seconds,
        epoch: mapping.epoch,
      }),
      environment: Object.freeze({
        gateway_input_kind: 'literal-ipv4',
        client_input_kind: 'literal-ipv4',
        dns_hostname_lookup_count: 0,
        proxy_mode: value.mode === 'baseline' ? 'none' : 'intentionally-invalid',
        proxy_environment_names_set: Object.freeze([...configuredProxies].sort()),
      }),
    });
  } finally {
    await server.close();
  }
}

function parseArgv(argv) {
  if (!Array.isArray(argv) || argv.length !== 3) fail('T8_ROUTE_PROBE_ARGV_INVALID');
  const result = {};
  for (const item of argv) {
    if (typeof item !== 'string' || !item.startsWith('--') ||
        !item.includes('=')) fail('T8_ROUTE_PROBE_ARGV_INVALID');
    const index = item.indexOf('=');
    const key = item.slice(2, index);
    if (!['gateway', 'client', 'mode'].includes(key) ||
        Object.hasOwn(result, key)) fail('T8_ROUTE_PROBE_ARGV_INVALID');
    result[key] = item.slice(index + 1);
  }
  return {
    gateway_address: result.gateway,
    client_address: result.client,
    mode: result.mode,
  };
}

async function main() {
  try {
    const result = await runT8MapperRouteProbe(parseArgv(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const reason = error instanceof T8RouteProbeError ||
      (error && typeof error.reason_code === 'string')
      ? error.reason_code : 'T8_ROUTE_PROBE_INTERNAL_ERROR';
    process.stdout.write(`${JSON.stringify({
      schema: 'ese.v92.t8-mapper-route-probe/v1',
      verdict: 'FAIL',
      reason,
    })}\n`);
    process.exitCode = 1;
  }
}

if (require.main === module) void main();

module.exports = Object.freeze({
  T8RouteProbeError,
  runT8MapperRouteProbe,
});
