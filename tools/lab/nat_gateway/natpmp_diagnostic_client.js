'use strict';

const dgram = require('node:dgram');
const { types } = require('node:util');

const objectPrototype = Object.prototype;
const IPV4 = /^(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$/;

class NatPmpDiagnosticError extends Error {
  constructor(reasonCode) {
    super(reasonCode);
    this.name = 'NatPmpDiagnosticError';
    this.reason_code = reasonCode;
  }
}
function fail(code) { throw new NatPmpDiagnosticError(code); }
function dataObject(value) {
  return value !== null && typeof value === 'object' &&
    !types.isProxy(value) && Object.getPrototypeOf(value) === objectPrototype;
}
function ownData(value, key) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable ? descriptor.value : undefined;
}
function config(input) {
  const keys = ['gateway_address', 'gateway_port', 'internal_port', 'suggested_external_port', 'lifetime_seconds', 'timeout_ms'];
  if (!dataObject(input) || Object.getOwnPropertySymbols(input).length ||
      Object.getOwnPropertyNames(input).length !== keys.length ||
      Object.getOwnPropertyNames(input).some((key) => !keys.includes(key))) fail('NATPMP_DIAGNOSTIC_CONFIG_INVALID');
  const value = Object.fromEntries(keys.map((key) => [key, ownData(input, key)]));
  if (typeof value.gateway_address !== 'string' || !IPV4.test(value.gateway_address) ||
      value.gateway_address !== '127.0.0.1' ||
      !Number.isInteger(value.gateway_port) || value.gateway_port < 1 || value.gateway_port > 65535 ||
      !Number.isInteger(value.internal_port) || value.internal_port < 1 || value.internal_port > 65535 ||
      !Number.isInteger(value.suggested_external_port) || value.suggested_external_port < 0 || value.suggested_external_port > 65535 ||
      !Number.isInteger(value.lifetime_seconds) || value.lifetime_seconds < 1 || value.lifetime_seconds > 0xffffffff ||
      !Number.isInteger(value.timeout_ms) || value.timeout_ms < 1 || value.timeout_ms > 5000) fail('NATPMP_DIAGNOSTIC_CONFIG_INVALID');
  return Object.freeze(value);
}
function request(value) {
  const packet = Buffer.alloc(12); packet[1] = 2;
  packet.writeUInt16BE(value.internal_port, 4);
  packet.writeUInt16BE(value.suggested_external_port, 6);
  packet.writeUInt32BE(value.lifetime_seconds, 8);
  return packet;
}
function parse(packet, value) {
  if (!Buffer.isBuffer(packet) || packet.length !== 16 || packet[0] !== 0 || packet[1] !== 130 ||
      packet.readUInt16BE(2) !== 0 || packet.readUInt16BE(8) !== value.internal_port ||
      packet.readUInt16BE(10) === 0 || packet.readUInt32BE(12) === 0) fail('NATPMP_DIAGNOSTIC_RESPONSE_INVALID');
  return Object.freeze({
    status: 'mapped',
    transport: 'tcp',
    internal_port: value.internal_port,
    external_port: packet.readUInt16BE(10),
    lifetime_seconds: packet.readUInt32BE(12),
    epoch: packet.readUInt32BE(4),
  });
}

async function runNatPmpDiagnostic(input) {
  const value = config(input); const socket = dgram.createSocket('udp4');
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (error, result) => {
      if (done) return; done = true; clearTimeout(timer);
      socket.removeAllListeners(); try { socket.close(); } catch {}
      if (error) reject(error); else resolve(result);
    };
    const timer = setTimeout(() => finish(new NatPmpDiagnosticError('NATPMP_DIAGNOSTIC_TIMEOUT')), value.timeout_ms);
    socket.once('error', () => finish(new NatPmpDiagnosticError('NATPMP_DIAGNOSTIC_SOCKET_FAILED')));
    socket.on('message', (packet, source) => {
      if (!dataObject(source) || ownData(source, 'address') !== value.gateway_address ||
          ownData(source, 'port') !== value.gateway_port) return;
      try { finish(null, parse(packet, value)); } catch (error) { finish(error); }
    });
    try {
      socket.bind(0, '127.0.0.1', () => socket.send(request(value), value.gateway_port, value.gateway_address, (error) => {
        if (error) finish(new NatPmpDiagnosticError('NATPMP_DIAGNOSTIC_SEND_FAILED'));
      }));
    } catch { finish(new NatPmpDiagnosticError('NATPMP_DIAGNOSTIC_SOCKET_FAILED')); }
  });
}

module.exports = Object.freeze({ NatPmpDiagnosticError, runNatPmpDiagnostic });
