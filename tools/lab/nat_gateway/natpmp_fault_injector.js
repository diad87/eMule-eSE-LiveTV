'use strict';

const { types } = require('node:util');
const { setTimeout: delayTimer } = require('node:timers/promises');

const objectPrototype = Object.prototype;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const rejectCodes = new Map([
  ['unsupported-version', 1],
  ['not-authorized', 2],
  ['network-failure', 3],
  ['out-of-resources', 4],
  ['unsupported-opcode', 5],
]);

class NatPmpFaultError extends Error {
  constructor(reasonCode) {
    super(reasonCode);
    this.name = 'NatPmpFaultError';
    this.reason_code = reasonCode;
  }
}

function fail(code) { throw new NatPmpFaultError(code); }
function dataObject(value) {
  return value !== null && typeof value === 'object' &&
    !types.isProxy(value) && Object.getPrototypeOf(value) === objectPrototype;
}
function ownData(object, key) {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable
    ? descriptor.value
    : undefined;
}
function exactDataObject(value, keys) {
  if (!dataObject(value) || Object.getOwnPropertySymbols(value).length) fail('NATPMP_FAULT_INVALID');
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== keys.length || names.some((name) => !keys.includes(name))) fail('NATPMP_FAULT_INVALID');
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail('NATPMP_FAULT_INVALID');
  }
}
function copyPacket(value) {
  if (types.isProxy(value) || !types.isUint8Array(value)) fail('NATPMP_FAULT_PACKET_INVALID');
  let length; let buffer; let offset;
  try {
    length = bufferLengthGetter.call(value);
    buffer = bufferGetter.call(value);
    offset = byteOffsetGetter.call(value);
  } catch { fail('NATPMP_FAULT_PACKET_INVALID'); }
  if (length !== 12 && length !== 16) fail('NATPMP_FAULT_PACKET_INVALID');
  if (types.isSharedArrayBuffer(buffer)) fail('NATPMP_FAULT_PACKET_INVALID');
  try { return Buffer.from(Buffer.from(buffer, offset, length)); } catch { fail('NATPMP_FAULT_PACKET_INVALID'); }
}
function normalizeAction(input) {
  if (!dataObject(input)) fail('NATPMP_FAULT_INVALID');
  const type = ownData(input, 'type');
  if (type === 'drop') {
    exactDataObject(input, ['type']);
    return Object.freeze({ type });
  }
  if (type === 'delay') {
    exactDataObject(input, ['type', 'delay_ms', 'jitter_ms']);
    const delayMs = ownData(input, 'delay_ms'); const jitterMs = ownData(input, 'jitter_ms');
    if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > 0xffffffff ||
        !Number.isInteger(jitterMs) || jitterMs !== 0) fail('NATPMP_FAULT_INVALID');
    return Object.freeze({ type, delay_ms: delayMs });
  }
  if (type === 'reject') {
    exactDataObject(input, ['type', 'result_code']);
    const resultCode = ownData(input, 'result_code');
    if (!rejectCodes.has(resultCode)) fail('NATPMP_FAULT_INVALID');
    return Object.freeze({ type, result_code: rejectCodes.get(resultCode) });
  }
  fail('NATPMP_FAULT_UNSUPPORTED');
}

function createNatPmpFaultInjector(actionInput, dependencies = {}) {
  const action = normalizeAction(actionInput);
  if (!dataObject(dependencies)) fail('NATPMP_FAULT_DEPENDENCIES_INVALID');
  const hasSleep = Object.hasOwn(dependencies, 'sleep');
  exactDataObject(dependencies, hasSleep ? ['sleep'] : []);
  const sleep = hasSleep
    ? ownData(dependencies, 'sleep')
    : ((milliseconds, signal) => delayTimer(milliseconds, undefined, { signal }));
  if (typeof sleep !== 'function') fail('NATPMP_FAULT_DEPENDENCIES_INVALID');
  return async function injectNatPmpFault(packet, command, signal) {
    const snapshot = copyPacket(packet);
    if (!dataObject(command) || !Object.isFrozen(command)) fail('NATPMP_FAULT_COMMAND_INVALID');
    if (!(signal instanceof AbortSignal)) fail('NATPMP_FAULT_SIGNAL_INVALID');
    if (signal.aborted) fail('NATPMP_FAULT_ABORTED');
    if (action.type === 'drop') return null;
    if (action.type === 'delay') {
      try { await sleep(action.delay_ms, signal); } catch { fail(signal.aborted ? 'NATPMP_FAULT_ABORTED' : 'NATPMP_FAULT_DELAY_FAILED'); }
      if (signal.aborted) fail('NATPMP_FAULT_ABORTED');
      return snapshot;
    }
    if (action.type === 'reject') {
      snapshot.writeUInt16BE(action.result_code, 2);
      if (snapshot.length === 12) snapshot.fill(0, 8, 12);
      else snapshot.fill(0, 10, 16);
      return snapshot;
    }
    fail('NATPMP_FAULT_UNSUPPORTED');
  };
}

module.exports = Object.freeze({ NatPmpFaultError, createNatPmpFaultInjector });
