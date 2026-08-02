'use strict';

const { types } = require('node:util');
const {
  isUpnpSsdpDiscovery,
} = require('./upnp_ssdp_discovery');
const {
  isUpnpDescriptionHttp,
} = require('./upnp_description_http');
const {
  isUpnpSoapControl,
} = require('./upnp_soap_control');

class UpnpModuleCompositionError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpModuleCompositionError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpModuleCompositionError(reasonCode, fieldPath);
}

function createUpnpIgdModules(input) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_MODULE_COMPOSITION_INVALID', '$');
  }
  const required = ['ssdp', 'description', 'soap'];
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_MODULE_COMPOSITION_INVALID', '$');
  }
  const modules = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_MODULE_COMPOSITION_INVALID', `$.${name}`);
    }
    modules[name] = descriptor.value;
  }
  if (!isUpnpSsdpDiscovery(modules.ssdp)) {
    fail('UPNP_MODULE_SURFACE_MISMATCH', '$.ssdp');
  }
  if (!isUpnpDescriptionHttp(modules.description)) {
    fail('UPNP_MODULE_SURFACE_MISMATCH', '$.description');
  }
  if (!isUpnpSoapControl(modules.soap)) {
    fail('UPNP_MODULE_SURFACE_MISMATCH', '$.soap');
  }
  return Object.freeze({
    ssdp: modules.ssdp,
    description: modules.description,
    soap: modules.soap,
  });
}

module.exports = Object.freeze({
  UpnpModuleCompositionError,
  createUpnpIgdModules,
});
