'use strict';

const moduleBrand = new WeakSet();

class UpnpSoapBoundaryError extends Error {
  constructor() {
    super('UPNP_SOAP_BOUNDARY_INVALID at $');
    this.name = 'UpnpSoapBoundaryError';
    this.reason_code = 'UPNP_SOAP_BOUNDARY_INVALID';
    this.field_path = '$';
  }
}

function createUpnpSoapControl() {
  if (arguments.length !== 0) throw new UpnpSoapBoundaryError();
  const result = Object.freeze({
    surface: 'soap-control',
    transport: 'http',
    operations: Object.freeze(['control-action']),
  });
  moduleBrand.add(result);
  return result;
}

function isUpnpSoapControl(value) {
  return moduleBrand.has(value);
}

module.exports = Object.freeze({
  UpnpSoapBoundaryError,
  createUpnpSoapControl,
  isUpnpSoapControl,
});
