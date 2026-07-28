'use strict';

const moduleBrand = new WeakSet();

class UpnpDescriptionBoundaryError extends Error {
  constructor() {
    super('UPNP_DESCRIPTION_BOUNDARY_INVALID at $');
    this.name = 'UpnpDescriptionBoundaryError';
    this.reason_code = 'UPNP_DESCRIPTION_BOUNDARY_INVALID';
    this.field_path = '$';
  }
}

function createUpnpDescriptionHttp() {
  if (arguments.length !== 0) throw new UpnpDescriptionBoundaryError();
  const result = Object.freeze({
    surface: 'description-http',
    transport: 'http',
    operations: Object.freeze([
      'device-document',
      'service-document',
    ]),
  });
  moduleBrand.add(result);
  return result;
}

function isUpnpDescriptionHttp(value) {
  return moduleBrand.has(value);
}

module.exports = Object.freeze({
  UpnpDescriptionBoundaryError,
  createUpnpDescriptionHttp,
  isUpnpDescriptionHttp,
});
