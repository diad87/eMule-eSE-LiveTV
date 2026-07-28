'use strict';

const moduleBrand = new WeakSet();

class UpnpSsdpBoundaryError extends Error {
  constructor() {
    super('UPNP_SSDP_BOUNDARY_INVALID at $');
    this.name = 'UpnpSsdpBoundaryError';
    this.reason_code = 'UPNP_SSDP_BOUNDARY_INVALID';
    this.field_path = '$';
  }
}

function createUpnpSsdpDiscovery() {
  if (arguments.length !== 0) throw new UpnpSsdpBoundaryError();
  const result = Object.freeze({
    surface: 'ssdp-discovery',
    transport: 'udp',
    operations: Object.freeze(['m-search']),
  });
  moduleBrand.add(result);
  return result;
}

function isUpnpSsdpDiscovery(value) {
  return moduleBrand.has(value);
}

module.exports = Object.freeze({
  UpnpSsdpBoundaryError,
  createUpnpSsdpDiscovery,
  isUpnpSsdpDiscovery,
});
