'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  UpnpSsdpBoundaryError,
  createUpnpSsdpDiscovery,
  isUpnpSsdpDiscovery,
} = require('../upnp_ssdp_discovery');
const {
  UpnpDescriptionBoundaryError,
  createUpnpDescriptionHttp,
  isUpnpDescriptionHttp,
} = require('../upnp_description_http');
const {
  UpnpSoapBoundaryError,
  createUpnpSoapControl,
  isUpnpSoapControl,
} = require('../upnp_soap_control');
const {
  UpnpModuleCompositionError,
  createUpnpIgdModules,
} = require('../upnp_igd_modules');

test('E01: SSDP, description HTTP and SOAP are fixed disjoint surfaces', () => {
  const ssdp = createUpnpSsdpDiscovery();
  const description = createUpnpDescriptionHttp();
  const soap = createUpnpSoapControl();
  assert.deepEqual(ssdp, {
    surface: 'ssdp-discovery',
    transport: 'udp',
    operations: ['m-search'],
  });
  assert.deepEqual(description, {
    surface: 'description-http',
    transport: 'http',
    operations: ['device-document', 'service-document'],
  });
  assert.deepEqual(soap, {
    surface: 'soap-control',
    transport: 'http',
    operations: ['control-action'],
  });
  for (const surface of [ssdp, description, soap]) {
    assert.ok(Object.isFrozen(surface));
    assert.ok(Object.isFrozen(surface.operations));
    assert.equal('handle_request' in surface, false);
  }
  assert.equal(isUpnpSsdpDiscovery(ssdp), true);
  assert.equal(isUpnpDescriptionHttp(description), true);
  assert.equal(isUpnpSoapControl(soap), true);
  assert.equal(isUpnpSsdpDiscovery(description), false);
  assert.equal(isUpnpDescriptionHttp(soap), false);
  assert.equal(isUpnpSoapControl(ssdp), false);
});

test('E01: surface constructors have no callback or universal-handler input', () => {
  const universal = () => 'universal';
  assert.throws(() => createUpnpSsdpDiscovery(universal),
    UpnpSsdpBoundaryError);
  assert.throws(() => createUpnpDescriptionHttp({ handler: universal }),
    UpnpDescriptionBoundaryError);
  assert.throws(() => createUpnpSoapControl({ invoke_action: universal }),
    UpnpSoapBoundaryError);
  assert.throws(() => createUpnpSsdpDiscovery(null),
    UpnpSsdpBoundaryError);
});

test('E01: composition accepts exact branded surfaces in any key order', () => {
  const ssdp = createUpnpSsdpDiscovery();
  const description = createUpnpDescriptionHttp();
  const soap = createUpnpSoapControl();
  const input = { soap, ssdp, description };
  const modules = createUpnpIgdModules(input);
  assert.deepEqual(Object.keys(modules), ['ssdp', 'description', 'soap']);
  assert.equal(modules.ssdp, ssdp);
  assert.equal(modules.description, description);
  assert.equal(modules.soap, soap);
  assert.ok(Object.isFrozen(modules));
});

test('E01: composition rejects fake, swapped, missing, extra and hostile surfaces', () => {
  const ssdp = createUpnpSsdpDiscovery();
  const description = createUpnpDescriptionHttp();
  const soap = createUpnpSoapControl();
  for (const value of [
    null,
    {},
    { ssdp, description, soap, extra: true },
    { ssdp: description, description, soap },
    { ssdp, description: soap, soap },
    { ssdp, description, soap: ssdp },
    {
      ssdp: { ...ssdp },
      description,
      soap,
    },
    new Proxy({}, {}),
    [],
  ]) {
    assert.throws(() => createUpnpIgdModules(value),
      UpnpModuleCompositionError);
  }
  const accessor = { ssdp, description };
  Object.defineProperty(accessor, 'soap', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  assert.throws(() => createUpnpIgdModules(accessor),
    UpnpModuleCompositionError);
});
