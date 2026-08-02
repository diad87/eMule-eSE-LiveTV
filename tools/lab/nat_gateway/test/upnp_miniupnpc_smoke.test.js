'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const dgram = require('node:dgram');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const test = require('node:test');
const { createMappingState } = require('../mapping_model');
const {
  encodeUpnpDeviceDescription,
  encodeUpnpServiceDescription,
  encodeUpnpWanCommonInterfaceConfigDescription,
} = require('../upnp_description_http');
const {
  decodeUpnpAddPortMapping,
  decodeUpnpDeletePortMapping,
  decodeUpnpPortMappingReadback,
  decodeUpnpSoapQuery,
  encodeUpnpSoapQueryResponse,
} = require('../upnp_soap_control');
const { applyUpnpAddPortMapping } = require('../upnp_mapping_lifecycle');
const {
  projectUpnpReadbackSoapResult,
  readUpnpPortMapping,
} = require('../upnp_mapping_readback');
const {
  applyUpnpDeletePortMapping,
  projectUpnpDeleteSoapResult,
} = require('../upnp_mapping_delete');
const {
  decodeUpnpMSearch,
  encodeUpnpMSearchResponse,
} = require('../upnp_ssdp_discovery');

const runFile = promisify(execFile);
const enabled = process.env.ESE_RUN_MINIUPNPC_SMOKE === '1';
const executable = path.resolve(
  __dirname, '..', '..', '..', '..', 'miniupnpc', 'msvc', 'Release',
  'upnpc-static.exe');
const digestA = 'a'.repeat(64);
const digestB = 'b'.repeat(64);

function adapterAddress() {
  const candidates = [];
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === 'IPv4' && !entry.internal &&
          !entry.address.startsWith('169.254.')) {
        candidates.push(entry);
      }
    }
  }
  const preferred = candidates.find((entry) =>
    entry.cidr && !entry.cidr.endsWith('/32') &&
    (/^192\.168\./.test(entry.address) ||
     /^10\./.test(entry.address) ||
     /^172\.(1[6-9]|2[0-9]|3[01])\./.test(entry.address)));
  if (preferred) return preferred.address;
  if (candidates.length > 0) return candidates[0].address;
  throw new Error('E08 requires one non-loopback IPv4 adapter');
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    request.on('data', (chunk) => {
      length += chunk.length;
      if (length > 8192) {
        reject(new Error('SOAP body exceeds E08 bound'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function send(response, statusCode, body, contentType = 'text/xml') {
  response.writeHead(statusCode, {
    'Content-Type': `${contentType}; charset="utf-8"`,
    'Content-Length': body.length,
    Connection: 'close',
  });
  response.end(body);
}

test('E08: real miniupnpc completes HTTP control lifecycle',
  { skip: !enabled, timeout: 30000 }, async (context) => {
    const address = adapterAddress();
    let mappingState = createMappingState({
      epoch: 17,
      generation: 3,
      mappings: [],
    });
    const server = http.createServer(async (request, response) => {
      try {
        const port = server.address().port;
        const config = {
          adapter_address: address,
          http_port: port,
          igd_version: 1,
          service_version: 1,
          udn_uuid: 'uuid:12345678-1234-1234-1234-123456789abc',
          wan_device_uuid: 'uuid:22345678-1234-1234-1234-123456789abc',
          wan_connection_device_uuid:
            'uuid:32345678-1234-1234-1234-123456789abc',
          cif_scpd_path: '/wancommonifcSCPD.xml',
          cif_control_path: '/control/WANCommonIFC1',
          cif_event_sub_path: null,
          scpd_path: '/wanipconnSCPD.xml',
          control_path: '/control/WANIPConn1',
          event_sub_path: null,
        };
        if (request.method === 'GET' && request.url === '/rootDesc.xml') {
          send(response, 200, encodeUpnpDeviceDescription(config));
          return;
        }
        if (request.method === 'GET' &&
            request.url === '/wanipconnSCPD.xml') {
          send(response, 200,
            encodeUpnpServiceDescription({ service_version: 1 }));
          return;
        }
        if (request.method === 'GET' &&
            request.url === '/wancommonifcSCPD.xml') {
          send(response, 200,
            encodeUpnpWanCommonInterfaceConfigDescription({
              service_version: 1,
            }));
          return;
        }
        if (request.method !== 'POST' ||
            request.url !== '/control/WANIPConn1') {
          send(response, 404, Buffer.from('not found'), 'text/plain');
          return;
        }
        const soapAction = request.headers.soapaction;
        const wire = await readBody(request);
        let command;
        let semantic;
        if (soapAction.endsWith('#GetExternalIPAddress"') ||
            soapAction.endsWith('#GetStatusInfo"')) {
          command = decodeUpnpSoapQuery(soapAction, wire);
          semantic = command.operation === 'get_external_ip_address' ?
            { ok: true, external_address: '88.11.22.44' } :
            {
              ok: true,
              connection_status: 'Connected',
              last_connection_error: 'ERROR_NONE',
              uptime_seconds: 17,
            };
        } else if (soapAction.endsWith('#AddPortMapping"')) {
          command = decodeUpnpAddPortMapping(soapAction, wire);
          const result = applyUpnpAddPortMapping(
            mappingState, command, {
              client_id: 'miniupnpc.client',
              gateway_external_address: '88.11.22.44',
              gateway_identity_digest: digestA,
              instance_id_digest: digestB,
              now_monotonic_ms: 1000,
              table_capacity: 16,
            });
          mappingState = result.state;
          semantic = result.ok ? { ok: true } : {
            ok: false,
            error_code: result.error_code,
            error_description: result.error_description,
          };
        } else if (soapAction.endsWith('#DeletePortMapping"')) {
          command = decodeUpnpDeletePortMapping(soapAction, wire);
          const result = applyUpnpDeletePortMapping(
            mappingState, command, {
              gateway_external_address: '88.11.22.44',
              now_monotonic_ms: 1000,
            });
          mappingState = result.state;
          semantic = projectUpnpDeleteSoapResult(result);
        } else {
          command = decodeUpnpPortMappingReadback(soapAction, wire);
          const result = readUpnpPortMapping(
            mappingState, command, {
              readback: 'full',
              gateway_external_address: '88.11.22.44',
              now_monotonic_ms: 1000,
              description_limit: 64,
            });
          mappingState = result.state;
          semantic = projectUpnpReadbackSoapResult(result);
        }
        const output = encodeUpnpSoapQueryResponse(command, semantic);
        send(response, output.status_code, output.body);
      } catch (error) {
        response.destroy(error);
      }
    });
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, address, resolve);
    });
    context.after(() => new Promise((resolve) => server.close(resolve)));
    const url = `http://${address}:${server.address().port}/rootDesc.xml`;
    const invoke = async (...args) => runFile(executable,
      ['-u', url, ...args], { timeout: 10000, windowsHide: true });

    const status = await invoke('-s');
    assert.match(status.stdout, /ExternalIPAddress = 88\.11\.22\.44/);

    const ssdp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let ssdpClosed = false;
    context.after(() => new Promise((resolve) => {
      if (ssdpClosed) {
        resolve();
        return;
      }
      ssdpClosed = true;
      try {
        ssdp.close(resolve);
      } catch {
        resolve();
      }
    }));
    await new Promise((resolve, reject) => {
      ssdp.once('error', reject);
      ssdp.bind(1900, '0.0.0.0', () => {
        try {
          ssdp.addMembership('239.255.255.250', address);
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    ssdp.on('message', (wire, source) => {
      try {
        const discovery = decodeUpnpMSearch(wire, {
          search_target:
            'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        });
        const response = encodeUpnpMSearchResponse(discovery, {
          adapter_address: address,
          http_port: server.address().port,
          description_path: '/rootDesc.xml',
          usn_uuid: 'uuid:12345678-1234-1234-1234-123456789abc',
          max_age_seconds: 1800,
        });
        ssdp.send(response, source.port, source.address);
      } catch {
        // miniupnpc may probe additional ST values; this fixture exposes IGD v1.
      }
    });
    const discovered = await runFile(executable,
      ['-m', address, '-s'],
      { timeout: 10000, windowsHide: true });
    assert.match(discovered.stdout,
      new RegExp(`Found.*IGD.*${address.replaceAll('.', '\\.')}`, 's'));
    assert.match(discovered.stdout, /ExternalIPAddress = 88\.11\.22\.44/);

    await invoke('-e', 'eMule TCP', '-a', address, '4662', '4662', 'TCP', '0');
    await invoke('-e', 'eMule UDP', '-a', address, '4672', '4672', 'UDP', '0');
    assert.equal(mappingState.mappings.length, 2);
    const listed = await invoke('-l');
    assert.match(listed.stdout, /4662/);
    assert.match(listed.stdout, /4672/);
    await invoke('-d', '4662', 'TCP');
    await invoke('-d', '4672', 'UDP');
    assert.equal(mappingState.mappings.length, 0);
  });
