'use strict';

const net = require('node:net');
const { types } = require('node:util');

const moduleBrand = new WeakSet();

class UpnpDescriptionBoundaryError extends Error {
  constructor(reasonCode = 'UPNP_DESCRIPTION_BOUNDARY_INVALID',
      fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpDescriptionBoundaryError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpDescriptionBoundaryError(reasonCode, fieldPath);
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

function readClosedData(input, required, fieldPath) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', fieldPath);
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_DESCRIPTION_CONFIG_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function adapterHost(address) {
  if (typeof address !== 'string') {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config.adapter_address');
  }
  const family = net.isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    if (octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 ||
        octets.every((octet) => octet === 255)) {
      fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config.adapter_address');
    }
    return address;
  }
  if (family !== 6 || address === '::' || address === '::1' ||
      /^ff/i.test(address) || /^::ffff:/i.test(address)) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config.adapter_address');
  }
  const zoneIndex = address.lastIndexOf('%');
  const bareAddress = zoneIndex < 0 ? address : address.slice(0, zoneIndex);
  const zone = zoneIndex < 0 ? '' : address.slice(zoneIndex + 1);
  if (/^fe[89ab]/i.test(bareAddress) &&
      !/^[A-Za-z0-9_.-]{1,32}$/.test(zone)) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config.adapter_address');
  }
  return `[${address.replace('%', '%25')}]`;
}

function validatePath(value, fieldPath, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' ||
      !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,255}$/.test(value)) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', fieldPath);
  }
  return value;
}

function deviceConfig(input) {
  const required = [
    'adapter_address', 'http_port', 'igd_version', 'service_version',
    'udn_uuid', 'wan_device_uuid', 'wan_connection_device_uuid',
    'cif_scpd_path', 'cif_control_path', 'cif_event_sub_path',
    'scpd_path', 'control_path', 'event_sub_path',
  ];
  const result = readClosedData(input, required, '$.config');
  result.host = adapterHost(result.adapter_address);
  if (!Number.isInteger(result.http_port) ||
      result.http_port < 1 || result.http_port > 65535 ||
      result.igd_version !== 1 ||
      result.service_version !== 1 ||
      typeof result.udn_uuid !== 'string' ||
      !/^uuid:[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/
        .test(result.udn_uuid) ||
      typeof result.wan_device_uuid !== 'string' ||
      !/^uuid:[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/
        .test(result.wan_device_uuid) ||
      typeof result.wan_connection_device_uuid !== 'string' ||
      !/^uuid:[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/
        .test(result.wan_connection_device_uuid) ||
      new Set([
        result.udn_uuid.toLowerCase(),
        result.wan_device_uuid.toLowerCase(),
        result.wan_connection_device_uuid.toLowerCase(),
      ]).size !== 3) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config');
  }
  result.scpd_path = validatePath(result.scpd_path, '$.config.scpd_path');
  result.control_path =
    validatePath(result.control_path, '$.config.control_path');
  result.event_sub_path = validatePath(
    result.event_sub_path, '$.config.event_sub_path', true);
  result.cif_scpd_path =
    validatePath(result.cif_scpd_path, '$.config.cif_scpd_path');
  result.cif_control_path =
    validatePath(result.cif_control_path, '$.config.cif_control_path');
  result.cif_event_sub_path = validatePath(
    result.cif_event_sub_path, '$.config.cif_event_sub_path', true);
  return result;
}

function encodeUpnpDeviceDescription(configInput) {
  const config = deviceConfig(configInput);
  const serviceType =
    `urn:schemas-upnp-org:service:WANIPConnection:${config.service_version}`;
  const eventLine = config.event_sub_path === null ? [] :
    [`<eventSubURL>${config.event_sub_path}</eventSubURL>`];
  const cifEventLine = config.cif_event_sub_path === null ? [] :
    [`<eventSubURL>${config.cif_event_sub_path}</eventSubURL>`];
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<root xmlns="urn:schemas-upnp-org:device-1-0">',
    '<specVersion><major>1</major><minor>0</minor></specVersion>',
    `<URLBase>http://${config.host}:${config.http_port}/</URLBase>`,
    '<device>',
    `<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:${config.igd_version}</deviceType>`,
    '<friendlyName>eSE T8 Internet Gateway</friendlyName>',
    '<manufacturer>eSE</manufacturer>',
    '<modelName>eSE T8 IGD</modelName>',
    `<UDN>${config.udn_uuid}</UDN>`,
    '<deviceList>',
    '<device>',
    `<deviceType>urn:schemas-upnp-org:device:WANDevice:${config.igd_version}</deviceType>`,
    '<friendlyName>eSE T8 WAN Device</friendlyName>',
    '<manufacturer>eSE</manufacturer>',
    '<modelName>eSE T8 WAN</modelName>',
    `<UDN>${config.wan_device_uuid}</UDN>`,
    '<serviceList>',
    '<service>',
    '<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>',
    '<serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>',
    `<SCPDURL>${config.cif_scpd_path}</SCPDURL>`,
    `<controlURL>${config.cif_control_path}</controlURL>`,
    ...cifEventLine,
    '</service>',
    '</serviceList>',
    '<deviceList>',
    '<device>',
    `<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:${config.igd_version}</deviceType>`,
    '<friendlyName>eSE T8 WAN Connection Device</friendlyName>',
    '<manufacturer>eSE</manufacturer>',
    '<modelName>eSE T8 WAN Connection</modelName>',
    `<UDN>${config.wan_connection_device_uuid}</UDN>`,
    '<serviceList>',
    '<service>',
    `<serviceType>${serviceType}</serviceType>`,
    '<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>',
    `<SCPDURL>${config.scpd_path}</SCPDURL>`,
    `<controlURL>${config.control_path}</controlURL>`,
    ...eventLine,
    '</service>',
    '</serviceList>',
    '</device>',
    '</deviceList>',
    '</device>',
    '</deviceList>',
    '</device>',
    '</root>',
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

function serviceConfig(input) {
  const result = readClosedData(input, ['service_version'], '$.config');
  if (result.service_version !== 1) {
    fail('UPNP_DESCRIPTION_CONFIG_INVALID', '$.config.service_version');
  }
  return result;
}

function encodeUpnpServiceDescription(configInput) {
  serviceConfig(configInput);
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<scpd xmlns="urn:schemas-upnp-org:service-1-0">',
    '<specVersion><major>1</major><minor>0</minor></specVersion>',
    '<actionList>',
    '<action><name>GetStatusInfo</name><argumentList>',
    '<argument><name>NewConnectionStatus</name><direction>out</direction><relatedStateVariable>ConnectionStatus</relatedStateVariable></argument>',
    '<argument><name>NewLastConnectionError</name><direction>out</direction><relatedStateVariable>LastConnectionError</relatedStateVariable></argument>',
    '<argument><name>NewUptime</name><direction>out</direction><relatedStateVariable>Uptime</relatedStateVariable></argument>',
    '</argumentList></action>',
    '<action><name>GetExternalIPAddress</name><argumentList>',
    '<argument><name>NewExternalIPAddress</name><direction>out</direction><relatedStateVariable>ExternalIPAddress</relatedStateVariable></argument>',
    '</argumentList></action>',
    '<action><name>AddPortMapping</name><argumentList>',
    '<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>',
    '<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>',
    '<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>',
    '<argument><name>NewInternalPort</name><direction>in</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>',
    '<argument><name>NewInternalClient</name><direction>in</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>',
    '<argument><name>NewEnabled</name><direction>in</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>',
    '<argument><name>NewPortMappingDescription</name><direction>in</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>',
    '<argument><name>NewLeaseDuration</name><direction>in</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>',
    '</argumentList></action>',
    '<action><name>DeletePortMapping</name><argumentList>',
    '<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>',
    '<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>',
    '<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>',
    '</argumentList></action>',
    '<action><name>GetSpecificPortMappingEntry</name><argumentList>',
    '<argument><name>NewRemoteHost</name><direction>in</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>',
    '<argument><name>NewExternalPort</name><direction>in</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>',
    '<argument><name>NewProtocol</name><direction>in</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>',
    '<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>',
    '<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>',
    '<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>',
    '<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>',
    '<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>',
    '</argumentList></action>',
    '<action><name>GetGenericPortMappingEntry</name><argumentList>',
    '<argument><name>NewPortMappingIndex</name><direction>in</direction><relatedStateVariable>PortMappingNumberOfEntries</relatedStateVariable></argument>',
    '<argument><name>NewRemoteHost</name><direction>out</direction><relatedStateVariable>RemoteHost</relatedStateVariable></argument>',
    '<argument><name>NewExternalPort</name><direction>out</direction><relatedStateVariable>ExternalPort</relatedStateVariable></argument>',
    '<argument><name>NewProtocol</name><direction>out</direction><relatedStateVariable>PortMappingProtocol</relatedStateVariable></argument>',
    '<argument><name>NewInternalPort</name><direction>out</direction><relatedStateVariable>InternalPort</relatedStateVariable></argument>',
    '<argument><name>NewInternalClient</name><direction>out</direction><relatedStateVariable>InternalClient</relatedStateVariable></argument>',
    '<argument><name>NewEnabled</name><direction>out</direction><relatedStateVariable>PortMappingEnabled</relatedStateVariable></argument>',
    '<argument><name>NewPortMappingDescription</name><direction>out</direction><relatedStateVariable>PortMappingDescription</relatedStateVariable></argument>',
    '<argument><name>NewLeaseDuration</name><direction>out</direction><relatedStateVariable>PortMappingLeaseDuration</relatedStateVariable></argument>',
    '</argumentList></action>',
    '</actionList>',
    '<serviceStateTable>',
    '<stateVariable sendEvents="yes"><name>ConnectionStatus</name><dataType>string</dataType><allowedValueList><allowedValue>Unconfigured</allowedValue><allowedValue>Connecting</allowedValue><allowedValue>Connected</allowedValue><allowedValue>PendingDisconnect</allowedValue><allowedValue>Disconnecting</allowedValue><allowedValue>Disconnected</allowedValue></allowedValueList></stateVariable>',
    '<stateVariable sendEvents="no"><name>LastConnectionError</name><dataType>string</dataType><allowedValueList><allowedValue>ERROR_NONE</allowedValue><allowedValue>ERROR_COMMAND_ABORTED</allowedValue><allowedValue>ERROR_NOT_ENABLED_FOR_INTERNET</allowedValue><allowedValue>ERROR_USER_DISCONNECT</allowedValue><allowedValue>ERROR_ISP_DISCONNECT</allowedValue><allowedValue>ERROR_IDLE_DISCONNECT</allowedValue><allowedValue>ERROR_FORCED_DISCONNECT</allowedValue><allowedValue>ERROR_NO_CARRIER</allowedValue><allowedValue>ERROR_IP_CONFIGURATION</allowedValue><allowedValue>ERROR_UNKNOWN</allowedValue></allowedValueList></stateVariable>',
    '<stateVariable sendEvents="no"><name>Uptime</name><dataType>ui4</dataType></stateVariable>',
    '<stateVariable sendEvents="yes"><name>ExternalIPAddress</name><dataType>string</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>RemoteHost</name><dataType>string</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>ExternalPort</name><dataType>ui2</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>PortMappingProtocol</name><dataType>string</dataType><allowedValueList><allowedValue>TCP</allowedValue><allowedValue>UDP</allowedValue></allowedValueList></stateVariable>',
    '<stateVariable sendEvents="no"><name>InternalPort</name><dataType>ui2</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>InternalClient</name><dataType>string</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>PortMappingEnabled</name><dataType>boolean</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>PortMappingDescription</name><dataType>string</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>PortMappingLeaseDuration</name><dataType>ui4</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>PortMappingNumberOfEntries</name><dataType>ui2</dataType></stateVariable>',
    '</serviceStateTable>',
    '</scpd>',
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

function encodeUpnpWanCommonInterfaceConfigDescription(configInput) {
  serviceConfig(configInput);
  const lines = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<scpd xmlns="urn:schemas-upnp-org:service-1-0">',
    '<specVersion><major>1</major><minor>0</minor></specVersion>',
    '<actionList>',
    '<action><name>GetCommonLinkProperties</name><argumentList>',
    '<argument><name>NewWANAccessType</name><direction>out</direction><relatedStateVariable>WANAccessType</relatedStateVariable></argument>',
    '<argument><name>NewLayer1UpstreamMaxBitRate</name><direction>out</direction><relatedStateVariable>Layer1UpstreamMaxBitRate</relatedStateVariable></argument>',
    '<argument><name>NewLayer1DownstreamMaxBitRate</name><direction>out</direction><relatedStateVariable>Layer1DownstreamMaxBitRate</relatedStateVariable></argument>',
    '<argument><name>NewPhysicalLinkStatus</name><direction>out</direction><relatedStateVariable>PhysicalLinkStatus</relatedStateVariable></argument>',
    '</argumentList></action>',
    '</actionList>',
    '<serviceStateTable>',
    '<stateVariable sendEvents="no"><name>WANAccessType</name><dataType>string</dataType><allowedValueList><allowedValue>DSL</allowedValue><allowedValue>POTS</allowedValue><allowedValue>Cable</allowedValue><allowedValue>Ethernet</allowedValue><allowedValue>Other</allowedValue></allowedValueList></stateVariable>',
    '<stateVariable sendEvents="no"><name>Layer1UpstreamMaxBitRate</name><dataType>ui4</dataType></stateVariable>',
    '<stateVariable sendEvents="no"><name>Layer1DownstreamMaxBitRate</name><dataType>ui4</dataType></stateVariable>',
    '<stateVariable sendEvents="yes"><name>PhysicalLinkStatus</name><dataType>string</dataType><allowedValueList><allowedValue>Up</allowedValue><allowedValue>Down</allowedValue><allowedValue>Initializing</allowedValue><allowedValue>Unavailable</allowedValue></allowedValueList></stateVariable>',
    '</serviceStateTable>',
    '</scpd>',
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

module.exports = Object.freeze({
  UpnpDescriptionBoundaryError,
  createUpnpDescriptionHttp,
  encodeUpnpDeviceDescription,
  encodeUpnpServiceDescription,
  encodeUpnpWanCommonInterfaceConfigDescription,
  isUpnpDescriptionHttp,
});
