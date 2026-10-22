'use strict';

const net = require('net');
const { listenDashboardRange } = require('./dashboard_port_range');

const DEFAULT_BIND_HOST = '127.0.0.1';

function normalizeBindHost(value) {
  const host = String(value || '').trim();
  if (!host || host.toLowerCase() === 'localhost') return DEFAULT_BIND_HOST;
  if (net.isIP(host) === 0) {
    throw new Error('ESE_BIND_HOST must be an IPv4 or IPv6 literal');
  }
  return host;
}

function isLoopbackBindHost(host) {
  const normalized = normalizeBindHost(host).toLowerCase();
  if (normalized === '::1') return true;
  if (net.isIP(normalized) !== 4) return false;
  return normalized.split('.')[0] === '127';
}

function validateBindConfiguration(host, accessTokenReady) {
  const normalized = normalizeBindHost(host);
  if (!isLoopbackBindHost(normalized) && !accessTokenReady) {
    return {
      ok: false,
      host: normalized,
      error: 'remote dashboard binding requires an access token of at least 16 characters'
    };
  }
  return { ok: true, host: normalized, remote: !isLoopbackBindHost(normalized) };
}

function listenDashboard(server, port, host, callback) {
  const normalized = normalizeBindHost(host);
  return listenDashboardRange(server, port, normalized, callback);
}

module.exports = {
  DEFAULT_BIND_HOST,
  normalizeBindHost,
  isLoopbackBindHost,
  validateBindConfiguration,
  listenDashboard
};
