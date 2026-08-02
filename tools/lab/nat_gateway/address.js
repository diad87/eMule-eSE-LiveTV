'use strict';

const net = require('node:net');

/**
 * Returns the canonical textual form used for semantic address comparisons.
 * Invalid input returns null rather than attempting DNS or any network I/O.
 */
function normalizeAddress(address) {
  if (typeof address !== 'string') return null;
  const family = net.isIP(address);
  if (family === 4) return address;
  if (family !== 6) return null;
  const hostname = new URL(`http://[${address}]/`).hostname;
  return hostname.slice(1, -1);
}

module.exports = { normalizeAddress };
