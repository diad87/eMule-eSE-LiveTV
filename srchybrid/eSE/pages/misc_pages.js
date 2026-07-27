'use strict';

const http = require('http');
const APP_VERSION = require('../package.json').version;

let context = null;

function init(ctx) {
  context = ctx;
}

function gone(res) {
  res.writeHead(410, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify({
    error: 'gone',
    reason: 'remote_access_postponed'
  }));
  return true;
}

function handle(url, req, res) {
  const { HW_ENCODER } = context;

  if (url.pathname === '/api/status') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    });
    res.end(JSON.stringify({
      status: 'ok',
      version: APP_VERSION,
      uptime: Math.round(process.uptime()),
      encoder: HW_ENCODER,
      hasPublicUrl: false,
      hasTunnel: false,
      remoteAccess: 'postponed'
    }));
    return true;
  }

  if (url.pathname === '/api/connect-seed' ||
      url.pathname === '/manifest.json' ||
      url.pathname === '/go' ||
      url.pathname.startsWith('/go/') ||
      url.pathname === '/remote' ||
      url.pathname === '/qr') {
    return gone(res);
  }

  // NAT traversal health is a localhost-only proxy to the native WebServer.
  if (url.pathname === '/api/nat-health') {
    const natProbe = http.get(
      'http://127.0.0.1:4711/api/status',
      { timeout: 2000 },
      (natRes) => {
        let body = '';
        natRes.on('data', (chunk) => { body += chunk; });
        natRes.on('end', () => {
          try {
            const raw = JSON.parse(body);
            const payload = {
              hole_punch_attempts: raw.hole_punch_attempts || 0,
              hole_punch_success: raw.hole_punch_success || 0,
              hole_punch_sym_nat_fail: raw.hole_punch_sym_nat_fail || 0,
              hole_punch_encrypted: raw.hole_punch_encrypted || 0,
              hole_punch_plaintext: raw.hole_punch_plaintext || 0,
              kad_connected: raw.kad_connected || false,
              kad_configured_mask: raw.kad_configured_mask || 0,
              kad_running_mask: raw.kad_running_mask || 0,
              kad2_running: raw.kad2_running || false,
              kad2_connected: raw.kad2_connected || false,
              kad6_running: raw.kad6_running || false,
              kad6_connected: raw.kad6_connected || false,
              kad6_verified_contacts: raw.kad6_verified_contacts || 0,
              upnp_critical_error: raw.upnp_critical_error || false,
              upnp_ports_forwarded: raw.upnp_ports_forwarded || 'unknown'
            };
            res.writeHead(200, {
              'Content-Type': 'application/json',
              'Cache-Control': 'no-store'
            });
            res.end(JSON.stringify(payload));
          } catch (_) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end('{"error":"parse_failed"}');
          }
        });
      }
    );
    natProbe.on('timeout', () => natProbe.destroy());
    natProbe.on('error', () => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end('{"error":"backend_unreachable"}');
    });
    return true;
  }

  return false;
}

module.exports = { init, handle };
