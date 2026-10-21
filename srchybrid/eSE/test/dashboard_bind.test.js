'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const http = require('node:http');
const test = require('node:test');
const bind = require('../dashboard_bind');

test('dashboard bind defaults to IPv4 loopback', async () => {
  assert.equal(bind.normalizeBindHost(''), '127.0.0.1');
  assert.equal(bind.normalizeBindHost('localhost'), '127.0.0.1');
  assert.equal(bind.isLoopbackBindHost('127.0.0.42'), true);
  assert.equal(bind.isLoopbackBindHost('::1'), true);
  assert.equal(bind.isLoopbackBindHost('0.0.0.0'), false);
  assert.throws(() => bind.normalizeBindHost('dashboard.example'), /IP.*literal/i);

  const server = http.createServer((_req, res) => res.end('ok'));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    bind.listenDashboard(server, 0, '', resolve);
  });
  try {
    assert.equal(server.address().address, '127.0.0.1');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('remote binding fails closed without a configured token', () => {
  assert.deepEqual(bind.validateBindConfiguration('0.0.0.0', false), {
    ok: false,
    host: '0.0.0.0',
    error: 'remote dashboard binding requires an access token of at least 16 characters'
  });
  assert.deepEqual(bind.validateBindConfiguration('192.168.1.10', true), {
    ok: true,
    host: '192.168.1.10',
    remote: true
  });
});

test('dashboard source self-test exits successfully', () => {
  const result = spawnSync(process.execPath, ['server.js', '--selftest'], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    timeout: 5000
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /dashboard self-test: PASS/);
});
