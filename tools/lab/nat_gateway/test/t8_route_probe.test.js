'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const {
  runT8MapperRouteProbe,
  T8RouteProbeError,
} = require('../t8_route_probe');

const proxyNames = [
  'ALL_PROXY', 'HTTPS_PROXY', 'HTTP_PROXY',
  'all_proxy', 'https_proxy', 'http_proxy',
];

async function withProxyEnvironment(mode, callback) {
  const before = Object.fromEntries(proxyNames.map((name) =>
    [name, Object.hasOwn(process.env, name) ? process.env[name] : undefined]));
  try {
    for (const name of proxyNames) {
      if (mode === 'none') delete process.env[name];
      else process.env[name] = 'http://127.0.0.1:9';
    }
    return await callback();
  } finally {
    for (const name of proxyNames) {
      if (before[name] === undefined) delete process.env[name];
      else process.env[name] = before[name];
    }
  }
}

test('F05: mapper reaches the exact T8 endpoint with proxy/DNS-independent semantics', async () => {
  const baseline = await withProxyEnvironment('none', () =>
    runT8MapperRouteProbe({
      gateway_address: '127.0.0.1',
      client_address: '127.0.0.1',
      mode: 'baseline',
    }));
  const perturbed = await withProxyEnvironment('invalid', () =>
    runT8MapperRouteProbe({
      gateway_address: '127.0.0.1',
      client_address: '127.0.0.1',
      mode: 'dns-proxy-perturbed',
    }));
  assert.equal(baseline.verdict, 'PASS');
  assert.equal(perturbed.verdict, 'PASS');
  assert.deepEqual(baseline.mapper, perturbed.mapper);
  assert.equal(baseline.environment.dns_hostname_lookup_count, 0);
  assert.equal(perturbed.environment.dns_hostname_lookup_count, 0);
  assert.equal(baseline.environment.proxy_environment_names_set.length, 0);
  assert.equal(perturbed.environment.proxy_environment_names_set.length, 6);
  const serialized = JSON.stringify([baseline, perturbed]);
  assert.equal(serialized.includes('127.0.0.1'), false);
});

test('F05: route probe rejects open, hostile and mismatched environment input', async () => {
  await withProxyEnvironment('none', async () => {
    for (const input of [
      null,
      {},
      { gateway_address: '127.0.0.1', client_address: '127.0.0.1',
        mode: 'baseline', extra: true },
      new Proxy({}, {}),
      { gateway_address: '127.0.0.1', client_address: '127.0.0.1',
        mode: 'other' },
    ]) {
      await assert.rejects(runT8MapperRouteProbe(input), T8RouteProbeError);
    }
  });
  await withProxyEnvironment('invalid', async () => {
    await assert.rejects(runT8MapperRouteProbe({
      gateway_address: '127.0.0.1',
      client_address: '127.0.0.1',
      mode: 'baseline',
    }), (error) => error.reason_code === 'T8_ROUTE_PROBE_ENVIRONMENT_INVALID');
  });
});

test('F05: CLI emits exactly one JSON line and stable exit codes', () => {
  const cli = path.join(__dirname, '..', 't8_route_probe.js');
  const cleanEnvironment = { ...process.env };
  for (const name of proxyNames) delete cleanEnvironment[name];
  const success = spawnSync(process.execPath, [
    cli,
    '--gateway=127.0.0.1',
    '--client=127.0.0.1',
    '--mode=baseline',
  ], { encoding: 'utf8', env: cleanEnvironment });
  assert.equal(success.status, 0);
  assert.equal(success.stderr, '');
  assert.equal(success.stdout.trim().split(/\r?\n/u).length, 1);
  assert.equal(JSON.parse(success.stdout).verdict, 'PASS');

  const invalid = spawnSync(process.execPath, [cli, '--gateway=bad'], {
    encoding: 'utf8',
    env: cleanEnvironment,
  });
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stderr, '');
  assert.equal(invalid.stdout.trim().split(/\r?\n/u).length, 1);
  assert.equal(JSON.parse(invalid.stdout).reason, 'T8_ROUTE_PROBE_ARGV_INVALID');
});
