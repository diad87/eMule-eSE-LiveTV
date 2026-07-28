'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createCanonicalReport,
  projectPublicMappings
} = require('../tools/lab/nat_gateway/structured_log');

const OWNER_INSTANCE = 'a'.repeat(64);
const GATEWAY_FINGERPRINT = 'b'.repeat(64);
const PCP_NONCE = 'c'.repeat(24);
const INTERNAL_IP = '192.168.71.23';
const EXTERNAL_IP = '203.0.113.91';
const OWNER_DESCRIPTION = 'ese-owner-runtime-secret';

function mapping(id, owner, overrides = {}) {
  return {
    mapping_id: id,
    protocol: owner.kind === 'pcp-nonce' ? 'pcp' :
      owner.kind === 'upnp-journal' ? 'upnp' : 'natpmp',
    transport: 'tcp',
    client_id: `client-${id}`,
    internal_address: INTERNAL_IP,
    internal_port: 4662,
    requested_external_port: 0,
    external_address: EXTERNAL_IP,
    external_port: 48123,
    lease: {
      lifetime_seconds: 60,
      created_monotonic_ms: 1000,
      expires_monotonic_ms: 61000
    },
    owner,
    epoch: 7,
    generation: 11,
    ...overrides
  };
}

function sensitiveMappings() {
  return [
    mapping('upnp-map', {
      kind: 'upnp-journal',
      instance_id_digest: OWNER_INSTANCE,
      gateway_identity_digest: GATEWAY_FINGERPRINT,
      description: OWNER_DESCRIPTION
    }),
    mapping('pcp-map', {
      kind: 'pcp-nonce',
      instance_id_digest: OWNER_INSTANCE,
      nonce: PCP_NONCE
    }),
    mapping('natpmp-map', {
      kind: 'natpmp-lease-scope',
      instance_id_digest: OWNER_INSTANCE,
      scope_id: 'natpmp-runtime-scope'
    }, { transport: 'udp' })
  ];
}

function assertNoSensitiveMaterial(value) {
  const serialized = JSON.stringify(value);
  for (const secret of [
    OWNER_INSTANCE,
    GATEWAY_FINGERPRINT,
    PCP_NONCE,
    INTERNAL_IP,
    EXTERNAL_IP,
    OWNER_DESCRIPTION,
    'natpmp-runtime-scope'
  ]) {
    assert.equal(serialized.includes(secret), false, `leaked ${secret}`);
  }
  assert.match(serialized, /sha256:t8\.owner-instance\/v1:/);
  assert.match(serialized, /sha256:t8\.owner-gateway\/v1:/);
  assert.match(serialized, /sha256:t8\.pcp-nonce\/v1:/);
  assert.match(serialized, /"classification":/);
}

test('L08 runtime projection digests owner, nonce, addresses and gateway', () => {
  assertNoSensitiveMaterial(projectPublicMappings(sensitiveMappings()));
});

test('L08 canonical report never reintroduces projected sensitive material', () => {
  const report = createCanonicalReport({
    scenario_id: 'l08-runtime',
    run_id: 'l08-runtime-run',
    scenario_hash: 'd'.repeat(64),
    seed: 92,
    effective_config: {
      clock_mode: 'virtual',
      allocation_strategy: 'requested-or-next',
      enabled_protocols: ['upnp', 'pcp', 'natpmp']
    },
    initial_state: { epoch: 7, generation: 11, status: 'discovering' },
    final_state: { epoch: 7, generation: 11, status: 'mapped' },
    counters: { count: 3, request_count: 3, mapping_count: 3 },
    faults: { count: 0, applied: 0, rejected: 0 },
    mappings: sensitiveMappings(),
    verdict: 'passed'
  });
  assertNoSensitiveMaterial(report);
});
