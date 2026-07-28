'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  TwoClientLabError,
  createTwoClientLab,
  createClientMapping,
  renewClientMapping,
  deleteClientMapping,
  advanceTwoClientTime,
  crashClient,
  restartClient,
  snapshotTwoClientLab
} = require('../two_client_lab');

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);
const DIGEST_C = 'c'.repeat(64);
const GATEWAY_DIGEST = 'd'.repeat(64);

function config(protocolA = 'upnp', protocolB = protocolA) {
  return {
    epoch: 10,
    generation: 4,
    start_monotonic_ms: 0,
    external_address: '198.51.100.1',
    gateway_identity_digest: GATEWAY_DIGEST,
    clients: [
      {
        client_id: 'client-a',
        protocol: protocolA,
        internal_address: '192.0.2.10',
        instance_id_digest: DIGEST_A
      },
      {
        client_id: 'client-b',
        protocol: protocolB,
        internal_address: '192.0.2.11',
        instance_id_digest: DIGEST_B
      }
    ]
  };
}

function mapRequest(clientId, mappingId, externalPort, overrides = {}) {
  return {
    client_id: clientId,
    mapping_id: mappingId,
    transport: 'tcp',
    internal_port: clientId === 'client-a' ? 4662 : 4663,
    external_port: externalPort,
    lifetime_seconds: 60,
    now_monotonic_ms: 1000,
    ...overrides
  };
}

function expectLabError(action, reasonCode, fieldPath) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof TwoClientLabError);
    if (reasonCode !== undefined) assert.equal(error.reason_code, reasonCode);
    if (fieldPath !== undefined) assert.equal(error.field_path, fieldPath);
    return true;
  });
}

test('F02 A/B same port: first client owns it and second gets a contained collision', () => {
  for (const protocols of [['upnp', 'upnp'], ['pcp', 'pcp'], ['natpmp', 'natpmp'], ['upnp', 'pcp']]) {
    const initial = createTwoClientLab(config(...protocols));
    const first = createClientMapping(initial, mapRequest('client-a', 'map-a', 45000, {
      lifetime_seconds: protocols[0] === 'upnp' ? 0 : 60
    }));
    assert.equal(first.ok, true);
    const second = createClientMapping(first.lab, mapRequest('client-b', 'map-b', 45000, {
      lifetime_seconds: protocols[1] === 'upnp' ? 0 : 60
    }));
    assert.equal(second.ok, false);
    assert.equal(second.reason_code, 'MAPPING_COLLISION');
    assert.equal(second.lab, first.lab);
    assert.deepEqual(snapshotTwoClientLab(second.lab).mappings, [{
      mapping_id: 'map-a',
      client_id: 'client-a',
      protocol: protocols[0],
      transport: 'tcp',
      external_port: 45000,
      lifetime_seconds: protocols[0] === 'upnp' ? 0 : 60
    }]);
  }
});

test('F02 A/B different ports: both mappings coexist without shared ownership', () => {
  let lab = createTwoClientLab(config('pcp', 'natpmp'));
  const first = createClientMapping(lab, mapRequest('client-a', 'map-a', 45000));
  lab = first.lab;
  const second = createClientMapping(lab, mapRequest('client-b', 'map-b', 45001));
  assert.equal(second.ok, true);
  assert.deepEqual(snapshotTwoClientLab(second.lab).mappings.map((mapping) => [
    mapping.mapping_id,
    mapping.client_id,
    mapping.protocol,
    mapping.external_port
  ]), [
    ['map-a', 'client-a', 'pcp', 45000],
    ['map-b', 'client-b', 'natpmp', 45001]
  ]);
  assert.equal(snapshotTwoClientLab(lab).mappings.length, 1);
});

test('F02 A renew: only A can extend its lease and identity remains stable', () => {
  const created = createClientMapping(
    createTwoClientLab(config('pcp')),
    mapRequest('client-a', 'map-a', 45000)
  );
  const renewed = renewClientMapping(created.lab, {
    client_id: 'client-a',
    mapping_id: 'map-a',
    lifetime_seconds: 120,
    now_monotonic_ms: 2000
  });
  assert.equal(renewed.ok, true);
  assert.deepEqual(snapshotTwoClientLab(renewed.lab).mappings, [{
    mapping_id: 'map-a',
    client_id: 'client-a',
    protocol: 'pcp',
    transport: 'tcp',
    external_port: 45000,
    lifetime_seconds: 120
  }]);
  assert.equal(snapshotTwoClientLab(created.lab).mappings[0].lifetime_seconds, 60);
});

test('F02 B delete A: ownership mismatch cannot remove or mutate A mapping', () => {
  const created = createClientMapping(
    createTwoClientLab(config('upnp')),
    mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 0 })
  );
  const denied = deleteClientMapping(created.lab, {
    client_id: 'client-b',
    mapping_id: 'map-a'
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.reason_code, 'OWNERSHIP_MISMATCH');
  assert.equal(denied.lab, created.lab);
  assert.equal(snapshotTwoClientLab(denied.lab).mappings[0].client_id, 'client-a');

  const removed = deleteClientMapping(created.lab, {
    client_id: 'client-a',
    mapping_id: 'map-a'
  });
  assert.equal(removed.ok, true);
  assert.deepEqual(snapshotTwoClientLab(removed.lab).mappings, []);
});

test('F02 B delete A is contained when clients use different protocols', () => {
  const created = createClientMapping(
    createTwoClientLab(config('upnp', 'pcp')),
    mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 0 })
  );
  const denied = deleteClientMapping(created.lab, {
    client_id: 'client-b',
    mapping_id: 'map-a'
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.reason_code, 'OWNER_PROTOCOL_MISMATCH');
  assert.equal(denied.lab, created.lab);
  assert.equal(snapshotTwoClientLab(denied.lab).mappings.length, 1);
});

test('F02 A crash: gateway mapping survives while A operations are disabled and B continues', () => {
  const created = createClientMapping(
    createTwoClientLab(config('natpmp')),
    mapRequest('client-a', 'map-a', 45000)
  );
  const crashed = crashClient(created.lab, { client_id: 'client-a' });
  assert.equal(crashed.ok, true);
  assert.equal(snapshotTwoClientLab(crashed.lab).clients[0].status, 'crashed');
  assert.equal(snapshotTwoClientLab(crashed.lab).mappings.length, 1);

  const blockedRenew = renewClientMapping(crashed.lab, {
    client_id: 'client-a',
    mapping_id: 'map-a',
    lifetime_seconds: 120,
    now_monotonic_ms: 2000
  });
  assert.equal(blockedRenew.ok, false);
  assert.equal(blockedRenew.reason_code, 'CLIENT_NOT_RUNNING');
  assert.equal(snapshotTwoClientLab(blockedRenew.lab).now_monotonic_ms, 2000);
  assert.equal(snapshotTwoClientLab(blockedRenew.lab).mappings.length, 1);

  const bMapping = createClientMapping(
    blockedRenew.lab,
    mapRequest('client-b', 'map-b', 45001, { now_monotonic_ms: 2000 })
  );
  assert.equal(bMapping.ok, true);
  assert.equal(snapshotTwoClientLab(bMapping.lab).mappings.length, 2);
});

test('F02 A restart: new instance cannot claim stale ownership but can create a distinct mapping', () => {
  for (const protocol of ['upnp', 'pcp', 'natpmp']) {
    const created = createClientMapping(
      createTwoClientLab(config(protocol)),
      mapRequest('client-a', 'map-a-old', 45000, { lifetime_seconds: protocol === 'upnp' ? 0 : 60 })
    );
    const crashed = crashClient(created.lab, { client_id: 'client-a' });
    const restarted = restartClient(crashed.lab, {
      client_id: 'client-a',
      instance_id_digest: DIGEST_C
    });
    assert.equal(restarted.ok, true);
    const client = snapshotTwoClientLab(restarted.lab).clients[0];
    assert.equal(client.status, 'running');
    assert.equal(client.restart_count, 1);

    const staleRenew = renewClientMapping(restarted.lab, {
      client_id: 'client-a',
      mapping_id: 'map-a-old',
      lifetime_seconds: protocol === 'upnp' ? 0 : 120,
      now_monotonic_ms: 2000
    });
    assert.equal(staleRenew.ok, false);
    assert.equal(staleRenew.reason_code, 'OWNERSHIP_MISMATCH');
    assert.equal(snapshotTwoClientLab(staleRenew.lab).now_monotonic_ms, 2000);
    assert.deepEqual(snapshotTwoClientLab(staleRenew.lab).mappings.map((mapping) => mapping.mapping_id), ['map-a-old']);

    const fresh = createClientMapping(
      staleRenew.lab,
      mapRequest('client-a', 'map-a-new', 45001, {
        lifetime_seconds: protocol === 'upnp' ? 0 : 60,
        now_monotonic_ms: 2000
      })
    );
    assert.equal(fresh.ok, true);
    assert.deepEqual(snapshotTwoClientLab(fresh.lab).mappings.map((mapping) => mapping.mapping_id), [
      'map-a-new',
      'map-a-old'
    ]);
  }
});

test('F02 restart identities are never reusable to reconstruct stale ownership', () => {
  const created = createClientMapping(
    createTwoClientLab(config('upnp')),
    mapRequest('client-a', 'map-a-old', 45000, { lifetime_seconds: 0 })
  );
  const firstCrash = crashClient(created.lab, { client_id: 'client-a' });
  const firstRestart = restartClient(firstCrash.lab, {
    client_id: 'client-a',
    instance_id_digest: DIGEST_C
  });
  const secondCrash = crashClient(firstRestart.lab, { client_id: 'client-a' });
  expectLabError(() => restartClient(secondCrash.lab, {
    client_id: 'client-a',
    instance_id_digest: DIGEST_A
  }), 'TWO_CLIENT_INSTANCE_REUSED', '$.instance_id_digest');
  assert.equal(snapshotTwoClientLab(secondCrash.lab).clients[0].status, 'crashed');
  assert.deepEqual(snapshotTwoClientLab(secondCrash.lab).mappings.map((mapping) => mapping.mapping_id), ['map-a-old']);
});

test('F02 expired crash residue is removed at the exact deadline and the port is reclaimable', () => {
  const created = createClientMapping(
    createTwoClientLab(config('pcp')),
    mapRequest('client-a', 'map-a-old', 45000, {
      lifetime_seconds: 1,
      now_monotonic_ms: 0
    })
  );
  const crashed = crashClient(created.lab, { client_id: 'client-a' });
  const restarted = restartClient(crashed.lab, {
    client_id: 'client-a',
    instance_id_digest: DIGEST_C
  });

  const beforeDeadline = advanceTwoClientTime(restarted.lab, { now_monotonic_ms: 999 }).lab;
  assert.equal(snapshotTwoClientLab(beforeDeadline).mappings.length, 1);
  const occupied = createClientMapping(
    beforeDeadline,
    mapRequest('client-a', 'map-a-new', 45000, {
      lifetime_seconds: 60,
      now_monotonic_ms: 999
    })
  );
  assert.equal(occupied.ok, false);
  assert.equal(occupied.reason_code, 'MAPPING_COLLISION');

  const atDeadline = advanceTwoClientTime(occupied.lab, { now_monotonic_ms: 1000 }).lab;
  assert.deepEqual(snapshotTwoClientLab(atDeadline).mappings, []);
  const reclaimed = createClientMapping(
    atDeadline,
    mapRequest('client-a', 'map-a-new', 45000, {
      lifetime_seconds: 60,
      now_monotonic_ms: 1000
    })
  );
  assert.equal(reclaimed.ok, true);
  assert.deepEqual(snapshotTwoClientLab(reclaimed.lab).mappings.map((mapping) => mapping.mapping_id), ['map-a-new']);
});

test('F02 lifetime zero follows each protocol instead of creating accidental permanent leases', () => {
  const upnp = createTwoClientLab(config('upnp'));
  const rejectedFinite = createClientMapping(
    upnp,
    mapRequest('client-a', 'upnp-finite', 45000, { lifetime_seconds: 60 })
  );
  assert.equal(rejectedFinite.ok, false);
  assert.equal(rejectedFinite.reason_code, 'UPNP_ONLY_PERMANENT_LEASES');
  assert.deepEqual(snapshotTwoClientLab(rejectedFinite.lab).mappings, []);
  const upnpPermanent = createClientMapping(
    rejectedFinite.lab,
    mapRequest('client-a', 'upnp-permanent', 45000, { lifetime_seconds: 0 })
  );
  assert.equal(upnpPermanent.ok, true);
  const rejectedRenew = renewClientMapping(upnpPermanent.lab, {
    client_id: 'client-a',
    mapping_id: 'upnp-permanent',
    lifetime_seconds: 60,
    now_monotonic_ms: 2000
  });
  assert.equal(rejectedRenew.ok, false);
  assert.equal(rejectedRenew.reason_code, 'UPNP_ONLY_PERMANENT_LEASES');
  const renewedPermanent = renewClientMapping(rejectedRenew.lab, {
    client_id: 'client-a',
    mapping_id: 'upnp-permanent',
    lifetime_seconds: 0,
    now_monotonic_ms: 2000
  });
  assert.equal(renewedPermanent.ok, true);
  assert.equal(snapshotTwoClientLab(renewedPermanent.lab).mappings[0].lifetime_seconds, 0);

  for (const protocol of ['pcp', 'natpmp']) {
    const initial = createTwoClientLab(config(protocol));
    const zeroWithoutMapping = createClientMapping(
      initial,
      mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 0 })
    );
    assert.equal(zeroWithoutMapping.ok, false);
    assert.equal(zeroWithoutMapping.reason_code, 'MAPPING_NOT_FOUND');
    assert.deepEqual(snapshotTwoClientLab(zeroWithoutMapping.lab).mappings, []);

    const finite = createClientMapping(
      zeroWithoutMapping.lab,
      mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 60 })
    );
    assert.equal(finite.ok, true);
    const deleted = renewClientMapping(finite.lab, {
      client_id: 'client-a',
      mapping_id: 'map-a',
      lifetime_seconds: 0,
      now_monotonic_ms: 2000
    });
    assert.equal(deleted.ok, true);
    assert.deepEqual(snapshotTwoClientLab(deleted.lab).mappings, []);
  }
});

test('F02 transport spaces remain independent even for the same external port', () => {
  const first = createClientMapping(
    createTwoClientLab(config()),
    mapRequest('client-a', 'map-a-tcp', 45000, { lifetime_seconds: 0 })
  );
  const second = createClientMapping(
    first.lab,
    mapRequest('client-b', 'map-b-udp', 45000, { transport: 'udp', lifetime_seconds: 0 })
  );
  assert.equal(second.ok, true);
  assert.deepEqual(snapshotTwoClientLab(second.lab).mappings.map((mapping) => mapping.transport), ['tcp', 'udp']);
});

test('F02 snapshots configuration and requests without mutating caller or prior lab states', () => {
  const input = config();
  const before = structuredClone(input);
  const lab = createTwoClientLab(input);
  assert.deepEqual(input, before);
  input.clients[0].client_id = 'changed';
  input.external_address = '203.0.113.1';
  assert.equal(snapshotTwoClientLab(lab).clients[0].client_id, 'client-a');

  const request = mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 0 });
  const requestBefore = structuredClone(request);
  const result = createClientMapping(lab, request);
  assert.deepEqual(request, requestBefore);
  request.mapping_id = 'changed';
  assert.equal(snapshotTwoClientLab(result.lab).mappings[0].mapping_id, 'map-a');
  assert.deepEqual(snapshotTwoClientLab(lab).mappings, []);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.lab));
});

test('F02 public snapshot omits addresses and ownership material', () => {
  const mapped = createClientMapping(
    createTwoClientLab(config('pcp')),
    mapRequest('client-a', 'map-a', 45000)
  );
  const json = JSON.stringify(snapshotTwoClientLab(mapped.lab));
  for (const secret of ['192.0.2.10', '198.51.100.1', DIGEST_A, GATEWAY_DIGEST, '"owner"', '"nonce"']) {
    assert.equal(json.includes(secret), false);
  }
});

test('F02 lifecycle failures are deterministic and leave the lab unchanged', () => {
  const lab = createTwoClientLab(config());
  const crash = crashClient(lab, { client_id: 'client-a' });
  const secondCrash = crashClient(crash.lab, { client_id: 'client-a' });
  assert.deepEqual([secondCrash.ok, secondCrash.reason_code, secondCrash.lab], [false, 'CLIENT_NOT_RUNNING', crash.lab]);
  const runningRestart = restartClient(lab, { client_id: 'client-a', instance_id_digest: DIGEST_C });
  assert.deepEqual([runningRestart.ok, runningRestart.reason_code, runningRestart.lab], [false, 'CLIENT_NOT_CRASHED', lab]);
  expectLabError(
    () => restartClient(crash.lab, { client_id: 'client-a', instance_id_digest: DIGEST_A }),
    'TWO_CLIENT_INSTANCE_REUSED',
    '$.instance_id_digest'
  );
  expectLabError(() => crashClient(lab, { client_id: 'client-z' }), 'TWO_CLIENT_UNKNOWN_CLIENT', '$.client_id');
});

test('F02 rejects malformed configuration, requests and scalar boundaries before state change', () => {
  for (const invalid of [
    null,
    () => {},
    { ...config(), clients: [config().clients[0]] },
    { ...config(), epoch: -0 },
    { ...config(), epoch: Number.NaN },
    { ...config(), generation: 0 },
    { ...config(), start_monotonic_ms: -0 },
    { ...config(), external_address: '999.1.1.1' },
    { ...config(), gateway_identity_digest: 'bad' },
    { ...config(), clients: [{ ...config().clients[0], client_id: 'Bad' }, config().clients[1]] },
    { ...config(), clients: [{ ...config().clients[0], protocol: 'icmp' }, config().clients[1]] },
    { ...config(), clients: [{ ...config().clients[0], internal_address: 'invalid' }, config().clients[1]] },
    { ...config(), clients: [{ ...config().clients[0], instance_id_digest: 'bad' }, config().clients[1]] },
    { ...config(), clients: [{ ...config().clients[0] }, { ...config().clients[1], client_id: 'client-a' }] },
    { ...config(), clients: [{ ...config().clients[0] }, { ...config().clients[1], internal_address: '192.0.2.10' }] }
  ]) {
    expectLabError(() => createTwoClientLab(invalid));
  }

  const lab = createTwoClientLab(config());
  for (const request of [
    null,
    { ...mapRequest('client-a', 'map-a', 45000), extra: true },
    { ...mapRequest('client-a', 'Bad', 45000) },
    { ...mapRequest('client-a', 'map-a', 45000), transport: 'sctp' },
    { ...mapRequest('client-a', 'map-a', 45000), internal_port: -0 },
    { ...mapRequest('client-a', 'map-a', 45000), external_port: 65536 },
    { ...mapRequest('client-a', 'map-a', 45000), lifetime_seconds: 0xffffffff, now_monotonic_ms: Number.MAX_SAFE_INTEGER }
  ]) {
    expectLabError(() => createClientMapping(lab, request));
  }
  const created = createClientMapping(lab, mapRequest('client-a', 'map-a', 45000, { lifetime_seconds: 0 }));
  expectLabError(() => renewClientMapping(created.lab, {
    client_id: 'client-a',
    mapping_id: 'map-a',
    lifetime_seconds: 0xffffffff,
    now_monotonic_ms: Number.MAX_SAFE_INTEGER
  }), 'TWO_CLIENT_VALUE_INVALID', '$.lifetime_seconds');
  expectLabError(() => renewClientMapping(created.lab, {
    client_id: 'client-a',
    mapping_id: 'map-a',
    lifetime_seconds: 0,
    now_monotonic_ms: 999
  }), 'TWO_CLIENT_TIME_REGRESSION', '$.now_monotonic_ms');
  const missing = deleteClientMapping(created.lab, { client_id: 'client-a', mapping_id: 'missing' });
  assert.equal(missing.ok, false);
  assert.equal(missing.reason_code, 'MAPPING_NOT_FOUND');
  const duplicateId = createClientMapping(created.lab, mapRequest('client-b', 'map-a', 45001, { lifetime_seconds: 0 }));
  assert.equal(duplicateId.ok, false);
  assert.equal(duplicateId.reason_code, 'MAPPING_ID_EXISTS');
  expectLabError(() => createClientMapping({}, mapRequest('client-a', 'map-a', 45000)), 'TWO_CLIENT_STATE_INVALID');
});

test('F02 rejects proxies, accessors, symbols, sparse arrays and cycles without executing traps', () => {
  let traps = 0;
  const trap = () => { traps += 1; throw new Error('secret'); };
  const hostile = new Proxy(config(), {
    get: trap,
    getPrototypeOf: trap,
    ownKeys: trap,
    getOwnPropertyDescriptor: trap
  });
  expectLabError(() => createTwoClientLab(hostile), 'TWO_CLIENT_INPUT_INVALID');
  assert.equal(traps, 0);

  const nested = config();
  nested.clients[0] = new Proxy(nested.clients[0], { get: trap, ownKeys: trap });
  expectLabError(() => createTwoClientLab(nested), 'TWO_CLIENT_INPUT_INVALID');
  assert.equal(traps, 0);

  const accessor = config();
  Object.defineProperty(accessor, 'epoch', { enumerable: true, get: () => 10 });
  expectLabError(() => createTwoClientLab(accessor), 'TWO_CLIENT_INPUT_INVALID', '$.epoch');

  const symbol = config();
  symbol[Symbol('hidden')] = true;
  expectLabError(() => createTwoClientLab(symbol), 'TWO_CLIENT_INPUT_INVALID');

  const customArray = config();
  customArray.clients.extra = true;
  expectLabError(() => createTwoClientLab(customArray), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const numericOutsideLength = config();
  Object.defineProperty(numericOutsideLength.clients, '4294967295', {
    value: 'hidden',
    enumerable: true
  });
  expectLabError(() => createTwoClientLab(numericOutsideLength), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const subclassArray = config();
  subclassArray.clients = new (class ClientArray extends Array {})(...subclassArray.clients);
  expectLabError(() => createTwoClientLab(subclassArray), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const hiddenElement = config();
  Object.defineProperty(hiddenElement.clients, '0', {
    value: hiddenElement.clients[0],
    enumerable: false
  });
  expectLabError(() => createTwoClientLab(hiddenElement), 'TWO_CLIENT_INPUT_INVALID', '$.clients[0]');

  const arraySymbol = config();
  arraySymbol.clients[Symbol('hidden')] = true;
  expectLabError(() => createTwoClientLab(arraySymbol), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const sparse = config();
  sparse.clients = new Array(2);
  expectLabError(() => createTwoClientLab(sparse), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const hugeSparse = config();
  hugeSparse.clients = new Array(0xffffffff);
  expectLabError(() => createTwoClientLab(hugeSparse), 'TWO_CLIENT_INPUT_INVALID', '$.clients');

  const classInput = config();
  classInput.clients[0] = new (class ClientConfig {
    constructor() {
      Object.assign(this, config().clients[0]);
    }
  })();
  expectLabError(() => createTwoClientLab(classInput), 'TWO_CLIENT_INPUT_INVALID', '$.clients[0]');

  const withToJson = config();
  withToJson.toJSON = () => ({});
  expectLabError(() => createTwoClientLab(withToJson), 'TWO_CLIENT_INPUT_INVALID', '$.toJSON');

  const hidden = config();
  Object.defineProperty(hidden, 'hidden', { value: true, enumerable: false });
  expectLabError(() => createTwoClientLab(hidden), 'TWO_CLIENT_INPUT_INVALID', '$.hidden');

  const cyclic = config();
  cyclic.self = cyclic;
  expectLabError(() => createTwoClientLab(cyclic), 'TWO_CLIENT_INPUT_INVALID', '$.self');

  let deep = {};
  for (let index = 0; index < 20000; index += 1) deep = { x: deep };
  const deeplyNested = config();
  deeplyNested.extra = deep;
  expectLabError(() => createTwoClientLab(deeplyNested), 'TWO_CLIENT_INPUT_INVALID');

  const tooWide = config();
  tooWide.extra = {};
  for (let index = 0; index < 257; index += 1) tooWide.extra[`p${index}`] = index;
  expectLabError(() => createTwoClientLab(tooWide), 'TWO_CLIENT_INPUT_INVALID', '$.extra');

  let sharedDag = { leaf: 'bounded' };
  for (let index = 0; index < 3; index += 1) {
    sharedDag = { items: new Array(256).fill(sharedDag) };
  }
  const repeatedDag = config();
  repeatedDag.extra = sharedDag;
  expectLabError(() => createTwoClientLab(repeatedDag), 'TWO_CLIENT_INPUT_INVALID');

  const excessiveText = config();
  excessiveText.extra = 'x'.repeat((1024 * 1024) + 1);
  expectLabError(() => createTwoClientLab(excessiveText), 'TWO_CLIENT_INPUT_INVALID', '$.extra');

  const excessiveUtf8Text = config();
  excessiveUtf8Text.extra = '€'.repeat(400000);
  expectLabError(() => createTwoClientLab(excessiveUtf8Text), 'TWO_CLIENT_INPUT_INVALID', '$.extra');

  const excessiveKey = config();
  excessiveKey.extra = { ['k'.repeat(257)]: true };
  expectLabError(() => createTwoClientLab(excessiveKey), 'TWO_CLIENT_INPUT_INVALID', '$.extra');

  const excessiveUtf8Key = config();
  excessiveUtf8Key.extra = { ['é'.repeat(200)]: true };
  expectLabError(() => createTwoClientLab(excessiveUtf8Key), 'TWO_CLIENT_INPUT_INVALID', '$.extra');
});

test('F02 owns no clocks, timers, sockets or process-wide client state', () => {
  const beforeHandles = process._getActiveHandles().length;
  const first = crashClient(createTwoClientLab(config()), { client_id: 'client-a' }).lab;
  const second = createTwoClientLab(config());
  assert.equal(snapshotTwoClientLab(first).clients[0].status, 'crashed');
  assert.equal(snapshotTwoClientLab(second).clients[0].status, 'running');
  assert.equal(process._getActiveHandles().length, beforeHandles);
});
