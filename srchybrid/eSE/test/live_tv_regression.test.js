'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const eseRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(eseRoot, '..', '..');
const read = (...parts) => fs.readFileSync(path.join(...parts), 'utf8');

test('browser players use the packaged HLS runtime and guard missing support', () => {
  const player = require('../live_player_html')();
  const channelApi = read(eseRoot, 'eSE-live', 'channel_api.js');
  const navbar = read(eseRoot, 'shared', 'navbar.js');
  const vendor = path.join(eseRoot, 'eSE-live', 'vendor', 'hls.min.js');

  assert.match(player, /src="\/live\/vendor\/hls\.min\.js"/);
  assert.match(player, /window\.Hls\s*&&\s*Hls\.isSupported\(\)/);
  assert.doesNotMatch(player, /cdn\.jsdelivr\.net\/npm\/hls\.js/);
  assert.doesNotMatch(player, /fonts\.googleapis\.com/);
  assert.doesNotMatch(navbar, /fonts\.googleapis\.com/);
  assert.match(channelApi, /p === '\/live\/vendor\/hls\.min\.js'/);
  assert.ok(fs.statSync(vendor).size > 100000, 'vendored hls.js should not be empty');
});

test('first-run action points at the real local watch route', () => {
  const page = read(eseRoot, 'eSE-live', 'live_tv_page.js');
  assert.match(page, /window\.location\.href=.*\/live\/watch\/local/);
  assert.doesNotMatch(page, /window\.location\.href=.*['"]\/player/);
});

test('category and language aliases are canonical and searchable', () => {
  const search = require('../eSE-live/channel_search');
  assert.equal(search.canonicalCategory('Deportes'), 'sports');
  assert.equal(search.canonicalCategory('Música'), 'music');
  assert.equal(search.canonicalCategory('24h'), '24/7');
  assert.equal(search.canonicalLanguage('Español'), 'es');
  assert.equal(search.canonicalLanguage('English'), 'en');

  const key = 'regression_' + Date.now();
  search.addRemoteChannel({
    streamKey: key,
    title: 'Canal de prueba',
    category: 'Cine',
    language: 'Español',
    bitrate: 3000,
    started: new Date().toISOString()
  });
  const matches = search.search({ category: 'movies', language: 'es' });
  assert.ok(matches.some(channel => channel.streamKey === key));
  search.unregisterChannel(key);
});

test('DirectShow input validation rejects device-name injection', () => {
  const selector = require('../eSE-live/source_selector');
  assert.equal(selector.validateSource({ type: 'webcam', id: 'Camera HD' }).valid, true);
  assert.equal(selector.validateSource({ type: 'webcam', id: 'Camera; calc.exe' }).valid, false);
  assert.equal(selector.validateSource({ type: 'screen', audioDevice: 'Stereo Mix|bad' }).valid, false);
});

test('legacy start routes are bridged to the P2P broadcaster', () => {
  const api = read(eseRoot, 'eSE-live', 'channel_api.js');
  assert.match(api, /source_not_supported_by_p2p/);
  assert.match(api, /proxyEmuleJson\(res, '\/api\/live\/broadcast\/start\?'/);
  assert.match(api, /proxyEmuleJson\(res, '\/api\/live\/broadcast\/stop'/);
  assert.doesNotMatch(api, /const result = pipeline\.start\(/);
  assert.doesNotMatch(api, /ed2k:\/\/\|stream\|/);
  assert.match(api, /ed2k:\/\/\|live\|\$\{key\}\|\|/);
});

test('C++ broadcaster rolls back failed prebuffer and removes HLS output', () => {
  const manager = read(repoRoot, 'srchybrid', 'LiveStreamManager.cpp');
  const ingest = read(repoRoot, 'srchybrid', 'RTMPIngest.cpp');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');

  assert.match(manager, /Prebuffer TIMEOUT:[\s\S]*StopBroadcast\(\);[\s\S]*return false;/);
  assert.match(manager, /ResetViewerHlsOutput\(true\)/);
  assert.match(ingest, /_T\("\\\\\*\.m3u8"\)/);
  assert.match(ingest, /RTMPCleanOutputDir\(m_strOutputDir\)/);
  assert.match(web, /\\"ready\\":%s,\\"state\\":\\"%s\\",\\"chunks\\":%d/);
  assert.match(web, /ch\.category/);
  assert.match(web, /ch\.startedAt/);
});

test('controlled 30 fps sources align two-second GOPs with independent HLS segments', () => {
  const ingest = read(repoRoot, 'srchybrid', 'RTMPIngest.cpp');
  assert.match(ingest, /gdigrab[\s\S]{0,260}-g 60 -keyint_min 60 -sc_threshold 0/);
  assert.match(ingest, /testsrc2[\s\S]{0,320}-g 60 -keyint_min 60 -sc_threshold 0/);
  assert.match(ingest, /delete_segments\+independent_segments\+program_date_time/);
  assert.match(ingest, /Slow OBS keyframe cadence detected/);
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  assert.doesNotMatch(web, /segmentDurationSec\\\":4/);
});

test('package manifest includes every offline player asset', () => {
  const pkg = JSON.parse(read(eseRoot, 'package.json'));
  assert.ok(pkg.pkg.assets.includes('eSE-live/vendor/hls.min.js'));
  assert.ok(pkg.pkg.assets.includes('eSE-live/vendor/hls.LICENSE'));
  assert.ok(pkg.pkg.assets.includes('eSE_Remote.html'));
  assert.equal(pkg.dependencies['nat-upnp-2'], undefined);
  assert.match(pkg.scripts.build, /node22-win-x64/);
  assert.ok(pkg.devDependencies['@yao-pkg/pkg']);
  assert.equal(pkg.devDependencies.pkg, undefined);
});

test('restarting the dashboard does not delete C++-owned HLS output', () => {
  const server = read(eseRoot, 'server.js');
  assert.match(server, /HLS files belong to the C\+\+ broadcast\/view session/);
  assert.doesNotMatch(server, /function cleanHlsOnExit\(/);
  assert.doesNotMatch(server, /setupUPnP\(/);
  assert.match(server, /process\.env\.ESE_PORT/);
});

test('hole-punch keeps Kad identity separate from the eD2K user hash', () => {
  const kad = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const udp = read(repoRoot, 'srchybrid', 'ClientUDPSocket.cpp');
  const udpHeader = read(repoRoot, 'srchybrid', 'ClientUDPSocket.h');

  assert.doesNotMatch(kad, /md4cpy\(entry\.abyExpectedKadID,\s*pExpectedClient->GetUserHash\(\)\)/);
  assert.match(kad, /pIdentityContact->GetClientID\(\)\.ToByteArray\(entry\.abyExpectedKadID\)/);
  assert.doesNotMatch(kad, /SetUserHash\(abyResponderKadID\)/);
  assert.match(kad, /InitiateUtpConnect\(uIP, uUDPPort, pExpectedClient\)/);
  assert.match(udpHeader, /InitiateUtpConnect\([^;]+CUpDownClient\* pExpectedClient\)/);
  assert.doesNotMatch(udp, /FindClientByUserHash\(pClientHash\)/);
  assert.match(udp, /FindClientByIP_KadPort\(uIPNetwork, nUDPPort\)/);
});

test('v9 capabilities and remote administration fail closed by default', () => {
  const prefs = read(repoRoot, 'srchybrid', 'Preferences.cpp');
  const dlg = read(repoRoot, 'srchybrid', 'EmuleDlg.cpp');
  const base = read(repoRoot, 'srchybrid', 'BaseClient.cpp');
  const keepalive = read(repoRoot, 'srchybrid', 'KadKeepalive.cpp');
  const prober = read(repoRoot, 'srchybrid', 'FirewallProberV6.cpp');
  const tunnel = read(repoRoot, 'srchybrid', 'LiveTunnel.cpp');
  const relay = read(repoRoot, 'srchybrid', 'RelayClient.cpp');
  const kadUdp = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const packaging = read(repoRoot, 'build_package.ps1');

  assert.match(prefs, /EseV9Experimental"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseKad3Rendezvous"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseAutoKeepalive"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseRelayAccept"\),\s+false, _T\("eSE"\)/);
  assert.match(prefs, /EseRelayEgress"\),\s+false, _T\("eSE"\)/);
  assert.match(prefs, /EseReachSelector"\), false, _T\("eSE"\)/);
  assert.match(prefs, /KrpRelayEnabled"\), false, _T\("KRPRelay"\)/);
  assert.match(prefs, /EseHolePunchPortPredict"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseEd2kPunch3"\), false, _T\("eSE"\)/);
  assert.match(prefs, /Kad6PublicExitOptIn"\), false, _T\("eSE"\)/);
  assert.match(prefs, /WriteBool\(_T\("EseV9Experimental"\)/);
  assert.match(dlg, /RefreshEseV9PreviewCaps\(\)/);
  assert.doesNotMatch(dlg, /g_uEseCapsRuntime\s*=\s*[^;]*ESE_CAP_TUNNEL_BULK/s);
  assert.match(prober, /uint32 g_uEseCapsRuntime = 0;/);
  assert.match(prober, /if \(!CPreferences::GetEseV9Experimental\(\)\)\s*return;/);
  assert.match(prober, /ESE_CAP_KAD6 \| ESE_CAP_KAD6_ECONOMY/);
  assert.match(base, /GetEseEd2kPunch3\(\) && thePrefs\.GetEseKad3Rendezvous\(\)/);
  assert.match(tunnel, /!thePrefs\.GetEseV9Experimental\(\)[\s\S]{0,100}ESE_CAP_KAD6/);
  assert.match(tunnel, /!optIn \? kad6::K6ReleaseGateStatus::OperatorOptOut/);
  assert.match(relay, /config\.enabled = thePrefs\.GetKrpRelayEnabled\(\)/);
  assert.match(relay, /m_initialized && config\.enabled && !config\.kill_switch/);
  assert.match(relay, /thePrefs\.GetKrpRelayEnabled\(\)[\s\S]{0,100}GetKrpRelayExperimentalTcp\(\)/);
  assert.match(kadUdp, /Process_KADEMLIA3_PING_REQ[\s\S]{0,500}g_uEseCapsRuntime & ESE_CAP_KAD_KEEPALIVE/);
  assert.match(kadUdp, /Process_KADEMLIA3_PING_RES[\s\S]{0,300}g_uEseCapsRuntime & ESE_CAP_KAD_KEEPALIVE/);
  assert.match(keepalive, /OnPong[\s\S]{0,300}!IsRunning\(\)/);
  assert.match(kadUdp, /ProcessPacketKad6[\s\S]{0,500}!thePrefs\.GetEseV9Experimental\(\)[\s\S]{0,100}ESE_CAP_KAD6/);
  assert.match(web, /SetEseV9Experimental\(bOn\)/);

  assert.match(packaging, /"\[UPnP\]"[\s\S]{0,80}"EnableUPnP=1"/);
  assert.match(packaging, /"\[WebServer\]"[\s\S]{0,120}"WebUseUPnP=0"/);
  assert.match(packaging, /"\[eSE\]"[\s\S]{0,100}"EseV9Experimental=0"/);
  for (const safeDefault of [
    'EseKad3Rendezvous=0', 'EseAutoKeepalive=0', 'EseRelayAccept=0',
    'EseRelayEgress=0', 'EseReachSelector=0', 'EseHolePunchPortPredict=0',
    'EseEd2kPunch3=0', 'Kad6PublicExitOptIn=0', 'KrpRelayEnabled=0',
    'KrpRelayKillSwitch=0', 'ExperimentalTcpDataPlane=0'
  ]) {
    assert.ok(packaging.includes(safeDefault), `missing fail-closed package default: ${safeDefault}`);
  }
  assert.doesNotMatch(packaging, /WebServerUseUPnP=1/);
});

test('download session expiry is reported as failure', () => {
  const api = read(eseRoot, 'emule_api.js');
  assert.match(api, /function finishDownloadRequest\(err, html\)/);
  assert.match(api, /session expired before the download was queued/);
  assert.doesNotMatch(api, /callback\(err, !err\)/);
});

test('IPv6, capability and share-link regressions remain guarded', () => {
  const base = read(repoRoot, 'srchybrid', 'BaseClient.cpp');
  const prober = read(repoRoot, 'srchybrid', 'FirewallProberV6.cpp');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const channelApi = read(eseRoot, 'eSE-live', 'channel_api.js');
  const server = read(eseRoot, 'server.js');

  assert.match(base, /IPv6-only endpoint has no validated native-v6 route/);
  assert.match(base, /!bNoCallbacks && !IsIPv6OnlyEndpoint\(\)/);
  assert.match(prober, /uni->DadState != IpDadStatePreferred/);
  assert.match(prober, /uni->SuffixOrigin == IpSuffixOriginRandom/);
  assert.match(prober, /first validated candidate wins/);
  assert.match(web, /InterlockedOr\(pEseCaps, \(LONG\)ESE_CAP_HOLEPUNCH_RDV\)/);
  assert.match(web, /InterlockedAnd\(pEseCaps, ~\(LONG\)ESE_CAP_HOLEPUNCH_RDV\)/);
  assert.match(server, /port: PORT/);
  assert.match(channelApi, /localhost:\$\{dashboardPort\}\/live\/watch/);
  assert.doesNotMatch(channelApi, /localhost:8080\/live\/watch/);
});

function fakeResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: '',
    setHeader(name, value) { this.headers[name] = value; },
    writeHead(status, headers) {
      this.statusCode = status;
      Object.assign(this.headers, headers || {});
    },
    end(body) { this.body = body || ''; }
  };
}

test('received HLS is local-only unless the remote request is authenticated', () => {
  const security = require('../security');
  const accessToken = '0123456789abcdef0123456789abcdef';
  security.init({ tunnel: { CONFIG: { accessToken } }, trustedProxies: [] });
  security._test.resetRateState();

  const remoteReq = {
    method: 'GET', headers: { host: 'localhost:8080' },
    socket: { remoteAddress: '203.0.113.20', encrypted: false }
  };
  const denied = fakeResponse();
  assert.equal(security.apply(new URL('http://localhost:8080/hls-local/abc/stream.m3u8'), remoteReq, denied), false);
  assert.equal(denied.statusCode, 401);
  assert.equal(denied.headers['Cache-Control'], 'no-store');

  const allowed = fakeResponse();
  assert.equal(security.apply(new URL('http://localhost:8080/hls-local/abc/stream.m3u8?a=' + accessToken), remoteReq, allowed), true);
  assert.match(String(allowed.headers['Set-Cookie']), /ese_access=/);

  const localReq = {
    method: 'GET', headers: { host: 'localhost:8080' },
    socket: { remoteAddress: '127.0.0.1', encrypted: false }
  };
  assert.equal(security.apply(new URL('http://localhost:8080/hls-local'), localReq, fakeResponse()), true);
  assert.equal(security.apply(new URL('http://localhost:8080/hls-local-evil/file.ts'), remoteReq, fakeResponse()), true);
});

test('dashboard rate limiting is bounded and only trusts configured proxies', () => {
  const security = require('../security');
  security.init({ trustedProxies: [], maxRateBuckets: 2 });
  security._test.resetRateState();

  const spoofed = {
    headers: { 'x-forwarded-for': '198.51.100.99' },
    socket: { remoteAddress: '203.0.113.30' }
  };
  assert.equal(security._test.clientKey(spoofed), '203.0.113.30');

  security.init({ trustedProxies: ['127.0.0.1'], maxRateBuckets: 2 });
  const proxied = {
    headers: { 'x-forwarded-for': '198.51.100.99, 203.0.113.31' },
    socket: { remoteAddress: '127.0.0.1' }
  };
  assert.equal(security._test.clientKey(proxied), '203.0.113.31');
  assert.equal(security._test.clientKey({ headers: {}, socket: { remoteAddress: '2001:db8:1:2:abcd::1' } }), '2001:db8:1:2::/64');

  const loginUrl = new URL('http://localhost/api/emule/login');
  for (let i = 1; i <= 3; i++) {
    const req = { headers: {}, socket: { remoteAddress: '203.0.113.' + i } };
    assert.equal(security._test.checkRate(loginUrl, req, fakeResponse()), true);
  }
  assert.equal(security._test.bucketCount(), 2);
  assert.equal(security._test.overflowBucketCount(), 1);

  let limited = false;
  for (let i = 0; i < 11; i++) {
    const req = { headers: {}, socket: { remoteAddress: '203.0.114.' + i } };
    const res = fakeResponse();
    if (!security._test.checkRate(loginUrl, req, res)) {
      limited = true;
      assert.equal(res.statusCode, 429);
    }
  }
  assert.equal(limited, true);
  assert.equal(security._test.bucketCount(), 2);
});

function makeNodesDatFixture() {
  const count = 3;
  const buffer = Buffer.alloc(12 + count * 34);
  buffer.writeUInt32LE(0, 0);
  buffer.writeUInt32LE(2, 4);
  buffer.writeUInt32LE(count, 8);
  for (let i = 0; i < count; i++) {
    const offset = 12 + i * 34;
    buffer.fill(i + 1, offset, offset + 16);
    buffer.writeUInt32LE(0x01020304 + i, offset + 16);
    buffer.writeUInt16LE(4672 + i, offset + 20);
    buffer.writeUInt16LE(4662 + i, offset + 22);
    buffer.writeUInt8(9, offset + 24);
  }
  return buffer;
}

test('nodes.dat bootstrap is disabled by default and requires verified deterministic input', async () => {
  const bootstrap = require('../eSE-live/nodes_bootstrap');
  const fixture = makeNodesDatFixture();
  const hash = crypto.createHash('sha256').update(fixture).digest('hex');

  assert.deepEqual(bootstrap.validateNodesDat(fixture), {
    version: 2, bootstrapEdition: 0, count: 3, recordBytes: 34
  });
  assert.equal(bootstrap.verifyBuffer(fixture, hash).sha256, hash);
  assert.throws(() => bootstrap.verifyBuffer(fixture, '0'.repeat(64)), /SHA-256 mismatch/);
  const invalid = Buffer.from(fixture);
  invalid.writeUInt32LE(0, 12 + 16);
  assert.throws(() => bootstrap.validateNodesDat(invalid), /invalid endpoint/);
  assert.equal(bootstrap.configFromEnv({}), null);
  assert.throws(() => bootstrap.configFromEnv({ ESE_NODES_DAT_URL: 'https://example.invalid/nodes.dat' }), /must be set together/);
  assert.throws(() => bootstrap.configFromEnv({
    ESE_NODES_DAT_URL: 'http://example.invalid/nodes.dat',
    ESE_NODES_DAT_SHA256: hash,
    ESE_NODES_DAT_DEST: path.join(os.tmpdir(), 'nodes.dat')
  }), /must be an HTTPS URL/);

  let networkCalls = 0;
  assert.deepEqual(await bootstrap.startFromEnv({}, { https: { get() { networkCalls++; } } }), { status: 'disabled' });
  assert.equal(networkCalls, 0);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ese-nodes-test-'));
  try {
    const destination = path.join(tempDir, 'config', 'nodes.dat');
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, Buffer.from('old'));
    bootstrap.installBuffer(fixture, destination);
    assert.deepEqual(fs.readFileSync(destination), fixture);
    assert.deepEqual(fs.readFileSync(destination + '.bak'), Buffer.from('old'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }

  const channelApi = read(eseRoot, 'eSE-live', 'channel_api.js');
  const packaging = read(repoRoot, 'build_package.ps1');
  assert.doesNotMatch(channelApi, /nodes-dat\.com/);
  assert.doesNotMatch(packaging, /Invoke-WebRequest[^\n]+nodes\.dat/);
  assert.match(packaging, /nodes\.dat\.sha256/);
});

test('source loss schedules bounded rotating peer replenishment', () => {
  const manager = read(repoRoot, 'srchybrid', 'LiveStreamManager.cpp');
  const mesh = read(repoRoot, 'srchybrid', 'LiveMeshManager.cpp');
  const policy = read(repoRoot, 'srchybrid', 'LivePeerRefreshPolicy.h');

  assert.doesNotMatch(manager, /TODO:\s*Request more peers from broadcaster/);
  assert.match(manager, /m_peerRefreshPolicy\.OnSourceLost/);
  assert.match(manager, /if \(m_peerRefreshPolicy\.IsPending\(\)\)[\s\S]{0,100}RequestMorePeers\(\)/);
  assert.match(manager, /Peer refresh via tunnel/);
  assert.match(manager, /m_strictTunnelOnly/);
  assert.match(mesh, /m_pManager->RequestMorePeers\(\)/);
  assert.match(policy, /LOSS_GRACE_MS = 2000/);
  assert.match(policy, /REQUEST_COOLDOWN_MS = 15000/);
  assert.match(policy, /TakeCandidate/);
  assert.match(policy, /\(int32_t\)\(now - target\) >= 0/);
});

test('Adaptive is Kad6-first, auto-seeds, and reports the real route state', () => {
  const selector = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'KadV2ModeSelector.cpp');
  const pool = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'KadV2TunnelPool.cpp');
  const tunnel = read(repoRoot, 'srchybrid', 'LiveTunnel.cpp');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const api = read(eseRoot, 'eSE-live', 'channel_api.js');

  assert.match(selector, /case CKadV2Mode::Adaptive:[\s\S]{0,900}return CKadV2Mode::Tunneled;/);
  assert.match(pool, /privateActive == 0[\s\S]{0,1200}BuildSuccessorCircuit\(\)/);
  assert.match(pool, /AUTO_SEED_RETRY_MAX_MS = 5u \* 60u \* 1000u/);
  assert.match(tunnel, /Prefer a Kad6-capable EXIT[\s\S]{0,400}ESE_CAP_KAD6/);
  assert.match(tunnel, /HasEseNodePub\(\)[\s\S]{0,180}Kad6CtEqual/);
  assert.match(tunnel, /kK6FlagStrict[\s\S]{0,100}minimumHops = 3;[\s\S]{0,100}else if \(quotaMessage\)/);
  assert.ok(web.includes('\\\"kad6CircuitActive\\\":%s'));
  assert.ok(web.includes('\\\"routeState\\\":\\\"%s\\\"'));
  for (const state of ['kad6', 'tunnel_kad2_compat', 'kad2_fallback',
                       'kad2_direct', 'blocked_waiting_kad6']) {
    assert.match(api, new RegExp(state));
  }
});

test('Kad6 Private and Strict paths fail closed at their declared hop counts', () => {
  const tunnel = read(repoRoot, 'srchybrid', 'LiveTunnel.cpp');
  const circuit = read(repoRoot, 'srchybrid', 'LiveCircuit.h');
  const keepalive = read(repoRoot, 'srchybrid', 'KadKeepalive.cpp');
  const successor = tunnel.slice(
    tunnel.indexOf('bool CLiveTunnel::BuildSuccessorCircuit()'),
    tunnel.indexOf('bool CLiveTunnel::BuildQuotaGuardCircuit()'));

  assert.match(successor, /if \(BuildSuccessor3Hop\(\)\) return true;[\s\S]{0,80}return BuildSuccessor2Hop\(\);/);
  assert.doesNotMatch(successor, /BuildPool|1-hop fallback/);
  assert.match(circuit, /bool m_private2 = false;/);
  assert.match(tunnel, /c->m_private2 = true;[\s\S]{0,80}m_pendingHopClients\.push_back\(hop2\)/);
  assert.match(tunnel, /Kad6CtEqual\(a->GetEseNodePub\(\), b->GetEseNodePub\(\), 32\)/);
  assert.match(tunnel, /circ->m_private2 \|\| circ->m_strict3[\s\S]{0,500}DestroyCircuitFailClosed\(circ\)/);
  assert.match(tunnel, /minimumHops = sub_cmd == TUN_OP_KAD6_GATEWAY \? 2 : 1;/);
  assert.match(tunnel, /quotaMessage[\s\S]{0,500}minimumHops = 3;[\s\S]{0,300}minimumHops = 1;/);
  assert.match(keepalive, /InterlockedCompareExchange[\s\S]{0,200}m_running/);
  assert.match(keepalive, /InterlockedIncrement\(&m_statPingsSent\)/);
});

test('--selftest verifies signed chunk ingest and returns failure to the caller', () => {
  const dialog = read(repoRoot, 'srchybrid', 'EmuleDlg.cpp');
  const manager = read(repoRoot, 'srchybrid', 'LiveStreamManager.cpp');
  const preferences = read(repoRoot, 'srchybrid', 'Preferences.cpp');

  assert.match(dialog, /RunIsolatedLoopbackSelfTest\(failure\)/);
  assert.match(dialog, /ScheduleSelfTestExit\(passed \? 0 : 2\)/);
  assert.match(dialog, /PostThreadMessage\(g_uMainThreadId, WM_QUIT/);
  assert.match(dialog, /m_nSelfTestExitCode = exitCode/);
  const app = read(repoRoot, 'srchybrid', 'Emule.cpp');
  assert.match(app, /return m_bSelfTest \? m_nSelfTestExitCode : baseExitCode/);
  assert.match(dialog, /if \(!theApp\.m_bSelfTest\)[\s\S]{0,80}LaunchEseServer/);
  assert.match(dialog, /AfxBeginThread\(HeadlessActionDelayThread/);
  assert.match(dialog, /PostMessage\(hwnd, UM_LIVE_HEADLESS_ACTION/);
  assert.match(dialog, /ON_MESSAGE\(UM_LIVE_HEADLESS_ACTION, OnLiveHeadlessAction\)/);
  assert.match(dialog, /if \(theApp\.m_bSelfTest\) \{[\s\S]{0,180}RunHeadlessAction\(\);[\s\S]{0,40}return TRUE;/);
  assert.doesNotMatch(dialog, /Selftest: 5 s testpattern broadcast/);
  assert.match(manager, /CreateChunkPacketV2/);
  assert.match(manager, /duplicate V2 chunk was not rejected exactly once/);
  assert.match(manager, /tampered\.back\(\) \^= 0x01/);
  assert.match(manager, /m_bSuppressHlsOutput = true/);
  assert.match(manager, /Selftest loopback PASS/);
  assert.match(preferences, /bPortableSelfTest && bConfigAvailableExecutable/);
  assert.match(preferences, /nRegistrySetting = 2/);
});
