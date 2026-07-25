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

test('legacy C++ HLS route falls back to the active viewer stream namespace', () => {
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');

  assert.match(web, /hF == INVALID_HANDLE_VALUE && theApp\.liveStreamManager != NULL/);
  assert.match(web, /GetStreamKey\(\)/);
  assert.match(web, /eMule_RTMP\\\\%hs\\\\%hs/);
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

test('hardware encoder selection proves the GPU can initialize and falls back safely', () => {
  const ingest = read(repoRoot, 'srchybrid', 'RTMPIngest.cpp');

  assert.doesNotMatch(ingest, /-hide_banner -encoders/);
  assert.match(ingest, /color=c=black:s=640x360:r=24/);
  assert.match(ingest, /-frames:v 1 -an -c:v %s -pix_fmt %s -f null NUL/);
  assert.match(ingest, /WaitForSingleObject\(pi\.hProcess, 10000\)/);
  assert.match(ingest, /waitResult == WAIT_OBJECT_0 && exitCode == 0/);
  assert.match(ingest, /HWENC_NVENC[\s\S]*HWENC_QSV[\s\S]*HWENC_AMF/);
  assert.match(ingest, /s_cached = HWENC_CPU_X264/);
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

test('Kad2 and Kad6 are independently selectable with dual mode as the default', () => {
  const policy = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'KadNetworkPolicy.h');
  const prefs = read(repoRoot, 'srchybrid', 'Preferences.cpp');
  const prefsHeader = read(repoRoot, 'srchybrid', 'Preferences.h');
  const kad = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'Kademlia.cpp');
  const kadUdp = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const clientUdp = read(repoRoot, 'srchybrid', 'ClientUDPSocket.cpp');
  const connectionPage = read(repoRoot, 'srchybrid', 'PPgConnection.cpp');
  const resources = read(repoRoot, 'srchybrid', 'emule.rc');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const natHealth = read(eseRoot, 'pages', 'misc_pages.js');

  assert.match(policy, /Kad2\s*=\s*1u\s*<<\s*0/);
  assert.match(policy, /Kad6\s*=\s*1u\s*<<\s*1/);
  assert.match(policy, /Both\s*=\s*Kad2\s*\|\s*Kad6/);
  assert.match(policy, /legacyKadEnabled\s*\?\s*static_cast<std::uint8_t>\(Both\)/);
  assert.match(policy, /LegacyKad2Enabled[\s\S]{0,160}return HasKad2\(mask\)/);

  assert.match(prefs, /m_uKadNetworkMask\s*=\s*KadNetworkPolicy::Both/);
  assert.match(prefs, /Migrate\(persistedMask,\s*networkkademlia\)/);
  assert.match(prefs, /WriteInt\(_T\("KadNetworkMask"\),\s*m_uKadNetworkMask,\s*_T\("Connection"\)\)/);
  assert.match(prefsHeader, /GetEffectiveKadNetworkMask\(\)[\s\S]{0,140}udpport\s*>\s*0/);

  assert.match(connectionPage, /ON_BN_CLICKED\(IDC_NETWORK_KADEMLIA/);
  assert.match(connectionPage, /ON_BN_CLICKED\(IDC_NETWORK_KAD6/);
  assert.match(connectionPage, /SetKadNetworkMask\(uKadNetworkMask\)/);
  assert.match(connectionPage, /ApplyNetworkMask\(thePrefs\.GetEffectiveKadNetworkMask\(\)\)/);
  assert.match(resources, /"Kad2",IDC_NETWORK_KADEMLIA[\s\S]{0,180}"Kad6",IDC_NETWORK_KAD6/);

  assert.match(kad, /ProcessPacket\([\s\S]{0,240}IsKad2Running\(\)/);
  assert.match(kad, /ProcessPacketV6\([\s\S]{0,220}IsKad6Running\(\)/);
  assert.match(kad, /ProcessPacketV4\([\s\S]{0,220}IsKad6Running\(\)/);
  assert.match(kadUdp, /ProcessPacketKad6[\s\S]{0,500}!CKademlia::IsKad6Running\(\)/);
  assert.match(clientUdp, /OP_KAD6HEADER[\s\S]{0,180}IsKad6Running\(\)/);
  assert.match(clientUdp, /OP_KADEMLIAPACKEDPROT[\s\S]{0,180}!Kademlia::CKademlia::IsKad2Running\(\)/);

  for (const field of [
    'kad_configured_mask', 'kad_running_mask',
    'kad2_running', 'kad2_connected',
    'kad6_running', 'kad6_connected', 'kad6_verified_contacts'
  ]) {
    assert.ok(web.includes(`\\"${field}\\"`), `missing C++ network status field: ${field}`);
    assert.ok(natHealth.includes(field), `missing dashboard network status field: ${field}`);
  }
});

test('hole-punch keeps Kad identity separate from the eD2K user hash', () => {
  const kad = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const udp = read(repoRoot, 'srchybrid', 'ClientUDPSocket.cpp');
  const udpHeader = read(repoRoot, 'srchybrid', 'ClientUDPSocket.h');

  assert.doesNotMatch(kad, /md4cpy\(entry\.abyExpectedKadID,\s*pExpectedClient->GetUserHash\(\)\)/);
  assert.match(kad, /pIdentityContact->GetClientID\(\)\.ToByteArray\(entry\.abyExpectedKadID\)/);
  assert.doesNotMatch(kad, /SetUserHash\(abyResponderKadID\)/);
  assert.match(kad, /InitiateUtpConnect\([\s\S]{0,120}pExpectedClient, bViaRendezvous\)/);
  assert.match(udpHeader, /InitiateUtpConnect\([^;]+CUpDownClient\* pExpectedClient,\s*bool bViaRendezvous/);
  assert.doesNotMatch(udp, /FindClientByUserHash\(pClientHash\)/);
  assert.match(udp, /FindClientByIP_KadPort\(uIPNetwork, nUDPPort\)/);
});

test('v9 capabilities and remote administration fail closed by default', () => {
  const prefs = read(repoRoot, 'srchybrid', 'Preferences.cpp');
  const dlg = read(repoRoot, 'srchybrid', 'EmuleDlg.cpp');
  const base = read(repoRoot, 'srchybrid', 'BaseClient.cpp');
  const keepalive = read(repoRoot, 'srchybrid', 'KadKeepalive.cpp');
  const prober = read(repoRoot, 'srchybrid', 'FirewallProberV6.cpp');
  const utp = read(repoRoot, 'srchybrid', 'eMuleAI', 'UtpSocket.cpp');
  const prefsHeader = read(repoRoot, 'srchybrid', 'Preferences.h');
  const client = read(repoRoot, 'srchybrid', 'UpdownClient.h');
  const downloads = read(repoRoot, 'srchybrid', 'DownloadQueue.cpp');
  const kadSearch = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'Search.cpp');
  const tunnel = read(repoRoot, 'srchybrid', 'LiveTunnel.cpp');
  const relay = read(repoRoot, 'srchybrid', 'RelayClient.cpp');
  const kadUdp = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const partFile = read(repoRoot, 'srchybrid', 'PartFile.cpp');
  const partWriteThread = read(repoRoot, 'srchybrid', 'PartFileWriteThread.cpp');
  const packaging = read(repoRoot, 'build_package.ps1');

  assert.match(prefs, /EseV9Experimental"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseNetLabConsent"\), EseNetLabUndecided, _T\("eSE"\)/);
  assert.match(prefs, /EseNetLabAdvancedConsent"\), EseNetLabUndecided, _T\("eSE"\)/);
  assert.match(prefs, /EseNetLabContributionConsent"\), EseNetLabUndecided, _T\("eSE"\)/);
  assert.match(prefs, /EseNetLabEnabled"\), false, _T\("eSE"\)/);
  assert.match(prefs, /WriteInt\(_T\("EseNetLabConsent"\)/);
  assert.match(prefs, /WriteInt\(_T\("EseNetLabAdvancedConsent"\)/);
  assert.match(prefs, /WriteInt\(_T\("EseNetLabContributionConsent"\)/);
  assert.match(prefs, /WriteBool\(_T\("EseNetLabEnabled"\)/);
  assert.match(prefsHeader, /IsEseNetLabActive\(\)[\s\S]{0,160}EseNetLabAccepted/);
  assert.match(prefs, /EseKad3Rendezvous"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseAutoKeepalive"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseRelayAccept"\),\s+false, _T\("eSE"\)/);
  assert.match(prefs, /EseRelayEgress"\),\s+false, _T\("eSE"\)/);
  assert.match(prefs, /EseReachSelector"\), false, _T\("eSE"\)/);
  assert.match(prefs, /KrpRelayEnabled"\), false, _T\("KRPRelay"\)/);
  assert.match(prefs, /EseHolePunchPortPredict"\), false, _T\("eSE"\)/);
  assert.match(prefs, /EseEd2kPunch3"\), false, _T\("eSE"\)/);
  assert.match(prefs, /Kad6PublicExitOptIn"\), false, _T\("eSE"\)/);
  assert.match(prefs, /Kad6BetaExitOptIn"\), false, _T\("eSE"\)/);
  assert.match(prefs, /WriteBool\(_T\("EseV9Experimental"\)/);
  assert.match(dlg, /RefreshEseV9PreviewCaps\(\)/);
  assert.match(dlg, /Esta es una beta de laboratorio de red/);
  assert.match(dlg, /bool activateAcceptedLevels = thePrefs\.GetEseNetLabEnabled\(\)/);
  assert.match(dlg, /const bool accepted =[\s\S]{0,120}AfxMessageBox\(notice[\s\S]{0,180}SetEseNetLabConsent\(accepted/);
  assert.match(dlg, /if \(theApp\.m_bHeadless\)[\s\S]{0,180}ApplyEseNetLabPreferenceState\(activateAcceptedLevels\)/);
  assert.match(dlg, /SetEseNetLabAdvancedConsent\([\s\S]{0,220}AfxMessageBox\(notice/);
  assert.match(dlg, /SetEseNetLabContributionConsent\([\s\S]{0,220}AfxMessageBox\(notice/);
  assert.match(dlg, /ApplyEseNetLabPreferenceState\(activateAcceptedLevels\)/);
  assert.match(prefs, /void CPreferences::ApplyEseNetLabPreferenceState\(bool active\)/);
  assert.match(prefs, /SetEseV9Experimental\(advanced\)/);
  assert.match(prefs, /SetEseRelayAccept\(contribution\)/);
  assert.match(prefs, /SetKrpRelayEnabled\(krpConfigured\)/);
  assert.match(prefs, /SetKrpRelayKillSwitch\(!krpConfigured\)/);
  assert.match(prefs, /SetKad6BetaExitOptIn\(contribution\)/);
  assert.doesNotMatch(dlg, /g_uEseCapsRuntime\s*=\s*[^;]*ESE_CAP_TUNNEL_BULK/s);
  assert.match(prober, /uint32 g_uEseCapsRuntime = 0;/);
  assert.match(prober, /if \(!CPreferences::GetEseV9Experimental\(\)\)\s*return;/);
  assert.match(prober, /ESE_CAP_KAD6 \| ESE_CAP_KAD6_ECONOMY/);
  assert.match(prober, /IsEseNetLabActive\(\)[\s\S]{0,180}ESE_CAP_NETLAB_V1/);
  assert.match(base, /GetEseEd2kPunch3\(\) && thePrefs\.GetEseKad3Rendezvous\(\)/);
  assert.match(base, /CanUseEseHolePunch\(\)[\s\S]{0,220}IsEseNetLabActive\(\)[\s\S]{0,120}SupportsEseNetLabV1Target\(\)/);
  assert.match(client, /SupportsEseNetLabV1Target\(\)[\s\S]{0,420}SupportsReachNetLabV1\(\)/);
  assert.match(downloads, /bNetLabPeer[\s\S]{0,180}KAD_REACH_CAP_NETLAB_V1/);
  assert.match(kadSearch, /bNetLab[\s\S]{0,120}KAD_REACH_CAP_NETLAB_V1/);
  assert.match(kadUdp, /Process_ESE_HOLEPUNCH_REQ[\s\S]{0,500}IsEseNetLabActive\(\)/);
  assert.match(kadUdp, /uSenderCaps & \(ESE_CAP_HOLEPUNCH_COOKIE \| ESE_CAP_NETLAB_V1\)/);
  assert.match(kadUdp, /SendEseHolePunchReq\([\s\S]{0,500}SupportsEseNetLabV1Target\(\)/);
  assert.match(utp, /on_utp_accept[\s\S]{0,300}IsEseNetLabActive\(\)/);
  assert.match(tunnel, /!thePrefs\.GetEseV9Experimental\(\)[\s\S]{0,100}ESE_CAP_KAD6/);
  assert.match(tunnel, /!optIn \? kad6::K6ReleaseGateStatus::OperatorOptOut/);
  assert.match(tunnel, /BuildTestCircuit\(CUpDownClient\* clientHint\)[\s\S]{0,900}GetConnectedSnapshot\(cands, 3, \/\*tunnelOnly=\*\/true\)/);
  assert.doesNotMatch(tunnel, /BuildTestCircuit\(CUpDownClient\* clientHint\)[\s\S]{0,1200}GetConnectedSnapshot\(cands, 3, \/\*tunnelOnly=\*\/false\)/);
  assert.match(relay, /config\.enabled = thePrefs\.GetKrpRelayEnabled\(\)/);
  assert.match(relay, /configured == relay::RelayStatus::Ok && config\.enabled && !config\.kill_switch/);
  assert.match(relay, /if \(!enabled \|\| killSwitch\)[\s\S]{0,240}SetKillSwitch\(true\)/);
  assert.match(relay, /thePrefs\.GetKrpRelayEnabled\(\)[\s\S]{0,100}GetKrpRelayExperimentalTcp\(\)/);
  assert.match(kadUdp, /Process_KADEMLIA3_PING_REQ[\s\S]{0,500}g_uEseCapsRuntime & ESE_CAP_KAD_KEEPALIVE/);
  assert.match(kadUdp, /Process_KADEMLIA3_PING_REQ[\s\S]{0,900}senderCaps & \(ESE_CAP_NETLAB_V1 \| ESE_CAP_KAD_KEEPALIVE\)/);
  assert.match(kadUdp, /Process_KADEMLIA3_PING_RES[\s\S]{0,300}g_uEseCapsRuntime & ESE_CAP_KAD_KEEPALIVE/);
  assert.match(keepalive, /OnPong[\s\S]{0,300}!IsRunning\(\)/);
  // Native DHT participation is an ordinary user-selected network plane.
  // Experimental service/exit capabilities remain fail-closed elsewhere.
  assert.match(kadUdp, /ProcessPacketKad6[\s\S]{0,500}!CKademlia::IsKad6Running\(\)/);
  assert.match(web, /explicit_consent_required/);
  assert.match(web, /ApplyEseNetLabPreferenceState\(false\)/);
  assert.doesNotMatch(web, /\/api\/ese\/v9[\s\S]{0,900}RequestK6PublicRelease\(/);
  assert.doesNotMatch(web, /\/api\/ese\/v9[\s\S]{0,900}SetKad6PublicExitOptIn\(false\)/);
  assert.match(web, /ApplyEseNetLabPreferenceState\(true\)/);
  assert.match(web, /advanced_consent/);
  assert.match(web, /contribution_consent/);
  assert.match(web, /kad6_beta_exit/);
  assert.match(web, /sURL\.Left\(15\) == "\/api\/ese\/netlab"/);
  assert.match(prober, /previewMask[\s\S]{0,360}ESE_CAP_HOLEPUNCH_RDV[\s\S]{0,180}InterlockedAnd\(caps, ~previewMask\)/);
  assert.match(web, /netlab_target_required/);
  assert.doesNotMatch(web, /\/api\/ese\/v9[\s\S]{0,1800}SetEseRelayAccept\(bOn\)/);
  assert.doesNotMatch(web, /\/api\/ese\/v9[\s\S]{0,1800}SetEseRelayEgress\(bOn\)/);
  assert.match(web, /\/api\/live\/direct_join[\s\S]{0,9000}PROXYTYPE_SOCKS4[\s\S]{0,160}PROXYTYPE_SOCKS4A/);
  assert.match(web, /\/api\/live\/direct_join[\s\S]{0,10000}ipv6_not_supported_by_socks4/);
  assert.match(web, /ESE_NETLAB_REPORT_V1/);
  assert.match(web, /GetConnectedSocketCount\(\)/);
  assert.match(web, /\\"central_telemetry\\":false/);
  assert.match(web, /sURL\.Left\(13\) == "\/api\/network\/"/);
  assert.match(web, /\/api\/network\/connect[\s\S]{0,1800}WEBGUIIA_CONNECTTOSERVER/);
  assert.match(web, /\/api\/network\/connect[\s\S]{0,2200}WEBGUIIA_KAD_START/);
  assert.match(web, /WebFileOperationRequest \*request[\s\S]{0,2200}WEBGUIIA_FILE_OPERATION/);
  assert.doesNotMatch(web, /WithFileByID\(FileHash,[\s\S]{0,900}DeletePartFile\(\)/);
  assert.match(dlg, /WEBGUIIA_FILE_OPERATION[\s\S]{0,500}WithFileByID[\s\S]{0,650}WEBFILEOP_CANCEL[\s\S]{0,120}DeletePartFile\(\)/);
  assert.match(partFile, /m_FlushList\.AddHead\(ToWrite\{[\s\S]{0,220}PART_WRITE_SET_LENGTH/);
  assert.doesNotMatch(partFile, /if \(newsize\) \{\s*const DWORD dwAllocT0/);
  assert.match(partWriteThread, /PART_WRITE_SET_LENGTH[\s\S]{0,1000}GetFileSizeEx[\s\S]{0,500}SetEndOfFile/);

  assert.match(packaging, /"\[UPnP\]"[\s\S]{0,80}"EnableUPnP=1"/);
  assert.match(packaging, /"\[WebServer\]"[\s\S]{0,120}"WebUseUPnP=0"/);
  assert.match(packaging, /"\[eSE\]"[\s\S]{0,240}"EseV9Experimental=0"/);
  assert.match(packaging, /'MaxUpload=-1'/);
  assert.match(packaging, /'MaxDownload=-1'/);
  for (const safeDefault of [
    'EseNetLabConsent=0', 'EseNetLabAdvancedConsent=0',
    'EseNetLabContributionConsent=0', 'EseNetLabEnabled=0',
    'EseKad3Rendezvous=0', 'EseAutoKeepalive=0', 'EseRelayAccept=0',
    'EseRelayEgress=0', 'EseReachSelector=0', 'EseHolePunchPortPredict=0',
    'NetworkKademlia=1', 'KadNetworkMask=3',
    'EseEd2kPunch3=0', 'Kad6PublicExitOptIn=0', 'Kad6BetaExitOptIn=0',
    'KrpRelayEnabled=0', 'KrpRelayKillSwitch=1', 'ExperimentalTcpDataPlane=0'
  ]) {
    assert.ok(packaging.includes(safeDefault), `missing fail-closed package default: ${safeDefault}`);
  }
  assert.doesNotMatch(packaging, /WebServerUseUPnP=1/);
});

test('Live send queues are bounded and ratio drops release their packet', () => {
  const socketHeader = read(repoRoot, 'srchybrid', 'EMSocket.h');
  const socket = read(repoRoot, 'srchybrid', 'EMSocket.cpp');
  const clientHeader = read(repoRoot, 'srchybrid', 'UpdownClient.h');
  const protocol = read(repoRoot, 'srchybrid', 'LiveProtocol.h');
  const manager = read(repoRoot, 'srchybrid', 'LiveStreamManager.cpp');

  assert.match(socketHeader, /GetQueuedDataBytes\(\) const/);
  assert.match(socket, /CSingleLock lock\(&self->sendLocker, TRUE\)/);
  assert.match(socket, /controlpacket_queue[\s\S]{0,500}standardpacket_queue/);
  assert.match(clientHeader, /GetSocketQueuedBytes\(\) const/);
  assert.match(protocol, /ESE_LIVE_MAX_PEER_QUEUE_BYTES\s+\(8u \* 1024u \* 1024u\)/);
  assert.ok(
    (manager.match(/GetSocketQueuedBytes\(\) > ESE_LIVE_MAX_PEER_QUEUE_BYTES/g) || []).length >= 3,
    'initial push, requested chunks and relay fanout must all apply backpressure'
  );
  assert.match(manager, /DROP-strong[\s\S]{0,360}delete chunkPkt;\s*return;/);
  assert.match(manager, /DROP-medium[\s\S]{0,360}delete chunkPkt;\s*return;/);
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
  const client = read(repoRoot, 'srchybrid', 'UpdownClient.h');
  const clientUdp = read(repoRoot, 'srchybrid', 'ClientUDPSocket.cpp');
  const utp = read(repoRoot, 'srchybrid', 'eMuleAI', 'UtpSocket.cpp');
  const kadSearch = read(repoRoot, 'srchybrid', 'kademlia', 'kademlia', 'Search.cpp');
  const kadUdp = read(repoRoot, 'srchybrid', 'kademlia', 'net', 'KademliaUDPListener.cpp');
  const channelApi = read(eseRoot, 'eSE-live', 'channel_api.js');
  const server = read(eseRoot, 'server.js');
  const liveManager = read(repoRoot, 'srchybrid', 'LiveStreamManager.cpp');
  const liveManagerHeader = read(repoRoot, 'srchybrid', 'LiveStreamManager.h');

  assert.match(base, /IPv6-only endpoint has no validated native-v6 route/);
  assert.match(base, /!bNoCallbacks && !IsIPv6OnlyEndpoint\(\)/);
  assert.match(prober, /uni->DadState != IpDadStatePreferred/);
  assert.match(prober, /uni->SuffixOrigin == IpSuffixOriginRandom/);
  assert.match(prober, /first validated candidate wins/);
  // Leave enough room for CRLF checkouts while keeping both operations in the
  // same compact kill-switch branch.
  assert.match(web, /ApplyEseNetLabPreferenceState\(false\)[\s\S]{0,480}RequestStop\(\)/);
  assert.match(web, /capability_advertised/);
  assert.match(client, /SupportsEseHolePunchRdvTarget\(\)[\s\S]{0,120}SupportsReachPunch3\(\)/);
  assert.match(kadSearch, /bPunch3[\s\S]{0,300}KAD_REACH_CAP_PUNCH_3W/);
  assert.match(base, /SupportsEseHolePunchRdvTarget\(\)/);
  assert.match(base, /InitiateKad3Rendezvous\([\s\S]{0,120}GetKadPort\(\), this\)/);
  assert.match(kadUdp, /EseRememberHolePunchNonce\(uTargetIP, uTargetPort, uNonce, pExpectedClient, true\)/);
  assert.match(kadUdp, /InitiateUtpConnect\([\s\S]{0,120}pExpectedClient, bViaRendezvous\)/);
  assert.match(kadUdp, /EseFindAuthenticatedRdvPeer[\s\S]{0,500}HasPassedSecureIdent\(false\)/);
  assert.match(clientUdp, /SetEseRdvTransport\(bViaRendezvous\)/);
  assert.match(utp, /IsEseRdvTransport\(\)[\s\S]{0,400}m_dwReachConnPunch3/);
  assert.match(server, /port: PORT/);
  assert.match(channelApi, /localhost:\$\{dashboardPort\}\/live\/watch/);
  assert.doesNotMatch(channelApi, /localhost:8080\/live\/watch/);
  assert.match(liveManagerHeader, /const CAddress& address, uint16 port/);
  assert.match(web, /ed2k:\/\/\|live\|HEXKEY\|\[IPv6\]:PORT\|TITLE\|\//);
  assert.match(web, /closeBracket[\s\S]{0,260}ReverseFind\(_T\(':'\)\)/);
  assert.match(web, /validIPv6[\s\S]{0,180}parsed\.IsUsablePublic\(\)/);
  assert.match(liveManager, /native IPv6 Live source/);
  assert.match(liveManager, /SetDirectIPv6Source\(\)/);
  assert.match(base, /IsLiveIPv6Source\(\) \|\| IsDirectIPv6Source\(\)/);
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
  const labTwoHop = tunnel.slice(
    tunnel.indexOf('uint32_t CLiveTunnel::BuildTestCircuit2Hop()'),
    tunnel.indexOf('void CLiveTunnel::GetCircuitsSnapshot'));
  assert.match(labTwoHop, /c->m_private2 = true;[\s\S]{0,80}m_pendingHopClients\.push_back\(hop2\)/);
  assert.match(circuit, /enum class CircuitAbortReason[\s\S]{0,300}HandshakeTimeout[\s\S]{0,100}ExtendTimeout/);
  for (const reason of ['StrictV1', 'PinMismatch', 'CapsFloor', 'SigFail']) {
    assert.match(tunnel, new RegExp(`m_abort_reason = CircuitAbortReason::${reason}`));
  }
  assert.match(tunnel, /void CLiveTunnel::DestroyCircuitFailClosed[\s\S]{0,900}m_auth_ok = false/);
  assert.match(tunnel, /HandshakeTimeout;[\s\S]{0,160}m_private2 \|\| c->m_strict3\) DestroyCircuitFailClosed/);
  assert.match(tunnel, /ExtendTimeout;[\s\S]{0,160}m_private2 \|\| c->m_strict3\) DestroyCircuitFailClosed/);
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
  assert.match(dialog, /if \(!theApp\.m_bSelfTest && theApp\.m_uHeadlessMetricsPort == 0\)[\s\S]{0,80}LaunchEseServer/);
  assert.match(dialog, /Metrics isolation: dashboard auto-spawn skipped \(port=%u\)/);
  const web = read(repoRoot, 'srchybrid', 'WebServer.cpp');
  const netlabSwitch = web.slice(
    web.indexOf('if (sURL.Left(11) == "/api/ese/v9")'),
    web.indexOf('// Local, sanitized cohort report'));
  assert.match(netlabSwitch, /if \(ok && CPreferences::Save\(\)\)/);
  assert.match(netlabSwitch, /error = "persist_failed"/);
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
  assert.match(preferences, /bPortableCommandLine && bConfigAvailableExecutable/);
  assert.match(preferences, /_tcsicmp\(value, _T\("portable"\)\)/);
  assert.match(preferences, /nRegistrySetting = 2/);
  for (const persistedGate of [
    'EseAutoKeepalive',
    'EseRelayAccept',
    'EseRelayEgress',
    'EseReachSelector',
    'EseHolePunchPortPredict',
    'EseEd2kPunch3'
  ]) {
    assert.match(preferences, new RegExp(`WriteBool\\(_T\\("${persistedGate}"\\)`));
  }
});

test('cross-site browser requests cannot inherit localhost trust', () => {
  const security = require('../security');
  security.init({ tunnel: { CONFIG: { accessToken: '0123456789abcdef0123456789abcdef' } }, trustedProxies: [] });
  security._test.resetRateState();
  const target = new URL('http://localhost:8080/api/settings');

  const crossOrigin = {
    method: 'POST',
    headers: { host: 'localhost:8080', origin: 'https://attacker.example' },
    socket: { remoteAddress: '127.0.0.1', encrypted: false }
  };
  const deniedByOrigin = fakeResponse();
  assert.equal(security.apply(target, crossOrigin, deniedByOrigin), false);
  assert.equal(deniedByOrigin.statusCode, 403);

  const crossSiteSubresource = {
    method: 'GET',
    headers: { host: 'localhost:8080', 'sec-fetch-site': 'cross-site' },
    socket: { remoteAddress: '::1', encrypted: false }
  };
  const deniedByMetadata = fakeResponse();
  assert.equal(security.apply(target, crossSiteSubresource, deniedByMetadata), false);
  assert.equal(deniedByMetadata.statusCode, 403);

  const sameOrigin = {
    method: 'POST',
    headers: { host: 'localhost:8080', origin: 'http://localhost:8080' },
    socket: { remoteAddress: '127.0.0.1', encrypted: false }
  };
  assert.equal(security.apply(target, sameOrigin, fakeResponse()), true);
});

test('malformed percent escapes in cookies fail closed instead of throwing', () => {
  const security = require('../security');
  security.init({ tunnel: { CONFIG: { accessToken: '0123456789abcdef0123456789abcdef' } }, trustedProxies: [] });
  security._test.resetRateState();
  const req = {
    method: 'GET',
    headers: { host: 'localhost:8080', cookie: 'ese_access=%E0%A4%A' },
    socket: { remoteAddress: '203.0.113.50', encrypted: false }
  };
  const res = fakeResponse();
  assert.doesNotThrow(() => security.apply(new URL('http://localhost:8080/api/settings'), req, res));
  assert.equal(res.statusCode, 401);
});

test('request body reader enforces its byte limit', async () => {
  const { PassThrough } = require('node:stream');
  const utils = require('../utils');
  const req = new PassThrough();
  req.headers = {};

  const result = new Promise(resolve => {
    utils.readBodyLimited(req, { limit: 4 }, (err, body) => resolve({ err, body }));
  });
  req.end('12345');

  const { err, body } = await result;
  assert.equal(err.code, 'BODY_TOO_LARGE');
  assert.equal(err.statusCode, 413);
  assert.equal(body, undefined);
});

test('log and download UI render untrusted text without HTML event handlers', () => {
  const server = read(eseRoot, 'server.js');
  const logRoute = read(eseRoot, 'debug_log.js');
  const myList = read(eseRoot, 'pages', 'mylist_page.js');

  assert.match(server, /document\.createTextNode/);
  assert.doesNotMatch(server, /pre\.innerHTML\s*=\s*colorize/);
  assert.doesNotMatch(logRoute, /Access-Control-Allow-Origin['"]?\s*:\s*['"]\*/);
  assert.match(myList, /data-dl-cancel/);
  assert.doesNotMatch(myList, /onclick="dlCancel/);
});

test('download metadata reaches the eMule API adapter', () => {
  const server = read(eseRoot, 'server.js');
  assert.match(
    server,
    /function emuleDownload\(h, cb, meta\)\s*\{\s*return emuleApi\.emuleDownload\(h, cb, meta\);\s*\}/
  );
});

test('URL sources resolve publicly and are pinned before FFmpeg starts', async () => {
  const selector = require('../eSE-live/source_selector');

  assert.equal(selector.isAllowedInputUrl('http://127.0.0.1/video'), false);
  assert.equal(selector.isAllowedInputUrl('http://[::1]/video'), false);
  assert.equal(selector.isAllowedInputUrl('http://[::ffff:127.0.0.1]/video'), false);

  const privateDns = await selector.resolveAndPinInputUrl(
    'http://media.example/video',
    async () => [{ address: '192.168.1.8', family: 4 }]
  );
  assert.equal(privateDns.valid, false);

  const publicDns = await selector.resolveAndPinInputUrl(
    'http://media.example:8080/video',
    async () => [{ address: '93.184.216.34', family: 4 }]
  );
  assert.equal(publicDns.valid, true);
  assert.equal(publicDns.url, 'http://93.184.216.34:8080/video');

  const prepared = await selector.prepareSource(
    { type: 'url', id: 'http://media.example:8080/video' },
    async () => [{ address: '93.184.216.34', family: 4 }]
  );
  assert.equal(prepared.valid, true);
  const args = selector.buildInputArgs(prepared.source);
  assert.ok(args.includes('http://93.184.216.34:8080/video'));
  assert.ok(args.includes('-max_redirects'));
  assert.throws(
    () => selector.buildInputArgs({ type: 'url', id: 'http://media.example/video' }),
    /DNS-resolved/
  );
});
