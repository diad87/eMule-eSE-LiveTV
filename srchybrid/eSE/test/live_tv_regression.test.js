'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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
