'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { resolveWebPort } = require('../emule_web_port');
const { publishEndpoint } = require('../dashboard_endpoint');
const { listenDashboardRange } = require('../dashboard_port_range');

test('configured WebUI port and portable directory are preserved', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ese-startup-'));
  const ini = path.join(root, 'preferences.ini');
  const marker = path.join(root, 'ese-dashboard.endpoint');
  const runtime = path.join(root, 'runtime');
  try {
    fs.writeFileSync(ini, '[Other]\nPort=5\n[WebServer]\nPort=49383\n');
    assert.equal(resolveWebPort({ ESE_EMULE_CONFIG_DIR: root }), 49383);
    assert.equal(resolveWebPort({ ESE_EMULE_WEB_PORT: '49384', ESE_EMULE_CONFIG_DIR: root }), 49384);
    fs.writeFileSync(ini, Buffer.concat([Buffer.from([0xff, 0xfe]),
      Buffer.from('[WebServer]\r\nPort=49385\r\n', 'utf16le')]));
    assert.equal(resolveWebPort({ ESE_EMULE_CONFIG_DIR: root }), 49385);
    fs.appendFileSync(ini, Buffer.from([0x00]));
    assert.throws(() => resolveWebPort({ ESE_EMULE_CONFIG_DIR: root }), /encoding/);
    for (const value of ['0', '65536', '4711x', '', '-1']) {
      assert.throws(() => resolveWebPort({ ESE_EMULE_WEB_PORT: value }), /Invalid/);
    }
    publishEndpoint(marker, 8082, 12345);
    assert.equal(fs.readFileSync(marker, 'ascii'), '12345 8082\n');
    publishEndpoint(marker, 8083, 12346);
    assert.equal(fs.readFileSync(marker, 'ascii'), '12346 8083\n');
    assert.throws(() => publishEndpoint(marker, 65536, 12346), /Invalid/);
    assert.equal(fs.readFileSync(marker, 'ascii'), '12346 8083\n');
    const result = spawnSync(process.execPath, ['-e', 'process.stdout.write(require(process.argv[1]).get())',
      path.resolve(__dirname, '../runtime_dir.js')], {
      env: { ...process.env, ESE_RUNTIME_DIR: runtime }, encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, runtime);
    assert.equal(fs.statSync(runtime).isDirectory(), true);
  } finally {
    for (const file of [ini, marker]) if (fs.existsSync(file)) fs.unlinkSync(file);
    if (fs.existsSync(runtime)) fs.rmdirSync(runtime);
    fs.rmdirSync(root);
  }
});
test('real listener skips occupied 8080 and remains on loopback', async () => {
  const occupied = http.createServer(); let ownsOccupied = false;
  await new Promise((resolve, reject) => {
    occupied.once('error', error => error.code === 'EADDRINUSE' ? resolve() : reject(error));
    occupied.listen(8080, '127.0.0.1', () => { ownsOccupied = true; resolve(); });
  });
  const expected = 'local dashboard'.repeat(40000);
  const dashboard = http.createServer((_req, res) => res.end(expected));
  try {
    await new Promise((resolve, reject) => listenDashboardRange(dashboard, 8080, '127.0.0.1', resolve, reject));
    assert.equal(dashboard.address().address, '127.0.0.1');
    assert.ok(dashboard.address().port >= 8081 && dashboard.address().port <= 8090);
    const body = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: dashboard.address().port,
        headers: { Connection: 'close' }, agent: false }, response => {
        let text = ''; response.on('data', bytes => text += bytes); response.on('end', () => resolve(text));
      }).on('error', reject);
    });
    assert.equal(body, expected);
  } finally {
    if (dashboard.listening) await new Promise(resolve => dashboard.close(resolve));
    if (ownsOccupied) await new Promise(resolve => occupied.close(resolve));
  }
});
