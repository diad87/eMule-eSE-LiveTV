'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const page = require('../eSE-live/live_tv_page');

function statusPanel() {
  const html = page.render({}, {});
  const script = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
  new vm.Script(script);
  const start = script.indexOf('// Pre-flight + live monitor pollers');
  const end = script.indexOf('\ncheckConnection();', start);
  const nodes = {};
  const requests = [];
  for (const id of ['preflight-panel', 'pf-freshness', 'pf-summary-state', 'pf-kad', 'pf-id', 'pf-up', 'pf-ff', 'pf-ip', 'live-monitor', 'mon-label', 'mon-freshness', 'mon-mode', 'mon-buf', 'mon-viewers', 'mon-served', 'mon-recv', 'mon-missing', 'mon-mesh']) {
    const classes = new Set();
    nodes[id] = { textContent: '', style: {}, classList: { toggle(name, enabled) { enabled ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) } };
  }
  const context = vm.createContext({
    document: { getElementById: id => nodes[id] || null },
    fetch(url) { return new Promise((resolve, reject) => requests.push({ url, reject, resolve(data, ok = true) { resolve({ ok, json: () => Promise.resolve(data) }); } })); }
  });
  vm.runInContext(script.slice(start, end), context);
  async function reply(method, data, ok = true) {
    const done = context[method]();
    requests.at(-1).resolve(data, ok);
    await done;
  }
  return { nodes, context, requests, reply };
}

const preflight = { kad_connected: true, high_id: true, max_upload_kbs: 500, ffmpeg_found: true, public_ip: '192.0.2.1', port: 4662 };

test('preflight marks every old check as stale on backend failure and restores fresh data on recovery', async () => {
  const ui = statusPanel();
  await ui.reply('refreshPreflight', preflight);
  const timestamp = ui.nodes['pf-freshness'].textContent.replace('Actualizado: ', '');
  assert.match(ui.nodes['pf-id'].textContent, /HighID/);
  assert.match(ui.nodes['pf-ip'].textContent, /192\.0\.2\.1/);
  await ui.reply('refreshPreflight', { ready: false, error: 'eMule offline' });
  assert.equal(ui.nodes['preflight-panel'].classList.contains('is-stale'), true);
  assert.equal(ui.nodes['pf-freshness'].textContent, 'Datos desactualizados · Última actualización: ' + timestamp);
  for (const id of ['pf-kad', 'pf-id', 'pf-up', 'pf-ff']) {
    assert.match(ui.nodes[id].textContent, /sin datos actuales/);
    assert.doesNotMatch(ui.nodes[id].textContent, /✅/);
  }
  assert.equal(ui.nodes['pf-ip'].textContent, 'IP sin actualizar');
  await ui.reply('refreshPreflight', { ...preflight, public_ip: '192.0.2.2' });
  assert.equal(ui.nodes['preflight-panel'].classList.contains('is-stale'), false);
  assert.equal(ui.nodes['pf-summary-state'].textContent, '');
  assert.match(ui.nodes['pf-ip'].textContent, /192\.0\.2\.2/);
});

test('monitor distinguishes empty error payloads from an explicitly stopped session', async () => {
  const ui = statusPanel();
  await ui.reply('refreshMonitor', { broadcasting: true, viewing: false, broadcastPeers: 4, bufCount: 6 });
  assert.equal(ui.nodes['mon-mode'].textContent, 'EMITIENDO');
  const timestamp = ui.nodes['mon-freshness'].textContent.replace('Actualizado: ', '');
  await ui.reply('refreshMonitor', {});
  assert.equal(ui.nodes['live-monitor'].style.display, '');
  assert.equal(ui.nodes['live-monitor'].classList.contains('is-stale'), true);
  assert.equal(ui.nodes['mon-label'].textContent, 'Estado de la emisión sin confirmar');
  assert.equal(ui.nodes['mon-freshness'].textContent, 'Datos desactualizados · Última actualización: ' + timestamp);
  for (const id of ['mon-mode', 'mon-buf', 'mon-viewers', 'mon-served', 'mon-recv', 'mon-missing', 'mon-mesh']) assert.equal(ui.nodes[id].textContent, '—');
  await ui.reply('refreshMonitor', { broadcasting: false, viewing: false });
  assert.equal(ui.nodes['live-monitor'].style.display, 'none');
  assert.equal(ui.nodes['live-monitor'].classList.contains('is-stale'), false);
  await ui.reply('refreshMonitor', { broadcasting: false, viewing: true, bufCount: 3 });
  assert.equal(ui.nodes['live-monitor'].style.display, '');
  assert.equal(ui.nodes['mon-mode'].textContent, 'VIENDO');
});

test('initial HTTP and network errors show unavailable data without inventing a last update', async () => {
  const ui = statusPanel();
  await ui.reply('refreshPreflight', preflight, false);
  assert.equal(ui.nodes['pf-summary-state'].textContent, ' · Sin datos');
  assert.equal(ui.nodes['pf-freshness'].textContent, 'Sin datos disponibles · Reintentando automáticamente');
  const done = ui.context.refreshMonitor();
  ui.requests.at(-1).reject(new Error('network unavailable'));
  await done;
  assert.equal(ui.nodes['mon-freshness'].textContent, 'Sin datos disponibles · Reintentando automáticamente');
  assert.equal(ui.nodes['mon-mode'].textContent, '—');
});

test('older status responses cannot restore obsolete green checks or monitor counters', async () => {
  const ui = statusPanel();
  const oldPreflight = ui.context.refreshPreflight();
  const newPreflight = ui.context.refreshPreflight();
  ui.requests[1].resolve({ error: 'offline' });
  await newPreflight;
  ui.requests[0].resolve(preflight);
  await oldPreflight;
  assert.equal(ui.nodes['preflight-panel'].classList.contains('is-stale'), true);
  assert.match(ui.nodes['pf-kad'].textContent, /sin datos actuales/);
  const oldMonitor = ui.context.refreshMonitor();
  const newMonitor = ui.context.refreshMonitor();
  ui.requests[3].resolve({});
  await newMonitor;
  ui.requests[2].resolve({ broadcasting: true, viewing: false, broadcastPeers: 99 });
  await oldMonitor;
  assert.equal(ui.nodes['live-monitor'].classList.contains('is-stale'), true);
  assert.equal(ui.nodes['mon-viewers'].textContent, '—');
});
