'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const source = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function harness() {
  const nodes = new Map(), handlers = new Set(), pending = [], notices = [];
  const document = { activeElement: null, getElementById: id => nodes.get(id) || null,
    addEventListener(type, handler, capture) { if (type === 'keydown') { assert.equal(capture, true); handlers.add(handler); } },
    removeEventListener(_type, handler) { handlers.delete(handler); },
    createElement: () => element(), querySelector: () => invoker };
  function element(attrs = {}, tag = 'div') {
    let html = '';
    const node = { attrs, style: {}, children: [], inert: false, isConnected: true, tabIndex: attrs.tabindex === '-1' ? -1 : 0,
      value: attrs.value || '', disabled: false, hidden: false, owner: null,
      setAttribute(key, value) { attrs[key] = value; }, getAttribute: key => attrs[key],
      focus() { document.activeElement = this; }, getClientRects: () => [{}],
      contains(other) { return other === this || (other && other.owner === this); },
      querySelector(selector) { return this.children.find(child => selector === '.settings-close' && child.attrs.class === 'settings-close') || null; },
      querySelectorAll() { return this.children.filter(child => ['button', 'a', 'input', 'select'].includes(child.tag) && !child.disabled); },
      set innerHTML(value) {
        html = value;
        for (const child of this.children) { child.isConnected = false; if (child.attrs.id) nodes.delete(child.attrs.id); }
        this.children = [];
        for (const match of value.matchAll(/<(button|a|input|select|div|h2)\b[^>]*>/g)) {
          const childAttrs = Object.fromEntries([...match[0].matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
          const child = element(childAttrs, match[1]); child.owner = this;
          child.disabled = /\sdisabled(?:\s|>)/.test(match[0]);
          this.children.push(child); if (childAttrs.id) nodes.set(childAttrs.id, child);
        }
      }, get innerHTML() { return html; },
      remove() {
        this.isConnected = false; document.body.children = document.body.children.filter(child => child !== this);
        nodes.delete(this.id); this.children.forEach(child => { child.isConnected = false; if (child.attrs.id) nodes.delete(child.attrs.id); });
      }, tag };
    return node;
  }
  const background = element(), alreadyInert = element(); alreadyInert.inert = true;
  const invoker = element({}, 'button'); invoker.focus();
  document.body = { style: { overflow: 'auto' }, children: [background, alreadyInert],
    appendChild(node) { this.children.push(node); nodes.set(node.id, node); } };
  const context = vm.createContext({ document, AbortController, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
    fetch(url, options) { return new Promise((resolve, reject) => pending.push({ url, options, resolve, reject })); }, console });
  context.window = context;
  vm.runInContext(source('shared/safe_dom.js'), context);
  vm.runInContext(source('tunnel_settings.js'), context);
  context.showNotification = message => notices.push(message);
  async function reply(request, data, ok = true) { request.resolve({ ok, json: async () => data }); await flush(); }
  function key(key, shiftKey = false) {
    let prevented = false, stopped = false;
    for (const handler of [...handlers]) handler({ key, shiftKey, preventDefault() { prevented = true; }, stopImmediatePropagation() { stopped = true; } });
    return { prevented, stopped };
  }
  return { context, document, nodes, pending, handlers, notices, invoker, background, alreadyInert, reply, key };
}

test('settings trap keyboard focus, close with Escape and restore the previous focus and background state', async () => {
  const ui = harness(); ui.context.toggleSettings();
  const panel = ui.nodes.get('settings-panel');
  assert.equal(panel.getAttribute('role'), 'dialog');
  assert.equal(panel.getAttribute('aria-modal'), 'true');
  assert.equal(panel.getAttribute('aria-labelledby'), 'settings-title');
  assert.equal(ui.background.inert, true);
  assert.equal(ui.document.body.style.overflow, 'hidden');
  await ui.reply(ui.pending[0], {});
  const close = panel.querySelector('.settings-close');
  const controls = panel.querySelectorAll();
  assert.equal(ui.document.activeElement, close);
  assert.equal(close.getAttribute('aria-label'), 'Cerrar ajustes');
  assert.equal(ui.key('Tab', true).prevented, true);
  assert.equal(ui.document.activeElement, controls.at(-1));
  assert.equal(ui.key('Tab').prevented, true);
  assert.equal(ui.document.activeElement, close);
  assert.deepEqual(ui.key('Escape'), { prevented: true, stopped: true });
  assert.equal(ui.nodes.has('settings-panel'), false);
  assert.equal(ui.document.activeElement, ui.invoker);
  assert.equal(ui.background.inert, false);
  assert.equal(ui.alreadyInert.inert, true);
  assert.equal(ui.document.body.style.overflow, 'auto');
  assert.equal(ui.handlers.size, 0);
});

test('closing a loading dialog aborts it and stale data cannot reopen or replace the next settings dialog', async () => {
  const ui = harness(); ui.context.toggleSettings(); const old = ui.pending[0];
  ui.context.toggleSettings(); assert.equal(old.options.signal.aborted, true);
  ui.context.toggleSettings(); const current = ui.nodes.get('settings-panel');
  await ui.reply(old, { quality: '4k' });
  assert.match(current.innerHTML, /Cargando ajustes/);
  await ui.reply(ui.pending[1], {}, false);
  assert.match(current.innerHTML, /No se han podido cargar/);
  assert.doesNotMatch(current.innerHTML, /set-quality|Guardar Ajustes/);
  assert.equal(ui.nodes.get('settings-panel'), current);
});

test('settings controls are named and remote access uses the connection page without loading connection secrets', async () => {
  const ui = harness(); ui.context.toggleSettings(); await ui.reply(ui.pending[0], {});
  const panel = ui.nodes.get('settings-panel');
  for (const id of ['set-quality', 'set-language', 'set-method', 'set-minsize', 'set-password']) {
    assert.match(panel.innerHTML, new RegExp('<label[^>]*for="' + id + '"'));
  }
  for (const id of ['google-client-id', 'google-client-secret', 'set-openai-key', 'set-claude-key']) assert.ok(ui.nodes.get(id).getAttribute('aria-label'));
  assert.equal(ui.nodes.get('google-client-secret').getAttribute('type'), 'password');
  assert.match(panel.innerHTML, /href="\/connect"/);
  assert.doesNotMatch(panel.innerHTML, /Canal ntfy|set-public-ip/);
  assert.equal(ui.pending.some(p => p.url === '/api/connect-seed'), false);
  ui.context.selectAiProvider('openai');
  assert.equal(ui.nodes.get('choose-ai-openai').getAttribute('aria-pressed'), 'true');
  assert.equal(ui.nodes.get('choose-ai-gemini').getAttribute('aria-pressed'), 'false');
});

test('failed saves leave the dialog open and successful saves close through the same focus lifecycle', async () => {
  const ui = harness(); ui.context.toggleSettings(); await ui.reply(ui.pending[0], {});
  ui.context.saveSettingsPanel(); await ui.reply(ui.pending.at(-1), {}, false);
  assert.equal(ui.nodes.has('settings-panel'), true);
  assert.match(ui.notices.at(-1), /Error al guardar/);
  ui.context.saveSettingsPanel(); await ui.reply(ui.pending.at(-1), {});
  assert.equal(ui.pending.at(-1).url, '/api/emule/resync');
  await ui.reply(ui.pending.at(-1), { success: true });
  assert.equal(ui.nodes.has('settings-panel'), false);
  assert.equal(ui.document.activeElement, ui.invoker);
  assert.equal(ui.background.inert, false);
});

test('connection tests never send a stored password mask and explicit passwords travel only in JSON', async () => {
  const ui = harness(); ui.context.toggleSettings(); await ui.reply(ui.pending[0], { emulePassword: '********' });
  ui.context.testEmuleConnection();
  const saved = ui.pending.at(-1);
  assert.equal(saved.url, '/api/emule/login');
  assert.equal(saved.options.method, 'POST');
  assert.deepEqual(JSON.parse(saved.options.body), {});
  await ui.reply(saved, { success: false, reason: 'password_mismatch' });
  assert.match(ui.nodes.get('emule-test-status').innerHTML, /rechazado la contraseña/);
  assert.equal(ui.nodes.get('emule-test-status').getAttribute('role'), 'status');
  ui.nodes.get('set-password').value = 'test-new-password';
  ui.context.testEmuleConnection();
  const explicit = ui.pending.at(-1);
  assert.equal(explicit.url, '/api/emule/login');
  assert.deepEqual(JSON.parse(explicit.options.body), { password: 'test-new-password' });
  await ui.reply(explicit, { success: true });
  assert.match(ui.nodes.get('emule-test-status').innerHTML, /Conectado correctamente/);
});

test('saving masked settings resyncs on the server and keeps a failed connection visible without reporting a failed save', async () => {
  const ui = harness(); ui.context.toggleSettings(); await ui.reply(ui.pending[0], { emulePassword: '********' });
  ui.context.saveSettingsPanel();
  const save = ui.pending.at(-1);
  assert.equal(Object.hasOwn(JSON.parse(save.options.body), 'emulePassword'), false);
  await ui.reply(save, { emulePassword: '********' });
  const resync = ui.pending.at(-1);
  assert.equal(resync.url, '/api/emule/resync');
  assert.equal(resync.options.method, 'POST');
  assert.equal(resync.options.body, undefined);
  await ui.reply(resync, { success: false, reason: 'webserver_down' });
  assert.equal(ui.nodes.has('settings-panel'), true);
  assert.match(ui.nodes.get('emule-test-status').innerHTML, /Ajustes guardados.*WebServer no responde/);
  assert.doesNotMatch(ui.notices.at(-1), /Error al guardar/);
  ui.nodes.get('set-password').value = 'test-new-password';
  ui.context.saveSettingsPanel();
  assert.equal(JSON.parse(ui.pending.at(-1).options.body).emulePassword, 'test-new-password');
});

test('old connection results cannot overwrite a newer attempt or settings panel', async () => {
  const ui = harness(); ui.context.toggleSettings(); await ui.reply(ui.pending[0], {});
  ui.context.testEmuleConnection(); const older = ui.pending.at(-1);
  ui.context.testEmuleConnection(); const newer = ui.pending.at(-1);
  await ui.reply(newer, { success: true });
  await ui.reply(older, { success: false, reason: 'password_mismatch' });
  assert.match(ui.nodes.get('emule-test-status').innerHTML, /Conectado correctamente/);
  ui.context.testEmuleConnection(); const replaced = ui.pending.at(-1);
  ui.context.closeSettingsPanel(); ui.context.toggleSettings();
  await ui.reply(ui.pending.at(-1), {});
  await ui.reply(replaced, { success: true });
  assert.equal(ui.nodes.get('emule-test-status').innerHTML, '');
});
