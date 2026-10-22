'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const live = require('../eSE-live/live_tv_page');

function holePunchPanel(ip, port) {
  const html = live.render({}, {});
  const script = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
  new vm.Script(script);
  const start = script.indexOf('// Hole-punch diagnostic panel');
  const end = script.indexOf('// v7.4.0', start);
  const elements = {};
  const requests = [];
  for (const id of ['hp-test-btn', 'hp-target-ip', 'hp-target-port', 'hp-test-result']) {
    elements[id] = { value: '', style: {}, addEventListener(event, fn) { this[event] = fn; } };
  }
  elements['hp-target-ip'].value = ip;
  elements['hp-target-port'].value = port;
  vm.runInNewContext(script.slice(start, end), {
    document: { getElementById: id => elements[id] },
    setTimeout() {},
    fetch(url) { requests.push(url); return Promise.resolve({ json: () => Promise.resolve({ success: true, counters: {} }) }); }
  });
  elements['hp-test-btn'].click();
  return { elements, requests };
}

test('rendered Live diagnostic accepts a valid IPv4 address and UDP port', () => {
  const panel = holePunchPanel('192.168.1.10', '4672');
  assert.deepEqual(panel.requests, ['/api/holepunch/test?ip=192.168.1.10&udp_port=4672']);
});

test('rendered Live diagnostic rejects malformed addresses and ports', () => {
  for (const [ip, port] of [['not-an-ip', '4672'], ['192.168.1.10', 'letters'], ['192.168.1.10', '0']]) {
    const panel = holePunchPanel(ip, port);
    assert.deepEqual(panel.requests, []);
    assert.match(panel.elements['hp-test-result'].textContent, /no v/);
  }
});
