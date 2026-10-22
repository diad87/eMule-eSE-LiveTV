'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { EventEmitter } = require('node:events');
const { listenDashboardRange } = require('../dashboard_port_range');

class FakeServer extends EventEmitter {
  constructor(busy) { super(); this.busy = busy; this.attempts = []; }
  listen(port, host) {
    this.attempts.push([port, host]);
    queueMicrotask(() => this.emit(this.busy.has(port) ? 'error' : 'listening', { code: 'EADDRINUSE' }));
  }
}
test('default dashboard retries occupied ports without changing host', async () => {
  const server = new FakeServer(new Set([8080, 8081])); let completions = 0;
  await new Promise(resolve => listenDashboardRange(server, 8080, '127.0.0.1', () => { ++completions; resolve(); }));
  assert.deepEqual(server.attempts, [[8080, '127.0.0.1'], [8081, '127.0.0.1'], [8082, '127.0.0.1']]);
  assert.equal(completions, 1);
  assert.equal(server.listenerCount('error'), 0);
  assert.equal(server.listenerCount('listening'), 0);
});
test('exhausted range fails at 8090 and explicit ports do not move', async () => {
  for (const port of [8080, 9000]) {
    const server = new FakeServer(new Set(Array.from({ length: 11 }, (_, i) => 8080 + i).concat(9000)));
    await new Promise(resolve => listenDashboardRange(server, port, '127.0.0.1', null, resolve));
    assert.equal(server.attempts.length, port === 8080 ? 11 : 1);
    assert.equal(server.attempts.at(-1)[0], port === 8080 ? 8090 : 9000);
  }
});
