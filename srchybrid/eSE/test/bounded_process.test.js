'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { ProcessLimiter } = require('../bounded_process');

test('bounded process runner uses argument arrays and captures output', async () => {
  const limiter = new ProcessLimiter(1);
  const result = await limiter.run(
    process.execPath,
    ['-e', 'process.stdout.write(process.argv[1])', 'safe value; not a shell command'],
    { timeoutMs: 2000 });
  assert.equal(result.stdout, 'safe value; not a shell command');
  assert.deepEqual(limiter.stats(), { active: 0, queued: 0, limit: 1 });
});

test('bounded process runner enforces timeout and concurrency', async () => {
  const limiter = new ProcessLimiter(1);
  const first = limiter.run(process.execPath, ['-e', 'setTimeout(() => {}, 80)'], {
    timeoutMs: 1000
  });
  const second = limiter.run(process.execPath, ['-e', 'process.stdout.write("second")'], {
    timeoutMs: 1000
  });
  assert.deepEqual(limiter.stats(), { active: 1, queued: 1, limit: 1 });
  await first;
  assert.equal((await second).stdout, 'second');

  await assert.rejects(
    limiter.run(process.execPath, ['-e', 'setTimeout(() => {}, 5000)'], { timeoutMs: 30 }),
    error => error && error.code === 'ETIMEDOUT');
});
