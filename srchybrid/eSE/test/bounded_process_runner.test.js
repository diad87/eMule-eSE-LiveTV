"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const runner = require("../bounded_process_runner");

const node = process.execPath;

test("bounded runner captures successful output without a shell", async () => {
  const result = await runner.runProcess(
    node,
    ["-e", "process.stdout.write('ok'); process.stderr.write('warn')"],
    { timeoutMs: 2000, maxOutputBytes: 1024 },
  );
  assert.equal(result.ok, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "ok");
  assert.equal(result.stderr, "warn");
  assert.equal(result.timedOut, false);
  assert.equal(result.outputExceeded, false);
});

test("bounded runner reports accepted and rejected exit codes", async () => {
  const rejected = await runner.runProcess(node, ["-e", "process.exit(7)"]);
  assert.equal(rejected.ok, false);
  assert.equal(rejected.exitCode, 7);

  const accepted = await runner.runProcess(
    node,
    ["-e", "process.exit(7)"],
    { acceptedExitCodes: [0, 7] },
  );
  assert.equal(accepted.ok, true);
  assert.equal(accepted.exitCode, 7);
});

test("bounded runner kills timeouts and oversized output", async () => {
  const timed = await runner.runProcess(
    node,
    ["-e", "setInterval(() => {}, 1000)"],
    { timeoutMs: 50, maxOutputBytes: 1024 },
  );
  assert.equal(timed.ok, false);
  assert.equal(timed.timedOut, true);

  const oversized = await runner.runProcess(
    node,
    ["-e", "process.stdout.write('x'.repeat(4096))"],
    { timeoutMs: 2000, maxOutputBytes: 128 },
  );
  assert.equal(oversized.ok, false);
  assert.equal(oversized.outputExceeded, true);
  assert.equal(Buffer.byteLength(oversized.stdout), 128);
});

test("bounded runner rejects hostile configuration before spawning", async () => {
  assert.throws(
    () => runner.runProcess(node, [], { timeoutMs: 30001 }),
    /timeoutMs/,
  );
  const hostileArg = await runner.runProcess(node, ["bad\0arg"]);
  assert.equal(hostileArg.ok, false);
  assert.match(hostileArg.error, /NUL/);
  assert.throws(() => runner.spawnManaged("", []), /non-empty/);
});
