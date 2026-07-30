'use strict';

const { spawn } = require('node:child_process');

const DEFAULT_TIMEOUT_MS = 10000;
const MAX_TIMEOUT_MS = 30000;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

function normalizeFile(file) {
  if (typeof file !== 'string' || file.length === 0 || file.includes('\0')) {
    throw new TypeError('process file must be a non-empty string without NUL');
  }
  return file;
}

function normalizeArgs(args) {
  if (!Array.isArray(args) || args.length > 256) {
    throw new TypeError('process args must be an array with at most 256 entries');
  }
  return args.map(arg => {
    const value = String(arg);
    if (value.includes('\0')) throw new TypeError('process args must not contain NUL');
    return value;
  });
}

function boundedInteger(value, fallback, minimum, maximum, label) {
  const selected = value === undefined ? fallback : value;
  if (!Number.isInteger(selected) || selected < minimum || selected > maximum) {
    throw new RangeError(`${label} must be an integer from ${minimum} to ${maximum}`);
  }
  return selected;
}

function spawnManaged(file, args = [], options = {}) {
  const detached = options.detached === undefined
    ? process.platform !== 'win32'
    : options.detached === true;
  const child = spawn(normalizeFile(file), normalizeArgs(args), {
    cwd: options.cwd,
    env: options.env,
    detached,
    windowsHide: true,
    shell: false,
    stdio: options.stdio || ['ignore', 'pipe', 'pipe'],
  });
  return child;
}

function terminateSpawned(child, signal = 'SIGKILL') {
  if (process.platform !== 'win32' && child.pid) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch (_) {
      // Fall back to the direct child when it is not a process-group leader.
    }
  }
  child.kill(signal);
}

function spawnDetached(file, args = [], options = {}) {
  return new Promise(resolve => {
    let child;
    try {
      child = spawnManaged(file, args, {
        cwd: options.cwd,
        env: options.env,
        detached: true,
        stdio: 'ignore',
      });
    } catch (error) {
      resolve({ ok: false, pid: null, error: error.message });
      return;
    }
    child.once('error', error => {
      resolve({ ok: false, pid: null, error: error.message });
    });
    child.once('spawn', () => {
      child.unref();
      resolve({ ok: true, pid: child.pid });
    });
  });
}

function runProcess(file, args = [], options = {}) {
  const timeoutMs = boundedInteger(
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS,
    1,
    MAX_TIMEOUT_MS,
    'timeoutMs',
  );
  const maxOutputBytes = boundedInteger(
    options.maxOutputBytes,
    DEFAULT_MAX_OUTPUT_BYTES,
    1,
    MAX_OUTPUT_BYTES,
    'maxOutputBytes',
  );
  const acceptedExitCodes = new Set(options.acceptedExitCodes || [0]);

  return new Promise(resolve => {
    let child;
    try {
      child = spawnManaged(file, args, options);
    } catch (error) {
      resolve({
        ok: false,
        exitCode: null,
        signal: null,
        stdout: '',
        stderr: '',
        timedOut: false,
        outputExceeded: false,
        error: error.message,
      });
      return;
    }

    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let timedOut = false;
    let outputExceeded = false;
    let spawnError = null;
    let settled = false;

    const append = (current, chunk) => {
      const remaining = maxOutputBytes - stdout.length - stderr.length;
      if (remaining <= 0) {
        outputExceeded = true;
        terminateSpawned(child);
        return current;
      }
      const data = Buffer.from(chunk);
      if (data.length > remaining) {
        outputExceeded = true;
        terminateSpawned(child);
        return Buffer.concat([current, data.subarray(0, remaining)]);
      }
      return Buffer.concat([current, data]);
    };

    if (child.stdout) child.stdout.on('data', chunk => { stdout = append(stdout, chunk); });
    if (child.stderr) child.stderr.on('data', chunk => { stderr = append(stderr, chunk); });
    child.on('error', error => { spawnError = error; });

    const timer = setTimeout(() => {
      timedOut = true;
      terminateSpawned(child);
    }, timeoutMs);
    timer.unref();

    child.on('close', (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const encoding = options.encoding || 'utf8';
      resolve({
        ok: !spawnError && !timedOut && !outputExceeded
          && acceptedExitCodes.has(exitCode),
        exitCode,
        signal,
        stdout: stdout.toString(encoding),
        stderr: stderr.toString(encoding),
        timedOut,
        outputExceeded,
        error: spawnError ? spawnError.message : null,
      });
    });
  });
}

async function killProcessTree(pid, options = {}) {
  if (!Number.isSafeInteger(pid) || pid <= 0) {
    return { ok: false, error: 'invalid pid' };
  }
  if (process.platform === 'win32') {
    return runProcess(
      'taskkill',
      ['/F', '/T', '/PID', String(pid)],
      { timeoutMs: options.timeoutMs || 3000, maxOutputBytes: 64 * 1024 },
    );
  }
  const timeoutMs = boundedInteger(
    options.timeoutMs,
    3000,
    1,
    MAX_TIMEOUT_MS,
    'timeoutMs',
  );
  const graceMs = Math.min(
    boundedInteger(options.graceMs, 500, 0, MAX_TIMEOUT_MS, 'graceMs'),
    timeoutMs,
  );
  const isAlive = () => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (error) {
      return error.code === 'EPERM';
    }
  };
  const waitUntilGone = async deadline => {
    while (isAlive() && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    return !isAlive();
  };
  const signalTree = signal => {
    try {
      process.kill(-pid, signal);
    } catch (groupError) {
      if (groupError.code !== 'ESRCH') throw groupError;
      process.kill(pid, signal);
    }
  };
  try {
    const deadline = Date.now() + timeoutMs;
    signalTree(options.signal || 'SIGTERM');
    if (await waitUntilGone(Math.min(deadline, Date.now() + graceMs))) {
      return { ok: true, exitCode: 0, signal: options.signal || 'SIGTERM', stdout: '', stderr: '' };
    }
    signalTree('SIGKILL');
    const gone = await waitUntilGone(deadline);
    return {
      ok: gone,
      exitCode: gone ? 0 : null,
      signal: 'SIGKILL',
      stdout: '',
      stderr: '',
      error: gone ? null : 'process tree did not exit before deadline',
    };
  } catch (error) {
    if (error.code === 'ESRCH') {
      return { ok: true, exitCode: 0, signal: null, stdout: '', stderr: '' };
    }
    return { ok: false, error: error.message };
  }
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  MAX_TIMEOUT_MS,
  DEFAULT_MAX_OUTPUT_BYTES,
  MAX_OUTPUT_BYTES,
  runProcess,
  spawnManaged,
  spawnDetached,
  killProcessTree,
};
