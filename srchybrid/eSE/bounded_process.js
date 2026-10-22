'use strict';

const { spawn } = require('child_process');

class ProcessLimiter {
  constructor(maxConcurrent = 4) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
      throw new TypeError('maxConcurrent must be a positive integer');
    }
    this.maxConcurrent = maxConcurrent;
    this.active = 0;
    this.queue = [];
  }

  run(file, args = [], options = {}) {
    if (!file || !Array.isArray(args)) {
      return Promise.reject(new TypeError('file and an argument array are required'));
    }
    return new Promise((resolve, reject) => {
      this.queue.push({ file, args, options, resolve, reject });
      this._drain();
    });
  }

  stats() {
    return { active: this.active, queued: this.queue.length, limit: this.maxConcurrent };
  }

  _drain() {
    while (this.active < this.maxConcurrent && this.queue.length > 0) {
      const job = this.queue.shift();
      if (job.options.signal && job.options.signal.aborted) {
        const error = new Error('process cancelled before start');
        error.code = 'EABORT';
        job.reject(error);
        continue;
      }
      this.active++;
      this._start(job);
    }
  }

  _start(job) {
    const timeoutMs = Math.max(1, Math.min(Number(job.options.timeoutMs) || 15000, 120000));
    const maxOutputBytes = Math.max(
      1024, Math.min(Number(job.options.maxOutputBytes) || 2 * 1024 * 1024, 16 * 1024 * 1024));
    const child = spawn(job.file, job.args, {
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: job.options.cwd,
      env: job.options.env
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;

    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (job.options.signal) job.options.signal.removeEventListener('abort', onAbort);
      this.active--;
      if (error) job.reject(error);
      else job.resolve(result);
      this._drain();
    };

    const terminate = (code, message) => {
      const error = new Error(message);
      error.code = code;
      try { child.kill(); } catch (_) {}
      finish(error);
    };

    const append = (target, chunk, isStdout) => {
      const next = (isStdout ? stdoutBytes : stderrBytes) + chunk.length;
      if (next > maxOutputBytes) {
        terminate('EOUTPUTLIMIT', 'process output exceeded the configured limit');
        return;
      }
      if (isStdout) stdoutBytes = next;
      else stderrBytes = next;
      target.push(chunk);
    };

    child.stdout.on('data', chunk => append(stdout, chunk, true));
    child.stderr.on('data', chunk => append(stderr, chunk, false));
    child.once('error', error => finish(error));
    child.once('close', (code, signal) => {
      if (settled) return;
      const result = {
        code,
        signal,
        stdout: Buffer.concat(stdout).toString(job.options.encoding || 'utf8'),
        stderr: Buffer.concat(stderr).toString(job.options.encoding || 'utf8')
      };
      if (code === 0) finish(null, result);
      else {
        const error = new Error('process exited with code ' + code);
        error.code = 'EPROCESS';
        error.exitCode = code;
        error.stderr = result.stderr;
        finish(error);
      }
    });

    const onAbort = () => terminate('EABORT', 'process cancelled');
    if (job.options.signal) job.options.signal.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(
      () => terminate('ETIMEDOUT', 'process exceeded ' + timeoutMs + ' ms'),
      timeoutMs);
  }
}

const defaultLimiter = new ProcessLimiter(4);

function runFile(file, args, options) {
  return defaultLimiter.run(file, args, options);
}

module.exports = { ProcessLimiter, runFile, stats: () => defaultLimiter.stats() };
