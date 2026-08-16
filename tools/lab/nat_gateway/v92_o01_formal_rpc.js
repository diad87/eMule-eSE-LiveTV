'use strict';

const readline = require('node:readline');

const REQUEST_SCHEMA = 'ese.v92.o01-formal-rpc-request/v1';
const RESPONSE_SCHEMA = 'ese.v92.o01-formal-rpc-response/v1';

function exactKeys(value, expected) {
  return value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function createFormalRpc(options) {
  if (!options || !options.input || !options.output ||
      typeof options.output.write !== 'function' || typeof options.input.on !== 'function') {
    throw new Error('O01_RPC_CONFIG_INVALID');
  }
  const lines = readline.createInterface({ input: options.input, crlfDelay: Infinity,
    terminal: false });
  const pending = new Map(); let nextSequence = 1; let closed = false; let poisoned = null;
  function poison(code) {
    if (poisoned) return;
    poisoned = new Error(code); closed = true;
    for (const entry of pending.values()) entry.reject(poisoned);
    pending.clear(); lines.close();
  }
  lines.on('line', (line) => {
    if (closed || Buffer.byteLength(line, 'utf8') > 65536) return poison('O01_RPC_RESPONSE_INVALID');
    let value; try { value = JSON.parse(line); } catch (_) { return poison('O01_RPC_RESPONSE_INVALID'); }
    if (!exactKeys(value, ['schema','sequence','ok','record']) || value.schema !== RESPONSE_SCHEMA ||
        !Number.isSafeInteger(value.sequence) || value.sequence < 1 || typeof value.ok !== 'boolean' ||
        (value.ok ? !exactKeys(value.record, ['line']) || typeof value.record.line !== 'string' ||
          Buffer.byteLength(value.record.line, 'utf8') > 65536 : value.record !== null)) {
      return poison('O01_RPC_RESPONSE_INVALID');
    }
    const entry = pending.get(value.sequence);
    if (!entry || value.sequence !== Math.min(...pending.keys())) return poison('O01_RPC_RESPONSE_ORDER');
    pending.delete(value.sequence);
    if (!value.ok) entry.reject(new Error('O01_RPC_REMOTE_FAILURE'));
    else entry.resolve(value.record.line);
  });
  lines.on('close', () => { if (!closed) poison('O01_RPC_CLOSED'); });
  function requestProduct() {
    if (closed || poisoned || pending.size !== 0) return Promise.reject(poisoned || new Error('O01_RPC_BUSY'));
    const sequence = nextSequence++;
    return new Promise((resolve, reject) => {
      pending.set(sequence, { resolve, reject });
      const body = `${JSON.stringify({ schema: REQUEST_SCHEMA, sequence, operation: 'product_next' })}\n`;
      options.output.write(body, 'utf8', (error) => { if (error) poison('O01_RPC_WRITE_FAILED'); });
    });
  }
  function close() { if (!closed) { closed = true; lines.close(); for (const entry of pending.values()) entry.reject(new Error('O01_RPC_CLOSED')); pending.clear(); } }
  return Object.freeze({ requestProduct, close });
}

module.exports = Object.freeze({ createFormalRpc, REQUEST_SCHEMA, RESPONSE_SCHEMA });
