'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createT8Child } = require('./v92_o01_t8_child');

const REQUIRED = [
  'O01_T8_BIND_ADDRESS', 'O01_T8_ALLOWED_SOURCE',
  'O01_T8_INTERFACE_SHA256', 'O01_T8_SWITCH_SHA256',
  'O01_T8_EXTERNAL_ADDRESS',
  'O01_T8_HTTP_PORT', 'O01_READY_PATH', 'O01_COMPLETE_PATH',
  'O01_RESULT_PATH',
];

function readConfig(environment) {
  if (process.versions.node.split('.')[0] !== '22' ||
      REQUIRED.some((name) => typeof environment[name] !== 'string' || environment[name].length === 0)) {
    throw new Error('O01_FORMAL_HOLD_CONFIG_INVALID');
  }
  const httpPort = Number(environment.O01_T8_HTTP_PORT);
  if (!Number.isInteger(httpPort) || environment.O01_T8_EXTERNAL_ADDRESS !== '88.11.22.4') throw new Error('O01_FORMAL_HOLD_CONFIG_INVALID');
  const files = ['O01_READY_PATH', 'O01_COMPLETE_PATH', 'O01_RESULT_PATH'].map((name) => path.resolve(environment[name]));
  if (new Set(files.map((item) => item.toLowerCase())).size !== files.length || files.some((item) => fs.existsSync(item))) {
    throw new Error('O01_FORMAL_HOLD_OUTPUT_INVALID');
  }
  return Object.freeze({
    child: Object.freeze({ mode: 'FORMAL_T8', bindAddress: environment.O01_T8_BIND_ADDRESS,
      allowedSource: environment.O01_T8_ALLOWED_SOURCE, interfaceSha256: environment.O01_T8_INTERFACE_SHA256,
      switchSha256: environment.O01_T8_SWITCH_SHA256, httpPort, externalAddress: environment.O01_T8_EXTERNAL_ADDRESS }),
    readyPath: files[0], completePath: files[1], resultPath: files[2],
  });
}

function writeExclusive(file, value) {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  const handle = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(handle, body, { encoding: 'utf8' }); fs.fsyncSync(handle); } finally { fs.closeSync(handle); }
}

async function waitForSignal(file, sessionDigest, timeoutMs = 300000) {
  const started = performance.now();
  while (performance.now() - started < timeoutMs) {
    if (fs.existsSync(file)) {
      let value; try { value=JSON.parse(fs.readFileSync(file,'utf8')); } catch (_) { throw new Error('O01_FORMAL_HOLD_SIGNAL_INVALID'); }
      if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).sort().join(',')!=='schema,session_id_digest'||
         value.schema!=='ese.v92.o01-t8-formal-complete/v1'||value.session_id_digest!==sessionDigest)throw new Error('O01_FORMAL_HOLD_SIGNAL_INVALID');
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('O01_FORMAL_HOLD_TIMEOUT');
}

async function main() {
  const config = readConfig(process.env); const child = createT8Child(config.child); let started = false;
  const sessionDigest=require('node:crypto').randomBytes(32).toString('hex');
  try {
    const hello = await child.start(); started = true;
    const initial = await child.observe();
    writeExclusive(config.readyPath, { schema: 'ese.v92.o01-t8-formal-ready/v1', state: hello.state,session_id_digest:sessionDigest,
      gateway_generation: initial.gateway.generation, foreign_fixture_present: initial.gateway.foreign_fixture_present });
    await waitForSignal(config.completePath,sessionDigest);
    const final = await child.observe();
    await child.shutdown();started=false;
    writeExclusive(config.resultPath, { schema: 'ese.v92.o01-t8-formal-smoke/v1', verdict: 'PASS',
      session_id_digest:sessionDigest,gateway_generation: final.gateway.generation, mapping_count: final.gateway.mapping_count,
      pair_atomic: final.gateway.pair_atomic, foreign_fixture_present: final.gateway.foreign_fixture_present,
      traffic: final.traffic });
  } finally { if (started) await child.shutdown(); }
}

if (require.main === module) main().catch((error) => { process.stderr.write(`V92_O01_FORMAL_HOLD_FAIL ${error.message}\n`); process.exitCode = 1; });
module.exports = Object.freeze({ readConfig, writeExclusive, waitForSignal });
