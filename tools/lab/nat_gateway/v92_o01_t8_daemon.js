'use strict';
const readline = require('node:readline');
const { createSession } = require('./v92_o01_bridge_protocol');

async function runDaemon(input, output, environment, adapter) {
  if (!environment || !/^[a-f0-9]{64}$/.test(environment.O01_CONTROL_TOKEN_SHA256 || '')) throw new Error('O01_DAEMON_TOKEN_HASH_REQUIRED');
  if (!['NON_RELEASE','FORMAL_T8'].includes(environment.O01_MODE)) throw new Error('O01_DAEMON_MODE_INVALID');
  if (environment.O01_MODE === 'FORMAL_T8' && process.versions.node.split('.')[0] !== '22') throw new Error('O01_DAEMON_NODE22_REQUIRED');
  const session = createSession(environment.O01_CONTROL_TOKEN_SHA256, adapter);
  const lines = readline.createInterface({ input, crlfDelay: Infinity, terminal: false });
  try {
    for await (const line of lines) {
      let result;
      try { result = await session.dispatch(line); }
      catch (error) { output.write(`${JSON.stringify({ schema: 'ese.v92.o01-control-result/v1', ok: false, reason_code: error.reason_code || 'O01_DAEMON_INTERNAL' })}\n`); throw error; }
      output.write(`${JSON.stringify(result)}\n`);
      if (result.state === 'closed') break;
    }
  } finally { lines.close(); }
}

if (require.main === module) {
  const { createT8NetworkAdapter } = require('./v92_o01_t8_network_adapter');
  let adapter;
  Promise.resolve().then(async () => {
    const formal=process.env.O01_MODE==='FORMAL_T8';
    const provenance=formal?{schema:'ese.v92.t8-bind/v1',adapter_address:process.env.O01_T8_BIND_ADDRESS,
      interface_id_digest:process.env.O01_T8_INTERFACE_SHA256,hyperv_switch_digest:process.env.O01_T8_SWITCH_SHA256,
      http_port:Number(process.env.O01_T8_HTTP_PORT)}:undefined;
    adapter = await createT8NetworkAdapter({ mode: process.env.O01_MODE, bindAddress: process.env.O01_T8_BIND_ADDRESS,
      allowedSources:[process.env.O01_T8_ALLOWED_SOURCE||process.env.O01_T8_BIND_ADDRESS],provenance,
      externalAddress:formal?process.env.O01_T8_EXTERNAL_ADDRESS:undefined });
    await runDaemon(process.stdin, process.stdout, process.env, adapter);
  }).catch(async (error) => {
    if (adapter && typeof adapter.shutdown === 'function') { try { await adapter.shutdown(); } catch (_) {} }
    process.stderr.write(`V92_O01_DAEMON_FAIL ${error.reason_code || error.message}\n`); process.exitCode = 1;
  });
}
module.exports = { runDaemon };
