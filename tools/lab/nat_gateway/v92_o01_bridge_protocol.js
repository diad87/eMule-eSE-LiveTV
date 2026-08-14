'use strict';

const crypto = require('node:crypto');
const { types } = require('node:util');

const FAULTS = new Set(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
const COMMANDS = new Set(['hello','observe','inject','shutdown']);
class O01ProtocolError extends Error { constructor(code) { super(code); this.name = 'O01ProtocolError'; this.reason_code = code; } }
function fail(code) { throw new O01ProtocolError(code); }
function plain(value) { return value && typeof value === 'object' && !Array.isArray(value) && !types.isProxy(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function exact(value, required, optional = []) {
  if (!plain(value) || Object.getOwnPropertySymbols(value).length) fail('O01_PROTOCOL_SHAPE');
  const keys = Object.keys(value); const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !Object.hasOwn(value, key)) || keys.some((key) => !allowed.has(key))) fail('O01_PROTOCOL_SHAPE');
  for (const key of keys) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail('O01_PROTOCOL_SHAPE'); }
  return value;
}
function uint(value, nonzero = false) { if (!Number.isSafeInteger(value) || value < (nonzero ? 1 : 0)) fail('O01_PROTOCOL_INTEGER'); return value; }
function parseLine(line) {
  if (typeof line !== 'string' || Buffer.byteLength(line, 'utf8') > 4096 || line.includes('\r') || line.includes('\n')) fail('O01_PROTOCOL_LINE');
  let value; try { value = JSON.parse(line); } catch (_) { fail('O01_PROTOCOL_JSON'); }
  exact(value, ['schema','sequence','command','arguments']);
  if (value.schema !== 'ese.v92.o01-control/v1' || !COMMANDS.has(value.command)) fail('O01_PROTOCOL_COMMAND');
  uint(value.sequence, true); exact(value.arguments, value.command === 'hello' ? ['token'] : value.command === 'inject' ? ['fault','planned_ordinal'] : []);
  if (value.command === 'hello' && (typeof value.arguments.token !== 'string' || !/^[a-f0-9]{64}$/.test(value.arguments.token))) fail('O01_PROTOCOL_TOKEN');
  if (value.command === 'inject' && (!FAULTS.has(value.arguments.fault) || uint(value.arguments.planned_ordinal, true) !== value.arguments.planned_ordinal)) fail('O01_PROTOCOL_FAULT');
  return Object.freeze({ ...value, arguments: Object.freeze({ ...value.arguments }) });
}
function tokenHash(token) { return crypto.createHash('sha256').update('ese.v92.o01-control-token/v1\0').update(token).digest('hex'); }
function validateObservation(value) {
  exact(value, ['gateway','product','resources','traffic']);
  exact(value.gateway, ['generation','epoch','mapping_count','pair_atomic','foreign_fixture_present','last_fault']);
  exact(value.product, ['topology_generation','tcp_state','udp_state','publisher_active','journal_entry_count']);
  exact(value.resources, ['gateway_rss_bytes','product_working_set_bytes','gateway_handles','product_handles','gateway_sockets','product_sockets','event_loop_lag_ms']);
  exact(value.traffic, ['pcp_requests','natpmp_requests','upnp_add_requests','upnp_get_requests','upnp_delete_requests','accepted_outcomes','rejected_outcomes','pcp_accepted','pcp_rejected','natpmp_accepted','natpmp_rejected','upnp_accepted','upnp_rejected','max_owned_mapping_count','final_owned_mapping_count','final_owned_pcp','final_owned_natpmp','final_owned_upnp']);
  for (const field of ['generation','epoch','mapping_count']) uint(value.gateway[field]);
  uint(value.product.topology_generation); uint(value.product.journal_entry_count);
  for (const field of Object.keys(value.resources)) uint(value.resources[field]);
  for (const field of Object.keys(value.traffic)) uint(value.traffic[field]);
  if (typeof value.gateway.pair_atomic !== 'boolean' || typeof value.gateway.foreign_fixture_present !== 'boolean' ||
      !FAULTS.has(value.gateway.last_fault) || !['DISABLED','DISCOVERING','CANDIDATE','VERIFIED','WITHDRAWN','FAILED'].includes(value.product.tcp_state) ||
      !['DISABLED','DISCOVERING','CANDIDATE','VERIFIED','WITHDRAWN','FAILED'].includes(value.product.udp_state) || typeof value.product.publisher_active !== 'boolean') fail('O01_PROTOCOL_OBSERVATION');
  return value;
}
function createSession(expectedTokenHash, adapter) {
  if (typeof expectedTokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(expectedTokenHash) || !plain(adapter) || typeof adapter.observe !== 'function' || typeof adapter.inject !== 'function' || typeof adapter.shutdown !== 'function') fail('O01_PROTOCOL_SESSION');
  let authenticated = false; let lastSequence = 0; let lastPlannedOrdinal = 0; let closed = false;
  return Object.freeze({ async dispatch(line) {
    if (closed) fail('O01_PROTOCOL_CLOSED'); const message = parseLine(line);
    if (message.sequence !== lastSequence + 1) fail('O01_PROTOCOL_SEQUENCE');
    if (!authenticated) {
      if (message.command !== 'hello' || tokenHash(message.arguments.token) !== expectedTokenHash) fail('O01_PROTOCOL_AUTH');
      authenticated = true; lastSequence = message.sequence;
      return { schema: 'ese.v92.o01-control-result/v1', sequence: message.sequence, ok: true, state: 'authenticated' };
    }
    if (message.command === 'hello') fail('O01_PROTOCOL_REAUTH');
    let observation;
    if (message.command === 'observe') observation = await adapter.observe();
    else if (message.command === 'inject') {
      if (message.arguments.planned_ordinal !== lastPlannedOrdinal + 1) fail('O01_PROTOCOL_ORDINAL');
      observation = await adapter.inject(message.arguments.fault); lastPlannedOrdinal = message.arguments.planned_ordinal;
    } else { observation = await adapter.shutdown(); closed = true; }
    validateObservation(observation);
    lastSequence = message.sequence;
    return { schema: 'ese.v92.o01-control-result/v1', sequence: message.sequence, ok: true,
      state: message.command === 'shutdown' ? 'closed' : 'ready', observation };
  } });
}
module.exports = { FAULTS, O01ProtocolError, parseLine, tokenHash, validateObservation, createSession };
