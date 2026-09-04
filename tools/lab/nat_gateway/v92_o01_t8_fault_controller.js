'use strict';

const { createNatPmpFaultInjector } = require('./natpmp_fault_injector');

const NAMES = new Set(['renew_success','dropped_late','explicit_reject','expiry','epoch_reset','stale','replay_duplicate','malformed','partial_pair','final_boundary']);
const BOUNDARY_FAULTS = new Set(['expiry','epoch_reset']);

function isMappingPairMember(command) {
  return Boolean(command && command.operation === 'map' &&
    ['pcp','natpmp'].includes(command.protocol) && ['tcp','udp'].includes(command.transport));
}
function mappingKey(command, clientIdentity) {
  if (!isMappingPairMember(command)) return null;
  const identity = command.protocol === 'pcp' ? command.nonce : String(command.internal_port);
  return `${command.protocol}:${clientIdentity || 'none'}:${command.transport}:${command.internal_port}:${command.suggested_external_port}:${identity}`;
}
function validClientIdentity(value) { return typeof value === 'string' && value.length >= 1 && value.length <= 128; }

function createO01FaultController(dependencies = {}) {
  const sleep = dependencies.sleep || ((milliseconds, signal) => new Promise((resolve, reject) => {
    const id = setTimeout(resolve, milliseconds);
    signal.addEventListener('abort', () => { clearTimeout(id); reject(new Error('aborted')); }, { once: true });
  }));
  const defaultLateDelayMs = dependencies.lateDelayMs === undefined ? 101 : dependencies.lateDelayMs;
  if (!Number.isSafeInteger(defaultLateDelayMs) || defaultLateDelayMs < 1 || defaultLateDelayMs > 10000) {
    throw new Error('O01_FAULT_LATE_DELAY_INVALID');
  }

  let armed = null; let pendingFault = null; let boundaryClaim = null; let boundaryAudit = null; let lateWindow = null;
  const captured = new Map(); const pairKeys = new Map(); const stagedCaptures = new WeakMap();
  const pendingTcpCaptures = new Map(); const latestPairOrdinals = new Map();
  let wireOrdinal = 0; let lastPlannedOrdinal = 0;
  let lastExecutedOrdinal = 0; let lastExecutedName = 'renew_success'; let lastOutcome = 'none';
  let pairAttempted = 0; let pairCommitted = 0; let pairAborted = 0; let faultAttempted = 0;
  let recoveryAttempted = 0; let lastRecoveryOrdinal = 0; let lateEmitted = 0; let lateSuppressed = 0;
  let lastCandidateCommitted = false; let lastWireProtocol = 'none';
  let audit = { generation_before: 0, generation_after: 0, epoch_before: 0, epoch_after: 0,
    owned_before: 0, owned_after: 0, publisher_before: false, publisher_after: false,
    journal_before: 0, journal_after: 0 };

  const snapshotAudit = (before, after) => ({
    generation_before: before.gateway.generation, generation_after: after.gateway.generation,
    epoch_before: before.gateway.epoch, epoch_after: after.gateway.epoch,
    owned_before: before.traffic.final_owned_mapping_count, owned_after: after.traffic.final_owned_mapping_count,
    publisher_before: before.product.publisher_active, publisher_after: after.product.publisher_active,
    journal_before: before.product.journal_entry_count, journal_after: after.product.journal_entry_count,
  });
  const stageCapture = (decision, key, packet, command, clientIdentity) => {
    if (key) {
      const pairIdentity = `${command.protocol}:${clientIdentity || 'none'}`;
      let correlatedTcp = null;
      if (command.transport === 'tcp') {
        pendingTcpCaptures.delete(pairIdentity);
      } else {
        const pendingTcp = pendingTcpCaptures.get(pairIdentity);
        pendingTcpCaptures.delete(pairIdentity);
        if (pendingTcp && pendingTcp.ordinal < decision.ordinal &&
            (command.protocol !== 'pcp' || pendingTcp.identity === command.nonce)) correlatedTcp = pendingTcp;
      }
      latestPairOrdinals.set(pairIdentity, decision.ordinal);
      stagedCaptures.set(decision, Object.freeze({ key, packet: Buffer.from(packet), pair_identity: pairIdentity,
        transport: command.transport, protocol: command.protocol, ordinal: decision.ordinal,
        identity: command.protocol === 'pcp' ? command.nonce : String(command.internal_port), correlated_tcp: correlatedTcp }));
    }
    return decision;
  };
  const promoteCapture = (capture) => {
    captured.set(capture.key, Buffer.from(capture.packet));
    const correlated = Object.freeze(capture.correlated_tcp ?
      [capture.correlated_tcp.key, capture.key] : [capture.key]);
    for (const memberKey of correlated) pairKeys.set(memberKey, correlated);
  };
  const bindConsumedDecision = (decision, outcome) => {
    if (!pendingFault || pendingFault.decision || decision.fault !== pendingFault.fault.name ||
        decision.planned_ordinal !== pendingFault.fault.planned_ordinal ||
        !['committed','aborted','late_emitted'].includes(outcome)) {
      throw new Error('O01_FAULT_TRANSACTION_INVALID');
    }
    pendingFault.decision = decision; pendingFault.outcome = outcome;
    return decision;
  };

  return Object.freeze({
    arm(name, options = {}) {
      const planned = options.planned_ordinal || lastPlannedOrdinal + 1;
      const delayMs = options.delay_ms ?? options.deadline_ms ?? defaultLateDelayMs;
      if (armed || pendingFault || boundaryClaim || boundaryAudit || lateWindow || !NAMES.has(name) ||
          !Number.isSafeInteger(planned) || planned !== lastPlannedOrdinal + 1 ||
          !Number.isSafeInteger(delayMs) || delayMs < 1 || delayMs > 10000) {
        throw new Error('O01_FAULT_ARM_INVALID');
      }
      armed = { name, planned_ordinal: planned, delay_ms: delayMs, boundary_claimed: false };
      lastPlannedOrdinal = planned;
    },

    claimBoundary(command, clientIdentity) {
      if (!armed || !BOUNDARY_FAULTS.has(armed.name) || armed.boundary_claimed ||
          !isMappingPairMember(command) || command.transport !== 'tcp') return null;
      if (!validClientIdentity(clientIdentity)) throw new Error('O01_FAULT_BOUNDARY_INVALID');
      armed.boundary_claimed = true;
      const token = Object.freeze({ name: armed.name, planned_ordinal: armed.planned_ordinal,
        protocol: command.protocol, client_identity: clientIdentity });
      boundaryClaim = token;
      return token;
    },

    recordBoundary(token, before, after, pairWasCommitted) {
      if (!boundaryClaim || token !== boundaryClaim || boundaryAudit || !before || !after || pairWasCommitted !== false) {
        throw new Error('O01_FAULT_BOUNDARY_INVALID');
      }
      boundaryAudit = Object.freeze({ name: token.name, planned_ordinal: token.planned_ordinal,
        protocol: token.protocol, client_identity: token.client_identity,
        values: Object.freeze(snapshotAudit(before, after)) });
    },

    async apply(packet, command, signal, clientIdentity) {
      if (!Buffer.isBuffer(packet) || !(signal instanceof AbortSignal)) throw new Error('O01_FAULT_INPUT_INVALID');
      wireOrdinal += 1;
      const pairMember = isMappingPairMember(command);
      const key = mappingKey(command, clientIdentity);

      if (lateWindow && key && lateWindow.keys.has(key)) {
        if (!pendingFault || pendingFault.fault.planned_ordinal !== lateWindow.planned_ordinal) {
          throw new Error('O01_FAULT_TRANSACTION_INVALID');
        }
        pendingFault.late_suppressed += 1;
        return Object.freeze({ packets: Object.freeze([]), fault: 'dropped_late', ordinal: wireOrdinal,
          late: false, commit: false, consumed: false, planned_ordinal: lateWindow.planned_ordinal });
      }

      const boundaryMatches = Boolean(boundaryClaim && validClientIdentity(clientIdentity) &&
        boundaryClaim.protocol === command?.protocol && boundaryClaim.client_identity === clientIdentity);
      if (armed && BOUNDARY_FAULTS.has(armed.name) && pairMember && command.transport === 'udp' &&
          boundaryMatches && !boundaryAudit) {
        return Object.freeze({ packets: Object.freeze([]), fault: armed.name, ordinal: wireOrdinal,
          late: false, commit: false, consumed: false, planned_ordinal: armed.planned_ordinal });
      }

      const consume = Boolean(armed && pairMember && command.transport === 'udp' &&
        (!BOUNDARY_FAULTS.has(armed.name) || boundaryMatches && boundaryAudit));
      const fault = consume ? armed : null;
      const replay = fault?.name === 'replay_duplicate' && key ? captured.get(key) : null;
      if (fault?.name === 'replay_duplicate' && !replay) {
        const decision = Object.freeze({ packets: Object.freeze([Buffer.from(packet)]), fault: 'renew_success',
          ordinal: wireOrdinal, commit: true, consumed: false, planned_ordinal: lastExecutedOrdinal });
        return stageCapture(decision, key, packet, command, clientIdentity);
      }
      if (consume) {
        armed = null;
        pendingFault = { fault, protocol: command.protocol, decision: null, outcome: null,
          late_emitted: 0, late_suppressed: 0 };
      }
      if (!fault) {
        const decision = Object.freeze({ packets: Object.freeze([Buffer.from(packet)]), fault: 'renew_success',
          ordinal: wireOrdinal, commit: true, consumed: false, planned_ordinal: lastExecutedOrdinal });
        return stageCapture(decision, key, packet, command, clientIdentity);
      }

      try {
      if (fault.name === 'renew_success') {
        const decision = Object.freeze({ packets: Object.freeze([Buffer.from(packet)]), fault: fault.name,
          ordinal: wireOrdinal, commit: true, consumed: true, planned_ordinal: fault.planned_ordinal });
        return bindConsumedDecision(stageCapture(decision, key, packet, command, clientIdentity), 'committed');
      }
      if (BOUNDARY_FAULTS.has(fault.name)) {
        if (!boundaryAudit || boundaryAudit.planned_ordinal !== fault.planned_ordinal || boundaryAudit.name !== fault.name ||
            boundaryAudit.protocol !== command.protocol || boundaryAudit.client_identity !== clientIdentity) {
          throw new Error('O01_FAULT_BOUNDARY_MISSING');
        }
        return bindConsumedDecision(Object.freeze({ packets: Object.freeze([]), fault: fault.name, ordinal: wireOrdinal,
          commit: false, consumed: true, planned_ordinal: fault.planned_ordinal }), 'aborted');
      }
      if (fault.name === 'replay_duplicate') {
        return bindConsumedDecision(Object.freeze({ packets: Object.freeze([Buffer.from(replay), Buffer.from(replay)]),
          fault: fault.name, ordinal: wireOrdinal, commit: false, consumed: true,
          planned_ordinal: fault.planned_ordinal }), 'aborted');
      }
      if (fault.name === 'dropped_late') {
        const correlated = new Set([key]); for (const item of pairKeys.get(key) || []) correlated.add(item);
        const window = Object.freeze({ protocol: command.protocol, planned_ordinal: fault.planned_ordinal,
          keys: Object.freeze(correlated) });
        lateWindow = window;
        try {
          await sleep(fault.delay_ms, signal);
          pendingFault.late_emitted += 1;
          return bindConsumedDecision(Object.freeze({ packets: Object.freeze([Buffer.from(packet)]), fault: fault.name,
            ordinal: wireOrdinal, late: true, commit: false, consumed: true,
            planned_ordinal: fault.planned_ordinal }), 'late_emitted');
        } finally {
          if (lateWindow === window) lateWindow = null;
        }
      }
      if (command.protocol === 'natpmp') {
        const action = ['explicit_reject','stale'].includes(fault.name)
          ? { type: 'reject', result_code: 'not-authorized' }
          : fault.name === 'malformed' ? { type: 'truncate', length_bytes: 3 } : { type: 'drop' };
        const out = await createNatPmpFaultInjector(action, { sleep })(packet, command, signal);
        return bindConsumedDecision(Object.freeze({ packets: Object.freeze(out ? [Buffer.from(out)] : []), fault: fault.name,
          ordinal: wireOrdinal, late: false, commit: false, consumed: true,
          planned_ordinal: fault.planned_ordinal }), 'aborted');
      }
      if (['explicit_reject','stale'].includes(fault.name)) {
        const out = Buffer.from(packet); out[3] = 2; out.fill(0, 12, 24);
        return bindConsumedDecision(Object.freeze({ packets: Object.freeze([out]), fault: fault.name, ordinal: wireOrdinal,
          commit: false, consumed: true, planned_ordinal: fault.planned_ordinal }), 'aborted');
      }
      if (fault.name === 'malformed') {
        return bindConsumedDecision(Object.freeze({ packets: Object.freeze([Buffer.from(packet.subarray(0, 3))]), fault: fault.name,
          ordinal: wireOrdinal, commit: false, consumed: true, planned_ordinal: fault.planned_ordinal }), 'aborted');
      }
      return bindConsumedDecision(Object.freeze({ packets: Object.freeze([]), fault: fault.name, ordinal: wireOrdinal,
        late: false, commit: false, consumed: true, planned_ordinal: fault.planned_ordinal }), 'aborted');
      } catch (error) {
        if (pendingFault && pendingFault.fault === fault && !pendingFault.decision) {
          lateSuppressed += pendingFault.late_suppressed;
          armed = fault; pendingFault = null;
        }
        throw error;
      }
    },

    recordTransaction(decision, pairWasCommitted, before, after, protocol, pairMember) {
      if (!decision || typeof pairWasCommitted !== 'boolean' || typeof pairMember !== 'boolean' ||
          !['pcp','natpmp'].includes(protocol)) {
        throw new Error('O01_FAULT_TRANSACTION_INVALID');
      }
      const stagedCapture = stagedCaptures.get(decision);
      if (stagedCapture && stagedCapture.protocol !== protocol) throw new Error('O01_FAULT_TRANSACTION_INVALID');
      if (decision.consumed && (!pendingFault || pendingFault.decision !== decision ||
          pendingFault.protocol !== protocol || !pairMember)) throw new Error('O01_FAULT_TRANSACTION_INVALID');
      if (stagedCapture && !pairMember) throw new Error('O01_FAULT_TRANSACTION_INVALID');
      const completed = decision.consumed ? pendingFault : null;
      const nextAudit = decision.consumed
        ? boundaryAudit && boundaryAudit.planned_ordinal === decision.planned_ordinal
          ? { ...boundaryAudit.values } : snapshotAudit(before, after)
        : null;
      if (!pairMember) return;
      stagedCaptures.delete(decision);
      if (stagedCapture && stagedCapture.transport === 'tcp' && !pairWasCommitted &&
          latestPairOrdinals.get(stagedCapture.pair_identity) === stagedCapture.ordinal) {
        pendingTcpCaptures.set(stagedCapture.pair_identity, stagedCapture);
      }
      if (stagedCapture && stagedCapture.transport === 'udp' && pairWasCommitted) promoteCapture(stagedCapture);
      if (decision.consumed) {
        lastExecutedOrdinal = completed.fault.planned_ordinal;
        lastExecutedName = completed.fault.name; lastOutcome = completed.outcome;
        pairAttempted += 1; faultAttempted += 1; lastCandidateCommitted = pairWasCommitted;
        lastWireProtocol = completed.protocol;
        if (boundaryAudit && boundaryAudit.planned_ordinal === decision.planned_ordinal) {
          boundaryAudit = null; boundaryClaim = null;
        }
        audit = nextAudit; lateEmitted += completed.late_emitted; lateSuppressed += completed.late_suppressed;
        pendingFault = null;
      }
      if (decision.consumed && pairWasCommitted) {
        pairCommitted += 1; lastRecoveryOrdinal = decision.planned_ordinal;
      } else if (decision.consumed) {
        pairAborted += 1;
      } else if (pairWasCommitted && lastExecutedOrdinal > lastRecoveryOrdinal) {
        pairAttempted += 1; recoveryAttempted += 1; pairCommitted += 1;
        lastRecoveryOrdinal = lastExecutedOrdinal;
      }
    },

    state() {
      const projectedArmed = armed || pendingFault?.fault;
      return Object.freeze({ armed_fault_ordinal: projectedArmed ? projectedArmed.planned_ordinal : 0,
        armed_fault_name: projectedArmed ? projectedArmed.name : 'none', last_executed_fault_ordinal: lastExecutedOrdinal,
        last_executed_fault_name: lastExecutedName, last_executed_outcome: lastOutcome,
        last_fault_candidate_committed: lastCandidateCommitted, last_wire_protocol: lastWireProtocol,
        pair_transactions_attempted: pairAttempted, pair_transactions_committed: pairCommitted,
        pair_transactions_aborted: pairAborted, fault_transactions_attempted: faultAttempted,
        recovery_transactions_attempted: recoveryAttempted,
        last_recovery_transaction_ordinal: lastRecoveryOrdinal, late_packets_emitted: lateEmitted,
        late_packets_suppressed: lateSuppressed, ...audit });
    },
  });
}

module.exports = Object.freeze({ createO01FaultController });
