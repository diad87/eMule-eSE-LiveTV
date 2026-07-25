'use strict';

const fs = require('fs');
const net = require('net');

const [
  listenHost,
  listenPortText,
  targetHost,
  targetPortText,
  candidateToTargetPath,
  targetToCandidatePath,
  eventsPath,
] = process.argv.slice(2);

const listenPort = Number.parseInt(listenPortText, 10);
const targetPort = Number.parseInt(targetPortText, 10);
if (!listenHost || !targetHost || !Number.isInteger(listenPort) ||
    !Number.isInteger(targetPort) || !candidateToTargetPath ||
    !targetToCandidatePath || !eventsPath) {
  throw new Error(
    'usage: node tcp_capture_proxy.js listenHost listenPort targetHost ' +
    'targetPort candidateToTarget.bin targetToCandidate.bin events.jsonl'
  );
}

for (const path of [candidateToTargetPath, targetToCandidatePath, eventsPath]) {
  try {
    fs.unlinkSync(path);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

const candidateToTarget = fs.createWriteStream(candidateToTargetPath, { flags: 'a' });
const targetToCandidate = fs.createWriteStream(targetToCandidatePath, { flags: 'a' });
let connections = 0;
let candidateToTargetBytes = 0;
let targetToCandidateBytes = 0;

function event(value) {
  fs.appendFileSync(eventsPath, `${JSON.stringify({
    utc: new Date().toISOString(),
    ...value,
  })}\n`);
}

const server = net.createServer((candidate) => {
  const connection = ++connections;
  const target = net.createConnection({ host: targetHost, port: targetPort });
  candidate.setNoDelay(true);
  target.setNoDelay(true);
  event({ type: 'connect', connection });

  candidate.on('data', (chunk) => {
    candidateToTargetBytes += chunk.length;
    candidateToTarget.write(chunk);
    event({ type: 'data', connection, direction: 'candidate_to_target', bytes: chunk.length });
  });
  target.on('data', (chunk) => {
    targetToCandidateBytes += chunk.length;
    targetToCandidate.write(chunk);
    event({ type: 'data', connection, direction: 'target_to_candidate', bytes: chunk.length });
  });

  candidate.pipe(target);
  target.pipe(candidate);
  candidate.on('close', () => event({ type: 'close', connection, side: 'candidate' }));
  target.on('close', () => event({ type: 'close', connection, side: 'target' }));
  candidate.on('error', (error) => {
    event({ type: 'error', connection, side: 'candidate', message: error.message });
  });
  target.on('error', (error) => {
    event({ type: 'error', connection, side: 'target', message: error.message });
    candidate.destroy(error);
  });
});

server.on('error', (error) => {
  event({ type: 'server_error', message: error.message });
  process.exitCode = 1;
});
server.listen(listenPort, listenHost, () => {
  event({ type: 'start', listen_host: listenHost, listen_port: listenPort,
    target_host: targetHost, target_port: targetPort });
});

function finish(reason) {
  event({
    type: 'summary',
    reason,
    connections,
    candidate_to_target_bytes: candidateToTargetBytes,
    target_to_candidate_bytes: targetToCandidateBytes,
  });
  candidateToTarget.end();
  targetToCandidate.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}

process.on('SIGINT', () => finish('SIGINT'));
process.on('SIGTERM', () => finish('SIGTERM'));
