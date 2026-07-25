'use strict';

const fs = require('fs');
const net = require('net');

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

const args = Object.fromEntries(process.argv.slice(2).map((arg) => {
  const pos = arg.indexOf('=');
  return pos < 0 ? [arg, ''] : [arg.slice(0, pos), arg.slice(pos + 1)];
}));
const mode = args['--mode'];
const port = Number(args['--port']);
const out = args['--out'];
const timeoutMs = Number(args['--timeout-ms'] || 10000);
if (!['socks5', 'http', 'socks4'].includes(mode) ||
    !Number.isInteger(port) || port < 1 || port > 65535 || !out) {
  fail('Usage: node mock_proxy_capture.js --mode=socks5|http|socks4 --port=N --out=FILE [--timeout-ms=N]');
}

const startedAt = new Date().toISOString();
let completed = false;
let connections = 0;
let timer;

function writeResult(result, exitCode = 0) {
  if (completed) return;
  completed = true;
  clearTimeout(timer);
  const artifact = {
    schema: 'ese.v91.mock-proxy-capture/v1',
    mode,
    port,
    started_at_utc: startedAt,
    finished_at_utc: new Date().toISOString(),
    connections,
    ...result,
  };
  fs.writeFileSync(out, `${JSON.stringify(artifact, null, 2)}\n`, { encoding: 'utf8' });
  server.close(() => process.exit(exitCode));
  setTimeout(() => process.exit(exitCode), 250).unref();
}

const server = net.createServer((socket) => {
  connections += 1;
  const chunks = [];
  let repliedGreeting = false;
  socket.on('data', (chunk) => {
    chunks.push(chunk);
    const data = Buffer.concat(chunks);
    if (mode === 'socks5') {
      if (!repliedGreeting) {
        if (data.length < 2) return;
        const greetingLength = 2 + data[1];
        if (data.length < greetingLength) return;
        repliedGreeting = true;
        socket.write(Buffer.from([0x05, 0x00]));
        chunks.length = 0;
        return;
      }
      if (data.length < 4) return;
      const addressLength = data[3] === 0x04 ? 16 :
        data[3] === 0x01 ? 4 :
          data[3] === 0x03 && data.length >= 5 ? 1 + data[4] : 0;
      if (!addressLength || data.length < 4 + addressLength + 2) return;
      const requestLength = 4 + addressLength + 2;
      const request = data.subarray(0, requestLength);
      socket.write(Buffer.from([
        0x05, 0x00, 0x00, 0x04,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0,
      ]));
      writeResult({
        request_hex: request.toString('hex'),
        version: request[0],
        command: request[1],
        atyp: request[3],
        destination_hex: request.subarray(4, 4 + addressLength).toString('hex'),
        destination_port: request.readUInt16BE(4 + addressLength),
      });
      return;
    }

    if (mode === 'http') {
      const text = data.toString('latin1');
      if (!text.includes('\r\n\r\n')) return;
      socket.write('HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n');
      writeResult({
        request_text: text,
        request_line: text.split('\r\n', 1)[0],
      });
      return;
    }

    writeResult({
      unexpected_connection: true,
      request_hex: data.toString('hex'),
    }, 1);
  });
  socket.on('error', (error) => {
    if (!completed) writeResult({ socket_error: error.message }, 1);
  });
});

server.on('error', (error) => fail(`Mock proxy failed: ${error.message}`));
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`READY ${mode} 127.0.0.1:${port}\n`);
});

timer = setTimeout(() => {
  writeResult({
    timed_out: true,
    no_connection: connections === 0,
  }, mode === 'socks4' && connections === 0 ? 0 : 1);
}, timeoutMs);
