/**
 * eSE Live — WebSocket/TLS Tunnel
 * Wraps live stream protocol in WebSocket frames over TLS (port 443).
 * Makes P2P traffic look like normal HTTPS to bypass firewalls/ISP throttling.
 *
 * Hardened: ping/pong keepalive, frame reassembly, RFC 6455 close handling.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');

// Tunnel state
let tunnelServer = null;
let tunnelConnections = new Map(); // clientId -> { socket, lastPong, bytesIn, bytesOut, recvBuf }
let tunnelStatus = 'idle'; // idle | listening | error
let keepaliveTimer = null;

const PING_INTERVAL_MS = 30000;  // Send ping every 30s
const PONG_TIMEOUT_MS  = 90000;  // Kill connection if no pong in 90s

// v7.5.0 — frame/buffer hard caps. Prevents OOM via:
//   (a) attacker announcing payloadLen=2^53 (we reject before alloc)
//   (b) trickle-feed chunks growing recvBuf linearly (we reject before concat)
const MAX_FRAME_PAYLOAD = 1 * 1024 * 1024;   // 1 MB per frame
const MAX_RECV_BUFFER   = 4 * 1024 * 1024;   // 4 MB pending reassembly

// v7.5.0 — Origin allowlist for the WS upgrade. Without this any web page can
// open a WS to localhost:8443 and inject crafted frames.
function _wsOriginIsAllowed(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1') return true;
    return false;
  } catch { return false; }
}

/**
 * Start the WebSocket tunnel server.
 * Upgrades HTTP connections on a given port to WebSocket for P2P relay.
 *
 * @param {Object} opts
 * @param {number} [opts.port=8443] - Tunnel listen port
 * @param {Function} [opts.onConnection] - Callback when peer connects
 * @param {Function} [opts.onMessage] - Callback(clientId, opcode, data)
 * @returns {{success: boolean, error?: string}}
 */
function startServer(opts) {
  if (tunnelServer) {
    return { success: false, error: 'Tunnel already running' };
  }

  const port = opts.port || 8443;

  try {
    tunnelServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Service Available</h1></body></html>');
    });

    // Handle WebSocket upgrade
    tunnelServer.on('upgrade', (req, socket, head) => {
      if (req.url !== '/ese-live') {
        socket.destroy();
        return;
      }

      // v7.5.0 — reject upgrades from cross-origin pages. The Origin header
      // is set by browsers automatically and cannot be spoofed from JS, so
      // this catches the "any web page opens a WS to localhost" attack.
      // Native eSE peer-to-peer connections that aren't browsers can either
      // omit the header (we accept that case — non-browser) or set it to
      // a local value.
      const origin = req.headers.origin;
      if (origin && !_wsOriginIsAllowed(origin)) {
        socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
        socket.destroy();
        return;
      }

      const key = req.headers['sec-websocket-key'];
      if (!key) {
        socket.destroy();
        return;
      }

      const acceptKey = crypto
        .createHash('sha1')
        .update(key + '258EAFA5-E914-47DA-95CA-5AB5DA688355')
        .digest('base64');

      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        'Sec-WebSocket-Accept: ' + acceptKey + '\r\n' +
        '\r\n'
      );

      const clientId = crypto.randomBytes(8).toString('hex');
      tunnelConnections.set(clientId, {
        socket,
        lastPong: Date.now(),
        bytesIn: 0,
        bytesOut: 0,
        recvBuf: Buffer.alloc(0) // Frame reassembly buffer
      });

      console.log('[eSE Tunnel] Peer connected:', clientId);
      if (opts.onConnection) opts.onConnection(clientId);

      // Process any data from the upgrade head
      if (head && head.length > 0) {
        processIncoming(clientId, head, opts);
      }

      socket.on('data', (data) => {
        processIncoming(clientId, data, opts);
      });

      socket.on('close', () => {
        tunnelConnections.delete(clientId);
        console.log('[eSE Tunnel] Peer disconnected:', clientId);
      });

      socket.on('error', (err) => {
        console.warn('[eSE Tunnel] Peer socket error:', clientId, err.message);
        tunnelConnections.delete(clientId);
      });
    });

    tunnelServer.listen(port, () => {
      tunnelStatus = 'listening';
      console.log('[eSE Tunnel] WebSocket tunnel on port', port);
    });

    tunnelServer.on('error', (err) => {
      tunnelStatus = 'error';
      console.error('[eSE Tunnel] Error:', err.message);
    });

    // Start keepalive ping timer
    startKeepalive();

    return { success: true, port };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

/**
 * Stop the tunnel server.
 */
function stopServer() {
  stopKeepalive();

  if (tunnelServer) {
    for (const [id, conn] of tunnelConnections) {
      try {
        // Send close frame (opcode 0x8) before destroying
        const closeFrame = Buffer.from([0x88, 0x02, 0x03, 0xE8]); // 1000 = normal closure
        conn.socket.write(closeFrame);
        conn.socket.destroy();
      } catch (e) {}
    }
    tunnelConnections.clear();

    tunnelServer.close();
    tunnelServer = null;
    tunnelStatus = 'idle';
  }
  return { success: true };
}

/**
 * Send data to a specific peer through the tunnel.
 * @param {string} clientId
 * @param {Buffer} payload - Raw eSE Live protocol data
 */
function sendToPeer(clientId, payload) {
  const conn = tunnelConnections.get(clientId);
  if (!conn) return false;

  try {
    const frame = encodeWsFrame(0x02, payload); // 0x02 = binary
    conn.socket.write(frame);
    conn.bytesOut += payload.length;
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Broadcast data to all connected peers.
 * @param {Buffer} payload
 */
function broadcast(payload) {
  const frame = encodeWsFrame(0x02, payload); // 0x02 = binary
  for (const [id, conn] of tunnelConnections) {
    try {
      conn.socket.write(frame);
      conn.bytesOut += payload.length;
    } catch (e) {}
  }
}

/**
 * Get tunnel status.
 */
function getStatus() {
  return {
    status: tunnelStatus,
    connections: tunnelConnections.size,
    totalBytesIn: [...tunnelConnections.values()].reduce((s, c) => s + c.bytesIn, 0),
    totalBytesOut: [...tunnelConnections.values()].reduce((s, c) => s + c.bytesOut, 0)
  };
}

// --- Keepalive (ping/pong) ---

function startKeepalive() {
  if (keepaliveTimer) return;
  keepaliveTimer = setInterval(() => {
    const now = Date.now();
    for (const [id, conn] of tunnelConnections) {
      // Check for pong timeout
      if (now - conn.lastPong > PONG_TIMEOUT_MS) {
        console.log('[eSE Tunnel] Pong timeout for peer:', id);
        try { conn.socket.destroy(); } catch (e) {}
        tunnelConnections.delete(id);
        continue;
      }
      // Send ping
      try {
        const pingFrame = encodeWsFrame(0x09, Buffer.alloc(0)); // opcode 0x09 = ping
        conn.socket.write(pingFrame);
      } catch (e) {
        tunnelConnections.delete(id);
      }
    }
  }, PING_INTERVAL_MS);
}

function stopKeepalive() {
  if (keepaliveTimer) {
    clearInterval(keepaliveTimer);
    keepaliveTimer = null;
  }
}

// --- Frame reassembly & processing ---

/**
 * Append incoming TCP data to per-connection buffer and extract complete frames.
 * TCP can split a WebSocket frame across multiple data events,
 * or bundle multiple frames into one event.
 */
function processIncoming(clientId, chunk, opts) {
  const conn = tunnelConnections.get(clientId);
  if (!conn) return;

  // v7.5.0 — bound the reassembly buffer BEFORE the concat so a trickle-feed
  // attacker can't push us past MAX_RECV_BUFFER even momentarily. Previous
  // code allowed an unbounded grow and only checked AFTER concat, so a peer
  // announcing a 2GB frame could OOM the host while the concat ran.
  if (conn.recvBuf.length + chunk.length > MAX_RECV_BUFFER) {
    console.log('[eSE Tunnel] Buffer over hard cap, disconnecting peer:', clientId);
    try { conn.socket.destroy(); } catch (e) {}
    tunnelConnections.delete(clientId);
    return;
  }

  // Append new data to reassembly buffer
  conn.recvBuf = Buffer.concat([conn.recvBuf, chunk]);

  // Try to extract complete frames
  while (conn.recvBuf.length >= 2) {
    const frameInfo = peekFrameLength(conn.recvBuf);
    if (!frameInfo) break; // Not enough data for header
    if (frameInfo.totalLen < 0 || frameInfo.totalLen > MAX_FRAME_PAYLOAD + 14) {
      // Header announced a payload bigger than we'll ever accept — drop peer.
      console.log('[eSE Tunnel] Frame size over cap, disconnecting peer:', clientId);
      try { conn.socket.destroy(); } catch (e) {}
      tunnelConnections.delete(clientId);
      return;
    }

    if (conn.recvBuf.length < frameInfo.totalLen) break; // Incomplete frame

    // Extract the complete frame
    const frameData = conn.recvBuf.slice(0, frameInfo.totalLen);
    conn.recvBuf = conn.recvBuf.slice(frameInfo.totalLen);

    handleWsFrame(clientId, frameData, opts);
  }
}

/**
 * Peek at the buffer to determine the total frame length without consuming data.
 * Returns { totalLen } or null if not enough data for the header.
 */
function peekFrameLength(data) {
  if (data.length < 2) return null;

  let offset = 2;
  let payloadLen = data[1] & 0x7F;
  const masked = !!(data[1] & 0x80);

  if (payloadLen === 126) {
    if (data.length < 4) return null;
    payloadLen = data.readUInt16BE(2);
    offset = 4;
  } else if (payloadLen === 127) {
    if (data.length < 10) return null;
    // v7.5.0 — readBigUInt64BE can yield values up to 2^64; once cast to
    // Number anything > 2^53 loses precision and we end up trusting bogus
    // arithmetic in totalLen. Reject anything over the per-frame cap before
    // it can poison `offset + payloadLen`.
    const big = data.readBigUInt64BE(2);
    if (big > BigInt(MAX_FRAME_PAYLOAD)) {
      // Sentinel — caller treats negative as "too big" and drops the peer.
      return { totalLen: -1 };
    }
    payloadLen = Number(big);
    offset = 10;
  }

  if (masked) offset += 4;

  return { totalLen: offset + payloadLen };
}

// --- WebSocket frame handling ---

function handleWsFrame(clientId, rawData, opts) {
  const conn = tunnelConnections.get(clientId);
  if (!conn) return;

  try {
    if (rawData.length < 2) return;

    const opcode = rawData[0] & 0x0F;

    // Handle control frames (RFC 6455 §5.5)
    if (opcode === 0x08) {
      // Close frame — respond with close and disconnect
      try {
        const closeReply = encodeWsFrame(0x08, Buffer.alloc(0));
        conn.socket.write(closeReply);
        conn.socket.destroy();
      } catch (e) {}
      tunnelConnections.delete(clientId);
      console.log('[eSE Tunnel] Peer sent close:', clientId);
      return;
    }

    if (opcode === 0x09) {
      // Ping frame — respond with pong (same payload)
      const payload = decodeWsPayload(rawData);
      const pongFrame = encodeWsFrame(0x0A, payload || Buffer.alloc(0));
      try { conn.socket.write(pongFrame); } catch (e) {}
      conn.lastPong = Date.now();
      return;
    }

    if (opcode === 0x0A) {
      // Pong frame — update keepalive timestamp
      conn.lastPong = Date.now();
      return;
    }

    // Data frames (0x01 text, 0x02 binary)
    if (opcode === 0x01 || opcode === 0x02) {
      const payload = decodeWsPayload(rawData);
      if (!payload || payload.length < 1) return;

      conn.bytesIn += payload.length;
      conn.lastPong = Date.now(); // Any data counts as alive

      // The payload is a raw eSE Live protocol message
      // Format: [opcode 1 byte][data...]
      const eseOpcode = payload[0];
      const eseData = payload.slice(1);

      if (opts.onMessage) {
        opts.onMessage(clientId, eseOpcode, eseData);
      }
    }
  } catch (e) { console.warn('[eSE Tunnel] Frame handling error for peer:', clientId, e.message); }
}

/**
 * Encode a WebSocket frame with the given opcode and payload.
 * @param {number} opcode - 0x01=text, 0x02=binary, 0x08=close, 0x09=ping, 0x0A=pong
 * @param {Buffer} payload
 * @returns {Buffer}
 */
function encodeWsFrame(opcode, payload) {
  const len = payload.length;
  let header;

  if (len < 126) {
    header = Buffer.alloc(2);
    header[0] = 0x80 | opcode; // FIN + opcode
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }

  return Buffer.concat([header, payload]);
}

/**
 * Decode just the payload from a raw WebSocket frame buffer.
 * Handles masking if present.
 * @param {Buffer} data - Complete frame
 * @returns {Buffer|null}
 */
function decodeWsPayload(data) {
  if (data.length < 2) return null;

  let offset = 2;
  let payloadLen = data[1] & 0x7F;
  const masked = !!(data[1] & 0x80);

  if (payloadLen === 126) {
    if (data.length < 4) return null;
    payloadLen = data.readUInt16BE(2);
    offset = 4;
  } else if (payloadLen === 127) {
    if (data.length < 10) return null;
    payloadLen = Number(data.readBigUInt64BE(2));
    offset = 10;
  }

  let mask = null;
  if (masked) {
    if (data.length < offset + 4) return null;
    mask = data.slice(offset, offset + 4);
    offset += 4;
  }

  if (data.length < offset + payloadLen) return null;

  const payload = Buffer.alloc(payloadLen);
  data.copy(payload, 0, offset, offset + payloadLen);

  if (mask) {
    for (let i = 0; i < payloadLen; i++) {
      payload[i] ^= mask[i & 3];
    }
  }

  return payload;
}

module.exports = { startServer, stopServer, sendToPeer, broadcast, getStatus };
