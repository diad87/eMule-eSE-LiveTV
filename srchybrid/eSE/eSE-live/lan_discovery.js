// Decentralized Capa 2 — LAN discovery via UDP multicast.
//
// Simple eSE-specific protocol on the standard mDNS multicast group
// (224.0.0.251) but on a non-conflicting port (5354) so we don't fight
// with Windows Bonjour / Avahi. Payload is plain text, 100% backward
// compatible because no other code parses it.
//
// Announce every 30 s while we are broadcasting locally. Listen
// continuously; when we hear another peer's announce, POST it to the
// C++ /api/live/direct_join so the discovered stream gets dialed
// through the same throttled queue as Kad results.
//
// Pure P2P / decentralized: no servers, works without internet, instant
// discovery on home WiFi / office LAN / conference networks.

'use strict';
const dgram = require('dgram');
const os = require('os');
const http = require('http');

const MCAST_GROUP = '224.0.0.251';   // Standard mDNS group (any router lets it through on LAN)
const PORT = 5354;                    // Non-conflicting with Bonjour (5353)
const ANNOUNCE_INTERVAL_MS = 30 * 1000;
const STALE_AFTER_MS = 90 * 1000;    // Drop entries we haven't heard from in 90s

let socket = null;
let announceTimer = null;
let discoveredPeers = new Map(); // streamKey -> { ip, port, title, bitrate, lastSeen }

function start() {
  if (socket) return;
  socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

  socket.on('error', (err) => {
    console.log('[LAN] Socket error:', err.message);
    try { socket.close(); } catch (_) {}
    socket = null;
  });

  socket.on('message', (msg, rinfo) => {
    // Ignore messages from ourselves (own LAN IPs).
    if (isOwnIP(rinfo.address)) return;
    try {
      const payload = msg.toString('utf8');
      if (!payload.startsWith('eSE-LAN/1.0')) return;
      const entry = parseAnnounce(payload, rinfo.address);
      if (entry && entry.hash) {
        const wasNew = !discoveredPeers.has(entry.hash);
        entry.lastSeen = Date.now();
        discoveredPeers.set(entry.hash, entry);
        if (wasNew) {
          console.log(`[LAN] discovered ${entry.hash} from ${entry.ip}:${entry.port} title="${entry.title}"`);
          dialViaCpp(entry);
        }
      }
    } catch (e) {
      // Silently ignore malformed packets
    }
  });

  socket.bind(PORT, () => {
    try {
      socket.addMembership(MCAST_GROUP);
      socket.setMulticastTTL(1); // LAN only, never escape the subnet
      console.log(`[LAN] mDNS listener bound on ${MCAST_GROUP}:${PORT}`);
    } catch (e) {
      console.log('[LAN] addMembership failed:', e.message);
    }
  });

  announceTimer = setInterval(announce, ANNOUNCE_INTERVAL_MS);
  setTimeout(announce, 2000); // first announce 2 s after start

  // Prune stale peers periodically
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of discoveredPeers) {
      if (now - entry.lastSeen > STALE_AFTER_MS) {
        discoveredPeers.delete(key);
      }
    }
  }, 30 * 1000);
}

function stop() {
  if (announceTimer) { clearInterval(announceTimer); announceTimer = null; }
  if (socket) { try { socket.close(); } catch (_) {} socket = null; }
}

// Get list of currently-discovered LAN peers — used by /api/live/channels
// to merge into the channel grid.
function getDiscovered() {
  return Array.from(discoveredPeers.values());
}

function isOwnIP(addr) {
  const ifaces = os.networkInterfaces();
  for (const name in ifaces) {
    for (const iface of ifaces[name]) {
      if (iface.address === addr) return true;
    }
  }
  return false;
}

function parseAnnounce(payload, fallbackIp) {
  const lines = payload.split(/\r?\n/);
  const obj = { ip: fallbackIp };
  for (const line of lines) {
    const ix = line.indexOf(':');
    if (ix <= 0) continue;
    const k = line.substring(0, ix).trim().toLowerCase();
    const v = line.substring(ix + 1).trim();
    if (k === 'hash')    obj.hash = v;
    if (k === 'ip')      obj.ip = v;
    if (k === 'port')    obj.port = parseInt(v, 10);
    if (k === 'title')   obj.title = v;
    if (k === 'bitrate') obj.bitrate = parseInt(v, 10);
    if (k === 'category')obj.category = v;
    if (k === 'language')obj.language = v;
  }
  if (!obj.hash || !/^[a-fA-F0-9]{32}$/.test(obj.hash)) return null;
  if (!obj.port || obj.port <= 0 || obj.port > 65535) return null;
  return obj;
}

// Build + send a single announce packet describing our local broadcast.
// Pulls metadata from the C++ /api/live/channels endpoint.
function announce() {
  if (!socket) return;
  http.get('http://127.0.0.1:4711/api/live/channels', { timeout: 1500 }, (res) => {
    let body = '';
    res.on('data', c => body += c);
    res.on('end', () => {
      try {
        const json = JSON.parse(body);
        if (!json.channels || json.channels.length === 0) return;
        const ch = json.channels[0]; // own broadcast
        if (!ch.hash) return;

        // Get our preferred LAN IP (first private RFC1918 address).
        const myIp = preferredLanIp();
        if (!myIp) return;

        // Get the broadcaster TCP port from /api/live/preflight.
        http.get('http://127.0.0.1:4711/api/live/preflight', { timeout: 1500 }, (r2) => {
          let pfBody = '';
          r2.on('data', c => pfBody += c);
          r2.on('end', () => {
            try {
              const pf = JSON.parse(pfBody);
              const port = pf.port || 4662;
              const payload =
                'eSE-LAN/1.0\n' +
                'hash: '     + ch.hash + '\n' +
                'ip: '       + myIp + '\n' +
                'port: '     + port + '\n' +
                'title: '    + (ch.title || 'Live') + '\n' +
                'bitrate: '  + (ch.bitrate || 0) + '\n' +
                'category: ' + (ch.category || 'general') + '\n' +
                'language: ' + (ch.language || 'es') + '\n';
              const buf = Buffer.from(payload, 'utf8');
              socket.send(buf, 0, buf.length, PORT, MCAST_GROUP, (err) => {
                if (err) console.log('[LAN] announce send error:', err.message);
              });
            } catch (_) {}
          });
        }).on('error', () => {});
      } catch (_) {}
    });
  }).on('error', () => {});
}

function preferredLanIp() {
  const ifaces = os.networkInterfaces();
  // Prefer 192.168.x, then 10.x, then 172.16-31.x
  const candidates = { '192.168.': null, '10.': null, '172.': null };
  for (const name in ifaces) {
    for (const iface of ifaces[name]) {
      if (iface.family !== 'IPv4' || iface.internal) continue;
      const a = iface.address;
      if (a.startsWith('192.168.') && !candidates['192.168.']) candidates['192.168.'] = a;
      else if (a.startsWith('10.') && !candidates['10.']) candidates['10.'] = a;
      else if (a.startsWith('172.') && !candidates['172.']) {
        // Validate it's actually in 172.16-31
        const second = parseInt(a.split('.')[1], 10);
        if (second >= 16 && second <= 31) candidates['172.'] = a;
      }
    }
  }
  return candidates['192.168.'] || candidates['10.'] || candidates['172.'] || null;
}

// When a new LAN peer is heard, tell C++ to dial it via the existing
// throttled direct_join pipeline.
function dialViaCpp(entry) {
  const path = '/api/live/direct_join?key=' + encodeURIComponent(entry.hash) +
               '&ip=' + encodeURIComponent(entry.ip) +
               '&port=' + entry.port +
               '&title=' + encodeURIComponent(entry.title || 'LAN');
  const req = http.get('http://127.0.0.1:4711' + path, { timeout: 2000 }, (res) => {
    // Drain response; we don't care about content.
    res.on('data', () => {});
  });
  req.on('error', () => {});
  req.on('timeout', () => req.destroy());
}

module.exports = { start, stop, getDiscovered };
