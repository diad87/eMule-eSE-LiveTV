'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');

const MIN_BYTES = 100;
const MAX_BYTES = 5 * 1024 * 1024;

function readUInt32LE(buffer, offset) {
  if (offset < 0 || offset + 4 > buffer.length) throw new Error('nodes.dat header is truncated');
  return buffer.readUInt32LE(offset);
}

function validateNodesDat(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error('nodes.dat must be a Buffer');
  if (buffer.length < MIN_BYTES || buffer.length > MAX_BYTES) {
    throw new Error('nodes.dat size is outside the accepted range');
  }

  let count = readUInt32LE(buffer, 0);
  let version = 0;
  let bootstrapEdition = 0;
  let headerBytes = 4;
  let recordBytes = 25;

  if (count === 0) {
    version = readUInt32LE(buffer, 4);
    if (version < 1 || version > 3) throw new Error('nodes.dat version is not supported');
    if (version === 3) {
      bootstrapEdition = readUInt32LE(buffer, 8);
      count = readUInt32LE(buffer, 12);
      headerBytes = 16;
      recordBytes = bootstrapEdition === 1 ? 25 : 34;
    } else {
      count = readUInt32LE(buffer, 8);
      headerBytes = 12;
      recordBytes = version >= 2 ? 34 : 25;
    }
  }

  if (count < 1 || count > 1000) throw new Error('nodes.dat contact count is invalid');
  const recordsEnd = headerBytes + count * recordBytes;
  if (recordsEnd > buffer.length) throw new Error('nodes.dat contact records are truncated');

  for (let offset = headerBytes; offset < recordsEnd; offset += recordBytes) {
    const ip = buffer.readUInt32LE(offset + 16);
    const udpPort = buffer.readUInt16LE(offset + 20);
    // A zero TCP port is valid for UDP-only Kad contacts; the UDP endpoint is
    // the bootstrap requirement enforced by eMule's own loader.
    if (ip === 0 || ip === 0xFFFFFFFF || udpPort === 0) {
      throw new Error('nodes.dat contains an invalid endpoint');
    }
  }

  // eSE may append its additive ESV6 trailer. Foreign or partial trailing data
  // is rejected so a hash-pinned bootstrap cannot smuggle an unknown format.
  if (recordsEnd !== buffer.length) {
    if (recordsEnd + 9 > buffer.length || readUInt32LE(buffer, recordsEnd) !== 0x36565345) {
      throw new Error('nodes.dat has an unknown trailer');
    }
    const trailerVersion = buffer.readUInt8(recordsEnd + 4);
    const ipv6Count = readUInt32LE(buffer, recordsEnd + 5);
    if (trailerVersion !== 1 || ipv6Count > 1000 || recordsEnd + 9 + ipv6Count * 32 !== buffer.length) {
      throw new Error('nodes.dat ESV6 trailer is invalid');
    }
  }

  return { version, bootstrapEdition, count, recordBytes };
}

function normalizeExpectedHash(value) {
  const hash = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error('ESE_NODES_DAT_SHA256 must contain 64 hexadecimal characters');
  return hash;
}

function verifyBuffer(buffer, expectedHash) {
  const metadata = validateNodesDat(buffer);
  const expected = Buffer.from(normalizeExpectedHash(expectedHash), 'hex');
  const actual = crypto.createHash('sha256').update(buffer).digest();
  if (!crypto.timingSafeEqual(actual, expected)) throw new Error('nodes.dat SHA-256 mismatch');
  return Object.assign(metadata, { sha256: actual.toString('hex') });
}

function configFromEnv(env) {
  const source = env || process.env;
  const rawUrl = String(source.ESE_NODES_DAT_URL || '').trim();
  const rawHash = String(source.ESE_NODES_DAT_SHA256 || '').trim();
  const rawDestination = String(source.ESE_NODES_DAT_DEST || '').trim();
  if (!rawUrl && !rawHash && !rawDestination) return null;
  if (!rawUrl || !rawHash || !rawDestination) {
    throw new Error('ESE_NODES_DAT_URL, ESE_NODES_DAT_SHA256 and ESE_NODES_DAT_DEST must be set together');
  }

  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('ESE_NODES_DAT_URL must be an HTTPS URL without embedded credentials');
  }
  if (!path.isAbsolute(rawDestination)) throw new Error('ESE_NODES_DAT_DEST must be an absolute path');
  return { url: parsed.toString(), sha256: normalizeExpectedHash(rawHash), destination: path.normalize(rawDestination) };
}

function downloadBuffer(url, httpsImpl) {
  const client = httpsImpl || https;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve(value);
    };
    const request = client.get(url, {
      timeout: 30000,
      headers: { 'User-Agent': 'eSE-LiveTV nodes.dat verifier' }
    }, response => {
      if (response.statusCode !== 200) {
        response.resume();
        finish(new Error('nodes.dat HTTP status ' + response.statusCode));
        return;
      }
      const chunks = [];
      let total = 0;
      response.on('data', chunk => {
        total += chunk.length;
        if (total > MAX_BYTES) {
          response.destroy();
          finish(new Error('nodes.dat exceeded the download limit'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => finish(null, Buffer.concat(chunks, total)));
      response.on('error', error => finish(error));
    });
    request.on('error', error => finish(error));
    request.on('timeout', function() {
      this.destroy();
      finish(new Error('nodes.dat download timed out'));
    });
  });
}

function installBuffer(buffer, destination, fsImpl) {
  const io = fsImpl || fs;
  const directory = path.dirname(destination);
  const temporary = destination + '.tmp-' + process.pid + '-' + Date.now();
  const backup = destination + '.bak';
  io.mkdirSync(directory, { recursive: true });
  io.writeFileSync(temporary, buffer, { mode: 0o600 });
  try {
    if (io.existsSync(destination)) io.copyFileSync(destination, backup);
    try {
      io.renameSync(temporary, destination);
    } catch (error) {
      if (!io.existsSync(destination)) throw error;
      const old = destination + '.old-' + process.pid;
      io.renameSync(destination, old);
      try {
        io.renameSync(temporary, destination);
        io.rmSync(old, { force: true });
      } catch (replaceError) {
        if (!io.existsSync(destination) && io.existsSync(old)) io.renameSync(old, destination);
        throw replaceError;
      }
    }
  } finally {
    if (io.existsSync(temporary)) io.rmSync(temporary, { force: true });
  }
}

async function startFromEnv(env, dependencies) {
  const config = configFromEnv(env);
  if (!config) return { status: 'disabled' };
  const deps = dependencies || {};
  const buffer = await downloadBuffer(config.url, deps.https);
  const metadata = verifyBuffer(buffer, config.sha256);
  installBuffer(buffer, config.destination, deps.fs);
  return { status: 'installed', destination: config.destination, metadata };
}

module.exports = {
  startFromEnv,
  configFromEnv,
  validateNodesDat,
  verifyBuffer,
  installBuffer,
  MIN_BYTES,
  MAX_BYTES
};
