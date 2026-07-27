'use strict';

const crypto = require('crypto');
const net = require('net');

let _ctx = {};
const buckets = new Map();
const overflowBuckets = new Map();
let trustedProxies = new Set();
let rateChecks = 0;
let maxRateBuckets = 4096;

const RATE_PRUNE_EVERY = 64;

const SENSITIVE_KEY_RE = /(password|passwd|api[_-]?key|token|secret|client[_-]?secret|refresh|access[_-]?token|enc[_-]?key|chat[_-]?id)/i;
const REDACTED = '********';

function init(ctx) {
  _ctx = ctx || {};
  const configuredProxies = Object.prototype.hasOwnProperty.call(_ctx, 'trustedProxies')
    ? _ctx.trustedProxies
    : process.env.ESE_TRUST_PROXY;
  trustedProxies = new Set(parseTrustedProxies(configuredProxies));
  maxRateBuckets = Number.isInteger(_ctx.maxRateBuckets)
    ? Math.max(1, Math.min(_ctx.maxRateBuckets, 65536))
    : 4096;
}

function getAccessToken() {
  return _ctx.tunnel && _ctx.tunnel.CONFIG && _ctx.tunnel.CONFIG.accessToken
    ? String(_ctx.tunnel.CONFIG.accessToken)
    : '';
}

function isReady() {
  return getAccessToken().length >= 16;
}

function fixedTimeEqual(a, b) {
  if (!a || !b) return false;
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function parseCookies(req) {
  // Object.create(null): cookie names become object keys — a null prototype
  // keeps hostile names like __proto__/constructor from touching Object.prototype.
  const out = Object.create(null);
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const name = part.slice(0, idx).trim();
      // Only accept RFC6265 token cookie names as keys (CodeQL js/remote-property-injection):
      // keeps a hostile property name out of the map. Object.create(null) above also blocks
      // any prototype pollution.
      if (/^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/.test(name)) {
        try {
          out[name] = decodeURIComponent(part.slice(idx + 1).trim());
        } catch (_) {
          // A malformed percent escape is an invalid cookie value, not a server
          // exception. Ignore only that cookie so authentication fails closed.
        }
      }
    }
  });
  return out;
}

function getPresentedToken(url, req) {
  const auth = req.headers.authorization || '';
  if (/^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
  if (req.headers['x-ese-token']) return String(req.headers['x-ese-token']).trim();
  if (url.searchParams.get('a')) return String(url.searchParams.get('a')).trim();
  return parseCookies(req).ese_access || '';
}

function isValidToken(url, req) {
  return fixedTimeEqual(getPresentedToken(url, req), getAccessToken());
}

// v7.5.0 — DNS-rebinding defense. A request is treated as "local" only when:
//   (a) The TCP peer address is loopback (127.0.0.1 / ::1), AND
//   (b) The HTTP Host header is loopback or numeric IP (NOT a hostname).
//
// Without (b), an attacker can DNS-rebind `attacker.com` → 127.0.0.1, get the
// victim's browser to send a request whose socket.remoteAddress IS loopback,
// and the original ListenSocket->WebServer chain treats it as trusted. The
// browser still attaches `Host: attacker.com`, so we use that as the second
// signal. We accept hostnames `localhost`, `127.0.0.1`, `[::1]`, and any
// RFC1918 address the local box owns (so LAN access from a phone with a
// real `Host: 192.168.1.50:8080` works).
function _hostIsLocal(hostHeader) {
  if (!hostHeader) return false;
  // strip port
  let h = String(hostHeader);
  if (h.startsWith('[')) {
    // IPv6 literal: "[::1]:8080"
    const end = h.indexOf(']');
    if (end < 0) return false;
    h = h.slice(1, end);
    return h === '::1' || h.toLowerCase() === '::1';
  }
  const colon = h.lastIndexOf(':');
  if (colon > 0) h = h.slice(0, colon);
  h = h.toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true;
  // RFC1918 / link-local — own LAN, real numeric IPs only (not arbitrary hostnames)
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  // Tailscale (CGNAT 100.64.0.0/10) — 100.64.x.x .. 100.127.x.x
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

function _expectedRequestOrigin(req) {
  const host = String(req.headers.host || '').trim();
  if (!host) return '';
  try {
    const protocol = isSecureRequest(req) ? 'https:' : 'http:';
    return new URL(protocol + '//' + host).origin;
  } catch (_) {
    return '';
  }
}

function _originMatchesRequest(req, value) {
  if (!value || value === 'null') return false;
  const expected = _expectedRequestOrigin(req);
  if (!expected) return false;
  try {
    return new URL(String(value)).origin === expected;
  } catch (_) {
    return false;
  }
}

// Browsers can reach a loopback HTTP service from an unrelated web page. CORS
// controls whether that page can read the response; it does not stop the
// request itself. Fetch Metadata is checked as well as Origin/Referer so
// subresource requests such as <img src=http://127.0.0.1:8080/api/...> are
// rejected before localhost trust or route dispatch.
function isCrossSiteBrowserRequest(req) {
  const fetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') return true;

  const origin = req.headers.origin;
  if (origin) return !_originMatchesRequest(req, origin);

  const referer = req.headers.referer;
  if (referer) return !_originMatchesRequest(req, referer);

  // Native clients and address-bar requests do not send browser provenance
  // headers. They remain eligible for the existing loopback-only trust path.
  return false;
}

function isLocalRequest(req) {
  if (req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip']) return false;
  if (isCrossSiteBrowserRequest(req)) return false;
  const addr = req.socket && req.socket.remoteAddress;
  const peerIsLoopback = addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
  if (!peerIsLoopback) return false;
  // v7.5.0 — Host header MUST match a known local name to block DNS-rebinding.
  return _hostIsLocal(req.headers.host);
}

function isSecureRequest(req) {
  return !!req.socket.encrypted
    || (isTrustedProxy(req) && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
}

function cookieFor(req) {
  // v7.5.0 — SameSite=Strict (was Lax). With Lax, top-level navigations from
  // a third-party site (e.g. attacker links to http://127.0.0.1:8080/api/...
  // via window.open) attach the cookie. Strict blocks that entirely; the only
  // way to acquire the cookie is the /api/auth/session flow, which itself
  // requires the access token. Genuine bookmarks from the same origin still
  // get the cookie attached.
  const parts = [
    'ese_access=' + encodeURIComponent(getAccessToken()),
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=2592000'
  ];
  if (isSecureRequest(req)) parts.push('Secure');
  return parts.join('; ');
}

function cleanUrl(url) {
  const clone = new URL(url.toString());
  clone.searchParams.delete('a');
  return clone.pathname + (clone.search ? clone.search : '');
}

function isProtectedPath(pathname) {
  return pathname.startsWith('/api/')
    || pathname.startsWith('/hls/')
    || pathname === '/hls-local'
    || pathname.startsWith('/hls-local/')
    || pathname.startsWith('/api/stream/')
    || pathname.startsWith('/api/live/')
    || pathname === '/app'
    || pathname === '/connect'
    || pathname.startsWith('/pair/')
    || pathname === '/manifest.json'
    || pathname === '/go'
    || pathname.startsWith('/go/')
    || pathname === '/remote'
    || pathname === '/qr';
}

function isBootstrapPath(pathname) {
  return pathname === '/emule_mascot.svg'
    || pathname === '/favicon.ico';
}

function expandIpv6(address) {
  let value = String(address || '').toLowerCase().split('%')[0];
  if (net.isIP(value) !== 6) return null;

  // Convert an embedded IPv4 tail (for example ::ffff:192.0.2.1) into two
  // hextets before expanding the compressed IPv6 notation.
  const ipv4Tail = value.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (ipv4Tail) {
    const octets = ipv4Tail[1].split('.').map(Number);
    value = value.slice(0, -ipv4Tail[1].length)
      + ((octets[0] << 8) | octets[1]).toString(16)
      + ':' + ((octets[2] << 8) | octets[3]).toString(16);
  }

  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const full = left.concat(new Array(missing).fill('0'), right);
  if (full.length !== 8 || full.some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return full.map(part => parseInt(part, 16).toString(16));
}

function normalizeIp(value) {
  let address = String(value || '').trim();
  if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1);
  address = address.split('%')[0];

  const mapped = address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped && net.isIP(mapped[1]) === 4) address = mapped[1];

  const family = net.isIP(address);
  if (family === 4) return address.split('.').map(part => String(Number(part))).join('.');
  if (family === 6) {
    const full = expandIpv6(address);
    return full ? full.join(':') : '';
  }
  return '';
}

function rateIdentity(address) {
  const normalized = normalizeIp(address);
  if (!normalized) return 'unknown';
  if (normalized.includes(':')) return normalized.split(':').slice(0, 4).join(':') + '::/64';
  return normalized;
}

function parseTrustedProxies(value) {
  const items = Array.isArray(value) ? value : String(value || '').split(',');
  return items.map(normalizeIp).filter(Boolean);
}

function directPeer(req) {
  return normalizeIp(req.socket && req.socket.remoteAddress);
}

function isTrustedProxy(req) {
  const direct = directPeer(req);
  return !!direct && trustedProxies.has(direct);
}

function parseForwardedChain(req) {
  const raw = String(req.headers['x-forwarded-for'] || '');
  if (!raw || raw.length > 1024) return null;
  const parts = raw.split(',');
  if (parts.length > 16) return null;
  const normalized = parts.map(normalizeIp);
  return normalized.every(Boolean) ? normalized : null;
}

function clientKey(req) {
  const direct = directPeer(req);
  if (!direct || !trustedProxies.has(direct)) return rateIdentity(direct);

  const chain = parseForwardedChain(req);
  if (!chain || chain.length === 0) return rateIdentity(direct);

  // Walk from the socket towards the original client. We only advance while
  // the current hop is explicitly trusted, so an attacker-controlled value at
  // the left of X-Forwarded-For cannot override the nearest untrusted address.
  let current = direct;
  for (let i = chain.length - 1; i >= 0 && trustedProxies.has(current); i--) current = chain[i];
  return rateIdentity(current);
}

function rateRule(pathname) {
  if (pathname === '/connect' || pathname.startsWith('/pair/')) return { name: 'pair', limit: 20, windowMs: 10 * 60 * 1000 };
  if (pathname === '/api/emule/login') return { name: 'login', limit: 10, windowMs: 5 * 60 * 1000 };
  if (pathname === '/api/emule/search' || pathname === '/api/emule/smartsearch') return { name: 'search', limit: 40, windowMs: 60 * 1000 };
  if (pathname === '/api/emule/download' || pathname === '/api/emule/ed2klink') return { name: 'download', limit: 40, windowMs: 60 * 1000 };
  if (pathname === '/api/tunnel/start' || pathname === '/api/tunnel/stop') return { name: 'tunnel', limit: 6, windowMs: 5 * 60 * 1000 };
  if (pathname.startsWith('/api/ai/oauth')) return { name: 'oauth', limit: 20, windowMs: 10 * 60 * 1000 };
  return null;
}

function checkRate(url, req, res) {
  const rule = rateRule(url.pathname);
  if (!rule) return true;
  const now = Date.now();
  rateChecks++;
  if ((rateChecks % RATE_PRUNE_EVERY) === 0) {
    for (const [bucketKey, value] of buckets) {
      if (now >= value.resetAt) buckets.delete(bucketKey);
    }
  }

  const key = rule.name + ':' + clientKey(req);
  let bucket = buckets.get(key);
  let isOverflow = false;
  if (!bucket && buckets.size >= maxRateBuckets) {
    isOverflow = true;
    bucket = overflowBuckets.get(rule.name);
  }
  if (!bucket || now >= bucket.resetAt) bucket = { count: 0, resetAt: now + rule.windowMs };
  bucket.count++;
  if (isOverflow) overflowBuckets.set(rule.name, bucket);
  else buckets.set(key, bucket);
  if (bucket.count <= rule.limit) return true;

  res.writeHead(429, {
    'Content-Type': 'application/json',
    'Retry-After': Math.ceil((bucket.resetAt - now) / 1000)
  });
  res.end(JSON.stringify({ error: 'rate_limited' }));
  return false;
}

function sendUnauthorized(res) {
  res.writeHead(401, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify({ error: 'unauthorized' }));
}

function sendCrossSiteDenied(res) {
  res.writeHead(403, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify({ error: 'cross_site_request_denied' }));
}

// BUG-052 FIX: CORS origin whitelist instead of reflection.
// v7.4.0: trycloudflare.com entry removed (Cloudflare Quick Tunnel gone).
function isAllowedOrigin(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1') return true;
    return false;
  } catch { return false; }
}

function getSafeOrigin(req) {
  const origin = req.headers.origin;
  return isAllowedOrigin(origin) ? origin : '';
}

function handleCorsPreflight(req, res) {
  if (req.method !== 'OPTIONS') return false;
  const safeOrigin = getSafeOrigin(req);
  res.writeHead(204, {
    'Access-Control-Allow-Origin': safeOrigin,
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Headers': 'Authorization, X-ESE-Token, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Max-Age': '600'
  });
  res.end();
  return true;
}

function apply(url, req, res) {
  if (handleCorsPreflight(req, res)) return false;

  if (!checkRate(url, req, res)) return false;

  if (isProtectedPath(url.pathname) && isCrossSiteBrowserRequest(req)) {
    sendCrossSiteDenied(res);
    return false;
  }

  if (url.pathname === '/api/auth/session') {
    if (!isValidToken(url, req)) {
      sendUnauthorized(res);
      return false;
    }
    const safeOrigin = getSafeOrigin(req); // BUG-052 FIX
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': cookieFor(req),
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': safeOrigin,
      'Access-Control-Allow-Credentials': 'true'
    });
    res.end(JSON.stringify({ ok: true }));
    return false;
  }

  if (url.searchParams.get('a') && isValidToken(url, req) && req.method === 'GET' && !isProtectedPath(url.pathname)) {
    res.writeHead(302, {
      'Location': cleanUrl(url),
      'Set-Cookie': cookieFor(req),
      'Cache-Control': 'no-store'
    });
    res.end();
    return false;
  }

  if (url.searchParams.get('a') && isValidToken(url, req)) {
    res.setHeader('Set-Cookie', cookieFor(req));
  }

  if (!isProtectedPath(url.pathname) || isBootstrapPath(url.pathname)) return true;

  // Localhost is always trusted — no token needed (zero-setup for local users)
  if (isLocalRequest(req)) return true;

  if (!isReady() || !isValidToken(url, req)) {
    sendUnauthorized(res);
    return false;
  }
  return true;
}

function isSensitiveKey(key) {
  return SENSITIVE_KEY_RE.test(String(key || ''));
}

function redactSettings(value) {
  if (Array.isArray(value)) return value.map(redactSettings);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  Object.keys(value).forEach(key => {
    const val = value[key];
    if (isSensitiveKey(key)) out[key] = val ? REDACTED : '';
    else out[key] = redactSettings(val);
  });
  return out;
}

function mergeSettings(current, incoming) {
  const target = current && typeof current === 'object' ? current : {};
  if (!incoming || typeof incoming !== 'object') return target;
  Object.keys(incoming).forEach(key => {
    // Prototype-pollution guard: a JSON body like {"__proto__":{...}} must not
    // let the recursive merge write through to Object.prototype.
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
    const val = incoming[key];
    if (isSensitiveKey(key) && (val === REDACTED || val === '' || val === null || typeof val === 'undefined')) return;
    if (val && typeof val === 'object' && !Array.isArray(val) && target[key] && typeof target[key] === 'object' && !Array.isArray(target[key])) {
      mergeSettings(target[key], val);
    } else {
      target[key] = val;
    }
  });
  return target;
}

module.exports = {
  init,
  apply,
  isReady,
  redactSettings,
  mergeSettings,
  isValidToken,
  // v7.5.0 — exported for unit tests and any caller that needs the DNS-rebinding-aware check.
  isLocalRequest,
  isCrossSiteBrowserRequest,
  _hostIsLocal,
  _test: {
    clientKey,
    isProtectedPath,
    checkRate,
    bucketCount: () => buckets.size,
    overflowBucketCount: () => overflowBuckets.size,
    resetRateState: () => {
      buckets.clear();
      overflowBuckets.clear();
      rateChecks = 0;
    }
  }
};
