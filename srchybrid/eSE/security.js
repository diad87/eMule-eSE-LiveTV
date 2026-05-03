'use strict';

const crypto = require('crypto');

let _ctx = {};
const buckets = new Map();

const SENSITIVE_KEY_RE = /(password|passwd|api[_-]?key|token|secret|client[_-]?secret|refresh|access[_-]?token|enc[_-]?key|chat[_-]?id)/i;
const REDACTED = '********';

function init(ctx) {
  _ctx = ctx || {};
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
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
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

// Localhost connections are trusted (user is on their own machine)
function isLocalRequest(req) {
  // If request comes through a reverse proxy (Cloudflare tunnel), it's NOT local
  if (req.headers['x-forwarded-for'] || req.headers['cf-connecting-ip']) return false;
  const addr = req.socket && req.socket.remoteAddress;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

function isSecureRequest(req) {
  return !!req.socket.encrypted || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
}

function cookieFor(req) {
  const parts = [
    'ese_access=' + encodeURIComponent(getAccessToken()),
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
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
    || pathname.startsWith('/api/stream/')
    || pathname.startsWith('/api/live/');
}

function isBootstrapPath(pathname) {
  return pathname === '/app'
    || pathname === '/connect'
    || pathname.startsWith('/pair/')
    || pathname === '/manifest.json'
    || pathname === '/emule_mascot.svg'
    || pathname === '/favicon.ico';
}

function clientKey(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || (req.socket && req.socket.remoteAddress) || 'unknown';
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
  const key = rule.name + ':' + clientKey(req);
  let bucket = buckets.get(key);
  if (!bucket || now >= bucket.resetAt) bucket = { count: 0, resetAt: now + rule.windowMs };
  bucket.count++;
  buckets.set(key, bucket);
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

// BUG-052 FIX: CORS origin whitelist instead of reflection
function isAllowedOrigin(origin) {
  if (!origin) return false;
  try {
    const u = new URL(origin);
    if (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '::1') return true;
    if (u.hostname.endsWith('.trycloudflare.com')) return true;
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
  isValidToken
};
