// filepath: srchybrid/eSE/ai_oauth.js
/**
 * ai_oauth.js — Google OAuth2 for Gemini (no API key needed)
 *
 * Implements Authorization Code Flow with loopback redirect to localhost:8080.
 * The user clicks "Conectar con Google", approves in browser, and eSE stores
 * the access_token + refresh_token in settings.json.
 *
 * For OpenAI and Claude there is no OAuth — the user must provide an API key.
 * We provide direct links to their key pages to minimise friction.
 *
 * GOOGLE OAUTH CLIENT SETUP (one-time, free):
 *   1. Go to https://console.cloud.google.com/apis/credentials
 *   2. Create OAuth Client → Desktop app (or Web app with http://localhost:8080)
 *   3. Enable "Generative Language API" in your project
 *   4. Paste your client_id and client_secret in eSE Settings → IA
 *
 * The client_id/secret are stored in settings.json (local only, never sent anywhere
 * except Google's OAuth server). They are NOT secret for desktop-type OAuth clients.
 */
'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const url    = require('url');

// ─── GOOGLE OAUTH CONSTANTS ───────────────────────────────────────────────────

const GOOGLE_AUTH_URL    = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL   = 'https://oauth2.googleapis.com/token';
const GOOGLE_REVOKE_URL  = 'https://oauth2.googleapis.com/revoke';
const GEMINI_SCOPE       = 'https://www.googleapis.com/auth/generative-language';
const REDIRECT_PATH      = '/api/ai/oauth/callback';

// In-flight state: code_verifier + state token per pending login
const _pendingConnections = new Map(); // state → { codeVerifier, resolve, reject, timeout }

let _loadSettings = () => ({});
let _saveSettings = () => {};

function init(loadSettings, saveSettings) {
  _loadSettings = loadSettings;
  _saveSettings = saveSettings;
}

// ─── PUBLIC: build the Google consent URL ────────────────────────────────────

/**
 * Builds a Google OAuth2 authorization URL for Gemini.
 * Returns { authUrl, state } — the caller opens authUrl in the browser,
 * then polls /api/ai/oauth/status?state=... until resolved.
 *
 * @param {number} port  - eSE server port (for redirect_uri)
 * @returns {{ authUrl: string, state: string }}
 */
function buildGoogleAuthUrl(port) {
  const s     = _loadSettings();
  const id    = (s.googleClientId || '').trim();
  if (!id) throw new Error('google_client_id not configured. Add it in eSE Settings → IA.');

  const state        = crypto.randomBytes(12).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Store pending state
  const entry = { codeVerifier, resolved: false, result: null };
  _pendingConnections.set(state, entry);

  // Auto-cleanup after 10 minutes
  entry.timeout = setTimeout(() => {
    if (!entry.resolved) {
      entry.resolved = true;
      entry.result   = { error: 'OAuth timeout — the authorization window expired.' };
    }
    _pendingConnections.delete(state);
  }, 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id:             id,
    redirect_uri:          `http://localhost:${port}${REDIRECT_PATH}`,
    response_type:         'code',
    scope:                 GEMINI_SCOPE,
    access_type:           'offline',
    prompt:                'consent',
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256'
  });

  return { authUrl: GOOGLE_AUTH_URL + '?' + params.toString(), state };
}

// ─── PUBLIC: handle the OAuth callback redirect ───────────────────────────────

/**
 * Call this when the server receives GET /api/ai/oauth/callback.
 * Exchanges the code for tokens and saves them to settings.
 * Sends a user-facing HTML response.
 *
 * @param {URL}      reqUrl
 * @param {object}   res    - Node http.ServerResponse
 * @param {number}   port
 */
function handleCallback(reqUrl, res, port) {
  const code  = reqUrl.searchParams.get('code');
  const state = reqUrl.searchParams.get('state');
  const err   = reqUrl.searchParams.get('error');

  const entry = _pendingConnections.get(state);

  const sendPage = (ok, message) => {
    const color = ok ? '#2ecc71' : '#e74c3c';
    const icon  = ok ? '✔' : '✗';
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>eSE – Conectar IA</title>
<style>body{background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;gap:16px}
h2{font-size:28px;font-weight:800} p{color:#888;font-size:15px}
.icon{font-size:64px}</style></head><body>
<div class="icon" style="color:${color}">${icon}</div>
<h2 style="color:${color}">${ok ? 'Gemini conectado' : 'Error de conexión'}</h2>
<p>${message}</p>
<p style="font-size:12px;color:#444">Puedes cerrar esta pestaña y volver a eSE.</p>
<script>setTimeout(()=>window.close(),3000);</script>
</body></html>`);
  };

  if (err || !code || !entry) {
    const msg = err || (!entry ? 'Estado OAuth no reconocido' : 'Código no recibido');
    if (entry) { entry.resolved = true; entry.result = { error: msg }; }
    return sendPage(false, msg);
  }

  const s      = _loadSettings();
  const id     = (s.googleClientId  || '').trim();
  const secret = (s.googleClientSecret || '').trim();

  if (!id || !secret) {
    entry.resolved = true;
    entry.result   = { error: 'Client ID / Secret no configurados' };
    return sendPage(false, 'Configura googleClientId y googleClientSecret en Ajustes → IA.');
  }

  // Exchange authorization code → tokens
  _exchangeCode(code, entry.codeVerifier, id, secret, port, (exchangeErr, tokens) => {
    clearTimeout(entry.timeout);
    _pendingConnections.delete(state);

    if (exchangeErr) {
      entry.resolved = true;
      entry.result   = { error: exchangeErr.message };
      return sendPage(false, exchangeErr.message);
    }

    // Persist tokens (access_token may expire; refresh_token is permanent)
    const current = _loadSettings();
    current.aiProvider        = 'gemini';
    current.aiApiKey          = tokens.access_token;  // used by ai_assistant.js
    current.googleAccessToken = tokens.access_token;
    current.googleRefreshToken = tokens.refresh_token || current.googleRefreshToken;
    current.googleTokenExpiry  = Date.now() + ((tokens.expires_in || 3600) * 1000);
    current.aiEnhanceQuery    = current.aiEnhanceQuery !== false;
    current.aiRankResults     = current.aiRankResults  !== false;
    _saveSettings(current);

    entry.resolved = true;
    entry.result   = { ok: true };
    console.log('[AI OAuth] Google token saved. Provider set to gemini.');
    sendPage(true, 'Tu cuenta de Google está conectada a eSE. Gemini está activo.');
  });
}

// ─── PUBLIC: poll connection result (frontend polling) ───────────────────────

/**
 * Returns the current status for a pending OAuth state.
 * { pending: true }               — still waiting for user
 * { ok: true }                    — connected successfully
 * { error: '...' }                — failed
 */
function pollStatus(state) {
  const entry = _pendingConnections.get(state);
  if (!entry) {
    // Check if already resolved and cleaned up
    const s = _loadSettings();
    if (s.googleAccessToken) return { ok: true };
    return { error: 'Estado no encontrado' };
  }
  if (!entry.resolved) return { pending: true };
  return entry.result;
}

// ─── PUBLIC: revoke / disconnect Google ──────────────────────────────────────

function revokeGoogle(callback) {
  const s = _loadSettings();
  const token = s.googleAccessToken || s.googleRefreshToken;

  // Clear from settings regardless
  delete s.aiApiKey;
  delete s.googleAccessToken;
  delete s.googleRefreshToken;
  delete s.googleTokenExpiry;
  if (s.aiProvider === 'gemini') s.aiProvider = 'none';
  _saveSettings(s);

  if (!token) return callback(null, { ok: true });

  // Best-effort revoke at Google
  const revokeUrl = GOOGLE_REVOKE_URL + '?token=' + encodeURIComponent(token);
  https.get(revokeUrl, (res) => {
    res.resume();
    callback(null, { ok: true });
  }).on('error', () => callback(null, { ok: true })); // ignore errors
}

// ─── PUBLIC: refresh the access token if expired ─────────────────────────────

/**
 * Transparently refreshes the Google access token if it's within 5 minutes
 * of expiry. Updates settings.json with the new token.
 * No-op if not using Google OAuth or token is still valid.
 * @param {function} callback - (err)
 */
function maybeRefreshToken(callback) {
  const s = _loadSettings();
  if (s.aiProvider !== 'gemini' || !s.googleRefreshToken) return callback(null);

  const expiry = s.googleTokenExpiry || 0;
  const fiveMin = 5 * 60 * 1000;
  if (Date.now() < expiry - fiveMin) return callback(null); // still valid

  const id     = (s.googleClientId     || '').trim();
  const secret = (s.googleClientSecret || '').trim();
  if (!id || !secret) return callback(null);

  const body = new URLSearchParams({
    client_id:     id,
    client_secret: secret,
    refresh_token: s.googleRefreshToken,
    grant_type:    'refresh_token'
  }).toString();

  const options = {
    hostname: 'oauth2.googleapis.com',
    path:     '/token',
    method:   'POST',
    headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    timeout:  10000
  };

  let called = false;
  const done = (err, data) => { if (!called) { called = true; callback(err, data); } };

  const req = https.request(options, (res) => {
    const chunks = [];
    res.on('data', d => chunks.push(d));
    res.on('end', () => {
      try {
        const tokens = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (tokens.access_token) {
          s.aiApiKey          = tokens.access_token;
          s.googleAccessToken = tokens.access_token;
          s.googleTokenExpiry = Date.now() + ((tokens.expires_in || 3600) * 1000);
          _saveSettings(s);
          console.log('[AI OAuth] Access token refreshed.');
        }
        done(null);
      } catch (e) { done(null); } // non-fatal
    });
  });
  req.on('error', () => done(null));
  req.on('timeout', () => { req.destroy(); done(null); });
  req.write(body);
  req.end();
}

// ─── INTERNAL: exchange authorization code ───────────────────────────────────

function _exchangeCode(code, codeVerifier, clientId, clientSecret, port, callback) {
  const body = new URLSearchParams({
    code,
    client_id:     clientId,
    client_secret: clientSecret,
    redirect_uri:  `http://localhost:${port}${REDIRECT_PATH}`,
    grant_type:    'authorization_code',
    code_verifier: codeVerifier
  }).toString();

  const options = {
    hostname: 'oauth2.googleapis.com',
    path:     '/token',
    method:   'POST',
    headers:  { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    timeout:  15000
  };

  let called = false;
  const done = (err, data) => { if (!called) { called = true; callback(err, data); } };

  const req = https.request(options, (res) => {
    const chunks = [];
    res.on('data', d => chunks.push(d));
    res.on('end', () => {
      try {
        const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (data.error) return done(new Error(data.error_description || data.error));
        done(null, data);
      } catch (e) { done(new Error('Token parse error: ' + e.message)); }
    });
  });
  req.on('error', done);
  req.on('timeout', () => { req.destroy(); done(new Error('Token exchange timed out')); });
  req.write(body);
  req.end();
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────

module.exports = {
  init,
  buildGoogleAuthUrl,
  handleCallback,
  pollStatus,
  revokeGoogle,
  maybeRefreshToken,
  REDIRECT_PATH
};
