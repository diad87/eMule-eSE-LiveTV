/**
 * eSE Live — Cloudflare Tunnel wrapper (REMOVED in v7.4.0)
 *
 * This module previously spawned `cloudflared.exe` to publish a
 * `https://<random>.trycloudflare.com` URL exposing the local HLS server.
 *
 * REMOVED for two reasons:
 *   1. Cloudflare AUP explicitly prohibits "tunnels that repackage P2P
 *      file-sharing networks". Sustained use carried a real ban risk and
 *      we never had a path to legitimately address that.
 *   2. The project's "100% gratis, sin dominios" invariant: we depend on
 *      zero third-party domains for the actual data path. Discovery is
 *      handled by UPnP + ntfy.sh (heartbeat only, no payload); the data
 *      goes peer-to-peer.
 *
 * If you need cross-NAT live broadcast and UPnP is unavailable, set up
 * Tailscale or a Tor onion service manually outside of eSE.
 *
 * This file is kept as a stub so existing `require('./cloudflare_tunnel')`
 * statements don't throw during the lifetime of in-flight v7.3.x clients.
 */
'use strict';

function start() {
  return { success: false, status: 'removed', error: 'cloudflare_removed',
    message: 'Cloudflare Quick Tunnel was removed in v7.4.0.' };
}

function stop() {
  return { success: true, status: 'removed' };
}

function getStatus() {
  return { status: 'removed', url: null, error: null, startedAt: null };
}

module.exports = { start, stop, getStatus };
