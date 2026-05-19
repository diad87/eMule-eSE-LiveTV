// this file is part of eMule eSE — Bootstrap cascade B-1..B-5 (F3)
//
// Cap 3 §3.4 thesis. Five-tier bootstrap so new users can join without
// any single point of trust.
//
// B-1 nodes.dat  — existing eMule mechanism, no eSE change
// B-2 mDNS       — local LAN discovery via _ese-live._udp.local
// B-3 invite tokens — Ed25519-signed PeerInvite blobs, base32-encodable
// B-4 .onion bootstrap — invite restricted to onion endpoints
// B-5 Gist seed (opt-in) — fetched from configurable URL with project pubkey
//
// LiveBootstrap orchestrates the cascade. It does NOT implement nodes.dat
// or mDNS directly — those are wrappers around existing eMule code and
// Bonjour SDK calls. B-3/B-4 token parsing lives here.
#pragma once

#include <vector>

namespace eSELive {

// === PeerInvite token (B-3/B-4) ==========================================
// Wire format (Cap 5 §5.4.3 thesis):
//   version    uint8 = 1
//   node_id    [16]
//   pubkey     [32]   Ed25519 signing key
//   endpoints  RendezvousList serialised (same as ChannelRecord)
//   expires    uint64 LE unix ts
//   nonce      [16]
//   signature  [64]   Ed25519 over all the above

struct PeerInviteEndpoint {
    uint8_t type;          // 1=onion 2=tailnet 3=clearnet4 4=clearnet6
    uint16_t port;
    uint8_t priority;
    CStringA addr;
};
struct PeerInvite {
    uint8_t version;
    uint8_t node_id[16];
    uint8_t pubkey[32];
    std::vector<PeerInviteEndpoint> endpoints;
    uint64_t expires_unix;
    uint8_t nonce[16];
    uint8_t signature[64];
};

bool PeerInviteSerializeBody(const PeerInvite& inv, std::vector<uint8_t>& out);
bool PeerInviteSerialize(const PeerInvite& inv, std::vector<uint8_t>& out);
bool PeerInviteParse(const uint8_t* in, size_t inLen, PeerInvite& out);
bool PeerInviteSign(PeerInvite& inv, const uint8_t secret[32]);
bool PeerInviteVerify(const PeerInvite& inv);

// Base32-encode/decode a serialised invite. Lowercase RFC 4648 base32,
// no padding, no separators. ~180 chars for a 1-endpoint invite —
// QR-code friendly.
bool PeerInviteToBase32(const std::vector<uint8_t>& serialised, CStringA& out);
bool PeerInviteFromBase32(const CStringA& in, std::vector<uint8_t>& out);

// === Bootstrap orchestrator ==============================================
class CLiveBootstrap {
public:
    static CLiveBootstrap& Get();

    // Called at app startup. Walks the cascade until a usable peer is found.
    // Non-blocking: each tier is initiated and the caller is notified via
    // CLiveStreamManager when peers arrive.
    void Start();

    // mDNS scan tick. Called from CLiveStreamManager::Process every 60 s
    // while we have zero peers.
    void TickMDNS();

    // Manual injection: user pastes an invite token in the UI.
    bool ImportInvite(const CStringA& base32Token);

    // B-5 gist seed (off by default — Decision 3.3).
    void SetGistSeedURL(const CStringW& url);
    void SetGistSeedEnabled(bool enabled);
    bool IsGistSeedEnabled() const { return m_gistEnabled; }

private:
    CLiveBootstrap();
    CLiveBootstrap(const CLiveBootstrap&) = delete;
    CLiveBootstrap& operator=(const CLiveBootstrap&) = delete;

    mutable CCriticalSection m_lock;
    CStringW m_gistUrl;
    bool     m_gistEnabled;
    DWORD    m_lastMDNSTick;
};

}  // namespace eSELive
