// this file is part of eMule eSE — Bootstrap cascade impl (F3)
#include "stdafx.h"
#include "LiveBootstrap.h"
#include "LiveCrypto.h"

namespace eSELive {

namespace {

inline void PushU8(std::vector<uint8_t>& o, uint8_t v) { o.push_back(v); }
inline void PushU16(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back((uint8_t)(v & 0xFF));
    o.push_back((uint8_t)((v >> 8) & 0xFF));
}
inline void PushU64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}
inline void PushBytes(std::vector<uint8_t>& o, const uint8_t* p, size_t n) {
    o.insert(o.end(), p, p + n);
}
inline bool PopU8(const uint8_t*& p, const uint8_t* e, uint8_t& v) { if (p >= e) return false; v = *p++; return true; }
inline bool PopU16(const uint8_t*& p, const uint8_t* e, uint16_t& v) { if (p + 2 > e) return false; v = (uint16_t)p[0] | ((uint16_t)p[1] << 8); p += 2; return true; }
inline bool PopU64(const uint8_t*& p, const uint8_t* e, uint64_t& v) { if (p + 8 > e) return false; v = 0; for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (i * 8); p += 8; return true; }
inline bool PopBytes(const uint8_t*& p, const uint8_t* e, uint8_t* d, size_t n) { if (p + n > e) return false; memcpy(d, p, n); p += n; return true; }

// RFC 4648 base32 (lowercase, no padding).
const char B32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

}  // namespace

bool PeerInviteSerializeBody(const PeerInvite& inv, std::vector<uint8_t>& out)
{
    out.clear();
    if (inv.endpoints.size() > 16) return false;  // sanity
    PushU8(out, inv.version);
    PushBytes(out, inv.node_id, 16);
    PushBytes(out, inv.pubkey, 32);
    PushU8(out, (uint8_t)inv.endpoints.size());
    for (const auto& e : inv.endpoints) {
        if (e.addr.GetLength() > 64) return false;
        PushU8(out, e.type);
        PushU8(out, (uint8_t)e.addr.GetLength());
        PushBytes(out, (const uint8_t*)(LPCSTR)e.addr, e.addr.GetLength());
        PushU16(out, e.port);
        PushU8(out, e.priority);
    }
    PushU64(out, inv.expires_unix);
    PushBytes(out, inv.nonce, 16);
    return true;
}

bool PeerInviteSerialize(const PeerInvite& inv, std::vector<uint8_t>& out)
{
    if (!PeerInviteSerializeBody(inv, out)) return false;
    PushBytes(out, inv.signature, 64);
    return true;
}

bool PeerInviteParse(const uint8_t* in, size_t inLen, PeerInvite& inv)
{
    if (!in || inLen < 1 + 16 + 32 + 1 + 8 + 16 + 64) return false;
    const uint8_t* p = in;
    const uint8_t* e = in + inLen;
    if (!PopU8(p, e, inv.version)) return false;
    if (inv.version != 1) return false;
    if (!PopBytes(p, e, inv.node_id, 16)) return false;
    if (!PopBytes(p, e, inv.pubkey, 32)) return false;
    uint8_t ec;
    if (!PopU8(p, e, ec)) return false;
    if (ec > 16) return false;
    inv.endpoints.clear();
    inv.endpoints.reserve(ec);
    for (uint8_t i = 0; i < ec; ++i) {
        PeerInviteEndpoint ep;
        if (!PopU8(p, e, ep.type)) return false;
        uint8_t alen;
        if (!PopU8(p, e, alen)) return false;
        if (alen > 64 || p + alen > e) return false;
        ep.addr = CStringA((const char*)p, alen);
        p += alen;
        if (!PopU16(p, e, ep.port)) return false;
        if (!PopU8(p, e, ep.priority)) return false;
        inv.endpoints.push_back(ep);
    }
    if (!PopU64(p, e, inv.expires_unix)) return false;
    if (!PopBytes(p, e, inv.nonce, 16)) return false;
    if (!PopBytes(p, e, inv.signature, 64)) return false;
    return true;
}

bool PeerInviteSign(PeerInvite& inv, const uint8_t secret[32])
{
    std::vector<uint8_t> body;
    if (!PeerInviteSerializeBody(inv, body)) return false;
    return SignMessage(secret, inv.pubkey, body.data(), body.size(), inv.signature);
}

bool PeerInviteVerify(const PeerInvite& inv)
{
    std::vector<uint8_t> body;
    if (!PeerInviteSerializeBody(inv, body)) return false;
    if (inv.expires_unix < (uint64_t)time(NULL)) return false;
    return VerifySignature(inv.pubkey, body.data(), body.size(), inv.signature);
}

// === Base32 ===============================================================

bool PeerInviteToBase32(const std::vector<uint8_t>& serialised, CStringA& out)
{
    out.Empty();
    const size_t inLen = serialised.size();
    if (inLen == 0) return false;
    // 5 input bytes -> 8 output chars.
    size_t outLen = ((inLen * 8) + 4) / 5;
    out.Preallocate((int)outLen);
    uint32_t buffer = 0;
    int bitsLeft = 0;
    for (size_t i = 0; i < inLen; ++i) {
        buffer = (buffer << 8) | serialised[i];
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            const int idx = (int)((buffer >> (bitsLeft - 5)) & 0x1F);
            out.AppendChar(B32_ALPHABET[idx]);
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0) {
        const int idx = (int)((buffer << (5 - bitsLeft)) & 0x1F);
        out.AppendChar(B32_ALPHABET[idx]);
    }
    return true;
}

bool PeerInviteFromBase32(const CStringA& in, std::vector<uint8_t>& out)
{
    out.clear();
    uint32_t buffer = 0;
    int bitsLeft = 0;
    for (int i = 0; i < in.GetLength(); ++i) {
        const char c = in[i];
        int v = -1;
        for (int j = 0; j < 32; ++j)
            if (B32_ALPHABET[j] == c) { v = j; break; }
        if (v < 0) return false;
        buffer = (buffer << 5) | (uint32_t)v;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            out.push_back((uint8_t)((buffer >> (bitsLeft - 8)) & 0xFF));
            bitsLeft -= 8;
        }
    }
    return true;
}

// === Orchestrator =========================================================

CLiveBootstrap::CLiveBootstrap()
    : m_gistEnabled(false)
    , m_lastMDNSTick(0)
{}

CLiveBootstrap& CLiveBootstrap::Get()
{
    static CLiveBootstrap s_instance;
    return s_instance;
}

void CLiveBootstrap::Start()
{
    // F3: skeleton. B-1 (nodes.dat) is automatic via existing eMule Kad code.
    // B-2 mDNS scan kicks in via TickMDNS once a tick if no peers yet.
    // B-5 Gist seed is opt-in; nothing fires until user enables + sets URL.
}

void CLiveBootstrap::TickMDNS()
{
    // F3 skeleton: real mDNS scan is F5 (requires linking Bonjour SDK or
    // a minimal DNS-SD parser). For now this is a no-op that logs intent.
    CSingleLock lock(&m_lock, TRUE);
    m_lastMDNSTick = GetTickCount();
}

bool CLiveBootstrap::ImportInvite(const CStringA& base32Token)
{
    std::vector<uint8_t> raw;
    if (!PeerInviteFromBase32(base32Token, raw)) return false;
    PeerInvite inv;
    if (!PeerInviteParse(raw.data(), raw.size(), inv)) return false;
    if (!PeerInviteVerify(inv)) return false;
    // F5 wiring: insert each endpoint into eMule's Kad routing zone /
    // nodes.dat cache + LiveStreamManager peer list.
    return true;
}

void CLiveBootstrap::SetGistSeedURL(const CStringW& url) { CSingleLock l(&m_lock, TRUE); m_gistUrl = url; }
void CLiveBootstrap::SetGistSeedEnabled(bool e)         { CSingleLock l(&m_lock, TRUE); m_gistEnabled = e; }

}  // namespace eSELive
