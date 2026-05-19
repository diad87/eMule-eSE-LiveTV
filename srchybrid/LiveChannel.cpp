// this file is part of eMule eSE — Live channel identity impl (F2)
#include "stdafx.h"
#include "LiveChannel.h"
#include "LiveCrypto.h"           // reuse Ed25519 keypair/sign/verify
#include "LiveOnionCrypto.h"      // AEAD seal/open

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace eSELive {

// === ctors ===============================================================

ChannelRecord::ChannelRecord()
    : version(1)
    , seq(0)
    , timestamp_unix(0)
    , category(6)              // "Otros" default
    , access_mode(0)
    , flags(0)
    , has_successor(false)
{
    memset(channel_pubkey, 0, sizeof channel_pubkey);
    language[0] = ' ';
    language[1] = ' ';
    memset(icon_md4, 0, sizeof icon_md4);
    memset(successor, 0, sizeof successor);
    memset(signature, 0, sizeof signature);
}

bool ChannelKeyGenerate(ChannelKey& outKey)
{
    return GenerateBroadcasterKeypair(outKey.pubkey, outKey.secret);
}

// === Wire helpers ========================================================

namespace {

inline void PushU8(std::vector<uint8_t>& out, uint8_t v) { out.push_back(v); }
inline void PushU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back((uint8_t)(v & 0xFF));
    out.push_back((uint8_t)((v >> 8) & 0xFF));
}
inline void PushU32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}
inline void PushU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}
inline void PushBytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
    out.insert(out.end(), p, p + n);
}

inline bool PopU8(const uint8_t*& p, const uint8_t* end, uint8_t& v) {
    if (p >= end) return false;
    v = *p++;
    return true;
}
inline bool PopU16(const uint8_t*& p, const uint8_t* end, uint16_t& v) {
    if (p + 2 > end) return false;
    v = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    p += 2;
    return true;
}
inline bool PopU32(const uint8_t*& p, const uint8_t* end, uint32_t& v) {
    if (p + 4 > end) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v |= ((uint32_t)p[i]) << (i * 8);
    p += 4;
    return true;
}
inline bool PopU64(const uint8_t*& p, const uint8_t* end, uint64_t& v) {
    if (p + 8 > end) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (i * 8);
    p += 8;
    return true;
}
inline bool PopBytes(const uint8_t*& p, const uint8_t* end, uint8_t* dst, size_t n) {
    if (p + n > end) return false;
    memcpy(dst, p, n);
    p += n;
    return true;
}

}  // namespace

bool ChannelRecordSerializeBody(const ChannelRecord& r, std::vector<uint8_t>& out)
{
    out.clear();
    if (r.name.GetLength() > 64) return false;
    if (r.description.GetLength() > 256) return false;
    if (r.rendezvous.size() > 255) return false;

    PushU8(out, r.version);
    PushBytes(out, r.channel_pubkey, 32);
    PushU32(out, r.seq);
    PushU64(out, r.timestamp_unix);

    PushU8(out, (uint8_t)r.name.GetLength());
    PushBytes(out, (const uint8_t*)(LPCSTR)r.name, r.name.GetLength());

    PushU16(out, (uint16_t)r.description.GetLength());
    PushBytes(out, (const uint8_t*)(LPCSTR)r.description, r.description.GetLength());

    PushU8(out, r.category);
    PushBytes(out, (const uint8_t*)r.language, 2);
    PushBytes(out, r.icon_md4, 16);
    PushU8(out, r.access_mode);
    PushU8(out, r.flags);

    PushU8(out, (uint8_t)r.rendezvous.size());
    for (size_t i = 0; i < r.rendezvous.size(); ++i) {
        const RendezvousEntry& e = r.rendezvous[i];
        if (e.addr.GetLength() > 64) return false;
        PushU8(out, e.type);
        PushU8(out, (uint8_t)e.addr.GetLength());
        PushBytes(out, (const uint8_t*)(LPCSTR)e.addr, e.addr.GetLength());
        PushU16(out, e.port);
        PushU8(out, e.priority);
    }

    PushU8(out, r.has_successor ? 1 : 0);
    if (r.has_successor)
        PushBytes(out, r.successor, 32);

    return true;
}

bool ChannelRecordSerialize(const ChannelRecord& r, std::vector<uint8_t>& out)
{
    if (!ChannelRecordSerializeBody(r, out)) return false;
    PushBytes(out, r.signature, 64);
    return true;
}

bool ChannelRecordParse(const uint8_t* in, size_t inLen, ChannelRecord& rec)
{
    if (!in || inLen < (1 + 32 + 4 + 8 + 1 + 0 + 2 + 0 + 1 + 2 + 16 + 1 + 1 + 1 + 1 + 64))
        return false;
    const uint8_t* p = in;
    const uint8_t* end = in + inLen;

    if (!PopU8(p, end, rec.version)) return false;
    if (rec.version != 1) return false;

    if (!PopBytes(p, end, rec.channel_pubkey, 32)) return false;
    if (!PopU32(p, end, rec.seq)) return false;
    if (!PopU64(p, end, rec.timestamp_unix)) return false;

    uint8_t nameLen = 0;
    if (!PopU8(p, end, nameLen)) return false;
    if (p + nameLen > end || nameLen > 64) return false;
    rec.name = CStringA((const char*)p, nameLen);
    p += nameLen;

    uint16_t descLen = 0;
    if (!PopU16(p, end, descLen)) return false;
    if (p + descLen > end || descLen > 256) return false;
    rec.description = CStringA((const char*)p, descLen);
    p += descLen;

    if (!PopU8(p, end, rec.category)) return false;
    if (!PopBytes(p, end, (uint8_t*)rec.language, 2)) return false;
    if (!PopBytes(p, end, rec.icon_md4, 16)) return false;
    if (!PopU8(p, end, rec.access_mode)) return false;
    if (!PopU8(p, end, rec.flags)) return false;

    uint8_t rdvCount = 0;
    if (!PopU8(p, end, rdvCount)) return false;
    rec.rendezvous.clear();
    rec.rendezvous.reserve(rdvCount);
    for (uint8_t i = 0; i < rdvCount; ++i) {
        RendezvousEntry e;
        if (!PopU8(p, end, e.type)) return false;
        uint8_t addrLen = 0;
        if (!PopU8(p, end, addrLen)) return false;
        if (p + addrLen > end || addrLen > 64) return false;
        e.addr = CStringA((const char*)p, addrLen);
        p += addrLen;
        if (!PopU16(p, end, e.port)) return false;
        if (!PopU8(p, end, e.priority)) return false;
        rec.rendezvous.push_back(e);
    }

    uint8_t hasSucc = 0;
    if (!PopU8(p, end, hasSucc)) return false;
    rec.has_successor = (hasSucc != 0);
    if (rec.has_successor) {
        if (!PopBytes(p, end, rec.successor, 32)) return false;
    } else {
        memset(rec.successor, 0, 32);
    }

    if (!PopBytes(p, end, rec.signature, 64)) return false;
    // We tolerate trailing bytes (forward compat).
    return true;
}

bool ChannelRecordSign(ChannelRecord& rec, const uint8_t secret[32])
{
    std::vector<uint8_t> body;
    if (!ChannelRecordSerializeBody(rec, body)) return false;
    return SignMessage(secret, rec.channel_pubkey,
                       body.data(), body.size(),
                       rec.signature);
}

bool ChannelRecordVerify(const ChannelRecord& rec)
{
    std::vector<uint8_t> body;
    if (!ChannelRecordSerializeBody(rec, body)) return false;
    return VerifySignature(rec.channel_pubkey,
                           body.data(), body.size(),
                           rec.signature);
}

// === Sealed records ======================================================

namespace {

// K_kad = HKDF(channel_secret, info="ese-kad-record-key-v1")
bool DeriveKadRecordKey(const uint8_t secret[32], uint8_t kOut[32])
{
    const char info[] = "ese-kad-record-key-v1";
    return Hkdf(secret, 32, nullptr, 0,
                (const uint8_t*)info, sizeof info - 1,
                kOut, 32);
}

}  // namespace

bool ChannelRecordSeal(const std::vector<uint8_t>& bodySerialised,
                       const uint8_t secret[32],
                       uint8_t nonceOut[12],
                       std::vector<uint8_t>& outCipher)
{
    uint8_t key[32];
    if (!DeriveKadRecordKey(secret, key)) return false;
    SecureRandomBytes(nonceOut, 12);
    outCipher.resize(bodySerialised.size() + 16);
    const bool ok = AeadEncrypt(key, nonceOut,
                                nullptr, 0,
                                bodySerialised.data(), bodySerialised.size(),
                                outCipher.data());
    SecureWipe(key, 32);
    return ok;
}

bool ChannelRecordOpen(const uint8_t* cipher, size_t cipherLen,
                       const uint8_t nonce[12],
                       const uint8_t secret[32],
                       std::vector<uint8_t>& outBody)
{
    if (!cipher || cipherLen < 16) return false;
    uint8_t key[32];
    if (!DeriveKadRecordKey(secret, key)) return false;
    outBody.resize(cipherLen - 16);
    const bool ok = AeadDecrypt(key, nonce,
                                nullptr, 0,
                                cipher, cipherLen,
                                outBody.data());
    SecureWipe(key, 32);
    if (!ok) outBody.clear();
    return ok;
}

}  // namespace eSELive
