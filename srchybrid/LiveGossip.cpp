// this file is part of eMule eSE — Channel gossip protocol impl (F3)
#include "stdafx.h"
#include "LiveGossip.h"
#include "LiveSubscriptionStore.h"

namespace eSELive {

namespace {

inline void PushU8(std::vector<uint8_t>& o, uint8_t v) { o.push_back(v); }
inline void PushU16(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back((uint8_t)(v & 0xFF));
    o.push_back((uint8_t)((v >> 8) & 0xFF));
}
inline void PushU32(std::vector<uint8_t>& o, uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back((uint8_t)((v >> (i * 8)) & 0xFF));
}
inline void PushBytes(std::vector<uint8_t>& o, const uint8_t* p, size_t n) {
    o.insert(o.end(), p, p + n);
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
inline bool PopBytes(const uint8_t*& p, const uint8_t* end, uint8_t* dst, size_t n) {
    if (p + n > end) return false;
    memcpy(dst, p, n);
    p += n;
    return true;
}

// Hard caps to bound parsing cost / memory:
const uint16_t MAX_MY_SUBS = 1024;
const uint16_t MAX_FRESH   = 1024;

}  // namespace

bool ChannelGossipSerialize(const ChannelGossip& g, std::vector<uint8_t>& out)
{
    out.clear();
    if (g.my_subs.size() > MAX_MY_SUBS) return false;
    if (g.fresh.size()   > MAX_FRESH)   return false;
    PushU8(out, g.version);
    PushU16(out, (uint16_t)g.my_subs.size());
    for (const auto& e : g.my_subs)
        PushBytes(out, e.pubkey, 32);
    PushU16(out, (uint16_t)g.fresh.size());
    for (const auto& e : g.fresh) {
        PushBytes(out, e.pubkey, 32);
        PushU32(out, e.last_seen_unix);
        PushU8(out, e.was_live ? 1 : 0);
    }
    return true;
}

bool ChannelGossipParse(const uint8_t* in, size_t inLen, ChannelGossip& g)
{
    if (!in || inLen < 1 + 2 + 2) return false;
    const uint8_t* p = in;
    const uint8_t* end = in + inLen;

    if (!PopU8(p, end, g.version)) return false;
    if (g.version != 1) return false;

    uint16_t mySubsCount = 0;
    if (!PopU16(p, end, mySubsCount)) return false;
    if (mySubsCount > MAX_MY_SUBS) return false;
    g.my_subs.clear();
    g.my_subs.reserve(mySubsCount);
    for (uint16_t i = 0; i < mySubsCount; ++i) {
        ChannelGossipMySub s;
        if (!PopBytes(p, end, s.pubkey, 32)) return false;
        g.my_subs.push_back(s);
    }

    uint16_t freshCount = 0;
    if (!PopU16(p, end, freshCount)) return false;
    if (freshCount > MAX_FRESH) return false;
    g.fresh.clear();
    g.fresh.reserve(freshCount);
    for (uint16_t i = 0; i < freshCount; ++i) {
        ChannelGossipFresh f;
        if (!PopBytes(p, end, f.pubkey, 32)) return false;
        if (!PopU32(p, end, f.last_seen_unix)) return false;
        uint8_t live;
        if (!PopU8(p, end, live)) return false;
        f.was_live = (live != 0);
        g.fresh.push_back(f);
    }
    return true;
}

// F3 wiring stubs — the actual cadence + ClientList tick integration goes
// in F5 when LiveStreamManager wires this to its Process(). For now these
// are no-ops so the symbols exist for callers in F5.
void LiveGossipMaybeSend(CUpDownClient* /*peer*/)
{
    // F5: build a ChannelGossip from CLiveSubscriptionStore + known cache,
    // serialise, send via OP_LIVE_CHANNEL_GOSSIP if peer advertises
    // TAG_ESE_CAPS bit 10. Throttle by per-peer last-sent timestamp.
}

void LiveGossipOnReceived(CUpDownClient* /*peer*/, const uint8_t* payload, size_t payloadLen)
{
    ChannelGossip g;
    if (!ChannelGossipParse(payload, payloadLen, g)) return;
    // F5: feed g.fresh into the known-channels cache (CLiveKadBridge has
    // m_streamDirectory; we want a parallel m_channelDirectory introduced
    // in F5 LiveStreamManager refactor).
}

}  // namespace eSELive
