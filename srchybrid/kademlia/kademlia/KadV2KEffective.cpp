// this file is part of eMule eSE — Kad Search v2 M6 (k effective) impl
#include "stdafx.h"
#include "KadV2KEffective.h"
#include "KadV2Stats.h"
#include "kademlia/utils/UInt128.h"
#include <math.h>

namespace Kademlia
{

CKadV2KEffective::CKadV2KEffective() {}

CKadV2KEffective& CKadV2KEffective::Get()
{
    static CKadV2KEffective s_instance;
    return s_instance;
}

CStringA CKadV2KEffective::KeyOf(const CUInt128 &u)
{
    uchar bytes[16];
    u.ToByteArray(bytes);
    CStringA out;
    char *buf = out.GetBufferSetLength(32);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        buf[i * 2 + 0] = hex[bytes[i] >> 4];
        buf[i * 2 + 1] = hex[bytes[i] & 0xF];
    }
    out.ReleaseBuffer(32);
    return out;
}

uint8 CKadV2KEffective::ComputeKEffective(uint32 queriesForKw, uint32 meanQueries)
{
    if (meanQueries == 0) return KADV2_K_BASE;
    const double ratio = (double)queriesForKw / (double)meanQueries;
    if (ratio <= 1.0) return KADV2_K_BASE;
    const double term = log2(ratio) + 1.0;          // > 1 because ratio > 1
    const double k = (double)KADV2_K_BASE * term;
    if (k < KADV2_K_MIN) return KADV2_K_MIN;
    if (k > KADV2_K_MAX) return KADV2_K_MAX;
    return (uint8)k;
}

void CKadV2KEffective::OnQueryReceived(const CUInt128 &uTarget)
{
    CSingleLock lock(&m_lock, TRUE);
    const CStringA key = KeyOf(uTarget);
    const uint32 now = (uint32)time(NULL);
    CustodianBucket b;
    if (m_custodian.Lookup(key, b)) {
        ++b.queriesLastWindow;
    } else {
        b.queriesLastWindow = 1;
        b.kEffective = KADV2_K_BASE;
        b.windowStartUnixTs = now;
    }
    m_custodian[key] = b;
}

void CKadV2KEffective::RecomputeAndGetChanges(CArray<KEffUpdate> &outChanges)
{
    outChanges.RemoveAll();
    CSingleLock lock(&m_lock, TRUE);
    const uint32 now = (uint32)time(NULL);

    // First pass: total + sample size for mean.
    uint64 totalQueries = 0;
    uint32 sampleSize = 0;
    CStringA k;
    CustodianBucket b;
    POSITION pos = m_custodian.GetStartPosition();
    while (pos) {
        m_custodian.GetNextAssoc(pos, k, b);
        totalQueries += b.queriesLastWindow;
        ++sampleSize;
    }
    if (sampleSize == 0) return;
    const uint32 mean = (uint32)(totalQueries / sampleSize);
    if (mean == 0) return;

    // Second pass: compute new k for each, emit if delta >= K_HYST.
    CArray<CStringA> keys;
    pos = m_custodian.GetStartPosition();
    while (pos) {
        m_custodian.GetNextAssoc(pos, k, b);
        const uint8 newK = ComputeKEffective(b.queriesLastWindow, mean);
        const int delta = (int)newK - (int)b.kEffective;
        if (delta >= KADV2_K_HYST || -delta >= KADV2_K_HYST) {
            // Materialise change.
            KEffUpdate u;
            // Reconstruct CUInt128 from hex key.
            uchar bytes[16];
            for (int i = 0; i < 16; ++i) {
                auto cv = [](char c) -> uint8 {
                    if (c >= '0' && c <= '9') return (uint8)(c - '0');
                    if (c >= 'a' && c <= 'f') return (uint8)(c - 'a' + 10);
                    if (c >= 'A' && c <= 'F') return (uint8)(c - 'A' + 10);
                    return 0;
                };
                bytes[i] = (uint8)((cv(k[i * 2]) << 4) | cv(k[i * 2 + 1]));
            }
            u.uTarget.SetValueBE(bytes);
            u.kNew = newK;
            outChanges.Add(u);
            b.kEffective = newK;
            CKadV2Stats::Get().OnKEffectiveUpdate();
        }
        b.queriesLastWindow = 0;
        b.windowStartUnixTs = now;
        m_custodian[k] = b;
    }
}

uint8 CKadV2KEffective::LookupKEffective(const CUInt128 &uTarget) const
{
    CSingleLock lock(&m_lock, TRUE);
    AnnouncedBucket b;
    if (m_announced.Lookup(KeyOf(uTarget), b))
        return b.kEffective;
    return KADV2_K_BASE;
}

void CKadV2KEffective::OnKEffectiveAnnounceReceived(const CUInt128 &uTarget, uint8 kNew)
{
    if (kNew < KADV2_K_MIN || kNew > KADV2_K_MAX) return;  // ignore malformed
    CSingleLock lock(&m_lock, TRUE);
    AnnouncedBucket b;
    b.kEffective = kNew;
    b.lastSeenUnixTs = (uint32)time(NULL);
    m_announced[KeyOf(uTarget)] = b;
}

}  // namespace Kademlia
