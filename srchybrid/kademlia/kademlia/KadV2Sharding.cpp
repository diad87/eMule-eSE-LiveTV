// this file is part of eMule eSE — Kad Search v2 sharding impl (M3)
#include "stdafx.h"
#include "KadV2Sharding.h"
#include "KadV2Stats.h"
#include "MD4.h"
#include "kademlia/utils/UInt128.h"

namespace Kademlia
{

CKadV2Sharding::CKadV2Sharding() {}

CKadV2Sharding& CKadV2Sharding::Get()
{
    static CKadV2Sharding s_instance;
    return s_instance;
}

CStringA CKadV2Sharding::KeyOf(const CUInt128 &u)
{
    // 16 bytes big-endian -> 32 lowercase hex chars.
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

uint8 CKadV2Sharding::ComputeShardDegree(uint32 entryCount)
{
    if (entryCount < KADV2_T_HOT_ENTRIES) return 0;
    // s = ceil(log2(n / T_hot))
    uint32 ratio = entryCount / KADV2_T_HOT_ENTRIES;
    uint8  s = 0;
    while (ratio > 1) { ratio >>= 1; ++s; }
    // ceil correction: if not power-of-two-exact, bump by 1.
    if ((entryCount > KADV2_T_HOT_ENTRIES) && (entryCount & (entryCount - 1)) != 0)
        ++s;
    if (s < 1) s = 1;
    if (s > KADV2_S_MAX) s = KADV2_S_MAX;
    return s;
}

uint8 CKadV2Sharding::OnEntryAdded(const CUInt128 &uKeywordHash, uint32 entryCount, bool &outShouldAnnounce)
{
    outShouldAnnounce = false;
    const uint8 newS = ComputeShardDegree(entryCount);
    if (newS == 0) return 0;

    CSingleLock lock(&m_lock, TRUE);
    const CStringA key = KeyOf(uKeywordHash);
    CustodianState st;
    const uint32 now = (uint32)time(NULL);
    if (m_custodian.Lookup(key, st)) {
        if (newS != st.s) {
            st.s = newS;
            st.lastCheck = now;
            outShouldAnnounce = true;
            CKadV2Stats::Get().OnHotKeywordPromote();
        }
    } else {
        st.s = newS;
        st.lastHotSince = now;
        st.lastCheck    = now;
        outShouldAnnounce = true;
        CKadV2Stats::Get().OnHotKeywordPromote();
    }
    m_custodian[key] = st;
    return newS;
}

void CKadV2Sharding::ProcessDecay()
{
    CSingleLock lock(&m_lock, TRUE);
    const uint32 now = (uint32)time(NULL);
    // Demote announced entries past their valid_until.
    CStringA k;
    AnnouncedState av;
    CArray<CStringA> toRemoveAnnounced;
    POSITION pos = m_announced.GetStartPosition();
    while (pos) {
        m_announced.GetNextAssoc(pos, k, av);
        if (now > av.validUntilUnixTs) toRemoveAnnounced.Add(k);
    }
    for (INT_PTR i = 0; i < toRemoveAnnounced.GetCount(); ++i)
        m_announced.RemoveKey(toRemoveAnnounced[i]);

    // Custodian: deactivate entries that haven't been touched in COOLDOWN.
    // (Real promotion via OnEntryAdded; demotion via this decay loop.)
    CustodianState cs;
    CArray<CStringA> toRemoveCustodian;
    pos = m_custodian.GetStartPosition();
    while (pos) {
        m_custodian.GetNextAssoc(pos, k, cs);
        if (now - cs.lastCheck > KADV2_SHARD_COOLDOWN_S) {
            toRemoveCustodian.Add(k);
            CKadV2Stats::Get().OnHotKeywordDemote();
        }
    }
    for (INT_PTR i = 0; i < toRemoveCustodian.GetCount(); ++i)
        m_custodian.RemoveKey(toRemoveCustodian[i]);
}

void CKadV2Sharding::OnShardAnnounceReceived(const CUInt128 &uTarget, uint8 s, uint32 validUntilUnixTs)
{
    if (s == 0 || s > KADV2_S_MAX) return;  // ignore malformed
    CSingleLock lock(&m_lock, TRUE);
    AnnouncedState st;
    st.s = s;
    st.validUntilUnixTs = validUntilUnixTs;
    m_announced[KeyOf(uTarget)] = st;
    CKadV2Stats::Get().OnShardAnnounceRx();
}

uint8 CKadV2Sharding::LookupShardDegree(const CUInt128 &uTarget) const
{
    CSingleLock lock(&m_lock, TRUE);
    AnnouncedState st;
    if (!m_announced.Lookup(KeyOf(uTarget), st)) return 0;
    const uint32 now = (uint32)time(NULL);
    if (now > st.validUntilUnixTs) return 0;
    return st.s;
}

CUInt128 CKadV2Sharding::DeriveShardKey(const CStringA &kwBytes, uint8 i)
{
    // shard_key(kw, i) = MD4(kw_bytes || 0x1E || uint8(i))
    CMD4 md4;
    md4.Add((byte*)(LPCSTR)kwBytes, kwBytes.GetLength());
    uint8 sep = KADV2_SHARD_SEPARATOR_BYTE;
    md4.Add(&sep, 1);
    md4.Add(&i, 1);
    md4.Finish();
    CUInt128 out;
    out.SetValueBE(md4.GetHash());
    return out;
}

size_t CKadV2Sharding::SerializeAnnounce(const CUInt128 &uTarget, uint8 s, uint32 validUntilUnixTs, uint8 *out, size_t outLen)
{
    if (out == NULL || outLen < 21) return 0;
    uchar bytes[16];
    uTarget.ToByteArray(bytes);
    memcpy(out, bytes, 16);
    out[16] = s;
    // valid_until uint32 little-endian
    out[17] = (uint8)(validUntilUnixTs & 0xFF);
    out[18] = (uint8)((validUntilUnixTs >> 8)  & 0xFF);
    out[19] = (uint8)((validUntilUnixTs >> 16) & 0xFF);
    out[20] = (uint8)((validUntilUnixTs >> 24) & 0xFF);
    return 21;
}

bool CKadV2Sharding::ParseAnnounce(const uint8 *in, size_t inLen, CUInt128 &outTarget, uint8 &outS, uint32 &outValidUntilUnixTs)
{
    if (in == NULL || inLen < 21) return false;
    outTarget.SetValueBE(in);
    outS = in[16];
    outValidUntilUnixTs = (uint32)in[17]
                       | ((uint32)in[18] << 8)
                       | ((uint32)in[19] << 16)
                       | ((uint32)in[20] << 24);
    if (outS > KADV2_S_MAX) return false;
    return true;
}

}  // namespace Kademlia
