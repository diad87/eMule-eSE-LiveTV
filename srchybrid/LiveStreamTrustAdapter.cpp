#include "stdafx.h"
#include "LiveStreamTrustAdapter.h"

using ese::live::LiveTrustIdentity;
using ese::live::LiveTrustIdentityKind;
using ese::live::LiveTrustRecord;
using ese::live::LiveTrustStoreResult;

namespace {

LiveTrustIdentity IdentityOf(const LivePeerId& id)
{
    LiveTrustIdentity identity;
    identity.kind = static_cast<LiveTrustIdentityKind>(id.kind);
    memcpy(identity.bytes.data(), id.bytes, identity.bytes.size());
    return identity;
}

LiveTrustRecord RecordOf(const PeerTrust& trust)
{
    LiveTrustRecord record;
    record.joined_at = trust.joinedAt;
    record.bytes_served = trust.bytesServed;
    record.bytes_received = trust.bytesReceived;
    record.requests_received = trust.requestsReceived;
    record.requests_served = trust.requestsServed;
    record.current_level =
        static_cast<ese::live::LiveTrustLevel>(trust.currentLevel);
    record.fail_count = trust.failCount;
    record.last_promotion_time = trust.lastPromotionTime;
    record.last_probe_time = trust.lastProbeTime;
    record.is_banned = trust.isBanned;
    record.last_seen = trust.lastSeen;
    return record;
}

PeerTrust TrustOf(const LiveTrustRecord& record)
{
    PeerTrust trust;
    trust.joinedAt = record.joined_at;
    trust.bytesServed = record.bytes_served;
    trust.bytesReceived = record.bytes_received;
    trust.requestsReceived = record.requests_received;
    trust.requestsServed = record.requests_served;
    trust.currentLevel = static_cast<int>(record.current_level);
    trust.failCount = record.fail_count;
    trust.lastPromotionTime = record.last_promotion_time;
    trust.lastProbeTime = record.last_probe_time;
    trust.isBanned = record.is_banned;
    trust.lastSeen = record.last_seen;
    return trust;
}

} // namespace

LivePeerId LiveStreamTrustAdapter::PeerIdFromUserHash(const uchar* userHash)
{
    LivePeerId id;
    if (userHash == NULL)
        return id;
    bool hasHash = false;
    for (int index = 0; index < 16; ++index) {
        if (userHash[index] != 0) {
            hasHash = true;
            break;
        }
    }
    if (hasHash) {
        id.kind = LPID_USERHASH;
        memcpy(id.bytes, userHash, 16);
    }
    return id;
}

bool LiveStreamTrustAdapter::Get(
    const LivePeerId& id,
    PeerTrust& trust) const
{
    if (security_ == nullptr)
        return false;
    LiveTrustRecord record;
    if (!security_->GetTrust(IdentityOf(id), record))
        return false;
    trust = TrustOf(record);
    return true;
}

bool LiveStreamTrustAdapter::Set(
    const LivePeerId& id,
    const PeerTrust& trust)
{
    return security_ != nullptr &&
        security_->SetTrust(IdentityOf(id), RecordOf(trust)) ==
            LiveTrustStoreResult::Stored;
}

bool LiveStreamTrustAdapter::Touch(
    const LivePeerId& id,
    DWORD now,
    PeerTrust& trust)
{
    if (security_ == nullptr)
        return false;
    LiveTrustRecord record;
    if (security_->TouchTrust(
            IdentityOf(id), static_cast<std::uint32_t>(now), record) !=
        LiveTrustStoreResult::Stored)
        return false;
    trust = TrustOf(record);
    return true;
}

std::size_t LiveStreamTrustAdapter::Prune(DWORD now, DWORD ttl)
{
    return security_ == nullptr ? 0u :
        security_->PruneTrust(
            static_cast<std::uint32_t>(now),
            static_cast<std::uint32_t>(ttl));
}
