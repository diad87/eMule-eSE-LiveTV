#pragma once

#include "LiveProtocol.h"
#include "LiveStreamSecurity.h"

class LiveStreamTrustAdapter final
{
public:
    LiveStreamTrustAdapter() = default;
    explicit LiveStreamTrustAdapter(ese::live::LiveStreamSecurity& security)
        : security_(&security) {}

    void Bind(ese::live::LiveStreamSecurity& security) { security_ = &security; }
    static LivePeerId PeerIdFromUserHash(const uchar* userHash);
    bool Get(const LivePeerId& id, PeerTrust& trust) const;
    bool Set(const LivePeerId& id, const PeerTrust& trust);
    bool Touch(const LivePeerId& id, DWORD now, PeerTrust& trust);
    std::size_t Prune(DWORD now, DWORD ttl);

private:
    ese::live::LiveStreamSecurity* security_ = nullptr;
};
