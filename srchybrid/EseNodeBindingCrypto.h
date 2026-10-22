#pragma once
#include "EseChannelBinding.h"
namespace ese { namespace binding {
class TlsExporter {
public:
    virtual ~TlsExporter() = default;
    // The transport must reject calls before TLS completion and use normal
    // RFC5705 exporter label EXPORTER-eSE-peer-v1, exactly 32-byte context.
    virtual bool PeerExporter(const std::array<std::uint8_t,32>&,
        std::array<std::uint8_t,32>&) noexcept = 0;
};
class NodeCrypto final : public Crypto {
public:
    explicit NodeCrypto(TlsExporter& tls) noexcept : tls_(tls) {}
    bool Hash(const std::uint8_t*,std::size_t,std::array<std::uint8_t,32>&) noexcept override;
    bool Export(const std::array<std::uint8_t,32>&,std::array<std::uint8_t,32>&) noexcept override;
    bool Sign(const std::uint8_t*,std::size_t,std::array<std::uint8_t,64>&) noexcept override;
    bool Verify(const std::array<std::uint8_t,32>&,const std::uint8_t*,std::size_t,
        const std::uint8_t*) noexcept override;
private:
    TlsExporter& tls_;
};
} }
