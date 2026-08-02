#pragma once

#include "natmap/pcp_map_projection.h"

#include <cstdint>

namespace natmap {

enum class PcpPairTransactionStatus : std::uint8_t {
    AwaitingTcp = 0,
    AwaitingUdp = 1,
    Ready = 2,
    Failed = 3,
    TcpRollbackRequired = 4,
    Committed = 5,
};

struct PcpPairCommit {
    PcpMapProjection tcp{};
    PcpMapProjection udp{};
    bool has_udp = false;

    bool IsValid() const noexcept;
};

class PcpPairTransaction final {
public:
    PcpPairTransaction(
        bool udp_required,
        bool initial_operation) noexcept;

    bool StageTcp(const PcpMapProjection& projection) noexcept;
    bool StageUdp(const PcpMapProjection& projection) noexcept;
    void RecordTcpFailure() noexcept;
    void RecordUdpFailure() noexcept;

    bool TryCommit(PcpPairCommit& output) noexcept;
    bool GetTcpRollbackIdentity(
        PcpMappingIdentity& identity) const noexcept;

    PcpPairTransactionStatus status() const noexcept {
        return status_;
    }

private:
    void ClearStagedProjections() noexcept;

    bool udp_required_;
    bool initial_operation_;
    PcpPairTransactionStatus status_;
    PcpMapProjection tcp_{};
    PcpMapProjection udp_{};
    PcpMappingIdentity tcp_rollback_identity_{};
};

} // namespace natmap
