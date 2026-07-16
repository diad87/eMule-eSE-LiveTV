// SPDX-License-Identifier: MIT
// Optional MFC-free adapter: existing K6TargetTicket -> KRP service authority.
#pragma once

#include "relay/krp_authority.h"

#include "kad6/kad6_ticket.h"

#include <array>
#include <cstddef>

namespace relay {

constexpr std::size_t kKad6AuthorityMaxSecretSize = 64;

class Kad6TargetAuthorityVerifier final : public IServiceAuthorityVerifier {
public:
    Kad6TargetAuthorityVerifier(const kad6::Kad6CryptoHooks& crypto,
                                const kad6::K6TargetPolicy& policy,
                                const Byte* secret,
                                std::size_t secret_size) noexcept;

    bool ready() const noexcept { return ready_; }

    RelayStatus VerifyAndConsume(const KrpAuthorityRequest& request,
                                 std::uint64_t now,
                                 KrpAuthorityGrant& grant) noexcept override;

private:
    kad6::Kad6CryptoHooks crypto_{};
    kad6::K6TargetPolicy policy_{};
    std::array<Byte, kKad6AuthorityMaxSecretSize> secret_{};
    std::size_t secret_size_ = 0;
    bool ready_ = false;
};

} // namespace relay
