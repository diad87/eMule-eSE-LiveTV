// SPDX-License-Identifier: MIT
#pragma once

#include "edge/relay_carrier.h"

#include <cstdint>
#include <memory>

namespace relayedge {

class TlsTcpCarrier;

relay::RelayStatus ValidateLabTlsCredentials(const char* certificate_path,
                                              const char* private_key_path) noexcept;

class LabTlsListener {
public:
    LabTlsListener();
    ~LabTlsListener();
    LabTlsListener(const LabTlsListener&) = delete;
    LabTlsListener& operator=(const LabTlsListener&) = delete;

    relay::RelayStatus Open(const char* loopback_address,
                            std::uint16_t port) noexcept;
    // P4-only explicit public binding. Validation belongs to EdgeConfig; this
    // lower-level primitive still rejects empty addresses and zero ports.
    relay::RelayStatus OpenPublic(const char* bind_address,
                                  std::uint16_t port) noexcept;
    relay::RelayStatus Accept(const char* certificate_path,
                              const char* private_key_path,
                              TlsTcpCarrier& carrier) noexcept;
    std::uint16_t bound_port() const noexcept;
    void Close() noexcept;

private:
    relay::RelayStatus OpenInternal(const char* address,
                                    std::uint16_t port) noexcept;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class TlsTcpCarrier final : public IRelayCarrier {
public:
    TlsTcpCarrier();
    ~TlsTcpCarrier() override;
    TlsTcpCarrier(const TlsTcpCarrier&) = delete;
    TlsTcpCarrier& operator=(const TlsTcpCarrier&) = delete;

    // Outbound client connector with mandatory CA and hostname verification.
    relay::RelayStatus Connect(const char* address,
                               std::uint16_t port,
                               const char* ca_certificate_path,
                               const char* expected_server_name) noexcept;

    relay::RelayStatus ConnectLab(const char* loopback_address,
                                  std::uint16_t port,
                                  const char* ca_certificate_path,
                                  const char* expected_server_name) noexcept;

    // Bounded socket readiness probe used by the P3 worker so Stop never has
    // to race a blocking mbedTLS call from another thread.
    relay::RelayStatus WaitReadable(std::uint32_t timeout_ms,
                                    bool& readable) noexcept;

    CarrierState state() const noexcept override;
    relay::KrpCarrierProfile profile() const noexcept override {
        return relay::KrpCarrierProfile::LabTlsTcp;
    }
    relay::RelayStatus Send(const relay::Byte* data,
                            std::size_t size) noexcept override;
    relay::RelayStatus Receive(relay::Byte* data,
                               std::size_t capacity,
                               std::size_t& received) noexcept override;
    relay::RelayStatus ExportBinding(
        relay::KrpCarrierBinding& binding) noexcept override;
    void Close() noexcept override;

    const char* negotiated_tls_version() const noexcept;
    int last_tls_error() const noexcept;

private:
    friend class LabTlsListener;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace relayedge
