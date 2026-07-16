// SPDX-License-Identifier: MIT
#include "edge/edge_daemon.h"

namespace relayedge {

relay::RelayStatus EdgeDaemon::Start(const EdgeConfig& config,
                                      std::uint64_t now_ms) noexcept {
    if (started_)
        return relay::RelayStatus::InvalidState;
    relay::RelayStatus status = runtime_.Start(config, now_ms);
    if (status != relay::RelayStatus::Ok)
        return status;
    status = ValidateLabTlsCredentials(config.certificate_path.c_str(),
                                       config.private_key_path.c_str());
    if (status != relay::RelayStatus::Ok) {
        (void)runtime_.Fail(now_ms, status);
        return status;
    }
    status = sessions_.Initialize(config, &runtime_.metrics());
    if (status == relay::RelayStatus::Ok)
        status = allocator_.Initialize(config.lease_first_port, config.lease_last_port,
                                       config.reuse_delay_ms, &runtime_.metrics());
    if (status == relay::RelayStatus::Ok) {
        status = config.mode == EdgeMode::ExperimentalPublic
            ? listener_.OpenPublic(config.bind_address.c_str(), config.port)
            : listener_.Open(config.bind_address.c_str(), config.port);
    }
    if (status != relay::RelayStatus::Ok) {
        listener_.Close();
        (void)runtime_.Fail(now_ms, status);
        return status;
    }
    started_ = true;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeDaemon::BeginDrain(std::uint64_t now_ms,
                                           std::uint64_t deadline_ms) noexcept {
    const relay::RelayStatus status = runtime_.BeginDrain(now_ms, deadline_ms);
    if (status == relay::RelayStatus::Ok) {
        listener_.Close();
        sessions_.BeginDrainAll();
    }
    return status;
}

relay::RelayStatus EdgeDaemon::AcceptTls(TlsTcpCarrier& carrier) noexcept {
    if (!started_ || !runtime_.CanAcceptSessions())
        return relay::RelayStatus::Disabled;
    return listener_.Accept(runtime_.config().certificate_path.c_str(),
                            runtime_.config().private_key_path.c_str(), carrier);
}

void EdgeDaemon::CloseResources(std::uint64_t now_ms) noexcept {
    listener_.Close();
    (void)allocator_.ReleaseAll(now_ms);
    sessions_.CloseAll();
}

relay::RelayStatus EdgeDaemon::Tick(std::uint64_t now_ms) noexcept {
    if (!started_)
        return relay::RelayStatus::InvalidState;
    (void)sessions_.Tick(now_ms);
    (void)allocator_.Tick(now_ms);
    const relay::RelayStatus status = runtime_.Tick(now_ms);
    if (runtime_.state() == EdgeLifecycle::Stopped) {
        CloseResources(now_ms);
        started_ = false;
    }
    return status;
}

relay::RelayStatus EdgeDaemon::Kill(std::uint64_t now_ms) noexcept {
    if (!started_)
        return relay::RelayStatus::InvalidState;
    CloseResources(now_ms);
    started_ = false;
    return runtime_.Kill(now_ms);
}

} // namespace relayedge
