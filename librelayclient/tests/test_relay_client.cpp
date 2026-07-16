// SPDX-License-Identifier: MIT
#include "relayclient/relay_client.h"

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>

namespace {

std::uint64_t g_checks = 0;

void Check(bool condition, const char* expression, int line) {
    ++g_checks;
    if (!condition) {
        std::cerr << "CHECK failed at line " << line << ": " << expression << '\n';
        std::exit(1);
    }
}

#define CHECK(value) Check((value), #value, __LINE__)

class FakeTransport final : public relayclient::IRelayTransportController {
public:
    relay::RelayStatus Start(std::uint64_t generation,
                             const relayclient::RelayClientConfig& config,
                             const std::shared_ptr<relayclient::RelayEventQueue>& events) noexcept override {
        ++starts;
        current_generation = generation;
        last_config = config;
        queue = events;
        running = start_status == relay::RelayStatus::Ok;
        return start_status;
    }

    void Stop(std::uint64_t generation) noexcept override {
        ++stops;
        stopped_generation = generation;
        running = false;
    }

    void Join() noexcept override { ++joins; }

    bool Post(relayclient::RelayClientEventType type,
              relayclient::RelayReason reason = relayclient::RelayReason::None,
              std::uint64_t generation = 0) {
        relayclient::RelayClientEvent event;
        event.type = type;
        event.generation = generation == 0 ? current_generation : generation;
        event.reason = reason;
        return queue && queue->Push(event);
    }

    relay::RelayStatus start_status = relay::RelayStatus::Ok;
    relayclient::RelayClientConfig last_config;
    std::shared_ptr<relayclient::RelayEventQueue> queue;
    std::uint64_t current_generation = 0;
    std::uint64_t stopped_generation = 0;
    std::uint64_t starts = 0;
    std::uint64_t stops = 0;
    std::uint64_t joins = 0;
    bool running = false;
};

relayclient::RelayClientConfig ValidConfig() {
    relayclient::RelayClientConfig config;
    config.enabled = true;
    config.endpoint_host = "relay.example.invalid";
    config.expected_server_name = config.endpoint_host;
    config.ca_bundle_path = "test-ca.pem";
    config.reconnect_min_ms = 1000;
    config.reconnect_max_ms = 8000;
    config.reconnect_jitter_percent = 20;
    config.lease_grace_ms = 3000;
    return config;
}

void ReachActiveLease(FakeTransport& transport, relayclient::RelayClientManager& manager,
                      std::uint64_t now) {
    CHECK(transport.Post(relayclient::RelayClientEventType::TransportConnected));
    CHECK(transport.Post(relayclient::RelayClientEventType::WssReady));
    CHECK(transport.Post(relayclient::RelayClientEventType::AuthStarted));
    CHECK(transport.Post(relayclient::RelayClientEventType::Authenticated));
    CHECK(transport.Post(relayclient::RelayClientEventType::LeaseRequested));
    CHECK(transport.Post(relayclient::RelayClientEventType::LeaseAllocated));
    CHECK(transport.Post(relayclient::RelayClientEventType::LeaseProbing));
    CHECK(transport.Post(relayclient::RelayClientEventType::LeaseActive));
    CHECK(transport.Post(relayclient::RelayClientEventType::EndpointReachable));
    CHECK(manager.Tick(now) == relay::RelayStatus::Ok);
}

void TestConfigAndDefaultOff() {
    relayclient::RelayClientConfig config;
    CHECK(!config.enabled);
    CHECK(relayclient::ValidateRelayClientConfig(config) == relay::RelayStatus::Ok);
    config.enabled = true;
    CHECK(relayclient::ValidateRelayClientConfig(config) == relay::RelayStatus::InvalidArgument);
    config = ValidConfig();
    CHECK(relayclient::ValidateRelayClientConfig(config) == relay::RelayStatus::Ok);
    config.reconnect_jitter_percent = 26;
    CHECK(relayclient::ValidateRelayClientConfig(config) == relay::RelayStatus::InvalidArgument);
    config = ValidConfig();
    config.endpoint_host.assign(relayclient::kRelayEndpointHostMax + 1, 'x');
    CHECK(relayclient::ValidateRelayClientConfig(config) == relay::RelayStatus::InvalidArgument);

    FakeTransport transport;
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(relayclient::RelayClientConfig{}) == relay::RelayStatus::Ok);
    CHECK(manager.Start(0) == relay::RelayStatus::Disabled);
    CHECK(transport.starts == 0);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
}

void TestStateSeparationAndMainThreadEvidence() {
    FakeTransport transport;
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(ValidConfig()) == relay::RelayStatus::Ok);
    CHECK(manager.Start(100) == relay::RelayStatus::Ok);
    CHECK(manager.Snapshot().carrier == relayclient::RelayCarrierState::Connecting);
    ReachActiveLease(transport, manager, 110);
    CHECK(manager.Snapshot().carrier == relayclient::RelayCarrierState::Active);
    CHECK(manager.Snapshot().session == relayclient::RelaySessionState::Active);
    CHECK(manager.Snapshot().lease == relayclient::RelayLeaseState::Active);
    CHECK(manager.Snapshot().endpoint == relayclient::RelayEndpointState::Reachable);
    CHECK(manager.Snapshot().route == relayclient::RelayRouteState::RelayReady);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::RelayPending);
    CHECK(manager.Snapshot().kad == relayclient::RelayKadState::Classic);
    CHECK(manager.ApplyEd2kRelayEvidence(false, true, true) == relay::RelayStatus::InvalidState);
    CHECK(manager.ApplyEd2kRelayEvidence(true, false, true) == relay::RelayStatus::InvalidState);
    CHECK(manager.ApplyEd2kRelayEvidence(true, true, false) == relay::RelayStatus::InvalidState);
    CHECK(manager.ApplyEd2kRelayEvidence(true, true, true) == relay::RelayStatus::Ok);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::RelayHighId);
    CHECK(manager.Snapshot().route == relayclient::RelayRouteState::RelayActive);

    std::atomic<int> other_status{0};
    std::thread wrong_thread([&]() {
        other_status = static_cast<int>(manager.Tick(120));
    });
    wrong_thread.join();
    CHECK(other_status == static_cast<int>(relay::RelayStatus::InvalidState));
}

void TestDisconnectGraceBackoffAndNoStorm() {
    FakeTransport transport;
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(ValidConfig()) == relay::RelayStatus::Ok);
    CHECK(manager.Start(1000) == relay::RelayStatus::Ok);
    ReachActiveLease(transport, manager, 1010);
    CHECK(manager.ApplyEd2kRelayEvidence(true, true, true) == relay::RelayStatus::Ok);
    CHECK(transport.Post(relayclient::RelayClientEventType::Disconnected,
                         relayclient::RelayReason::RemoteClosed));
    CHECK(manager.Tick(1100) == relay::RelayStatus::Ok);
    const auto after_disconnect = manager.Snapshot();
    CHECK(after_disconnect.carrier == relayclient::RelayCarrierState::Backoff);
    CHECK(after_disconnect.lease == relayclient::RelayLeaseState::Grace);
    CHECK(after_disconnect.endpoint == relayclient::RelayEndpointState::Degraded);
    CHECK(after_disconnect.ed2k == relayclient::RelayEd2kState::RelayDegraded);
    CHECK(after_disconnect.route == relayclient::RelayRouteState::FallbackClassic);
    CHECK(after_disconnect.next_retry_ms >= 1900);
    CHECK(after_disconnect.next_retry_ms <= 2300);
    const std::uint64_t starts = transport.starts;
    for (int i = 0; i < 100; ++i)
        CHECK(manager.Tick(after_disconnect.next_retry_ms - 1) == relay::RelayStatus::Ok);
    CHECK(transport.starts == starts);
    CHECK(manager.Tick(after_disconnect.next_retry_ms) == relay::RelayStatus::Ok);
    CHECK(transport.starts == starts + 1);
    CHECK(manager.Tick(4100) == relay::RelayStatus::Ok);
    CHECK(manager.Snapshot().lease == relayclient::RelayLeaseState::None);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
}

void TestStaleDoubleCallbackKillAndShutdown() {
    FakeTransport transport;
    relayclient::RelayClientManager manager(transport);
    CHECK(manager.Configure(ValidConfig()) == relay::RelayStatus::Ok);
    CHECK(manager.Start(0) == relay::RelayStatus::Ok);
    const std::uint64_t old_generation = transport.current_generation;
    CHECK(manager.SetKillSwitch(true) == relay::RelayStatus::Ok);
    CHECK(manager.Snapshot().carrier == relayclient::RelayCarrierState::Disabled);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
    CHECK(transport.stops == 1);
    CHECK(transport.Post(relayclient::RelayClientEventType::Authenticated,
                         relayclient::RelayReason::None, old_generation));
    CHECK(manager.Tick(1) == relay::RelayStatus::Ok);
    CHECK(manager.Metrics().stale_events == 1);
    CHECK(manager.Snapshot().ed2k == relayclient::RelayEd2kState::LowId);
    CHECK(manager.Shutdown() == relay::RelayStatus::Ok);
    CHECK(manager.Shutdown() == relay::RelayStatus::Ok);
    CHECK(manager.Metrics().shutdowns == 1);
    CHECK(!transport.Post(relayclient::RelayClientEventType::Disconnected));
}

void TestQueueBoundAndConcurrentProducer() {
    auto queue = std::make_shared<relayclient::RelayEventQueue>();
    relayclient::RelayClientEvent event;
    event.generation = 1;
    for (std::size_t i = 0; i < relayclient::kRelayEventQueueCapacity; ++i)
        CHECK(queue->Push(event));
    CHECK(!queue->Push(event));
    CHECK(queue->Size() == relayclient::kRelayEventQueueCapacity);
    CHECK(queue->Dropped() == 1);
    for (std::size_t i = 0; i < relayclient::kRelayEventQueueCapacity; ++i)
        CHECK(queue->Pop(event));
    CHECK(!queue->Pop(event));

    std::atomic<std::uint64_t> accepted{0};
    std::thread producer([&]() {
        for (std::uint64_t i = 0; i < 100000; ++i) {
            relayclient::RelayClientEvent value;
            value.generation = 2;
            value.value = i;
            while (!queue->Push(value)) {
                relayclient::RelayClientEvent discarded;
                queue->Pop(discarded);
            }
            ++accepted;
        }
    });
    while (accepted.load() < 100000) {
        relayclient::RelayClientEvent discarded;
        queue->Pop(discarded);
    }
    producer.join();
    CHECK(accepted == 100000);
    CHECK(queue->Size() <= relayclient::kRelayEventQueueCapacity);
}

void TestLifetimeCyclesAndInvalidTransitions() {
    for (int cycle = 0; cycle < 10000; ++cycle) {
        FakeTransport transport;
        relayclient::RelayClientManager manager(transport);
        CHECK(manager.Configure(ValidConfig()) == relay::RelayStatus::Ok);
        CHECK(manager.Start(static_cast<std::uint64_t>(cycle)) == relay::RelayStatus::Ok);
        CHECK(transport.Post(relayclient::RelayClientEventType::Authenticated));
        CHECK(manager.Tick(static_cast<std::uint64_t>(cycle)) == relay::RelayStatus::Ok);
        CHECK(manager.Metrics().invalid_transitions == 1);
        CHECK(manager.Disable() == relay::RelayStatus::Ok);
        CHECK(manager.Snapshot().route == relayclient::RelayRouteState::Classic);
    }
}

} // namespace

int main() {
    TestConfigAndDefaultOff();
    TestStateSeparationAndMainThreadEvidence();
    TestDisconnectGraceBackoffAndNoStorm();
    TestStaleDoubleCallbackKillAndShutdown();
    TestQueueBoundAndConcurrentProducer();
    TestLifetimeCyclesAndInvalidTransitions();
    std::cout << "librelayclient P3 tests passed: " << g_checks
              << " checks, 100000 concurrent queue actions, 10000 lifetime cycles\n";
    return 0;
}
