#include "../LiveTunnelPending.h"

#include <atomic>
#include <cstdint>
#include <iostream>
#include <set>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

static_assert(
    !std::is_copy_constructible<eSELive::LiveTunnelPending::Handle>::value,
    "a pending handle must have exactly one waiter owner");

int failures = 0;

void Check(bool condition, const char* label)
{
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

eSELive::LiveTunnelPending::RequestIdGenerator Sequence(
    const std::vector<std::uint32_t>& values)
{
    return [values, index = std::size_t{0}]() mutable {
        const std::uint32_t value = values[index < values.size() ? index : values.size() - 1];
        ++index;
        return value;
    };
}

void TestRegistrationAndConfiguration()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto first = pending.Register(Sequence({0, 7}));
    const auto second = pending.Register(Sequence({7, 8}));
    Check(first && first.request_id() == 7, "registration rejects zero id");
    Check(second && second.request_id() == 8, "registration rejects collision");
    Check(pending.size() == 2, "registration owns two requests");

    const std::vector<std::uint8_t> message{1, 2, 3, 4};
    Check(
        pending.Configure(first, 0x40, 0x11223344, 2, message.data(), message.size()),
        "configuration accepts registered handle");
    Check(pending.SetCircuit(first.request_id(), 42), "set circuit accepts registered request");

    LiveTunnelPending::Outcome outcome;
    const std::vector<std::uint8_t> reply{9, 8, 7};
    Check(
        pending.Complete(first.request_id(), reply.data(), reply.size(), 99),
        "first completion wins");
    Check(
        !pending.Complete(first.request_id(), reply.data(), reply.size(), 100),
        "duplicate completion loses");
    Check(pending.Wait(std::move(first), 0, outcome), "completed request waits successfully");
    Check(
        !pending.Wait(std::move(first), 0, outcome),
        "consumed waiter handle cannot be reused");
    Check(
        outcome.reply == reply && outcome.result == 99 && outcome.circuit_id == 42,
        "completion preserves reply result and circuit");
}

void TestTimeoutAndLateCompletion()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({11}));
    LiveTunnelPending::Outcome outcome;
    Check(!pending.Wait(std::move(handle), 0, outcome), "zero timeout returns incomplete request");
    Check(pending.size() == 0, "timeout unregisters request");
    Check(!pending.Complete(11, nullptr, 0, 1), "late completion is ignored");
}

void TestBlockingCompletion()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({12}));
    Check(pending.SetCircuit(12, 77), "blocking fixture circuit");

    LiveTunnelPending::Outcome outcome;
    std::atomic<bool> waited{false};
    std::thread waiter([&] {
        waited = pending.Wait(std::move(handle), 2000, outcome);
    });
    const std::vector<std::uint8_t> reply{0xA5, 0x5A};
    Check(pending.Complete(12, reply.data(), reply.size(), 5), "blocking completion commits");
    waiter.join();
    Check(waited && outcome.reply == reply && outcome.result == 5,
          "blocking waiter observes completion");
}

void TestRetryAndFailureCompletion()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({21}));
    const std::vector<std::uint8_t> message{4, 3, 2, 1};
    Check(pending.Configure(handle, 0x41, 0x55AA, 2, message.data(), message.size()),
          "retry fixture configured");
    Check(pending.SetCircuit(21, 100), "retry fixture circuit one");

    Check(pending.CollectRetries(std::set<std::uint32_t>{100}).empty(),
          "active circuit is not retried");
    auto actions = pending.CollectRetries({});
    Check(actions.size() == 1, "dead circuit produces first retry");
    if (actions.size() == 1) {
        Check(
            actions[0].request_id == 21 && actions[0].sub_cmd == 0x41
                && actions[0].required_exit_caps == 0x55AA
                && actions[0].message == message,
            "retry action is an exact immutable snapshot");
    }

    Check(pending.SetCircuit(21, 101), "retry fixture circuit two");
    actions = pending.CollectRetries({});
    Check(actions.size() == 1, "dead circuit produces second retry");
    Check(pending.SetCircuit(21, 102), "retry fixture circuit three");
    Check(pending.CollectRetries({}).empty(), "exhaustion does not enqueue another retry");

    LiveTunnelPending::Outcome outcome;
    Check(!pending.Wait(std::move(handle), 0, outcome), "retry exhaustion completes as failure");
    Check(!pending.Complete(21, nullptr, 0, 1), "completion after retry failure loses");
}

void TestCompletionPreventsRetry()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({31}));
    const std::vector<std::uint8_t> message{6};
    Check(pending.Configure(handle, 0x40, 0, 2, message.data(), message.size()),
          "completed retry fixture configured");
    Check(pending.SetCircuit(31, 200), "completed retry fixture circuit");
    Check(pending.Complete(31, nullptr, 0, 7), "reply completes before retry sweep");
    Check(pending.CollectRetries({}).empty(), "completed request never retries");
    LiveTunnelPending::Outcome outcome;
    Check(pending.Wait(std::move(handle), 0, outcome) && outcome.result == 7,
          "completed request remains successful");
}

void TestFastCompletionStillRecordsCircuit()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({32}));
    Check(pending.Complete(32, nullptr, 0, 8), "fast reply completes before circuit record");
    Check(pending.SetCircuit(32, 201), "terminal registered request accepts circuit record");
    LiveTunnelPending::Outcome outcome;
    Check(
        pending.Wait(std::move(handle), 0, outcome)
            && outcome.result == 8
            && outcome.circuit_id == 201,
        "fast completion preserves later circuit bookkeeping");
}

void TestConcurrentCompletionExactlyOnce()
{
    using eSELive::LiveTunnelPending;
    LiveTunnelPending pending;
    auto handle = pending.Register(Sequence({41}));
    std::atomic<int> winners{0};
    std::vector<std::thread> threads;
    for (std::uint32_t value = 1; value <= 8; ++value) {
        threads.emplace_back([&, value] {
            if (pending.Complete(41, nullptr, 0, value))
                ++winners;
        });
    }
    for (auto& thread : threads)
        thread.join();

    LiveTunnelPending::Outcome outcome;
    Check(winners == 1, "concurrent completion has exactly one winner");
    Check(pending.Wait(std::move(handle), 0, outcome), "concurrently completed request succeeds");
    Check(outcome.result >= 1 && outcome.result <= 8, "winner result is preserved");
}

}  // namespace

int main()
{
    TestRegistrationAndConfiguration();
    TestTimeoutAndLateCompletion();
    TestBlockingCompletion();
    TestRetryAndFailureCompletion();
    TestCompletionPreventsRetry();
    TestFastCompletionStillRecordsCircuit();
    TestConcurrentCompletionExactlyOnce();

    if (failures != 0)
        return 1;
    std::cout << "Live tunnel pending ownership: PASS\n";
    return 0;
}
