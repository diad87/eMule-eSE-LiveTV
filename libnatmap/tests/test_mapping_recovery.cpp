#include "natmap/natmap_policy.h"

#include <cstdint>
#include <cstdio>
#include <limits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

void TestFirstRetryAndGrowth() {
    MappingRecoverySchedule schedule;
    CHECK(!schedule.IsActive());
    CHECK(schedule.ResetForNetworkChange(7, 1000));
    CHECK(schedule.IsActive());
    CHECK(schedule.ShouldAttempt(7, 1000));
    CHECK(schedule.BeginAttempt(7, 1000));
    CHECK(schedule.attempt_count() == 1);
    CHECK(schedule.next_attempt_ms() == 31000);
    CHECK(!schedule.ShouldAttempt(7, 30999));
    CHECK(schedule.ShouldAttempt(7, 31000));

    CHECK(schedule.BeginAttempt(7, 31000));
    CHECK(schedule.attempt_count() == 2);
    CHECK(schedule.next_attempt_ms() == 91000);
    CHECK(schedule.BeginAttempt(7, 91000));
    CHECK(schedule.attempt_count() == 3);
    CHECK(schedule.next_attempt_ms() == 211000);
    CHECK(schedule.BeginAttempt(7, 211000));
    CHECK(schedule.attempt_count() == 4);
    CHECK(schedule.next_attempt_ms() == 451000);
}

void TestMaximumAttemptsAndDelay() {
    MappingRecoverySchedule schedule;
    CHECK(schedule.ResetForNetworkChange(9, 0));
    std::uint64_t now = 0;
    for (std::uint32_t attempt = 1;
         attempt <= MappingRecoverySchedule::kMaximumAttempts;
         ++attempt) {
        CHECK(schedule.ShouldAttempt(9, now));
        CHECK(schedule.BeginAttempt(9, now));
        now = schedule.next_attempt_ms();
    }
    CHECK(schedule.attempt_count() ==
          MappingRecoverySchedule::kMaximumAttempts);
    CHECK(schedule.IsExhausted());
    CHECK(!schedule.ShouldAttempt(9, UINT64_MAX));
    CHECK(!schedule.BeginAttempt(9, UINT64_MAX));
    CHECK(schedule.next_attempt_ms() == 1050000);
}

void TestSuccessResetIsGenerationBound() {
    MappingRecoverySchedule schedule;
    CHECK(schedule.ResetForNetworkChange(11, 500));
    CHECK(schedule.BeginAttempt(11, 500));
    CHECK(!schedule.RecordSuccess(10));
    CHECK(schedule.IsActive());
    CHECK(schedule.attempt_count() == 1);
    CHECK(schedule.RecordSuccess(11));
    CHECK(!schedule.IsActive());
    CHECK(schedule.attempt_count() == 0);
    CHECK(schedule.next_attempt_ms() == 0);
    CHECK(!schedule.RecordSuccess(11));
}

void TestNetworkChangeResetIsControlled() {
    MappingRecoverySchedule schedule;
    CHECK(schedule.ResetForNetworkChange(20, 1000));
    CHECK(schedule.BeginAttempt(20, 1000));
    CHECK(!schedule.ResetForNetworkChange(20, 1001));
    CHECK(!schedule.ResetForNetworkChange(19, 1001));
    CHECK(schedule.attempt_count() == 1);
    CHECK(!schedule.ShouldAttempt(19, UINT64_MAX));
    CHECK(schedule.ResetForNetworkChange(21, 1001));
    CHECK(schedule.generation() == 21);
    CHECK(schedule.attempt_count() == 0);
    CHECK(schedule.ShouldAttempt(21, 1001));
    CHECK(!schedule.BeginAttempt(20, 1001));
    CHECK(schedule.BeginAttempt(21, 1001));
}

void TestOverflowAndShutdownCancellation() {
    MappingRecoverySchedule schedule;
    const std::uint64_t maximum =
        (std::numeric_limits<std::uint64_t>::max)();
    CHECK(!schedule.ResetForNetworkChange(0, 1));
    CHECK(schedule.ResetForNetworkChange(1, maximum - 10));
    CHECK(schedule.BeginAttempt(1, maximum - 10));
    CHECK(schedule.next_attempt_ms() == maximum);
    schedule.Cancel();
    CHECK(!schedule.IsActive());
    CHECK(schedule.generation() == 0);
    CHECK(!schedule.ShouldAttempt(1, maximum));
}

}  // namespace

int main() {
    TestFirstRetryAndGrowth();
    TestMaximumAttemptsAndDelay();
    TestSuccessResetIsGenerationBound();
    TestNetworkChangeResetIsControlled();
    TestOverflowAndShutdownCancellation();
    std::printf("test_mapping_recovery: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
