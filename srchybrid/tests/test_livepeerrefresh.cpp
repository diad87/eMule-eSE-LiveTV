#include "../LivePeerRefreshPolicy.h"

#include <stdio.h>

static int g_failures = 0;

static void Expect(bool condition, const char* message)
{
    if (!condition) {
        ++g_failures;
        printf("FAIL: %s\n", message);
    }
}

int main()
{
    CLivePeerRefreshPolicy policy;

    policy.OnSourceLost(1000, 2);
    Expect(policy.IsPending(), "source loss below the floor must arm replenishment");
    Expect(!policy.ShouldRequest(2999, 2), "pointer-swap grace must suppress an early refresh");
    Expect(policy.ShouldRequest(3000, 2), "refresh must fire when the loss grace expires");
    Expect(!policy.ShouldRequest(3001, 2), "refreshes must be deduplicated inside the cooldown");
    Expect(policy.ShouldRequest(3000 + CLivePeerRefreshPolicy::REQUEST_COOLDOWN_MS, 2),
        "refresh must retry after the cooldown if the mesh is still thin");

    Expect(policy.TakeCandidate(3) == 0, "candidate rotation must start at source zero");
    Expect(policy.TakeCandidate(3) == 1, "candidate rotation must advance to source one");
    Expect(policy.TakeCandidate(3) == 2, "candidate rotation must advance to source two");
    Expect(policy.TakeCandidate(3) == 0, "candidate rotation must wrap safely");

    policy.Reset();
    policy.OnSourceLost(500, 0);
    Expect(!policy.ShouldRequest(2500, 0), "zero-source refresh must wait for Kad discovery");
    Expect(policy.IsPending(), "zero-source refresh must remain pending");
    Expect(policy.ShouldRequest(2501, 1), "the first newly discovered source must satisfy the pending refresh");
    Expect(!policy.ShouldRequest(2502, CLivePeerRefreshPolicy::MIN_PEERS),
        "reaching the resilience floor must clear the pending refresh");
    Expect(!policy.IsPending(), "the pending flag must clear at the resilience floor");

    policy.Reset();
    const uint32_t nearWrap = 0xFFFFFF00u;
    policy.OnSourceLost(nearWrap, 1);
    Expect(!policy.ShouldRequest(nearWrap + CLivePeerRefreshPolicy::LOSS_GRACE_MS - 1u, 1),
        "loss grace must survive uint32 clock wrap");
    Expect(policy.ShouldRequest(nearWrap + CLivePeerRefreshPolicy::LOSS_GRACE_MS, 1),
        "wrapped loss grace must expire at the correct tick");
    Expect(!policy.ShouldRequest(nearWrap + CLivePeerRefreshPolicy::LOSS_GRACE_MS
        + CLivePeerRefreshPolicy::REQUEST_COOLDOWN_MS - 1u, 1),
        "cooldown must survive uint32 clock wrap");
    Expect(policy.ShouldRequest(nearWrap + CLivePeerRefreshPolicy::LOSS_GRACE_MS
        + CLivePeerRefreshPolicy::REQUEST_COOLDOWN_MS, 1),
        "wrapped cooldown must expire at the correct tick");

    if (g_failures == 0)
        printf("Live peer refresh policy tests passed.\n");
    return g_failures == 0 ? 0 : 1;
}
