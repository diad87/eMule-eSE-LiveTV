#include "../LiveRequestRateLimiter.h"

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
    CLiveRequestRateLimiter limiter;
    const uint32_t subnetAHost = 0x0201A8C0u;

    for (int i = 0; i < 50; ++i)
        Expect(limiter.Check(subnetAHost + ((uint32_t)i << 24), 100) == CLiveRequestRateLimiter::ALLOW,
            "first 50 requests from one /24 must pass");
    Expect(limiter.Check(subnetAHost, 100) == CLiveRequestRateLimiter::LIMIT_SUBNET,
        "request 51 from one /24 must be limited");
    Expect(limiter.Check(subnetAHost, 5100) == CLiveRequestRateLimiter::ALLOW,
        "subnet window must reset after five seconds");

    limiter.Reset();
    for (uint32_t i = 1; i <= CLiveRequestRateLimiter::SLOT_COUNT; ++i)
        Expect(limiter.Check(i, 100) == CLiveRequestRateLimiter::ALLOW,
            "fixed subnet slots must accept their first request");
    Expect(limiter.ActiveSlotCount() == CLiveRequestRateLimiter::SLOT_COUNT,
        "all fixed subnet slots must be occupied");
    for (int i = 0; i < 100; ++i)
        Expect(limiter.Check(0x00010000u + (uint32_t)i, 100) == CLiveRequestRateLimiter::ALLOW,
            "bounded overflow bucket must allow its initial quota");
    Expect(limiter.Check(0x00020000u, 100) == CLiveRequestRateLimiter::LIMIT_OVERFLOW,
        "saturated table must never fail open");

    limiter.Reset();
    for (uint32_t subnet = 0; subnet < 10; ++subnet) {
        for (uint32_t request = 0; request < 50; ++request)
            Expect(limiter.Check(0x00001000u + subnet, 200) == CLiveRequestRateLimiter::ALLOW,
                "global quota must allow 500 normal requests");
    }
    Expect(limiter.Check(0x00002000u, 200) == CLiveRequestRateLimiter::LIMIT_GLOBAL,
        "global request 501 must be limited");

    limiter.Reset();
    const uint32_t nearWrap = 0xFFFFFF00u;
    for (int i = 0; i < 50; ++i)
        Expect(limiter.Check(subnetAHost, nearWrap) == CLiveRequestRateLimiter::ALLOW,
            "pre-wrap subnet quota must work");
    Expect(limiter.Check(subnetAHost, nearWrap + 100u) == CLiveRequestRateLimiter::LIMIT_SUBNET,
        "pre-wrap request 51 must be limited");
    Expect(limiter.Check(subnetAHost, nearWrap + CLiveRequestRateLimiter::WINDOW_MS) == CLiveRequestRateLimiter::ALLOW,
        "window reset must survive uint32 clock wrap");

    if (g_failures == 0)
        printf("Live request limiter tests passed.\n");
    return g_failures == 0 ? 0 : 1;
}
