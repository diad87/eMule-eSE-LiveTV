#pragma once

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

// Fixed-memory request limiter for OP_LIVE_REQUEST. Thread safety is supplied
// by the caller so the state machine stays deterministic and unit-testable.
class CLiveRequestRateLimiter
{
public:
    enum Decision {
        ALLOW = 0,
        LIMIT_SUBNET,
        LIMIT_OVERFLOW,
        LIMIT_GLOBAL
    };

    enum {
        SLOT_COUNT = 256,
        WINDOW_MS = 5000,
        MAX_SUBNET_REQUESTS = 50,
        MAX_OVERFLOW_REQUESTS = 100,
        MAX_GLOBAL_REQUESTS = 500
    };

    CLiveRequestRateLimiter() { Reset(); }

    void Reset()
    {
        for (size_t i = 0; i < SLOT_COUNT; ++i) {
            m_slots[i].used = false;
            m_slots[i].ipv6 = false;
            m_slots[i].subnet24 = 0;
            m_slots[i].windowStart = 0;
            m_slots[i].count = 0;
        }
        ResetWindow(m_overflow, 0);
        m_overflow.used = false;
        ResetWindow(m_global, 0);
        m_global.used = false;
    }

    Decision Check(uint32_t ipNet, uint32_t now)
    {
        return CheckKey(ipNet & 0x00FFFFFFu, false, now);
    }

    // Native-address entry point used by the dual-stack live protocol. IPv4
    // keeps the historical /24 policy; IPv6 is bucketed by a typed /64 hash,
    // never by CUpDownClient's lossy synthetic uint32 compatibility value.
    template <typename AddressT>
    Decision CheckAddress(const AddressT& address, uint32_t now)
    {
        if (address.IsNativeIPv6())
            return CheckKey(address.GetSubnet(64).HashKey(), true, now);
        uint32_t ipNet = 0;
        if (address.TryToUInt32(ipNet))
            return Check(ipNet, now);
        return Check(0, now);
    }

    size_t ActiveSlotCount() const
    {
        size_t count = 0;
        for (size_t i = 0; i < SLOT_COUNT; ++i)
            if (m_slots[i].used)
                ++count;
        return count;
    }

private:
    Decision CheckKey(uint32_t subnet, bool ipv6, uint32_t now)
    {
        StartOrRollWindow(m_global, now);
        SaturatingIncrement(m_global.count);
        if (m_global.count > MAX_GLOBAL_REQUESTS)
            return LIMIT_GLOBAL;

        subnet &= 0x00FFFFFFu;
        int match = -1;
        int reusable = -1;
        for (size_t i = 0; i < SLOT_COUNT; ++i) {
            if (m_slots[i].used && m_slots[i].ipv6 == ipv6 && m_slots[i].subnet24 == subnet) {
                match = (int)i;
                break;
            }
            if (reusable < 0 && (!m_slots[i].used || WindowElapsed(now, m_slots[i].windowStart)))
                reusable = (int)i;
        }

        if (match >= 0) {
            StartOrRollWindow(m_slots[match], now);
            SaturatingIncrement(m_slots[match].count);
            return m_slots[match].count > MAX_SUBNET_REQUESTS ? LIMIT_SUBNET : ALLOW;
        }

        if (reusable >= 0) {
            RateWindow& slot = m_slots[reusable];
            ResetWindow(slot, now);
            slot.used = true;
            slot.ipv6 = ipv6;
            slot.subnet24 = subnet;
            slot.count = 1;
            return ALLOW;
        }

        // Never fail open when the fixed table is saturated. Previously the
        // 65th active /24 was not counted at all; new subnets now share this
        // bounded overflow window while existing subnets keep their own quota.
        StartOrRollWindow(m_overflow, now);
        SaturatingIncrement(m_overflow.count);
        return m_overflow.count > MAX_OVERFLOW_REQUESTS ? LIMIT_OVERFLOW : ALLOW;
    }

    struct RateWindow {
        bool used;
        bool ipv6;
        uint32_t subnet24;
        uint32_t windowStart;
        uint32_t count;
    };

    RateWindow m_slots[SLOT_COUNT];
    RateWindow m_overflow;
    RateWindow m_global;

    static bool WindowElapsed(uint32_t now, uint32_t start)
    {
        return (uint32_t)(now - start) >= (uint32_t)WINDOW_MS;
    }

    static void SaturatingIncrement(uint32_t& value)
    {
        if (value < UINT32_MAX)
            ++value;
    }

    static void ResetWindow(RateWindow& value, uint32_t now)
    {
        value.used = true;
        value.ipv6 = false;
        value.subnet24 = 0;
        value.windowStart = now;
        value.count = 0;
    }

    static void StartOrRollWindow(RateWindow& value, uint32_t now)
    {
        if (!value.used || WindowElapsed(now, value.windowStart))
            ResetWindow(value, now);
    }
};
