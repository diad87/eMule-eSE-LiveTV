#pragma once

#include <stdint.h>

// Deterministic state machine for replenishing LiveTV source peers. The short
// loss grace absorbs CClientList pointer swaps; the cooldown prevents repeated
// SUBSCRIBEs from turning a transient disconnect into reconnect churn.
class CLivePeerRefreshPolicy
{
public:
    enum {
        MIN_PEERS = 3,
        LOSS_GRACE_MS = 2000,
        REQUEST_COOLDOWN_MS = 15000
    };

    CLivePeerRefreshPolicy() { Reset(); }

    void Reset()
    {
        m_pending = false;
        m_hasNotBefore = false;
        m_notBeforeTick = 0;
        m_hasRequested = false;
        m_lastRequestTick = 0;
        m_nextCandidate = 0;
    }

    void OnSourceLost(uint32_t now, uint32_t remainingSources)
    {
        if (remainingSources >= MIN_PEERS) {
            m_pending = false;
            m_hasNotBefore = false;
            return;
        }
        m_pending = true;
        m_hasNotBefore = true;
        m_notBeforeTick = now + LOSS_GRACE_MS;
    }

    bool ShouldRequest(uint32_t now, uint32_t sourceCount)
    {
        if (sourceCount >= MIN_PEERS) {
            m_pending = false;
            m_hasNotBefore = false;
            return false;
        }

        // A periodic mesh check can arm a refresh even when no explicit loss
        // event was observed (for example, a session that never reached three
        // sources). Explicit loss events retain their short grace period.
        if (!m_pending) {
            m_pending = true;
            m_hasNotBefore = true;
            m_notBeforeTick = now;
        }

        // With no surviving source there is nobody to ask. Keep the request
        // pending so the first source discovered by Kad can be queried.
        if (sourceCount == 0)
            return false;

        if (m_hasNotBefore && !TickReached(now, m_notBeforeTick))
            return false;
        if (m_hasRequested
            && (uint32_t)(now - m_lastRequestTick) < REQUEST_COOLDOWN_MS)
            return false;

        m_hasRequested = true;
        m_lastRequestTick = now;
        m_hasNotBefore = false;
        return true;
    }

    uint32_t TakeCandidate(uint32_t sourceCount)
    {
        if (sourceCount == 0)
            return 0;
        const uint32_t selected = m_nextCandidate % sourceCount;
        m_nextCandidate = (selected + 1u) % sourceCount;
        return selected;
    }

    bool IsPending() const { return m_pending; }

private:
    bool m_pending;
    bool m_hasNotBefore;
    uint32_t m_notBeforeTick;
    bool m_hasRequested;
    uint32_t m_lastRequestTick;
    uint32_t m_nextCandidate;

    static bool TickReached(uint32_t now, uint32_t target)
    {
        return (int32_t)(now - target) >= 0;
    }
};
