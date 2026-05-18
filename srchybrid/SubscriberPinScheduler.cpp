// this file is part of eMule eSE — generic subscriber-pin scheduler impl (F3)
#include "stdafx.h"
#include "SubscriberPinScheduler.h"
#include "LiveOnionCrypto.h"   // SecureRandomBytes for jitter

namespace eSELive {

CSubscriberPinScheduler& CSubscriberPinScheduler::Get()
{
    static CSubscriberPinScheduler s_instance;
    return s_instance;
}

uint32_t CSubscriberPinScheduler::NextFireFromNow(uint32_t intervalSec, uint32_t jitterSec)
{
    uint8_t r[4];
    SecureRandomBytes(r, 4);
    const uint32_t rnd = (uint32_t)r[0] | ((uint32_t)r[1] << 8)
                       | ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 24);
    int32_t delta = 0;
    if (jitterSec > 0)
        delta = (int32_t)(rnd % (2u * jitterSec + 1u)) - (int32_t)jitterSec;
    const uint32_t now = (uint32_t)time(NULL);
    int64_t fire = (int64_t)now + (int64_t)intervalSec + delta;
    if (fire < (int64_t)now) fire = now + 60;
    return (uint32_t)fire;
}

void CSubscriberPinScheduler::AddOrUpdate(uint64_t opaqueId, uint32_t intervalSec, uint32_t jitterSec, JobCallback fn)
{
    CSingleLock lock(&m_lock, TRUE);
    for (auto& j : m_jobs) {
        if (j.opaqueId == opaqueId) {
            j.intervalSec = intervalSec;
            j.jitterSec   = jitterSec;
            j.fn          = fn;
            return;
        }
    }
    Job j;
    j.opaqueId = opaqueId;
    j.intervalSec = intervalSec;
    j.jitterSec   = jitterSec;
    j.nextFireUnixTs = NextFireFromNow(intervalSec, jitterSec);
    j.fn = fn;
    m_jobs.push_back(j);
}

void CSubscriberPinScheduler::Remove(uint64_t opaqueId, void* /*tagPtr*/)
{
    CSingleLock lock(&m_lock, TRUE);
    for (auto it = m_jobs.begin(); it != m_jobs.end(); ++it) {
        if (it->opaqueId == opaqueId) {
            m_jobs.erase(it);
            return;
        }
    }
}

void CSubscriberPinScheduler::Process()
{
    const uint32_t now = (uint32_t)time(NULL);

    // Snapshot of jobs due. We fire callbacks WITHOUT holding the lock
    // (callbacks may call back into AddOrUpdate / Remove).
    std::vector<Job> due;
    {
        CSingleLock lock(&m_lock, TRUE);
        for (auto& j : m_jobs) {
            if (now >= j.nextFireUnixTs) {
                due.push_back(j);
                j.nextFireUnixTs = NextFireFromNow(j.intervalSec, j.jitterSec);
            }
        }
    }
    for (const auto& j : due) {
        try { j.fn(j.opaqueId); }
        catch (...) { /* swallow — never crash the scheduler */ }
    }
}

size_t CSubscriberPinScheduler::JobCount() const
{
    CSingleLock lock(&m_lock, TRUE);
    return m_jobs.size();
}

}  // namespace eSELive
