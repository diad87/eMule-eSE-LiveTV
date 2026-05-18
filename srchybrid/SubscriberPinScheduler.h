// this file is part of eMule eSE — generic subscriber-pin scheduler (F3)
//
// Shared scheduler used by:
//   - Kad v2 M1 (KadV2SubscriberPin): republishes file metadata for files
//     the local user has downloaded.
//   - Privacy LiveSubscriberPinning: republishes ChannelRecords for
//     channels the local user is subscribed to.
//
// The scheduler maintains a list of "jobs" each with a next-fire timestamp
// and a callback. Process() is called once per Kademlia::Process tick.
// Jobs whose time arrived are fired and rescheduled with their interval +
// jitter.
//
// Each subsystem registers callbacks and adds/removes jobs as files complete
// or subscriptions change.
#pragma once

#include <functional>
#include <vector>

namespace eSELive {

class CSubscriberPinScheduler {
public:
    using JobCallback = std::function<void(uint64_t opaqueId)>;
    struct Job {
        uint64_t   opaqueId;          // module-defined (file hash / channel pubkey hash)
        uint32_t   intervalSec;       // base interval
        uint32_t   jitterSec;          // ± jitter
        uint32_t   nextFireUnixTs;
        JobCallback fn;
    };

    static CSubscriberPinScheduler& Get();

    // Add or update a job. If opaqueId already exists for the same callback,
    // updates interval; otherwise appends. Initial nextFire is randomised
    // within [now + interval - jitter, now + interval + jitter] to spread
    // load.
    void AddOrUpdate(uint64_t opaqueId, uint32_t intervalSec, uint32_t jitterSec, JobCallback fn);

    // Remove a job (called when a file is removed from shared / channel
    // unsubscribed).
    void Remove(uint64_t opaqueId, void* tagPtr = nullptr);

    // Tick: fire any due jobs.
    void Process();

    size_t JobCount() const;

private:
    CSubscriberPinScheduler() {}
    CSubscriberPinScheduler(const CSubscriberPinScheduler&) = delete;
    CSubscriberPinScheduler& operator=(const CSubscriberPinScheduler&) = delete;

    mutable CCriticalSection m_lock;
    std::vector<Job> m_jobs;

    static uint32_t NextFireFromNow(uint32_t intervalSec, uint32_t jitterSec);
};

}  // namespace eSELive
