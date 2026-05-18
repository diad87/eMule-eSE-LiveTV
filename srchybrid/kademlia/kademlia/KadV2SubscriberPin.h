// this file is part of eMule eSE — Kad v2 M1 subscriber pinning (F3)
//
// Cap 4 §4.2 monograph. Re-publishes file metadata for files the local
// user has DOWNLOADED (not just authored). Cadence: T_pin ∈ [3600, 7200]s.
// Uses the shared CSubscriberPinScheduler.
#pragma once

class CKnownFile;

namespace Kademlia {

class CKadV2SubscriberPin {
public:
    static CKadV2SubscriberPin& Get();

    // Called once at startup: scans CSharedFileList for files marked
    // as completed-by-me and registers a periodic job per file.
    void Start();

    // Lifecycle hooks
    void OnFileCompleted(const CKnownFile* pFile);
    void OnFileRemoved(const uchar* fileHash);

    // Toggle from preferences UI ("Help index files I download" — Cap 4
    // §4.2 policy). When false, all jobs are removed; when true, Start()
    // re-scans shared files.
    void SetEnabled(bool enabled);
    bool IsEnabled() const { return m_enabled; }

private:
    CKadV2SubscriberPin();
    CKadV2SubscriberPin(const CKadV2SubscriberPin&) = delete;
    CKadV2SubscriberPin& operator=(const CKadV2SubscriberPin&) = delete;

    static void DoRepublish(uint64_t opaqueId);
    static uint64_t IdOfFileHash(const uchar* fileHash);

    bool m_enabled;
};

}  // namespace Kademlia
