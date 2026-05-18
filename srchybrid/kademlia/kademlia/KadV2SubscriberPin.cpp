// this file is part of eMule eSE — Kad v2 M1 subscriber pinning impl (F3)
#include "stdafx.h"
#include "KadV2SubscriberPin.h"
#include "SubscriberPinScheduler.h"
#include "KadV2Defines.h"

namespace Kademlia {

// T_pin ∈ [3600, 7200] seconds = base 5400 ± 1800.
const uint32_t M1_PIN_INTERVAL_SEC = 5400u;
const uint32_t M1_PIN_JITTER_SEC   = 1800u;

CKadV2SubscriberPin::CKadV2SubscriberPin()
    : m_enabled(true)   // default ON per Cap 4 §4.2 monograph
{}

uint64_t CKadV2SubscriberPin::IdOfFileHash(const uchar* fileHash)
{
    uint64_t id = 0;
    for (int i = 0; i < 8; ++i) id |= ((uint64_t)fileHash[i]) << (i * 8);
    return id;
}

CKadV2SubscriberPin& CKadV2SubscriberPin::Get()
{
    static CKadV2SubscriberPin s_instance;
    return s_instance;
}

void CKadV2SubscriberPin::Start()
{
    // F3 skeleton: full scan of CSharedFileList happens in F5 when we wire
    // M1 to the actual share-list. For now the scheduler infrastructure is
    // in place; OnFileCompleted hook (called from eMule's file-done path)
    // registers individual jobs as files complete.
}

void CKadV2SubscriberPin::OnFileCompleted(const CKnownFile* pFile)
{
    if (!m_enabled || pFile == NULL) return;
    // F5 wiring: pFile->GetFileHash() -> register job; the callback would
    // call SearchManager::PrepareLookup(STOREKEYWORD, ...) per keyword of
    // the file, with TAG_PINNED_BY_SUBSCRIBER=1.
    // For now leave the scheduler entry creation to F5.
    (void)pFile;
}

void CKadV2SubscriberPin::OnFileRemoved(const uchar* fileHash)
{
    if (!fileHash) return;
    eSELive::CSubscriberPinScheduler::Get().Remove(IdOfFileHash(fileHash));
}

void CKadV2SubscriberPin::SetEnabled(bool enabled)
{
    if (m_enabled == enabled) return;
    m_enabled = enabled;
    if (!enabled) {
        // Best-effort: scheduler.Clear() doesn't exist; rely on Remove
        // being called for every file the caller knows about. In F5 the
        // KnownFile registry will give us the full list and we'll iterate.
    } else {
        Start();
    }
}

void CKadV2SubscriberPin::DoRepublish(uint64_t opaqueId)
{
    // F5: locate file by hash, build CKeyEntry per keyword with the
    // TAG_PINNED_BY_SUBSCRIBER tag, dispatch STOREKEYWORD search.
    (void)opaqueId;
}

}  // namespace Kademlia
