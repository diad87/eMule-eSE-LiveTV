// this file is part of eMule eSE — Live subscription store (F2)
//
// Per-user encrypted list of subscribed channel pubkeys. Stored at
// %APPDATA%\eMule\ese\subscriptions.dat, encrypted via Windows DPAPI so
// only the local user account can decrypt (no key material in the file).
//
// Channel IDs are public keys. Private subscription state is stored in a
// DPAPI-encrypted file.
#pragma once

#include <vector>

namespace eSELive {

struct SubscriptionEntry {
    uint8_t channel_pubkey[32];
    CStringA name;            // last-known UI label (optional, cached for offline display)
    uint64_t added_unix_ts;
    bool notifications;       // notify when channel goes LIVE
};

class CLiveSubscriptionStore {
public:
    static CLiveSubscriptionStore& Get();

    // Load from disk. Returns true on success or true if the file didn't
    // exist yet (empty store = first run). Returns false only if the file
    // exists but DPAPI decryption fails or parse fails (corruption).
    bool Load();

    // Save to disk. Atomic via .new + MoveFileEx.
    bool Save() const;

    // CRUD
    bool Add(const SubscriptionEntry& e);
    bool Remove(const uint8_t channel_pubkey[32]);
    bool IsSubscribed(const uint8_t channel_pubkey[32]) const;
    size_t Count() const;
    bool GetAll(std::vector<SubscriptionEntry>& out) const;

    // For cover-traffic mixing during refreshes (Cap 5 §5.3.4 thesis):
    // returns up to `n` random channel_pubkeys NOT in the subscription set.
    // The "known channels" set is supplied by the caller from gossip cache.
    void PickCoverTrafficSet(const std::vector<std::vector<uint8_t>>& knownNotSubscribed,
                             size_t n,
                             std::vector<std::vector<uint8_t>>& out) const;

    static CStringW StorePath();

private:
    CLiveSubscriptionStore();
    CLiveSubscriptionStore(const CLiveSubscriptionStore&) = delete;
    CLiveSubscriptionStore& operator=(const CLiveSubscriptionStore&) = delete;

    // Serialise the entry list to a flat buffer (before DPAPI).
    bool SerializeUnencrypted(std::vector<uint8_t>& out) const;
    bool ParseUnencrypted(const uint8_t* in, size_t inLen);

    mutable CCriticalSection m_lock;
    std::vector<SubscriptionEntry> m_entries;
    bool m_loaded;
};

}  // namespace eSELive
