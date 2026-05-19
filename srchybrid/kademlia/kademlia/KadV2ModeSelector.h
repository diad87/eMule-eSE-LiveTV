// this file is part of eMule eSE — Kad v2 mode selector (F4b)
//
// Cap 6 §6.3 monograph. Decides per-query whether to use Direct, Tunneled
// or Adaptive mode. The user picks the default (Direct/Tunneled/Adaptive)
// in the UI; Adaptive uses the rules below.
#pragma once

#include "KadV2Defines.h"
#include <vector>

namespace Kademlia {

class CKadV2ModeSelector {
public:
    static CKadV2ModeSelector& Get();

    // === Per-query inputs ===
    struct QueryContext {
        bool   includesPrivateChannelHash;   // looking up a private channel
        CStringW keywordLowercase;            // empty for hash-only lookups
    };

    // Decide the mode for `q`. The user-selected default mode is applied
    // first; Adaptive then refines via the 4 rules of Cap 6 §6.3 Modo C.
    CKadV2Mode Decide(const QueryContext& q) const;

    // === User-controlled defaults ===
    void SetDefaultMode(CKadV2Mode m);
    CKadV2Mode GetDefaultMode() const { return m_default; }

    // === Sensitive-keyword list (local, never synced) ===
    void AddSensitiveKeyword(const CStringW& kwLowercase);
    void RemoveSensitiveKeyword(const CStringW& kwLowercase);
    bool IsSensitive(const CStringW& kwLowercase) const;
    void GetSensitiveKeywords(std::vector<CStringW>& out) const;

    // === tunnel_fallback_policy (Cap 6 §6.7 monograph) ===
    enum FallbackPolicy : uint8_t {
        STRICT_PRIVACY = 0,    // abort op if relés insuficientes
        BALANCED       = 1,    // reduce fanout proportionally (default)
        BEST_EFFORT    = 2     // fall back to Direct + warn user
    };
    void SetFallbackPolicy(FallbackPolicy p) { m_fallback = p; }
    FallbackPolicy GetFallbackPolicy() const { return m_fallback; }

private:
    CKadV2ModeSelector();
    CKadV2ModeSelector(const CKadV2ModeSelector&) = delete;
    CKadV2ModeSelector& operator=(const CKadV2ModeSelector&) = delete;

    mutable CCriticalSection m_lock;
    CKadV2Mode m_default;
    FallbackPolicy m_fallback;
    std::vector<CStringW> m_sensitive;
};

}  // namespace Kademlia
