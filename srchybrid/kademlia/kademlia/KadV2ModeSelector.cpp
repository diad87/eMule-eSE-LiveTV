// this file is part of eMule eSE — Kad v2 mode selector impl (F4b)
#include "stdafx.h"
#include "KadV2ModeSelector.h"

namespace Kademlia {

CKadV2ModeSelector::CKadV2ModeSelector()
    : m_default(CKadV2Mode::Adaptive)
    , m_fallback(BALANCED)
{
    // Default sensitive-keyword list — empty. The UI offers to pre-populate
    // with common Spanish-ISP-letter-vector words (sporting events etc.),
    // but the default is empty to avoid pre-judging the user's content.
}

CKadV2ModeSelector& CKadV2ModeSelector::Get()
{
    static CKadV2ModeSelector s_instance;
    return s_instance;
}

void CKadV2ModeSelector::SetDefaultMode(CKadV2Mode m)
{
    CSingleLock lock(&m_lock, TRUE);
    m_default = m;
}

void CKadV2ModeSelector::AddSensitiveKeyword(const CStringW& kw)
{
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& k : m_sensitive)
        if (k.CompareNoCase(kw) == 0) return;
    m_sensitive.push_back(kw);
}

void CKadV2ModeSelector::RemoveSensitiveKeyword(const CStringW& kw)
{
    CSingleLock lock(&m_lock, TRUE);
    for (auto it = m_sensitive.begin(); it != m_sensitive.end(); ++it) {
        if (it->CompareNoCase(kw) == 0) {
            m_sensitive.erase(it);
            return;
        }
    }
}

bool CKadV2ModeSelector::IsSensitive(const CStringW& kw) const
{
    CSingleLock lock(&m_lock, TRUE);
    for (const auto& k : m_sensitive)
        if (kw.Find(k) >= 0) return true;
    return false;
}

void CKadV2ModeSelector::GetSensitiveKeywords(std::vector<CStringW>& out) const
{
    CSingleLock lock(&m_lock, TRUE);
    out = m_sensitive;
}

CKadV2Mode CKadV2ModeSelector::Decide(const QueryContext& q) const
{
    CSingleLock lock(&m_lock, TRUE);
    switch (m_default) {
        case CKadV2Mode::Direct:    return CKadV2Mode::Direct;
        case CKadV2Mode::Tunneled:  return CKadV2Mode::Tunneled;
        case CKadV2Mode::Adaptive: {
            // Adoption policy: Adaptive is Kad6-first for every supported operation.
            // Availability remains a caller concern: if no authenticated circuit exists,
            // STRICT aborts while BALANCED/BEST_EFFORT may use the explicit Kad2 fallback.
            // Keeping that choice at the call site prevents the selector from mistaking a
            // configured preference for proof that a usable circuit is actually Active.
            //
            // The query context and sensitive-keyword list remain part of the stable API;
            // they can tighten a future per-operation fallback without changing the
            // Direct/Tunneled/Adaptive wire-independent enum.
            (void)q;
            return CKadV2Mode::Tunneled;
        }
    }
    return CKadV2Mode::Direct;
}

}  // namespace Kademlia
