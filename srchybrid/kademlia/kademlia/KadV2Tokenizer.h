// this file is part of eMule eSE — Kad Search v2 tokenizer (F8)
//
// Cap 4 §4.3 (M2 composite keys) + §4.5 (M4 trigrams) monograph.
//
// Canonical tokenisation: lowercase + strip diacritics + split on
// whitespace. Used to derive composite_key_2 and trigram set.
#pragma once

#include "KadV2Defines.h"
#include <vector>

namespace Kademlia {

// === Tokeniser ============================================================

class CKadV2Tokenizer {
public:
    // canon(t) = lower(stripDiacritics(t)). UTF-8 in, UTF-8 out.
    static CStringA Canon(const CStringA& t);

    // Split UTF-8 string on whitespace, return canonical tokens.
    static std::vector<CStringA> Tokenize(const CStringA& utf8Input);

    // M2 composite_key_2(a, b) = MD4("\x02" || canon(min(a,b)) || "\x1F" || canon(max(a,b)))
    // The pair (a,b) is sorted lexicographically so any order produces the
    // same key (Cap 4 §4.3 spec).
    static CUInt128 CompositeKey2(const CStringA& a, const CStringA& b);

    // Choose the K rarest pairs from the tokens (K <= 15 per spec).
    // Rarity proxy: longer tokens are rarer. For real ranking the
    // monograph references a precomputed frequency table embedded in
    // the client (~200KB); F8 ships a SIMPLE proxy (length * uniqueness
    // bonus) until that table is generated.
    static void ChooseRarePairs(const std::vector<CStringA>& tokens,
                                size_t kMax,
                                std::vector<std::pair<CStringA, CStringA>>& outPairs);

    // M4 trigrams(t) = { t[i:i+3] | 0 <= i <= len(t)-3 } if len(t) >= 5.
    // Returns canonicalised n-gram strings. Empty if token too short.
    static std::vector<CStringA> Trigrams(const CStringA& token);

    // Trigram key in the DHT = MD4("\xT3" || trigram). The literal "\xT3"
    // is the 4-byte prefix from Cap 4 §4.5 spec (bytes 0x54, 0x33).
    static CUInt128 TrigramKey(const CStringA& trigram);

private:
    CKadV2Tokenizer() = delete;
};

}  // namespace Kademlia
