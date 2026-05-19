// this file is part of eMule eSE — Kad Search v2 tokenizer impl (F8)
#include "stdafx.h"
#include "KadV2Tokenizer.h"
#include "MD4.h"

namespace Kademlia {

CStringA CKadV2Tokenizer::Canon(const CStringA& t)
{
    // lower + strip diacritics. Simple ASCII-fast-path: a-z direct,
    // mapping a few common Latin-1 supplement diacritics to their ASCII
    // base. UTF-8 multibyte sequences are stripped if their first byte is
    // >= 0x80 and the mapped form isn't in our table.
    //
    // This is intentionally simple — the canonical form must be stable
    // across builds (no locale-dependent libc tolower), so we maintain
    // the table inline.
    CStringA out;
    out.Preallocate(t.GetLength());
    for (int i = 0; i < t.GetLength(); ) {
        unsigned char c = (unsigned char)t[i];
        if (c < 0x80) {
            // ASCII
            if (c >= 'A' && c <= 'Z') out.AppendChar((char)(c - 'A' + 'a'));
            else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out.AppendChar((char)c);
            ++i;
        } else if ((c & 0xE0) == 0xC0 && i + 1 < t.GetLength()) {
            // 2-byte UTF-8 — fold a small set of Latin-1/Latin-Extended-A
            const unsigned char c2 = (unsigned char)t[i + 1];
            const unsigned int cp = ((c & 0x1F) << 6) | (c2 & 0x3F);
            char folded = 0;
            switch (cp) {
                case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
                case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC4: case 0xC5: folded = 'a'; break;
                case 0xE8: case 0xE9: case 0xEA: case 0xEB:
                case 0xC8: case 0xC9: case 0xCA: case 0xCB: folded = 'e'; break;
                case 0xEC: case 0xED: case 0xEE: case 0xEF:
                case 0xCC: case 0xCD: case 0xCE: case 0xCF: folded = 'i'; break;
                case 0xF2: case 0xF3: case 0xF4: case 0xF5: case 0xF6:
                case 0xD2: case 0xD3: case 0xD4: case 0xD5: case 0xD6: folded = 'o'; break;
                case 0xF9: case 0xFA: case 0xFB: case 0xFC:
                case 0xD9: case 0xDA: case 0xDB: case 0xDC: folded = 'u'; break;
                case 0xF1: case 0xD1:                                folded = 'n'; break;
                default: folded = 0; break;
            }
            if (folded) out.AppendChar(folded);
            i += 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < t.GetLength()) {
            // 3-byte UTF-8 — skip entirely (no fold table for CJK etc.)
            i += 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < t.GetLength()) {
            i += 4;
        } else {
            ++i;
        }
    }
    return out;
}

std::vector<CStringA> CKadV2Tokenizer::Tokenize(const CStringA& utf8Input)
{
    std::vector<CStringA> out;
    int start = 0;
    for (int i = 0; i <= utf8Input.GetLength(); ++i) {
        const bool atEnd = (i == utf8Input.GetLength());
        const char c = atEnd ? ' ' : utf8Input[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '.' || c == ',' || c == '-' || c == '_') {
            if (i > start) {
                CStringA piece = utf8Input.Mid(start, i - start);
                CStringA canon = Canon(piece);
                if (canon.GetLength() >= 1) out.push_back(canon);
            }
            start = i + 1;
        }
    }
    return out;
}

CUInt128 CKadV2Tokenizer::CompositeKey2(const CStringA& a, const CStringA& b)
{
    const CStringA ca = Canon(a);
    const CStringA cb = Canon(b);
    const CStringA& lo = (ca < cb) ? ca : cb;
    const CStringA& hi = (ca < cb) ? cb : ca;
    CMD4 md4;
    const uint8 ver = 0x02;          // 2-token composite prefix
    md4.Add(&ver, 1);
    md4.Add((byte*)(LPCSTR)lo, lo.GetLength());
    const uint8 sep = 0x1F;          // unit separator
    md4.Add(&sep, 1);
    md4.Add((byte*)(LPCSTR)hi, hi.GetLength());
    md4.Finish();
    CUInt128 out;
    out.SetValueBE(md4.GetHash());
    return out;
}

void CKadV2Tokenizer::ChooseRarePairs(const std::vector<CStringA>& tokens,
                                     size_t kMax,
                                     std::vector<std::pair<CStringA, CStringA>>& outPairs)
{
    outPairs.clear();
    const size_t n = tokens.size();
    if (n < 2 || kMax == 0) return;
    // Heuristic: pair "rarity" ~ len(a) * len(b). Cap to kMax.
    struct Pair { size_t i, j; size_t score; };
    std::vector<Pair> pairs;
    for (size_t i = 0; i < n; ++i)
        for (size_t j = i + 1; j < n; ++j)
            pairs.push_back({ i, j, (size_t)tokens[i].GetLength() * (size_t)tokens[j].GetLength() });
    // sort by score DESC
    std::sort(pairs.begin(), pairs.end(),
              [](const Pair& a, const Pair& b) { return a.score > b.score; });
    const size_t take = (kMax < pairs.size()) ? kMax : pairs.size();
    for (size_t i = 0; i < take; ++i)
        outPairs.push_back({ tokens[pairs[i].i], tokens[pairs[i].j] });
}

std::vector<CStringA> CKadV2Tokenizer::Trigrams(const CStringA& token)
{
    std::vector<CStringA> out;
    if (token.GetLength() < 5) return out;
    const int n = token.GetLength();
    for (int i = 0; i + 3 <= n; ++i)
        out.push_back(token.Mid(i, 3));
    return out;
}

CUInt128 CKadV2Tokenizer::TrigramKey(const CStringA& trigram)
{
    CMD4 md4;
    // "\xT3" prefix = 0x54 0x33 per Cap 4 §4.5 wire format
    const uint8 prefix[2] = { 0x54, 0x33 };
    md4.Add(prefix, 2);
    md4.Add((byte*)(LPCSTR)trigram, trigram.GetLength());
    md4.Finish();
    CUInt128 out;
    out.SetValueBE(md4.GetHash());
    return out;
}

}  // namespace Kademlia
