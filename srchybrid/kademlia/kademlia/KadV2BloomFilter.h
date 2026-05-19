// this file is part of eMule eSE — Kad Search v2 Bloom filter (M5)
//
// Cap 4 §4.6 monograph. 32 KB Bloom filter with 4 MurmurHash3 derivations.
// FPR ~1.2 % at 50 000 inserts.
#pragma once

#include "KadV2Defines.h"

namespace Kademlia
{

class CKadV2BloomFilter
{
public:
    CKadV2BloomFilter();

    // Insert / query
    void Add(const char* token, size_t tokenLen);
    void Add(LPCSTR token) { Add(token, strlen(token)); }
    bool ProbablyContains(const char* token, size_t tokenLen) const;
    bool ProbablyContains(LPCSTR token) const { return ProbablyContains(token, strlen(token)); }

    void Clear();
    uint64 InsertedCount() const { return m_uInserted; }

    // Wire serialization. Format: raw 32 KB bitstream + 8 B insertedCount
    // suffix (total 32 776 B). The receiver uses insertedCount to detect
    // saturated filters (FPR explodes near 200 000+ items — silently degrade).
    bool SerializeTo(uint8* out, size_t outLen) const;
    bool DeserializeFrom(const uint8* in, size_t inLen);
    static size_t WireSize() { return KADV2_BLOOM_SIZE_BYTES + sizeof(uint64); }

private:
    // 4 hash values derived from MurmurHash3 of (token, seed_i).
    // Returns 4 bit positions into m_bits[].
    void DeriveBitPositions(const char* token, size_t tokenLen, uint32 outPos[KADV2_BLOOM_NUM_HASHES]) const;

    // Standard MurmurHash3 32-bit. Inline because it's tight and only used here.
    static uint32 MurmurHash3(const char* data, size_t len, uint32 seed);

    uint8  m_bits[KADV2_BLOOM_SIZE_BYTES];
    uint64 m_uInserted;
};

}  // namespace Kademlia
