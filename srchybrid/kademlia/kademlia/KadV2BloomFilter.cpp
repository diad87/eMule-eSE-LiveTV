// this file is part of eMule eSE — Kad Search v2 Bloom filter impl (M5)
#include "stdafx.h"
#include "KadV2BloomFilter.h"

namespace Kademlia
{

CKadV2BloomFilter::CKadV2BloomFilter()
    : m_uInserted(0)
{
    memset(m_bits, 0, sizeof m_bits);
}

void CKadV2BloomFilter::Clear()
{
    memset(m_bits, 0, sizeof m_bits);
    m_uInserted = 0;
}

void CKadV2BloomFilter::Add(const char* token, size_t tokenLen)
{
    uint32 pos[KADV2_BLOOM_NUM_HASHES];
    DeriveBitPositions(token, tokenLen, pos);
    for (int i = 0; i < KADV2_BLOOM_NUM_HASHES; ++i) {
        const uint32 p = pos[i];
        m_bits[p >> 3] |= (uint8)(1u << (p & 7u));
    }
    ++m_uInserted;
}

bool CKadV2BloomFilter::ProbablyContains(const char* token, size_t tokenLen) const
{
    uint32 pos[KADV2_BLOOM_NUM_HASHES];
    DeriveBitPositions(token, tokenLen, pos);
    for (int i = 0; i < KADV2_BLOOM_NUM_HASHES; ++i) {
        const uint32 p = pos[i];
        if ((m_bits[p >> 3] & (uint8)(1u << (p & 7u))) == 0)
            return false;
    }
    return true;
}

void CKadV2BloomFilter::DeriveBitPositions(const char* token, size_t tokenLen, uint32 outPos[KADV2_BLOOM_NUM_HASHES]) const
{
    // Total bits in the filter
    const uint32 numBits = (uint32)(KADV2_BLOOM_SIZE_BYTES * 8u);
    // 4 independent positions via 4 distinct seeds. Standard Bloom-with-MurmurHash3
    // double-hashing optimisation: derive any number of hashes from just two real
    // MurmurHash3 calls (h1 + i*h2). We compute two with seeds 0x9747b28c and
    // 0xc6a4a793, then linear-combine for the 4 positions.
    const uint32 h1 = MurmurHash3(token, tokenLen, 0x9747b28cu);
    const uint32 h2 = MurmurHash3(token, tokenLen, 0xc6a4a793u);
    for (uint32 i = 0; i < KADV2_BLOOM_NUM_HASHES; ++i)
        outPos[i] = (h1 + i * h2) % numBits;
}

bool CKadV2BloomFilter::SerializeTo(uint8* out, size_t outLen) const
{
    if (out == NULL || outLen < WireSize()) return false;
    memcpy(out, m_bits, KADV2_BLOOM_SIZE_BYTES);
    // Append insertedCount as little-endian uint64.
    uint64 v = m_uInserted;
    for (size_t i = 0; i < 8; ++i) {
        out[KADV2_BLOOM_SIZE_BYTES + i] = (uint8)(v & 0xFF);
        v >>= 8;
    }
    return true;
}

bool CKadV2BloomFilter::DeserializeFrom(const uint8* in, size_t inLen)
{
    if (in == NULL || inLen < WireSize()) return false;
    memcpy(m_bits, in, KADV2_BLOOM_SIZE_BYTES);
    uint64 v = 0;
    for (size_t i = 0; i < 8; ++i)
        v |= ((uint64)in[KADV2_BLOOM_SIZE_BYTES + i]) << (i * 8);
    m_uInserted = v;
    return true;
}

// MurmurHash3 x86 32-bit — reference impl by Austin Appleby (public domain).
// Trimmed to the bare minimum we need: no platform/alignment specialisation.
uint32 CKadV2BloomFilter::MurmurHash3(const char* data, size_t len, uint32 seed)
{
    const uint32 c1 = 0xcc9e2d51u;
    const uint32 c2 = 0x1b873593u;
    uint32 h1 = seed;

    const size_t nblocks = len / 4;
    const uint8* bytes = (const uint8*)data;

    for (size_t i = 0; i < nblocks; ++i) {
        uint32 k1 = (uint32)bytes[i * 4 + 0]
                  | ((uint32)bytes[i * 4 + 1] << 8)
                  | ((uint32)bytes[i * 4 + 2] << 16)
                  | ((uint32)bytes[i * 4 + 3] << 24);
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5u + 0xe6546b64u;
    }

    uint32 k1 = 0;
    const uint8* tail = bytes + nblocks * 4;
    switch (len & 3) {
        case 3: k1 ^= ((uint32)tail[2]) << 16;
            // fallthrough
        case 2: k1 ^= ((uint32)tail[1]) << 8;
            // fallthrough
        case 1: k1 ^= ((uint32)tail[0]);
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    h1 ^= (uint32)len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6bu;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35u;
    h1 ^= h1 >> 16;
    return h1;
}

}  // namespace Kademlia
