// this file is part of eMule eSE — Tunnel circuit state impl (F4)
#include "stdafx.h"
#include "LiveCircuit.h"
#include "LiveOnionCrypto.h"
#include <vector>   // v0.71 C — OnionDecryptAll scratch buffers

namespace eSELive {

CLiveCircuit::CLiveCircuit(uint32_t circ_id)
    : m_circ_id(circ_id)
    , m_state(CircuitState::Pending)
    , m_born_tick(GetTickCount())
{}

CLiveCircuit::~CLiveCircuit()
{
    WipeKeys();
}

void CLiveCircuit::WipeKeys()
{
    for (auto& h : m_hops) {
        SecureWipe(h.k_send, sizeof h.k_send);
        SecureWipe(h.k_recv, sizeof h.k_recv);
    }
    // v0.71 P3.3 — also wipe the handshake ephemeral if still present.
    if (m_have_ephemeral) {
        SecureWipe(m_ephemeral_priv, sizeof m_ephemeral_priv);
        m_have_ephemeral = false;
    }
}

bool CLiveCircuit::AddHop(const CircuitHop& hop)
{
    if (m_hops.size() >= 3) return false;   // 3-hop is the high-risk max
    m_hops.push_back(hop);
    return true;
}

// Build a 12-byte ChaCha20-Poly1305 nonce from the 64-bit counter for a
// given hop direction. Spec: first 8 bytes = nonce_send/recv LE, last 4 = 0.
// Simple and unambiguous; CryptoPP will accept any 12 bytes.
static void BuildNonce(uint64_t counter, uint8_t out[12])
{
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((counter >> (i * 8)) & 0xFF);
    memset(out + 8, 0, 4);
}

bool CLiveCircuit::OnionEncrypt(const uint8_t* plaintext, size_t plaintextLen,
                                uint8_t outCellPayload[CELL_PAYLOAD_MAX],
                                size_t& outPayloadLen)
{
    if (m_hops.empty()) return false;
    // v8.1 fix: bail BEFORE touching any nonce_send counter if the fully
    // onion-wrapped cell would not fit. Each hop appends a 16-byte AEAD
    // tag. The old code only discovered an overflow mid-loop, by which
    // point the already-processed layers had their nonce_send advanced
    // while the cell was never sent -> the peer's nonce_recv never caught
    // up and every later cell on the circuit failed AEAD auth. Atomic now.
    if (plaintextLen + m_hops.size() * 16 > CELL_PAYLOAD_MAX)
        return false;
    // The deepest message is the plaintext itself, wrapped progressively
    // by each hop in reverse order: layer N..1.
    // For F4 we apply AEAD per layer with a fresh nonce; the AEAD tag
    // (16 B) is appended.
    std::vector<uint8_t> buf(plaintext, plaintext + plaintextLen);

    for (auto it = m_hops.rbegin(); it != m_hops.rend(); ++it) {
        CircuitHop& h = *it;
        uint8_t nonce[12];
        BuildNonce(h.nonce_send++, nonce);
        // ciphertext len = buf.size() + 16 tag
        std::vector<uint8_t> ct(buf.size() + 16);
        if (!AeadEncrypt(h.k_send, nonce, NULL, 0,
                         buf.data(), buf.size(), ct.data()))
            return false;
        buf.swap(ct);
        if (buf.size() > CELL_PAYLOAD_MAX) return false;
    }
    memcpy(outCellPayload, buf.data(), buf.size());
    outPayloadLen = buf.size();
    return true;
}

bool CLiveCircuit::OnionPeelOne(uint8_t hopIdx,
                                const uint8_t* in, size_t inLen,
                                uint8_t* out, size_t& outLen)
{
    if (hopIdx >= m_hops.size()) return false;
    CircuitHop& h = m_hops[hopIdx];
    uint8_t nonce[12];
    BuildNonce(h.nonce_recv++, nonce);
    if (inLen < 16) return false;
    if (!AeadDecrypt(h.k_recv, nonce, NULL, 0, in, inLen, out))
        return false;
    outLen = inLen - 16;
    return true;
}

bool CLiveCircuit::EncryptOneLayer(uint8_t hopIdx,
                                   const uint8_t* in, size_t inLen,
                                   uint8_t* out, size_t& outLen)
{
    if (hopIdx >= m_hops.size()) return false;
    CircuitHop& h = m_hops[hopIdx];
    uint8_t nonce[12];
    BuildNonce(h.nonce_send++, nonce);
    if (!AeadEncrypt(h.k_send, nonce, NULL, 0, in, inLen, out))
        return false;
    outLen = inLen + 16;   // 16-byte AEAD tag appended
    return true;
}

// v0.71 C — peel all registered hops in forward order. Each layer
// strips 16 bytes of AEAD tag. For a 2-hop circuit, inLen of the
// cell payload must be original_plaintext + 32 (2 tags).
bool CLiveCircuit::OnionDecryptAll(const uint8_t* in, size_t inLen,
                                  uint8_t* out, size_t outBufLen, size_t& outLen)
{
    if (m_hops.empty()) return false;
    // Decrypt into a scratch buffer in-place style: alternate between
    // two buffers to avoid in-place AEAD overlap issues.
    std::vector<uint8_t> a(in, in + inLen);
    std::vector<uint8_t> b(inLen);
    bool useA = true;
    for (size_t i = 0; i < m_hops.size(); ++i) {
        const uint8_t* src = useA ? a.data() : b.data();
        uint8_t* dst       = useA ? b.data() : a.data();
        size_t srcLen      = useA ? a.size() : b.size();
        if (srcLen < 16) return false;
        size_t dstLen = 0;
        if (!OnionPeelOne((uint8_t)i, src, srcLen, dst, dstLen))
            return false;
        if (useA) b.resize(dstLen); else a.resize(dstLen);
        useA = !useA;
    }
    // Result is in whichever buffer we wrote LAST (so the "not useA" one,
    // since useA was flipped after the final iteration).
    const std::vector<uint8_t>& finalBuf = useA ? a : b;
    if (finalBuf.size() > outBufLen) return false;
    memcpy(out, finalBuf.data(), finalBuf.size());
    outLen = finalBuf.size();
    return true;
}

// === v8.1.1 Sprint E (E1.4 / B2) — explicit-nonce bulk crypto ===============
// Mirror of EncryptOneLayer / OnionPeelOne / OnionDecryptAll, but the AEAD nonce
// comes from the explicit per-cell nonce_seq (wire) instead of a per-hop counter,
// so a dropped/reordered/retransmitted bulk cell does NOT desync and kill the
// circuit. No nonce_send/nonce_recv counter is touched. Same keys/direction as the
// counter-based twins. Caller-provided buffers (no 505-byte cap) for 16 KB symbols.

bool CLiveCircuit::EncryptOneLayerExplicit(uint8_t hopIdx, uint64_t nonce_seq,
                                           const uint8_t* in, size_t inLen,
                                           uint8_t* out, size_t& outLen)
{
    if (hopIdx >= m_hops.size()) return false;
    CircuitHop& h = m_hops[hopIdx];
    uint8_t nonce[12];
    BuildNonce(nonce_seq, nonce);                 // explicit — counter untouched
    if (!AeadEncrypt(h.k_send, nonce, NULL, 0, in, inLen, out))
        return false;
    outLen = inLen + 16;                          // 16-byte AEAD tag appended
    return true;
}

bool CLiveCircuit::OnionPeelOneExplicit(uint8_t hopIdx, uint64_t nonce_seq,
                                        const uint8_t* in, size_t inLen,
                                        uint8_t* out, size_t& outLen)
{
    if (hopIdx >= m_hops.size()) return false;
    if (inLen < 16) return false;
    CircuitHop& h = m_hops[hopIdx];
    uint8_t nonce[12];
    BuildNonce(nonce_seq, nonce);                 // explicit — counter untouched
    if (!AeadDecrypt(h.k_recv, nonce, NULL, 0, in, inLen, out))
        return false;
    outLen = inLen - 16;
    return true;
}

bool CLiveCircuit::OnionDecryptAllExplicit(uint64_t nonce_seq,
                                           const uint8_t* in, size_t inLen,
                                           uint8_t* out, size_t outBufLen, size_t& outLen)
{
    if (m_hops.empty()) return false;
    std::vector<uint8_t> a(in, in + inLen);
    std::vector<uint8_t> b(inLen);
    bool useA = true;
    for (size_t i = 0; i < m_hops.size(); ++i) {
        const uint8_t* src = useA ? a.data() : b.data();
        uint8_t* dst       = useA ? b.data() : a.data();
        size_t srcLen      = useA ? a.size() : b.size();
        if (srcLen < 16) return false;
        size_t dstLen = 0;
        if (!OnionPeelOneExplicit((uint8_t)i, nonce_seq, src, srcLen, dst, dstLen))
            return false;
        if (useA) b.resize(dstLen); else a.resize(dstLen);
        useA = !useA;
    }
    const std::vector<uint8_t>& finalBuf = useA ? a : b;
    if (finalBuf.size() > outBufLen) return false;
    memcpy(out, finalBuf.data(), finalBuf.size());
    outLen = finalBuf.size();
    return true;
}

}  // namespace eSELive
