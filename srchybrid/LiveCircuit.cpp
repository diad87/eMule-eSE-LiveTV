// this file is part of eMule eSE — Tunnel circuit state impl (F4)
#include "stdafx.h"
#include "LiveCircuit.h"
#include "LiveOnionCrypto.h"

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

}  // namespace eSELive
