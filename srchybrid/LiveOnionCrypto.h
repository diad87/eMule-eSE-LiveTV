// this file is part of eMule eSE — Live onion crypto primitives (F2)
//
// Wrappers around CryptoPP for the privacy layer:
//   - X25519 ECDH for tunnel handshake (ntor-style, Cap 4 §4.6 thesis)
//   - ChaCha20-Poly1305 AEAD for per-layer onion encryption + record sealing
//   - HKDF-SHA-256 for key derivation
//
// All primitives are deterministic given inputs; randomness comes from
// CryptoPP::AutoSeededRandomPool (system entropy).
#pragma once

namespace eSELive {

// === X25519 — Diffie-Hellman key exchange ================================
// Used by tunnel handshake (ntor-style, see LiveTunnel in F4).
// Curve25519 keys are 32 bytes each. Shared secret is 32 bytes.

// Generate ephemeral keypair. Caller MUST clear privOut after use.
// Returns true on success.
bool X25519GenerateKeypair(uint8_t pubOut[32], uint8_t privOut[32]);

// Compute shared secret. Returns true on success.
// pubPeer = the OTHER party's public key. privSelf = our private key.
bool X25519SharedSecret(const uint8_t pubPeer[32], const uint8_t privSelf[32], uint8_t sharedOut[32]);

// === ChaCha20-Poly1305 AEAD =============================================
// Per-layer onion encryption, sealed records, stream session keys.
// Nonce is 12 bytes. Tag is 16 bytes appended after ciphertext.

// ENCRYPT: ciphertextOut = AEAD-Encrypt(key, nonce, aad, plaintext)
// ciphertextOut must hold plaintextLen + 16 bytes (tag).
// Returns true on success.
bool AeadEncrypt(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* plaintext, size_t plaintextLen,
                 uint8_t* ciphertextOut /* plaintextLen + 16 */);

// DECRYPT: plaintextOut = AEAD-Decrypt(key, nonce, aad, ciphertext)
// ciphertextLen MUST include the 16-byte tag. plaintextOut needs
// ciphertextLen - 16 bytes. Returns true iff the tag verifies.
bool AeadDecrypt(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* ciphertext, size_t ciphertextLen,
                 uint8_t* plaintextOut /* ciphertextLen - 16 */);

// === HKDF-SHA-256 ========================================================
// Derive symmetric keys from shared secrets.
// `info` is a context string (e.g. "ese-tunnel-send-key-v1").

bool Hkdf(const uint8_t* ikm, size_t ikmLen,
          const uint8_t* salt, size_t saltLen,
          const uint8_t* info, size_t infoLen,
          uint8_t* okmOut, size_t okmLen);

// === Random ==============================================================
// Fill `out` with cryptographically secure random bytes.
void SecureRandomBytes(uint8_t* out, size_t outLen);

// === Memory hygiene ======================================================
// Zero `len` bytes at `p` in a way the compiler cannot optimise away.
// Use this for any secret (private keys, session keys, plaintext after AEAD).
void SecureWipe(void* p, size_t len);

}  // namespace eSELive
