// this file is part of eMule eSE — Live onion crypto primitives impl (F2)
#include "stdafx.h"
#include "LiveOnionCrypto.h"

#include "cryptopp/osrng.h"
#include "cryptopp/xed25519.h"
#include "cryptopp/chachapoly.h"
#include "cryptopp/hkdf.h"
#include "cryptopp/sha.h"
#include "cryptopp/secblock.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace eSELive {

namespace {

// Single AutoSeededRandomPool per thread (CryptoPP recommendation; uses
// OS entropy under the hood).
CryptoPP::AutoSeededRandomPool& Rng()
{
    static thread_local CryptoPP::AutoSeededRandomPool s_rng;
    return s_rng;
}

}  // namespace

// === X25519 ==============================================================

bool X25519GenerateKeypair(uint8_t pubOut[32], uint8_t privOut[32])
{
    if (!pubOut || !privOut) return false;
    try {
        CryptoPP::x25519 dh;
        dh.GeneratePrivateKey(Rng(), privOut);
        dh.GeneratePublicKey(Rng(), privOut, pubOut);
        return true;
    } catch (...) {
        return false;
    }
}

bool X25519SharedSecret(const uint8_t pubPeer[32], const uint8_t privSelf[32], uint8_t sharedOut[32])
{
    if (!pubPeer || !privSelf || !sharedOut) return false;
    try {
        CryptoPP::x25519 dh;
        // validateOtherPublicKey=true rejects small-order points (defence
        // against curve-twist + small-subgroup attacks).
        return dh.Agree(sharedOut, privSelf, pubPeer, true);
    } catch (...) {
        return false;
    }
}

// === ChaCha20-Poly1305 ===================================================

bool AeadEncrypt(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* plaintext, size_t plaintextLen,
                 uint8_t* ciphertextOut)
{
    if (!key || !nonce || !ciphertextOut) return false;
    if (plaintextLen > 0 && !plaintext) return false;
    if (aadLen > 0 && !aad) return false;
    try {
        CryptoPP::ChaCha20Poly1305::Encryption enc;
        enc.SetKeyWithIV(key, 32, nonce, 12);
        enc.SpecifyDataLengths(aadLen, plaintextLen, 0);
        enc.EncryptAndAuthenticate(
            ciphertextOut,
            ciphertextOut + plaintextLen,   // tag follows ciphertext
            16,                              // tag len
            nonce, 12,
            aad, aadLen,
            plaintext, plaintextLen);
        return true;
    } catch (...) {
        return false;
    }
}

bool AeadDecrypt(const uint8_t key[32],
                 const uint8_t nonce[12],
                 const uint8_t* aad, size_t aadLen,
                 const uint8_t* ciphertext, size_t ciphertextLen,
                 uint8_t* plaintextOut)
{
    if (!key || !nonce) return false;
    if (ciphertextLen < 16) return false;          // must hold the tag
    const size_t ptLen = ciphertextLen - 16;
    if (ptLen > 0 && !plaintextOut) return false;
    if (aadLen > 0 && !aad) return false;
    if (!ciphertext) return false;
    try {
        CryptoPP::ChaCha20Poly1305::Decryption dec;
        dec.SetKeyWithIV(key, 32, nonce, 12);
        dec.SpecifyDataLengths(aadLen, ptLen, 0);
        return dec.DecryptAndVerify(
            plaintextOut,
            ciphertext + ptLen,   // tag location
            16,
            nonce, 12,
            aad, aadLen,
            ciphertext, ptLen);
    } catch (...) {
        return false;
    }
}

// === HKDF-SHA-256 ========================================================

bool Hkdf(const uint8_t* ikm, size_t ikmLen,
          const uint8_t* salt, size_t saltLen,
          const uint8_t* info, size_t infoLen,
          uint8_t* okmOut, size_t okmLen)
{
    if (!ikm || !okmOut) return false;
    try {
        CryptoPP::HKDF<CryptoPP::SHA256> kdf;
        kdf.DeriveKey(
            okmOut, okmLen,
            ikm, ikmLen,
            salt, saltLen,
            info, infoLen);
        return true;
    } catch (...) {
        return false;
    }
}

// === Random ==============================================================

void SecureRandomBytes(uint8_t* out, size_t outLen)
{
    if (!out || outLen == 0) return;
    Rng().GenerateBlock(out, outLen);
}

// === Memory wipe =========================================================

void SecureWipe(void* p, size_t len)
{
    if (!p || len == 0) return;
    // CryptoPP's SecureWipeBuffer for unsigned char — the standard
    // anti-DCE-of-memset idiom.
    CryptoPP::SecureWipeBuffer(static_cast<unsigned char*>(p), len);
}

}  // namespace eSELive
