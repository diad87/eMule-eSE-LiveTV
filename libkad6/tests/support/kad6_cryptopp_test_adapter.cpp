// SPDX-License-Identifier: MIT
#include "kad6_cryptopp_test_adapter.h"

#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/sha.h"
#include "cryptopp/xed25519.h"

#include <cstddef>

namespace {

const kad6::Byte* NonNull(const kad6::Byte* data, std::size_t size) noexcept {
    static const kad6::Byte empty = 0;
    return size == 0 ? &empty : data;
}

bool HmacSha256(const kad6::Byte* key, std::size_t keyLen,
                const kad6::Byte* msg, std::size_t msgLen,
                kad6::Byte mac[kad6::kMacSize]) {
    try {
        if ((!key && keyLen != 0) || (!msg && msgLen != 0) || !mac) return false;
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(NonNull(key, keyLen), keyLen);
        hmac.CalculateDigest(mac, NonNull(msg, msgLen), msgLen);
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

bool Sha256(const kad6::Byte* msg, std::size_t msgLen,
            kad6::Byte out[kad6::kHash32Size]) {
    try {
        if ((!msg && msgLen != 0) || !out) return false;
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(out, NonNull(msg, msgLen), msgLen);
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

bool Ed25519Sign(const kad6::Byte* secret, std::size_t secretLen,
                 const kad6::Byte* msg, std::size_t msgLen,
                 kad6::Byte sig[kad6::kEd25519SigSize]) {
    try {
        if (!secret || (secretLen != 32 && secretLen != 64) ||
            (!msg && msgLen != 0) || !sig) return false;
        CryptoPP::AutoSeededRandomPool rng;
        if (secretLen == 64) {
            // Explicit host convention: seed[32] || public[32].
            CryptoPP::ed25519Signer signer(secret + 32, secret);
            return signer.SignMessage(rng, NonNull(msg, msgLen), msgLen, sig) == 64;
        }
        CryptoPP::ed25519Signer signer(secret);
        return signer.SignMessage(rng, NonNull(msg, msgLen), msgLen, sig) == 64;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

bool Ed25519Verify(const kad6::Byte pub[kad6::kEd25519PubSize],
                   const kad6::Byte* msg, std::size_t msgLen,
                   const kad6::Byte sig[kad6::kEd25519SigSize]) {
    try {
        if (!pub || (!msg && msgLen != 0) || !sig) return false;
        CryptoPP::ed25519Verifier verifier(pub);
        return verifier.VerifyMessage(NonNull(msg, msgLen), msgLen, sig, 64);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

bool RandomBytes(kad6::Byte* out, std::size_t size) {
    try {
        if (!out && size != 0) return false;
        CryptoPP::AutoSeededRandomPool rng;
        if (size != 0) rng.GenerateBlock(out, size);
        return true;
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}

} // namespace

kad6::Kad6CryptoHooks MakeKad6CryptoPpTestHooks() {
    kad6::Kad6CryptoHooks hooks{};
    hooks.hmac_sha256 = &HmacSha256;
    hooks.sha256 = &Sha256;
    hooks.ed25519_sign = &Ed25519Sign;
    hooks.ed25519_verify = &Ed25519Verify;
    hooks.random_bytes = &RandomBytes;
    return hooks;
}
