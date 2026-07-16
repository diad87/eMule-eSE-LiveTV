#include "stdafx.h"
#include "Kad6CryptoHost.h"

#include "LiveCrypto.h"
#include "NodeIdentity.h"
#include "../cryptopp/hmac.h"
#include "../cryptopp/osrng.h"
#include "../cryptopp/sha.h"

namespace {

bool HostHmacSha256(const kad6::Byte* key, std::size_t keyLength,
                    const kad6::Byte* message, std::size_t messageLength,
                    kad6::Byte output[kad6::kMacSize]) {
    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, keyLength);
        hmac.CalculateDigest(output, message, messageLength);
        return true;
    } catch (...) {
        return false;
    }
}

bool HostSha256(const kad6::Byte* message, std::size_t messageLength,
                kad6::Byte output[kad6::kHash32Size]) {
    try {
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(output, message, messageLength);
        return true;
    } catch (...) {
        return false;
    }
}

bool HostEd25519Sign(const kad6::Byte* secret, std::size_t secretLength,
                     const kad6::Byte* message, std::size_t messageLength,
                     kad6::Byte signature[kad6::kEd25519SigSize]) {
    // libkad6 forwards an opaque secret handle. The eMule host intentionally
    // passes nullptr/0 so raw NodeIdentity private bytes never leave their
    // DPAPI-backed owner module.
    if (secret != nullptr || secretLength != 0)
        return false;
    return eSELive::NodeIdentityIsPersistent() &&
           eSELive::NodeIdentitySign(message, messageLength, signature);
}

bool HostEd25519Verify(const kad6::Byte pub[kad6::kEd25519PubSize],
                       const kad6::Byte* message, std::size_t messageLength,
                       const kad6::Byte signature[kad6::kEd25519SigSize]) {
    return eSELive::VerifySignature(pub, message, messageLength, signature);
}

bool HostRandom(kad6::Byte* output, std::size_t length) {
    try {
        CryptoPP::AutoSeededRandomPool random;
        random.GenerateBlock(output, length);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

kad6::Kad6CryptoHooks MakeKad6HostCryptoHooks() {
    kad6::Kad6CryptoHooks hooks;
    hooks.hmac_sha256 = &HostHmacSha256;
    hooks.sha256 = &HostSha256;
    hooks.ed25519_sign = &HostEd25519Sign;
    hooks.ed25519_verify = &HostEd25519Verify;
    hooks.random_bytes = &HostRandom;
    return hooks;
}
