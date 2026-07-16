// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include "edge/krp_p4_crypto.h"

#if !defined(RELAYEDGE_DISABLE_ED25519)
#include "../../cryptopp/xed25519.h"
#endif

#include <algorithm>
#include <fstream>
#include <iterator>
#include <limits>

namespace relayedge {
namespace {

int HexNibble(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

} // namespace

relay::RelayStatus LoadKrpAuthToken(const char* path, KrpAuthToken& token) noexcept {
    token.fill(0);
    if (path == nullptr || *path == '\0') return relay::RelayStatus::InvalidArgument;
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) return relay::RelayStatus::AuthFailed;
        std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        if (text.size() > 128) return relay::RelayStatus::TooLarge;
        text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char c) {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }), text.end());
        if (text.size() != token.size() * 2) return relay::RelayStatus::Malformed;
        for (std::size_t i = 0; i < token.size(); ++i) {
            const int high = HexNibble(text[i * 2]);
            const int low = HexNibble(text[i * 2 + 1]);
            if (high < 0 || low < 0) { token.fill(0); return relay::RelayStatus::Malformed; }
            token[i] = static_cast<relay::Byte>((high << 4) | low);
        }
        const bool all_zero = std::all_of(token.begin(), token.end(), [](relay::Byte b) { return b == 0; });
        if (all_zero) { token.fill(0); return relay::RelayStatus::AuthFailed; }
        return relay::RelayStatus::Ok;
    } catch (...) {
        token.fill(0);
        return relay::RelayStatus::AuthFailed;
    }
}

relay::RelayStatus ComputeKrpTokenProof(const KrpAuthToken& token,
                                         const std::vector<relay::Byte>& transcript,
                                         const relay::KrpAuthSignature& signature,
                                         relay::KrpTokenProof& proof) noexcept {
    proof.fill(0);
    if (transcript.empty() || transcript.size() > relay::kKrpMaxAuthTranscriptSize)
        return relay::RelayStatus::InvalidArgument;
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD copied = 0;
    NTSTATUS result = BCryptOpenAlgorithmProvider(&algorithm,
        BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (BCRYPT_SUCCESS(result))
        result = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
            &copied, 0);
    std::vector<relay::Byte> object;
    if (BCRYPT_SUCCESS(result)) {
        try { object.resize(object_size); }
        catch (...) { result = static_cast<NTSTATUS>(-1); }
    }
    if (BCRYPT_SUCCESS(result))
        result = BCryptCreateHash(algorithm, &hash, object.data(), object_size,
            const_cast<PUCHAR>(token.data()), static_cast<ULONG>(token.size()), 0);
    if (BCRYPT_SUCCESS(result))
        result = BCryptHashData(hash, const_cast<PUCHAR>(transcript.data()),
            static_cast<ULONG>(transcript.size()), 0);
    if (BCRYPT_SUCCESS(result))
        result = BCryptHashData(hash, const_cast<PUCHAR>(signature.data()),
            static_cast<ULONG>(signature.size()), 0);
    if (BCRYPT_SUCCESS(result))
        result = BCryptFinishHash(hash, proof.data(),
            static_cast<ULONG>(proof.size()), 0);
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!object.empty()) SecureZeroMemory(object.data(), object.size());
    if (!BCRYPT_SUCCESS(result)) {
        proof.fill(0);
        return relay::RelayStatus::AuthFailed;
    }
    return relay::RelayStatus::Ok;
}

bool ConstantTimeEqual(const relay::KrpTokenProof& left,
                       const relay::KrpTokenProof& right) noexcept {
    relay::Byte difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i)
        difference = static_cast<relay::Byte>(difference | (left[i] ^ right[i]));
    return difference == 0;
}

relay::RelayStatus SecureRandom(relay::Byte* output, std::size_t size) noexcept {
    if (output == nullptr || size == 0 || size > (std::numeric_limits<ULONG>::max)())
        return relay::RelayStatus::InvalidArgument;
    return BCRYPT_SUCCESS(BCryptGenRandom(nullptr, output, static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG)) ? relay::RelayStatus::Ok : relay::RelayStatus::InvalidState;
}

bool Ed25519IdentityVerifier::Verify(const relay::NodeId& public_node_id,
                                     const relay::Byte* message,
                                     std::size_t message_size,
                                     const relay::KrpAuthSignature& signature) noexcept {
    if (message == nullptr || message_size == 0) return false;
#if defined(RELAYEDGE_DISABLE_ED25519)
    (void)public_node_id;
    (void)signature;
    return false;
#else
    try {
        CryptoPP::ed25519Verifier verifier(public_node_id.data());
        return verifier.VerifyMessage(message, message_size, signature.data(), signature.size());
    } catch (...) {
        return false;
    }
#endif
}

} // namespace relayedge
