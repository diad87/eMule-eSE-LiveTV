// RFC 9474 RSABSSA-SHA384-PSS-Randomized provider for Kad6 admission quota.
// MFC-free: it can be linked by the application and by the standalone vector
// gate.  The RSA signing key is dedicated to this one encoding profile.
#pragma once

#include "kad6/kad6_quota.h"

#include <memory>
#include <string>

class CKad6QuotaCrypto {
public:
    CKad6QuotaCrypto();
    ~CKad6QuotaCrypto();

    CKad6QuotaCrypto(const CKad6QuotaCrypto&) = delete;
    CKad6QuotaCrypto& operator=(const CKad6QuotaCrypto&) = delete;

    // Loads a fixed-size DPAPI/0600 blob or generates and persists a dedicated
    // RSA key. Production uses 4096; 2048 is accepted for fast test fixtures.
    bool Initialize(const std::string& storage_path, unsigned modulus_bits = 4096);
    bool GenerateEphemeral(unsigned modulus_bits = 2048);

    bool Ready() const noexcept;
    bool Persistent() const noexcept;
    const kad6::K6QuotaPublicKey& PublicKey() const noexcept;
    const kad6::Hash32& KeyId() const noexcept;
    kad6::K6QuotaCryptoHooks Hooks() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    static bool Blind(void*, const kad6::K6QuotaPublicKey&, const kad6::Byte*,
                      std::size_t, std::vector<kad6::Byte>&,
                      std::vector<kad6::Byte>&, std::vector<kad6::Byte>&);
    static bool BlindSign(void*, const kad6::Hash32&, const kad6::Byte*,
                          std::size_t, std::vector<kad6::Byte>&);
    static bool Finalize(void*, const kad6::K6QuotaPublicKey&, const kad6::Byte*,
                         std::size_t, const kad6::Byte*, std::size_t,
                         const kad6::Byte*, std::size_t,
                         std::vector<kad6::Byte>&);
    static bool Verify(void*, const kad6::K6QuotaPublicKey&, const kad6::Byte*,
                       std::size_t, const kad6::Byte*, std::size_t);
};
