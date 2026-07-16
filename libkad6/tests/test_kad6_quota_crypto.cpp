// SPDX-License-Identifier: MIT
// Real-provider gate for RFC 9474 RSABSSA-SHA384-PSS-Randomized.
#include "Kad6QuotaCrypto.h"
#include "kad6/kad6_quota.h"
#include "cryptopp/sha.h"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static std::array<Byte, 32> g_pub{};

static bool Sha(const Byte* data, std::size_t size, Byte output[32]) {
    if ((!data && size != 0) || !output) return false;
    static const Byte empty = 0;
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(output, size == 0 ? &empty : data, size);
    return true;
}

static void IdentitySignature(const Byte pub[32], const Byte* message,
                              std::size_t size, Byte output[64]) {
    std::vector<Byte> material(pub, pub + 32);
    material.insert(material.end(), message, message + size);
    Sha(material.data(), material.size(), output);
    material.push_back(0xA5);
    Sha(material.data(), material.size(), output + 32);
}

static bool Sign(const Byte* secret, std::size_t secret_size, const Byte* message,
                 std::size_t size, Byte output[64]) {
    if (secret != nullptr || secret_size != 0) return false;
    IdentitySignature(g_pub.data(), message, size, output);
    return true;
}

static bool VerifyIdentity(const Byte pub[32], const Byte* message,
                           std::size_t size, const Byte signature[64]) {
    Byte expected[64]{};
    IdentitySignature(pub, message, size, expected);
    return Kad6CtEqual(expected, signature, sizeof expected);
}

static Kad6CryptoHooks IdentityHooks() {
    Kad6CryptoHooks hooks{};
    hooks.sha256 = &Sha;
    hooks.ed25519_sign = &Sign;
    hooks.ed25519_verify = &VerifyIdentity;
    return hooks;
}

static std::vector<Byte> Hex(const char* input) {
    std::vector<Byte> output;
    int high = -1;
    for (const char* p = input; *p; ++p) {
        int value = -1;
        if (*p >= '0' && *p <= '9') value = *p - '0';
        else if (*p >= 'a' && *p <= 'f') value = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') value = *p - 'A' + 10;
        else continue;
        if (high < 0) high = value;
        else { output.push_back(static_cast<Byte>((high << 4) | value)); high = -1; }
    }
    if (high >= 0) output.clear();
    return output;
}

static void TestRfc9474A1Verify() {
    // RFC 9474 Appendix A.1, RSABSSA-SHA384-PSS-Randomized.
    const std::vector<Byte> n = Hex(
        "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047"
        "a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be3"
        "35d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c533"
        "77fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a"
        "2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6"
        "685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d"
        "63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413"
        "e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c5"
        "42cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52"
        "a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d78"
        "8a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aa"
        "c8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cf"
        "d1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d00"
        "0a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8"
        "b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b329"
        "48bdead5");
    const std::vector<Byte> prepared = Hex(
        "8417e699b219d583fb6216ae0c53ca0e9723442d02f1d1a34295527e7d929e8b"
        "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b"
        "59f8cfec5fdbb36331372ebefedae7d");
    std::vector<Byte> signature = Hex(
        "191e941c57510e22d29afad257de5ca436d2316221fe870c7cb75205a6c071"
        "c2735aed0bc24c37f3d5bd960ab97a829a508f966bbaed7a82645e65eadaf24ab5e6"
        "d9421392c5b15b7f9b640d34fec512846a3100b80f75ef51064602118c1a77d28d93"
        "8f6efc22041d60159a518d3de7c4d840c9c68109672d743d299d8d2577ef60c19ab4"
        "63c716b3fa75fa56f5735349d414a44df12bf0dd44aa3e10822a651ed4cb0eb6f47c"
        "9bd0ef14a034a7ac2451e30434d513eb22e68b7587a8de9b4e63a059d05c8b22c7c5"
        "1e2cfee2d8bef511412e93c859a13726d87c57d1bc4c2e68ab121562f839c3a3d233"
        "e87ed63c69b7e57525367753fbebcc2a9805a2802659f5888b2c69115bf865559f10"
        "d906c09d048a0d71bfee4b33857393ec2b69e451433496d02c9a7910abb954317720"
        "bbde9e69108eafc3e90bad3d5ca4066d7b1e49013fa04e948104a1dd82b12509ecb1"
        "46e948c54bd8bfb5e6d18127cd1f7a93c3cf9f2d869d5a78878c03fe808a0d799e91"
        "0be6f26d18db61c485b303631d3568368fc41986d08a95ea6ac0592240c19d7b2241"
        "6b9c82ae6241e211dd5610d0baaa9823158f9c32b66318f5529491b7eeadcaa71898"
        "a63bac9d95f4aa548d5e97568d744fc429104e32edd9c87519892a198a30d333d427"
        "739ffb9607b092e910ae37771abf2adb9f63bc058bf58062ad456cb934679795bbdf"
        "cdfad5e0f2");
    CHECK(n.size() == 512 && prepared.size() == 80 && signature.size() == 512,
          "RFC A.1 fixture widths");
    K6QuotaPublicKey key;
    key.modulus = n;
    CKad6QuotaCrypto provider;
    K6QuotaCryptoHooks hooks = provider.Hooks();
    CHECK(hooks.verify(hooks.context, key, prepared.data(), prepared.size(),
                       signature.data(), signature.size()),
          "RFC 9474 A.1 signature verifies");
    signature[0] ^= 1;
    CHECK(!hooks.verify(hooks.context, key, prepared.data(), prepared.size(),
                        signature.data(), signature.size()),
          "RFC A.1 tamper rejected");
}

static void TestRealRoundTrip() {
    CKad6QuotaCrypto provider;
    CHECK(provider.GenerateEphemeral(2048) && provider.Ready(),
          "ephemeral dedicated RSA-2048 test key generated");
    CHECK(!provider.Persistent(), "ephemeral key is marked non-persistent");
    const K6QuotaCryptoHooks quota = provider.Hooks();
    const Kad6CryptoHooks identity = IdentityHooks();
    const std::uint64_t epoch = 1234;

    K6QuotaIssuerCertificate certificate;
    certificate.key = provider.PublicKey();
    for (std::size_t i = 0; i < g_pub.size(); ++i) g_pub[i] = static_cast<Byte>(i + 1);
    certificate.issuer_node_pub = g_pub;
    certificate.policy_id = 9;
    certificate.service_mask = 1u << static_cast<Byte>(K6QuotaService::ExitEd2kFull);
    certificate.valid_from_epoch = epoch;
    certificate.valid_until_epoch = epoch + 1;
    std::vector<Byte> certificate_wire;
    CHECK(SignK6QuotaIssuerCertificate(identity, certificate, certificate_wire) ==
          Kad6Status::Ok, "real-provider issuer certificate signs");
    CHECK(certificate.key_id == provider.KeyId(), "provider and portable key IDs agree");

    K6QuotaToken token;
    token.policy_id = 9;
    token.valid_epoch = epoch;
    token.admission_unit.fill(0xA4);
    token.presentation_context_hash.fill(0x5B);
    K6QuotaBlindState state;
    CHECK(BlindK6QuotaToken(quota, certificate.key, token, state) == Kad6Status::Ok,
          "real PrepareRandomize and Blind");
    std::vector<Byte> blind_signature;
    CHECK(quota.blind_sign(quota.context, certificate.key_id,
          state.blinded_message.data(), state.blinded_message.size(), blind_signature),
          "real blind RSA private operation");
    K6QuotaPresentation presentation;
    CHECK(FinalizeK6QuotaToken(quota, certificate, state, blind_signature, presentation) ==
          Kad6Status::Ok, "real Finalize verifies before returning");
    K6QuotaSpentSet spent(16);
    CHECK(VerifyAndSpendK6Quota(identity, quota, spent, presentation,
          K6QuotaService::ExitEd2kFull, 9, epoch, token.presentation_context_hash, true) ==
          K6QuotaStatus::Ok, "real token verifies and spends");
    CHECK(VerifyAndSpendK6Quota(identity, quota, spent, presentation,
          K6QuotaService::ExitEd2kFull, 9, epoch, token.presentation_context_hash, true) ==
          K6QuotaStatus::AlreadySpent, "real token cannot be spent twice");
}

static void TestPersistence() {
    const char* path = "build\\kad6_quota_rsa_test.dat";
    (void)std::remove(path);
    K6QuotaPublicKey first_key;
    {
        CKad6QuotaCrypto first;
        CHECK(first.Initialize(path, 2048) && first.Persistent(),
              "dedicated RSA key persisted through protected storage");
        first_key = first.PublicKey();
    }
    {
        CKad6QuotaCrypto second;
        CHECK(second.Initialize(path, 2048) && second.Persistent(),
              "dedicated RSA key reloads");
        CHECK(second.PublicKey().modulus == first_key.modulus,
              "reload retains the issuer key identity");
    }
    (void)std::remove(path);
}

int main() {
    TestRfc9474A1Verify();
    TestRealRoundTrip();
    TestPersistence();
    std::printf("test_kad6_quota_crypto: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
