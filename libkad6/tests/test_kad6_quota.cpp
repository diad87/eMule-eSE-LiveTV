// SPDX-License-Identifier: MIT
// K6-8 anonymous quota: canonical wire formats, issuer limiting, blind-token
// lifecycle and fail-closed single-use verification.  The arithmetic oracle is
// deliberately fake here; the Crypto++ RFC 9474 adapter has separate vectors.
#include "kad6/kad6_quota.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace kad6;

static int g_pass = 0;
static int g_fail = 0;
#define CHECK(c, m) do { if (c) ++g_pass; else { ++g_fail; \
    std::printf("  FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); } } while (0)

static std::array<Byte, 32> g_signing_pub{};

static bool FakeSha(const Byte* data, std::size_t size, Byte out[32]) {
    if ((!data && size != 0) || !out) return false;
    std::uint32_t state = 2166136261u;
    for (std::size_t i = 0; i < size; ++i) state = (state ^ data[i]) * 16777619u;
    for (std::size_t i = 0; i < 32; ++i) {
        state = state * 1664525u + 1013904223u + static_cast<std::uint32_t>(i);
        out[i] = static_cast<Byte>(state >> 24);
    }
    return true;
}

static void FakeIdentitySignature(const Byte pub[32], const Byte* message,
                                  std::size_t size, Byte signature[64]) {
    std::vector<Byte> input(pub, pub + 32);
    if (size) input.insert(input.end(), message, message + size);
    (void)FakeSha(input.data(), input.size(), signature);
    input.push_back(0xA5);
    (void)FakeSha(input.data(), input.size(), signature + 32);
}

static bool FakeIdentitySign(const Byte* secret, std::size_t secret_size,
                             const Byte* message, std::size_t size,
                             Byte signature[64]) {
    if (secret != nullptr || secret_size != 0 || (!message && size != 0) || !signature)
        return false;
    FakeIdentitySignature(g_signing_pub.data(), message, size, signature);
    return true;
}

static bool FakeIdentityVerify(const Byte pub[32], const Byte* message,
                               std::size_t size, const Byte signature[64]) {
    Byte expected[64]{};
    FakeIdentitySignature(pub, message, size, expected);
    return Kad6CtEqual(expected, signature, sizeof expected);
}

static Kad6CryptoHooks IdentityHooks() {
    Kad6CryptoHooks hooks{};
    hooks.sha256 = &FakeSha;
    hooks.ed25519_sign = &FakeIdentitySign;
    hooks.ed25519_verify = &FakeIdentityVerify;
    return hooks;
}

struct FakeQuotaContext {
    std::size_t width = 256;
    bool fail = false;
};

static void FakeQuotaSignature(const K6QuotaPublicKey& key, const Byte* prepared,
                               std::size_t prepared_size, std::vector<Byte>& out) {
    std::vector<Byte> material(key.modulus.begin(), key.modulus.end());
    material.insert(material.end(), prepared, prepared + prepared_size);
    Byte digest[32]{};
    (void)FakeSha(material.data(), material.size(), digest);
    out.resize(key.modulus.size());
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<Byte>(digest[i % sizeof digest] ^ static_cast<Byte>(i));
}

static bool FakeBlind(void* opaque, const K6QuotaPublicKey& key,
                      const Byte* message, std::size_t message_size,
                      std::vector<Byte>& prepared, std::vector<Byte>& blinded,
                      std::vector<Byte>& inverse) {
    FakeQuotaContext* context = static_cast<FakeQuotaContext*>(opaque);
    if (!context || context->fail || (!message && message_size != 0) ||
        key.modulus.size() != context->width)
        return false;
    prepared.resize(kK6QuotaRandomizerSize, 0x5C);
    prepared.insert(prepared.end(), message, message + message_size);
    blinded.assign(context->width, 0xB7);
    inverse.assign(context->width, 0x49);
    return true;
}

static bool FakeBlindSign(void* opaque, const Hash32&, const Byte* blinded,
                          std::size_t blinded_size, std::vector<Byte>& output) {
    FakeQuotaContext* context = static_cast<FakeQuotaContext*>(opaque);
    if (!context || context->fail || !blinded || blinded_size != context->width)
        return false;
    output.resize(blinded_size);
    for (std::size_t i = 0; i < blinded_size; ++i)
        output[i] = static_cast<Byte>(blinded[i] ^ 0xA6);
    return true;
}

static bool FakeFinalize(void* opaque, const K6QuotaPublicKey& key,
                         const Byte* prepared, std::size_t prepared_size,
                         const Byte* blind_signature, std::size_t blind_signature_size,
                         const Byte* inverse, std::size_t inverse_size,
                         std::vector<Byte>& signature) {
    FakeQuotaContext* context = static_cast<FakeQuotaContext*>(opaque);
    if (!context || context->fail || !prepared || !blind_signature || !inverse ||
        prepared_size < kK6QuotaRandomizerSize + 1 ||
        prepared_size != K6QuotaPreparedSize(prepared[kK6QuotaRandomizerSize]) ||
        blind_signature_size != context->width || inverse_size != context->width)
        return false;
    FakeQuotaSignature(key, prepared, prepared_size, signature);
    return true;
}

static bool FakeVerify(void* opaque, const K6QuotaPublicKey& key,
                       const Byte* prepared, std::size_t prepared_size,
                       const Byte* signature, std::size_t signature_size) {
    FakeQuotaContext* context = static_cast<FakeQuotaContext*>(opaque);
    if (!context || context->fail || !prepared || !signature ||
        prepared_size < kK6QuotaRandomizerSize + 1 ||
        prepared_size != K6QuotaPreparedSize(prepared[kK6QuotaRandomizerSize]) ||
        signature_size != context->width)
        return false;
    std::vector<Byte> expected;
    FakeQuotaSignature(key, prepared, prepared_size, expected);
    return Kad6CtEqual(expected.data(), signature, expected.size());
}

static K6QuotaCryptoHooks QuotaHooks(FakeQuotaContext& context) {
    K6QuotaCryptoHooks hooks{};
    hooks.context = &context;
    hooks.blind = &FakeBlind;
    hooks.blind_sign = &FakeBlindSign;
    hooks.finalize = &FakeFinalize;
    hooks.verify = &FakeVerify;
    return hooks;
}

static K6QuotaIssuerCertificate Certificate(std::uint64_t epoch,
                                             const Kad6CryptoHooks& identity) {
    K6QuotaIssuerCertificate certificate;
    certificate.key.modulus.assign(256, 0xA5);
    certificate.key.modulus.back() |= 1;
    for (std::size_t i = 0; i < certificate.issuer_node_pub.size(); ++i)
        certificate.issuer_node_pub[i] = static_cast<Byte>(0x20 + i);
    g_signing_pub = certificate.issuer_node_pub;
    certificate.policy_id = 7;
    certificate.service_mask = static_cast<Byte>(1u <<
        static_cast<Byte>(K6QuotaService::ExitEd2kFull));
    certificate.valid_from_epoch = epoch;
    certificate.valid_until_epoch = epoch + 1;
    std::vector<Byte> encoded;
    CHECK(SignK6QuotaIssuerCertificate(identity, certificate, encoded) == Kad6Status::Ok,
          "issuer certificate signs");
    return certificate;
}

static K6QuotaToken Token(std::uint64_t epoch, const Hash32& issuer_key_id,
                          std::uint16_t slot = 4) {
    K6QuotaToken token;
    token.policy_id = 7;
    token.valid_epoch = epoch;
    token.subepoch_slot = slot;
    token.issuer_key_id = issuer_key_id;
    for (std::size_t i = 0; i < token.admission_unit.size(); ++i)
        token.admission_unit[i] = static_cast<Byte>(0x40 + i);
    for (std::size_t i = 0; i < token.presentation_context_hash.size(); ++i)
        token.presentation_context_hash[i] = static_cast<Byte>(0x80 + i);
    return token;
}

static void TestEpochAndCanonicalObjects() {
    CHECK(K6QuotaEpoch(0) == 0, "epoch zero");
    CHECK(K6QuotaEpoch(899) == 0, "epoch lower boundary");
    CHECK(K6QuotaEpoch(900) == 1, "epoch is fifteen minutes");
    CHECK(K6QuotaSubepoch(0) == 0 && K6QuotaSubepoch(59) == 0 &&
          K6QuotaSubepoch(60) == 1 && K6QuotaSubepoch(899) == 14 &&
          K6QuotaSubepoch(900) == 0, "subepochs are sixty-second epoch slots");
    CHECK(K6QuotaServiceValid(K6QuotaService::Control), "control service valid");
    CHECK(!K6QuotaServiceValid(static_cast<K6QuotaService>(4)), "unknown service rejected");

    const Kad6CryptoHooks identity = IdentityHooks();
    Hash32 context_a{}, context_b{};
    const Byte context_body[] = {1, 2, 3};
    CHECK(K6QuotaContextHash(identity, 0x30, context_body, sizeof context_body,
          context_a) == Kad6Status::Ok, "operation context hash");
    CHECK(K6QuotaContextHash(identity, 0x31, context_body, sizeof context_body,
          context_b) == Kad6Status::Ok && context_a != context_b,
          "operation type is context-bound");
    K6QuotaIssuerCertificate certificate = Certificate(100, identity);
    std::vector<Byte> encoded;
    CHECK(EncodeK6QuotaIssuerCertificate(certificate, encoded) == Kad6Status::Ok,
          "issuer certificate encodes");
    K6QuotaIssuerCertificate decoded;
    std::size_t used = 0;
    CHECK(DecodeK6QuotaIssuerCertificate(encoded.data(), encoded.size(), decoded, &used) ==
          Kad6Status::Ok && used == encoded.size(), "issuer certificate round trip");
    CHECK(VerifyK6QuotaIssuerCertificate(identity, decoded, 100) == Kad6Status::Ok,
          "issuer certificate verifies in epoch");
    CHECK(VerifyK6QuotaIssuerCertificate(identity, decoded, 99) == Kad6Status::Expired,
          "issuer certificate is not accepted early");
    decoded.policy_id ^= 1;
    CHECK(VerifyK6QuotaIssuerCertificate(identity, decoded, 100) == Kad6Status::AuthFailed,
          "issuer certificate tamper rejected");

    K6QuotaToken token = Token(100, certificate.key_id);
    CHECK(EncodeK6QuotaToken(token, encoded) == Kad6Status::Ok &&
          encoded.size() == kK6QuotaTokenBodySize, "token has fixed canonical size");
    K6QuotaToken parsed;
    used = 0;
    CHECK(DecodeK6QuotaToken(encoded.data(), encoded.size(), parsed, &used) == Kad6Status::Ok &&
          used == encoded.size() && parsed.issuer_key_id == certificate.key_id &&
          parsed.subepoch_slot == 4, "v2 token round trip and issuer/slot binding");
    encoded[3] = 1;
    CHECK(DecodeK6QuotaToken(encoded.data(), encoded.size(), parsed) == Kad6Status::BadValue,
          "reserved token bits fail closed");
    CHECK(DecodeK6QuotaToken(encoded.data(), 10, parsed) == Kad6Status::Truncated,
          "truncated token rejected");

    token.version = 1;
    token.subepoch_slot = 0;
    token.issuer_key_id.fill(0);
    CHECK(EncodeK6QuotaToken(token, encoded) == Kad6Status::Ok &&
          encoded.size() == kK6QuotaTokenV1BodySize,
          "v1 token remains readable during rolling migration");
    CHECK(DecodeK6QuotaToken(encoded.data(), encoded.size(), parsed, &used) ==
          Kad6Status::Ok && parsed.version == 1 && used == encoded.size(),
          "v1 token round trip");
    encoded.push_back(0xA5);
    CHECK(DecodeK6QuotaToken(encoded.data(), encoded.size(), parsed) ==
          Kad6Status::Malformed, "token decoder rejects trailing bytes without consumed");
}

static void TestWireMessages() {
    K6QuotaBlindRequest request;
    request.issuer_key_id.fill(0x33);
    request.service = K6QuotaService::ExitEd2kFull;
    request.subepoch_slot = 4;
    request.blinded_messages.assign(2, std::vector<Byte>(256, 0x44));
    std::vector<Byte> wire;
    CHECK(EncodeK6QuotaBlindRequest(request, wire) == Kad6Status::Ok,
          "blind request encodes");
    K6QuotaBlindRequest decoded_request;
    std::size_t used = 0;
    CHECK(DecodeK6QuotaBlindRequest(wire.data(), wire.size(), decoded_request, &used) ==
          Kad6Status::Ok && used == wire.size() && decoded_request.blinded_messages.size() == 2 &&
          decoded_request.version == 2 &&
          decoded_request.service == K6QuotaService::ExitEd2kFull &&
          decoded_request.subepoch_slot == 4,
          "blind request round trip");
    wire[0] = 3;
    CHECK(DecodeK6QuotaBlindRequest(wire.data(), wire.size(), decoded_request) ==
          Kad6Status::UnsupportedVersion, "blind request version guarded");

    K6QuotaBlindResponse denied;
    denied.status = K6QuotaStatus::RateLimited;
    CHECK(EncodeK6QuotaBlindResponse(denied, wire) == Kad6Status::Ok,
          "denial response is bounded and proof-free");
    K6QuotaBlindResponse decoded_response;
    CHECK(DecodeK6QuotaBlindResponse(wire.data(), wire.size(), decoded_response, &used) ==
          Kad6Status::Ok && decoded_response.status == K6QuotaStatus::RateLimited,
          "denial response round trip");

    K6QuotaPresentationResult result;
    result.status = K6QuotaStatus::Ok;
    result.admission_unit_hash.fill(0x77);
    result.valid_epoch = 100;
    CHECK(EncodeK6QuotaPresentationResult(result, wire) == Kad6Status::Ok,
          "presentation status encodes");
    K6QuotaPresentationResult decoded_result;
    CHECK(DecodeK6QuotaPresentationResult(wire.data(), wire.size(), decoded_result, &used) ==
          Kad6Status::Ok && used == wire.size(), "presentation status round trip");
}

static void TestRateAndSpentBounds() {
    Hash32 principal{};
    principal.fill(1);
    K6QuotaIssuerLimiter limiter(3);
    CHECK(limiter.Reserve(principal, 20, 2) == K6QuotaStatus::Ok,
          "issuer reserves first batch");
    CHECK(limiter.Reserve(principal, 20, 2) == K6QuotaStatus::RateLimited,
          "issuer epoch budget enforced");
    CHECK(limiter.Reserve(principal, 19, 1) == K6QuotaStatus::WrongEpoch,
          "issuer rejects epoch rollback");
    CHECK(limiter.Reserve(principal, 21, 3) == K6QuotaStatus::Ok,
          "issuer budget resets next epoch");
    limiter.Prune(23);
    CHECK(limiter.principal_count() == 0, "old issuer principals pruned");

    std::array<Byte, kK6QuotaUnitSize> one{};
    std::array<Byte, kK6QuotaUnitSize> two{};
    one.fill(1); two.fill(2);
    K6QuotaSpentSet spent(1);
    CHECK(spent.Consume(30, one, 30) == K6QuotaStatus::Ok, "unit consumed once");
    CHECK(spent.Consume(30, one, 30) == K6QuotaStatus::AlreadySpent,
          "duplicate unit rejected");
    CHECK(spent.Consume(30, two, 30) == K6QuotaStatus::Capacity,
          "spent set bounded per epoch");
    CHECK(spent.Consume(29, two, 30) == K6QuotaStatus::WrongEpoch,
          "spent set rejects stale epoch");
    CHECK(spent.Consume(31, two, 31) == K6QuotaStatus::Ok && spent.size(30) == 0,
          "spent set prunes prior epoch");
    spent.Prune(30);
    CHECK(spent.Consume(30, one, 30) == K6QuotaStatus::WrongEpoch,
          "spent set rejects replay after wall-clock rollback");
    CHECK(spent.Consume(31, two, 31) == K6QuotaStatus::AlreadySpent,
          "rollback attempt does not erase current nullifiers");
}

static void TestBlindLifecycleAndSingleUse() {
    const std::uint64_t epoch = 100;
    const Kad6CryptoHooks identity = IdentityHooks();
    FakeQuotaContext context;
    const K6QuotaCryptoHooks quota = QuotaHooks(context);
    const K6QuotaIssuerCertificate certificate = Certificate(epoch, identity);
    const K6QuotaToken token = Token(epoch, certificate.key_id);

    K6QuotaBlindState state;
    CHECK(BlindK6QuotaToken(quota, certificate.key, token, state) == Kad6Status::Ok,
          "token prepare-randomize and blind");
    CHECK(state.prepared_message.size() == kK6QuotaPreparedSize &&
          state.blinded_message.size() == certificate.key.modulus.size(),
          "blind state uses fixed widths");
    std::vector<Byte> blind_signature;
    CHECK(quota.blind_sign(quota.context, certificate.key_id,
          state.blinded_message.data(), state.blinded_message.size(), blind_signature),
          "issuer blind-signs without seeing token body");
    K6QuotaPresentation presentation;
    CHECK(FinalizeK6QuotaToken(quota, certificate, state, blind_signature, presentation) ==
          Kad6Status::Ok, "client finalizes anonymous token");

    std::vector<Byte> wire;
    CHECK(EncodeK6QuotaPresentation(presentation, wire) == Kad6Status::Ok,
          "presentation wire encodes");
    K6QuotaPresentation decoded;
    std::size_t used = 0;
    CHECK(DecodeK6QuotaPresentation(wire.data(), wire.size(), decoded, &used) ==
          Kad6Status::Ok && used == wire.size(), "presentation wire round trip");

    K6QuotaSpentSet spent(8);
    K6QuotaToken verified;
    CHECK(VerifyAndSpendK6Quota(identity, quota, spent, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch, token.subepoch_slot,
          token.presentation_context_hash,
          true, &verified) == K6QuotaStatus::Ok, "valid proof admits and spends");
    CHECK(verified.admission_unit == token.admission_unit, "verified token returned");
    CHECK(VerifyAndSpendK6Quota(identity, quota, spent, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch, token.subepoch_slot,
          token.presentation_context_hash,
          true) == K6QuotaStatus::AlreadySpent, "replay rejected after verification");

    K6QuotaSpentSet fresh(8);
    Hash32 wrong_context = token.presentation_context_hash;
    wrong_context[0] ^= 1;
    CHECK(VerifyAndSpendK6Quota(identity, quota, fresh, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch, token.subepoch_slot,
          wrong_context, true) ==
          K6QuotaStatus::WrongContext, "operation context is bound");
    CHECK(VerifyAndSpendK6Quota(identity, quota, fresh, decoded,
          K6QuotaService::ExitEd2kDial, 7, epoch, token.subepoch_slot,
          token.presentation_context_hash,
          true) == K6QuotaStatus::PolicyDenied, "service substitution rejected");
    CHECK(VerifyAndSpendK6Quota(identity, quota, fresh, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch, token.subepoch_slot,
          token.presentation_context_hash,
          false) == K6QuotaStatus::UnknownIssuer, "unknown issuer fails closed");
    CHECK(VerifyAndSpendK6Quota(identity, quota, fresh, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch,
          static_cast<std::uint16_t>((token.subepoch_slot + 1) %
                                     kK6QuotaSubepochsPerEpoch),
          token.presentation_context_hash, true) == K6QuotaStatus::WrongEpoch,
          "v2 token cannot move to another subepoch slot");
    decoded.signature[0] ^= 1;
    CHECK(VerifyAndSpendK6Quota(identity, quota, fresh, decoded,
          K6QuotaService::ExitEd2kFull, 7, epoch, token.subepoch_slot,
          token.presentation_context_hash,
          true) == K6QuotaStatus::InvalidProof, "signature tamper rejected");

    K6QuotaToken wrong_issuer = token;
    wrong_issuer.issuer_key_id[0] ^= 1;
    CHECK(BlindK6QuotaToken(quota, certificate.key, wrong_issuer, state) == Kad6Status::Ok,
          "blind provider cannot inspect issuer binding");
    CHECK(quota.blind_sign(quota.context, certificate.key_id,
          state.blinded_message.data(), state.blinded_message.size(), blind_signature) &&
          FinalizeK6QuotaToken(quota, certificate, state, blind_signature, presentation) ==
              Kad6Status::BadValue,
          "finalization anchors token issuer to selected certificate");

    context.fail = true;
    CHECK(BlindK6QuotaToken(quota, certificate.key, token, state) == Kad6Status::AuthFailed,
          "provider failure is fail closed");
}

static K6QuotaHierarchyRequest HierarchyRequest(std::uint64_t now_ms,
                                                 Byte discriminator = 1) {
    K6QuotaHierarchyRequest request;
    request.principal.fill(discriminator);
    request.prefix48.fill(static_cast<Byte>(0x20 + discriminator));
    request.issuer_key_id.fill(static_cast<Byte>(0x40 + discriminator));
    request.asn = 64512u + discriminator;
    request.service = K6QuotaService::ExitEd2kFull;
    request.now_ms = now_ms;
    return request;
}

static void TestHierarchicalContinuousQuota() {
    K6QuotaHierarchyPolicy attack_policy;
    attack_policy.principal = {16, 16};
    attack_policy.prefix48 = {16, 16};
    attack_policy.issuer = {32, 32};
    attack_policy.asn = {64, 64};
    attack_policy.service = {128, 128};
    attack_policy.global = {256, 256};
    K6QuotaHierarchy attack(attack_policy);
    K6QuotaHierarchyRequest request = HierarchyRequest(1000);
    std::size_t admitted = 0;
    for (std::size_t i = 0; i < 1000000; ++i)
        if (attack.Reserve(request) == K6QuotaStatus::Ok) ++admitted;
    CHECK(admitted == 16 && attack.principal_count() == 1 &&
          attack.prefix_count() == 1,
          "one million rotating addresses in one /48 share bounded state and budget");

    K6QuotaHierarchyPolicy boundary_policy;
    boundary_policy.principal = {2, 2};
    boundary_policy.prefix48 = {2, 2};
    boundary_policy.issuer = {2, 2};
    boundary_policy.asn = {2, 2};
    boundary_policy.service = {2, 2};
    boundary_policy.global = {2, 2};
    K6QuotaHierarchy boundary(boundary_policy);
    request = HierarchyRequest(899999);
    request.units = 2;
    CHECK(boundary.Reserve(request) == K6QuotaStatus::Ok,
          "hierarchy atomically consumes all six scopes");
    request.now_ms = 900001;
    request.units = 1;
    CHECK(boundary.Reserve(request) == K6QuotaStatus::RateLimited,
          "epoch boundary creates no capacity reset spike");
    request.now_ms = 1349999;
    CHECK(boundary.Reserve(request) == K6QuotaStatus::Ok,
          "continuous refill restores fractional capacity over time");
    request.now_ms = 1349998;
    CHECK(boundary.Reserve(request) == K6QuotaStatus::WrongEpoch,
          "hierarchy rejects monotonic-clock rollback");

    K6QuotaHierarchyPolicy asn_policy;
    asn_policy.principal = {16, 16};
    asn_policy.prefix48 = {16, 16};
    asn_policy.issuer = {16, 16};
    asn_policy.asn = {3, 3};
    asn_policy.service = {64, 64};
    asn_policy.global = {64, 64};
    K6QuotaHierarchy asn_limited(asn_policy);
    std::size_t asn_admitted = 0;
    for (Byte i = 1; i <= 8; ++i) {
        request = HierarchyRequest(2000, i);
        request.asn = 64520;
        if (asn_limited.Reserve(request) == K6QuotaStatus::Ok) ++asn_admitted;
    }
    CHECK(asn_admitted == 3 && asn_limited.principal_count() == 8,
          "many prefixes and issuers cannot exceed the shared ASN bucket");
    asn_limited.Prune(2u * kK6QuotaEpochSeconds * 1000u + 3000u);
    CHECK(asn_limited.principal_count() == 0 && asn_limited.prefix_count() == 0,
          "idle hierarchy state is bounded and prunable");
}

int main() {
    TestEpochAndCanonicalObjects();
    TestWireMessages();
    TestRateAndSpentBounds();
    TestBlindLifecycleAndSingleUse();
    TestHierarchicalContinuousQuota();
    std::printf("test_kad6_quota: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
