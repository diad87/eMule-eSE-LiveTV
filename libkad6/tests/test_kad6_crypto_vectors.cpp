// SPDX-License-Identifier: MIT
// Normative external crypto vectors executed against vendored Crypto++.
#include "support/kad6_cryptopp_test_adapter.h"
#include "vector_json.h"

#include "kad6/kad6_records.h"
#include "kad6/kad6_ticket.h"

#include "cryptopp/chachapoly.h"
#include "cryptopp/hkdf.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"

#include <array>
#include <cstdio>
#include <string>
#include <vector>

using namespace kad6;
using namespace kad6_vectors;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::printf("  FAIL: %s  (%s:%d)\n", msg, __FILE__, __LINE__); } } while (0)

static std::string CryptoObject(const char* id) {
    return ObjectById(LoadText("vectors/crypto.json"), id);
}

static std::vector<Byte> FieldBytes(const std::string& object, const char* field) {
    std::vector<Byte> out;
    CHECK(HexToBytes(StringField(object, field), out), "crypto vector hex parses");
    return out;
}

static void TestShaAndHmac(const Kad6CryptoHooks& hooks) {
    {
        const std::string object = CryptoObject("sha256-abc");
        const std::vector<Byte> input = FieldBytes(object, "input_hex");
        const std::vector<Byte> expected = FieldBytes(object, "expected_hex");
        std::array<Byte, 32> actual{};
        CHECK(hooks.sha256(input.data(), input.size(), actual.data()), "Crypto++ SHA hook succeeds");
        CHECK(std::vector<Byte>(actual.begin(), actual.end()) == expected, "FIPS SHA-256 vector");
    }
    {
        const std::string object = CryptoObject("hmac-sha256-rfc4231-case-1");
        const std::vector<Byte> key = FieldBytes(object, "key_hex");
        const std::vector<Byte> input = FieldBytes(object, "input_hex");
        const std::vector<Byte> expected = FieldBytes(object, "expected_hex");
        std::array<Byte, 32> actual{};
        CHECK(hooks.hmac_sha256(key.data(), key.size(), input.data(), input.size(), actual.data()),
              "Crypto++ HMAC hook succeeds");
        CHECK(std::vector<Byte>(actual.begin(), actual.end()) == expected, "RFC 4231 HMAC-SHA256 vector");
    }
}

static void TestEd25519(const Kad6CryptoHooks& hooks) {
    const std::string object = CryptoObject("ed25519-rfc8032-test-1");
    const std::vector<Byte> secret = FieldBytes(object, "secret_hex");
    const std::vector<Byte> pub = FieldBytes(object, "public_hex");
    const std::vector<Byte> message = FieldBytes(object, "input_hex");
    const std::vector<Byte> expected = FieldBytes(object, "expected_hex");
    std::array<Byte, 64> signature{};
    CHECK(hooks.ed25519_sign(secret.data(), secret.size(), nullptr, message.size(), signature.data()),
          "Crypto++ Ed25519 hook signs empty message");
    CHECK(std::vector<Byte>(signature.begin(), signature.end()) == expected, "RFC 8032 signature vector");
    CHECK(hooks.ed25519_verify(pub.data(), nullptr, message.size(), signature.data()),
          "RFC 8032 signature verifies");
    signature[0] ^= 1;
    CHECK(!hooks.ed25519_verify(pub.data(), nullptr, message.size(), signature.data()),
          "altered Ed25519 signature is rejected");
}

static void TestHkdf() {
    const std::string object = CryptoObject("hkdf-sha256-rfc5869-case-1");
    const std::vector<Byte> ikm = FieldBytes(object, "ikm_hex");
    const std::vector<Byte> salt = FieldBytes(object, "salt_hex");
    const std::vector<Byte> info = FieldBytes(object, "info_hex");
    const std::vector<Byte> expectedPrk = FieldBytes(object, "expected_prk_hex");
    const std::vector<Byte> expected = FieldBytes(object, "expected_hex");

    std::array<Byte, 32> prk{};
    CryptoPP::HMAC<CryptoPP::SHA256> extract(salt.data(), salt.size());
    extract.CalculateDigest(prk.data(), ikm.data(), ikm.size());
    CHECK(std::vector<Byte>(prk.begin(), prk.end()) == expectedPrk, "RFC 5869 extract PRK");

    std::vector<Byte> actual(expected.size());
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(actual.data(), actual.size(), ikm.data(), ikm.size(),
                   salt.data(), salt.size(), info.data(), info.size());
    CHECK(actual == expected, "RFC 5869 HKDF-SHA256 OKM");
}

static void TestChaChaPoly() {
    const std::string object = CryptoObject("chacha20-poly1305-rfc8439-2-8-2");
    const std::vector<Byte> key = FieldBytes(object, "key_hex");
    const std::vector<Byte> nonce = FieldBytes(object, "nonce_hex");
    const std::vector<Byte> aad = FieldBytes(object, "aad_hex");
    const std::vector<Byte> plain = FieldBytes(object, "input_hex");
    const std::vector<Byte> expected = FieldBytes(object, "expected_hex");
    const std::vector<Byte> expectedTag = FieldBytes(object, "expected_tag_hex");
    std::vector<Byte> cipher(plain.size());
    std::array<Byte, 16> tag{};
    CryptoPP::ChaCha20Poly1305::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
    enc.EncryptAndAuthenticate(cipher.data(), tag.data(), tag.size(),
        nonce.data(), static_cast<int>(nonce.size()), aad.data(), aad.size(),
        plain.data(), plain.size());
    CHECK(cipher == expected, "RFC 8439 ChaCha20 ciphertext");
    CHECK(std::vector<Byte>(tag.begin(), tag.end()) == expectedTag, "RFC 8439 Poly1305 tag");

    std::vector<Byte> opened(plain.size());
    CryptoPP::ChaCha20Poly1305::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
    CHECK(dec.DecryptAndVerify(opened.data(), tag.data(), tag.size(),
              nonce.data(), static_cast<int>(nonce.size()), aad.data(), aad.size(),
              cipher.data(), cipher.size()), "RFC 8439 AEAD opens");
    CHECK(opened == plain, "RFC 8439 plaintext restored");
    tag[0] ^= 1;
    CHECK(!dec.DecryptAndVerify(opened.data(), tag.data(), tag.size(),
              nonce.data(), static_cast<int>(nonce.size()), aad.data(), aad.size(),
              cipher.data(), cipher.size()), "altered Poly1305 tag is rejected");
}

static bool AllowTarget(void*, Byte, const K6Endpoint&) { return true; }
static bool ConsumeUse(void*, const K6TargetTicket&) { return true; }

static void TestLibKad6Integration(const Kad6CryptoHooks& hooks) {
    const std::string ed = CryptoObject("ed25519-rfc8032-test-1");
    const std::vector<Byte> secret = FieldBytes(ed, "secret_hex");
    const std::vector<Byte> pub = FieldBytes(ed, "public_hex");
    K6NodeBind bind;
    for (std::size_t i = 0; i < bind.kad_id.size(); ++i) bind.kad_id[i] = static_cast<Byte>(i);
    std::copy(pub.begin(), pub.end(), bind.node_pub.begin());
    bind.epoch = 1;
    std::vector<Byte> wire;
    CHECK(SignK6NodeBind(hooks, secret.data(), secret.size(), bind, wire) == Kad6Status::Ok,
          "real Crypto++ signs K6NodeBind");
    K6NodeBind decoded;
    CHECK(DecodeK6NodeBind(wire.data(), wire.size(), decoded) == Kad6Status::Ok,
          "real-signed K6NodeBind decodes");
    CHECK(VerifyK6NodeBind(hooks, decoded) == Kad6Status::Ok,
          "real Crypto++ verifies K6NodeBind domain signature");

    K6TargetTicket ticket;
    ticket.lease_id = 1;
    ticket.provenance_session = 2;
    ticket.provenance_stream = 3;
    ticket.provenance_seq = 4;
    ticket.provenance_digest[0] = 1;
    ticket.target_endpoint.addr.family = Kad6Address::Family::IPv4;
    ticket.target_endpoint.addr.addr = {8, 8, 8, 8};
    ticket.target_endpoint.udp_port = 4672;
    ticket.target_endpoint.tcp_port = 4662;
    ticket.target_endpoint.valid_until = 2000;
    ticket.object_hash[0] = 1;
    ticket.issued_at = 1000;
    ticket.expires_at = 1300;
    ticket.max_bytes = 1024;
    ticket.max_connections = 1;
    ticket.nonce[0] = 1;
    K6TargetPolicy policy{};
    policy.allow_target = &AllowTarget;
    policy.consume_use = &ConsumeUse;
    const Byte ticketSecret[] = {0, 1, 2, 3, 4, 5, 6, 7};
    CHECK(IssueK6TargetTicket(hooks, policy, ticketSecret, sizeof(ticketSecret), ticket, wire)
              == Kad6Status::Ok, "real Crypto++ MACs K6TargetTicket");
    K6TargetTicket verified;
    CHECK(VerifyK6TargetTicket(hooks, policy, ticketSecret, sizeof(ticketSecret),
              wire.data(), wire.size(), 1100, verified) == Kad6Status::Ok,
          "real Crypto++ verifies K6TargetTicket MAC");

    std::array<Byte, 32> random{};
    CHECK(hooks.random_bytes(random.data(), random.size()), "Crypto++ CSPRNG hook succeeds");
}

int main() {
    const Kad6CryptoHooks hooks = MakeKad6CryptoPpTestHooks();
    CHECK(Kad6CryptoReady(hooks), "all production-shape crypto hooks are wired");
    TestShaAndHmac(hooks);
    TestEd25519(hooks);
    TestHkdf();
    TestChaChaPoly();
    TestLibKad6Integration(hooks);
    std::printf("test_kad6_crypto_vectors: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
