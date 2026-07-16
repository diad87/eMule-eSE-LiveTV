// RFC 9474 arithmetic using Crypto++ only.  Important security properties:
// - exactly RSABSSA-SHA384-PSS-Randomized (SHA-384, MGF1-SHA384, 48-byte salt);
// - fresh 32-byte PrepareRandomize prefix and uniform RSA blinding factor;
// - a dedicated persisted key, never the NodeIdentity Ed25519 key;
// - Crypto++ private-operation blinding plus its public-operation fault check;
// - Finalize verifies the resulting ordinary RSA-PSS signature before return.
#include "Kad6QuotaCrypto.h"

#include "INodeIdentityStorage.h"
#include "kad6/kad6_bytes.h"

#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/pssr.h"
#include "cryptopp/queue.h"
#include "cryptopp/rsa.h"
#include "cryptopp/secblock.h"
#include "cryptopp/sha.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace {

constexpr std::size_t kPersistedBlobSize = 4096;
constexpr std::size_t kPersistedHeaderSize = 48;
const kad6::Byte kPersistedMagic[8] = {'K','6','R','S','A','1',0,0};

const kad6::Byte* NonNull(const kad6::Byte* data, std::size_t size) noexcept {
    static const kad6::Byte empty = 0;
    return size == 0 ? &empty : data;
}

std::uint32_t LoadU32(const kad6::Byte* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

void StoreU32(kad6::Byte* p, std::uint32_t value) noexcept {
    for (unsigned i = 0; i < 4; ++i)
        p[i] = static_cast<kad6::Byte>((value >> (8 * i)) & 0xFFu);
}

bool PublicKeyFromWire(const kad6::K6QuotaPublicKey& wire,
                       CryptoPP::RSA::PublicKey& output) {
    if (wire.suite != kad6::K6QuotaSuite::RsabssaSha384PssRandomized ||
        wire.modulus.size() < kad6::kK6QuotaMinModulusBytes ||
        wire.modulus.size() > kad6::kK6QuotaMaxModulusBytes ||
        wire.exponent != kad6::kK6QuotaPublicExponent ||
        (wire.modulus.front() & 0x80u) == 0 || (wire.modulus.back() & 1u) == 0)
        return false;
    const CryptoPP::Integer n(wire.modulus.data(), wire.modulus.size());
    const CryptoPP::Integer e(wire.exponent);
    if (n.IsEven() || n.BitCount() < 2048 || n.BitCount() > 4096) return false;
    output.Initialize(n, e);
    CryptoPP::AutoSeededRandomPool rng;
    return output.Validate(rng, 2);
}

class K6PssEncoder : public CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA384>::Verifier {
    using Base = CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA384>::Verifier;
public:
    explicit K6PssEncoder(const CryptoPP::RSA::PublicKey& key) : Base(key) {}

    void Encode(CryptoPP::RandomNumberGenerator& rng, const kad6::Byte* message,
                std::size_t message_size, std::vector<kad6::Byte>& output) const {
        CryptoPP::SHA384 hash;
        hash.Update(NonNull(message, message_size), message_size);
        output.resize(MessageRepresentativeLength());
        GetMessageEncodingInterface().ComputeMessageRepresentative(
            rng, nullptr, 0, hash, GetHashIdentifier(), message_size == 0,
            output.data(), MessageRepresentativeBitLength());
    }
};

bool HashPublicKey(const kad6::K6QuotaPublicKey& key, kad6::Hash32& output) {
    std::vector<kad6::Byte> canonical;
    if (kad6::K6QuotaPublicKeySerialize(key, canonical) != kad6::Kad6Status::Ok)
        return false;
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(output.data(), canonical.data(), canonical.size());
    return true;
}

bool SamePublicKey(const kad6::K6QuotaPublicKey& a,
                   const kad6::K6QuotaPublicKey& b) noexcept {
    return a.suite == b.suite && a.exponent == b.exponent &&
        a.modulus.size() == b.modulus.size() &&
        kad6::Kad6CtEqual(a.modulus.data(), b.modulus.data(), a.modulus.size());
}

void SecureWipe(std::vector<kad6::Byte>& value) noexcept {
    if (!value.empty()) CryptoPP::SecureWipeBuffer(value.data(), value.size());
    value.clear();
}

} // namespace

struct CKad6QuotaCrypto::Impl {
    CryptoPP::InvertibleRSAFunction private_key;
    kad6::K6QuotaPublicKey public_key;
    kad6::Hash32 key_id{};
    bool ready = false;
    bool persistent = false;

    bool SetReady(unsigned expected_bits) {
        CryptoPP::AutoSeededRandomPool rng;
        if (!private_key.Validate(rng, 3) ||
            private_key.GetModulus().BitCount() != expected_bits ||
            private_key.GetPublicExponent() != CryptoPP::Integer(kad6::kK6QuotaPublicExponent))
            return false;
        public_key = kad6::K6QuotaPublicKey{};
        public_key.modulus.resize(private_key.GetModulus().ByteCount());
        private_key.GetModulus().Encode(public_key.modulus.data(), public_key.modulus.size());
        if (!HashPublicKey(public_key, key_id)) return false;
        ready = true;
        return true;
    }

    bool Generate(unsigned bits) {
        if (bits != 2048 && bits != 4096) return false;
        try {
            CryptoPP::AutoSeededRandomPool rng;
            private_key.Initialize(rng, bits, CryptoPP::Integer(kad6::kK6QuotaPublicExponent));
            return SetReady(bits);
        } catch (const CryptoPP::Exception&) {
            return false;
        }
    }

    bool Load(const std::array<kad6::Byte, kPersistedBlobSize>& blob,
              unsigned expected_bits) {
        try {
            if (!std::equal(kPersistedMagic, kPersistedMagic + sizeof kPersistedMagic,
                            blob.begin()) || LoadU32(blob.data() + 8) != 1)
                return false;
            const std::uint32_t length = LoadU32(blob.data() + 12);
            if (length == 0 || length > kPersistedBlobSize - kPersistedHeaderSize)
                return false;
            kad6::Byte digest[32]{};
            CryptoPP::SHA256 hash;
            hash.CalculateDigest(digest, blob.data() + kPersistedHeaderSize, length);
            if (!kad6::Kad6CtEqual(digest, blob.data() + 16, sizeof digest)) return false;
            CryptoPP::ByteQueue queue;
            queue.Put(blob.data() + kPersistedHeaderSize, length);
            queue.MessageEnd();
            private_key.Load(queue);
            return queue.CurrentSize() == 0 && SetReady(expected_bits);
        } catch (const CryptoPP::Exception&) {
            return false;
        }
    }

    bool Save(INodeIdentityStorage& storage) const {
        try {
            CryptoPP::ByteQueue queue;
            private_key.Save(queue);
            const std::size_t length = queue.CurrentSize();
            if (length == 0 || length > kPersistedBlobSize - kPersistedHeaderSize)
                return false;
            std::array<kad6::Byte, kPersistedBlobSize> blob{};
            std::copy(kPersistedMagic, kPersistedMagic + sizeof kPersistedMagic, blob.begin());
            StoreU32(blob.data() + 8, 1);
            StoreU32(blob.data() + 12, static_cast<std::uint32_t>(length));
            queue.Get(blob.data() + kPersistedHeaderSize, length);
            CryptoPP::SHA256 hash;
            hash.CalculateDigest(blob.data() + 16,
                                 blob.data() + kPersistedHeaderSize, length);
            const bool saved = storage.SaveKey(blob.data(), blob.size());
            CryptoPP::SecureWipeBuffer(blob.data(), blob.size());
            return saved;
        } catch (const CryptoPP::Exception&) {
            return false;
        }
    }
};

CKad6QuotaCrypto::CKad6QuotaCrypto() : impl_(new Impl) {}
CKad6QuotaCrypto::~CKad6QuotaCrypto() = default;

bool CKad6QuotaCrypto::Initialize(const std::string& storage_path,
                                  unsigned modulus_bits) {
    if (storage_path.empty() || (modulus_bits != 2048 && modulus_bits != 4096))
        return false;
    impl_.reset(new Impl);
    std::unique_ptr<INodeIdentityStorage> storage = CreateNodeIdentityStorage(storage_path);
    if (!storage) return false;
    std::array<kad6::Byte, kPersistedBlobSize> blob{};
    if (storage->LoadKey(blob.data(), blob.size()) && impl_->Load(blob, modulus_bits)) {
        CryptoPP::SecureWipeBuffer(blob.data(), blob.size());
        impl_->persistent = true;
        return true;
    }
    CryptoPP::SecureWipeBuffer(blob.data(), blob.size());
    if (!impl_->Generate(modulus_bits)) return false;
    impl_->persistent = impl_->Save(*storage);
    return true;
}

bool CKad6QuotaCrypto::GenerateEphemeral(unsigned modulus_bits) {
    impl_.reset(new Impl);
    return impl_->Generate(modulus_bits);
}

bool CKad6QuotaCrypto::Ready() const noexcept { return impl_ && impl_->ready; }
bool CKad6QuotaCrypto::Persistent() const noexcept { return Ready() && impl_->persistent; }

const kad6::K6QuotaPublicKey& CKad6QuotaCrypto::PublicKey() const noexcept {
    static const kad6::K6QuotaPublicKey empty{};
    return Ready() ? impl_->public_key : empty;
}

const kad6::Hash32& CKad6QuotaCrypto::KeyId() const noexcept {
    static const kad6::Hash32 empty{};
    return Ready() ? impl_->key_id : empty;
}

kad6::K6QuotaCryptoHooks CKad6QuotaCrypto::Hooks() noexcept {
    kad6::K6QuotaCryptoHooks hooks{};
    hooks.context = this;
    hooks.blind = &CKad6QuotaCrypto::Blind;
    hooks.blind_sign = &CKad6QuotaCrypto::BlindSign;
    hooks.finalize = &CKad6QuotaCrypto::Finalize;
    hooks.verify = &CKad6QuotaCrypto::Verify;
    return hooks;
}

bool CKad6QuotaCrypto::Blind(void* opaque, const kad6::K6QuotaPublicKey& wire_key,
                             const kad6::Byte* message, std::size_t message_size,
                             std::vector<kad6::Byte>& prepared,
                             std::vector<kad6::Byte>& blinded,
                             std::vector<kad6::Byte>& inverse) {
    prepared.clear(); blinded.clear(); SecureWipe(inverse);
    CKad6QuotaCrypto* self = static_cast<CKad6QuotaCrypto*>(opaque);
    if (!self || (!message && message_size != 0)) return false;
    try {
        CryptoPP::RSA::PublicKey key;
        if (!PublicKeyFromWire(wire_key, key)) return false;
        CryptoPP::AutoSeededRandomPool rng;
        prepared.resize(kad6::kK6QuotaRandomizerSize);
        rng.GenerateBlock(prepared.data(), prepared.size());
        prepared.insert(prepared.end(), message, message + message_size);

        K6PssEncoder encoder(key);
        std::vector<kad6::Byte> representative;
        encoder.Encode(rng, prepared.data(), prepared.size(), representative);
        const CryptoPP::Integer m(representative.data(), representative.size());
        const CryptoPP::Integer& n = key.GetModulus();
        if (m >= n || CryptoPP::Integer::Gcd(m, n) != CryptoPP::Integer::One())
            return false;

        CryptoPP::Integer r, inv;
        do {
            r.Randomize(rng, CryptoPP::Integer::One(), n - CryptoPP::Integer::One());
            inv = r.InverseMod(n);
        } while (inv.IsZero());
        const CryptoPP::Integer z = a_times_b_mod_c(m, key.ApplyFunction(r), n);
        blinded.resize(wire_key.modulus.size());
        inverse.resize(wire_key.modulus.size());
        z.Encode(blinded.data(), blinded.size());
        inv.Encode(inverse.data(), inverse.size());
        SecureWipe(representative);
        return true;
    } catch (const CryptoPP::Exception&) {
        prepared.clear(); blinded.clear(); SecureWipe(inverse);
        return false;
    }
}

bool CKad6QuotaCrypto::BlindSign(void* opaque, const kad6::Hash32& key_id,
                                 const kad6::Byte* blinded,
                                 std::size_t blinded_size,
                                 std::vector<kad6::Byte>& blind_signature) {
    blind_signature.clear();
    CKad6QuotaCrypto* self = static_cast<CKad6QuotaCrypto*>(opaque);
    if (!self || !self->Ready() || !blinded ||
        blinded_size != self->impl_->public_key.modulus.size() ||
        !kad6::Kad6CtEqual(key_id.data(), self->impl_->key_id.data(), key_id.size()))
        return false;
    try {
        const CryptoPP::Integer input(blinded, blinded_size);
        if (input >= self->impl_->private_key.GetModulus()) return false;
        CryptoPP::AutoSeededRandomPool rng;
        // Crypto++ CalculateInverse internally blinds the private operation and
        // verifies ApplyFunction(result)==input before returning (fault check).
        const CryptoPP::Integer signed_value =
            self->impl_->private_key.CalculateInverse(rng, input);
        if (self->impl_->private_key.ApplyFunction(signed_value) != input) return false;
        blind_signature.resize(blinded_size);
        signed_value.Encode(blind_signature.data(), blind_signature.size());
        return true;
    } catch (const CryptoPP::Exception&) {
        blind_signature.clear();
        return false;
    }
}

bool CKad6QuotaCrypto::Finalize(void* opaque,
                                const kad6::K6QuotaPublicKey& wire_key,
                                const kad6::Byte* prepared,
                                std::size_t prepared_size,
                                const kad6::Byte* blind_signature,
                                std::size_t blind_signature_size,
                                const kad6::Byte* inverse,
                                std::size_t inverse_size,
                                std::vector<kad6::Byte>& signature) {
    signature.clear();
    CKad6QuotaCrypto* self = static_cast<CKad6QuotaCrypto*>(opaque);
    if (!self || !prepared || !blind_signature || !inverse ||
        blind_signature_size != wire_key.modulus.size() ||
        inverse_size != wire_key.modulus.size())
        return false;
    try {
        CryptoPP::RSA::PublicKey key;
        if (!PublicKeyFromWire(wire_key, key)) return false;
        const CryptoPP::Integer z(blind_signature, blind_signature_size);
        const CryptoPP::Integer inv(inverse, inverse_size);
        const CryptoPP::Integer& n = key.GetModulus();
        if (z >= n || inv.IsZero() || inv >= n) return false;
        const CryptoPP::Integer s = a_times_b_mod_c(z, inv, n);
        signature.resize(wire_key.modulus.size());
        s.Encode(signature.data(), signature.size());
        if (!Verify(opaque, wire_key, prepared, prepared_size,
                    signature.data(), signature.size())) {
            signature.clear();
            return false;
        }
        return true;
    } catch (const CryptoPP::Exception&) {
        signature.clear();
        return false;
    }
}

bool CKad6QuotaCrypto::Verify(void* opaque,
                              const kad6::K6QuotaPublicKey& wire_key,
                              const kad6::Byte* prepared,
                              std::size_t prepared_size,
                              const kad6::Byte* signature,
                              std::size_t signature_size) {
    CKad6QuotaCrypto* self = static_cast<CKad6QuotaCrypto*>(opaque);
    if (!self || (!prepared && prepared_size != 0) || !signature ||
        signature_size != wire_key.modulus.size())
        return false;
    try {
        CryptoPP::RSA::PublicKey key;
        if (!PublicKeyFromWire(wire_key, key)) return false;
        CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA384>::Verifier verifier(key);
        return verifier.VerifyMessage(NonNull(prepared, prepared_size), prepared_size,
                                      signature, signature_size);
    } catch (const CryptoPP::Exception&) {
        return false;
    }
}
