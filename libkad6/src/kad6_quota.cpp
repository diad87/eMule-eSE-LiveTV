// SPDX-License-Identifier: MIT
#include "kad6/kad6_quota.h"

#include "kad6/kad6_bytes.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace kad6 {
namespace {

const char kIssuerDomain[] = "eSE-Kad6-QuotaIssuer-v1";

bool Any(const Byte* p, std::size_t n) noexcept {
    Byte value = 0;
    for (std::size_t i = 0; i < n; ++i) value = static_cast<Byte>(value | p[i]);
    return value != 0;
}

bool ValidPublicKey(const K6QuotaPublicKey& key) noexcept {
    return key.suite == K6QuotaSuite::RsabssaSha384PssRandomized &&
        key.modulus.size() >= kK6QuotaMinModulusBytes &&
        key.modulus.size() <= kK6QuotaMaxModulusBytes &&
        (key.modulus.front() & 0x80) != 0 && (key.modulus.back() & 1) != 0 &&
        key.exponent == kK6QuotaPublicExponent;
}

Kad6Status ReaderStatus(const ByteReader& reader) noexcept {
    return reader.null_arg() ? Kad6Status::NullArgument : Kad6Status::Truncated;
}

std::string BinaryKey(const Byte* p, std::size_t n) {
    return std::string(reinterpret_cast<const char*>(p), n);
}

bool ValidStatus(K6QuotaStatus status) noexcept {
    return static_cast<unsigned>(status) <= static_cast<unsigned>(K6QuotaStatus::CryptoFailure);
}

} // namespace

bool K6QuotaCryptoReady(const K6QuotaCryptoHooks& hooks) noexcept {
    return hooks.blind && hooks.blind_sign && hooks.finalize && hooks.verify;
}

std::uint64_t K6QuotaEpoch(std::uint64_t unix_seconds) noexcept {
    return unix_seconds / kK6QuotaEpochSeconds;
}

bool K6QuotaServiceValid(K6QuotaService service) noexcept {
    return static_cast<unsigned>(service) <=
        static_cast<unsigned>(K6QuotaService::ExitEd2kFull);
}

Kad6Status K6QuotaContextHash(const Kad6CryptoHooks& crypto, Byte msg_type,
                              const Byte* body, std::size_t body_size,
                              Hash32& out) {
    out.fill(0);
    if (!crypto.sha256 || (body_size != 0 && body == nullptr) || body_size > 65535)
        return Kad6Status::BadValue;
    std::vector<Byte> message;
    message.reserve(sizeof(kK6QuotaContextDomain) - 1 + 1 + body_size);
    message.insert(message.end(), kK6QuotaContextDomain,
                   kK6QuotaContextDomain + sizeof(kK6QuotaContextDomain) - 1);
    message.push_back(msg_type);
    if (body_size != 0) message.insert(message.end(), body, body + body_size);
    return crypto.sha256(message.data(), message.size(), out.data())
        ? Kad6Status::Ok : Kad6Status::AuthFailed;
}

Kad6Status K6QuotaPublicKeySerialize(const K6QuotaPublicKey& value,
                                      std::vector<Byte>& out) {
    out.clear();
    if (!ValidPublicKey(value)) return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(static_cast<Byte>(value.suite));
    writer.u16le(static_cast<std::uint16_t>(value.modulus.size()));
    writer.bytes(value.modulus.data(), value.modulus.size());
    writer.u32le(value.exponent);
    return Kad6Status::Ok;
}

Kad6Status K6QuotaPublicKeyId(const Kad6CryptoHooks& crypto,
                              const K6QuotaPublicKey& value, Hash32& out) {
    out.fill(0);
    std::vector<Byte> canonical;
    const Kad6Status encoded = K6QuotaPublicKeySerialize(value, canonical);
    if (encoded != Kad6Status::Ok) return encoded;
    if (!crypto.sha256 || !crypto.sha256(canonical.data(), canonical.size(), out.data())) {
        out.fill(0);
        return Kad6Status::AuthFailed;
    }
    return Kad6Status::Ok;
}

Kad6Status K6QuotaIssuerCertificateSerializeSigned(
    const K6QuotaIssuerCertificate& value, std::vector<Byte>& out) {
    out.clear();
    if (value.version != 1 || !ValidPublicKey(value.key) || value.policy_id == 0 ||
        value.service_mask == 0 || (value.service_mask & 0xF0) != 0 ||
        value.valid_from_epoch == 0 || value.valid_until_epoch < value.valid_from_epoch ||
        !Any(value.key_id.data(), value.key_id.size()) ||
        !Any(value.issuer_node_pub.data(), value.issuer_node_pub.size()))
        return Kad6Status::BadValue;
    std::vector<Byte> key;
    const Kad6Status encoded = K6QuotaPublicKeySerialize(value.key, key);
    if (encoded != Kad6Status::Ok) return encoded;
    ByteWriter writer(out);
    writer.u8(value.version);
    writer.u16le(static_cast<std::uint16_t>(key.size()));
    writer.bytes(key.data(), key.size());
    writer.bytes(value.key_id.data(), value.key_id.size());
    writer.bytes(value.issuer_node_pub.data(), value.issuer_node_pub.size());
    writer.u32le(value.policy_id);
    writer.u8(value.service_mask);
    writer.u64le(value.valid_from_epoch);
    writer.u64le(value.valid_until_epoch);
    return Kad6Status::Ok;
}

Kad6Status SignK6QuotaIssuerCertificate(const Kad6CryptoHooks& crypto,
                                         K6QuotaIssuerCertificate& value,
                                         std::vector<Byte>& out) {
    out.clear();
    if (K6QuotaPublicKeyId(crypto, value.key, value.key_id) != Kad6Status::Ok)
        return Kad6Status::AuthFailed;
    std::vector<Byte> body, message;
    const Kad6Status status = K6QuotaIssuerCertificateSerializeSigned(value, body);
    if (status != Kad6Status::Ok) return status;
    message.insert(message.end(), kIssuerDomain, kIssuerDomain + sizeof(kIssuerDomain) - 1);
    message.insert(message.end(), body.begin(), body.end());
    if (!crypto.ed25519_sign ||
        !crypto.ed25519_sign(nullptr, 0, message.data(), message.size(), value.signature.data()))
        return Kad6Status::AuthFailed;
    return EncodeK6QuotaIssuerCertificate(value, out);
}

Kad6Status EncodeK6QuotaIssuerCertificate(const K6QuotaIssuerCertificate& value,
                                           std::vector<Byte>& out) {
    const Kad6Status status = K6QuotaIssuerCertificateSerializeSigned(value, out);
    if (status != Kad6Status::Ok) { out.clear(); return status; }
    out.insert(out.end(), value.signature.begin(), value.signature.end());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaIssuerCertificate(const Byte* in, std::size_t len,
                                           K6QuotaIssuerCertificate& out,
                                           std::size_t* consumed) noexcept {
    out = K6QuotaIssuerCertificate{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    K6QuotaIssuerCertificate value;
    value.version = reader.u8();
    const std::uint16_t key_size = reader.u16le();
    const Byte* key_data = reader.take(key_size);
    if (!reader.ok()) return ReaderStatus(reader);
    ByteReader key_reader(key_data, key_size);
    value.key.suite = static_cast<K6QuotaSuite>(key_reader.u8());
    const std::uint16_t modulus_size = key_reader.u16le();
    const Byte* modulus = key_reader.take(modulus_size);
    if (key_reader.ok() && modulus)
        value.key.modulus.assign(modulus, modulus + modulus_size);
    value.key.exponent = key_reader.u32le();
    if (!key_reader.ok()) return ReaderStatus(key_reader);
    if (key_reader.remaining() != 0) return Kad6Status::Malformed;
    reader.bytes(value.key_id.data(), value.key_id.size());
    reader.bytes(value.issuer_node_pub.data(), value.issuer_node_pub.size());
    value.policy_id = reader.u32le();
    value.service_mask = reader.u8();
    value.valid_from_epoch = reader.u64le();
    value.valid_until_epoch = reader.u64le();
    reader.bytes(value.signature.data(), value.signature.size());
    if (!reader.ok()) return ReaderStatus(reader);
    if (value.version != 1 || !ValidPublicKey(value.key) || value.policy_id == 0 ||
        value.service_mask == 0 || (value.service_mask & 0xF0) != 0 ||
        value.valid_from_epoch == 0 || value.valid_until_epoch < value.valid_from_epoch ||
        !Any(value.key_id.data(), value.key_id.size()) ||
        !Any(value.issuer_node_pub.data(), value.issuer_node_pub.size()))
        return Kad6Status::BadValue;
    out = std::move(value);
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status VerifyK6QuotaIssuerCertificate(const Kad6CryptoHooks& crypto,
                                           const K6QuotaIssuerCertificate& value,
                                           std::uint64_t current_epoch) {
    if (current_epoch == 0 || current_epoch < value.valid_from_epoch ||
        current_epoch > value.valid_until_epoch)
        return Kad6Status::Expired;
    Hash32 expected{};
    if (K6QuotaPublicKeyId(crypto, value.key, expected) != Kad6Status::Ok ||
        !Kad6CtEqual(expected.data(), value.key_id.data(), expected.size()))
        return Kad6Status::AuthFailed;
    std::vector<Byte> body, message;
    const Kad6Status status = K6QuotaIssuerCertificateSerializeSigned(value, body);
    if (status != Kad6Status::Ok) return status;
    message.insert(message.end(), kIssuerDomain, kIssuerDomain + sizeof(kIssuerDomain) - 1);
    message.insert(message.end(), body.begin(), body.end());
    if (!crypto.ed25519_verify ||
        !crypto.ed25519_verify(value.issuer_node_pub.data(), message.data(), message.size(),
                               value.signature.data()))
        return Kad6Status::AuthFailed;
    return Kad6Status::Ok;
}

Kad6Status EncodeK6QuotaToken(const K6QuotaToken& value, std::vector<Byte>& out) {
    out.clear();
    if (value.version != 1 ||
        value.suite != K6QuotaSuite::RsabssaSha384PssRandomized ||
        !K6QuotaServiceValid(value.service) || value.reserved != 0 ||
        value.policy_id == 0 || value.valid_epoch == 0 ||
        !Any(value.admission_unit.data(), value.admission_unit.size()) ||
        !Any(value.presentation_context_hash.data(), value.presentation_context_hash.size()))
        return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(value.version);
    writer.u8(static_cast<Byte>(value.suite));
    writer.u8(static_cast<Byte>(value.service));
    writer.u8(value.reserved);
    writer.u32le(value.policy_id);
    writer.u64le(value.valid_epoch);
    writer.bytes(value.admission_unit.data(), value.admission_unit.size());
    writer.bytes(value.presentation_context_hash.data(), value.presentation_context_hash.size());
    return out.size() == kK6QuotaTokenBodySize ? Kad6Status::Ok : Kad6Status::Malformed;
}

Kad6Status DecodeK6QuotaToken(const Byte* in, std::size_t len, K6QuotaToken& out,
                              std::size_t* consumed) noexcept {
    out = K6QuotaToken{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    K6QuotaToken value;
    value.version = reader.u8();
    value.suite = static_cast<K6QuotaSuite>(reader.u8());
    value.service = static_cast<K6QuotaService>(reader.u8());
    value.reserved = reader.u8();
    value.policy_id = reader.u32le();
    value.valid_epoch = reader.u64le();
    reader.bytes(value.admission_unit.data(), value.admission_unit.size());
    reader.bytes(value.presentation_context_hash.data(), value.presentation_context_hash.size());
    if (!reader.ok()) return ReaderStatus(reader);
    if (value.version != 1 ||
        value.suite != K6QuotaSuite::RsabssaSha384PssRandomized ||
        !K6QuotaServiceValid(value.service) || value.reserved != 0 ||
        value.policy_id == 0 || value.valid_epoch == 0 ||
        !Any(value.admission_unit.data(), value.admission_unit.size()) ||
        !Any(value.presentation_context_hash.data(), value.presentation_context_hash.size()))
        return Kad6Status::BadValue;
    out = value;
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaPreparedMessage(const Byte* in, std::size_t len,
                                        K6QuotaToken& out) noexcept {
    out = K6QuotaToken{};
    if (!in && len != 0) return Kad6Status::NullArgument;
    if (len != kK6QuotaPreparedSize) return len < kK6QuotaPreparedSize
        ? Kad6Status::Truncated : Kad6Status::Malformed;
    std::size_t used = 0;
    const Kad6Status status = DecodeK6QuotaToken(in + kK6QuotaRandomizerSize,
        len - kK6QuotaRandomizerSize, out, &used);
    return status == Kad6Status::Ok && used == kK6QuotaTokenBodySize
        ? Kad6Status::Ok : status == Kad6Status::Ok ? Kad6Status::Malformed : status;
}

Kad6Status EncodeK6QuotaBlindRequest(const K6QuotaBlindRequest& value,
                                      std::vector<Byte>& out) {
    out.clear();
    if (!Any(value.issuer_key_id.data(), value.issuer_key_id.size()) ||
        value.blinded_messages.empty() || value.blinded_messages.size() > kK6QuotaMaxBatch)
        return Kad6Status::BadValue;
    const std::size_t width = value.blinded_messages.front().size();
    if (width < kK6QuotaMinModulusBytes || width > kK6QuotaMaxModulusBytes)
        return Kad6Status::BadValue;
    for (const std::vector<Byte>& item : value.blinded_messages)
        if (item.size() != width) return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(1);
    writer.bytes(value.issuer_key_id.data(), value.issuer_key_id.size());
    writer.u8(static_cast<Byte>(value.blinded_messages.size()));
    writer.u16le(static_cast<std::uint16_t>(width));
    for (const std::vector<Byte>& item : value.blinded_messages)
        writer.bytes(item.data(), item.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaBlindRequest(const Byte* in, std::size_t len,
                                      K6QuotaBlindRequest& out,
                                      std::size_t* consumed) noexcept {
    out = K6QuotaBlindRequest{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    const Byte version = reader.u8();
    K6QuotaBlindRequest value;
    reader.bytes(value.issuer_key_id.data(), value.issuer_key_id.size());
    const Byte count = reader.u8();
    const std::uint16_t width = reader.u16le();
    if (!reader.ok()) return ReaderStatus(reader);
    if (version != 1) return Kad6Status::UnsupportedVersion;
    if (!Any(value.issuer_key_id.data(), value.issuer_key_id.size()) || count == 0 ||
        count > kK6QuotaMaxBatch || width < kK6QuotaMinModulusBytes ||
        width > kK6QuotaMaxModulusBytes)
        return Kad6Status::BadValue;
    if (reader.remaining() < static_cast<std::size_t>(count) * width)
        return Kad6Status::Truncated;
    value.blinded_messages.reserve(count);
    for (Byte i = 0; i < count; ++i) {
        const Byte* item = reader.take(width);
        if (!item) return ReaderStatus(reader);
        value.blinded_messages.emplace_back(item, item + width);
    }
    out = std::move(value);
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6QuotaBlindResponse(const K6QuotaBlindResponse& value,
                                       std::vector<Byte>& out) {
    out.clear();
    if (!ValidStatus(value.status) || value.issuer_certificate.size() > 2048 ||
        value.blind_signatures.size() > kK6QuotaMaxBatch)
        return Kad6Status::BadValue;
    if (value.status == K6QuotaStatus::Ok &&
        (value.issuer_certificate.empty() || value.blind_signatures.empty()))
        return Kad6Status::BadValue;
    std::size_t width = value.blind_signatures.empty() ? 0 : value.blind_signatures.front().size();
    if (value.status == K6QuotaStatus::Ok &&
        (width < kK6QuotaMinModulusBytes || width > kK6QuotaMaxModulusBytes))
        return Kad6Status::BadValue;
    for (const std::vector<Byte>& item : value.blind_signatures)
        if (item.size() != width) return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(1);
    writer.u8(static_cast<Byte>(value.status));
    writer.u16le(static_cast<std::uint16_t>(value.issuer_certificate.size()));
    writer.bytes(value.issuer_certificate.data(), value.issuer_certificate.size());
    writer.u8(static_cast<Byte>(value.blind_signatures.size()));
    writer.u16le(static_cast<std::uint16_t>(width));
    for (const std::vector<Byte>& item : value.blind_signatures)
        writer.bytes(item.data(), item.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaBlindResponse(const Byte* in, std::size_t len,
                                       K6QuotaBlindResponse& out,
                                       std::size_t* consumed) noexcept {
    out = K6QuotaBlindResponse{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    const Byte version = reader.u8();
    K6QuotaBlindResponse value;
    value.status = static_cast<K6QuotaStatus>(reader.u8());
    const std::uint16_t cert_size = reader.u16le();
    const Byte* cert = reader.take(cert_size);
    if (reader.ok() && cert) value.issuer_certificate.assign(cert, cert + cert_size);
    const Byte count = reader.u8();
    const std::uint16_t width = reader.u16le();
    if (!reader.ok()) return ReaderStatus(reader);
    if (version != 1) return Kad6Status::UnsupportedVersion;
    if (!ValidStatus(value.status) || cert_size > 2048 || count > kK6QuotaMaxBatch)
        return Kad6Status::BadValue;
    if (value.status == K6QuotaStatus::Ok &&
        (cert_size == 0 || count == 0 || width < kK6QuotaMinModulusBytes ||
         width > kK6QuotaMaxModulusBytes))
        return Kad6Status::BadValue;
    if (value.status != K6QuotaStatus::Ok && (count != 0 || width != 0))
        return Kad6Status::BadValue;
    if (reader.remaining() < static_cast<std::size_t>(count) * width)
        return Kad6Status::Truncated;
    value.blind_signatures.reserve(count);
    for (Byte i = 0; i < count; ++i) {
        const Byte* item = reader.take(width);
        if (!item) return ReaderStatus(reader);
        value.blind_signatures.emplace_back(item, item + width);
    }
    out = std::move(value);
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6QuotaPresentation(const K6QuotaPresentation& value,
                                      std::vector<Byte>& out) {
    out.clear();
    if (value.issuer_certificate.empty() || value.issuer_certificate.size() > 2048 ||
        value.prepared_message.size() != kK6QuotaPreparedSize ||
        value.signature.size() < kK6QuotaMinModulusBytes ||
        value.signature.size() > kK6QuotaMaxModulusBytes)
        return Kad6Status::BadValue;
    K6QuotaToken token;
    if (DecodeK6QuotaPreparedMessage(value.prepared_message.data(),
            value.prepared_message.size(), token) != Kad6Status::Ok)
        return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(1);
    writer.u16le(static_cast<std::uint16_t>(value.issuer_certificate.size()));
    writer.bytes(value.issuer_certificate.data(), value.issuer_certificate.size());
    writer.u16le(static_cast<std::uint16_t>(value.prepared_message.size()));
    writer.bytes(value.prepared_message.data(), value.prepared_message.size());
    writer.u16le(static_cast<std::uint16_t>(value.signature.size()));
    writer.bytes(value.signature.data(), value.signature.size());
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaPresentation(const Byte* in, std::size_t len,
                                      K6QuotaPresentation& out,
                                      std::size_t* consumed) noexcept {
    out = K6QuotaPresentation{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    const Byte version = reader.u8();
    const std::uint16_t cert_size = reader.u16le();
    const Byte* cert = reader.take(cert_size);
    const std::uint16_t prepared_size = reader.u16le();
    const Byte* prepared = reader.take(prepared_size);
    const std::uint16_t signature_size = reader.u16le();
    const Byte* signature = reader.take(signature_size);
    if (!reader.ok()) return ReaderStatus(reader);
    if (version != 1) return Kad6Status::UnsupportedVersion;
    if (!cert || cert_size == 0 || cert_size > 2048 || !prepared ||
        prepared_size != kK6QuotaPreparedSize || !signature ||
        signature_size < kK6QuotaMinModulusBytes ||
        signature_size > kK6QuotaMaxModulusBytes)
        return Kad6Status::BadValue;
    K6QuotaPresentation value;
    value.issuer_certificate.assign(cert, cert + cert_size);
    value.prepared_message.assign(prepared, prepared + prepared_size);
    value.signature.assign(signature, signature + signature_size);
    K6QuotaToken token;
    if (DecodeK6QuotaPreparedMessage(prepared, prepared_size, token) != Kad6Status::Ok)
        return Kad6Status::BadValue;
    out = std::move(value);
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status EncodeK6QuotaPresentationResult(const K6QuotaPresentationResult& value,
                                            std::vector<Byte>& out) {
    out.clear();
    if (!ValidStatus(value.status)) return Kad6Status::BadValue;
    if (value.status == K6QuotaStatus::Ok &&
        (!Any(value.admission_unit_hash.data(), value.admission_unit_hash.size()) ||
         value.valid_epoch == 0))
        return Kad6Status::BadValue;
    ByteWriter writer(out);
    writer.u8(1);
    writer.u8(static_cast<Byte>(value.status));
    writer.bytes(value.admission_unit_hash.data(), value.admission_unit_hash.size());
    writer.u64le(value.valid_epoch);
    return Kad6Status::Ok;
}

Kad6Status DecodeK6QuotaPresentationResult(const Byte* in, std::size_t len,
                                            K6QuotaPresentationResult& out,
                                            std::size_t* consumed) noexcept {
    out = K6QuotaPresentationResult{};
    if (consumed) *consumed = 0;
    ByteReader reader(in, len);
    const Byte version = reader.u8();
    K6QuotaPresentationResult value;
    value.status = static_cast<K6QuotaStatus>(reader.u8());
    reader.bytes(value.admission_unit_hash.data(), value.admission_unit_hash.size());
    value.valid_epoch = reader.u64le();
    if (!reader.ok()) return ReaderStatus(reader);
    if (version != 1) return Kad6Status::UnsupportedVersion;
    if (!ValidStatus(value.status) ||
        (value.status == K6QuotaStatus::Ok &&
         (!Any(value.admission_unit_hash.data(), value.admission_unit_hash.size()) ||
          value.valid_epoch == 0)))
        return Kad6Status::BadValue;
    out = value;
    if (consumed) *consumed = reader.pos();
    return Kad6Status::Ok;
}

Kad6Status BlindK6QuotaToken(const K6QuotaCryptoHooks& crypto,
                             const K6QuotaPublicKey& issuer_key,
                             const K6QuotaToken& token, K6QuotaBlindState& out) {
    out = K6QuotaBlindState{};
    if (!K6QuotaCryptoReady(crypto) || !ValidPublicKey(issuer_key))
        return Kad6Status::AuthFailed;
    std::vector<Byte> message;
    const Kad6Status status = EncodeK6QuotaToken(token, message);
    if (status != Kad6Status::Ok) return status;
    K6QuotaBlindState candidate;
    candidate.token = token;
    if (!crypto.blind(crypto.context, issuer_key, message.data(), message.size(),
            candidate.prepared_message, candidate.blinded_message, candidate.inverse) ||
        candidate.prepared_message.size() != kK6QuotaPreparedSize ||
        candidate.blinded_message.size() != issuer_key.modulus.size() ||
        candidate.inverse.size() != issuer_key.modulus.size())
        return Kad6Status::AuthFailed;
    K6QuotaToken parsed;
    if (DecodeK6QuotaPreparedMessage(candidate.prepared_message.data(),
            candidate.prepared_message.size(), parsed) != Kad6Status::Ok ||
        parsed.policy_id != token.policy_id || parsed.valid_epoch != token.valid_epoch ||
        parsed.service != token.service ||
        !Kad6CtEqual(parsed.admission_unit.data(), token.admission_unit.data(),
                     token.admission_unit.size()) ||
        !Kad6CtEqual(parsed.presentation_context_hash.data(),
                     token.presentation_context_hash.data(), token.presentation_context_hash.size()))
        return Kad6Status::AuthFailed;
    out = std::move(candidate);
    return Kad6Status::Ok;
}

Kad6Status FinalizeK6QuotaToken(const K6QuotaCryptoHooks& crypto,
                                const K6QuotaIssuerCertificate& certificate,
                                const K6QuotaBlindState& state,
                                const std::vector<Byte>& blind_signature,
                                K6QuotaPresentation& out) {
    out = K6QuotaPresentation{};
    if (!K6QuotaCryptoReady(crypto) || state.prepared_message.size() != kK6QuotaPreparedSize ||
        state.inverse.size() != certificate.key.modulus.size() ||
        blind_signature.size() != certificate.key.modulus.size())
        return Kad6Status::BadValue;
    std::vector<Byte> signature;
    if (!crypto.finalize(crypto.context, certificate.key,
            state.prepared_message.data(), state.prepared_message.size(),
            blind_signature.data(), blind_signature.size(), state.inverse.data(),
            state.inverse.size(), signature) ||
        signature.size() != certificate.key.modulus.size())
        return Kad6Status::AuthFailed;
    std::vector<Byte> cert;
    if (EncodeK6QuotaIssuerCertificate(certificate, cert) != Kad6Status::Ok)
        return Kad6Status::BadValue;
    out.issuer_certificate = std::move(cert);
    out.prepared_message = state.prepared_message;
    out.signature = std::move(signature);
    return Kad6Status::Ok;
}

K6QuotaIssuerLimiter::K6QuotaIssuerLimiter(std::uint16_t units_per_epoch) noexcept
    : units_per_epoch_(units_per_epoch ? units_per_epoch : 1) {}

K6QuotaStatus K6QuotaIssuerLimiter::Reserve(const Hash32& principal,
                                             std::uint64_t epoch,
                                             std::size_t units) noexcept {
    if (epoch == 0 || units == 0 || units > kK6QuotaMaxBatch ||
        !Any(principal.data(), principal.size()))
        return K6QuotaStatus::BadRequest;
    const std::string key = BinaryKey(principal.data(), principal.size());
    auto found = entries_.find(key);
    if (found == entries_.end()) {
        if (entries_.size() >= kK6QuotaMaxIssuerPrincipals)
            return K6QuotaStatus::Capacity;
        Entry entry;
        entry.epoch = epoch;
        entry.units = static_cast<std::uint16_t>(units);
        if (entry.units > units_per_epoch_) return K6QuotaStatus::RateLimited;
        entries_.emplace(key, entry);
        return K6QuotaStatus::Ok;
    }
    if (epoch < found->second.epoch) return K6QuotaStatus::WrongEpoch;
    if (epoch > found->second.epoch) {
        found->second.epoch = epoch;
        found->second.units = 0;
    }
    if (units > units_per_epoch_ - found->second.units)
        return K6QuotaStatus::RateLimited;
    found->second.units = static_cast<std::uint16_t>(found->second.units + units);
    return K6QuotaStatus::Ok;
}

void K6QuotaIssuerLimiter::Prune(std::uint64_t current_epoch) noexcept {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.epoch + 1 < current_epoch) it = entries_.erase(it);
        else ++it;
    }
}

K6QuotaSpentSet::K6QuotaSpentSet(std::size_t capacity_per_epoch) noexcept
    : capacity_per_epoch_(capacity_per_epoch ? capacity_per_epoch : 1) {}

K6QuotaStatus K6QuotaSpentSet::Consume(
    std::uint64_t epoch, const std::array<Byte, kK6QuotaUnitSize>& unit,
    std::uint64_t current_epoch) noexcept {
    if (epoch == 0 || current_epoch == 0 || !Any(unit.data(), unit.size()))
        return K6QuotaStatus::BadRequest;
    if (epoch_floor_ != 0 && current_epoch < epoch_floor_)
        return K6QuotaStatus::WrongEpoch;
    if (epoch != current_epoch) return K6QuotaStatus::WrongEpoch;
    Prune(current_epoch);
    std::map<std::string, bool>& entries = epochs_[epoch];
    const std::string key = BinaryKey(unit.data(), unit.size());
    if (entries.find(key) != entries.end()) return K6QuotaStatus::AlreadySpent;
    if (entries.size() >= capacity_per_epoch_) return K6QuotaStatus::Capacity;
    entries.emplace(key, true);
    return K6QuotaStatus::Ok;
}

void K6QuotaSpentSet::Prune(std::uint64_t current_epoch) noexcept {
    if (current_epoch == 0 || (epoch_floor_ != 0 && current_epoch < epoch_floor_))
        return;
    epoch_floor_ = current_epoch;
    for (auto it = epochs_.begin(); it != epochs_.end();) {
        if (it->first != current_epoch) it = epochs_.erase(it);
        else ++it;
    }
}

std::size_t K6QuotaSpentSet::size(std::uint64_t epoch) const noexcept {
    const auto found = epochs_.find(epoch);
    return found == epochs_.end() ? 0 : found->second.size();
}

K6QuotaStatus VerifyAndSpendK6Quota(
    const Kad6CryptoHooks& identity_crypto,
    const K6QuotaCryptoHooks& quota_crypto,
    K6QuotaSpentSet& spent,
    const K6QuotaPresentation& presentation,
    K6QuotaService expected_service,
    std::uint32_t expected_policy,
    std::uint64_t current_epoch,
    const Hash32& expected_context,
    bool issuer_trusted,
    K6QuotaToken* token_out,
    K6QuotaIssuerCertificate* certificate_out) {
    if (token_out) *token_out = K6QuotaToken{};
    if (certificate_out) *certificate_out = K6QuotaIssuerCertificate{};
    if (!issuer_trusted) return K6QuotaStatus::UnknownIssuer;
    if (!K6QuotaCryptoReady(quota_crypto) || !K6QuotaServiceValid(expected_service) ||
        expected_policy == 0 || current_epoch == 0 ||
        !Any(expected_context.data(), expected_context.size()))
        return K6QuotaStatus::BadRequest;
    K6QuotaIssuerCertificate certificate;
    std::size_t used = 0;
    if (DecodeK6QuotaIssuerCertificate(presentation.issuer_certificate.data(),
            presentation.issuer_certificate.size(), certificate, &used) != Kad6Status::Ok ||
        used != presentation.issuer_certificate.size() ||
        VerifyK6QuotaIssuerCertificate(identity_crypto, certificate, current_epoch) !=
            Kad6Status::Ok)
        return K6QuotaStatus::UnknownIssuer;
    K6QuotaToken token;
    if (DecodeK6QuotaPreparedMessage(presentation.prepared_message.data(),
            presentation.prepared_message.size(), token) != Kad6Status::Ok)
        return K6QuotaStatus::InvalidProof;
    const Byte service_bit = static_cast<Byte>(1u << static_cast<Byte>(token.service));
    if (token.service != expected_service || token.policy_id != expected_policy ||
        certificate.policy_id != token.policy_id ||
        (certificate.service_mask & service_bit) == 0)
        return K6QuotaStatus::PolicyDenied;
    if (token.valid_epoch != current_epoch) return K6QuotaStatus::WrongEpoch;
    if (!Kad6CtEqual(token.presentation_context_hash.data(), expected_context.data(),
                     expected_context.size()))
        return K6QuotaStatus::WrongContext;
    if (presentation.signature.size() != certificate.key.modulus.size() ||
        !quota_crypto.verify(quota_crypto.context, certificate.key,
            presentation.prepared_message.data(), presentation.prepared_message.size(),
            presentation.signature.data(), presentation.signature.size()))
        return K6QuotaStatus::InvalidProof;
    const K6QuotaStatus consumed = spent.Consume(token.valid_epoch,
        token.admission_unit, current_epoch);
    if (consumed != K6QuotaStatus::Ok) return consumed;
    if (token_out) *token_out = token;
    if (certificate_out) *certificate_out = certificate;
    return K6QuotaStatus::Ok;
}

} // namespace kad6
