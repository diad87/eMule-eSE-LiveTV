#include "ServerTls.h"

#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <algorithm>
#include <ctime>

namespace ese::server {
namespace {
struct PublicKey { gnutls_pubkey_t value=nullptr; ~PublicKey() { if(value) gnutls_pubkey_deinit(value); } };
struct Datum { gnutls_datum_t value{}; ~Datum() { gnutls_free(value.data); } };

template<class Bytes>
gnutls_datum_t View(const Bytes& bytes) noexcept
{
    return {const_cast<unsigned char*>(bytes.data()),static_cast<unsigned int>(bytes.size())};
}

bool CommonTls(gnutls_session_t session,gnutls_certificate_credentials_t credentials) noexcept
{
    if(!session || !credentials ||
        gnutls_priority_set_direct(session,"NORMAL:-VERS-ALL:+VERS-TLS1.3",nullptr)<0 ||
        gnutls_credentials_set(session,GNUTLS_CRD_CERTIFICATE,credentials)<0) return false;
    auto* name=const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(kEseWireServerAlpn));
    const gnutls_datum_t alpn{name,static_cast<unsigned int>(sizeof(kEseWireServerAlpn)-1)};
    return gnutls_alpn_set_protocols(session,&alpn,1,GNUTLS_ALPN_MANDATORY)==0;
}

int VerifyPin(gnutls_session_t session) noexcept
{
    const auto* policy=static_cast<const TlsClientPolicy*>(gnutls_session_get_ptr(session));
    if(!policy || policy->trust!=TlsTrust::Pinned || gnutls_certificate_type_get(session)!=GNUTLS_CRT_X509)
        return GNUTLS_E_CERTIFICATE_ERROR;
    unsigned count=0;
    const auto* peers=gnutls_certificate_get_peers(session,&count);
    if(!peers || !count) return GNUTLS_E_CERTIFICATE_ERROR;

    gnutls_x509_crt_t certificate=nullptr;
    if(gnutls_x509_crt_init(&certificate)<0) return GNUTLS_E_CERTIFICATE_ERROR;
    struct Certificate { gnutls_x509_crt_t value; ~Certificate() { gnutls_x509_crt_deinit(value); } } crt{certificate};
    if(gnutls_x509_crt_import(crt.value,&peers[0],GNUTLS_X509_FMT_DER)<0)
        return GNUTLS_E_CERTIFICATE_ERROR;
    const auto now=std::time(nullptr);
    const auto start=gnutls_x509_crt_get_activation_time(crt.value);
    const auto end=gnutls_x509_crt_get_expiration_time(crt.value);
    unsigned usage=0;
    const int usageStatus=gnutls_x509_crt_get_key_usage(crt.value,&usage,nullptr);
    if(now<0 || start<0 || end<0 || now<start || now>=end ||
        !gnutls_x509_crt_check_hostname(crt.value,policy->host.c_str()) ||
        !gnutls_x509_crt_check_key_purpose(crt.value,GNUTLS_KP_TLS_WWW_SERVER,0) ||
        (usageStatus!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE &&
            (usageStatus<0 || !(usage & GNUTLS_KEY_DIGITAL_SIGNATURE))))
        return GNUTLS_E_CERTIFICATE_ERROR;

    PublicKey key;
    Datum spki;
    Bytes32 digest{};
    if(gnutls_pubkey_init(&key.value)<0 || gnutls_pubkey_import_x509(key.value,crt.value,0)<0 ||
        gnutls_pubkey_export2(key.value,GNUTLS_X509_FMT_DER,&spki.value)<0 ||
        gnutls_hash_fast(GNUTLS_DIG_SHA256,spki.value.data,spki.value.size,digest.data())<0 ||
        gnutls_memcmp(digest.data(),policy->spkiSha256.data(),digest.size())!=0)
        return GNUTLS_E_CERTIFICATE_ERROR;
    // The TLS 1.3 handshake separately verifies CertificateVerify, proving
    // possession of the private key corresponding to this pinned SPKI.
    return 0;
}
}

bool ConfigureTlsClient(gnutls_session_t session,gnutls_certificate_credentials_t credentials,const TlsClientPolicy& policy) noexcept
{
    if(policy.host.empty() || policy.host.size()>253 || policy.host.find('\0')!=std::string::npos ||
        !CommonTls(session,credentials) ||
        gnutls_server_name_set(session,GNUTLS_NAME_DNS,policy.host.data(),policy.host.size())<0) return false;
    switch(policy.trust) {
    case TlsTrust::Pinned:
        if(std::none_of(policy.spkiSha256.begin(),policy.spkiSha256.end(),[](std::uint8_t b) { return b!=0; }))
            return false;
        gnutls_session_set_ptr(session,const_cast<TlsClientPolicy*>(&policy));
        gnutls_session_set_verify_function(session,VerifyPin);
        return true;
    case TlsTrust::Pkix:
        gnutls_session_set_verify_cert(session,policy.host.c_str(),0);
        return true;
    }
    return false;
}

bool ConfigureTlsServer(gnutls_session_t session,gnutls_certificate_credentials_t credentials) noexcept
{
    return CommonTls(session,credentials);
}

bool IsServerTls(gnutls_session_t session) noexcept
{
    gnutls_datum_t protocol{};
    return session && gnutls_protocol_get_version(session)==GNUTLS_TLS1_3 &&
        gnutls_alpn_get_selected_protocol(session,&protocol)==0 &&
        AcceptsAlpn({reinterpret_cast<const char*>(protocol.data),protocol.size});
}

bool ExportServerAuth(gnutls_session_t session,const Bytes32& helloDigest,Bytes32& exporter) noexcept
{
    return IsServerTls(session) &&
        gnutls_prf_rfc5705(session,sizeof(kEseWireServerExporterLabel)-1,kEseWireServerExporterLabel,
            helloDigest.size(),reinterpret_cast<const char*>(helloDigest.data()),exporter.size(),
            reinterpret_cast<char*>(exporter.data()))==0;
}

bool ReadEd25519Identity(gnutls_privkey_t identity,Bytes32& node) noexcept
{
    PublicKey key;
    Datum x,y;
    gnutls_ecc_curve_t curve{};
    if(!identity || gnutls_pubkey_init(&key.value)<0 || gnutls_pubkey_import_privkey(key.value,identity,0,0)<0 ||
        gnutls_pubkey_export_ecc_raw2(key.value,&curve,&x.value,&y.value,GNUTLS_EXPORT_FLAG_NO_LZ)<0 ||
        curve!=GNUTLS_ECC_CURVE_ED25519 || x.value.size!=node.size()) return false;
    std::copy_n(x.value.data,node.size(),node.begin());
    return true;
}

bool ChannelCrypto::Hash(ByteView input,Bytes32& output) noexcept
{
    return (!input.size || input.data) && gnutls_hash_fast(GNUTLS_DIG_SHA256,input.data,input.size,output.data())==0;
}

bool ChannelCrypto::Export(const Bytes32& digest,Bytes32& output) noexcept
{
    return ExportServerAuth(session_,digest,output);
}

bool ChannelCrypto::Sign(const AuthTranscript& transcript,Signature& output) noexcept
{
    if(!identity_) return false;
    const auto bytes=View(transcript);
    Datum signature;
    if(gnutls_privkey_sign_data2(identity_,GNUTLS_SIGN_EDDSA_ED25519,0,&bytes,&signature.value)<0 ||
        signature.value.size!=output.size()) return false;
    std::copy_n(signature.value.data,output.size(),output.begin());
    return true;
}

bool ChannelCrypto::VerifySignature(const Bytes32& node,const AuthTranscript& transcript,const Signature& signature) noexcept
{
    PublicKey key;
    const auto x=View(node),bytes=View(transcript),sig=View(signature);
    return gnutls_pubkey_init(&key.value)==0 &&
        gnutls_pubkey_import_ecc_raw(key.value,GNUTLS_ECC_CURVE_ED25519,&x,nullptr)==0 &&
        gnutls_pubkey_verify_data2(key.value,GNUTLS_SIGN_EDDSA_ED25519,0,&bytes,&sig)==0;
}

bool ChannelCrypto::Verify(const Bytes32& node,const AuthTranscript& transcript,const Signature& signature) noexcept
{
    return VerifySignature(node,transcript,signature);
}
}
