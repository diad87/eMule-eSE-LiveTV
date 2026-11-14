#pragma once
#include "EseServerAuth.h"
#ifdef _MSC_VER
#include <BaseTsd.h>
using ssize_t = SSIZE_T; // Signed size type expected by the MinGW GnuTLS header.
#endif
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <string>

namespace ese::server {
enum class TlsTrust { Pinned, Pkix };
struct TlsClientPolicy {
    TlsTrust trust = TlsTrust::Pinned;
    std::string host;
    Bytes32 spkiSha256{};
};

// The policy must outlive the GnuTLS session. Transport callbacks and any
// trusted CA credentials are supplied by its owner.
bool ConfigureTlsClient(gnutls_session_t,gnutls_certificate_credentials_t,const TlsClientPolicy&) noexcept;
bool ConfigureTlsServer(gnutls_session_t,gnutls_certificate_credentials_t) noexcept;
bool IsServerTls(gnutls_session_t) noexcept;

// Call only after gnutls_handshake returns success. An exporter is not itself
// application identity.
bool ExportServerAuth(gnutls_session_t,const Bytes32& helloDigest,Bytes32& exporter) noexcept;
bool ExportRendezvousKey(gnutls_session_t,const Bytes32& helloDigest,Bytes32& key) noexcept;

bool ReadEd25519Identity(gnutls_privkey_t,Bytes32& node) noexcept;
class ChannelCrypto final : public AuthCrypto {
public:
    ChannelCrypto(gnutls_session_t session,gnutls_privkey_t identity) noexcept
        : session_(session), identity_(identity) {}
    bool Hash(ByteView,Bytes32&) noexcept override;
    bool Export(const Bytes32&,Bytes32&) noexcept override;
    bool Sign(const AuthTranscript&,Signature&) noexcept override;
    bool Verify(const Bytes32&,const AuthTranscript&,const Signature&) noexcept override;
    static bool VerifySignature(const Bytes32&,const AuthTranscript&,const Signature&) noexcept;
private:
    gnutls_session_t session_;
    gnutls_privkey_t identity_;
};
}
