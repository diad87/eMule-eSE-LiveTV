#pragma once
#include "EseServerAuth.h"
#ifdef _MSC_VER
#include <BaseTsd.h>
using ssize_t = SSIZE_T; // Signed size type expected by the MinGW GnuTLS header.
#endif
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
}
