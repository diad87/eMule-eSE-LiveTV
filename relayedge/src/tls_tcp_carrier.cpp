// SPDX-License-Identifier: MIT
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "edge/tls_tcp_carrier.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/threading.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

#if defined(RELAYEDGE_EXTERNAL_MBEDTLS_RUNTIME)
int threading_mutex_init_alt(mbedtls_platform_mutex_t*) noexcept;
void threading_mutex_destroy_alt(mbedtls_platform_mutex_t*) noexcept;
int threading_mutex_lock_alt(mbedtls_platform_mutex_t*) noexcept;
int threading_mutex_unlock_alt(mbedtls_platform_mutex_t*) noexcept;
int cond_init_alt(mbedtls_platform_condition_variable_t*) noexcept;
void cond_destroy_alt(mbedtls_platform_condition_variable_t*) noexcept;
int cond_signal_alt(mbedtls_platform_condition_variable_t*) noexcept;
int cond_broadcast_alt(mbedtls_platform_condition_variable_t*) noexcept;
int cond_wait_alt(mbedtls_platform_condition_variable_t*,
                  mbedtls_platform_mutex_t*) noexcept;
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>

namespace relayedge {

namespace {

constexpr char kExporterLabel[] = "EXPORTER-eMule-KRP-v1";
// Short bounded read slices let a client observe its local kill switch without
// touching an mbedTLS context from another thread.
constexpr DWORD kTlsIoTimeoutMs = 500;

bool SetIoTimeouts(const mbedtls_net_context& socket) noexcept {
    const char* const timeout = reinterpret_cast<const char*>(&kTlsIoTimeoutMs);
    return setsockopt(static_cast<SOCKET>(socket.fd), SOL_SOCKET, SO_RCVTIMEO,
                      timeout, sizeof(kTlsIoTimeoutMs)) == 0 &&
           setsockopt(static_cast<SOCKET>(socket.fd), SOL_SOCKET, SO_SNDTIMEO,
                      timeout, sizeof(kTlsIoTimeoutMs)) == 0;
}

#if !defined(RELAYEDGE_EXTERNAL_MBEDTLS_RUNTIME)
int MutexInit(mbedtls_platform_mutex_t* mutex) noexcept {
    if (mutex == nullptr)
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    InitializeCriticalSection(&mutex->cs);
    mutex->is_valid = 1;
    return 0;
}

void MutexFree(mbedtls_platform_mutex_t* mutex) noexcept {
    if (mutex != nullptr && mutex->is_valid) {
        DeleteCriticalSection(&mutex->cs);
        mutex->is_valid = 0;
    }
}

int MutexLock(mbedtls_platform_mutex_t* mutex) noexcept {
    if (mutex == nullptr || !mutex->is_valid)
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    EnterCriticalSection(&mutex->cs);
    return 0;
}

int MutexUnlock(mbedtls_platform_mutex_t* mutex) noexcept {
    if (mutex == nullptr || !mutex->is_valid)
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    LeaveCriticalSection(&mutex->cs);
    return 0;
}

int CondInit(mbedtls_platform_condition_variable_t*) noexcept { return 0; }
void CondFree(mbedtls_platform_condition_variable_t*) noexcept {}
int CondSignal(mbedtls_platform_condition_variable_t*) noexcept { return 0; }
int CondBroadcast(mbedtls_platform_condition_variable_t*) noexcept { return 0; }
int CondWait(mbedtls_platform_condition_variable_t*,
             mbedtls_platform_mutex_t*) noexcept { return 0; }
#endif

bool EnsurePsa() noexcept {
    static std::once_flag once;
    static bool initialized = false;
    try {
        std::call_once(once, []() {
#if defined(RELAYEDGE_EXTERNAL_MBEDTLS_RUNTIME)
            mbedtls_threading_set_alt(threading_mutex_init_alt,
                                      threading_mutex_destroy_alt,
                                      threading_mutex_lock_alt,
                                      threading_mutex_unlock_alt,
                                      cond_init_alt, cond_destroy_alt,
                                      cond_signal_alt, cond_broadcast_alt,
                                      cond_wait_alt);
#else
            mbedtls_threading_set_alt(MutexInit, MutexFree, MutexLock, MutexUnlock,
                                      CondInit, CondFree, CondSignal, CondBroadcast,
                                      CondWait);
#endif
            initialized = psa_crypto_init() == PSA_SUCCESS;
        });
    } catch (...) {
        return false;
    }
    return initialized;
}

relay::RelayStatus MapTlsResult(int result) noexcept {
    if (result == 0)
        return relay::RelayStatus::Ok;
    if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)
        return relay::RelayStatus::Truncated;
    if (result == MBEDTLS_ERR_SSL_TIMEOUT)
        return relay::RelayStatus::Truncated;
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
        result == MBEDTLS_ERR_NET_CONN_RESET)
        return relay::RelayStatus::Expired;
    return relay::RelayStatus::AuthFailed;
}

bool IsLoopback(const char* address) noexcept {
    return address != nullptr &&
        (std::strcmp(address, "127.0.0.1") == 0 || std::strcmp(address, "::1") == 0);
}

} // namespace

struct LabTlsListener::Impl {
    mbedtls_net_context socket{};
    std::uint16_t port = 0;
    bool open = false;

    Impl() { mbedtls_net_init(&socket); }
    ~Impl() { mbedtls_net_free(&socket); }
};

struct TlsTcpCarrier::Impl {
    mbedtls_net_context socket{};
    mbedtls_ssl_context ssl{};
    mbedtls_ssl_config config{};
    mbedtls_x509_crt certificate{};
    mbedtls_x509_crt ca{};
    mbedtls_pk_context private_key{};
    CarrierState state = CarrierState::Closed;
    int last_error = 0;

    Impl() {
        mbedtls_net_init(&socket);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
        mbedtls_x509_crt_init(&certificate);
        mbedtls_x509_crt_init(&ca);
        mbedtls_pk_init(&private_key);
    }
    ~Impl() {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&config);
        mbedtls_x509_crt_free(&certificate);
        mbedtls_x509_crt_free(&ca);
        mbedtls_pk_free(&private_key);
        mbedtls_net_free(&socket);
    }
};

relay::RelayStatus ValidateLabTlsCredentials(const char* certificate_path,
                                              const char* private_key_path) noexcept {
    if (certificate_path == nullptr || *certificate_path == '\0' ||
        private_key_path == nullptr || *private_key_path == '\0' || !EnsurePsa())
        return relay::RelayStatus::InvalidArgument;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context private_key;
    mbedtls_x509_crt_init(&certificate);
    mbedtls_pk_init(&private_key);
    int result = mbedtls_x509_crt_parse_file(&certificate, certificate_path);
    if (result == 0)
        result = mbedtls_pk_parse_keyfile(&private_key, private_key_path, nullptr);
    if (result == 0)
        result = mbedtls_pk_check_pair(&certificate.pk, &private_key);
    if (result == 0 && (mbedtls_x509_time_is_future(&certificate.valid_from) != 0 ||
                        mbedtls_x509_time_is_past(&certificate.valid_to) != 0))
        result = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    mbedtls_pk_free(&private_key);
    mbedtls_x509_crt_free(&certificate);
    return result == 0 ? relay::RelayStatus::Ok : relay::RelayStatus::AuthFailed;
}

LabTlsListener::LabTlsListener() : impl_(new (std::nothrow) Impl) {}
LabTlsListener::~LabTlsListener() = default;

relay::RelayStatus LabTlsListener::OpenInternal(const char* address,
                                                std::uint16_t port) noexcept {
    if (impl_ == nullptr || impl_->open || address == nullptr || *address == '\0')
        return relay::RelayStatus::InvalidArgument;
    char port_text[6]{};
    if (std::snprintf(port_text, sizeof(port_text), "%u",
                      static_cast<unsigned>(port)) <= 0)
        return relay::RelayStatus::InvalidArgument;
    const int result = mbedtls_net_bind(&impl_->socket, address, port_text,
                                        MBEDTLS_NET_PROTO_TCP);
    if (result != 0)
        return relay::RelayStatus::TargetForbidden;
    sockaddr_storage bound{};
    int bound_size = sizeof(bound);
    if (getsockname(static_cast<SOCKET>(impl_->socket.fd),
                    reinterpret_cast<sockaddr*>(&bound), &bound_size) != 0) {
        mbedtls_net_free(&impl_->socket); mbedtls_net_init(&impl_->socket);
        return relay::RelayStatus::InvalidState;
    }
    if (bound.ss_family == AF_INET)
        impl_->port = ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);
    else if (bound.ss_family == AF_INET6)
        impl_->port = ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port);
    if (impl_->port == 0) {
        mbedtls_net_free(&impl_->socket); mbedtls_net_init(&impl_->socket);
        return relay::RelayStatus::InvalidState;
    }
    impl_->open = true;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus LabTlsListener::Open(const char* loopback_address,
                                         std::uint16_t port) noexcept {
    if (impl_ == nullptr || impl_->open || !IsLoopback(loopback_address))
        return relay::RelayStatus::InvalidArgument;
    return OpenInternal(loopback_address, port);
}

relay::RelayStatus LabTlsListener::OpenPublic(const char* bind_address,
                                               std::uint16_t port) noexcept {
    if (port == 0)
        return relay::RelayStatus::InvalidArgument;
    return OpenInternal(bind_address, port);
}

relay::RelayStatus LabTlsListener::Accept(const char* certificate_path,
                                           const char* private_key_path,
                                           TlsTcpCarrier& carrier) noexcept {
    if (impl_ == nullptr || !impl_->open || carrier.impl_ == nullptr ||
        carrier.impl_->state != CarrierState::Closed || certificate_path == nullptr ||
        private_key_path == nullptr || !EnsurePsa())
        return relay::RelayStatus::InvalidState;
    TlsTcpCarrier::Impl& target = *carrier.impl_;
    target.state = CarrierState::Handshaking;
    int result = mbedtls_net_accept(&impl_->socket, &target.socket, nullptr, 0, nullptr);
    if (result == 0 && !SetIoTimeouts(target.socket))
        result = MBEDTLS_ERR_NET_SOCKET_FAILED;
    if (result == 0)
        result = mbedtls_x509_crt_parse_file(&target.certificate, certificate_path);
    if (result == 0)
        result = mbedtls_pk_parse_keyfile(&target.private_key, private_key_path, nullptr);
    if (result == 0)
        result = mbedtls_ssl_config_defaults(&target.config, MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result == 0) {
        mbedtls_ssl_conf_min_tls_version(&target.config, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_authmode(&target.config, MBEDTLS_SSL_VERIFY_NONE);
        result = mbedtls_ssl_conf_own_cert(&target.config, &target.certificate,
                                           &target.private_key);
    }
    if (result == 0)
        result = mbedtls_ssl_setup(&target.ssl, &target.config);
    if (result == 0) {
        mbedtls_ssl_set_bio(&target.ssl, &target.socket, mbedtls_net_send,
                            mbedtls_net_recv, mbedtls_net_recv_timeout);
        do {
            result = mbedtls_ssl_handshake(&target.ssl);
        } while (result == MBEDTLS_ERR_SSL_WANT_READ ||
                 result == MBEDTLS_ERR_SSL_WANT_WRITE);
    }
    target.state = result == 0 ? CarrierState::Open : CarrierState::Failed;
    target.last_error = result;
    return MapTlsResult(result);
}

std::uint16_t LabTlsListener::bound_port() const noexcept {
    return impl_ == nullptr ? 0 : impl_->port;
}

void LabTlsListener::Close() noexcept {
    if (impl_ == nullptr)
        return;
    mbedtls_net_free(&impl_->socket);
    mbedtls_net_init(&impl_->socket);
    impl_->port = 0;
    impl_->open = false;
}

TlsTcpCarrier::TlsTcpCarrier() : impl_(new (std::nothrow) Impl) {}
TlsTcpCarrier::~TlsTcpCarrier() = default;

relay::RelayStatus TlsTcpCarrier::ConnectLab(const char* loopback_address,
                                              std::uint16_t port,
                                              const char* ca_certificate_path,
                                              const char* expected_server_name) noexcept {
    if (!IsLoopback(loopback_address))
        return relay::RelayStatus::InvalidArgument;
    return Connect(loopback_address, port, ca_certificate_path, expected_server_name);
}

relay::RelayStatus TlsTcpCarrier::Connect(const char* address,
                                           std::uint16_t port,
                                           const char* ca_certificate_path,
                                           const char* expected_server_name) noexcept {
    if (impl_ == nullptr || impl_->state != CarrierState::Closed ||
        address == nullptr || *address == '\0' || port == 0 || ca_certificate_path == nullptr ||
        expected_server_name == nullptr || *expected_server_name == '\0' || !EnsurePsa())
        return relay::RelayStatus::InvalidArgument;
    impl_->state = CarrierState::Handshaking;
    char port_text[6]{};
    if (std::snprintf(port_text, sizeof(port_text), "%u",
                      static_cast<unsigned>(port)) <= 0) {
        impl_->state = CarrierState::Failed;
        return relay::RelayStatus::InvalidArgument;
    }
    int result = mbedtls_x509_crt_parse_file(&impl_->ca, ca_certificate_path);
    if (result == 0)
        result = mbedtls_ssl_config_defaults(&impl_->config, MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (result == 0) {
        mbedtls_ssl_conf_min_tls_version(&impl_->config, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_authmode(&impl_->config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&impl_->config, &impl_->ca, nullptr);
        result = mbedtls_ssl_setup(&impl_->ssl, &impl_->config);
    }
    if (result == 0)
        result = mbedtls_ssl_set_hostname(&impl_->ssl, expected_server_name);
    if (result == 0)
        result = mbedtls_net_connect(&impl_->socket, address, port_text,
                                     MBEDTLS_NET_PROTO_TCP);
    if (result == 0 && !SetIoTimeouts(impl_->socket))
        result = MBEDTLS_ERR_NET_SOCKET_FAILED;
    if (result == 0) {
        mbedtls_ssl_set_bio(&impl_->ssl, &impl_->socket, mbedtls_net_send,
                            mbedtls_net_recv, mbedtls_net_recv_timeout);
        do {
            result = mbedtls_ssl_handshake(&impl_->ssl);
        } while (result == MBEDTLS_ERR_SSL_WANT_READ ||
                 result == MBEDTLS_ERR_SSL_WANT_WRITE);
    }
    if (result == 0 && mbedtls_ssl_get_verify_result(&impl_->ssl) != 0)
        result = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    impl_->state = result == 0 ? CarrierState::Open : CarrierState::Failed;
    impl_->last_error = result;
    return MapTlsResult(result);
}

CarrierState TlsTcpCarrier::state() const noexcept {
    return impl_ == nullptr ? CarrierState::Failed : impl_->state;
}

relay::RelayStatus TlsTcpCarrier::WaitReadable(std::uint32_t timeout_ms,
                                                bool& readable) noexcept {
    readable = false;
    if (impl_ == nullptr || impl_->state != CarrierState::Open ||
        impl_->socket.fd < 0 || timeout_ms > 60000)
        return relay::RelayStatus::InvalidState;
    fd_set read_set;
    FD_ZERO(&read_set);
    const SOCKET socket = static_cast<SOCKET>(impl_->socket.fd);
    FD_SET(socket, &read_set);
    timeval timeout{};
    timeout.tv_sec = static_cast<long>(timeout_ms / 1000);
    timeout.tv_usec = static_cast<long>((timeout_ms % 1000) * 1000);
    const int selected = select(0, &read_set, nullptr, nullptr, &timeout);
    if (selected == SOCKET_ERROR)
        return relay::RelayStatus::AuthFailed;
    readable = selected > 0 && FD_ISSET(socket, &read_set) != 0;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus TlsTcpCarrier::Send(const relay::Byte* data,
                                        std::size_t size) noexcept {
    if (impl_ == nullptr || impl_->state != CarrierState::Open ||
        (data == nullptr && size != 0))
        return relay::RelayStatus::InvalidState;
    std::size_t sent = 0;
    while (sent < size) {
        const std::size_t chunk = (std::min)(size - sent,
            static_cast<std::size_t>((std::numeric_limits<int>::max)()));
        const int result = mbedtls_ssl_write(&impl_->ssl, data + sent, chunk);
        if (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (result <= 0) {
            impl_->state = CarrierState::Failed;
            return MapTlsResult(result);
        }
        sent += static_cast<std::size_t>(result);
    }
    return relay::RelayStatus::Ok;
}

relay::RelayStatus TlsTcpCarrier::Receive(relay::Byte* data,
                                           std::size_t capacity,
                                           std::size_t& received) noexcept {
    received = 0;
    if (impl_ == nullptr || impl_->state != CarrierState::Open || data == nullptr ||
        capacity == 0)
        return relay::RelayStatus::InvalidArgument;
    const std::size_t chunk = (std::min)(capacity,
        static_cast<std::size_t>((std::numeric_limits<int>::max)()));
    int result = 0;
    do {
        result = mbedtls_ssl_read(&impl_->ssl, data, chunk);
    } while (result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (result <= 0) {
        if (result == MBEDTLS_ERR_SSL_TIMEOUT)
            return relay::RelayStatus::Truncated;
        if (result != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            impl_->state = CarrierState::Failed;
        return MapTlsResult(result);
    }
    received = static_cast<std::size_t>(result);
    return relay::RelayStatus::Ok;
}

relay::RelayStatus TlsTcpCarrier::ExportBinding(
    relay::KrpCarrierBinding& binding) noexcept {
    binding.fill(0);
    if (impl_ == nullptr || impl_->state != CarrierState::Open)
        return relay::RelayStatus::InvalidState;
#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
    const int result = mbedtls_ssl_export_keying_material(
        &impl_->ssl, binding.data(), binding.size(), kExporterLabel,
        sizeof(kExporterLabel) - 1, nullptr, 0, 0);
    return MapTlsResult(result);
#else
    return relay::RelayStatus::UnsupportedOption;
#endif
}

void TlsTcpCarrier::Close() noexcept {
    if (impl_ == nullptr)
        return;
    if (impl_->state == CarrierState::Open)
        (void)mbedtls_ssl_close_notify(&impl_->ssl);
    impl_.reset(new (std::nothrow) Impl);
}

const char* TlsTcpCarrier::negotiated_tls_version() const noexcept {
    if (impl_ == nullptr || impl_->state != CarrierState::Open)
        return "none";
    const char* const version = mbedtls_ssl_get_version(&impl_->ssl);
    return version == nullptr ? "unknown" : version;
}

int TlsTcpCarrier::last_tls_error() const noexcept {
    return impl_ == nullptr ? -1 : impl_->last_error;
}

} // namespace relayedge
