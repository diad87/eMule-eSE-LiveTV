// SPDX-License-Identifier: MIT
#ifdef _MSC_VER
#include <BaseTsd.h>
typedef SSIZE_T ssize_t; // GnuTLS MinGW headers expect the POSIX signed size type.
#endif
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const ngtcp2_info *info = ngtcp2_version(0);
    const char *tls_version = gnutls_check_version(NULL);
    gnutls_session_t client = NULL, server = NULL;
    int result = 1;
    if (!info || strcmp(info->version_str, "1.25.0") || !tls_version ||
        strcmp(tls_version, "3.8.13")) {
        fprintf(stderr, "Pinned runtime version mismatch\n");
        return 1;
    }
    if (gnutls_global_init() < 0) return 1;
    if (gnutls_init(&client, GNUTLS_CLIENT) < 0 ||
        gnutls_init(&server, GNUTLS_SERVER) < 0) goto cleanup;
    if (gnutls_priority_set_direct(client, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL) < 0 ||
        gnutls_priority_set_direct(server, "NORMAL:-VERS-ALL:+VERS-TLS1.3", NULL) < 0)
        goto cleanup;
    if (ngtcp2_crypto_gnutls_configure_client_session(client) != 0 ||
        ngtcp2_crypto_gnutls_configure_server_session(server) != 0) goto cleanup;
    printf("QUIC dependency ABI PASS: ngtcp2=%s GnuTLS=%s, client/server hooks configured\n",
           info->version_str, tls_version);
    printf("Scope: ABI only; no UDP handshake, peer identity or file transfer tested\n");
    result = 0;
cleanup:
    if (client) gnutls_deinit(client);
    if (server) gnutls_deinit(server);
    gnutls_global_deinit();
    return result;
}
