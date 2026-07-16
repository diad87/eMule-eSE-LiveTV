#include "Kad6ExitNoticeServer.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <string>

namespace {
int checks = 0;
int failures = 0;

void Check(bool condition, const char* label) {
    ++checks;
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << label << '\n';
    }
}

std::string Request(std::uint16_t port, const std::string& request, bool ipv4) {
    const int family = ipv4 ? AF_INET : AF_INET6;
    SOCKET socket_value = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_value == INVALID_SOCKET) return {};
    int connected = SOCKET_ERROR;
    if (ipv4) {
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &endpoint.sin_addr);
        connected = connect(socket_value, reinterpret_cast<sockaddr*>(&endpoint),
                            sizeof endpoint);
    } else {
        sockaddr_in6 endpoint{};
        endpoint.sin6_family = AF_INET6;
        endpoint.sin6_port = htons(port);
        inet_pton(AF_INET6, "::1", &endpoint.sin6_addr);
        connected = connect(socket_value, reinterpret_cast<sockaddr*>(&endpoint),
                            sizeof endpoint);
    }
    if (connected == SOCKET_ERROR) {
        closesocket(socket_value);
        return {};
    }
    send(socket_value, request.data(), static_cast<int>(request.size()), 0);
    shutdown(socket_value, SD_SEND);
    std::string response;
    char buffer[1024];
    for (;;) {
        const int got = recv(socket_value, buffer, sizeof buffer, 0);
        if (got <= 0) break;
        response.append(buffer, buffer + got);
    }
    closesocket(socket_value);
    return response;
}
} // namespace

int main() {
    CKad6ExitNoticeServer server;
    Check(!server.Start(0, "{}"), "port zero is not an implicit public bind");
    Check(!server.Start(39100, "not-json"), "non-object document rejected");

    std::uint16_t port = 0;
    for (std::uint16_t candidate = 39100; candidate < 39132; ++candidate) {
        if (server.Start(candidate, "{\"version\":1}")) {
            port = candidate;
            break;
        }
    }
    Check(port != 0, "dedicated dual-stack listener starts");
    if (port != 0) {
        const std::string get =
            "GET /.well-known/kad6-exit HTTP/1.1\r\nHost: localhost\r\n\r\n";
        const std::string v6 = Request(port, get, false);
        Check(v6.find("HTTP/1.1 200 OK") == 0, "IPv6 loopback GET succeeds");
        Check(v6.find("Content-Type: application/kad6-exit+json") !=
                  std::string::npos, "dedicated media type");
        Check(v6.find("{\"version\":1}") != std::string::npos,
              "signed document body is exact");

        const std::string v4 = Request(port, get, true);
        Check(v4.find("HTTP/1.1 200 OK") == 0, "IPv4-mapped dual-stack GET succeeds");

        const std::string post = Request(port,
            "POST /.well-known/kad6-exit HTTP/1.1\r\n\r\n", false);
        Check(post.find("404 Not Found") != std::string::npos,
              "write-capable method has no surface");
        Check(post.find("{\"version\":1}") == std::string::npos,
              "rejection never reflects notice or request");

        Check(server.Update("{\"version\":2}"), "atomic signed notice update");
        const std::string updated = Request(port, get, false);
        Check(updated.find("{\"version\":2}") != std::string::npos,
              "updated body served");
        Check(!server.Update(std::string(8193, 'x')), "oversized update rejected");

        const K6ExitNoticeServerSnapshot snapshot = server.Snapshot();
        Check(snapshot.running && snapshot.port == port, "running snapshot");
        Check(snapshot.requests >= 4 && snapshot.rejected >= 1,
              "bounded aggregate counters");
        Check(snapshot.bytes_sent > 0, "aggregate byte counter");
    }
    server.Stop();
    Check(!server.Snapshot().running, "stop closes isolated listener");
    std::cout << "Kad6 exit notice server: " << (checks - failures) << "/"
              << checks << " checks passed\n";
    return failures == 0 ? 0 : 1;
}
