// IGD/PCP/NAT-PMP diagnostic. Read-only unless --map-test is supplied.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#define MINIUPNP_STATICLIB
#include "miniupnpc.h"
#include "upnpcommands.h"
#include "upnperrors.h"
#include "natmap/natmap_chain.h"
#include "natmap/natpmp_codec.h"
#include "natmap/pcp_codec.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr unsigned short kMapperPort = 5351;
constexpr unsigned short kSsdpPort = 1900;

std::string AddressText(std::uint32_t address) {
    in_addr value{};
    value.s_addr = address;
    char buffer[INET_ADDRSTRLEN]{};
    return InetNtopA(AF_INET, &value, buffer, sizeof(buffer)) != nullptr
        ? buffer : "invalid";
}

std::uint32_t DefaultGateway() {
    MIB_IPFORWARDROW route{};
    return GetBestRoute(0, 0, &route) == NO_ERROR
        ? route.dwForwardNextHop : 0;
}

std::array<std::uint8_t, 16> ClientForGateway(std::uint32_t gateway) {
    std::array<std::uint8_t, 16> result{};
    SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET)
        return result;
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(kMapperPort);
    destination.sin_addr.s_addr = gateway;
    sockaddr_in local{};
    int length = sizeof(local);
    if (connect(socket_handle, reinterpret_cast<sockaddr*>(&destination),
                sizeof(destination)) == 0 &&
        getsockname(socket_handle, reinterpret_cast<sockaddr*>(&local),
                    &length) == 0) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(
            &local.sin_addr.s_addr);
        result = natmap::PcpIpv4Mapped(bytes[0], bytes[1], bytes[2], bytes[3]);
    }
    closesocket(socket_handle);
    return result;
}

bool Exchange(std::uint32_t gateway, const std::uint8_t* request,
              int request_size, std::uint8_t* response, int capacity,
              int& response_size) {
    SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET)
        return false;
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(kMapperPort);
    destination.sin_addr.s_addr = gateway;
    bool ok = sendto(socket_handle, reinterpret_cast<const char*>(request),
        request_size, 0, reinterpret_cast<sockaddr*>(&destination),
        sizeof(destination)) == request_size;
    if (ok) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(socket_handle, &read_set);
        timeval timeout{0, 700000};
        ok = select(0, &read_set, nullptr, nullptr, &timeout) > 0;
    }
    if (ok) {
        sockaddr_in source{};
        int source_length = sizeof(source);
        response_size = recvfrom(socket_handle, reinterpret_cast<char*>(response),
            capacity, 0, reinterpret_cast<sockaddr*>(&source), &source_length);
        ok = response_size > 0 && source.sin_addr.s_addr == gateway &&
             source.sin_port == htons(kMapperPort);
    }
    closesocket(socket_handle);
    return ok;
}

void PrintAddress(std::uint32_t address) {
    std::printf("%s", AddressText(address).c_str());
}

bool ExtractLocation(const char* response, std::size_t response_size,
                     std::string& location) {
    std::string headers(response, response_size);
    std::size_t offset = 0;
    while (offset < headers.size()) {
        const std::size_t end = headers.find('\n', offset);
        std::string line = headers.substr(offset,
            end == std::string::npos ? std::string::npos : end - offset);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower.rfind("location:", 0) == 0) {
            const std::size_t first = line.find_first_not_of(" \t", 9);
            if (first == std::string::npos)
                return false;
            location = line.substr(first);
            return location.size() <= 2048;
        }
        if (end == std::string::npos)
            break;
        offset = end + 1;
    }
    return false;
}

bool LocationMatchesTarget(const std::string& location,
                           const std::string& target) {
    const std::string prefix = "http://";
    if (location.size() <= prefix.size()
        || _strnicmp(location.c_str(), prefix.c_str(), prefix.size()) != 0)
        return false;
    const std::size_t host_end = location.find_first_of(":/", prefix.size());
    const std::string host = location.substr(prefix.size(),
        host_end == std::string::npos ? std::string::npos
                                     : host_end - prefix.size());
    return _stricmp(host.c_str(), target.c_str()) == 0;
}

bool DiscoverUnicastIgd(std::uint32_t target, std::string& location) {
    SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET)
        return false;
    const std::string target_text = AddressText(target);
    const std::string request =
        "M-SEARCH * HTTP/1.1\r\nHOST: " + target_text + ":1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(kSsdpPort);
    destination.sin_addr.s_addr = target;
    bool ok = sendto(socket_handle, request.data(),
        static_cast<int>(request.size()), 0,
        reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) ==
        static_cast<int>(request.size());
    if (ok) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(socket_handle, &read_set);
        timeval timeout{1, 500000};
        ok = select(0, &read_set, nullptr, nullptr, &timeout) > 0;
    }
    if (ok) {
        char response[8193]{};
        sockaddr_in source{};
        int source_length = sizeof(source);
        const int received = recvfrom(socket_handle, response,
            sizeof(response) - 1, 0, reinterpret_cast<sockaddr*>(&source),
            &source_length);
        ok = received > 0 && source.sin_addr.s_addr == target
            && ExtractLocation(response, static_cast<std::size_t>(received),
                               location)
            && LocationMatchesTarget(location, target_text);
    }
    closesocket(socket_handle);
    return ok;
}

void EnumerateMappings(const UPNPUrls& urls, const IGDdatas& data) {
    std::printf("  Existing mappings (read-only):\n");
    unsigned found = 0;
    unsigned tailscale = 0;
    for (unsigned index = 0; index < 128; ++index) {
        char map_index[12]{};
        std::snprintf(map_index, sizeof(map_index), "%u", index);
        char external[8]{}, internal_client[40]{}, internal_port[8]{};
        char protocol[8]{}, description[80]{}, enabled[8]{}, remote[40]{};
        char duration[16]{};
        const int result = UPNP_GetGenericPortMappingEntry(urls.controlURL,
            data.first.servicetype, map_index, external, internal_client,
            internal_port, protocol, description, enabled, remote, duration);
        if (result != UPNPCOMMAND_SUCCESS) {
            if (index == 0)
                std::printf("    unavailable: %d (%s)\n", result,
                            strupnperror(result));
            break;
        }
        ++found;
        if (_stricmp(description, "tailscale-portmap") == 0)
            ++tailscale;
        if (index < 40)
            std::printf("    %s/%s -> %s:%s desc=%s lease=%s\n",
                external, protocol, internal_client, internal_port, description,
                duration);
        else if (index == 40)
            std::printf("    ... further entries omitted from display ...\n");
    }
    if (found == 0)
        std::printf("    no readable entries\n");
    else
        std::printf("    total-readable=%u tailscale=%u%s\n", found,
            tailscale, found == 128 ? " (at least; probe limit reached)" : "");
}

void PrintSpecificMapping(const UPNPUrls& urls, const IGDdatas& data,
                          const char* external, const char* protocol) {
    char observed_client[40]{}, observed_port[8]{}, description[80]{};
    char enabled[8]{}, duration[16]{};
    const int result = UPNP_GetSpecificPortMappingEntry(urls.controlURL,
        data.first.servicetype, external, protocol, nullptr, observed_client,
        observed_port, description, enabled, duration);
    std::printf("  specific %s/%s: %d (%s)", external, protocol, result,
                strupnperror(result));
    if (result == UPNPCOMMAND_SUCCESS)
        std::printf(" -> %s:%s desc=%s lease=%s", observed_client,
                    observed_port, description, duration);
    std::printf("\n");
}

struct MappingKey {
    std::string external;
    std::string protocol;
};

bool CleanupTailscaleMappings(const UPNPUrls& urls, const IGDdatas& data,
                              const char* local_client) {
    std::vector<MappingKey> matches;
    for (unsigned index = 0; index < 128; ++index) {
        char map_index[12]{};
        std::snprintf(map_index, sizeof(map_index), "%u", index);
        char external[8]{}, internal_client[40]{}, internal_port[8]{};
        char protocol[8]{}, description[80]{}, enabled[8]{}, remote[40]{};
        char duration[16]{};
        const int result = UPNP_GetGenericPortMappingEntry(urls.controlURL,
            data.first.servicetype, map_index, external, internal_client,
            internal_port, protocol, description, enabled, remote, duration);
        if (result != UPNPCOMMAND_SUCCESS)
            break;
        // Deliberately narrow ownership filter. Never delete another host,
        // protocol, application description or internal destination.
        if (_stricmp(description, "tailscale-portmap") == 0
            && _stricmp(protocol, "UDP") == 0
            && std::strcmp(internal_client, local_client) == 0
            && std::strcmp(internal_port, "41641") == 0) {
            matches.push_back({external, protocol});
        }
    }

    std::printf("  CLEANUP authorized Tailscale duplicates: matched=%zu\n",
                matches.size());
    unsigned deleted = 0;
    unsigned failed = 0;
    for (const MappingKey& mapping : matches) {
        const int result = UPNP_DeletePortMapping(urls.controlURL,
            data.first.servicetype, mapping.external.c_str(),
            mapping.protocol.c_str(), nullptr);
        if (result == UPNPCOMMAND_SUCCESS || result == 714)
            ++deleted;
        else {
            ++failed;
            std::printf("    delete %s/%s failed: %d (%s)\n",
                mapping.external.c_str(), mapping.protocol.c_str(), result,
                strupnperror(result));
        }
    }
    std::printf("    cleanup result: deleted-or-expired=%u failed=%u\n",
                deleted, failed);
    return !matches.empty() && failed == 0;
}

bool EnsureEmuleMapping(const UPNPUrls& urls, const IGDdatas& data,
                        const char* local_client, const char* port,
                        const char* protocol, const char* description,
                        bool& created) {
    created = false;
    char observed_client[40]{}, observed_port[8]{}, observed_desc[80]{};
    char enabled[8]{}, duration[16]{};
    int result = UPNP_GetSpecificPortMappingEntry(urls.controlURL,
        data.first.servicetype, port, protocol, nullptr, observed_client,
        observed_port, observed_desc, enabled, duration);
    if (result == UPNPCOMMAND_SUCCESS
        && std::strcmp(observed_client, local_client) == 0
        && std::strcmp(observed_port, port) == 0) {
        std::printf("    %s/%s already exact -> %s:%s\n", port, protocol,
                    observed_client, observed_port);
        return true;
    }
    if (result == UPNPCOMMAND_SUCCESS) {
        std::printf("    %s/%s belongs to %s:%s; refusing takeover\n",
                    port, protocol, observed_client, observed_port);
        return false;
    }

    result = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
        port, port, local_client, description, protocol, nullptr, "7200");
    std::printf("    create %s/%s timed: %d (%s)\n", port, protocol,
                result, strupnperror(result));
    if (result != UPNPCOMMAND_SUCCESS) {
        result = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
            port, port, local_client, description, protocol, nullptr, nullptr);
        std::printf("    create %s/%s permanent fallback: %d (%s)\n",
                    port, protocol, result, strupnperror(result));
    }
    if (result != UPNPCOMMAND_SUCCESS)
        return false;
    created = true;

    std::memset(observed_client, 0, sizeof(observed_client));
    std::memset(observed_port, 0, sizeof(observed_port));
    result = UPNP_GetSpecificPortMappingEntry(urls.controlURL,
        data.first.servicetype, port, protocol, nullptr, observed_client,
        observed_port, observed_desc, enabled, duration);
    const bool exact = result == UPNPCOMMAND_SUCCESS
        && std::strcmp(observed_client, local_client) == 0
        && std::strcmp(observed_port, port) == 0;
    std::printf("    verify %s/%s: %d (%s), target=%s:%s exact=%s lease=%s\n",
        port, protocol, result, strupnperror(result), observed_client,
        observed_port, exact ? "yes" : "NO", duration);
    if (!exact) {
        UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, port,
                               protocol, nullptr);
        created = false;
    }
    return exact;
}

bool InstallEmuleMappings(const UPNPUrls& urls, const IGDdatas& data,
                          const char* local_client) {
    std::printf("  INSTALL eMule mappings transaction:\n");
    bool tcp_created = false;
    if (!EnsureEmuleMapping(urls, data, local_client, "4662", "TCP",
                            "eMule_TCP", tcp_created))
        return false;
    bool udp_created = false;
    if (!EnsureEmuleMapping(urls, data, local_client, "4672", "UDP",
                            "eMule_UDP", udp_created)) {
        if (tcp_created)
            UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype,
                                   "4662", "TCP", nullptr);
        return false;
    }
    std::printf("    transaction committed: 4662/TCP + 4672/UDP\n");
    return true;
}

bool TemporaryMapTest(const char* label, const UPNPUrls& urls,
                      const IGDdatas& data, const char* internal_client,
                      unsigned short external_port) {
    char external[8]{}, internal[8]{};
    std::snprintf(external, sizeof(external), "%hu", external_port);
    std::snprintf(internal, sizeof(internal), "%u", 4662u);
    std::printf("  TEMP MAP TEST %s: %s/TCP -> %s:%s (lease 120s)\n",
        label, external, internal_client, internal);

    int add = UPNP_AddPortMapping(urls.controlURL,
        data.first.servicetype, external, internal, internal_client,
        "eMule_NATMAP_PROBE", "TCP", nullptr, "120");
    std::printf("    create timed: %d (%s)\n", add, strupnperror(add));
    if (add != UPNPCOMMAND_SUCCESS) {
        add = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
            external, internal, internal_client, "eMule_NATMAP_PROBE",
            "TCP", nullptr, nullptr);
        std::printf("    create permanent fallback: %d (%s)\n", add,
                    strupnperror(add));
    }

    char observed_client[40]{}, observed_port[8]{}, description[80]{};
    char enabled[8]{}, duration[16]{};
    int verify = -1;
    bool exact = false;
    if (add == UPNPCOMMAND_SUCCESS) {
        verify = UPNP_GetSpecificPortMappingEntry(urls.controlURL,
            data.first.servicetype, external, "TCP", nullptr,
            observed_client, observed_port, description, enabled, duration);
        exact = verify == UPNPCOMMAND_SUCCESS
            && std::strcmp(observed_client, internal_client) == 0
            && std::strcmp(observed_port, internal) == 0;
        std::printf("    reread: %d (%s), target=%s:%s, lease=%s, exact=%s\n",
            verify, strupnperror(verify), observed_client, observed_port,
            duration, exact ? "yes" : "NO");
    } else {
        std::printf("    reread: skipped because create failed\n");
    }

    // Always attempt deletion when creation reported success. This makes the
    // diagnostic transactional even if verification produced bad data.
    if (add == UPNPCOMMAND_SUCCESS) {
        const int remove = UPNP_DeletePortMapping(urls.controlURL,
            data.first.servicetype, external, "TCP", nullptr);
        std::printf("    delete: %d (%s)\n", remove, strupnperror(remove));
        return exact && remove == UPNPCOMMAND_SUCCESS;
    }
    return false;
}

void ProbeUnicastIgd(std::uint32_t target, bool map_test,
                     const char* local_client, unsigned short map_port) {
    std::string location;
    std::printf("Unicast UPnP probe ");
    PrintAddress(target);
    std::printf(":\n");
    if (!DiscoverUnicastIgd(target, location)) {
        std::printf("  no validated SSDP response\n");
        return;
    }
    std::printf("  location=%s\n", location.c_str());
    UPNPUrls urls{};
    IGDdatas data{};
    char lan[40]{};
    const int valid = UPNP_GetIGDFromUrl(location.c_str(), &urls, &data,
                                         lan, sizeof(lan));
    std::printf("  IGD description: %s, LAN=%s, service=%s\n",
        valid ? "valid" : "invalid", lan, data.first.servicetype);
    if (valid) {
        char external[40]{};
        const int result = UPNP_GetExternalIPAddress(urls.controlURL,
            data.first.servicetype, external);
        std::printf("  external=%s result=%d (%s)\n", external, result,
                    strupnperror(result));
        EnumerateMappings(urls, data);
        PrintSpecificMapping(urls, data, "4662", "TCP");
        PrintSpecificMapping(urls, data, "4672", "UDP");
        if (map_test)
            TemporaryMapTest("unicast IGD", urls, data, local_client,
                             map_port);
    }
    FreeUPNPUrls(&urls);
}

void ProbeMapper(std::uint32_t gateway,
                 const std::array<std::uint8_t, 16>& pcp_client) {
    std::printf("  candidate ");
    PrintAddress(gateway);
    std::printf(":\n");

    std::uint8_t request[24]{};
    std::uint8_t response[natmap::kPcpMaximumMessageSize + 1]{};
    int response_size = 0;
    const std::size_t pcp_size = natmap::EncodePcpAnnounceRequest(
        pcp_client, request, sizeof(request));
    natmap::PcpAnnounceResponse pcp{};
    const bool pcp_ok = pcp_size != 0 && Exchange(gateway, request,
        static_cast<int>(pcp_size), response, sizeof(response), response_size) &&
        natmap::DecodePcpAnnounceResponse(response,
            static_cast<std::size_t>(response_size), pcp) ==
                natmap::PcpDecodeStatus::Ok;
    std::printf("    PCP ANNOUNCE: %s", pcp_ok ? "response" : "no response");
    if (pcp_ok)
        std::printf(" (result=%u, epoch=%u)",
            static_cast<unsigned>(pcp.result), pcp.epoch);
    std::printf("\n");

    natmap::EncodeNatPmpExternalAddressRequest(request, sizeof(request));
    natmap::NatPmpExternalAddressResponse natpmp{};
    response_size = 0;
    const bool natpmp_ok = Exchange(gateway, request, 2, response,
        sizeof(response), response_size) &&
        natmap::DecodeNatPmpExternalAddressResponse(response,
            static_cast<std::size_t>(response_size), natpmp) ==
                natmap::NatPmpDecodeStatus::Ok;
    std::printf("    NAT-PMP public-address: %s",
        natpmp_ok ? "response" : "no response");
    if (natpmp_ok) {
        std::printf(" (result=%u, epoch=%u, external=",
            natpmp.result_code, natpmp.epoch);
        PrintAddress(natpmp.external_ip_network_order);
        std::printf(")");
    }
    std::printf("\n");
}

} // namespace

int main(int argc, char** argv) {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0)
        return 2;

    bool map_test = false;
    bool cleanup_tailscale = false;
    bool install_emule_maps = false;
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--map-test") == 0)
            map_test = true;
        else if (std::strcmp(argv[i], "--cleanup-tailscale") == 0)
            cleanup_tailscale = true;
        else if (std::strcmp(argv[i], "--install-emule-maps") == 0)
            install_emule_maps = true;
    bool mutation_ok = true;

    const std::uint32_t gateway = DefaultGateway();
    std::printf("Default gateway: ");
    PrintAddress(gateway);
    std::printf("\n");

    int error = 0;
    UPNPDev* devices = upnpDiscover(2500, nullptr, nullptr, 0, 0, 2, &error);
    UPNPUrls urls{};
    IGDdatas data{};
    char lan[40]{};
    char wan[40]{};
    char external[40]{};
    int valid_igd = 0;
    int external_result = -1;
    if (devices != nullptr) {
        valid_igd = UPNP_GetValidIGD(devices, &urls, &data,
            lan, sizeof(lan), wan, sizeof(wan));
        if (valid_igd > 0 && urls.controlURL != nullptr)
            external_result = UPNP_GetExternalIPAddress(urls.controlURL,
                data.first.servicetype, external);
    }
    std::printf("UPnP IGD: %s (selection=%d, error=%d)\n",
        valid_igd > 0 ? "found" : "not found", valid_igd, error);
    if (valid_igd > 0)
        std::printf("  LAN=%s WAN=%s external=%s external-result=%d (%s) service=%s\n",
            lan, wan, external, external_result,
            strupnperror(external_result), data.first.servicetype);
    if (valid_igd > 0) {
        if (cleanup_tailscale)
            mutation_ok = CleanupTailscaleMappings(urls, data, lan)
                && mutation_ok;
        if (install_emule_maps)
            mutation_ok = InstallEmuleMappings(urls, data, lan)
                && mutation_ok;
        EnumerateMappings(urls, data);
        PrintSpecificMapping(urls, data, "4662", "TCP");
        PrintSpecificMapping(urls, data, "4672", "UDP");
        if (map_test)
            TemporaryMapTest("adjacent IGD", urls, data, lan, 58461);
    }

    std::printf("Adjacent mapper probes:\n");
    ProbeMapper(gateway, ClientForGateway(gateway));
	for (int i = 1; i < argc; ++i) {
		in_addr explicit_gateway{};
		if (InetPtonA(AF_INET, argv[i], &explicit_gateway) == 1
			&& explicit_gateway.s_addr != gateway) {
			std::printf("Explicit route-hop probe:\n");
			ProbeMapper(explicit_gateway.s_addr,
				ClientForGateway(explicit_gateway.s_addr));
			ProbeUnicastIgd(explicit_gateway.s_addr, map_test, lan, 58462);
		}
	}

    in_addr observed_address{};
    const bool has_observed = InetPtonA(AF_INET, external, &observed_address) == 1;
    const unsigned long observed = observed_address.s_addr;
    if (has_observed && observed != 0) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&observed);
        const natmap::IpAddress wan_address = natmap::IpAddress::V4(
            bytes[0], bytes[1], bytes[2], bytes[3]);
        const auto candidates = natmap::BuildUpstreamGatewayCandidates(wan_address);
        if (candidates.status == natmap::UpstreamDiscoveryStatus::CandidateGateways) {
            std::printf("Bounded upstream probes (read-only):\n");
            const auto pcp_client = natmap::PcpIpv4Mapped(
                bytes[0], bytes[1], bytes[2], bytes[3]);
            for (std::uint8_t i = 0; i < candidates.count; ++i) {
                std::uint32_t candidate = 0;
                std::memcpy(&candidate, candidates.addresses[i].bytes.data(), 4);
                ProbeMapper(candidate, pcp_client);
            }
        } else if (candidates.status ==
                   natmap::UpstreamDiscoveryStatus::OperatorCgnat) {
            std::printf("Upstream classification: operator CGNAT; no probes sent.\n");
        }
    }

    if (devices != nullptr)
        freeUPNPDevlist(devices);
    FreeUPNPUrls(&urls);
    WSACleanup();
    if ((cleanup_tailscale || install_emule_maps) && valid_igd <= 0)
        return 4;
    return mutation_ok ? 0 : 5;
}
