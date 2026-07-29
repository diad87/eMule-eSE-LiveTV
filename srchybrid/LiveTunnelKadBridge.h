// this file is part of eMule eSE - explicit Kad2/Kad6 tunnel adapter boundary
#pragma once

#include <cstdint>
#include <functional>
#include <vector>

namespace eSELive {

struct LiveTunnelKadPorts {
    std::function<bool(const wchar_t*, std::uint8_t)> should_route;
    std::function<bool(const wchar_t*, std::vector<std::uint32_t>*, bool)>
        search_streams;
    std::function<void(std::uint32_t)> stop_search;
    std::function<std::uint8_t()> selected_networks;
};

class LiveTunnelKadBridge {
public:
    static const std::uint8_t kSelectedKad2 = 0x01;
    static const std::uint8_t kSelectedKad6 = 0x02;

    explicit LiveTunnelKadBridge(LiveTunnelKadPorts ports);
    LiveTunnelKadBridge(const LiveTunnelKadBridge&) = delete;
    LiveTunnelKadBridge& operator=(const LiveTunnelKadBridge&) = delete;

    bool ShouldRouteThroughTunnel(const wchar_t* keyword,
                                  std::uint8_t operation_class) const;
    bool SearchStreams(const wchar_t* keyword,
                       std::vector<std::uint32_t>* search_ids,
                       bool force_direct) const;
    void StopSearches(const std::vector<std::uint32_t>& search_ids) const noexcept;
    std::uint8_t SelectedNetworkMask(std::uint8_t kad2_mask,
                                     std::uint8_t kad6_mask) const;

    static std::uint8_t BuildNetworkMask(bool kad2_selected,
                                         bool kad6_selected,
                                         std::uint8_t kad2_mask,
                                         std::uint8_t kad6_mask) noexcept;
    static std::uint8_t BuildSearchFlags(std::uint8_t network_mask,
                                         std::uint8_t kad2_mask,
                                         std::uint8_t kad6_mask,
                                         std::uint8_t kad2_flag,
                                         std::uint8_t kad6_flag) noexcept;
    static std::size_t NetworkIndex(std::uint8_t network_origin,
                                    std::uint8_t kad6_origin) noexcept;

private:
    LiveTunnelKadPorts m_ports;
};

bool RunLiveTunnelKadBridgeCharacterizationSelfTest();

} // namespace eSELive
