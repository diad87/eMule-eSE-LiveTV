// this file is part of eMule eSE - explicit Kad2/Kad6 tunnel adapter boundary
#include "LiveTunnelKadBridge.h"

#include <utility>

namespace eSELive {

LiveTunnelKadBridge::LiveTunnelKadBridge(LiveTunnelKadPorts ports)
    : m_ports(std::move(ports))
{
}

bool LiveTunnelKadBridge::ShouldRouteThroughTunnel(
    const wchar_t* keyword, std::uint8_t operation_class) const
{
    return m_ports.should_route &&
           m_ports.should_route(keyword, operation_class);
}

bool LiveTunnelKadBridge::SearchStreams(
    const wchar_t* keyword, std::vector<std::uint32_t>* search_ids,
    bool force_direct) const
{
    return m_ports.search_streams && keyword &&
           m_ports.search_streams(keyword, search_ids, force_direct);
}

void LiveTunnelKadBridge::StopSearches(
    const std::vector<std::uint32_t>& search_ids) const noexcept
{
    if (!m_ports.stop_search)
        return;
    for (std::uint32_t search_id : search_ids) {
        try {
            m_ports.stop_search(search_id);
        } catch (...) {
        }
    }
}

std::uint8_t LiveTunnelKadBridge::SelectedNetworkMask(
    std::uint8_t kad2_mask, std::uint8_t kad6_mask) const
{
    const std::uint8_t selected = m_ports.selected_networks
        ? m_ports.selected_networks() : 0;
    return BuildNetworkMask((selected & kSelectedKad2) != 0,
                            (selected & kSelectedKad6) != 0,
                            kad2_mask, kad6_mask);
}

std::uint8_t LiveTunnelKadBridge::BuildNetworkMask(
    bool kad2_selected, bool kad6_selected, std::uint8_t kad2_mask,
    std::uint8_t kad6_mask) noexcept
{
    std::uint8_t mask = 0;
    if (kad2_selected)
        mask |= kad2_mask;
    if (kad6_selected)
        mask |= kad6_mask;
    return mask;
}

std::uint8_t LiveTunnelKadBridge::BuildSearchFlags(
    std::uint8_t network_mask, std::uint8_t kad2_mask,
    std::uint8_t kad6_mask, std::uint8_t kad2_flag,
    std::uint8_t kad6_flag) noexcept
{
    return static_cast<std::uint8_t>(
        ((network_mask & kad2_mask) ? kad2_flag : 0) |
        ((network_mask & kad6_mask) ? kad6_flag : 0));
}

std::size_t LiveTunnelKadBridge::NetworkIndex(
    std::uint8_t network_origin, std::uint8_t kad6_origin) noexcept
{
    return network_origin == kad6_origin ? 1u : 0u;
}

bool RunLiveTunnelKadBridgeCharacterizationSelfTest()
{
    std::vector<std::uint32_t> stopped;
    LiveTunnelKadPorts ports;
    ports.should_route = [](const wchar_t* keyword, std::uint8_t operation) {
        return keyword != nullptr && operation == 7;
    };
    ports.search_streams =
        [](const wchar_t* keyword, std::vector<std::uint32_t>* ids, bool force) {
            if (!keyword || !ids || !force)
                return false;
            ids->push_back(42);
            return true;
        };
    ports.stop_search = [&stopped](std::uint32_t id) {
        stopped.push_back(id);
    };
    ports.selected_networks = [] {
        return static_cast<std::uint8_t>(
            LiveTunnelKadBridge::kSelectedKad2 |
            LiveTunnelKadBridge::kSelectedKad6);
    };

    LiveTunnelKadBridge bridge(std::move(ports));
    std::vector<std::uint32_t> ids;
    if (!bridge.ShouldRouteThroughTunnel(L"live", 7) ||
        !bridge.SearchStreams(L"live", &ids, true) ||
        ids != std::vector<std::uint32_t>{42})
        return false;
    bridge.StopSearches(ids);
    if (stopped != ids || bridge.SelectedNetworkMask(0x10, 0x20) != 0x30)
        return false;
    if (LiveTunnelKadBridge::BuildSearchFlags(
            0x20, 0x10, 0x20, 0x01, 0x02) != 0x02)
        return false;
    return LiveTunnelKadBridge::NetworkIndex(2, 2) == 1 &&
           LiveTunnelKadBridge::NetworkIndex(1, 2) == 0;
}

} // namespace eSELive
