#pragma once

#include "M2ABindingPort.h"

#include <cstdint>
#include <string>

namespace ese { namespace web {

// Final response policy shared by every Live API adapter.  The facade accepts
// response metadata only; credentials and request URLs deliberately never
// cross this boundary.
std::string HardenLiveResponseHeaders(const std::string& header, bool noStore);
std::string BuildRejectedLiveSessionLog(std::uint32_t ipv4NetworkOrder);
std::string BuildRejectedHlsCapabilityLog(std::uint32_t ipv4NetworkOrder);
std::string BuildHlsCapabilityPlaylistPath(
	const std::string& token,
	std::uint64_t generation,
	const std::string& streamKey);
bool RewriteLiveIndexForCookieSession(
	std::string& header,
	std::string& body);
bool RewriteLivePlayerForHlsCapability(
	std::string& header,
	std::string& body,
	const std::string& streamKey,
	const std::string& capabilityPlaylistPath);
bool RunWebServerFacadeCharacterizationSelfTest(std::string& failure);

} } // namespace ese::web

namespace eSELive {

class WebServerFacade final {
public:
	explicit WebServerFacade(const M2AParentPort& parent) noexcept;

private:
	M2AParentPort m_parent;
};

M2AModuleHandle M2A_BIND_W12_B26D83D73F(const M2AParentPort& parent);
void M2A_UNBIND_W12_B26D83D73F(const M2AParentPort& parent);

} // namespace eSELive
