#pragma once

#include <cstdint>

namespace KadProtocolPolicy
{
	inline bool HasReachedTick(std::uint32_t now, std::uint32_t deadline)
	{
		return static_cast<std::int32_t>(now - deadline) >= 0;
	}

	inline bool IsExpectedResponseEndpoint(std::uint32_t expectedIP,
		std::uint16_t expectedPort, std::uint32_t actualIP, std::uint16_t actualPort)
	{
		return expectedIP == actualIP && expectedPort == actualPort;
	}

	inline bool IsResponseContactCountAllowed(std::uint32_t received,
		std::uint32_t expected)
	{
		return received <= expected;
	}
}
