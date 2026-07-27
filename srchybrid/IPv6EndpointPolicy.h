#pragma once

#include <cstdint>

namespace IPv6EndpointPolicy
{
	static constexpr std::uint32_t kInvalidIPv4 = 0xFFFFFFFFu;

	inline constexpr std::uint32_t ByteSwap32(std::uint32_t value)
	{
		return ((value & 0x000000FFu) << 24)
			| ((value & 0x0000FF00u) << 8)
			| ((value & 0x00FF0000u) >> 8)
			| ((value & 0xFF000000u) >> 24);
	}

	inline constexpr bool IsUsableStoredIPv4(std::uint32_t value)
	{
		return value != 0 && value != kInvalidIPv4;
	}

	inline constexpr bool IsSyntheticIPv4(std::uint32_t value,
		std::uint32_t synthetic)
	{
		return value == synthetic || value == ByteSwap32(synthetic);
	}

	// Legacy fields may contain the real endpoint in either the preferred
	// connect slot or the last-observed user slot. For a peer which also has a
	// native IPv6 address, reject both byte orders of its compatibility-only
	// synthetic uint32 before selecting an IPv4 route.
	inline constexpr std::uint32_t SelectRealIPv4(
		std::uint32_t connectIPv4, std::uint32_t userIPv4,
		bool hasIPv6, std::uint32_t syntheticIPv4)
	{
		if (IsUsableStoredIPv4(connectIPv4)
			&& (!hasIPv6 || !IsSyntheticIPv4(connectIPv4, syntheticIPv4)))
			return connectIPv4;
		if (IsUsableStoredIPv4(userIPv4)
			&& (!hasIPv6 || !IsSyntheticIPv4(userIPv4, syntheticIPv4)))
			return userIPv4;
		return 0;
	}
}
