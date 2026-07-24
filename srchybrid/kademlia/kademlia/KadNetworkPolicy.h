#pragma once

#include <cstdint>

namespace KadNetworkPolicy
{
	enum Network : std::uint8_t
	{
		None = 0,
		Kad2 = 1u << 0,
		Kad6 = 1u << 1,
		Both = Kad2 | Kad6
	};

	inline bool IsValid(int value)
	{
		return value >= static_cast<int>(None)
			&& value <= static_cast<int>(Both);
	}

	inline std::uint8_t Migrate(int persistedValue, bool legacyKadEnabled)
	{
		if (IsValid(persistedValue))
			return static_cast<std::uint8_t>(persistedValue);
		return legacyKadEnabled ? static_cast<std::uint8_t>(Both)
			: static_cast<std::uint8_t>(None);
	}

	inline std::uint8_t Effective(std::uint8_t configuredMask, bool udpEnabled)
	{
		return udpEnabled && IsValid(configuredMask)
			? configuredMask : static_cast<std::uint8_t>(None);
	}

	inline bool HasKad2(std::uint8_t mask)
	{
		return (mask & static_cast<std::uint8_t>(Kad2)) != 0;
	}

	inline bool HasKad6(std::uint8_t mask)
	{
		return (mask & static_cast<std::uint8_t>(Kad6)) != 0;
	}

	// Value written to the pre-selector NetworkKademlia boolean. A downgraded
	// client cannot run Kad6, so Kad6-only must not silently become Kad2.
	inline bool LegacyKad2Enabled(std::uint8_t mask)
	{
		return HasKad2(mask);
	}

	inline std::uint8_t Added(std::uint8_t oldMask, std::uint8_t newMask)
	{
		return static_cast<std::uint8_t>(
			newMask & static_cast<std::uint8_t>(~oldMask) & Both);
	}

	inline std::uint8_t Removed(std::uint8_t oldMask, std::uint8_t newMask)
	{
		return static_cast<std::uint8_t>(
			oldMask & static_cast<std::uint8_t>(~newMask) & Both);
	}

	inline std::uint8_t Intersect(std::uint8_t requestedMask,
		std::uint8_t availableMask)
	{
		return static_cast<std::uint8_t>(requestedMask & availableMask & Both);
	}
}
