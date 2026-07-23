#pragma once

#include <cstdint>

namespace UploadLimitPolicy
{
	inline std::uint32_t EffectiveMaximum(std::uint32_t configuredLimit, std::uint32_t configuredCapacity, std::uint32_t unlimitedValue)
	{
		return configuredLimit != unlimitedValue ? configuredLimit : configuredCapacity;
	}
}
