#pragma once

#include <cstdint>

namespace Known2MetOffset
{
	inline bool IsHashBlockWithinFile(std::uint64_t position, std::uint32_t hashCount,
		std::uint64_t fileSize, std::uint32_t hashSize)
	{
		if (position > fileSize || hashSize == 0)
			return false;
		return hashCount <= (fileSize - position) / hashSize;
	}
}
