#pragma once

#include <cstdint>

namespace KnownFileHashPolicy
{
	inline bool UsesDirectFileHash(std::uint64_t fileSize, std::uint64_t partSize)
	{
		return partSize != 0 && fileSize < partSize;
	}

	inline bool NeedsTrailingEmptyPart(std::uint64_t remaining, std::uint64_t hashedSize,
		std::uint64_t partSize)
	{
		return partSize != 0 && remaining == 0 && hashedSize == partSize;
	}
}
