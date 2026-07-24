#pragma once

#include <cstdint>

namespace ClientTransferPolicy
{
	enum class PostBlockAction
	{
		Cancel,
		Requeue,
		KeepConnected
	};

	inline bool CanUseDownloadQueueFile(bool found, std::uint64_t fileSize,
		std::uint64_t partSize)
	{
		return found && partSize != 0 && fileSize > partSize;
	}

	inline PostBlockAction ClassifyPostBlock(bool stopped, bool pausedOrError)
	{
		if (stopped)
			return PostBlockAction::Cancel;
		return pausedOrError ? PostBlockAction::Requeue : PostBlockAction::KeepConnected;
	}
}
