#pragma once

#include <cstdint>

namespace PartFileIoPolicy
{
	static constexpr std::uint32_t kStatsHeartbeatMs = 10u * 60u * 1000u;

	inline constexpr bool HasElapsed(std::uint32_t now, std::uint32_t since,
		std::uint32_t interval)
	{
		return static_cast<std::uint32_t>(now - since) >= interval;
	}

	inline constexpr bool HasReachedDeadline(std::uint32_t now, std::uint32_t deadline)
	{
		return deadline == 0
			|| static_cast<std::int32_t>(now - deadline) >= 0;
	}

	inline constexpr std::uint32_t StartBufferWindow(std::uint64_t bufferedBefore,
		std::uint32_t now, std::uint32_t previousStart)
	{
		return bufferedBefore == 0 ? now : previousStart;
	}

	inline constexpr bool ShouldPersistMetadata(bool hardDirty, bool statsDirty,
		std::uint32_t now, std::uint32_t lastSave,
		std::uint32_t statsHeartbeat = kStatsHeartbeatMs)
	{
		return hardDirty || (statsDirty && HasElapsed(now, lastSave, statsHeartbeat));
	}

	inline constexpr bool ShouldRunPeriodicFlush(std::uint64_t bufferedBytes,
		std::uint64_t bufferLimit, bool metadataSaveDue,
		bool needsCompletionPolling, bool completionReady,
		std::uint32_t now, std::uint32_t lastFlush,
		std::uint32_t flushInterval)
	{
		if (completionReady)
			return true;
		if (bufferedBytes == 0 && !metadataSaveDue && !needsCompletionPolling)
			return false;
		if (bufferedBytes > bufferLimit)
			return true;
		return HasElapsed(now, lastFlush, flushInterval);
	}
}
