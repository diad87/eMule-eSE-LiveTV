#pragma once

#include <cstdint>

namespace IPv6FallbackPolicy
{
	static constexpr std::uint32_t kFallbackDelayMs = 3000u;

	struct State
	{
		bool armed;
		bool halfOpen;
		bool clientOwnsSocket;
		bool lowId;
		bool ipv6Only;
		bool hasIPv4;
		bool proxyConnectFailed;
		bool directTransport;
	};

	inline constexpr bool IsEligible(const State& state)
	{
		return state.armed
			&& state.halfOpen
			&& state.clientOwnsSocket
			&& !state.lowId
			&& !state.ipv6Only
			&& state.hasIPv4
			&& !state.proxyConnectFailed
			&& state.directTransport;
	}

	inline constexpr bool HasElapsed(std::uint32_t now, std::uint32_t started,
		std::uint32_t delay = kFallbackDelayMs)
	{
		return static_cast<std::uint32_t>(now - started) >= delay;
	}
}
