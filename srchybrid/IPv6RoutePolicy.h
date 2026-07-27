#pragma once

namespace IPv6RoutePolicy
{
	// A current HELLO supplies both the public IPv6 candidate and these fork
	// capabilities. This is the stable v9.1 route and must not depend on
	// consent to run bounded NetLab measurements.
	inline constexpr bool HasStableHelloRoute(bool supportsIPv6Wire,
		bool hasObservedDualStack)
	{
		return supportsIPv6Wire && hasObservedDualStack;
	}

	// A cold Kad source may carry reach metadata before HELLO exists. Keep
	// that experimental projection inside the bilateral NetLab cohort.
	inline constexpr bool HasNetLabReachRoute(bool supportsReachV6Inbound,
		bool localNetLabActive, bool peerNetLabActive)
	{
		return supportsReachV6Inbound
			&& localNetLabActive
			&& peerNetLabActive;
	}
}
