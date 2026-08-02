#pragma once

#include "LiveStreamRecovery.h"

class CUpDownClient;

class LiveRecoveryTransportAdapter final {
public:
	static ese::live::LiveRecoveryEndpoint EndpointOf(
		const CUpDownClient* peer);
};
