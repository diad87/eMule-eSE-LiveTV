#pragma once

#include "LiveStreamAnnouncer.h"

#include <cstddef>
#include <vector>

class CUpDownClient;

class LiveAnnounceTransportAdapter final {
public:
	static std::size_t Send(
		const ese::live::LiveAnnounceDescriptor& descriptor,
		const std::vector<CUpDownClient*>& peers);

private:
	LiveAnnounceTransportAdapter() = delete;
};
