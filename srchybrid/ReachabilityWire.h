// this file is part of eMule
// Narrow host bridge to libreach's versioned TAG_REACH codec.  Keeping the
// C++17 libreach types behind this plain interface lets the legacy MFC project
// consume the normative codec without exposing its build mode to every TU.
#pragma once

#include <stddef.h>

enum KadReachCapability {
	KAD_REACH_CAP_V4_TCP_IN = 1u << 0,
	KAD_REACH_CAP_V4_UDP_IN = 1u << 1,
	KAD_REACH_CAP_V6_IN     = 1u << 2,
	KAD_REACH_CAP_PUNCH_2W  = 1u << 3,
	KAD_REACH_CAP_PUNCH_3W  = 1u << 4,
	KAD_REACH_CAP_KEEPALIVE = 1u << 5,
	KAD_REACH_CAP_RELAY_OFFER = 1u << 6,
	KAD_REACH_CAP_V6_OUT      = 1u << 7,
	KAD_REACH_CAP_RELAY_CLIENT = 1u << 8,
	KAD_REACH_CAP_RELAY_SERVICE = 1u << 9,
	KAD_REACH_CAP_NETLAB_V1     = 1u << 10
};

bool EseEncodeReachVectorV2(unsigned short capFlags,
	unsigned char* out, size_t outCapacity, unsigned char* outLength);

bool EseDecodeReachVector(const unsigned char* data, size_t length,
	unsigned char* outVersion, unsigned short* outKnownCaps);
