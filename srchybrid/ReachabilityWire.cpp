// this file is part of eMule
#include "ReachabilityWire.h"
#include "reach/reach_codec.h"

#include <limits>

bool EseEncodeReachVectorV2(unsigned short capFlags,
	unsigned char* out, size_t outCapacity, unsigned char* outLength)
{
	if (outLength == nullptr)
		return false;
	*outLength = 0;

	reach::ReachVector vector;
	vector.version = reach::kReachVersion;
	vector.capFlags = capFlags;

	std::size_t written = 0;
	const reach::ReachStatus status = reach::EncodeReachVector(
		vector, out, outCapacity, &written);
	if (status != reach::ReachStatus::Ok
		|| written > std::numeric_limits<unsigned char>::max())
		return false;

	*outLength = static_cast<unsigned char>(written);
	return true;
}

bool EseDecodeReachVector(const unsigned char* data, size_t length,
	unsigned char* outVersion, unsigned short* outKnownCaps)
{
	if (outVersion == nullptr || outKnownCaps == nullptr)
		return false;
	*outVersion = 0;
	*outKnownCaps = 0;

	reach::ReachVector vector;
	std::size_t consumed = 0;
	const reach::ReachStatus status = reach::DecodeReachVector(
		data, length, vector, &consumed);
	if (status != reach::ReachStatus::Ok || consumed != length)
		return false;

	*outVersion = vector.version;
	*outKnownCaps = reach::ReachKnownCaps(vector);
	return true;
}
