#include "LiveBroadcastSession.h"

#include <cstring>

namespace ese {
namespace live {

LiveBroadcastSession::~LiveBroadcastSession()
{
	SecureWipePrivateKey();
}

void LiveBroadcastSession::SecureWipePrivateKey()
{
	volatile std::uint8_t* byte = identity_.private_key.data();
	for (std::size_t index = 0; index < identity_.private_key.size(); ++index)
		byte[index] = 0u;
}

std::uint64_t LiveBroadcastSession::NextGeneration(std::uint64_t current)
{
	++current;
	return current == 0u ? 1u : current;
}

bool LiveBroadcastSession::Start(const LiveBroadcastIdentity& identity)
{
	if (active_)
		return false;

	identity_ = identity;
	generation_ = NextGeneration(generation_);
	next_sequence_ = 0u;
	active_ = true;
	return true;
}

bool LiveBroadcastSession::Stop()
{
	if (!active_)
		return false;

	active_ = false;
	next_sequence_ = 0u;
	SecureWipePrivateKey();
	return true;
}

bool LiveBroadcastSession::Matches(
	const std::uint8_t* stream_key,
	std::size_t size) const
{
	return active_ && stream_key != nullptr &&
		size == identity_.stream_key.size() &&
		std::memcmp(
			identity_.stream_key.data(),
			stream_key,
			identity_.stream_key.size()) == 0;
}

bool LiveBroadcastSession::NextSequence(std::uint32_t& sequence)
{
	if (!active_)
		return false;
	sequence = next_sequence_++;
	return true;
}

} // namespace live
} // namespace ese
