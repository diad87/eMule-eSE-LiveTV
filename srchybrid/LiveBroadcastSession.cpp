#include "LiveBroadcastSession.h"

#include <cstring>

namespace ese {
namespace live {

namespace {

void SecureWipe(std::array<std::uint8_t, 32>& key)
{
	volatile std::uint8_t* byte = key.data();
	for (std::size_t index = 0; index < key.size(); ++index)
		byte[index] = 0u;
}

} // namespace

LiveBroadcastIdentity::~LiveBroadcastIdentity()
{
	SecureWipe(private_key);
}

LiveBroadcastIdentity::LiveBroadcastIdentity(
	LiveBroadcastIdentity&& other) noexcept
	: stream_key(other.stream_key),
	  public_key(other.public_key),
	  private_key(other.private_key)
{
	SecureWipe(other.private_key);
}

LiveBroadcastIdentity& LiveBroadcastIdentity::operator=(
	LiveBroadcastIdentity&& other) noexcept
{
	if (this != &other) {
		SecureWipe(private_key);
		stream_key = other.stream_key;
		public_key = other.public_key;
		private_key = other.private_key;
		SecureWipe(other.private_key);
	}
	return *this;
}

LiveBroadcastSession::~LiveBroadcastSession()
{
	SecureWipePrivateKey();
}

void LiveBroadcastSession::SecureWipePrivateKey()
{
	SecureWipe(identity_.private_key);
}

std::uint64_t LiveBroadcastSession::NextGeneration(std::uint64_t current)
{
	++current;
	return current == 0u ? 1u : current;
}

bool LiveBroadcastSession::Start(const LiveBroadcastIdentity& identity)
{
	if (IsActive())
		return false;

	identity_.stream_key = identity.stream_key;
	identity_.public_key = identity.public_key;
	identity_.private_key = identity.private_key;
	generation_ = NextGeneration(generation_);
	next_sequence_ = 0u;
	active_.store(true, std::memory_order_release);
	return true;
}

bool LiveBroadcastSession::Stop()
{
	if (!IsActive())
		return false;

	active_.store(false, std::memory_order_release);
	next_sequence_ = 0u;
	SecureWipePrivateKey();
	return true;
}

bool LiveBroadcastSession::Matches(
	const std::uint8_t* stream_key,
	std::size_t size) const
{
	return IsActive() && stream_key != nullptr &&
		size == identity_.stream_key.size() &&
		std::memcmp(
			identity_.stream_key.data(),
			stream_key,
			identity_.stream_key.size()) == 0;
}

bool LiveBroadcastSession::NextSequence(std::uint32_t& sequence)
{
	if (!IsActive())
		return false;
	sequence = next_sequence_++;
	return true;
}

} // namespace live
} // namespace ese
