#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ese {
namespace live {

struct LiveBroadcastIdentity {
	std::array<std::uint8_t, 16> stream_key{};
	std::array<std::uint8_t, 32> public_key{};
	std::array<std::uint8_t, 32> private_key{};
};

class LiveBroadcastSession final
{
public:
	~LiveBroadcastSession();

	bool Start(const LiveBroadcastIdentity& identity);
	bool Stop();

	bool IsActive() const { return active_; }
	bool Matches(const std::uint8_t* stream_key, std::size_t size) const;
	bool NextSequence(std::uint32_t& sequence);

	std::uint64_t Generation() const { return generation_; }
	const std::array<std::uint8_t, 16>& StreamKey() const
	{
		return identity_.stream_key;
	}
	const std::array<std::uint8_t, 32>& PublicKey() const
	{
		return identity_.public_key;
	}
	const std::array<std::uint8_t, 32>& PrivateKey() const
	{
		return identity_.private_key;
	}

private:
	static std::uint64_t NextGeneration(std::uint64_t current);
	void SecureWipePrivateKey();

	bool active_ = false;
	std::uint64_t generation_ = 0;
	std::uint32_t next_sequence_ = 0;
	LiveBroadcastIdentity identity_;
};

} // namespace live
} // namespace ese
