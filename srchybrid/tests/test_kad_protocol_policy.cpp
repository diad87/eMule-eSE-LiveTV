#include "../kademlia/kademlia/KadProtocolPolicy.h"

#include <cstdint>
#include <cstdio>

static int failures = 0;

#define CHECK(condition, message) do { \
	if (!(condition)) { \
		std::printf("FAIL: %s\n", message); \
		++failures; \
	} \
} while (0)

int main()
{
	CHECK(!KadProtocolPolicy::HasReachedTick(99, 100),
		"a Buddy deadline must not fire early");
	CHECK(KadProtocolPolicy::HasReachedTick(100, 100),
		"a Buddy deadline fires at equality");
	CHECK(KadProtocolPolicy::HasReachedTick(101, 100),
		"a Buddy deadline remains reached afterwards");

	const std::uint32_t wrappedDeadline = 0x00000020u;
	CHECK(!KadProtocolPolicy::HasReachedTick(0xFFFFFFF0u, wrappedDeadline),
		"a wrapped Buddy deadline must not fire before GetTickCount rolls over");
	CHECK(!KadProtocolPolicy::HasReachedTick(0x0000001Fu, wrappedDeadline),
		"a wrapped Buddy deadline must remain pending immediately before expiry");
	CHECK(KadProtocolPolicy::HasReachedTick(0x00000020u, wrappedDeadline),
		"a wrapped Buddy deadline fires at the correct post-rollover tick");

	const std::uint32_t peerIP = 0x01020304u;
	const std::uint16_t peerPort = 4672;
	CHECK(KadProtocolPolicy::IsExpectedResponseEndpoint(
		peerIP, peerPort, peerIP, peerPort),
		"an exact Kad response endpoint is accepted");
	CHECK(!KadProtocolPolicy::IsExpectedResponseEndpoint(
		peerIP, peerPort, peerIP, peerPort + 1),
		"a changed UDP source port must not inherit a contact identity");
	CHECK(!KadProtocolPolicy::IsExpectedResponseEndpoint(
		peerIP, peerPort, peerIP + 1, peerPort),
		"a different IP must not inherit a contact identity");

	CHECK(KadProtocolPolicy::IsResponseContactCountAllowed(0, 0),
		"an empty response is within an empty contact allowance");
	CHECK(KadProtocolPolicy::IsResponseContactCountAllowed(10, 10),
		"a response at the requested contact limit is accepted");
	CHECK(!KadProtocolPolicy::IsResponseContactCountAllowed(11, 10),
		"a response above the requested contact limit is rejected");

	if (failures != 0)
		return 1;
	std::printf("Kad protocol regression policies: PASS\n");
	return 0;
}
