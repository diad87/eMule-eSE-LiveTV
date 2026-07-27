#include "../ClientTransferPolicy.h"
#include "../IPv6FallbackPolicy.h"
#include "../IPv6EndpointPolicy.h"
#include "../IPv6RoutePolicy.h"
#include "../KnownFileHashPolicy.h"
#include "../SourceResolutionPolicy.h"
#include "../kademlia/kademlia/KadPublishPolicy.h"

#include <cstdint>
#include <cstdio>
#include <ctime>

static int failures = 0;

#define CHECK(condition, message) do { \
	if (!(condition)) { \
		std::printf("FAIL: %s\n", message); \
		++failures; \
	} \
} while (0)

int main()
{
	const std::uint64_t partSize = 9728000;

	CHECK(KnownFileHashPolicy::UsesDirectFileHash(0, partSize),
		"an empty file uses its direct MD4 hash");
	CHECK(KnownFileHashPolicy::UsesDirectFileHash(partSize - 1, partSize),
		"a sub-part file uses its direct MD4 hash");
	CHECK(!KnownFileHashPolicy::UsesDirectFileHash(partSize, partSize),
		"an exact-part file must use a hashset");
	CHECK(KnownFileHashPolicy::NeedsTrailingEmptyPart(0, partSize, partSize),
		"an exact-part file must append the empty-part MD4");
	CHECK(!KnownFileHashPolicy::NeedsTrailingEmptyPart(0, 0, partSize),
		"the trailing empty part must be appended only once");
	CHECK(!KnownFileHashPolicy::NeedsTrailingEmptyPart(0, 1, partSize),
		"a partial final part must not append an empty-part MD4");

	CHECK(!ClientTransferPolicy::CanUseDownloadQueueFile(false, 0, partSize),
		"a missing requested file must receive File Not Found");
	CHECK(ClientTransferPolicy::CanUseDownloadQueueFile(true, partSize, partSize),
		"a one-part download-queue file may answer SetReqFileID");
	CHECK(!ClientTransferPolicy::CanUseDownloadQueueFile(true, partSize + 1, partSize),
		"a multi-part download-queue file must receive File Not Found");
	CHECK(ClientTransferPolicy::ClassifyPostBlock(true, false)
		== ClientTransferPolicy::PostBlockAction::Cancel,
		"a stopped file must cancel the transfer");
	CHECK(ClientTransferPolicy::ClassifyPostBlock(true, true)
		== ClientTransferPolicy::PostBlockAction::Cancel,
		"stopped state must take precedence over paused/error state");
	CHECK(ClientTransferPolicy::ClassifyPostBlock(false, true)
		== ClientTransferPolicy::PostBlockAction::Requeue,
		"a paused or erroneous active file must requeue");
	CHECK(ClientTransferPolicy::ClassifyPostBlock(false, false)
		== ClientTransferPolicy::PostBlockAction::KeepConnected,
		"a healthy active file must stay connected");

	IPv6FallbackPolicy::State fallback = {
		true, true, true, false, false, true, false, true
	};
	CHECK(IPv6FallbackPolicy::IsEligible(fallback),
		"a half-open dual-stack HighID peer may fall back once");
	CHECK(!IPv6FallbackPolicy::HasElapsed(12999u, 10000u),
		"IPv6 fallback must not fire before 3000 ms");
	CHECK(IPv6FallbackPolicy::HasElapsed(13000u, 10000u),
		"IPv6 fallback fires at the 3000 ms boundary");
	CHECK(IPv6FallbackPolicy::HasElapsed(0x00000AB8u, 0xFFFFFF00u),
		"IPv6 fallback delay survives GetTickCount wrap");
	CHECK(!IPv6FallbackPolicy::HasElapsed(
		0x00000AAFu, 0xFFFF5AF0u, 45000u),
		"the logical 45-second connection deadline must not fire early across wrap");
	CHECK(IPv6FallbackPolicy::HasElapsed(
		0x00000AB8u, 0xFFFF5AF0u, 45000u),
		"the logical 45-second connection deadline fires exactly across wrap");

	fallback.halfOpen = false;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a completed socket cannot start an address-family fallback");
	fallback.halfOpen = true;
	fallback.clientOwnsSocket = false;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a detached or replaced client socket cannot fall back");
	fallback.clientOwnsSocket = true;
	fallback.lowId = true;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a LowID peer never uses a synthetic direct IPv4 fallback");
	fallback.lowId = false;
	fallback.ipv6Only = true;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"an IPv6-only peer has no IPv4 fallback");
	fallback.ipv6Only = false;
	fallback.hasIPv4 = false;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a peer without a real IPv4 address has no fallback");
	fallback.hasIPv4 = true;
	fallback.proxyConnectFailed = true;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a failed proxy connection is not retried as an address-family failure");
	fallback.proxyConnectFailed = false;
	fallback.directTransport = false;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a proxy handshake is never classified as a direct IPv6 blackhole");
	fallback.directTransport = true;
	fallback.armed = false;
	CHECK(!IPv6FallbackPolicy::IsEligible(fallback),
		"a disarmed fallback cannot run twice");

	const std::uint32_t realV4 = 0x01020304u;
	const std::uint32_t syntheticV4 = 0xA1B2C3D4u;
	CHECK(IPv6EndpointPolicy::SelectRealIPv4(
		realV4, realV4, true, syntheticV4) == realV4,
		"a dual-stack peer retains its real IPv4 route");
	CHECK(IPv6EndpointPolicy::SelectRealIPv4(
		syntheticV4, syntheticV4, true, syntheticV4) == 0,
		"an IPv6-only peer cannot use its synthetic uint32 as IPv4");
	CHECK(IPv6EndpointPolicy::SelectRealIPv4(
		IPv6EndpointPolicy::ByteSwap32(syntheticV4), 0, true,
		syntheticV4) == 0,
		"the opposite byte order of a synthetic uint32 is also rejected");
	CHECK(IPv6EndpointPolicy::SelectRealIPv4(
		syntheticV4, realV4, true, syntheticV4) == realV4,
		"a preserved real user IPv4 repairs a synthetic connect slot");
	CHECK(IPv6EndpointPolicy::SelectRealIPv4(
		realV4, 0, false, syntheticV4) == realV4,
		"an IPv4-only peer keeps the legacy route unchanged");

	CHECK(IPv6RoutePolicy::HasStableHelloRoute(true, true),
		"a current WIRE+DUALSTACK HELLO enables the stable IPv6 route");
	CHECK(!IPv6RoutePolicy::HasStableHelloRoute(true, false),
		"WIRE alone must not claim an inbound-capable IPv6 route");
	CHECK(!IPv6RoutePolicy::HasStableHelloRoute(false, true),
		"DUALSTACK without IPv6 wire negotiation is not routable");
	CHECK(IPv6RoutePolicy::HasNetLabReachRoute(true, true, true),
		"cold Kad reach metadata requires bilateral NetLab participation");
	CHECK(!IPv6RoutePolicy::HasNetLabReachRoute(true, false, true),
		"local NetLab revocation closes the cold Kad reach route");
	CHECK(!IPv6RoutePolicy::HasNetLabReachRoute(true, true, false),
		"peer NetLab revocation closes the cold Kad reach route");

	CHECK(SourceResolutionPolicy::CanonicalizeHostname(
		"[D01-DUAL.Example.]") == "d01-dual.example",
		"source-resolution hostname hashing uses the documented canonical form");
	const SourceResolutionPolicy::Endpoint sourceV4 = {
		4, { 203, 0, 113, 7 }, 0x1234
	};
	const std::vector<std::uint8_t> encodedSourceV4 =
		SourceResolutionPolicy::EncodeEndpoint(sourceV4);
	const std::vector<std::uint8_t> expectedSourceV4 = {
		4, 203, 0, 113, 7, 0x12, 0x34
	};
	CHECK(encodedSourceV4 == expectedSourceV4,
		"source-resolution endpoint encoding is family + network bytes + big-endian port");
	const SourceResolutionPolicy::Endpoint sourceV6 = {
		6, { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 7 }, 0x1234
	};
	const std::vector<SourceResolutionPolicy::Endpoint> unorderedEndpoints = {
		sourceV6, sourceV4, sourceV4
	};
	const std::vector<std::uint8_t> encodedEndpointSet =
		SourceResolutionPolicy::EncodeEndpointSet(unorderedEndpoints);
	CHECK(encodedEndpointSet.size() == 26
		&& std::equal(expectedSourceV4.begin(), expectedSourceV4.end(),
			encodedEndpointSet.begin()),
		"source-resolution endpoint sets are sorted and deduplicated");

	const std::time_t hour = 60 * 60;
	const std::time_t now = 10 * hour;
	CHECK(KadPublishPolicy::IsFastRefresh(now, now - 4 * hour + 1, 5 * hour, hour),
		"a Kad republish just inside the four-hour threshold is fast");
	CHECK(!KadPublishPolicy::IsFastRefresh(now, now - 4 * hour, 5 * hour, hour),
		"the exact Kad republish threshold is not fast");
	CHECK(KadPublishPolicy::IsFastRefresh(now, now + 1, 5 * hour, hour),
		"a backwards clock step is conservatively treated as fast");
	CHECK(!KadPublishPolicy::IsFastRefresh(now, now, hour, hour),
		"an invalid Kad interval/tolerance pair must not underflow");

	if (failures != 0)
		return 1;
	std::printf("eMule 0.70b core regression policies: PASS\n");
	return 0;
}
