#include "../ClientTransferPolicy.h"
#include "../KnownFileHashPolicy.h"
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
