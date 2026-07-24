#include "../PartFileIoPolicy.h"

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
	const std::uint32_t minute = 60u * 1000u;
	int idleFlushes = 0;
	for (int i = 0; i < 1225; ++i) {
		if (PartFileIoPolicy::ShouldRunPeriodicFlush(
			0, 1024, false, false, false, minute, 0, minute))
		{
			++idleFlushes;
		}
	}
	CHECK(idleFlushes == 0,
		"1225 clean idle part files must schedule no periodic flushes");

	CHECK(PartFileIoPolicy::ShouldPersistMetadata(
		true, false, minute, minute, PartFileIoPolicy::kStatsHeartbeatMs),
		"hard metadata changes must be persisted immediately");
	CHECK(!PartFileIoPolicy::ShouldPersistMetadata(
		false, true, 9u * minute, 0, PartFileIoPolicy::kStatsHeartbeatMs),
		"soft statistics must wait for their heartbeat");
	CHECK(PartFileIoPolicy::ShouldPersistMetadata(
		false, true, 10u * minute, 0, PartFileIoPolicy::kStatsHeartbeatMs),
		"soft statistics must be persisted at the heartbeat");

	CHECK(PartFileIoPolicy::StartBufferWindow(0, 42, 7) == 42,
		"the first buffered byte must start a fresh flush window");
	CHECK(PartFileIoPolicy::StartBufferWindow(1, 42, 7) == 7,
		"more buffered data must retain the existing flush window");
	CHECK(PartFileIoPolicy::ShouldRunPeriodicFlush(
		2049, 2048, false, false, false, 1, 1, minute),
		"exceeding the buffer limit must flush immediately");
	CHECK(!PartFileIoPolicy::ShouldRunPeriodicFlush(
		1, 2048, false, false, false, minute - 1, 0, minute),
		"a small buffered write must retain the normal flush window");
	CHECK(PartFileIoPolicy::ShouldRunPeriodicFlush(
		1, 2048, false, false, false, minute, 0, minute),
		"a small buffered write must flush when its window expires");
	CHECK(PartFileIoPolicy::ShouldRunPeriodicFlush(
		0, 2048, true, false, false, minute, 0, minute),
		"due metadata must flush after the normal interval");
	CHECK(!PartFileIoPolicy::ShouldRunPeriodicFlush(
		0, 2048, false, true, false, minute - 1, 0, minute),
		"pending completion work must respect its polling interval");
	CHECK(PartFileIoPolicy::ShouldRunPeriodicFlush(
		0, 2048, false, true, false, minute, 0, minute),
		"pending completion work must continue to be polled");
	CHECK(PartFileIoPolicy::ShouldRunPeriodicFlush(
		0, 2048, false, true, true, 1, 1, minute),
		"a ready completion must run without waiting for another interval");

	CHECK(PartFileIoPolicy::HasElapsed(0x10u, 0xfffffff0u, 0x20u),
		"elapsed-time checks must survive the 32-bit tick rollover");
	CHECK(PartFileIoPolicy::HasReachedDeadline(0x10u, 0xfffffff0u),
		"an expired deadline before rollover must remain expired");
	CHECK(!PartFileIoPolicy::HasReachedDeadline(0xfffffff0u, 0x20u),
		"a deadline after rollover must not fire early");
	CHECK(PartFileIoPolicy::HasReachedDeadline(1u, 0u),
		"deadline zero must mean no rate-limit deadline");

	if (failures != 0)
		return 1;
	std::printf("eMule 0.70b part-file I/O policy: PASS\n");
	return 0;
}
