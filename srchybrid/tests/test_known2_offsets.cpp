#include "../Known2MetOffset.h"

#include <cstdio>
#include <cstdint>

static int failures = 0;

#define CHECK(condition, message) do { \
	if (!(condition)) { \
		std::printf("FAIL: %s\n", message); \
		++failures; \
	} \
} while (0)

int main()
{
	const std::uint64_t above4GiB = (std::uint64_t(5) << 30);
	const std::uint32_t hashSize = 20;

	CHECK(Known2MetOffset::IsHashBlockWithinFile(above4GiB, 3, above4GiB + 60, hashSize),
		"valid records above 4 GiB must be accepted");
	CHECK(Known2MetOffset::IsHashBlockWithinFile(above4GiB, 3, above4GiB + 61, hashSize),
		"a block may leave trailing bytes for the next record");
	CHECK(!Known2MetOffset::IsHashBlockWithinFile(above4GiB, 4, above4GiB + 60, hashSize),
		"a truncated block above 4 GiB must be rejected");
	CHECK(!Known2MetOffset::IsHashBlockWithinFile(UINT64_MAX - 5, UINT32_MAX, UINT64_MAX, hashSize),
		"the bounds check must not overflow near UINT64_MAX");
	CHECK(!Known2MetOffset::IsHashBlockWithinFile(101, 0, 100, hashSize),
		"a position beyond the file must be rejected");
	CHECK(!Known2MetOffset::IsHashBlockWithinFile(0, 1, 100, 0),
		"a zero hash size must be rejected");

	if (failures != 0)
		return 1;
	std::printf("known2.met 64-bit offsets: PASS\n");
	return 0;
}
