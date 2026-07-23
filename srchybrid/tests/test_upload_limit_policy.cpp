#include "../UploadLimitPolicy.h"

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
	const std::uint32_t unlimited = 0xFFFFFFFFu;

	CHECK(UploadLimitPolicy::EffectiveMaximum(80u, 100u, unlimited) == 80u,
		"manual limit must win");
	CHECK(UploadLimitPolicy::EffectiveMaximum(unlimited, 100u, unlimited) == 100u,
		"configured capacity must control uncapped mode");
	CHECK(UploadLimitPolicy::EffectiveMaximum(unlimited, unlimited, unlimited) == unlimited,
		"estimator is only used when both values are unknown");
	CHECK(UploadLimitPolicy::EffectiveMaximum(1u, unlimited, unlimited) == 1u,
		"small explicit limits must be preserved");

	if (failures != 0)
		return 1;
	std::printf("upload limit policy: PASS\n");
	return 0;
}
