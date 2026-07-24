#include "../kademlia/kademlia/KadNetworkPolicy.h"

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
	using namespace KadNetworkPolicy;

	CHECK(IsValid(None) && IsValid(Kad2) && IsValid(Kad6) && IsValid(Both),
		"all four supported masks are valid");
	CHECK(!IsValid(-1) && !IsValid(4) && !IsValid(255),
		"missing, unknown and corrupt masks are invalid");

	CHECK(Migrate(-1, true) == Both,
		"a legacy enabled profile migrates to Kad2 plus Kad6");
	CHECK(Migrate(255, true) == Both,
		"a corrupt enabled profile falls back to Kad2 plus Kad6");
	CHECK(Migrate(-1, false) == None,
		"a legacy disabled profile remains disabled");
	CHECK(Migrate(Kad2, true) == Kad2 && Migrate(Kad6, true) == Kad6,
		"an explicit valid selection wins over the legacy setting");

	CHECK(Effective(Both, true) == Both,
		"both networks are effective when UDP is available");
	CHECK(Effective(Both, false) == None,
		"disabling UDP suspends both networks without changing the selection");
	CHECK(Effective(255, true) == None,
		"an invalid in-memory mask fails closed");

	CHECK(HasKad2(Kad2) && HasKad2(Both) && !HasKad2(Kad6),
		"Kad2 membership follows bit zero");
	CHECK(HasKad6(Kad6) && HasKad6(Both) && !HasKad6(Kad2),
		"Kad6 membership follows bit one");
	CHECK(!LegacyKad2Enabled(None) && LegacyKad2Enabled(Kad2)
		&& !LegacyKad2Enabled(Kad6) && LegacyKad2Enabled(Both),
		"legacy boolean preserves Kad2 intent and fails closed for Kad6-only");

	CHECK(Added(Kad2, Both) == Kad6,
		"enabling dual mode adds only Kad6");
	CHECK(Removed(Both, Kad6) == Kad2,
		"switching to Kad6-only removes only Kad2");
	CHECK(Added(None, Both) == Both && Removed(Both, None) == Both,
		"full start and stop transitions contain both planes");

	CHECK(Intersect(Both, Kad2) == Kad2,
		"requested dual discovery is constrained to the available plane");
	CHECK(Intersect(Kad6, Kad2) == None,
		"an unavailable requested plane never silently falls back");

	if (failures != 0)
		return 1;
	std::printf("Kad network policy: PASS\n");
	return 0;
}
