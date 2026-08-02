#include "natmap/upnp_discovery.h"

#include <cstdio>
#include <type_traits>

using namespace natmap;

namespace {

int failures = 0;
int checks = 0;

#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; \
    std::printf("FAIL line %d: %s\n", __LINE__, #expr); } } while (0)

UpnpIgdObservation Candidate(UpnpIgdQuality quality,
                             bool control = true,
                             bool service = true) {
    return UpnpIgdObservation{quality, control, service};
}

void TestValidIgdStopsSearch() {
    UpnpDiscoverySelection selection;
    CHECK(selection.status() == UpnpDiscoveryStatus::Searching);
    CHECK(selection.should_continue());
    CHECK(!selection.has_candidate());
    CHECK(selection.Consider(Candidate(UpnpIgdQuality::Connected)));
    CHECK(selection.status() == UpnpDiscoveryStatus::Selected);
    CHECK(!selection.should_continue());
    CHECK(selection.has_candidate());
    CHECK(selection.selected_quality() == UpnpIgdQuality::Connected);
}

void TestInvalidFirstThenValid() {
    UpnpDiscoverySelection selection;
    CHECK(!selection.Consider(Candidate(UpnpIgdQuality::None)));
    CHECK(!selection.Consider(
        Candidate(UpnpIgdQuality::Connected, false, true)));
    CHECK(!selection.Consider(
        Candidate(UpnpIgdQuality::Connected, true, false)));
    CHECK(selection.should_continue());
    CHECK(selection.selected_quality() == UpnpIgdQuality::None);
    CHECK(selection.Consider(Candidate(UpnpIgdQuality::Connected)));
    CHECK(selection.status() == UpnpDiscoveryStatus::Selected);
}

void TestBestCandidateAtEnd() {
    UpnpDiscoverySelection selection;
    CHECK(selection.Consider(
        Candidate(UpnpIgdQuality::UnknownDevice)));
    CHECK(selection.Consider(
        Candidate(UpnpIgdQuality::Disconnected)));
    CHECK(selection.Consider(
        Candidate(UpnpIgdQuality::PrivateAddress)));
    CHECK(selection.status() == UpnpDiscoveryStatus::Selected);
    CHECK(selection.has_candidate());
    CHECK(selection.selected_quality() ==
          UpnpIgdQuality::PrivateAddress);
    CHECK(!selection.Consider(Candidate(UpnpIgdQuality::Connected)));
    CHECK(selection.selected_quality() ==
          UpnpIgdQuality::PrivateAddress);
}

void TestTimeoutIsTerminal() {
    UpnpDiscoverySelection selection;
    selection.Complete();
    CHECK(selection.status() == UpnpDiscoveryStatus::TimedOut);
    CHECK(!selection.should_continue());
    CHECK(!selection.has_candidate());
    CHECK(selection.selected_quality() == UpnpIgdQuality::None);
    CHECK(!selection.Consider(Candidate(UpnpIgdQuality::Connected)));
    selection.Complete();
    CHECK(selection.status() == UpnpDiscoveryStatus::TimedOut);
}

void TestCancellationWinsBeforePublication() {
    UpnpDiscoverySelection selection;
    CHECK(selection.Consider(
        Candidate(UpnpIgdQuality::PrivateAddress)));
    selection.Cancel();
    CHECK(selection.status() == UpnpDiscoveryStatus::Cancelled);
    CHECK(!selection.should_continue());
    CHECK(!selection.has_candidate());
    CHECK(selection.selected_quality() == UpnpIgdQuality::None);
    CHECK(!selection.Consider(Candidate(UpnpIgdQuality::Connected)));
    selection.Complete();
    CHECK(selection.status() == UpnpDiscoveryStatus::Cancelled);

    UpnpDiscoverySelection connected;
    CHECK(connected.Consider(Candidate(UpnpIgdQuality::Connected)));
    connected.Cancel();
    CHECK(connected.status() == UpnpDiscoveryStatus::Cancelled);
    CHECK(!connected.has_candidate());
    connected.Cancel();
    CHECK(connected.status() == UpnpDiscoveryStatus::Cancelled);
}

void TestInvalidEnumFailsClosed() {
    UpnpDiscoverySelection selection;
    const UpnpIgdObservation invalid{
        static_cast<UpnpIgdQuality>(255), true, true};
    CHECK(!selection.Consider(invalid));
    CHECK(selection.status() == UpnpDiscoveryStatus::Searching);
    selection.Complete();
    CHECK(selection.status() == UpnpDiscoveryStatus::TimedOut);
}

} // namespace

int main() {
    static_assert(!std::is_copy_constructible_v<UpnpDiscoverySelection>);
    static_assert(!std::is_copy_assignable_v<UpnpDiscoverySelection>);
    static_assert(!std::is_move_constructible_v<UpnpDiscoverySelection>);
    static_assert(!std::is_move_assignable_v<UpnpDiscoverySelection>);

    TestValidIgdStopsSearch();
    TestInvalidFirstThenValid();
    TestBestCandidateAtEnd();
    TestTimeoutIsTerminal();
    TestCancellationWinsBeforePublication();
    TestInvalidEnumFailsClosed();

    std::printf("test_upnp_discovery: %d checks, %d failures\n",
                checks, failures);
    return failures == 0 ? 0 : 1;
}
