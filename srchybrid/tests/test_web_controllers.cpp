#include "../WebSearchController.h"
#include "../WebSharedController.h"
#include "../WebTransferController.h"

#include <cstdio>
#include <limits>
#include <string>

namespace {

int failures = 0;

void Check(bool condition, const char* message)
{
	if (!condition) {
		std::fprintf(stderr, "FAIL: %s\n", message);
		++failures;
	}
}

void TestTransferController()
{
	using namespace ese::web;
	const std::string hash(32, 'a');
	const WebTransferFileAction rename =
		WebTransferController::PlanFileAction(
			true, "rename", hash, "new name", "");
	Check(
		rename.allowed &&
			rename.operation == WebTransferFileOperation::Rename &&
			rename.file_hash == hash && rename.text == "new name",
		"admin rename must produce an immutable typed action");
	const WebTransferFileAction seek =
		WebTransferController::PlanFileAction(
			true, "streamseek", hash, "", "42");
	Check(
		seek.allowed && seek.value == 42,
		"stream seek must parse the complete bounded numeric value");
	Check(
		!WebTransferController::PlanFileAction(
			false, "cancel", hash, "", "").allowed,
		"non-admin transfer mutation must fail closed");
	Check(
		!WebTransferController::PlanFileAction(
			true, "unknown", hash, "", "").allowed,
		"unknown transfer operation must fail closed");
	Check(
		!WebTransferController::PlanFileAction(
			true, "setcat", hash, "", "1x").allowed,
		"partial numeric category input must fail closed");
	Check(
		!WebTransferController::PlanFileAction(
			true, "pause", "not-a-hash", "", "").allowed,
		"invalid transfer hash must fail closed");

	const WebTransferFriendAction add =
		WebTransferController::PlanFriendAction(
			true, "addfriend", hash);
	Check(
		add.allowed &&
			add.operation == WebTransferFriendOperation::Add,
		"friend mutation must own its exact action vocabulary");
	Check(
		!WebTransferController::PlanFriendAction(
			true, "friend", hash).allowed,
		"unknown friend mutation must fail closed");

	const WebTransferColumnChange download =
		WebTransferController::PlanColumnChange(
			"menudown", "7", "1");
	Check(
		download.allowed &&
			download.group == WebTransferColumnGroup::Download &&
			download.index == 7 && download.hidden,
		"last valid download column must be accepted");
	Check(
		!WebTransferController::PlanColumnChange(
			"menudown", "8", "1").allowed &&
			!WebTransferController::PlanColumnChange(
				"menuup", "5", "1").allowed &&
			!WebTransferController::PlanColumnChange(
				"menuqueue", "4", "1").allowed,
		"every out-of-range transfer column must fail closed");

	const WebTransferSortDecision named =
		WebTransferController::PlanSort("dname", "");
	Check(
		named.allowed && named.reverse &&
			named.sort == WebTransferSort::DownloadName &&
			named.domain == WebTransferSortDomain::Download &&
			named.target_index == 2,
		"download-name sorting must preserve legacy default direction");
	const WebTransferSortDecision uploadUser =
		WebTransferController::PlanSort("uuser", "");
	Check(
		uploadUser.allowed &&
			uploadUser.domain == WebTransferSortDomain::Upload &&
			uploadUser.target_index == 1,
		"upload-user sorting must map to the legacy adapter enum");
	const WebTransferSortDecision queueScore =
		WebTransferController::PlanSort("qscore", "");
	Check(
		queueScore.allowed &&
			queueScore.domain == WebTransferSortDomain::Queue &&
			queueScore.target_index == 4,
		"queue-score sorting must map to the legacy adapter enum");
	const WebTransferSortDecision explicitDirection =
		WebTransferController::PlanSort("dname", "false");
	Check(
		explicitDirection.allowed && !explicitDirection.reverse,
		"explicit transfer sort direction must override the default");
	Check(
		!WebTransferController::PlanSort("dname", "maybe").allowed,
		"invalid transfer sort direction must fail closed");

	const WebTransferPriorityDecision priority =
		WebTransferController::PlanCategoryPriority(true, "auto");
	Check(
		priority.allowed &&
			priority.priority == WebTransferCategoryPriority::Auto,
		"category priority must preserve the exact auto token");
	Check(
		!WebTransferController::PlanCategoryPriority(
			true, "unexpected").allowed,
		"unknown category priority must fail closed");
	bool output = false;
	Check(
		WebTransferController::TryApplyBoolean(false, "true", output) &&
			output &&
			!WebTransferController::TryApplyBoolean(true, "yes", output),
		"transfer display flags must accept only exact booleans");
}

void TestSearchController()
{
	using namespace ese::web;
	const WebSearchRequest request = WebSearchController::PlanSearch(
		true, "linux", "archive", "1", "2", "25", "zip", "global");
	Check(
		request.allowed && request.method == WebSearchMethod::Global &&
			request.minimum_bytes == 1048576u &&
			request.maximum_bytes == 2097152u &&
			request.availability == 25,
		"search plan must preserve exact valid size and method semantics");
	Check(
		!WebSearchController::PlanSearch(
			false, "linux", "", "", "", "", "", "").allowed,
		"non-admin search dispatch must fail closed");
	Check(
		!WebSearchController::PlanSearch(
			true, "linux", "executable", "", "", "", "", "").allowed,
		"unknown search file type must fail closed");
	Check(
		!WebSearchController::PlanSearch(
			true, "linux", "", "18446744073709551615", "", "", "", "")
			.allowed,
		"search size multiplication overflow must fail closed");
	Check(
		!WebSearchController::PlanSearch(
			true, "linux", "", "", "", "1000001", "", "").allowed,
		"search availability above one million must fail closed");

	const std::string a(32, 'a');
	const std::string b(32, 'B');
	const std::vector<std::string> downloads =
		WebSearchController::PlanDownloads(
			true, a + "|bad|" + b + "|");
	Check(
		downloads.size() == 2 &&
			downloads[0] == a && downloads[1] == b,
		"search downloads must retain only exact MD4 hex hashes");
	Check(
		WebSearchController::PlanDownloads(false, a).empty(),
		"non-admin search downloads must fail closed");

	Check(
		WebSearchController::PlanColumnChange("3", "1").allowed &&
			!WebSearchController::PlanColumnChange("4", "1").allowed,
		"search column bounds must be exact");
	Check(
		WebSearchController::PlanSort("3", "1", 0, false).allowed &&
			!WebSearchController::PlanSort("4", "1", 0, false).allowed,
		"search sort column bounds must be exact");
	Check(
		std::string(WebSearchController::SourceImageBucket(4)) == "0" &&
			std::string(WebSearchController::SourceImageBucket(5)) == "5" &&
			std::string(WebSearchController::SourceImageBucket(10)) == "10" &&
			std::string(WebSearchController::SourceImageBucket(25)) == "25" &&
			std::string(WebSearchController::SourceImageBucket(50)) == "50",
		"search result source buckets must preserve every threshold");
}

void TestSharedController()
{
	using namespace ese::web;
	const std::string hash(32, 'f');
	const WebSharedSortDecision named =
		WebSharedController::PlanSort("name", "");
	Check(
		named.allowed && named.reverse &&
			named.sort == WebSharedSort::Name &&
			named.target_index == 2,
		"shared-name sorting must preserve legacy default direction");
	Check(
		WebSharedController::PlanSort("requests", "true").allowed &&
			!WebSharedController::PlanSort("requests", "yes").allowed,
		"shared sort direction must accept only exact booleans");

	const WebSharedPriorityDecision release =
		WebSharedController::PlanPriority(true, hash, "release");
	Check(
		release.allowed &&
			release.priority == WebSharedPriority::Release &&
			release.file_hash == hash,
		"shared priority must bind the validated hash and exact token");
	Check(
		!WebSharedController::PlanPriority(
			false, hash, "release").allowed &&
			!WebSharedController::PlanPriority(
				true, hash, "surprise").allowed,
		"shared priority must require admin and reject unknown values");
	Check(
		WebSharedController::PlanColumnChange("6", "0").allowed &&
			!WebSharedController::PlanColumnChange("7", "0").allowed,
		"shared column bounds must be exact");
}

} // namespace

int main()
{
	TestTransferController();
	TestSearchController();
	TestSharedController();
	if (failures != 0) {
		std::fprintf(stderr, "%d Web controller test(s) failed.\n", failures);
		return 1;
	}
	std::puts("Web controller tests passed.");
	return 0;
}
