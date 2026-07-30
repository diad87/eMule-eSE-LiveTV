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
	struct FileOperationCase {
		const char* token;
		WebTransferFileOperation operation;
	};
	const FileOperationCase fileOperations[] = {
		{"stop", WebTransferFileOperation::Stop},
		{"pause", WebTransferFileOperation::Pause},
		{"resume", WebTransferFileOperation::Resume},
		{"cancel", WebTransferFileOperation::Cancel},
		{"getflc", WebTransferFileOperation::GetFileLink},
		{"rename", WebTransferFileOperation::Rename},
		{"priolow", WebTransferFileOperation::PriorityLow},
		{"prionormal", WebTransferFileOperation::PriorityNormal},
		{"priohigh", WebTransferFileOperation::PriorityHigh},
		{"prioauto", WebTransferFileOperation::PriorityAuto},
		{"setcat", WebTransferFileOperation::SetCategory},
		{"streamseek", WebTransferFileOperation::StreamSeek}
	};
	for (const FileOperationCase& item : fileOperations) {
		const WebTransferFileAction action =
			WebTransferController::PlanFileAction(
				true, item.token, hash, "name", "7");
		Check(
			action.allowed && action.operation == item.operation,
			"every exact transfer file operation must map to its enum");
		Check(
			!WebTransferController::PlanFileAction(
				false, item.token, hash, "name", "7").allowed,
			"every transfer file operation must require admin");
	}
	Check(
		!WebTransferController::PlanFileAction(
			true, "setcat", hash, "",
			"999999999999999999999999").allowed,
		"transfer numeric overflow must fail closed");
	Check(
		WebTransferController::PlanClearCompleted(
			true, "ALL").allowed &&
			WebTransferController::PlanClearCompleted(
				true, "All").all &&
			!WebTransferController::PlanClearCompleted(
				false, "all").allowed &&
			WebTransferController::PlanAddDownload(
				true, "ed2k://|file|x|1|h|/").allowed &&
			!WebTransferController::PlanAddDownload(
				false, "ed2k://|file|x|1|h|/").allowed,
		"clear and add-download actions must preserve admin boundaries");

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
			true, "menudown", "7", "1");
	Check(
		download.allowed &&
			download.group == WebTransferColumnGroup::Download &&
			download.index == 7 && download.hidden,
		"last valid download column must be accepted");
	Check(
		!WebTransferController::PlanColumnChange(
			true, "menudown", "8", "1").allowed &&
			!WebTransferController::PlanColumnChange(
				true, "menuup", "5", "1").allowed &&
			!WebTransferController::PlanColumnChange(
				true, "menuqueue", "4", "1").allowed &&
			!WebTransferController::PlanColumnChange(
				true, "menudown", "0", "").allowed &&
			!WebTransferController::PlanColumnChange(
				false, "menudown", "0", "1").allowed,
		"every out-of-range transfer column must fail closed");

	const WebTransferSortDecision named =
		WebTransferController::PlanSort(true, "dname", "");
	Check(
		named.allowed && named.reverse &&
			named.sort == WebTransferSort::DownloadName &&
			named.domain == WebTransferSortDomain::Download &&
			named.target_index == 2,
		"download-name sorting must preserve legacy default direction");
	const WebTransferSortDecision uploadUser =
		WebTransferController::PlanSort(true, "uuser", "");
	Check(
		uploadUser.allowed &&
			uploadUser.domain == WebTransferSortDomain::Upload &&
			uploadUser.target_index == 1,
		"upload-user sorting must map to the legacy adapter enum");
	const WebTransferSortDecision queueScore =
		WebTransferController::PlanSort(true, "qscore", "");
	Check(
		queueScore.allowed &&
			queueScore.domain == WebTransferSortDomain::Queue &&
			queueScore.target_index == 4,
		"queue-score sorting must map to the legacy adapter enum");
	const WebTransferSortDecision explicitDirection =
		WebTransferController::PlanSort(true, "dname", "false");
	Check(
		explicitDirection.allowed && !explicitDirection.reverse,
		"explicit transfer sort direction must override the default");
	Check(
		!WebTransferController::PlanSort(true, "dname", "maybe").allowed &&
			!WebTransferController::PlanSort(
				false, "dname", "").allowed,
		"invalid transfer sort direction must fail closed");
	struct TransferSortCase {
		const char* token;
		WebTransferSort sort;
		WebTransferSortDomain domain;
		unsigned index;
		bool reverse;
	};
	const TransferSortCase transferSorts[] = {
		{"dstate", WebTransferSort::DownloadState, WebTransferSortDomain::Download, 0, false},
		{"dtype", WebTransferSort::DownloadType, WebTransferSortDomain::Download, 1, false},
		{"dname", WebTransferSort::DownloadName, WebTransferSortDomain::Download, 2, true},
		{"dsize", WebTransferSort::DownloadSize, WebTransferSortDomain::Download, 3, false},
		{"dtransferred", WebTransferSort::DownloadTransferred, WebTransferSortDomain::Download, 4, false},
		{"dspeed", WebTransferSort::DownloadSpeed, WebTransferSortDomain::Download, 5, false},
		{"dprogress", WebTransferSort::DownloadProgress, WebTransferSortDomain::Download, 6, false},
		{"dsources", WebTransferSort::DownloadSources, WebTransferSortDomain::Download, 7, false},
		{"dpriority", WebTransferSort::DownloadPriority, WebTransferSortDomain::Download, 8, false},
		{"dcategory", WebTransferSort::DownloadCategory, WebTransferSortDomain::Download, 9, true},
		{"uuser", WebTransferSort::UploadUser, WebTransferSortDomain::Upload, 1, true},
		{"uclient", WebTransferSort::UploadClient, WebTransferSortDomain::Upload, 0, false},
		{"uversion", WebTransferSort::UploadVersion, WebTransferSortDomain::Upload, 2, false},
		{"ufilename", WebTransferSort::UploadFilename, WebTransferSortDomain::Upload, 3, true},
		{"utransferred", WebTransferSort::UploadTransferred, WebTransferSortDomain::Upload, 4, false},
		{"uspeed", WebTransferSort::UploadSpeed, WebTransferSortDomain::Upload, 5, false},
		{"qclient", WebTransferSort::QueueClient, WebTransferSortDomain::Queue, 0, false},
		{"quser", WebTransferSort::QueueUser, WebTransferSortDomain::Queue, 1, true},
		{"qversion", WebTransferSort::QueueVersion, WebTransferSortDomain::Queue, 2, false},
		{"qfilename", WebTransferSort::QueueFilename, WebTransferSortDomain::Queue, 3, true},
		{"qscore", WebTransferSort::QueueScore, WebTransferSortDomain::Queue, 4, false}
	};
	for (const TransferSortCase& item : transferSorts) {
		const WebTransferSortDecision decision =
			WebTransferController::PlanSort(true, item.token, "");
		Check(
			decision.allowed && decision.sort == item.sort &&
				decision.domain == item.domain &&
				decision.target_index == item.index &&
				decision.reverse == item.reverse,
			"every exact transfer sort must map to enum/index/direction");
	}
	Check(
		WebTransferController::PlanSort(
			true, "dname", "TRUE").allowed &&
			WebTransferController::PlanSort(
				true, "dname", "FaLsE").reverse == false,
		"transfer sort direction must preserve case-insensitive baseline");

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
	const char* categoryTokens[] = {"low", "normal", "high", "auto"};
	const WebTransferCategoryPriority categoryValues[] = {
		WebTransferCategoryPriority::Low,
		WebTransferCategoryPriority::Normal,
		WebTransferCategoryPriority::High,
		WebTransferCategoryPriority::Auto
	};
	for (unsigned index = 0; index < 4; ++index) {
		const WebTransferPriorityDecision decision =
			WebTransferController::PlanCategoryPriority(
				true, categoryTokens[index]);
		Check(
			decision.allowed && decision.priority == categoryValues[index] &&
				!WebTransferController::PlanCategoryPriority(
					false, categoryTokens[index]).allowed,
			"every transfer category priority must map and require admin");
	}
	bool output = false;
	Check(
		WebTransferController::TryApplyBoolean(
			true, false, "true", output) &&
			output &&
			!WebTransferController::TryApplyBoolean(
				true, true, "yes", output) &&
			!WebTransferController::TryApplyBoolean(
				false, true, "false", output),
		"transfer display flags must accept only exact booleans");
	WebTransferDownloadComparison downloadComparisons;
	int* downloadValues[] = {
		&downloadComparisons.state, &downloadComparisons.type,
		&downloadComparisons.name, &downloadComparisons.size,
		&downloadComparisons.transferred, &downloadComparisons.speed,
		&downloadComparisons.progress, &downloadComparisons.sources,
		&downloadComparisons.priority, &downloadComparisons.category
	};
	for (unsigned index = 0; index < 10; ++index) {
		*downloadValues[index] = 7;
		Check(
			WebTransferController::CompareDownload(
				index, false, downloadComparisons) == -1 &&
				WebTransferController::CompareDownload(
					index, true, downloadComparisons) == 1,
			"every download comparator key must preserve direction");
		*downloadValues[index] = 0;
	}
	WebTransferUploadComparison uploadComparisons;
	int* uploadValues[] = {
		&uploadComparisons.client, &uploadComparisons.user,
		&uploadComparisons.version, &uploadComparisons.filename,
		&uploadComparisons.transferred, &uploadComparisons.speed
	};
	for (unsigned index = 0; index < 6; ++index) {
		*uploadValues[index] = 7;
		Check(
			WebTransferController::CompareUpload(
				index, false, uploadComparisons) == -1 &&
				WebTransferController::CompareUpload(
					index, true, uploadComparisons) == 1,
			"every upload comparator key must preserve direction");
		*uploadValues[index] = 0;
	}
}

void TestSearchController()
{
	using namespace ese::web;
	const WebSearchRequest request = WebSearchController::PlanSearch(
		true, "linux", "Arc", "1", "2", "25", "zip", "global");
	Check(
		request.allowed && request.method == WebSearchMethod::Global &&
			request.minimum_bytes == 1048576u &&
			request.maximum_bytes == 2097152u &&
			request.availability == 25,
		"search plan must preserve exact valid size and method semantics");
	const std::string decentralizedMethod = "kadem" "lia";
	Check(
		WebSearchController::PlanSearch(
			true, "linux", "", "", "", "", "",
			decentralizedMethod).method ==
			static_cast<WebSearchMethod>(2) &&
			WebSearchController::PlanSearch(
				true, "linux", "", "", "", "", "", "global").method ==
			WebSearchMethod::Global &&
			WebSearchController::PlanSearch(
				true, "linux", "", "", "", "", "", "").method ==
			WebSearchMethod::Server,
		"every search method token must map to its legacy enum");
	Check(
		!WebSearchController::PlanSearch(
			false, "linux", "", "", "", "", "", "").allowed,
		"non-admin search dispatch must fail closed");
	Check(
		!WebSearchController::PlanSearch(
			true, "linux", "executable", "", "", "", "", "").allowed,
		"unknown search file type must fail closed");
	const char* exactFileTypes[] = {
		"Arc", "Audio", "Iso", "Doc", "Image", "Pro", "Video",
		"EmuleCollection"
	};
	for (const char* fileType : exactFileTypes) {
		Check(
			WebSearchController::PlanSearch(
				true, "linux", fileType, "", "", "", "", "").allowed,
			"every exact Web UI file type must remain accepted");
	}
	Check(
		!WebSearchController::PlanSearch(
			true, "linux", "archive", "", "", "", "", "").allowed &&
			!WebSearchController::PlanSearch(
				true, "linux", "audio", "", "", "", "", "").allowed,
		"search file type aliases and casing drift must fail closed");
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
		WebSearchController::PlanColumnChange(true, "3", "1").allowed &&
			!WebSearchController::PlanColumnChange(
				true, "4", "1").allowed &&
			!WebSearchController::PlanColumnChange(
				false, "0", "1").allowed,
		"search column bounds must be exact");
	Check(
		WebSearchController::PlanSort(
			true, "3", "1", 0, false).allowed &&
			!WebSearchController::PlanSort(
				true, "4", "1", 0, false).allowed &&
			!WebSearchController::PlanSort(
				true, "3", "true", 0, false).allowed &&
			!WebSearchController::PlanSort(
				false, "3", "1", 0, false).allowed,
		"search sort column bounds must be exact");
	Check(
		std::string(WebSearchController::SourceImageBucket(4)) == "0" &&
			std::string(WebSearchController::SourceImageBucket(5)) == "5" &&
			std::string(WebSearchController::SourceImageBucket(10)) == "10" &&
			std::string(WebSearchController::SourceImageBucket(25)) == "25" &&
			std::string(WebSearchController::SourceImageBucket(50)) == "50",
		"search result source buckets must preserve every threshold");
	const WebSearchResultProjection downloading =
		WebSearchController::ProjectResult(true, true, 5);
	const WebSearchResultProjection known =
		WebSearchController::ProjectResult(false, true, 10);
	const WebSearchResultProjection unknown =
		WebSearchController::ProjectResult(false, false, 50);
	Check(
		downloading.red == 255 && downloading.green == 128 &&
			downloading.blue == 128 &&
			std::string(downloading.source_bucket) == "5" &&
			known.red == 128 && known.green == 255 && known.blue == 128 &&
			std::string(known.source_bucket) == "10" &&
			unknown.red == 255 && unknown.green == 255 &&
			unknown.blue == 255 &&
			std::string(unknown.source_bucket) == "50",
		"search result projection must own colors and source buckets");
}

void TestSharedController()
{
	using namespace ese::web;
	const std::string hash(32, 'f');
	const WebSharedSortDecision named =
		WebSharedController::PlanSort(true, "name", "");
	Check(
		named.allowed && named.reverse &&
			named.sort == WebSharedSort::Name &&
			named.target_index == 2,
		"shared-name sorting must preserve legacy default direction");
	Check(
		WebSharedController::PlanSort(
			true, "requests", "true").allowed &&
			!WebSharedController::PlanSort(
				true, "requests", "yes").allowed &&
			!WebSharedController::PlanSort(
				false, "requests", "true").allowed,
		"shared sort direction must accept only exact booleans");
	const WebSharedSortDecision directionOnly =
		WebSharedController::PlanSort(true, "", "true");
	Check(
		directionOnly.allowed && !directionOnly.update_sort &&
			directionOnly.update_reverse && directionOnly.reverse,
		"shared direction-only update must preserve the current sort");
	struct SharedSortCase {
		const char* token;
		WebSharedSort sort;
		unsigned index;
		bool reverse;
	};
	const SharedSortCase sharedSorts[] = {
		{"state", WebSharedSort::State, 0, false},
		{"type", WebSharedSort::Type, 1, false},
		{"name", WebSharedSort::Name, 2, true},
		{"size", WebSharedSort::Size, 3, false},
		{"transferred", WebSharedSort::Transferred, 4, false},
		{"alltimetransferred", WebSharedSort::AllTimeTransferred, 5, false},
		{"requests", WebSharedSort::Requests, 6, false},
		{"alltimerequests", WebSharedSort::AllTimeRequests, 7, false},
		{"accepts", WebSharedSort::Accepts, 8, false},
		{"alltimeaccepts", WebSharedSort::AllTimeAccepts, 9, false},
		{"completes", WebSharedSort::Completes, 10, false},
		{"priority", WebSharedSort::Priority, 11, false}
	};
	for (const SharedSortCase& item : sharedSorts) {
		const WebSharedSortDecision decision =
			WebSharedController::PlanSort(true, item.token, "");
		Check(
			decision.allowed && decision.update_sort &&
				decision.update_reverse && decision.sort == item.sort &&
				decision.target_index == item.index &&
				decision.reverse == item.reverse,
			"every shared sort must map to enum/index/direction");
	}

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
	const char* sharedPriorityTokens[] = {
		"verylow", "low", "normal", "high", "release", "auto"
	};
	const WebSharedPriority sharedPriorityValues[] = {
		WebSharedPriority::VeryLow, WebSharedPriority::Low,
		WebSharedPriority::Normal, WebSharedPriority::High,
		WebSharedPriority::Release, WebSharedPriority::Auto
	};
	for (unsigned index = 0; index < 6; ++index) {
		const WebSharedPriorityDecision decision =
			WebSharedController::PlanPriority(
				true, hash, sharedPriorityTokens[index]);
		Check(
			decision.allowed &&
				decision.priority == sharedPriorityValues[index] &&
				!WebSharedController::PlanPriority(
					false, hash, sharedPriorityTokens[index]).allowed,
			"every shared priority must map exactly and require admin");
	}
	Check(
		WebSharedController::PlanColumnChange(true, "6", "0").allowed &&
			!WebSharedController::PlanColumnChange(
				true, "7", "0").allowed &&
			!WebSharedController::PlanColumnChange(
				false, "0", "0").allowed,
		"shared column bounds must be exact");
	Check(
		WebSharedController::PlanReload(true, "true") &&
			!WebSharedController::PlanReload(false, "true") &&
			!WebSharedController::PlanReload(true, "false"),
		"shared reload must require admin and exact input");
	WebSharedComparison comparisons;
	int* comparisonValues[] = {
		&comparisons.state, &comparisons.type, &comparisons.name,
		&comparisons.size, &comparisons.transferred,
		&comparisons.all_time_transferred, &comparisons.requests,
		&comparisons.all_time_requests, &comparisons.accepts,
		&comparisons.all_time_accepts, &comparisons.completes,
		&comparisons.priority
	};
	for (unsigned index = 0; index < 12; ++index) {
		*comparisonValues[index] = 9;
		Check(
			WebSharedController::Compare(index, false, comparisons) == -1 &&
				WebSharedController::Compare(
					index, true, comparisons) == 1,
			"every shared comparator key must preserve direction");
		*comparisonValues[index] = 0;
	}
	const WebSharedRowProjection automatic =
		WebSharedController::ProjectRow(
			true, WebSharedPriority::Low, false, 1, 1, 0, 7);
	const WebSharedRowProjection releaseRow =
		WebSharedController::ProjectRow(
			false, WebSharedPriority::Release, false, 1, 1, 7, 7);
	const WebSharedRowProjection blocked =
		WebSharedController::ProjectRow(
			false, WebSharedPriority::Normal, true, 1, 0, 2, 7);
	Check(
		std::string(automatic.priority_token) == "Auto" &&
			automatic.downloadable &&
			automatic.complete_sources == "< 7" &&
			std::string(releaseRow.priority_token) == "Release" &&
			releaseRow.complete_sources == "7" &&
			!blocked.downloadable &&
			blocked.complete_sources == "2 - 7",
		"shared row projection must own priority, download and completion policy");
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
