#include "WebTransferController.h"

#include <charconv>
#include <cctype>
#include <limits>

namespace ese {
namespace web {
namespace {

bool IsMd4Hex(const std::string& value)
{
	if (value.size() != 32)
		return false;
	for (const unsigned char ch : value) {
		if (!std::isxdigit(ch))
			return false;
	}
	return true;
}

bool ParseLong(const std::string& value, long& result)
{
	if (value.empty()) {
		result = -1;
		return true;
	}
	const char* begin = value.data();
	const char* end = begin + value.size();
	const std::from_chars_result parsed =
		std::from_chars(begin, end, result);
	return parsed.ec == std::errc() && parsed.ptr == end;
}

WebTransferFileOperation FileOperation(const std::string& value)
{
	if (value == "stop") return WebTransferFileOperation::Stop;
	if (value == "pause") return WebTransferFileOperation::Pause;
	if (value == "resume") return WebTransferFileOperation::Resume;
	if (value == "cancel") return WebTransferFileOperation::Cancel;
	if (value == "getflc") return WebTransferFileOperation::GetFileLink;
	if (value == "rename") return WebTransferFileOperation::Rename;
	if (value == "priolow") return WebTransferFileOperation::PriorityLow;
	if (value == "prionormal")
		return WebTransferFileOperation::PriorityNormal;
	if (value == "priohigh") return WebTransferFileOperation::PriorityHigh;
	if (value == "prioauto") return WebTransferFileOperation::PriorityAuto;
	if (value == "setcat") return WebTransferFileOperation::SetCategory;
	if (value == "streamseek") return WebTransferFileOperation::StreamSeek;
	return WebTransferFileOperation::None;
}

WebTransferSort SortValue(const std::string& value, bool& defaultReverse)
{
	defaultReverse = false;
	if (value == "dstate") return WebTransferSort::DownloadState;
	if (value == "dtype") return WebTransferSort::DownloadType;
	if (value == "dname") {
		defaultReverse = true;
		return WebTransferSort::DownloadName;
	}
	if (value == "dsize") return WebTransferSort::DownloadSize;
	if (value == "dtransferred")
		return WebTransferSort::DownloadTransferred;
	if (value == "dspeed") return WebTransferSort::DownloadSpeed;
	if (value == "dprogress") return WebTransferSort::DownloadProgress;
	if (value == "dsources") return WebTransferSort::DownloadSources;
	if (value == "dpriority") return WebTransferSort::DownloadPriority;
	if (value == "dcategory") {
		defaultReverse = true;
		return WebTransferSort::DownloadCategory;
	}
	if (value == "uuser") {
		defaultReverse = true;
		return WebTransferSort::UploadUser;
	}
	if (value == "uclient") return WebTransferSort::UploadClient;
	if (value == "uversion") return WebTransferSort::UploadVersion;
	if (value == "ufilename") {
		defaultReverse = true;
		return WebTransferSort::UploadFilename;
	}
	if (value == "utransferred")
		return WebTransferSort::UploadTransferred;
	if (value == "uspeed") return WebTransferSort::UploadSpeed;
	if (value == "qclient") return WebTransferSort::QueueClient;
	if (value == "quser") {
		defaultReverse = true;
		return WebTransferSort::QueueUser;
	}
	if (value == "qversion") return WebTransferSort::QueueVersion;
	if (value == "qfilename") {
		defaultReverse = true;
		return WebTransferSort::QueueFilename;
	}
	if (value == "qscore") return WebTransferSort::QueueScore;
	return WebTransferSort::None;
}

} // namespace

WebTransferFileAction WebTransferController::PlanFileAction(
	bool isAdmin,
	const std::string& operation,
	const std::string& fileHash,
	const std::string& text,
	const std::string& numericValue)
{
	WebTransferFileAction action;
	if (!isAdmin || !IsMd4Hex(fileHash))
		return action;
	action.operation = FileOperation(operation);
	if (action.operation == WebTransferFileOperation::None)
		return action;
	action.file_hash = fileHash;
	if (action.operation == WebTransferFileOperation::Rename)
		action.text = text;
	if (action.operation == WebTransferFileOperation::SetCategory ||
		action.operation == WebTransferFileOperation::StreamSeek) {
		if (!ParseLong(numericValue, action.value))
			return WebTransferFileAction{};
	}
	action.allowed = true;
	return action;
}

WebTransferFriendAction WebTransferController::PlanFriendAction(
	bool isAdmin,
	const std::string& operation,
	const std::string& userHash)
{
	WebTransferFriendAction action;
	if (!isAdmin || !IsMd4Hex(userHash))
		return action;
	if (operation == "addfriend")
		action.operation = WebTransferFriendOperation::Add;
	else if (operation == "removefriend")
		action.operation = WebTransferFriendOperation::Remove;
	else
		return action;
	action.allowed = true;
	action.user_hash = userHash;
	return action;
}

WebTransferColumnChange WebTransferController::PlanColumnChange(
	const std::string& command,
	const std::string& index,
	const std::string& hidden)
{
	WebTransferColumnChange change;
	unsigned limit = 0;
	if (command == "menudown") {
		change.group = WebTransferColumnGroup::Download;
		limit = 8;
	} else if (command == "menuup") {
		change.group = WebTransferColumnGroup::Upload;
		limit = 5;
	} else if (command == "menuqueue") {
		change.group = WebTransferColumnGroup::Queue;
		limit = 4;
	} else {
		return change;
	}
	unsigned parsedIndex = 0;
	const std::from_chars_result parsed = std::from_chars(
		index.data(), index.data() + index.size(), parsedIndex);
	if (index.empty() || parsed.ec != std::errc() ||
		parsed.ptr != index.data() + index.size() || parsedIndex >= limit)
		return WebTransferColumnChange{};
	long parsedHidden = 0;
	if (!ParseLong(hidden, parsedHidden))
		return WebTransferColumnChange{};
	change.allowed = true;
	change.index = parsedIndex;
	change.hidden = parsedHidden != 0;
	return change;
}

WebTransferSortDecision WebTransferController::PlanSort(
	const std::string& sort,
	const std::string& explicitReverse)
{
	WebTransferSortDecision decision;
	bool defaultReverse = false;
	decision.sort = SortValue(sort, defaultReverse);
	if (decision.sort == WebTransferSort::None)
		return decision;
	const unsigned sortValue = static_cast<unsigned>(decision.sort);
	if (decision.sort >= WebTransferSort::DownloadState &&
		decision.sort <= WebTransferSort::DownloadCategory) {
		decision.domain = WebTransferSortDomain::Download;
		decision.target_index =
			sortValue - static_cast<unsigned>(WebTransferSort::DownloadState);
	} else if (decision.sort >= WebTransferSort::UploadUser &&
		decision.sort <= WebTransferSort::UploadSpeed) {
		decision.domain = WebTransferSortDomain::Upload;
		if (decision.sort == WebTransferSort::UploadUser)
			decision.target_index = 1;
		else if (decision.sort == WebTransferSort::UploadClient)
			decision.target_index = 0;
		else
			decision.target_index =
				sortValue - static_cast<unsigned>(WebTransferSort::UploadUser);
	} else {
		decision.domain = WebTransferSortDomain::Queue;
		decision.target_index =
			sortValue - static_cast<unsigned>(WebTransferSort::QueueClient);
	}
	decision.reverse = defaultReverse;
	if (!explicitReverse.empty()) {
		if (explicitReverse == "true")
			decision.reverse = true;
		else if (explicitReverse == "false")
			decision.reverse = false;
		else
			return WebTransferSortDecision{};
	}
	decision.allowed = true;
	return decision;
}

WebTransferPriorityDecision WebTransferController::PlanCategoryPriority(
	bool isAdmin,
	const std::string& priority)
{
	WebTransferPriorityDecision decision;
	if (!isAdmin)
		return decision;
	if (priority == "low")
		decision.priority = WebTransferCategoryPriority::Low;
	else if (priority == "normal")
		decision.priority = WebTransferCategoryPriority::Normal;
	else if (priority == "high")
		decision.priority = WebTransferCategoryPriority::High;
	else if (priority == "auto")
		decision.priority = WebTransferCategoryPriority::Auto;
	else
		return decision;
	decision.allowed = true;
	return decision;
}

bool WebTransferController::TryApplyBoolean(
	bool currentValue,
	const std::string& input,
	bool& output)
{
	output = currentValue;
	if (input == "true")
		output = true;
	else if (input == "false")
		output = false;
	else
		return false;
	return true;
}

} // namespace web
} // namespace ese
