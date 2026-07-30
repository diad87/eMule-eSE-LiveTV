#pragma once

#include <string>

namespace ese {
namespace web {

enum class WebTransferFileOperation {
	None,
	Stop,
	Pause,
	Resume,
	Cancel,
	GetFileLink,
	Rename,
	PriorityLow,
	PriorityNormal,
	PriorityHigh,
	PriorityAuto,
	SetCategory,
	StreamSeek
};

enum class WebTransferFriendOperation {
	None,
	Add,
	Remove
};

enum class WebTransferColumnGroup {
	None,
	Download,
	Upload,
	Queue
};

enum class WebTransferSort {
	None,
	DownloadState,
	DownloadType,
	DownloadName,
	DownloadSize,
	DownloadTransferred,
	DownloadSpeed,
	DownloadProgress,
	DownloadSources,
	DownloadPriority,
	DownloadCategory,
	UploadUser,
	UploadClient,
	UploadVersion,
	UploadFilename,
	UploadTransferred,
	UploadSpeed,
	QueueClient,
	QueueUser,
	QueueVersion,
	QueueFilename,
	QueueScore
};

enum class WebTransferSortDomain {
	None,
	Download,
	Upload,
	Queue
};

enum class WebTransferCategoryPriority {
	None,
	Low,
	Normal,
	High,
	Auto
};

struct WebTransferFileAction {
	bool allowed = false;
	WebTransferFileOperation operation = WebTransferFileOperation::None;
	std::string file_hash;
	std::string text;
	long value = -1;
};

struct WebTransferFriendAction {
	bool allowed = false;
	WebTransferFriendOperation operation = WebTransferFriendOperation::None;
	std::string user_hash;
};

struct WebTransferColumnChange {
	bool allowed = false;
	WebTransferColumnGroup group = WebTransferColumnGroup::None;
	unsigned index = 0;
	bool hidden = false;
};

struct WebTransferSortDecision {
	bool allowed = false;
	WebTransferSort sort = WebTransferSort::None;
	WebTransferSortDomain domain = WebTransferSortDomain::None;
	unsigned target_index = 0;
	bool reverse = false;
};

struct WebTransferPriorityDecision {
	bool allowed = false;
	WebTransferCategoryPriority priority =
		WebTransferCategoryPriority::None;
};

class WebTransferController {
public:
	static WebTransferFileAction PlanFileAction(
		bool isAdmin,
		const std::string& operation,
		const std::string& fileHash,
		const std::string& text,
		const std::string& numericValue);

	static WebTransferFriendAction PlanFriendAction(
		bool isAdmin,
		const std::string& operation,
		const std::string& userHash);

	static WebTransferColumnChange PlanColumnChange(
		const std::string& command,
		const std::string& index,
		const std::string& hidden);

	static WebTransferSortDecision PlanSort(
		const std::string& sort,
		const std::string& explicitReverse);

	static WebTransferPriorityDecision PlanCategoryPriority(
		bool isAdmin,
		const std::string& priority);

	static bool TryApplyBoolean(
		bool currentValue,
		const std::string& input,
		bool& output);
};

} // namespace web
} // namespace ese
