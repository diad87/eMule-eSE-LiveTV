#pragma once

#include "M2ABindingPort.h"

#include <cstdint>
#include <string>

namespace eSELive {

enum class WebTransferActionKind : std::uint8_t {
	None = 0,
	ClearCompletedAll,
	ClearCompletedFile,
	AddDownload,
	SaveDownloadColumn,
	SaveUploadColumn,
	SaveQueueColumn,
	CategoryPriorityLow,
	CategoryPriorityNormal,
	CategoryPriorityHigh,
	CategoryPriorityAuto,
	FriendAdd,
	FriendRemove,
	FileStop,
	FilePause,
	FileResume,
	FileCancel,
	FileGetLink,
	FileRename,
	FilePriorityLow,
	FilePriorityNormal,
	FilePriorityHigh,
	FilePriorityAuto,
	FileSetCategory,
	FileStreamSeek
};

enum class WebTransferActionSortDomain : std::uint8_t {
	None = 0,
	Download,
	Upload,
	Queue
};

struct WebTransferActionCommand {
	WebTransferActionKind kind = WebTransferActionKind::None;
	std::string value;
	long number = -1;
	unsigned index = 0;
	bool flag = false;
};

struct WebTransferActionInput {
	bool admin = false;
	int category = 0;
	std::string clearCompleted;
	std::string addDownload;
	std::string columnCommand;
	std::string columnIndex;
	std::string columnValue;
	std::string categoryPriority;
	std::string operation;
	std::string fileHash;
	std::string userHash;
	std::string actionText;
	std::string numericValue;
	std::string sort;
	std::string sortReverse;
	std::string showQueue;
	std::string showBanned;
	std::string showFriend;
	unsigned downloadSort = 0;
	unsigned uploadSort = 0;
	unsigned queueSort = 0;
	bool downloadReverse = false;
	bool uploadReverse = false;
	bool queueReverse = false;
	bool queueVisible = false;
	bool bannedVisible = false;
	bool friendVisible = false;
};

struct WebTransferActionResult {
	WebTransferActionSortDomain sortDomain =
		WebTransferActionSortDomain::None;
	unsigned downloadSort = 0;
	unsigned uploadSort = 0;
	unsigned queueSort = 0;
	bool downloadReverse = false;
	bool uploadReverse = false;
	bool queueReverse = false;
	bool queueVisible = false;
	bool bannedVisible = false;
	bool friendVisible = false;
};

struct WebTransferActionsPort {
	void* context = nullptr;
	void (*emit)(void*, const WebTransferActionCommand&) = nullptr;

	bool Complete() const noexcept;
};

class WebTransferActions final {
public:
	explicit WebTransferActions(const M2AParentPort& parent) noexcept;

	WebTransferActionResult Execute(
		const WebTransferActionInput& input,
		const WebTransferActionsPort& port) const;

private:
	void* m_parent = nullptr;
};

M2AModuleHandle M2A_BIND_W5_095B87253F(const M2AParentPort& parent);
void M2A_UNBIND_W5_095B87253F(const M2AParentPort& parent);
WebTransferActionResult RunWebTransferActions(
	const M2AParentPort& parent,
	const WebTransferActionInput& input,
	const WebTransferActionsPort& port);
bool RunWebTransferActionsCharacterizationSelfTest();

} // namespace eSELive
