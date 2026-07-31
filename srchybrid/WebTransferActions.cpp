#include "WebTransferActions.h"

#include <charconv>
#include <cctype>
#include <memory>
#include <mutex>

namespace eSELive {
namespace {

std::mutex bindingMutex;
std::shared_ptr<WebTransferActions> binding;
void* bindingParent = nullptr;

bool EqualsNoCase(const std::string& left, const char* right) {
	std::size_t index = 0;
	for (; index < left.size() && right[index] != '\0'; ++index) {
		if (std::tolower(static_cast<unsigned char>(left[index]))
			!= std::tolower(static_cast<unsigned char>(right[index])))
			return false;
	}
	return index == left.size() && right[index] == '\0';
}

bool IsMd4Hex(const std::string& value) {
	if (value.size() != 32) return false;
	for (const unsigned char character : value)
		if (!std::isxdigit(character)) return false;
	return true;
}

bool ParseUnsigned(const std::string& text, unsigned& value) {
	if (text.empty()) return false;
	const std::from_chars_result parsed =
		std::from_chars(text.data(), text.data() + text.size(), value);
	return parsed.ec == std::errc()
		&& parsed.ptr == text.data() + text.size();
}

bool ParseLong(const std::string& text, long& value) {
	if (text.empty()) {
		value = -1;
		return true;
	}
	const std::from_chars_result parsed =
		std::from_chars(text.data(), text.data() + text.size(), value);
	return parsed.ec == std::errc()
		&& parsed.ptr == text.data() + text.size();
}

bool ParseBoolean(const std::string& text, bool& value) {
	if (text == "true") value = true;
	else if (text == "false") value = false;
	else return false;
	return true;
}

void Emit(const WebTransferActionsPort& port, WebTransferActionKind kind,
	const std::string& value = std::string(), long number = -1,
	unsigned index = 0, bool flag = false) {
	WebTransferActionCommand command;
	command.kind = kind;
	command.value = value;
	command.number = number;
	command.index = index;
	command.flag = flag;
	port.emit(port.context, command);
}

WebTransferActionKind FileKind(const std::string& operation) {
	if (operation == "stop") return WebTransferActionKind::FileStop;
	if (operation == "pause") return WebTransferActionKind::FilePause;
	if (operation == "resume") return WebTransferActionKind::FileResume;
	if (operation == "cancel") return WebTransferActionKind::FileCancel;
	if (operation == "getflc") return WebTransferActionKind::FileGetLink;
	if (operation == "rename") return WebTransferActionKind::FileRename;
	if (operation == "priolow")
		return WebTransferActionKind::FilePriorityLow;
	if (operation == "prionormal")
		return WebTransferActionKind::FilePriorityNormal;
	if (operation == "priohigh")
		return WebTransferActionKind::FilePriorityHigh;
	if (operation == "prioauto")
		return WebTransferActionKind::FilePriorityAuto;
	if (operation == "setcat")
		return WebTransferActionKind::FileSetCategory;
	if (operation == "streamseek")
		return WebTransferActionKind::FileStreamSeek;
	return WebTransferActionKind::None;
}

struct SortPlan {
	WebTransferActionSortDomain domain =
		WebTransferActionSortDomain::None;
	unsigned index = 0;
	bool reverse = false;
	bool allowed = false;
};

SortPlan PlanSort(const std::string& sort,
	const std::string& explicitReverse) {
	SortPlan plan;
	bool defaultReverse = false;
	if (sort == "dstate") plan.index = 0;
	else if (sort == "dtype") plan.index = 1;
	else if (sort == "dname") { plan.index = 2; defaultReverse = true; }
	else if (sort == "dsize") plan.index = 3;
	else if (sort == "dtransferred") plan.index = 4;
	else if (sort == "dspeed") plan.index = 5;
	else if (sort == "dprogress") plan.index = 6;
	else if (sort == "dsources") plan.index = 7;
	else if (sort == "dpriority") plan.index = 8;
	else if (sort == "dcategory") {
		plan.index = 9;
		defaultReverse = true;
	} else if (sort == "uclient") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 0;
	} else if (sort == "uuser") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 1;
		defaultReverse = true;
	} else if (sort == "uversion") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 2;
	} else if (sort == "ufilename") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 3;
		defaultReverse = true;
	} else if (sort == "utransferred") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 4;
	} else if (sort == "uspeed") {
		plan.domain = WebTransferActionSortDomain::Upload;
		plan.index = 5;
	} else if (sort == "qclient") {
		plan.domain = WebTransferActionSortDomain::Queue;
		plan.index = 0;
	} else if (sort == "quser") {
		plan.domain = WebTransferActionSortDomain::Queue;
		plan.index = 1;
		defaultReverse = true;
	} else if (sort == "qversion") {
		plan.domain = WebTransferActionSortDomain::Queue;
		plan.index = 2;
	} else if (sort == "qfilename") {
		plan.domain = WebTransferActionSortDomain::Queue;
		plan.index = 3;
		defaultReverse = true;
	} else if (sort == "qscore") {
		plan.domain = WebTransferActionSortDomain::Queue;
		plan.index = 4;
	} else {
		return plan;
	}
	if (plan.domain == WebTransferActionSortDomain::None)
		plan.domain = WebTransferActionSortDomain::Download;
	plan.reverse = defaultReverse;
	if (!explicitReverse.empty()) {
		if (EqualsNoCase(explicitReverse, "true")) plan.reverse = true;
		else if (EqualsNoCase(explicitReverse, "false"))
			plan.reverse = false;
		else return SortPlan{};
	}
	plan.allowed = true;
	return plan;
}

struct SelfState {
	int emitted = 0;
	WebTransferActionKind last = WebTransferActionKind::None;
};

void SelfEmit(void* raw, const WebTransferActionCommand& command) {
	SelfState& state = *static_cast<SelfState*>(raw);
	++state.emitted;
	state.last = command.kind;
}

} // namespace

bool WebTransferActionsPort::Complete() const noexcept {
	return emit != nullptr;
}

WebTransferActions::WebTransferActions(
	const M2AParentPort& parent) noexcept : m_parent(parent.context) {}

WebTransferActionResult WebTransferActions::Execute(
	const WebTransferActionInput& input,
	const WebTransferActionsPort& port) const {
	WebTransferActionResult result;
	result.downloadSort = input.downloadSort;
	result.uploadSort = input.uploadSort;
	result.queueSort = input.queueSort;
	result.downloadReverse = input.downloadReverse;
	result.uploadReverse = input.uploadReverse;
	result.queueReverse = input.queueReverse;
	result.queueVisible = input.queueVisible;
	result.bannedVisible = input.bannedVisible;
	result.friendVisible = input.friendVisible;
	if (m_parent == nullptr || !port.Complete() || !input.admin)
		return result;

	if (!input.clearCompleted.empty()) {
		if (EqualsNoCase(input.clearCompleted, "all"))
			Emit(port, WebTransferActionKind::ClearCompletedAll);
		else if (IsMd4Hex(input.clearCompleted))
			Emit(port, WebTransferActionKind::ClearCompletedFile,
				input.clearCompleted);
	}
	if (!input.addDownload.empty())
		Emit(port, WebTransferActionKind::AddDownload, input.addDownload);

	unsigned column = 0;
	WebTransferActionKind columnKind = WebTransferActionKind::None;
	unsigned columnLimit = 0;
	if (input.columnCommand == "menudown") {
		columnKind = WebTransferActionKind::SaveDownloadColumn;
		columnLimit = 8;
	} else if (input.columnCommand == "menuup") {
		columnKind = WebTransferActionKind::SaveUploadColumn;
		columnLimit = 5;
	} else if (input.columnCommand == "menuqueue") {
		columnKind = WebTransferActionKind::SaveQueueColumn;
		columnLimit = 4;
	}
	long hidden = 0;
	if (columnKind != WebTransferActionKind::None
		&& ParseUnsigned(input.columnIndex, column) && column < columnLimit
		&& !input.columnValue.empty()
		&& ParseLong(input.columnValue, hidden))
		Emit(port, columnKind, std::string(), -1, column, hidden != 0);
	else if (input.columnCommand == "menuprio") {
		WebTransferActionKind priority = WebTransferActionKind::None;
		if (input.categoryPriority == "low")
			priority = WebTransferActionKind::CategoryPriorityLow;
		else if (input.categoryPriority == "normal")
			priority = WebTransferActionKind::CategoryPriorityNormal;
		else if (input.categoryPriority == "high")
			priority = WebTransferActionKind::CategoryPriorityHigh;
		else if (input.categoryPriority == "auto")
			priority = WebTransferActionKind::CategoryPriorityAuto;
		if (priority != WebTransferActionKind::None) Emit(port, priority);
	}

	if (!input.operation.empty() && input.fileHash.empty()) {
		if (IsMd4Hex(input.userHash)) {
			if (input.operation == "addfriend")
				Emit(port, WebTransferActionKind::FriendAdd, input.userHash);
			else if (input.operation == "removefriend")
				Emit(port, WebTransferActionKind::FriendRemove,
					input.userHash);
		}
	} else if (!input.operation.empty() && IsMd4Hex(input.fileHash)) {
		const WebTransferActionKind kind = FileKind(input.operation);
		if (kind != WebTransferActionKind::None) {
			long number = -1;
			const bool numeric = kind == WebTransferActionKind::FileSetCategory
				|| kind == WebTransferActionKind::FileStreamSeek;
			if (!numeric || ParseLong(input.numericValue, number))
				Emit(port, kind,
					kind == WebTransferActionKind::FileRename
						? input.actionText : input.fileHash,
					number);
		}
	}

	const SortPlan sort = PlanSort(input.sort, input.sortReverse);
	if (sort.allowed) {
		result.sortDomain = sort.domain;
		if (sort.domain == WebTransferActionSortDomain::Download) {
			result.downloadSort = sort.index;
			result.downloadReverse = sort.reverse;
		} else if (sort.domain == WebTransferActionSortDomain::Upload) {
			result.uploadSort = sort.index;
			result.uploadReverse = sort.reverse;
		} else {
			result.queueSort = sort.index;
			result.queueReverse = sort.reverse;
		}
	}
	ParseBoolean(input.showQueue, result.queueVisible);
	ParseBoolean(input.showBanned, result.bannedVisible);
	ParseBoolean(input.showFriend, result.friendVisible);
	return result;
}

M2AModuleHandle M2A_BIND_W5_095B87253F(const M2AParentPort& parent) {
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent != parent.context || !binding) {
		binding = std::make_shared<WebTransferActions>(parent);
		bindingParent = parent.context;
	}
	return MakeM2AModuleHandle(new WebTransferActions(parent));
}

void M2A_UNBIND_W5_095B87253F(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent == parent.context) {
		binding.reset();
		bindingParent = nullptr;
	}
}

WebTransferActionResult RunWebTransferActions(
	const M2AParentPort& parent, const WebTransferActionInput& input,
	const WebTransferActionsPort& port) {
	std::shared_ptr<WebTransferActions> module;
	{
		std::lock_guard<std::mutex> lock(bindingMutex);
		if (bindingParent == parent.context) module = binding;
	}
	return module ? module->Execute(input, port)
		: WebTransferActionResult{};
}

bool RunWebTransferActionsCharacterizationSelfTest() {
	SelfState state;
	WebTransferActionsPort port{&state, SelfEmit};
	WebTransferActions module(M2AParentPort{&state});
	WebTransferActionInput denied;
	denied.operation = "cancel";
	denied.fileHash = "00112233445566778899aabbccddeeff";
	module.Execute(denied, port);
	if (state.emitted != 0) return false;
	WebTransferActionInput allowed(denied);
	allowed.admin = true;
	const WebTransferActionResult first(module.Execute(allowed, port));
	if (state.emitted != 1
		|| state.last != WebTransferActionKind::FileCancel)
		return false;
	allowed.sort = "dname";
	allowed.sortReverse = "false";
	allowed.showQueue = "true";
	module.Execute(allowed, port);
	return state.emitted == 2 && first.downloadSort == 0;
}

} // namespace eSELive
