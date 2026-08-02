#include "WebSharedFilesController.h"

#include <algorithm>
#include <limits>

namespace eSELive {
namespace {

void ReplaceAll(std::wstring& text, const std::wstring& token,
	const std::wstring& value)
{
	if (token.empty()) return;
	for (std::size_t at = 0; (at = text.find(token, at)) != std::wstring::npos;) {
		text.replace(at, token.size(), value);
		at += value.size();
	}
}

std::wstring HtmlEscape(const std::wstring& value)
{
	std::wstring escaped;
	escaped.reserve(value.size());
	for (const wchar_t character : value) {
		switch (character) {
		case L'&': escaped += L"&amp;"; break;
		case L'<': escaped += L"&lt;"; break;
		case L'>': escaped += L"&gt;"; break;
		case L'\"': escaped += L"&quot;"; break;
		case L'\'': escaped += L"&#8217;"; break;
		case L'\n': escaped += L"\\n"; break;
		default: escaped += character; break;
		}
	}
	return escaped;
}

std::wstring MenuEscape(const std::wstring& value)
{
	std::wstring escaped(value);
	ReplaceAll(escaped, L"'", L"&#8217;");
	return HtmlEscape(escaped);
}

std::wstring ShortName(const std::wstring& name, std::size_t limit)
{
	if (limit < 4 || name.size() <= limit) return HtmlEscape(name);
	return HtmlEscape(name.substr(0, limit - 3)) + L"...";
}

std::wstring PriorityToken(const WebSharedFilesRow& file)
{
	if (file.autoPriority) return L"Auto";
	switch (file.priority) {
	case WebSharedFilePriority::VeryLow: return L"VeryLow";
	case WebSharedFilePriority::Low: return L"Low";
	case WebSharedFilePriority::Normal: return L"Normal";
	case WebSharedFilePriority::High: return L"High";
	case WebSharedFilePriority::Release: return L"Release";
	}
	return std::wstring();
}

bool IsDownloadable(const WebSharedFilesInput& input,
	const WebSharedFilesRow& file)
{
	const std::uint64_t mebibyte = 1048576u;
	return !file.partFile && (input.maximumDownloadMiB == 0 ||
		(input.maximumDownloadMiB <=
			std::numeric_limits<std::uint64_t>::max() / mebibyte &&
			file.fileSizeBytes < input.maximumDownloadMiB * mebibyte));
}

std::wstring CompleteSources(const WebSharedFilesRow& file)
{
	if (file.completeSourcesLow == 0)
		return L"< " + std::to_wstring(file.completeSourcesHigh);
	if (file.completeSourcesLow == file.completeSourcesHigh)
		return std::to_wstring(file.completeSourcesLow);
	return std::to_wstring(file.completeSourcesLow) + L" - " +
		std::to_wstring(file.completeSourcesHigh);
}

std::wstring Parenthesized(const std::wstring& value)
{
	return L" (" + value + L")";
}

void ReplaceRow(std::wstring& row, const WebSharedFilesInput& input,
	const WebSharedFilesRow& file)
{
	const bool selected = file.hash == input.selectedHash;
	const bool downloadable = IsDownloadable(input, file);
	ReplaceAll(row, L"[LastChangedDataset]",
		selected ? L"checked" : L"checked_no");
	ReplaceAll(row, L"[hash]", file.hash);
	ReplaceAll(row, L"[FileIsPriority]",
		file.priority == WebSharedFilePriority::Release ? L"release" : L"none");
	ReplaceAll(row, L"[admin]", input.admin ? L"admin" : L"");
	ReplaceAll(row, L"[ed2k]", MenuEscape(file.ed2kLink));
	ReplaceAll(row, L"[fname]", MenuEscape(file.fileName));
	ReplaceAll(row, L"[session]", input.session);
	ReplaceAll(row, L"[shared-priority]", PriorityToken(file));
	ReplaceAll(row, L"[FileName]", HtmlEscape(file.fileName));
	ReplaceAll(row, L"[FileType]", file.fileType);
	ReplaceAll(row, L"[FileState]", file.fileState);
	ReplaceAll(row, L"[Downloadable]", downloadable ? L"yes" : L"no");
	ReplaceAll(row, L"[IFDOWNLOADABLE]", downloadable ? L"" : L"<!--");
	ReplaceAll(row, L"[/IFDOWNLOADABLE]", downloadable ? L"" : L"-->");
	ReplaceAll(row, L"[ShortFileName]", input.hidden[0]
		? L"" : ShortName(file.fileName, input.shortNameLimit));
	ReplaceAll(row, L"[FileTransferred]", input.hidden[1]
		? L"" : file.transferredText);
	ReplaceAll(row, L"[FileAllTimeTransferred]", input.hidden[1]
		? L"" : Parenthesized(file.allTimeTransferredText));
	ReplaceAll(row, L"[FileRequests]", input.hidden[2]
		? L"" : std::to_wstring(file.requests));
	ReplaceAll(row, L"[FileAllTimeRequests]", input.hidden[2]
		? L"" : Parenthesized(std::to_wstring(file.allTimeRequests)));
	ReplaceAll(row, L"[FileAccepts]", input.hidden[3]
		? L"" : std::to_wstring(file.accepts));
	ReplaceAll(row, L"[FileAllTimeAccepts]", input.hidden[3]
		? L"" : Parenthesized(std::to_wstring(file.allTimeAccepts)));
	ReplaceAll(row, L"[FileSize]", input.hidden[4] ? L"" : file.fileSizeText);
	ReplaceAll(row, L"[Completes]", input.hidden[5]
		? L"" : CompleteSources(file));
	ReplaceAll(row, L"[Priority]", input.hidden[6] ? L"" : file.priorityLabel);
	ReplaceAll(row, L"[FileHash]", file.hash);
}

int CompareText(const std::wstring& left, const std::wstring& right)
{
	return left < right ? -1 : (left > right ? 1 : 0);
}

int CompareOrder(std::uint64_t left, std::uint64_t right)
{
	return left < right ? -1 : (left > right ? 1 : 0);
}

int CompareRows(const WebSharedFilesInput& input,
	const WebSharedFilesRow& left, const WebSharedFilesRow& right)
{
	const unsigned index = static_cast<unsigned>(input.sort);
	int comparison = 0;
	if (index < 3)
		comparison = CompareText(left.textOrder[index], right.textOrder[index]);
	else {
		const std::uint64_t leftValues[] = {
			left.fileSizeBytes, left.transferredBytes,
			left.allTimeTransferredBytes, left.requests,
			left.allTimeRequests, left.accepts, left.allTimeAccepts,
			left.completeSourcesOrder, left.priorityOrder };
		const std::uint64_t rightValues[] = {
			right.fileSizeBytes, right.transferredBytes,
			right.allTimeTransferredBytes, right.requests,
			right.allTimeRequests, right.accepts, right.allTimeAccepts,
			right.completeSourcesOrder, right.priorityOrder };
		comparison = CompareOrder(leftValues[index - 3], rightValues[index - 3]);
	}
	if (index < 2) comparison = -comparison;
	return input.reverse ? comparison : -comparison;
}

std::wstring Toggle(bool reverse)
{
	return reverse ? L"false" : L"true";
}

void ReplaceSimpleSort(std::wstring& page, const wchar_t* token,
	const wchar_t* name, WebSharedFilesSort target,
	const WebSharedFilesInput& input)
{
	std::wstring value(L"sort=");
	value += name;
	if (input.sort == target)
		value += L"&amp;sortreverse=" + Toggle(input.reverse);
	ReplaceAll(page, token, value);
}

void ReplaceAlternatingSort(std::wstring& page, const wchar_t* token,
	const wchar_t* primaryName, WebSharedFilesSort primary,
	const wchar_t* allTimeName, WebSharedFilesSort allTime,
	const WebSharedFilesInput& input)
{
	if (input.sort != primary && input.sort != allTime) {
		ReplaceAll(page, token,
			std::wstring(L"&amp;sort=") + primaryName +
			L"&amp;sortreverse=false");
		return;
	}
	const wchar_t* selected = input.reverse
		? (input.sort == primary ? allTimeName : primaryName)
		: (input.sort == primary ? primaryName : allTimeName);
	ReplaceAll(page, token, std::wstring(L"sort=") + selected +
		L"&amp;sortreverse=" + Toggle(input.reverse));
}

std::wstring ColumnIcon(const WebSharedFilesInput& input,
	std::size_t column)
{
	const std::array<WebSharedFilesSort, 7> primary = {
		WebSharedFilesSort::Name, WebSharedFilesSort::Transferred,
		WebSharedFilesSort::Requests, WebSharedFilesSort::Accepts,
		WebSharedFilesSort::Size, WebSharedFilesSort::Completes,
		WebSharedFilesSort::Priority };
	if (input.sort == primary[column])
		return input.reverse ? input.upArrow : input.downArrow;
	if ((column == 1 && input.sort == WebSharedFilesSort::AllTimeTransferred) ||
		(column == 2 && input.sort == WebSharedFilesSort::AllTimeRequests) ||
		(column == 3 && input.sort == WebSharedFilesSort::AllTimeAccepts))
		return input.reverse ? input.upDoubleArrow : input.downDoubleArrow;
	return std::wstring();
}

void ReplacePageProjection(std::wstring& page,
	const WebSharedFilesInput& input)
{
	ReplaceSimpleSort(page, L"[SortState]", L"state",
		WebSharedFilesSort::State, input);
	ReplaceSimpleSort(page, L"[SortType]", L"type",
		WebSharedFilesSort::Type, input);
	ReplaceSimpleSort(page, L"[SortName]", L"name",
		WebSharedFilesSort::Name, input);
	ReplaceSimpleSort(page, L"[SortSize]", L"size",
		WebSharedFilesSort::Size, input);
	ReplaceSimpleSort(page, L"[SortCompletes]", L"completes",
		WebSharedFilesSort::Completes, input);
	ReplaceSimpleSort(page, L"[SortPriority]", L"priority",
		WebSharedFilesSort::Priority, input);
	ReplaceAlternatingSort(page, L"[SortTransferred]", L"transferred",
		WebSharedFilesSort::Transferred, L"alltimetransferred",
		WebSharedFilesSort::AllTimeTransferred, input);
	ReplaceAlternatingSort(page, L"[SortRequests]", L"requests",
		WebSharedFilesSort::Requests, L"alltimerequests",
		WebSharedFilesSort::AllTimeRequests, input);
	ReplaceAlternatingSort(page, L"[SortAccepts]", L"accepts",
		WebSharedFilesSort::Accepts, L"alltimeaccepts",
		WebSharedFilesSort::AllTimeAccepts, input);
	const std::array<const wchar_t*, 7> iconTokens = {
		L"[FilenameI]", L"[FileTransferredI]", L"[FileRequestsI]",
		L"[FileAcceptsI]", L"[SizeI]", L"[CompletesI]", L"[PriorityI]" };
	const std::array<const wchar_t*, 7> headingTokens = {
		L"[Filename]", L"[FileTransferred]", L"[FileRequests]",
		L"[FileAccepts]", L"[Size]", L"[Completes]", L"[Priority]" };
	const std::array<const wchar_t*, 7> menuTokens = {
		L"[FilenameM]", L"[FileTransferredM]", L"[FileRequestsM]",
		L"[FileAcceptsM]", L"[SizeM]", L"[CompletesM]", L"[PriorityM]" };
	for (std::size_t column = 0; column < input.hidden.size(); ++column) {
		ReplaceAll(page, iconTokens[column], input.hidden[column]
			? std::wstring() : ColumnIcon(input, column));
		ReplaceAll(page, headingTokens[column], input.hidden[column]
			? std::wstring() : input.columnNames[column]);
		ReplaceAll(page, menuTokens[column], input.columnNames[column]);
	}
	ReplaceAll(page, L"[Actions]", input.actionsLabel);
	ReplaceAll(page, L"[Reload]", input.reloadLabel);
	ReplaceAll(page, L"[SharedList]", input.sharedListLabel);
	ReplaceAll(page, L"[Session]", input.session);
	ReplaceAll(page, L"[Message]", input.message);
}

}

WebSharedFilesController::WebSharedFilesController(const M2AParentPort& parent)
	: m_parent(parent)
{
}

std::wstring WebSharedFilesController::Render(
	const WebSharedFilesInput& input) const
{
	if (!m_parent) return std::wstring();
	std::vector<WebSharedFilesRow> rows(input.rows);
	const unsigned index = static_cast<unsigned>(input.sort);
	if (index < 12) {
		std::stable_sort(rows.begin(), rows.end(), [&input](
			const WebSharedFilesRow& left, const WebSharedFilesRow& right) {
			return CompareRows(input, left, right) < 0;
		});
	}
	std::wstring list;
	for (const WebSharedFilesRow& file : rows) {
		std::wstring row(input.rowTemplate);
		ReplaceRow(row, input, file);
		list += row;
	}
	std::wstring page(input.pageTemplate);
	ReplacePageProjection(page, input);
	for (const auto& replacement : input.replacements)
		ReplaceAll(page, replacement.first, replacement.second);
	ReplaceAll(page, L"[SharedFilesList]", list);
	return page;
}

M2AModuleHandle M2A_BIND_W6_B161DA740E(
	const M2AParentPort& parent)
{
	return parent ? MakeM2AModuleHandle(
		new WebSharedFilesController(parent)) : M2AModuleHandle();
}

void M2A_UNBIND_W6_B161DA740E(const M2AParentPort&)
{
}

std::wstring RunWebSharedFilesController(const M2AParentPort& parent,
	const WebSharedFilesInput& input)
{
	return WebSharedFilesController(parent).Render(input);
}

bool RunWebSharedFilesControllerCharacterizationSelfTest()
{
	int parent = 1;
	WebSharedFilesInput input;
	input.pageTemplate = L"[SortName]|[SortTransferred]|[Filename]|[FilenameI]|[FilenameM]|[SharedFilesList]|[Session]|[Message]|[Title]";
	input.rowTemplate = L"[ShortFileName]|[FileHash]|[Downloadable]|[ed2k]|[IFDOWNLOADABLE]x[/IFDOWNLOADABLE]|[FileTransferred][FileAllTimeTransferred]|[FileRequests][FileAllTimeRequests]|[Priority]|[shared-priority]";
	input.session = L"sess";
	input.message = L"ready";
	input.sort = WebSharedFilesSort::Size;
	input.reverse = true;
	input.columnNames[0] = L"Name";
	input.upArrow = L"up";
	input.downArrow = L"down";
	input.maximumDownloadMiB = 1;
	input.replacements.push_back(std::make_pair(L"[Title]", L"Shared"));
	WebSharedFilesRow later;
	later.hash = L"b";
	later.fileName = L"later";
	later.ed2kLink = L"ed2k://later";
	later.fileSizeBytes = 2;
	later.partFile = true;
	WebSharedFilesRow first;
	first.hash = L"a";
	first.fileName = L"雪'&.mkv";
	first.ed2kLink = L"ed2k://雪'&";
	first.fileSizeBytes = 1;
	first.transferredText = L"1 B";
	first.allTimeTransferredText = L"2 B";
	first.requests = 3;
	first.allTimeRequests = 4;
	first.priorityLabel = L"Normal label";
	WebSharedFilesRow tied(first);
	tied.hash = L"c";
	tied.fileName = L"tie";
	tied.ed2kLink = L"ed2k://tie";
	input.rows.push_back(later);
	input.rows.push_back(first);
	input.rows.push_back(tied);
	const M2AParentPort port{&parent};
	M2AModuleHandle binding(M2A_BIND_W6_B161DA740E(port));
	const std::wstring rendered = RunWebSharedFilesController(port, input);
	input.rows.clear();
	const std::wstring empty = RunWebSharedFilesController(port, input);
	M2A_UNBIND_W6_B161DA740E(port);
	return binding && rendered.find(L"雪&#8217;&amp;.mkv|a|yes") != std::wstring::npos &&
		rendered.find(L"ed2k://雪&amp;#8217;&amp;") != std::wstring::npos &&
		rendered.find(L"a|yes") < rendered.find(L"tie|c") &&
		rendered.find(L"tie|c") < rendered.find(L"later|b") &&
		rendered.find(L"1 B (2 B)|3 (4)|Normal label|Normal") != std::wstring::npos &&
		rendered.find(L"sort=name|&amp;sort=transferred&amp;sortreverse=false|Name||Name|") != std::wstring::npos &&
		rendered.find(L"|sess|ready|Shared") != std::wstring::npos &&
		empty.find(L"a|yes") == std::wstring::npos;
}

} // namespace eSELive
