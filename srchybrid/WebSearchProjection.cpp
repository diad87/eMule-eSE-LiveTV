#include "WebSearchProjection.h"
#include <cwchar>

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

std::wstring EscapeApostrophe(std::wstring text)
{
	ReplaceAll(text, L"'", L"\\'");
	return text;
}

std::wstring FormatRgb(
	std::uint8_t red, std::uint8_t green, std::uint8_t blue)
{
	wchar_t value[32] = {};
	std::swprintf(value, 32, L"<font color=#%02x%02x%02x>",
		static_cast<unsigned>(red), static_cast<unsigned>(green),
		static_cast<unsigned>(blue));
	return value;
}

std::wstring FormatRow(std::wstring format,
	const std::array<std::wstring, 9>& values)
{
	std::size_t cursor = 0;
	for (const std::wstring& value : values) {
		const std::size_t marker = format.find(L"%s", cursor);
		if (marker == std::wstring::npos) return std::wstring();
		format.replace(marker, 2, value);
		cursor = marker + value.size();
	}
	return format.find(L"%s", cursor) == std::wstring::npos
		? format : std::wstring();
}

std::wstring SortValue(unsigned column, unsigned active, bool ascending)
{
	return column != active || (column == active && !ascending) ? L"1" : L"0";
}

}

WebSearchProjection::WebSearchProjection(const M2AParentPort& parent)
	: m_parent(parent)
{
}

std::wstring WebSearchProjection::Render(
	const WebSearchProjectionInput& input) const
{
	if (!m_parent) return std::wstring();
	std::wstring result(input.headerTemplate);
	for (const WebSearchProjectionRow& row : input.rows) {
		const std::wstring color = FormatRgb(row.red, row.green, row.blue);
		const std::wstring suffix = L"</font>";
		const std::wstring fileName = EscapeApostrophe(row.fileName);
		const std::wstring link = L"ed2k://|file|" + fileName + L"|" +
			std::to_wstring(row.sizeBytes) + L"|" + row.hash + L"|/";
		const std::array<std::wstring, 9> values = {
			row.sourceBucket, link, L"none", row.typeImage,
			input.hidden[0] ? L"" : color + row.limitedName + suffix,
			input.hidden[1] ? L"" : color + row.sizeText + suffix,
			input.hidden[2] ? L"" : color + row.hash + suffix,
			input.hidden[3] ? L"" : color + row.sources + suffix,
			row.hash
		};
		const std::wstring rendered = FormatRow(input.rowTemplate, values);
		if (rendered.empty() && !input.rowTemplate.empty()) return std::wstring();
		result += rendered;
	}
	std::wstring page(input.pageTemplate);
	ReplaceAll(page, L"[Message]", input.message);
	ReplaceAll(page, L"[CATBOX]", input.categoryBox);
	ReplaceAll(page, L"[SEARCHINFOMSG]", L"");
	ReplaceAll(page, L"[RESULTLIST]", result);
	ReplaceAll(page, L"[Session]", input.session);
	for (const auto& replacement : input.replacements)
		ReplaceAll(page, replacement.first, replacement.second);
	const std::wstring icon = input.ascending
		? input.upArrow : input.downArrow;
	static const wchar_t* prefixes[] = {
		L"Filename", L"Filesize", L"Filehash", L"Sources"
	};
	for (unsigned column = 0; column < 4; ++column) {
		const std::wstring prefix(prefixes[column]);
		ReplaceAll(page, L"[" + prefix + L"I]",
			!input.hidden[column] && input.sortColumn == column ? icon : L"");
		ReplaceAll(page, L"[" + prefix + L"H]",
			input.hidden[column] ? L"" : input.columnNames[column]);
		ReplaceAll(page, L"[" + prefix + L"M]", input.columnNames[column]);
	}
	for (unsigned column = 0; column < 6; ++column)
		ReplaceAll(page, L"[SORTASCVALUE" + std::to_wstring(column) + L"]",
			SortValue(column, input.sortColumn, input.ascending));
	return page;
}

M2AModuleHandle M2A_BIND_W6_64C04005E2(
	const M2AParentPort& parent)
{
	return parent
		? MakeM2AModuleHandle(new WebSearchProjection(parent))
		: M2AModuleHandle();
}

void M2A_UNBIND_W6_64C04005E2(const M2AParentPort&)
{
}

std::wstring RunWebSearchProjection(const M2AParentPort& parent,
	const WebSearchProjectionInput& input)
{
	return WebSearchProjection(parent).Render(input);
}

bool RunWebSearchProjectionCharacterizationSelfTest()
{
	int parent = 1;
	WebSearchProjectionInput input;
	input.pageTemplate = L"[RESULTLIST]|[Session]";
	input.headerTemplate = L"H";
	input.rowTemplate = L"%s|%s|%s|%s|%s|%s|%s|%s|%s";
	input.session = L"S";
	input.rows.push_back({
		L"雪'.mkv", L"雪'.mkv", L"video", L"7", 7, L"0123",
		L"4(2)", L"high", 1, 2, 3
	});
	const std::wstring first =
		RunWebSearchProjection(M2AParentPort{&parent}, input);
	input.rows[0].fileName = L"changed";
	return first.find(L"雪\\'.mkv") != std::wstring::npos &&
		first.find(L"|S") != std::wstring::npos &&
		first.find(L"changed") == std::wstring::npos;
}

}
