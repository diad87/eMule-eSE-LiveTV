#include "stdafx.h"
#include "WebServerListController.h"
#include "OtherFunctions.h"
#include "resource.h"
#include <algorithm>
#include <memory>
#include <mutex>

namespace eSELive {
namespace {

std::mutex bindingMutex;
std::shared_ptr<WebServerListController> binding;
const void* bindingParent = nullptr;

CString Parse(const WebServerGuiPort& port, const CString& url, LPCTSTR field) {
	return port.parse(port.context, url, field);
}

CString Plain(const WebServerGuiPort& port, unsigned id) {
	return port.plain(port.context, id);
}

int CompareRows(void* raw, const void* left, const void* right) {
	const WebServerRow& first = *static_cast<const WebServerRow*>(left);
	const WebServerRow& second = *static_cast<const WebServerRow*>(right);
	const WebServerPageResult& state = *static_cast<const WebServerPageResult*>(raw);
	int order = 0;
	switch (state.sort) {
	case 0: order = second.state.CompareNoCase(first.state); break;
	case 1: order = first.name.CompareNoCase(second.name); break;
	case 2:
		order = first.fullIp.Compare(second.fullIp);
		if (order == 0) order = first.port - second.port;
		break;
	case 3: order = first.description.CompareNoCase(second.description); break;
	case 4: order = static_cast<int>(first.ping - second.ping); break;
	case 5: order = static_cast<int>(first.users - second.users); break;
	case 6: order = static_cast<int>(first.files - second.files); break;
	case 7: order = first.priority - second.priority; break;
	case 8: order = first.failed - second.failed; break;
	case 9: order = static_cast<int>(first.softLimit - second.softLimit); break;
	case 10: order = first.version.Compare(second.version); break;
	default: return 0;
	}
	return state.reverse ? order : -order;
}

CString LastLogLine(CString value) {
	value.TrimRight(_T('\n'));
	const int newline = value.ReverseFind(_T('\n'));
	if (newline >= 0) value.Delete(0, newline);
	return value;
}

CString RenderAddBox(const WebServerPageInput& input,
	const WebServerGuiPort& port) {
	if (!input.admin) return CString();
	const CString session(Parse(port, input.url, _T("ses")));
	CString output(input.addTemplate), message;
	if (Parse(port, input.url, _T("addserver")) == _T("true")) {
		CString address(Parse(port, input.url, _T("serveraddr")));
		CString portText(Parse(port, input.url, _T("serverport")));
		CString name(Parse(port, input.url, _T("servername")));
		if (name.Trim().IsEmpty()) name = address;
		const bool valid = !address.Trim().IsEmpty() && !portText.Trim().IsEmpty();
		if (!valid || !port.addServer(port.context, address, _tstoi(portText), name,
			Parse(port, input.url, _T("priority")),
			Parse(port, input.url, _T("addtostatic")) == _T("true"),
			Parse(port, input.url, _T("connectnow")) == _T("true"), message))
			message = Plain(port, IDS_ERROR);
		output.Replace(_T("[Message]"), LastLogLine(message));
	} else if (Parse(port, input.url, _T("updateservermetfromurl")) == _T("true")) {
		port.updateServerMet(port.context,
			Parse(port, input.url, _T("servermeturl")), message);
		output.Replace(_T("[Message]"), LastLogLine(message));
	} else output.Replace(_T("[Message]"), _T(""));
	const struct { LPCTSTR token; unsigned id; } labels[] = {
		{_T("[AddServer]"), IDS_SV_NEWSERVER}, {_T("[IP]"), IDS_SV_ADDRESS},
		{_T("[Port]"), IDS_PORT}, {_T("[Name]"), IDS_SW_NAME},
		{_T("[Static]"), IDS_STATICSERVER}, {_T("[ConnectNow]"), IDS_IRC_CONNECT},
		{_T("[Priority]"), IDS_PRIORITY}, {_T("[Low]"), IDS_PRIOLOW},
		{_T("[Normal]"), IDS_PRIONORMAL}, {_T("[High]"), IDS_PRIOHIGH},
		{_T("[Add]"), IDS_SV_ADD}, {_T("[UpdateServerMetFromURL]"), IDS_SV_MET},
		{_T("[URL]"), IDS_SV_URL}, {_T("[Apply]"), IDS_PW_APPLY},
		{_T("[Disconnect]"), IDS_IRC_DISCONNECT},
		{_T("[Connect]"), IDS_CONNECTTOANYSERVER},
		{_T("[ServerOptions]"), IDS_CONNECTION}, {_T("[Execute]"), IDS_IRC_PERFORM}
	};
	for (const auto& label : labels) output.Replace(label.token, Plain(port, label.id));
	CString url;
	url.Format(_T("?ses=%s&amp;w=server&amp;c=disconnect"), (LPCTSTR)session);
	output.Replace(_T("[URL_Disconnect]"), url);
	url.Format(_T("?ses=%s&amp;w=server&amp;c=connect"), (LPCTSTR)session);
	output.Replace(_T("[URL_Connect]"), url);
	return output;
}

void ApplyRequest(const WebServerPageInput& input, const WebServerGuiPort& port,
	WebServerPageResult& result) {
	const CString command(Parse(port, input.url, _T("c")));
	const CString ip(Parse(port, input.url, _T("ip")));
	const int serverPort = _tstoi(Parse(port, input.url, _T("port")));
	if (input.admin) {
		WebServerAction action;
		bool dispatch = true;
		if (command == _T("connect")) action = WebServerAction::Connect;
		else if (command == _T("disconnect")) action = WebServerAction::Disconnect;
		else if (command == _T("remove")) action = WebServerAction::Remove;
		else if (command == _T("addtostatic")) action = WebServerAction::AddStatic;
		else if (command == _T("removefromstatic")) action = WebServerAction::RemoveStatic;
		else if (command == _T("priolow")) action = WebServerAction::PriorityLow;
		else if (command == _T("prionormal")) action = WebServerAction::PriorityNormal;
		else if (command == _T("priohigh")) action = WebServerAction::PriorityHigh;
		else dispatch = false;
		if (dispatch && (action == WebServerAction::Connect
			|| action == WebServerAction::Disconnect || !ip.IsEmpty()))
			port.action(port.context, action, ip, serverPort);
	} else if (command == _T("menu")) {
		const int menu = _tstoi(Parse(port, input.url, _T("m")));
		if (menu >= 0 && menu < static_cast<int>(result.hidden.size())) {
			result.hidden[menu] = Parse(port, input.url, _T("v")) == _T("1");
			port.saveHidden(port.context, result.hidden);
		}
	}
	const CString sort(Parse(port, input.url, _T("sort")));
	const CString reverse(Parse(port, input.url, _T("sortreverse")));
	if (!sort.IsEmpty()) {
		static const LPCTSTR names[] = {
			_T("state"), _T("name"), _T("ip"), _T("description"), _T("ping"),
			_T("users"), _T("files"), _T("priority"), _T("failed"),
			_T("limit"), _T("version")
		};
		bool defaultReverse = false;
		for (unsigned index = 0; index < _countof(names); ++index)
			if (sort == names[index]) {
				result.sort = index;
				defaultReverse = index == 1 || index == 3;
				break;
			}
		if (reverse.IsEmpty()) result.reverse = defaultReverse;
	}
	if (!reverse.IsEmpty()) result.reverse = reverse == _T("true");
}

void RenderHead(CString& output, const WebServerPageInput& input,
	const WebServerGuiPort& port, const WebServerPageResult& result) {
	const CString session(Parse(port, input.url, _T("ses")));
	output.Replace(_T("[Session]"), session);
	CString toggle(result.reverse
		? _T("&amp;sortreverse=false") : _T("&amp;sortreverse=true"));
	static const LPCTSTR sorts[] = {
		_T("State"), _T("Name"), _T("IP"), _T("Description"), _T("Ping"),
		_T("Users"), _T("Files"), _T("Priority"), _T("Failed"),
		_T("Limit"), _T("Version")
	};
	for (unsigned index = 0; index < _countof(sorts); ++index) {
		CString token; token.Format(_T("[Sort%s]"), sorts[index]);
		output.Replace(token, result.sort == index ? toggle : _T(""));
	}
	output.Replace(_T("[ServerList]"), Plain(port, IDS_SV_SERVERLIST));
	const CString icon(result.reverse ? input.upArrow : input.downArrow);
	static const LPCTSTR columns[] = {
		_T("Servername"), _T("Address"), _T("Description"), _T("Ping"),
		_T("Users"), _T("Files"), _T("Priority"), _T("Failed"),
		_T("Limit"), _T("Version")
	};
	static const unsigned ids[] = {
		IDS_SL_SERVERNAME, IDS_IP, IDS_DESCRIPTION, IDS_PING, IDS_UUSERS,
		IDS_FILES, IDS_PRIORITY, IDS_UFAILED, IDS_SERVER_LIMITS, IDS_SV_SERVERINFO
	};
	static const unsigned columnSort[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	for (unsigned index = 0; index < _countof(columns); ++index) {
		const CString label(Plain(port, ids[index]));
		CString image, head, menu;
		image.Format(_T("[%sI]"), columns[index]);
		head.Format(_T("[%sH]"), columns[index]);
		menu.Format(_T("[%sM]"), columns[index]);
		output.Replace(image, result.hidden[index]
			? _T("") : (result.sort == columnSort[index] ? icon : _T("")));
		output.Replace(head, result.hidden[index] ? _T("") : label);
		output.Replace(menu, label);
	}
	output.Replace(_T("[Actions]"), Plain(port, IDS_WEB_ACTIONS));
}

CString ShortText(const CString& value, int limit) {
	if (value.GetLength() <= limit) return value;
	CString result;
	result.Format(_T("<acronym title=\"%s\">%s...</acronym>"),
		(LPCTSTR)value, (LPCTSTR)value.Left(limit - 3));
	return result;
}

CString RenderRows(const WebServerPageInput& input, const WebServerGuiPort& port,
	const WebServerPageResult& result, std::vector<WebServerRow>& rows) {
	if (!rows.empty())
		qsort_s(rows.data(), rows.size(), sizeof(WebServerRow), CompareRows,
			const_cast<WebServerPageResult*>(&result));
	CString rowTemplate(input.rowTemplate);
	rowTemplate.Replace(_T("[admin]"), input.admin ? _T("admin") : _T(""));
	rowTemplate.Replace(_T("[session]"), Parse(port, input.url, _T("ses")));
	const CString selectedIp(Parse(port, input.url, _T("ip")));
	const CString selectedPort(Parse(port, input.url, _T("port")));
	CString list;
	for (const WebServerRow& row : rows) {
		CString line(rowTemplate), portText, link, value;
		portText.Format(_T("%i"), row.port);
		link.Format(_T("ed2k://|server|%s|%s|/"), (LPCTSTR)row.ip,
			(LPCTSTR)portText);
		line.Replace(_T("[LastChangedDataset]"),
			row.ip == selectedIp && portText == selectedPort
				? _T("checked") : _T("checked_no"));
		line.Replace(_T("[isstatic]"), row.isStatic ? _T("staticsrv") : _T(""));
		line.Replace(_T("[ServerType]"), row.isStatic ? _T("static") : _T("none"));
		static const LPCTSTR priorities[] = {_T("Low"), _T("Normal"), _T("High")};
		line.Replace(_T("[server-priority]"),
			row.priority < _countof(priorities) ? priorities[row.priority] : _T(""));
		line.Replace(_T("[ed2k]"), link); line.Replace(_T("[ip]"), row.ip);
		line.Replace(_T("[port]"), portText);
		line.Replace(_T("[Servername]"), result.hidden[0] ? _T("") : ShortText(row.name, 40));
		if (result.hidden[1]) value.Empty(); else value.Format(_T("%s:%d"), (LPCTSTR)row.ip, row.port);
		line.Replace(_T("[Address]"), value);
		line.Replace(_T("[Description]"), result.hidden[2] ? _T("") : ShortText(row.description, 40));
		if (result.hidden[3]) value.Empty(); else value.Format(_T("%u"), row.ping);
		line.Replace(_T("[Ping]"), value);
		value.Empty();
		if (!result.hidden[4] && row.users > 0) {
			value = CastItoIShort(row.users);
			if (row.maxUsers > 0) value.AppendFormat(_T(" (%s)"), (LPCTSTR)CastItoIShort(row.maxUsers));
		}
		line.Replace(_T("[Users]"), value);
		line.Replace(_T("[Files]"), result.hidden[5] && row.files > 0
			? _T("") : CastItoIShort(row.files));
		line.Replace(_T("[Priority]"), result.hidden[6] ? _T("") : row.priorityText);
		if (result.hidden[7]) value.Empty(); else value.Format(_T("%d"), row.failed);
		line.Replace(_T("[Failed]"), value);
		if (result.hidden[8]) value.Empty();
		else { value = CastItoIShort(row.softLimit); value.AppendFormat(_T(" (%s)"), (LPCTSTR)CastItoIShort(row.hardLimit)); }
		line.Replace(_T("[Limit]"), value);
		line.Replace(_T("[Version]"), result.hidden[9] ? _T("") : ShortText(row.version, 30));
		line.Replace(_T("[ServerState]"), row.state);
		list += line;
	}
	return list;
}

std::shared_ptr<WebServerListController> Acquire(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	return parent.context == bindingParent ? binding : nullptr;
}

struct MockState {
	int actions = 0;
	int saves = 0;
	bool empty = false;
	CString events;
};
CString MockParse(void*, const CString& url, const CString& field) {
	CString key; key.Format(_T("%s="), (LPCTSTR)field);
	const int start = url.Find(key); if (start < 0) return CString();
	const int valueStart = start + key.GetLength(); int end = url.Find(_T("&"), valueStart);
	return url.Mid(valueStart, end < 0 ? url.GetLength() - valueStart : end - valueStart);
}
CString MockPlain(void*, unsigned id) { CString value; value.Format(_T("%u"), id); return value; }
void MockAction(void* raw, WebServerAction, const CString&, int) {
	MockState& state = *static_cast<MockState*>(raw);
	++state.actions; state.events += _T("C");
}
bool MockAdd(void* raw, const CString&, int, const CString&, const CString&,
	bool, bool, CString&) {
	static_cast<MockState*>(raw)->events += _T("A");
	return true;
}
void MockUpdate(void*, const CString&, CString&) {}
void MockSave(void* raw, const std::array<bool, 10>&) {
	++static_cast<MockState*>(raw)->saves;
}
void MockSnapshot(void* raw, std::vector<WebServerRow>& rows) {
	if (static_cast<MockState*>(raw)->empty) return;
	WebServerRow bravo; bravo.name = _T("Bravo");
	WebServerRow alpha; alpha.name = _T("Alpha");
	rows.push_back(bravo); rows.push_back(alpha);
}

} // namespace

bool WebServerGuiPort::Complete() const noexcept {
	return context != nullptr && parse != nullptr && plain != nullptr
		&& action != nullptr && addServer != nullptr && updateServerMet != nullptr
		&& saveHidden != nullptr && snapshot != nullptr;
}

WebServerListController::WebServerListController(
	const M2AParentPort& parent) noexcept : m_parent(parent.context) {}

WebServerPageResult WebServerListController::Render(
	const WebServerPageInput& input, const WebServerGuiPort& port) const {
	WebServerPageResult result;
	if (m_parent == nullptr || !port.Complete()) return result;
	result.sort = input.sort; result.reverse = input.reverse; result.hidden = input.hidden;
	const CString addBox(RenderAddBox(input, port));
	ApplyRequest(input, port, result);
	result.html = input.pageTemplate;
	result.html.Replace(_T("[AddServerBox]"), addBox);
	RenderHead(result.html, input, port, result);
	std::vector<WebServerRow> rows; port.snapshot(port.context, rows);
	result.html.Replace(_T("[ServersList]"), RenderRows(input, port, result, rows));
	result.html.Replace(_T("[Session]"), Parse(port, input.url, _T("ses")));
	return result;
}

M2AModuleHandle M2A_BIND_W3_F05B56128F(const M2AParentPort& parent) {
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent != parent.context || binding == nullptr) {
		const auto owner = std::make_shared<M2AModuleHandle>(
			MakeM2AModuleHandle(new WebServerListController(parent)));
		binding = std::shared_ptr<WebServerListController>(
			owner, static_cast<WebServerListController*>(owner->Get()));
		bindingParent = parent.context;
	}
	return M2AModuleHandle(binding.get(), nullptr);
}

void M2A_UNBIND_W3_F05B56128F(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (parent.context == bindingParent) {
		bindingParent = nullptr; binding.reset();
	}
}

WebServerPageResult RunWebServerPage(const M2AParentPort& parent,
	const WebServerPageInput& input, const WebServerGuiPort& port) {
	const std::shared_ptr<WebServerListController> controller(Acquire(parent));
	return controller == nullptr ? WebServerPageResult()
		: controller->Render(input, port);
}

bool RunWebServerPageCharacterizationSelfTest() {
	const M2AParentPort parent{reinterpret_cast<void*>(1)};
	M2AModuleHandle handle = M2A_BIND_W3_F05B56128F(parent);
	MockState state;
	WebServerGuiPort port{&state, MockParse, MockPlain, MockAction, MockAdd,
		MockUpdate, MockSave, MockSnapshot};
	WebServerPageInput input;
	input.url = _T("ses=7&c=remove&ip=1.2.3.4&port=1");
	input.pageTemplate = _T("[AddServerBox][ServersList]");
	input.rowTemplate = _T("[Servername]|");
	input.sort = 1; input.reverse = true;
	const WebServerPageResult ordered(RunWebServerPage(parent, input, port));
	const bool denied = state.actions == 0;
	state.empty = true;
	input.url = _T("ses=7");
	input.pageTemplate = _T("L[ServersList]R");
	const WebServerPageResult empty(RunWebServerPage(parent, input, port));
	input.url = _T("ses=7&c=menu&m=99&v=1");
	const WebServerPageResult invalidMenu(RunWebServerPage(parent, input, port));
	const bool bounded = state.saves == 0 && !invalidMenu.hidden[3];
	input.url = _T("ses=7&c=menu&m=3&v=1");
	const WebServerPageResult validMenu(RunWebServerPage(parent, input, port));
	const bool persisted = state.saves == 1 && validMenu.hidden[3];
	input.admin = true;
	input.url = _T("ses=7&c=remove&ip=1.2.3.4&port=1");
	RunWebServerPage(parent, input, port);
	input.url = _T("ses=7&c=disconnect");
	RunWebServerPage(parent, input, port);
	state.events.Empty();
	input.url = _T("ses=7&addserver=true&serveraddr=1.2.3.4&serverport=1&c=disconnect");
	input.addTemplate = _T("[Message]");
	RunWebServerPage(parent, input, port);
	M2A_UNBIND_W3_F05B56128F(parent);
	return handle && denied && ordered.html.Find(_T("Alpha|Bravo|")) >= 0
		&& empty.html == _T("LR") && bounded && persisted && state.actions == 3
		&& state.events == _T("AC");
}

} // namespace eSELive
