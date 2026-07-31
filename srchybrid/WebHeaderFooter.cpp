#include "stdafx.h"
#include "WebHeaderFooter.h"
#include "OtherFunctions.h"
#include "Preferences.h"
#include "resource.h"
#include <limits>
#include <memory>
#include <mutex>
namespace eSELive {
namespace {
std::mutex bindingMutex;
std::shared_ptr<WebHeaderFooter> binding;
const void* bindingParent = nullptr;
CString Plain(UINT id, bool noquote = true) {
	CString result(GetResString(id));
	result.Remove(_T('&'));
	if (noquote) {
		result.Replace(_T("'"), _T("&#8217;"));
		result.Replace(_T("\n"), _T("\\n"));
	}
	return result;
}
CString Escape(const CString& input, bool noquote) {
	CString output(input);
	output.Replace(_T("&"), _T("&amp;"));
	output.Replace(_T("<"), _T("&lt;"));
	output.Replace(_T(">"), _T("&gt;"));
	output.Replace(_T("\""), _T("&quot;"));
	if (noquote) {
		output.Replace(_T("'"), _T("&#8217;"));
		output.Replace(_T("\n"), _T("\\n"));
	}
	return output;
}
CString SubCategoryLabel(int category) {
	switch (category) {
	case -1: return Plain(IDS_ALLOTHERS);
	case -2: return Plain(IDS_STATUS_NOTCOMPLETED);
	case -3: return Plain(IDS_DL_TRANSFCOMPL);
	case -4: return Plain(IDS_WAITING);
	case -5: return Plain(IDS_DOWNLOADING);
	case -6: return Plain(IDS_ERRORLIKE);
	case -7: return Plain(IDS_PAUSED);
	case -8: return Plain(IDS_SEENCOMPL);
	case -9: return Plain(IDS_VIDEO);
	case -10: return Plain(IDS_AUDIO);
	case -11: return Plain(IDS_SEARCH_ARC);
	case -12: return Plain(IDS_SEARCH_CDIMG);
	case -13: return Plain(IDS_SEARCH_DOC);
	case -14: return Plain(IDS_SEARCH_PICS);
	case -15: return Plain(IDS_SEARCH_PRG);
	default: return _T("?");
	}
}
void InsertCategoryBox(CString& output, int selected, LPCTSTR label,
	bool jump, bool extra, const CString& session, const CString& fileHash,
	int fileCategory, bool ed2k) {
	CString html(_T("<form action=\"\">"));
	html.Append(label);
	html += jump
		? _T("<select name=\"cat\" size=\"1\" onchange=GotoCat(this.form.cat.options[this.form.cat.selectedIndex].value)>")
		: _T("<select name=\"cat\" size=\"1\">");
	for (int index = 0; index < thePrefs.GetCatCount(); ++index) {
		CString category(thePrefs.GetCategory(index)->strTitle);
		category.Replace(_T("'"), _T("\\'"));
		html.AppendFormat(_T("<option%s value=\"%i\">%s</option>\n"),
			index == selected ? _T(" selected") : _T(""), index,
			(LPCTSTR)category);
	}
	if (extra) {
		if (thePrefs.GetCatCount() > 1) html += _T("<option>-------------------</option>\n");
		for (int index = 1; index < 16; ++index)
			html.AppendFormat(_T("<option%s value=\"%i\">%s</option>\n"),
				-index == selected ? _T(" selected") : _T(""), -index,
				(LPCTSTR)SubCategoryLabel(-index));
	}
	html.Append(_T("</select></form>"));
	output.Replace(ed2k ? _T("[CATBOXED2K]") : _T("[CATBOX]"), html);
	CString checked, selectedLabel, menu, category;
	for (int index = 0; index < thePrefs.GetCatCount(); ++index) {
		checked = index == selected ? _T("checked.gif") : _T("checked_no.gif");
		if (index == selected)
			selectedLabel = index == 0 ? GetResString(IDS_ALL)
				: thePrefs.GetCategory(index)->strTitle;
		category = index == 0 ? GetResString(IDS_ALL)
			: thePrefs.GetCategory(index)->strTitle;
		category.Replace(_T("'"), _T("\\'"));
		menu.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer&cat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
			(LPCTSTR)session, index, (LPCTSTR)checked, (LPCTSTR)category);
	}
	if (extra) {
		menu.Append(_T("<div class=menuitems>&nbsp;------------------------------&nbsp;</div>"));
		for (int index = 1; index < 16; ++index) {
			checked = -index == selected ? _T("checked.gif") : _T("checked_no.gif");
			if (-index == selected) selectedLabel = SubCategoryLabel(-index);
			menu.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer&cat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
				(LPCTSTR)session, -index, (LPCTSTR)checked,
				(LPCTSTR)SubCategoryLabel(-index));
		}
	}
	output.Replace(_T("[CatBox]"), menu);
	output.Replace(_T("[Category]"), selectedLabel);
	menu.Empty();
	if (!fileHash.IsEmpty()) selected = fileCategory;
	for (int index = 0; index < thePrefs.GetCatCount(); ++index) {
		checked = index == selected ? _T("checked.gif") : _T("checked_no.gif");
		if (index == selected)
			selectedLabel = index == 0 ? GetResString(IDS_ALL)
				: thePrefs.GetCategory(index)->strTitle;
		category = index == 0 ? GetResString(IDS_CAT_UNASSIGN)
			: thePrefs.GetCategory(index)->strTitle;
		category.Replace(_T("'"), _T("\\'"));
		menu.AppendFormat(_T("<a href=&quot;/?ses=%s&w=transfer[CatSel]&op=setcat&file=%s&filecat=%d&quot;><div class=menuitems><img class=menuchecked src=%s>%s&nbsp;</div></a>"),
			(LPCTSTR)session, (LPCTSTR)fileHash, index,
			(LPCTSTR)checked, (LPCTSTR)category);
	}
	output.Replace(_T("[SetCatBox]"), menu);
}
std::shared_ptr<WebHeaderFooter> Acquire(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	return parent.context == bindingParent ? binding : nullptr;
}
} // namespace
WebHeaderFooter::WebHeaderFooter(const M2AParentPort& parent) noexcept
	: m_parent(parent.context) {
}
CString WebHeaderFooter::Header(const CString& page, const CString& category,
	const CString& action, long session, bool admin,
	std::uint32_t requestWord, const CString& source,
	const CString& stylesheet, const CString& categoryArrow,
	const WebHeaderRuntime& runtime) const
{
	if (m_parent == nullptr) return CString();
	CString sessionText; sessionText.Format(_T("%ld"), session);
	CString output(source);
	output.Replace(_T("[CharSet]"), _T("utf-8"));
	CString refresh;
	if (page == _T("options") || page == _T("stats") || page == _T("password")) refresh = _T("0");
	else refresh.Format(_T("%d"), thePrefs.GetWebPageRefresh() * 1000);
	CString command(page);
	command.AppendFormat(_T("&amp;cat=%s&amp;dummy=%u"),
		(LPCTSTR)category, requestWord);
	output.Replace(_T("[admin]"),
		admin && thePrefs.GetWebAdminAllowedHiLevFunc() ? _T("admin") : _T(""));
	output.Replace(_T("[Session]"), sessionText);
	output.Replace(_T("[RefreshVal]"), refresh);
	output.Replace(_T("[wCommand]"), command);
	output.Replace(_T("[eMuleAppName]"), _T("eMule"));
	output.Replace(_T("[version]"), runtime.version);
	output.Replace(_T("[StyleSheet]"), stylesheet);
	const struct { LPCTSTR marker; UINT id; } resources[] = {
		{_T("[WebControl]"), IDS_WEB_CONTROL}, {_T("[Transfer]"), IDS_CD_TRANS},
		{_T("[Server]"), IDS_SV_SERVERLIST}, {_T("[Shared]"), IDS_SHAREDFILES},
		{_T("[Graphs]"), IDS_GRAPHS}, {_T("[Log]"), IDS_SV_LOG},
		{_T("[ServerInfo]"), IDS_SV_SERVERINFO}, {_T("[DebugLog]"), IDS_SV_DEBUGLOG},
		{_T("[MyInfo]"), IDS_MYINFO}, {_T("[Stats]"), IDS_SF_STATISTICS},
		{_T("[Options]"), IDS_EM_PREFS}, {_T("[Ed2klink]"), IDS_SW_LINK},
		{_T("[Close]"), IDS_WEB_SHUTDOWN}, {_T("[Reboot]"), IDS_WEB_REBOOT},
		{_T("[Shutdown]"), IDS_WEB_SHUTDOWNSYSTEM}, {_T("[WebOptions]"), IDS_WEB_ADMINMENU},
		{_T("[Logout]"), IDS_WEB_LOGOUT}, {_T("[Search]"), IDS_EM_SEARCH},
		{_T("[Download]"), IDS_SW_DOWNLOAD}, {_T("[Start]"), IDS_SW_START},
		{_T("[Version]"), IDS_VERSION}, {_T("[Kad]"), IDS_KADEMLIA},
		{_T("[FileIsHashing]"), IDS_HASHING}, {_T("[FileIsErroneous]"), IDS_ERRORLIKE},
		{_T("[FileIsCompleting]"), IDS_COMPLETING}, {_T("[FileDetails]"), IDS_FD_TITLE},
		{_T("[FileComments]"), IDS_CMT_SHOWALL}, {_T("[ClearCompleted]"), IDS_DL_CLEAR},
		{_T("[RunFile]"), IDS_DOWNLOAD}, {_T("[Resume]"), IDS_DL_RESUME},
		{_T("[Stop]"), IDS_DL_STOP}, {_T("[Pause]"), IDS_DL_PAUSE},
		{_T("[ConfirmCancel]"), IDS_Q_CANCELDL2}, {_T("[Cancel]"), IDS_MAIN_BTN_CANCEL},
		{_T("[GetFLC]"), IDS_DOWNLOADMOVIECHUNKS}, {_T("[Rename]"), IDS_RENAME},
		{_T("[Connect]"), IDS_IRC_CONNECT}, {_T("[ConfirmRemove]"), IDS_WEB_CONFIRM_REMOVE_SERVER},
		{_T("[ConfirmClose]"), IDS_WEB_MAIN_CLOSE}, {_T("[ConfirmReboot]"), IDS_WEB_MAIN_REBOOT},
		{_T("[ConfirmShutdown]"), IDS_WEB_MAIN_SHUTDOWN}, {_T("[RemoveServer]"), IDS_REMOVETHIS},
		{_T("[StaticServer]"), IDS_STATICSERVER}, {_T("[Friend]"), IDS_PW_FRIENDS},
		{_T("[PriorityVeryLow]"), IDS_PRIOVERYLOW}, {_T("[PriorityLow]"), IDS_PRIOLOW},
		{_T("[PriorityNormal]"), IDS_PRIONORMAL}, {_T("[PriorityHigh]"), IDS_PRIOHIGH},
		{_T("[PriorityRelease]"), IDS_PRIORELEASE}, {_T("[PriorityAuto]"), IDS_PRIOAUTO}
	};
	for (const auto& resource : resources)
		output.Replace(resource.marker, Plain(resource.id));
	output.Replace(_T("[VersionCheck]"), thePrefs.GetVersionCheckURL());
	CString users(_T("0")), maximumUsers(_T("0")), files(_T("0")), percent(_T("0"));
	const bool disconnect = action == _T("disconnect");
	const bool connect = action == _T("connect");
	CString connectionState, connectionText;
	if ((runtime.serverConnecting && !disconnect) || connect) {
		connectionState = _T("connecting"); connectionText = Plain(IDS_CONNECTING);
	} else if (runtime.serverConnected && !disconnect) {
		connectionState = runtime.highId ? _T("high") : _T("low");
		if (!runtime.serverName.IsEmpty()) {
			connectionText = runtime.serverName;
			if (connectionText.GetLength() > 40) connectionText = connectionText.Left(37) + _T("...");
			if (admin)
				connectionText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=server&amp;c=disconnect\">%s</a>)"),
					(LPCTSTR)sessionText, (LPCTSTR)Plain(IDS_IRC_DISCONNECT));
			users = CastItoIShort(runtime.serverUsers);
			maximumUsers = CastItoIShort(runtime.serverMaxUsers);
			files = CastItoIShort(runtime.serverFiles);
			if (runtime.serverMaxUsers > 0) percent.Format(_T("%.0f"), 100.0 * runtime.serverUsers / runtime.serverMaxUsers);
		}
	} else {
		connectionState = _T("disconnected"); connectionText = Plain(IDS_DISCONNECTED);
		if (admin)
			connectionText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=server&amp;c=connect\">%s</a>)"),
				(LPCTSTR)sessionText, (LPCTSTR)Plain(IDS_CONNECTTOANYSERVER));
	}
	output.Replace(_T("[AllUsers]"), CastItoIShort(runtime.allUsers));
	output.Replace(_T("[AllFiles]"), CastItoIShort(runtime.allFiles));
	output.Replace(_T("[ConState]"), connectionState);
	output.Replace(_T("[ConText]"), connectionText);
	if (runtime.kad2Connected) {
		if (runtime.kadFirewalled) {
			connectionText = GetResString(IDS_FIREWALLED);
			connectionText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=rcfirewall\">%s</a>"),
				(LPCTSTR)sessionText, (LPCTSTR)GetResString(IDS_KAD_RECHECKFW));
			connectionText.AppendFormat(_T(", <a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>)"),
				(LPCTSTR)sessionText, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		} else {
			connectionText = GetResString(IDS_CONNECTED);
			connectionText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>)"),
				(LPCTSTR)sessionText, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
		}
	} else if (runtime.kad6Connected) {
		connectionText = GetResString(IDS_CONNECTED);
		connectionText.AppendFormat(_T(" (Kad6, <a href=\"?ses=%s&amp;w=kad&amp;c=disconnect\">%s</a>)"),
			(LPCTSTR)sessionText, (LPCTSTR)GetResString(IDS_IRC_DISCONNECT));
	} else if (runtime.kadRunning) {
		connectionText = GetResString(IDS_CONNECTING);
	} else {
		connectionText = GetResString(IDS_DISCONNECTED);
		connectionText.AppendFormat(_T(" (<a href=\"?ses=%s&amp;w=kad&amp;c=connect\">%s</a>)"),
			(LPCTSTR)sessionText, (LPCTSTR)GetResString(IDS_IRC_CONNECT));
	}
	output.Replace(_T("[KadConText]"), connectionText);
	CString value, help;
	const auto replacePercent = [&](LPCTSTR marker, double current, double maximum) {
		value.Format(_T("%.0f"), maximum > 0.0 ? current / maximum : 0.0);
		output.Replace(marker, value);
	};
	replacePercent(_T("[DownloadValue]"), runtime.downloadRate / 10.24,
		thePrefs.GetMaxDownload() == (std::numeric_limits<uint32>::max)() ? thePrefs.GetMaxGraphDownloadRate() : thePrefs.GetMaxDownload());
	replacePercent(_T("[UploadValue]"), runtime.uploadRate / 10.24,
		thePrefs.GetMaxUpload() == (std::numeric_limits<uint32>::max)() ? thePrefs.GetMaxGraphUploadRate(true) : thePrefs.GetMaxUpload());
	replacePercent(_T("[ConnectionValue]"), 100.0 * runtime.openSockets,
		thePrefs.GetMaxConnections());
	value.Format(_T("%.1f"), runtime.uploadRate / 1024.0);
	output.Replace(_T("[CurUpload]"), value);
	value.Format(_T("%.1f"), runtime.downloadRate / 1024.0);
	output.Replace(_T("[CurDownload]"), value);
	value.Format(_T("%u.0"), runtime.openSockets);
	output.Replace(_T("[CurConnection]"), value);
	const auto replaceMaximum = [&](LPCTSTR marker, uint32 maximum) {
		if (maximum == (std::numeric_limits<uint32>::max)()) help = GetResString(IDS_PW_UNLIMITED);
		else help.Format(_T("%u"), maximum);
		output.Replace(marker, help);
	};
	replaceMaximum(_T("[MaxUpload]"), thePrefs.GetMaxUpload());
	replaceMaximum(_T("[MaxDownload]"), thePrefs.GetMaxDownload());
	replaceMaximum(_T("[MaxConnection]"), thePrefs.GetMaxConnections());
	output.Replace(_T("[UserValue]"), percent);
	output.Replace(_T("[MaxUsers]"), maximumUsers);
	output.Replace(_T("[CurUsers]"), users);
	output.Replace(_T("[CurFiles]"), files);
	output.Replace(_T("[Connection]"), Plain(IDS_CONNECTION));
	output.Replace(_T("[QuickStats]"), Plain(IDS_STATUS));
	output.Replace(_T("[Users]"), Plain(IDS_UUSERS));
	output.Replace(_T("[Files]"), Plain(IDS_FILES));
	output.Replace(_T("[Con]"), Plain(IDS_ST_ACTIVEC));
	output.Replace(_T("[Up]"), Plain(IDS_PW_CON_UPLBL));
	output.Replace(_T("[Down]"), Plain(IDS_PW_CON_DOWNLBL));
	if (thePrefs.GetCatCount() > 1)
		InsertCategoryBox(output, 0, categoryArrow, false, false,
			sessionText, _T(""), 0, true);
	else output.Replace(_T("[CATBOXED2K]"), _T(""));
	return output;
}
CString WebHeaderFooter::Footer(const CString& source) const
{
	return m_parent == nullptr ? CString() : source;
}
CString WebHeaderFooter::Login(const CString& source, const CStringA& nonce,
	bool failed, const CString& version) const
{
	if (m_parent == nullptr) return CString();
	CString output(source), nonceText(nonce);
	output.Replace(_T("[CharSet]"), _T("utf-8"));
	output.Replace(_T("[eMuleAppName]"), _T("eMule"));
	output.Replace(_T("[version]"), version);
	output.Replace(_T("[Login]"), Plain(IDS_WEB_LOGIN));
	output.Replace(_T("[EnterPassword]"), Plain(IDS_WEB_ENTER_PASSWORD));
	output.Replace(_T("[LoginNow]"), Plain(IDS_WEB_LOGIN_NOW));
	output.Replace(_T("[WebControl]"), Plain(IDS_WEB_CONTROL));
	output.Replace(_T("[ChallengeNonce]"), nonceText);
	CString message;
	if (failed)
		message.Format(_T("<p class=\"failed\">%s</p>"),
			(LPCTSTR)Plain(IDS_WEB_BADLOGINATTEMPT));
	else message = _T("&nbsp;");
	output.Replace(_T("[FailedLogin]"), message);
	return output;
}
M2AModuleHandle M2A_BIND_W2_9330EBAD15(const M2AParentPort& parent) {
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent != parent.context || binding == nullptr) {
		const auto owner = std::make_shared<M2AModuleHandle>(
			MakeM2AModuleHandle(new WebHeaderFooter(parent)));
		binding = std::shared_ptr<WebHeaderFooter>(
			owner, static_cast<WebHeaderFooter*>(owner->Get()));
		bindingParent = parent.context;
	}
	return M2AModuleHandle(binding.get(), nullptr);
}
void M2A_UNBIND_W2_9330EBAD15(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (parent.context == bindingParent) {
		bindingParent = nullptr; binding.reset();
	}
}
CString RenderWebHeader(const M2AParentPort& parent, const CString& page,
	const CString& category, const CString& action, long session, bool admin,
	std::uint32_t requestWord, const CString& source,
	const CString& stylesheet, const CString& arrow,
	const WebHeaderRuntime& runtime) {
	const std::shared_ptr<WebHeaderFooter> renderer(Acquire(parent));
	return renderer == nullptr ? CString() : renderer->Header(
		page, category, action, session, admin, requestWord, source,
		stylesheet, arrow, runtime);
}
CString RenderWebFooter(const M2AParentPort& parent, const CString& source) {
	const std::shared_ptr<WebHeaderFooter> renderer(Acquire(parent));
	return renderer == nullptr ? CString() : renderer->Footer(source);
}
CString RenderWebLogin(const M2AParentPort& parent, const CString& source,
	const CStringA& nonce, bool failed, const CString& version) {
	const std::shared_ptr<WebHeaderFooter> renderer(Acquire(parent));
	return renderer == nullptr ? CString()
		: renderer->Login(source, nonce, failed, version);
}
CString RenderWebLogView(WebTemplateLogView view, const CString& source,
	const CString& session, const CString& rawText) {
	CString output(source);
	CString text(Escape(rawText, false));
	text += _T("<br><a name=\"end\"></a>");
	output.Replace(_T("[Clear]"), Plain(IDS_PW_RESET));
	output.Replace(view == WebTemplateLogView::Log ? _T("[Log]")
		: view == WebTemplateLogView::ServerInfo ? _T("[ServerInfo]")
		: _T("[DebugLog]"), text);
	output.Replace(_T("[Session]"), session);
	return output;
}
CString RenderWebMyInfo(const CString& source, const CString& myInfo) {
	CString output(source);
	output.Replace(_T("[MYINFOLOG]"), myInfo);
	return output;
}
CString RenderWebStats(const CString& source, const CString& stats) {
	CString output(source);
	output.Replace(_T("[Stats]"), stats);
	return output;
}
CString RenderWebCommentList(const WebCommentListInput& input,
	const CString& source, const CString& lineTemplate) {
	if (!input.found) return CString();
	CString output(source), title(GetResString(IDS_COMMENT));
	title.AppendFormat(_T(": %s"), (LPCTSTR)input.fileName);
	output.Replace(_T("[COMMENTS]"), title);
	CString lines;
	for (const auto& row : input.rows)
		lines.AppendFormat(lineTemplate, (LPCTSTR)Escape(row.user, true),
			(LPCTSTR)Escape(row.file, true), (LPCTSTR)Escape(row.text, true),
			(LPCTSTR)Escape(row.rating, true));
	output.Replace(_T("[COMMENTLINES]"), lines);
	output.Replace(_T("[COMMENTS]"), _T(""));
	output.Replace(_T("[USERNAME]"), GetResString(IDS_QL_USERNAME));
	output.Replace(_T("[FILENAME]"), GetResString(IDS_DL_FILENAME));
	output.Replace(_T("[COMMENT]"), GetResString(IDS_COMMENT));
	output.Replace(_T("[RATING]"), GetResString(IDS_QL_RATING));
	output.Replace(_T("[CLOSE]"), GetResString(IDS_CW_CLOSE));
	output.Replace(_T("[CharSet]"), _T("utf-8"));
	return output;
}
void InsertWebCategoryBox(CString& output, int selected, LPCTSTR label,
	bool jump, bool extra, const CString& session, const CString& fileHash,
	int fileCategory, bool ed2k) {
	InsertCategoryBox(output, selected, label, jump, extra, session, fileHash,
		fileCategory, ed2k);
}
bool RunWebPageChromeCharacterizationSelfTest() {
	WebHeaderFooter missing{M2AParentPort()};
	if (!missing.Footer(_T("footer")).IsEmpty()) return false;
	const M2AParentPort parent{reinterpret_cast<void*>(1)};
	WebHeaderFooter renderer(parent);
	if (renderer.Footer(_T("footer")) != _T("footer")) return false;
	if (Escape(_T("<&>\"'\n"), true) != _T("&lt;&amp;&gt;&quot;&#8217;\\n")) return false;
	return true;
}
} // namespace eSELive
