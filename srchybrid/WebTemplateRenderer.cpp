#include "stdafx.h"
#include "WebTemplateRenderer.h"
#include "emule.h"
#include "LiveDebugLog.h"
#include "Log.h"
#include "MD5Sum.h"
#include "OtherFunctions.h"
#include <locale.h>
#include <memory>
namespace eSELive {
namespace {
#define WEB_SERVER_TEMPLATES_VERSION 8
const LPCTSTR kTemplateNames[] = {
	_T("TMPL_HEADER"), _T("TMPL_HEADER_STYLESHEET"), _T("TMPL_FOOTER"),
	_T("TMPL_SERVER_LIST"), _T("TMPL_SERVER_LINE"), _T("TMPL_TRANSFER_IMAGES"),
	_T("TMPL_TRANSFER_LIST"), _T("TMPL_TRANSFER_DOWN_HEADER"),
	_T("TMPL_TRANSFER_DOWN_FOOTER"), _T("TMPL_TRANSFER_DOWN_LINE"),
	_T("TMPL_TRANSFER_UP_HEADER"), _T("TMPL_TRANSFER_UP_FOOTER"),
	_T("TMPL_TRANSFER_UP_LINE"), _T("TMPL_TRANSFER_UP_QUEUE_SHOW"),
	_T("TMPL_TRANSFER_UP_QUEUE_HIDE"), _T("TMPL_TRANSFER_UP_QUEUE_LINE"),
	_T("TMPL_TRANSFER_UP_QUEUE_BANNED_SHOW"),
	_T("TMPL_TRANSFER_UP_QUEUE_BANNED_HIDE"),
	_T("TMPL_TRANSFER_UP_QUEUE_BANNED_LINE"),
	_T("TMPL_TRANSFER_UP_QUEUE_FRIEND_SHOW"),
	_T("TMPL_TRANSFER_UP_QUEUE_FRIEND_HIDE"),
	_T("TMPL_TRANSFER_UP_QUEUE_FRIEND_LINE"), _T("TMPL_SHARED_LIST"),
	_T("TMPL_SHARED_LINE"), _T("TMPL_GRAPHS"), _T("TMPL_LOG"),
	_T("TMPL_SERVERINFO"), _T("TMPL_DEBUGLOG"), _T("TMPL_STATS"),
	_T("TMPL_PREFERENCES"), _T("TMPL_LOGIN"), _T("TMPL_ADDSERVERBOX"),
	_T("TMPL_SEARCH"), _T("PROGRESSBARWIDTH"),
	_T("TMPL_SEARCH_RESULT_HEADER"), _T("TMPL_SEARCH_RESULT_LINE"),
	_T("PROGRESSBARIMGS"), _T("PROGRESSBARPERCENTIMG"), _T("TMPL_CATARROW"),
	_T("TMPL_DOWNARROW"), _T("TMPL_UPARROW"), _T("TMPL_DNDOUBLEARROW"),
	_T("TMPL_UPDOUBLEARROW"), _T("TMPL_KADDLG"), _T("TMPL_BOOTSTRAPLINE"),
	_T("TMPL_MYINFO"), _T("TMPL_COMMENTLIST"), _T("TMPL_COMMENTLIST_LINE")
};
static_assert(_countof(kTemplateNames)
	== static_cast<std::size_t>(WebTemplateId::Count), "template map drift");
std::mutex bindingMutex;
std::shared_ptr<WebTemplateRenderer> binding;
const void* bindingParent = nullptr;
struct RequestSnapshot {
	const void* parent = nullptr;
	unsigned depth = 0;
	std::array<CString, static_cast<std::size_t>(WebTemplateId::Count)> values;
	CString lastModified;
	CString etag;
};
thread_local RequestSnapshot requestSnapshot;
CString ExtractTemplate(const CString& all, const CString& name, bool report) {
	const int length = name.GetLength();
	CString marker;
	marker.Format(_T("<--%s-->"), (LPCTSTR)name);
	const int startMarker = all.Find(marker);
	marker.Insert(length + 3, _T("_END"));
	const int endMarker = all.Find(marker);
	if (startMarker >= 0 && startMarker < endMarker) {
		const int start = startMarker + length + 7;
		return all.Mid(start, endMarker - start - 1);
	}
	if (report && name == _T("TMPL_VERSION")) AddLogLine(true, (LPCTSTR)GetResString(IDS_WS_ERR_LOADTEMPLATE), (LPCTSTR)name);
	if (report && startMarker == -1) AddLogLine(false, (LPCTSTR)GetResString(IDS_WEB_ERR_CANTLOAD), (LPCTSTR)name);
	return CString();
}
std::shared_ptr<WebTemplateRenderer> Acquire(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	return parent.context == bindingParent ? binding : nullptr;
}
void ReleaseSnapshot(void* parent) {
	if (requestSnapshot.parent == parent && requestSnapshot.depth != 0
		&& --requestSnapshot.depth == 0)
		requestSnapshot = RequestSnapshot();
}
} // namespace
WebTemplateRenderer::WebTemplateRenderer(const M2AParentPort& parent) noexcept
	: m_parent(parent.context) {
}
bool WebTemplateRenderer::Reload(const CString& path, bool enabled,
	bool working, bool& stopServer) {
	stopServer = false;
	_locale_t locale = _create_locale(LC_TIME, "C");
	TCHAR timeText[32] = {};
	const time_t now = time(NULL);
	if (locale == nullptr || !_tcsftime_l(timeText, _countof(timeText),
		_T("%a, %d %b %Y %H:%M:%S GMT"), gmtime(&now), locale))
		*timeText = _T('\0');
	if (locale != nullptr)
		_free_locale(locale);
	const CString lastModified(timeText);
	const CString etag(MD5Sum(lastModified).GetHashString());
	CStdioFile file;
	if (!file.Open(path, CFile::modeRead | CFile::shareDenyWrite | CFile::typeText)) {
		if (working) {
			AddLogLine(true, GetResString(IDS_WEB_ERR_CANTLOAD), (LPCTSTR)path);
			stopServer = true;
		}
		std::lock_guard<std::mutex> lock(m_mutex);
		m_lastModified = lastModified; m_etag = etag;
		return false;
	}
	CString all, line;
	while (file.ReadString(line))
		all.AppendFormat(_T("%s\n"), (LPCTSTR)line);
	file.Close();
	const CString version(ExtractTemplate(all, _T("TMPL_VERSION"), true));
	if (_tstol(version) < WEB_SERVER_TEMPLATES_VERSION) {
		if (enabled || working) {
			CString message;
			message.Format(GetResString(IDS_WS_ERR_LOADTEMPLATE), (LPCTSTR)path);
			AddLogLine(true, message);
			AfxMessageBox(message, MB_OK);
			stopServer = true;
		}
		std::lock_guard<std::mutex> lock(m_mutex);
		m_lastModified = lastModified; m_etag = etag;
		return false;
	}
	std::array<CString, static_cast<std::size_t>(WebTemplateId::Count)> next;
	for (std::size_t index = 0; index < next.size(); ++index)
		next[index] = ExtractTemplate(all, kTemplateNames[index], true);
	next[static_cast<std::size_t>(WebTemplateId::ProgressbarImgsPercent)]
		.Replace(_T("[PROGRESSGIFNAME]"), _T("%s"));
	next[static_cast<std::size_t>(WebTemplateId::ProgressbarImgsPercent)]
		.Replace(_T("[PROGRESSGIFINTERNAL]"), _T("%i"));
	next[static_cast<std::size_t>(WebTemplateId::ProgressbarImgs)]
		.Replace(_T("[PROGRESSGIFNAME]"), _T("%s"));
	next[static_cast<std::size_t>(WebTemplateId::ProgressbarImgs)]
		.Replace(_T("[PROGRESSGIFINTERNAL]"), _T("%i"));
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_values = next; m_lastModified = lastModified; m_etag = etag;
	}
	LIVE_LOG("WS", "ReloadTemplates: W2 loaded \"%S\"", (LPCWSTR)path);
	return true;
}
CString WebTemplateRenderer::Get(WebTemplateId id) const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	const std::size_t index = static_cast<std::size_t>(id);
	return index < m_values.size() ? m_values[index] : CString();
}
CString WebTemplateRenderer::LastModified() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_lastModified;
}
CString WebTemplateRenderer::ETag() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_etag;
}
void WebTemplateRenderer::Capture(
	std::array<CString, static_cast<std::size_t>(WebTemplateId::Count)>& values,
	CString& lastModified, CString& etag) const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	values = m_values;
	lastModified = m_lastModified;
	etag = m_etag;
}
M2AModuleHandle M2A_BIND_W2_071B3D442B(const M2AParentPort& parent) {
	if (!parent) return M2AModuleHandle();
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (bindingParent != parent.context || binding == nullptr) {
		const auto owner = std::make_shared<M2AModuleHandle>(
			MakeM2AModuleHandle(new WebTemplateRenderer(parent)));
		binding = std::shared_ptr<WebTemplateRenderer>(
			owner, static_cast<WebTemplateRenderer*>(owner->Get()));
		bindingParent = parent.context;
	}
	return M2AModuleHandle(binding.get(), nullptr);
}
void M2A_UNBIND_W2_071B3D442B(const M2AParentPort& parent) {
	std::lock_guard<std::mutex> lock(bindingMutex);
	if (parent.context == bindingParent) {
		bindingParent = nullptr;
		binding.reset();
	}
}
bool ReloadWebTemplates(const M2AParentPort& parent, const CString& path,
	bool enabled, bool working, bool& stopServer) {
	const std::shared_ptr<WebTemplateRenderer> renderer(Acquire(parent));
	return renderer != nullptr
		&& renderer->Reload(path, enabled, working, stopServer);
}
CString GetWebTemplate(const M2AParentPort& parent, WebTemplateId id) {
	if (requestSnapshot.parent == parent.context && requestSnapshot.depth != 0) {
		const std::size_t index = static_cast<std::size_t>(id);
		return index < requestSnapshot.values.size()
			? requestSnapshot.values[index] : CString();
	}
	const std::shared_ptr<WebTemplateRenderer> renderer(Acquire(parent));
	return renderer == nullptr ? CString() : renderer->Get(id);
}
CString GetWebTemplateLastModified(const M2AParentPort& parent) {
	if (requestSnapshot.parent == parent.context && requestSnapshot.depth != 0)
		return requestSnapshot.lastModified;
	const std::shared_ptr<WebTemplateRenderer> renderer(Acquire(parent));
	return renderer == nullptr ? CString() : renderer->LastModified();
}
CString GetWebTemplateETag(const M2AParentPort& parent) {
	if (requestSnapshot.parent == parent.context && requestSnapshot.depth != 0)
		return requestSnapshot.etag;
	const std::shared_ptr<WebTemplateRenderer> renderer(Acquire(parent));
	return renderer == nullptr ? CString() : renderer->ETag();
}
M2AModuleHandle CaptureWebTemplateSnapshot(const M2AParentPort& parent) {
	if (requestSnapshot.parent == parent.context && requestSnapshot.depth != 0) {
		++requestSnapshot.depth;
		return M2AModuleHandle(parent.context, ReleaseSnapshot);
	}
	const std::shared_ptr<WebTemplateRenderer> renderer(Acquire(parent));
	if (renderer == nullptr)
		return M2AModuleHandle();
	requestSnapshot = RequestSnapshot();
	requestSnapshot.parent = parent.context;
	requestSnapshot.depth = 1;
	renderer->Capture(requestSnapshot.values, requestSnapshot.lastModified,
		requestSnapshot.etag);
	return M2AModuleHandle(parent.context, ReleaseSnapshot);
}
CString EscapeWebTemplateText(const CString& input, bool noquote) {
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
CString GetWebPlainResource(UINT id, bool noquote) {
	CString result(GetResString(id));
	result.Remove(_T('&'));
	if (noquote) {
		result.Replace(_T("'"), _T("&#8217;"));
		result.Replace(_T("\n"), _T("\\n"));
	}
	return result;
}
bool RunWebTemplateCharacterizationSelfTest() {
	const CString source(_T("<--TMPL_VERSION-->\n8\n<--TMPL_VERSION_END-->\n"
		"<--TMPL_HEADER-->\nhead\n<--TMPL_HEADER_END-->\n"));
	if (ExtractTemplate(source, _T("TMPL_HEADER"), false) != _T("head")
		|| !ExtractTemplate(source, _T("MISSING"), false).IsEmpty())
		return false;
	if (EscapeWebTemplateText(_T("<&\"'\n"), true)
		!= _T("&lt;&amp;&quot;&#8217;\\n"))
		return false;
	const CString modified(_T("Mon, 01 Jan 2024 00:00:00 GMT"));
	const CString etag(MD5Sum(modified).GetHashString());
	return !etag.IsEmpty() && etag == MD5Sum(modified).GetHashString();
}
} // namespace eSELive
