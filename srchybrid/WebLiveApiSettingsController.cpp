#include "WebLiveApiSettingsController.h"

#include <cstdlib>
#include <iomanip>
#include <locale>
#include <sstream>

namespace {
const char* Bool(bool value) { return value ? "true" : "false"; }
std::string Escape(const std::string& text) {
	std::string out;
	for (unsigned char c : text) {
		if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
		else if (c == '\b') out += "\\b"; else if (c == '\f') out += "\\f";
		else if (c == '\n') out += "\\n"; else if (c == '\r') out += "\\r";
		else if (c == '\t') out += "\\t"; else if (c < 0x20) { const char hex[] = "0123456789abcdef"; out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
		else out += static_cast<char>(c);
	}
	return out;
}
enum class HeaderStyle { Netlab, Privacy, Sabotage, Forbidden };
std::string Header(unsigned status, const char* reason, const std::string& body, HeaderStyle style) {
	std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
	if (style == HeaderStyle::Privacy) out += "Server: eMule\r\nConnection: close\r\nContent-Type: text/html\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: http://localhost:3000\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\nAccess-Control-Expose-Headers: X-CSRF-Token\r\n";
	out += "Content-Type: application/json\r\n";
	if (style == HeaderStyle::Netlab) out += "Cache-Control: no-store\r\nAccess-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\n";
	if (style == HeaderStyle::Sabotage) out += "Access-Control-Allow-Origin: http://127.0.0.1\r\nX-Content-Type-Options: nosniff\r\n";
	if (style == HeaderStyle::Forbidden) out += "Cache-Control: no-store\r\n";
	out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
	return out;
}
bool ValidMode(const std::string& value) { return value == "direct" || value == "tunneled" || value == "adaptive"; }
bool ValidFallback(const std::string& value) { return value == "strict" || value == "balanced" || value == "best_effort"; }
std::uint32_t LegacyDelay(const std::string& text) {
	const int value = std::atoi(text.c_str());
	return value > 0 ? static_cast<std::uint32_t>(value) : 6000u;
}
void JsonList(std::string& out, const std::vector<std::string>& values) {
	for (std::size_t i = 0; i < values.size(); ++i) { if (i) out += ','; out += '"' + Escape(values[i]) + '"'; }
}
std::string NetlabJson(bool ok, bool changed, const char* error, const W10NetlabSnapshot& s) {
	std::ostringstream o; o.imbue(std::locale::classic());
	o << "{\"success\":" << Bool(ok) << ",\"changed\":" << Bool(changed) << ",\"error\":\"" << error
	  << "\",\"netlab\":{\"consent\":\"" << Escape(s.consent) << "\",\"advanced_consent\":\"" << Escape(s.advanced_consent)
	  << "\",\"contribution_consent\":\"" << Escape(s.contribution_consent) << "\",\"enabled\":" << Bool(s.enabled) << ",\"capability_advertised\":" << Bool(s.capability_advertised)
	  << ",\"base\":{\"ipv6_auto\":" << Bool(s.ipv6_auto) << ",\"mappings\":true,\"hole_punch\":" << Bool(s.hole_punch) << ",\"auto_keepalive\":" << Bool(s.auto_keepalive)
	  << "},\"staged\":{\"selector\":" << Bool(s.selector) << ",\"port_predict\":" << Bool(s.port_predict) << ",\"ed2k_punch3\":" << Bool(s.ed2k_punch3) << ",\"kad3_rendezvous\":" << Bool(s.kad3_rendezvous)
	  << "},\"independent\":{\"relay_accept\":" << Bool(s.relay_accept) << ",\"relay_egress\":" << Bool(s.relay_egress) << ",\"krp\":" << Bool(s.krp) << ",\"kad6_beta_exit\":" << Bool(s.kad6_beta_exit) << ",\"kad6_stable_public_exit\":" << Bool(s.kad6_stable_public_exit)
	  << "},\"keepalive_running\":" << Bool(s.keepalive_running) << "},\"v9\":{\"experimental\":" << Bool(s.experimental) << ",\"port_predict\":" << Bool(s.port_predict) << ",\"ed2k_punch3\":" << Bool(s.ed2k_punch3) << ",\"kad3_rendezvous\":" << Bool(s.kad3_rendezvous) << ",\"keepalive_running\":" << Bool(s.keepalive_running) << ",\"hole_punch_master\":" << Bool(s.hole_punch_master) << "},\"reach_connects\":{\"direct\":" << s.reach_direct << ",\"punch2\":" << s.reach_punch2 << ",\"punch3\":" << s.reach_punch3 << ",\"relay\":" << s.reach_relay << "}}";
	return o.str();
}
std::string PrivacyJson(const W10PrivacySnapshot& s) {
	std::ostringstream o; o.imbue(std::locale::classic()); o << "{\"mode\":\"" << Escape(s.mode) << "\",\"fallback\":\"" << Escape(s.fallback) << "\",\"sensitiveKeywords\":["; std::string out = o.str(); JsonList(out, s.sensitive_keywords); o.str(""); o.clear(); o << "],\"runtime\":{\"capsBits\":\"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << s.caps_bits << std::dec << "\",\"capsHumanReadable\":["; out += o.str(); JsonList(out, s.caps_human); o.str(""); o.clear(); o << "],\"kad6Preferred\":" << Bool(s.kad6_preferred) << ",\"kad6CircuitActive\":" << Bool(s.kad6_circuit_active) << ",\"routeState\":\"" << Escape(s.route_state) << "\",\"circuitsActive\":" << s.circuits_active << ",\"circuitsPending\":" << s.circuits_pending << ",\"tunnelPoolSize\":" << s.tunnel_pool_size << ",\"subscriptionsLoaded\":" << s.subscriptions_loaded << ",\"cellsSent\":" << s.cells_sent << ",\"cellsRecv\":" << s.cells_recv << ",\"bytesSent\":" << s.bytes_sent << ",\"bytesRecv\":" << s.bytes_recv << ",\"meanRttMs\":" << s.mean_rtt_ms << ",\"publicIPv6\":\"" << Escape(s.public_ipv6) << "\"}}"; return out + o.str();
}
void Call(void (*fn)(void*, bool), const W10SettingsPort& p, bool value) { if (fn) fn(p.context, value); }
void Call(void (*fn)(void*), const W10SettingsPort& p) { if (fn) fn(p.context); }
void Call(void (*fn)(void*, const std::string&), const W10SettingsPort& p, const std::string& value) { if (fn) fn(p.context, value); }
}

bool RunW10LiveSettingsApi(const W10SettingsRequest& request, const W10SettingsPort& port, W10SettingsResponse& response) {
	response = W10SettingsResponse();
	if (request.operation == W10SettingsOperation::EdgeSabotage) {
		if (!port.test_hooks_enabled) return false;
		if (!request.loopback) { response.status = 403; response.reason = "Forbidden"; response.body = "{\"error\":\"forbidden\",\"hint\":\"loopback required\"}"; response.header = Header(403, "Forbidden", response.body, HeaderStyle::Forbidden); return true; }
		if (!port.set_edge_sabotage) return false;
		const bool on = request.on == "1"; const int mode = request.mode == "delay" ? 1 : 0; const std::uint32_t delay = LegacyDelay(request.delay);
		port.set_edge_sabotage(port.context, on, mode, delay);
		response.body = "{\"ok\":true,\"on\":" + std::string(Bool(on)) + ",\"mode\":\"" + (mode ? "delay" : "drop") + "\",\"delayMs\":" + std::to_string(delay) + "}"; response.header = Header(200, "OK", response.body, HeaderStyle::Sabotage); return true;
	}
	if (request.operation == W10SettingsOperation::EseV9) {
		if (!port.read_netlab) return false;
		bool ok = true, changed = !request.on.empty(); const char* error = "";
		if (changed) { if (!port.post_krp_event) return false; if (request.on == "0") { if (!port.apply_netlab || !port.refresh_preview_caps || !port.request_keepalive || !port.persist_disable_and_verify) return false; Call(port.apply_netlab, port, false); Call(port.refresh_preview_caps, port); Call(port.request_keepalive, port, false); if (!port.persist_disable_and_verify(port.context)) { ok = false; error = "persist_failed"; } } else if (request.on == "1") { if (!port.netlab_consent_accepted) return false; if (!port.netlab_consent_accepted(port.context)) { ok = false; error = "explicit_consent_required"; } else { if (!port.apply_netlab || !port.refresh_preview_caps || !port.request_keepalive || !port.save_preferences) return false; Call(port.apply_netlab, port, true); Call(port.refresh_preview_caps, port); Call(port.request_keepalive, port, true); if (port.save_preferences(port.context)) { ok = false; error = "persist_failed"; } } } else { ok = false; error = "invalid_on_value"; } port.post_krp_event(port.context); }
		W10NetlabSnapshot snapshot; if (!port.read_netlab(port.context, snapshot)) return false; response.status = ok ? 200 : 409; response.reason = ok ? "OK" : "Conflict"; response.body = NetlabJson(ok, changed, error, snapshot); response.header = Header(response.status, response.reason.c_str(), response.body, HeaderStyle::Netlab); return true;
	}
	const bool changed = !request.mode.empty() || !request.fallback.empty() || !request.add_sensitive.empty() || !request.rm_sensitive.empty();
	if (!port.read_privacy_policy || !port.read_privacy_runtime || (ValidMode(request.mode) && !port.set_privacy_mode) || (ValidFallback(request.fallback) && !port.set_fallback) || (!request.add_sensitive.empty() && !port.add_sensitive) || (!request.rm_sensitive.empty() && !port.remove_sensitive) || (changed && !port.mirror_privacy_preferences)) return false;
	if (ValidMode(request.mode)) Call(port.set_privacy_mode, port, request.mode); if (ValidFallback(request.fallback)) Call(port.set_fallback, port, request.fallback); if (!request.add_sensitive.empty()) Call(port.add_sensitive, port, request.add_sensitive); if (!request.rm_sensitive.empty()) Call(port.remove_sensitive, port, request.rm_sensitive); if (changed) Call(port.mirror_privacy_preferences, port);
	W10PrivacySnapshot snapshot; if (!port.read_privacy_policy(port.context, snapshot) || !port.read_privacy_runtime(port.context, snapshot)) return false;
	response.body = PrivacyJson(snapshot); response.header = Header(200, "OK", response.body, HeaderStyle::Privacy); return true;
}

namespace {
struct Probe { std::vector<std::string> calls; W10NetlabSnapshot net; W10PrivacySnapshot privacy; bool edge_called = false; };
bool ProbeNet(void* raw, W10NetlabSnapshot& out) { Probe& p = *static_cast<Probe*>(raw); p.calls.push_back("net"); out = p.net; return true; }
bool ProbeConsent(void* raw) { Probe& p = *static_cast<Probe*>(raw); p.calls.push_back("consent"); return p.net.consent == "accepted"; }
void ProbeBool(void* raw, bool value) { static_cast<Probe*>(raw)->calls.push_back(value ? "bool1" : "bool0"); }
void ProbeVoid(void* raw) { static_cast<Probe*>(raw)->calls.push_back("void"); }
bool ProbePrivacy(void* raw, W10PrivacySnapshot& out) { Probe& p = *static_cast<Probe*>(raw); p.calls.push_back("privacy"); out = p.privacy; return true; }
void ProbeText(void* raw, const std::string& text) { static_cast<Probe*>(raw)->calls.push_back(text); }
void ProbeEdge(void* raw, bool, int, std::uint32_t) { Probe& p = *static_cast<Probe*>(raw); p.edge_called = true; p.calls.push_back("edge"); }
bool Has(const std::vector<std::string>& calls, const char* value) { for (const std::string& call : calls) if (call == value) return true; return false; }
}

bool RunW10LiveSettingsCharacterizationSelfTest(std::string& failure) {
	failure.clear(); Probe p; p.net.consent = "accepted"; W10SettingsPort port; port.context = &p; port.read_netlab = ProbeNet; port.netlab_consent_accepted = ProbeConsent; port.apply_netlab = ProbeBool; port.refresh_preview_caps = ProbeVoid; port.request_keepalive = ProbeBool; port.persist_disable_and_verify = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("persist"); return true; }; port.save_preferences = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("save"); return false; }; port.post_krp_event = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("post"); }; port.read_privacy_policy = ProbePrivacy; port.set_privacy_mode = ProbeText; port.set_fallback = ProbeText; port.add_sensitive = ProbeText; port.remove_sensitive = ProbeText; port.mirror_privacy_preferences = ProbeVoid; port.read_privacy_runtime = ProbePrivacy; port.test_hooks_enabled = true; port.set_edge_sabotage = ProbeEdge;
	W10SettingsResponse out; W10SettingsRequest snapshot; snapshot.operation = W10SettingsOperation::EseV9; if (!RunW10LiveSettingsApi(snapshot, port, out) || p.calls.size() != 1 || p.calls[0] != "net") { failure = "W10 NetLab snapshot read count changed"; return false; }
	p.calls.clear(); W10SettingsRequest off; off.operation = W10SettingsOperation::EseV9; off.on = "0"; if (!RunW10LiveSettingsApi(off, port, out) || out.status != 200 || p.calls.size() != 6 || p.calls[0] != "bool0" || p.calls[1] != "void" || p.calls[2] != "bool0" || p.calls[3] != "persist" || p.calls[4] != "post" || out.header.find("Access-Control-Allow-Origin: http://127.0.0.1") == std::string::npos) { failure = "W10 NetLab ordering changed"; return false; }
	p.calls.clear(); W10SettingsRequest invalidOn; invalidOn.operation = W10SettingsOperation::EseV9; invalidOn.on = "x"; if (!RunW10LiveSettingsApi(invalidOn, port, out) || out.status != 409 || !Has(p.calls, "post")) { failure = "W10 invalid NetLab event changed"; return false; }
	p.calls.clear(); port.persist_disable_and_verify = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("persist"); return false; }; if (!RunW10LiveSettingsApi(off, port, out) || out.status != 409 || !Has(p.calls, "post")) { failure = "W10 NetLab persist failure changed"; return false; } port.persist_disable_and_verify = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("persist"); return true; };
	p.calls.clear(); W10SettingsRequest enable; enable.operation = W10SettingsOperation::EseV9; enable.on = "1"; port.save_preferences = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("save"); return true; }; if (!RunW10LiveSettingsApi(enable, port, out) || out.status != 409 || !Has(p.calls, "consent") || !Has(p.calls, "save") || !Has(p.calls, "post")) { failure = "W10 NetLab enable persistence changed"; return false; } port.save_preferences = [](void* raw) { static_cast<Probe*>(raw)->calls.push_back("save"); return false; };
	p.net.consent = "declined"; p.calls.clear(); W10SettingsRequest denied; denied.operation = W10SettingsOperation::EseV9; denied.on = "1"; if (!RunW10LiveSettingsApi(denied, port, out) || out.status != 409 || Has(p.calls, "bool1") || !Has(p.calls, "post")) { failure = "W10 NetLab consent gate changed"; return false; } p.net.consent = "accepted";
	p.calls.clear(); W10SettingsRequest privacy; privacy.operation = W10SettingsOperation::Privacy; privacy.mode = "direct"; privacy.fallback = "strict"; privacy.add_sensitive = "a|b"; privacy.rm_sensitive = "x"; if (!RunW10LiveSettingsApi(privacy, port, out) || !Has(p.calls, "direct") || !Has(p.calls, "strict") || !Has(p.calls, "a|b") || !Has(p.calls, "x") || out.header.find("Content-Type: text/html\r\n") == std::string::npos || out.header.find("Content-Type: application/json\r\n") == std::string::npos) { failure = "W10 privacy wire changed"; return false; }
	p.calls.clear(); W10SettingsRequest invalid; invalid.operation = W10SettingsOperation::Privacy; invalid.mode = "invalid"; if (!RunW10LiveSettingsApi(invalid, port, out) || Has(p.calls, "invalid") || !Has(p.calls, "void")) { failure = "W10 privacy invalid-value mirror changed"; return false; }
	p.edge_called = false; W10SettingsRequest remote; remote.operation = W10SettingsOperation::EdgeSabotage; W10SettingsPort disabled = port; disabled.test_hooks_enabled = false; if (RunW10LiveSettingsApi(remote, disabled, out) || !RunW10LiveSettingsApi(remote, port, out) || out.status != 403 || p.edge_called || out.body.find("loopback required") == std::string::npos) { failure = "W10 test-hook loopback gate changed"; return false; }
	W10SettingsRequest edge; edge.operation = W10SettingsOperation::EdgeSabotage; edge.loopback = true; edge.on = "1"; edge.mode = "delay"; edge.delay = "7"; if (!RunW10LiveSettingsApi(edge, port, out) || !p.edge_called || out.body.find("\"delayMs\":7") == std::string::npos) { failure = "W10 test-hook serialization changed"; return false; }
	return true;
}

namespace eSELive {
WebLiveApiSettingsController::WebLiveApiSettingsController(const M2AParentPort& parent) noexcept : m_parent(parent) {}
M2AModuleHandle M2A_BIND_W10_E9722EA045(const M2AParentPort& parent) { if (!parent) return M2AModuleHandle(); return MakeM2AModuleHandle(new WebLiveApiSettingsController(parent)); }
void M2A_UNBIND_W10_E9722EA045(const M2AParentPort&) {}
} // namespace eSELive
