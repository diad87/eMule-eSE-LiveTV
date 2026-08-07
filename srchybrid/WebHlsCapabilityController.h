#pragma once

#include "WebAuthPolicy.h"

#include <cstdint>
#include <string>

namespace ese {
namespace web {

struct WebHlsLiveSourceSnapshot {
	std::string stream_key;
	std::uint64_t generation = 0;
	WebHlsSourceRole role = WebHlsSourceRole::Viewer;
};

struct WebHlsCapabilityReadRequest {
	std::string token_digest;
	std::uint64_t path_generation = 0;
	std::string stream_key;
	std::string resource;
	std::string range;
	std::uint64_t now_ms = 0;
	std::uint64_t session_timeout_ms = 0;
};

struct WebHlsCapabilityReadPort {
	void* context = nullptr;
	bool (*copy_live_source)(
		void*, const std::string&, WebHlsLiveSourceSnapshot&) = nullptr;

	bool Complete() const noexcept;
};

enum class WebHlsCapabilityReadStatus : std::uint8_t {
	Rejected = 0,
	Candidate
};

struct WebHlsCapabilityReadDecision {
	WebHlsCapabilityReadStatus status =
		WebHlsCapabilityReadStatus::Rejected;
	WebHlsLiveSourceSnapshot source;
	std::string resource;
	std::string range;
};

WebHlsCapabilityReadDecision RunWebHlsCapabilityRead(
	WebAuthPolicy& policy,
	const WebHlsCapabilityReadRequest& request,
	const WebHlsCapabilityReadPort& port);

// The preliminary controller deliberately has no session-touch side effect.
// Call this only from the live-manager lease after exact source revalidation
// and immediately before bounded local-file capture.
bool CommitWebHlsCapabilityRead(
	WebAuthPolicy& policy,
	const WebHlsCapabilityReadRequest& request,
	const WebHlsLiveSourceSnapshot& source,
	std::uint64_t commit_now_ms);

bool RunWebHlsCapabilityControllerSelfTest(std::string& failure);

} // namespace web
} // namespace ese
