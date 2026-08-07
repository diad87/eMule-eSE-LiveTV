#include "WebHlsCapabilityController.h"

namespace ese {
namespace web {
namespace {

bool ValidSource(const WebHlsLiveSourceSnapshot& source)
{
	return source.generation != 0 &&
		WebAuthPolicy::IsValidHexToken(
			source.stream_key, WebAuthPolicy::kStreamKeyHexLength) &&
		(source.role == WebHlsSourceRole::Viewer ||
		 source.role == WebHlsSourceRole::Broadcast);
}

bool SameSource(
	const WebHlsLiveSourceSnapshot& lhs,
	const WebHlsLiveSourceSnapshot& rhs)
{
	return ValidSource(lhs) && ValidSource(rhs) &&
		lhs.role == rhs.role && lhs.generation == rhs.generation &&
		WebAuthPolicy::ConstantTimeEqual(lhs.stream_key, rhs.stream_key);
}

} // namespace

bool WebHlsCapabilityReadPort::Complete() const noexcept
{
	return context != nullptr && copy_live_source != nullptr;
}

WebHlsCapabilityReadDecision RunWebHlsCapabilityRead(
	WebAuthPolicy& policy,
	const WebHlsCapabilityReadRequest& request,
	const WebHlsCapabilityReadPort& port)
{
	WebHlsCapabilityReadDecision decision;
	if (!port.Complete() || request.resource.empty())
		return decision;

	WebHlsCapabilitySnapshot inspected;
	if (!policy.InspectHlsReadCapability(
			request.token_digest,
			request.path_generation,
			request.stream_key,
			request.now_ms,
			request.session_timeout_ms,
			&inspected))
		return decision;

	WebHlsLiveSourceSnapshot first;
	WebHlsLiveSourceSnapshot confirmed;
	if (!port.copy_live_source(port.context, request.stream_key, first) ||
		!ValidSource(first) ||
		!WebAuthPolicy::ConstantTimeEqual(
			first.stream_key, request.stream_key) ||
		!port.copy_live_source(port.context, request.stream_key, confirmed) ||
		!SameSource(first, confirmed) ||
		!WebAuthPolicy::ConstantTimeEqual(
			confirmed.stream_key, request.stream_key))
		return decision;

	if (inspected.source_role != confirmed.role ||
		inspected.generation != confirmed.generation ||
		!WebAuthPolicy::ConstantTimeEqual(
			inspected.stream_key, confirmed.stream_key))
		return decision;

	// This is only a side-effect-free candidate.  Commit is intentionally
	// deferred to the live-manager lease that also captures immutable bytes.
	decision.status = WebHlsCapabilityReadStatus::Candidate;
	decision.source = confirmed;
	decision.resource = request.resource;
	decision.range = request.range;
	return decision;
}

bool CommitWebHlsCapabilityRead(
	WebAuthPolicy& policy,
	const WebHlsCapabilityReadRequest& request,
	const WebHlsLiveSourceSnapshot& source,
	std::uint64_t commit_now_ms)
{
	if (!ValidSource(source) ||
		!WebAuthPolicy::ConstantTimeEqual(
			source.stream_key, request.stream_key) ||
		source.generation != request.path_generation)
		return false;
	return policy.CommitHlsReadCapability(
		request.token_digest,
		request.stream_key,
		source.role,
		source.generation,
		commit_now_ms,
		request.session_timeout_ms,
		nullptr);
}

bool RunWebHlsCapabilityControllerSelfTest(std::string& failure)
{
	struct Probe {
		WebHlsLiveSourceSnapshot source;
		unsigned copies = 0;
	};
	auto copy = [](void* raw, const std::string& key,
		WebHlsLiveSourceSnapshot& source) {
		Probe& probe = *static_cast<Probe*>(raw);
		++probe.copies;
		source = probe.source;
		return source.stream_key == key;
	};
	const std::string csrf(WebAuthPolicy::kCsrfTokenHexLength, 'a');
	const std::string browser(WebAuthPolicy::kBrowserSessionTokenHexLength, 'b');
	const std::string digest(WebAuthPolicy::kHlsCapabilityTokenHexLength, 'c');
	const std::string stream(WebAuthPolicy::kStreamKeyHexLength, '1');
	WebAuthPolicy policy;
	WebHlsCapabilitySnapshot capability;
	Probe probe;
	probe.source.stream_key = stream;
	probe.source.generation = 7;
	probe.source.role = WebHlsSourceRole::Viewer;
	const WebHlsCapabilityReadPort port{&probe, copy};
	WebHlsCapabilityReadRequest request;
	request.token_digest = digest;
	request.path_generation = 7;
	request.stream_key = stream;
	request.resource = "stream.m3u8";
	request.now_ms = 110;
	request.session_timeout_ms = 300;
	if (!policy.AddSession(1, WebRole::Guest, 0, 100, csrf, browser) ||
		!policy.IssueHlsReadCapability(
			1, stream, WebHlsSourceRole::Viewer, 7, digest,
			100, 300, capability)) {
		failure = "HLS controller setup";
		return false;
	}
	WebHlsCapabilityReadRequest invalid = request;
	invalid.token_digest.assign(WebAuthPolicy::kHlsCapabilityTokenHexLength, 'd');
	const WebHlsCapabilityReadDecision rejected =
		RunWebHlsCapabilityRead(policy, invalid, port);
	if (rejected.status != WebHlsCapabilityReadStatus::Rejected ||
		probe.copies != 0) {
		failure = "invalid HLS capability side effects";
		return false;
	}
	const WebHlsCapabilityReadDecision candidate =
		RunWebHlsCapabilityRead(policy, request, port);
	WebSessionSnapshot ownerBeforeCommit;
	if (candidate.status != WebHlsCapabilityReadStatus::Candidate ||
		candidate.source.generation != 7 ||
		candidate.source.role != WebHlsSourceRole::Viewer ||
		candidate.resource != request.resource ||
		candidate.range != request.range || probe.copies != 2 ||
		!policy.GetSession(1, ownerBeforeCommit) ||
		ownerBeforeCommit.last_seen_ms != 100) {
		failure = "valid HLS capability candidate";
		return false;
	}
	if (!CommitWebHlsCapabilityRead(
			policy, request, candidate.source, request.now_ms)) {
		failure = "valid HLS capability commit";
		return false;
	}
	WebSessionSnapshot ownerAfterCommit;
	if (!policy.GetSession(1, ownerAfterCommit) ||
		ownerAfterCommit.last_seen_ms != request.now_ms) {
		failure = "HLS capability touched outside commit";
		return false;
	}
	failure.clear();
	return true;
}

} // namespace web
} // namespace ese
