#include "../WebHlsCapabilityController.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using ese::web::CommitWebHlsCapabilityRead;
using ese::web::RunWebHlsCapabilityRead;
using ese::web::WebAuthPolicy;
using ese::web::WebHlsCapabilityReadDecision;
using ese::web::WebHlsCapabilityReadPort;
using ese::web::WebHlsCapabilityReadRequest;
using ese::web::WebHlsCapabilityReadStatus;
using ese::web::WebHlsCapabilitySnapshot;
using ese::web::WebHlsLiveSourceSnapshot;
using ese::web::WebHlsSourceRole;
using ese::web::WebRole;
using ese::web::WebSessionSnapshot;

constexpr std::uint64_t kIssuedAtMs = 100;
constexpr std::uint64_t kReadAtMs = 110;
constexpr std::uint64_t kCommitAtMs = 120;
constexpr std::uint64_t kSessionTimeoutMs = 1000;

void Require(bool condition, const char* message)
{
	if (!condition)
		throw std::runtime_error(message);
}

struct CompletionWatchdog {
	std::mutex mutex;
	std::condition_variable changed;
	unsigned completed = 0;

	void Complete()
	{
		{
			std::lock_guard<std::mutex> lock(mutex);
			++completed;
		}
		changed.notify_all();
	}

	bool WaitFor(unsigned expected, std::chrono::milliseconds timeout)
	{
		std::unique_lock<std::mutex> lock(mutex);
		return changed.wait_for(lock, timeout, [this, expected]() {
			return completed == expected;
		});
	}
};

void AbortOnWatchdogTimeout(
	CompletionWatchdog& watchdog,
	unsigned expected,
	const char* message)
{
	if (watchdog.WaitFor(expected, std::chrono::seconds(5)))
		return;
	std::cerr << "FAIL: " << message << '\n' << std::flush;
	// A deadlocked worker cannot be joined safely.  Terminating here makes the
	// timeout effective instead of hanging while thread destructors unwind.
	std::abort();
}

std::string Token(char value)
{
	return std::string(WebAuthPolicy::kHlsCapabilityTokenHexLength, value);
}

std::string Stream(char value)
{
	return std::string(WebAuthPolicy::kStreamKeyHexLength, value);
}

WebHlsLiveSourceSnapshot Source(
	const std::string& stream,
	std::uint64_t generation,
	WebHlsSourceRole role)
{
	WebHlsLiveSourceSnapshot source;
	source.stream_key = stream;
	source.generation = generation;
	source.role = role;
	return source;
}

WebHlsCapabilityReadRequest Request(
	const std::string& digest,
	const std::string& stream,
	std::uint64_t generation,
	const std::string& resource = "stream.m3u8",
	const std::string& range = std::string())
{
	WebHlsCapabilityReadRequest request;
	request.token_digest = digest;
	request.path_generation = generation;
	request.stream_key = stream;
	request.resource = resource;
	request.range = range;
	request.now_ms = kReadAtMs;
	request.session_timeout_ms = kSessionTimeoutMs;
	return request;
}

void AddOwnerAndCapability(
	WebAuthPolicy& policy,
	std::uint32_t sessionId,
	const std::string& stream,
	WebHlsSourceRole role,
	std::uint64_t generation,
	const std::string& digest)
{
	WebHlsCapabilitySnapshot capability;
	Require(policy.AddSession(
		sessionId, WebRole::Guest, 0, kIssuedAtMs,
		Token('a'), Token('b')),
		"owner session setup");
	Require(policy.IssueHlsReadCapability(
		sessionId, stream, role, generation, digest,
		kIssuedAtMs, kSessionTimeoutMs, capability),
		"HLS capability setup");
}

bool SameSource(
	const WebHlsLiveSourceSnapshot& lhs,
	const WebHlsLiveSourceSnapshot& rhs)
{
	return lhs.generation != 0 && lhs.generation == rhs.generation &&
		lhs.role == rhs.role &&
		WebAuthPolicy::ConstantTimeEqual(lhs.stream_key, rhs.stream_key);
}

enum class LeaseStatus : std::uint8_t {
	Stale = 0,
	CommitRejected,
	Prepared
};

struct BufferedDelivery {
	LeaseStatus status = LeaseStatus::Stale;
	int http_status = 0;
	std::string resource;
	std::string range;
	std::string body;
};

struct DeliverySink {
	std::mutex mutex;
	std::vector<std::string> bodies;
	std::vector<std::string> ranges;
};

// This models the production manager lease.  The manager mutex protects the
// authoritative source identity and bytes.  Exact revalidation, capability
// Commit, bounded capture, and the optional Viewer Note all happen while the
// lease is held.  Delivery is a deliberately separate operation after return.
struct LeaseHarness {
	std::mutex mutex;
	WebHlsLiveSourceSnapshot source;
	std::string bytes;
	std::atomic<unsigned> copies{0};
	std::atomic<unsigned> commit_attempts{0};
	std::atomic<unsigned> commits{0};
	std::atomic<unsigned> file_reads{0};
	std::atomic<unsigned> viewer_notes{0};
	std::atomic<unsigned> deliveries{0};
	std::mutex capture_control_mutex;
	std::condition_variable capture_control_changed;
	bool block_capture = false;
	bool capture_entered = false;
	bool release_capture = false;

	static bool Copy(
		void* raw,
		const std::string& requestedStream,
		WebHlsLiveSourceSnapshot& output)
	{
		LeaseHarness& harness = *static_cast<LeaseHarness*>(raw);
		std::lock_guard<std::mutex> lock(harness.mutex);
		harness.copies.fetch_add(1, std::memory_order_relaxed);
		output = harness.source;
		return WebAuthPolicy::ConstantTimeEqual(
			output.stream_key, requestedStream);
	}

	WebHlsCapabilityReadPort Port()
	{
		WebHlsCapabilityReadPort port;
		port.context = this;
		port.copy_live_source = &Copy;
		return port;
	}

	void ReplaceSource(
		const WebHlsLiveSourceSnapshot& replacement,
		const std::string& replacementBytes)
	{
		std::lock_guard<std::mutex> lock(mutex);
		source = replacement;
		bytes = replacementBytes;
	}

	void ReplaceBytes(const std::string& replacementBytes)
	{
		std::lock_guard<std::mutex> lock(mutex);
		bytes = replacementBytes;
	}

	void BlockNextCapture()
	{
		std::lock_guard<std::mutex> lock(capture_control_mutex);
		block_capture = true;
		capture_entered = false;
		release_capture = false;
	}

	bool WaitForBlockedCapture(std::chrono::milliseconds timeout)
	{
		std::unique_lock<std::mutex> lock(capture_control_mutex);
		return capture_control_changed.wait_for(lock, timeout, [this]() {
			return capture_entered;
		});
	}

	void ReleaseBlockedCapture()
	{
		{
			std::lock_guard<std::mutex> lock(capture_control_mutex);
			release_capture = true;
		}
		capture_control_changed.notify_all();
	}

	BufferedDelivery Acquire(
		WebAuthPolicy& policy,
		const WebHlsCapabilityReadRequest& request,
		const WebHlsCapabilityReadDecision& candidate,
		int httpStatus,
		std::uint64_t commitNowMs = 0)
	{
		BufferedDelivery prepared;
		std::unique_lock<std::mutex> lock(mutex);
		if (candidate.status != WebHlsCapabilityReadStatus::Candidate ||
			!SameSource(candidate.source, source)) {
			return prepared;
		}

		commit_attempts.fetch_add(1, std::memory_order_relaxed);
		const std::uint64_t effectiveCommitNow =
			commitNowMs == 0 ? request.now_ms : commitNowMs;
		if (!CommitWebHlsCapabilityRead(
				policy, request, source, effectiveCommitNow)) {
			prepared.status = LeaseStatus::CommitRejected;
			return prepared;
		}
		commits.fetch_add(1, std::memory_order_relaxed);
		{
			std::unique_lock<std::mutex> control(capture_control_mutex);
			if (block_capture) {
				capture_entered = true;
				capture_control_changed.notify_all();
				capture_control_changed.wait(control, [this]() {
					return release_capture;
				});
				block_capture = false;
			}
		}

		prepared.status = LeaseStatus::Prepared;
		prepared.http_status = httpStatus;
		prepared.resource = candidate.resource;
		prepared.range = candidate.range;
		const bool bodyResponse =
			(httpStatus == 200 || httpStatus == 206) && !bytes.empty();
		if (bodyResponse) {
			prepared.body = bytes;
			file_reads.fetch_add(1, std::memory_order_relaxed);
			if (source.role == WebHlsSourceRole::Viewer) {
				viewer_notes.fetch_add(1, std::memory_order_relaxed);
			}
		}
		return prepared;
	}

	void DeliverOutside(BufferedDelivery prepared, DeliverySink& sink)
	{
		Require(prepared.status == LeaseStatus::Prepared,
			"only a prepared response may be delivered");
		// No manager mutex is held here: queued bytes are immutable and owned
		// by the response, so a later source transition cannot change them.
		{
			std::lock_guard<std::mutex> lock(sink.mutex);
			sink.bodies.push_back(std::move(prepared.body));
			sink.ranges.push_back(std::move(prepared.range));
		}
		deliveries.fetch_add(1, std::memory_order_relaxed);
	}
};

WebHlsCapabilityReadDecision Candidate(
	WebAuthPolicy& policy,
	const WebHlsCapabilityReadRequest& request,
	LeaseHarness& live)
{
	return RunWebHlsCapabilityRead(policy, request, live.Port());
}

void TestCandidateDoesNotTouchOwner()
{
	const std::string stream = Stream('1');
	const std::string digest = Token('c');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 1, stream, WebHlsSourceRole::Viewer, 7, digest);
	LeaseHarness live;
	live.source = Source(stream, 7, WebHlsSourceRole::Viewer);
	live.bytes = "candidate-body";

	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, Request(digest, stream, 7), live);
	Require(candidate.status == WebHlsCapabilityReadStatus::Candidate,
		"matching capability must produce a candidate");
	Require(live.copies.load(std::memory_order_relaxed) == 2,
		"candidate must use two coherent preliminary snapshots");
	Require(live.commit_attempts.load(std::memory_order_relaxed) == 0 &&
		live.file_reads.load(std::memory_order_relaxed) == 0 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 0,
		"candidate must not Commit, read, or Note");
	WebSessionSnapshot owner;
	Require(policy.GetSession(1, owner) && owner.last_seen_ms == kIssuedAtMs,
		"candidate inspection must not touch its owner session");
}

void TestRolloverBeforeLeaseHasNoEffects()
{
	const std::string stream = Stream('2');
	const std::string digest = Token('d');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 2, stream, WebHlsSourceRole::Viewer, 8, digest);
	LeaseHarness live;
	live.source = Source(stream, 8, WebHlsSourceRole::Viewer);
	live.bytes = "generation-eight";
	const WebHlsCapabilityReadRequest request = Request(digest, stream, 8);
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	Require(candidate.status == WebHlsCapabilityReadStatus::Candidate,
		"pre-rollover read must reach candidate state");

	live.ReplaceSource(
		Source(stream, 9, WebHlsSourceRole::Viewer), "generation-nine");
	const BufferedDelivery prepared =
		live.Acquire(policy, request, candidate, 200);
	Require(prepared.status == LeaseStatus::Stale,
		"generation rollover before the lease must be stale");
	Require(live.commit_attempts.load(std::memory_order_relaxed) == 0 &&
		live.commits.load(std::memory_order_relaxed) == 0 &&
		live.file_reads.load(std::memory_order_relaxed) == 0 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 0 &&
		live.deliveries.load(std::memory_order_relaxed) == 0,
		"stale lease must stop before Commit, I/O, Note, and delivery");
	WebSessionSnapshot owner;
	Require(policy.GetSession(2, owner) && owner.last_seen_ms == kIssuedAtMs,
		"stale lease must not touch its owner session");
}

void TestLogoutBetweenCandidateAndCommit()
{
	const std::string stream = Stream('3');
	const std::string digest = Token('e');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 3, stream, WebHlsSourceRole::Viewer, 10, digest);
	LeaseHarness live;
	live.source = Source(stream, 10, WebHlsSourceRole::Viewer);
	live.bytes = "must-not-be-read";
	const WebHlsCapabilityReadRequest request = Request(digest, stream, 10);
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	Require(candidate.status == WebHlsCapabilityReadStatus::Candidate,
		"logout race must first produce a candidate");
	Require(policy.RemoveSession(3),
		"logout must remove the capability owner before Commit");

	const BufferedDelivery prepared =
		live.Acquire(policy, request, candidate, 200);
	Require(prepared.status == LeaseStatus::CommitRejected,
		"lease Commit must observe concurrent logout");
	Require(live.commit_attempts.load(std::memory_order_relaxed) == 1 &&
		live.commits.load(std::memory_order_relaxed) == 0 &&
		live.file_reads.load(std::memory_order_relaxed) == 0 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 0 &&
		live.deliveries.load(std::memory_order_relaxed) == 0,
		"failed Commit must stop before I/O, Note, and delivery");
	Require(policy.HlsCapabilityCount() == 0,
		"logout must revoke the owner's HLS capability");
}

void TestExpiryBetweenInspectAndCommit()
{
	const std::string stream = Stream('a');
	const std::string digest = Token('6');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 10, stream, WebHlsSourceRole::Viewer, 18, digest);
	LeaseHarness live;
	live.source = Source(stream, 18, WebHlsSourceRole::Viewer);
	live.bytes = "expired-body-must-not-be-read";
	const WebHlsCapabilityReadRequest request = Request(digest, stream, 18);
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	Require(candidate.status == WebHlsCapabilityReadStatus::Candidate,
		"capability must be live during preliminary Inspect");

	const std::uint64_t expiredCommitNow =
		kIssuedAtMs + kSessionTimeoutMs + 1;
	const BufferedDelivery prepared =
		live.Acquire(policy, request, candidate, 200, expiredCommitNow);
	Require(prepared.status == LeaseStatus::CommitRejected,
		"fresh Commit time must reject a session expired after Inspect");
	Require(live.commit_attempts.load(std::memory_order_relaxed) == 1 &&
		live.commits.load(std::memory_order_relaxed) == 0 &&
		live.file_reads.load(std::memory_order_relaxed) == 0 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 0 &&
		live.deliveries.load(std::memory_order_relaxed) == 0,
		"expired Commit must stop before capture, Note, and delivery");
	WebSessionSnapshot owner;
	Require(!policy.GetSession(10, owner) && policy.HlsCapabilityCount() == 0,
		"expired Commit must purge the owner and its capability");
}

void TestCommitWinsBeforeLogout()
{
	const std::string stream = Stream('b');
	const std::string digest = Token('7');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 11, stream, WebHlsSourceRole::Viewer, 19, digest);
	LeaseHarness live;
	live.source = Source(stream, 19, WebHlsSourceRole::Viewer);
	live.bytes = "authorized-before-logout";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 19, "seg_00019.ts");
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	BufferedDelivery prepared =
		live.Acquire(policy, request, candidate, 200, kCommitAtMs);
	Require(prepared.status == LeaseStatus::Prepared &&
		prepared.body == "authorized-before-logout" &&
		live.commits.load(std::memory_order_relaxed) == 1 &&
		live.file_reads.load(std::memory_order_relaxed) == 1 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 1,
		"winning Commit must capture and authorize bytes inside the lease");
	Require(policy.RemoveSession(11),
		"logout after capture must still remove the browser session");
	Require(policy.HlsCapabilityCount() == 0,
		"post-Commit logout must revoke future capability reads");

	DeliverySink sink;
	live.DeliverOutside(std::move(prepared), sink);
	Require(sink.bodies.size() == 1 &&
		sink.bodies.front() == "authorized-before-logout",
		"logout after an authorized capture must not discard queued bytes");
}

void TestCapturedBytesAreImmutableAfterLease()
{
	const std::string stream = Stream('4');
	const std::string digest = Token('f');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 4, stream, WebHlsSourceRole::Viewer, 11, digest);
	LeaseHarness live;
	live.source = Source(stream, 11, WebHlsSourceRole::Viewer);
	live.bytes = "immutable-generation-eleven";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 11, "seg_00011.ts");
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	BufferedDelivery prepared =
		live.Acquire(policy, request, candidate, 200, kCommitAtMs);
	Require(prepared.status == LeaseStatus::Prepared &&
		prepared.body == "immutable-generation-eleven",
		"lease must capture the requested bytes before release");
	Require(live.commits.load(std::memory_order_relaxed) == 1 &&
		live.file_reads.load(std::memory_order_relaxed) == 1 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 1 &&
		live.deliveries.load(std::memory_order_relaxed) == 0,
		"Viewer lease must Commit, capture, and Note before delivery");

	live.ReplaceSource(
		Source(stream, 12, WebHlsSourceRole::Viewer), "replacement-bytes");
	DeliverySink sink;
	live.DeliverOutside(std::move(prepared), sink);
	Require(sink.bodies.size() == 1 &&
		sink.bodies.front() == "immutable-generation-eleven",
		"source mutation after lease release must not alter queued bytes");
	WebSessionSnapshot owner;
	Require(policy.GetSession(4, owner) && owner.last_seen_ms == kCommitAtMs,
		"only the successful lease Commit may touch the owner");
}

void TestTransitionWaitsForCaptureLease()
{
	const std::string stream = Stream('c');
	const std::string digest = Token('8');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 12, stream, WebHlsSourceRole::Viewer, 20, digest);
	LeaseHarness live;
	live.source = Source(stream, 20, WebHlsSourceRole::Viewer);
	live.bytes = "generation-twenty";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 20, "seg_00020.ts");
	const WebHlsCapabilityReadDecision candidate =
		Candidate(policy, request, live);
	Require(candidate.status == WebHlsCapabilityReadStatus::Candidate,
		"blocked capture test must first produce a candidate");

	live.BlockNextCapture();
	BufferedDelivery prepared;
	CompletionWatchdog watchdog;
	std::thread reader([&]() {
		prepared = live.Acquire(policy, request, candidate, 200);
		watchdog.Complete();
	});
	const bool entered =
		live.WaitForBlockedCapture(std::chrono::seconds(5));
	if (!entered) {
		live.ReleaseBlockedCapture();
		AbortOnWatchdogTimeout(
			watchdog, 1, "capture worker stalled before its lease barrier");
		reader.join();
		Require(false, "capture did not enter its manager lease");
	}

	std::atomic<bool> transitionStarted{false};
	std::atomic<bool> transitionFinished{false};
	std::thread transition([&]() {
		transitionStarted.store(true, std::memory_order_release);
		live.ReplaceSource(
			Source(stream, 21, WebHlsSourceRole::Viewer),
			"generation-twenty-one");
		transitionFinished.store(true, std::memory_order_release);
		watchdog.Complete();
	});
	const auto startDeadline =
		std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (!transitionStarted.load(std::memory_order_acquire) &&
		std::chrono::steady_clock::now() < startDeadline) {
		std::this_thread::yield();
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	const bool transitionWaited =
		transitionStarted.load(std::memory_order_acquire) &&
		!transitionFinished.load(std::memory_order_acquire);

	live.ReleaseBlockedCapture();
	AbortOnWatchdogTimeout(
		watchdog, 2, "capture and waiting transition deadlocked");
	reader.join();
	transition.join();
	Require(transitionWaited,
		"generation transition must wait while capture holds the lease");
	Require(prepared.status == LeaseStatus::Prepared &&
		prepared.body == "generation-twenty" &&
		transitionFinished.load(std::memory_order_acquire),
		"capture must finish old immutable bytes before generation changes");
	const WebHlsCapabilityReadDecision staleAfterTransition =
		Candidate(policy, request, live);
	Require(staleAfterTransition.status == WebHlsCapabilityReadStatus::Rejected,
		"old capability must reject after the waiting transition completes");
}

void TestNoteRequiresViewerSuccessfulBody()
{
	const std::string broadcastStream = Stream('5');
	const std::string broadcastDigest = Token('1');
	WebAuthPolicy broadcastPolicy;
	AddOwnerAndCapability(
		broadcastPolicy, 5, broadcastStream,
		WebHlsSourceRole::Broadcast, 13, broadcastDigest);
	LeaseHarness broadcast;
	broadcast.source = Source(
		broadcastStream, 13, WebHlsSourceRole::Broadcast);
	broadcast.bytes = "broadcast-partial-body";
	const WebHlsCapabilityReadRequest broadcastRequest =
		Request(broadcastDigest, broadcastStream, 13, "seg_00013.ts",
			"bytes=0-7");
	const WebHlsCapabilityReadDecision broadcastCandidate =
		Candidate(broadcastPolicy, broadcastRequest, broadcast);
	const BufferedDelivery broadcastPrepared = broadcast.Acquire(
		broadcastPolicy, broadcastRequest, broadcastCandidate, 206);
	Require(broadcastPrepared.status == LeaseStatus::Prepared &&
		broadcast.file_reads.load(std::memory_order_relaxed) == 1 &&
		broadcast.viewer_notes.load(std::memory_order_relaxed) == 0,
		"Broadcast body must be captured without a Viewer Note");

	const std::string viewerStream = Stream('6');
	const std::string viewerDigest = Token('2');
	WebAuthPolicy viewerPolicy;
	AddOwnerAndCapability(
		viewerPolicy, 6, viewerStream,
		WebHlsSourceRole::Viewer, 14, viewerDigest);
	LeaseHarness viewer;
	viewer.source = Source(viewerStream, 14, WebHlsSourceRole::Viewer);
	viewer.bytes = "not-an-error-body";
	const WebHlsCapabilityReadRequest viewerRequest =
		Request(viewerDigest, viewerStream, 14);
	const WebHlsCapabilityReadDecision viewerCandidate =
		Candidate(viewerPolicy, viewerRequest, viewer);
	const BufferedDelivery errorPrepared =
		viewer.Acquire(viewerPolicy, viewerRequest, viewerCandidate, 416);
	Require(errorPrepared.status == LeaseStatus::Prepared &&
		errorPrepared.body.empty() &&
		viewer.file_reads.load(std::memory_order_relaxed) == 0 &&
		viewer.viewer_notes.load(std::memory_order_relaxed) == 0,
		"non-200/206 response must not read or Note a Viewer body");

	const std::string emptyStream = Stream('7');
	const std::string emptyDigest = Token('3');
	WebAuthPolicy emptyPolicy;
	AddOwnerAndCapability(
		emptyPolicy, 7, emptyStream,
		WebHlsSourceRole::Viewer, 15, emptyDigest);
	LeaseHarness empty;
	empty.source = Source(emptyStream, 15, WebHlsSourceRole::Viewer);
	const WebHlsCapabilityReadRequest emptyRequest =
		Request(emptyDigest, emptyStream, 15);
	const WebHlsCapabilityReadDecision emptyCandidate =
		Candidate(emptyPolicy, emptyRequest, empty);
	const BufferedDelivery emptyPrepared =
		empty.Acquire(emptyPolicy, emptyRequest, emptyCandidate, 200);
	Require(emptyPrepared.status == LeaseStatus::Prepared &&
		empty.file_reads.load(std::memory_order_relaxed) == 0 &&
		empty.viewer_notes.load(std::memory_order_relaxed) == 0,
		"empty 200 response must not produce a Viewer Note");
}

void TestExactRangeRetry()
{
	const std::string stream = Stream('8');
	const std::string digest = Token('4');
	const std::string resource = "seg_00042.ts";
	const std::string range = "bytes=17-31";
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 8, stream, WebHlsSourceRole::Viewer, 16, digest);
	LeaseHarness live;
	live.source = Source(stream, 16, WebHlsSourceRole::Viewer);
	live.bytes = "0123456789abcdef";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 16, resource, range);
	DeliverySink sink;

	for (unsigned attempt = 0; attempt < 2; ++attempt) {
		WebHlsCapabilityReadRequest attemptRequest = request;
		attemptRequest.now_ms += static_cast<std::uint64_t>(attempt) * 20;
		const WebHlsCapabilityReadDecision candidate =
			Candidate(policy, attemptRequest, live);
		Require(candidate.status == WebHlsCapabilityReadStatus::Candidate &&
			candidate.resource == resource && candidate.range == range,
			"exact retry must preserve resource and Range");
		BufferedDelivery prepared =
			live.Acquire(policy, attemptRequest, candidate, 206);
		Require(prepared.status == LeaseStatus::Prepared &&
			prepared.resource == resource && prepared.range == range,
			"lease must preserve exact retry metadata");
		live.DeliverOutside(std::move(prepared), sink);
	}

	Require(live.copies.load(std::memory_order_relaxed) == 4 &&
		live.commit_attempts.load(std::memory_order_relaxed) == 2 &&
		live.commits.load(std::memory_order_relaxed) == 2 &&
		live.file_reads.load(std::memory_order_relaxed) == 2 &&
		live.viewer_notes.load(std::memory_order_relaxed) == 2 &&
		live.deliveries.load(std::memory_order_relaxed) == 2,
		"initial Range read and retry must each run every effect once");
	Require(sink.ranges.size() == 2 && sink.ranges[0] == range &&
		sink.ranges[1] == range && sink.bodies[0] == sink.bodies[1],
		"delivered Range retries must be byte-for-byte equivalent");
}

void TestEightConcurrentReadsDoNotDeadlock()
{
	constexpr unsigned kWorkerCount = 8;
	const std::string stream = Stream('9');
	const std::string digest = Token('5');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 9, stream, WebHlsSourceRole::Viewer, 17, digest);
	LeaseHarness live;
	live.source = Source(stream, 17, WebHlsSourceRole::Viewer);
	live.bytes = "concurrent-body";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 17, "seg_00017.ts", "bytes=0-14");
	DeliverySink sink;
	std::atomic<unsigned> successes{0};
	CompletionWatchdog watchdog;
	std::vector<std::thread> workers;
	workers.reserve(kWorkerCount);
	const auto started = std::chrono::steady_clock::now();
	for (unsigned index = 0; index < kWorkerCount; ++index) {
		workers.emplace_back([&]() {
			const WebHlsCapabilityReadDecision candidate =
				Candidate(policy, request, live);
			BufferedDelivery prepared =
				live.Acquire(policy, request, candidate, 206);
			if (prepared.status == LeaseStatus::Prepared &&
				prepared.body == "concurrent-body") {
				live.DeliverOutside(std::move(prepared), sink);
				successes.fetch_add(1, std::memory_order_relaxed);
			}
			watchdog.Complete();
		});
	}
	AbortOnWatchdogTimeout(
		watchdog, kWorkerCount,
		"eight concurrent manager-to-policy reads deadlocked");
	for (std::thread& worker : workers)
		worker.join();
	const auto elapsed = std::chrono::steady_clock::now() - started;

	Require(successes.load(std::memory_order_relaxed) == kWorkerCount,
		"all eight concurrent lease reads must complete");
	Require(elapsed < std::chrono::seconds(5),
		"concurrent manager-to-policy lock order must not deadlock");
	Require(live.copies.load(std::memory_order_relaxed) ==
		kWorkerCount * 2 &&
		live.commits.load(std::memory_order_relaxed) == kWorkerCount &&
		live.file_reads.load(std::memory_order_relaxed) == kWorkerCount &&
		live.viewer_notes.load(std::memory_order_relaxed) == kWorkerCount &&
		live.deliveries.load(std::memory_order_relaxed) == kWorkerCount,
		"concurrent reads must perform each effect exactly once");
}

void TestMixedReadRejoinLogoutStressDoesNotDeadlock()
{
	constexpr unsigned kReaderCount = 4;
	constexpr unsigned kReadAttempts = 128;
	constexpr unsigned kTransitions = 64;
	const std::string stream = Stream('d');
	const std::string digest = Token('9');
	WebAuthPolicy policy;
	AddOwnerAndCapability(
		policy, 13, stream, WebHlsSourceRole::Viewer, 22, digest);
	LeaseHarness live;
	live.source = Source(stream, 22, WebHlsSourceRole::Viewer);
	live.bytes = "stress-generation-twenty-two";
	const WebHlsCapabilityReadRequest request =
		Request(digest, stream, 22, "seg_00022.ts");
	DeliverySink sink;
	std::atomic<bool> start{false};
	std::atomic<bool> logoutSucceeded{false};
	std::atomic<unsigned> invalidDeliveries{0};
	CompletionWatchdog watchdog;
	std::vector<std::thread> workers;
	workers.reserve(kReaderCount + 2);

	for (unsigned index = 0; index < kReaderCount; ++index) {
		workers.emplace_back([&]() {
			while (!start.load(std::memory_order_acquire))
				std::this_thread::yield();
			for (unsigned attempt = 0; attempt < kReadAttempts; ++attempt) {
				const WebHlsCapabilityReadDecision candidate =
					Candidate(policy, request, live);
				BufferedDelivery prepared =
					live.Acquire(policy, request, candidate, 200);
				if (prepared.status == LeaseStatus::Prepared) {
					if (prepared.body != "stress-generation-twenty-two") {
						invalidDeliveries.fetch_add(
							1, std::memory_order_relaxed);
					}
					live.DeliverOutside(std::move(prepared), sink);
				}
				if ((attempt & 7U) == 0)
					std::this_thread::yield();
			}
			watchdog.Complete();
		});
	}

	workers.emplace_back([&]() {
		while (!start.load(std::memory_order_acquire))
			std::this_thread::yield();
		for (unsigned transition = 0;
			transition < kTransitions; ++transition) {
			// A leave exposes no valid generation; the following rejoin gets
			// a fresh generation. Both changes take the same manager lease
			// used by reads, so capture can never straddle either transition.
			live.ReplaceSource(
				Source(stream, 0, WebHlsSourceRole::Viewer), std::string());
			std::this_thread::yield();
			live.ReplaceSource(
				Source(stream, 23 + transition, WebHlsSourceRole::Viewer),
				"stress-rejoined-body");
		}
		watchdog.Complete();
	});

	workers.emplace_back([&]() {
		while (!start.load(std::memory_order_acquire))
			std::this_thread::yield();
		for (unsigned spin = 0; spin < 32; ++spin)
			std::this_thread::yield();
		logoutSucceeded.store(
			policy.RemoveSession(13), std::memory_order_release);
		watchdog.Complete();
	});

	const auto started = std::chrono::steady_clock::now();
	start.store(true, std::memory_order_release);
	AbortOnWatchdogTimeout(
		watchdog, kReaderCount + 2,
		"mixed read, leave/rejoin, and logout activity deadlocked");
	for (std::thread& worker : workers)
		worker.join();
	const auto elapsed = std::chrono::steady_clock::now() - started;

	Require(logoutSucceeded.load(std::memory_order_acquire),
		"mixed readers, leave/rejoin, and logout must all complete");
	Require(elapsed < std::chrono::seconds(5),
		"mixed manager-to-policy activity must not deadlock");
	Require(invalidDeliveries.load(std::memory_order_relaxed) == 0,
		"mixed stress must never deliver bytes from a rejoined generation");
	Require(live.commits.load(std::memory_order_relaxed) ==
		live.file_reads.load(std::memory_order_relaxed) &&
		live.commits.load(std::memory_order_relaxed) ==
		live.viewer_notes.load(std::memory_order_relaxed) &&
		live.commits.load(std::memory_order_relaxed) ==
		live.deliveries.load(std::memory_order_relaxed),
		"every winning mixed-stress Commit must have one complete delivery");
	Require(policy.HlsCapabilityCount() == 0,
		"mixed-stress logout must revoke all future reads");
}

} // namespace

int main()
{
	try {
		TestCandidateDoesNotTouchOwner();
		TestRolloverBeforeLeaseHasNoEffects();
		TestLogoutBetweenCandidateAndCommit();
		TestExpiryBetweenInspectAndCommit();
		TestCommitWinsBeforeLogout();
		TestCapturedBytesAreImmutableAfterLease();
		TestTransitionWaitsForCaptureLease();
		TestNoteRequiresViewerSuccessfulBody();
		TestExactRangeRetry();
		TestEightConcurrentReadsDoNotDeadlock();
		TestMixedReadRejoinLogoutStressDoesNotDeadlock();
	} catch (const std::exception& error) {
		std::cerr << "FAIL: " << error.what() << '\n';
		return 1;
	}
	std::cout << "web HLS capability controller lease tests: PASS\n";
	return 0;
}
