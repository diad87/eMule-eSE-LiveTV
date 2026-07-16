// SPDX-License-Identifier: MIT
// Rev3 LT3: real-time, real TCP loopback exercise for Kad6 byte-credit flow control.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "kad6/kad6_gateway.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

using namespace kad6;
using Clock = std::chrono::steady_clock;

namespace {
constexpr std::uint64_t kStreamId = 42;
constexpr std::uint64_t kRunSeconds = 60;
constexpr std::uint64_t kOfferedBytesPerSecond = 640u * 1024u;
constexpr std::uint64_t kConsumedBytesPerSecond = 64u * 1024u;
constexpr std::uint32_t kControlMagic = 0x3354364c; // "L6T3", lab envelope only.
constexpr std::size_t kControlBytes = 4 + 4 + 8 + 20 + 12;

std::uint64_t NowNs() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now().time_since_epoch()).count());
}

void AtomicMax(std::atomic<std::uint64_t>& target, std::uint64_t value) {
    std::uint64_t old = target.load();
    while (old < value && !target.compare_exchange_weak(old, value)) {}
}

Byte Pattern(std::uint64_t offset) {
    return static_cast<Byte>((offset * 131u + 17u) & 0xffu);
}

bool WouldBlock() { return WSAGetLastError() == WSAEWOULDBLOCK; }

bool SetNonBlocking(SOCKET socket) {
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0;
}

bool SendAll(SOCKET socket, const Byte* bytes, std::size_t length) {
    const Clock::time_point deadline = Clock::now() + std::chrono::seconds(2);
    std::size_t sent = 0;
    while (sent < length && Clock::now() < deadline) {
        const int rc = send(socket, reinterpret_cast<const char*>(bytes + sent),
            static_cast<int>(length - sent), 0);
        if (rc > 0) sent += static_cast<std::size_t>(rc);
        else if (rc == SOCKET_ERROR && WouldBlock())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        else
            return false;
    }
    return sent == length;
}

struct Shared {
    std::atomic<bool> server_done{false};
    std::atomic<std::uint64_t> sender_sent{0};
    std::atomic<std::uint64_t> receiver_accepted{0};
    std::atomic<std::uint64_t> receiver_consumed{0};
    std::atomic<std::uint64_t> max_buffered{0};
    std::atomic<std::uint64_t> pause_transitions{0};
    std::atomic<std::uint64_t> resume_transitions{0};
    std::atomic<std::uint64_t> control_sent{0};
    std::atomic<std::uint64_t> bad_pattern{0};
    std::atomic<std::uint64_t> credit_errors{0};
    std::atomic<std::uint64_t> premature_close{0};
};

bool SendCredit(SOCKET socket, std::uint32_t serial,
        const K6MaxStreamData& streamCredit, const K6MaxData& circuitCredit) {
    std::vector<Byte> streamWire, circuitWire;
    if (EncodeK6MaxStreamData(streamCredit, streamWire) != Kad6Status::Ok ||
        EncodeK6MaxData(circuitCredit, circuitWire) != Kad6Status::Ok ||
        streamWire.size() != 20 || circuitWire.size() != 12) return false;
    std::array<Byte, kControlBytes> packet{};
    const std::uint64_t created = NowNs();
    std::memcpy(packet.data(), &kControlMagic, 4);
    std::memcpy(packet.data() + 4, &serial, 4);
    std::memcpy(packet.data() + 8, &created, 8);
    std::memcpy(packet.data() + 16, streamWire.data(), streamWire.size());
    std::memcpy(packet.data() + 36, circuitWire.data(), circuitWire.size());
    return SendAll(socket, packet.data(), packet.size());
}

void Receiver(SOCKET listener, const Clock::time_point started, Shared& shared) {
    SOCKET socket = accept(listener, nullptr, nullptr);
    if (socket == INVALID_SOCKET || !SetNonBlocking(socket)) {
        shared.credit_errors.fetch_add(1); shared.server_done.store(true); return;
    }
    K6ReceiveCreditWindow receiver;
    K6MaxStreamData streamCredit;
    K6MaxData circuitCredit;
    std::uint32_t controlSerial = 1;
    if (receiver.RegisterStream(kStreamId) != Kad6Status::Ok ||
        receiver.InitialCredit(kStreamId, 0, streamCredit, circuitCredit) !=
            Kad6Status::Ok ||
        !SendCredit(socket, controlSerial++, streamCredit, circuitCredit)) {
        shared.credit_errors.fetch_add(1); closesocket(socket);
        shared.server_done.store(true); return;
    }
    shared.control_sent.fetch_add(1);

    std::uint64_t expectedOffset = 0;
    std::uint64_t consumeRemainder = 0;
    Clock::time_point lastConsume = Clock::now();
    bool wasPaused = false;
    bool eof = false;
    std::array<Byte, 64u * 1024u> input{};

    while (!eof) {
        const Clock::time_point now = Clock::now();
        const std::uint64_t elapsedSeconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(now - started).count());
        const bool downstreamStalled = (elapsedSeconds >= 10 && elapsedSeconds < 15) ||
            (elapsedSeconds >= 30 && elapsedSeconds < 35) ||
            (elapsedSeconds >= 50 && elapsedSeconds < 55);

        if (!receiver.reads_paused()) {
            for (;;) {
                const int rc = recv(socket, reinterpret_cast<char*>(input.data()),
                    static_cast<int>(input.size()), 0);
                if (rc == 0) { eof = true; break; }
                if (rc == SOCKET_ERROR) {
                    if (!WouldBlock()) { shared.credit_errors.fetch_add(1); eof = true; }
                    break;
                }
                const std::size_t received = static_cast<std::size_t>(rc);
                for (std::size_t i = 0; i < received; ++i)
                    if (input[i] != Pattern(expectedOffset + i))
                        shared.bad_pattern.fetch_add(1);
                if (receiver.Accept(kStreamId, 0, received, NowNs() / 1000000u) !=
                        Kad6Status::Ok) {
                    shared.credit_errors.fetch_add(1); eof = true; break;
                }
                expectedOffset += received;
                shared.receiver_accepted.fetch_add(received);
                AtomicMax(shared.max_buffered, receiver.buffered_bytes());
                if (receiver.reads_paused()) break;
            }
        }

        const std::uint64_t deltaNs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(now - lastConsume).count());
        lastConsume = now;
        if (!downstreamStalled && receiver.buffered_bytes() != 0) {
            consumeRemainder += deltaNs * kConsumedBytesPerSecond;
            std::uint64_t consume = consumeRemainder / 1000000000u;
            consumeRemainder %= 1000000000u;
            consume = (std::min)(consume, receiver.buffered_bytes());
            if (consume != 0) {
                if (receiver.Consume(kStreamId, 0, consume, NowNs() / 1000000u,
                        streamCredit, circuitCredit) != Kad6Status::Ok ||
                    !SendCredit(socket, controlSerial++, streamCredit, circuitCredit)) {
                    shared.credit_errors.fetch_add(1); break;
                }
                shared.receiver_consumed.fetch_add(consume);
                shared.control_sent.fetch_add(1);
            }
        } else {
            // No accumulated catch-up burst after a deliberate downstream stall.
            consumeRemainder = 0;
        }

        const bool paused = receiver.reads_paused();
        if (!wasPaused && paused) shared.pause_transitions.fetch_add(1);
        if (wasPaused && !paused) shared.resume_transitions.fetch_add(1);
        wasPaused = paused;
        if (receiver.stalled(NowNs() / 1000000u)) {
            shared.premature_close.fetch_add(1); break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    closesocket(socket);
    shared.server_done.store(true);
}

void DrainControls(SOCKET socket, std::vector<Byte>& buffered, K6SendCreditLedger& sender,
        Shared& shared, std::uint64_t& maxDelayNs, std::uint32_t& lastSerial) {
    std::array<Byte, 4096> bytes{};
    for (;;) {
        const int rc = recv(socket, reinterpret_cast<char*>(bytes.data()),
            static_cast<int>(bytes.size()), 0);
        if (rc > 0) buffered.insert(buffered.end(), bytes.begin(), bytes.begin() + rc);
        else if (rc == SOCKET_ERROR && WouldBlock()) break;
        else break;
    }
    while (buffered.size() >= kControlBytes) {
        std::uint32_t magic = 0, serial = 0;
        std::uint64_t created = 0;
        std::memcpy(&magic, buffered.data(), 4);
        std::memcpy(&serial, buffered.data() + 4, 4);
        std::memcpy(&created, buffered.data() + 8, 8);
        K6MaxStreamData streamCredit; K6MaxData circuitCredit;
        std::size_t used = 0;
        const bool valid = magic == kControlMagic && serial > lastSerial &&
            DecodeK6MaxStreamData(buffered.data() + 16, 20, streamCredit, &used) ==
                Kad6Status::Ok && used == 20 &&
            DecodeK6MaxData(buffered.data() + 36, 12, circuitCredit, &used) ==
                Kad6Status::Ok && used == 12 &&
            sender.Grant(streamCredit) == Kad6Status::Ok &&
            sender.Grant(circuitCredit) == Kad6Status::Ok;
        if (!valid) shared.credit_errors.fetch_add(1);
        else {
            lastSerial = serial;
            maxDelayNs = (std::max)(maxDelayNs, NowNs() - created);
        }
        buffered.erase(buffered.begin(), buffered.begin() + kControlBytes);
    }
}
} // namespace

int main() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 2;
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return 2;
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = 0;
    if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(listener, 1) != 0) return 2;
    int addressLength = sizeof(address);
    getsockname(listener, reinterpret_cast<sockaddr*>(&address), &addressLength);

    Shared shared;
    const Clock::time_point started = Clock::now();
    std::thread receiver(Receiver, listener, started, std::ref(shared));
    SOCKET senderSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (senderSocket == INVALID_SOCKET || connect(senderSocket,
            reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        !SetNonBlocking(senderSocket)) return 2;

    K6SendCreditLedger sender;
    sender.RegisterStream(kStreamId);
    std::vector<Byte> controlBuffer;
    std::uint64_t maxControlDelayNs = 0;
    std::uint32_t lastControlSerial = 0;
    std::uint64_t sentBytes = 0;
    std::uint64_t offeredBytes = 0;
    std::uint64_t senderPauseTransitions = 0;
    bool senderWasPaused = false;
    const std::uint64_t unlimited = (std::numeric_limits<std::uint64_t>::max)();
    std::array<Byte, 16u * 1024u> output{};

    while (Clock::now() - started < std::chrono::seconds(kRunSeconds)) {
        DrainControls(senderSocket, controlBuffer, sender, shared,
            maxControlDelayNs, lastControlSerial);
        const std::uint64_t elapsedNs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - started).count());
        offeredBytes = elapsedNs * kOfferedBytesPerSecond / 1000000000u;
        const std::uint64_t available = sender.Available(kStreamId, 0, unlimited,
            unlimited, kK6DefaultReceiveBuffer);
        const std::uint64_t backlog = offeredBytes > sentBytes ? offeredBytes - sentBytes : 0;
        const std::size_t attempt = static_cast<std::size_t>((std::min)({available,
            backlog, static_cast<std::uint64_t>(output.size())}));
        const bool senderPaused = backlog != 0 && available == 0;
        if (!senderWasPaused && senderPaused) ++senderPauseTransitions;
        senderWasPaused = senderPaused;
        if (attempt != 0) {
            for (std::size_t i = 0; i < attempt; ++i) output[i] = Pattern(sentBytes + i);
            const int rc = send(senderSocket, reinterpret_cast<const char*>(output.data()),
                static_cast<int>(attempt), 0);
            if (rc > 0) {
                const std::uint64_t committed = static_cast<std::uint64_t>(rc);
                if (sender.CommitSend(kStreamId, 0, committed, unlimited, unlimited,
                        kK6DefaultReceiveBuffer) != Kad6Status::Ok)
                    shared.credit_errors.fetch_add(1);
                sentBytes += committed;
                shared.sender_sent.store(sentBytes);
            } else if (rc != SOCKET_ERROR || !WouldBlock()) {
                shared.credit_errors.fetch_add(1); break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // Capture the closing edge rather than the last loop sample immediately
    // before it; otherwise scheduler granularity can under-report the declared
    // 60-second offered load by a few milliseconds.
    offeredBytes = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - started).count()) *
        kOfferedBytesPerSecond / 1000000000u;

    shutdown(senderSocket, SD_SEND);
    const Clock::time_point drainDeadline = Clock::now() + std::chrono::seconds(5);
    while (!shared.server_done.load() && Clock::now() < drainDeadline) {
        DrainControls(senderSocket, controlBuffer, sender, shared,
            maxControlDelayNs, lastControlSerial);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    receiver.join();
    closesocket(senderSocket); closesocket(listener); WSACleanup();

    const std::uint64_t runtimeMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - started).count());
    const std::uint64_t accepted = shared.receiver_accepted.load();
    const bool pass = runtimeMs >= kRunSeconds * 1000u &&
        offeredBytes >= kRunSeconds * kOfferedBytesPerSecond &&
        sentBytes == accepted && shared.bad_pattern.load() == 0 &&
        shared.credit_errors.load() == 0 &&
        shared.max_buffered.load() <= kK6DefaultReceiveBuffer &&
        shared.pause_transitions.load() != 0 && shared.resume_transitions.load() != 0 &&
        senderPauseTransitions != 0 && shared.premature_close.load() == 0 &&
        shared.control_sent.load() != 0 && maxControlDelayNs <= 100000000u;

    std::printf("LT3_REAL_LOOPBACK status=%s runtime_ms=%llu offered=%llu sent=%llu "
        "accepted=%llu consumed=%llu max_buffered=%llu receiver_pause=%llu "
        "receiver_resume=%llu sender_pause=%llu controls=%llu max_control_delay_us=%llu "
        "pattern_errors=%llu credit_errors=%llu premature_close=%llu\n",
        pass ? "PASS" : "FAIL",
        static_cast<unsigned long long>(runtimeMs),
        static_cast<unsigned long long>(offeredBytes),
        static_cast<unsigned long long>(sentBytes),
        static_cast<unsigned long long>(accepted),
        static_cast<unsigned long long>(shared.receiver_consumed.load()),
        static_cast<unsigned long long>(shared.max_buffered.load()),
        static_cast<unsigned long long>(shared.pause_transitions.load()),
        static_cast<unsigned long long>(shared.resume_transitions.load()),
        static_cast<unsigned long long>(senderPauseTransitions),
        static_cast<unsigned long long>(shared.control_sent.load()),
        static_cast<unsigned long long>(maxControlDelayNs / 1000u),
        static_cast<unsigned long long>(shared.bad_pattern.load()),
        static_cast<unsigned long long>(shared.credit_errors.load()),
        static_cast<unsigned long long>(shared.premature_close.load()));
    return pass ? 0 : 1;
}
