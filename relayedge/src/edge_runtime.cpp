// SPDX-License-Identifier: MIT
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "edge/edge_runtime.h"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <string>

namespace relayedge {

namespace {

std::string Trim(const std::string& input) {
    const std::size_t first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const std::size_t last = input.find_last_not_of(" \t\r\n");
    return input.substr(first, last - first + 1);
}

bool ParseUnsigned(const std::string& text, std::uint64_t& value) noexcept {
    if (text.empty())
        return false;
    std::uint64_t parsed = 0;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const std::from_chars_result result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end)
        return false;
    value = parsed;
    return true;
}

bool FitsSize(std::uint64_t value) noexcept {
    return value <= static_cast<std::uint64_t>(
        (std::numeric_limits<std::size_t>::max)());
}

bool ValidPath(const std::string& value) noexcept {
    return !value.empty() && value.size() <= kMaxConfigPathBytes &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte >= 0x20u && byte != 0x7Fu;
        });
}

bool SeenKey(const std::array<std::string, 24>& seen,
             std::size_t count,
             const std::string& key) {
    return std::find(seen.begin(), seen.begin() + count, key) != seen.begin() + count;
}

relay::RelayStatus SetConfigValue(EdgeConfig& config,
                                  const std::string& key,
                                  const std::string& value) {
    std::uint64_t number = 0;
    if (key == "mode") {
        if (value == "disabled") config.mode = EdgeMode::Disabled;
        else if (value == "lab-loopback") config.mode = EdgeMode::LabLoopback;
        else if (value == "experimental-public") config.mode = EdgeMode::ExperimentalPublic;
        else return relay::RelayStatus::UnsupportedOption;
    } else if (key == "explicit_lab_enable") {
        if (value == "true") config.explicit_lab_enable = true;
        else if (value == "false") config.explicit_lab_enable = false;
        else return relay::RelayStatus::InvalidArgument;
    } else if (key == "explicit_public_enable") {
        if (value == "true") config.explicit_public_enable = true;
        else if (value == "false") config.explicit_public_enable = false;
        else return relay::RelayStatus::InvalidArgument;
    } else if (key == "bind_address") {
        config.bind_address = value;
    } else if (key == "certificate_path") {
        config.certificate_path = value;
    } else if (key == "private_key_path") {
        config.private_key_path = value;
    } else if (key == "public_ipv4") {
        config.public_ipv4 = value;
    } else if (key == "auth_token_path") {
        config.auth_token_path = value;
    } else if (key == "port") {
        if (!ParseUnsigned(value, number) || number > 65535) return relay::RelayStatus::InvalidArgument;
        config.port = static_cast<std::uint16_t>(number);
    } else if (key == "max_sessions") {
        if (!ParseUnsigned(value, number) || !FitsSize(number)) return relay::RelayStatus::InvalidArgument;
        config.max_sessions = static_cast<std::size_t>(number);
    } else if (key == "max_flows_per_session") {
        if (!ParseUnsigned(value, number) || !FitsSize(number)) return relay::RelayStatus::InvalidArgument;
        config.max_flows_per_session = static_cast<std::size_t>(number);
    } else if (key == "max_leases_per_session") {
        if (!ParseUnsigned(value, number) || !FitsSize(number)) return relay::RelayStatus::InvalidArgument;
        config.max_leases_per_session = static_cast<std::size_t>(number);
    } else if (key == "max_preauth_bytes") {
        if (!ParseUnsigned(value, number) || !FitsSize(number)) return relay::RelayStatus::InvalidArgument;
        config.max_preauth_bytes = static_cast<std::size_t>(number);
    } else if (key == "preauth_timeout_ms") {
        if (!ParseUnsigned(value, number)) return relay::RelayStatus::InvalidArgument;
        config.preauth_timeout_ms = number;
    } else if (key == "idle_timeout_ms") {
        if (!ParseUnsigned(value, number)) return relay::RelayStatus::InvalidArgument;
        config.idle_timeout_ms = number;
    } else if (key == "reuse_delay_ms") {
        if (!ParseUnsigned(value, number)) return relay::RelayStatus::InvalidArgument;
        config.reuse_delay_ms = number;
    } else if (key == "lease_first_port") {
        if (!ParseUnsigned(value, number) || number > 65535) return relay::RelayStatus::InvalidArgument;
        config.lease_first_port = static_cast<std::uint16_t>(number);
    } else if (key == "lease_last_port") {
        if (!ParseUnsigned(value, number) || number > 65535) return relay::RelayStatus::InvalidArgument;
        config.lease_last_port = static_cast<std::uint16_t>(number);
    } else {
        return relay::RelayStatus::UnsupportedOption;
    }
    return relay::RelayStatus::Ok;
}

} // namespace

relay::RelayStatus ValidateEdgeConfig(const EdgeConfig& config) noexcept {
    if (config.mode == EdgeMode::Disabled)
        return relay::RelayStatus::Disabled;
    if (config.mode == EdgeMode::LabLoopback) {
        if (!config.explicit_lab_enable)
            return relay::RelayStatus::Disabled;
        if (config.bind_address != "127.0.0.1" && config.bind_address != "::1")
            return relay::RelayStatus::TargetForbidden;
    } else if (config.mode == EdgeMode::ExperimentalPublic) {
        if (!config.explicit_public_enable || config.explicit_lab_enable ||
            config.port == 0 || !ValidPath(config.auth_token_path))
            return relay::RelayStatus::Disabled;
        IN_ADDR public_address{};
        if (::InetPtonA(AF_INET, config.public_ipv4.c_str(), &public_address) != 1)
            return relay::RelayStatus::InvalidArgument;
        const std::uint32_t host = ntohl(public_address.S_un.S_addr);
        const std::uint8_t first = static_cast<std::uint8_t>(host >> 24);
        const std::uint8_t second = static_cast<std::uint8_t>(host >> 16);
        if (first == 0 || first == 10 || first == 127 || first >= 224 ||
            (first == 100 && second >= 64 && second <= 127) ||
            (first == 169 && second == 254) ||
            (first == 172 && second >= 16 && second <= 31) ||
            (first == 192 && second == 168))
            return relay::RelayStatus::TargetForbidden;
    } else {
        return relay::RelayStatus::Disabled;
    }
    if (!ValidPath(config.certificate_path) || !ValidPath(config.private_key_path))
        return relay::RelayStatus::InvalidArgument;
    if (config.max_sessions == 0 || config.max_sessions > 50000 ||
        config.max_flows_per_session == 0 || config.max_flows_per_session > 1024 ||
        config.max_leases_per_session == 0 || config.max_leases_per_session > 8 ||
        config.max_preauth_bytes == 0 || config.max_preauth_bytes > 64 * 1024 ||
        config.preauth_timeout_ms == 0 || config.preauth_timeout_ms > 30000 ||
        config.idle_timeout_ms < 1000 || config.idle_timeout_ms > 600000 ||
        config.reuse_delay_ms < 1000 || config.reuse_delay_ms > 600000 ||
        config.lease_first_port < 1024 ||
        config.lease_last_port < config.lease_first_port ||
        static_cast<std::uint32_t>(config.lease_last_port) - config.lease_first_port + 1 > 4096)
        return relay::RelayStatus::InvalidArgument;
    return relay::RelayStatus::Ok;
}

relay::RelayStatus LoadEdgeConfig(const char* path, EdgeConfig& config) {
    if (path == nullptr || *path == '\0')
        return relay::RelayStatus::InvalidArgument;
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return relay::RelayStatus::InvalidArgument;
    file.seekg(0, std::ios::end);
    const std::streamoff file_size = file.tellg();
    if (file_size < 0)
        return relay::RelayStatus::Malformed;
    if (file_size > static_cast<std::streamoff>(kMaxConfigFileBytes))
        return relay::RelayStatus::TooLarge;
    std::string contents(static_cast<std::size_t>(file_size), '\0');
    file.seekg(0, std::ios::beg);
    if (!contents.empty() &&
        !file.read(&contents[0], static_cast<std::streamsize>(contents.size())))
        return relay::RelayStatus::Malformed;
    if (contents.find('\0') != std::string::npos)
        return relay::RelayStatus::Malformed;

    EdgeConfig parsed;
    std::array<std::string, 24> seen{};
    std::size_t seen_count = 0;
    std::size_t position = 0;
    while (position <= contents.size()) {
        const std::size_t end = contents.find('\n', position);
        const std::size_t length = (end == std::string::npos ? contents.size() : end) - position;
        if (length > kMaxConfigLineBytes)
            return relay::RelayStatus::TooLarge;
        std::string line = Trim(contents.substr(position, length));
        if (!line.empty() && line[0] != '#') {
            const std::size_t separator = line.find('=');
            if (separator == std::string::npos)
                return relay::RelayStatus::Malformed;
            const std::string key = Trim(line.substr(0, separator));
            const std::string value = Trim(line.substr(separator + 1));
            if (key.empty() || value.empty() || seen_count >= seen.size() ||
                SeenKey(seen, seen_count, key))
                return relay::RelayStatus::Malformed;
            const relay::RelayStatus status = SetConfigValue(parsed, key, value);
            if (status != relay::RelayStatus::Ok)
                return status;
            seen[seen_count++] = key;
        }
        if (end == std::string::npos)
            break;
        position = end + 1;
    }
    const relay::RelayStatus validation = ValidateEdgeConfig(parsed);
    if (validation != relay::RelayStatus::Ok)
        return validation;
    config = parsed;
    return relay::RelayStatus::Ok;
}

void EdgeMetrics::Increment(EdgeMetric metric, std::uint64_t amount) noexcept {
    const std::size_t index = static_cast<std::size_t>(metric);
    if (index >= values_.size())
        return;
    const std::uint64_t maximum = (std::numeric_limits<std::uint64_t>::max)();
    values_[index] = amount > maximum - values_[index] ? maximum : values_[index] + amount;
}

std::uint64_t EdgeMetrics::Get(EdgeMetric metric) const noexcept {
    const std::size_t index = static_cast<std::size_t>(metric);
    return index < values_.size() ? values_[index] : 0;
}

void AuditRing::Push(const AuditEvent& event) noexcept {
    events_[next_] = event;
    next_ = (next_ + 1) % events_.size();
    if (size_ < events_.size())
        ++size_;
}

const AuditEvent* AuditRing::At(std::size_t oldest_index) const noexcept {
    if (oldest_index >= size_)
        return nullptr;
    const std::size_t first = (next_ + events_.size() - size_) % events_.size();
    return &events_[(first + oldest_index) % events_.size()];
}

relay::RelayStatus EdgeRuntime::Start(const EdgeConfig& config,
                                      std::uint64_t now_ms) noexcept {
    if (state_ != EdgeLifecycle::Stopped)
        return relay::RelayStatus::InvalidState;
    state_ = EdgeLifecycle::Starting;
    const relay::RelayStatus validation = ValidateEdgeConfig(config);
    if (validation != relay::RelayStatus::Ok) {
        state_ = EdgeLifecycle::Stopped;
        metrics_.Increment(EdgeMetric::StartRejected);
        audit_.Push({now_ms, AuditReason::ConfigRejected, 0, 0, validation});
        return validation;
    }
    config_ = config;
    kill_switch_ = false;
    state_ = EdgeLifecycle::Running;
    metrics_.Increment(EdgeMetric::StartOk);
    audit_.Push({now_ms, AuditReason::Started, 0, 0, relay::RelayStatus::Ok});
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeRuntime::BeginDrain(std::uint64_t now_ms,
                                           std::uint64_t deadline_ms) noexcept {
    if (state_ != EdgeLifecycle::Running)
        return relay::RelayStatus::InvalidState;
    if (deadline_ms <= now_ms || deadline_ms - now_ms > kMaxDrainMs)
        return relay::RelayStatus::InvalidArgument;
    state_ = EdgeLifecycle::Draining;
    drain_deadline_ms_ = deadline_ms;
    metrics_.Increment(EdgeMetric::GoAwaySent);
    audit_.Push({now_ms, AuditReason::Draining, 0, 0, relay::RelayStatus::Ok});
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeRuntime::Tick(std::uint64_t now_ms) noexcept {
    if (state_ != EdgeLifecycle::Draining)
        return relay::RelayStatus::Ok;
    if (now_ms < drain_deadline_ms_)
        return relay::RelayStatus::Ok;
    state_ = EdgeLifecycle::Stopped;
    audit_.Push({now_ms, AuditReason::Stopped, 0, 0, relay::RelayStatus::Ok});
    return relay::RelayStatus::Expired;
}

relay::RelayStatus EdgeRuntime::Kill(std::uint64_t now_ms) noexcept {
    kill_switch_ = true;
    state_ = EdgeLifecycle::Stopped;
    drain_deadline_ms_ = 0;
    metrics_.Increment(EdgeMetric::KillSwitch);
    audit_.Push({now_ms, AuditReason::Killed, 0, 0, relay::RelayStatus::Disabled});
    return relay::RelayStatus::Ok;
}

relay::RelayStatus EdgeRuntime::Fail(std::uint64_t now_ms,
                                     relay::RelayStatus reason) noexcept {
    if (reason == relay::RelayStatus::Ok)
        return relay::RelayStatus::InvalidArgument;
    state_ = EdgeLifecycle::Failed;
    audit_.Push({now_ms, AuditReason::Failed, 0, 0, reason});
    return reason;
}

EdgeHealth EdgeRuntime::health() const noexcept {
    switch (state_) {
        case EdgeLifecycle::Stopped:  return EdgeHealth::Disabled;
        case EdgeLifecycle::Starting: return EdgeHealth::Starting;
        case EdgeLifecycle::Running:  return EdgeHealth::Healthy;
        case EdgeLifecycle::Draining: return EdgeHealth::Draining;
        case EdgeLifecycle::Failed:   return EdgeHealth::Failed;
    }
    return EdgeHealth::Failed;
}

const char* EdgeLifecycleName(EdgeLifecycle state) noexcept {
    switch (state) {
        case EdgeLifecycle::Stopped:  return "STOPPED";
        case EdgeLifecycle::Starting: return "STARTING";
        case EdgeLifecycle::Running:  return "RUNNING";
        case EdgeLifecycle::Draining: return "DRAINING";
        case EdgeLifecycle::Failed:   return "FAILED";
    }
    return "UNKNOWN";
}

} // namespace relayedge
