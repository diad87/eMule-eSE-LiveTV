// SPDX-License-Identifier: MIT
#pragma once
#include "reach/direct_session.h"
#include <limits>
#include <optional>

namespace reach {
enum class DirectConsumerKind : std::uint8_t { Download, Upload, ClientList, Discovery };
struct DirectSubscriber {
    std::uint64_t token=0;
    std::uint64_t client_lifetime=0; // host monotonic lifetime ID, never a pointer/IP
    DirectConsumerKind consumer=DirectConsumerKind::Download;
    std::optional<DirectHandle> attempt;
    std::optional<DirectReason> terminal_reason;
    bool terminal_taken=false;
    bool merged_follower=false;
};
// Main-thread registry. Resolve returns a copy: callbacks may remove records
// without leaving references into reused slots. Tokens never wrap or reset.
class DirectSubscribers {
public:
    static constexpr std::size_t Capacity=4096; // 256 attempts * 16 subscribers
    std::uint64_t Acquire(std::uint64_t lifetime,DirectConsumerKind consumer) {
        if(!lifetime || static_cast<std::uint8_t>(consumer)>static_cast<std::uint8_t>(DirectConsumerKind::Discovery)) return 0;
        for(const auto& record:records_) if(record.token && record.client_lifetime==lifetime && record.consumer==consumer) return record.token;
        if(last_token_==(std::numeric_limits<std::uint64_t>::max)()) return 0;
        for(auto& record:records_) if(!record.token) {
            record={++last_token_,lifetime,consumer,std::nullopt}; return record.token;
        }
        return 0;
    }
    std::optional<DirectSubscriber> Resolve(std::uint64_t token) const {
        if(token) for(const auto& record:records_) if(record.token==token) return record;
        return std::nullopt;
    }
    std::optional<DirectSubscriber> FindLifetime(std::uint64_t lifetime) const noexcept {
        if(lifetime) for(const auto& record:records_) if(record.token && record.client_lifetime==lifetime) return record;
        return std::nullopt;
    }
    // Identity lookup is not consumer authority. Only a live transfer
    // subscription for this exact generation may adopt/deliver a transport.
    bool HasTransferBinding(std::uint64_t lifetime,DirectHandle handle) const noexcept {
        if(!lifetime || !handle.generation || handle.slot>=256) return false;
        for(const auto& record:records_) if(record.token && record.client_lifetime==lifetime
            && (record.consumer==DirectConsumerKind::Download || record.consumer==DirectConsumerKind::Upload)
            && record.attempt && record.attempt->slot==handle.slot && record.attempt->generation==handle.generation
            && !record.terminal_reason) return true;
        return false;
    }
    std::optional<std::uint64_t> TransferLifetime(DirectHandle handle) const noexcept {
        if(!handle.generation || handle.slot>=256) return std::nullopt;
        std::optional<std::uint64_t> selected;
        bool selectedFollower=true;
        for(const auto& record:records_) if(record.token && record.client_lifetime
            && (record.consumer==DirectConsumerKind::Download || record.consumer==DirectConsumerKind::Upload)
            && record.attempt && record.attempt->slot==handle.slot && record.attempt->generation==handle.generation
            && !record.terminal_reason && (!selected ||
                (selectedFollower && !record.merged_follower) ||
                (selectedFollower==record.merged_follower && record.client_lifetime<*selected))) {
                selected=record.client_lifetime; selectedFollower=record.merged_follower;
            }
        return selected;
    }
    // Validate the whole transfer before changing any scalar binding. Keep the
    // established target's delivery owner; an older merged lifetime must not
    // silently replace the client already attached to its authenticated socket.
    bool RebindMerged(DirectHandle from,DirectHandle to,const std::vector<std::uint64_t>& tokens) noexcept {
        if(!from.generation || !to.generation || from.slot>=256 || to.slot>=256 ||
            (from.slot==to.slot && from.generation==to.generation) || tokens.size()>16) return false;
        for(std::size_t i=0;i<tokens.size();++i) {
            const auto record=Resolve(tokens[i]);
            if(!record || !record->attempt || record->terminal_reason ||
                record->attempt->slot!=from.slot || record->attempt->generation!=from.generation) return false;
            for(std::size_t j=0;j<i;++j) if(tokens[j]==tokens[i]) return false;
        }
        for(auto& record:records_) for(const auto token:tokens) if(record.token==token) {
            record.attempt=to; record.merged_follower=true;
        }
        return true;
    }
    std::size_t Size() const noexcept {
        std::size_t count=0;
        for(const auto& record:records_) if(record.token) ++count;
        return count;
    }
    bool Bind(std::uint64_t token,DirectHandle handle) {
        if(!token || !handle.generation) return false;
        for(auto& record:records_) if(record.token==token) {
            if(record.attempt) return record.attempt->slot==handle.slot && record.attempt->generation==handle.generation;
            record.attempt=handle; return true;
        }
        return false;
    }
    bool Complete(std::uint64_t token,DirectReason reason) noexcept {
        if(token) for(auto& record:records_) if(record.token==token) {
            if(!record.attempt || record.terminal_reason) return false;
            record.terminal_reason=reason; return true;
        }
        return false;
    }
    std::optional<DirectReason> TakeTerminal(std::uint64_t token) noexcept {
        if(token) for(auto& record:records_) if(record.token==token) {
            if(!record.terminal_reason || record.terminal_taken) return std::nullopt;
            record.terminal_taken=true; return record.terminal_reason;
        }
        return std::nullopt;
    }
    // Caller owns unsubscription/terminal dispatch outside registry mutation.
    std::optional<DirectSubscriber> Remove(std::uint64_t token) {
        if(token) for(auto& record:records_) if(record.token==token) {
            const auto retired=record; record={}; return retired;
        }
        return std::nullopt;
    }
private:
    std::array<DirectSubscriber,Capacity> records_{};
    std::uint64_t last_token_=0;
};
}
