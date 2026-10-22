#pragma once
#include "EseChannelBinding.h"
#include <algorithm>
#include <optional>

// Local trust policy, never a network record. Profile IO must atomically persist
// a prepared TOFU record before using it to authorize application traffic.
// Caller owns the stable local peer reference; IP/user_hash are not trust keys.
namespace ese { namespace trust {
enum class Kind : std::uint8_t { Tofu=1, Pinned=2 };
enum class Match { Unknown, Known, Changed, Invalid };
enum class CommitResult { Stored, PinChanged, PersistenceFailed };
class Committer {
public:
    virtual ~Committer() = default;
    // Called once after binding AUTH; must not reenter the transport. Stored
    // means durable profile publication, not merely an in-memory observation.
    virtual CommitResult Commit(const binding::Session&,
        const std::array<std::uint8_t,32>& expected) noexcept = 0;
};
struct Record {
    std::array<std::uint8_t,32> node{};
    std::uint64_t version=0;
    Kind kind=Kind::Tofu;
};
inline bool Valid(const Record& record) noexcept {
    return record.version &&
        (record.kind==Kind::Tofu || record.kind==Kind::Pinned) &&
        std::any_of(record.node.begin(),record.node.end(),[](std::uint8_t b){return b!=0;});
}
inline Match Check(const std::optional<Record>& known,
    const std::array<std::uint8_t,32>& expected) noexcept {
    if(std::all_of(expected.begin(),expected.end(),[](std::uint8_t b){return b==0;})) return Match::Invalid;
    if(!known) return Match::Unknown;
    if(!Valid(*known)) return Match::Invalid;
    return known->node==expected ? Match::Known : Match::Changed;
}
// Signature-bound peer only. Merely decoded HELLO/descriptor cannot call this
// successfully. Existing records are never replaced, even by a valid new key.
inline std::optional<Record> PrepareFirstUse(const binding::Session& session,
    const std::array<std::uint8_t,32>& expected,const std::optional<Record>& known) noexcept {
    if(Check(known,expected)!=Match::Unknown) return std::nullopt;
    const auto* peer=session.BoundPeer();
    if(!peer || peer->node!=expected) return std::nullopt;
    return Record{expected,1,Kind::Tofu};
}
constexpr std::size_t RecordSize=48;
inline bool Encode(const Record& record,std::array<std::uint8_t,RecordSize>& output) noexcept {
    if(!Valid(record)) return false;
    std::array<std::uint8_t,RecordSize> bytes{};
    bytes[0]='E'; bytes[1]='P'; bytes[2]='T'; bytes[3]=1;
    bytes[4]=static_cast<std::uint8_t>(record.kind);
    for(unsigned i=0;i<8;++i) bytes[8+i]=static_cast<std::uint8_t>(record.version>>(56-8*i));
    std::copy(record.node.begin(),record.node.end(),bytes.begin()+16);
    output=bytes; return true;
}
inline bool Decode(const std::uint8_t* bytes,std::size_t length,Record& output) noexcept {
    if(!bytes || length!=RecordSize || bytes[0]!='E' || bytes[1]!='P' || bytes[2]!='T' ||
        bytes[3]!=1 || bytes[5] || bytes[6] || bytes[7]) return false;
    Record record; record.kind=static_cast<Kind>(bytes[4]);
    for(unsigned i=0;i<8;++i) record.version=(record.version<<8)|bytes[8+i];
    std::copy_n(bytes+16,32,record.node.begin());
    if(!Valid(record)) return false;
    output=record; return true;
}
} }
