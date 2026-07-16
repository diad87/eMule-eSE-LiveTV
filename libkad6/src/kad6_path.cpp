// SPDX-License-Identifier: MIT
#include "kad6/kad6_path.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace kad6 {
namespace {

bool NonZero(const Byte* value, std::size_t length) noexcept;

class K6PathWriter {
public:
    explicit K6PathWriter(std::vector<Byte>& out) : out_(out) { out_.clear(); }
    void U8(Byte value) { out_.push_back(value); }
    void U16(std::uint16_t value) { for (unsigned i=0;i<2;++i) U8(static_cast<Byte>(value>>(8*i))); }
    void U32(std::uint32_t value) { for (unsigned i=0;i<4;++i) U8(static_cast<Byte>(value>>(8*i))); }
    void U64(std::uint64_t value) { for (unsigned i=0;i<8;++i) U8(static_cast<Byte>(value>>(8*i))); }
    void Bytes(const Byte* data,std::size_t length){out_.insert(out_.end(),data,data+length);}
private:
    std::vector<Byte>& out_;
};

class K6PathReader {
public:
    K6PathReader(const Byte* data,std::size_t length):data_(data),length_(length){}
    bool U8(Byte& value){if(pos_>=length_)return false;value=data_[pos_++];return true;}
    bool U16(std::uint16_t& value){value=0;for(unsigned i=0;i<2;++i){Byte b=0;if(!U8(b))return false;value|=static_cast<std::uint16_t>(b)<<(8*i);}return true;}
    bool U32(std::uint32_t& value){value=0;for(unsigned i=0;i<4;++i){Byte b=0;if(!U8(b))return false;value|=static_cast<std::uint32_t>(b)<<(8*i);}return true;}
    bool U64(std::uint64_t& value){value=0;for(unsigned i=0;i<8;++i){Byte b=0;if(!U8(b))return false;value|=static_cast<std::uint64_t>(b)<<(8*i);}return true;}
    bool Bytes(Byte* out,std::size_t length){if(length>length_-pos_)return false;std::memcpy(out,data_+pos_,length);pos_+=length;return true;}
    bool Done()const{return pos_==length_;}
private:
    const Byte* data_=nullptr;std::size_t length_=0,pos_=0;
};

template <typename T>
bool CanonicalObserverList(const std::vector<T>& values) noexcept
{
    if (values.size() > kK6PathEvidenceMaxObservers) return false;
    for (std::size_t i=0;i<values.size();++i)
        if (values[i]==0 || (i && values[i-1]>=values[i])) return false;
    return true;
}

bool CanonicalEvidenceRecord(const K6PathEvidenceRecord& record) noexcept
{
    return NonZero(record.node_pub.data(),record.node_pub.size())
        && CanonicalObserverList(record.access_forward_as)
        && CanonicalObserverList(record.access_reverse_as)
        && CanonicalObserverList(record.access_forward_ixp)
        && CanonicalObserverList(record.access_reverse_ixp)
        && CanonicalObserverList(record.egress_forward_as)
        && CanonicalObserverList(record.egress_reverse_as)
        && CanonicalObserverList(record.egress_forward_ixp)
        && CanonicalObserverList(record.egress_reverse_ixp);
}

template <typename T>
void WriteObserverList(K6PathWriter& writer,const std::vector<T>& values)
{
    writer.U8(static_cast<Byte>(values.size()));
    for (const T value:values) {
        if constexpr (sizeof(T)==4) writer.U32(static_cast<std::uint32_t>(value));
        else writer.U64(static_cast<std::uint64_t>(value));
    }
}

template <typename T>
bool ReadObserverList(K6PathReader& reader,std::vector<T>& values)
{
    Byte count=0;if(!reader.U8(count)||count>kK6PathEvidenceMaxObservers)return false;
    values.clear();values.reserve(count);
    for(Byte i=0;i<count;++i){
        T value=0;
        if constexpr(sizeof(T)==4){std::uint32_t parsed=0;if(!reader.U32(parsed))return false;value=static_cast<T>(parsed);}
        else{std::uint64_t parsed=0;if(!reader.U64(parsed))return false;value=static_cast<T>(parsed);}
        if(value==0||(!values.empty()&&values.back()>=value))return false;
        values.push_back(value);
    }
    return true;
}

bool NonZero(const Byte* value, std::size_t length) noexcept
{
    Byte aggregate = 0;
    for (std::size_t i = 0; i < length; ++i)
        aggregate = static_cast<Byte>(aggregate | value[i]);
    return aggregate != 0;
}

bool Eligible(const K6PathCandidate& c, bool exit_role) noexcept
{
    const std::size_t address_bytes = c.address.family == Kad6Address::Family::IPv4
        ? 4 : c.address.family == Kad6Address::Family::IPv6 ? 16 : 0;
    return c.authenticated && c.endpoint_verified && c.connected
        && c.supports_strict3 && c.supports_shaping && c.has_capacity
        && (!exit_role || c.supports_exit)
        && !c.current_content_peer && c.weight != 0 && c.asn != 0
        && address_bytes != 0
        && NonZero(c.address.addr.data(), address_bytes)
        && NonZero(c.node_pub.data(), c.node_pub.size())
        && NonZero(c.user_hash.data(), c.user_hash.size());
}

bool SameIdentity(const K6PathCandidate& a, const K6PathCandidate& b) noexcept
{
    return Kad6CtEqual(a.node_pub.data(), b.node_pub.data(), a.node_pub.size())
        || Kad6CtEqual(a.user_hash.data(), b.user_hash.data(), a.user_hash.size());
}

bool Diverse(const K6PathCandidate& a, const K6PathCandidate& b) noexcept
{
    const bool same_subnet = a.address.family == b.address.family
        && Kad6AddressInSameSubnet(a.address,b.address,
            a.address.family == Kad6Address::Family::IPv4 ? 20 : 48);
    if (SameIdentity(a, b) || same_subnet || a.asn == b.asn)
        return false;
    // Unknown operator groups are not asserted equal.  Known groups are a
    // hard anti-correlation boundary in addition to /48 and ASN.
    return a.operator_group == 0 || b.operator_group == 0
        || a.operator_group != b.operator_group;
}

template <typename T>
bool Contains(const std::vector<T>& values, T value) noexcept
{
    for (const T& candidate : values)
        if (candidate == value) return true;
    return false;
}

template <typename T>
bool Intersects(const std::vector<T>& a1, const std::vector<T>& a2,
                const std::vector<T>& b1, const std::vector<T>& b2) noexcept
{
    for (const T& value : a1)
        if (Contains(b1, value) || Contains(b2, value)) return true;
    for (const T& value : a2)
        if (Contains(b1, value) || Contains(b2, value)) return true;
    return false;
}

bool CompleteAccessEvidence(const K6PathCandidate& candidate,
                            const K6NetworkPathPolicy& policy) noexcept
{
    return (!policy.require_multi_vantage || candidate.access_multi_vantage)
        && !candidate.access_forward_as.empty()
        && !candidate.access_reverse_as.empty();
}

bool CompleteEgressEvidence(const K6PathCandidate& candidate,
                            const K6NetworkPathPolicy& policy) noexcept
{
    return (!policy.require_multi_vantage || candidate.egress_multi_vantage)
        && !candidate.egress_forward_as.empty()
        && !candidate.egress_reverse_as.empty();
}

template <typename T>
bool SharedConfiguredRisk(const std::vector<T>& configured,
                          const std::vector<T>& a1, const std::vector<T>& a2,
                          const std::vector<T>& b1, const std::vector<T>& b2) noexcept
{
    for (const T& value : configured)
        if ((Contains(a1, value) || Contains(a2, value)) &&
            (Contains(b1, value) || Contains(b2, value))) return true;
    return false;
}

bool ReadRandom64(K6PathRandom random, void* context, std::uint64_t& out) noexcept
{
    Byte bytes[8]{};
    if (!random || !random(context, bytes, sizeof bytes))
        return false;
    out = 0;
    for (unsigned i = 0; i < 8; ++i)
        out |= static_cast<std::uint64_t>(bytes[i]) << (i * 8);
    return true;
}

K6PathStatus PickWeighted(const std::vector<K6PathCandidate>& candidates,
                          const std::vector<std::size_t>& eligible,
                          K6PathRandom random, void* context,
                          std::size_t& selected) noexcept
{
    if (eligible.empty())
        return K6PathStatus::NotDiverse;
    std::uint64_t total = 0;
    for (std::size_t index : eligible) {
        const std::uint64_t weight = candidates[index].weight;
        if (total > std::numeric_limits<std::uint64_t>::max() - weight)
            return K6PathStatus::TooManyCandidates;
        total += weight;
    }
    if (total == 0)
        return K6PathStatus::NotDiverse;

    // Rejection sampling avoids modulo bias while retaining deterministic
    // host-injected test vectors.
    std::uint64_t value = 0;
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max()
        - (std::numeric_limits<std::uint64_t>::max() % total);
    do {
        if (!ReadRandom64(random, context, value))
            return K6PathStatus::RandomFailed;
    } while (value >= limit);
    value %= total;
    for (std::size_t index : eligible) {
        if (value < candidates[index].weight) {
            selected = index;
            return K6PathStatus::Ok;
        }
        value -= candidates[index].weight;
    }
    return K6PathStatus::RandomFailed; // unreachable unless arithmetic drifts
}

} // namespace

Kad6Status EncodeK6PathEvidenceSnapshot(const K6PathEvidenceSnapshot& snapshot,
        std::vector<Byte>& out) noexcept
{
    out.clear();
    if (!snapshot.sequence || !snapshot.generated_at
        || snapshot.valid_until <= snapshot.generated_at
        || snapshot.records.empty()
        || snapshot.records.size() > kK6PathEvidenceMaxRecords
        || !NonZero(snapshot.dataset_hash.data(),snapshot.dataset_hash.size()))
        return Kad6Status::BadValue;
    for(std::size_t i=0;i<snapshot.records.size();++i){
        if(!CanonicalEvidenceRecord(snapshot.records[i])
            || (i && std::memcmp(snapshot.records[i-1].node_pub.data(),
                snapshot.records[i].node_pub.data(),kEd25519PubSize)>=0))
            return Kad6Status::BadValue;
    }
    try {
        K6PathWriter writer(out);
        const Byte magic[4]={'K','6','P','E'};writer.Bytes(magic,sizeof magic);
        writer.U8(1);writer.U8(0);writer.U8(0);writer.U8(0);
        writer.U64(snapshot.sequence);writer.U64(snapshot.generated_at);
        writer.U64(snapshot.valid_until);
        writer.Bytes(snapshot.dataset_hash.data(),snapshot.dataset_hash.size());
        writer.U16(static_cast<std::uint16_t>(snapshot.records.size()));writer.U16(0);
        for(const K6PathEvidenceRecord& record:snapshot.records){
            writer.Bytes(record.node_pub.data(),record.node_pub.size());
            writer.U8(static_cast<Byte>((record.access_multi_vantage?1:0)
                |(record.egress_multi_vantage?2:0)));
            writer.U8(0);writer.U8(0);writer.U8(0);
            WriteObserverList(writer,record.access_forward_as);
            WriteObserverList(writer,record.access_reverse_as);
            WriteObserverList(writer,record.access_forward_ixp);
            WriteObserverList(writer,record.access_reverse_ixp);
            WriteObserverList(writer,record.egress_forward_as);
            WriteObserverList(writer,record.egress_reverse_as);
            WriteObserverList(writer,record.egress_forward_ixp);
            WriteObserverList(writer,record.egress_reverse_ixp);
        }
    } catch (...) { out.clear();return Kad6Status::TooLarge; }
    return Kad6Status::Ok;
}

Kad6Status DecodeK6PathEvidenceSnapshot(const Byte* data,std::size_t length,
        K6PathEvidenceSnapshot& out) noexcept
{
    out=K6PathEvidenceSnapshot{};
    if(!data||length<68)return Kad6Status::Malformed;
    try {
        K6PathReader reader(data,length);Byte magic[4]{},version=0,reserved=0;
        std::uint16_t count=0,reserved16=0;
        if(!reader.Bytes(magic,sizeof magic)||std::memcmp(magic,"K6PE",4)!=0
            ||!reader.U8(version)||version!=1||!reader.U8(reserved)||reserved
            ||!reader.U8(reserved)||reserved||!reader.U8(reserved)||reserved
            ||!reader.U64(out.sequence)||!reader.U64(out.generated_at)
            ||!reader.U64(out.valid_until)
            ||!reader.Bytes(out.dataset_hash.data(),out.dataset_hash.size())
            ||!reader.U16(count)||!reader.U16(reserved16)||reserved16
            ||!out.sequence||!out.generated_at||out.valid_until<=out.generated_at
            ||!NonZero(out.dataset_hash.data(),out.dataset_hash.size())
            ||!count||count>kK6PathEvidenceMaxRecords)
            return Kad6Status::Malformed;
        out.records.reserve(count);
        for(std::uint16_t i=0;i<count;++i){
            K6PathEvidenceRecord record;Byte flags=0;
            if(!reader.Bytes(record.node_pub.data(),record.node_pub.size())
                ||!reader.U8(flags)||(flags&~3u)
                ||!reader.U8(reserved)||reserved||!reader.U8(reserved)||reserved
                ||!reader.U8(reserved)||reserved
                ||!ReadObserverList(reader,record.access_forward_as)
                ||!ReadObserverList(reader,record.access_reverse_as)
                ||!ReadObserverList(reader,record.access_forward_ixp)
                ||!ReadObserverList(reader,record.access_reverse_ixp)
                ||!ReadObserverList(reader,record.egress_forward_as)
                ||!ReadObserverList(reader,record.egress_reverse_as)
                ||!ReadObserverList(reader,record.egress_forward_ixp)
                ||!ReadObserverList(reader,record.egress_reverse_ixp))
                return Kad6Status::Malformed;
            record.access_multi_vantage=(flags&1)!=0;
            record.egress_multi_vantage=(flags&2)!=0;
            if(!CanonicalEvidenceRecord(record)
                ||(!out.records.empty()&&std::memcmp(out.records.back().node_pub.data(),
                    record.node_pub.data(),kEd25519PubSize)>=0))
                return Kad6Status::Malformed;
            out.records.push_back(std::move(record));
        }
        if(!reader.Done())return Kad6Status::Malformed;
    } catch (...) {out=K6PathEvidenceSnapshot{};return Kad6Status::TooLarge;}
    return Kad6Status::Ok;
}

bool ApplyK6PathEvidence(const K6PathEvidenceSnapshot& snapshot,
        const Byte node_pub[kEd25519PubSize],std::uint64_t now_seconds,
        K6PathCandidate& candidate) noexcept
{
    if(!node_pub||!snapshot.sequence||now_seconds<snapshot.generated_at
        ||now_seconds>=snapshot.valid_until)return false;
    for(const K6PathEvidenceRecord& record:snapshot.records){
        const int order=std::memcmp(record.node_pub.data(),node_pub,kEd25519PubSize);
        if(order>0)break;
        if(order!=0)continue;
        candidate.access_forward_as=record.access_forward_as;
        candidate.access_reverse_as=record.access_reverse_as;
        candidate.access_forward_ixp=record.access_forward_ixp;
        candidate.access_reverse_ixp=record.access_reverse_ixp;
        candidate.egress_forward_as=record.egress_forward_as;
        candidate.egress_reverse_as=record.egress_reverse_as;
        candidate.egress_forward_ixp=record.egress_forward_ixp;
        candidate.egress_reverse_ixp=record.egress_reverse_ixp;
        candidate.access_multi_vantage=record.access_multi_vantage;
        candidate.egress_multi_vantage=record.egress_multi_vantage;
        return true;
    }
    return false;
}

Kad6Status EncodeK6PathTraceFile(const std::vector<K6PathTraceSample>& samples,
        std::vector<Byte>& out) noexcept
{
    out.clear();if(samples.empty()||samples.size()>kK6PathTraceMaxSamples)
        return Kad6Status::BadValue;
    try{
        K6PathWriter writer(out);const Byte magic[4]={'K','6','T','R'};
        writer.Bytes(magic,sizeof magic);writer.U8(1);writer.U8(0);writer.U8(0);writer.U8(0);
        writer.U32(static_cast<std::uint32_t>(samples.size()));
        for(const K6PathTraceSample& sample:samples){
            if((sample.baseline_overlap&&sample.baseline_unknown)
                ||(sample.selected_overlap&&sample.selected_unknown)){
                out.clear();return Kad6Status::BadValue;
            }
            writer.U8(static_cast<Byte>((sample.baseline_overlap?1:0)
                |(sample.baseline_unknown?2:0)|(sample.selected_overlap?4:0)
                |(sample.selected_unknown?8:0)));
        }
    }catch(...){out.clear();return Kad6Status::TooLarge;}
    return Kad6Status::Ok;
}

Kad6Status DecodeK6PathTraceFile(const Byte* data,std::size_t length,
        std::vector<K6PathTraceSample>& out) noexcept
{
    out.clear();if(!data||length<13)return Kad6Status::Malformed;
    try{
        K6PathReader reader(data,length);Byte magic[4]{},version=0,reserved=0;
        std::uint32_t count=0;
        if(!reader.Bytes(magic,sizeof magic)||std::memcmp(magic,"K6TR",4)!=0
            ||!reader.U8(version)||version!=1||!reader.U8(reserved)||reserved
            ||!reader.U8(reserved)||reserved||!reader.U8(reserved)||reserved
            ||!reader.U32(count)||!count||count>kK6PathTraceMaxSamples)
            return Kad6Status::Malformed;
        out.reserve(count);
        for(std::uint32_t i=0;i<count;++i){Byte flags=0;if(!reader.U8(flags)||(flags&~15u)
                ||((flags&3u)==3u)||((flags&12u)==12u))return Kad6Status::Malformed;
            K6PathTraceSample sample;sample.baseline_overlap=(flags&1)!=0;
            sample.baseline_unknown=(flags&2)!=0;sample.selected_overlap=(flags&4)!=0;
            sample.selected_unknown=(flags&8)!=0;out.push_back(sample);}
        if(!reader.Done())return Kad6Status::Malformed;
    }catch(...){out.clear();return Kad6Status::TooLarge;}
    return Kad6Status::Ok;
}

K6PathStatus SelectInternal(const std::vector<K6PathCandidate>& candidates,
                            const Byte* pinned_guard,
                            const K6NetworkPathPolicy* network_policy,
                            K6PathRandom random,
                            void* random_context,
                            K6StrictPath& out) noexcept
{
    out = K6StrictPath{};
    if (!random)
        return K6PathStatus::NullArgument;
    if (candidates.size() > kK6PathMaxCandidates)
        return K6PathStatus::TooManyCandidates;

    std::vector<std::size_t> guards;
    for (std::size_t i = 0; i < candidates.size(); ++i) {
        if (!Eligible(candidates[i], false))
            continue;
        if (!pinned_guard
            || Kad6CtEqual(candidates[i].node_pub.data(), pinned_guard,
                           candidates[i].node_pub.size()))
            guards.push_back(i);
    }
    if (guards.empty())
        return pinned_guard ? K6PathStatus::PinnedGuardUnavailable
                            : K6PathStatus::NoEligibleGuard;
    K6PathStatus status = PickWeighted(candidates, guards, random,
                                       random_context, out.index[0]);
    if (status != K6PathStatus::Ok)
        return status;

    std::vector<std::size_t> middles;
    for (std::size_t i = 0; i < candidates.size(); ++i)
        if (Eligible(candidates[i], false)
            && Diverse(candidates[out.index[0]], candidates[i]))
            middles.push_back(i);
    status = PickWeighted(candidates, middles, random,
                          random_context, out.index[1]);
    if (status != K6PathStatus::Ok)
        return status == K6PathStatus::RandomFailed ? status
                                                    : K6PathStatus::NotDiverse;

    std::vector<std::size_t> exits;
    bool missingEvidence = false;
    bool observerOverlap = false;
    for (std::size_t i = 0; i < candidates.size(); ++i)
        if (Eligible(candidates[i], true)
            && Diverse(candidates[out.index[0]], candidates[i])
            && Diverse(candidates[out.index[1]], candidates[i])) {
            if (network_policy) {
                const K6PathStatus diversity = CheckK6NetworkPathDiversity(
                    candidates[out.index[0]], candidates[i], *network_policy);
                if (diversity != K6PathStatus::Ok) {
                    missingEvidence = missingEvidence ||
                        diversity == K6PathStatus::MissingPathEvidence;
                    observerOverlap = observerOverlap ||
                        diversity == K6PathStatus::NetworkObserverOverlap;
                    continue;
                }
            }
            exits.push_back(i);
        }
    if (exits.empty() && network_policy && network_policy->fail_closed) {
        if (observerOverlap) return K6PathStatus::NetworkObserverOverlap;
        if (missingEvidence) return K6PathStatus::MissingPathEvidence;
    }
    status = PickWeighted(candidates, exits, random,
                          random_context, out.index[2]);
    if (status != K6PathStatus::Ok)
        return status == K6PathStatus::RandomFailed ? status
                                                    : K6PathStatus::NotDiverse;
    return K6PathStatus::Ok;
}

K6PathStatus SelectK6StrictPath(const std::vector<K6PathCandidate>& candidates,
                                const Byte* pinned_guard,
                                K6PathRandom random,
                                void* random_context,
                                K6StrictPath& out) noexcept
{
    return SelectInternal(candidates, pinned_guard, nullptr, random,
                          random_context, out);
}

K6PathStatus SelectK6StrictPathV2(const std::vector<K6PathCandidate>& candidates,
                                  const Byte* pinned_guard,
                                  const K6NetworkPathPolicy& policy,
                                  K6PathRandom random,
                                  void* random_context,
                                  K6StrictPath& out) noexcept
{
    return SelectInternal(candidates, pinned_guard, &policy, random,
                          random_context, out);
}

K6PathStatus CheckK6NetworkPathDiversity(const K6PathCandidate& guard,
                                         const K6PathCandidate& exit,
                                         const K6NetworkPathPolicy& policy) noexcept
{
    if (!CompleteAccessEvidence(guard, policy) ||
        !CompleteEgressEvidence(exit, policy))
        return K6PathStatus::MissingPathEvidence;
    if (Intersects(guard.access_forward_as, guard.access_reverse_as,
                   exit.egress_forward_as, exit.egress_reverse_as) ||
        Intersects(guard.access_forward_ixp, guard.access_reverse_ixp,
                   exit.egress_forward_ixp, exit.egress_reverse_ixp) ||
        SharedConfiguredRisk(policy.high_risk_transit_as,
                   guard.access_forward_as, guard.access_reverse_as,
                   exit.egress_forward_as, exit.egress_reverse_as) ||
        SharedConfiguredRisk(policy.high_risk_ixp,
                   guard.access_forward_ixp, guard.access_reverse_ixp,
                   exit.egress_forward_ixp, exit.egress_reverse_ixp))
        return K6PathStatus::NetworkObserverOverlap;
    return K6PathStatus::Ok;
}

K6PathTraceReport EvaluateK6PathTraces(
        const std::vector<K6PathTraceSample>& samples) noexcept
{
    K6PathTraceReport report;
    report.samples = samples.size();
    for (const K6PathTraceSample& sample : samples) {
        if (sample.baseline_overlap) ++report.baseline_overlaps;
        if (sample.selected_overlap) ++report.selected_overlaps;
        if (sample.baseline_unknown) ++report.baseline_unknown;
        if (sample.selected_unknown) ++report.selected_unknown;
    }
    if (report.samples) {
        report.baseline_probability = static_cast<double>(report.baseline_overlaps) /
            static_cast<double>(report.samples);
        report.selected_probability = static_cast<double>(report.selected_overlaps) /
            static_cast<double>(report.samples);
        report.baseline_upper_probability = static_cast<double>(
            report.baseline_overlaps + report.baseline_unknown) /
            static_cast<double>(report.samples);
        report.selected_upper_probability = static_cast<double>(
            report.selected_overlaps + report.selected_unknown) /
            static_cast<double>(report.samples);
    }
    return report;
}

const char* K6PathStatusName(K6PathStatus status) noexcept
{
    switch (status) {
        case K6PathStatus::Ok:                     return "Ok";
        case K6PathStatus::NullArgument:           return "NullArgument";
        case K6PathStatus::TooManyCandidates:      return "TooManyCandidates";
        case K6PathStatus::NoEligibleGuard:        return "NoEligibleGuard";
        case K6PathStatus::PinnedGuardUnavailable: return "PinnedGuardUnavailable";
        case K6PathStatus::NotDiverse:             return "NotDiverse";
        case K6PathStatus::MissingPathEvidence:    return "MissingPathEvidence";
        case K6PathStatus::NetworkObserverOverlap: return "NetworkObserverOverlap";
        case K6PathStatus::RandomFailed:            return "RandomFailed";
    }
    return "?";
}

} // namespace kad6
