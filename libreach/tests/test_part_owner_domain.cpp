// SPDX-License-Identifier: MIT
#include "reach/part_contributions.h"
#include "reach/accepted_part_ranges.h"
#include <cstdio>
int main() {
    reach::DirectPartContributions records;
    reach::DirectFileKey file; file.lifetime=1; file.hash[0]=1;
    reach::DirectPartContributor quic{7,{0,1},3,1,1};
    auto legacy=quic; legacy.kind=reach::DirectPartOwnerKind::Legacy;
    auto invalid=quic; invalid.kind=static_cast<reach::DirectPartOwnerKind>(255);
    if(records.Record(file,0,invalid,1) || !records.Record(file,0,quic,10) ||
        !records.Record(file,0,legacy,20) || records.Size()!=2) return 1;
    const auto receipts=records.Snapshot(file,0,1);
    if(receipts.size()!=2 || receipts[0].bytes!=10 || receipts[1].bytes!=20 ||
        receipts[0].source.kind!=reach::DirectPartOwnerKind::Quic ||
        receipts[1].source.kind!=reach::DirectPartOwnerKind::Legacy) return 2;
    if(records.DiscardSource(quic)!=1 || records.Contains(file,0,quic) ||
        !records.Contains(file,0,legacy) || records.DiscardSource(quic)!=0) return 3;
    if(records.DiscardSource(legacy)!=1 || records.Size()!=0) return 4;
    // Product provenance splitter must preserve offsets beyond the 32-bit
    // wire dialect, independently of transport and without allocating F3.
    constexpr std::uint64_t partSize=9728000;
    constexpr std::uint64_t start=4294967294ULL,end=4294967296ULL;
    unsigned calls=0;
    if(!reach::ForEachAcceptedPart(start,end,3,partSize,[&](std::uint32_t part,std::uint32_t bytes) {
        ++calls;
        return part==441 && bytes==3 && records.Record(file,part,quic,bytes);
    }) || calls!=1 || records.Contains(file,0,quic)) return 5;
    const auto large=records.Snapshot(file,441,1);
    if(large.size()!=1 || large[0].bytes!=3 ||
        !records.TakeVerified(large[0],1,reach::PartVerification::Verified) || records.Size()!=0) return 6;
    // Cross a real part boundary above 4GiB, keeping byte attribution exact.
    constexpr auto boundary=partSize*442;
    calls=0;
    if(!reach::ForEachAcceptedPart(boundary-1,boundary+1,3,partSize,[&](std::uint32_t part,std::uint32_t bytes) {
        ++calls;
        return part==(calls==1 ? 441U : 442U) && bytes==(calls==1 ? 1U : 2U) &&
            records.Record(file,part,quic,bytes);
    }) || calls!=2 || records.Size()!=2) return 7;
    calls=0;
    if(reach::ForEachAcceptedPart(start,end,2,partSize,[&](std::uint32_t,std::uint32_t) { ++calls; return true; }) || calls)
        return 8; // invalid aggregate must cause no partial attribution
    records.Clear();
    // A handover changes delivery authority, not the bytes already attributed
    // to a part. Retiring QUIC must leave the new TCP contributor and other
    // pending parts intact. Verify the real ledger without any network fixture.
    auto tcp=quic; tcp.kind=reach::DirectPartOwnerKind::Legacy; ++tcp.epoch;
    if(!records.Record(file,0,quic,100) || !records.Record(file,0,tcp,200) ||
        !records.Record(file,1,tcp,17)) return 9;
    const auto mixed=records.Snapshot(file,0,2);
    const auto partial=records.Snapshot(file,1,3);
    if(mixed.size()!=2 || partial.size()!=1) return 10;
    auto stolen=mixed[0]; stolen.source=tcp;
    if(records.TakeVerified(stolen,2,reach::PartVerification::Verified)) return 11;
    if(records.DiscardSource(quic)!=1 || records.Size()!=2 ||
        records.TakeVerified(mixed[0],2,reach::PartVerification::Verified)) return 12;
    const auto accepted=records.TakeVerified(mixed[1],2,reach::PartVerification::Verified);
    if(!accepted || accepted->source.kind!=reach::DirectPartOwnerKind::Legacy ||
        accepted->source.epoch!=tcp.epoch || accepted->bytes!=200) return 13;
    // An accepted value-owned proof survives retirement. Pending unverified
    // provenance is retired separately and cannot later credit a reused epoch.
    if(records.DiscardSource(tcp)!=1 || records.Size()!=0 || accepted->bytes!=200 ||
        accepted->hash_generation!=2 || records.TakeVerified(partial[0],3,reach::PartVerification::Verified)) return 14;
    ++tcp.epoch;
    if(!records.Record(file,1,tcp,17) ||
        records.TakeVerified(partial[0],3,reach::PartVerification::Verified)) return 15;
    const auto replacement=records.Snapshot(file,1,4);
    if(replacement.size()!=1 || replacement[0].source.epoch!=tcp.epoch ||
        !records.TakeVerified(replacement[0],4,reach::PartVerification::Verified)) return 16;
    std::puts("part provenance 64bit: PASS (4GiB crossing, part split, verified receipt and invalid-range atomicity)");
    std::puts("part owner domains: PASS (colliding scalar identities separated; invalid domain rejected)");
    std::puts("part recovery ownership: PASS (retired epoch fenced, other contributors retained, verified proof value preserved)");
    return 0;
}
