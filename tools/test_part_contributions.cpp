#include "reach/part_contributions.h"
#include "reach/accepted_part_ranges.h"
#include <memory>
#include <cstdio>
#include <cstdlib>
static unsigned checks=0;
static void Check(bool condition) { ++checks; if(!condition) std::exit(1); }
int main() {
    using namespace reach;
    std::array<std::uint32_t,3> pieces{};
    Check(ForEachAcceptedPart(8,21,14,10,[&](std::uint32_t part,std::uint32_t bytes) { pieces[part]=bytes; return true; }));
    Check(pieces[0]==2 && pieces[1]==10 && pieces[2]==2);
    unsigned callbacks=0;
    auto count=[&](std::uint32_t,std::uint32_t) { ++callbacks; return true; };
    Check(!ForEachAcceptedPart(8,21,13,10,count) && callbacks==0);
    Check(!ForEachAcceptedPart(8,7,1,10,count) && callbacks==0);
    Check(!ForEachAcceptedPart(0,0,1,0,count) && callbacks==0);
    Check(!ForEachAcceptedPart(0,64,65,1,count) && callbacks==0);
    Check(ForEachAcceptedPart(9,9,1,10,count) && callbacks==1);
    const auto largest=(std::numeric_limits<std::uint64_t>::max)();
    Check(ForEachAcceptedPart(largest,largest,1,largest,count) && callbacks==2);
    auto ledger=std::make_unique<DirectPartContributions>();
    DirectFileKey file; file.lifetime=1; file.hash[0]=7;
    DirectPartContributor source{1,{0,1},3,1,7};
    Check(ledger->Size()==0 && !ledger->Contains(file,0,source));
    Check(!ledger->Record({},0,source,1));
    Check(!ledger->Record(file,0,source,0));
    Check(ledger->Record(file,0,source,100));
    Check(ledger->Size()==1 && ledger->Contains(file,0,source));
    auto snapshot=ledger->Snapshot(file,0,9);
    Check(snapshot.size()==1 && snapshot[0].bytes==100);
    Check(!ledger->TakeVerified(snapshot[0],8,PartVerification::Verified));
    Check(!ledger->TakeVerified(snapshot[0],9,PartVerification::Unavailable));
    Check(!ledger->TakeVerified(snapshot[0],9,PartVerification::Corrupt));
    Check(ledger->Record(file,0,source,50));
    Check(!ledger->TakeVerified(snapshot[0],9,PartVerification::Verified));
    auto current=ledger->Snapshot(file,0,10);
    Check(current.size()==1 && current[0].bytes==150 && snapshot[0].bytes==100);
    Check(ledger->TakeVerified(current[0],10,PartVerification::Verified).has_value());
    Check(!ledger->TakeVerified(current[0],10,PartVerification::Verified));
    auto epoch=source; ++epoch.epoch;
    Check(ledger->Record(file,0,source,1));
    const auto beforeNewContributor=ledger->Snapshot(file,0,11);
    Check(ledger->Record(file,0,epoch,2));
    Check(!ledger->TakeVerified(beforeNewContributor[0],11,PartVerification::Verified));
    Check(ledger->Snapshot(file,0,11).size()==2);
    auto newFile=file; ++newFile.lifetime;
    Check(ledger->Snapshot(newFile,0,11).empty());
    ledger->DiscardFile(file);
    Check(ledger->Snapshot(file,0,11).empty());
    Check(!ledger->TakeVerified(current[0],10,PartVerification::Verified));
    for(std::size_t i=0;i<DirectPartContributions::Capacity;++i)
        Check(ledger->Record(file,static_cast<std::uint32_t>(i),source,1));
    Check(!ledger->Record(file,99999,source,1));
    Check(ledger->Size()==DirectPartContributions::Capacity);
    Check(ledger->Snapshot(file,0,12).size()==1);
    const auto retired=ledger->Snapshot(file,0,12);
    auto replacement=source; ++replacement.handle.generation;
    Check(ledger->DiscardSource(replacement)==0);
    Check(ledger->DiscardSource(source)==DirectPartContributions::Capacity);
    Check(ledger->Size()==0 && !ledger->Contains(file,0,source));
    Check(!ledger->TakeVerified(retired[0],12,PartVerification::Verified));
    Check(ledger->DiscardSource(source)==0);
    Check(ledger->Record(file,0,source,1));
    Check(ledger->Record(file,0,replacement,2));
    const auto both=ledger->Snapshot(file,0,13);
    Check(both.size()==2);
    Check(ledger->DiscardSource(source)==1);
    const auto survivor=ledger->Snapshot(file,0,13);
    Check(survivor.size()==1 && survivor[0].source.handle.generation==replacement.handle.generation);
    Check(ledger->TakeVerified(survivor[0],13,PartVerification::Verified).has_value());
    Check(ledger->Record(file,0,source,10));
    Check(ledger->Record(file,1,source,20));
    const auto oldPart=ledger->Snapshot(file,0,14);
    const auto otherPart=ledger->Snapshot(file,1,14);
    ledger->InvalidateRange(file,0,0);
    Check(!ledger->TakeVerified(oldPart[0],14,PartVerification::Verified));
    Check(ledger->TakeVerified(otherPart[0],14,PartVerification::Verified).has_value());
    Check(ledger->Snapshot(file,0,15)[0].bytes==10);
    ledger->InvalidateRange(file,0,0,true);
    Check(ledger->Snapshot(file,0,15).empty());
    Check(ledger->Record(file,0,source,1));
    Check(ledger->Record(file,0,replacement,2));
    Check(ledger->DiscardHandle(source.handle)==1);
    Check(ledger->Snapshot(file,0,16).size()==1);
    const auto beforeClear=ledger->Snapshot(file,0,16);
    ledger->Clear();
    Check(ledger->Size()==0);
    Check(ledger->Record(file,0,replacement,2));
    Check(!ledger->TakeVerified(beforeClear[0],16,PartVerification::Verified));
    std::printf("part contributions: %u checks PASS (owned provenance, not a hash computation)\n",checks);
}
