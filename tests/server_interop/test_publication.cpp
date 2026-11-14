#include "PublicationStore.h"
#include "hex_fixture.h"

#include <algorithm>
#include <cstring>
#include <iostream>

namespace {
using namespace ese::server;
using server_test::Check;
using Bytes=std::vector<std::uint8_t>;

class DigestOracle final : public AuthCrypto {
public:
    Bytes expected;
    Bytes32 digest{};
    bool Hash(ByteView bytes,Bytes32& output) noexcept override
    {
        if(bytes.size!=expected.size() || !std::equal(expected.begin(),expected.end(),bytes.data))
            return false;
        output=digest;
        return true;
    }
    bool Export(const Bytes32&,Bytes32&) noexcept override { return false; }
    bool Sign(const AuthTranscript&,Signature&) noexcept override { return false; }
    bool Verify(const Bytes32&,const AuthTranscript&,const Signature&) noexcept override { return false; }
};

Bytes Record(std::uint8_t hash,const char* name,std::uint8_t kind)
{
    const auto length=std::strlen(name);
    Bytes record(26,0);
    record[0]=hash;
    record[23]=1;
    record[25]=static_cast<std::uint8_t>(length);
    const auto* bytes=reinterpret_cast<const std::uint8_t*>(name);
    record.insert(record.end(),bytes,bytes+length);
    record.push_back(kind);
    return record;
}

Bytes Chunk(std::uint8_t revision,std::uint8_t index,std::uint8_t records,Bytes canonical)
{
    Bytes payload(14,0);
    payload[7]=revision;
    payload[11]=index;
    payload[13]=records;
    payload.insert(payload.end(),canonical.begin(),canonical.end());
    return payload;
}

ByteView View(const Bytes& bytes)
{
    return {bytes.data(),bytes.size()};
}

void Test()
{
    const auto one=Record(0x11,"alpha",1);
    const auto two=Record(0x22,"beta",2);
    const auto first=Chunk(1,0,1,one),second=Chunk(1,1,1,two);
    DigestOracle hash;
    hash.expected=one;
    hash.expected.insert(hash.expected.end(),two.begin(),two.end());
    hash.digest.fill(0x44);
    Bytes32 empty{};
    empty.fill(0x99);
    PublishState initial{0,0,empty}, desired{1,2,hash.digest}, decoded;
    PublicationStore store(empty);
    auto initialBytes=EncodePublishState(initial);
    Check(DecodePublishState({initialBytes.data(),initialBytes.size()},decoded) && decoded.digest==empty,
          "initial state exact round trip");
    Check(store.Begin(desired,1)==0 && store.Chunk(View(first),2)==0 && store.Chunk(View(second),3)==0,
          "ordered consecutive chunks");
    Check(store.State().revision==0 && store.State().digest==empty,"staging is invisible");
    Check(store.Commit(1,hash.digest,hash,4)==0 && store.State().revision==1 && store.State().records==2,
          "validated digest commits exact concatenated records");
    Check(store.Begin(desired,5)==0 && store.Commit(1,hash.digest,hash,6)==0,"known revision idempotent");

    desired.revision=2;
    auto later=Chunk(2,0,1,one);
    Check(store.Begin(desired,10)==0 && store.Chunk(View(later),11)==0 && store.Chunk(View(later),30010)==0,
          "exact duplicate before deadline");
    Check(store.Chunk(View(Chunk(2,1,1,two)),30011)==kEseWireServerWrongState,
          "duplicate does not renew staging timeout");
    Check(store.State().revision==1,"timeout preserves visible state");
    Check(store.Begin(desired,30012)==0 && store.Chunk(View(later),30013)==0 &&
        store.Chunk(View(Chunk(2,0,1,two)),30014)==kEseWireServerConflict &&
        store.Commit(2,hash.digest,hash,30015)==kEseWireServerWrongState,
        "conflicting chunk destroys staging only");
    Check(store.Begin(desired,30016)==0 && store.Chunk(View(Chunk(2,0,1,two)),30017)==0 &&
        store.Chunk(View(Chunk(2,1,1,one)),30018)==kEseWireServerConflict,
        "strict key order across chunk boundaries");
    Check(store.State().revision==1,"conflicts preserve previously committed state");

    PublishChunk parsed;
    for(size_t length=0;length<first.size();++length)
        Check(!DecodePublishChunk({first.data(),length},parsed),"every truncated chunk is invalid");
    Check(DecodePublishChunk(View(first),parsed),"exact valid chunk");
    Check(!DecodePublishChunk(View(Chunk(1,0,1,Record(0x22,"../beta",2))),parsed),"reject path segments");
    Check(!DecodePublishChunk(View(Chunk(1,0,1,Record(0x22,"bad\xc0\x80",2))),parsed),"reject overlong UTF-8");
    Check(!DecodePublishChunk(View(Chunk(1,0,1,Record(0x22,"beta",9))),parsed),"reject reserved MIME kind");
}
}

int main()
{
    try {
        Test();
        std::cout<<"Atomic publication codec, ordering, idempotency, rollback and expiry PASS\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"Publication test failed: "<<error.what()<<'\n';
        return 1;
    }
}
