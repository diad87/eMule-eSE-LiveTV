#include "../srchybrid/EseKad6PublicationDescriptor.h"
#include "../srchybrid/EseWitnessDescriptors.h"
#include "../srchybrid/LiveCrypto.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
using namespace ese;
static unsigned checks=0;
static void Check(bool value) { ++checks; if(!value) { std::printf("large index FAIL check%u\n",checks); std::exit(1); } }
struct Signer final : control::Signer {
    std::array<std::uint8_t,32> node{},secret{};
    ~Signer() { volatile std::uint8_t* bytes=secret.data(); for(unsigned i=0;i<secret.size();++i) bytes[i]=0; }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& signature) noexcept override {
        return eSELive::SignMessage(secret.data(),node.data(),p,n,signature.data());
    }
};
int main() {
    using Store=discovery::WitnessDescriptors<10000,8*1024*1024-512*1024>;
    auto store=std::make_unique<Store>();
    std::array<discovery::OwnedPublicationCandidate,2> routes{};
    std::array<std::uint8_t,16> user{},kad{},hash{};
    std::array<std::uint8_t,discovery::DescriptorMax> descriptor{};
    std::array<std::uint8_t,173> bytes{}; std::size_t length=0;
    unsigned total=0;
    for(unsigned publisher=0;publisher<1250;++publisher) {
        Signer signer; Check(eSELive::GenerateBroadcasterKeypair(signer.node.data(),signer.secret.data()));
        udp::Endpoint endpoint; endpoint.address[0]=52;
        endpoint.address[1]=static_cast<std::uint8_t>(publisher>>8);
        endpoint.address[2]=static_cast<std::uint8_t>(publisher); endpoint.address[3]=1; endpoint.port=4665;
        for(unsigned ownFile=0;ownFile<8;++ownFile) {
            const auto index=++total; hash={};
            for(unsigned i=0;i<4;++i) hash[i]=static_cast<std::uint8_t>(index>>(8*i));
            hash[15]=1;
            Check(discovery::BuildOwnedPublication(hash,123,1,1,signer.node,user,kad,routes,0,120,signer,
                descriptor,length,bytes,2000));
            discovery::DirectSource source;
            Check(control::VerifyDirectSource(signer.node,bytes.data(),bytes.size(),2000,source));
            Check(store->PutVerified(hash,descriptor.data(),length,source.digest,endpoint,0,100)==discovery::StoreResult::Provisional);
            Check(store->DirectSourceVerified(bytes.data(),bytes.size(),2000,100)==discovery::SourceStoreResult::Stored);
        }
    }
    Check(total==10000 && store->ChargedBytes()<=8*1024*1024-512*1024);
    discovery::FoundSources found;
    Check(store->Find(hash,123,4,100,found) && found.count==1 && found.remainingTtl[0]==120);
    const auto started=std::chrono::steady_clock::now(); store.reset();
    const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    Check(elapsed<5000);
    std::printf("large Kad6 index: %u checks PASS 10000 real signed metadata pairs charged<=8MiB destruction=%lldms; component shutdown not physical peers or file ownership proof\n",
        checks,static_cast<long long>(elapsed));
}
