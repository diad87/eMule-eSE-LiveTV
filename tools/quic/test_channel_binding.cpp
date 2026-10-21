#include "../../srchybrid/EseChannelBinding.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
using namespace ese::binding;
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) { std::printf("FAIL %u\n",checks); std::exit(1); } }
// Test double only: checks transcript/role/exporter plumbing, not cryptography.
struct FakeCrypto final : Crypto {
    std::uint8_t channel=9; bool fail=false;
    bool Hash(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,32>& out) noexcept override {
        if(fail) return false; out.fill(0);
        for(std::size_t i=0;i<n;++i) out[i%32]=static_cast<std::uint8_t>((out[i%32]*33)^p[i]);
        return true;
    }
    bool Export(const std::array<std::uint8_t,32>& context,std::array<std::uint8_t,32>& out) noexcept override {
        out=context; for(auto& b:out) b^=channel; return !fail;
    }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        std::array<std::uint8_t,32> digest{}; if(!Hash(p,n,digest)) return false;
        for(std::size_t i=0;i<64;++i) out[i]=digest[i%32]; return true;
    }
    bool Verify(const std::array<std::uint8_t,32>&,const std::uint8_t* p,std::size_t n,
        const std::uint8_t* sig) noexcept override {
        std::array<std::uint8_t,64> expected{}; return Sign(p,n,expected) && std::memcmp(sig,expected.data(),64)==0;
    }
};
static void SessionTests() {
    Hello a,b; a.node.fill(1); b.node.fill(2); a.attempt.fill(3); b.attempt=a.attempt;
    a.nonce.fill(4); b.nonce.fill(5); a.caps=7; b.caps=1; b.role=1;
    std::array<std::uint8_t,HelloSize> aw{},bw{};
    Check(EncodeHello(a,aw) && EncodeHello(b,bw));
    FakeCrypto crypto;
    Session client(a,b.node,&b.node,true,true,100),server(b,a.node,nullptr,true,true,100);
    Check(!client.Ready() && !client.BoundPeer() && client.SelectedCaps()==0);
    Check(client.LocalHello(aw) && server.LocalHello(bw));
    Check(client.RemoteHello(bw.data(),bw.size()) && server.RemoteHello(aw.data(),aw.size()));
    std::array<std::uint8_t,AuthSize> ca{},sa{};
    Check(client.LocalAuth(crypto,ca) && server.LocalAuth(crypto,sa));
    Check(client.RemoteAuth(crypto,sa.data(),sa.size())); Check(!client.Ready());
    Check(client.AuthSent() && client.Ready() && client.SelectedCaps()==1);
    Check(server.AuthSent() && server.RemoteAuth(crypto,ca.data(),ca.size()) && server.Ready());
    Check(client.BoundPeer()->node==b.node);
    Check(!client.RemoteHello(bw.data(),bw.size()) && !client.Ready());
    Session changed(a,b.node,&a.node,true,true,100);
    Check(!changed.RemoteHello(bw.data(),bw.size()) && changed.Error()==Failure::PinChanged);
    Session ephemeral(a,b.node,nullptr,false,true,100); Check(ephemeral.Error()==Failure::InvalidConfig);
    Session early(a,b.node,nullptr,true,false,100); Check(early.Error()==Failure::InvalidConfig);
    Session timeout(a,b.node,nullptr,true,true,100); timeout.Tick(5099); Check(timeout.Error()==Failure::None);
    timeout.Tick(5100); Check(timeout.Error()==Failure::AuthTimeout);
    Session outOfOrder(a,b.node,nullptr,true,true,0);
    Check(!outOfOrder.LocalAuth(crypto,ca) && outOfOrder.Error()==Failure::WrongState);
    auto mutated=bw; mutated[50]^=1;
    Session attempt(a,b.node,nullptr,true,true,0);
    Check(!attempt.RemoteHello(mutated.data(),mutated.size()) && attempt.Error()==Failure::IdentityMismatch);
    Session replay(a,b.node,nullptr,true,true,0);
    Check(replay.LocalHello(aw) && replay.RemoteHello(bw.data(),bw.size()));
    crypto.channel=10;
    Check(!replay.RemoteAuth(crypto,sa.data(),sa.size()) && replay.Error()==Failure::IdentityMismatch);
    crypto.channel=9;
    Session failure(a,b.node,nullptr,true,true,0);
    Check(failure.LocalHello(aw) && failure.RemoteHello(bw.data(),bw.size())); crypto.fail=true;
    Check(!failure.LocalAuth(crypto,ca) && failure.Error()==Failure::CryptoFailed);
}
static void ExchangeTests() {
    struct Sink final : ControlSink {
        unsigned calls=0;
        bool Frame(std::uint8_t type,const std::uint8_t*,std::size_t length) noexcept override {
            ++calls; return type==6 && length==0;
        }
    };
    Hello a,b; a.node.fill(1); b.node.fill(2); a.attempt.fill(3); b.attempt=a.attempt;
    a.nonce.fill(4); b.nonce.fill(5); a.caps=b.caps=1; b.role=1;
    FakeCrypto crypto;
    for(std::size_t split=0;split<=HelloSize+5;++split) {
        ControlExchange client(a,b.node,&b.node,true,true,0),server(b,a.node,&a.node,true,true,0);
        const auto ca=client.Pending(),sa=server.Pending();
        Check(ca.size==115 && sa.size==115 && !client.Ready());
        Check(client.SubmittedThrough(115) && server.SubmittedThrough(115));
        Check(client.Receive(crypto,sa.data,split));
        Check(client.Receive(crypto,sa.data+split,sa.size-split));
        Check(server.Receive(crypto,ca.data,ca.size));
        const auto auth=client.Pending(),reply=server.Pending();
        Check(auth.size==70 && reply.size==70 && auth.data==ca.data+115);
        Check(client.SubmittedThrough(185));
        Check(server.Receive(crypto,auth.data,auth.size) && !server.Ready());
        Check(server.SubmittedThrough(185) && server.Ready());
        Check(client.Receive(crypto,reply.data,reply.size) && client.Ready());
        Check(client.Pending().size==0 && client.SelectedCaps()==1 && client.BoundPeer()->node==b.node);
        Check(client.SubmittedThrough(185)); // idempotent cumulative submission
        Sink sink; const std::uint8_t ping[]={0,0,0,1,6};
        Check(client.Receive(crypto,ping,sizeof(ping),&sink) && sink.calls==1);
        Check(!client.QueueClose(0) && !client.QueueClose(22) && !client.QueueClose(65535));
        Check(client.QueueClose(16) && client.QueueClose(16) && !client.QueueClose(15));
        const auto close=client.Pending();
        const std::uint8_t golden[]={0,0,0,3,3,0,16};
        Check(close.data==ca.data+185 && close.size==sizeof(golden));
        Check(std::memcmp(close.data,golden,sizeof(golden))==0);
        Check(client.SubmittedThrough(188) && client.Ready());
        Check(client.Pending().data==close.data+3 && client.Pending().size==4);
        Check(std::memcmp(close.data,golden,sizeof(golden))==0);
        Check(client.SubmittedThrough(192) && client.Ready() && client.Pending().size==0);
        Check(client.QueueClose(16) && client.Pending().size==0);
        Check(std::memcmp(close.data,golden,sizeof(golden))==0);
        Check(!client.SubmittedThrough(184) && !client.Ready());
    }
    ControlExchange early(a,b.node,nullptr,true,true,0);
    Check(!early.QueueClose(16) && early.Error()==Failure::None && early.Pending().size==115);
    const std::uint8_t ping[]={0,0,0,1,6};
    Check(!early.Receive(crypto,ping,sizeof(ping)) && early.Error()==Failure::WrongState);
    ControlExchange badOffset(a,b.node,nullptr,true,true,0);
    Check(!badOffset.SubmittedThrough(116) && badOffset.Error()==Failure::WrongState);
    ControlExchange client(a,b.node,nullptr,true,true,0),server(b,a.node,nullptr,true,true,0);
    const auto helloA=client.Pending(),helloB=server.Pending();
    Check(client.SubmittedThrough(115) && server.SubmittedThrough(115));
    Check(client.Receive(crypto,helloB.data,helloB.size) && server.Receive(crypto,helloA.data,helloA.size));
    const auto authA=client.Pending(),authB=server.Pending();
    Check(client.SubmittedThrough(185) && server.SubmittedThrough(185));
    Check(client.Receive(crypto,authB.data,authB.size) && server.Receive(crypto,authA.data,authA.size));
    Sink sink; const std::uint8_t credit[]={0,0,0,1,4};
    Check(!client.Receive(crypto,credit,sizeof(credit),&sink) && sink.calls==0 && client.Error()==Failure::WrongState);
    const std::uint8_t dvl[]={0,0,0,1,8};
    Check(!server.Receive(crypto,dvl,sizeof(dvl),&sink) && sink.calls==0 && server.Error()==Failure::WrongState);
}
int main() {
    SessionTests();
    ExchangeTests();
    ControlReader empty; Check(empty.Type()==0 && empty.Payload()==nullptr && empty.PayloadSize()==0);
    Hello h; h.node.fill(1); h.attempt.fill(2); h.nonce.fill(3);
    h.userHash.fill(4); h.topologyGeneration=0x0123456789abcdefULL; h.caps=7;
    std::array<std::uint8_t,HelloSize> wire{};
    Check(EncodeHello(h,wire)); Check(wire[66]==1 && wire[73]==0xef && wire[109]==7);
    Hello decoded; Check(DecodeHello(wire.data(),wire.size(),decoded));
    Check(decoded.node==h.node && decoded.nonce==h.nonce && decoded.attempt==h.attempt &&
        decoded.userHash==h.userHash && decoded.topologyGeneration==h.topologyGeneration);
    for(std::size_t n=0;n<HelloSize;++n) Check(!DecodeHello(wire.data(),n,decoded));
    Check(!DecodeHello(nullptr,HelloSize,decoded));
    auto bad=wire; bad[0]=2; Check(!DecodeHello(bad.data(),bad.size(),decoded));
    bad=wire; bad[1]=2; Check(!DecodeHello(bad.data(),bad.size(),decoded));
    bad=wire; bad[106]=0x80; Check(DecodeHello(bad.data(),bad.size(),decoded));
    Check((decoded.caps & KnownCaps)==7); Check(!EncodeHello(decoded,bad));
    h.nonce.fill(0); Check(!EncodeHello(h,bad));
    std::array<std::uint8_t,32> exporter{},context{}; exporter.fill(0x11); context.fill(0x22);
    const auto msg=AuthMessage(exporter,context,1);
    Check(std::memcmp(msg.data(),"ESE-PEER-AUTH/1",15)==0 && msg[15]==0);
    Check(msg[16]==0x11 && msg[47]==0x11 && msg[48]==0x22 && msg[79]==0x22 && msg[80]==1);
    std::vector<std::uint8_t> frame={0,0,0,111,1}; frame.insert(frame.end(),wire.begin(),wire.end());
    for(std::size_t split=0;split<=frame.size();++split) {
        ControlReader r; std::size_t used=999;
        auto result=r.Feed(frame.data(),split,used); Check(used==split);
        if(split<frame.size()) {
            Check(result==ReadResult::NeedMore);
            result=r.Feed(frame.data()+split,frame.size()-split,used); Check(used==frame.size()-split);
        }
        Check(result==ReadResult::Frame && r.Type()==1 && r.PayloadSize()==HelloSize);
        Check(std::memcmp(r.Payload(),wire.data(),HelloSize)==0);
    }
    ControlReader joined; auto two=frame; two.insert(two.end(),frame.begin(),frame.end());
    std::size_t used=0; Check(joined.Feed(two.data(),two.size(),used)==ReadResult::Frame);
    Check(used==frame.size()); Check(joined.Feed(two.data()+used,two.size()-used,used)==ReadResult::Frame);
    for(const std::uint32_t length : {0U,4097U,0xffffffffU}) {
        const std::uint8_t prefix[]={static_cast<std::uint8_t>(length>>24),static_cast<std::uint8_t>(length>>16),
            static_cast<std::uint8_t>(length>>8),static_cast<std::uint8_t>(length)};
        ControlReader r; Check(r.Feed(prefix,4,used)==ReadResult::Invalid && used==4);
        Check(r.Feed(frame.data(),frame.size(),used)==ReadResult::Invalid && used==0);
    }
    std::vector<std::uint8_t> maxFrame(4100,0); maxFrame[2]=0x10; maxFrame[4]=10;
    ControlReader maxReader; Check(maxReader.Feed(maxFrame.data(),maxFrame.size(),used)==ReadResult::Frame);
    Check(maxReader.PayloadSize()==4095);
    maxFrame[4]=11; ControlReader unknown; Check(unknown.Feed(maxFrame.data(),maxFrame.size(),used)==ReadResult::Invalid);
    std::printf("channel binding wire: %u checks PASS (no cryptographic authentication credited)\n",checks);
}
