#include "../../srchybrid/EseUdpDemux.h"
#include "SimulatedQuicPort.h"
#include <cstdio>
#include <cstdlib>
using namespace ese::udp;
static unsigned checks=0;
static void Check(bool b) { ++checks; if(!b) { std::printf("FAIL %u\n",checks); std::exit(1); } }
struct Probe final : Inspector {
    Header header{}; bool decode=true,accept=true;
    Match control=Match::None,utp=Match::None;
    Match Control(const std::uint8_t*,std::size_t,const Endpoint&,std::uint64_t& owner) const noexcept override {
        owner=90; return control;
    }
    bool QuicHeader(const std::uint8_t*,std::size_t,std::size_t,Header& out) const noexcept override {
        out=header; return decode;
    }
    bool AcceptInitial(const std::uint8_t*,std::size_t) const noexcept override { return accept; }
    Match Utp(const std::uint8_t*,std::size_t,const Endpoint&,std::uint64_t& owner) const noexcept override {
        owner=91; return utp;
    }
};
int main() {
    {
        struct Ingress final : ese::QuicUdpIngress {
            unsigned received=0,resets=0,polls=0; std::uint64_t lastNow=0; Endpoint source; std::uint8_t byte=0; bool claim=true;
            bool Receive(const Endpoint& from,reach::DirectByteView payload) noexcept override {
                ++received; source=from; byte=payload.data[0]; return claim;
            }
            void Poll(std::uint64_t now) override { ++polls; lastNow=now; }
            void SocketReset() noexcept override { ++resets; }
        } a,b;
        Endpoint left,right; left.address[0]=8; left.port=1000; right.address[0]=9; right.port=2000;
        auto networkA=std::make_unique<ese::test::SimulatedQuicPort>(left);
        auto networkB=std::make_unique<ese::test::SimulatedQuicPort>(right);
        Check(!networkA->Link(*networkA) && networkA->Link(*networkB));
        Check(!networkA->Link(*networkB));
        Check(networkA->AttachQuicIngress(&a) && networkB->AttachQuicIngress(&b));
        Check(!networkA->AttachQuicIngress(&b));
        networkA->Poll(123); Check(a.polls==1 && a.lastNow==123 && b.polls==0);
        std::uint8_t payload=17;
        Check(!networkA->DropNext(0) && !networkA->DropNext(65) && networkA->DropNext(1));
        Check(!networkA->DropNext(1));
        auto wrong=right; ++wrong.port;
        Check(networkA->SendQuicDatagram(&a,wrong,&payload,1).status==ese::QuicUdpSendStatus::Invalid);
        Check(networkA->Dropped()==0);
        Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::Sent && networkB->Queued()==0 && networkA->Dropped()==1);
        Check(networkA->SendQuicDatagram(&b,right,&payload,1).status==ese::QuicUdpSendStatus::Invalid);
        Check(networkA->SendQuicDatagram(&a,right,nullptr,1).status==ese::QuicUdpSendStatus::Invalid);
        Check(networkA->SendQuicDatagram(&a,right,&payload,1201).status==ese::QuicUdpSendStatus::Invalid);
        Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::Sent);
        payload=99;
        Check(networkB->Deliver(1)==1 && b.received==1 && b.source==left && b.byte==17);
        for(unsigned i=0;i<ese::test::SimulatedQuicPort::Capacity;++i)
            Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::Sent);
        Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::WouldBlock);
        Check(networkB->Queued()==64 && networkB->Deliver(32)==32 && networkB->Queued()==32);
        b.claim=false;
        Check(networkB->Deliver()==32 && networkB->Unclaimed()==32);
        Check(networkB->SendQuicDatagram(&b,left,&payload,1).status==ese::QuicUdpSendStatus::Sent);
        Check(networkA->Deliver()==1 && a.source==right && a.byte==99);
        Check(!networkB->DetachQuicIngress(&a));
        Check(networkB->DetachQuicIngress(&b) && b.resets==1);
        networkB->Poll(456); Check(b.polls==0);
        Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::Closed);
        networkB.reset();
        Check(networkA->SendQuicDatagram(&a,right,&payload,1).status==ese::QuicUdpSendStatus::Closed);
        networkA.reset(); Check(a.resets==1 && b.resets==1);
    }
    Demux demux; Probe probe; Endpoint endpoint; endpoint.port=4665; endpoint.address[0]=127;
    Cid cid; cid.size=8; cid.bytes.fill(1); probe.header.destination=cid;
    const std::uint8_t bytes[]={0x40,1,1,1,1,1,1,1,1};
    Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Legacy);
    Check(!demux.RegisterCid(cid,0) && demux.RegisterCid(cid,1));
    const auto known=demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0);
    Check(known.channel==Channel::Quic && known.owner==1 && demux.Current(known));
    Check(demux.RegisterCid(cid,1) && !demux.RegisterCid(cid,2));
    Cid prefix=cid; prefix.size=4; Check(!demux.RegisterCid(prefix,2));
    probe.control=Match::Valid; Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Control);
    probe.control=Match::Invalid; Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Drop);
    probe.control=Match::None; demux.RemoveOwner(1); Check(!demux.Current(known));
    Check(demux.ExpectInitial(endpoint,2,100)); probe.header.initial=true;
    auto initial=demux.Inspect(probe,bytes,sizeof(bytes),endpoint,99);
    Check(initial.channel==Channel::Quic && initial.owner==2 && initial.newInitial);
    Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,100).channel==Channel::Legacy);
    Endpoint other=endpoint; ++other.port;
    Check(demux.Inspect(probe,bytes,sizeof(bytes),other,0).channel==Channel::Legacy);
    probe.accept=false; probe.utp=Match::Valid;
    Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Utp);
    probe.utp=Match::Invalid; Check(demux.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Drop);
    Check(!demux.ExpectInitial(endpoint,3,100)); demux.Expire(100); Check(!demux.Current(initial));
    Check(demux.ExpectInitial(endpoint,3,200));
    Check(demux.Inspect(probe,nullptr,1,endpoint,0).channel==Channel::Drop);
    Demux limits;
    for(unsigned i=0;i<8;++i) { Cid c=cid; c.bytes[0]=static_cast<std::uint8_t>(i); Check(limits.RegisterCid(c,1)); }
    cid.bytes[0]=8; Check(!limits.RegisterCid(cid,1));
    Cid retired=cid; retired.bytes[0]=0;
    probe.header.destination=retired; probe.header.initial=false; probe.utp=Match::None;
    const auto beforeRemoval=limits.Inspect(probe,bytes,sizeof(bytes),endpoint,0);
    Check(beforeRemoval.channel==Channel::Quic && limits.Current(beforeRemoval));
    Check(!limits.RemoveCid(retired,2) && limits.Current(beforeRemoval));
    Check(limits.RemoveCid(retired,1) && !limits.Current(beforeRemoval));
    Check(limits.Inspect(probe,bytes,sizeof(bytes),endpoint,0).channel==Channel::Legacy);
    Check(!limits.RemoveCid(retired,1));
    Check(limits.RegisterCid(cid,1)); // freed owner slot is reusable
    Cid invalid{}; Check(!limits.RemoveCid(invalid,1) && !limits.RemoveCid(cid,0));
    for(unsigned i=0;i<128;++i) { Endpoint e=endpoint; e.port=static_cast<std::uint16_t>(i+1); Check(limits.ExpectInitial(e,i+1,100)); }
    other.port=200; Check(!limits.ExpectInitial(other,200,100)); limits.Expire(100);
    Check(limits.ExpectInitial(other,200,200));
    std::printf("UDP demux: %u checks PASS (probe double; no native wire parser acceptance)\n",checks);
}
