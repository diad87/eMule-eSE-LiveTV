#include "EseServerProtocol.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
using namespace ese::server;
using Bytes = std::vector<std::uint8_t>;

void Check(bool condition,const char* message)
{
    if(!condition) throw std::runtime_error(message);
}

Bytes LoadFixture(const std::filesystem::path& path)
{
    std::ifstream input(path);
    std::string wire, trailing;
    Check(bool(input>>wire) && !(input>>trailing) && wire.size()%2==0,"fixture readable, exactly one hex record");
    Bytes result;
    for(std::size_t i=0;i<wire.size();i+=2) {
        const auto byte=wire.substr(i,2);
        Check(byte.find_first_not_of("0123456789abcdef") == std::string::npos,"canonical fixture hex");
        result.push_back(static_cast<std::uint8_t>(std::stoul(byte,nullptr,16)));
    }
    return result;
}

std::optional<FrameView> ReadFrame(FrameDecoder& decoder,const Bytes& bytes)
{
    const auto fed=decoder.Feed({bytes.data(),bytes.size()});
    Check(fed.consumed==bytes.size() && fed.state==DecodeState::Ready,"one complete frame");
    return decoder.Get();
}

void CheckPingPong(const Bytes& ping,const Bytes& pong)
{
    FrameDecoder fragmented;
    for(std::size_t i=0;i<ping.size();++i) {
        const auto fed=fragmented.Feed({&ping[i],1});
        Check(fed.consumed==1,"consumed one input byte");
        Check((fed.state==DecodeState::Ready)==(i+1==ping.size()),"frame available only after last byte");
    }
    Bytes both=ping;
    both.insert(both.end(),pong.begin(),pong.end());
    FrameDecoder joined;
    std::size_t offset=0,events=0;
    for(const Bytes* expected : {&ping,&pong}) {
        const auto fed=joined.Feed({both.data()+offset,both.size()-offset});
        const auto frame=joined.Get();
        Check(frame && fed.consumed==expected->size() && fed.state==DecodeState::Ready,"one event per frame");
        const bool request=events==0;
        Check(frame->header.type==(request ? 0x00FE : 0x00FD) && frame->header.flags==(request ? 0 : 3),
            "golden PING and PONG headers");
        Check(std::all_of(frame->header.request.begin(),frame->header.request.end(),
            [](std::uint8_t byte) { return byte==1; }),"golden correlation ID");
        Check(frame->payload.size==16 && std::equal(frame->payload.data,frame->payload.data+16,expected->end()-16),
            "golden PING and PONG nonce");
        Check(ClassifyFrame(frame->header,request ? Direction::ClientToServer : Direction::ServerToClient,
            Phase::Authenticated)==Disposition::Message,"valid direction and authenticated phase");
        Bytes restored;
        Check(EncodeFrame(*frame,restored) && restored==*expected,"encoder agrees with independent golden bytes");
        Check(joined.Feed({both.data()+offset,1}).consumed==0,"ready frame retained until consumed");
        Check(joined.Consume() && !joined.Get(),"consumed only one event");
        offset+=fed.consumed;
        ++events;
    }
    Check(offset==both.size() && events==2 && !joined.Consume(),"no phantom frame after concatenated valid input");

    for(const Bytes* expected : {&ping,&pong}) {
        for(std::size_t length=0;length<expected->size();++length) {
            FrameDecoder truncated;
            const auto fed=truncated.Feed({expected->data(),length});
            Check(fed.consumed==length && fed.state==DecodeState::Reading && !truncated.Get(),"every truncation waits for input");
        }
    }
}

void CheckBadHeaders(const Bytes& ping,const Bytes& oversized)
{
    auto rejects=[&](const Bytes& bad) {
        FrameDecoder decoder;
        const auto fed=decoder.Feed({bad.data(),bad.size()});
        Check(fed.consumed==28 && fed.state==DecodeState::Malformed && decoder.ReservedPayloadSize()==0,
            "reject malformed header before body allocation");
        Check(!decoder.Get() && !decoder.Consume() && decoder.Feed({ping.data(),ping.size()}).consumed==0,
            "malformed stream never resynchronizes or emits");
    };
    auto bad=ping;
    bad[0]='X';
    rejects(bad);
    bad=ping;
    bad[11]=0x04;
    rejects(bad);
    bad=ping;
    bad[11]=0x02; // FINAL without RESPONSE on a request
    rejects(bad);
    bad=ping;
    bad[11]=0x01;
    std::fill(bad.begin()+12,bad.begin()+28,std::uint8_t{0});
    rejects(bad);
    rejects(oversized);
    for(const std::size_t length : {65507u,65508u,65509u,0xffffffffu}) {
        auto frame=ping;
        frame.resize(length<=65508 ? length+28 : 28);
        for(unsigned offset=0;offset<4;++offset)
            frame[4+offset]=static_cast<std::uint8_t>(length>>((3-offset)*8));
        if(length>65508) { rejects(frame); continue; }
        FrameDecoder decoder;
        const auto parsed=ReadFrame(decoder,frame);
        Check(parsed && parsed->payload.size==length,"accept both in-range maximum lengths");
        Check(decoder.Consume() && decoder.ReservedPayloadSize()==0,"release payload at frame boundary");
    }
    Bytes preserved={1,2,3};
    const FrameView impossible{{kEseWireServerPing,0,{}},{nullptr,65509}};
    Check(!EncodeFrame(impossible,preserved) && preserved==Bytes({1,2,3}),"invalid output serialization is transactional");
}

void CheckUnknown(const Bytes& unknown,const Bytes& expectedError)
{
    FrameDecoder decoder;
    const auto frame=ReadFrame(decoder,unknown);
    Check(frame && frame->payload.size==0,"unknown type structurally decodes");
    Check(ClassifyFrame(frame->header,Direction::ClientToServer,Phase::Authentication)==Disposition::Invalid,
        "unknown pre-auth type is invalid");
    Check(ClassifyFrame(frame->header,Direction::ServerToClient,Phase::Authenticated)==Disposition::Invalid,
        "unknown server notification is invalid");
    unsigned operationMutations=0;
    const auto disposition=ClassifyFrame(frame->header,Direction::ClientToServer,Phase::Authenticated);
    Check(disposition==Disposition::UnsupportedRequest,"authenticated unknown request bypasses operation dispatch");
    if(disposition==Disposition::Message) ++operationMutations;
    Check(operationMutations==0,"no operation event for unknown type");
    const std::uint8_t errorPayload[]={0,2,0,0,0,0};
    const FrameView error{{kEseWireServerError,kEseWireServerResponse | kEseWireServerFinal,frame->header.request},
        {errorPayload,sizeof errorPayload}};
    Check(ClassifyFrame(error.header,Direction::ServerToClient,Phase::Authenticated)==Disposition::Message,
        "recoverable error header is correlated and terminal");
    Bytes output;
    Check(EncodeFrame(error,output) && output==expectedError,"UNSUPPORTED exact independent wire vector");
    Check(decoder.Consume(),"unsupported message does not terminate the framing stream");
}
}

int main(int argc,char** argv)
{
    try {
        Check(argc==2,"path to fixture directory");
        const auto directory=std::filesystem::path(argv[1]);
        auto load=[&](const char* name) { return LoadFixture(directory/name); };
        const auto ping=load("ping.hex"), pong=load("pong.hex");
        Check(AcceptsAlpn("ese-server/1") && !AcceptsAlpn("ese-server/2") && !AcceptsAlpn("ese-peer/1") &&
            !AcceptsAlpn(std::string_view("ese-server/1\0",13)),"version matches exact ALPN");
        Check(SelectCapabilities(0xffffffffu,0x3fu)==0x3fu && SelectCapabilities(0x80000039u,0x80000039u)==0x11u &&
            !SelectCapabilities(0x01,0x3f),"capability intersection is known and dependency-closed");
        CheckPingPong(ping,pong);
        CheckBadHeaders(ping,load("bad_length.hex"));
        CheckUnknown(load("unknown.hex"),load("unsupported.hex"));
        std::cout<<"DS-03 frame/dispatch codec PASS\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"DS-03 FAIL "<<error.what()<<'\n';
        return 1;
    }
}
