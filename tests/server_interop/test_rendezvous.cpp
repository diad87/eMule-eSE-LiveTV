#include "EseRendezvousV2.h"
#include "ServerTls.h" // GnuTLS headers with Windows signed-size ABI
#include "hex_fixture.h"
#include <gnutls/crypto.h>
#include <algorithm>
#include <iostream>

namespace {
using namespace ese::server;
using namespace ese::server::rdv;
using server_test::Check;
using server_test::LoadFixture;

struct CryptoHooks final : Crypto {
    bool Hmac(const Bytes32& key,ByteView input,Bytes32& output) noexcept override
    {
        return gnutls_hmac_fast(GNUTLS_MAC_SHA256,key.data(),key.size(),input.data,input.size,output.data())==0;
    }
    bool Equal(const Bytes32& left,const Bytes32& right) noexcept override
    {
        return gnutls_memcmp(left.data(),right.data(),left.size())==0;
    }
};

template<class Bytes>
ByteView View(const Bytes& bytes) { return {bytes.data(),bytes.size()}; }

template<std::size_t Size>
std::array<std::uint8_t,Size> Read(const std::filesystem::path& directory,const char* name)
{
    const auto bytes=LoadFixture(directory/name);
    Check(bytes.size()==Size,"fixed-size independent RDV vectors");
    std::array<std::uint8_t,Size> output{};
    std::copy(bytes.begin(),bytes.end(),output.begin());
    return output;
}

void Test(const std::filesystem::path& directory)
{
    constexpr std::uint64_t start=90001;
    const auto key=Read<32>(directory,"udp_key.hex"),cookieSecret=Read<32>(directory,"cookie_secret.hex");
    const auto request=Read<DatagramSize>(directory,"register.hex"),
        challenge=Read<DatagramSize>(directory,"challenge.hex"),echo=Read<DatagramSize>(directory,"echo.hex");
    const auto cookieInput=LoadFixture(directory/"cookie_input.hex");
    CryptoHooks crypto;
    CookieSecrets keys;
    Check(keys.Rotate(cookieSecret,0),"initialize test cookie secret");
    Message client,expectedChallenge;
    Check(Decode(View(request),Direction::ClientToServer,key,crypto,client) &&
        Decode(View(challenge),Direction::ServerToClient,key,crypto,expectedChallenge),"independent authenticated wire goldens");
    Check(!Decode(View(request),Direction::ServerToClient,key,crypto,client) &&
        !Decode(View(challenge),Direction::ClientToServer,key,crypto,client),"reject direction confusion");
    Bytes32 cookie{};
    Endpoint observed;
    observed.family=4;
    observed.address={127,0,0,1};
    observed.port=49400;
    Check(BuildCookie(client,observed,9,cookieSecret,crypto,cookie) && cookie==expectedChallenge.cookie,
        "fixed IPv4 cookie wire input includes exact observed port");
    Bytes32 independent{};
    Check(crypto.Hmac(cookieSecret,View(cookieInput),independent) && independent==cookie,
        "independent HMAC transcript matches reference cookie");
    Datagram restored;
    Check(Encode(client,key,crypto,restored) && restored==request,"register encoder exact match");

    Session ledger(client.context);
    for(std::size_t length=0;length<request.size();++length)
        Check(!ledger.Receive({request.data(),length},observed,key,keys,crypto,start).challenge,"truncation yields silence");
    std::array<std::uint8_t,DatagramSize+1> tooLong{};
    std::copy(request.begin(),request.end(),tooLong.begin());
    Check(!ledger.Receive(View(tooLong),observed,key,keys,crypto,start).challenge,"extra byte yields silence");
    auto bad=request;
    bad.back()^=1;
    Check(!ledger.Receive(View(bad),observed,key,keys,crypto,start).challenge,"bad MAC does not advance sequence");
    auto wrongContext=client.context;
    ++wrongContext.generation;
    Session unrelated(wrongContext);
    Check(!unrelated.Receive(View(request),observed,key,keys,crypto,start).challenge,"old generation silent");
    const auto requested=ledger.Receive(View(request),observed,key,keys,crypto,start);
    Check(requested.challenge==challenge && !requested.status && !ledger.Current(4,start),
        "only byte-for-byte 1:1 challenge before proof");
    Check(ledger.Receive(View(request),observed,key,keys,crypto,start+1).challenge==challenge,
        "exact REGISTER replay returns exact prior challenge");
    Endpoint otherPort=observed;
    ++otherPort.port;
    Check(!ledger.Receive(View(request),otherPort,key,keys,crypto,start+2).challenge &&
        !ledger.Receive(View(echo),otherPort,key,keys,crypto,start+2).status && !ledger.Current(4,start+2),
        "misrouted retry and echo do not register or consume sequence");
    auto proved=ledger.Receive(View(echo),observed,key,keys,crypto,start+3).status;
    Check(proved && SameEndpoint(proved->endpoint,observed) && proved->until==start+60003,
        "echo proves original endpoint for exact lease");
    auto duplicate=ledger.Receive(View(echo),observed,key,keys,crypto,start+30000).status;
    Check(duplicate && duplicate->until==proved->until && !ledger.Current(4,proved->until),
        "duplicate echo reports original lease with no refresh");

    Session migrates(client.context);
    Check(migrates.Receive(View(request),observed,key,keys,crypto,start).challenge &&
        migrates.Receive(View(echo),observed,key,keys,crypto,start+1).status,"establish original endpoint");
    Message keepalive=client;
    keepalive.type=kEseWireRdv2Keepalive;
    keepalive.sequence=3;
    ++keepalive.nonce[0];
    Datagram keepaliveBytes;
    Check(Encode(keepalive,key,crypto,keepaliveBytes),"encode exact renewal request");
    const auto retry=migrates.Receive(View(keepaliveBytes),otherPort,key,keys,crypto,start+20000);
    Message renewProof;
    Check(retry.challenge && !retry.status && SameEndpoint(migrates.Current(4,start+20000)->endpoint,observed) &&
        Decode(View(*retry.challenge),Direction::ServerToClient,key,crypto,renewProof),
        "new port retains old registration pending new return proof");
    renewProof.type=kEseWireRdv2Echo;
    ++renewProof.sequence;
    Datagram renewEcho;
    Check(Encode(renewProof,key,crypto,renewEcho) &&
        !migrates.Receive(View(renewEcho),observed,key,keys,crypto,start+20001).status,"old port cannot renew new grant");
    const auto changed=migrates.Receive(View(renewEcho),otherPort,key,keys,crypto,start+20002);
    Check(changed.supersededEndpoint && changed.status && SameEndpoint(changed.status->endpoint,otherPort),
        "same-channel return proof explicitly replaces previous endpoint");

    Session rate(client.context);
    for(unsigned count=0;count<4;++count)
        Check(rate.Receive(View(request),observed,key,keys,crypto,start).challenge.has_value(),
            "bounded identical challenge replay");
    Check(!rate.Receive(View(request),observed,key,keys,crypto,start).challenge && !rate.Current(4,start),
        "excess reflection suppressed without granting a route");

    Session expired(client.context);
    Check(expired.Receive(View(request),observed,key,keys,crypto,start).challenge.has_value() &&
        !expired.Receive(View(echo),observed,key,keys,crypto,110000).status,
        "cookies from older than previous bucket cannot register");
    Session rotates(client.context);
    const auto late=rotates.Receive(View(request),observed,key,keys,crypto,599990).challenge;
    Message lateChallenge;
    Check(late && Decode(View(*late),Direction::ServerToClient,key,crypto,lateChallenge),"old-secret challenge ready");
    Bytes32 nextSecret=cookieSecret;
    ++nextSecret[0];
    Check(!keys.Rotate(nextSecret,599999) && keys.Rotate(nextSecret,600000) &&
          keys.Previous(619999) && !keys.Previous(620000),"rotate at ten minutes and retire previous secret after twenty seconds");
    lateChallenge.type=kEseWireRdv2Echo;
    ++lateChallenge.sequence;
    Datagram lateEcho;
    Check(Encode(lateChallenge,key,crypto,lateEcho) &&
        rotates.Receive(View(lateEcho),observed,key,keys,crypto,600001).status.has_value(),
        "previous cookie secret accepted only across one bucket transition");
}
}

int main(int argc,char** argv)
{
    try {
        Check(argc==2,"path to fixtures");
        Check(gnutls_global_init()==0,"initialize GnuTLS");
        struct Runtime { ~Runtime() { gnutls_global_deinit(); } } runtime;
        Test(argv[1]);
        std::cout<<"DS-11 RendezvousV2 codec, return proof, replay and cookie rotation PASS\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"DS-11 FAIL "<<error.what()<<'\n';
        return 1;
    }
}
