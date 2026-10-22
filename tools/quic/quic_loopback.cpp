// SPDX-License-Identifier: MIT
// Windows UDP transport acceptance fixture for the pinned ngtcp2/GnuTLS ABI.
// Lab identities exercise signed binding; persistence/DCO/eD2K remain untested.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <vector>
#include <memory>
#include "../../srchybrid/EseChannelBinding.h"
#include "../../srchybrid/LiveCrypto.h"
#include "reach/direct_transport.h"
#include "../../srchybrid/EseQuicHeaderProbe.h"

static void CheckExporter(gnutls_session_t client,gnutls_session_t server);

static std::uint64_t Now()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
static void Require(bool value,const char* message) { if(!value) throw std::runtime_error(message); }
static void Tls(int result) { if(result<0) throw std::runtime_error(gnutls_strerror(result)); }
static void CheckExporter(gnutls_session_t client,gnutls_session_t server)
{
    using namespace ese::binding;
    Hello a,b; a.role=0; b.role=1; a.node.fill(1); b.node.fill(2);
    a.attempt.fill(3); b.attempt=a.attempt; a.caps=b.caps=1;
    Tls(gnutls_rnd(GNUTLS_RND_NONCE,a.nonce.data(),a.nonce.size()));
    Tls(gnutls_rnd(GNUTLS_RND_NONCE,b.nonce.data(),b.nonce.size()));
    std::array<std::uint8_t,HelloSize> aw{},bw{};
    Require(EncodeHello(a,aw) && EncodeHello(b,bw),"binding HELLO serialization");
    std::array<std::uint8_t,HelloSize*2> transcript{};
    std::copy(aw.begin(),aw.end(),transcript.begin());
    std::copy(bw.begin(),bw.end(),transcript.begin()+HelloSize);
    std::array<std::uint8_t,32> context{},first{},second{},changed{};
    Tls(gnutls_hash_fast(GNUTLS_DIG_SHA256,transcript.data(),transcript.size(),context.data()));
    static constexpr char label[]="EXPORTER-eSE-peer-v1";
    const auto exportKey=[&](gnutls_session_t session,const std::array<std::uint8_t,32>& c,
        std::array<std::uint8_t,32>& out) {
        Tls(gnutls_prf_rfc5705(session,sizeof(label)-1,label,c.size(),
            reinterpret_cast<const char*>(c.data()),out.size(),reinterpret_cast<char*>(out.data())));
    };
    exportKey(client,context,first); exportKey(server,context,second);
    Require(first==second,"TLS exporters disagree");
    context[0]^=1; exportKey(client,context,changed);
    Require(first!=changed,"TLS exporter ignores transcript context");
    std::printf("TLS exporter PASS: peer equality; changed context differs (signatures/pins not tested)\n");
}
struct AlpnRejected : std::exception {};
struct BindingRejected : std::exception {};
struct QuicProbe final : ese::udp::Inspector {
    ese::udp::Match Control(const std::uint8_t*,std::size_t,const ese::udp::Endpoint&,std::uint64_t&) const noexcept override {
        return ese::udp::Match::None;
    }
    bool QuicHeader(const std::uint8_t* p,std::size_t n,std::size_t size,ese::udp::Header& out) const noexcept override {
        return ese::udp::DecodeQuicHeader(p,n,size,out);
    }
    bool AcceptInitial(const std::uint8_t* p,std::size_t n) const noexcept override { return ese::udp::AcceptQuicInitial(p,n); }
    ese::udp::Match Utp(const std::uint8_t*,std::size_t,const ese::udp::Endpoint&,std::uint64_t&) const noexcept override {
        return ese::udp::Match::None;
    }
};
struct FixtureCrypto final : ese::binding::Crypto {
    gnutls_session_t& tls;
    std::array<std::uint8_t,32> pub{},priv{};
    explicit FixtureCrypto(gnutls_session_t& session):tls(session) {
        Require(eSELive::GenerateBroadcasterKeypair(pub.data(),priv.data()),"lab Ed25519 key generation");
    }
    ~FixtureCrypto() { SecureZeroMemory(priv.data(),priv.size()); }
    bool Hash(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,32>& out) noexcept override {
        return gnutls_hash_fast(GNUTLS_DIG_SHA256,p,n,out.data())==0;
    }
    bool Export(const std::array<std::uint8_t,32>& c,std::array<std::uint8_t,32>& out) noexcept override {
        static constexpr char label[]="EXPORTER-eSE-peer-v1";
        return gnutls_prf_rfc5705(tls,sizeof(label)-1,label,c.size(),
            reinterpret_cast<const char*>(c.data()),out.size(),reinterpret_cast<char*>(out.data()))==0;
    }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& sig) noexcept override {
        return eSELive::SignMessage(priv.data(),pub.data(),p,n,sig.data());
    }
    bool Verify(const std::array<std::uint8_t,32>& key,const std::uint8_t* p,std::size_t n,
        const std::uint8_t* sig) noexcept override { return eSELive::VerifySignature(key.data(),p,n,sig); }
};
struct Runtime {
    Runtime() {
        WSADATA data{};
        Require(WSAStartup(MAKEWORD(2,2),&data)==0,"WSAStartup");
        const int result=gnutls_global_init();
        if(result<0) { WSACleanup(); Tls(result); }
    }
    ~Runtime() { gnutls_global_deinit(); WSACleanup(); }
};

struct Endpoint {
    SOCKET socket=INVALID_SOCKET;
    sockaddr_in local{},remote{};
    ngtcp2_conn* conn=nullptr;
    gnutls_session_t tls=nullptr;
    FixtureCrypto crypto{tls};
    reach::DirectTransportBuffers dataBuffers;
    reach::DirectStreamWriter dataWriter;
    std::unique_ptr<ese::binding::ControlExchange> binding;
    std::size_t controlConsumed=0;
    bool corruptAuth=false,authCorrupted=false;
    ese::udp::Demux demux;
    QuicProbe udpProbe;
    gnutls_certificate_credentials_t credentials=nullptr;
    gnutls_x509_privkey_t key=nullptr;
    gnutls_x509_crt_t cert=nullptr;
    ngtcp2_crypto_conn_ref reference{};
    bool server=false,handshake=false;
    std::array<std::vector<std::uint8_t>,2> sent,received;
    std::array<std::size_t,2> submitted{};
    std::uint64_t datagrams_sent=0,datagrams_received=0;
    std::uint64_t datagrams_dropped=0;
    bool inject_loss=false;
    explicit Endpoint(bool is_server,reach::DirectBufferPool& pool)
        : dataBuffers(pool),dataWriter(dataBuffers),server(is_server)
    {
        try {
        // ngtcp2 retains send pointers until ACK. Appending AUTH must not move HELLO.
        sent[0].reserve(4096);
        socket=::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        Require(socket!=INVALID_SOCKET,"socket");
        // Write batches can exceed the default Windows UDP receive buffer.
        // Keep kernel overflow separate from our explicit 10% loss injection.
        const int receiveBuffer=4*1024*1024;
        Require(setsockopt(socket,SOL_SOCKET,SO_RCVBUF,
            reinterpret_cast<const char*>(&receiveBuffer),sizeof(receiveBuffer))==0,"UDP receive budget");
        local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        Require(bind(socket,reinterpret_cast<sockaddr*>(&local),sizeof(local))==0,"bind loopback");
        int length=sizeof(local);
        Require(getsockname(socket,reinterpret_cast<sockaddr*>(&local),&length)==0,"getsockname");
        u_long nonblocking=1;
        Require(ioctlsocket(socket,FIONBIO,&nonblocking)==0,"nonblocking");
        reference.user_data=this;
        reference.get_conn=[](ngtcp2_crypto_conn_ref* r) { return static_cast<Endpoint*>(r->user_data)->conn; };
        } catch(...) {
            if(socket!=INVALID_SOCKET) closesocket(socket);
            throw;
        }
    }
    ~Endpoint()
    {
        if(conn) ngtcp2_conn_del(conn);
        if(tls) gnutls_deinit(tls);
        if(credentials) gnutls_certificate_free_credentials(credentials);
        if(cert) gnutls_x509_crt_deinit(cert);
        if(key) gnutls_x509_privkey_deinit(key);
        if(socket!=INVALID_SOCKET) closesocket(socket);
    }
    Endpoint(const Endpoint&)=delete;
    Endpoint& operator=(const Endpoint&)=delete;
    ngtcp2_path Path()
    {
        ngtcp2_path p{};
        p.local.addr=reinterpret_cast<sockaddr*>(&local); p.local.addrlen=sizeof(local);
        p.remote.addr=reinterpret_cast<sockaddr*>(&remote); p.remote.addrlen=sizeof(remote);
        return p;
    }
    ese::udp::Endpoint RemoteEndpoint() const {
        ese::udp::Endpoint out; out.port=ntohs(remote.sin_port);
        std::memcpy(out.address.data(),&remote.sin_addr,4); return out;
    }
    void InitTls(const char* protocol)
    {
        Tls(gnutls_certificate_allocate_credentials(&credentials));
        if(server) {
            Tls(gnutls_x509_privkey_init(&key));
            Tls(gnutls_x509_privkey_generate(key,GNUTLS_PK_ECDSA,
                GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),0));
            Tls(gnutls_x509_crt_init(&cert));
            Tls(gnutls_x509_crt_set_version(cert,3));
            std::array<unsigned char,16> serial{};
            Tls(gnutls_rnd(GNUTLS_RND_RANDOM,serial.data(),serial.size()));
            serial[0]&=0x7f; serial[0]|=1;
            Tls(gnutls_x509_crt_set_serial(cert,serial.data(),serial.size()));
            Tls(gnutls_x509_crt_set_activation_time(cert,std::time(nullptr)-60));
            Tls(gnutls_x509_crt_set_expiration_time(cert,std::time(nullptr)+3600));
            Tls(gnutls_x509_crt_set_dn_by_oid(cert,GNUTLS_OID_X520_COMMON_NAME,0,"localhost",9));
            Tls(gnutls_x509_crt_set_key(cert,key));
            Tls(gnutls_x509_crt_sign2(cert,cert,key,GNUTLS_DIG_SHA256,0));
            Tls(gnutls_certificate_set_x509_key(credentials,&cert,1,key));
        }
        Tls(gnutls_init(&tls,(server ? GNUTLS_SERVER : GNUTLS_CLIENT)|
            GNUTLS_NO_END_OF_EARLY_DATA|GNUTLS_NO_AUTO_SEND_TICKET));
        Tls(gnutls_priority_set_direct(tls,"NORMAL:-VERS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE",nullptr));
        Require((server ? ngtcp2_crypto_gnutls_configure_server_session(tls) :
            ngtcp2_crypto_gnutls_configure_client_session(tls))==0,"QUIC TLS hooks");
        gnutls_session_set_ptr(tls,&reference);
        Tls(gnutls_credentials_set(tls,GNUTLS_CRD_CERTIFICATE,credentials));
        gnutls_datum_t alpn{reinterpret_cast<unsigned char*>(const_cast<char*>(protocol)),
            static_cast<unsigned>(std::strlen(protocol))};
        Tls(gnutls_alpn_set_protocols(tls,&alpn,1,GNUTLS_ALPN_MANDATORY));
    }
    static int Received(ngtcp2_conn*,std::uint32_t flags,int64_t stream,std::uint64_t offset,
        const std::uint8_t* bytes,std::size_t length,void* userdata,void*) noexcept
    {
        auto& e=*static_cast<Endpoint*>(userdata);
        if((stream!=0 && stream!=4) || (flags&NGTCP2_STREAM_DATA_FLAG_0RTT))
            return NGTCP2_ERR_CALLBACK_FAILURE;
        if(stream==4 && (!e.binding || !e.binding->Ready())) return NGTCP2_ERR_CALLBACK_FAILURE;
        auto& data=e.received[stream==0 ? 0 : 1];
        if(offset!=data.size() || length>4u*1024u*1024u-data.size()) return NGTCP2_ERR_CALLBACK_FAILURE;
        try {
            if(stream==4 && e.dataBuffers.Receive({bytes,length}).accepted!=length)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            data.insert(data.end(),bytes,bytes+length);
            if(stream==4 && !e.dataBuffers.ConsumeReceived(length)) return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        catch(...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
        return 0;
    }
    void BeginBinding(const std::array<std::uint8_t,32>& peer,const std::array<std::uint8_t,16>& attempt) {
        ese::binding::Hello hello; hello.role=server ? 1 : 0; hello.node=crypto.pub;
        hello.attempt=attempt; hello.caps=1; hello.topologyGeneration=1;
        Tls(gnutls_rnd(GNUTLS_RND_NONCE,hello.nonce.data(),hello.nonce.size()));
        // Persistent=true is a laboratory precondition, not a storage test.
        binding=std::make_unique<ese::binding::ControlExchange>(hello,peer,&peer,true,handshake,Now()/NGTCP2_MILLISECONDS);
        const auto pending=binding->Pending(); Require(pending.size==115,"local HELLO");
        sent[0].assign(pending.data,pending.data+pending.size);
    }
    void PumpBinding() {
        if(!binding) return;
        Require(binding->SubmittedThrough(submitted[0]),"binding submitted offset");
        if(controlConsumed<received[0].size()) {
            if(!binding->Receive(crypto,received[0].data()+controlConsumed,received[0].size()-controlConsumed))
                throw BindingRejected{};
            controlConsumed=received[0].size();
        }
        const auto pending=binding->Pending();
        const auto end=submitted[0]+pending.size;
        if(end>sent[0].size()) {
            const auto already=sent[0].size()-submitted[0];
            Require(end<=4096,"bounded fixture control");
            sent[0].insert(sent[0].end(),pending.data+already,pending.data+pending.size);
        }
        if(corruptAuth && !authCorrupted && sent[0].size()==185) {
            sent[0][121]^=1; authCorrupted=true;
        }
        binding->Tick(Now()/NGTCP2_MILLISECONDS);
        Require(binding->Error()==ese::binding::Failure::None,"binding timeout/state failure");
    }
    void InitConnection(const ngtcp2_pkt_hd* initial=nullptr)
    {
        ngtcp2_callbacks callbacks{};
        callbacks.client_initial=ngtcp2_crypto_client_initial_cb;
        callbacks.recv_client_initial=ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data=ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt=ngtcp2_crypto_encrypt_cb; callbacks.decrypt=ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask=ngtcp2_crypto_hp_mask_cb; callbacks.recv_retry=ngtcp2_crypto_recv_retry_cb;
        callbacks.update_key=ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx=ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx=ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.version_negotiation=ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_path_challenge_data2=ngtcp2_crypto_get_path_challenge_data2_cb;
        callbacks.rand=[](std::uint8_t* dest,std::size_t size,const ngtcp2_rand_ctx*) {
            if(gnutls_rnd(GNUTLS_RND_RANDOM,dest,size)!=0) std::abort();
        };
        callbacks.get_new_connection_id2=[](ngtcp2_conn*,ngtcp2_cid* cid,
            ngtcp2_stateless_reset_token* token,std::size_t size,void* userdata) {
            if(!size || size>20) return NGTCP2_ERR_CALLBACK_FAILURE;
            cid->datalen=size;
            if(gnutls_rnd(GNUTLS_RND_RANDOM,cid->data,size)!=0 ||
                gnutls_rnd(GNUTLS_RND_RANDOM,token->data,sizeof(token->data))!=0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            ese::udp::Cid routingCid; routingCid.size=static_cast<std::uint8_t>(size);
            std::copy_n(cid->data,size,routingCid.bytes.begin());
            return static_cast<Endpoint*>(userdata)->demux.RegisterCid(routingCid,1) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        callbacks.handshake_completed=[](ngtcp2_conn*,void* userdata) {
            auto& e=*static_cast<Endpoint*>(userdata);
            gnutls_datum_t selected{};
            if(gnutls_alpn_get_selected_protocol(e.tls,&selected)<0 || selected.size!=10 ||
                std::memcmp(selected.data,"ese-peer/1",10)) return NGTCP2_ERR_CALLBACK_FAILURE;
            e.handshake=true; return 0;
        };
        callbacks.recv_stream_data=Received;
        callbacks.acked_stream_data_offset=[](ngtcp2_conn*,int64_t stream,std::uint64_t offset,
            std::uint64_t length,void* userdata,void*) noexcept {
            auto& e=*static_cast<Endpoint*>(userdata);
            if(stream==0) return 0; // fixed control bytes retained until connection destruction
            try { return stream==4 && e.dataWriter.Acknowledged(offset,length) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE; }
            catch(...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
        };
        ngtcp2_cid dcid{},scid{};
        scid.datalen=8; Tls(gnutls_rnd(GNUTLS_RND_RANDOM,scid.data,scid.datalen));
        if(server) dcid=initial->scid;
        else { dcid.datalen=NGTCP2_MIN_INITIAL_DCIDLEN; Tls(gnutls_rnd(GNUTLS_RND_RANDOM,dcid.data,dcid.datalen)); }
        ngtcp2_settings settings; ngtcp2_settings_default(&settings); settings.initial_ts=Now();
        ngtcp2_transport_params params; ngtcp2_transport_params_default(&params);
        params.initial_max_streams_bidi=server ? 2 : 0;
        params.initial_max_streams_uni=0;
        params.initial_max_stream_data_bidi_local=4u*1024u*1024u;
        params.initial_max_stream_data_bidi_remote=4u*1024u*1024u;
        params.initial_max_data=8u*1024u*1024u;
        if(server) { params.original_dcid=initial->dcid; params.original_dcid_present=1; }
        auto path=Path();
        const int result=server ? ngtcp2_conn_server_new(&conn,&dcid,&scid,&path,NGTCP2_PROTO_VER_V1,
            &callbacks,&settings,&params,nullptr,this) : ngtcp2_conn_client_new(&conn,&dcid,&scid,&path,
            NGTCP2_PROTO_VER_V1,&callbacks,&settings,&params,nullptr,this);
        Require(result==0,ngtcp2_strerror(result));
        ese::udp::Cid routingCid; routingCid.size=static_cast<std::uint8_t>(scid.datalen);
        std::copy_n(scid.data,scid.datalen,routingCid.bytes.begin());
        Require(demux.RegisterCid(routingCid,1),"QUIC routing CID registration");
        // Server's original destination CID still routes retransmitted Initials.
        if(server) {
            routingCid.size=static_cast<std::uint8_t>(initial->dcid.datalen);
            std::copy_n(initial->dcid.data,initial->dcid.datalen,routingCid.bytes.begin());
            Require(demux.RegisterCid(routingCid,1),"original Initial CID registration");
        }
        ngtcp2_conn_set_tls_native_handle(conn,tls);
    }
    void Read()
    {
        std::array<std::uint8_t,65536> packet{};
        for(unsigned i=0;i<128;++i) {
            sockaddr_in from{}; int from_size=sizeof(from);
            const int length=recvfrom(socket,reinterpret_cast<char*>(packet.data()),
                static_cast<int>(packet.size()),0,reinterpret_cast<sockaddr*>(&from),&from_size);
            if(length==SOCKET_ERROR) { Require(WSAGetLastError()==WSAEWOULDBLOCK,"recvfrom"); return; }
            Require(from.sin_addr.s_addr==remote.sin_addr.s_addr && from.sin_port==remote.sin_port,"unexpected endpoint");
            ++datagrams_received;
            const auto decision=demux.Inspect(udpProbe,packet.data(),static_cast<std::size_t>(length),
                RemoteEndpoint(),Now()/NGTCP2_MILLISECONDS);
            Require(decision.channel==ese::udp::Channel::Quic && decision.owner==1 && demux.Current(decision),
                "UDP demux did not authorize QUIC delivery");
            if(!conn) {
                auto unexpected=RemoteEndpoint(); ++unexpected.port;
                Require(demux.Inspect(udpProbe,packet.data(),static_cast<std::size_t>(length),unexpected,
                    Now()/NGTCP2_MILLISECONDS).channel==ese::udp::Channel::Legacy,"Initial from unexpected endpoint claimed");
                ngtcp2_pkt_hd initial{};
                Require(server && ngtcp2_accept(&initial,packet.data(),static_cast<std::size_t>(length))==0,"accept initial");
                InitConnection(&initial);
            }
            auto path=Path(); ngtcp2_pkt_info info{};
            const auto result=ngtcp2_conn_read_pkt(conn,&path,&info,packet.data(),static_cast<std::size_t>(length),Now());
            if(result==NGTCP2_ERR_CRYPTO && ngtcp2_conn_get_tls_alert(conn)==GNUTLS_A_NO_APPLICATION_PROTOCOL)
                throw AlpnRejected{};
            Require(result==0,ngtcp2_strerror(result));
        }
    }
    void Write()
    {
        if(!conn) return;
        const auto now=Now();
        if(ngtcp2_conn_get_expiry(conn)<=now)
            Require(ngtcp2_conn_handle_expiry(conn,now)==0,"QUIC expiry");
        for(unsigned i=0;i<64;++i) {
            std::array<std::uint8_t,1452> packet{};
            ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path); ngtcp2_pkt_info info{};
            ngtcp2_ssize accepted=-1;
            int64_t stream=-1; ngtcp2_vec vec{}; std::size_t count=0;
            for(std::size_t index=0;index<2;++index) {
                if(index==1) {
                    const auto pending=dataWriter.Pending();
                    if(pending.size) {
                        stream=4; vec.base=const_cast<std::uint8_t*>(pending.data); vec.len=pending.size;
                        count=1; break;
                    }
                    continue;
                }
                if(submitted[index]<sent[index].size()) {
                    stream=index==0 ? 0 : 4;
                    vec.base=sent[index].data()+submitted[index]; vec.len=sent[index].size()-submitted[index];
                    count=1; break;
                }
            }
            const auto result=ngtcp2_conn_writev_stream(conn,&path.path,&info,packet.data(),packet.size(),
                &accepted,NGTCP2_WRITE_STREAM_FLAG_NONE,stream,&vec,count,Now());
            Require(result>=0,ngtcp2_strerror(static_cast<int>(result)));
            if(accepted>0) {
                if(stream==4) Require(dataWriter.Submitted(static_cast<std::size_t>(accepted)),"QUIC submit range");
                submitted[stream==0 ? 0 : 1]+=static_cast<std::size_t>(accepted);
            }
            if(!result) return;
            ++datagrams_sent;
            if(inject_loss && datagrams_sent%10==0) { ++datagrams_dropped; continue; }
            const int written=sendto(socket,reinterpret_cast<const char*>(packet.data()),static_cast<int>(result),0,
                reinterpret_cast<sockaddr*>(&remote),sizeof(remote));
            Require(written==result,"sendto");
        }
    }
};

int main(int argc,char** argv)
{
    const bool wrong_alpn=argc==2 && std::strcmp(argv[1],"--wrong-alpn")==0;
    const bool loss=argc==2 && std::strcmp(argv[1],"--loss")==0;
    const bool bad_auth=argc==2 && std::strcmp(argv[1],"--bad-auth")==0;
    if(argc>2 || (argc==2 && !wrong_alpn && !loss && !bad_auth)) return 2;
    try {
        Runtime runtime;
        reach::DirectBufferPool pool;
        Endpoint client(false,pool),server(true,pool);
        client.remote=server.local; server.remote=client.local;
        Require(server.demux.ExpectInitial(server.RemoteEndpoint(),1,Now()/NGTCP2_MILLISECONDS+5000),
            "expected Initial endpoint");
        client.inject_loss=server.inject_loss=loss;
        client.corruptAuth=bad_auth;
        client.InitTls(wrong_alpn ? "wrong-peer/1" : "ese-peer/1"); server.InitTls("ese-peer/1"); client.InitConnection();
        const std::uint8_t lookalike[32]={0x40};
        Require(client.demux.Inspect(client.udpProbe,lookalike,sizeof(lookalike),client.RemoteEndpoint(),
            Now()/NGTCP2_MILLISECONDS).channel==ese::udp::Channel::Legacy,"fixed-bit lookalike claimed as QUIC");
        const auto started=Now(); bool streams=false,response=false,dataQueued=false;
        std::uint64_t handshake_elapsed=0;
        while(Now()-started<10u*NGTCP2_SECONDS) {
            client.Write(); server.Read(); server.Write(); client.Read();
            if(client.handshake && server.handshake && !streams) {
                Require(!wrong_alpn,"incompatible ALPN reached handshake");
                handshake_elapsed=Now()-started;
                CheckExporter(client.tls,server.tls);
                Require(handshake_elapsed<=4u*NGTCP2_SECONDS,"handshake exceeds 4 seconds");
                int64_t control=-1,data=-1;
                Require(ngtcp2_conn_open_bidi_stream(client.conn,&control,nullptr)==0 && control==0,"control stream 0");
                Require(ngtcp2_conn_open_bidi_stream(client.conn,&data,nullptr)==0 && data==4,"data stream 4");
                int64_t extra=-1;
                Require(ngtcp2_conn_open_bidi_stream(client.conn,&extra,nullptr)==NGTCP2_ERR_STREAM_ID_BLOCKED,
                    "third stream must be blocked");
                Require(ngtcp2_conn_open_bidi_stream(server.conn,&extra,nullptr)==NGTCP2_ERR_STREAM_ID_BLOCKED,
                    "responder must not open streams");
                std::array<std::uint8_t,16> attempt{};
                Tls(gnutls_rnd(GNUTLS_RND_RANDOM,attempt.data(),attempt.size()));
                client.BeginBinding(server.crypto.pub,attempt); server.BeginBinding(client.crypto.pub,attempt);
                streams=true;
            }
            if(streams) {
                try { client.PumpBinding(); server.PumpBinding(); }
                catch(const BindingRejected&) {
                    Require(bad_auth && server.binding->Error()==ese::binding::Failure::IdentityMismatch,
                        "unexpected binding rejection");
                    Require(client.sent[1].empty() && server.sent[1].empty() &&
                        client.received[1].empty() && server.received[1].empty(),"bulk before valid binding");
                    std::printf("QUIC bad AUTH PASS: Ed25519 rejection; zero bulk bytes\n"); return 0;
                }
            }
            if(streams && client.binding->Ready() && server.binding->Ready() && !dataQueued) {
                Require(!bad_auth,"corrupt AUTH reached READY");
                std::printf("QUIC signed binding PASS: HELLO/AUTH on stream 0, both NODE_BOUND before bulk\n");
                client.sent[1].resize(1024u*1024u);
                for(std::size_t i=0;i<client.sent[1].size();++i) client.sent[1][i]=static_cast<std::uint8_t>((i*37u+13u)&255u);
                Require(client.dataBuffers.Send({client.sent[1].data(),client.sent[1].size()}).accepted==client.sent[1].size(),
                    "owned client bulk buffer");
                dataQueued=true;
            }
            if(dataQueued && !response && server.received[1]==client.sent[1]) {
                server.sent[1]=client.sent[1]; response=true;
                Require(server.dataBuffers.Send({server.sent[1].data(),server.sent[1].size()}).accepted==server.sent[1].size(),
                    "owned server bulk buffer");
            }
            if(response && client.received[1]==server.sent[1] && server.received[1]==client.sent[1] &&
                client.dataBuffers.Snapshot().acknowledged_offset==client.sent[1].size() &&
                server.dataBuffers.Snapshot().acknowledged_offset==server.sent[1].size()) {
                Require(pool.Used()==0,"owned buffers not retired after full ACK/consume");
                Require(gnutls_protocol_get_version(client.tls)==GNUTLS_TLS1_3 &&
                        gnutls_protocol_get_version(server.tls)==GNUTLS_TLS1_3,"TLS1.3");
                std::printf("QUIC loopback PASS: TLS1.3 ALPN ese-peer/1; control=0 data=4; 1048576 data bytes exact per direction\n");
                std::printf("UDP client sent=%llu received=%llu; server sent=%llu received=%llu\n",
                    static_cast<unsigned long long>(client.datagrams_sent),static_cast<unsigned long long>(client.datagrams_received),
                    static_cast<unsigned long long>(server.datagrams_sent),static_cast<unsigned long long>(server.datagrams_received));
                std::printf("Handshake=%llu ms; injected drops client=%llu server=%llu; third stream blocked\n",
                    static_cast<unsigned long long>(handshake_elapsed/NGTCP2_MILLISECONDS),
                    static_cast<unsigned long long>(client.datagrams_dropped),static_cast<unsigned long long>(server.datagrams_dropped));
                std::printf("Scope: lab signed binding; persistent identity/trust, eD2K hash, DCO and product acceptance pending\n");
                std::printf("Owned stream buffers PASS: submitted/ACK=1048576 each; shared pool drained\n");
                return 0;
            }
            // Keep ngtcp2's own monotonic pacing/expiry authoritative. Windows
            // may round Sleep(1) to a full scheduler tick; doing that on every
            // credit/ACK iteration makes this 10-second fixture depend on an
            // unrelated process having requested a finer timer resolution.
            // Yield the CPU without adding an artificial per-packet delay.
            SwitchToThread();
        }
        std::fprintf(stderr,"Deadline diagnostics: submitted=%zu/%zu received=%zu/%zu; UDP=%llu/%llu\n",
            client.submitted[1],server.submitted[1],server.received[1].size(),client.received[1].size(),
            static_cast<unsigned long long>(client.datagrams_sent),static_cast<unsigned long long>(server.datagrams_sent));
        throw std::runtime_error("QUIC loopback deadline");
    } catch(const AlpnRejected&) {
        if(wrong_alpn) { std::printf("QUIC ALPN rejection PASS: TLS alert NO_APPLICATION_PROTOCOL; no stream payload\n"); return 0; }
        std::fprintf(stderr,"Unexpected ALPN rejection\n"); return 1;
    } catch(const std::exception& error) {
        std::fprintf(stderr,"QUIC loopback FAIL: %s\n",error.what()); return 1;
    }
}
