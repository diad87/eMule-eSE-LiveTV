#include <winsock2.h>
#include <ws2tcpip.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include "EseNativeQuicRuntime.h"
#include "LiveCrypto.h"
#include "NodeIdentity.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <stdexcept>
namespace ese {
namespace {
std::uint64_t TimeNs() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
void Require(bool b,const char* message) { if(!b) throw std::runtime_error(message); }
void Tls(int code) { if(code<0) throw std::runtime_error(gnutls_strerror(code)); }
sockaddr_storage Address(const udp::Endpoint& endpoint) {
    sockaddr_storage out{};
    if(endpoint.ipv6) {
        auto& a=*reinterpret_cast<sockaddr_in6*>(&out); a.sin6_family=AF_INET6;
        a.sin6_port=htons(endpoint.port); a.sin6_scope_id=endpoint.scope;
        std::memcpy(&a.sin6_addr,endpoint.address.data(),16);
    } else {
        auto& a=*reinterpret_cast<sockaddr_in*>(&out); a.sin_family=AF_INET;
        a.sin_port=htons(endpoint.port); std::memcpy(&a.sin_addr,endpoint.address.data(),4);
    }
    return out;
}
class NativeRuntime final : public QuicRuntime, public binding::Crypto {
    NativeQuicConfig config_;
    QuicDatagramSink& sink_;
    QuicIdentitySigner* signer_;
    reach::DirectTransportBuffers packets_,staged_;
    QuicIo* io_=nullptr;
    udp::Endpoint remote_;
    sockaddr_storage localAddress_{},remoteAddress_{};
    ngtcp2_conn* conn_=nullptr;
    gnutls_session_t tls_=nullptr;
    gnutls_certificate_credentials_t credentials_=nullptr;
    gnutls_x509_privkey_t key_=nullptr;
    gnutls_x509_crt_t cert_=nullptr;
    ngtcp2_crypto_conn_ref reference_{};
    std::array<std::uint8_t,1200> outbound_{};
    std::array<std::uint64_t,2> receivedOffset_{};
    std::size_t outboundSize_=0,readBudget_=reach::kDirectSessionBufferLimit;
    std::uint64_t flowEnd_=4096;
    bool global_=false,started_=false,stopped_=false,handshake_=false,dataStreamOpen_=false;
    bool dataOpeningSubmitted_=false;
public:
    NativeRuntime(const NativeQuicConfig& config,QuicDatagramSink& sink,
        reach::DirectBufferPool& pool,QuicIdentitySigner* signer)
        : config_(config),sink_(sink),signer_(signer),packets_(pool),staged_(pool) {
        Tls(gnutls_global_init()); global_=true;
        if(std::strcmp(gnutls_check_version(nullptr),"3.8.13") ||
            std::strcmp(ngtcp2_version(0)->version_str,"1.25.0")) {
            gnutls_global_deinit(); global_=false;
            throw std::runtime_error("pinned QUIC ABI version mismatch");
        }
        reference_.user_data=this;
        reference_.get_conn=[](ngtcp2_crypto_conn_ref* ref) { return static_cast<NativeRuntime*>(ref->user_data)->conn_; };
    }
    ~NativeRuntime() override { Shutdown(); if(global_) gnutls_global_deinit(); }
    std::uint64_t NowMs() const noexcept override { return TimeNs()/NGTCP2_MILLISECONDS; }
    binding::Crypto& Crypto() noexcept override { return *this; }
    bool Hash(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,32>& out) noexcept override {
        return gnutls_hash_fast(GNUTLS_DIG_SHA256,p,n,out.data())==0;
    }
    bool Export(const std::array<std::uint8_t,32>& c,std::array<std::uint8_t,32>& out) noexcept override {
        if(!handshake_) return false;
        static constexpr char label[]="EXPORTER-eSE-peer-v1";
        return gnutls_prf_rfc5705(tls_,sizeof(label)-1,label,c.size(),reinterpret_cast<const char*>(c.data()),
            out.size(),reinterpret_cast<char*>(out.data()))==0;
    }
    bool Sign(const std::uint8_t* p,std::size_t n,std::array<std::uint8_t,64>& out) noexcept override {
        if(signer_) return signer_->Sign(p,n,out.data());
        return eSELive::NodeIdentityIsPersistent() && eSELive::NodeIdentitySign(p,n,out.data());
    }
    bool Verify(const std::array<std::uint8_t,32>& key,const std::uint8_t* p,std::size_t n,const std::uint8_t* sig) noexcept override {
        return eSELive::VerifySignature(key.data(),p,n,sig);
    }
    bool Start(const reach::DirectSessionRoute& route,QuicIo& io) override {
        if(started_ || stopped_ || !config_.local.port || config_.server!=(io.LocalRole()==1)) return false;
        started_=true; io_=&io;
        remote_.address=route.candidate.address; remote_.port=route.candidate.port;
        remote_.ipv6=route.candidate.family==6;
        if(remote_.ipv6 && route.candidate.scope==reach::DirectScope::SameLan) {
            if(!route.candidate.interface_id || route.candidate.interface_id!=config_.local.scope) return false;
            remote_.scope=config_.local.scope;
        }
        localAddress_=Address(config_.local); remoteAddress_=Address(remote_);
        InitTls(); if(!config_.server) InitConnection(nullptr); return true;
    }
    void SetReadBudget(std::size_t bytes) override { readBudget_=(std::min)(bytes,reach::kDirectSessionBufferLimit); }
    bool QueueDatagram(const udp::Endpoint& source,reach::DirectByteView packet) override {
        if(!started_ || stopped_ || !(source==remote_) || !packet.data || !packet.size || packet.size>65536) return false;
        return packets_.ReceiveAtomic(packet).accepted==packet.size;
    }
    void Shutdown() noexcept override {
        if(stopped_) return; stopped_=true;
        if(conn_) { ngtcp2_conn_del(conn_); conn_=nullptr; }
        if(tls_) { gnutls_deinit(tls_); tls_=nullptr; }
        if(credentials_) { gnutls_certificate_free_credentials(credentials_); credentials_=nullptr; }
        if(cert_) { gnutls_x509_crt_deinit(cert_); cert_=nullptr; }
        if(key_) { gnutls_x509_privkey_deinit(key_); key_=nullptr; }
        packets_.Close(); staged_.Close(); outboundSize_=0; sink_.RemoveCids(); io_=nullptr;
    }
private:
    ngtcp2_path Path() {
        ngtcp2_path path{}; path.local.addr=reinterpret_cast<sockaddr*>(&localAddress_);
        path.local.addrlen=config_.local.ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        path.remote.addr=reinterpret_cast<sockaddr*>(&remoteAddress_);
        path.remote.addrlen=remote_.ipv6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in); return path;
    }
    void InitTls() {
        Tls(gnutls_certificate_allocate_credentials(&credentials_));
        if(config_.server) {
            Tls(gnutls_x509_privkey_init(&key_));
            Tls(gnutls_x509_privkey_generate(key_,GNUTLS_PK_ECDSA,GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1),0));
            Tls(gnutls_x509_crt_init(&cert_)); Tls(gnutls_x509_crt_set_version(cert_,3));
            std::array<std::uint8_t,16> serial{}; Tls(gnutls_rnd(GNUTLS_RND_RANDOM,serial.data(),serial.size()));
            serial[0]&=0x7f; serial[0]|=1;
            Tls(gnutls_x509_crt_set_serial(cert_,serial.data(),serial.size()));
            Tls(gnutls_x509_crt_set_activation_time(cert_,std::time(nullptr)-60));
            Tls(gnutls_x509_crt_set_expiration_time(cert_,std::time(nullptr)+3600));
            Tls(gnutls_x509_crt_set_dn_by_oid(cert_,GNUTLS_OID_X520_COMMON_NAME,0,"ese-peer",8));
            Tls(gnutls_x509_crt_set_key(cert_,key_)); Tls(gnutls_x509_crt_sign2(cert_,cert_,key_,GNUTLS_DIG_SHA256,0));
            Tls(gnutls_certificate_set_x509_key(credentials_,&cert_,1,key_));
        }
        Tls(gnutls_init(&tls_,(config_.server ? GNUTLS_SERVER : GNUTLS_CLIENT)|GNUTLS_NO_END_OF_EARLY_DATA|GNUTLS_NO_AUTO_SEND_TICKET));
        Tls(gnutls_priority_set_direct(tls_,"NORMAL:-VERS-ALL:+VERS-TLS1.3:%DISABLE_TLS13_COMPAT_MODE",nullptr));
        Require((config_.server ? ngtcp2_crypto_gnutls_configure_server_session(tls_) :
            ngtcp2_crypto_gnutls_configure_client_session(tls_))==0,"QUIC TLS configuration");
        gnutls_session_set_ptr(tls_,&reference_); Tls(gnutls_credentials_set(tls_,GNUTLS_CRD_CERTIFICATE,credentials_));
        gnutls_datum_t alpn{reinterpret_cast<unsigned char*>(const_cast<char*>(wire::kEseWirePeerAlpn)),
            static_cast<unsigned int>(sizeof(wire::kEseWirePeerAlpn)-1)};
        Tls(gnutls_alpn_set_protocols(tls_,&alpn,1,GNUTLS_ALPN_MANDATORY));
    }
    static int ReceiveStream(ngtcp2_conn*,std::uint32_t flags,int64_t stream,std::uint64_t offset,
        const std::uint8_t* p,std::size_t n,void* user,void*) noexcept {
        auto& self=*static_cast<NativeRuntime*>(user);
        try {
            if((stream!=0 && stream!=4) || (flags&NGTCP2_STREAM_DATA_FLAG_0RTT)) return NGTCP2_ERR_CALLBACK_FAILURE;
            const auto index=stream==0 ? 0 : 1;
            if(offset!=self.receivedOffset_[index] || n>NGTCP2_MAX_VARINT-offset)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            if(stream==0) {
                const auto r=self.io_->Received(stream,{p,n});
                if(r.status!=reach::DirectIoStatus::Accepted || r.accepted!=n) return NGTCP2_ERR_CALLBACK_FAILURE;
            } else {
                self.dataStreamOpen_=true;
                std::size_t accepted=0;
                if(!self.staged_.ReceiveFront().size) {
                    const auto r=self.io_->Received(stream,{p,n});
                    if(r.status!=reach::DirectIoStatus::Accepted && r.status!=reach::DirectIoStatus::WouldBlock)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    accepted=r.accepted;
                }
                if(accepted<n && self.staged_.Receive({p+accepted,n-accepted}).accepted!=n-accepted)
                    return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            self.receivedOffset_[index]+=n; return 0;
        } catch(...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
    }
    void InitConnection(const ngtcp2_pkt_hd* initial) {
        ngtcp2_callbacks cb{};
        cb.client_initial=ngtcp2_crypto_client_initial_cb; cb.recv_client_initial=ngtcp2_crypto_recv_client_initial_cb;
        cb.recv_crypto_data=ngtcp2_crypto_recv_crypto_data_cb; cb.encrypt=ngtcp2_crypto_encrypt_cb;
        cb.decrypt=ngtcp2_crypto_decrypt_cb; cb.hp_mask=ngtcp2_crypto_hp_mask_cb; cb.recv_retry=ngtcp2_crypto_recv_retry_cb;
        cb.update_key=ngtcp2_crypto_update_key_cb; cb.delete_crypto_aead_ctx=ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cb.delete_crypto_cipher_ctx=ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        cb.version_negotiation=ngtcp2_crypto_version_negotiation_cb; cb.get_path_challenge_data2=ngtcp2_crypto_get_path_challenge_data2_cb;
        cb.rand=[](std::uint8_t* p,std::size_t n,const ngtcp2_rand_ctx*) { if(gnutls_rnd(GNUTLS_RND_RANDOM,p,n)) std::abort(); };
        cb.get_new_connection_id2=[](ngtcp2_conn*,ngtcp2_cid* cid,ngtcp2_stateless_reset_token* token,std::size_t n,void* user) {
            if(!n || n>20) return NGTCP2_ERR_CALLBACK_FAILURE;
            cid->datalen=n;
            if(gnutls_rnd(GNUTLS_RND_RANDOM,cid->data,n) || gnutls_rnd(GNUTLS_RND_RANDOM,token->data,sizeof(token->data)))
                return NGTCP2_ERR_CALLBACK_FAILURE;
            udp::Cid key; key.size=static_cast<std::uint8_t>(n); std::copy_n(cid->data,n,key.bytes.begin());
            return static_cast<NativeRuntime*>(user)->sink_.RegisterCid(key) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        cb.handshake_completed=[](ngtcp2_conn*,void* user) noexcept {
            try {
            auto& self=*static_cast<NativeRuntime*>(user); gnutls_datum_t alpn{};
            if(gnutls_alpn_get_selected_protocol(self.tls_,&alpn)<0 || alpn.size!=sizeof(wire::kEseWirePeerAlpn)-1 ||
                std::memcmp(alpn.data,wire::kEseWirePeerAlpn,sizeof(wire::kEseWirePeerAlpn)-1))
                return NGTCP2_ERR_CALLBACK_FAILURE;
            self.handshake_=true;
            if(!self.config_.server) {
                int64_t id=-1;
                if(ngtcp2_conn_open_bidi_stream(self.conn_,&id,nullptr) || id!=0 ||
                    ngtcp2_conn_open_bidi_stream(self.conn_,&id,nullptr) || id!=4) return NGTCP2_ERR_CALLBACK_FAILURE;
                self.dataStreamOpen_=true;
            }
            return self.io_->HandshakeComplete() ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
            } catch(...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
        };
        cb.remove_connection_id=[](ngtcp2_conn*,const ngtcp2_cid* cid,void* user) noexcept {
            if(!cid->datalen || cid->datalen>20) return NGTCP2_ERR_CALLBACK_FAILURE;
            udp::Cid key; key.size=static_cast<std::uint8_t>(cid->datalen);
            std::copy_n(cid->data,cid->datalen,key.bytes.begin());
            return static_cast<NativeRuntime*>(user)->sink_.RemoveCid(key) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        cb.recv_stream_data=ReceiveStream;
        cb.stream_open=[](ngtcp2_conn*,int64_t stream,void* user) noexcept {
            if(stream!=0 && stream!=4) return NGTCP2_ERR_CALLBACK_FAILURE;
            if(stream==4) static_cast<NativeRuntime*>(user)->dataStreamOpen_=true;
            return 0;
        };
        cb.acked_stream_data_offset=[](ngtcp2_conn*,int64_t stream,std::uint64_t offset,std::uint64_t n,void* user,void*) noexcept {
            try { return static_cast<NativeRuntime*>(user)->io_->Acknowledged(stream,offset,n) ? 0 : NGTCP2_ERR_CALLBACK_FAILURE; }
            catch(...) { return NGTCP2_ERR_CALLBACK_FAILURE; }
        };
        ngtcp2_cid source{},destination{}; source.datalen=8;
        Tls(gnutls_rnd(GNUTLS_RND_RANDOM,source.data,source.datalen));
        if(config_.server) destination=initial->scid;
        else { destination.datalen=NGTCP2_MIN_INITIAL_DCIDLEN; Tls(gnutls_rnd(GNUTLS_RND_RANDOM,destination.data,destination.datalen)); }
        ngtcp2_settings settings; ngtcp2_settings_default(&settings); settings.initial_ts=TimeNs();
        settings.max_tx_udp_payload_size=1200;
        ngtcp2_transport_params params; ngtcp2_transport_params_default(&params);
        params.initial_max_streams_bidi=config_.server ? 2 : 0; params.initial_max_streams_uni=0;
        params.initial_max_stream_data_bidi_local=params.initial_max_stream_data_bidi_remote=4096;
        params.initial_max_data=8192;
        if(config_.server) { params.original_dcid=initial->dcid; params.original_dcid_present=1; }
        auto path=Path();
        const auto result=config_.server ? ngtcp2_conn_server_new(&conn_,&destination,&source,&path,NGTCP2_PROTO_VER_V1,
            &cb,&settings,&params,nullptr,this) : ngtcp2_conn_client_new(&conn_,&destination,&source,&path,NGTCP2_PROTO_VER_V1,
            &cb,&settings,&params,nullptr,this);
        Require(result==0,"QUIC connection allocation"); ngtcp2_conn_set_tls_native_handle(conn_,tls_);
        udp::Cid cid; cid.size=static_cast<std::uint8_t>(source.datalen); std::copy_n(source.data,source.datalen,cid.bytes.begin());
        Require(sink_.RegisterCid(cid),"QUIC source CID registration");
        if(config_.server) { cid.size=static_cast<std::uint8_t>(initial->dcid.datalen);
            std::copy_n(initial->dcid.data,initial->dcid.datalen,cid.bytes.begin()); Require(sink_.RegisterCid(cid),"Initial CID registration"); }
    }
public:
    void Poll(std::uint64_t) override {
        if(stopped_ || !started_) return;
        // Copy one packet to a fixed scratch area and release its reservation
        // before library callbacks allocate the (smaller) decrypted payload.
        std::array<std::uint8_t,65536> packet{};
        for(unsigned i=0;i<128;++i) {
            const auto next=packets_.ReceiveFront(); if(!next.size) break;
            const auto length=next.size; std::copy_n(next.data,length,packet.begin());
            Require(packets_.ConsumeReceived(length),"packet dequeue");
            if(!conn_) {
                ngtcp2_pkt_hd initial{};
                Require(config_.server && length>=1200 && ngtcp2_accept(&initial,packet.data(),length)==0,"expected QUIC Initial");
                InitConnection(&initial);
            }
            auto path=Path(); ngtcp2_pkt_info info{};
            const int r=ngtcp2_conn_read_pkt(conn_,&path,&info,packet.data(),length,TimeNs());
            if(r==NGTCP2_ERR_DISCARD_PKT) continue;
            Require(r==0,ngtcp2_strerror(r));
        }
        if(!conn_) return;
        while(staged_.ReceiveFront().size) {
            const auto p=staged_.ReceiveFront(); const auto r=io_->Received(4,p);
            if(r.status==reach::DirectIoStatus::WouldBlock) break;
            Require(r.status==reach::DirectIoStatus::Accepted && r.accepted>0,"staged stream delivery");
            Require(staged_.ConsumeReceived(r.accepted),"staged consume");
        }
        // ngtcp2 silently ignores credit for streams that do not exist yet.
        // Do not advance our advertised end until stream 4 has been opened.
        if(io_->DataReady() && dataStreamOpen_) {
            const auto consumed=(std::min)(io_->ConsumedData(),std::uint64_t{NGTCP2_MAX_VARINT});
            const auto end=consumed+(std::min)(std::uint64_t{readBudget_},NGTCP2_MAX_VARINT-consumed);
            if(end>flowEnd_) {
                Require(ngtcp2_conn_extend_max_stream_offset(conn_,4,end-flowEnd_)==0,"QUIC stream receive credit");
                ngtcp2_conn_extend_max_offset(conn_,end-flowEnd_); flowEnd_=end;
            }
        }
        if(ngtcp2_conn_get_expiry(conn_)<=TimeNs()) Require(ngtcp2_conn_handle_expiry(conn_,TimeNs())==0,"QUIC expiry");
        // Pace the completed batch, not each individual datagram. Per-packet
        // updates otherwise make coarse event loops send only one MTU per tick.
        // The library quantum and the existing 64-packet cap bound each burst.
        struct BatchPacing {
            ngtcp2_conn* conn;
            std::size_t sent=0;
            ~BatchPacing() { if(sent) ngtcp2_conn_update_pkt_tx_time(conn,TimeNs()); }
        } batch{conn_};
        const auto quantum=ngtcp2_conn_get_send_quantum2(conn_);
        for(unsigned i=0;i<64;++i) {
            if(outboundSize_) {
                if(batch.sent && (batch.sent>=quantum || outboundSize_>quantum-batch.sent)) return;
                if(!sink_.Send(remote_,{outbound_.data(),outboundSize_})) return;
                batch.sent+=outboundSize_; outboundSize_=0;
            }
            if(batch.sent>=quantum) return;
            ngtcp2_path_storage path; ngtcp2_path_storage_zero(&path); ngtcp2_pkt_info info{};
            ngtcp2_ssize accepted=-1; int64_t stream=-1; ngtcp2_vec vector{}; std::size_t count=0;
            for(const int64_t id : {int64_t{0},int64_t{4}}) {
                // Responder cannot write the initiator-owned bidi data stream
                // before the first incoming STREAM frame creates it locally.
                if(id==4 && !dataStreamOpen_) continue;
                const auto p=io_->Pending(id);
                if(p.size) { stream=id; vector.base=const_cast<std::uint8_t*>(p.data); vector.len=p.size; count=1; break; }
            }
            // A zero-length STREAM (no FIN) opens stream 4 at the responder
            // without injecting application bytes or requiring client bulk.
            const bool opening=stream==-1 && !config_.server && io_->DataReady() && !dataOpeningSubmitted_;
            if(opening) stream=4;
            auto size=ngtcp2_conn_writev_stream(conn_,&path.path,&info,outbound_.data(),outbound_.size(),&accepted,
                NGTCP2_WRITE_STREAM_FLAG_NONE,stream,&vector,count,TimeNs());
            if(size==NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                // Flow control is backpressure, not a terminal transport error.
                // Still permit ACK/credit/crypto packets without app data.
                accepted=-1; stream=-1;
                size=ngtcp2_conn_writev_stream(conn_,&path.path,&info,outbound_.data(),outbound_.size(),&accepted,
                    NGTCP2_WRITE_STREAM_FLAG_NONE,-1,nullptr,0,TimeNs());
            }
            Require(size>=0,ngtcp2_strerror(static_cast<int>(size)));
            if(stream==4 && accepted>=0) dataOpeningSubmitted_=true;
            if(accepted>0) Require(io_->Submitted(stream,static_cast<std::size_t>(accepted)),"QUIC submitted range");
            if(!size) return; outboundSize_=static_cast<std::size_t>(size);
        }
    }
};
}
std::unique_ptr<QuicRuntime> CreateNativeQuicRuntime(const NativeQuicConfig& config,
    QuicDatagramSink& sink,reach::DirectBufferPool& pool,QuicIdentitySigner* signer) {
    return std::make_unique<NativeRuntime>(config,sink,pool,signer);
}
}
