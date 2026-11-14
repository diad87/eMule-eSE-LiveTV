#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "ServerTls.h"
#include "hex_fixture.h"
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <thread>

namespace {
using namespace ese::server;
using server_test::Check;
using server_test::LoadFixture;

struct Library {
    Library()
    {
        WSADATA data{};
        Check(WSAStartup(MAKEWORD(2,2),&data)==0,"Winsock initialization");
        if(gnutls_global_init()<0) {
            WSACleanup();
            throw std::runtime_error("GnuTLS initialization");
        }
    }
    ~Library() { gnutls_global_deinit(); WSACleanup(); }
};

struct Socket {
    explicit Socket(SOCKET raw) : value(raw) { Check(value!=INVALID_SOCKET,"open loopback socket"); }
    ~Socket() { closesocket(value); }
    const SOCKET value;
};

struct Credentials {
    gnutls_certificate_credentials_t value=nullptr;
    Credentials() { Check(gnutls_certificate_allocate_credentials(&value)==0,"TLS credentials"); }
    ~Credentials() { gnutls_certificate_free_credentials(value); }
};

struct Session {
    gnutls_session_t value=nullptr;
    explicit Session(unsigned flags) { Check(gnutls_init(&value,flags | GNUTLS_NO_TICKETS)==0,"TLS session"); }
    ~Session() { gnutls_deinit(value); }
};

struct Datum {
    gnutls_datum_t value{};
    ~Datum() { gnutls_free(value.data); }
};

struct ApplicationKey {
    gnutls_privkey_t key=nullptr;
    Bytes32 node{};
    ApplicationKey()
    {
        Check(gnutls_privkey_init(&key)==0,"application key handle");
        try {
            gnutls_pubkey_t raw=nullptr;
            Check(gnutls_pubkey_init(&raw)==0,"application public key handle");
            struct PublicKey { gnutls_pubkey_t value; ~PublicKey() { gnutls_pubkey_deinit(value); } } pub{raw};
            Datum x,y;
            gnutls_ecc_curve_t curve{};
            Check(gnutls_privkey_generate(key,GNUTLS_PK_EDDSA_ED25519,0,0)==0 &&
                gnutls_pubkey_import_privkey(pub.value,key,0,0)==0 &&
                gnutls_pubkey_export_ecc_raw2(pub.value,&curve,&x.value,&y.value,GNUTLS_EXPORT_FLAG_NO_LZ)==0 &&
                curve==GNUTLS_ECC_CURVE_ED25519 && x.value.size==node.size(),"export Ed25519 application public key");
            std::copy_n(x.value.data,node.size(),node.begin());
        } catch(...) {
            gnutls_privkey_deinit(key);
            throw;
        }
    }
    ~ApplicationKey() { gnutls_privkey_deinit(key); }
};

template<class Bytes>
gnutls_datum_t View(const Bytes& bytes) noexcept
{
    return {const_cast<unsigned char*>(bytes.data()),static_cast<unsigned int>(bytes.size())};
}

class ChannelCrypto final : public AuthCrypto {
public:
    ChannelCrypto(gnutls_session_t session,const ApplicationKey& identity)
        : session_(session), identity_(identity) {}
    bool Hash(ByteView bytes,Bytes32& output) noexcept override
    {
        return gnutls_hash_fast(GNUTLS_DIG_SHA256,bytes.data,bytes.size,output.data())==0;
    }
    bool Export(const Bytes32& digest,Bytes32& output) noexcept override
    {
        return ExportServerAuth(session_,digest,output);
    }
    bool Sign(const AuthTranscript& transcript,Signature& output) noexcept override
    {
        const auto bytes=View(transcript);
        Datum signature;
        if(gnutls_privkey_sign_data2(identity_.key,GNUTLS_SIGN_EDDSA_ED25519,0,&bytes,&signature.value)<0 ||
            signature.value.size!=output.size()) return false;
        std::copy_n(signature.value.data,output.size(),output.begin());
        return true;
    }
    static bool VerifySignature(const Bytes32& node,const AuthTranscript& transcript,const Signature& signature) noexcept
    {
        gnutls_pubkey_t publicKey=nullptr;
        if(gnutls_pubkey_init(&publicKey)<0) return false;
        struct PublicKey { gnutls_pubkey_t value; ~PublicKey() { gnutls_pubkey_deinit(value); } } key{publicKey};
        const auto x=View(node),bytes=View(transcript),sig=View(signature);
        return gnutls_pubkey_import_ecc_raw(key.value,GNUTLS_ECC_CURVE_ED25519,&x,nullptr)==0 &&
            gnutls_pubkey_verify_data2(key.value,GNUTLS_SIGN_EDDSA_ED25519,0,&bytes,&sig)==0;
    }
    bool Verify(const Bytes32& node,const AuthTranscript& transcript,const Signature& signature) noexcept override
    {
        return VerifySignature(node,transcript,signature);
    }
private:
    gnutls_session_t session_;
    const ApplicationKey& identity_;
};

void CheckAuthVectors(const std::filesystem::path& directory)
{
    auto expected=[&](const char* name) { return LoadFixture(directory/name); };
    const auto rawClient=expected("client_hello.hex"),rawServer=expected("server_hello.hex");
    ClientHello client;
    ServerHello server;
    Check(DecodeClientHello({rawClient.data(),rawClient.size()},client) &&
        DecodeServerHello({rawServer.data(),rawServer.size()},server),"independent canonical HELLO vectors are accepted");
    ClientHelloBytes encodedClient{};
    ServerHelloBytes encodedServer{};
    Check(EncodeClientHello(client,encodedClient) && EncodeServerHello(server,encodedServer) &&
        std::equal(encodedClient.begin(),encodedClient.end(),rawClient.begin(),rawClient.end()) &&
        std::equal(encodedServer.begin(),encodedServer.end(),rawServer.begin(),rawServer.end()),"canonical HELLO encoder bytes");
    for(size_t length=0;length<rawClient.size();++length)
        Check(!DecodeClientHello({rawClient.data(),length},client),"reject every truncated CLIENT_HELLO");
    for(size_t length=0;length<rawServer.size();++length)
        Check(!DecodeServerHello({rawServer.data(),length},server),"reject every truncated SERVER_HELLO");
    auto hellos=rawClient;
    hellos.insert(hellos.end(),rawServer.begin(),rawServer.end());
    Bytes32 digest{},exporter{};
    const auto rawExporter=expected("exporter.hex"),rawDigest=expected("hello_sha256.hex");
    Check(gnutls_hash_fast(GNUTLS_DIG_SHA256,hellos.data(),hellos.size(),digest.data())==0 &&
        std::equal(digest.begin(),digest.end(),rawDigest.begin(),rawDigest.end()) && rawExporter.size()==exporter.size(),
        "HELLO transcript matches independent SHA-256");
    std::copy(rawExporter.begin(),rawExporter.end(),exporter.begin());
    const auto clientProof=BuildAuthTranscript(exporter,digest,AuthRole::Client);
    const auto rawClientProof=expected("client_transcript.hex");
    const auto serverProof=BuildAuthTranscript(exporter,digest,AuthRole::Server);
    const auto rawServerProof=expected("server_transcript.hex");
    Check(std::equal(clientProof.begin(),clientProof.end(),rawClientProof.begin(),rawClientProof.end()) &&
        std::equal(serverProof.begin(),serverProof.end(),rawServerProof.begin(),rawServerProof.end()),
        "signature domain includes exact NUL before exporter, digest and role");
    Signature clientSignature{},serverSignature{};
    const auto rawClientSignature=expected("client_signature.hex"),rawServerSignature=expected("server_signature.hex");
    Check(rawClientSignature.size()==clientSignature.size() && rawServerSignature.size()==serverSignature.size(),
        "complete independent Ed25519 vectors");
    std::copy(rawClientSignature.begin(),rawClientSignature.end(),clientSignature.begin());
    std::copy(rawServerSignature.begin(),rawServerSignature.end(),serverSignature.begin());
    Check(ChannelCrypto::VerifySignature(client.node,clientProof,clientSignature) &&
        ChannelCrypto::VerifySignature(server.node,serverProof,serverSignature) &&
        !ChannelCrypto::VerifySignature(server.node,clientProof,clientSignature) &&
        !ChannelCrypto::VerifySignature(client.node,serverProof,clientSignature),
        "independent Ed25519 signatures accept only exact key, role and transcript");
}

struct TestCertificate {
    Credentials credentials;
    gnutls_x509_crt_t certificate=nullptr;
    gnutls_x509_privkey_t key=nullptr;
    TestCertificate()
    {
        Check(gnutls_x509_crt_init(&certificate)==0,"certificate handle");
        if(gnutls_x509_privkey_init(&key)<0) {
            gnutls_x509_crt_deinit(certificate);
            throw std::runtime_error("certificate private key handle");
        }
    }
    ~TestCertificate() { gnutls_x509_crt_deinit(certificate); gnutls_x509_privkey_deinit(key); }

    Bytes32 Issue(time_t validFrom,time_t validUntil)
    {
        constexpr char host[]="localhost";
        unsigned char serial=77;
        Check(gnutls_x509_privkey_generate(key,GNUTLS_PK_EDDSA_ED25519,0,0)==0 &&
            gnutls_x509_crt_set_version(certificate,3)==0 &&
            gnutls_x509_crt_set_serial(certificate,&serial,sizeof serial)==0 &&
            gnutls_x509_crt_set_activation_time(certificate,validFrom)==0 &&
            gnutls_x509_crt_set_expiration_time(certificate,validUntil)==0 &&
            gnutls_x509_crt_set_dn_by_oid(certificate,GNUTLS_OID_X520_COMMON_NAME,0,host,sizeof(host)-1)==0 &&
            gnutls_x509_crt_set_subject_alt_name(certificate,GNUTLS_SAN_DNSNAME,host,sizeof(host)-1,GNUTLS_FSAN_SET)==0 &&
            gnutls_x509_crt_set_key_usage(certificate,GNUTLS_KEY_DIGITAL_SIGNATURE)==0 &&
            gnutls_x509_crt_set_key_purpose_oid(certificate,GNUTLS_KP_TLS_WWW_SERVER,0)==0 &&
            gnutls_x509_crt_set_key(certificate,key)==0 &&
            gnutls_x509_crt_sign2(certificate,certificate,key,GNUTLS_DIG_UNKNOWN,0)==0 &&
            gnutls_certificate_set_x509_key(credentials.value,&certificate,1,key)==0,
            "issue test-only localhost certificate");

        // Cross-check the client verifier with GnuTLS's certificate SPKI
        // fingerprint API, independent of its DER export + explicit SHA256.
        Bytes32 pin{};
        size_t size=pin.size();
        Check(gnutls_x509_crt_get_key_id(certificate,GNUTLS_KEYID_USE_SHA256,pin.data(),&size)==0 &&
            size==pin.size(),"certificate SPKI fingerprint");
        return pin;
    }
};

ssize_t Push(gnutls_transport_ptr_t ptr,const void* bytes,size_t count)
{
    auto& socket=*static_cast<const Socket*>(ptr);
    const int result=send(socket.value,static_cast<const char*>(bytes),static_cast<int>((std::min)(count,size_t{65536})),0);
    if(result==SOCKET_ERROR) errno=EIO;
    return result;
}

ssize_t Pull(gnutls_transport_ptr_t ptr,void* bytes,size_t count)
{
    auto& socket=*static_cast<const Socket*>(ptr);
    const int result=recv(socket.value,static_cast<char*>(bytes),static_cast<int>((std::min)(count,size_t{65536})),0);
    if(result==SOCKET_ERROR) errno=EIO;
    return result;
}

void Attach(Session& session,Socket& socket)
{
    const DWORD deadline=3000;
    Check(setsockopt(socket.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&deadline),sizeof deadline)==0 &&
        setsockopt(socket.value,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&deadline),sizeof deadline)==0,
        "bound TLS socket I/O time");
    gnutls_transport_set_ptr(session.value,&socket);
    gnutls_transport_set_push_function(session.value,Push);
    gnutls_transport_set_pull_function(session.value,Pull);
}

struct Handshake {
    int client = GNUTLS_E_INTERNAL_ERROR;
    int server = GNUTLS_E_INTERNAL_ERROR;
    bool clientProtocol = false;
    bool serverProtocol = false;
    Bytes32 clientExporter{}, serverExporter{};
};

using WireBytes = std::vector<std::uint8_t>;

bool ReceiveAuth(gnutls_session_t sender,gnutls_session_t receiver,AuthSession& remote,
    AuthCrypto& remoteCrypto,const WireBytes& encoded)
{
    for(size_t offset=0;offset<encoded.size();) {
        const auto sent=gnutls_record_send(sender,encoded.data()+offset,encoded.size()-offset);
        Check(sent>0,"write encrypted authentication frame");
        offset+=static_cast<size_t>(sent);
    }
    FrameDecoder decoder;
    std::array<std::uint8_t,7> fragment{};
    for(;;) {
        const auto received=gnutls_record_recv(receiver,fragment.data(),fragment.size());
        Check(received>0,"receive encrypted authentication bytes");
        const auto fed=decoder.Feed({fragment.data(),static_cast<size_t>(received)});
        Check(fed.consumed==static_cast<size_t>(received) && fed.state!=DecodeState::Malformed,
            "decode arbitrarily fragmented authentication stream");
        if(fed.state==DecodeState::Ready) break;
    }
    const auto decoded=decoder.Get();
    Check(decoded.has_value(),"authentication frame ready");
    return remote.Receive(1,remoteCrypto,*decoded);
}

void ExchangeAuth(gnutls_session_t sender,gnutls_session_t receiver,AuthSession& local,
    AuthSession& remote,AuthCrypto& localCrypto,AuthCrypto& remoteCrypto)
{
    WireBytes encoded;
    Check(local.MakeNext(1,localCrypto,encoded) && ReceiveAuth(sender,receiver,remote,remoteCrypto,encoded),
        "authenticate expected peer and frame");
}

struct AuthVectors {
    ApplicationKey clientKey, serverKey;
    ClientHello clientHello;
    ServerHello serverHello;
    WireBytes recordedClientProof;
    static constexpr std::uint32_t supported=0x11;

    AuthVectors()
    {
        clientHello.node=clientKey.node;
        clientHello.supported=0x80000011u;
        clientHello.nonce.fill(0x20);
        clientHello.bootId.fill(0x22);
        clientHello.userHash.fill(0x23); // correlation only
        serverHello.node=serverKey.node;
        serverHello.nonce.fill(0x40);
        serverHello.epoch.fill(0x44);
        serverHello.session.fill(0x45);
        serverHello.generation=1;
    }
};

void ExerciseApplicationIdentity(gnutls_session_t client,gnutls_session_t server,AuthVectors& vectors)
{
    const auto& [clientKey,serverKey,clientHello,serverHello,recordedProof]=vectors;
    ChannelCrypto clientCrypto(client,clientKey), serverCrypto(server,serverKey);
    AuthSession nonPersistent(clientHello,serverKey.node,false,0);
    AuthSession expired(clientHello,serverKey.node,true,0);
    WireBytes rejected;
    Check(nonPersistent.State()==AuthState::Failed && !expired.MakeNext(10000,clientCrypto,rejected),
        "nonpersistent identity and auth timeout fail closed");
    AuthSession a(clientHello,serverKey.node,true,0), b(serverHello,AuthVectors::supported,true,0);
    Check(!a.RemoteServer() && !b.RemoteClient(),"unproven identities unavailable");
    ExchangeAuth(client,server,a,b,clientCrypto,serverCrypto);
    ExchangeAuth(server,client,b,a,serverCrypto,clientCrypto);
    Check(!a.RemoteServer() && !b.RemoteClient(),"HELLO does not authenticate");
    ExchangeAuth(server,client,b,a,serverCrypto,clientCrypto);
    if(!recordedProof.empty()) {
        Check(!ReceiveAuth(client,server,b,serverCrypto,recordedProof) && b.State()==AuthState::Failed && !b.RemoteClient(),
            "same identities and HELLO bytes reject a proof from another TLS channel");
        return;
    }
    Check(a.MakeNext(1,clientCrypto,vectors.recordedClientProof) &&
        ReceiveAuth(client,server,b,serverCrypto,vectors.recordedClientProof),"first-channel client proof");
    Check(!a.RemoteServer() && !b.RemoteClient(),"proofs alone do not dispatch operations");
    ExchangeAuth(server,client,b,a,serverCrypto,clientCrypto);
    Check(a.RemoteServer() && a.RemoteServer()->node==serverKey.node && a.RemoteServer()->selected==AuthVectors::supported &&
        b.RemoteClient() && b.RemoteClient()->node==clientKey.node && b.RemoteClient()->userHash==clientHello.userHash,
        "only ordered proofs and AUTH_OK release application identities");
}

Handshake Connect(const TestCertificate& serverIdentity,const TlsClientPolicy& policy,
    const Bytes32& transcriptHash,const char* alternativeAlpn=nullptr,bool tls12Only=false,bool trustCertificate=false,
    AuthVectors* auth=nullptr)
{
    Socket listener(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    sockaddr_in address{};
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    int addressSize=sizeof address;
    Check(bind(listener.value,reinterpret_cast<sockaddr*>(&address),sizeof address)==0 &&
        listen(listener.value,1)==0 && getsockname(listener.value,reinterpret_cast<sockaddr*>(&address),&addressSize)==0 &&
        address.sin_addr.s_addr==htonl(INADDR_LOOPBACK) && address.sin_port!=0,"bind owned IPv4 loopback endpoint");
    Socket clientSocket(socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    Check(connect(clientSocket.value,reinterpret_cast<const sockaddr*>(&address),sizeof address)==0,"connect owned loopback endpoint");
    Socket serverSocket(accept(listener.value,nullptr,nullptr));
    Credentials clientCerts;
    if(trustCertificate) {
        auto certificate=serverIdentity.certificate;
        Check(gnutls_certificate_set_x509_trust(clientCerts.value,&certificate,1)==1,"test PKIX anchor");
    }
    Session client(GNUTLS_CLIENT), server(GNUTLS_SERVER);
    Check(ConfigureTlsClient(client.value,clientCerts.value,policy) &&
        ConfigureTlsServer(server.value,serverIdentity.credentials.value),"configure exclusive TLS1.3 ESE application channel");
    Attach(client,clientSocket);
    Attach(server,serverSocket);
    if(alternativeAlpn) {
        auto* data=const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(alternativeAlpn));
        const gnutls_datum_t wrong{data,static_cast<unsigned>(std::strlen(alternativeAlpn))};
        Check(gnutls_alpn_set_protocols(client.value,&wrong,1,GNUTLS_ALPN_MANDATORY)==0,"set negative ALPN");
    }
    if(tls12Only)
        Check(gnutls_priority_set_direct(client.value,"NORMAL:-VERS-ALL:+VERS-TLS1.2",nullptr)==0,"set negative TLS version");

    Handshake result;
    Check(!ExportServerAuth(client.value,transcriptHash,result.clientExporter),"no pre-handshake exporter");
    std::thread peer([&] {
        result.server=gnutls_handshake(server.value);
        result.serverProtocol=result.server==0 && ExportServerAuth(server.value,transcriptHash,result.serverExporter);
        if(result.server<0) shutdown(serverSocket.value,SD_BOTH);
    });
    result.client=gnutls_handshake(client.value);
    result.clientProtocol=result.client==0 && ExportServerAuth(client.value,transcriptHash,result.clientExporter);
    if(result.client<0) shutdown(clientSocket.value,SD_BOTH);
    peer.join();
    if(auth) {
        Check(result.clientProtocol && result.serverProtocol,"TLS established before application authentication");
        ExerciseApplicationIdentity(client.value,server.value,*auth);
    }
    return result;
}
}

int main(int argc,char** argv)
{
    try {
        Check(argc==2,"path to fixture directory");
        Library library;
        CheckAuthVectors(argv[1]);
        const auto now=std::time(nullptr);
        Check(now>3600,"usable wall clock");
        TestCertificate valid, expired, future;
        const auto goodPin=valid.Issue(now-300,now+3600);
        Bytes32 helloDigest{};
        const char fixture[]="reference TLS transcript context";
        Check(gnutls_hash_fast(GNUTLS_DIG_SHA256,fixture,sizeof(fixture)-1,helloDigest.data())==0,"hello digest");
        const TlsClientPolicy pinned{TlsTrust::Pinned,"localhost",goodPin};
        AuthVectors auth;
        const auto first=Connect(valid,pinned,helloDigest,nullptr,false,false,&auth);
        const auto second=Connect(valid,pinned,helloDigest,nullptr,false,false,&auth);
        Check(first.client==0 && first.server==0 && first.clientProtocol && first.serverProtocol &&
            first.clientExporter==first.serverExporter && second.clientExporter==second.serverExporter &&
            second.clientProtocol && second.serverProtocol && first.clientExporter!=second.clientExporter,
            "real TLS 1.3 exporters agree on each channel and differ between connections");
        auto wrong=pinned;
        wrong.spkiSha256[0]^=1;
        Check(Connect(valid,wrong,helloDigest).client<0,"wrong SPKI pin fails");
        wrong=pinned;
        wrong.host="wrong.local";
        Check(Connect(valid,wrong,helloDigest).client<0,"wrong certificate hostname fails");
        auto expiredPolicy=pinned;
        expiredPolicy.spkiSha256=expired.Issue(now-3600,now-1);
        Check(Connect(expired,expiredPolicy,helloDigest).client<0,"expired certificate with exact pin still fails");
        auto futurePolicy=pinned;
        futurePolicy.spkiSha256=future.Issue(now+300,now+3600);
        Check(Connect(future,futurePolicy,helloDigest).client<0,"not-yet-valid certificate with exact pin still fails");
        Check(Connect(valid,pinned,helloDigest,"ese-server/2").client<0,"wrong ALPN fails");
        Check(Connect(valid,pinned,helloDigest,nullptr,true).client<0,"TLS1.2-only peer fails");
        const TlsClientPolicy pkix{TlsTrust::Pkix,"localhost",{}};
        Check(Connect(valid,pkix,helloDigest).client<0,"untrusted PKIX chain fails");
        Check(Connect(valid,pkix,helloDigest,nullptr,false,true).clientProtocol,"explicit test CA permits PKIX with matching hostname");
        std::cout<<"TLS 1.3 localhost PIN/PKIX, ALPN v1, ordered proof and cross-channel replay rejection PASS\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"TLS loopback FAIL "<<error.what()<<'\n';
        return 1;
    }
}
